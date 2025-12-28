from __future__ import annotations

import base64
import os
import tempfile
import time
import uuid
from typing import Any
from multiprocessing import Process, Queue

import signal

from fastapi import FastAPI
from pydantic import BaseModel, Field

try:
    import winrm  # pywinrm
except Exception:  # pragma: no cover
    winrm = None  # type: ignore

app = FastAPI(title="provity-sandbox-controller", version="0.1.0")


class ScanRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=260)
    file_sha256: str = Field(..., min_length=64, max_length=64)
    file_b64: str = Field(..., min_length=1)
    timeout_sec: int = Field(20, ge=5, le=300)


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    if v is None or not str(v).strip():
        return default
    return v


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "sandbox-controller"}


def _max_bytes() -> int:
    mb = int(_env("SANDBOX_MAX_MB", "10") or "10")
    return max(1, mb) * 1024 * 1024


def _ps_escape_single_quotes(s: str) -> str:
    # For single-quoted PowerShell strings: ' -> ''
    return s.replace("'", "''")


def _build_powershell_script(*, b64: str, filename: str, timeout_sec: int) -> str:
    # Minimal dynamic run + basic observability.
    # Returns JSON via ConvertTo-Json.
    safe_name = os.path.basename(filename)

    b64_escaped = _ps_escape_single_quotes(b64)
    name_escaped = _ps_escape_single_quotes(safe_name)

    return f"""
$ErrorActionPreference = 'Stop'

$runId = [guid]::NewGuid().ToString()
$baseDir = 'C:\\provity-sandbox'
$runDir = Join-Path $baseDir ('run\\' + $runId)
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$samplePath = Join-Path $runDir '{name_escaped}'

# Write file from base64
$bytes = [System.Convert]::FromBase64String('{b64_escaped}')
[System.IO.File]::WriteAllBytes($samplePath, $bytes)

function Get-ProcSnapshot {{
    try {{
        Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, CreationDate
    }} catch {{
        @()
    }}
}}

function Get-NetSnapshot {{
    try {{
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    }} catch {{
        @()
    }}
}}

function Get-NetKey($c) {{
    try {{
        return ([string]$c.LocalAddress) + ':' + ([string]$c.LocalPort) + '->' + ([string]$c.RemoteAddress) + ':' + ([string]$c.RemotePort) + '|' + ([string]$c.State) + '|pid=' + ([string]$c.OwningProcess)
    }} catch {{
        return ''
    }}
}}

function Get-DefenderStatus {{
    try {{
        $s = Get-MpComputerStatus -ErrorAction Stop
        return [pscustomobject]@{{
            am_service_enabled = $s.AMServiceEnabled
            antivirus_enabled = $s.AntivirusEnabled
            antispyware_enabled = $s.AntispywareEnabled
            realtime_protection_enabled = $s.RealTimeProtectionEnabled
            signature_last_updated = $s.AntivirusSignatureLastUpdated
            signature_version = $s.AntivirusSignatureVersion
            engine_version = $s.AMEngineVersion
            quick_scan_age = $s.QuickScanAge
            full_scan_age = $s.FullScanAge
        }}
    }} catch {{
        return $null
    }}
}}

function Try-UpdateDefenderSignature {{
    try {{
        Update-MpSignature -ErrorAction Stop | Out-Null
        return $true
    }} catch {{
        return $false
    }}
}}

function Try-DefenderCustomScan($path) {{
    try {{
        Start-MpScan -ScanType CustomScan -ScanPath $path -ErrorAction Stop | Out-Null
        return $true
    }} catch {{
        return $false
    }}
}}

function Get-RecentDetections($since) {{
    $out = @()
    try {{
        $raw = Get-MpThreatDetection -ErrorAction Stop | Where-Object {{ $_.InitialDetectionTime -ge $since }}
        foreach ($t in $raw) {{
            $out += [pscustomobject]@{{
                threat_name = $t.ThreatName
                detection_time = $t.InitialDetectionTime
                action_success = $t.ActionSuccess
                resources = $t.Resources
            }}
        }}
    }} catch {{
        # swallow
    }}
    return $out
}}

$beforeProc = Get-ProcSnapshot
$beforeNet = Get-NetSnapshot

$start = Get-Date
$proc = $null
$exitCode = $null
$note = @()

$defenderStatusBefore = Get-DefenderStatus
$defenderSignatureUpdated = $false
$defenderScanAttempted = $false

try {{
    # Try to improve detection quality: update signatures + custom scan the sample before execution.
    # Best-effort only; will add a note if it fails.
    $doSigUpdate = '{os.getenv("SANDBOX_DEFENDER_UPDATE", "0")}'.ToLower() -in @('1','true','yes')
    $doDefenderScan = '{os.getenv("SANDBOX_DEFENDER_SCAN", "1")}'.ToLower() -in @('1','true','yes')
    $defenderWaitSec = [int]('{os.getenv("SANDBOX_DEFENDER_WAIT_SEC", "10")}')
    if ($defenderWaitSec -lt 0) {{ $defenderWaitSec = 0 }}
    if ($defenderWaitSec -gt 60) {{ $defenderWaitSec = 60 }}

    if ($doSigUpdate) {{
        $defenderSignatureUpdated = Try-UpdateDefenderSignature
        if (-not $defenderSignatureUpdated) {{ $note += 'Defender signature update failed or unavailable' }}
    }}

    if ($doDefenderScan) {{
        $defenderScanAttempted = Try-DefenderCustomScan $samplePath
        if (-not $defenderScanAttempted) {{ $note += 'Defender custom scan failed or unavailable' }}
    }}

    # Attempt to start the sample. Many installers need UI; this is best-effort.
    $proc = Start-Process -FilePath $samplePath -PassThru
    Start-Sleep -Seconds {timeout_sec}

    if ($proc -and -not $proc.HasExited) {{
        try {{
            Stop-Process -Id $proc.Id -Force
            $note += 'Process terminated after timeout'
        }} catch {{
            $note += ('Failed to terminate process: ' + $_.Exception.Message)
        }}
    }}

    if ($proc) {{
        try {{ $exitCode = $proc.ExitCode }} catch {{ $exitCode = $null }}
    }}
}} catch {{
    $note += ('Execution error: ' + $_.Exception.Message)
}}

$afterProc = Get-ProcSnapshot
$afterNet = Get-NetSnapshot

$elapsed = (Get-Date) - $start

# Diff processes by (ProcessId) presence
$beforeIds = @{{}}
foreach ($p in $beforeProc) {{ $beforeIds[[string]$p.ProcessId] = $true }}
$newProc = @()
foreach ($p in $afterProc) {{
    if (-not $beforeIds.ContainsKey([string]$p.ProcessId)) {{ $newProc += $p }}
}}

# Diff TCP connections by key
$beforeNetKeys = @{{}}
foreach ($c in $beforeNet) {{
    $k = Get-NetKey $c
    if ($k) {{ $beforeNetKeys[$k] = $true }}
}}
$newNet = @()
foreach ($c in $afterNet) {{
    $k = Get-NetKey $c
    if ($k -and -not $beforeNetKeys.ContainsKey($k)) {{ $newNet += $c }}
}}

# Collect Windows Defender detections since start (best-effort)
$detections = @()
try {{
    # Poll for a short window because detections can appear slightly after execution/scan.
    $since = $start.AddSeconds(-2)
    $pollStart = Get-Date
    do {{
        $detections = Get-RecentDetections $since
        if ($detections.Count -gt 0) {{ break }}
        Start-Sleep -Milliseconds 500
    }} while (((Get-Date) - $pollStart).TotalSeconds -lt [math]::Max(0, $defenderWaitSec))
}} catch {{
    $note += ('Defender query failed: ' + $_.Exception.Message)
}}

$verdict = 'unknown'
$score = 0
if ($detections.Count -gt 0) {{
    $verdict = 'malicious'
    $score = 100
}} elseif ($newNet.Count -gt 0 -or $newProc.Count -gt 0) {{
    $verdict = 'suspicious'
    $score = 40
}}

$result = [ordered]@{{
    ok = $true
    run_id = $runId
    sample_path = $samplePath
    timeout_sec = {timeout_sec}
    exit_code = $exitCode
    elapsed_sec = [int][Math]::Round($elapsed.TotalSeconds)
    verdict = $verdict
    score = $score
    detections = $detections
    defender = [ordered]@{{
        scan_attempted = $defenderScanAttempted
        signature_updated = $defenderSignatureUpdated
        status_before = $defenderStatusBefore
        status_after = (Get-DefenderStatus)
    }}
    new_processes = $newProc
    new_net_connections = $newNet
    net_connections = $afterNet
    notes = $note
}}

$result | ConvertTo-Json -Depth 6
""".strip()


def _run_winrm(*, script: str) -> str:
    host = _env("WINRM_HOST")
    user = _env("WINRM_USER")
    password = _env("WINRM_PASSWORD")
    transport = _env("WINRM_TRANSPORT", "ntlm")

    if not host or not user or not password:
        raise RuntimeError("WINRM is not configured (set WINRM_HOST/WINRM_USER/WINRM_PASSWORD)")
    if winrm is None:
        raise RuntimeError("pywinrm not installed")

    # NOTE: For MVP we keep this simple. In production, pin TLS, use HTTPS, and avoid plaintext creds.
    session = winrm.Session(host, auth=(user, password), transport=transport)
    r = session.run_ps(script)
    stdout = (r.std_out or b"").decode("utf-8", errors="replace")
    stderr = (r.std_err or b"").decode("utf-8", errors="replace")
    if r.status_code != 0:
        raise RuntimeError(f"WinRM status={r.status_code}. stderr={stderr[:400]}")
    return stdout.strip() or stderr.strip()


def _extract_suspicious_api_calls(report: dict[str, Any]) -> dict[str, Any]:
    suspicious_markers = {
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "QueueUserAPC",
        "SetWindowsHookEx",
        "NtCreateThreadEx",
        "URLDownloadToFile",
        "InternetOpenUrl",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "CreateService",
        "StartService",
        "RegSetValue",
        "RegSetValueEx",
        "ShellExecute",
        "ShellExecuteEx",
        "WinExec",
        "CreateProcess",
        "CreateProcessW",
    }

    calls: list[str] = []
    suspicious_hits: list[str] = []

    api_calls = report.get("api_calls")
    if isinstance(api_calls, list):
        for c in api_calls:
            if not isinstance(c, dict):
                continue
            api = c.get("api") or c.get("name")
            if isinstance(api, str) and api:
                calls.append(api)

    # Some report variants nest calls under "modules" -> "api_calls"
    if not calls:
        modules = report.get("modules")
        if isinstance(modules, list):
            for m in modules:
                if not isinstance(m, dict):
                    continue
                m_calls = m.get("api_calls")
                if isinstance(m_calls, list):
                    for c in m_calls:
                        if not isinstance(c, dict):
                            continue
                        api = c.get("api") or c.get("name")
                        if isinstance(api, str) and api:
                            calls.append(api)

    for api in calls:
        base = api.split("!")[-1]
        if base in suspicious_markers:
            suspicious_hits.append(base)

    return {
        "api_calls_count": len(calls),
        "suspicious_api_hits": sorted(set(suspicious_hits)),
        "suspicious_api_hits_count": len(set(suspicious_hits)),
    }


def _speakeasy_worker(*, sample_path: str, result_q: Queue) -> None:
    try:
        from speakeasy import Speakeasy  # type: ignore

        se = Speakeasy()

        def _alarm_handler(_signum: int, _frame: Any) -> None:  # pragma: no cover
            raise TimeoutError("emulation timeout")

        # Best-effort graceful timeout so we can still return a partial report.
        # The parent process still enforces a hard timeout as a safety net.
        alarm_sec_env = os.getenv("SANDBOX_EMULATE_ALARM_SEC")
        alarm_sec = int(alarm_sec_env) if (alarm_sec_env and alarm_sec_env.isdigit()) else 0
        if alarm_sec > 0:
            signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(alarm_sec)

        timed_out = False
        try:
            module = se.load_module(sample_path)
            se.run_module(module)
        except TimeoutError:
            timed_out = True
        finally:
            if alarm_sec > 0:
                signal.alarm(0)

        report = se.get_report()
        if not isinstance(report, dict):
            result_q.put({"ok": False, "reason": "invalid speakeasy report"})
            return
        result_q.put({"ok": True, "report": report, "timed_out": timed_out})
    except Exception as e:
        result_q.put({"ok": False, "reason": f"emulation failed: {e}"})


def _run_emulate(*, raw: bytes, filename: str, timeout_sec: int) -> dict[str, Any]:
    run_id = str(uuid.uuid4())

    with tempfile.TemporaryDirectory(prefix="provity-sandbox-") as td:
        safe_name = os.path.basename(filename) or "sample.bin"
        sample_path = os.path.join(td, safe_name)
        with open(sample_path, "wb") as f:
            f.write(raw)

        q: Queue = Queue(maxsize=1)
        # Give the child a chance to stop gracefully at timeout_sec via SIGALRM,
        # but keep a small hard-kill headroom to avoid hung workers.
        os.environ.setdefault("SANDBOX_EMULATE_ALARM_SEC", str(int(timeout_sec)))
        p = Process(target=_speakeasy_worker, kwargs={"sample_path": sample_path, "result_q": q})
        start = time.time()
        p.start()
        p.join(timeout=max(5, int(timeout_sec) + 5))

        if p.is_alive():
            p.terminate()
            p.join(timeout=2)
            return {
                "ok": True,
                "run_id": run_id,
                "reason": "emulation timeout",
                "elapsed_sec": int(time.time() - start),
                "verdict": "suspicious",
                "score": 25,
                "detections": [],
                "emulation": {
                    "timed_out": True,
                    "api_calls_count": 0,
                    "suspicious_api_hits": [],
                    "suspicious_api_hits_count": 0,
                    "notes": [
                        "SANDBOX_MODE=emulate",
                        "emulation timed out; verdict is conservative",
                        "try increasing Dynamic scan runtime",
                    ],
                },
            }

        if q.empty():
            return {
                "ok": False,
                "run_id": run_id,
                "reason": "emulation produced no result",
                "elapsed_sec": int(time.time() - start),
            }

        res = q.get()
        if not isinstance(res, dict) or res.get("ok") is not True:
            return {
                "ok": False,
                "run_id": run_id,
                "reason": str((res or {}).get("reason") or "emulation failed"),
                "elapsed_sec": int(time.time() - start),
            }

        report = res.get("report")
        if not isinstance(report, dict):
            return {
                "ok": False,
                "run_id": run_id,
                "reason": "invalid emulation report",
                "elapsed_sec": int(time.time() - start),
            }

        timed_out = bool(res.get("timed_out"))

        summary = _extract_suspicious_api_calls(report)
        hits = int(summary.get("suspicious_api_hits_count") or 0)
        api_calls_count = int(summary.get("api_calls_count") or 0)

        verdict = "unknown"
        score = 0
        if hits >= 2:
            verdict = "malicious"
            score = 85
        elif hits == 1 or api_calls_count > 50:
            verdict = "suspicious"
            score = 45

        return {
            "ok": True,
            "run_id": run_id,
            "reason": "emulate" if not timed_out else "emulate (partial; timed out)",
            "elapsed_sec": int(time.time() - start),
            "verdict": verdict,
            "score": score,
            "detections": [],
            "emulation": {
                **summary,
                "timed_out": timed_out,
                "notes": [
                    "SANDBOX_MODE=emulate",
                    "verdict derived from suspicious API usage",
                    "increase runtime if frequently timing out",
                ],
            },
        }


@app.post("/scan")
def scan(req: ScanRequest) -> dict[str, Any]:
    # Allow a mock mode for wiring/testing without a VM.
    mode = (_env("SANDBOX_MODE", "winrm") or "winrm").lower()

    raw = base64.b64decode(req.file_b64.encode("ascii"), validate=False)
    if len(raw) > _max_bytes():
        return {"ok": False, "reason": "file too large", "max_bytes": _max_bytes()}

    if mode == "mock":
        return {
            "ok": True,
            "run_id": str(uuid.uuid4()),
            "reason": "mock",
            "elapsed_sec": 1,
            "verdict": "unknown",
            "score": 0,
            "detections": [],
            "new_processes": [],
            "new_net_connections": [],
            "net_connections": [],
            "notes": ["SANDBOX_MODE=mock"],
        }

    if mode == "emulate":
        return _run_emulate(raw=raw, filename=req.filename, timeout_sec=req.timeout_sec)

    start = time.time()
    try:
        ps = _build_powershell_script(b64=req.file_b64, filename=req.filename, timeout_sec=req.timeout_sec)
        out = _run_winrm(script=ps)
        # PowerShell outputs JSON; return it as parsed dict if possible.
        import json

        data = json.loads(out)
        if isinstance(data, dict):
            data.setdefault("ok", True)
            data.setdefault("elapsed_sec", int(time.time() - start))
            data.setdefault("verdict", "unknown")
            data.setdefault("score", 0)
            data.setdefault("detections", [])
            return data
        return {"ok": True, "raw": data, "elapsed_sec": int(time.time() - start)}
    except Exception as e:
        return {"ok": False, "reason": str(e), "elapsed_sec": int(time.time() - start)}
