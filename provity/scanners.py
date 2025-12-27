from __future__ import annotations

import os
import re
import subprocess
import shutil
import tempfile
import tarfile
from pathlib import Path
from typing import Any

DEFAULT_CA_PATH = "/etc/ssl/certs/ca-certificates.crt"

SUSPICIOUS_PATTERNS: dict[str, str] = {
    "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "URL": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
    "Suspicious Cmd": r"(cmd\.exe|powershell|wget|curl|/bin/sh)",
    "Registry Key": r"HKLM\\\\|HKCU\\\\|Software\\\\Microsoft\\\\Windows",
}


def verify_signature(file_path: str, ca_path: str = DEFAULT_CA_PATH) -> tuple[bool, str, dict[str, Any]]:
    """Signature verification using osslsigncode."""
    if not os.path.exists(ca_path):
        return False, "CA certificate not found.", {}

    try:
        cmd = ["osslsigncode", "verify", "-CAfile", ca_path, "-in", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = (result.stdout or "") + (result.stderr or "")

        info: dict[str, Any] = {"signer": "Unknown"}
        is_valid = "Signature verification: ok" in output

        subject_match = re.search(r"Subject:.*?CN=([^,\n]+)", output)
        if subject_match:
            info["signer"] = subject_match.group(1).strip()

        return is_valid, output, info
    except subprocess.TimeoutExpired:
        return False, "Signature verification timed out.", {}
    except FileNotFoundError:
        return False, "osslsigncode is not installed.", {}


def verify_signature_detailed(
    file_path: str,
    *,
    ca_path: str = DEFAULT_CA_PATH,
    enable_revocation: bool = False,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    """Detailed signature verification (Authenticode).

    Prefers Windows `signtool` if available, otherwise falls back to `osslsigncode`.
    Returns a structured dict suitable for UI rendering.

    Notes on revocation:
    - Revocation (OCSP/CRL) generally requires online access.
    - Tool support varies. This function reports revocation as best-effort.
    """
    if shutil.which("signtool"):
        return _verify_signature_detailed_signtool(
            file_path,
            enable_revocation=enable_revocation,
            timeout_sec=timeout_sec,
        )

    return _verify_signature_detailed_osslsigncode(
        file_path,
        ca_path=ca_path,
        enable_revocation=enable_revocation,
        timeout_sec=timeout_sec,
    )


def _verify_signature_detailed_signtool(
    file_path: str,
    *,
    enable_revocation: bool,
    timeout_sec: int,
) -> dict[str, Any]:
    # `signtool` availability is optional; this codepath is used only when present.
    # We keep parsing resilient because signtool output varies by Windows/SDK version.
    cmd = ["signtool", "verify", "/pa", "/v", file_path]

    revocation_checked = False
    if enable_revocation:
        # Signtool typically performs chain evaluation using Windows trust settings.
        # Some environments validate revocation by default when online. We mark this
        # as best-effort rather than claiming strict OCSP/CRL behavior.
        revocation_checked = True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        return {
            "backend": "signtool",
            "valid": False,
            "failure_reason": "Signature verification timed out.",
            "raw_log": "signtool verify timed out.",
            "revocation_checked": revocation_checked,
            "revocation_ok": None,
            "timestamp_present": None,
        }

    is_valid = ("Successfully verified" in output) or ("SignTool Error" not in output and result.returncode == 0)

    subject = _first_match(output, r"Issued to:\s*(.+)")
    issuer = _first_match(output, r"Issued by:\s*(.+)")
    not_before = _first_match(output, r"Valid from:\s*(.+)")
    not_after = _first_match(output, r"Valid to:\s*(.+)")

    signer_cn = None
    if subject:
        cn_match = re.search(r"CN=([^,]+)", subject)
        if cn_match:
            signer_cn = cn_match.group(1).strip()

    timestamp_present = _contains_any(output, ["Timestamp", "timestamp", "Time Stamping", "time stamping"])

    failure_reason = None
    if not is_valid:
        failure_reason = _first_match(output, r"SignTool Error:\s*(.+)") or "Signature verification failed."

    return {
        "backend": "signtool",
        "valid": is_valid,
        "signer_cn": signer_cn,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "timestamp_present": timestamp_present,
        "revocation_checked": revocation_checked,
        "revocation_ok": None if not revocation_checked else (True if is_valid else None),
        "failure_reason": failure_reason,
        "raw_log": output,
    }


def _verify_signature_detailed_osslsigncode(
    file_path: str,
    *,
    ca_path: str,
    enable_revocation: bool,
    timeout_sec: int,
) -> dict[str, Any]:
    if not os.path.exists(ca_path):
        return {
            "backend": "osslsigncode",
            "valid": False,
            "failure_reason": "CA certificate not found.",
            "raw_log": "CA certificate not found.",
            "revocation_checked": False,
            "revocation_ok": None,
            "timestamp_present": None,
        }

    revocation_checked = False
    if enable_revocation:
        # osslsigncode verification does not reliably provide OCSP/CRL checks across setups.
        # We treat revocation as unsupported here unless the environment explicitly wraps it.
        revocation_checked = False

    try:
        cmd = ["osslsigncode", "verify", "-CAfile", ca_path, "-in", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        return {
            "backend": "osslsigncode",
            "valid": False,
            "failure_reason": "Signature verification timed out.",
            "raw_log": "osslsigncode verify timed out.",
            "revocation_checked": False,
            "revocation_ok": None,
            "timestamp_present": None,
        }
    except FileNotFoundError:
        return {
            "backend": "osslsigncode",
            "valid": False,
            "failure_reason": "osslsigncode is not installed.",
            "raw_log": "osslsigncode is not installed.",
            "revocation_checked": False,
            "revocation_ok": None,
            "timestamp_present": None,
        }

    is_valid = "Signature verification: ok" in output
    subject = _first_match(output, r"Subject:\s*(.+)")
    issuer = _first_match(output, r"Issuer:\s*(.+)")
    not_before = _first_match(output, r"Not Before\s*:?\s*(.+)")
    not_after = _first_match(output, r"Not After\s*:?\s*(.+)")

    signer_cn = None
    cn_match = re.search(r"Subject:.*?CN=([^,\n]+)", output)
    if cn_match:
        signer_cn = cn_match.group(1).strip()

    timestamp_present = _contains_any(output, ["Timestamp", "timestamp", "Time Stamping", "time stamping", "TSA"])

    failure_reason = None
    if not is_valid:
        # Best-effort extraction of a human-readable failure line.
        failure_reason = (
            _first_match(output, r"Signature verification:\s*(.+)")
            or _first_match(output, r"ERROR:\s*(.+)")
            or "Signature verification failed."
        )

    revocation_note = None
    if enable_revocation:
        revocation_note = "Revocation check requested, but not supported by osslsigncode backend."

    return {
        "backend": "osslsigncode",
        "valid": is_valid,
        "signer_cn": signer_cn,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "timestamp_present": timestamp_present,
        "revocation_checked": False,
        "revocation_ok": None,
        "revocation_note": revocation_note,
        "failure_reason": failure_reason,
        "raw_log": output,
    }


def _first_match(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip()


def _contains_any(text: str, needles: list[str]) -> bool:
    lowered = text.lower()
    return any(n.lower() in lowered for n in needles)


def scan_virus_clamav(file_path: str, *, enable_extended: bool = True) -> tuple[bool | None, str, str]:
    """Local threat scan using ClamAV (clamscan).

    Historically this function only reported "malware". It now best-effort enables
    extra ClamAV detections (PUA/phishing/macro/encrypted/broken) when the local
    clamscan supports them, while preserving the original return type.

    Returns:
      - (True,  "Clean", <stdout>) when no threats are detected
      - (False, <label>,  <stdout>) when threats are detected
      - (None,  <label>,  <stderr/diagnostic>) on scanner errors
    """
    detail = scan_threats_clamav(file_path, recursive=False, enable_extended=enable_extended)
    return detail.get("state"), str(detail.get("label")), str(detail.get("raw_log"))


def scan_threats_clamav(
    file_path: str,
    *,
    recursive: bool = False,
    enable_extended: bool = True,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    """Run ClamAV scan with best-effort extra checks.

    This expands beyond classic malware signatures and can surface:
      - PUA (potentially unwanted applications)
      - phishing signatures
      - macro alerts
      - encrypted content alerts
      - broken file alerts

    Since clamscan options vary across versions/builds, we attempt an extended
    flag set and fall back to a minimal scan if clamscan rejects unknown flags.

    Output schema (stable for UI/DB):
      - state: True/False/None
      - label: short summary label ("Clean" or a categorized signature name)
      - findings: list of {path, signature, category}
      - flags: list of flags used
      - raw_log: combined stdout/stderr for display/debug
    """

    def _parse_findings(stdout: str) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        for line in (stdout or "").splitlines():
            if not line.strip().endswith("FOUND"):
                continue
            # Typical format: "/path/file: Signature.Name FOUND"
            try:
                left, _ = line.rsplit("FOUND", 1)
                if ":" not in left:
                    continue
                p, sig = left.split(":", 1)
                path_s = p.strip()
                sig_s = sig.strip()
                if not path_s or not sig_s:
                    continue
                findings.append(
                    {
                        "path": path_s,
                        "signature": sig_s,
                        "category": _categorize_clamav_signature(sig_s),
                    }
                )
            except Exception:
                continue
        return findings

    def _run(flags: list[str]) -> tuple[int, str, str]:
        cmd = ["clamscan", *flags, file_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")

    base_flags = ["--no-summary"]
    if recursive:
        base_flags.insert(0, "-r")

    # Extended checks: keep these conservative; unsupported flags are handled by fallback.
    extended_flags = [
        *base_flags,
        "--detect-pua=yes",
        "--detect-structured=yes",
        "--alert-macros=yes",
        "--alert-encrypted=yes",
        "--alert-broken=yes",
        "--alert-phishing-ssl=yes",
        "--alert-phishing-cloak=yes",
    ]

    try:
        flags_to_try = extended_flags if enable_extended else base_flags
        returncode, stdout, stderr = _run(flags_to_try)
        combined = (stdout or "") + ("\n" if stdout and stderr else "") + (stderr or "")

        # Some clamscan builds return 2 + "Unknown option" when flags aren't supported.
        lowered = combined.lower()
        if enable_extended and returncode == 2 and (
            "unknown option" in lowered
            or "unrecognized option" in lowered
            or "can't parse option" in lowered
            or "invalid option" in lowered
        ):
            returncode, stdout, stderr = _run(base_flags)
            combined = (stdout or "") + ("\n" if stdout and stderr else "") + (stderr or "")
            used_flags = base_flags
        else:
            used_flags = flags_to_try

        if returncode == 0:
            return {
                "state": True,
                "label": "Clean",
                "findings": [],
                "flags": used_flags,
                "raw_log": combined.strip(),
            }

        if returncode == 1:
            findings = _parse_findings(stdout)
            label = "Threat Detected"
            if findings:
                f0 = findings[0]
                label = f"{f0.get('category', 'Threat')}: {f0.get('signature', 'Unknown')}"
            return {
                "state": False,
                "label": label,
                "findings": findings,
                "flags": used_flags,
                "raw_log": combined.strip(),
            }

        # returncode 2 or other non-standard values
        return {
            "state": None,
            "label": "Engine Error",
            "findings": [],
            "flags": used_flags,
            "raw_log": combined.strip(),
        }

    except FileNotFoundError:
        return {
            "state": None,
            "label": "ClamAV (clamscan) is not installed.",
            "findings": [],
            "flags": [],
            "raw_log": "",
        }
    except subprocess.TimeoutExpired:
        return {
            "state": None,
            "label": "Scan Timeout",
            "findings": [],
            "flags": extended_flags if enable_extended else base_flags,
            "raw_log": "ClamAV scan timed out.",
        }


def _categorize_clamav_signature(signature: str) -> str:
    s = (signature or "").strip().lower()
    if not s:
        return "Threat"

    # PUA
    if s.startswith("pua.") or "pua" in s:
        return "PUA"

    # Phishing
    if "phish" in s:
        return "Phishing"

    # Macro / documents
    if "macro" in s:
        return "Macro"

    # Encrypted content
    if "encrypt" in s:
        return "Encrypted"

    # Heuristics / broken / limits
    if s.startswith("heuristics.") or "heuristic" in s or "broken" in s or "exceed" in s:
        return "Heuristic"

    return "Malware"


def static_analysis(file_path: str) -> dict[str, list[str]]:
    """Static analysis using Linux strings command (IOC Extraction)."""
    found_artifacts: dict[str, list[str]] = {k: [] for k in SUSPICIOUS_PATTERNS.keys()}

    try:
        cmd = ["strings", "-n", "6", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=120)

        for line in (result.stdout or "").splitlines():
            if len(line) > 200:
                continue

            for category, pattern in SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    item = line.strip()
                    if item not in found_artifacts[category] and len(found_artifacts[category]) < 5:
                        found_artifacts[category].append(item)

        return found_artifacts
    except subprocess.TimeoutExpired:
        return {}
    except Exception:
        return {}


def scan_deb_package(file_path: str, *, enable_extended: bool = True) -> dict[str, Any]:
    """Specialized handling for Debian packages (.deb).

    Returns a dict with keys:
      - sig_detail: dict with signature verification details (backend, valid, raw_log, ...)
      - clam_result: tuple (is_clean | None, label, raw_log)
      - artifacts: dict of static analysis findings

    This function prefers `dpkg-deb`/`dpkg-sig` when available and falls back to
    extracting the ar archive if needed.
    """
    result: dict[str, Any] = {
        "sig_detail": {"backend": "dpkg-sig", "valid": False, "raw_log": "Not checked"},
        "clam_result": (None, "ClamAV not run", ""),
        "artifacts": {},
    }

    tmpdir = Path(tempfile.mkdtemp(prefix="provity_deb_"))
    extract_dir = tmpdir / "extract"
    control_dir = tmpdir / "control"
    extract_dir.mkdir(parents=True, exist_ok=True)
    control_dir.mkdir(parents=True, exist_ok=True)

    # 1) Signature: try dpkg-sig if present
    try:
        if shutil.which("dpkg-sig"):
            cmd = ["dpkg-sig", "--verify", file_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out = (proc.stdout or "") + (proc.stderr or "")
            valid = proc.returncode == 0
            result["sig_detail"] = {"backend": "dpkg-sig", "valid": valid, "raw_log": out}
        else:
            result["sig_detail"] = {"backend": "dpkg-sig", "valid": False, "raw_log": "dpkg-sig not installed"}
    except subprocess.TimeoutExpired:
        result["sig_detail"] = {"backend": "dpkg-sig", "valid": False, "raw_log": "dpkg-sig timed out"}
    except Exception as e:
        result["sig_detail"] = {"backend": "dpkg-sig", "valid": False, "raw_log": str(e)}

    # 2) Extract package contents (prefer dpkg-deb)
    extracted_ok = False
    try:
        if shutil.which("dpkg-deb"):
            # -x extracts data, -e extracts control (DEBIAN)
            subprocess.run(["dpkg-deb", "-x", file_path, str(extract_dir)], check=True, capture_output=True, text=True, timeout=60)
            subprocess.run(["dpkg-deb", "-e", file_path, str(control_dir)], check=True, capture_output=True, text=True, timeout=30)
            extracted_ok = True
        else:
            # Fallback: use 'ar' to extract members, then untar data.tar.*
            if shutil.which("ar"):
                # run in temp dir
                subprocess.run(["ar", "x", file_path], cwd=str(tmpdir), check=True, capture_output=True, text=True, timeout=30)
                # find data.tar.*
                for member in tmpdir.iterdir():
                    if member.name.startswith("data.tar"):
                        # extract
                        try:
                            with tarfile.open(member, "r:*") as t:
                                t.extractall(path=str(extract_dir))
                            extracted_ok = True
                        except Exception:
                            continue
    except subprocess.CalledProcessError:
        extracted_ok = False
    except subprocess.TimeoutExpired:
        extracted_ok = False

    # 3) ClamAV: scan the .deb file and (if extracted) the extracted tree recursively
    try:
        # First scan the .deb file itself
        clam_deb = scan_virus_clamav(file_path, enable_extended=enable_extended)

        # Then, if extracted, scan the extracted tree recursively.
        if extracted_ok and shutil.which("clamscan"):
            tree_detail = scan_threats_clamav(
                str(extract_dir),
                recursive=True,
                enable_extended=enable_extended,
                timeout_sec=300,
            )
            clam_tree = (tree_detail.get("state"), str(tree_detail.get("label")), str(tree_detail.get("raw_log")))

            # Prefer tree result if it found threats, else fallback to single-file result
            if clam_tree[0] is False:
                result["clam_result"] = clam_tree
            else:
                result["clam_result"] = clam_deb
        else:
            result["clam_result"] = clam_deb
    except subprocess.TimeoutExpired:
        result["clam_result"] = (None, "Scan Timeout", "ClamAV scan timed out")
    except Exception:
        result["clam_result"] = (None, "Scan Error", "")

    # 4) Static analysis: run on the .deb file and on extracted executables
    artifacts: dict[str, list[str]] = {}
    try:
        # Start with the archive itself
        base_art = static_analysis(file_path) or {}
        for k, v in base_art.items():
            artifacts.setdefault(k, [])
            for it in v:
                if it not in artifacts[k]:
                    artifacts[k].append(it)

        if extracted_ok:
            for root, dirs, files in os.walk(str(extract_dir)):
                for name in files:
                    p = Path(root) / name
                    # perform static analysis on likely binaries or scripts
                    try:
                        if os.access(p, os.X_OK) or p.suffix in {".sh", ".py", ".pl", ""}:
                            a = static_analysis(str(p)) or {}
                            for k, v in a.items():
                                artifacts.setdefault(k, [])
                                for it in v:
                                    if it not in artifacts[k] and len(artifacts[k]) < 5:
                                        artifacts[k].append(it)
                    except Exception:
                        continue

        result["artifacts"] = artifacts
    except Exception:
        result["artifacts"] = {}

    # Cleanup
    try:
        shutil.rmtree(str(tmpdir))
    except Exception:
        pass

    return result
