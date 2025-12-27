import subprocess

import provity.scanners as scanners


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_scan_threats_clamav_fallback_on_unknown_option(monkeypatch):
    calls = []

    def fake_run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        # First attempt (extended) fails with unknown option
        if len(calls) == 1:
            return _FakeCompleted(2, stdout="", stderr="Unknown option --alert-macros")
        # Second attempt (base) clean
        return _FakeCompleted(0, stdout=f"{cmd[-1]}: OK\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    detail = scanners.scan_threats_clamav("/tmp/sample.bin", enable_extended=True, recursive=False)
    assert detail["state"] is True
    assert detail["extended_requested"] is True
    assert detail["extended_effective"] is False
    assert "fell back" in (detail.get("fallback_reason") or "").lower()
    assert detail["flags"] == ["--no-summary"]


def test_scan_threats_clamav_parses_findings(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        stdout = "/tmp/eicar.com: Eicar-Test-Signature FOUND\n"
        return _FakeCompleted(1, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    detail = scanners.scan_threats_clamav("/tmp/eicar.com", enable_extended=False, recursive=False)

    assert detail["state"] is False
    assert detail["findings"]
    assert detail["findings"][0]["signature"] == "Eicar-Test-Signature"
    assert detail["findings"][0]["category"] in {"Malware", "Threat"}
    assert ":" in detail["label"]


def test_scan_threats_clamav_timeout(monkeypatch):
    def fake_run(cmd, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    detail = scanners.scan_threats_clamav("/tmp/slow.bin", enable_extended=True, recursive=False, timeout_sec=1)
    assert detail["state"] is None
    assert detail["label"] == "Scan Timeout"
