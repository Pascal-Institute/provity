import subprocess

import provity.scanners as scanners


class _FakeCompleted:
    def __init__(self, stdout: str):
        self.stdout = stdout
        self.stderr = ""


def test_static_analysis_extracts_basic_iocs(monkeypatch):
    stdout = """hello world
http://example.com/path
192.168.0.1
HKLM\\Software\\Microsoft\\Windows\\Run
powershell -enc AAA
"""

    def fake_run(cmd, capture_output, text, errors, timeout):
        return _FakeCompleted(stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    artifacts = scanners.static_analysis("/tmp/file.bin")

    assert "URL" in artifacts and artifacts["URL"]
    assert "IP Address" in artifacts and artifacts["IP Address"]
    assert "Registry Key" in artifacts and artifacts["Registry Key"]
    assert "Suspicious Cmd" in artifacts and artifacts["Suspicious Cmd"]
