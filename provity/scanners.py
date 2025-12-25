from __future__ import annotations

import os
import re
import subprocess
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
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = (result.stdout or "") + (result.stderr or "")

        info: dict[str, Any] = {"signer": "Unknown"}
        is_valid = "Signature verification: ok" in output

        subject_match = re.search(r"Subject:.*?CN=([^,\n]+)", output)
        if subject_match:
            info["signer"] = subject_match.group(1).strip()

        return is_valid, output, info
    except FileNotFoundError:
        return False, "osslsigncode is not installed.", {}


def scan_virus_clamav(file_path: str) -> tuple[bool | None, str, str]:
    """Local virus scan using ClamAV (clamscan)."""
    try:
        cmd = ["clamscan", "--no-summary", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return True, "Clean", result.stdout
        if result.returncode == 1:
            virus_name = "Unknown Malware"
            if "FOUND" in (result.stdout or ""):
                parts = result.stdout.split("FOUND")
                if len(parts) > 0:
                    raw_name = parts[0].split(":")[-1].strip()
                    virus_name = raw_name
            return False, virus_name, result.stdout

        return None, "Engine Error", result.stderr

    except FileNotFoundError:
        return None, "ClamAV (clamscan) is not installed.", ""


def static_analysis(file_path: str) -> dict[str, list[str]]:
    """Static analysis using Linux strings command (IOC Extraction)."""
    found_artifacts: dict[str, list[str]] = {k: [] for k in SUSPICIOUS_PATTERNS.keys()}

    try:
        cmd = ["strings", "-n", "6", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")

        for line in (result.stdout or "").splitlines():
            if len(line) > 200:
                continue

            for category, pattern in SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    item = line.strip()
                    if item not in found_artifacts[category] and len(found_artifacts[category]) < 5:
                        found_artifacts[category].append(item)

        return found_artifacts
    except Exception:
        return {}
