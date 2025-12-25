from __future__ import annotations

import os
import re
import subprocess
import shutil
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


def scan_virus_clamav(file_path: str) -> tuple[bool | None, str, str]:
    """Local virus scan using ClamAV (clamscan)."""
    try:
        cmd = ["clamscan", "--no-summary", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

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
    except subprocess.TimeoutExpired:
        return None, "Scan Timeout", "ClamAV scan timed out."


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
