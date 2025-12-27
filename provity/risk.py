from __future__ import annotations

from typing import Any


def compute_risk_assessment(
    sig_valid: bool,
    sig_info: dict[str, Any] | None,
    clam_clean_state: bool | None,
    clam_label: str,
    artifacts: dict[str, list[str]] | None,
) -> tuple[int, str, list[str]]:
    """Compute a simple risk score/level and evidence list from scan outputs."""
    score = 0
    evidence: list[str] = []

    # Signature
    if sig_valid:
        signer = (sig_info or {}).get("signer") or "Unknown"
        evidence.append(f"Signature: valid (Signer: {signer})")
        if str(signer).strip().lower() == "unknown":
            score += 5
    else:
        score += 25
        evidence.append("Signature: missing or invalid")

    # ClamAV
    if clam_clean_state is True:
        evidence.append("ClamAV: clean")
    elif clam_clean_state is False:
        category, weight = _clamav_category_and_weight(clam_label)
        score += weight
        if category == "Malware":
            evidence.append(f"ClamAV: malware detected ({clam_label})")
        else:
            evidence.append(f"ClamAV: {category} detected ({clam_label})")
    else:
        score += 25
        evidence.append(f"ClamAV: scanner error ({clam_label})")

    # Static IoCs
    artifact_weights: dict[str, int] = {
        "Suspicious Cmd": 20,
        "URL": 15,
        "IP Address": 10,
        "Registry Key": 10,
    }

    artifacts = artifacts or {}
    any_artifacts = False
    for category, items in artifacts.items():
        if not items:
            continue
        any_artifacts = True
        score += artifact_weights.get(category, 5)
        evidence.append(f"Static IoC: {category} found ({len(items)})")

    if not any_artifacts:
        evidence.append("Static IoC: none found")

    score = max(0, min(100, score))
    if score >= 70:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return score, level, evidence


def _clamav_category_and_weight(clam_label: str) -> tuple[str, int]:
    """Infer a threat category from the clamscan label.

    We keep this best-effort and backward-compatible: if the label doesn't
    look categorized, default to Malware.
    """
    label = (clam_label or "").strip()
    lower = label.lower()

    # If the scanners prefix the label as "Category: ...", prefer that.
    if ":" in label:
        prefix = label.split(":", 1)[0].strip().lower()
        if prefix in {"pua", "phishing", "macro", "encrypted", "heuristic", "malware", "threat"}:
            if prefix == "threat":
                return "Malware", 80
            if prefix == "pua":
                return "PUA", 45
            if prefix == "phishing":
                return "Phishing", 70
            if prefix == "macro":
                return "Macro", 55
            if prefix == "encrypted":
                return "Encrypted", 30
            if prefix == "heuristic":
                return "Heuristic", 40
            if prefix == "malware":
                return "Malware", 80

    # Heuristic inference for legacy labels
    if "pua" in lower:
        return "PUA", 45
    if "phish" in lower:
        return "Phishing", 70
    if "macro" in lower:
        return "Macro", 55
    if "encrypt" in lower:
        return "Encrypted", 30
    if "heuristic" in lower or lower.startswith("heuristics.") or "broken" in lower or "exceed" in lower:
        return "Heuristic", 40

    return "Malware", 80
