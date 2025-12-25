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
        score += 80
        evidence.append(f"ClamAV: malware detected ({clam_label})")
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
