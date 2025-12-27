from provity.risk import compute_risk_assessment, _clamav_category_and_weight


def test_clamav_category_and_weight_prefixes():
    assert _clamav_category_and_weight("PUA: Something")[0] == "PUA"
    assert _clamav_category_and_weight("Phishing: Something")[0] == "Phishing"
    assert _clamav_category_and_weight("Macro: Something")[0] == "Macro"
    assert _clamav_category_and_weight("Encrypted: Something")[0] == "Encrypted"
    assert _clamav_category_and_weight("Heuristic: Something")[0] == "Heuristic"
    assert _clamav_category_and_weight("Malware: Something")[0] == "Malware"


def test_compute_risk_low_clean_signed_no_ioc():
    score, level, evidence = compute_risk_assessment(
        sig_valid=True,
        sig_info={"signer": "Microsoft"},
        clam_clean_state=True,
        clam_label="Clean",
        artifacts={},
    )
    assert level == "Low"
    assert score < 30
    assert any("Signature: valid" in e for e in evidence)
    assert any("ClamAV: clean" in e for e in evidence)


def test_compute_risk_high_unsigned_malware_iocs():
    score, level, evidence = compute_risk_assessment(
        sig_valid=False,
        sig_info=None,
        clam_clean_state=False,
        clam_label="Malware: Eicar-Test-Signature",
        artifacts={"URL": ["http://example.com"], "Suspicious Cmd": ["powershell -enc ..."]},
    )
    assert level == "High"
    assert score >= 70
    assert any("Signature: missing" in e for e in evidence)
    assert any("malware detected" in e.lower() for e in evidence)


def test_compute_risk_medium_pua_detection():
    score, level, evidence = compute_risk_assessment(
        sig_valid=True,
        sig_info={"signer": "Unknown"},
        clam_clean_state=False,
        clam_label="PUA: PUA.Win.Tool",
        artifacts={},
    )
    assert level in {"Medium", "High"}
    assert any("PUA" in e for e in evidence)
