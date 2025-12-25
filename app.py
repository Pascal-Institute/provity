import streamlit as st
import subprocess
import tempfile
import os
import re

# Page Configuration
st.set_page_config(page_title="Provity : Trustured Software Validator", layout="wide")

st.title("🛡️ Provity : Trustured Software Validator")
st.markdown("""
**Without external network connections**, this tool performs security checks using local server resources.
1. **Signature Verification**: `osslsigncode` (Authenticode)
2. **Virus Scan**: `ClamAV` (Local Antivirus Engine)
3. **Static Analysis**: `strings` (Suspicious IOC Extraction)
""")

# File Upload
uploaded_file = st.file_uploader("Upload file to scan (.exe, .dll, .sys, .msi)", type=["exe", "dll", "sys", "msi"])

def compute_risk_assessment(sig_valid, sig_info, clam_clean_state, clam_label, artifacts):
    """Compute a simple risk score/level and evidence list from scan outputs."""
    score = 0
    evidence = []

    # Signature
    if sig_valid:
        signer = (sig_info or {}).get("signer") or "Unknown"
        evidence.append(f"Signature: valid (Signer: {signer})")
        if signer.strip().lower() == "unknown":
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
    artifact_weights = {
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

def verify_signature(file_path):
    """Signature verification using osslsigncode"""
    ca_path = "/etc/ssl/certs/ca-certificates.crt"
    if not os.path.exists(ca_path):
        return False, "CA certificate not found.", {}

    try:
        cmd = ["osslsigncode", "verify", "-CAfile", ca_path, "-in", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr
        
        info = {"signer": "Unknown"}
        is_valid = "Signature verification: ok" in output

        subject_match = re.search(r"Subject:.*?CN=([^,\n]+)", output)
        if subject_match:
            info["signer"] = subject_match.group(1).strip()
        
        return is_valid, output, info
    except FileNotFoundError:
        return False, "osslsigncode is not installed.", {}

def scan_virus_clamav(file_path):
    """Local virus scan using ClamAV (clamscan)"""
    try:
        # --no-summary: Output results only, excluding summary
        # -i: Output only infected files (No output if clean)
        cmd = ["clamscan", "--no-summary", file_path]
        
        # clamscan return codes:
        # 0: No virus found
        # 1: Virus found
        # 2: Error
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, "Clean", result.stdout
        elif result.returncode == 1:
            # Output example: /tmp/tmpxxx: Win.Trojan.Agent-1234 FOUND
            virus_name = "Unknown Malware"
            if "FOUND" in result.stdout:
                parts = result.stdout.split("FOUND")
                if len(parts) > 0:
                    # Attempt to extract only virus name by removing file path
                    raw_name = parts[0].split(":")[-1].strip()
                    virus_name = raw_name
            return False, virus_name, result.stdout
        else:
            return None, "Engine Error", result.stderr

    except FileNotFoundError:
        return None, "ClamAV (clamscan) is not installed.", ""

def static_analysis(file_path):
    """Static analysis using Linux strings command (IOC Extraction)"""
    suspicious_patterns = {
        "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "URL": r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        "Suspicious Cmd": r"(cmd\.exe|powershell|wget|curl|/bin/sh)",
        "Registry Key": r"HKLM\\|HKCU\\|Software\\Microsoft\\Windows"
    }
    
    found_artifacts = {k: [] for k in suspicious_patterns.keys()}
    
    try:
        # -n 6: Extract strings with at least 6 characters (Noise reduction)
        cmd = ["strings", "-n", "6", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
        
        lines = result.stdout.splitlines()
        
        # Simple pattern matching (Limited check to avoid performance issues on large files)
        for line in lines:
            if len(line) > 200: continue # Skip overly long lines
            
            for category, pattern in suspicious_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    # Add after deduplication (Save max 5 items)
                    if line.strip() not in found_artifacts[category] and len(found_artifacts[category]) < 5:
                        found_artifacts[category].append(line.strip())
                        
        return found_artifacts
    except Exception:
        return {}

if uploaded_file is not None:
    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name

    col1, col2 = st.columns(2)

    # 1. Signature Verification
    with col1:
        st.subheader("1️⃣ Signature Verification")
        with st.spinner('Checking Signature...'):
            sig_valid, sig_msg, sig_info = verify_signature(tmp_path)
        
        if sig_valid:
            st.success("✅ Valid Signature")
            st.info(f"**Signer:** {sig_info.get('signer')}")
        else:
            st.error("❌ Invalid / Unsigned")
            st.warning("Digital signature is missing or invalid.")
        
        with st.expander("Log Details"):
            st.code(sig_msg)

    # 2. Virus Scan & Static Analysis
    with col2:
        st.subheader("2️⃣ Security Threat Detection (Local)")
        
        # ClamAV Scan
        with st.spinner('Scanning Malware (ClamAV)...'):
            is_clean, virus_name, scan_log = scan_virus_clamav(tmp_path)
        
        if is_clean is True:
            st.success("✅ Clean (No Malware Detected)")
            st.caption("Safe according to ClamAV engine scan results.")
        elif is_clean is False:
            st.error(f"🚫 Malware Detected: {virus_name}")
            st.caption("ClamAV engine detected malicious code.")
        else:
            st.warning("⚠️ Scanner Error")
            st.write(scan_log)

        st.markdown("---")
        
        # Static Analysis
        st.subheader("3️⃣ Static Analysis (IoC Extraction)")
        with st.spinner('Extracting Strings...'):
            artifacts = static_analysis(tmp_path)
        
        has_artifacts = any(v for v in artifacts.values())
        
        if has_artifacts:
            for category, items in artifacts.items():
                if items:
                    st.write(f"**🚩 {category} Found:**")
                    for item in items:
                        st.code(item, language="text")
        else:
            st.info("No suspicious strings or URLs found.")

    st.markdown("---")
    st.subheader("Risk Summary")
    risk_score, risk_level, risk_evidence = compute_risk_assessment(
        sig_valid=sig_valid,
        sig_info=sig_info,
        clam_clean_state=is_clean,
        clam_label=virus_name,
        artifacts=artifacts,
    )

    if risk_level == "Low":
        st.success(f"Overall Risk: {risk_level}")
    elif risk_level == "Medium":
        st.warning(f"Overall Risk: {risk_level}")
    else:
        st.error(f"Overall Risk: {risk_level}")

    st.metric("Risk Score", f"{risk_score}/100")
    st.markdown("\n".join([f"- {item}" for item in risk_evidence]))

    # Cleanup
    os.remove(tmp_path)