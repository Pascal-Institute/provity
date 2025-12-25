import streamlit as st
import tempfile
import os

from provity.risk import compute_risk_assessment
from provity.scanners import scan_virus_clamav, static_analysis, verify_signature_detailed

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

if uploaded_file is not None:
    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name

    col1, col2 = st.columns(2)

    # 1. Signature Verification
    with col1:
        st.subheader("1️⃣ Signature Verification")
        enable_revocation = st.checkbox(
            "Enable online revocation check (OCSP/CRL)",
            value=False,
            help="May require network access. Support depends on the verification backend.",
        )
        with st.spinner('Checking Signature...'):
            sig_detail = verify_signature_detailed(tmp_path, enable_revocation=enable_revocation)
            sig_valid = bool(sig_detail.get("valid"))
            sig_msg = str(sig_detail.get("raw_log") or "")
            sig_info = {"signer": sig_detail.get("signer_cn") or "Unknown"}
        
        if sig_valid:
            st.success("✅ Valid Signature")
            st.info(f"**Signer:** {sig_info.get('signer')}")
        else:
            st.error("❌ Invalid / Unsigned")
            st.warning("Digital signature is missing or invalid.")

        with st.expander("Structured Details"):
            st.write(f"**Backend:** {sig_detail.get('backend', 'unknown')}")
            st.write(f"**Subject:** {sig_detail.get('subject') or 'N/A'}")
            st.write(f"**Issuer:** {sig_detail.get('issuer') or 'N/A'}")
            st.write(f"**Validity:** {sig_detail.get('not_before') or 'N/A'} → {sig_detail.get('not_after') or 'N/A'}")
            ts_present = sig_detail.get("timestamp_present")
            st.write(f"**Timestamp Present:** {'Yes' if ts_present else 'No' if ts_present is not None else 'Unknown'}")

            if enable_revocation:
                rev_checked = bool(sig_detail.get("revocation_checked"))
                rev_ok = sig_detail.get("revocation_ok")
                st.write(f"**Revocation Check:** {'Supported' if rev_checked else 'Not supported/Not performed'}")
                if rev_ok is True:
                    st.write("**Revocation Status:** OK")
                elif rev_ok is False:
                    st.write("**Revocation Status:** Failed")
                else:
                    st.write("**Revocation Status:** Unknown")
                if sig_detail.get("revocation_note"):
                    st.caption(str(sig_detail.get("revocation_note")))

            if sig_detail.get("failure_reason") and not sig_valid:
                st.write(f"**Failure Reason:** {sig_detail.get('failure_reason')}")
        
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