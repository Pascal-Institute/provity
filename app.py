import streamlit as st
import tempfile
import os
import hashlib
from datetime import datetime
import re
from io import BytesIO
from pathlib import Path
import base64

from provity.risk import compute_risk_assessment
from provity.scanners import (
    scan_virus_clamav,
    static_analysis,
    verify_signature_detailed,
    scan_deb_package,
)
try:
    from provity.db import ensure_schema, insert_scan_event, fetch_recent_scans, fetch_file_last_seen, fetch_latest_scan_for_hash
    _DB_IMPORT_ERROR = None
except Exception as e:  # pragma: no cover
    ensure_schema = None  # type: ignore[assignment]
    insert_scan_event = None  # type: ignore[assignment]
    fetch_recent_scans = None  # type: ignore[assignment]
    fetch_file_last_seen = None  # type: ignore[assignment]
    fetch_latest_scan_for_hash = None  # type: ignore[assignment]
    _DB_IMPORT_ERROR = str(e)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _guess_app_name(original_filename: str) -> str:
        """Derive a user-friendly app name from an uploaded filename.

        This is intentionally lightweight and offline-first.
        Examples:
            - "GoogleChromeStandaloneEnterprise64.msi" -> "Google Chrome"
            - "notion-setup-3.2.1.exe" -> "Notion"
        """
        name = os.path.basename(original_filename)
        name = re.sub(r"\.[A-Za-z0-9]{1,6}$", "", name)  # strip extension
        name = name.replace("_", " ").replace("-", " ").strip()
        # drop common suffix tokens
        name = re.sub(r"\b(setup|installer|install|x64|x86|amd64|arm64|win64|win32)\b", "", name, flags=re.IGNORECASE)
        name = re.sub(r"\b(v)?\d+(?:\.\d+){0,3}\b", "", name, flags=re.IGNORECASE)  # versions
        name = re.sub(r"\s+", " ", name).strip()

        if not name:
                return "Unknown"

        # Title-case without shouting acronyms too much
        safe = name[:80]
        return safe


def _extract_app_icon(uploaded_file) -> tuple[bytes | None, str | None]:
    """Best-effort icon extraction.

    Currently supported:
      - .ico uploads: stored as-is.

    Best-effort support:
      - Windows binaries (.exe/.dll/.sys) and some installers: try extract the first icon.
    """
    try:
        name = getattr(uploaded_file, "name", "") or ""
        if name.lower().endswith(".ico"):
            raw = uploaded_file.getvalue()
            if raw:
                return raw, "image/x-icon"

        # Try to extract icon from PE/installer formats.
        if name.lower().endswith((".exe", ".dll", ".sys", ".msi")):
            try:
                # icoextract works on PE files; for MSI this may fail (we just fall back).
                # API note (icoextract>=0.2): list_group_icons() + export_icon().
                from icoextract import IconExtractor  # type: ignore

                data = uploaded_file.getvalue()
                if not data:
                    return None, None

                # IconExtractor expects a file path.
                with tempfile.NamedTemporaryFile(delete=False, suffix=Path(name).suffix) as f:
                    f.write(data)
                    tmp = f.name

                try:
                    extractor = IconExtractor(tmp)
                    group_icons = extractor.list_group_icons()
                    if not group_icons:
                        return None, None

                    # group_icons is a list of icon identifiers (group indices).
                    # We take the first group and export it as .ico bytes.
                    ico_bytes = extractor.export_icon(group_icons[0])
                    if ico_bytes:
                        return ico_bytes, "image/x-icon"
                finally:
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass
            except Exception:
                # Extraction is best-effort; ignore and continue.
                if os.getenv("PROVITY_DEBUG_ICON") == "1":
                    try:
                        st.sidebar.caption(f"[icon] extraction failed for {name}")
                    except Exception:
                        pass
                return None, None
    except Exception:
        pass
    return None, None


def _ico_bytes_to_png_bytes(ico_bytes: bytes) -> bytes | None:
    """Convert .ico bytes to PNG bytes (best-effort).

    Streamlit can be picky with some .ico variants; converting to PNG improves reliability.
    If Pillow isn't available or conversion fails, return None.
    """
    if not ico_bytes:
        return None

    try:
        from PIL import Image  # type: ignore

        im = Image.open(BytesIO(ico_bytes))
        # ICO can contain multiple sizes; pick the largest.
        try:
            n = getattr(im, "n_frames", 1)
        except Exception:
            n = 1

        best = None
        best_area = -1
        for i in range(max(1, n)):
            try:
                im.seek(i)
            except Exception:
                break
            w, h = im.size
            if w * h > best_area:
                best_area = w * h
                best = im.copy()

        if best is None:
            best = im

        if best.mode not in ("RGBA", "RGB"):
            best = best.convert("RGBA")

        out = BytesIO()
        best.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return None


def _image_bytes_to_png_bytes(image_bytes: bytes, mime: str | None) -> bytes | None:
    """Convert various image bytes to PNG (best-effort).

    We primarily see ICO; PNG is passed through; other formats try Pillow.
    """
    if not image_bytes:
        return None
    if mime == "image/png":
        return image_bytes
    if mime in ("image/x-icon", "image/vnd.microsoft.icon"):
        return _ico_bytes_to_png_bytes(image_bytes)
    try:
        from PIL import Image  # type: ignore

        im = Image.open(BytesIO(image_bytes))
        if im.mode not in ("RGBA", "RGB"):
            im = im.convert("RGBA")
        out = BytesIO()
        im.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return None


def _encode_icon_for_db(icon_bytes: bytes | None, icon_mime: str | None) -> tuple[str | None, str | None]:
    """Return (b64, mime) to store in DB.

    We store PNG bytes as base64 (most reliable to render in Streamlit).
    """
    if not icon_bytes:
        return None, None

    png_bytes = _image_bytes_to_png_bytes(icon_bytes, icon_mime)
    if png_bytes:
        return base64.b64encode(png_bytes).decode("ascii"), "image/png"

    # Fallback: store original bytes.
    try:
        return base64.b64encode(icon_bytes).decode("ascii"), icon_mime
    except Exception:
        return None, None


def _debug_icon_pipeline(*, label: str, raw_bytes: bytes | None, raw_mime: str | None, b64: str | None, b64_mime: str | None) -> None:
    """Emit small, non-sensitive diagnostics for icon extraction.

    Enabled only when PROVITY_DEBUG_ICON=1.
    """
    if os.getenv("PROVITY_DEBUG_ICON") != "1":
        return
    try:
        raw_len = len(raw_bytes) if raw_bytes else 0
        b64_len = len(b64) if b64 else 0
        st.sidebar.caption(
            f"[icon] {label}: raw_len={raw_len} raw_mime={raw_mime or 'n/a'} → b64_len={b64_len} b64_mime={b64_mime or 'n/a'}"
        )
    except Exception:
        pass


def _decode_icon_from_db(*, icon_b64: str | None, icon_b64_mime: str | None) -> tuple[bytes | None, str | None]:
    """Decode icon from base64 DB fields (base64-only)."""
    if not icon_b64:
        return None, None
    try:
        return base64.b64decode(icon_b64), (icon_b64_mime or "image/png")
    except Exception:
        return None, None

# Page Configuration
# NOTE: `page_icon` sets the browser tab favicon in Streamlit.
st.set_page_config(page_title="Provity : Trustured Software Validator", page_icon="🛡️", layout="wide")

st.title("🛡️ Provity : Trustured Software Validator")
st.markdown("""
**Without external network connections**, this tool performs security checks using local server resources.
1. **Signature Verification**: `osslsigncode` (Authenticode)
2. **Virus Scan**: `ClamAV` (Local Antivirus Engine)
3. **Static Analysis**: `strings` (Suspicious IOC Extraction)
""")

# DB + Dashboard controls
with st.sidebar:
    st.header("Dashboard")
    db_enabled = st.toggle("Enable scan history (PostgreSQL)", value=True)
    st.caption(
        "Connects to local Docker Postgres by default. "
        "For safer dashboard access, set DATABASE_URL_READONLY (recommended) or DATABASE_URL."
    )

    # Read-only mode is enforced by design.
    # Dashboard queries always use DATABASE_URL_READONLY (or fallback) and we never expose schema init in the UI.
    db_readonly = True
    st.caption("Read-only dashboard mode: enforced")

    # Separate toggle: allow logging even when the dashboard itself is read-only.
    # This keeps the UI safe-by-default while still enabling scan history capture.
    db_log_scans = st.toggle(
        "Log scan events to DB",
        value=True,
        help="Uses DATABASE_URL (read-write). Disable if you want a view-only dashboard.",
    )

    if db_enabled:
        if _DB_IMPORT_ERROR:
            st.error(f"DB features unavailable: {_DB_IMPORT_ERROR}")
            st.caption("Install dependencies into your current Python: python3 -m pip install --user -r requirements.txt")
            db_enabled = False

        # We intentionally do not expose schema init/migrations from the UI.
        # Provision schema out-of-band (see README).

    st.divider()
    st.caption("Anonymous mode: when logging is enabled, scans are stored as user_id='anonymous'.")


tab_scan, tab_dashboard = st.tabs(["Scan", "Dashboard"])


with tab_scan:
    # File Upload
    uploaded_file = st.file_uploader(
        "Upload file to scan (.exe, .dll, .sys, .msi, .deb, .ico)",
        type=["exe", "dll", "sys", "msi", "deb", "ico"],
    )

    if uploaded_file is None:
        st.info("Select a file to start scanning.")
    else:
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_path = tmp_file.name

        # Compute hash early for duplicate checks and logging.
        file_hash = _sha256_file(tmp_path)

        # Best-effort app icon extraction (currently: if uploaded file is .ico)
        icon_bytes, icon_mime = _extract_app_icon(uploaded_file)

        # Prefer storing icons as base64 PNG for reliability.
        icon_b64, icon_b64_mime = _encode_icon_for_db(icon_bytes, icon_mime)

        _debug_icon_pipeline(
            label=f"upload:{uploaded_file.name}",
            raw_bytes=icon_bytes,
            raw_mime=icon_mime,
            b64=icon_b64,
            b64_mime=icon_b64_mime,
        )

        # Duplicate check (best-effort): if we've seen this hash before, show last scan time + score.
        if db_enabled and fetch_latest_scan_for_hash is not None:
            try:
                prev = fetch_latest_scan_for_hash(file_hash)
            except Exception:
                prev = None

            if prev is not None:
                st.info("We've seen this file before.")

                # Show stored app icon (if any)
                prev_icon_bytes, prev_icon_mime = _decode_icon_from_db(
                    icon_b64=prev.get("app_icon_b64"),
                    icon_b64_mime=prev.get("app_icon_b64_mime"),
                )
                if prev_icon_bytes:
                    try:
                        png_bytes = _image_bytes_to_png_bytes(prev_icon_bytes, prev_icon_mime)
                        st.image(png_bytes or prev_icon_bytes, width=48)
                    except Exception:
                        pass

                c1, c2, c3, c4, c5 = st.columns([1.2, 1.0, 1.2, 1.8, 1.8])
                with c1:
                    st.metric("Last scanned", str(prev.get("scanned_at") or "N/A"))
                with c2:
                    st.metric("Issuer", str(prev.get("signature_issuer") or "N/A"))
                with c3:
                    st.metric("Signer", str(prev.get("signature_signer") or "N/A"))
                with c4:
                    st.metric("Last risk level", str(prev.get("risk_level") or "N/A"))
                with c5:
                    st.metric("Last risk score", f"{prev.get('score')}/100" if prev.get("score") is not None else "N/A")

                st.caption(
                    f"App name: {prev.get('app_name') or 'Unknown'} · "
                    f"Last uploaded as: {prev.get('original_filename') or 'Unknown'}"
                )

        # If a .deb was uploaded, pre-run the specialized deb scanner so the UI can
        # display signature, ClamAV and static-analysis results consistently.
        is_deb = uploaded_file.name.lower().endswith(".deb")
        deb_scan = None
        if is_deb:
            with st.spinner("Analyzing .deb package..."):
                try:
                    deb_scan = scan_deb_package(tmp_path)
                except Exception as e:
                    deb_scan = {
                        "sig_detail": {"backend": "dpkg-sig", "valid": False, "raw_log": str(e)},
                        "clam_result": (None, "scan error", ""),
                        "artifacts": {},
                    }

        col1, col2 = st.columns(2)

        # 1. Signature Verification
        with col1:
            st.subheader("1️⃣ Signature Verification")
            enable_revocation = st.checkbox(
                "Enable online revocation check (OCSP/CRL)",
                value=False,
                help="May require network access. Support depends on the verification backend.",
            )
            # If this is a .deb package we use the special handler,
            # otherwise fall back to the existing Authenticode verifier.
            if is_deb:
                sig_detail = (deb_scan or {}).get(
                    "sig_detail",
                    {"backend": "dpkg-sig", "valid": False, "raw_log": "Not checked"},
                )
                sig_valid = bool(sig_detail.get("valid"))
                sig_msg = str(sig_detail.get("raw_log") or "")
                sig_info = {"signer": sig_detail.get("signer") or sig_detail.get("signer_cn") or "Unknown"}
            else:
                with st.spinner("Checking Signature..."):
                    sig_detail = verify_signature_detailed(tmp_path, enable_revocation=enable_revocation)
                    sig_valid = bool(sig_detail.get("valid"))
                    sig_msg = str(sig_detail.get("raw_log") or "")
                    sig_info = {"signer": sig_detail.get("signer_cn") or "Unknown"}
        
            if sig_valid:
                st.success("✅ Valid Signature")
                st.info(f"**Signer:** {sig_info.get('signer')}")
                st.info(f"**Issuer:** {sig_detail.get('issuer') or 'N/A'}")
            else:
                st.error("❌ Invalid / Unsigned")
                st.warning("Digital signature is missing or invalid.")
                st.info(f"**Signer:** {sig_info.get('signer') or 'Unknown'}")
                st.info(f"**Issuer:** {sig_detail.get('issuer') or 'N/A'}")

            with st.expander("Structured Details"):
                st.write(f"**Backend:** {sig_detail.get('backend', 'unknown')}")
                st.write(f"**Subject:** {sig_detail.get('subject') or 'N/A'}")
                st.write(f"**Issuer:** {sig_detail.get('issuer') or 'N/A'}")
                st.write(
                    f"**Validity:** {sig_detail.get('not_before') or 'N/A'} → {sig_detail.get('not_after') or 'N/A'}"
                )
                ts_present = sig_detail.get("timestamp_present")
                st.write(
                    f"**Timestamp Present:** {'Yes' if ts_present else 'No' if ts_present is not None else 'Unknown'}"
                )

                if enable_revocation:
                    rev_checked = bool(sig_detail.get("revocation_checked"))
                    rev_ok = sig_detail.get("revocation_ok")
                    st.write(
                        f"**Revocation Check:** {'Supported' if rev_checked else 'Not supported/Not performed'}"
                    )
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
            if is_deb and deb_scan is not None:
                is_clean, virus_name, scan_log = deb_scan.get("clam_result", (None, "ClamAV not run", ""))
            else:
                with st.spinner("Scanning Malware (ClamAV)..."):
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
        with st.spinner("Extracting Strings..."):
            if is_deb and deb_scan is not None:
                artifacts = deb_scan.get("artifacts", {})
            else:
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

        # Persist scan event (best-effort)
        if db_enabled and db_log_scans:
            try:
                # Schema must already exist (provision out-of-band). We keep this call
                # to avoid silent failures if the schema has not been created yet.
                ensure_schema()
                insert_scan_event(
                    user_id="anonymous",
                    original_filename=uploaded_file.name,
                    file_sha256=file_hash,
                    valid_signature=bool(sig_valid),
                    app_icon_b64=icon_b64,
                    app_icon_b64_mime=icon_b64_mime,
                    score=risk_score,
                    risk_level=risk_level,
                    metadata={
                        "app_name": _guess_app_name(uploaded_file.name),
                        "is_deb": bool(is_deb),
                        "signature_backend": sig_detail.get("backend"),
                        "signature_valid": bool(sig_valid),
                        "signature_signer": sig_info.get("signer") if isinstance(sig_info, dict) else None,
                        "signature_issuer": sig_detail.get("issuer"),
                        "clam_state": is_clean,
                        "clam_label": virus_name,
                    },
                )
                st.sidebar.success("Logged to DB")
            except Exception as e:
                st.sidebar.warning(f"DB logging failed: {e}")

        # Cleanup
        os.remove(tmp_path)


with tab_dashboard:
    st.subheader("Recent scan activity")

    if not db_enabled:
        st.info("Enable scan history in the sidebar to view the dashboard.")
    else:
        try:
            # In read-only mode we don't attempt DDL. If schema is missing, SELECTs will fail
            # and we'll show a clear error below.
            if not db_readonly:
                ensure_schema()
            col_a, col_b = st.columns(2)
            with col_a:
                recent_limit = st.number_input("Recent scans", min_value=5, max_value=500, value=50, step=5)
            with col_b:
                file_limit = st.number_input("File summary rows", min_value=5, max_value=500, value=50, step=5)

            recent = fetch_recent_scans(limit=int(recent_limit))
            file_summary = fetch_file_last_seen(limit_files=int(file_limit))

            # Friendlier boolean display
            if recent:
                for r in recent:
                    if "valid_signature" in r:
                        r["Signature"] = "✅" if r.get("valid_signature") else "❌"

            # Top metrics
            if recent:
                last_scan_time = recent[0]["scanned_at"]
                st.caption(f"Last scan: {last_scan_time}")

            st.markdown("### Files scanned recently")
            st.dataframe(file_summary, use_container_width=True)

            st.markdown("### Recent scans")
            if not recent:
                st.info("No scan events yet.")
            else:
                # Custom row rendering so icons can be shown per-row.
                header = st.columns([2.6, 1.0, 0.9, 1.1, 1.0, 1.8, 2.0])
                header[0].markdown("**App**")
                header[1].markdown("**Signature**")
                header[2].markdown("**Risk**")
                header[3].markdown("**Score**")
                header[4].markdown("**User**")
                header[5].markdown("**Scanned at**")
                header[6].markdown("**File**")
                st.divider()

                for r in recent:
                    cols = st.columns([2.6, 1.0, 0.9, 1.1, 1.0, 1.8, 2.0])

                    # App column: icon + name
                    with cols[0]:
                        left, right = st.columns([0.22, 0.78])
                        with left:
                            icon_bytes_row, icon_mime_row = _decode_icon_from_db(
                                icon_b64=r.get("app_icon_b64"),
                                icon_b64_mime=r.get("app_icon_b64_mime"),
                            )
                            if icon_bytes_row:
                                png_bytes = _image_bytes_to_png_bytes(icon_bytes_row, icon_mime_row)
                                try:
                                    st.image(png_bytes or icon_bytes_row, width=22)
                                except Exception:
                                    st.write(" ")
                            else:
                                st.write(" ")
                        with right:
                            st.write(r.get("app_name") or "Unknown")

                    cols[1].write(r.get("Signature") or "")
                    cols[2].write(str(r.get("risk_level") or ""))
                    cols[3].write("N/A" if r.get("score") is None else f"{r.get('score')}/100")
                    cols[4].write(str(r.get("user_id") or ""))
                    cols[5].write(str(r.get("scanned_at") or ""))
                    cols[6].write(str(r.get("original_filename") or ""))

        except Exception as e:
            st.error(f"Dashboard unavailable: {e}")