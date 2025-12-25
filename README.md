# Provity: Local Security Analyzer

Provity is a Streamlit-based interface for locally assessing Windows executables without relying on external network calls. It orchestrates three on-box checks: signature verification (osslsigncode), malware scanning (ClamAV), and a lightweight static strings pass for common IoCs.

## Features

- Offline-first workflow: all analysis stays on the local host.
- Signature verification via osslsigncode with CA bundle validation.
- Malware scan using the ClamAV CLI (clamscan) and concise result messaging.
- Static strings extraction (strings) with simple heuristics for IPs, URLs, shell usage, and registry keys.
- Temporary files are cleaned after each scan.

## Requirements

- Python 3.9+ with Streamlit installed (`pip install streamlit`).
- System binaries available on PATH:
  - `osslsigncode`
  - `clamscan` (ClamAV)
  - `strings` (from binutils or equivalent)
- CA certificates bundle readable at `/etc/ssl/certs/ca-certificates.crt` for signature validation (adjust the path in `verify_signature` if your system differs).

## Setup

1. Create and activate a virtual environment.
2. Install Python dependencies:
   ```bash
   pip install streamlit
   ```
3. Ensure osslsigncode, ClamAV, and strings are installed and callable from the shell.

## Run

From the project root, launch Streamlit:

```bash
streamlit run app.py
```

The app starts a local web UI. Upload a Windows PE file (`.exe`, `.dll`, `.sys`, `.msi`) to initiate analysis.

## How It Works

1. The uploaded file is written to a temporary location.
2. Signature check: `osslsigncode verify -CAfile /etc/ssl/certs/ca-certificates.crt -in <file>`; reports validity and signer CN if present.
3. Malware scan: `clamscan --no-summary <file>`; returns clean, infected with name, or engine error.
4. Static analysis: `strings -n 6 <file>`; scans extracted text for IPs, URLs, common shell commands, and registry references, keeping up to five hits per category.
5. Temporary file is deleted after processing.

## Notes and Limitations

- The current CA path and CLI binaries assume a Unix-like environment; adjust paths for Windows if needed.
- ClamAV and strings outputs are directly surfaced; large binaries may take time to process.
- Detection heuristics are intentionally simple and should be complemented with deeper analysis for production use.
- No network calls are made by the app itself, but system tools may rely on existing signature trust stores.

## File Reference

- Main app: [app.py](app.py)
