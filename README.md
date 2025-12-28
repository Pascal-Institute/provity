[![DeepWiki](https://img.shields.io/badge/DeepWiki-Pascal--Institute%2Fprovity-blue.svg?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAyCAYAAAAnWDnqAAAAAXNSR0IArs4c6QAAA05JREFUaEPtmUtyEzEQhtWTQyQLHNak2AB7ZnyXZMEjXMGeK/AIi+QuHrMnbChYY7MIh8g01fJoopFb0uhhEqqcbWTp06/uv1saEDv4O3n3dV60RfP947Mm9/SQc0ICFQgzfc4CYZoTPAswgSJCCUJUnAAoRHOAUOcATwbmVLWdGoH//PB8mnKqScAhsD0kYP3j/Yt5LPQe2KvcXmGvRHcDnpxfL2zOYJ1mFwrryWTz0advv1Ut4CJgf5uhDuDj5eUcAUoahrdY/56ebRWeraTjMt/00Sh3UDtjgHtQNHwcRGOC98BJEAEymycmYcWwOprTgcB6VZ5JK5TAJ+fXGLBm3FDAmn6oPPjR4rKCAoJCal2eAiQp2x0vxTPB3ALO2CRkwmDy5WohzBDwSEFKRwPbknEggCPB/imwrycgxX2NzoMCHhPkDwqYMr9tRcP5qNrMZHkVnOjRMWwLCcr8ohBVb1OMjxLwGCvjTikrsBOiA6fNyCrm8V1rP93iVPpwaE+gO0SsWmPiXB+jikdf6SizrT5qKasx5j8ABbHpFTx+vFXp9EnYQmLx02h1QTTrl6eDqxLnGjporxl3NL3agEvXdT0WmEost648sQOYAeJS9Q7bfUVoMGnjo4AZdUMQku50McDcMWcBPvr0SzbTAFDfvJqwLzgxwATnCgnp4wDl6Aa+Ax283gghmj+vj7feE2KBBRMW3FzOpLOADl0Isb5587h/U4gGvkt5v60Z1VLG8BhYjbzRwyQZemwAd6cCR5/XFWLYZRIMpX39AR0tjaGGiGzLVyhse5C9RKC6ai42ppWPKiBagOvaYk8lO7DajerabOZP46Lby5wKjw1HCRx7p9sVMOWGzb/vA1hwiWc6jm3MvQDTogQkiqIhJV0nBQBTU+3okKCFDy9WwferkHjtxib7t3xIUQtHxnIwtx4mpg26/HfwVNVDb4oI9RHmx5WGelRVlrtiw43zboCLaxv46AZeB3IlTkwouebTr1y2NjSpHz68WNFjHvupy3q8TFn3Hos2IAk4Ju5dCo8B3wP7VPr/FGaKiG+T+v+TQqIrOqMTL1VdWV1DdmcbO8KXBz6esmYWYKPwDL5b5FA1a0hwapHiom0r/cKaoqr+27/XcrS5UwSMbQAAAABJRU5ErkJggg==)](https://deepwiki.com/Pascal-Institute/provity)

# Provity: Trusted Software Validator

Provity is a Streamlit-based interface for locally assessing Windows executables without relying on external network calls. It orchestrates three on-box checks—signature verification (osslsigncode), malware scanning (ClamAV), and a lightweight static strings pass for common IoCs—and then summarizes the results into an overall risk level.

## Features

- Offline-first workflow: all analysis stays on the local host.
- Signature verification via osslsigncode with CA bundle validation.
- Threat scan using the ClamAV CLI (clamscan) and concise result messaging.
- ClamAV extended checks (best-effort): may detect PUA/phishing/macro/encrypted/broken-file alerts depending on the local clamscan build.
- Static strings extraction (strings) with simple heuristics for IPs, URLs, shell usage, and registry keys.
- Risk Summary: overall risk level (Low/Medium/High), score (0–100), and evidence list.
- Temporary files are cleaned after each scan.
- Optional scan history dashboard backed by PostgreSQL (anonymous logging).
- Signed attestation export: generates a verifiable JSON “scan certificate” and verifies it inside Provity.

## Attestation (Signed Scan Result)

Provity can export a signed **attestation** (`attestation_*.json`) after each scan.
An attestation is a JSON bundle of the scan results plus a digital signature. This provides:

- Integrity: if anyone edits the result JSON, signature verification fails.
- Authenticity: you can verify the result was produced by the Provity instance holding the signing key.

### Key storage (local, offline)

On first use, Provity generates an Ed25519 keypair and stores it locally:

- Default directory: `~/.provity/attestation/`
  - `ed25519_private_key.pem`
  - `ed25519_public_key.pem`

You can override the location with:

```bash
export PROVITY_ATTESTATION_DIR=/path/to/attestation
```

### Verify inside Provity (Pattern A)

Use the **Verify** tab:

1. Upload the exported `attestation_*.json`
2. Upload the original file that was scanned
3. (Optional) Upload the issuer public key (PEM)
   - If not provided, Provity uses the **local trusted issuer** (same Provity instance)
   - For external verification (different PC/organization), provide the PEM explicitly
4. Provity verifies:
   - The signature over the attestation payload (using the pinned issuer public key or local key)
   - The file SHA-256 matches the payload

**Trusted Issuer Resolution:**

- Explicit PEM upload (highest priority) - use for cross-organization verification
- Local keypair (same Provity instance) - convenient for internal verification
- Embedded keys in attestation are **never** trusted for security

## Requirements

- Python 3.9+ with Streamlit installed (`pip install streamlit`).
- Python packages in `requirements.txt` (includes `Pillow` and `pefile` for icon handling on Windows PE files).
- System binaries available on PATH:
  - `osslsigncode`
  - `clamscan` (ClamAV)
  - `strings` (from binutils or equivalent)
- Optional (for .deb signature checks): `dpkg-deb` and `dpkg-sig`.
- CA certificates bundle readable at `/etc/ssl/certs/ca-certificates.crt` for signature validation (adjust the path in `verify_signature` if your system differs).

### Optional: PostgreSQL (scan history)

Provity can store scan results (risk score/level and basic metadata) in PostgreSQL and show them in a dashboard inside the Streamlit UI.

- Storage is anonymous by default: all scan events are stored with `user_id='anonymous'`.
- Database files are kept locally under `./pgdata` when using Docker (and ignored by git).

## Setup

### Option A (recommended): install into a system-wide Python environment

If you prefer not to use a virtual environment, install the Python dependencies into your system Python.

On Debian/Ubuntu this typically means:

```bash
python3 -m pip install --user -r requirements.txt
```

Then you can run Streamlit via:

```bash
python3 -m streamlit run app.py
```

### Option B: use a virtual environment (optional)

If you _do_ want isolation:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

On Windows PowerShell (example):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### System tools

Ensure osslsigncode, ClamAV, and strings are installed and callable from the shell.

### Start PostgreSQL with Docker (recommended)

From the project root:

```bash
docker compose up -d
docker compose ps
```

Then set the connection string (example):

````bash
export DATABASE_URL='postgresql://provity:provity@localhost:5432/provity'

#### Recommended: Read-only dashboard access

Provity's **Dashboard** can run in a safer read-only mode. In this mode:

- The UI shows history by running **SELECT** queries only.
- DB initialization and scan logging are disabled.
- The app prefers `DATABASE_URL_READONLY` for dashboard queries.

Set (example):

```bash
export DATABASE_URL_READONLY='postgresql://provity_ro:provity_ro@localhost:5432/provity'
````

Create the read-only user inside the Docker Postgres (one-time):

```bash
sudo docker exec -i provity-postgres psql -U provity -d provity <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='provity_ro') THEN
    CREATE ROLE provity_ro LOGIN PASSWORD 'provity_ro';
  END IF;
END $$;

GRANT CONNECT ON DATABASE provity TO provity_ro;
GRANT USAGE ON SCHEMA public TO provity_ro;
GRANT SELECT ON TABLE scan_events TO provity_ro;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO provity_ro;
SQL
```

Security note: it is recommended to **avoid exposing Postgres (5432) to the public internet**.

````

## Run

From the project root, launch Streamlit (system Python):

```bash
python3 -m streamlit run app.py
````

On Windows PowerShell (example):

```powershell
python -m streamlit run app.py
```

## Tests

Provity includes a lightweight pytest suite that does not require ClamAV/osslsigncode/Postgres to be installed (it uses mocks for external tools).

Install dev dependencies:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run tests:

```bash
python3 -m pytest -q
```

## Deploy (PC2 push → PC1 auto-update)

If PC1 can be reached by SSH from GitHub Actions, you can auto-deploy on every push to `main`.

- Workflow: `.github/workflows/deploy_server.yml`
- Remote script: `scripts/deploy_server.sh` (runs `git fetch/reset`, installs deps, and restarts Streamlit)

### GitHub repo secrets required

Configure these repository secrets:

- `DEPLOY_HOST`: Server public hostname/IP
- `DEPLOY_PORT`: SSH port (e.g. `22`)
- `DEPLOY_USER`: SSH username
- `DEPLOY_SSH_KEY`: private key (PEM) for SSH auth
- `DEPLOY_PROVITY_DIR`: absolute path to the repo on the server (e.g. `/home/pascal/provity`)

### Recommended: systemd

For reliable restarts, install the sample unit `deploy/provity.service` on PC1 (adjust paths/user) and enable it.
If `provity.service` is not present, the deploy script falls back to restarting via `nohup`.

The app starts a local web UI.

- Upload a file (`.exe`, `.dll`, `.sys`, `.msi`, `.deb`) to initiate analysis.
- If you enable **Enable scan history (PostgreSQL)** in the sidebar (and have `DATABASE_URL` set), the app will log scan events and show the **Dashboard** tab.

## How It Works

1. The uploaded file is written to a temporary location.
2. Signature check: `osslsigncode verify -CAfile /etc/ssl/certs/ca-certificates.crt -in <file>`; reports validity and signer CN if present.
3. Threat scan: `clamscan --no-summary <file>`; returns clean, infected with name, or engine error.

- Provity also attempts to enable additional ClamAV alerts (PUA/phishing/macro/encrypted/broken) and falls back automatically if the installed clamscan does not support some options.

4. Static analysis: `strings -n 6 <file>`; scans extracted text for IPs, URLs, common shell commands, and registry references, keeping up to five hits per category.
5. Risk summary: computes a score and level (Low/Medium/High) with evidence based on the three checks.
6. Temporary file is deleted after processing.

### Dashboard (scan history)

When enabled, Provity stores each scan as a row in the `scan_events` table:

- `original_filename`
- `file_sha256` (SHA-256 hash of the uploaded file)
- `score`, `risk_level`
- `scanned_at`
- small `metadata` JSON (scanner backend, whether .deb, etc.)

The Dashboard tab shows:

- A per-file summary (last seen time, scan count, last risk level)
- A recent scans table (most recent first)

## Project Structure

- Streamlit entrypoint: `app.py`
- Scanners and utilities: `provity/`
  - `provity/scanners.py`: signature verification, ClamAV scan, and IoC extraction
  - `provity/risk.py`: risk scoring and evidence generation
- Database helper: `provity/db.py`
- SQL schema: `sql/schema.sql`
- Docker Postgres (optional): `docker-compose.yml` (data in `pgdata/`)

## Notes and Limitations

- The current CA path and CLI binaries assume a Unix-like environment; adjust paths for Windows if needed.
- ClamAV and strings outputs are directly surfaced; large binaries may take time to process.
- Detection heuristics are intentionally simple and should be complemented with deeper analysis for production use.
- No network calls are made by the app itself, but system tools may rely on existing signature trust stores.

## File Reference

- Streamlit app: [app.py](app.py)
- Scanners: [provity/scanners.py](provity/scanners.py)
- Risk scoring: [provity/risk.py](provity/risk.py)
