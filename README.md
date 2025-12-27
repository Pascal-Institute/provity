# Provity: Trustured Software Validator

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

## Requirements

- Python 3.9+ with Streamlit installed (`pip install streamlit`).
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
