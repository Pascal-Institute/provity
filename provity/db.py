from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore[assignment]


DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "sql" / "schema.sql"

# Default connection for the bundled docker-compose Postgres service.
# Users can override by setting DATABASE_URL / DATABASE_URL_READONLY.
DEFAULT_DATABASE_URL = "postgresql://provity:provity@localhost:5432/provity"

# Separate, optional read-only connection string for dashboards.
# If set, the app can show history using a DB user with SELECT privileges only.
DEFAULT_DATABASE_URL_READONLY = "postgresql://provity_ro:provity_ro@localhost:5432/provity"


def get_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    # If not provided, default to the local Docker Postgres from docker-compose.yml.
    # This makes the app work out-of-the-box after `docker compose up -d`.
    return url or DEFAULT_DATABASE_URL


def get_database_url_readonly() -> str:
    """Fetch read-only database URL.

    Precedence:
      1) DATABASE_URL_READONLY
      2) DATABASE_URL (fallback)
      3) DEFAULT_DATABASE_URL_READONLY
      4) DEFAULT_DATABASE_URL
    """
    url_ro = os.getenv("DATABASE_URL_READONLY")
    if url_ro:
        return url_ro
    url_rw = os.getenv("DATABASE_URL")
    if url_rw:
        return url_rw
    return DEFAULT_DATABASE_URL_READONLY or DEFAULT_DATABASE_URL


def connect(*, readonly: bool = False):
    """Create a psycopg connection.

    When readonly=True, we attempt to enforce read-only semantics at the
    transaction level (best-effort). The DB role should still be configured as
    read-only for real safety.
    """
    _require_psycopg()
    url = get_database_url_readonly() if readonly else get_database_url()
    conn = psycopg.connect(url)  # type: ignore[attr-defined]
    if readonly:
        try:
            # Enforce transaction read-only if supported.
            with conn.cursor() as cur:
                cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        except Exception:
            # If the server/driver doesn't support it, role permissions should still protect.
            pass
    return conn


def _require_psycopg() -> None:
    if psycopg is None:  # pragma: no cover
        raise RuntimeError(
            "psycopg is not installed. Install with: pip install 'psycopg[binary]'"
        )


def ensure_schema(schema_path: str | os.PathLike[str] = DEFAULT_SCHEMA_PATH) -> None:
    """Create tables/indexes if they do not exist."""
    _require_psycopg()

    ddl = Path(schema_path).read_text(encoding="utf-8")
    with connect(readonly=False) as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)

            # ---- Lightweight migrations (idempotent) ----
            # Add `valid_signature` column if it doesn't exist.
            cur.execute(
                """
                ALTER TABLE scan_events
                ADD COLUMN IF NOT EXISTS valid_signature BOOLEAN NOT NULL DEFAULT FALSE
                """
            )

            # Optional app icon storage (NULL when unavailable).
            cur.execute(
                """
                ALTER TABLE scan_events
                ADD COLUMN IF NOT EXISTS app_icon BYTEA
                """
            )
            cur.execute(
                """
                ALTER TABLE scan_events
                ADD COLUMN IF NOT EXISTS app_icon_mime TEXT
                """
            )

            # Backfill existing rows from metadata.signature_valid when available.
            # We only update rows that are still FALSE, so rerunning is safe.
            cur.execute(
                """
                UPDATE scan_events
                SET valid_signature = TRUE
                WHERE valid_signature = FALSE
                  AND LOWER(COALESCE(metadata->>'signature_valid', '')) IN ('true', 't', '1', 'yes')
                """
            )
        conn.commit()


def insert_scan_event(
    *,
    user_id: str = "anonymous",
    original_filename: str | None,
    file_sha256: str,
    valid_signature: bool = False,
    app_icon: bytes | None = None,
    app_icon_mime: str | None = None,
    score: int | None,
    risk_level: str | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    _require_psycopg()

    metadata = metadata or {}
    with connect(readonly=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_events (
                    user_id,
                    original_filename,
                    file_sha256,
                    valid_signature,
                    app_icon,
                    app_icon_mime,
                    score,
                    risk_level,
                    metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    user_id,
                    original_filename,
                    file_sha256,
                    bool(valid_signature),
                    app_icon,
                    app_icon_mime,
                    score,
                    risk_level,
                    json.dumps(metadata),
                ),
            )
        conn.commit()


def fetch_recent_scans(limit: int = 50) -> list[dict[str, Any]]:
    _require_psycopg()

    with connect(readonly=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  id,
                  scanned_at,
                  user_id,
                  original_filename,
                  COALESCE(metadata->>'app_name', '') AS app_name,
                                    COALESCE(metadata->>'signature_signer', '') AS signature_signer,
                                    COALESCE(metadata->>'signature_issuer', '') AS signature_issuer,
                  file_sha256,
                                    valid_signature,
                                    app_icon,
                                    app_icon_mime,
                  score,
                  risk_level
                FROM scan_events
                ORDER BY scanned_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()

    return [
        {
            "id": r[0],
            "scanned_at": r[1],
            "user_id": r[2],
            "original_filename": r[3],
            "app_name": r[4] or "Unknown",
            "signature_signer": r[5] or "",
            "signature_issuer": r[6] or "",
            "file_sha256": r[7],
            "valid_signature": bool(r[8]),
            "app_icon": r[9],
            "app_icon_mime": r[10],
            "score": r[11],
            "risk_level": r[12],
        }
        for r in rows
    ]


def fetch_file_last_seen(limit_files: int = 50) -> list[dict[str, Any]]:
    """Per file hash: last scan time, count, and latest score/level (best-effort)."""
    _require_psycopg()

    with connect(readonly=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  file_sha256,
                  MAX(scanned_at) AS last_scanned_at,
                  COUNT(*) AS scan_count,
                  MAX(score) AS max_score,
                  (ARRAY_AGG(risk_level ORDER BY scanned_at DESC))[1] AS last_risk_level,
                                    (ARRAY_AGG(original_filename ORDER BY scanned_at DESC))[1] AS last_filename,
                                    (ARRAY_AGG(COALESCE(metadata->>'app_name','') ORDER BY scanned_at DESC))[1] AS last_app_name,
                                    (ARRAY_AGG(COALESCE(metadata->>'signature_signer','') ORDER BY scanned_at DESC))[1] AS last_signature_signer,
                                    (ARRAY_AGG(COALESCE(metadata->>'signature_issuer','') ORDER BY scanned_at DESC))[1] AS last_signature_issuer
                FROM scan_events
                GROUP BY file_sha256
                ORDER BY last_scanned_at DESC
                LIMIT %s
                """,
                (limit_files,),
            )
            rows = cur.fetchall()

    return [
        {
            "file_sha256": r[0],
            "last_scanned_at": r[1],
            "scan_count": r[2],
            "max_score": r[3],
            "last_risk_level": r[4],
            "last_filename": r[5],
            "app_name": r[6] or "Unknown",
            "signature_signer": r[7] or "",
            "signature_issuer": r[8] or "",
        }
        for r in rows
    ]


def fetch_latest_scan_for_hash(file_sha256: str) -> dict[str, Any] | None:
    """Fetch latest scan info for a given file hash (read-only).

    Returns None when no prior scans exist.
    """
    _require_psycopg()

    with connect(readonly=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                                SELECT
                                    scanned_at,
                                    score,
                                    risk_level,
                                    original_filename,
                                    COALESCE(metadata->>'app_name','') AS app_name,
                                    COALESCE(metadata->>'signature_signer','') AS signature_signer,
                                    COALESCE(metadata->>'signature_issuer','') AS signature_issuer,
                                    app_icon,
                                    app_icon_mime
                FROM scan_events
                WHERE file_sha256 = %s
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (file_sha256,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return {
        "scanned_at": row[0],
        "score": row[1],
        "risk_level": row[2],
        "original_filename": row[3],
        "app_name": row[4] or "Unknown",
        "signature_signer": row[5] or "",
        "signature_issuer": row[6] or "",
        "app_icon": row[7],
        "app_icon_mime": row[8],
    }
