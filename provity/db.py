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
# Users can override by setting DATABASE_URL.
DEFAULT_DATABASE_URL = "postgresql://provity:provity@localhost:5432/provity"


def get_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    # If not provided, default to the local Docker Postgres from docker-compose.yml.
    # This makes the app work out-of-the-box after `docker compose up -d`.
    return url or DEFAULT_DATABASE_URL


def _require_psycopg() -> None:
    if psycopg is None:  # pragma: no cover
        raise RuntimeError(
            "psycopg is not installed. Install with: pip install 'psycopg[binary]'"
        )


def ensure_schema(schema_path: str | os.PathLike[str] = DEFAULT_SCHEMA_PATH) -> None:
    """Create tables/indexes if they do not exist."""
    _require_psycopg()

    ddl = Path(schema_path).read_text(encoding="utf-8")
    with psycopg.connect(get_database_url()) as conn:  # type: ignore[attr-defined]
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()


def insert_scan_event(
    *,
    user_id: str = "anonymous",
    original_filename: str | None,
    file_sha256: str,
    score: int | None,
    risk_level: str | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    _require_psycopg()

    metadata = metadata or {}
    with psycopg.connect(get_database_url()) as conn:  # type: ignore[attr-defined]
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_events (user_id, original_filename, file_sha256, score, risk_level, metadata)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                """,
                (user_id, original_filename, file_sha256, score, risk_level, json.dumps(metadata)),
            )
        conn.commit()


def fetch_recent_scans(limit: int = 50) -> list[dict[str, Any]]:
    _require_psycopg()

    with psycopg.connect(get_database_url()) as conn:  # type: ignore[attr-defined]
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, scanned_at, user_id, original_filename, file_sha256, score, risk_level
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
            "file_sha256": r[4],
            "score": r[5],
            "risk_level": r[6],
        }
        for r in rows
    ]


def fetch_file_last_seen(limit_files: int = 50) -> list[dict[str, Any]]:
    """Per file hash: last scan time, count, and latest score/level (best-effort)."""
    _require_psycopg()

    with psycopg.connect(get_database_url()) as conn:  # type: ignore[attr-defined]
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  file_sha256,
                  MAX(scanned_at) AS last_scanned_at,
                  COUNT(*) AS scan_count,
                  MAX(score) AS max_score,
                  (ARRAY_AGG(risk_level ORDER BY scanned_at DESC))[1] AS last_risk_level,
                  (ARRAY_AGG(original_filename ORDER BY scanned_at DESC))[1] AS last_filename
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
        }
        for r in rows
    ]
