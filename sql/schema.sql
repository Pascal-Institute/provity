CREATE TABLE IF NOT EXISTS scan_events (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL DEFAULT 'anonymous',
  original_filename TEXT,
  file_sha256 TEXT NOT NULL,
  valid_signature BOOLEAN NOT NULL DEFAULT FALSE,
  app_icon_b64 TEXT,
  app_icon_b64_mime TEXT,
  score INTEGER,
  risk_level TEXT,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scan_events_scanned_at ON scan_events (scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_events_file_sha256 ON scan_events (file_sha256);

-- ---- Read-only dashboard role (optional) ----
-- The app's dashboard can use a separate read-only connection string.
-- We create the role here so fresh databases work out-of-the-box.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'provity_ro') THEN
    CREATE ROLE provity_ro LOGIN PASSWORD 'provity_ro';
  END IF;
END $$;

GRANT CONNECT ON DATABASE provity TO provity_ro;
GRANT USAGE ON SCHEMA public TO provity_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO provity_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO provity_ro;
