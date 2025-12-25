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
