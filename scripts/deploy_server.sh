#!/usr/bin/env bash
set -euo pipefail

# Repo directory on PC1 (set by workflow)
: "${PROVITY_DIR:?PROVITY_DIR is required}"

cd "$PROVITY_DIR"

echo "[deploy] Updating source..."
git fetch --prune origin main
git reset --hard origin/main

# Pick interpreter
if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  PY="python"
fi

echo "[deploy] Using python: $PY"

echo "[deploy] Installing deps..."
"$PY" -m pip install -r requirements.txt

# Prefer systemd if present (recommended)
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^provity\.service'; then
  echo "[deploy] Restarting systemd service: provity.service"
  sudo systemctl restart provity.service
  sudo systemctl --no-pager --full status provity.service || true
  exit 0
fi

# Fallback: direct execution (no systemd). Starts Streamlit in background.
# NOTE: This is best-effort; systemd is more reliable.
echo "[deploy] systemd service not found; restarting via nohup"

pkill -f "streamlit run app.py" >/dev/null 2>&1 || true

nohup "$PY" -m streamlit run app.py \
  --server.address 0.0.0.0 \
  --server.port 8501 \
  > "$PROVITY_DIR/streamlit.log" 2>&1 &

sleep 0.5
pgrep -f "streamlit run app.py" >/dev/null 2>&1 && echo "[deploy] Streamlit started" || echo "[deploy] Streamlit may not have started (check streamlit.log)"
