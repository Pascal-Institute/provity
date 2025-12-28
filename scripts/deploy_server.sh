#!/usr/bin/env bash
set -euo pipefail

PORT=8501
HOST=127.0.0.1
HEALTHCHECK_ATTEMPTS=30
HEALTHCHECK_SLEEP_SEC=1

APP_DIR="${PROVITY_DIR:-$(pwd)}"

health_check() {
	"$PY" - <<'PY'
import os
import socket
import sys
import time

host = os.environ.get("HEALTH_HOST", "127.0.0.1")
port = int(os.environ.get("HEALTH_PORT", "8501"))
attempts = int(os.environ.get("HEALTH_ATTEMPTS", "30"))
sleep_sec = float(os.environ.get("HEALTH_SLEEP", "1"))

last_err: str | None = None
for _ in range(attempts):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(1.0)
	try:
		s.connect((host, port))
		s.close()
		print(f"[deploy] Health check OK: {host}:{port}")
		sys.exit(0)
	except Exception as e:
		last_err = str(e)
		try:
			s.close()
		except Exception:
			pass
		time.sleep(sleep_sec)

print(f"[deploy] ERROR: health check failed for {host}:{port} (last error: {last_err})", file=sys.stderr)
sys.exit(1)
PY
}

if command -v python3 >/dev/null 2>&1; then
	PY=python3
elif command -v python >/dev/null 2>&1; then
	PY=python
else
	echo "[deploy] ERROR: python3/python not found" >&2
	exit 127
fi

echo "[deploy] Using python: $PY"

# Prefer systemd if present and provity.service is installed
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q '^provity\.service'; then
	echo "[deploy] Restarting systemd service: provity.service"
	if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
		sudo -n systemctl restart provity.service
	else
		systemctl restart provity.service
	fi

	export HEALTH_HOST="$HOST"
	export HEALTH_PORT="$PORT"
	export HEALTH_ATTEMPTS="$HEALTHCHECK_ATTEMPTS"
	export HEALTH_SLEEP="$HEALTHCHECK_SLEEP_SEC"
	health_check

	if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
		sudo -n systemctl --no-pager --full status provity.service || true
	else
		systemctl --no-pager --full status provity.service || true
	fi
	exit 0
fi

# Stop anything currently listening on PORT (best-effort)
if command -v lsof >/dev/null 2>&1; then
	PIDS=$(lsof -ti tcp:"$PORT" || true)
	if [[ -n "$PIDS" ]]; then
		echo "[deploy] Stopping processes on port $PORT: $PIDS"
		kill $PIDS || true
		sleep 0.5
		kill -9 $PIDS || true
	fi
elif command -v fuser >/dev/null 2>&1; then
	echo "[deploy] Stopping processes on port $PORT via fuser"
	fuser -k "${PORT}/tcp" || true
else
	echo "[deploy] lsof/fuser not found; falling back to pkill"
	pkill -f "streamlit run app.py" >/dev/null 2>&1 || true
	pkill -f "-m streamlit run app.py" >/dev/null 2>&1 || true
fi

echo "[deploy] Starting Streamlit on port $PORT"
	cd "$APP_DIR"
	nohup "$PY" -m streamlit run app.py \
	--server.address 0.0.0.0 \
	--server.port "$PORT" \
	> "$APP_DIR/streamlit.log" 2>&1 &

sleep 0.5

export HEALTH_HOST="$HOST"
export HEALTH_PORT="$PORT"
export HEALTH_ATTEMPTS="$HEALTHCHECK_ATTEMPTS"
export HEALTH_SLEEP="$HEALTHCHECK_SLEEP_SEC"
health_check

echo "[deploy] Done (pid $!)"
