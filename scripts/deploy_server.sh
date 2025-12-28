#!/usr/bin/env bash
set -euo pipefail

PORT=8501

if command -v python3 >/dev/null 2>&1; then
	PY=python3
elif command -v python >/dev/null 2>&1; then
	PY=python
else
	echo "[deploy] ERROR: python3/python not found" >&2
	exit 127
fi

echo "[deploy] Using python: $PY"

# Stop anything currently listening on PORT (best-effort)
if command -v lsof >/dev/null 2>&1; then
	PIDS=$(lsof -ti tcp:"$PORT" || true)
	if [[ -n "$PIDS" ]]; then
		echo "[deploy] Stopping processes on port $PORT: $PIDS"
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
nohup "$PY" -m streamlit run app.py \
	--server.address 0.0.0.0 \
	--server.port "$PORT" \
	> streamlit.log 2>&1 &

sleep 0.5
echo "[deploy] Done (pid $!)"
