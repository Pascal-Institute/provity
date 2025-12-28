from __future__ import annotations

import base64
import json
import os
import urllib.request
from typing import Any


class SandboxError(RuntimeError):
    pass


DEFAULT_SANDBOX_CONTROLLER_URL = "http://localhost:8000"


def get_sandbox_controller_url(*, default_if_unset: bool = True) -> str | None:
    url = os.getenv("PROVITY_SANDBOX_CONTROLLER_URL")
    if url and url.strip():
        return url.strip().rstrip("/")

    if default_if_unset:
        return DEFAULT_SANDBOX_CONTROLLER_URL

    return None


def run_dynamic_scan(
    *,
    file_bytes: bytes,
    filename: str,
    file_sha256: str,
    timeout_sec: int = 20,
    controller_url: str | None = None,
) -> dict[str, Any]:
    url = (controller_url or get_sandbox_controller_url() or "").strip().rstrip("/")
    if not url:
        return {
            "ok": False,
            "reason": "Sandbox controller URL is missing (set PROVITY_SANDBOX_CONTROLLER_URL)",
        }

    body = {
        "filename": filename,
        "file_sha256": file_sha256,
        "file_b64": base64.b64encode(file_bytes).decode("ascii"),
        "timeout_sec": int(timeout_sec),
    }

    req = urllib.request.Request(
        url + "/scan",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=max(5, int(timeout_sec) + 10)) as resp:
            raw = resp.read()
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise SandboxError("Invalid controller response")
        return obj
    except Exception as e:
        return {"ok": False, "reason": f"Sandbox controller request failed: {e}"}
