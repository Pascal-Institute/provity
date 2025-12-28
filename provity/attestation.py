from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography import x509
    from cryptography.x509 import ocsp
except Exception as e:  # pragma: no cover
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    x509 = None  # type: ignore[assignment]
    ocsp = None  # type: ignore[assignment]
    _CRYPTO_IMPORT_ERROR = str(e)
else:
    _CRYPTO_IMPORT_ERROR = None


ATTESTATION_SCHEMA = "provity.attestation"
ATTESTATION_VERSION = 1

# Default TSA (Time Stamping Authority) URL for RFC 3161 timestamps.
# FreeTSA is a public, free TSA service. Override via PROVITY_TSA_URL env var.
DEFAULT_TSA_URL = "http://freetsa.org/tsr"


class AttestationError(RuntimeError):
    pass


@dataclass(frozen=True)
class KeyPaths:
    private_key: Path
    public_key: Path


def _require_crypto() -> None:
    if _CRYPTO_IMPORT_ERROR is not None:  # pragma: no cover
        raise AttestationError(
            "cryptography is required for attestation. "
            "Install dependencies with: pip install -r requirements.txt\n"
            f"Import error: {_CRYPTO_IMPORT_ERROR}"
        )


def now_rfc3339_utc() -> str:
    dt = datetime.now(timezone.utc).replace(microsecond=0)
    return dt.isoformat().replace("+00:00", "Z")


def canonical_json_bytes(obj: Any) -> bytes:
    """Stable JSON encoding for signing/verifying."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def default_attestation_dir() -> Path:
    """Directory where the signing keypair is stored.

    Can be overridden via PROVITY_ATTESTATION_DIR.
    """
    override = os.getenv("PROVITY_ATTESTATION_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".provity" / "attestation").resolve()


def key_paths(att_dir: Path | None = None) -> KeyPaths:
    base = att_dir or default_attestation_dir()
    return KeyPaths(
        private_key=base / "ed25519_private_key.pem",
        public_key=base / "ed25519_public_key.pem",
    )


def ensure_keypair(att_dir: Path | None = None) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Load or generate an Ed25519 keypair.

    Returns (private_key, public_key, key_id).
    key_id is a short, stable identifier derived from the public key bytes.
    """
    _require_crypto()

    paths = key_paths(att_dir)
    paths.private_key.parent.mkdir(parents=True, exist_ok=True)

    if paths.private_key.exists() and paths.public_key.exists():
        priv = load_private_key(paths.private_key)
        pub = load_public_key(paths.public_key)
        return priv, pub, public_key_id(pub)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    paths.private_key.write_bytes(priv_pem)
    paths.public_key.write_bytes(pub_pem)

    try:
        os.chmod(paths.private_key, 0o600)
    except Exception:
        # Best-effort: Windows may not support chmod semantics the same way.
        pass

    return priv, pub, public_key_id(pub)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    _require_crypto()
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise AttestationError("Unsupported private key type (expected Ed25519)")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    _require_crypto()
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise AttestationError("Unsupported public key type (expected Ed25519)")
    return key


def public_key_pem_bytes(public_key: Ed25519PublicKey) -> bytes:
    _require_crypto()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_id(public_key: Ed25519PublicKey) -> str:
    """Short identifier for UI/logs; derived from the public key."""
    pem = public_key_pem_bytes(public_key)
    digest = hashlib.sha256(pem).hexdigest()
    return digest[:12]


def sign_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> bytes:
    _require_crypto()
    msg = canonical_json_bytes(payload)
    return private_key.sign(msg)


def verify_payload_signature(
    payload: dict[str, Any],
    *,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    _require_crypto()
    msg = canonical_json_bytes(payload)
    try:
        public_key.verify(signature, msg)
        return True
    except Exception:
        return False


def get_tsa_url() -> str:
    """Get TSA URL from environment or default."""
    return os.getenv("PROVITY_TSA_URL") or DEFAULT_TSA_URL


def request_timestamp_token(
    data: bytes,
    *,
    tsa_url: str | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Request an RFC 3161 timestamp token for the given data.

    Returns a dict with:
      - ok: bool
      - token_der: bytes (DER-encoded timestamp token) if ok=True
      - tsa_url: str
      - error: str (if ok=False)
    """
    _require_crypto()
    tsa_url = tsa_url or get_tsa_url()

    # Compute SHA-256 hash of the data (this is what we timestamp)
    digest = hashlib.sha256(data).digest()

    # Build RFC 3161 TimeStampReq (simplified: we use ASN.1 manually or rely on external lib)
    # For production, use a proper RFC 3161 client library or call out to openssl.
    # Here we do a minimal implementation using HTTP POST with DER-encoded request.

    try:
        import io
        import urllib.request

        # Minimal ASN.1 DER encoding for TimeStampReq (MessageImprint + request)
        # This is a simplified approach; production should use a proper ASN.1 library.
        # For now, we use openssl command-line as fallback or accept that this is best-effort.

        # Actually, let's use a simpler approach: shell out to openssl ts command if available,
        # or use the cryptography library's limited support.
        # Since cryptography doesn't have full RFC 3161 client support built-in,
        # we'll do a basic HTTP POST with a hand-crafted request.

        # Minimal TimeStampReq DER structure (this is a simplified version):
        # We'll construct the request manually or use openssl.

        # For simplicity in this implementation, let's use subprocess + openssl:
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".dat") as f:
            f.write(data)
            data_path = f.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".tsq") as f:
            tsq_path = f.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".tsr") as f:
            tsr_path = f.name

        try:
            # Create timestamp query
            subprocess.run(
                ["openssl", "ts", "-query", "-data", data_path, "-sha256", "-out", tsq_path],
                check=True,
                capture_output=True,
                timeout=5,
            )

            # Send request to TSA
            with open(tsq_path, "rb") as f:
                tsq_data = f.read()

            req = urllib.request.Request(
                tsa_url,
                data=tsq_data,
                headers={"Content-Type": "application/timestamp-query"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                tsr_data = response.read()

            with open(tsr_path, "wb") as f:
                f.write(tsr_data)

            # Verify response is valid (basic check)
            result = subprocess.run(
                ["openssl", "ts", "-reply", "-in", tsr_path, "-text"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return {"ok": False, "tsa_url": tsa_url, "error": "Invalid TSA response"}

            return {
                "ok": True,
                "token_der": tsr_data,
                "tsa_url": tsa_url,
            }

        finally:
            for p in [data_path, tsq_path, tsr_path]:
                try:
                    os.unlink(p)
                except Exception:
                    pass

    except FileNotFoundError:
        return {"ok": False, "tsa_url": tsa_url, "error": "openssl not available"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "tsa_url": tsa_url, "error": "TSA request timed out"}
    except Exception as e:
        return {"ok": False, "tsa_url": tsa_url, "error": str(e)}


def verify_timestamp_token(
    data: bytes,
    *,
    token_der: bytes,
    tsa_url: str,
) -> dict[str, Any]:
    """Verify an RFC 3161 timestamp token.

    Returns dict with:
      - ok: bool
      - timestamp: str (ISO 8601) if ok=True
      - error: str if ok=False
    """
    _require_crypto()

    try:
        import subprocess
        import tempfile
        import re

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".dat") as f:
            f.write(data)
            data_path = f.name

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".tsr") as f:
            f.write(token_der)
            tsr_path = f.name

        try:
            # Verify timestamp token
            result = subprocess.run(
                ["openssl", "ts", "-verify", "-data", data_path, "-in", tsr_path, "-text"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            output = result.stdout + result.stderr

            if "Verification: OK" not in output:
                return {"ok": False, "error": "Timestamp verification failed"}

            # Extract timestamp from output
            match = re.search(r"Time stamp: (.+)", output)
            timestamp_str = match.group(1).strip() if match else "unknown"

            return {
                "ok": True,
                "timestamp": timestamp_str,
                "tsa_url": tsa_url,
            }

        finally:
            for p in [data_path, tsr_path]:
                try:
                    os.unlink(p)
                except Exception:
                    pass

    except FileNotFoundError:
        return {"ok": False, "error": "openssl not available"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def build_attestation(
    payload: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    use_timestamp: bool = False,
    tsa_url: str | None = None,
) -> dict[str, Any]:
    """Build a signed attestation, optionally with RFC 3161 timestamp.

    Args:
        payload: The attestation payload (scan results)
        private_key: Ed25519 private key for signing
        public_key: Corresponding public key
        use_timestamp: If True, request RFC 3161 timestamp (requires network)
        tsa_url: TSA URL override (default: PROVITY_TSA_URL or freetsa.org)
    """
    sig = sign_payload(payload, private_key)
    attestation = {
        "schema": ATTESTATION_SCHEMA,
        "version": ATTESTATION_VERSION,
        "payload": payload,
        "signature": {
            "alg": "Ed25519",
            "key_id": public_key_id(public_key),
            # Embedding the public key keeps the attestation self-contained.
            "public_key_pem": public_key_pem_bytes(public_key).decode("utf-8"),
            "sig_b64": base64.b64encode(sig).decode("ascii"),
        },
    }

    # Optional: Add RFC 3161 timestamp
    if use_timestamp:
        canonical = canonical_json_bytes(payload)
        ts_result = request_timestamp_token(canonical, tsa_url=tsa_url)
        if ts_result.get("ok"):
            attestation["timestamp"] = {
                "tsa_url": ts_result["tsa_url"],
                "token_der_b64": base64.b64encode(ts_result["token_der"]).decode("ascii"),
            }
        else:
            # Timestamp request failed; include error but don't fail attestation
            attestation["timestamp"] = {
                "requested": True,
                "ok": False,
                "error": ts_result.get("error", "unknown"),
                "tsa_url": ts_result.get("tsa_url", tsa_url or get_tsa_url()),
            }

    return attestation


def build_scan_payload(
    *,
    original_filename: str,
    file_sha256: str,
    is_deb: bool,
    sig_detail: dict[str, Any],
    sig_valid: bool,
    sig_info: dict[str, Any],
    clam_detail: dict[str, Any] | None,
    clam_state: bool | None,
    clam_label: str,
    artifacts: dict[str, Any],
    risk_score: int,
    risk_level: str,
    risk_evidence: list[str],
) -> dict[str, Any]:
    return {
        "type": "provity.scan",
        "scanned_at": now_rfc3339_utc(),
        "file": {
            "original_filename": original_filename,
            "sha256": file_sha256,
            "is_deb": bool(is_deb),
        },
        "signature": {
            "valid": bool(sig_valid),
            "backend": sig_detail.get("backend"),
            "signer": (sig_info or {}).get("signer") if isinstance(sig_info, dict) else None,
            "issuer": sig_detail.get("issuer"),
            "subject": sig_detail.get("subject"),
            "not_before": sig_detail.get("not_before"),
            "not_after": sig_detail.get("not_after"),
            "timestamp_present": sig_detail.get("timestamp_present"),
            "revocation_checked": sig_detail.get("revocation_checked"),
            "revocation_ok": sig_detail.get("revocation_ok"),
        },
        "clamav": {
            "state": clam_state,
            "label": clam_label,
            "extended_effective": (clam_detail.get("extended_effective") if isinstance(clam_detail, dict) else None),
            "flags": (clam_detail.get("flags") if isinstance(clam_detail, dict) else None),
        },
        "static_analysis": {
            "artifacts": artifacts,
        },
        "risk": {
            "score": int(risk_score),
            "level": str(risk_level),
            "evidence": list(risk_evidence),
        },
    }


def verify_attestation(
    attestation: dict[str, Any],
    *,
    file_bytes: bytes,
    public_key_pem: str | None = None,
    allow_local_trusted_issuer: bool = True,
) -> dict[str, Any]:
    """Verify an attestation and its binding to the provided file bytes.

    Args:
        attestation: The attestation object to verify
        file_bytes: Original file bytes for hash binding check
        public_key_pem: Explicit issuer public key (PEM). If None, falls back to local trusted issuer.
        allow_local_trusted_issuer: If True and public_key_pem is None, use local keypair as trusted issuer.

    Returns a structured dict suitable for UI rendering.
    """
    _require_crypto()

    if attestation.get("schema") != ATTESTATION_SCHEMA:
        return {"ok": False, "reason": "Unsupported attestation schema"}
    if int(attestation.get("version") or 0) != ATTESTATION_VERSION:
        return {"ok": False, "reason": "Unsupported attestation version"}

    payload = attestation.get("payload")
    sig_block = attestation.get("signature")
    if not isinstance(payload, dict) or not isinstance(sig_block, dict):
        return {"ok": False, "reason": "Malformed attestation"}

    sig_b64 = sig_block.get("sig_b64")
    if not isinstance(sig_b64, str):
        return {"ok": False, "reason": "Missing signature"}

    try:
        signature = base64.b64decode(sig_b64)
    except Exception:
        return {"ok": False, "reason": "Invalid signature encoding"}

    # Binding check: the attestation must match the provided file.
    expected_sha256 = None
    try:
        expected_sha256 = str(((payload.get("file") or {}).get("sha256")) or "")
    except Exception:
        expected_sha256 = ""

    actual_sha256 = sha256_bytes(file_bytes)
    if expected_sha256 and expected_sha256 != actual_sha256:
        return {
            "ok": False,
            "reason": "File hash mismatch",
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
        }

    # Public key resolution:
    # 1. Explicit PEM provided by verifier (highest priority)
    # 2. Local trusted issuer (same Provity instance) if allowed
    # We intentionally do NOT trust embedded keys in the attestation.
    pk_pem = public_key_pem
    used_local_issuer = False
    
    if not pk_pem or not str(pk_pem).strip():
        if allow_local_trusted_issuer:
            # Use local keypair as trusted issuer
            try:
                _, local_pub, local_key_id = ensure_keypair()
                pk_pem = public_key_pem_bytes(local_pub).decode("utf-8")
                used_local_issuer = True
                
                # Security: verify key_id matches attestation to prevent accepting wrong local key
                att_key_id = sig_block.get("key_id")
                if att_key_id and att_key_id != local_key_id:
                    return {
                        "ok": False,
                        "reason": f"Local issuer key mismatch (expected {att_key_id[:8]}..., got {local_key_id[:8]}...)",
                    }
            except Exception as e:
                return {"ok": False, "reason": f"Failed to load local trusted issuer: {e}"}
        else:
            return {"ok": False, "reason": "Missing issuer public key (PEM)."}

    try:
        pub_key = serialization.load_pem_public_key(pk_pem.encode("utf-8"))
    except Exception:
        return {"ok": False, "reason": "Invalid public key"}

    if not isinstance(pub_key, Ed25519PublicKey):
        return {"ok": False, "reason": "Unsupported public key type"}

    sig_ok = verify_payload_signature(payload, signature=signature, public_key=pub_key)
    if not sig_ok:
        return {"ok": False, "reason": "Signature verification failed", "actual_sha256": actual_sha256}

    # Optional: Verify RFC 3161 timestamp if present
    timestamp_info = attestation.get("timestamp")
    timestamp_verified = None
    timestamp_time = None
    if isinstance(timestamp_info, dict) and timestamp_info.get("token_der_b64"):
        try:
            token_der = base64.b64decode(timestamp_info["token_der_b64"])
            canonical = canonical_json_bytes(payload)
            ts_result = verify_timestamp_token(canonical, token_der=token_der, tsa_url=timestamp_info.get("tsa_url", ""))
            timestamp_verified = ts_result.get("ok")
            timestamp_time = ts_result.get("timestamp")
        except Exception:
            timestamp_verified = False

    result = {
        "ok": True,
        "reason": "OK",
        "actual_sha256": actual_sha256,
        "key_id": sig_block.get("key_id") or public_key_id(pub_key),
        "issuer_source": "local trusted issuer" if used_local_issuer else "provided PEM",
        "payload": payload,
    }

    if timestamp_verified is not None:
        result["timestamp_verified"] = timestamp_verified
        if timestamp_time:
            result["timestamp_time"] = timestamp_time

    return result


def parse_attestation_json(attestation_bytes: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(attestation_bytes.decode("utf-8"))
    except Exception as e:
        raise AttestationError(f"Invalid attestation JSON: {e}")
    if not isinstance(obj, dict):
        raise AttestationError("Attestation must be a JSON object")
    return obj
