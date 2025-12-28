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
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except Exception as e:  # pragma: no cover
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]
    _CRYPTO_IMPORT_ERROR = str(e)
else:
    _CRYPTO_IMPORT_ERROR = None


ATTESTATION_SCHEMA = "provity.attestation"
ATTESTATION_VERSION = 1


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


def build_attestation(
    payload: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    sig = sign_payload(payload, private_key)
    return {
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
) -> dict[str, Any]:
    """Verify an attestation and its binding to the provided file bytes.

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

    # Public key: prefer explicit input, then embedded, then local default.
    pk_pem = public_key_pem
    if not pk_pem:
        embedded = sig_block.get("public_key_pem")
        if isinstance(embedded, str) and embedded.strip():
            pk_pem = embedded

    if not pk_pem:
        _, pub, _ = ensure_keypair()
        pk_pem = public_key_pem_bytes(pub).decode("utf-8")

    try:
        pub_key = serialization.load_pem_public_key(pk_pem.encode("utf-8"))
    except Exception:
        return {"ok": False, "reason": "Invalid public key"}

    if not isinstance(pub_key, Ed25519PublicKey):
        return {"ok": False, "reason": "Unsupported public key type"}

    sig_ok = verify_payload_signature(payload, signature=signature, public_key=pub_key)
    if not sig_ok:
        return {"ok": False, "reason": "Signature verification failed", "actual_sha256": actual_sha256}

    return {
        "ok": True,
        "reason": "OK",
        "actual_sha256": actual_sha256,
        "key_id": sig_block.get("key_id") or public_key_id(pub_key),
        "payload": payload,
    }


def parse_attestation_json(attestation_bytes: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(attestation_bytes.decode("utf-8"))
    except Exception as e:
        raise AttestationError(f"Invalid attestation JSON: {e}")
    if not isinstance(obj, dict):
        raise AttestationError("Attestation must be a JSON object")
    return obj
