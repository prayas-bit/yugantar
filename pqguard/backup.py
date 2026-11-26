"""Authenticated, encrypted, and ML-DSA-65 signed key-material backup & recovery."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any, Dict, Optional

from pqguard.crypto import (
    aead_decrypt,
    aead_encrypt,
    b64decode_bytes,
    b64encode_str,
    dsa_sign,
    dsa_verify,
    hkdf_sha256,
    sha256_hex,
)
from pqguard.keystore import KeyStore
from pqguard.storage import atomic_write_json


@dataclass(frozen=True)
class BackupResult:
    backup_id: str
    backup_path: Path
    payload_sha256: str
    active_version: int


@dataclass(frozen=True)
class RestoreResult:
    verified: bool
    backup_id: Optional[str] = None
    error: Optional[str] = None
    restored_active_version: Optional[int] = None


def _derive_backup_key(master_secret: bytes, backup_id: str) -> bytes:
    return hkdf_sha256(
        ikm=master_secret,
        length=32,
        salt=b"pqguard-backup-v1",
        info=backup_id.encode("utf-8"),
    )


def _canonical_manifest(manifest: Dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def create_backup(
    keystore: KeyStore,
    backup_path: Path,
    master_secret: bytes,
    signing_sk: bytes,
    backup_id: Optional[str] = None,
) -> BackupResult:
    """Create an AES-256-GCM encrypted and ML-DSA-65 signed backup bundle."""
    bid = backup_id or f"bkp-{int(time.time() * 1000)}"
    payload_bytes = json.dumps(keystore.state, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    payload_digest = sha256_hex(payload_bytes)

    enc_key = _derive_backup_key(master_secret, bid)
    aad = f"{bid}:{payload_digest}".encode("utf-8")
    nonce, ciphertext = aead_encrypt(enc_key, payload_bytes, aad=aad)

    manifest = {
        "format": "pqguard-backup-v1",
        "backup_id": bid,
        "created_at": time.time(),
        "active_version": keystore.active_version(),
        "payload_sha256": payload_digest,
        "ciphertext_sha256": sha256_hex(ciphertext),
        "nonce_b64": b64encode_str(nonce),
        "ciphertext_b64": b64encode_str(ciphertext),
    }
    manifest_bytes = _canonical_manifest(manifest)
    sig = dsa_sign(signing_sk, manifest_bytes)
    bundle = {
        "manifest": manifest,
        "signature_b64": b64encode_str(sig),
    }
    atomic_write_json(backup_path, bundle)
    return BackupResult(
        backup_id=bid,
        backup_path=backup_path,
        payload_sha256=payload_digest,
        active_version=keystore.active_version(),
    )


def restore_backup(
    backup_path: Path,
    target_state_dir: Path,
    master_secret: bytes,
    signing_pk: bytes,
) -> RestoreResult:
    """Verify ML-DSA-65 signature, SHA-256 digests, and AES-GCM tag before restoring."""
    if not backup_path.is_file():
        return RestoreResult(verified=False, error="Backup file does not exist")

    try:
        with backup_path.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        manifest = bundle["manifest"]
        sig_bytes = b64decode_bytes(bundle["signature_b64"])
    except Exception as exc:
        return RestoreResult(verified=False, error=f"Malformed backup bundle: {exc}")

    manifest_bytes = _canonical_manifest(manifest)
    if not dsa_verify(signing_pk, manifest_bytes, sig_bytes):
        return RestoreResult(
            verified=False,
            backup_id=manifest.get("backup_id"),
            error="Backup ML-DSA-65 signature verification failed",
        )

    try:
        bid = str(manifest["backup_id"])
        nonce = b64decode_bytes(manifest["nonce_b64"])
        ciphertext = b64decode_bytes(manifest["ciphertext_b64"])
        expected_ct_hash = str(manifest["ciphertext_sha256"])
        expected_pt_hash = str(manifest["payload_sha256"])
    except Exception as exc:
        return RestoreResult(verified=False, error=f"Invalid backup manifest fields: {exc}")

    if sha256_hex(ciphertext) != expected_ct_hash:
        return RestoreResult(
            verified=False,
            backup_id=bid,
            error="Backup ciphertext SHA-256 digest mismatch",
        )

    enc_key = _derive_backup_key(master_secret, bid)
    aad = f"{bid}:{expected_pt_hash}".encode("utf-8")
    try:
        plaintext = aead_decrypt(enc_key, nonce, ciphertext, aad=aad)
    except Exception:
        return RestoreResult(
            verified=False,
            backup_id=bid,
            error="Backup AES-256-GCM decryption/authentication failed",
        )

    if sha256_hex(plaintext) != expected_pt_hash:
        return RestoreResult(
            verified=False,
            backup_id=bid,
            error="Backup plaintext SHA-256 digest mismatch",
        )

    restored_state = json.loads(plaintext.decode("utf-8"))
    target_state_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_json(target_state_dir / "keystore_state.json", restored_state)
    return RestoreResult(
        verified=True,
        backup_id=bid,
        restored_active_version=int(restored_state["active_version"]),
    )
