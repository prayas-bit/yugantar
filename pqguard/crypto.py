"""Post-quantum and standard symmetric/hash cryptographic primitives.

Uses vetted implementations only:
- ML-KEM-768 (FIPS 203) via pqcrypto==0.4.0
- ML-DSA-65 (FIPS 204) via pqcrypto==0.4.0
- HMAC-SHA-256 (RFC 2104) & HKDF-SHA-256 (RFC 5869) via Python stdlib
- AES-256-GCM (NIST SP 800-38D) via cryptography (for E2E messaging & encrypted backups)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Tuple

import pqcrypto.kem.ml_kem_768 as ml_kem_768
import pqcrypto.sign.ml_dsa_65 as ml_dsa_65


def b64encode_str(data: bytes) -> str:
    """Encode bytes as standard Base64 ASCII string."""
    return base64.b64encode(data).decode("ascii")


def b64decode_bytes(text: str) -> bytes:
    """Decode standard Base64 string strictly."""
    return base64.b64decode(text.encode("ascii"), validate=True)


def sha256_hex(data: bytes) -> str:
    """Return lowercase hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Return lowercase hexadecimal HMAC-SHA-256 tag."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hkdf_sha256(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    """RFC 5869 HKDF using HMAC-SHA-256."""
    if length <= 0 or length > 255 * 32:
        raise ValueError("Invalid HKDF output length")
    actual_salt = salt if salt else b"\x00" * 32
    prk = hmac.new(actual_salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(prev)
        counter += 1
    return bytes(okm[:length])


def kem_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair (public_key, secret_key)."""
    return ml_kem_768.generate_keypair()


def kem_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret to an ML-KEM-768 public key -> (ciphertext, shared_secret)."""
    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 public key size: expected {ml_kem_768.PUBLIC_KEY_SIZE}, got {len(public_key)}"
        )
    return ml_kem_768.encrypt(public_key)


def kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an ML-KEM-768 ciphertext -> shared_secret."""
    if len(secret_key) != ml_kem_768.SECRET_KEY_SIZE:
        raise ValueError("Invalid ML-KEM-768 secret key size")
    if len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
        raise ValueError("Invalid ML-KEM-768 ciphertext size")
    return ml_kem_768.decrypt(secret_key, ciphertext)


def dsa_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair (public_key, secret_key)."""
    return ml_dsa_65.generate_keypair()


def dsa_sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign message with ML-DSA-65 secret key."""
    if len(secret_key) != ml_dsa_65.SECRET_KEY_SIZE:
        raise ValueError("Invalid ML-DSA-65 secret key size")
    return ml_dsa_65.sign(secret_key, message)


def dsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature; returns False on invalid signature."""
    if len(public_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
        return False
    try:
        return bool(ml_dsa_65.verify(public_key, message, signature))
    except Exception:
        return False


def _get_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "cryptography package is required for AES-256-GCM operations (install via requirements.txt)"
        ) from exc
    return AESGCM


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM using a fresh 96-bit CSPRNG nonce -> (nonce, ciphertext_with_tag)."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    aesgcm_cls = _get_aesgcm()
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm_cls(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate with AES-256-GCM."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("AES-256-GCM requires a 12-byte nonce")
    aesgcm_cls = _get_aesgcm()
    return aesgcm_cls(key).decrypt(nonce, ciphertext, aad)


def zeroize_bytearray(buf: bytearray | None) -> None:
    """Best-effort in-place zeroization of mutable bytearray secret buffers.

    Limitation (F-12): CPython immutable `bytes` returned by CFFI/pqcrypto and
    hashlib/hmac cannot be deterministically wiped in user-space Python and may
    persist in the heap until garbage collection.
    """
    if buf is None:
        return
    for idx in range(len(buf)):
        buf[idx] = 0
