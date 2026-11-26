"""Post-quantum E2E encrypted messaging: ML-KEM-768 + ML-DSA-65 + HKDF + AES-256-GCM.

Covers:
- Goal 9: Replay protection and authenticated recipient binding
- Goal 10: Forward secrecy via ephemeral ML-KEM-768 + key-ratcheting + erasure
- Goal 11: Ordered delivery under packet loss or reordering
- Goal 12: Identity-bound, policy-checked session resumption
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

from pqguard.crypto import (
    aead_decrypt,
    aead_encrypt,
    b64decode_bytes,
    b64encode_str,
    dsa_generate_keypair,
    dsa_sign,
    dsa_verify,
    hkdf_sha256,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate_keypair,
    sha256_hex,
    zeroize_bytearray,
)


@dataclass(frozen=True)
class IdentityKeyPair:
    identity_id: str
    dsa_pk: bytes
    dsa_sk: bytes

    @classmethod
    def generate(cls, identity_id: str) -> "IdentityKeyPair":
        pk, sk = dsa_generate_keypair()
        return cls(identity_id=identity_id, dsa_pk=pk, dsa_sk=sk)


@dataclass(frozen=True)
class HandshakeInit:
    session_id: str
    initiator_id: str
    responder_id: str
    eph_kem_pk_b64: str
    signature_b64: str


@dataclass(frozen=True)
class HandshakeAccept:
    session_id: str
    initiator_id: str
    responder_id: str
    kem_ciphertext_b64: str
    signature_b64: str


@dataclass(frozen=True)
class EncryptedEnvelope:
    session_id: str
    msg_id: str
    seq: int
    sender_id: str
    recipient_id: str
    nonce_b64: str
    ciphertext_b64: str


@dataclass(frozen=True)
class DeliveryFailure:
    seq: int
    reason: str


def _aad_bytes(session_id: str, msg_id: str, seq: int, sender_id: str, recipient_id: str) -> bytes:
    payload = {
        "msg_id": msg_id,
        "recipient_id": recipient_id,
        "sender_id": sender_id,
        "seq": seq,
        "session_id": session_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _handshake_init_transcript(session_id: str, initiator_id: str, responder_id: str, eph_kem_pk: bytes) -> bytes:
    return f"pqguard-hs-init-v1|{session_id}|{initiator_id}|{responder_id}|".encode("utf-8") + eph_kem_pk


def _handshake_accept_transcript(
    session_id: str, initiator_id: str, responder_id: str, eph_kem_pk: bytes, kem_ct: bytes
) -> bytes:
    return (
        f"pqguard-hs-accept-v1|{session_id}|{initiator_id}|{responder_id}|".encode("utf-8")
        + eph_kem_pk
        + b"|"
        + kem_ct
    )


class E2ESession:
    """Ratcheted post-quantum E2E session with forward secrecy, replay, and reorder handling."""

    def __init__(
        self,
        session_id: str,
        local_id: str,
        peer_id: str,
        chain_key: bytes,
        max_reorder_buffer: int = 64,
    ) -> None:
        self.session_id = session_id
        self.local_id = local_id
        self.peer_id = peer_id
        self._send_chain = bytearray(chain_key)
        self._recv_chain = bytearray(chain_key)
        self.send_seq = 1
        self.expected_recv_seq = 1
        self._seen_msg_ids: Set[str] = set()
        self._seen_seqs: Set[int] = set()
        self._recv_key_cache: Dict[int, bytearray] = {}
        self._reorder_buffer: Dict[int, Tuple[bytes, float]] = {}
        self.max_reorder_buffer = max_reorder_buffer
        self.closed = False

    def _derive_msg_and_next_chain(self, chain: bytearray, seq: int) -> Tuple[bytes, bytearray]:
        msg_key = hkdf_sha256(bytes(chain), 32, salt=self.session_id.encode("utf-8"), info=f"msg:{seq}".encode("ascii"))
        next_chain = hkdf_sha256(
            bytes(chain), 32, salt=self.session_id.encode("utf-8"), info=f"next:{seq}".encode("ascii")
        )
        return msg_key, bytearray(next_chain)

    def _get_or_advance_recv_key(self, seq: int) -> bytes:
        if seq in self._recv_key_cache:
            return bytes(self._recv_key_cache[seq])
        if seq < self.expected_recv_seq:
            raise ValueError(f"Replay or expired sequence number: {seq}")
        if seq - self.expected_recv_seq > self.max_reorder_buffer:
            raise ValueError(f"Sequence {seq} exceeds reorder window")

        # Advance receive chain up to seq, caching skipped keys for out-of-order delivery
        cursor = self.expected_recv_seq
        while cursor in self._recv_key_cache:
            cursor += 1
        while cursor <= seq:
            msg_key, next_chain = self._derive_msg_and_next_chain(self._recv_chain, cursor)
            zeroize_bytearray(self._recv_chain)
            self._recv_chain = next_chain
            self._recv_key_cache[cursor] = bytearray(msg_key)
            cursor += 1
        return bytes(self._recv_key_cache[seq])

    def encrypt_message(self, plaintext: bytes, msg_id: Optional[str] = None) -> EncryptedEnvelope:
        """Encrypt and bind a message to sender, recipient, session, and sequence number."""
        if self.closed:
            raise RuntimeError("Session is closed")
        seq = self.send_seq
        mid = msg_id or f"{self.session_id}-m{seq}-{secrets.token_hex(4)}"
        msg_key, next_chain = self._derive_msg_and_next_chain(self._send_chain, seq)
        zeroize_bytearray(self._send_chain)
        self._send_chain = next_chain
        self.send_seq += 1

        aad = _aad_bytes(self.session_id, mid, seq, self.local_id, self.peer_id)
        nonce, ct = aead_encrypt(msg_key, plaintext, aad=aad)
        return EncryptedEnvelope(
            session_id=self.session_id,
            msg_id=mid,
            seq=seq,
            sender_id=self.local_id,
            recipient_id=self.peer_id,
            nonce_b64=b64encode_str(nonce),
            ciphertext_b64=b64encode_str(ct),
        )

    def receive_envelope(
        self, env: EncryptedEnvelope, now: Optional[float] = None
    ) -> Tuple[List[Tuple[int, bytes]], Optional[DeliveryFailure]]:
        """Authenticate, decrypt, deduplicate, and deliver in-order messages."""
        ts = time.time() if now is None else now
        if self.closed:
            return [], DeliveryFailure(seq=env.seq, reason="session_closed")
        if env.session_id != self.session_id:
            return [], DeliveryFailure(seq=env.seq, reason="session_id_mismatch")
        if env.recipient_id != self.local_id:
            return [], DeliveryFailure(seq=env.seq, reason="recipient_binding_mismatch")
        if env.sender_id != self.peer_id:
            return [], DeliveryFailure(seq=env.seq, reason="sender_binding_mismatch")
        if env.msg_id in self._seen_msg_ids or env.seq in self._seen_seqs:
            return [], DeliveryFailure(seq=env.seq, reason="replay_detected")

        try:
            msg_key = self._get_or_advance_recv_key(env.seq)
            nonce = b64decode_bytes(env.nonce_b64)
            ct = b64decode_bytes(env.ciphertext_b64)
            aad = _aad_bytes(env.session_id, env.msg_id, env.seq, env.sender_id, env.recipient_id)
            plaintext = aead_decrypt(msg_key, nonce, ct, aad=aad)
        except Exception as exc:
            return [], DeliveryFailure(seq=env.seq, reason=f"authentication_failed:{type(exc).__name__}")

        # Erase used message key immediately
        if env.seq in self._recv_key_cache:
            zeroize_bytearray(self._recv_key_cache.pop(env.seq))

        self._seen_msg_ids.add(env.msg_id)
        self._seen_seqs.add(env.seq)
        self._reorder_buffer[env.seq] = (plaintext, ts)

        delivered: List[Tuple[int, bytes]] = []
        while self.expected_recv_seq in self._reorder_buffer:
            pt, _ = self._reorder_buffer.pop(self.expected_recv_seq)
            delivered.append((self.expected_recv_seq, pt))
            self.expected_recv_seq += 1
        return delivered, None

    def flush_incomplete(self, max_age_seconds: float, now: Optional[float] = None) -> List[DeliveryFailure]:
        """Discard incomplete/stalled out-of-order sequences past timeout and report failures."""
        ts = time.time() if now is None else now
        if not self._reorder_buffer:
            return []
        failures: List[DeliveryFailure] = []
        oldest_ts = min(item_ts for _, item_ts in self._reorder_buffer.values())
        if ts - oldest_ts < max_age_seconds:
            return []

        max_buffered = max(self._reorder_buffer.keys())
        for seq in range(self.expected_recv_seq, max_buffered + 1):
            if seq not in self._reorder_buffer:
                failures.append(DeliveryFailure(seq=seq, reason="lost_packet_timeout"))
            else:
                self._reorder_buffer.pop(seq)
                failures.append(DeliveryFailure(seq=seq, reason="discarded_due_to_prior_gap"))
        for k in list(self._recv_key_cache.keys()):
            if k <= max_buffered:
                zeroize_bytearray(self._recv_key_cache.pop(k))
        self.expected_recv_seq = max_buffered + 1
        return failures

    def close(self) -> None:
        """Erase all ephemeral chain and cached message keys (forward secrecy)."""
        zeroize_bytearray(self._send_chain)
        zeroize_bytearray(self._recv_chain)
        for buf in self._recv_key_cache.values():
            zeroize_bytearray(buf)
        self._recv_key_cache.clear()
        self._reorder_buffer.clear()
        self.closed = True


class E2EHandshakeState:
    """Holds ephemeral ML-KEM-768 secret key only until handshake finishes, then erases it."""

    def __init__(self, session_id: str, initiator: IdentityKeyPair, responder_id: str) -> None:
        self.session_id = session_id
        self.initiator = initiator
        self.responder_id = responder_id
        pk, sk = kem_generate_keypair()
        self._eph_pk = pk
        self._eph_sk: Optional[bytearray] = bytearray(sk)

    def create_init(self) -> HandshakeInit:
        transcript = _handshake_init_transcript(
            self.session_id, self.initiator.identity_id, self.responder_id, self._eph_pk
        )
        sig = dsa_sign(self.initiator.dsa_sk, transcript)
        return HandshakeInit(
            session_id=self.session_id,
            initiator_id=self.initiator.identity_id,
            responder_id=self.responder_id,
            eph_kem_pk_b64=b64encode_str(self._eph_pk),
            signature_b64=b64encode_str(sig),
        )

    def finalize_initiator(self, accept: HandshakeAccept, responder_dsa_pk: bytes) -> E2ESession:
        if self._eph_sk is None:
            raise RuntimeError("Ephemeral secret key already erased")
        if accept.session_id != self.session_id or accept.responder_id != self.responder_id:
            raise ValueError("Handshake accept metadata mismatch")
        kem_ct = b64decode_bytes(accept.kem_ciphertext_b64)
        sig = b64decode_bytes(accept.signature_b64)
        transcript = _handshake_accept_transcript(
            self.session_id, self.initiator.identity_id, self.responder_id, self._eph_pk, kem_ct
        )
        if not dsa_verify(responder_dsa_pk, transcript, sig):
            raise ValueError("Responder ML-DSA-65 signature verification failed")

        shared_secret = kem_decapsulate(bytes(self._eph_sk), kem_ct)
        # Forward secrecy: erase ephemeral KEM secret key immediately after decapsulation
        zeroize_bytearray(self._eph_sk)
        self._eph_sk = None

        chain_key = hkdf_sha256(
            shared_secret, 32, salt=self.session_id.encode("utf-8"), info=b"pqguard-e2e-chain-v1"
        )
        return E2ESession(
            session_id=self.session_id,
            local_id=self.initiator.identity_id,
            peer_id=self.responder_id,
            chain_key=chain_key,
        )


def accept_handshake(
    init: HandshakeInit,
    responder: IdentityKeyPair,
    initiator_dsa_pk: bytes,
) -> Tuple[HandshakeAccept, E2ESession]:
    """Responder verifies initiator ML-DSA-65 signature, encapsulates to ephemeral ML-KEM-768 key."""
    if init.responder_id != responder.identity_id:
        raise ValueError("Handshake intended for a different responder")
    eph_pk = b64decode_bytes(init.eph_kem_pk_b64)
    sig = b64decode_bytes(init.signature_b64)
    init_transcript = _handshake_init_transcript(init.session_id, init.initiator_id, init.responder_id, eph_pk)
    if not dsa_verify(initiator_dsa_pk, init_transcript, sig):
        raise ValueError("Initiator ML-DSA-65 signature verification failed")

    kem_ct, shared_secret = kem_encapsulate(eph_pk)
    accept_transcript = _handshake_accept_transcript(
        init.session_id, init.initiator_id, init.responder_id, eph_pk, kem_ct
    )
    accept_sig = dsa_sign(responder.dsa_sk, accept_transcript)
    accept = HandshakeAccept(
        session_id=init.session_id,
        initiator_id=init.initiator_id,
        responder_id=responder.identity_id,
        kem_ciphertext_b64=b64encode_str(kem_ct),
        signature_b64=b64encode_str(accept_sig),
    )
    chain_key = hkdf_sha256(
        shared_secret, 32, salt=init.session_id.encode("utf-8"), info=b"pqguard-e2e-chain-v1"
    )
    session = E2ESession(
        session_id=init.session_id,
        local_id=responder.identity_id,
        peer_id=init.initiator_id,
        chain_key=chain_key,
    )
    return accept, session


@dataclass(frozen=True)
class ResumptionResult:
    allowed: bool
    reason: str
    session_id: Optional[str] = None
    peer_id: Optional[str] = None


class SessionResumptionAuthority:
    """Issues and verifies identity-bound, policy-checked session resumption tickets."""

    def __init__(self, ticket_key: Optional[bytes] = None) -> None:
        self._ticket_key = ticket_key if ticket_key is not None else secrets.token_bytes(32)

    def issue_ticket(
        self,
        session_id: str,
        peer_id: str,
        peer_dsa_pk: bytes,
        ttl_seconds: float = 300.0,
        now: Optional[float] = None,
    ) -> str:
        ts = time.time() if now is None else now
        payload = {
            "session_id": session_id,
            "peer_id": peer_id,
            "peer_dsa_pk_sha256": sha256_hex(peer_dsa_pk),
            "issued_at": ts,
            "expires_at": ts + ttl_seconds,
        }
        pt = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        nonce, ct = aead_encrypt(self._ticket_key, pt, aad=b"pqguard-resumption-v1")
        return json.dumps({"n": b64encode_str(nonce), "c": b64encode_str(ct)}, separators=(",", ":"))

    def resume_session(
        self,
        ticket_str: str,
        claimed_session_id: str,
        caller_id: str,
        caller_dsa_pk: bytes,
        is_peer_authorized_fn: Optional[Callable[[str], bool]] = None,
        now: Optional[float] = None,
    ) -> ResumptionResult:
        ts = time.time() if now is None else now
        try:
            wrapper = json.loads(ticket_str)
            nonce = b64decode_bytes(wrapper["n"])
            ct = b64decode_bytes(wrapper["c"])
            pt = aead_decrypt(self._ticket_key, nonce, ct, aad=b"pqguard-resumption-v1")
            ticket = json.loads(pt.decode("utf-8"))
        except Exception:
            return ResumptionResult(allowed=False, reason="invalid_or_tampered_ticket")

        if ticket.get("session_id") != claimed_session_id:
            return ResumptionResult(allowed=False, reason="session_id_mismatch")
        if ts > float(ticket.get("expires_at", 0.0)):
            return ResumptionResult(allowed=False, reason="ticket_expired")
        if ticket.get("peer_id") != caller_id:
            return ResumptionResult(allowed=False, reason="peer_identity_mismatch")
        if ticket.get("peer_dsa_pk_sha256") != sha256_hex(caller_dsa_pk):
            return ResumptionResult(allowed=False, reason="peer_key_mismatch")
        if is_peer_authorized_fn is not None and not is_peer_authorized_fn(caller_id):
            return ResumptionResult(allowed=False, reason="peer_revoked_or_unauthorized")

        return ResumptionResult(
            allowed=True,
            reason="resumed",
            session_id=claimed_session_id,
            peer_id=caller_id,
        )
