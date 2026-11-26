"""Tamper-evident hash-chained and ML-DSA-65 signed audit log."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pqguard.crypto import b64decode_bytes, b64encode_str, dsa_sign, dsa_verify, sha256_hex

GENESIS_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_body(record_body: Dict[str, Any]) -> bytes:
    return json.dumps(record_body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class LogVerificationResult:
    valid: bool
    checked_records: int
    failure_seq: Optional[int] = None
    reason: Optional[str] = None


class TamperEvidentAuditLog:
    """Append-only JSONL audit log with SHA-256 hash chaining and ML-DSA-65 signatures."""

    def __init__(self, log_path: Path, signing_sk: Optional[bytes] = None) -> None:
        self.log_path = log_path
        self._signing_sk = signing_sk
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_state(self) -> tuple[int, str]:
        if not self.log_path.is_file():
            return 0, GENESIS_HASH
        last_line = ""
        with self.log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return 0, GENESIS_HASH
        last_rec = json.loads(last_line)
        return int(last_rec["seq"]), str(last_rec["record_hash"])

    def append(
        self,
        actor: str,
        action: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append one canonicalized, hash-chained, ML-DSA-65-signed event."""
        if not isinstance(actor, str) or not isinstance(action, str) or not isinstance(outcome, str):
            raise ValueError("actor, action, and outcome must be strings")

        prev_seq, prev_hash = self._last_state()
        seq = prev_seq + 1
        body: Dict[str, Any] = {
            "seq": seq,
            "timestamp_utc": timestamp_utc or _utc_now_iso(),
            "actor": actor,
            "action": action,
            "outcome": outcome,
            "request_id": request_id,
            "details": details if details is not None else {},
            "prev_hash": prev_hash,
        }
        record_hash = sha256_hex(_canonical_body(body))
        record = dict(body)
        record["record_hash"] = record_hash
        if self._signing_sk is not None:
            sig = dsa_sign(self._signing_sk, record_hash.encode("ascii"))
            record["signature"] = b64encode_str(sig)

        line = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def read_all(self) -> List[Dict[str, Any]]:
        """Read all parsed records in order."""
        if not self.log_path.is_file():
            return []
        records: List[Dict[str, Any]] = []
        with self.log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))
        return records

    def find_by_request_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Return the latest record matching request_id, if any."""
        match: Optional[Dict[str, Any]] = None
        for rec in self.read_all():
            if rec.get("request_id") == request_id:
                match = rec
        return match


def verify_log(log_path: Path, signing_pk: Optional[bytes] = None) -> LogVerificationResult:
    """Verify hash-chain continuity, canonical hashes, and ML-DSA-65 signatures."""
    if not log_path.is_file():
        return LogVerificationResult(valid=True, checked_records=0)

    expected_seq = 1
    expected_prev_hash = GENESIS_HASH
    checked = 0

    with log_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except ValueError as exc:
                return LogVerificationResult(
                    valid=False,
                    checked_records=checked,
                    failure_seq=expected_seq,
                    reason=f"Malformed JSON record at sequence {expected_seq}: {exc}",
                )
            if not isinstance(rec, dict):
                return LogVerificationResult(
                    valid=False,
                    checked_records=checked,
                    failure_seq=expected_seq,
                    reason="Record is not a JSON object",
                )

            seq = rec.get("seq")
            if seq != expected_seq:
                return LogVerificationResult(
                    valid=False,
                    checked_records=checked,
                    failure_seq=expected_seq,
                    reason=f"Sequence mismatch: expected {expected_seq}, got {seq}",
                )

            if rec.get("prev_hash") != expected_prev_hash:
                return LogVerificationResult(
                    valid=False,
                    checked_records=checked,
                    failure_seq=seq,
                    reason=f"Hash chain broken at seq {seq}",
                )

            body_keys = ("seq", "timestamp_utc", "actor", "action", "outcome", "request_id", "details", "prev_hash")
            if any(k not in rec for k in body_keys):
                return LogVerificationResult(
                    valid=False,
                    checked_records=checked,
                    failure_seq=seq,
                    reason=f"Missing required fields at seq {seq}",
                )
            body = {k: rec[k] for k in body_keys}
            recomputed_hash = sha256_hex(_canonical_body(body))
            if rec.get("record_hash") != recomputed_hash:
                return LogVerificationResult(
                    valid=False,
                    checked_records=checked,
                    failure_seq=seq,
                    reason=f"Record hash mismatch at seq {seq}",
                )

            if signing_pk is not None:
                sig_b64 = rec.get("signature")
                if not isinstance(sig_b64, str):
                    return LogVerificationResult(
                        valid=False,
                        checked_records=checked,
                        failure_seq=seq,
                        reason=f"Missing ML-DSA-65 signature at seq {seq}",
                    )
                try:
                    sig_bytes = b64decode_bytes(sig_b64)
                except ValueError:
                    return LogVerificationResult(
                        valid=False,
                        checked_records=checked,
                        failure_seq=seq,
                        reason=f"Invalid Base64 signature at seq {seq}",
                    )
                if not dsa_verify(signing_pk, recomputed_hash.encode("ascii"), sig_bytes):
                    return LogVerificationResult(
                        valid=False,
                        checked_records=checked,
                        failure_seq=seq,
                        reason=f"ML-DSA-65 signature verification failed at seq {seq}",
                    )

            expected_prev_hash = recomputed_hash
            expected_seq += 1
            checked += 1

    return LogVerificationResult(valid=True, checked_records=checked)
