"""Versioned key lifecycle, crash-safe rotation, device enrollment, and revocation store."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from pqguard.audit_log import TamperEvidentAuditLog
from pqguard.crypto import (
    b64decode_bytes,
    b64encode_str,
    dsa_generate_keypair,
    kem_generate_keypair,
    sha256_hex,
)
from pqguard.storage import atomic_write_bytes, atomic_write_json, read_json_or_default

KEYSTORE_FILE = "keystore_state.json"
PENDING_ROTATION_FILE = "pending_rotation.json"


@dataclass
class KeyVersionRecord:
    version: int
    key_id: str
    algorithm: str
    public_key_b64: str
    secret_key_b64: str
    created_at: float
    activated_at: float
    cutoff_at: Optional[float]  # Old key rejected strictly after cutoff_at
    status: str  # "active" | "grace" | "retired" | "revoked"


@dataclass
class DeviceRecord:
    device_id: str
    actor: str
    kem_pk_b64: str
    dsa_pk_b64: str
    enrolled_at: float
    status: str  # "active" | "revoked"
    revoked_at: Optional[float] = None


class KeyStore:
    """Crash-safe key lifecycle and identity/device store."""

    def __init__(
        self,
        state_dir: Path,
        grace_period_seconds: float = 0.0,
        log_signing_sk: Optional[bytes] = None,
        log_signing_pk: Optional[bytes] = None,
        key_dir: Optional[Path] = None,
    ) -> None:
        if grace_period_seconds < 0:
            raise ValueError("grace_period_seconds must be non-negative")
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.grace_period_seconds = grace_period_seconds
        self.state_path = self.state_dir / KEYSTORE_FILE
        self.pending_path = self.state_dir / PENDING_ROTATION_FILE
        self._key_dir = key_dir or (self.state_dir.parent / f".{self.state_dir.name}-keys")
        self._signing_key_path = self._key_dir / "keystore_audit_signing.key"
        self._log_signing_sk: Optional[bytes] = log_signing_sk
        self._external_log_signing_pk: Optional[bytes] = log_signing_pk
        self._last_wal_reconcile: Dict[str, Any] = {"had_pending": False, "malformed_wal": False}
        self.state = self._load_or_init()
        if self.pending_path.is_file():
            self._last_wal_reconcile = self._reconcile_pending_wal()

    def _write_signing_key(self, sk: bytes) -> None:
        self._key_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(self._signing_key_path, b64encode_str(sk).encode("ascii"))
        try:
            os.chmod(self._key_dir, 0o700)
            os.chmod(self._signing_key_path, 0o600)
        except OSError:
            pass

    def _load_or_init(self) -> Dict[str, Any]:
        # Load committed state without silently discarding pending_rotation.json;
        # WAL reconciliation and audit logging happen once signing keys are available.
        existing = read_json_or_default(self.state_path, None)
        if existing is not None:
            # Migrate legacy plaintext log_signing_sk_b64 out of state file if present.
            if "log_signing_sk_b64" in existing:
                legacy_sk = b64decode_bytes(existing.pop("log_signing_sk_b64"))
                if self._log_signing_sk is None:
                    self._log_signing_sk = legacy_sk
                    self._write_signing_key(legacy_sk)
                atomic_write_json(self.state_path, existing)
            elif self._log_signing_sk is None:
                if not self._signing_key_path.is_file():
                    raise RuntimeError(
                        "Keystore audit signing private key missing; refusing to silently rotate signing identity."
                    )
                self._log_signing_sk = b64decode_bytes(
                    self._signing_key_path.read_text(encoding="ascii").strip()
                )
            return existing

        if self._log_signing_sk is not None and self._external_log_signing_pk is not None:
            log_pk, log_sk = self._external_log_signing_pk, self._log_signing_sk
        else:
            log_pk, log_sk = dsa_generate_keypair()
            self._log_signing_sk = log_sk
            self._write_signing_key(log_sk)

        kem_pk, kem_sk = kem_generate_keypair()
        now = time.time()
        v1 = KeyVersionRecord(
            version=1,
            key_id=f"k-v1-{sha256_hex(kem_pk)[:12]}",
            algorithm="ML-KEM-768",
            public_key_b64=b64encode_str(kem_pk),
            secret_key_b64=b64encode_str(kem_sk),
            created_at=now,
            activated_at=now,
            cutoff_at=None,
            status="active",
        )
        state: Dict[str, Any] = {
            "active_version": 1,
            "revocation_epoch": 0,
            "grace_period_seconds": self.grace_period_seconds,
            "key_versions": {"1": asdict(v1)},
            "revoked_versions": [],
            "revoked_actors": [],
            "devices": {},
            "log_signing_pk_b64": b64encode_str(log_pk),
        }
        atomic_write_json(self.state_path, state)
        self.state = state
        self.audit_log.append(
            actor="system",
            action="keystore_init",
            outcome="success",
            details={"active_version": 1, "grace_period_seconds": self.grace_period_seconds},
        )
        return state

    @property
    def audit_log(self) -> TamperEvidentAuditLog:
        return TamperEvidentAuditLog(self.state_dir / "keystore_audit.jsonl", signing_sk=self._log_signing_sk)

    @property
    def log_signing_pk(self) -> bytes:
        if self._external_log_signing_pk is not None:
            return self._external_log_signing_pk
        return b64decode_bytes(self.state["log_signing_pk_b64"])

    def _save(self) -> None:
        atomic_write_json(self.state_path, self.state)

    def active_version(self) -> int:
        return int(self.state["active_version"])

    def get_key_record(self, version: int) -> Optional[KeyVersionRecord]:
        raw = self.state["key_versions"].get(str(version))
        if raw is None:
            return None
        return KeyVersionRecord(**raw)

    def is_key_version_accepted(self, version: int, now: Optional[float] = None) -> Tuple[bool, str]:
        """Check whether a key version is currently accepted under rotation & revocation rules."""
        ts = time.time() if now is None else now
        if version in self.state.get("revoked_versions", []):
            return False, "key_version_revoked"
        rec = self.get_key_record(version)
        if rec is None:
            return False, "unknown_key_version"
        if rec.status == "revoked":
            return False, "key_version_revoked"
        if rec.status == "retired":
            return False, "key_version_retired"
        if rec.status == "active":
            return True, "active"
        if rec.status == "grace":
            if rec.cutoff_at is not None and ts <= rec.cutoff_at:
                return True, "within_grace_period"
            return False, "past_rotation_cutoff"
        return False, "invalid_key_status"

    def rotate_key(
        self,
        actor: str = "system",
        grace_period_seconds: Optional[float] = None,
        simulate_crash_before_commit: bool = False,
        now: Optional[float] = None,
    ) -> int:
        """Rotate to a new ML-KEM-768 key version with atomic WAL staging."""
        ts = time.time() if now is None else now
        grace = self.grace_period_seconds if grace_period_seconds is None else grace_period_seconds
        if grace < 0:
            raise ValueError("grace_period_seconds must be non-negative")

        current_ver = self.active_version()
        new_ver = max(int(k) for k in self.state["key_versions"].keys()) + 1
        kem_pk, kem_sk = kem_generate_keypair()
        new_rec = KeyVersionRecord(
            version=new_ver,
            key_id=f"k-v{new_ver}-{sha256_hex(kem_pk)[:12]}",
            algorithm="ML-KEM-768",
            public_key_b64=b64encode_str(kem_pk),
            secret_key_b64=b64encode_str(kem_sk),
            created_at=ts,
            activated_at=ts,
            cutoff_at=None,
            status="active",
        )

        # Stage pending rotation before committing
        atomic_write_json(
            self.pending_path,
            {"from_version": current_ver, "to_version": new_ver, "staged_at": ts},
        )
        if simulate_crash_before_commit:
            raise RuntimeError("Simulated crash during key rotation before commit")

        old_raw = self.state["key_versions"][str(current_ver)]
        if old_raw["status"] != "revoked":
            old_raw["cutoff_at"] = ts + grace
            old_raw["status"] = "grace" if grace > 0 else "retired"

        self.state["key_versions"][str(new_ver)] = asdict(new_rec)
        self.state["active_version"] = new_ver
        self._save()
        self.pending_path.unlink(missing_ok=True)

        self.audit_log.append(
            actor=actor,
            action="key_rotate",
            outcome="success",
            details={
                "from_version": current_ver,
                "to_version": new_ver,
                "grace_period_seconds": grace,
                "cutoff_at": old_raw["cutoff_at"],
            },
        )
        return new_ver

    def _reconcile_pending_wal(self) -> Dict[str, Any]:
        """Inspect pending WAL, record recovery outcome in audit log BEFORE unlinking, and clean up idempotently."""
        if not self.pending_path.is_file():
            return {"had_pending": False, "malformed_wal": False}

        malformed = False
        wal_details: Dict[str, Any] = {}
        try:
            raw_text = self.pending_path.read_text(encoding="utf-8", errors="replace")
            parsed = json.loads(raw_text)
            if not isinstance(parsed, dict):
                raise ValueError("WAL record is not a JSON object")
            wal_details = {
                "from_version": parsed.get("from_version"),
                "to_version": parsed.get("to_version"),
                "staged_at": parsed.get("staged_at"),
            }
        except Exception as exc:
            malformed = True
            wal_details = {"error": str(exc), "malformed_wal": True}

        outcome = "malformed_wal_discarded" if malformed else "rolled_back"
        try:
            self.audit_log.append(
                actor="system",
                action="wal_recovery",
                outcome=outcome,
                details=wal_details,
            )
        finally:
            self.pending_path.unlink(missing_ok=True)

        return {"had_pending": True, "malformed_wal": malformed, "details": wal_details}

    def recover_after_crash(self) -> Dict[str, Any]:
        """Recover consistent state after an interrupted rotation or restart."""
        wal_info = self._reconcile_pending_wal()
        had_pending = wal_info["had_pending"] or self._last_wal_reconcile.get("had_pending", False)
        malformed_wal = wal_info["malformed_wal"] or self._last_wal_reconcile.get("malformed_wal", False)
        self._last_wal_reconcile = {"had_pending": False, "malformed_wal": False}
        self.state = read_json_or_default(self.state_path, self.state)

        # Ensure monotonicity: every version in revoked_versions stays revoked.
        revoked_set = set(self.state.get("revoked_versions", []))
        for ver_str, raw in self.state["key_versions"].items():
            if int(ver_str) in revoked_set:
                raw["status"] = "revoked"

        # If active_version somehow points to a revoked version, fail closed or fall back to highest non-revoked
        active_ver = int(self.state["active_version"])
        if active_ver in revoked_set:
            candidates = [
                int(v)
                for v, raw in self.state["key_versions"].items()
                if int(v) not in revoked_set and raw.get("status") in ("active", "grace")
            ]
            if not candidates:
                raise RuntimeError("No unrevoked authorized key version available")
            active_ver = max(candidates)
            self.state["active_version"] = active_ver
            self.state["key_versions"][str(active_ver)]["status"] = "active"

        self._save()
        self.audit_log.append(
            actor="system",
            action="crash_recovery",
            outcome="success",
            details={
                "rolled_back_pending_rotation": had_pending,
                "malformed_wal": malformed_wal,
                "recovered_active_version": active_ver,
                "revoked_versions": sorted(revoked_set),
            },
        )
        return {
            "rolled_back_pending_rotation": had_pending,
            "malformed_wal": malformed_wal,
            "active_version": active_ver,
            "revoked_versions": sorted(revoked_set),
        }

    def enroll_device(self, actor: str, device_id: str, now: Optional[float] = None) -> Tuple[DeviceRecord, bytes, bytes]:
        """Enroll a new device for an actor with fresh ML-KEM-768 and ML-DSA-65 keypairs."""
        ts = time.time() if now is None else now
        kem_pk, kem_sk = kem_generate_keypair()
        dsa_pk, dsa_sk = dsa_generate_keypair()
        dev = DeviceRecord(
            device_id=device_id,
            actor=actor,
            kem_pk_b64=b64encode_str(kem_pk),
            dsa_pk_b64=b64encode_str(dsa_pk),
            enrolled_at=ts,
            status="active",
        )
        self.state["devices"][device_id] = asdict(dev)
        # Re-enrolling clears actor-level lockout only if explicitly re-enrolled with a new device
        if actor in self.state.get("revoked_actors", []):
            self.state["revoked_actors"] = [a for a in self.state["revoked_actors"] if a != actor]
        self.state["revocation_epoch"] = int(self.state.get("revocation_epoch", 0)) + 1
        self._save()
        self.audit_log.append(
            actor=actor,
            action="device_enroll",
            outcome="success",
            details={"device_id": device_id},
        )
        return dev, kem_sk, dsa_sk

    def revoke_device(self, device_id: str, operator: str = "system", now: Optional[float] = None) -> int:
        """Revoke a lost/compromised device and bump revocation epoch."""
        ts = time.time() if now is None else now
        dev = self.state["devices"].get(device_id)
        if dev is None:
            raise ValueError(f"Unknown device_id: {device_id}")
        dev["status"] = "revoked"
        dev["revoked_at"] = ts
        self.state["revocation_epoch"] = int(self.state.get("revocation_epoch", 0)) + 1
        self._save()
        self.audit_log.append(
            actor=operator,
            action="device_revoke",
            outcome="success",
            details={"device_id": device_id, "owner": dev["actor"], "epoch": self.state["revocation_epoch"]},
        )
        return int(self.state["revocation_epoch"])

    def revoke_key_version(self, version: int, operator: str = "system") -> int:
        """Permanently revoke a key version."""
        raw = self.state["key_versions"].get(str(version))
        if raw is None:
            raise ValueError(f"Unknown key version: {version}")
        raw["status"] = "revoked"
        revoked = set(self.state.get("revoked_versions", []))
        revoked.add(version)
        self.state["revoked_versions"] = sorted(revoked)
        self.state["revocation_epoch"] = int(self.state.get("revocation_epoch", 0)) + 1
        self._save()
        self.audit_log.append(
            actor=operator,
            action="key_revoke",
            outcome="success",
            details={"version": version, "epoch": self.state["revocation_epoch"]},
        )
        return int(self.state["revocation_epoch"])

    def is_device_authorized(self, actor: str, device_id: str) -> Tuple[bool, str]:
        if actor in self.state.get("revoked_actors", []):
            return False, "actor_revoked"
        dev = self.state["devices"].get(device_id)
        if dev is None:
            return False, "unknown_device"
        if dev["actor"] != actor:
            return False, "device_owner_mismatch"
        if dev["status"] != "active":
            return False, "device_revoked"
        return True, "authorized"
