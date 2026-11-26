"""Track 4 Adapter v1 service implementation (setup, read, revoke, audit, protected_read)."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Any, Dict

from pqguard.audit_log import TamperEvidentAuditLog
from pqguard.crypto import (
    b64decode_bytes,
    b64encode_str,
    dsa_generate_keypair,
    hmac_sha256_hex,
    kem_encapsulate,
    sha256_hex,
)
from pqguard.storage import atomic_write_bytes, atomic_write_json, get_state_dir, read_json_or_default

STATE_FILENAME = "service_state.json"
AUDIT_LOG_FILENAME = "audit.jsonl"


def _state_path(state_dir: Path) -> Path:
    return state_dir / STATE_FILENAME


def _audit_log_path(state_dir: Path) -> Path:
    return state_dir / AUDIT_LOG_FILENAME


def _signing_key_path(state_dir: Path) -> Path:
    """Separate private signing key path (never stored inside service_state.json)."""
    override = os.environ.get("PQGUARD_LOG_SIGNING_KEY_PATH")
    if override:
        return Path(override)
    return state_dir / ".keys" / "audit_signing.key"


def _write_private_key(path: Path, key_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(path, b64encode_str(key_bytes).encode("ascii"))
    try:
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_private_key(state_dir: Path) -> bytes:
    key_path = _signing_key_path(state_dir)
    if not key_path.is_file():
        raise RuntimeError(
            "Audit signing private key missing; refusing to silently rotate signing identity."
        )
    return b64decode_bytes(key_path.read_text(encoding="ascii").strip())


def _load_state(state_dir: Path) -> Dict[str, Any]:
    state = read_json_or_default(_state_path(state_dir), None)
    if state is None:
        raise RuntimeError("Service is not initialized; run setup first.")
    return state


def _is_authorized(state: Dict[str, Any], actor: str, asset: str) -> bool:
    if not actor or not asset:
        return False
    if actor in state.get("disabled", []):
        return False
    return state.get("owners", {}).get(asset) == actor


def _require_valid_id(value: Any, field_name: str) -> str:
    """Strictly require a non-empty, non-whitespace string identifier without NUL bytes."""
    if not isinstance(value, str):
        raise ValueError(f"Invalid {field_name}: expected string, got {type(value).__name__}")
    if not value or not value.strip():
        raise ValueError(f"Invalid {field_name}: must not be empty or whitespace-only")
    if "\x00" in value:
        raise ValueError(f"Invalid {field_name}: NUL byte not permitted")
    return value


def dispatch(request: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch one Track 4 adapter v1 operation."""
    op = request.get("op")
    state_dir = get_state_dir()

    if op == "setup":
        owners = request.get("owners")
        contents = request.get("contents")
        disabled = request.get("disabled", [])
        key_material = request.get("key_material", "")
        if not isinstance(owners, dict) or not isinstance(contents, dict) or not isinstance(disabled, list):
            raise ValueError("Invalid setup payload")

        validated_owners: Dict[str, str] = {
            _require_valid_id(k, "owners.asset"): _require_valid_id(v, "owners.actor")
            for k, v in owners.items()
        }
        validated_contents: Dict[str, str] = {}
        for k, v in contents.items():
            asset_id = _require_valid_id(k, "contents.asset")
            if not isinstance(v, str):
                raise ValueError("Invalid contents value: expected string")
            validated_contents[asset_id] = v
        validated_disabled = sorted(set(_require_valid_id(a, "disabled.actor") for a in disabled))

        log_pk, log_sk = dsa_generate_keypair()
        key_digest = sha256_hex(str(key_material).encode("utf-8"))

        # Reset audit log for a fresh setup in this state directory.
        audit_path = _audit_log_path(state_dir)
        if audit_path.exists():
            audit_path.unlink()

        state: Dict[str, Any] = {
            "owners": validated_owners,
            "contents": validated_contents,
            "disabled": validated_disabled,
            "key_material_digest": key_digest,
            "decisions": {},
            "log_signing_pk_b64": b64encode_str(log_pk),
        }
        _write_private_key(_signing_key_path(state_dir), log_sk)
        atomic_write_json(_state_path(state_dir), state)
        audit_log = TamperEvidentAuditLog(audit_path, signing_sk=log_sk)
        audit_log.append(
            actor="system",
            action="setup",
            outcome="success",
            details={"asset_count": len(validated_owners), "disabled_count": len(state["disabled"])},
        )
        return {"ready": True}

    state = _load_state(state_dir)
    log_sk = _load_private_key(state_dir)
    audit_log = TamperEvidentAuditLog(_audit_log_path(state_dir), signing_sk=log_sk)

    if op == "read":
        actor = _require_valid_id(request.get("actor"), "actor")
        asset = _require_valid_id(request.get("asset"), "asset")
        request_id = _require_valid_id(request.get("request_id"), "request_id")
        allowed = _is_authorized(state, actor, asset) and asset in state.get("contents", {})
        decision = "allow" if allowed else "deny"

        state.setdefault("decisions", {})[request_id] = decision
        atomic_write_json(_state_path(state_dir), state)

        audit_log.append(
            actor=actor,
            action="read",
            outcome=decision,
            request_id=request_id,
            details={"asset": asset},
        )
        if allowed:
            return {"decision": "allow", "body": state["contents"][asset]}
        return {"decision": "deny"}

    if op == "revoke":
        actor = _require_valid_id(request.get("actor"), "actor")
        disabled = set(state.get("disabled", []))
        disabled.add(actor)
        state["disabled"] = sorted(disabled)
        atomic_write_json(_state_path(state_dir), state)
        audit_log.append(
            actor="system",
            action="revoke",
            outcome="success",
            details={"revoked_actor": actor},
        )
        return {"revoked": True, "actor": actor}

    if op == "audit":
        request_id = _require_valid_id(request.get("request_id"), "request_id")
        decision = state.get("decisions", {}).get(request_id)
        if decision not in ("allow", "deny"):
            rec = audit_log.find_by_request_id(request_id)
            decision = rec.get("outcome") if rec and rec.get("outcome") in ("allow", "deny") else "deny"
        return {"request_id": request_id, "decision": decision}

    if op == "protected_read":
        actor = _require_valid_id(request.get("actor"), "actor")
        asset = _require_valid_id(request.get("asset"), "asset")
        challenge = request.get("challenge", "")
        public_key_b64 = request.get("public_key", "")
        if not isinstance(challenge, str) or not isinstance(public_key_b64, str):
            raise ValueError("Invalid protected_read parameters")

        allowed = _is_authorized(state, actor, asset) and asset in state.get("contents", {})
        decision = "allow" if allowed else "deny"
        audit_log.append(
            actor=actor,
            action="protected_read",
            outcome=decision,
            details={"asset": asset},
        )
        if not allowed:
            return {"decision": "deny"}

        pk_bytes = b64decode_bytes(public_key_b64)
        ciphertext, shared_secret = kem_encapsulate(pk_bytes)
        body = state["contents"][asset]
        proof_input = (challenge + body).encode("utf-8")
        proof = hmac_sha256_hex(shared_secret, proof_input)
        return {
            "decision": "allow",
            "ciphertext": b64encode_str(ciphertext),
            "proof": proof,
        }

    raise ValueError(f"Unsupported operation: {op}")
