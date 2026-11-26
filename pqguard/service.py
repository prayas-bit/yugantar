"""Track 4 Adapter v1 service implementation (setup, read, revoke, audit, protected_read)."""

from __future__ import annotations

from pathlib import Path
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
from pqguard.storage import atomic_write_json, get_state_dir, read_json_or_default

STATE_FILENAME = "service_state.json"
AUDIT_LOG_FILENAME = "audit.jsonl"


def _state_path(state_dir: Path) -> Path:
    return state_dir / STATE_FILENAME


def _audit_log_path(state_dir: Path) -> Path:
    return state_dir / AUDIT_LOG_FILENAME


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

        log_pk, log_sk = dsa_generate_keypair()
        key_digest = sha256_hex(str(key_material).encode("utf-8"))

        # Reset audit log for a fresh setup in this state directory.
        audit_path = _audit_log_path(state_dir)
        if audit_path.exists():
            audit_path.unlink()

        state: Dict[str, Any] = {
            "owners": dict(owners),
            "contents": dict(contents),
            "disabled": sorted(set(str(a) for a in disabled)),
            "key_material_digest": key_digest,
            "decisions": {},
            "log_signing_pk_b64": b64encode_str(log_pk),
            "log_signing_sk_b64": b64encode_str(log_sk),
        }
        atomic_write_json(_state_path(state_dir), state)
        audit_log = TamperEvidentAuditLog(audit_path, signing_sk=log_sk)
        audit_log.append(
            actor="system",
            action="setup",
            outcome="success",
            details={"asset_count": len(owners), "disabled_count": len(state["disabled"])},
        )
        return {"ready": True}

    state = _load_state(state_dir)
    log_sk = b64decode_bytes(state["log_signing_sk_b64"])
    audit_log = TamperEvidentAuditLog(_audit_log_path(state_dir), signing_sk=log_sk)

    if op == "read":
        actor = str(request.get("actor", ""))
        asset = str(request.get("asset", ""))
        request_id = str(request.get("request_id", ""))
        allowed = _is_authorized(state, actor, asset) and asset in state.get("contents", {})
        decision = "allow" if allowed else "deny"

        if request_id:
            state.setdefault("decisions", {})[request_id] = decision
            atomic_write_json(_state_path(state_dir), state)

        audit_log.append(
            actor=actor,
            action="read",
            outcome=decision,
            request_id=request_id or None,
            details={"asset": asset},
        )
        if allowed:
            return {"decision": "allow", "body": state["contents"][asset]}
        return {"decision": "deny"}

    if op == "revoke":
        actor = str(request.get("actor", ""))
        if not actor:
            raise ValueError("Missing actor for revoke")
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
        request_id = str(request.get("request_id", ""))
        decision = state.get("decisions", {}).get(request_id)
        if decision not in ("allow", "deny"):
            rec = audit_log.find_by_request_id(request_id)
            decision = rec.get("outcome") if rec and rec.get("outcome") in ("allow", "deny") else "deny"
        return {"request_id": request_id, "decision": decision}

    if op == "protected_read":
        actor = str(request.get("actor", ""))
        asset = str(request.get("asset", ""))
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
