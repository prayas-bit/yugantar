"""Adapter converting OTRF Security-Datasets Windows Security ECS/Winlogbeat logs into AccessEvent.

Honesty & field-mapping contract:
- Source: OTRF/Security-Datasets (MITRE ATT&CK Evaluations Round 1 APT3 Day 1,
  caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz).
- Filters to Windows Security audit channel ("security" / "Security"); non-Security
  channels (Sysmon, PowerShell, System) are counted and excluded as out-of-scope.
- Preserves genuine @timestamp, actor (TargetUserName/SubjectUserName), host/service
  (computer_name, ServiceName, ShareName, IpAddress), and logon session IDs
  (TargetLogonId/SubjectLogonId).
- Never fabricates RBAC roles, change-control approvals, or per-event ground-truth labels.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tarfile
from typing import Dict, List, Optional, Set, Tuple

from pqguard.detector import AccessEvent

UNKNOWN_ACTOR = "unknown-actor"
UNKNOWN_SESSION = "unknown-session"
DEFAULT_WIN_ROLE = "windows-principal"

CTX_EVALUATABLE = "evaluatable_identity"
CTX_INSUFFICIENT = "insufficient_identity_context"
CTX_NON_SECURITY = "non_security_channel"


@dataclass(frozen=True)
class IdentityExternalRecord:
    event: AccessEvent
    winlog_event_id: int
    computer_name: str
    context_status: str
    missing_reasons: Tuple[str, ...]
    has_privilege_indicator: bool


@dataclass(frozen=True)
class IdentityAdapterStats:
    total_raw_records: int
    non_security_channel_records: int
    security_channel_records: int
    evaluatable_records: int
    insufficient_context_records: int
    rejected_malformed_records: int
    duplicate_records: int


def _clean_str(val: object) -> str:
    if not isinstance(val, str):
        return ""
    s = val.strip()
    return "" if s in ("", "-") else s


def _extract_actor(eid: int, ed: Dict[str, object]) -> str:
    # For logon/Kerberos events, TargetUserName is the authenticating identity.
    if eid in (4624, 4625, 4768, 4769, 4776):
        actor = _clean_str(ed.get("TargetUserName")) or _clean_str(ed.get("SubjectUserName"))
    else:
        actor = _clean_str(ed.get("SubjectUserName")) or _clean_str(ed.get("TargetUserName"))
    return actor or UNKNOWN_ACTOR


def _extract_session_id(ed: Dict[str, object]) -> str:
    for key in ("TargetLogonId", "SubjectLogonId"):
        val = _clean_str(ed.get(key))
        if val and val.lower() != "0x0":
            return val
    return UNKNOWN_SESSION


def parse_otrf_security_record(obj: object, receipt_index: int) -> Tuple[Optional[IdentityExternalRecord], str]:
    """Parse one ECS/Winlogbeat JSON object into IdentityExternalRecord or return skip/error reason."""
    if not isinstance(obj, dict):
        return None, "malformed_non_dict"

    winlog = obj.get("winlog")
    if not isinstance(winlog, dict):
        return None, "malformed_missing_winlog"

    channel = str(winlog.get("channel") or "").strip().lower()
    if channel != "security":
        return None, CTX_NON_SECURITY

    ts = _clean_str(obj.get("@timestamp"))
    raw_eid = winlog.get("event_id")
    if not ts or raw_eid is None:
        return None, "malformed_missing_ts_or_eid"
    try:
        eid = int(raw_eid)
    except (TypeError, ValueError):
        return None, "malformed_invalid_eid"

    ed = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
    host_obj = obj.get("host") if isinstance(obj.get("host"), dict) else {}
    computer_name = _clean_str(winlog.get("computer_name")) or _clean_str(host_obj.get("name")) or "unknown-host"

    actor = _extract_actor(eid, ed)
    session_id = _extract_session_id(ed)
    ip_addr = _clean_str(ed.get("IpAddress"))
    source_service = ip_addr if ip_addr else computer_name
    target_service = (
        _clean_str(ed.get("ShareName"))
        or _clean_str(ed.get("ServiceName"))
        or f"{computer_name}:eid-{eid}"
    )

    ev_outcome = ""
    if isinstance(obj.get("event"), dict):
        ev_outcome = str(obj["event"].get("outcome") or "").lower()
    outcome = "deny" if (eid == 4625 or ev_outcome == "failure") else "allow"

    reasons: List[str] = []
    if actor == UNKNOWN_ACTOR:
        reasons.append("missing_actor_identity")
    if session_id == UNKNOWN_SESSION:
        reasons.append("missing_session_id")
    if computer_name == "unknown-host":
        reasons.append("missing_host_name")

    ctx_status = CTX_INSUFFICIENT if reasons else CTX_EVALUATABLE

    try:
        event = AccessEvent(
            receipt_index=receipt_index,
            event_id=f"otrf-{receipt_index}-{eid}",
            event_time_utc=ts,
            received_time_utc=ts,
            source_clock_offset_ms=0,
            actor=actor,
            source_service=source_service,
            target_service=target_service,
            action=f"winlog:{eid}",
            role_before=DEFAULT_WIN_ROLE,
            role_after=DEFAULT_WIN_ROLE,
            outcome=outcome,
            approval_id="",
            session_id=session_id,
            correlation_id=f"{computer_name}:{session_id}",
        )
    except Exception:
        return None, "malformed_timestamp"

    return (
        IdentityExternalRecord(
            event=event,
            winlog_event_id=eid,
            computer_name=computer_name,
            context_status=ctx_status,
            missing_reasons=tuple(reasons),
            has_privilege_indicator=(eid in (4672, 4673, 4703)),
        ),
        "ok",
    )


def load_otrf_tar_gz(
    tar_gz_path: Path,
    limit: Optional[int] = None,
) -> Tuple[List[IdentityExternalRecord], IdentityAdapterStats]:
    """Load and triage Windows Security events from an OTRF .tar.gz JSONL archive."""
    if not tar_gz_path.is_file():
        raise FileNotFoundError(f"OTRF archive not found: {tar_gz_path}")

    records: List[IdentityExternalRecord] = []
    seen_sigs: Set[Tuple[str, str, int, str, str, str]] = set()

    total_raw = 0
    non_sec = 0
    sec_total = 0
    rejected = 0
    duplicates = 0
    evaluatable = 0
    insufficient = 0

    with tarfile.open(tar_gz_path, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isfile() and m.name.endswith(".json")]
        if not members:
            raise ValueError("No JSONL member found in OTRF archive")
        stream = tf.extractfile(members[0])
        if stream is None:
            raise ValueError("Unable to extract JSONL member from OTRF archive")

        for raw_line in stream:
            if limit is not None and total_raw >= limit:
                break
            total_raw += 1
            try:
                obj = json.loads(raw_line.decode("utf-8"))
            except Exception:
                rejected += 1
                continue

            rec, status = parse_otrf_security_record(obj, receipt_index=len(records) + 1)
            if rec is None:
                if status == CTX_NON_SECURITY:
                    non_sec += 1
                else:
                    rejected += 1
                continue

            sec_total += 1
            sig = (
                rec.event.event_time_utc,
                rec.event.actor,
                rec.winlog_event_id,
                rec.event.source_service,
                rec.event.target_service,
                rec.event.session_id,
            )
            if sig in seen_sigs:
                duplicates += 1
                continue
            seen_sigs.add(sig)

            if rec.context_status == CTX_EVALUATABLE:
                evaluatable += 1
            else:
                insufficient += 1
            records.append(rec)

    stats = IdentityAdapterStats(
        total_raw_records=total_raw,
        non_security_channel_records=non_sec,
        security_channel_records=sec_total,
        evaluatable_records=evaluatable,
        insufficient_context_records=insufficient,
        rejected_malformed_records=rejected,
        duplicate_records=duplicates,
    )
    return records, stats
