"""Adapter converting UNSW-NB15 network-flow CSV records into TRUSTGUARD PQ AccessEvent records.

Field mapping and honesty contract:
- UNSW-NB15 (UNSW_NB15_testing-set.csv) is a network-flow intrusion dataset, NOT an
  identity/RBAC access log.
- Mapped fields:
  * id -> event_id ("unsw-<id>")
  * proto -> source_service
  * service (or "proto:<proto>" when "-") -> target_service
  * state -> action ("flow:<state>") and heuristic outcome ("allow" vs "deny")
  * label ("0"/"1") and attack_cat -> ground-truth evaluation labels only (never passed to detector)
- Unavailable fields (explicitly marked, never fabricated as identity/privilege claims):
  * actor -> "unknown-flow-actor" (source IP is omitted in UNSW_NB15_testing-set.csv)
  * role_before / role_after -> "network-flow" (no RBAC roles exist; never fabricates escalation)
  * approval_id -> "" (no change-control context exists)
  * session_id -> "unsw-no-session"
  * correlation_id -> "unsw-<id>"
  * event_time_utc / received_time_utc -> anchored to 1970-01-01T00:00:00.000Z (timestamps omitted in CSV)
  * source_clock_offset_ms -> 0
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

from pqguard.detector import AccessEvent

REFERENCE_EPOCH_UTC = "1970-01-01T00:00:00.000Z"
ALLOW_FLOW_STATES = {"FIN", "CON", "ACC", "CLO"}
DENY_FLOW_STATES = {"RST", "REQ", "INT", "ECO", "PAR", "URN", "no"}


UNKNOWN_ACTOR_PLACEHOLDER = "unknown-flow-actor"
NETWORK_FLOW_ROLE_PLACEHOLDER = "network-flow"
NO_SESSION_PLACEHOLDER = "unsw-no-session"

CONTEXT_EVALUATABLE_IDENTITY = "evaluatable_identity"
CONTEXT_INSUFFICIENT_IDENTITY = "insufficient_identity_context"
CONTEXT_OUT_OF_SCOPE_FLOW = "out_of_scope_network_flow"


@dataclass(frozen=True)
class ExternalRecord:
    event: AccessEvent
    label: int  # 0 = Normal, 1 = Attack
    attack_cat: str
    context_status: str = CONTEXT_OUT_OF_SCOPE_FLOW
    missing_context_reasons: Tuple[str, ...] = ()


def classify_event_context(event: AccessEvent) -> Tuple[str, Tuple[str, ...]]:
    """Classify whether an AccessEvent has sufficient identity context for ContextAwareDetector."""
    reasons: List[str] = []
    actor = (event.actor or "").strip()
    role_b = (event.role_before or "").strip()
    role_a = (event.role_after or "").strip()

    if not actor or actor == UNKNOWN_ACTOR_PLACEHOLDER:
        reasons.append("missing_actor_identity")
    if not role_b or not role_a or (role_b == NETWORK_FLOW_ROLE_PLACEHOLDER and role_a == NETWORK_FLOW_ROLE_PLACEHOLDER):
        reasons.append("missing_rbac_roles")
    if event.event_time_utc == REFERENCE_EPOCH_UTC:
        reasons.append("missing_timestamps")
    if not event.session_id or event.session_id == NO_SESSION_PLACEHOLDER:
        reasons.append("missing_session_id")

    if role_b == NETWORK_FLOW_ROLE_PLACEHOLDER and actor == UNKNOWN_ACTOR_PLACEHOLDER:
        return CONTEXT_OUT_OF_SCOPE_FLOW, tuple(reasons)
    if reasons:
        return CONTEXT_INSUFFICIENT_IDENTITY, tuple(reasons)
    return CONTEXT_EVALUATABLE_IDENTITY, ()


@dataclass(frozen=True)
class AdapterStats:
    total_rows: int
    mapped_rows: int
    rejected_rows: int
    duplicate_rows: int


def _map_flow_outcome(state: str) -> str:
    if state in ALLOW_FLOW_STATES:
        return "allow"
    if state in DENY_FLOW_STATES:
        return "deny"
    return "deny"


def load_unsw_nb15(
    csv_path: Path,
    limit: int | None = None,
) -> Tuple[List[ExternalRecord], AdapterStats]:
    """Load and validate UNSW-NB15 CSV rows into ExternalRecord objects."""
    if not csv_path.is_file():
        raise FileNotFoundError(f"UNSW-NB15 CSV not found: {csv_path}")

    records: List[ExternalRecord] = []
    seen_ids: Set[str] = set()
    seen_feature_sigs: Set[Tuple[str, ...]] = set()
    total_rows = 0
    rejected_rows = 0
    duplicate_rows = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required_cols = {"id", "proto", "service", "state", "attack_cat", "label"}
        if reader.fieldnames is None or not required_cols.issubset(set(reader.fieldnames)):
            raise ValueError(f"Missing required UNSW-NB15 columns: {required_cols}")

        for row in reader:
            if limit is not None and total_rows >= limit:
                break
            total_rows += 1

            raw_id = (row.get("id") or "").strip()
            proto = (row.get("proto") or "").strip()
            service = (row.get("service") or "").strip()
            state = (row.get("state") or "").strip()
            attack_cat = (row.get("attack_cat") or "").strip()
            raw_label = (row.get("label") or "").strip()

            if not raw_id or not proto or not state or raw_label not in {"0", "1"}:
                rejected_rows += 1
                continue
            try:
                int(raw_id)
            except ValueError:
                rejected_rows += 1
                continue

            if raw_id in seen_ids:
                duplicate_rows += 1
                continue
            feature_sig = tuple((row.get(k) or "").strip() for k in reader.fieldnames if k != "id")
            if feature_sig in seen_feature_sigs:
                duplicate_rows += 1
                continue

            seen_ids.add(raw_id)
            seen_feature_sigs.add(feature_sig)

            target_service = service if service and service != "-" else f"proto:{proto}"
            event = AccessEvent(
                receipt_index=len(records) + 1,
                event_id=f"unsw-{raw_id}",
                event_time_utc=REFERENCE_EPOCH_UTC,
                received_time_utc=REFERENCE_EPOCH_UTC,
                source_clock_offset_ms=0,
                actor=UNKNOWN_ACTOR_PLACEHOLDER,
                source_service=proto,
                target_service=target_service,
                action=f"flow:{state}",
                role_before=NETWORK_FLOW_ROLE_PLACEHOLDER,
                role_after=NETWORK_FLOW_ROLE_PLACEHOLDER,
                outcome=_map_flow_outcome(state),
                approval_id="",
                session_id=NO_SESSION_PLACEHOLDER,
                correlation_id=f"unsw-{raw_id}",
            )
            ctx_status, ctx_reasons = classify_event_context(event)
            records.append(
                ExternalRecord(
                    event=event,
                    label=int(raw_label),
                    attack_cat=attack_cat or "Unknown",
                    context_status=ctx_status,
                    missing_context_reasons=ctx_reasons,
                )
            )

    stats = AdapterStats(
        total_rows=total_rows,
        mapped_rows=len(records),
        rejected_rows=rejected_rows,
        duplicate_rows=duplicate_rows,
    )
    return records, stats
