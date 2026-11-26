"""Explainable rule- and graph-based detector for privilege escalation, lateral movement, and clock skew.

Covers:
- Goal 6: Routine vs. suspicious activity with change-control context (F1, TTA, FPR/1000)
- Goal 7: Multi-hop lateral movement detection across service edges
- Goal 8: Out-of-order delivery, source clock offset correction, and order-uncertainty flagging
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import statistics
import time
from typing import Any, Dict, List, Optional, Set, Tuple

DEFAULT_MAX_CLOCK_OFFSET_MS = 300_000  # +/- 5 minutes supported timing range
DEFAULT_CLOCK_UNCERTAINTY_MS = 500

# Expected service edges by role (explainable baseline policy)
DEFAULT_ALLOWED_EDGES: Dict[str, Set[Tuple[str, str]]] = {
    "viewer": {
        ("portal", "identity"),
        ("portal", "catalog"),
    },
    "report-reader": {
        ("portal", "identity"),
        ("portal", "catalog"),
        ("portal", "reports"),
        ("portal", "reports-node-a"),
        ("portal", "reports-node-b"),
    },
    "operator": {
        ("admin-console", "identity"),
        ("portal", "identity"),
        ("portal", "catalog"),
        ("portal", "reports"),
    },
    "service-reader": {
        ("reports", "catalog"),
    },
}


def parse_utc_ms(ts_str: str) -> datetime:
    """Parse ISO-8601 UTC timestamp string into aware datetime."""
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    return datetime.fromisoformat(ts_str).astimezone(timezone.utc)


def format_utc_ms(dt: datetime) -> str:
    """Format aware UTC datetime as ISO-8601 with millisecond precision."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class AccessEvent:
    receipt_index: int
    event_id: str
    event_time_utc: str
    received_time_utc: str
    source_clock_offset_ms: int
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str
    approval_id: str
    session_id: str
    correlation_id: str
    corrected_time: datetime = field(init=False)
    received_time: datetime = field(init=False)
    delivery_delay_ms: float = field(init=False)
    clock_offset_out_of_range: bool = field(init=False)
    order_uncertain: bool = False
    delayed_delivery: bool = False

    def __post_init__(self) -> None:
        raw_dt = parse_utc_ms(self.event_time_utc)
        self.received_time = parse_utc_ms(self.received_time_utc)
        self.corrected_time = raw_dt - timedelta(milliseconds=self.source_clock_offset_ms)
        self.delivery_delay_ms = (self.received_time - self.corrected_time).total_seconds() * 1000.0
        self.clock_offset_out_of_range = abs(self.source_clock_offset_ms) > DEFAULT_MAX_CLOCK_OFFSET_MS


@dataclass
class Alert:
    alert_id: str
    category: str  # "unexpected_role_change" | "review_after_role_change" | "lateral_movement"
    actor: str
    session_id: str
    correlation_id: str
    services: List[str]
    event_ids: List[str]
    rule: str
    path: str
    outcomes: List[str]
    explanation: str


@dataclass
class EvaluationMetrics:
    total_events: int
    benign_events: int
    suspicious_events: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    false_alerts_per_1000_benign: float
    median_time_to_alert_ms: float


def load_events_csv(path: Path) -> List[AccessEvent]:
    """Load events in receipt order without reading labels."""
    events: List[AccessEvent] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            events.append(
                AccessEvent(
                    receipt_index=idx,
                    event_id=row["event_id"],
                    event_time_utc=row["event_time_utc"],
                    received_time_utc=row["received_time_utc"],
                    source_clock_offset_ms=int(row["source_clock_offset_ms"]),
                    actor=row["actor"],
                    source_service=row["source_service"],
                    target_service=row["target_service"],
                    action=row["action"],
                    role_before=row["role_before"],
                    role_after=row["role_after"],
                    outcome=row["outcome"],
                    approval_id=row.get("approval_id", "") or "",
                    session_id=row["session_id"],
                    correlation_id=row["correlation_id"],
                )
            )
    return events


def load_approvals_json(path: Path) -> Dict[str, Dict[str, Any]]:
    """Load change-control approvals indexed by approval_id."""
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return {item["approval_id"]: item for item in data.get("changes", [])}


class ContextAwareDetector:
    """Deterministic, explainable detector for Track 4 access logs."""

    def __init__(
        self,
        approvals: Optional[Dict[str, Dict[str, Any]]] = None,
        allowed_edges: Optional[Dict[str, Set[Tuple[str, str]]]] = None,
        clock_uncertainty_ms: int = DEFAULT_CLOCK_UNCERTAINTY_MS,
        max_clock_offset_ms: int = DEFAULT_MAX_CLOCK_OFFSET_MS,
        lateral_window_seconds: float = 60.0,
    ) -> None:
        self.approvals = approvals or {}
        self.allowed_edges = allowed_edges or DEFAULT_ALLOWED_EDGES
        self.clock_uncertainty_ms = clock_uncertainty_ms
        self.max_clock_offset_ms = max_clock_offset_ms
        self.lateral_window_seconds = lateral_window_seconds

    def _is_approved_role_change(self, evt: AccessEvent) -> bool:
        if not evt.approval_id or evt.approval_id not in self.approvals:
            return False
        app = self.approvals[evt.approval_id]
        op = app.get("operation")
        if evt.action == "approve_role_change":
            return app.get("approved_by") == evt.actor
        if evt.action == "revoke_role":
            return app.get("approved_by") == evt.actor and op == "revoke_role"
        if op == "grant_role":
            if app.get("subject") != evt.actor or app.get("role") != evt.role_after:
                return False
            v_from = parse_utc_ms(app["valid_from_utc"])
            v_until = parse_utc_ms(app["valid_until_utc"])
            # valid_until_utc is exclusive per specification
            return v_from <= evt.corrected_time < v_until
        return False

    def _is_approved_access_scope(self, evt: AccessEvent) -> bool:
        if not evt.approval_id or evt.approval_id not in self.approvals:
            return False
        app = self.approvals[evt.approval_id]
        if app.get("subject") != evt.actor:
            return False
        if evt.target_service not in app.get("scope", []):
            return False
        if "valid_from_utc" in app and "valid_until_utc" in app:
            v_from = parse_utc_ms(app["valid_from_utc"])
            v_until = parse_utc_ms(app["valid_until_utc"])
            return v_from <= evt.corrected_time < v_until
        return False

    def _is_post_revocation_denial(self, evt: AccessEvent) -> bool:
        """Return True if evt is an expected denial on a recently revoked scope for this actor."""
        if evt.outcome != "deny":
            return False
        revoked_scopes: Set[str] = set()
        for app in self.approvals.values():
            if app.get("subject") == evt.actor and app.get("operation") == "grant_role":
                revoked_scopes.update(app.get("scope", []))
        if evt.target_service not in revoked_scopes:
            return False
        for app in self.approvals.values():
            if app.get("subject") == evt.actor and app.get("operation") == "revoke_role":
                eff = parse_utc_ms(app["effective_at_utc"])
                if evt.corrected_time >= eff:
                    return True
        return False

    def _is_expected_edge(self, evt: AccessEvent) -> bool:
        if self._is_approved_access_scope(evt):
            return True
        if self._is_post_revocation_denial(evt):
            return True
        role_edges = self.allowed_edges.get(evt.role_after, set())
        if (evt.source_service, evt.target_service) in role_edges:
            return True
        # Administration console actions by operators are expected
        if evt.source_service == "admin-console" and evt.target_service == "identity" and evt.action in {
            "approve_role_change",
            "revoke_role",
        }:
            return True
        return False

    def analyze(self, events: List[AccessEvent]) -> Dict[str, Any]:
        """Analyze events, preserving raw receipt order while sorting timelines by corrected time."""
        # Annotate clock range and out-of-order delivery
        max_corrected_seen: Optional[datetime] = None
        for evt in events:
            evt.clock_offset_out_of_range = abs(evt.source_clock_offset_ms) > self.max_clock_offset_ms
            if max_corrected_seen is not None and evt.corrected_time < max_corrected_seen:
                evt.delayed_delivery = True
            if max_corrected_seen is None or evt.corrected_time > max_corrected_seen:
                max_corrected_seen = evt.corrected_time

        timeline = sorted(events, key=lambda e: (e.corrected_time, e.receipt_index))

        # Check order uncertainty within each (actor, session_id)
        by_session: Dict[Tuple[str, str], List[AccessEvent]] = {}
        for evt in timeline:
            by_session.setdefault((evt.actor, evt.session_id), []).append(evt)
        for sess_events in by_session.values():
            for i in range(len(sess_events) - 1):
                delta_ms = (sess_events[i + 1].corrected_time - sess_events[i].corrected_time).total_seconds() * 1000.0
                if delta_ms < 2 * self.clock_uncertainty_ms:
                    sess_events[i].order_uncertain = True
                    sess_events[i + 1].order_uncertain = True

        event_classifications: Dict[str, str] = {}
        alerts: List[Alert] = []
        alert_counter = 0

        # Track unapproved role changes per (actor, session_id) regardless of action label
        tainted_sessions: Dict[Tuple[str, str], str] = {}
        for evt in timeline:
            role_before = evt.role_before.strip() if isinstance(evt.role_before, str) else ""
            role_after = evt.role_after.strip() if isinstance(evt.role_after, str) else ""
            if role_before and role_after and role_before != role_after:
                if self._is_approved_role_change(evt):
                    event_classifications[evt.event_id] = "approved_change"
                else:
                    event_classifications[evt.event_id] = "unexpected_role_change"
                    tainted_sessions[(evt.actor, evt.session_id)] = evt.event_id
                    alert_counter += 1
                    alerts.append(
                        Alert(
                            alert_id=f"alert-{alert_counter:04d}",
                            category="unexpected_role_change",
                            actor=evt.actor,
                            session_id=evt.session_id,
                            correlation_id=evt.correlation_id,
                            services=[evt.source_service, evt.target_service],
                            event_ids=[evt.event_id],
                            rule="unapproved_privilege_escalation",
                            path=f"{evt.source_service} -> {evt.target_service} ({role_before}->{role_after})",
                            outcomes=[evt.outcome],
                            explanation=(
                                f"Role change for {evt.actor} via action '{evt.action}' "
                                f"({role_before} -> {role_after}) has no matching valid approval "
                                f"in change-control context."
                            ),
                        )
                    )
            elif evt.action in {"approve_role_change", "revoke_role"} and self._is_approved_role_change(evt):
                event_classifications[evt.event_id] = "approved_change"
            elif (evt.actor, evt.session_id) in tainted_sessions and evt.outcome == "allow":
                event_classifications[evt.event_id] = "review_after_role_change"
                trigger_id = tainted_sessions[(evt.actor, evt.session_id)]
                alert_counter += 1
                alerts.append(
                    Alert(
                        alert_id=f"alert-{alert_counter:04d}",
                        category="review_after_role_change",
                        actor=evt.actor,
                        session_id=evt.session_id,
                        correlation_id=evt.correlation_id,
                        services=[evt.source_service, evt.target_service],
                        event_ids=[trigger_id, evt.event_id],
                        rule="access_following_unapproved_role_change",
                        path=f"{evt.source_service} -> {evt.target_service}",
                        outcomes=[evt.outcome],
                        explanation=(
                            f"Allowed {evt.action} on {evt.target_service} in {evt.session_id} "
                            f"follows unapproved role change {trigger_id}."
                        ),
                    )
                )

        # Group unexpected edges by (actor, session_id, correlation_id) for lateral movement
        by_flow: Dict[Tuple[str, str, str], List[AccessEvent]] = {}
        for evt in timeline:
            if evt.event_id in event_classifications:
                continue
            if not self._is_expected_edge(evt):
                by_flow.setdefault((evt.actor, evt.session_id, evt.correlation_id), []).append(evt)

        for (actor, sess_id, corr_id), flow_events in by_flow.items():
            if len(flow_events) >= 2:
                services: List[str] = []
                for fe in flow_events:
                    if not services or services[-1] != fe.source_service:
                        services.append(fe.source_service)
                    services.append(fe.target_service)
                path_str = " -> ".join(services)
                for fe in flow_events:
                    event_classifications[fe.event_id] = "lateral_movement_candidate"
                alert_counter += 1
                alerts.append(
                    Alert(
                        alert_id=f"alert-{alert_counter:04d}",
                        category="lateral_movement",
                        actor=actor,
                        session_id=sess_id,
                        correlation_id=corr_id,
                        services=services,
                        event_ids=[fe.event_id for fe in flow_events],
                        rule="multi_hop_unexpected_service_edges",
                        path=path_str,
                        outcomes=[fe.outcome for fe in flow_events],
                        explanation=(
                            f"{len(flow_events)} unexpected service edges by {actor} in {sess_id}/{corr_id}: "
                            f"{path_str} (outcomes={','.join(fe.outcome for fe in flow_events)})."
                        ),
                    )
                )

        # Secondary sliding-window correlation per actor to catch rotating correlation/session IDs
        by_actor_remaining: Dict[str, List[AccessEvent]] = {}
        for evt in timeline:
            if evt.event_id in event_classifications:
                continue
            if not self._is_expected_edge(evt):
                by_actor_remaining.setdefault(evt.actor, []).append(evt)

        for actor, actor_events in by_actor_remaining.items():
            # Partition actor's remaining unexpected edges into time-contiguous windows
            clusters: List[List[AccessEvent]] = []
            for evt in actor_events:
                if not clusters:
                    clusters.append([evt])
                else:
                    delta = (evt.corrected_time - clusters[-1][-1].corrected_time).total_seconds()
                    if delta <= self.lateral_window_seconds:
                        clusters[-1].append(evt)
                    else:
                        clusters.append([evt])

            for cluster in clusters:
                distinct_targets = {e.target_service for e in cluster}
                if len(cluster) >= 2 and len(distinct_targets) >= 2:
                    services: List[str] = []
                    for fe in cluster:
                        if not services or services[-1] != fe.source_service:
                            services.append(fe.source_service)
                        services.append(fe.target_service)
                    path_str = " -> ".join(services)
                    for fe in cluster:
                        event_classifications[fe.event_id] = "lateral_movement_candidate"
                    alert_counter += 1
                    alerts.append(
                        Alert(
                            alert_id=f"alert-{alert_counter:04d}",
                            category="lateral_movement",
                            actor=actor,
                            session_id=cluster[0].session_id,
                            correlation_id=cluster[0].correlation_id,
                            services=services,
                            event_ids=[fe.event_id for fe in cluster],
                            rule="sliding_window_unexpected_service_edges",
                            path=path_str,
                            outcomes=[fe.outcome for fe in cluster],
                            explanation=(
                                f"{len(cluster)} unexpected service edges by {actor} within "
                                f"{self.lateral_window_seconds}s window (across rotating correlation/session IDs): "
                                f"{path_str}."
                            ),
                        )
                    )
                else:
                    for fe in cluster:
                        event_classifications[fe.event_id] = "isolated_denial" if fe.outcome == "deny" else "routine"

        # Classify remaining benign events
        for evt in timeline:
            if evt.event_id not in event_classifications:
                if evt.outcome == "deny":
                    event_classifications[evt.event_id] = "routine_denial"
                elif evt.delayed_delivery:
                    event_classifications[evt.event_id] = "routine_delayed_delivery"
                elif evt.source_clock_offset_ms != 0:
                    event_classifications[evt.event_id] = "routine_clock_offset"
                else:
                    event_classifications[evt.event_id] = "routine"

        return {
            "classifications": event_classifications,
            "alerts": alerts,
            "timeline": timeline,
            "supported_clock_offset_range_ms": [-self.max_clock_offset_ms, self.max_clock_offset_ms],
            "clock_uncertainty_ms": self.clock_uncertainty_ms,
        }


ALERT_LABELS = {"unexpected_role_change", "review_after_role_change", "lateral_movement_candidate"}


def evaluate_against_labels(
    events: List[AccessEvent],
    labels_csv_path: Path,
    detector: ContextAwareDetector,
) -> EvaluationMetrics:
    """Evaluate detector F1, false alerts per 1,000 benign events, and median time to alert."""
    truth: Dict[str, str] = {}
    with labels_csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            truth[row["event_id"]] = row["label"]

    t0 = time.perf_counter()
    result = detector.analyze(events)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    per_event_latency_ms = elapsed_ms / max(len(events), 1)

    preds = result["classifications"]
    tp = fp = fn = tn = 0
    tta_samples_ms: List[float] = []

    for evt in events:
        gt_suspicious = truth[evt.event_id] in ALERT_LABELS
        pred_suspicious = preds[evt.event_id] in ALERT_LABELS
        if gt_suspicious and pred_suspicious:
            tp += 1
            tta_samples_ms.append(max(0.0, evt.delivery_delay_ms) + per_event_latency_ms)
        elif not gt_suspicious and pred_suspicious:
            fp += 1
        elif gt_suspicious and not pred_suspicious:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    benign_total = fp + tn
    fpr_per_1k = (fp / benign_total * 1000.0) if benign_total > 0 else 0.0
    median_tta = statistics.median(tta_samples_ms) if tta_samples_ms else 0.0

    return EvaluationMetrics(
        total_events=len(events),
        benign_events=benign_total,
        suspicious_events=tp + fn,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_alerts_per_1000_benign=fpr_per_1k,
        median_time_to_alert_ms=median_tta,
    )
