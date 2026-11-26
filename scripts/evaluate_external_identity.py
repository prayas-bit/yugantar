"""Independent evaluation of TRUSTGUARD PQ ContextAwareDetector on OTRF Windows Security logs."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pqguard.detector import ContextAwareDetector
from pqguard.external_identity_adapter import CTX_EVALUATABLE, load_otrf_tar_gz


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            h.update(chunk)
    return h.hexdigest()


def evaluate(archive_path: Path, limit: int | None = None) -> dict:
    file_hash = sha256_file(archive_path)
    records, stats = load_otrf_tar_gz(archive_path, limit=limit)

    evaluatable = [r for r in records if r.context_status == CTX_EVALUATABLE]
    insufficient = [r for r in records if r.context_status != CTX_EVALUATABLE]

    exclusion_reasons: Counter = Counter()
    for r in insufficient:
        for reason in r.missing_reasons:
            exclusion_reasons[reason] += 1

    actor_counts: Counter = Counter(r.event.actor for r in evaluatable)
    eid_counts: Counter = Counter(r.winlog_event_id for r in evaluatable)

    detector = ContextAwareDetector(approvals={})
    events = [r.event for r in evaluatable]
    t0 = time.perf_counter()
    result = detector.analyze(events)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    preds = result["classifications"]
    pred_counts: Counter = Counter(preds.values())
    alert_actors: Counter = Counter(a.actor for a in result["alerts"])
    alert_categories: Counter = Counter(a.category for a in result["alerts"])

    return {
        "dataset": "OTRF Security-Datasets (MITRE ATT&CK Evals Round 1 APT3 Day 1)",
        "archive": str(archive_path),
        "sha256": file_hash,
        "ground_truth_available": False,
        "ground_truth_note": (
            "OTRF Caldera APT3 Day 1 contains unlabelled red-team + OS background telemetry "
            "without per-event benign/malicious labels or change-control approvals; "
            "TP/TN/FP/FN and F1 are therefore not measurable."
        ),
        "adapter_stats": {
            "total_raw_records": stats.total_raw_records,
            "non_security_channel_excluded": stats.non_security_channel_records,
            "security_channel_records": stats.security_channel_records,
            "duplicate_records_removed": stats.duplicate_records,
            "rejected_malformed_records": stats.rejected_malformed_records,
            "evaluatable_identity_records": stats.evaluatable_records,
            "insufficient_context_excluded": stats.insufficient_context_records,
            "insufficient_context_reasons": dict(exclusion_reasons),
        },
        "evaluatable_profile": {
            "top_actors": dict(actor_counts.most_common(10)),
            "top_winlog_event_ids": dict(eid_counts.most_common(10)),
            "privilege_indicator_events_4672_4673_4703": sum(1 for r in evaluatable if r.has_privilege_indicator),
        },
        "detector_execution": {
            "evaluated_count": len(events),
            "classifications": dict(pred_counts),
            "alerts_emitted": len(result["alerts"]),
            "alert_categories": dict(alert_categories),
            "alert_actors": dict(alert_actors.most_common(10)),
            "sample_alerts": [
                {
                    "alert_id": a.alert_id,
                    "category": a.category,
                    "actor": a.actor,
                    "rule": a.rule,
                    "event_count": len(a.event_ids),
                    "path": a.path,
                }
                for a in result["alerts"][:5]
            ],
            "total_analysis_time_ms": round(elapsed_ms, 2),
            "per_event_latency_ms": round(elapsed_ms / max(len(events), 1), 6),
        },
        "metrics": {
            "precision": None,
            "recall": None,
            "f1": None,
            "false_positive_rate": None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=Path(
            "data/external/otrf/datasets/compound/windows/apt3/"
            "caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz"
        ),
        help="Path to OTRF .tar.gz archive",
    )
    parser.add_argument("--limit", type=int, default=None, help="Optional raw record limit")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.archive, limit=args.limit), indent=2))


if __name__ == "__main__":
    main()
