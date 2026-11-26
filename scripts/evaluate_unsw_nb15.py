"""Independent evaluation of TRUSTGUARD PQ ContextAwareDetector on UNSW-NB15."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pqguard.detector import ALERT_LABELS, ContextAwareDetector
from pqguard.external_unsw_adapter import (
    CONTEXT_EVALUATABLE_IDENTITY,
    CONTEXT_INSUFFICIENT_IDENTITY,
    CONTEXT_OUT_OF_SCOPE_FLOW,
    ExternalRecord,
    load_unsw_nb15,
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _score_subset(records: list[ExternalRecord]) -> dict:
    if not records:
        return {
            "evaluated_count": 0,
            "confusion_matrix": None,
            "metrics": None,
            "reason": "No records in this context scope.",
        }
    events = [r.event for r in records]
    detector = ContextAwareDetector(approvals={})
    t0 = time.perf_counter()
    result = detector.analyze(events)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    preds = result["classifications"]
    tp = fp = fn = tn = 0
    pred_class_counts: Counter = Counter()

    for rec in records:
        gt_attack = rec.label == 1
        pred_label = preds[rec.event.event_id]
        pred_attack = pred_label in ALERT_LABELS
        pred_class_counts[pred_label] += 1

        if gt_attack and pred_attack:
            tp += 1
        elif not gt_attack and pred_attack:
            fp += 1
        elif gt_attack and not pred_attack:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "evaluated_count": len(records),
        "detector_predictions": dict(pred_class_counts),
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "metrics": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "false_positive_rate": round(fpr, 6),
            "false_alerts_per_1000_benign": round(fpr * 1000.0, 2),
            "total_analysis_time_ms": round(elapsed_ms, 2),
            "per_event_latency_ms": round(elapsed_ms / len(events), 6),
            "alerts_emitted": len(result["alerts"]),
        },
    }


def evaluate(csv_path: Path, limit: int | None = None) -> dict:
    file_hash = sha256_file(csv_path)
    records, stats = load_unsw_nb15(csv_path, limit=limit)

    cat_counts: Counter = Counter(r.attack_cat for r in records)
    context_counts: Counter = Counter(r.context_status for r in records)
    exclusion_reasons: Counter = Counter()
    for r in records:
        if r.context_status != CONTEXT_EVALUATABLE_IDENTITY:
            for reason in r.missing_context_reasons:
                exclusion_reasons[reason] += 1

    evaluatable = [r for r in records if r.context_status == CONTEXT_EVALUATABLE_IDENTITY]
    insufficient = [r for r in records if r.context_status == CONTEXT_INSUFFICIENT_IDENTITY]
    out_of_scope = [r for r in records if r.context_status == CONTEXT_OUT_OF_SCOPE_FLOW]

    return {
        "dataset": "UNSW-NB15 (UNSW_NB15_testing-set.csv)",
        "sha256": file_hash,
        "adapter_stats": {
            "total_rows": stats.total_rows,
            "mapped_rows": stats.mapped_rows,
            "rejected_rows": stats.rejected_rows,
            "duplicate_rows": stats.duplicate_rows,
        },
        "class_distribution": dict(cat_counts),
        "context_triage": {
            "evaluatable_identity": len(evaluatable),
            "insufficient_identity_context": len(insufficient),
            "out_of_scope_network_flow": len(out_of_scope),
            "context_counts": dict(context_counts),
            "exclusion_reason_counts": dict(exclusion_reasons),
        },
        "full_dataset_unfiltered": _score_subset(records),
        "context_aware_scoped": _score_subset(evaluatable),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("data/external/UNSW_NB15_testing-set.csv"),
        help="Path to UNSW_NB15_testing-set.csv",
    )
    parser.add_argument("--limit", type=int, default=None, help="Optional row limit for quick runs")
    args = parser.parse_args()
    summary = evaluate(args.csv, limit=args.limit)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
