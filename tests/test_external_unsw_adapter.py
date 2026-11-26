"""Unit tests for the UNSW-NB15 external dataset adapter."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pqguard.detector import AccessEvent
from pqguard.external_unsw_adapter import (
    CONTEXT_EVALUATABLE_IDENTITY,
    CONTEXT_INSUFFICIENT_IDENTITY,
    CONTEXT_OUT_OF_SCOPE_FLOW,
    REFERENCE_EPOCH_UTC,
    classify_event_context,
    load_unsw_nb15,
)

HEADER = "id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,rate,attack_cat,label\n"


class TestExternalUNSWAdapter(unittest.TestCase):
    def test_valid_mapping_with_bom_and_non_fabrication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "unsw.csv"
            content = (
                "\ufeff" + HEADER
                + "1,0.001,tcp,http,FIN,10,8,1000,2000,500.0,Normal,0\n"
                + "2,0.002,udp,-,INT,2,0,496,0,90909.0,Generic,1\n"
            )
            csv_path.write_text(content, encoding="utf-8")

            records, stats = load_unsw_nb15(csv_path)
            self.assertEqual(stats.total_rows, 2)
            self.assertEqual(stats.mapped_rows, 2)
            self.assertEqual(stats.rejected_rows, 0)
            self.assertEqual(stats.duplicate_rows, 0)

            r0, r1 = records
            self.assertEqual(r0.event.event_id, "unsw-1")
            self.assertEqual(r0.event.source_service, "tcp")
            self.assertEqual(r0.event.target_service, "http")
            self.assertEqual(r0.event.outcome, "allow")
            self.assertEqual(r0.event.actor, "unknown-flow-actor")
            self.assertEqual(r0.event.role_before, "network-flow")
            self.assertEqual(r0.event.role_after, "network-flow")
            self.assertEqual(r0.event.approval_id, "")
            self.assertEqual(r0.event.event_time_utc, REFERENCE_EPOCH_UTC)
            self.assertEqual(r0.label, 0)

            self.assertEqual(r1.event.target_service, "proto:udp")
            self.assertEqual(r1.event.outcome, "deny")
            self.assertEqual(r1.label, 1)
            self.assertEqual(r1.attack_cat, "Generic")

    def test_rejects_malformed_and_deduplicates_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "unsw_bad.csv"
            content = (
                HEADER
                + "1,0.001,tcp,http,FIN,10,8,1000,2000,500.0,Normal,0\n"
                + "1,0.001,tcp,http,FIN,10,8,1000,2000,500.0,Normal,0\n"  # duplicate id
                + "2,0.001,tcp,http,FIN,10,8,1000,2000,500.0,Normal,0\n"  # duplicate features
                + "abc,0.001,tcp,http,FIN,10,8,1000,2000,500.0,Normal,0\n"  # non-int id
                + "3,0.001,,http,FIN,10,8,1000,2000,500.0,Normal,0\n"  # missing proto
                + "4,0.001,tcp,http,FIN,10,8,1000,2000,500.0,Normal,9\n"  # invalid label
            )
            csv_path.write_text(content, encoding="utf-8")

            records, stats = load_unsw_nb15(csv_path)
            self.assertEqual(stats.total_rows, 6)
            self.assertEqual(stats.mapped_rows, 1)
            self.assertEqual(stats.duplicate_rows, 2)
            self.assertEqual(stats.rejected_rows, 3)
            self.assertEqual(len(records), 1)

    def test_missing_required_columns_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "bad_cols.csv"
            csv_path.write_text("id,proto\n1,tcp\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_unsw_nb15(csv_path)

    def test_context_classification_missing_identity_and_unknown_actor(self) -> None:
        # 1. Out-of-scope network flow (unknown actor + network-flow role)
        flow_evt = AccessEvent(
            1, "e1", REFERENCE_EPOCH_UTC, REFERENCE_EPOCH_UTC, 0,
            "unknown-flow-actor", "tcp", "http", "flow:FIN", "network-flow", "network-flow",
            "allow", "", "unsw-no-session", "unsw-1",
        )
        status1, reasons1 = classify_event_context(flow_evt)
        self.assertEqual(status1, CONTEXT_OUT_OF_SCOPE_FLOW)
        self.assertIn("missing_actor_identity", reasons1)
        self.assertIn("missing_rbac_roles", reasons1)

        # 2. Insufficient identity context (real actor, but missing role/timestamp/session)
        partial_evt = AccessEvent(
            2, "e2", REFERENCE_EPOCH_UTC, REFERENCE_EPOCH_UTC, 0,
            "user-alex", "portal", "catalog", "read", "", "",
            "allow", "", "", "c-1",
        )
        status2, reasons2 = classify_event_context(partial_evt)
        self.assertEqual(status2, CONTEXT_INSUFFICIENT_IDENTITY)
        self.assertIn("missing_rbac_roles", reasons2)
        self.assertIn("missing_timestamps", reasons2)

        # 3. Evaluatable identity event
        id_evt = AccessEvent(
            3, "e3", "2026-01-15T09:00:00.000Z", "2026-01-15T09:00:00.100Z", 0,
            "user-alex", "portal", "catalog", "read", "viewer", "viewer",
            "allow", "", "sess-alex", "flow-1",
        )
        status3, reasons3 = classify_event_context(id_evt)
        self.assertEqual(status3, CONTEXT_EVALUATABLE_IDENTITY)
        self.assertEqual(reasons3, ())


if __name__ == "__main__":
    unittest.main()
