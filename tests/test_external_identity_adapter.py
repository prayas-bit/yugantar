"""Unit and evaluation tests for the OTRF Windows Security external identity adapter."""

from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from pqguard.external_identity_adapter import (
    CTX_EVALUATABLE,
    CTX_INSUFFICIENT,
    CTX_NON_SECURITY,
    DEFAULT_WIN_ROLE,
    load_otrf_tar_gz,
    parse_otrf_security_record,
)
from scripts.evaluate_external_identity import evaluate


class TestExternalIdentityAdapter(unittest.TestCase):
    def test_parses_valid_security_event_preserving_identity_and_session(self) -> None:
        raw = {
            "@timestamp": "2019-10-20T20:11:38.938Z",
            "winlog": {
                "channel": "Security",
                "event_id": 4769,
                "computer_name": "HFDC01.shire.com",
                "event_data": {
                    "TargetUserName": "pgustavo@SHIRE.COM",
                    "ServiceName": "HFDC01$",
                    "IpAddress": "::ffff:172.18.39.105",
                    "TargetLogonId": "0x637923",
                },
            },
        }
        rec, status = parse_otrf_security_record(raw, receipt_index=1)
        self.assertEqual(status, "ok")
        assert rec is not None
        self.assertEqual(rec.context_status, CTX_EVALUATABLE)
        self.assertEqual(rec.event.actor, "pgustavo@SHIRE.COM")
        self.assertEqual(rec.event.source_service, "::ffff:172.18.39.105")
        self.assertEqual(rec.event.target_service, "HFDC01$")
        self.assertEqual(rec.event.session_id, "0x637923")
        self.assertEqual(rec.event.role_before, DEFAULT_WIN_ROLE)
        self.assertEqual(rec.event.role_after, DEFAULT_WIN_ROLE)
        self.assertEqual(rec.event.approval_id, "")

    def test_excludes_non_security_and_flags_missing_context(self) -> None:
        sysmon = {"@timestamp": "2019-10-20T20:11:00.000Z", "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1}}
        rec_sys, st_sys = parse_otrf_security_record(sysmon, 1)
        self.assertIsNone(rec_sys)
        self.assertEqual(st_sys, CTX_NON_SECURITY)

        fw = {
            "@timestamp": "2019-10-20T20:11:00.000Z",
            "winlog": {
                "channel": "Security",
                "event_id": 5156,
                "computer_name": "WECServer",
                "event_data": {"SubjectUserName": "-", "SubjectLogonId": "0x0"},
            },
        }
        rec_fw, st_fw = parse_otrf_security_record(fw, 2)
        self.assertEqual(st_fw, "ok")
        assert rec_fw is not None
        self.assertEqual(rec_fw.context_status, CTX_INSUFFICIENT)
        self.assertIn("missing_actor_identity", rec_fw.missing_reasons)
        self.assertIn("missing_session_id", rec_fw.missing_reasons)

    def test_malformed_records_and_archive_deduplication(self) -> None:
        self.assertEqual(parse_otrf_security_record("not-a-dict", 1)[1], "malformed_non_dict")
        self.assertEqual(parse_otrf_security_record({"winlog": {"channel": "Security"}}, 1)[1], "malformed_missing_ts_or_eid")
        self.assertEqual(
            parse_otrf_security_record({"@timestamp": "bad-ts", "winlog": {"channel": "Security", "event_id": 4624}}, 1)[1],
            "malformed_timestamp",
        )

        ev = {
            "@timestamp": "2019-10-20T20:11:38.938Z",
            "winlog": {
                "channel": "Security",
                "event_id": 4624,
                "computer_name": "IT001.shire.com",
                "event_data": {"TargetUserName": "pgustavo", "TargetLogonId": "0xabc1", "IpAddress": "10.0.0.5"},
            },
        }
        lines = "\n".join([json.dumps(ev), json.dumps(ev), "{bad-json"]) + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            arc = Path(tmp) / "test.tar.gz"
            with tarfile.open(arc, "w:gz") as tf:
                data = lines.encode("utf-8")
                info = tarfile.TarInfo("events.json")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            records, stats = load_otrf_tar_gz(arc)
            self.assertEqual(stats.total_raw_records, 3)
            self.assertEqual(stats.rejected_malformed_records, 1)
            self.assertEqual(stats.duplicate_records, 1)
            self.assertEqual(stats.evaluatable_records, 1)
            self.assertEqual(len(records), 1)

            summary = evaluate(arc)
            self.assertFalse(summary["ground_truth_available"])
            self.assertIsNone(summary["metrics"]["f1"])
            self.assertEqual(summary["detector_execution"]["evaluated_count"], 1)


if __name__ == "__main__":
    unittest.main()
