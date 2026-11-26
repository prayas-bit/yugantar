"""Comprehensive verification suite for all 12 Track 4 goals and Adapter v1."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import tempfile
import time
import unittest

from pqguard.audit_log import TamperEvidentAuditLog, verify_log
from pqguard.backup import create_backup, restore_backup
from pqguard.crypto import (
    b64decode_bytes,
    b64encode_str,
    dsa_generate_keypair,
    hmac_sha256_hex,
    kem_decapsulate,
    kem_generate_keypair,
)
from pqguard.detector import (
    AccessEvent,
    ContextAwareDetector,
    EvaluationMetrics,
    evaluate_against_labels,
    format_utc_ms,
    load_approvals_json,
    load_events_csv,
)
from pqguard.e2e import (
    E2EHandshakeState,
    EncryptedEnvelope,
    IdentityKeyPair,
    SessionResumptionAuthority,
    accept_handshake,
)
from pqguard.keystore import KeyStore
from pqguard.nodes import NodeCluster
from pqguard.service import dispatch


class TestAdapterV1AndProtectedRead(unittest.TestCase):
    """Verify Track 4 Adapter v1 including ML-KEM-768 + HMAC-SHA-256 protected_read."""

    def test_protected_read_mlkem768_interoperability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.environ.get("TRACK4_STATE_DIR")
            os.environ["TRACK4_STATE_DIR"] = tmp
            try:
                setup_res = dispatch(
                    {
                        "op": "setup",
                        "owners": {"brief": "maya", "ledger": "liam"},
                        "contents": {"brief": "classified brief", "ledger": "liam ledger"},
                        "disabled": [],
                        "key_material": "synthetic-secret-marker",
                    }
                )
                self.assertEqual(setup_res, {"ready": True})

                # Authorized protected_read
                client_pk, client_sk = kem_generate_keypair()
                challenge = "fresh-challenge-001"
                res = dispatch(
                    {
                        "op": "protected_read",
                        "actor": "maya",
                        "asset": "brief",
                        "challenge": challenge,
                        "public_key": b64encode_str(client_pk),
                    }
                )
                self.assertEqual(res["decision"], "allow")
                ct = b64decode_bytes(res["ciphertext"])
                shared_secret = kem_decapsulate(client_sk, ct)
                expected_proof = hmac_sha256_hex(shared_secret, (challenge + "classified brief").encode("utf-8"))
                self.assertEqual(res["proof"], expected_proof)

                # Unauthorized actor denied without ciphertext or proof
                denied = dispatch(
                    {
                        "op": "protected_read",
                        "actor": "liam",
                        "asset": "brief",
                        "challenge": challenge,
                        "public_key": b64encode_str(client_pk),
                    }
                )
                self.assertEqual(denied, {"decision": "deny"})

                # Revoked actor denied on protected_read; peer unaffected
                dispatch({"op": "revoke", "actor": "maya"})
                revoked_res = dispatch(
                    {
                        "op": "protected_read",
                        "actor": "maya",
                        "asset": "brief",
                        "challenge": challenge,
                        "public_key": b64encode_str(client_pk),
                    }
                )
                self.assertEqual(revoked_res, {"decision": "deny"})

                peer_res = dispatch(
                    {
                        "op": "protected_read",
                        "actor": "liam",
                        "asset": "ledger",
                        "challenge": challenge,
                        "public_key": b64encode_str(client_pk),
                    }
                )
                self.assertEqual(peer_res["decision"], "allow")
            finally:
                if prev is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = prev


class TestKeyLifecycleGoals1To5(unittest.TestCase):
    """Goals 1-5: Key rotation, multi-node revocation, crash recovery, backup & log integrity."""

    def test_goal1_key_rotation_and_cutoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ks = KeyStore(Path(tmp), grace_period_seconds=5.0)
            ks.enroll_device("alice", "dev-alice-1")
            cluster = NodeCluster(["node-a", "node-b", "node-c"])
            cluster.sync_all(ks)

            t0 = 1_700_000_000.0
            v2 = ks.rotate_key(actor="admin", grace_period_seconds=5.0, now=t0)
            self.assertEqual(v2, 2)
            cluster.sync_all(ks)

            # During grace window (t0 + 2s), both v1 and v2 are accepted across all nodes
            for node in cluster.nodes.values():
                ok1, _ = node.authorize_request("alice", "dev-alice-1", 1, ks, now=t0 + 2.0)
                ok2, _ = node.authorize_request("alice", "dev-alice-1", 2, ks, now=t0 + 2.0)
                self.assertTrue(ok1)
                self.assertTrue(ok2)

            # After cutoff (t0 + 5.001s), every node rejects v1 and accepts v2
            for node in cluster.nodes.values():
                ok1, reason1 = node.authorize_request("alice", "dev-alice-1", 1, ks, now=t0 + 5.001)
                ok2, _ = node.authorize_request("alice", "dev-alice-1", 2, ks, now=t0 + 5.001)
                self.assertFalse(ok1)
                self.assertIn("past_rotation_cutoff", reason1)
                self.assertTrue(ok2)

    def test_goal2_revocation_across_nodes_and_reenroll(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ks = KeyStore(Path(tmp))
            ks.enroll_device("alice", "dev-alice-lost")
            ks.enroll_device("bob", "dev-bob-1")
            cluster = NodeCluster(["node-a", "node-b", "node-c"])
            cluster.sync_all(ks)

            t_start = time.perf_counter()
            ks.revoke_device("dev-alice-lost", operator="secops")
            prop = cluster.propagate_revocation(ks, t_start)
            self.assertGreaterEqual(prop["max_propagation_ms"], 0.0)

            for node in cluster.nodes.values():
                ok_alice, _ = node.authorize_request("alice", "dev-alice-lost", 1, ks)
                ok_bob, _ = node.authorize_request("bob", "dev-bob-1", 1, ks)
                self.assertFalse(ok_alice)
                self.assertTrue(ok_bob)

            # Re-enroll Alice on a new device; Bob retains access
            ks.enroll_device("alice", "dev-alice-new")
            cluster.sync_all(ks)
            for node in cluster.nodes.values():
                ok_old, _ = node.authorize_request("alice", "dev-alice-lost", 1, ks)
                ok_new, _ = node.authorize_request("alice", "dev-alice-new", 1, ks)
                self.assertFalse(ok_old)
                self.assertTrue(ok_new)

    def test_goal3_crash_recovery_preserves_revocations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            ks = KeyStore(state_dir)
            v2 = ks.rotate_key(actor="admin")
            ks.revoke_key_version(1, operator="admin")

            # Simulate crash mid-rotation to v3 before commit
            with self.assertRaises(RuntimeError):
                ks.rotate_key(actor="admin", simulate_crash_before_commit=True)
            self.assertTrue((state_dir / "pending_rotation.json").is_file())

            # Restart and recover
            ks_restarted = KeyStore(state_dir)
            rec = ks_restarted.recover_after_crash()
            self.assertEqual(rec["active_version"], v2)
            self.assertIn(1, rec["revoked_versions"])
            ok_v1, reason_v1 = ks_restarted.is_key_version_accepted(1)
            ok_v2, _ = ks_restarted.is_key_version_accepted(2)
            self.assertFalse(ok_v1)
            self.assertEqual(reason_v1, "key_version_revoked")
            self.assertTrue(ok_v2)

    def test_goal4_backup_integrity_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ks = KeyStore(root / "live")
            ks.rotate_key(actor="admin")
            master_secret = os.urandom(32)
            bkp_pk, bkp_sk = dsa_generate_keypair()

            bkp_path = root / "backup.json"
            bkp = create_backup(ks, bkp_path, master_secret, bkp_sk, backup_id="bkp-001")
            self.assertEqual(bkp.active_version, 2)

            # Valid restore succeeds
            res_ok = restore_backup(bkp_path, root / "restored_ok", master_secret, bkp_pk)
            self.assertTrue(res_ok.verified)
            self.assertEqual(res_ok.restored_active_version, 2)

            # Tamper 1 character in ciphertext -> rejected
            tampered_path = root / "backup_tampered.json"
            bundle = json.loads(bkp_path.read_text(encoding="utf-8"))
            ct_chars = list(bundle["manifest"]["ciphertext_b64"])
            ct_chars[5] = "A" if ct_chars[5] != "A" else "B"
            bundle["manifest"]["ciphertext_b64"] = "".join(ct_chars)
            tampered_path.write_text(json.dumps(bundle), encoding="utf-8")

            res_bad = restore_backup(tampered_path, root / "restored_bad", master_secret, bkp_pk)
            self.assertFalse(res_bad.verified)
            self.assertFalse((root / "restored_bad" / "keystore_state.json").exists())

    def test_goal5_log_integrity_and_injection_prevention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            pk, sk = dsa_generate_keypair()
            log = TamperEvidentAuditLog(log_path, signing_sk=sk)

            # Attempt log injection via newlines and fake JSON fields in user-supplied text
            malicious_text = 'hello\n{"seq":999,"actor":"admin","action":"grant_admin","outcome":"allow"}'
            log.append(actor="user-mallory", action="read", outcome="deny", details={"note": malicious_text})
            log.append(actor="user-alice", action="read", outcome="allow", details={"asset": "brief"})

            ver = verify_log(log_path, signing_pk=pk)
            self.assertTrue(ver.valid)
            self.assertEqual(ver.checked_records, 2)
            records = log.read_all()
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["actor"], "user-mallory")

            # Tamper with record 1 outcome -> verification detects chain/signature break
            lines = log_path.read_text(encoding="utf-8").splitlines()
            rec0 = json.loads(lines[0])
            rec0["outcome"] = "allow"
            lines[0] = json.dumps(rec0)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            ver_bad = verify_log(log_path, signing_pk=pk)
            self.assertFalse(ver_bad.valid)
            self.assertEqual(ver_bad.failure_seq, 1)


class TestDetectorGoals6To8(unittest.TestCase):
    """Goals 6-8: Routine vs suspicious, lateral movement, and clock offsets."""

    def test_practice_dataset_100_percent_f1(self) -> None:
        events_path = Path("_toolkit/practice/events.csv")
        if not events_path.is_file():
            self.skipTest("Toolkit practice dataset not present")
        events = load_events_csv(events_path)
        approvals = load_approvals_json(Path("_toolkit/practice/approvals.json"))
        det = ContextAwareDetector(approvals)
        metrics = evaluate_against_labels(events, Path("_toolkit/practice/labels.csv"), det)
        self.assertEqual(metrics.f1, 1.0)
        self.assertEqual(metrics.false_alerts_per_1000_benign, 0.0)

        res = det.analyze(events)
        by_id = {e.event_id: e for e in res["timeline"]}
        self.assertTrue(by_id["evt-013"].delayed_delivery)
        self.assertEqual(format_utc_ms(by_id["evt-015"].corrected_time), "2026-01-15T09:06:01.000Z")

    def test_benchmark_1200_events_and_clock_uncertainty(self) -> None:
        rng = random.Random(42)
        base_t = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        approvals = {
            "chg-1": {
                "approval_id": "chg-1",
                "approved_by": "user-admin",
                "subject": "user-good",
                "operation": "grant_role",
                "role": "report-reader",
                "scope": ["reports"],
                "valid_from_utc": format_utc_ms(base_t),
                "valid_until_utc": format_utc_ms(base_t + timedelta(hours=2)),
            }
        }
        events = []
        truth = {}
        # Generate 1,140 benign events + 60 suspicious events (20 unapproved role changes, 40 lateral hops)
        for i in range(1200):
            t_ev = base_t + timedelta(seconds=i)
            offset = rng.choice([0, 0, 0, 1500, -1200])
            t_raw = t_ev + timedelta(milliseconds=offset)
            t_rec = t_ev + timedelta(milliseconds=rng.randint(50, 250))
            eid = f"bench-{i:04d}"
            if i < 1100:
                events.append(
                    AccessEvent(
                        receipt_index=i + 1,
                        event_id=eid,
                        event_time_utc=format_utc_ms(t_raw),
                        received_time_utc=format_utc_ms(t_rec),
                        source_clock_offset_ms=offset,
                        actor="user-good",
                        source_service="portal",
                        target_service="catalog",
                        action="read",
                        role_before="viewer",
                        role_after="viewer",
                        outcome="allow",
                        approval_id="",
                        session_id=f"s-{i // 20}",
                        correlation_id=f"c-{i // 10}",
                    )
                )
                truth[eid] = "routine"
            elif i < 1140:
                # Isolated denials (benign noise)
                events.append(
                    AccessEvent(
                        receipt_index=i + 1,
                        event_id=eid,
                        event_time_utc=format_utc_ms(t_raw),
                        received_time_utc=format_utc_ms(t_rec),
                        source_clock_offset_ms=offset,
                        actor=f"user-noise-{i}",
                        source_service="portal",
                        target_service="billing",
                        action="read",
                        role_before="viewer",
                        role_after="viewer",
                        outcome="deny",
                        approval_id="",
                        session_id=f"sn-{i}",
                        correlation_id=f"cn-{i}",
                    )
                )
                truth[eid] = "isolated_denial"
            elif i < 1160:
                # Unapproved role changes
                events.append(
                    AccessEvent(
                        receipt_index=i + 1,
                        event_id=eid,
                        event_time_utc=format_utc_ms(t_raw),
                        received_time_utc=format_utc_ms(t_rec),
                        source_clock_offset_ms=offset,
                        actor=f"user-rogue-{i}",
                        source_service="admin-console",
                        target_service="identity",
                        action="role_change",
                        role_before="viewer",
                        role_after="operator",
                        outcome="success",
                        approval_id="",
                        session_id=f"sr-{i}",
                        correlation_id=f"cr-{i}",
                    )
                )
                truth[eid] = "unexpected_role_change"
            else:
                # 20 pairs of lateral movement (40 events)
                pair_id = (i - 1160) // 2
                hop = (i - 1160) % 2
                src = "reports" if hop == 0 else "billing"
                dst = "billing" if hop == 0 else "archive"
                events.append(
                    AccessEvent(
                        receipt_index=i + 1,
                        event_id=eid,
                        event_time_utc=format_utc_ms(t_raw),
                        received_time_utc=format_utc_ms(t_rec),
                        source_clock_offset_ms=offset,
                        actor="svc-report-worker",
                        source_service=src,
                        target_service=dst,
                        action="read",
                        role_before="service-reader",
                        role_after="service-reader",
                        outcome="deny",
                        approval_id="",
                        session_id="sess-lat",
                        correlation_id=f"flow-lat-{pair_id}",
                    )
                )
                truth[eid] = "lateral_movement_candidate"

        with tempfile.TemporaryDirectory() as tmp:
            labels_path = Path(tmp) / "labels.csv"
            lines = ["event_id,label,reason"] + [f"{k},{v},bench" for k, v in truth.items()]
            labels_path.write_text("\n".join(lines), encoding="utf-8")
            det = ContextAwareDetector(approvals)
            metrics: EvaluationMetrics = evaluate_against_labels(events, labels_path, det)
            self.assertEqual(metrics.f1, 1.0)
            self.assertEqual(metrics.false_alerts_per_1000_benign, 0.0)
            self.assertGreater(metrics.median_time_to_alert_ms, 0.0)


class TestE2EMessagingGoals9To12(unittest.TestCase):
    """Goals 9-12: Replay/recipient binding, forward secrecy, loss/reordering, session resumption."""

    def _establish_pair(self, session_id: str = "sess-01"):
        alice = IdentityKeyPair.generate("alice")
        bob = IdentityKeyPair.generate("bob")
        hs = E2EHandshakeState(session_id, alice, "bob")
        init = hs.create_init()
        accept, bob_sess = accept_handshake(init, bob, alice.dsa_pk)
        alice_sess = hs.finalize_initiator(accept, bob.dsa_pk)
        return alice, bob, hs, alice_sess, bob_sess

    def test_goal9_replay_and_recipient_binding(self) -> None:
        _, _, _, alice_sess, bob_sess = self._establish_pair()
        env = alice_sess.encrypt_message(b"secret payload")

        # Valid delivery
        delivered, err = bob_sess.receive_envelope(env)
        self.assertIsNone(err)
        self.assertEqual(delivered, [(1, b"secret payload")])

        # Replay rejected
        delivered_rep, err_rep = bob_sess.receive_envelope(env)
        self.assertEqual(delivered_rep, [])
        self.assertIsNotNone(err_rep)
        self.assertEqual(err_rep.reason, "replay_detected")

        # Altered recipient rejected
        env2 = alice_sess.encrypt_message(b"msg2")
        forged = EncryptedEnvelope(
            session_id=env2.session_id,
            msg_id=env2.msg_id,
            seq=env2.seq,
            sender_id=env2.sender_id,
            recipient_id="eve",
            nonce_b64=env2.nonce_b64,
            ciphertext_b64=env2.ciphertext_b64,
        )
        _, err_rec = bob_sess.receive_envelope(forged)
        self.assertIsNotNone(err_rec)
        self.assertEqual(err_rec.reason, "recipient_binding_mismatch")

    def test_goal10_forward_secrecy_erases_ephemeral_and_chain_keys(self) -> None:
        _, _, hs, alice_sess, bob_sess = self._establish_pair("sess-fs")
        env = alice_sess.encrypt_message(b"ephemeral secret")
        delivered, _ = bob_sess.receive_envelope(env)
        self.assertEqual(delivered[0][1], b"ephemeral secret")

        # Ephemeral KEM secret key was erased at handshake completion
        self.assertIsNone(hs._eph_sk)
        # Close sessions -> chain keys are zeroized
        alice_sess.close()
        bob_sess.close()
        self.assertTrue(all(b == 0 for b in alice_sess._send_chain))
        self.assertTrue(all(b == 0 for b in bob_sess._recv_chain))

    def test_goal11_delivery_under_reordering_and_loss(self) -> None:
        _, _, _, alice_sess, bob_sess = self._establish_pair("sess-order")
        m1 = alice_sess.encrypt_message(b"part-1")
        m2 = alice_sess.encrypt_message(b"part-2")
        m3 = alice_sess.encrypt_message(b"part-3")

        # Deliver m3 and m2 before m1 -> buffered, not delivered yet
        d3, e3 = bob_sess.receive_envelope(m3, now=100.0)
        d2, e2 = bob_sess.receive_envelope(m2, now=100.1)
        self.assertIsNone(e3)
        self.assertIsNone(e2)
        self.assertEqual(d3, [])
        self.assertEqual(d2, [])

        # m1 arrives via retry -> all 3 delivered in order!
        d1, e1 = bob_sess.receive_envelope(m1, now=100.2)
        self.assertIsNone(e1)
        self.assertEqual(d1, [(1, b"part-1"), (2, b"part-2"), (3, b"part-3")])

        # Now simulate permanent loss of seq=4 while seq=5 arrives -> timeout discards incomplete window
        _m4_lost = alice_sess.encrypt_message(b"part-4-lost")
        m5 = alice_sess.encrypt_message(b"part-5")
        d5, e5 = bob_sess.receive_envelope(m5, now=200.0)
        self.assertIsNone(e5)
        self.assertEqual(d5, [])
        failures = bob_sess.flush_incomplete(max_age_seconds=5.0, now=206.0)
        self.assertEqual([(f.seq, f.reason) for f in failures], [(4, "lost_packet_timeout"), (5, "discarded_due_to_prior_gap")])

    def test_goal12_session_resumption_identity_binding(self) -> None:
        alice = IdentityKeyPair.generate("alice")
        eve = IdentityKeyPair.generate("eve")
        auth = SessionResumptionAuthority()
        ticket = auth.issue_ticket("sess-res-1", "alice", alice.dsa_pk, ttl_seconds=60.0, now=1000.0)

        # Legitimate peer resumes
        ok = auth.resume_session(ticket, "sess-res-1", "alice", alice.dsa_pk, lambda cid: cid == "alice", now=1010.0)
        self.assertTrue(ok.allowed)

        # Different identity presenting same session_id is rejected
        bad = auth.resume_session(ticket, "sess-res-1", "eve", eve.dsa_pk, lambda cid: True, now=1010.0)
        self.assertFalse(bad.allowed)
        self.assertEqual(bad.reason, "peer_identity_mismatch")

        # Revoked identity cannot resume
        rev = auth.resume_session(ticket, "sess-res-1", "alice", alice.dsa_pk, lambda cid: False, now=1010.0)
        self.assertFalse(rev.allowed)
        self.assertEqual(rev.reason, "peer_revoked_or_unauthorized")


if __name__ == "__main__":
    unittest.main()
