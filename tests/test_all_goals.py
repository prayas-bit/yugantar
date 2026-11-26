"""Comprehensive verification suite for all 12 Track 4 goals and Adapter v1."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import tempfile
import threading
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
    sign_resumption_challenge,
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

    def test_regression_f01_concurrent_replay_and_challenge_burning(self) -> None:
        alice = IdentityKeyPair.generate("alice")
        eve = IdentityKeyPair.generate("eve")
        auth = SessionResumptionAuthority()
        ticket = auth.issue_ticket("sess-race", "alice", alice.dsa_pk, ttl_seconds=120.0, now=1000.0)
        ch = auth.issue_challenge("sess-race", "alice", ttl_seconds=60.0, now=1001.0)

        # Unauthenticated attacker tries to burn Alice's challenge with a bad signature
        forged_sig = sign_resumption_challenge(IdentityKeyPair("alice", alice.dsa_pk, eve.dsa_sk), ch, ticket)
        burn_attempt = auth.resume_session(
            ticket, "sess-race", "alice", alice.dsa_pk, ch.challenge_id, forged_sig, now=1002.0
        )
        self.assertFalse(burn_attempt.allowed)
        self.assertEqual(burn_attempt.reason, "invalid_pop_signature")

        # Concurrent threads submit Alice's valid proof for the same challenge
        valid_sig = sign_resumption_challenge(alice, ch, ticket)
        results = []
        barrier = threading.Barrier(6)
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            res = auth.resume_session(
                ticket, "sess-race", "alice", alice.dsa_pk, ch.challenge_id, valid_sig, now=1003.0
            )
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for r in results if r.allowed)
        self.assertEqual(allowed_count, 1)
        self.assertTrue(all(r.reason == "replayed_challenge" for r in results if not r.allowed))

    def test_regression_f02_full_local_snapshot_rollback_and_fresh_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_dir = root / "live"
            ks = KeyStore(live_dir)
            ks.enroll_device("alice", "dev-1")  # epoch 1
            ms = os.urandom(32)
            bkp_pk, bkp_sk = dsa_generate_keypair()

            old_bkp = root / "bkp_e1.json"
            create_backup(ks, old_bkp, ms, bkp_sk, backup_id="bkp-e1")

            ks.revoke_device("dev-1", operator="secops")  # epoch 2
            ks.revoke_key_version(1, operator="secops")  # epoch 3
            new_bkp = root / "bkp_e3.json"
            create_backup(ks, new_bkp, ms, bkp_sk, backup_id="bkp-e3")

            # Simulate full local snapshot rollback (attacker wipes live_dir including watermark)
            # With trusted external expected_min_epoch=3, old epoch-1 backup is still rejected.
            fresh_dir = root / "fresh_host"
            res_old = restore_backup(old_bkp, fresh_dir, ms, bkp_pk, expected_min_epoch=3)
            self.assertFalse(res_old.verified)
            self.assertIn("rollback", (res_old.error or "").lower())

            # Epoch-3 backup succeeds on fresh host
            res_new = restore_backup(new_bkp, fresh_dir, ms, bkp_pk, expected_min_epoch=3)
            self.assertTrue(res_new.verified)

    def test_regression_f03_interrupted_migration_and_historical_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ks_dir = root / "legacy_ks"
            ks_dir.mkdir(parents=True, exist_ok=True)
            log_pk, log_sk = dsa_generate_keypair()

            # Write historical audit log signed with original key
            hist_log = TamperEvidentAuditLog(ks_dir / "keystore_audit.jsonl", signing_sk=log_sk)
            hist_log.append("system", "keystore_init", "success", details={"legacy": True})

            # Legacy state file containing plaintext log_signing_sk_b64
            legacy_state = {
                "active_version": 1,
                "revocation_epoch": 0,
                "grace_period_seconds": 0.0,
                "key_versions": {},
                "revoked_versions": [],
                "revoked_actors": [],
                "devices": {},
                "log_signing_pk_b64": b64encode_str(log_pk),
                "log_signing_sk_b64": b64encode_str(log_sk),
            }
            (ks_dir / "keystore_state.json").write_text(json.dumps(legacy_state), encoding="utf-8")

            # Simulate interrupted migration: key file written, but state file not yet stripped
            key_dir = root / ".legacy_ks-keys"
            key_dir.mkdir(parents=True, exist_ok=True)
            (key_dir / "keystore_audit_signing.key").write_text(b64encode_str(log_sk), encoding="ascii")

            ks = KeyStore(ks_dir)
            ks.audit_log.append("admin", "post_migration_event", "success", details={})

            migrated_text = (ks_dir / "keystore_state.json").read_text(encoding="utf-8")
            self.assertNotIn("log_signing_sk_b64", migrated_text)
            self.assertEqual(list(ks_dir.glob("*.tmp")), [])
            ver = verify_log(ks_dir / "keystore_audit.jsonl", signing_pk=log_pk)
            self.assertTrue(ver.valid)
            self.assertEqual(ver.checked_records, 2)


class TestSecurityRemediationsMedium(unittest.TestCase):
    """Regression tests for F-04 through F-08."""

    def _pair(self, session_id: str = "sess-med"):
        alice = IdentityKeyPair.generate("alice")
        bob = IdentityKeyPair.generate("bob")
        hs = E2EHandshakeState(session_id, alice, "bob")
        acc, bob_sess = accept_handshake(hs.create_init(), bob, alice.dsa_pk)
        alice_sess = hs.finalize_initiator(acc, bob.dsa_pk)
        return alice_sess, bob_sess

    def test_regression_f04_bidirectional_chain_key_separation(self) -> None:
        alice_sess, bob_sess = self._pair("sess-f04")
        # Initiator send == Responder recv; Responder send == Initiator recv; opposite send chains differ
        self.assertEqual(alice_sess._send_chain, bob_sess._recv_chain)
        self.assertEqual(bob_sess._send_chain, alice_sess._recv_chain)
        self.assertNotEqual(alice_sess._send_chain, bob_sess._send_chain)

        # Both directions work concurrently at seq=1
        m_a2b = alice_sess.encrypt_message(b"from-alice-1")
        m_b2a = bob_sess.encrypt_message(b"from-bob-1")
        d_b, err_b = bob_sess.receive_envelope(m_a2b)
        d_a, err_a = alice_sess.receive_envelope(m_b2a)
        self.assertIsNone(err_b)
        self.assertIsNone(err_a)
        self.assertEqual(d_b, [(1, b"from-alice-1")])
        self.assertEqual(d_a, [(1, b"from-bob-1")])

        # Cross-direction substitution fails
        m_a2b_2 = alice_sess.encrypt_message(b"reflect-me")
        forged_reflect = EncryptedEnvelope(
            m_a2b_2.session_id, m_a2b_2.msg_id, 2, "bob", "alice", m_a2b_2.nonce_b64, m_a2b_2.ciphertext_b64
        )
        _, err_ref = alice_sess.receive_envelope(forged_reflect)
        self.assertIsNotNone(err_ref)
        self.assertIn("authentication_failed", err_ref.reason)

    def test_regression_f05_unauthenticated_packet_does_not_advance_recv_chain(self) -> None:
        alice_sess, bob_sess = self._pair("sess-f05")
        initial_chain = bytes(bob_sess._recv_chain)

        # Forged high-seq packet with invalid ciphertext must leave receive state untouched
        junk = EncryptedEnvelope("sess-f05", "junk-1", 65, "alice", "bob", b64encode_str(b"0" * 12), b64encode_str(b"1" * 24))
        _, err = bob_sess.receive_envelope(junk)
        self.assertIsNotNone(err)
        self.assertEqual(bytes(bob_sess._recv_chain), initial_chain)
        self.assertEqual(len(bob_sess._recv_key_cache), 0)
        self.assertEqual(bob_sess.expected_recv_seq, 1)

        # Forged packet with invalid AAD (tampered msg_id) leaves state untouched
        m1 = alice_sess.encrypt_message(b"legit-1")
        bad_aad = EncryptedEnvelope(m1.session_id, "tampered-id", m1.seq, m1.sender_id, m1.recipient_id, m1.nonce_b64, m1.ciphertext_b64)
        _, err_aad = bob_sess.receive_envelope(bad_aad)
        self.assertIsNotNone(err_aad)
        self.assertEqual(bytes(bob_sess._recv_chain), initial_chain)

        # Subsequent legitimate packet (even out-of-order) still succeeds, and replay is rejected
        m2 = alice_sess.encrypt_message(b"legit-2")
        d2, err2 = bob_sess.receive_envelope(m2)
        self.assertIsNone(err2)
        self.assertEqual(d2, [])
        d1, err1 = bob_sess.receive_envelope(m1)
        self.assertIsNone(err1)
        self.assertEqual(d1, [(1, b"legit-1"), (2, b"legit-2")])
        _, err_rep = bob_sess.receive_envelope(m1)
        self.assertEqual(err_rep.reason, "replay_detected")

    def test_regression_f06_service_node_uses_isolated_synced_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ks = KeyStore(Path(tmp))
            cluster = NodeCluster(["node-a"])
            cluster.sync_all(ks)

            # Enroll new device after sync -> stale node must deny until sync_from()
            ks.enroll_device("alice", "dev-late")
            ok_before, reason_before = cluster.nodes["node-a"].authorize_request("alice", "dev-late", 1)
            self.assertFalse(ok_before)
            self.assertEqual(reason_before, "node-a:device_unauthorized")

            # After sync, node authorizes; mutating keystore.state in-place does not mutate node snapshot
            cluster.sync_all(ks)
            ks.state["devices"]["dev-late"]["actor"] = "mallory"
            ok_after, _ = cluster.nodes["node-a"].authorize_request("alice", "dev-late", 1)
            self.assertTrue(ok_after)

            # Revocation propagates on sync
            ks.revoke_device("dev-late", operator="secops")
            cluster.sync_all(ks)
            ok_rev, reason_rev = cluster.nodes["node-a"].authorize_request("alice", "dev-late", 1)
            self.assertFalse(ok_rev)
            self.assertEqual(reason_rev, "node-a:device_revoked")

    def test_regression_f07_sliding_window_catches_rotating_correlation_ids(self) -> None:
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        evts = [
            AccessEvent(1, "e1", format_utc_ms(t0), format_utc_ms(t0), 0, "svc-report-worker", "reports", "billing", "read", "service-reader", "service-reader", "deny", "", "sess-1", "flow-A"),
            AccessEvent(2, "e2", format_utc_ms(t0 + timedelta(seconds=5)), format_utc_ms(t0 + timedelta(seconds=5)), 0, "svc-report-worker", "billing", "archive", "read", "service-reader", "service-reader", "deny", "", "sess-1", "flow-B"),
            AccessEvent(3, "e3", format_utc_ms(t0 + timedelta(seconds=10)), format_utc_ms(t0 + timedelta(seconds=10)), 0, "svc-report-worker", "archive", "identity", "list_roles", "service-reader", "service-reader", "deny", "", "sess-1", "flow-C"),
            # Legitimate workflow for another actor
            AccessEvent(4, "e4", format_utc_ms(t0 + timedelta(seconds=15)), format_utc_ms(t0 + timedelta(seconds=15)), 0, "user-alex", "portal", "catalog", "read", "viewer", "viewer", "allow", "", "sess-alex", "flow-D"),
            # Isolated denial outside window (> 60s later) for a different actor
            AccessEvent(5, "e5", format_utc_ms(t0), format_utc_ms(t0), 0, "user-casey", "portal", "billing", "read", "viewer", "viewer", "deny", "", "sess-casey", "flow-E"),
            AccessEvent(6, "e6", format_utc_ms(t0 + timedelta(seconds=120)), format_utc_ms(t0 + timedelta(seconds=120)), 0, "user-casey", "portal", "archive", "read", "viewer", "viewer", "deny", "", "sess-casey", "flow-F"),
        ]
        det = ContextAwareDetector({}, lateral_window_seconds=60.0)
        res = det.analyze(evts)
        self.assertEqual(len(res["alerts"]), 1)
        self.assertEqual(res["alerts"][0].category, "lateral_movement")
        self.assertEqual(res["alerts"][0].event_ids, ["e1", "e2", "e3"])
        self.assertEqual(res["classifications"]["e4"], "routine")
        self.assertEqual(res["classifications"]["e5"], "isolated_denial")
        self.assertEqual(res["classifications"]["e6"], "isolated_denial")

    def test_regression_f08_privilege_escalation_any_action_label(self) -> None:
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        approvals = {
            "chg-1": {
                "approval_id": "chg-1",
                "approved_by": "user-admin",
                "subject": "user-alex",
                "operation": "grant_role",
                "role": "report-reader",
                "scope": ["reports"],
                "valid_from_utc": format_utc_ms(t0 - timedelta(minutes=1)),
                "valid_until_utc": format_utc_ms(t0 + timedelta(minutes=5)),
            }
        }
        evts = [
            # Unapproved escalation disguised as token_refresh
            AccessEvent(1, "e1", format_utc_ms(t0), format_utc_ms(t0), 0, "user-mallory", "portal", "identity", "token_refresh", "viewer", "operator", "success", "", "s1", "c1"),
            # Approved role change
            AccessEvent(2, "e2", format_utc_ms(t0), format_utc_ms(t0), 0, "user-alex", "admin-console", "identity", "role_change", "viewer", "report-reader", "success", "chg-1", "s2", "c2"),
            # Unchanged role
            AccessEvent(3, "e3", format_utc_ms(t0), format_utc_ms(t0), 0, "user-bob", "portal", "catalog", "read", "viewer", "viewer", "allow", "", "s3", "c3"),
            # Missing/empty role fields handled safely without crashing
            AccessEvent(4, "e4", format_utc_ms(t0), format_utc_ms(t0), 0, "user-bob", "portal", "catalog", "read", "", "", "allow", "", "s3", "c4"),
        ]
        det = ContextAwareDetector(approvals)
        res = det.analyze(evts)
        self.assertEqual(len(res["alerts"]), 1)
        self.assertEqual(res["alerts"][0].category, "unexpected_role_change")
        self.assertEqual(res["alerts"][0].event_ids, ["e1"])
        self.assertEqual(res["classifications"]["e2"], "approved_change")
        self.assertEqual(res["classifications"]["e3"], "routine")
        self.assertEqual(res["classifications"]["e4"], "routine")


class TestSecurityRemediationsLow(unittest.TestCase):
    """Regression tests for F-09, F-10, and F-11."""

    def test_regression_f09_secure_temp_storage_and_symlink_rejection(self) -> None:
        from pqguard.storage import atomic_write_bytes, create_secure_temp_dir, get_state_dir

        d1 = create_secure_temp_dir()
        d2 = create_secure_temp_dir()
        try:
            self.assertNotEqual(d1, d2)
            self.assertTrue(d1.is_dir())
            if os.name == "posix":
                self.assertEqual(d1.stat().st_mode & 0o777, 0o700)

            target = d1 / "state.json"
            atomic_write_bytes(target, b'{"ok":true}')
            self.assertEqual(target.read_bytes(), b'{"ok":true}')
            self.assertEqual(list(d1.glob("*.tmp")), [])
            if os.name == "posix":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

            # Non-directory file passed as TRACK4_STATE_DIR is rejected
            prev = os.environ.get("TRACK4_STATE_DIR")
            os.environ["TRACK4_STATE_DIR"] = str(target)
            try:
                with self.assertRaises(ValueError):
                    get_state_dir()
            finally:
                if prev is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = prev

            # Symlink rejection (when OS permits creating symlinks)
            link_path = d1 / "sym_target.json"
            try:
                os.symlink(target, link_path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(ValueError):
                    atomic_write_bytes(link_path, b"bad")
        finally:
            import shutil

            shutil.rmtree(d1, ignore_errors=True)
            shutil.rmtree(d2, ignore_errors=True)

    def test_regression_f10_strict_identifier_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.environ.get("TRACK4_STATE_DIR")
            os.environ["TRACK4_STATE_DIR"] = tmp
            try:
                dispatch(
                    {
                        "op": "setup",
                        "owners": {"brief": "maya", "None": "True"},
                        "contents": {"brief": "ok", "None": "trap"},
                        "disabled": [],
                    }
                )
                bad_ids = [123, True, None, ["maya"], {"id": "maya"}, object(), "", "   ", "maya\x00"]
                for bad in bad_ids:
                    with self.assertRaises(ValueError):
                        dispatch({"op": "read", "actor": bad, "asset": "brief", "request_id": "r1"})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "read", "actor": "maya", "asset": bad, "request_id": "r2"})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "read", "actor": "maya", "asset": "brief", "request_id": bad})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "revoke", "actor": bad})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "audit", "request_id": bad})
                    with self.assertRaises(ValueError):
                        dispatch(
                            {
                                "op": "protected_read",
                                "actor": bad,
                                "asset": "brief",
                                "challenge": "c",
                                "public_key": "AA==",
                            }
                        )
                # Valid string IDs still succeed
                ok = dispatch({"op": "read", "actor": "maya", "asset": "brief", "request_id": "r-valid"})
                self.assertEqual(ok, {"decision": "allow", "body": "ok"})
            finally:
                if prev is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = prev

    def test_regression_f11_wal_recovery_auditability_and_idempotence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ks_dir = Path(tmp) / "ks"
            ks = KeyStore(ks_dir)
            ks.rotate_key(actor="admin")
            ks.revoke_key_version(1, operator="secops")
            with self.assertRaises(RuntimeError):
                ks.rotate_key(actor="admin", simulate_crash_before_commit=True)
            self.assertTrue((ks_dir / "pending_rotation.json").is_file())

            # Restart records wal_recovery BEFORE removing pending_rotation.json
            ks2 = KeyStore(ks_dir)
            self.assertFalse((ks_dir / "pending_rotation.json").is_file())
            rec = ks2.recover_after_crash()
            self.assertTrue(rec["rolled_back_pending_rotation"])
            self.assertEqual(rec["active_version"], 2)

            records = ks2.audit_log.read_all()
            wal_events = [r for r in records if r["action"] == "wal_recovery"]
            self.assertEqual(len(wal_events), 1)
            self.assertEqual(wal_events[0]["outcome"], "rolled_back")
            self.assertEqual(wal_events[0]["details"]["to_version"], 3)

            # Malformed WAL is safely recorded and discarded
            (ks_dir / "pending_rotation.json").write_text("{corrupt-wal", encoding="utf-8")
            rec_mal = ks2.recover_after_crash()
            self.assertTrue(rec_mal["malformed_wal"])
            self.assertFalse((ks_dir / "pending_rotation.json").is_file())
            wal_events2 = [r for r in ks2.audit_log.read_all() if r["action"] == "wal_recovery"]
            self.assertEqual(wal_events2[-1]["outcome"], "malformed_wal_discarded")

            # Repeated recovery is idempotent
            rec_idem = ks2.recover_after_crash()
            self.assertFalse(rec_idem["rolled_back_pending_rotation"])
            self.assertFalse(rec_idem["malformed_wal"])
            self.assertTrue(verify_log(ks_dir / "keystore_audit.jsonl", signing_pk=ks2.log_signing_pk).valid)


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

        # Legitimate peer resumes with fresh PoP challenge
        ch1 = auth.issue_challenge("sess-res-1", "alice", ttl_seconds=30.0, now=1005.0)
        sig1 = sign_resumption_challenge(alice, ch1, ticket)
        ok = auth.resume_session(
            ticket, "sess-res-1", "alice", alice.dsa_pk, ch1.challenge_id, sig1, lambda cid: cid == "alice", now=1010.0
        )
        self.assertTrue(ok.allowed)

        # Different identity presenting same session_id is rejected
        ch2 = auth.issue_challenge("sess-res-1", "eve", ttl_seconds=30.0, now=1005.0)
        sig2 = sign_resumption_challenge(eve, ch2, ticket)
        bad = auth.resume_session(
            ticket, "sess-res-1", "eve", eve.dsa_pk, ch2.challenge_id, sig2, lambda cid: True, now=1010.0
        )
        self.assertFalse(bad.allowed)
        self.assertEqual(bad.reason, "peer_identity_mismatch")

        # Revoked identity cannot resume
        ch3 = auth.issue_challenge("sess-res-1", "alice", ttl_seconds=30.0, now=1005.0)
        sig3 = sign_resumption_challenge(alice, ch3, ticket)
        rev = auth.resume_session(
            ticket, "sess-res-1", "alice", alice.dsa_pk, ch3.challenge_id, sig3, lambda cid: False, now=1010.0
        )
        self.assertFalse(rev.allowed)
        self.assertEqual(rev.reason, "peer_revoked_or_unauthorized")


class TestSecurityRemediationsHigh(unittest.TestCase):
    """Regression tests for F-01, F-02, and F-03."""

    def test_regression_f01_resumption_rejects_public_key_impersonation_and_replays(self) -> None:
        alice = IdentityKeyPair.generate("alice")
        eve = IdentityKeyPair.generate("eve")
        auth = SessionResumptionAuthority()
        ticket = auth.issue_ticket("sess-f01", "alice", alice.dsa_pk, ttl_seconds=120.0, now=1000.0)

        # Missing proof rejected
        missing = auth.resume_session(ticket, "sess-f01", "alice", alice.dsa_pk, now=1005.0)
        self.assertFalse(missing.allowed)
        self.assertEqual(missing.reason, "missing_pop_proof")

        # Impersonator knowing alice.dsa_pk but signing with eve.dsa_sk rejected
        ch_imp = auth.issue_challenge("sess-f01", "alice", ttl_seconds=30.0, now=1005.0)
        forged_sig = sign_resumption_challenge(
            IdentityKeyPair("alice", alice.dsa_pk, eve.dsa_sk), ch_imp, ticket
        )
        imp = auth.resume_session(
            ticket, "sess-f01", "alice", alice.dsa_pk, ch_imp.challenge_id, forged_sig, now=1006.0
        )
        self.assertFalse(imp.allowed)
        self.assertEqual(imp.reason, "invalid_pop_signature")

        # Valid proof succeeds once, then replay of same challenge is rejected
        ch_ok = auth.issue_challenge("sess-f01", "alice", ttl_seconds=30.0, now=1007.0)
        sig_ok = sign_resumption_challenge(alice, ch_ok, ticket)
        res_ok = auth.resume_session(
            ticket, "sess-f01", "alice", alice.dsa_pk, ch_ok.challenge_id, sig_ok, now=1008.0
        )
        self.assertTrue(res_ok.allowed)
        res_replay = auth.resume_session(
            ticket, "sess-f01", "alice", alice.dsa_pk, ch_ok.challenge_id, sig_ok, now=1009.0
        )
        self.assertFalse(res_replay.allowed)
        self.assertEqual(res_replay.reason, "replayed_challenge")

        # Expired challenge rejected
        ch_exp = auth.issue_challenge("sess-f01", "alice", ttl_seconds=5.0, now=1010.0)
        sig_exp = sign_resumption_challenge(alice, ch_exp, ticket)
        res_exp = auth.resume_session(
            ticket, "sess-f01", "alice", alice.dsa_pk, ch_exp.challenge_id, sig_exp, now=1020.0
        )
        self.assertFalse(res_exp.allowed)
        self.assertEqual(res_exp.reason, "challenge_expired")

    def test_regression_f02_backup_rollback_rejected_after_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_dir = root / "live"
            ks = KeyStore(live_dir)
            ks.enroll_device("alice", "dev-alice-1")
            ms = os.urandom(32)
            bkp_pk, bkp_sk = dsa_generate_keypair()

            # Create legitimate backup at epoch 1 (before revocation)
            old_bkp = root / "old_bkp.json"
            create_backup(ks, old_bkp, ms, bkp_sk, backup_id="bkp-old")

            # Revoke device and key version (epoch advances)
            ks.revoke_device("dev-alice-1", operator="secops")
            ks.revoke_key_version(1, operator="secops")

            # Rollback attempt with stale legitimately signed backup must fail
            res = restore_backup(old_bkp, live_dir, ms, bkp_pk)
            self.assertFalse(res.verified)
            self.assertIn("rollback", (res.error or "").lower())

            # Revoked device and key version remain revoked
            ks_after = KeyStore(live_dir)
            ok_dev, _ = ks_after.is_device_authorized("alice", "dev-alice-1")
            ok_key, _ = ks_after.is_key_version_accepted(1)
            self.assertFalse(ok_dev)
            self.assertFalse(ok_key)

    def test_regression_f03_state_files_do_not_expose_signing_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ks_dir = root / "ks"
            ks = KeyStore(ks_dir)
            ks.rotate_key(actor="admin")

            state_text = (ks_dir / "keystore_state.json").read_text(encoding="utf-8")
            self.assertNotIn("log_signing_sk_b64", state_text)
            pinned_pk = ks.log_signing_pk
            ver = verify_log(ks_dir / "keystore_audit.jsonl", signing_pk=pinned_pk)
            self.assertTrue(ver.valid)

            # Removing private signing key refuses silent rotation
            ks._signing_key_path.unlink()
            with self.assertRaises(RuntimeError):
                KeyStore(ks_dir)

            # Also verify service_state.json does not expose log_signing_sk_b64
            svc_dir = root / "svc"
            prev = os.environ.get("TRACK4_STATE_DIR")
            os.environ["TRACK4_STATE_DIR"] = str(svc_dir)
            try:
                dispatch({"op": "setup", "owners": {"a": "alice"}, "contents": {"a": "secret"}, "disabled": []})
                svc_text = (svc_dir / "service_state.json").read_text(encoding="utf-8")
                self.assertNotIn("log_signing_sk_b64", svc_text)
                svc_state = json.loads(svc_text)
                svc_pk = b64decode_bytes(svc_state["log_signing_pk_b64"])
                self.assertTrue(verify_log(svc_dir / "audit.jsonl", signing_pk=svc_pk).valid)
            finally:
                if prev is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = prev

    def test_regression_f01_concurrent_replay_and_challenge_burning(self) -> None:
        alice = IdentityKeyPair.generate("alice")
        eve = IdentityKeyPair.generate("eve")
        auth = SessionResumptionAuthority()
        ticket = auth.issue_ticket("sess-race", "alice", alice.dsa_pk, ttl_seconds=120.0, now=1000.0)
        ch = auth.issue_challenge("sess-race", "alice", ttl_seconds=60.0, now=1001.0)

        # Unauthenticated attacker tries to burn Alice's challenge with a bad signature
        forged_sig = sign_resumption_challenge(IdentityKeyPair("alice", alice.dsa_pk, eve.dsa_sk), ch, ticket)
        burn_attempt = auth.resume_session(
            ticket, "sess-race", "alice", alice.dsa_pk, ch.challenge_id, forged_sig, now=1002.0
        )
        self.assertFalse(burn_attempt.allowed)
        self.assertEqual(burn_attempt.reason, "invalid_pop_signature")

        # Concurrent threads submit Alice's valid proof for the same challenge
        valid_sig = sign_resumption_challenge(alice, ch, ticket)
        results = []
        barrier = threading.Barrier(6)
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            res = auth.resume_session(
                ticket, "sess-race", "alice", alice.dsa_pk, ch.challenge_id, valid_sig, now=1003.0
            )
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for r in results if r.allowed)
        self.assertEqual(allowed_count, 1)
        self.assertTrue(all(r.reason == "replayed_challenge" for r in results if not r.allowed))

    def test_regression_f02_full_local_snapshot_rollback_and_fresh_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_dir = root / "live"
            ks = KeyStore(live_dir)
            ks.enroll_device("alice", "dev-1")  # epoch 1
            ms = os.urandom(32)
            bkp_pk, bkp_sk = dsa_generate_keypair()

            old_bkp = root / "bkp_e1.json"
            create_backup(ks, old_bkp, ms, bkp_sk, backup_id="bkp-e1")

            ks.revoke_device("dev-1", operator="secops")  # epoch 2
            ks.revoke_key_version(1, operator="secops")  # epoch 3
            new_bkp = root / "bkp_e3.json"
            create_backup(ks, new_bkp, ms, bkp_sk, backup_id="bkp-e3")

            # Simulate full local snapshot rollback (attacker wipes live_dir including watermark)
            # With trusted external expected_min_epoch=3, old epoch-1 backup is still rejected.
            fresh_dir = root / "fresh_host"
            res_old = restore_backup(old_bkp, fresh_dir, ms, bkp_pk, expected_min_epoch=3)
            self.assertFalse(res_old.verified)
            self.assertIn("rollback", (res_old.error or "").lower())

            # Epoch-3 backup succeeds on fresh host
            res_new = restore_backup(new_bkp, fresh_dir, ms, bkp_pk, expected_min_epoch=3)
            self.assertTrue(res_new.verified)

    def test_regression_f03_interrupted_migration_and_historical_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ks_dir = root / "legacy_ks"
            ks_dir.mkdir(parents=True, exist_ok=True)
            log_pk, log_sk = dsa_generate_keypair()

            # Write historical audit log signed with original key
            hist_log = TamperEvidentAuditLog(ks_dir / "keystore_audit.jsonl", signing_sk=log_sk)
            hist_log.append("system", "keystore_init", "success", details={"legacy": True})

            # Legacy state file containing plaintext log_signing_sk_b64
            legacy_state = {
                "active_version": 1,
                "revocation_epoch": 0,
                "grace_period_seconds": 0.0,
                "key_versions": {},
                "revoked_versions": [],
                "revoked_actors": [],
                "devices": {},
                "log_signing_pk_b64": b64encode_str(log_pk),
                "log_signing_sk_b64": b64encode_str(log_sk),
            }
            (ks_dir / "keystore_state.json").write_text(json.dumps(legacy_state), encoding="utf-8")

            # Simulate interrupted migration: key file written, but state file not yet stripped
            key_dir = root / ".legacy_ks-keys"
            key_dir.mkdir(parents=True, exist_ok=True)
            (key_dir / "keystore_audit_signing.key").write_text(b64encode_str(log_sk), encoding="ascii")

            ks = KeyStore(ks_dir)
            ks.audit_log.append("admin", "post_migration_event", "success", details={})

            migrated_text = (ks_dir / "keystore_state.json").read_text(encoding="utf-8")
            self.assertNotIn("log_signing_sk_b64", migrated_text)
            self.assertEqual(list(ks_dir.glob("*.tmp")), [])
            ver = verify_log(ks_dir / "keystore_audit.jsonl", signing_pk=log_pk)
            self.assertTrue(ver.valid)
            self.assertEqual(ver.checked_records, 2)


class TestSecurityRemediationsMedium(unittest.TestCase):
    """Regression tests for F-04 through F-08."""

    def _pair(self, session_id: str = "sess-med"):
        alice = IdentityKeyPair.generate("alice")
        bob = IdentityKeyPair.generate("bob")
        hs = E2EHandshakeState(session_id, alice, "bob")
        acc, bob_sess = accept_handshake(hs.create_init(), bob, alice.dsa_pk)
        alice_sess = hs.finalize_initiator(acc, bob.dsa_pk)
        return alice_sess, bob_sess

    def test_regression_f04_bidirectional_chain_key_separation(self) -> None:
        alice_sess, bob_sess = self._pair("sess-f04")
        # Initiator send == Responder recv; Responder send == Initiator recv; opposite send chains differ
        self.assertEqual(alice_sess._send_chain, bob_sess._recv_chain)
        self.assertEqual(bob_sess._send_chain, alice_sess._recv_chain)
        self.assertNotEqual(alice_sess._send_chain, bob_sess._send_chain)

        # Both directions work concurrently at seq=1
        m_a2b = alice_sess.encrypt_message(b"from-alice-1")
        m_b2a = bob_sess.encrypt_message(b"from-bob-1")
        d_b, err_b = bob_sess.receive_envelope(m_a2b)
        d_a, err_a = alice_sess.receive_envelope(m_b2a)
        self.assertIsNone(err_b)
        self.assertIsNone(err_a)
        self.assertEqual(d_b, [(1, b"from-alice-1")])
        self.assertEqual(d_a, [(1, b"from-bob-1")])

        # Cross-direction substitution fails
        m_a2b_2 = alice_sess.encrypt_message(b"reflect-me")
        forged_reflect = EncryptedEnvelope(
            m_a2b_2.session_id, m_a2b_2.msg_id, 2, "bob", "alice", m_a2b_2.nonce_b64, m_a2b_2.ciphertext_b64
        )
        _, err_ref = alice_sess.receive_envelope(forged_reflect)
        self.assertIsNotNone(err_ref)
        self.assertIn("authentication_failed", err_ref.reason)

    def test_regression_f05_unauthenticated_packet_does_not_advance_recv_chain(self) -> None:
        alice_sess, bob_sess = self._pair("sess-f05")
        initial_chain = bytes(bob_sess._recv_chain)

        # Forged high-seq packet with invalid ciphertext must leave receive state untouched
        junk = EncryptedEnvelope("sess-f05", "junk-1", 65, "alice", "bob", b64encode_str(b"0" * 12), b64encode_str(b"1" * 24))
        _, err = bob_sess.receive_envelope(junk)
        self.assertIsNotNone(err)
        self.assertEqual(bytes(bob_sess._recv_chain), initial_chain)
        self.assertEqual(len(bob_sess._recv_key_cache), 0)
        self.assertEqual(bob_sess.expected_recv_seq, 1)

        # Forged packet with invalid AAD (tampered msg_id) leaves state untouched
        m1 = alice_sess.encrypt_message(b"legit-1")
        bad_aad = EncryptedEnvelope(m1.session_id, "tampered-id", m1.seq, m1.sender_id, m1.recipient_id, m1.nonce_b64, m1.ciphertext_b64)
        _, err_aad = bob_sess.receive_envelope(bad_aad)
        self.assertIsNotNone(err_aad)
        self.assertEqual(bytes(bob_sess._recv_chain), initial_chain)

        # Subsequent legitimate packet (even out-of-order) still succeeds, and replay is rejected
        m2 = alice_sess.encrypt_message(b"legit-2")
        d2, err2 = bob_sess.receive_envelope(m2)
        self.assertIsNone(err2)
        self.assertEqual(d2, [])
        d1, err1 = bob_sess.receive_envelope(m1)
        self.assertIsNone(err1)
        self.assertEqual(d1, [(1, b"legit-1"), (2, b"legit-2")])
        _, err_rep = bob_sess.receive_envelope(m1)
        self.assertEqual(err_rep.reason, "replay_detected")

    def test_regression_f06_service_node_uses_isolated_synced_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ks = KeyStore(Path(tmp))
            cluster = NodeCluster(["node-a"])
            cluster.sync_all(ks)

            # Enroll new device after sync -> stale node must deny until sync_from()
            ks.enroll_device("alice", "dev-late")
            ok_before, reason_before = cluster.nodes["node-a"].authorize_request("alice", "dev-late", 1)
            self.assertFalse(ok_before)
            self.assertEqual(reason_before, "node-a:device_unauthorized")

            # After sync, node authorizes; mutating keystore.state in-place does not mutate node snapshot
            cluster.sync_all(ks)
            ks.state["devices"]["dev-late"]["actor"] = "mallory"
            ok_after, _ = cluster.nodes["node-a"].authorize_request("alice", "dev-late", 1)
            self.assertTrue(ok_after)

            # Revocation propagates on sync
            ks.revoke_device("dev-late", operator="secops")
            cluster.sync_all(ks)
            ok_rev, reason_rev = cluster.nodes["node-a"].authorize_request("alice", "dev-late", 1)
            self.assertFalse(ok_rev)
            self.assertEqual(reason_rev, "node-a:device_revoked")

    def test_regression_f07_sliding_window_catches_rotating_correlation_ids(self) -> None:
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        evts = [
            AccessEvent(1, "e1", format_utc_ms(t0), format_utc_ms(t0), 0, "svc-report-worker", "reports", "billing", "read", "service-reader", "service-reader", "deny", "", "sess-1", "flow-A"),
            AccessEvent(2, "e2", format_utc_ms(t0 + timedelta(seconds=5)), format_utc_ms(t0 + timedelta(seconds=5)), 0, "svc-report-worker", "billing", "archive", "read", "service-reader", "service-reader", "deny", "", "sess-1", "flow-B"),
            AccessEvent(3, "e3", format_utc_ms(t0 + timedelta(seconds=10)), format_utc_ms(t0 + timedelta(seconds=10)), 0, "svc-report-worker", "archive", "identity", "list_roles", "service-reader", "service-reader", "deny", "", "sess-1", "flow-C"),
            # Legitimate workflow for another actor
            AccessEvent(4, "e4", format_utc_ms(t0 + timedelta(seconds=15)), format_utc_ms(t0 + timedelta(seconds=15)), 0, "user-alex", "portal", "catalog", "read", "viewer", "viewer", "allow", "", "sess-alex", "flow-D"),
            # Isolated denial outside window (> 60s later) for a different actor
            AccessEvent(5, "e5", format_utc_ms(t0), format_utc_ms(t0), 0, "user-casey", "portal", "billing", "read", "viewer", "viewer", "deny", "", "sess-casey", "flow-E"),
            AccessEvent(6, "e6", format_utc_ms(t0 + timedelta(seconds=120)), format_utc_ms(t0 + timedelta(seconds=120)), 0, "user-casey", "portal", "archive", "read", "viewer", "viewer", "deny", "", "sess-casey", "flow-F"),
        ]
        det = ContextAwareDetector({}, lateral_window_seconds=60.0)
        res = det.analyze(evts)
        self.assertEqual(len(res["alerts"]), 1)
        self.assertEqual(res["alerts"][0].category, "lateral_movement")
        self.assertEqual(res["alerts"][0].event_ids, ["e1", "e2", "e3"])
        self.assertEqual(res["classifications"]["e4"], "routine")
        self.assertEqual(res["classifications"]["e5"], "isolated_denial")
        self.assertEqual(res["classifications"]["e6"], "isolated_denial")

    def test_regression_f08_privilege_escalation_any_action_label(self) -> None:
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        approvals = {
            "chg-1": {
                "approval_id": "chg-1",
                "approved_by": "user-admin",
                "subject": "user-alex",
                "operation": "grant_role",
                "role": "report-reader",
                "scope": ["reports"],
                "valid_from_utc": format_utc_ms(t0 - timedelta(minutes=1)),
                "valid_until_utc": format_utc_ms(t0 + timedelta(minutes=5)),
            }
        }
        evts = [
            # Unapproved escalation disguised as token_refresh
            AccessEvent(1, "e1", format_utc_ms(t0), format_utc_ms(t0), 0, "user-mallory", "portal", "identity", "token_refresh", "viewer", "operator", "success", "", "s1", "c1"),
            # Approved role change
            AccessEvent(2, "e2", format_utc_ms(t0), format_utc_ms(t0), 0, "user-alex", "admin-console", "identity", "role_change", "viewer", "report-reader", "success", "chg-1", "s2", "c2"),
            # Unchanged role
            AccessEvent(3, "e3", format_utc_ms(t0), format_utc_ms(t0), 0, "user-bob", "portal", "catalog", "read", "viewer", "viewer", "allow", "", "s3", "c3"),
            # Missing/empty role fields handled safely without crashing
            AccessEvent(4, "e4", format_utc_ms(t0), format_utc_ms(t0), 0, "user-bob", "portal", "catalog", "read", "", "", "allow", "", "s3", "c4"),
        ]
        det = ContextAwareDetector(approvals)
        res = det.analyze(evts)
        self.assertEqual(len(res["alerts"]), 1)
        self.assertEqual(res["alerts"][0].category, "unexpected_role_change")
        self.assertEqual(res["alerts"][0].event_ids, ["e1"])
        self.assertEqual(res["classifications"]["e2"], "approved_change")
        self.assertEqual(res["classifications"]["e3"], "routine")
        self.assertEqual(res["classifications"]["e4"], "routine")


class TestSecurityRemediationsLow(unittest.TestCase):
    """Regression tests for F-09, F-10, and F-11."""

    def test_regression_f09_secure_temp_storage_and_symlink_rejection(self) -> None:
        from pqguard.storage import atomic_write_bytes, create_secure_temp_dir, get_state_dir

        d1 = create_secure_temp_dir()
        d2 = create_secure_temp_dir()
        try:
            self.assertNotEqual(d1, d2)
            self.assertTrue(d1.is_dir())
            if os.name == "posix":
                self.assertEqual(d1.stat().st_mode & 0o777, 0o700)

            target = d1 / "state.json"
            atomic_write_bytes(target, b'{"ok":true}')
            self.assertEqual(target.read_bytes(), b'{"ok":true}')
            self.assertEqual(list(d1.glob("*.tmp")), [])
            if os.name == "posix":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

            # Non-directory file passed as TRACK4_STATE_DIR is rejected
            prev = os.environ.get("TRACK4_STATE_DIR")
            os.environ["TRACK4_STATE_DIR"] = str(target)
            try:
                with self.assertRaises(ValueError):
                    get_state_dir()
            finally:
                if prev is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = prev

            # Symlink rejection (when OS permits creating symlinks)
            link_path = d1 / "sym_target.json"
            try:
                os.symlink(target, link_path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(ValueError):
                    atomic_write_bytes(link_path, b"bad")
        finally:
            import shutil

            shutil.rmtree(d1, ignore_errors=True)
            shutil.rmtree(d2, ignore_errors=True)

    def test_regression_f10_strict_identifier_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.environ.get("TRACK4_STATE_DIR")
            os.environ["TRACK4_STATE_DIR"] = tmp
            try:
                dispatch(
                    {
                        "op": "setup",
                        "owners": {"brief": "maya", "None": "True"},
                        "contents": {"brief": "ok", "None": "trap"},
                        "disabled": [],
                    }
                )
                bad_ids = [123, True, None, ["maya"], {"id": "maya"}, object(), "", "   ", "maya\x00"]
                for bad in bad_ids:
                    with self.assertRaises(ValueError):
                        dispatch({"op": "read", "actor": bad, "asset": "brief", "request_id": "r1"})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "read", "actor": "maya", "asset": bad, "request_id": "r2"})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "read", "actor": "maya", "asset": "brief", "request_id": bad})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "revoke", "actor": bad})
                    with self.assertRaises(ValueError):
                        dispatch({"op": "audit", "request_id": bad})
                    with self.assertRaises(ValueError):
                        dispatch(
                            {
                                "op": "protected_read",
                                "actor": bad,
                                "asset": "brief",
                                "challenge": "c",
                                "public_key": "AA==",
                            }
                        )
                # Valid string IDs still succeed
                ok = dispatch({"op": "read", "actor": "maya", "asset": "brief", "request_id": "r-valid"})
                self.assertEqual(ok, {"decision": "allow", "body": "ok"})
            finally:
                if prev is None:
                    os.environ.pop("TRACK4_STATE_DIR", None)
                else:
                    os.environ["TRACK4_STATE_DIR"] = prev

    def test_regression_f11_wal_recovery_auditability_and_idempotence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ks_dir = Path(tmp) / "ks"
            ks = KeyStore(ks_dir)
            ks.rotate_key(actor="admin")
            ks.revoke_key_version(1, operator="secops")
            with self.assertRaises(RuntimeError):
                ks.rotate_key(actor="admin", simulate_crash_before_commit=True)
            self.assertTrue((ks_dir / "pending_rotation.json").is_file())

            # Restart records wal_recovery BEFORE removing pending_rotation.json
            ks2 = KeyStore(ks_dir)
            self.assertFalse((ks_dir / "pending_rotation.json").is_file())
            rec = ks2.recover_after_crash()
            self.assertTrue(rec["rolled_back_pending_rotation"])
            self.assertEqual(rec["active_version"], 2)

            records = ks2.audit_log.read_all()
            wal_events = [r for r in records if r["action"] == "wal_recovery"]
            self.assertEqual(len(wal_events), 1)
            self.assertEqual(wal_events[0]["outcome"], "rolled_back")
            self.assertEqual(wal_events[0]["details"]["to_version"], 3)

            # Malformed WAL is safely recorded and discarded
            (ks_dir / "pending_rotation.json").write_text("{corrupt-wal", encoding="utf-8")
            rec_mal = ks2.recover_after_crash()
            self.assertTrue(rec_mal["malformed_wal"])
            self.assertFalse((ks_dir / "pending_rotation.json").is_file())
            wal_events2 = [r for r in ks2.audit_log.read_all() if r["action"] == "wal_recovery"]
            self.assertEqual(wal_events2[-1]["outcome"], "malformed_wal_discarded")

            # Repeated recovery is idempotent
            rec_idem = ks2.recover_after_crash()
            self.assertFalse(rec_idem["rolled_back_pending_rotation"])
            self.assertFalse(rec_idem["malformed_wal"])
            self.assertTrue(verify_log(ks_dir / "keystore_audit.jsonl", signing_pk=ks2.log_signing_pk).valid)


if __name__ == "__main__":
    unittest.main()
