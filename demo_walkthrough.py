"""End-to-end walkthrough of all 12 Track 4 ('Trust, but verify') objectives."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import tempfile
import time

from pqguard.audit_log import TamperEvidentAuditLog, verify_log
from pqguard.backup import create_backup, restore_backup
from pqguard.crypto import dsa_generate_keypair
from pqguard.detector import (
    AccessEvent,
    ContextAwareDetector,
    evaluate_against_labels,
    format_utc_ms,
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


def main() -> None:
    print("=== PQGuard (Track 4: Trust, but verify) Walkthrough ===\n")
    with tempfile.TemporaryDirectory(prefix="pqguard-demo-") as tmp:
        root = Path(tmp)

        # 1. Key rotation & cutoff
        ks = KeyStore(root / "ks", grace_period_seconds=5.0)
        ks.enroll_device("alice", "dev-alice-1")
        ks.enroll_device("bob", "dev-bob-1")
        cluster = NodeCluster(["node-a", "node-b", "node-c"])
        cluster.sync_all(ks)
        t0 = time.time()
        v2 = ks.rotate_key(actor="operator", grace_period_seconds=5.0, now=t0)
        cluster.sync_all(ks)
        grace_ok, _ = cluster.nodes["node-a"].authorize_request("alice", "dev-alice-1", 1, ks, now=t0 + 1.0)
        cutoff_ok, cutoff_reason = cluster.nodes["node-a"].authorize_request("alice", "dev-alice-1", 1, ks, now=t0 + 6.0)
        print(f"[1] Key rotation v1->v{v2} (5.0s grace): during_grace={grace_ok}, after_cutoff={cutoff_ok} ({cutoff_reason})")

        # 2. Revocation across nodes & re-enrollment
        t_rev = time.perf_counter()
        ks.revoke_device("dev-alice-1", operator="secops")
        prop = cluster.propagate_revocation(ks, t_rev)
        bob_ok, _ = cluster.nodes["node-c"].authorize_request("bob", "dev-bob-1", 2, ks)
        ks.enroll_device("alice", "dev-alice-2")
        cluster.sync_all(ks)
        alice_new_ok, _ = cluster.nodes["node-c"].authorize_request("alice", "dev-alice-2", 2, ks)
        print(
            f"[2] Multi-node revocation: max_propagation_ms={prop['max_propagation_ms']:.3f} ms, "
            f"peer_bob={bob_ok}, alice_reenrolled={alice_new_ok}"
        )

        # 3. Crash recovery
        ks.revoke_key_version(1, operator="secops")
        try:
            ks.rotate_key(actor="operator", simulate_crash_before_commit=True)
        except RuntimeError:
            pass
        recovered = KeyStore(root / "ks").recover_after_crash()
        print(f"[3] Crash recovery: rolled_back={recovered['rolled_back_pending_rotation']}, active_v={recovered['active_version']}, revoked={recovered['revoked_versions']}")

        # 4. Backup integrity
        master_secret = os.urandom(32)
        bkp_pk, bkp_sk = dsa_generate_keypair()
        bkp_path = root / "backup.json"
        bkp = create_backup(ks, bkp_path, master_secret, bkp_sk, backup_id="bkp-demo")
        res_ok = restore_backup(bkp_path, root / "restored", master_secret, bkp_pk)
        bundle = json.loads(bkp_path.read_text(encoding="utf-8"))
        bundle["manifest"]["ciphertext_b64"] = "X" + bundle["manifest"]["ciphertext_b64"][1:]
        (root / "backup_bad.json").write_text(json.dumps(bundle), encoding="utf-8")
        res_bad = restore_backup(root / "backup_bad.json", root / "restored_bad", master_secret, bkp_pk)
        print(f"[4] Backup integrity: valid_restore={res_ok.verified}, tampered_restore={res_bad.verified} ({res_bad.error})")

        # 5. Log integrity
        log_pk, log_sk = dsa_generate_keypair()
        log = TamperEvidentAuditLog(root / "audit.jsonl", signing_sk=log_sk)
        log.append("user-mallory", "read", "deny", details={"input": 'bad\n{"seq":2,"actor":"admin"}'})
        log.append("alice", "read", "allow", details={"asset": "brief"})
        ver = verify_log(root / "audit.jsonl", signing_pk=log_pk)
        print(f"[5] Log integrity: valid={ver.valid}, checked_records={ver.checked_records}")

        # 6, 7, 8. Detector benchmark (1,200 events)
        rng = random.Random(42)
        base_t = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = []
        truth = {}
        for i in range(1200):
            t_ev = base_t + timedelta(seconds=i)
            offset = rng.choice([0, 0, 1500, -1200])
            eid = f"e-{i:04d}"
            if i < 1140:
                events.append(
                    AccessEvent(
                        i + 1, eid, format_utc_ms(t_ev + timedelta(milliseconds=offset)),
                        format_utc_ms(t_ev + timedelta(milliseconds=120)), offset,
                        "user-good", "portal", "catalog", "read", "viewer", "viewer", "allow", "", f"s-{i//20}", f"c-{i//10}"
                    )
                )
                truth[eid] = "routine"
            elif i < 1160:
                events.append(
                    AccessEvent(
                        i + 1, eid, format_utc_ms(t_ev + timedelta(milliseconds=offset)),
                        format_utc_ms(t_ev + timedelta(milliseconds=120)), offset,
                        f"user-rogue-{i}", "admin-console", "identity", "role_change", "viewer", "operator", "success", "", f"sr-{i}", f"cr-{i}"
                    )
                )
                truth[eid] = "unexpected_role_change"
            else:
                pair = (i - 1160) // 2
                hop = (i - 1160) % 2
                events.append(
                    AccessEvent(
                        i + 1, eid, format_utc_ms(t_ev + timedelta(milliseconds=offset)),
                        format_utc_ms(t_ev + timedelta(milliseconds=120)), offset,
                        "svc-report-worker", "reports" if hop == 0 else "billing", "billing" if hop == 0 else "archive",
                        "read", "service-reader", "service-reader", "deny", "", "sess-lat", f"flow-lat-{pair}"
                    )
                )
                truth[eid] = "lateral_movement_candidate"
        labels_path = root / "labels.csv"
        labels_path.write_text("event_id,label,reason\n" + "\n".join(f"{k},{v},sim" for k, v in truth.items()), encoding="utf-8")
        det = ContextAwareDetector({})
        metrics = evaluate_against_labels(events, labels_path, det)
        print(
            f"[6-8] Detector (1200 events): F1={metrics.f1:.3f}, "
            f"FPR/1000={metrics.false_alerts_per_1000_benign:.2f}, median_TTA={metrics.median_time_to_alert_ms:.2f} ms"
        )

        # 9, 10, 11, 12. E2E messaging
        alice_id = IdentityKeyPair.generate("alice")
        bob_id = IdentityKeyPair.generate("bob")
        eve_id = IdentityKeyPair.generate("eve")
        hs = E2EHandshakeState("sess-e2e", alice_id, "bob")
        accept, bob_sess = accept_handshake(hs.create_init(), bob_id, alice_id.dsa_pk)
        alice_sess = hs.finalize_initiator(accept, bob_id.dsa_pk)

        m1 = alice_sess.encrypt_message(b"hello-1")
        m2 = alice_sess.encrypt_message(b"hello-2")
        d2, _ = bob_sess.receive_envelope(m2)
        d1, _ = bob_sess.receive_envelope(m1)
        _, replay_err = bob_sess.receive_envelope(m1)
        forged = EncryptedEnvelope(m1.session_id, "forged-id", 3, m1.sender_id, "eve", m1.nonce_b64, m1.ciphertext_b64)
        _, rec_err = bob_sess.receive_envelope(forged)
        alice_sess.close()
        bob_sess.close()

        res_auth = SessionResumptionAuthority()
        ticket = res_auth.issue_ticket("sess-e2e", "alice", alice_id.dsa_pk)
        ok_res = res_auth.resume_session(ticket, "sess-e2e", "alice", alice_id.dsa_pk, lambda _: True)
        bad_res = res_auth.resume_session(ticket, "sess-e2e", "eve", eve_id.dsa_pk, lambda _: True)
        print(
            f"[9-12] E2E Messaging: reordered_delivery={[x[1].decode() for x in d1]}, "
            f"replay={replay_err.reason if replay_err else None}, "
            f"recipient_bind={rec_err.reason if rec_err else None}, "
            f"eph_erased={hs._eph_sk is None}, "
            f"resume_owner={ok_res.allowed}, resume_imposter={bad_res.allowed} ({bad_res.reason})"
        )


if __name__ == "__main__":
    main()
