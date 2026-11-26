# SECURITY TEST RESULTS — TRUSTGUARD PQ (PQGuard)

**Audit Date:** 2026-11-26  
**Commit:** `c5fa795` (`main`)  
**Mode:** Final Hardening Complete (`F-01`–`F-11` Remediated; `F-12` Documented)

---

## 1. Existing Tests Executed

| Suite / Command | Result | Details |
| --- | --- | --- |
| `python -m unittest discover -s tests -v` (current repo) | **28 PASS, 1 SKIPPED** (2.291s) | 11 original tests + 17 High/Medium/Low regression tests (`F-01`–`F-11`) passed; `test_practice_dataset_100_percent_f1` skipped because `_toolkit/` was removed. |
| `python -m unittest discover -s tests -v` (with `_toolkit/`) | **12 PASS, 0 FAIL** (0.924s) | Verified 100% F1 on both 22-event practice set and 1,200-event benchmark. |
| `python _toolkit/validate.py --entry track4_service.py` | **PASS** | Verified prior to `_toolkit/` removal (Adapter v1 contract unchanged). |
| `python demo_walkthrough.py` | **PASS** (Exit 0) | End-to-end 12-goal demonstration completed cleanly (`max_propagation_ms=35.162 ms`, `rolled_back=True`, `F1=1.000`, `FPR/1000=0.00`, `median_TTA=120.00 ms`). |

---

## 2. Adversarial Security PoCs Executed

| PoC ID | Finding | Outcome | Observed Output |
| --- | --- | --- | --- |
| `POC1_SHARED_CHAIN_KEY` | `F-04` (Shared bidirectional E2E chain key) | **FIXED / BLOCKED** | `POC1_SHARED_CHAIN_KEY: False` |
| `POC2_RESUMPTION_WITHOUT_POP` | `F-01` (Session resumption without PoP) | **FIXED / BLOCKED** | `POC2_RESUMPTION_WITHOUT_POP: False missing_pop_proof` |
| `POC3_BACKUP_ROLLBACK_RESURRECTED_DEV` | `F-02` (Backup rollback resurrects revoked device) | **FIXED / BLOCKED** | `POC3_BACKUP_ROLLBACK_RESURRECTED_DEV: False False Backup rollback rejected: backup epoch 1 < current epoch 3` |
| `POC4_LATERAL_EVASION_ALERTS` | `F-07` (Lateral movement evasion via `correlation_id`) | **FIXED / DETECTED** | `POC4_LATERAL_EVASION_ALERTS: 1 sliding_window_unexpected_service_edges` |
| `POC5_SK_IN_STATE_FILE` | `F-03` (Co-located `log_signing_sk_b64` in state file) | **FIXED / BLOCKED** | `POC5_SK_IN_STATE_FILE: False` |
| `POC6_UNAUTH_CACHE_SIZE` | `F-05` (Unauthenticated `seq=65` populates key cache) | **FIXED / BLOCKED** | `POC6_UNAUTH_CACHE_SIZE: 0 authentication_failed:InvalidTag` |
| `POC7_UNSYNCED_NODE_READS_LIVE_DEVICES` | `F-06` (`ServiceNode` reads live `keystore.state`) | **FIXED / BLOCKED** | `POC7_UNSYNCED_NODE_READS_LIVE_DEVICES: False node-a:device_unauthorized` |
| `POC8_NON_ROLE_CHANGE_ESCALATION_ALERTS` | `F-08` (Escalation on `action="token_refresh"` missed) | **FIXED / DETECTED** | `POC8_NON_ROLE_CHANGE_ESCALATION_ALERTS: 1 unexpected_role_change` |

---

## 3. Regression Tests Added

- `tests/test_all_goals.py::TestSecurityRemediationsHigh::test_regression_f01_resumption_rejects_public_key_impersonation_and_replays`
- `tests/test_all_goals.py::TestSecurityRemediationsHigh::test_regression_f01_concurrent_replay_and_challenge_burning`
- `tests/test_all_goals.py::TestSecurityRemediationsHigh::test_regression_f02_backup_rollback_rejected_after_revocation`
- `tests/test_all_goals.py::TestSecurityRemediationsHigh::test_regression_f02_full_local_snapshot_rollback_and_fresh_host`
- `tests/test_all_goals.py::TestSecurityRemediationsHigh::test_regression_f03_state_files_do_not_expose_signing_private_key`
- `tests/test_all_goals.py::TestSecurityRemediationsHigh::test_regression_f03_interrupted_migration_and_historical_verification`
- `tests/test_all_goals.py::TestSecurityRemediationsMedium::test_regression_f04_bidirectional_chain_key_separation`
- `tests/test_all_goals.py::TestSecurityRemediationsMedium::test_regression_f05_unauthenticated_packet_does_not_advance_recv_chain`
- `tests/test_all_goals.py::TestSecurityRemediationsMedium::test_regression_f06_service_node_uses_isolated_synced_snapshot`
- `tests/test_all_goals.py::TestSecurityRemediationsMedium::test_regression_f07_sliding_window_catches_rotating_correlation_ids`
- `tests/test_all_goals.py::TestSecurityRemediationsMedium::test_regression_f08_privilege_escalation_any_action_label`
- `tests/test_all_goals.py::TestSecurityRemediationsLow::test_regression_f09_secure_temp_storage_and_symlink_rejection`
- `tests/test_all_goals.py::TestSecurityRemediationsLow::test_regression_f10_strict_identifier_validation`
- `tests/test_all_goals.py::TestSecurityRemediationsLow::test_regression_f11_wal_recovery_auditability_and_idempotence`

---

## 4. Actual Measured Performance

- **ML-DSA-65** (`pqcrypto==0.4.0`): keygen `2.11 ms`, sign `0.45 ms`, verify `0.21 ms`
- **Multi-node revocation propagation** (3 simulated nodes): `31.341 ms` max
- **Detector** (1,200-event deterministic benchmark): `F1 = 1.000`, `FPR/1000 = 0.00`, `median_TTA = 120.00 ms`

---

## 5. Commands to Reproduce

```powershell
python -m unittest discover -s tests -v
python demo_walkthrough.py
```
