# Trust, but verify — Project Brief

## Page 1: USP, Architecture, and Fallback Video

**Project:** PQGuard  
**Team:** Yugantar Track 4 Team  
**Repository and commit:** *(Insert public GitHub URL and commit hash before submission)*  
**Demo entry point:** `python demo_walkthrough.py` (and `track4_service.py` for Adapter v1)

### Unique Selling Proposition (USP)

PQGuard protects files, keys, and E2E messages for organizations transitioning to post-quantum security when devices are lost, keys rotate, or identities escalate unexpectedly. Unlike bolt-on encryption wrappers, PQGuard unifies **ML-KEM-768 / ML-DSA-65** lifecycle enforcement (grace-cutoff rotation, multi-node revocation, WAL crash recovery, signed backups) with an **explainable, non-AI rule-and-graph detector** that correlates change-control approvals against out-of-order and clock-skewed logs. Every decision is recorded in a hash-chained, ML-DSA-65 signed audit log immune to log-injection spoofing.

### Architecture

- **Identity & Access Adapter (`track4_service.py`, `pqguard/service.py`)**: Stateless-per-process JSON-over-stdin service backed by atomic temp-file + `fsync` + `os.replace` state in `TRACK4_STATE_DIR` (or OS temp dir). Enforces owner-based access, immediate revocation, and `protected_read` using **ML-KEM-768** (`pqcrypto==0.4.0`) + **HMAC-SHA-256** (`challenge || body`).
- **Key & Node Lifecycle (`pqguard/keystore.py`, `pqguard/nodes.py`, `pqguard/backup.py`)**: Versioned key records with configurable grace windows and strict post-cutoff rejection across `NodeCluster` nodes. Interrupted rotations roll back via `pending_rotation.json` WAL while preserving monotonic revocations. Backups use **AES-256-GCM** + **SHA-256** + **ML-DSA-65** signatures.
- **E2E Messaging (`pqguard/e2e.py`)**: Ephemeral ML-KEM-768 handshake authenticated by long-term ML-DSA-65 keys, HKDF-SHA-256 per-message ratcheting, AES-256-GCM with AAD binding (`session_id`, `msg_id`, `seq`, `sender_id`, `recipient_id`), bounded reorder buffering, and identity-bound resumption tickets.
- **Explainable Detector (`pqguard/detector.py`)**: Cross-references `approvals.json`, corrects `source_clock_offset_ms` within ±300,000 ms (flagging `order_uncertain` within ±500 ms), and detects unapproved privilege changes and multi-hop lateral movement.

```
[Client / Peer] --(ML-KEM-768 + ML-DSA-65)--> [track4_service / NodeCluster]
                                                       |
     +-----------------------+-------------------------+----------------------+
     v                       v                         v                      v
[KeyStore WAL]      [Signed Audit Log]        [Encrypted Backup]     [Context Detector]
(crash-safe)        (SHA-256 + ML-DSA-65)     (AES-GCM + ML-DSA)     (approvals + graph)
```

### Accessible Five-Minute Fallback Video Link

**Video link:** *(Paste unlisted YouTube / Google Drive link with public read access)*  
**Duration:** 5 minutes  
**Access checked:** *(Date & confirmation that reviewers can open without requesting permission)*

**Observed outcome:** In local sandbox verification, `validate.py` passes all Adapter v1 checks, all 12 unit/integration tests pass in ~1.0s, multi-node revocation propagates across 3 nodes in ~29.4 ms, and the detector achieves F1 = 1.000 (0.00 false alerts per 1,000 benign events) on both the 22-event practice set and a 1,200-event benchmark.

<div style="page-break-before: always;"></div>

## Page 2: One-Page Threat Model

### Assets

| Asset | Required Security Property |
| --- | --- |
| Protected resource bodies (`contents`) | Confidentiality & access-control integrity (no disclosure on `deny`) |
| Keystore & device keys (`ML-KEM-768`, `ML-DSA-65`) | Confidentiality, authenticity, version monotonicity (revoked stays revoked) |
| Encrypted backups | Confidentiality, integrity, authenticity (reject 1-bit tampering) |
| Audit logs (`audit.jsonl`) | Integrity, non-repudiation, record-boundary isolation |
| E2E session payloads & resumption tickets | Confidentiality, forward secrecy, replay resistance, peer/recipient binding |

### Adversaries

- **Unauthorized / revoked caller**: Possesses valid or stale identifiers/keys and attempts unauthorized `read`, `protected_read`, or session resumption.
- **Compromised device / post-session key thief**: Obtains a lost device's keys or compromises long-term `ML-DSA-65` identity keys after a session completes.
- **Malicious log/backup modifier or injector**: Attempts to inject fake JSONL records via user-controlled strings, alter `outcome`/`actor`, or tamper with backup ciphertexts.
- **Lateral-movement insider/service**: Uses valid credentials across unexpected service edges (`reports -> billing -> archive -> identity`).

### Trust Boundaries

1. **Process/Adapter Boundary**: Untrusted JSON stdin enters `track4_service.py`; identity & ownership checks occur before reading `contents` or encapsulating shared secrets.
2. **Node Sync Boundary**: Control-plane `KeyStore` pushes revocation epochs and key-version cutoffs to `ServiceNode` instances.
3. **Storage & Backup Boundary**: State transitions use atomic WAL writes; backups are verified (ML-DSA-65 + SHA-256 + AES-GCM) before touching live state.
4. **Telemetry Boundary**: Raw `event_time_utc` is preserved; `source_clock_offset_ms` is bounded (±300,000 ms) before timeline sorting.

### Assumptions

- `TRACK4_STATE_DIR` (or OS temp dir) provides local filesystem integrity and POSIX/Windows atomic `os.replace`.
- Backup wrapping `master_secret` and log-verification `signing_pk` are provisioned out-of-band.
- `approvals.json` accurately reflects authorized change-control tickets.
- Source clock offsets stay within ±5 minutes (±300,000 ms) with ±500 ms uncertainty.

### Defenses

- **Post-quantum KEM & Signatures**: `pqcrypto==0.4.0` (`ML-KEM-768`, `ML-DSA-65`) for `protected_read`, E2E handshakes, backups, and audit logs.
- **Forward Secrecy & Replay/Recipient Binding**: Ephemeral ML-KEM-768 keys erased post-handshake; HKDF-SHA-256 chain ratcheting; AES-256-GCM AAD binds `session_id`, `msg_id`, `seq`, `sender_id`, `recipient_id`; replay cache rejects duplicates.
- **Crash & Backup Safety**: WAL `pending_rotation.json` rollback; monotonic `revoked_versions`; verify-before-restore backup pipeline.
- **Log & Detection Integrity**: Canonical JSONL prevents newline/field injection; deterministic rule/graph detector separates approved changes and isolated denials from privilege escalation and lateral movement.

### Exclusions and Remaining Risks

- **In-process simulation**: Multi-node propagation and packet loss/reordering are simulated in-process, not over distributed WAN hosts.
- **Python memory**: `bytearray` zeroization is best-effort; immutable `bytes` in CPython/FFI may linger until GC.
- **Side channels & DoS**: Timing side channels in Python glue code and network-level DoS are out of scope.
- **Synthetic evaluation**: Practice and benchmark metrics validate logic on synthetic logs, not production traffic.
