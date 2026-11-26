# PQGuard — Post-Quantum Identity, Access Control & Explainable Audit Detection

**Track 4: "Trust, but verify" | Yugaantar DevForge**

PQGuard is a post-quantum cryptographic access-control, key-lifecycle, end-to-end messaging, and explainable log-detection prototype built using standardized NIST PQC algorithms (**ML-KEM-768** / FIPS 203 and **ML-DSA-65** / FIPS 204) via `pqcrypto==0.4.0`, **AES-256-GCM**, **HKDF-SHA-256**, and **HMAC-SHA-256**.

## Repository Layout

- `track4_service.py` — Track 4 Adapter v1 CLI/JSON-over-stdin entry point (`setup`, `read`, `revoke`, `audit`, `protected_read`). Uses only Python 3.12+ stdlib and `pqcrypto==0.4.0`.
- `threat-model.json` — Adapter threat-model declaration (`{"asset":"protected-resource","boundary":"identity-check"}`).
- `pqguard/` — Core library:
  - `crypto.py` — ML-KEM-768, ML-DSA-65, HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM, buffer zeroization.
  - `storage.py` — Crash-safe atomic file persistence (`TRACK4_STATE_DIR` / OS temp fallback).
  - `audit_log.py` — Hash-chained, ML-DSA-65 signed JSONL log with injection-safe canonicalization.
  - `keystore.py` — Versioned key rotation with configurable grace cutoff, WAL crash recovery, and device enrollment/revocation.
  - `nodes.py` — Multi-node cluster enforcement and revocation propagation latency measurement.
  - `backup.py` — AES-256-GCM encrypted and ML-DSA-65 signed backup/restore with strict integrity verification.
  - `detector.py` — Deterministic, explainable rule- and graph-based detector for privilege escalation, lateral movement, out-of-order delivery, and source clock offsets.
  - `e2e.py` — Ephemeral ML-KEM-768 + ML-DSA-65 forward-secure E2E messaging with replay/recipient binding, reorder buffering, and identity-bound session resumption.
  - `service.py` — Adapter v1 request dispatcher.
- `tests/test_all_goals.py` — Automated verification suite covering all 12 challenge objectives and Adapter v1.
- `demo_walkthrough.py` — End-to-end demonstration of all 12 objectives.
- `docs/two-page-brief.md` — 2-page project brief & 1-page threat model (ready for PDF export).
- `docs/evidence-sheet.md` — Measured evidence record mapped to all 12 goals.

## Clean-Machine Setup

### Prerequisites
- Python 3.12+
- `pip`

### Install Dependencies
```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Dependencies
- `pqcrypto==0.4.0` (ML-KEM-768, ML-DSA-65)
- `cryptography>=42.0.0` (AES-256-GCM for E2E messaging and encrypted backups; not required by `track4_service.py`)

## Running & Verifying

### 1. Run all 12-goal unit & integration tests
```bash
python -m unittest discover -s tests -v
```

### 2. Run the end-to-end walkthrough
```bash
python demo_walkthrough.py
```

### 3. Run the Track 4 Adapter v1 directly
```bash
echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo note"},"disabled":[],"key_material":"synthetic-only"}' | python track4_service.py
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r01"}' | python track4_service.py
```

## Measured Highlights (Local Sandbox)
- **Adapter v1**: Passes all public `validate.py` checks and `protected_read` ML-KEM-768 + HMAC-SHA-256 verification.
- **ML-DSA-65 latency** (measured locally): keygen ~2.11 ms, sign ~0.45 ms, verify ~0.21 ms.
- **Multi-node revocation propagation** (3 simulated nodes): ~29.4 ms max propagation delay.
- **Detector** (1,200-event deterministic synthetic benchmark + 22-event toolkit practice set): F1 = 1.000, false alerts per 1,000 benign events = 0.00, median time-to-alert = 120.00 ms (driven by simulated 120 ms collector delivery delay).

## Known Limitations
- Multi-node cluster (`NodeCluster`) and E2E packet loss/reordering are simulated in-process rather than over real WAN sockets.
- Python `zeroize_bytearray()` overwrites mutable `bytearray` buffers in-place, but immutable `bytes` objects managed by CPython/FFI cannot be guaranteed zeroized by user-space Python.
- Clock-offset correction relies on `source_clock_offset_ms` provided by telemetry; uncalibrated or maliciously forged source clocks outside ±300,000 ms are flagged rather than trusted.
