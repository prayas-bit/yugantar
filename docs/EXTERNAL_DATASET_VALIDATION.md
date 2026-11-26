# External Dataset Validation Report — TRUSTGUARD PQ

This document preserves all external validation benchmarks separately without overwriting prior results.

---

## Summary Comparison Across All Evaluations

| Evaluation | Dataset | Records / Scope | F1 | FPR | Notes |
| --- | --- | --- | ---: | ---: | --- |
| **A. Native Benchmark** | TRUSTGUARD PQ Synthetic | `1,200` identity events | `1.000` | `0.000` (`0.00/1k`) | Full RBAC, approvals, timestamps, and service edges present |
| **B. UNSW-NB15 (Unfiltered)** | `UNSW_NB15_testing-set.csv` | `55,945` unique flows | `0.559678` | `1.000` (`1,000/1k`) | Placeholder `"unknown-flow-actor"` collapsed all flows |
| **C. UNSW-NB15 (Scoped)** | `UNSW_NB15_testing-set.csv` | `0` evaluatable (`55,945` excluded) | `N/A` | `N/A` | Out-of-scope network flows; no identity/RBAC context |
| **D. OTRF APT3 Day 1** | `caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz` | `2,067` evaluatable Windows Security events (`99,837` excluded) | `N/A` | `N/A` | Real users, timestamps & sessions; **unlabelled** (no per-event `0/1` truth) |

---

## Part 1: Identity Dataset Suitability Comparison

| Dataset & Source | User IDs | Timestamps | Host / Service | Auth Events | Role / Priv Events | Session IDs | Ground-Truth Labels | License & Access | Suitability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **LANL Multi-Source (`csr.lanl.gov/data/cyber1`)** | Yes | Yes | Yes | Yes | Partial (process) | Partial | Yes (`redteam.txt`) | Research; **gated by email form + ~7 GB** | High, but inaccessible without manual form |
| **CERT Insider Threat r4.2 (`DOI: 10.1184/R1/12841247.v1`)** | Yes | Yes | Yes (`pc`) | Yes (`logon.csv`) | Yes (`LDAP/`) | No | Yes (`answers.tar.bz2`) | **CC BY 4.0**; `answers.tar.bz2` (1.25 MB) verified, `r4.2.tar.bz2` is **4.82 GB** | High, but full r4.2 archive too large for session |
| **AIT-LDS v2 / AIT-ADS (Zenodo `5789064` / `8263181`)** | Yes | Yes | Yes | Yes (`auth.log`) | Yes (`audit.log`) | Partial | Yes (`labels/`) | Open; **Zenodo returned 403 Forbidden** + 7.1 GB | High, but blocked by Zenodo 403 |
| **OTRF Security-Datasets (`OTRF/Security-Datasets`, APT3 Day 1)** | **Yes** | **Yes** | **Yes** | **Yes** (`4624`/`4769`) | **Yes** (`4672`/`4703`) | **Yes** (`LogonId`) | **No** (unlabelled red-team + OS noise) | **Open (MIT/Apache)**; directly downloadable (12.6 MB) | **Best accessible** for real identity/session/timestamp ingestion; cannot measure F1 |

---

## Part 2: UNSW-NB15 Validation (Preserved Results B & C)

## 1. Dataset Source, Version & License
- **Dataset:** UNSW-NB15 (`UNSW_NB15_testing-set.csv`, 82,332 records)
- **Original Source:** Australian Centre for Cyber Security (ACCS), UNSW Canberra — [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **Downloaded Mirror URL:** `https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv`
- **SHA-256:** `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`
- **Citation:** Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems*. Military Communications and Information Systems Conference (MilCIS), IEEE.
- **License / Usage:** Publicly released for academic and research evaluation; excluded from Git via `.gitignore` (`data/external/`).
- **Why Selected:** UNSW-NB15 is a widely cited, modern network intrusion dataset containing 9 attack categories (`Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms`) alongside `Normal` traffic, testing how TRUSTGUARD PQ's detector behaves outside its native identity/RBAC log domain.

---

## 2. Adapter & Field Mapping (`pqguard/external_unsw_adapter.py`)

UNSW-NB15 is a **network-flow** dataset, not an identity/RBAC access log. The adapter preserves the original CSV untouched, deduplicates exact feature rows, and avoids fabricating identity claims:

| `AccessEvent` Field | UNSW-NB15 Source | Mapping / Assumption |
| --- | --- | --- |
| `event_id` | `id` | `unsw-<id>` |
| `source_service` | `proto` | Transport/network protocol (`tcp`, `udp`, `arp`, etc.) |
| `target_service` | `service` | Application service (`http`, `dns`, `ftp`, etc.) or `proto:<proto>` when `"-"` |
| `action` | `state` | `flow:<state>` |
| `outcome` | `state` | Heuristic: `FIN`/`CON`/`ACC`/`CLO` → `allow`; `RST`/`REQ`/`INT`/etc. → `deny` |
| `actor` | *(unavailable)* | `"unknown-flow-actor"` (source IP omitted in `UNSW_NB15_testing-set.csv`) |
| `role_before`, `role_after` | *(unavailable)* | `"network-flow"` (no RBAC roles; never fabricates privilege escalation) |
| `approval_id` | *(unavailable)* | `""` (no change-control context) |
| `session_id` | *(unavailable)* | `"unsw-no-session"` |
| `correlation_id` | `id` | `unsw-<id>` |
| `event_time_utc`, `received_time_utc` | *(unavailable)* | Fixed epoch `1970-01-01T00:00:00.000Z` (timestamps omitted in CSV) |
| `source_clock_offset_ms` | *(unavailable)* | `0` |

---

## 3. Evaluation Methodology & Measured Results

- **Methodology:** `ContextAwareDetector(approvals={})` is purely rule-based (not trained on UNSW-NB15). Ground-truth `label` (`0` = Normal, `1` = Attack) and `attack_cat` are withheld from the detector and used only for scoring.
- **Adapter Counts:** `82,332` total rows → `55,945` mapped unique records (`26,387` duplicate rows removed, `0` rejected).
- **Class Distribution (unique):** `Normal`: 34,206 | `Exploits`: 7,609 | `Fuzzers`: 4,838 | `Generic`: 3,657 | `Reconnaissance`: 2,703 | `DoS`: 1,718 | `Analysis`: 446 | `Backdoor`: 346 | `Shellcode`: 378 | `Worms`: 44.

| Metric | TRUSTGUARD PQ Benchmark (1,200 events) | UNSW-NB15 External (55,945 unique flows) |
| --- | --- | --- |
| **Precision** | `1.000000` | `0.388578` |
| **Recall** | `1.000000` | `1.000000` |
| **F1 Score** | `1.000000` | `0.559678` |
| **False Positive Rate** | `0.000000` (`0.00 / 1,000`) | `1.000000` (`1,000.0 / 1,000`) |
| **Confusion Matrix** | `TP=60, TN=1140, FP=0, FN=0` | `TP=21739, TN=0, FP=34206, FN=0` |
| **Analysis Latency** | `120.00 ms` median TTA (incl. delivery delay) | `240.04 ms` total (`0.004291 ms/event`) |

---

## 4. Root-Cause Investigation: Why All 55,945 Records Triggered `lateral_movement_candidate`

1. **Adapter Collapsing:** `UNSW_NB15_testing-set.csv` omits `srcip`, `Stime`/`Ltime`, and RBAC roles. `external_unsw_adapter.py` assigns every row `actor="unknown-flow-actor"`, `event_time_utc="1970-01-01T00:00:00.000Z"`, and `role="network-flow"`.
2. **Detector Behavior on Placeholder Context:** Because `"network-flow"` is absent from `DEFAULT_ALLOWED_EDGES`, `_is_expected_edge()` returns `False` for every flow. `ContextAwareDetector`'s sliding-window rule (`lateral_window_seconds=60.0`) then groups all 55,945 flows under the single shared `"unknown-flow-actor"` at `delta = 0s <= 60s` with `>= 2` target services, emitting 1 alert covering all 55,945 records.
3. **Diagnosis (Both):** This is **both** a *dataset-domain mismatch* (network-flow features vs. identity/RBAC telemetry) and an *unscoped evaluation artifact* (collapsing 55,945 unrelated flows onto one placeholder actor and epoch). Treating missing identity/role context as positive evidence of lateral movement is invalid.

---

## 5. Context-Aware Scoped Evaluation vs. Full-Dataset Evaluation

To evaluate fairly without fabricating identities or tuning detector rules, `scripts/evaluate_unsw_nb15.py` now reports **both** modes side-by-side:

| Evaluation Mode | Records Evaluated | Excluded & Why | Result |
| --- | ---: | --- | --- |
| **`full_dataset_unfiltered`** | `55,945` | `0` excluded | `TP=21,739`, `FP=34,206`, `TN=0`, `FN=0`, `F1=0.559678`, `FPR=1.000` (all flagged as 1 lateral-movement cluster) |
| **`context_aware_scoped`** | `0` (`evaluatable_identity`) | `55,945` `out_of_scope_network_flow` (`missing_actor_identity`: 55,945, `missing_rbac_roles`: 55,945, `missing_timestamps`: 55,945, `missing_session_id`: 55,945) | `metrics: null` (`"No records in this context scope."`) |

**Honest Conclusion:** `UNSW_NB15_testing-set.csv` contains **zero** evaluatable identity-level events. TRUSTGUARD PQ's `ContextAwareDetector` does **not** support standalone network-flow intrusion detection without upstream identity/session/timestamp telemetry.

---

## 6. Reproduction Commands

```powershell
# 1. Download UNSW_NB15_testing-set.csv into data/external/ (excluded from Git)
New-Item -ItemType Directory -Force -Path data/external | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv" -OutFile "data/external/UNSW_NB15_testing-set.csv"

# 2. Run adapter unit tests & full existing test suite
python -m unittest discover -s tests -v

# 3. Run external evaluation
python scripts/evaluate_unsw_nb15.py
```

---

## Part 3: Identity-Focused Validation — OTRF Windows Security Logs (Result D)

- **Dataset:** `OTRF/Security-Datasets` — MITRE ATT&CK Evaluations Round 1 APT3 Day 1 (`caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz`, `12.6 MB`)
- **Source:** `https://github.com/OTRF/Security-Datasets` (`datasets/compound/windows/apt3/`)
- **SHA-256:** `37d2f27f2c4fa35fa1cda926fa5b1a45497777107dd33ba04f03e0613a09636f`
- **Adapter & Script:** `pqguard/external_identity_adapter.py`, `scripts/evaluate_external_identity.py`
- **Record Triage:**
  - Total raw ECS records: `101,904`
  - Non-Security channel excluded (Sysmon, PowerShell, System, etc.): `98,425`
  - Windows Security channel records: `3,479` (`317` duplicates removed, `0` malformed)
  - **Evaluatable identity records:** `2,067` (real users `IT001$`, `pgustavo`, `HFDC01$`, `Administrator`, `LOCAL SERVICE`, etc.; real `@timestamp`s; real `LogonId` sessions; `958` privilege-indicator events `4672`/`4673`/`4703`)
  - **Insufficient-context excluded:** `1,095` (`missing_actor_identity`: 1,070; `missing_session_id`: 1,095 — e.g. Windows Filtering Platform `5156`/`5158`)
- **Detector Execution (Unmodified `ContextAwareDetector(approvals={})`):**
  - `2,067` events analyzed in `5.50 ms` (`0.002659 ms/event`)
  - `93` `lateral_movement` alerts emitted (`2,043` `lateral_movement_candidate`, `24` `routine`) across real principals (`HFDC01$`: 40, `IT001$`: 22, `pgustavo`: 12, etc.)
  - **Metrics:** `Precision = null`, `Recall = null`, `F1 = null`, `FPR = null` (**Not measurable** because OTRF has no per-event `0/1` ground-truth labels or `approvals.json`).
- **Next-Best Labeled Option:** Extract `logon.csv` + `LDAP/` from **CERT r4.2** (`DOI: 10.1184/R1/12841247.v1`, CC BY 4.0) paired with the already-verified `answers.tar.bz2` (`SHA-256: ed21bf921def01e97326b314f2d1fa77651a945bd31bf513095f8ac7658c9ddd`) when a `4.82 GB` download budget is available.

### Reproduce OTRF Identity Evaluation
```powershell
python -m unittest discover -s tests -v
python scripts/evaluate_external_identity.py
```

