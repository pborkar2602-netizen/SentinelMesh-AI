# SentinelMesh v3 Scientific Evaluation & Robustness Audit Report

**Evaluation Timestamp**: 2026-11-14T21:30:00Z  
**Freeze Tags**: `v3-frozen` (Initial Test Execution) and `v3.1-frozen` (Enhanced Test & PII Fresh Partition Execution)  
**Evaluation Mode**: Held-Out Test Partitions (Single Official Execution per Freeze Boundary)  
**Hardware Profile**: Intel(R) Pentium(R) CPU 6405U @ 2.40GHz (2 Cores, 4 Threads), 8.0 GB RAM, Windows 11 OS

---

## 1. Primary External Benchmark: InjecAgent Enhanced Hacking Prompt (N=748)
*Conducted ONCE under `v3.1-frozen` on the group-aware 0% cross-partition leakage test partition (44 unique attacker instruction clusters).*

| Defense System | Overall Prev. (95% CI) | Direct Harm Prev. (95% CI) | Data Stealing Prev. (95% CI) | Benign Pass Rate (95% CI) | False Positive Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **B0: None (No Defense)** | 0.0% [0.0%, 0.5%] | 0.0% [0.0%, 1.0%] | 0.0% [0.0%, 1.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B1: Domain Allowlist Only** | 61.4% [57.8%, 64.8%] | 52.0% [47.0%, 57.0%] | 73.7% [69.0%, 78.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B2: Static Regex / Phrase Matching** | 100.0% [99.5%, 100.0%] | 100.0% [99.0%, 100.0%] | 100.0% [99.0%, 100.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B3: SentinelMesh (Taint Disabled Ablation)** | 2.3% [1.4%, 3.7%] | 4.0% [2.4%, 6.5%] | 0.0% [0.0%, 1.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B4: Full SentinelMesh Gateway** | **93.2%** [91.1%, 94.8%] | **92.0%** [88.8%, 94.4%] | **94.7%** [91.9%, 96.6%] | **100.0%** [99.5%, 100.0%] | **0.0%** |

### Cluster-Level Bootstrap & Leakage Accounting
- **Cross-Partition Leakage Audit**: The original hash split exhibited 62/62 (100.0%) attacker instruction leakage between dev and test. The group-aware clustering split partitioned unique attacker instructions into 18 dev clusters (306 cases) and 44 test clusters (748 cases), completely eliminating leakage (0.0% cross-partition instruction overlap).
- **Cluster Bootstrap (B=10,000 resamples across 44 attacker clusters)**:
  - B0: 0.0% [0.0%, 0.0%]
  - B1: 61.4% [47.7%, 75.0%]
  - B2: 100.0% [100.0%, 100.0%]
  - B3: 2.3% [0.0%, 6.8%]
  - B4: 93.2% [84.1%, 100.0%]

---

## 2. Test-Set Integrity & Historical InjecAgent Runs
In accordance with integrity guidelines, all historical evaluation runs are preserved:

| Run Identifier | Dataset Setting | N | B4 Overall Prev. | B5 Included? | Notes |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Run 1** (`v3-frozen`) | Base Unenhanced | 723 | 92.9% | Yes (stub) | First test run. B5 included uncalibrated heuristic stub. |
| **Run 2** (Audit Fix) | Base Unenhanced | 723 | 92.9% | No (removed) | *After audit fix (adapter changed after freeze), not a clean single run*. |
| **Run 3** (`v3.1-frozen`, Primary) | Enhanced Hacking | 748 | **93.2%** | No | Clean single run on frozen enhanced partition with group clustering. |

### Data Accounting & N Explanation
- **InjecAgent ($756 \to 723 \to 748$)**: In Zhan et al. (2024), 756 corresponds to an unenhanced test slice. When combining all raw test cases (`test_cases_dh_base.json` = 515, `test_cases_ds_base.json` = 539, total 1,054), applying a deterministic 70% individual case hash partition yielded $N=723$ (Run 1 & 2). Re-splitting by unique attacker instructions (group clustering) yielded 44 clusters containing $N=748$ cases (Run 3).
- **AgentDojo ($7 \to 1$)**: AgentDojo repository has only 54 local workspace task files downloaded (48 user tasks, 6 injection tasks), compared to >300 tasks in the full benchmark suite. In the 70% test split, only 39 tasks were partitioned: 38 user tasks and 1 injection task ($N_{\text{attack}} = 1$). Because $N < 30$, sample size is statistically uninformative and marked **"anecdotal (small sample, N < 30)"**.

---

## 3. Defense Layer Ablation & Provenance Tracking
Evaluated on the InjecAgent benign counterpart (748 cases) and adversarial exfiltration scenarios:

| Architecture | Threat Prevention | Benign False Positive Rate | Look-up Overhead | Handling of Encoded / Split Values |
| :--- | :---: | :---: | :---: | :--- |
| **Session-Level Taint** | 100.0% | 100.0% (Over-blocking) | ~0.03 ms | Blocks all subsequent actions regardless of content |
| **Value-Level Provenance** | 93.2% | **0.0%** (Zero disruption) | ~0.03 ms | Normalized substring matching; misses complex paraphrasing / polyglot splits |

---

## 4. Entity-Level PII Detection (ai4privacy Side-by-Side Comparison)
*Evaluated across initial v3 regex baseline, v3.1 on original test split, and v3.1 on fresh disjoint test split (Seed 99).*

| Split & Architecture | PHONE Precision | PHONE Recall | NATIONAL_ID Precision | NATIONAL_ID Recall | EMAIL F1 | Macro F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **v3 Regex (Old Slice, N=1,028)** | 48.4% [44.5%, 52.2%] | 94.2% [91.2%, 96.3%] | 100.0% [64.6%, 100.0%] | 2.7% [1.3%, 5.5%] | 0.9583 | 0.4125 |
| **v3.1 Enhanced (Old Slice, N=1,028)** | 29.8% [27.0%, 32.8%] | 94.2% [91.2%, 96.3%] | 100.0% [67.6%, 100.0%] | 3.1% [1.6%, 6.0%] | 0.9583 | 0.3995 |
| **v3.1 Enhanced (Fresh Slice, N=1,043)** | 21.0% [18.7%, 23.5%] | 94.3% [91.3%, 96.4%] | 100.0% [67.6%, 100.0%] | 2.2% [1.1%, 4.2%] | 0.9547 | 0.3702 |

*Scientific Transparency*:
- While `phonenumbers` correctly eliminates IPv4 and excessive digit sequences, ai4privacy ground truth strictly annotates narrow regional phone formats, leading to lower precision against loose token spans.
- `NATIONAL_ID` recall is ~2-3% because ai4privacy's `SOCIALNUMBER` includes Spanish DNI, German Personalausweis, French NIR, and Brazilian CPF, whereas SentinelMesh explicitly targets US SSN, UK NINO, and Canadian SIN. UI claims have been softened to reflect this scope limit.

---

## 5. Threshold Parameter Analysis ($\tau=35$)
- **Constants in Code**:
  - `backend/app/baseline/anomaly_detector.py`: Lines 611, 621 (`score += 35` for high-severity anomaly increments).
  - `backend/app/core/risk_scorer.py`: Line 30 (`_HIGH_SEVERITY_INCREMENT = 35`).
  - Action threshold in `policy_engine.py`: 70 (`risk_score >= 70` triggers `require_approval` or `block`).
- **Git Blame**: Introduced in commits `f079d53` and `7e17eabb` on Nov 9, 2026.
- **Empirical Threshold Dev Sweep (36 Scenarios)**:
  - $\tau=20$: 20/20 attacks detected (100.0%), 4/16 benign false alarms (25.0%), match rate 86.1%
  - $\tau=30$: 20/20 attacks detected (100.0%), 4/16 benign false alarms (25.0%), match rate 86.1%
  - $\tau=40$: 20/20 attacks detected (100.0%), 1/16 benign false alarms (6.2%), match rate 94.4%
  - $\tau=50$: 20/20 attacks detected (100.0%), 1/16 benign false alarms (6.2%), match rate 94.4%
  - $\tau=60$: 16/20 attacks detected (80.0%), 0/16 benign false alarms (0.0%), match rate 86.1%
  - $\tau=70$: 17/20 attacks detected (85.0%), 0/16 benign false alarms (0.0%), match rate 88.9%
  - $\tau=80$: 17/20 attacks detected (85.0%), 0/16 benign false alarms (0.0%), match rate 88.9%
- *Conclusion*: $\tau=35$ provides an additive 2-hit threshold ($35 + 35 = 70$) requiring at least two independent suspicious signals to trigger an inline block, keeping benign false alarms low.

---

## 6. Comprehensive Mutation Testing
- Suite: 47 AST and behavioral mutants across `policy_engine.py`, `rules.py`, and `tokens.py`.
- Tests distinguish `block`/`require_approval` vs `would_block` in Monitor mode and test malicious domain boundaries (`service.local` allowed, `evil.internal.example.com` blocked).
- **Mutation Score**: **100.00% (47/47 mutants killed)** in 6.18s. Zero surviving mutants.

---

## 7. Real HTTP Perimeter Latency & Concurrency
*Measured over real HTTP through Uvicorn with SQLite audit inserts and HMAC SHA-256 hash chaining (1,000 requests per concurrency level).*

| Concurrency | Completed Requests | Sustained Throughput | Error Rate | Latency p50 | Latency p95 | Latency p99 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | 1,000 | 4.7 req/s | **0.00%** | 183.8 ms | 571.0 ms | 767.7 ms |
| **5** | 1,000 | 5.0 req/s | **0.00%** | 937.7 ms | 1,886.0 ms | 2,265.7 ms |
| **20** | 1,000 | 4.4 req/s | 2.80% | 4,061.1 ms | 8,105.5 ms | 9,264.2 ms |
| **50** | 1,000 | 2.4 req/s | 59.10% | 18,200.0 ms | 20,000.0 ms | 20,000.0 ms |

*Hardware Bottleneck*: Under Windows 11 on a 2-core Intel Pentium 6405U @ 2.40GHz, SQLite WAL serialization and HMAC chain commits sustain ~5.0 req/s. Concurrency 50 saturates the dual CPU cores, leading to request timeouts.

---

## 8. External Baselines: MCP Client & Hugging Face Classifier
- **Official MCP Client SDK (`mcp==2.3.0`, MIT License)**: Verified in `backend/tests/test_mcp_client.py` using official `CallToolRequest` and `ListToolsRequest` models. All 3 tests passed.
- **Hugging Face Prompt Injection Classifier (`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0)**:
  - Detection Rate on InjecAgent Test Cases: 78.0% (Direct Harm: 98.0%, Data Stealing: 58.0%)
  - False Positive Rate on Benign Cases: 5.0%
  - Mean CPU Latency: 1,788.8 ms / sample (vs. SentinelMesh ~0.35 ms rule check)

---

## 9. Frontend Guided Tour & Responsive Verification
- Expanded to **9 full guided tour steps**:
  1. The Multi-Agent Indirect Injection Problem (`#hd`)
  2. Live 5-Step Incident Attack Chain (`#chain-card`)
  3. Multi-Signal Risk Scoring & Agent Mesh (`#gauge-box`)
  4. Where It Was Cut: Monitor vs. Enforce (`#mode-seg`)
  5. Risk Waterfall & Attribution Evidence (`#wf`)
  6. Policy Lab: All Defenses Active (`#sws`)
  7. Policy Lab: Defense Layer Ablation (`#f2`)
  8. Tamper-Evident Hash Chain Verification (`#ch`)
  9. Scientific Evidence Dashboard & Defense Radar (`#defense-radar-card`)
- **Boundary Clamping**: Card popup positioning is dynamically measured and unconditionally clamped between `16px` and `window.innerHeight - cardHeight - 16px`. Tested and verified via Playwright bounding-box assertions (`top >= 0`, `bottom <= viewport_height`) across 1366x768 and 1920x1080 resolutions with zero clipping.
- Screenshots saved to `docs/screenshots/` and indexed in `docs/screenshots/README.md`.
