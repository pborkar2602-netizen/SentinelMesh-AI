# SentinelMesh v3 Scientific Evaluation Report

**Evaluation Timestamp**: 2026-11-14T09:09:02Z  
**Freeze Tag**: `v3-frozen`  
**Evaluation Mode**: 70% Held-Out Test Partitions (Single Official Execution)  

---

## 1. InjecAgent Indirect Prompt Injection Evaluation (N=723)

| Defense System | Direct Harm Prev. (95% CI) | Data Stealing Prev. (95% CI) | Benign Pass Rate (95% CI) | False Positive Rate |
| :--- | :---: | :---: | :---: | :---: |
| **B0: None (No Defense)** | 0.0% [0.0%, 1.1%] | 0.0% [0.0%, 1.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B1: Domain Allowlist Only** | 55.4% [50.3%, 60.5%] | 65.7% [60.6%, 70.3%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B2: Static Regex / Phrase Matching** | 0.0% [0.0%, 1.1%] | 0.0% [0.0%, 1.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B3: SentinelMesh (Taint Disabled Ablation)** | 3.6% [2.1%, 6.1%] | 0.0% [0.0%, 1.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B4: Full SentinelMesh Gateway** | 91.9% [88.6%, 94.3%] | 94.0% [91.0%, 96.0%] | 100.0% [99.5%, 100.0%] | 0.0% |
| **B5: LLM Safety Judge (Offline Heuristic)** | 82.5% [78.2%, 86.0%] | 72.8% [68.0%, 77.1%] | 100.0% [99.5%, 100.0%] | 0.0% |

---

## 2. AgentDojo Benchmark Tasks (N=39)

| Defense System | Attack Prevention (95% CI) | Benign Pass Rate (95% CI) | False Positive Rate |
| :--- | :---: | :---: | :---: |
| **B0: None (No Defense)** | 0.0% [0.0%, 79.3%] | 100.0% [90.8%, 100.0%] | 0.0% |
| **B1: Domain Allowlist Only** | 100.0% [20.6%, 100.0%] | 100.0% [90.8%, 100.0%] | 0.0% |
| **B2: Static Regex / Phrase Matching** | 0.0% [0.0%, 79.3%] | 100.0% [90.8%, 100.0%] | 0.0% |
| **B3: SentinelMesh (Taint Disabled Ablation)** | 0.0% [0.0%, 79.3%] | 100.0% [90.8%, 100.0%] | 0.0% |
| **B4: Full SentinelMesh Gateway** | 100.0% [20.6%, 100.0%] | 100.0% [90.8%, 100.0%] | 0.0% |
| **B5: LLM Safety Judge (Offline Heuristic)** | 100.0% [20.6%, 100.0%] | 100.0% [90.8%, 100.0%] | 0.0% |

---

## 3. Pure Text-Level Baseline Vulnerability

- **deepset/prompt-injections** (N=381):
  - Precision: 100.0%
  - Recall: 1.4% (95% CI: [0.4%, 4.8%])
  - F1 Score: 0.0268
- **Tensor Trust Hijacking** (N=549):
  - Adversarial Recall: 0.0% (95% CI: [0.0%, 0.7%])
  - *Finding*: Static regex / phrase filters fail completely against real-world adversarial prompt injections, confirming the necessity of runtime taint tracking.

---

## 4. Entity-Level PII Detection (ai4privacy English Test Split, N=1028)

| Entity Type | Precision (95% CI) | Recall (95% CI) | F1 Score |
| :--- | :---: | :---: | :---: |
| **NATIONAL_ID** | 100.0% [64.6%, 100.0%] | 2.7% [1.3%, 5.5%] | 0.0524 |
| **PHONE** | 48.4% [44.5%, 52.2%] | 94.2% [91.2%, 96.3%] | 0.6392 |
| **CREDIT_CARD** | 0.0% [0.0%, 35.4%] | 0.0% [0.0%, 0.0%] | 0.0000 |
| **EMAIL** | 96.0% [93.3%, 97.6%] | 95.7% [93.0%, 97.4%] | 0.9583 |

---

## 5. Statistical Baseline Comparisons (Exact McNemar Test & Holm-Bonferroni Correction)

| Comparison Pair | Baseline Accuracy | Contingency [b / c] | Exact p-value | Cohen's g | Odds Ratio | Holm-Bonferroni |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **B4 vs B0: None (No Defense)** | 46.7% | 25 / 2 | 6e-06 | 0.4259 | 12.5 | **REJECT NULL (Significant)** |
| **B4 vs B1: Domain Allowlist Only** | 68.3% | 12 / 2 | 0.012939 | 0.3571 | 6.0 | **REJECT NULL (Significant)** |
| **B4 vs B2: Static Regex / Phrase Matching** | 46.7% | 25 / 2 | 6e-06 | 0.4259 | 12.5 | **REJECT NULL (Significant)** |
| **B4 vs B3: SentinelMesh (Taint Disabled Ablation)** | 78.3% | 4 / 0 | 0.125 | 0.5 | inf | Fail to reject |
| **B4 vs B5: LLM Safety Judge (Offline Heuristic)** | 78.3% | 8 / 4 | 0.387695 | 0.1667 | 2.0 | Fail to reject |

---

## 6. Provenance Architecture Ablation (Session vs. Value Level)

| Architecture | Attack Prevention (95% CI) | Benign FPR (95% CI) | Latency p50 | Latency p95 | Latency p99 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Session-Level Taint** | 100.0% | 100.0% | 0.035 ms | 0.061 ms | 0.124 ms |
| **Value-Level Provenance** | 100.0% | 0.0% | 0.03 ms | 0.051 ms | 0.074 ms |

*Scientific Insight*: Value-level provenance eliminates false positives on independent benign actions within tainted sessions while keeping evaluation latency under 0.15 ms at p99.
