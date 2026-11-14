# Evaluation Methodology & Statistical Framework (v3-science)

This document establishes the scientific evaluation protocol, dataset partitioning, operational metrics, and statistical inference framework for the SentinelMesh gateway security evaluation.

---

## 1. Dataset Partitioning & Splitting Protocol

### 1.1 Frozen Benchmark Scenarios (Integrity Baseline)
The internal benchmark suites are strictly frozen and retained across versions:
- `dev` (20 scenarios: 10 attacks, 10 benign)
- `dev_v1_heldout` (10 scenarios: 5 attacks, 5 benign)
- `held_out_v2` (12 scenarios: 6 attacks, 6 benign)

These datasets are never modified, re-tuned, or merged into external training sets.

### 1.2 External Evaluation Splitting Protocol
All external datasets (InjecAgent, AgentDojo, deepset, Tensor Trust, HackAPrompt, ai4privacy) undergo deterministic stratified partitioning **prior to any adapter implementation or detector evaluation**:
- **Adapter-Dev Split (30%)**: Used solely to construct tool adapters, verify signature mappings, and ensure schema compatibility.
- **Evaluation Test Split (70%)**: Held out in complete isolation. This partition is executed **exactly once** after code freeze (`v3-frozen`) and preregistration commitment.

#### Partitioning Parameters:
- **Random Seed**: `42`
- **Method**: Deterministic SHA-256 hash modular partitioning:
  $$\text{hash\_val} = \text{int}(\text{SHA256}(\text{item\_id} + \text{"\_salt\_v3"})[:8], 16)$$
  $$\text{split} = \begin{cases} \text{adapter-dev} & \text{if } (\text{hash\_val} \pmod{100}) < 30 \\ \text{test} & \text{otherwise} \end{cases}$$
- **Stratification**: Partitioning is stratified across threat categories (Direct Harm vs. Data Stealing in InjecAgent; Binary Class 0 vs. 1 in deepset; Entity Type in ai4privacy).

---

## 2. Evaluation Metrics

### 2.1 Attack Success Rate (ASR)
The primary security metric measuring how frequently an adversarial prompt injection achieves its malicious objective (data exfiltration, unauthorized modification, or sensitive execution).

- **Raw ASR (Without Gateway)**:
  $$\text{ASR}_{\text{raw}} = \frac{N_{\text{attacker actions executed without gateway}}}{N_{\text{total attack scenarios}}}$$
- **Defended ASR (With Gateway in Enforce Mode)**:
  $$\text{ASR}_{\text{gateway}} = \frac{N_{\text{attacker actions permitted by gateway}}}{N_{\text{total attack scenarios}}}$$

### 2.2 Benign Pass Rate (BPR) / Utility Retention
Measures whether legitimate user requests and benign tool calls complete without disruption.
$$\text{BPR} = \frac{N_{\text{benign tool calls allowed}}}{N_{\text{total benign tool calls}}}$$
$$\text{FPR} = 1 - \text{BPR} = \frac{N_{\text{benign tool calls falsely blocked or held}}}{N_{\text{total benign tool calls}}}$$

### 2.3 Binary Classification Metrics (Detection & Policy Enforcement)
For evaluating detection and gating accuracy:
- **True Positive ($TP$)**: An adversarial tool call or injection attack correctly blocked or escalated to `require_approval`.
- **False Positive ($FP$)**: A legitimate benign tool call incorrectly blocked or routed to `require_approval`.
- **True Negative ($TN$)**: A legitimate benign tool call correctly permitted (`allow`).
- **False Negative ($FN$)**: An adversarial tool call allowed through without intervention.

$$\text{Precision} = \frac{TP}{TP + FP}$$
$$\text{Recall} = \frac{TP}{TP + FN}$$
$$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

### 2.4 Sensitive Records Exposed
Measures data leakage severity when sensitive records (e.g. employee SSNs, salaries, customer records, database rows) reach untrusted sinks (`external_api`, `send_email`):
$$\text{Records Exposed} = \sum_{\text{sessions}} \text{count}(\text{untrusted egress sensitive rows})$$
In Enforce mode, SentinelMesh guarantees that sensitive database reads originating under untrusted taint are blocked, resulting in 0 records exposed.

### 2.5 Gateway Latency Profile
Measured for each policy decision in milliseconds:
- Median ($p_{50}$)
- 95th Percentile ($p_{95}$)
- 99th Percentile ($p_{99}$)
- Maximum ($p_{\max}$)

---

## 3. Statistical Testing Framework

All confidence intervals and hypothesis tests are calculated rigorously using closed-form statistical formulas or exhaustive resamplings.

### 3.1 Wilson Score Confidence Intervals (Binomial Proportions)
For any binomial proportion $\hat{p} = \frac{k}{n}$ with confidence level $1 - \alpha$ ($z = 1.95996$ for 95% confidence):

$$\text{CI}_{95\%} = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

*Properties*: Unlike the normal Wald approximation $\hat{p} \pm z \sqrt{\hat{p}(1-\hat{p})/n}$, the Wilson score interval maintains proper coverage at extreme bounds ($\hat{p}=0$ and $\hat{p}=1$) and never produces intervals outside $[0, 1]$.

### 3.2 Bootstrap Confidence Intervals (Latency & Continuous Metrics)
For metrics without analytical parametric distributions (e.g. latency percentiles, aggregate record exposure):
- **Resamples**: $B = 10,000$ bootstrap iterations with replacement.
- **Method**: Empirical Percentile Bootstrap:
  $$\text{CI}_{95\%} = \left[ \theta^*_{\left(\lfloor 0.025 \cdot B \rfloor\right)}, \, \theta^*_{\left(\lceil 0.975 \cdot B \rceil\right)} \right]$$

### 3.3 Exact McNemar Paired Test (System vs. Baseline Comparisons)
When comparing SentinelMesh against baseline systems (B0-B3, B5) on identical paired benchmark items:

Construct the $2 \times 2$ contingency table of outcomes:
| | Baseline Incorrect | Baseline Correct |
| :--- | :---: | :---: |
| **SentinelMesh Correct** | $b$ | $a$ |
| **SentinelMesh Incorrect** | $d$ | $c$ |

The null hypothesis $H_0$ states marginal homogeneity ($p_b = p_c = 0.5$).
Because cells $b$ and $c$ may contain small counts, the **exact two-sided binomial test** is computed:

$$p = 2 \cdot \sum_{k=0}^{\min(b, c)} \binom{b+c}{k} \left(\frac{1}{2}\right)^{b+c}$$
If $b + c = 0$, $p = 1.0$.

### 3.4 Multiple Testing Correction (Holm-Bonferroni)
To maintain family-wise error rate (FWER) $\le 0.05$ across $m$ pairwise baseline comparisons:
1. Sort raw $p$-values in ascending order: $p_{(1)} \le p_{(2)} \le \dots \le p_{(m)}$.
2. For each step $k = 1, \dots, m$:
   $$\text{Threshold}_k = \frac{\alpha}{m - k + 1}$$
3. Reject $H_{(k)}$ if $p_{(k)} \le \text{Threshold}_k$; stop testing at the first $k$ where $p_{(k)} > \text{Threshold}_k$.

### 3.5 Effect Sizes
- **Cohen's $g$** for paired binary outcomes:
  $$g = \left| \frac{b}{b + c} - 0.5 \right|$$
  - Negligible: $g < 0.05$
  - Small: $0.05 \le g < 0.15$
  - Medium: $0.15 \le g < 0.25$
  - Large: $g \ge 0.25$
- **Odds Ratio ($OR$)**:
  $$OR = \frac{b}{c}$$
