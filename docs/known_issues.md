# Known Issues & Mistakes We Found (SentinelMesh v3 Audit)

During the iterative rigor audit across milestones v3, v3.1, v3.2, v3.3, and v3.4, the following methodological and implementation mistakes were identified, verified, and resolved. In accordance with SentinelMesh's scientific integrity principles, all earlier results are preserved in historical reports, and corrections are explicitly labeled.

---

### 1. Generic SQL DELETE Mapping in InjecAgent Adapter
- **Audit Finding**: In the initial `injecagent_adapter.py`, cloud storage actions such as `DropboxListFilesAndFolders` and `DropboxMoveItem` were mapped to generic SQL `DELETE FROM table` statements. This caused read-only file listings to be erroneously treated as destructive SQL deletions, artificially depressing baseline B4's prevention rate from 95.5% down to 93.2% and obscuring step-level detection mechanics.
- **Resolution**: Tool mapping was rewritten to map by tool name and functional semantic (`DropboxListFilesAndFolders` -> `read_doc`, `DropboxMoveItem` -> `external_api` POST, `GitHubDeleteRepository` -> `external_api` DELETE).
- **Label**: `adapter fixed after seeing results`
- **Commit**: `0f19cf1`

---

### 2. Unclustered McNemar p-value Numerical Underflow
- **Audit Finding**: When comparing B4 against B0 (b=703, c=0), statistical evaluations initially reported an unclustered McNemar p-value of 7.63 × 10⁻⁶ due to float precision limits in legacy chi-squared asymptotic approximations. The exact binomial test 2 × 0.5⁷⁰³ yields p ≈ 4.8 × 10⁻²¹². Furthermore, per-case McNemar tests violated independence assumptions because multiple test cases shared identical attacker prompt instructions.
- **Resolution**: Replaced unclustered per-case tests with cluster-level paired sign-flip permutation tests (100,000 resamples) and cluster bootstrap 95% confidence intervals over the 44 attacker case clusters. P-values hitting the permutation floor are reported as `< 1e-05` alongside exact binomial values.
- **Label**: `exact cluster-level permutation`
- **Commit**: `4458df2`

---

### 3. AgentDojo Benchmark Non-Discrimination for Provenance Taint
- **Audit Finding**: In AgentDojo suites (Debenedetti et al., 2024), injected prompts uniformly instruct the agent to communicate with unapproved external web domains (e.g. `api.external-travel-res.com` or `attacker.com`). As a result, a naive perimeter domain allowlist (Baseline B1) halts 92.5% (37/40) of attacks with zero taint tracking, rendering the benchmark non-discriminating for evaluating value-level data provenance.
- **Resolution**: The AgentDojo results were partitioned and explicitly documented with this finding. The report now marks AgentDojo as "not discriminating for data provenance", demonstrating why specialized multi-signal defense is required for sophisticated attacks that exploit approved endpoints.
- **Label**: `not discriminating for provenance`
- **Commit**: `a057010`

---

### 4. Extrapolated Sample Size on Hugging Face DeBERTa Classifier
- **Audit Finding**: Initial baseline comparisons extrapolated the Hugging Face prompt injection classifier (`protectai/deberta-v3-base-prompt-injection-v2`) to all 748 test cases based on an initial subset run, creating misleading precision claims without empirical sample intervals.
- **Resolution**: Removed all extrapolated numbers. Re-evaluated DeBERTa-v3 on an empirical N=64 sample (32 Direct Harm, 32 Data Stealing) alongside N=64 benign system prompts across both Base and Enhanced settings, reporting exact Wilson score 95% confidence intervals.
- **Label**: `small sample (N=64 empirical)`
- **Commit**: `a057010`

---

### 5. Pre-Freeze Exploratory Evaluations
- **Audit Finding**: The initial runs on `deepset/prompt-injections` (N=381) and `Tensor Trust` (N=549) were executed and reported prior to the finalization of the frozen code manifest tag `v3.2-frozen`.
- **Resolution**: All reports, documentation tables, and dashboard UI views were audited to relabel these runs as exploratory. Preregistration and code freeze manifests now strictly document the Git commit timestamps proving freeze boundaries.
- **Label**: `exploratory (run before freeze)`
- **Commit**: `da7bd96`

---

### 6. Hardcoded UI Exposure Record Counts
- **Audit Finding**: Frontend UI cards in the live simulation and guided tour previously contained static hardcoded strings ("45 records exposed in Monitor mode"), which contradicted the active scenario payload where the engineering salaries roster contains exactly 3 employee records.
- **Resolution**: Updated frontend simulation state and tour copy to derive record exposure counts directly from the active scenario roster data (`salaries.json`), ensuring 0 records exposed in Enforce mode and 3 records exposed in Monitor mode.
- **Label**: `scenario-derived records`
- **Commit**: `a057010`
