# Dataset Registry & Integrity Manifest (v3-science)

This document catalogs every benchmark and evaluation dataset considered, verified, evaluated, or skipped during the SentinelMesh v3 science and robustness upgrade. 

In strict compliance with the **Integrity Rules**:
- Prior evaluation sets (`dev`, `dev_v1_heldout`, and `held_out_v2`) remain untouched with their existing labels.
- External datasets are partitioned prior to any adapter or detector design into **adapter-dev (30%, stratified, seed 42)** and **test (70%)**.
- No dataset contents, IDs, citations, or sample records are fabricated.
- Any dataset that is gated, requires non-public access credentials, or has restrictive licensing is recorded and skipped.

---

## 1. Verified & Incorporated Datasets

| Dataset | Source / Reference | Version / Commit | License | Format / Files | Size | Target Capability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **InjecAgent** | [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (Zhan et al., ACL 2024) | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT License | JSON / JSONL (`test_cases_dh_*.json`, `test_cases_ds_*.json`, `tools.json`, `user_cases.jsonl`) | ~3.5 MB | Indirect Prompt Injection on Tool-Integrated LLMs (Direct Harm & Data Stealing) |
| **AgentDojo** | [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al., NeurIPS 2024) | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT License | Python / JSON task suites (Banking, Slack, Travel, Workspace) | ~1.2 MB | Multi-turn Agent Security & Utility evaluation under indirect prompt injection |
| **deepset/prompt-injections** | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (deepset AI) | `4f61ecb038e9c3fb77e21034b22511b523772cdd` | Apache 2.0 | Parquet / JSON (792 samples: 661 train, 131 test) | ~450 KB | Text-level prompt injection detection baseline (binary classification) |
| **Tensor Trust** | [HumanCompatibleAI/tensor-trust-data](https://github.com/HumanCompatibleAI/tensor-trust-data) (Toreini et al., 2023) | `747a75e096761ebc01bd3970158827326b4add23` | MIT License | JSONL / CSV (`raw-data`, `benchmarks`) | ~15 MB | Adversarial prompt injection & system prompt extraction strings |
| **HackAPrompt** | [hackaprompt/hackaprompt-dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset) (Schulhoff et al., EMNLP 2023) | `25b87fbedfb86840abaf8cd09af7a029208a971a` | MIT License | Parquet / JSON (~600k red-team attempts across 10 levels) | ~24 MB | Jailbreaks, token smuggling, and indirect instruction overrides |
| **ai4privacy PII Masking** | [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) (AI4Privacy 2024) | `c8c77895a005822682b66ab547fc0422579bc1d3` | AI4Privacy Academic/Research (Attribution) | JSONL (`data/validation/1english_openpii_8k.jsonl`) | 27.3 MB (8,000 validation records) | Entity-level PII detection (Email, Phone, SSN, Credit Card, Address, Name) |

---

## 2. Dataset Detailed Profiles & Known Limitations

### 2.1 InjecAgent (Zhan et al., ACL 2024)
- **Source**: https://github.com/uiuc-kang-lab/InjecAgent
- **Commit**: `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`
- **What it Measures**: 
  Evaluates indirect prompt injection on tool-integrated LLMs. Cases are divided into two threat models:
  1. *Direct Harm (DH)*: The injected payload forces the agent to execute an unauthorized, destructive action (e.g. deleting files, modifying configuration, sending unauthorized commands).
  2. *Data Stealing (DS)*: The injected payload forces the agent to extract private context (emails, customer data, files) and exfiltrate it via an external channel (email, HTTP webhook).
- **Format**: Structured test cases specifying `user_case` (user instruction and benign parameters), `attacker_case` (injected prompt inserted in step 1 untrusted output), and target attacker tool calls.
- **Known Limitations**:
  - Prompts are generated from synthetic combinatorial templates rather than real production agent trajectories.
  - The default benchmark simulates single-turn tool calls without full interactive operating system state.
  - Tool signatures use general mock API names (e.g., `GoogleDrive_delete_file`) that require explicit mapping to gateway canonical primitives (`read_doc`, `db_query`, `send_email`, `external_api`).

### 2.2 AgentDojo (Debenedetti et al., NeurIPS 2024)
- **Source**: https://github.com/ethz-spylab/agentdojo
- **Commit**: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`
- **What it Measures**:
  Evaluates whether agent security defenses can block prompt injection attacks without degrading agent utility on benign tasks. Spans 4 realistic application environments: Banking, Slack, Travel, and Workspace.
- **Format**: Python task definitions, environments, and ground-truth tool-calling traces.
- **Known Limitations**:
  - Interactive multi-turn execution typically requires an active LLM backend. For offline deterministic evaluation, task goals and injected payloads are adapted into static multi-step tool call sequences.
  - Requires sandboxed mocking of internal state (mock bank accounts, mock calendar, mock email inboxes).

### 2.3 deepset/prompt-injections
- **Source**: https://huggingface.co/datasets/deepset/prompt-injections
- **Commit**: `4f61ecb038e9c3fb77e21034b22511b523772cdd`
- **What it Measures**:
  Evaluates binary text-level prompt injection detection. Contains handcrafted and scraped adversarial injection prompts alongside normal benign assistant requests.
- **Format**: Parquet files with fields `text` (string) and `label` (0 = benign, 1 = injection).
- **Known Limitations**:
  - Lacks tool-use semantics, arguments, provenance, or execution context. Evaluates text-level classifier / regex rules only.
  - Distribution contains short, standalone injection strings rather than realistic payloads buried inside 4KB HTML/JSON tool returns.

### 2.4 Tensor Trust (Toreini et al., 2023)
- **Source**: https://github.com/HumanCompatibleAI/tensor-trust-data
- **Commit**: `747a75e096761ebc01bd3970158827326b4add23`
- **What it Measures**:
  Adversarial prompt injection strings harvested from a public game where players attempted to trick LLMs into revealing a secret access code or ignoring guardrails.
- **Format**: JSONL records containing player attacks, defenses, and success flags.
- **Known Limitations**:
  - The HuggingFace mirror is gated, but the official GitHub repository contains the full open dataset.
  - Domain is game-theoretic password extraction, which tests prompt robustness but does not evaluate API exfiltration or destructive tool calls.

### 2.5 HackAPrompt (Schulhoff et al., EMNLP 2023)
- **Source**: https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset
- **Commit**: `25b87fbedfb86840abaf8cd09af7a029208a971a`
- **What it Measures**:
  Comprehensive red-teaming dataset of over 600,000 injection attempts against 10 levels of defense prompts, evaluating evasion strategies including delimiter confusion, language switching, and token obfuscation.
- **Format**: Parquet / JSONL.
- **Known Limitations**:
  - Evaluates text jailbreak completion ("I have been PWNED") rather than structured agent tool gating.

### 2.6 AI4Privacy PII Masking 300k (English Subset)
- **Source**: https://huggingface.co/datasets/ai4privacy/pii-masking-300k
- **Commit**: `c8c77895a005822682b66ab547fc0422579bc1d3`
- **What it Measures**:
  Token and span-level personal identifiable information (PII) recognition across high-risk entities: EMAIL, PHONE, SSN, CREDIT_CARD, PERSON, ADDRESS, USERNAME, DATE_OF_BIRTH.
- **Format**: JSONL (`data/validation/1english_openpii_8k.jsonl`) with exact span annotations `[start, end, label]`.
- **Known Limitations**:
  - Custom non-commercial research license requires strict scholarly attribution.
  - High proportion of synthetic sentence structures; span annotations must be mapped to SentinelMesh's 4 core exfiltration PII detectors (Email, Phone, SSN, Credit Card).

---

## 3. Skipped / Excluded Candidates

The following candidate datasets were considered but are explicitly excluded:

1. **Agent Security Bench (thu-coai/Agent-Safety-Bench / Agent-Security-Bench)**
   - **Reason**: Gated access (HTTP 401 Unauthorized / access request gate on HuggingFace and GitHub repositories). Requires private credentials, violating autonomous open reproducibility.
   - **Status**: Skipped.

2. **CMU CERT Insider Threat Test Dataset (r4.2 / r6.2)**
   - **Reason**: Monolithic 13+ GB tarball of enterprise synthetic LDAP/HTTP/Email host logs distributed via institutional request portal (`kilthub.cmu.edu`). Does not model LLM agent tool-calling APIs or prompt injection vectors.
   - **Status**: Skipped.

---

## 4. Stratified Split Protocol

To prevent test-set contamination and data snooping:
1. **Split Ratio**: 30% adapter-dev / 70% test.
2. **Stratification Key**: Stratified by threat type (Direct Harm vs. Data Stealing in InjecAgent; Label 0 vs 1 in deepset; Entity Type in ai4privacy).
3. **Random Seed**: Fixed at `42` (`hashlib.sha256` deterministic partitioning).
4. **Partition Isolation**:
   - `adapter-dev` (30%) is stored in `benchmark/data_splits/dev/` and is strictly used to verify parser correctness and tool mapping schemas.
   - `test` (70%) is stored in `benchmark/data_splits/test/` and remains completely untouched until the test run is frozen under tag `v3-frozen`.
