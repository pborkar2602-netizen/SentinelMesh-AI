# Comprehensive Threat Model & Industry Framework Alignment (v3-science)

**Document Status**: Official Threat Model Specification (Phase 2)  
**Standard Compliance**: OWASP Top 10 for LLM (2025), MITRE ATLAS, NIST AI RMF 1.0  
**Version**: 3.0-science  

---

## 1. System Architecture & Trust Boundaries

SentinelMesh operates as an in-line, deterministic security mediation gateway positioned between autonomous LLM agents and sensitive tools (relational databases, network endpoints, file systems, communication channels).

```
[ External Untrusted Sources ] (Internet, Third-Party APIs, Emails, Resumes)
               |
====== TRUST BOUNDARY 1: Untrusted Ingestion ======
               v
      [ LLM Agent (Untrusted Execution Runtime) ]
               |
====== TRUST BOUNDARY 2: Policy Mediation Gateway ======
               v
      [ SentinelMesh In-Line Enforcement Engine ]
         ├── Static Signature & Heuristic Rules
         ├── Dynamic Taint Tracker & Provenance Engine
         ├── Statistical Baseline Anomaly Scorer
         ├── Intent Judge (Escalation / Verification)
         ├── PII Recognition & Masking Vault
         └── Cryptographic Approval Reviewer
               |
====== TRUST BOUNDARY 3: Internal Confined Execution ======
               v
[ Protected Enterprise Resources ] (SQL Database, Vendor Master, Cloud Metadata, Internal Vault)
```

### 1.1 Trust Boundaries
- **Trust Boundary 1 (Ingestion Boundary)**: Separates external internet services, untrusted email senders, shared documents, and public web content from the agent's internal memory and context window. All data crossing this boundary is classified $\bot_{\mathcal{I}} = \text{Untrusted}$.
- **Trust Boundary 2 (Mediation Boundary)**: Separates the non-deterministic LLM agent reasoning environment from the execution of concrete tool primitives. The agent cannot directly invoke operating system sockets, SQL drivers, or HTTP libraries; it can only emit structured tool-call requests to SentinelMesh.
- **Trust Boundary 3 (Confined Storage Boundary)**: Separates SentinelMesh's mediated execution plane from internal enterprise datastores (`vendor_master`, `employees`, `credentials`). Direct mutation requires verified integrity or human cryptographic authorization.
- **Trust Boundary 4 (Human-in-the-Loop Governance Boundary)**: Separates high-impact or ambiguous operations from autonomous execution. Sensitive actions require non-repudiable HMAC approval tokens signed by verified operators.

---

## 2. Protected Assets & Critical Resources

| Asset Category | Target Resources | Confidentiality ($\mathcal{C}$) | Integrity ($\mathcal{I}$) | Threat Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Financial Ledgers** | `vendor_master`, `accounts`, wire routing numbers | Confidential | Trusted | Financial loss, fraudulent account modification, unauthorized disbursements |
| **Employee & Customer PII** | SSNs, salaries, medical records, home addresses | Restricted | Verified | Regulatory breach (GDPR, HIPAA, CCPA), identity theft, legal liability |
| **System Credentials** | API keys, AWS credentials (`169.254.169.254`), passwords | Restricted | Trusted | Full enterprise infrastructure compromise, privilege escalation |
| **Relational Database Schema** | SQL table definitions, system audit catalogs | Internal | Trusted | Denial of service, ransomware, data destruction |
| **Audit Logs** | Gateway event log, decision traces | Internal | Trusted | Forensic tampering, evidence destruction |

---

## 3. Threat Actors & Attacker Capabilities

1. **Adversarial External Ingestion (Indirect Injection)**:
   - *Capability*: The attacker places malicious instructions inside documents, customer support tickets, invoice notes, or web pages that an agent is tasked to read.
   - *Objective*: Subvert agent intent to extract internal context or execute unauthorized mutations.
2. **Rogue / Hijacked Agent Execution**:
   - *Capability*: The agent's reasoning loop has been compromised by an injection attack. The agent issues tool calls attempting SSRF, bulk data exfiltration, or database modifications.
   - *Objective*: Bypass traditional prompt-level defenses through multi-step split attacks or obfuscation (Base64, zero-width characters).
3. **Malicious Insider / Rogue Prompting**:
   - *Capability*: An authenticated internal user submits adversarial prompts attempting to probe unauthorized databases or exfiltrate peer data.
4. **Log Tampering Adversary**:
   - *Capability*: An adversary with local file system read/write access attempting to erase or modify evidence of malicious operations.

---

## 4. Alignment with OWASP Top 10 for LLM Applications (2025 Edition)

**Reference**: [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

| OWASP ID | Vulnerability Name | Threat Description | SentinelMesh Defense & Invariant |
| :--- | :--- | :--- | :--- |
| **LLM01** | **Prompt Injection** | Direct and indirect injection hijacking agent instructions. | Dynamic taint tracking propagates untrusted provenance from Step 0 reads. Invariant I1 blocks egress; Invariant I2 blocks sensitive writes. |
| **LLM02** | **Sensitive Information Disclosure** | PII, SSN, or confidential database records leaked in tool outputs. | Real-time `CompositePiiDetector` identifies SSN, email, credit card, and phone data. Untasked sensitive reads are blocked at query time (0 records exposed). |
| **LLM03** | **Supply Chain Vulnerabilities** | Compromised third-party tools, plugins, or libraries. | Strict canonical primitive isolation (`read_doc`, `db_query`, `send_email`, `external_api`) and strict JSON schema validation. |
| **LLM04** | **Data and Model Poisoning** | Adversarially modified retrieval contexts or training data. | Context source provenance tagging distinguishes trusted instructions from untrusted external retrieval snippets. |
| **LLM05** | **Improper Output Handling** | Unsanitized model output passed directly to shell or database. | `analyze_sql_sensitive_write` parses SQL via AST (`sqlglot`); shell commands are prohibited under untrusted taint (Invariant I3). |
| **LLM06** | **Excessive Agency** | Agent granted excessive permissions to execute destructive actions. | Dual-layer governance enforces principle of least agency: high-impact actions require cryptographic human approval (Invariants I2, I3). |
| **LLM07** | **System Prompt Leakage** | Extraction of internal meta-prompts, instructions, or guardrails. | Egress sinks checked for prompt leakage and credential signatures; unapproved outbound email/API blocked under taint. |
| **LLM08** | **Vector and Embedding Weaknesses** | Adversarial injection strings embedded in retrieved vector chunks. | Normalization and de-obfuscation (`normalize_and_deobfuscate_text`) strips zero-width spaces and decodes inline Base64 payloads. |
| **LLM09** | **Misinformation / Hallucination** | Hallucinated parameters leading to unauthorized transactions. | Financial disbursements require verified vendor master matches; routing mismatches force human review. |
| **LLM10** | **Unbounded Consumption** | Resource exhaustion, denial of service, recursive queries. | Anomaly detection flags statistical volume deviations; rate limiting and payload size caps constrain resource use. |

---

## 5. Alignment with MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

**Reference**: [MITRE ATLAS Matrix](https://atlas.mitre.org/)

| MITRE ATLAS ID | Technique Name | Tactic | SentinelMesh Mitigation |
| :--- | :--- | :--- | :--- |
| **AML.T0051** | **LLM Prompt Injection** | Initial Access / Execution | Track untrusted provenance across multi-step execution. Even if LLM is hijacked, gateway denies malicious sinks. |
| **AML.T0054** | **LLM Jailbreak** | Defense Evasion | Deterministic rules and lattice policy override all model-level jailbreak outputs. |
| **AML.T0015** | **Evade ML Model** | Defense Evasion | De-obfuscation pipeline normalizes ZWSP (`\u200b`, `\ufeff`) and decodes candidate Base64 strings before signature matching. |
| **AML.T0048** | **Exfiltration via ML Artifacts** | Exfiltration | Prevents model from returning internal credentials or database rows to untrusted output channels. |
| **AML.T0025** | **Exfiltration via Cyber Means** | Exfiltration | Invariant I1 restricts network egress (`external_api`, `send_email`) to domain allowlists under tainted sessions. |
| **AML.T0040** | **ML Supply Chain Compromise** | Persistence | Immutable frozen code manifests (`docs/frozen_manifest.md`) with cryptographic SHA-256 digests. |
| **AML.T0034** | **Cost Harvesting / Resource Exhaustion** | Impact | Request payload size caps, session rate limits, and behavioral anomaly scoring. |

---

## 6. Alignment with NIST AI Risk Management Framework (AI RMF 1.0)

**Reference**: [NIST AI RMF 1.0 (NIST Trustworthy and Responsible AI)](https://www.nist.gov/itl/ai-risk-management-framework)

| NIST Function | Category ID | Subcategory Requirement | SentinelMesh Technical Implementation |
| :--- | :--- | :--- | :--- |
| **GOVERN** | **GOVERN 1.2** | Legal, regulatory, and policy requirements are identified and integrated into AI governance. | Strict enforcement of data protection policies (PII redaction, financial disbursement approval tokens). |
| **MAP** | **MAP 1.5** | AI system context, operational dependencies, and potential attack vectors are mapped. | Formal lattice model ($\mathcal{C} \times \mathcal{I}$) maps information flow across all four tool primitives and trust boundaries. |
| **MEASURE** | **MEASURE 2.6** | AI system security, adversarial robustness, and resilience are evaluated and documented. | Offline benchmark evaluation across InjecAgent, AgentDojo, Tensor Trust, and ai4privacy with Wilson 95% CIs and exact McNemar tests. |
| **MEASURE** | **MEASURE 2.7** | Privacy risks and potential personal data exposures are quantified and minimized. | Granular entity-level evaluation of PII detection on ai4privacy English validation dataset (EMAIL F1: 0.958). |
| **MANAGE** | **MANAGE 1.3** | Systematic mechanisms are employed to detect, monitor, and mitigate identified AI risks. | In-line deterministic gateway intercepts requests at runtime with median decision latency < 0.05 ms. |
| **MANAGE** | **MANAGE 2.4** | Human oversight and intervention mechanisms are available for high-risk decisions. | Cryptographically signed, single-use HMAC approval tokens required for sensitive database writes and unverified transfers. |
