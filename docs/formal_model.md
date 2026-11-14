# Formal Security Model & Information Flow Lattice (v3-science)

**Document Status**: Formal Specification (Phase 2)  
**Version**: 3.0-science  

---

## 1. Information Flow Security Lattice

SentinelMesh formulates multi-agent tool execution governance as a dual information-flow lattice $\mathcal{L} = \langle \mathcal{C} \times \mathcal{I}, \, \sqsubseteq, \, \sqcup, \, \sqcap, \, \top, \, \bot \rangle$ combining **Confidentiality** (Bell-LaPadula model) and **Integrity / Provenance** (Biba integrity model).

### 1.1 Confidentiality Lattice ($\mathcal{C}$)
Let $\mathcal{C} = \{\text{Public}, \text{Internal}, \text{Confidential}, \text{Restricted}\}$ with partial ordering:
$$\text{Public} \sqsubseteq \text{Internal} \sqsubseteq \text{Confidential} \sqsubseteq \text{Restricted}$$
- $\bot_{\mathcal{C}} = \text{Public}$: Unclassified data permitted to egress to public internet sinks.
- $\top_{\mathcal{C}} = \text{Restricted}$: Highest confidentiality (e.g. Master encryption keys, SSNs, credit card numbers, passwords).

### 1.2 Integrity Lattice ($\mathcal{I}$)
Let $\mathcal{I} = \{\text{Untrusted}, \text{Tainted}, \text{Verified}, \text{Trusted}\}$ with partial ordering:
$$\text{Untrusted} \sqsubseteq \text{Tainted} \sqsubseteq \text{Verified} \sqsubseteq \text{Trusted}$$
- $\bot_{\mathcal{I}} = \text{Untrusted}$: External untrusted text, third-party web scraping, unauthenticated incoming emails, user comments.
- $\top_{\mathcal{I}} = \text{Trusted}$: Authenticated human operator directives, verified system configurations, cryptographic approval tokens.

### 1.3 Label Composition
Each context entity $e$ (variable, payload, document, or session) is assigned a security label:
$$\lambda(e) = \langle c(e), \, i(e) \rangle \in \mathcal{C} \times \mathcal{I}$$
When combining two inputs $e_1$ and $e_2$ into a derived value $e' = f(e_1, e_2)$:
$$c(e') = c(e_1) \sqcup c(e_2) = \max(c(e_1), c(e_2))$$
$$i(e') = i(e_1) \sqcap i(e_2) = \min(i(e_1), i(e_2))$$

---

## 2. System State & Execution Model

Let the gateway state $\sigma \in \Sigma$ be a tuple:
$$\sigma = \langle S, \, \tau, \, \mathcal{V}, \, \mathcal{H}, \, \mathcal{K} \rangle$$
where:
- $S \in \mathcal{S}$ is the active session identifier.
- $\tau: S \to \mathcal{P}(\text{SourceID})$ maps each session to its active untrusted taint sources.
- $\mathcal{V}: S \to \mathcal{P}(\text{String})$ maps each session to the set of untrusted string literals observed in incoming payloads.
- $\mathcal{H} = [h_0, h_1, \dots, h_k]$ is the cryptographic tamper-evident event hash chain ($h_k = \text{HMAC}(h_{k-1} \,\|\, e_k)$).
- $\mathcal{K}$ is the set of consumed cryptographic approval tokens.

### 2.1 Sources and Sinks
1. **Sources ($\mathcal{S}_{\text{in}}$)**:
   - Authenticated User Directive ($\lambda = \langle \text{Internal}, \text{Trusted} \rangle$)
   - Read Document / External HTTP Response / Email Body ($\lambda = \langle \text{Internal}, \text{Untrusted} \rangle$)
   - Database Query Result ($\lambda = \langle \text{Confidential}, \text{Verified} \rangle$)
2. **Sinks ($\mathcal{S}_{\text{out}}$)**:
   - External Network API (`external_api` to arbitrary host) ($C_{\text{sink}} = \text{Public}, \, I_{\text{sink}} = \text{Untrusted}$)
   - Outbound Email (`send_email` to external domain) ($C_{\text{sink}} = \text{Public}, \, I_{\text{sink}} = \text{Untrusted}$)
   - Sensitive Database Modification (`db_query` `UPDATE`/`DELETE` on sensitive tables) ($C_{\text{sink}} = \text{Restricted}, \, I_{\text{sink}} = \text{Trusted}$)
   - Administrative Actuation (`grant`, `execute`, `restart`) ($I_{\text{sink}} = \text{Trusted}$)

---

## 3. Formal Policy Function

The policy enforcement function is defined as:
$$\text{Policy}(\sigma, \, a, \, t, \, \text{args}, \, \tau) \longrightarrow \{\text{allow}, \, \text{block}, \, \text{require\_approval}, \, \text{redact}\}$$

where:
- $a \in \mathcal{A}$ is the invoking agent identity.
- $t \in \mathcal{T}$ is the requested tool primitive (`read_doc`, `db_query`, `send_email`, `external_api`).
- $\text{args} \in \text{Dict}[\text{str}, \text{Any}]$ are the arguments.
- $\tau \subseteq \mathcal{S}_{\text{in}}$ is the active taint set.

---

## 4. Formal Security Invariants

The SentinelMesh policy engine guarantees the following invariants across all state transitions $\sigma \xrightarrow{t(\text{args})} \sigma'$:

### Invariant 1 (I1: No Untrusted Egress to Public Sinks)
$$\forall \text{call } t(\text{args}), \quad (t \in \{\text{send\_email}, \text{external\_api}\} \;\land\; \text{dest}(\text{args}) \notin \text{ApprovedDomains} \;\land\; \tau(S) \neq \emptyset) \implies \text{Decision} \in \{\text{block}, \text{require\_approval}\}$$
*Statement*: An agent session that has ingested untrusted content can never transmit data to an unapproved external destination without human approval or blockage.

### Invariant 2 (I2: Integrity Protection of Sensitive Writes)
$$\forall \text{call } t(\text{args}), \quad (t = \text{db\_query} \;\land\; \text{is\_mutation}(\text{args}) \;\land\; \text{targets\_sensitive\_column}(\text{args}) \;\land\; (\tau(S) \neq \emptyset \;\lor\; \text{contains\_untrusted\_literal}(\text{args}, \mathcal{V}(S)))) \implies \text{Decision} \in \{\text{block}, \text{require\_approval}\}$$
*Statement*: No database mutation modifying sensitive columns (e.g. `account_number`, `password`, `ssn`) can execute under untrusted taint without human cryptographic approval.

### Invariant 3 (I3: Privileged Administrative Non-Delegation)
$$\forall \text{call } t(\text{args}), \quad (\text{is\_privileged\_action}(t, \text{args}) \;\land\; \tau(S) \neq \emptyset) \implies \text{Decision} \neq \text{allow}$$
*Statement*: An agent cannot execute administrative operations (DDL `DROP`/`ALTER`, `GRANT`, OS command execution) when its session context is tainted.

### Invariant 4 (I4: Intent Judge Monotonicity & Non-Downgrade)
$$\forall \text{verdict } J \in \text{JudgeVerdicts}, \quad \text{DeterministicDecision} \in \{\text{block}, \text{require\_approval}\} \implies \text{FinalDecision} \in \{\text{block}, \text{require\_approval}\}$$
*Statement*: An LLM Intent Judge or heuristic classifier can only elevate risk or escalate to human review; it can **never** downgrade, override, or silence a block or approval mandate produced by deterministic taint or rule engines.

### Invariant 5 (I5: Tamper-Evident Hash Chain Immutability)
$$\forall k \ge 1, \quad h_k = \text{SHA256}(h_{k-1} \,\|\, e_k \,\|\, t_k)$$
$$\forall \text{modification to } e_j \; (j < k), \quad \text{VerifyChain}(\mathcal{H}') = \text{False}$$
*Statement*: Any retroactive alteration or deletion of audit log entry $j$ invalidates all subsequent verification hashes from $j+1$ to $k$.

### Invariant 6 (I6: Anomaly-Driven Safety Escalation)
$$\forall \text{call } t(\text{args}), \quad \text{AnomalyScore}(a, t, \text{args}) \ge \theta_{\text{anomaly}} \implies \text{Decision} \in \{\text{require\_approval}, \text{block}\}$$
*Statement*: Any behavioral deviation whose statistical distance from the baseline distribution exceeds the policy threshold $\theta$ is escalated to human review, preventing silent execution.

---

## 5. Formal Limitations & Non-Covered Threat Vectors

1. **Covert Steganographic Channels**:
   If an untrusted source instructs an agent to encode sensitive data via subtle stylistic changes (e.g. acrostics, specific synonym substitutions, or punctuation spacing) sent to an *approved* business domain, statistical filters may fail to detect the leakage without semantic watermarking.
2. **Covert Timing & Resource Channels**:
   An adversary who influences an agent to perform conditional long-running compute loops or memory allocations can theoretically exfiltrate bits through side-channel observation of gateway response latency.
3. **Out-of-Band Modality Bypasses**:
   Direct hardware manipulation or local memory exploitation outside tool invocation signatures (e.g., memory corruption in the underlying host runtime) bypasses the API gateway abstraction layer.
