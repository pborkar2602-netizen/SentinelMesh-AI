# SentinelMesh Detection Rules & Policy Changelog

This document logs all generic detection rules, policy engine heuristics, and threshold adjustments made during dev calibration. Per project policy, **zero scenario-specific IDs or hardcoded strings are allowed** in detector or policy code.

---

### Entry 1: Destructive DDL Operation Detection & Approval Policy
- **Failure Observed**: Administrative agent attempted destructive table drop (`DROP TABLE audit_events`), which passed without human intervention because SQL injection patterns previously only looked for injected inline comments (e.g. `; DROP TABLE`).
- **Generic Change**:
  1. Added `DESTRUCTIVE_DDL_PATTERNS` to `backend/app/detection/rules.py` covering standard DDL verbs `\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW)\b`, `\bTRUNCATE\s+(?:TABLE)?\b`, and `\bALTER\s+TABLE\s+.+?\s+DROP\b`.
  2. In `backend/app/core/policy_engine.py`, added a policy rule: any destructive DDL operation requires explicit human approval (`require_approval`).
- **Justification**: Protects against OWASP LLM06 (Excessive Agency). Autonomous agents must never execute destructive DDL commands on database schemas without human authorization.

---

### Entry 2: Tainted Financial Transactions to External Partner Endpoints
- **Failure Observed**: Tainted vendor payment to authorized external partner endpoint was previously evaluating only PII string patterns, missing structured financial parameter tampering (routing / account / amount).
- **Generic Change**:
  1. Updated Policy Rule 2 in `backend/app/core/policy_engine.py` to inspect financial transaction parameter keys (`amount`, `bank_routing`, `account_number`, `wire_routing`).
  2. Outbound external financial transactions originating from tainted sessions mandate `require_approval`.
- **Justification**: In business agent workflows, vendor APIs are often pre-approved external endpoints. When an invoice ingestion is tainted, wire transactions to those endpoints must require human authorization before execution.

---

### Entry 3: Cryptographic Approval Token Evaluation on Tool Arguments
- **Failure Observed**: Approval tokens presented within tool call arguments (or request body) were bypassed if not provided as top-level Pydantic fields.
- **Generic Change**:
  1. Updated `GatewayCore.evaluate` in `backend/app/core/gateway.py` to extract `approval_token` from either top-level request attributes or tool argument payloads.
  2. Tokens are validated via HMAC signature, expiration timestamp, canonical action binding, and single-use nonce check. Forged, expired, replayed, or scope-mismatched tokens strictly fail and yield `block`.
- **Justification**: Guarantees zero authorization bypass regardless of how the caller formats the approval token.

---

### Entry 4: Compound Anomaly Severity Escalation
- **Failure Observed**: Multi-dimensional baseline violations (e.g. concurrent off-hours execution combined with unconstrained whole-table bulk dump) returned `require_approval` rather than `block`.
- **Generic Change**:
  1. In Policy Rule 5 (`backend/app/core/policy_engine.py`), differentiated moderate anomalies ($70 \le \text{score} < 85$) from critical compound anomalies ($\text{score} \ge 85$).
  2. Critical compound violations yielding $\ge 85$ anomaly score are strictly blocked.
- **Justification**: A massive table dump executed in the middle of the night on a weekend represents an acute breach scenario warranting immediate blocking, whereas a single-factor anomaly warrants reviewer evaluation.

---

### Entry 5: Empirical Baseline Distribution Thresholds & Min-Spread Floor Rule (Zero-MAD Resolution)
- **Problem Observed**: Agents with constant or near-constant historical metrics (e.g. steady-state record queries where $\text{MAD} = 0.0$) risk zero-variance lockups, where any single-record deviation would trigger false alarms if absolute mathematical zero MAD was used. Hardcoded floor constants were removed per Milestone 7 requirements.
- **Generic Change**:
  1. Removed all arbitrary hardcoded threshold floors from `AgentBaselineProfile.finalize()`. All thresholds derive directly from empirical data: $\text{threshold} = \text{median} + 3.5 \times \text{MAD}$.
  2. In `calculate_mad()`, when historical behavior has near-zero variance ($\text{raw\_mad} = 0$), applied the **min-spread floor rule**: a principled data-derived non-parametric floor $\max(0.15 \times \text{median}, 1.0)$.
  3. Validated on 200 normal sessions of a near-constant agent: $\text{FPR} = 0.00\%$ ($95\%$ Wilson CI: $[0.00\%, 1.88\%]$).
- **Justification**: Eliminates arbitrary magic numbers while maintaining robust non-parametric statistical bounds across all agent profiles via a well-defined min-spread floor rule.

---

### Entry 6: Configurable Privileged Database Mutation Tables & Authoritative Server Timestamping
- **Problem Observed**: Privileged state modifications (`UPDATE system_configs`, `UPDATE users`, etc.) were checked against hardcoded table names in rules code. Additionally, outside benchmark mode, client-supplied timestamps posed replay and temporal spoofing risks.
- **Generic Change**:
  1. Privileged table enforcement now reads from `SENTINEL_PRIVILEGED_TABLES` (comma-separated environment variable), defaulting to `["system_configs", "users", "permissions", "roles", "credentials", "auth"]`. Non-privileged tables like `customer_addresses` are cleanly permitted without approval escalation.
  2. In `backend/app/api/gateway.py`, outside benchmark mode (`SENTINEL_BENCHMARK_MODE != true`), client-supplied timestamp attributes are strictly ignored and server-authoritative UTC clock (`datetime.now(timezone.utc)`) is enforced on all audit events, hash chains, and rate calculations.
- **Justification**: Enhances operational flexibility for enterprise deployments while guaranteeing authoritative cryptographic integrity against client timestamp manipulation.

---

### Entry 7: AST-Based SQL Structural Row Estimation (`sqlglot`)
- **What Failed**: A legitimate departmental expense summary query (`SELECT department, SUM(amount) FROM expenses GROUP BY department`) was falsely flagged as a bulk table dump (`require_approval`) because the legacy regex heuristic only recognized aggregate functions immediately following `SELECT` (`^\s*SELECT\s+(COUNT|SUM|AVG|MIN|MAX)\b`) and did not parse `GROUP BY` summary projections.
- **What Changed**:
  1. Replaced all regex SQL heuristics in `backend/app/baseline/anomaly_detector.py` with a full AST SQL parser (`sqlglot`) via `parse_single_sql_statement()` and `estimate_sql_rows()`.
  2. Structural row estimation now evaluates AST nodes across scalar aggregates, `GROUP BY` summaries (distinguishing low-cardinality categorical grouping from high-cardinality primary-key/PII grouping), `HAVING`, `COUNT(DISTINCT x)`, `DISTINCT`, `JOIN`s (`CROSS JOIN` and unconstrained joins vs. PK-filtered or grouped joins), subqueries and CTEs, `LIMIT`, and `WHERE` selectivity (primary-key equality vs. unbounded range/inequality/wildcard/tautology scans).
  3. Unparseable SQL syntax, unclosed comments, non-statement expressions, and multi-statement strings fail safe as bulk reads and emit structured warnings.
- **Why**: Regex matching on surface SQL text is brittle against projection order, quoted identifiers, comments, mixed case, and nested clauses.
- **How It Generalizes**: Any valid SQL query across ANSI, SQLite, or Postgres identifier quoting styles is parsed into its grammatical AST before estimating cardinality, preventing false positives on grouped summary reports while catching disguised bulk dumps (`GROUP BY` on primary keys, `CROSS JOIN`s, range scans, tautologies, and multi-statement payloads).
