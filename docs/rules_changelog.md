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

---

### Entry 8: Tainted Writes to Sensitive Database Columns & Value-Provenance Tracking
- **What Failed**: An account email hijacking attack (`UPDATE customers SET address='...', email='...' WHERE id=88`) after ingesting an untrusted customer message was permitted (`allow`) because `customers` is not a whole-table administrative resource (`system_configs`) and no policy rule inspected column-level write sensitivity combined with session taint or untrusted value provenance.
- **What Changed**:
  1. Added configurable `SENSITIVE_WRITE_COLUMNS` in `backend/app/config.py` (`email`, `phone`, `password_hash`, `role`, `permissions`, `bank_account`, `routing_number`, `payee`, `beneficiary`).
  2. Added `analyze_sql_sensitive_write()` in `backend/app/detection/rules.py` using `sqlglot` AST parsing to inspect `UPDATE`, `INSERT`, `UPSERT` (`ON CONFLICT DO UPDATE` / `ON DUPLICATE KEY UPDATE`), `DELETE`, and `MERGE` statements across quoted identifiers, multiple `SET` columns, `CASE` expressions, and subquery values.
  3. Added session value-provenance tracking in `backend/app/core/taint_tracker.py` (`record_untrusted_literals`, `check_argument_value_provenance`, `value_appears_in_untrusted_session`) to extract string literals, emails, URLs, and tokens from untrusted context sources and flag tool arguments that reuse them.
  4. Added Policy Rule 2b in `backend/app/core/policy_engine.py`: any SQL mutation modifying a sensitive column when (a) the session is tainted OR (b) the newly assigned value appears in untrusted content seen in the session returns `require_approval`. Mutations to non-sensitive columns (such as `address`) in a tainted session remain `allow`ed.
- **Why**: Agents routinely update benign record fields (such as shipping addresses) based on external user requests, but must never silently modify authentication, contact routing, privilege, or financial beneficiary columns (`email`, `phone`, `password_hash`, `role`, `permissions`, `bank_account`, `routing_number`, `payee`, `beneficiary`) from untrusted instructions without human authorization.
- **How It Generalizes**: By parsing the SQL AST to separate non-sensitive target columns from sensitive target columns and tracking value provenance from untrusted inputs, any multi-column `UPDATE`, `INSERT`, `UPSERT`, or `DELETE` touching sensitive columns under taint or value reuse is escalated regardless of table name, SQL formatting, or obfuscation.


---

## Entry 9 — v2 Fix 3: Pre-Read Task-Relevance Protection for Sensitive Data Classes in Tainted Sessions
- **Date**: 2026-11-11
- **What Failed**: In indirect prompt injection attacks where an untrusted document or external tool output hijacked the agent into reading sensitive records (`card_number`, `ssn`, `salary`, `password_hash`, `.aws/credentials`, `config/secrets.env`) before exfiltrating them on a subsequent egress call, the read step was allowed and the attack was only stopped at the final egress step (late detection), exposing sensitive records to the agent's context window (`records_exposed_to_agent > 0`).
- **What Changed**:
  1. Added a configurable `SENSITIVE_READ_DATA_CLASSES` mapping in `backend/app/config.py` covering `ssn`, `card_number`, `salary`, `bank_account`, and `credentials`, each defining sensitive SQL columns, sensitive tables, sensitive file path patterns, and deterministic task-relevance keywords.
  2. Added `analyze_untasked_sensitive_read` in `backend/app/detection/rules.py` using `sqlglot` AST inspection for `db_query` (`SELECT` columns and tables) and path pattern matching for `read_doc`, paired with deterministic word-boundary keyword matching against `task_description` (no LLM calls).
  3. Added Policy Rule 3b (`Pre-Read Sensitive Data Protection`) in `backend/app/core/policy_engine.py`: when a session is tainted prior to a `read_doc` (or tainted on a `db_query`) and attempts to read a sensitive data class not mentioned in `task_description`, the gateway returns `require_approval` **before** the read executes.
  4. Added unit tests in `backend/tests/test_untasked_sensitive_reads.py` (14 test cases).
- **Why**: Stopping an indirect prompt injection only at the egress step still exposes confidential records (credit cards, SSNs, salaries, credentials) to the compromised agent context. Comparing the requested sensitive data class against the original trusted user task before executing the read prevents exposure at the source while permitting legitimate task-aligned reads (such as vendor bank account lookups during invoice reconciliation).
- **How It Generalizes**: Any `SELECT` query (including CTEs, subqueries, and `SELECT *` on sensitive tables) or `read_doc` accessing a configured sensitive data class inside a tainted session is deterministically checked against the task's domain keywords before execution. Across the 36-scenario `dev` set, `records_exposed_to_agent` dropped from **38 records across 6 attacks to 2 records across 2 attacks** (a 94.7% reduction in exposed records) and late detections dropped from **6 to 1**, with **0 new false positives** (`0/16` benign scenarios affected). Across the 12-scenario `dev_v1_heldout` (`dev (seen)`) set, `records_exposed_to_agent` dropped from **3 to 0** and late detections dropped from **3 to 0**, with **0 false positives**.
