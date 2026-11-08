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
