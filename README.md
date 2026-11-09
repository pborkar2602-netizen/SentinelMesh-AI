# SentinelMesh AI — Milestone 1: Gateway Core & End-to-End Skeleton

> **Autonomous, privacy-preserving security for enterprise AI agents.**  
> Milestone 1 establishes the end-to-end walking skeleton: inline tool interception gateway, immutable SQLite event store, live WebSocket dashboard, and scripted demo agents with synthetic attack/benign scenarios.

---

## 1. What Was Built in Milestone 1

1. **FastAPI Security Gateway (`backend/app/`)**:
   - Interception endpoint `POST /api/v1/gateway/execute` receiving agent tool calls (`agent_id`, `session_id`, `tool_name`, `arguments`, `context_sources` with trust labels, `timestamp`).
   - Clean pass-through evaluation stub returning `allow` decision, reason string, and microsecond latency measurement.
   - REST endpoints: `GET /api/v1/events` (paginated audit trail), `GET /api/v1/agents` (monitored agents inventory), `GET /health`.
   - Real-time WebSocket event broadcaster at `/ws/events` dispatching new audit events with zero polling.
2. **Immutable Event Store (`backend/app/db/`)**:
   - SQLite relational storage with foreign keys and indexes: `agents`, `sessions`, `audit_events`.
   - Every intercepted tool call is written with an auto-incrementing primary key guaranteeing strict monotonic sequence ordering.
   - Seeded with 5 default enterprise demo agents (`hr-agent`, `finance-agent`, `support-agent`, `code-agent`, `ops-agent`).
3. **Scripted Demo Agent (`demo_agents/`)**:
   - `GatewayClient` wrapping all tool invocations and dispatching requests through the gateway before execution.
   - Four mock tools: `read_doc`, `db_query`, `send_email`, `external_api`.
   - Two runnable synthetic scenarios:
     - **ATK-001 (Poisoned Résumé)**: Indirect prompt injection in `poisoned_resume.pdf.txt` hijacks the agent to query the salary DB and exfiltrate employee compensation records via email.
     - **BEN-001 (Security Résumé Review)**: Candidate with 8 years of AppSec experience (containing SQLi, penetration testing keywords) whose internal review email is legitimately permitted.
4. **Command Center Dashboard (`frontend/`)**:
   - Dark charcoal cyber-security aesthetic (`#0c0f14`, cyan `#4fb3c7`, green `#3fb68b`, red `#e5484d`, amber `#d9a441`) matching `sentinelmesh-live.html`.
   - Live WebSocket connection status pill and quick stats (actions inspected, decisions allowed, threats blocked, p95 latency).
   - Monitored agents panel with role and allowed tool tags.
   - Live streaming terminal decision feed with expandable JSON arguments, context source trust tags, and sub-millisecond gateway latency.
5. **Local Orchestration (`Makefile`)**:
   - `make demo` (or `python demo_agents/run_demo.py`) executes the demo agent tool calls live against the gateway.

---

## 2. Quickstart & How to Run (Local Execution)

1. **Terminal 1 — Start the Gateway**:
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
   ```
   - Gateway API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

2. **Terminal 2 — Start the Dashboard**:
   ```bash
   cd frontend && npm run dev
   ```
   - Dashboard UI: [http://localhost:3000](http://localhost:3000)

3. **Terminal 3 — Run the Demo Agent Scenarios**:
   ```bash
   python demo_agents/run_demo.py
   # or run attack scenario ATK-001
   python demo_agents/run_demo.py --scenario atk-001
   # or run benign twin scenario BEN-001
   python demo_agents/run_demo.py --scenario ben-001
   ```
   Watch the tool calls and policy decisions stream live into the dashboard feed!

---

## 3. Running Automated Tests

All tests run through the real gateway and database paths (no mocking):

```bash
make test
# or
python -m pytest backend/tests -v
```

### Test Coverage Summary:
- `backend/tests/test_gateway.py`: Gateway execute endpoint, health checks, untrusted context metadata tagging, and schema validation.
- `backend/tests/test_event_store.py`: SQLite event store persistence, strict monotonic ordering, agent registry, and agent filtering.
- `backend/tests/test_integration.py`: Complete end-to-end execution of both `ATK-001` and `BEN-001` through the real gateway path and verification of ordered event telemetry.

---

## 4. Security & Cryptographic Key Management (Milestone 4)

SentinelMesh enforces strict cryptographic separation of concerns between append-only audit logs and sensitive raw data:

### Environment Variables & Secrets
| Variable | Purpose | Default / Production Guidance |
| :--- | :--- | :--- |
| `SENTINEL_VAULT_KEY` | Master encryption key for the Fernet symmetric vault | **Never commit.** In production, set to a 32-byte base64-encoded secret (e.g. `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`). |
| `SENTINEL_JWT_SECRET` | HMAC-SHA256 signing secret for authentication tokens | **Never commit.** Set to a high-entropy secret string in production. |
| `SENTINEL_VAULT_RETENTION_HOURS` | Retention window for raw PII values in `privacy_vault` | Default: `720` (30 days). Once expired, raw token resolution fails with HTTP 410 and creates an audit record. |
| `SENTINEL_POLICY_MODE` | Gateway operational mode | `enforce` (blocks inline) or `monitor` (logs `would_block`). |
| `SENTINEL_HIGH_SENSITIVITY_EXTERNAL_ACTION` | Policy for untainted sensitive egress to external domains | `require_approval` (default) or `block`. |

### Role-Based Access Control & Demo Users
Protected endpoints (such as `POST /api/v1/privacy/raw-access`) require a signed Bearer JWT token issued at `POST /api/v1/auth/login`:
- **`viewer`** (`viewer` / `viewer123`): Read-only masked views. Attempting raw unmasking returns **HTTP 403 Forbidden**.
- **`analyst`** (`analyst` / `analyst123`): Incident investigation with masked payloads. Attempting raw unmasking returns **HTTP 403 Forbidden**.
- **`privacy_officer`** (`privacy_officer` / `officer123`): Authorized to retrieve raw PII with a mandatory compliance reason. Each unmasking access is cryptographically committed to the append-only audit hash chain.

---

## 5. Repository Structure

```text
Sentinel AI/
├── docker-compose.yml            # Multi-container orchestration (backend + frontend)
├── Makefile                      # Standard CLI shortcuts (make up, make demo, make test)
├── run_demo.py                   # Demo agent runner entrypoint
├── backend/                      # Python 3.11 + FastAPI
│   ├── app/
│   │   ├── main.py               # FastAPI entrypoint, lifespan, CORS, WebSocket
│   │   ├── config.py             # App settings (Pydantic)
│   │   ├── api/                  # Gateway, events, agents, websocket routers
│   │   ├── core/                 # GatewayCore evaluation stub
│   │   ├── db/                   # SQLite database manager & seed script
│   │   └── schemas/              # Pydantic v2 schemas
│   ├── tests/                    # Pytest test suite (gateway, event store, integration)
│   ├── Dockerfile
│   └── requirements.txt
├── demo_agents/                  # Scripted autonomous agents
│   ├── agent_runner.py           # Scenario orchestrator (ATK-001 and BEN-001)
│   ├── gateway_client.py         # Client interceptor routing calls to Gateway
│   ├── tools/                    # read_doc, db_query, send_email, external_api
│   └── synthetic_data/           # Synthetic resumes, salaries.json
├── frontend/                     # React 18 + TypeScript + Vite + Tailwind CSS
│   ├── src/                      # Header, QuickStats, AgentList, EventFeed
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
└── docs/
    └── benchmark_spec.md         # Final approved benchmark specification
```
