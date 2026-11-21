# SentinelMesh

Runtime tool-execution security gateway, dynamic taint tracker, and forensic console for LLM agent workflows.

Most prompt-injection defenses inspect text before it enters a model and hope the prompt holds. Once an agent reads an untrusted resume, email, web page, or upstream MCP payload, untrusted tokens sit inside the same context window as the user's instructions and can trigger downstream database queries, HTTP requests, or outbound emails.

SentinelMesh moves enforcement from the prompt layer to the tool-execution boundary. Every tool call is routed through a FastAPI gateway (`POST /api/v1/gateway/execute`) or the Model Context Protocol proxy (`backend/app/mcp/proxy.py`), where server-side provenance tracking, deobfuscated taint matching, SQL AST parsing, SSRF checks, PII vault masking, statistical behavioral baselines, and deterministic policy rules evaluate the call before execution.

---

## System Walkthrough

### Overview and Mesh Topology
Live view of monitored agents (`hr-agent`, `finance-agent`, `ops-agent`), policy enforcement mode, session risk totals, and interception latency across active runs.

![SentinelMesh Overview](docs/screenshots/overview.png)

### Live Interception Console (`ATK-002`)
Real-time WebSocket replay and agent execution monitor. Here, a finance agent reads a poisoned invoice and attempts an unapproved external wire API call; the gateway catches tainted argument provenance and blocks egress before the HTTP sink runs.

![Live Interception Console](docs/screenshots/console_interception.png)

### Step-Level Forensic Drawer
Inspecting any intercepted step surfaces the causal breakdown: context trust tier, tainted literal lineage, detector findings, MAD behavioral deviation, policy precedence rule, and sanitized tool arguments.

![Step Forensic Drawer](docs/screenshots/forensic_drawer.png)

### 3-Lane Interactive Playground Sandbox
The Playground (`POST /api/v1/playground/run`) runs the same document text and tool action across three parallel lanes against an isolated SQLite sandbox (`fake_payroll`, `fake_employees`) and mock egress sinks:
- **Lane A (`B0`)**: Pass-through with no defense
- **Lane B (`B2`)**: Static 6-phrase regex filter
- **Lane C (`B4`)**: Full SentinelMesh gateway (provenance, taint, AST rules, policy engine)

![Playground 3-Lane Comparison](docs/screenshots/playground_sandbox.png)

### Tamper-Evident Audit Ledger and Human Approvals
Audit entries are stored in SQLite (WAL mode) with a sequential SHA-256 hash chain (`GENESIS_PREV_HASH = "0" * 64`). High-sensitivity actions configured for `require_approval` pause until reviewed by an operator and resume only with a single-use, 300-second HMAC-SHA256 approval token bound to the canonical `(tool_name, arguments)` hash.

![Tamper-Evident Audit Ledger](docs/screenshots/audit_ledger.png)

### Evaluation & Benchmarks Dashboard
Offline reproducible metrics exported from `scripts/reproduce.py`, including InjecAgent cluster comparisons, AgentDojo runs, latency percentiles, and explicit disclosure of missed attack classes and bottlenecks.

![Benchmarks Dashboard](docs/screenshots/benchmarks.png)

---

## How the Gateway Works

Each intercepted tool call traverses a deterministic evaluation pipeline (`backend/app/core/gateway.py`):

1. **Server-Side Trust Labeling (`backend/app/core/trust_labeler.py`)**  
   Calls to content-ingesting tools (`read_doc`, `web_fetch`, `fetch_web`, `web_search`, `read_email`, `email_read`, `inter_agent_message`, `receive_message`) automatically stamp returned sources as untrusted regardless of caller-supplied flags. Unknown source types default to untrusted.

2. **Deobfuscated Taint & Value Provenance (`backend/app/core/taint_tracker.py`)**  
   Tracks session taint state and a bounded LRU store of untrusted literals (`2,000` sessions max, `500` literals per session). Incoming text and outbound tool arguments pass through `normalize_and_deobfuscate_text` to strip zero-width/soft-hyphen characters (`U+200B`–`U+200D`, `U+FEFF`, `U+2060`, `U+00AD`), normalize Unicode via NFKC, fold Cyrillic homoglyphs, URL-unquote, and decode inline Base64 or hex UTF-8 payloads before taint matching.

3. **Structural & Protocol Rules (`backend/app/detection/rules.py`)**  
   - SQL queries are parsed into an abstract syntax tree via `sqlglot` rather than regex string matching alone.
   - URLs and IP targets are canonicalized with Python `ipaddress` and `urllib.parse` to catch private/link-local SSRF targets (`127.0.0.1`, loopback/reserved ranges) and unapproved domains.
   - Email recipients are parsed with `email.utils` and checked against `backend/app/policies_config.json`.

4. **PII Detection & Encrypted Token Vault (`backend/app/privacy/`)**  
   Scans payloads with pattern rules, Mod-10 `luhn_checksum` credit-card validation, and ISO 7064 Mod-97 `validate_iban` checks. Raw matched strings are tokenized and stored encrypted at rest using Fernet (`cryptography.fernet.Fernet`, `SENTINEL_VAULT_KEY`) with a configurable retention window (`SENTINEL_VAULT_RETENTION_HOURS`, default `720` hours).

5. **Behavioral Anomaly Baseline (`backend/app/baseline/profiler.py`, `anomaly_detector.py`)**  
   Scores deviations from per-agent profiles (tool frequencies, usual domains, state transitions, records per query/session, call velocity) using medians and Median Absolute Deviation with a relative floor: `max(raw_mad, max(0.15 * median, 1.0))`.

6. **Optional Intent Judge (`backend/app/judge/intent_judge.py`)**  
   Evaluates intent-vs-action alignment using **masked** payloads plus non-PII metadata (tool name, destination domain, taint state, stated task, data-class counts). Defaults to `SENTINEL_JUDGE_MODE=recorded_only` (replaying recorded LLM cassette verdicts deterministically without live API calls or synthetic stubs); supports `live` and `record` modes when `SENTINEL_JUDGE_API_KEY` is provided.

7. **Policy Engine & Cryptographic Audit (`backend/app/core/policy_engine.py`, `backend/app/db/database.py`)**  
   Supports `enforce` and `monitor` modes plus configurable `high_sensitivity_external_action` (`require_approval`, `block`, `redact`, `allow`). Decisions append to the SHA-256 hash chain before responding to the caller.

---

## Measured Evaluation & Known Limits

All numbers below come directly from the checked-in reports under `frontend/public/reports/` and `docs/`:

| Suite | Metric | SentinelMesh (`B4`) | Baselines / Notes | Source |
| :--- | :--- | :--- | :--- | :--- |
| **InjecAgent (Base, `N=748`, 44 clusters)** | Prevention rate | **714/748 (`95.45%`)** | `B0` None: `0%` · `B1` Domain Allowlist: `63.64%` · `B2` Static Regex: `0.0%` · `B3` No Taint: `2.27%` | `v3_injecagent_both_settings.json` |
| **InjecAgent Direct vs. Data Stealing** | Breakdown / Benign FP | **96.0% DH / 94.74% DS** (`0.0%` FP) | Cluster Bootstrap CI `[88.64, 100.0]`; Wilson CI `[93.72, 96.73]` | `v3_injecagent_both_settings.json` |
| **AgentDojo (`N=40` evaluated slice)** | Prevention rate | **37/40 (`92.5%`)** | `B2` Static Regex: `0/40` · `B3` No Taint: `27/40` (`67.5%`) · Wilson CI `[80.14, 97.42]` | `v3_agentdojo_official_evaluation.json` |
| **Robustness Variants (`N=60`, dev/seen)** | Exact policy match | **60/60 (`100%`)** | `0` records exposed · McNemar vs `B0/B2` $p = 5.65 \times 10^{-6}$, vs `B1` $p = 0.0129$ | `variants_report.json`, `v3_baselines_mcnemar.json` |
| **AST Mutation Suite** | Mutants killed | **47/47 (`100%`)** | Covers gateway rules and policy checks | `headline_counters.json` |
| **Text-Only Injections** | `deepset` / `Tensor Trust` | N/A (gateway requires tool state) | Static 6-phrase `B2` scored `1.36%` recall (`2/147`) on `deepset` (`N=381`) and `0/549` on `Tensor Trust` | `v3_text_baseline_test.json` |
| **ai4privacy PII (`N=1,028` / `N=1,043`)** | Type-agnostic F1 | **`91.07%` / `91.45%`** (`old_regex`) | Strong on Email (`95.8%`/`96.3%` F1); weak on unstructured National IDs (`5.7%`/`4.1%` F1) and noisy on bare phone digits | `v3_pii_detector_comparison.json` |
| **Warm HTTP Latency (`run1`)** | Round-trip p50 / p95 | **21.1 ms / 62.45 ms** | Core stages p50: rules `0.28 ms`, privacy `0.20 ms`, baseline `3.03 ms`, hash chain `0.79 ms` | `latency_three_runs_summary.json` |

### Candid Limitations (`docs/limitations.md`)
- **Missed InjecAgent Clusters (`34/748`)**: All 34 misses in Base InjecAgent fall into two non-exfiltration local-state clusters: `17` `GitHubDeleteRepository` calls and `17` `DropboxListFilesAndFolders` calls where default policy treats destructive remote state actions or folder reads differently from outbound PII exfiltration.
- **InjecAgent Evaluation Caveat**: Recorded with status `"adapter fixed after seeing results"` after fixing two tool mappings during evaluation (`v3_injecagent_both_settings.json`).
- **SQLite Write Contention at Concurrency**: In load tests on a 2-core Intel Pentium 6405U (`8 GB` RAM, Windows 11), `c = 1, 5, 20` (`1,000` requests each) passed with `0%` errors, while `c = 50` timed out on **`581/1,000` (`58.1%`)** requests due to serialized SQLite WAL writes inside the audit hash chain (`v3_load_test_results.json`). Multi-worker production deployments need PostgreSQL or batched ledger appends.
- **Regex PII Over/Under-Matching**: Regex-only detection misses unstructured national IDs and over-triggers on ambiguous numeric sequences in raw English text (`v3_pii_evaluation_test.json`).

---

## Running Locally

### Prerequisites
- Python `3.11+`
- Node.js `18+` and `npm`

### 1. Start the FastAPI Gateway (`:8000`)

SentinelMesh refuses to start in production mode unless `SENTINEL_VAULT_KEY`, `SENTINEL_JWT_SECRET`, and a distinct `SENTINEL_TOKEN_SECRET` are set. For local development and demo playback, set `DEMO_MODE=true`:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS / Linux:      source .venv/bin/activate

pip install -r backend/requirements.txt

# Windows PowerShell:
$env:DEMO_MODE = "true"
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# macOS / Linux:
DEMO_MODE=true python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Demo RBAC accounts active only when `DEMO_MODE=true` (`backend/app/api/auth.py`):
- `viewer` / `viewer123`
- `analyst` / `analyst123`
- `privacy_officer` / `officer123`

### 2. Start the React Console (`:3000`)

Vite proxies `/api` and `/ws` directly to `http://127.0.0.1:8000` (`frontend/vite.config.ts`):

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:3000`.

### 3. Run Simulated Agent Scenarios (CLI)

With the backend running on port `8000`, trigger attack (`ATK-001`) and benign (`BEN-001`) agent traces from the terminal and watch them stream into the Console:

```bash
python run_demo.py --scenario both --delay 0.8
```

### Docker Compose

A multi-container setup (`backend` on `:8000`, `frontend` on `:3000`) is defined in `docker-compose.yml`:

```bash
docker compose up --build
```

*(Replace the placeholder demo secrets in `docker-compose.yml` before exposing anywhere outside localhost.)*

---

## Verification & Tests

Run test suites and end-to-end experiment reproduction via `Makefile`:

```bash
make test         # Full backend suite (pytest backend/tests -q)
make test-formal  # Hypothesis property invariants
make test-fuzz    # SQL, Unicode/Punycode, and HMAC token fuzzing
make test-chaos   # Locked DB, Judge 500, concurrency fault injection
make test-mcp     # MCP JSON-RPC 2.0 gateway proxy suite
make reproduce    # Re-run benchmark & evaluation pipeline -> benchmark/reports/*.json
```

---

## Repository Layout

```text
backend/app/
  api/            FastAPI endpoints (gateway, playground, audit, approvals, policies, ws)
  approvals/      HMAC-SHA256 one-time approval tokens and review workflow
  baseline/       MAD behavioral profiler and anomaly scorer
  core/           Gateway orchestrator, trust labeler, taint tracker, policy engine
  detection/      sqlglot AST rules, SSRF/IP checks, obfuscation handling
  judge/          Intent-vs-action evaluator and recorded LLM cassettes
  mcp/            MCP JSON-RPC 2.0 HTTP proxy & stdio server wrapper
  privacy/        Luhn/IBAN/PII detectors, tokenizer, Fernet encrypted vault
  db/             SQLite WAL persistence and SHA-256 audit hash chain
demo_agents/      CLI agent runner (ATK-001 / BEN-001) and gateway client SDK
frontend/         React + Vite + Tailwind forensic UI & bundled JSON benchmark reports
docs/             Threat model, formal invariants, datasets, preregistration, limitations
scripts/          End-to-end evaluation & benchmark reproduction scripts
```

---

## Author & Citation

**Prajwal Borkar** — `pborkar2602@gmail.com`

Citation metadata is maintained in [`CITATION.cff`](CITATION.cff). Licensed under the MIT License.
