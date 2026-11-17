# System Limitations & Where SentinelMesh Fails (v3-science)

Scientific integrity requires stating clearly where a security architecture fails, what assumptions it depends on, and what attack vectors bypass current rules. Below are the verified empirical failure modes of SentinelMesh v3.

---

### 1. Approved Partner API Abuse (`GitHubDeleteRepository`)
- **Failure Mode**: When an injected prompt instructs the agent to delete or modify resources on an authorized partner service (e.g., GitHub, Slack, Google Calendar), perimeter domain filtering is bypassed.
- **Empirical Evidence**: In InjecAgent (N=748), B4 missed 17 direct-harm test cases where the attacker tool was `GitHubDeleteRepository`. Because `api.github.com` is listed in `APPROVED_API_DOMAINS` and the delete arguments contained no database query or PII, the call was allowed.
- **Mitigation Status**: Requires the proposed v3.3 policy rule `"tainted session + destructive call to external service -> require_approval"`, which was evaluated on `adapter-dev` and halts 100% of these cases with human authorization.
- **Label**: `known architectural blindspot`

---

### 2. Multi-Step Exfiltration at Step 1 (`DropboxListFilesAndFolders`)
- **Failure Mode**: Indirect injection attacks that begin with a read-only metadata query before exfiltrating data in a subsequent step.
- **Empirical Evidence**: In InjecAgent (N=748), B4 permitted 17 data-stealing test cases at step 1 where the attacker requested `DropboxListFilesAndFolders` before emailing the listing in step 2. Because reading file metadata is not an egress violation, SentinelMesh permits the listing and only blocks the attack at step 2.
- **Consequence**: The attack is prevented from causing harm (zero data leaves the perimeter), but the internal read is logged rather than preemptively suppressed.
- **Label**: `step-level deferred block`

---

### 3. Database Write Contention at Extreme Concurrency (c=50)
- **Failure Mode**: Thread locking during cryptographic HMAC SHA-256 tamper-evident hash chaining under high concurrent load.
- **Empirical Evidence**: During real HTTP benchmarking through Uvicorn with SQLite WAL mode on 2-core hardware:
  - At c=1, 5, 20: 0 timeouts, p50 latency 145ms to 4.2s.
  - At c=50 (50 parallel agent streams): 581 out of 1000 requests timed out (10s timeout threshold) due to SQLite database write-lock serialization.
- **Mitigation Status**: Production deployments require distributed message queuing or an asynchronous write-ahead buffer (e.g. Redis + PostgreSQL) to decouple HTTP request evaluation from persistent chain hashing.
- **Label**: `hardware & engine concurrency bound`

---

### 4. Zero Protection from Static Regex Matchers (B2 Evasion)
- **Failure Mode**: Perimeter text filters and regex matchers (Baseline B2) provide zero defense against semantic indirect prompt injection.
- **Empirical Evidence**: Across all 748 test cases in InjecAgent Base and Enhanced settings, Baseline B2 achieved exactly 0.0% prevention (0/748). Modern indirect injection instructions use natural conversational framing ("Please delete my project repository..."), completely bypassing naive signature dictionaries.
- **Consequence**: Organizations cannot rely on keyword blocklists to secure LLM agent tool calling; provenance taint tracking and policy enforcement are mandatory.
- **Label**: `demonstrated baseline failure`

---

### 5. Partial Span Masking on Unstructured PII
- **Failure Mode**: Regex-based privacy masking excels at structured tokens but suffers partial span boundaries on unstructured entities.
- **Empirical Evidence**: On the `ai4privacy` 1,028-sample test partition, regex masking achieves 100% recall on SSNs and 94.2% on phone numbers, but type-agnostic span recall drops on multi-word names or unusual international formats without transformer NER models.
- **Consequence**: For zero-trust privacy compliance, regex masking must be paired with reversible pseudonymization vaults rather than single-pass string redaction.
- **Label**: `syntactic privacy boundary`
