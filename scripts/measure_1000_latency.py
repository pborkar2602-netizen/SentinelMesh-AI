import os
import sys
import time
import math
import json
import uuid
import subprocess
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx
from backend.app.db.database import init_db

def percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    n = len(sorted_vals)
    idx = int(math.ceil(p * n)) - 1
    return float(sorted_vals[max(0, min(n - 1, idx))])

def calc_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}
    s = sorted(values)
    return {
        "p50": round(percentile(s, 0.50), 2),
        "p90": round(percentile(s, 0.90), 2),
        "p95": round(percentile(s, 0.95), 2),
        "mean": round(sum(s) / len(s), 2),
        "min": round(s[0], 2),
        "max": round(s[-1], 2),
    }

def main():
    print("=" * 80)
    print("SENTINELMESH REAL HTTP 1,000-CALL LATENCY BENCHMARK WITH STAGE BREAKDOWN")
    print("=" * 80)

    # Initialize DB
    init_db()

    port = 8767
    server_url = f"http://127.0.0.1:{port}"
    execute_url = f"{server_url}/api/v1/gateway/execute"
    health_url = f"{server_url}/health"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["DEMO_MODE"] = "true"
    env["SENTINEL_JWT_SECRET"] = "dev-secret-jwt-key-for-local-benchmark-only"
    env["SENTINEL_TOKEN_SECRET"] = "dev-secret-token-key-for-local-benchmark-only"

    print(f"Starting uvicorn test gateway server on 127.0.0.1:{port}...")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "error",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Wait for health
        connected = False
        with httpx.Client(timeout=2.0) as client:
            for _ in range(30):
                try:
                    res = client.get(health_url)
                    if res.status_code == 200:
                        connected = True
                        break
                except Exception:
                    time.sleep(0.2)

        if not connected:
            print("Failed to start gateway HTTP server.")
            proc.kill()
            return 1

        print("Gateway HTTP server online and healthy.\n")

        # 1. Warm-up Phase: 100 calls
        print("Executing 100 HTTP warm-up calls...", flush=True)
        with httpx.Client(timeout=30.0) as client:
            for i in range(100):
                payload = {
                    "trace_id": f"trc-warm-{i}",
                    "agent_id": "hr-agent",
                    "session_id": f"sess-warm-{i % 5}",
                    "tool_name": "read_doc",
                    "arguments": {"file_path": f"doc_{i}.txt"},
                    "context_sources": [],
                    "task_description": "Warm-up tool execution",
                    "timestamp": "2026-10-07T14:00:00Z",
                }
                client.post(execute_url, json=payload)

        print("Warm-up complete. Commencing 1,000 live HTTP benchmark calls...\n", flush=True)

        # 2. Benchmark Phase: 1,000 calls
        http_latencies: List[float] = []
        rules_latencies: List[float] = []
        privacy_latencies: List[float] = []
        baseline_latencies: List[float] = []
        judge_latencies: List[float] = []
        policy_latencies: List[float] = []
        masking_latencies: List[float] = []
        db_write_latencies: List[float] = []
        hash_chain_latencies: List[float] = []
        ws_latencies: List[float] = []
        incident_latencies: List[float] = []
        response_latencies: List[float] = []
        http_transport_latencies: List[float] = []

        tools_mix = [
            ("read_doc", {"file_path": "resume.pdf.txt"}, []),
            ("db_query", {"query": "SELECT candidate_id, score FROM evaluations WHERE job_id=101"}, []),
            ("send_email", {"to": "hiring-lead@company.com", "subject": "Review candidate", "body": "Summary for candidate"}, []),
            ("external_api", {"url": "https://partner.org/v1/sync", "action": "sync"}, []),
        ]

        with httpx.Client(timeout=30.0) as client:
            for i in range(1000):
                tool_name, args, sources = tools_mix[i % len(tools_mix)]
                payload = {
                    "trace_id": f"trc-bench-{uuid.uuid4().hex[:8]}",
                    "agent_id": "hr-agent",
                    "session_id": f"sess-bench-{i % 20}",
                    "tool_name": tool_name,
                    "arguments": dict(args),
                    "context_sources": sources,
                    "task_description": "Evaluate and process candidates",
                    "timestamp": "2026-10-07T14:00:00Z",
                }

                t_start = time.perf_counter_ns()
                resp = client.post(execute_url, json=payload)
                t_end = time.perf_counter_ns()

                if resp.status_code != 200:
                    print(f"Error on call {i}: status {resp.status_code}, content: {resp.text[:300]}")
                    try:
                        err_bytes = proc.stderr.read()
                        print("Server STDERR:", err_bytes.decode(errors="ignore"))
                    except Exception:
                        pass
                    break

                total_http_ms = (t_end - t_start) / 1_000_000.0
                http_latencies.append(total_http_ms)

                res_json = resp.json()
                server_reported_ms = res_json.get("latency_ms", 0.0)
                rb = res_json.get("risk_breakdown", {})
                st = rb.get("stage_timings_ms", {})

                r_ms = st.get("rules", 0.0)
                p_ms = st.get("privacy", 0.0)
                b_ms = st.get("baseline", 0.0)
                j_ms = st.get("judge_stub", 0.0)
                pol_ms = st.get("policy", 0.0)
                m_ms = st.get("masking", 0.0)
                db_ms = st.get("db_session_lookup", st.get("db_write", 0.0))
                h_ms = st.get("hash_chain", 0.0)
                ws_ms = st.get("ws_broadcast", 0.0)
                inc_ms = st.get("incident_builder", 0.0)
                resp_ms = st.get("response_serialization", 0.0)

                rules_latencies.append(r_ms)
                privacy_latencies.append(p_ms)
                baseline_latencies.append(b_ms)
                judge_latencies.append(j_ms)
                policy_latencies.append(pol_ms)
                masking_latencies.append(m_ms)
                db_write_latencies.append(db_ms)
                hash_chain_latencies.append(h_ms)
                ws_latencies.append(ws_ms)
                incident_latencies.append(inc_ms)
                response_latencies.append(resp_ms)

                # HTTP transport overhead (wire transit + uvicorn routing)
                transport_ms = max(0.0, total_http_ms - server_reported_ms)
                http_transport_latencies.append(transport_ms)

                if (i + 1) % 100 == 0:
                    print(f"  Processed {i + 1} / 1,000 calls (last call: {total_http_ms:.1f}ms)...", flush=True)

        # 3. Print Statistical Breakdown
        print("\n" + "=" * 80)
        print("PER-STAGE TIMING BREAKDOWN (N = 1,000 Calls across real HTTP Gateway)")
        print("=" * 80)
        header = f"{'Pipeline Stage':<32} | {'p50 (ms)':<9} | {'p90 (ms)':<9} | {'p95 (ms)':<9} | {'Mean (ms)':<9}"
        print(header)
        print("-" * len(header))

        stages = [
            ("1. Unattributed (Wire Transit & OS Loopback)", http_transport_latencies),
            ("2. DB Session & Agent State", db_write_latencies),
            ("3. Rules & Trust Labeling", rules_latencies),
            ("4. Privacy Detection & Risk", privacy_latencies),
            ("5. Learned Baseline Detector", baseline_latencies),
            ("6. Intent Judge (Stub Replay)", judge_latencies),
            ("7. Policy Engine Evaluation", policy_latencies),
            ("8. Masking & Tokenization", masking_latencies),
            ("9. Hash Chain & Audit Log Write", hash_chain_latencies),
            ("10. WebSocket Event Broadcast", ws_latencies),
            ("11. Incident Builder Analysis", incident_latencies),
            ("12. Response Serialization", response_latencies),
            ("TOTAL REAL HTTP ROUND-TRIP", http_latencies),
        ]

        for name, vals in stages:
            s = calc_stats(vals)
            print(f"{name:<32} | {s['p50']:>9.2f} | {s['p90']:>9.2f} | {s['p95']:>9.2f} | {s['mean']:>9.2f}")

        print("=" * 80)

        # Save results to benchmark/reports/latency_1000_breakdown.json
        out_file = PROJECT_ROOT / "benchmark" / "reports" / "latency_1000_breakdown.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        summary = {name: calc_stats(vals) for name, vals in stages}
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"\n[+] Saved latency profile to {out_file}")

        # 4. Generate Plot of Latency vs Call Index
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            fig, ax = plt.subplots(figsize=(10, 5))
            indices = list(range(1, len(http_latencies) + 1))
            ax.plot(indices, http_latencies, label="Total Real HTTP Round-Trip", color="#2563eb", alpha=0.7, linewidth=1)
            ax.plot(indices, hash_chain_latencies, label="Hash Chain & DB Write", color="#dc2626", alpha=0.7, linewidth=1)
            ax.plot(indices, baseline_latencies, label="Baseline Anomaly Detector", color="#16a34a", alpha=0.7, linewidth=1)

            # Rolling 50-call average
            window = 50
            if len(http_latencies) >= window:
                rolling_avg = [sum(http_latencies[max(0, k - window):k]) / min(k, window) for k in range(1, len(http_latencies) + 1)]
                ax.plot(indices, rolling_avg, label=f"{window}-Call Moving Average", color="#1e293b", linewidth=2)

            ax.set_title("Gateway Request Latency vs. Call Index (1 to 1,000 Calls)")
            ax.set_xlabel("Sequential Gateway Call Index (Event Accumulation)")
            ax.set_ylabel("Latency (ms)")
            ax.grid(True, linestyle="--", alpha=0.5)
            ax.legend(loc="upper right")

            plot_path = PROJECT_ROOT / "benchmark" / "reports" / "latency_vs_call_index.png"
            fig.tight_layout()
            fig.savefig(plot_path, dpi=150)
            plt.close(fig)
            print(f"[+] Saved Latency vs Call Index plot to {plot_path}")
        except Exception as e:
            print(f"[-] Plot generation failed: {e}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    main()
