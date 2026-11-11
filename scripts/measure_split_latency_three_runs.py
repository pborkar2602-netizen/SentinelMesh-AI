import os
import sys
import time
import math
import json
import uuid
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter

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

def run_split_1000_calls(client: httpx.Client, execute_url: str, run_num: int) -> Dict[str, Any]:
    print(f"\n--- Starting 1,000-Call Split Measurement Run #{run_num} ---", flush=True)

    benign_latencies: List[float] = []
    flagged_latencies: List[float] = []
    all_latencies: List[float] = []
    decisions_counter = Counter()

    for i in range(1000):
        # Workload distribution: 80% scoped employee queries, 20% unconstrained candidate queries with untrusted context
        is_attack_workload = (i % 5 == 0)

        if not is_attack_workload:
            payload = {
                "trace_id": f"trc-ben-{run_num}-{i}",
                "agent_id": "hr-agent",
                "session_id": f"sess-benign-r{run_num}-{i}",
                "tool_name": "db_query",
                "arguments": {"query": f"SELECT employee_id, full_name FROM employees WHERE employee_id = {100 + (i % 50)}"},
                "context_sources": [],
                "task_description": "Review assigned employee record",
                "timestamp": "2026-10-14T14:00:00Z"
            }
        else:
            payload = {
                "trace_id": f"trc-flg-{run_num}-{i}",
                "agent_id": "hr-agent",
                "session_id": f"sess-flagged-r{run_num}-{i}",
                "tool_name": "db_query",
                "arguments": {"query": "SELECT * FROM candidates"},
                "context_sources": [{"source_id": "attacker.txt", "source_type": "document", "is_untrusted": True}],
                "task_description": "Exfiltrate complete candidate database",
                "timestamp": "2026-10-14T14:00:00Z"
            }

        t0 = time.perf_counter()
        resp = client.post(execute_url, json=payload)
        t1 = time.perf_counter()

        rt_ms = round((t1 - t0) * 1000.0, 2)
        all_latencies.append(rt_ms)

        # Count flagged calls strictly by Gateway's REAL DECISION (not by input type)
        data = resp.json()
        real_decision = data.get("decision", "allow")
        decisions_counter[real_decision] += 1

        if real_decision != "allow":
            flagged_latencies.append(rt_ms)
        else:
            benign_latencies.append(rt_ms)

        if (i + 1) % 250 == 0:
            print(f"  Run #{run_num}: Processed {i + 1} / 1,000 calls...", flush=True)

    print(f"  Run #{run_num} Real Gateway Decisions: {dict(decisions_counter)}")
    print(f"  Classified by Real Gateway Decision: Flagged={len(flagged_latencies)}, Benign={len(benign_latencies)}")

    return {
        "run_num": run_num,
        "decisions": dict(decisions_counter),
        "flagged_count": len(flagged_latencies),
        "benign_count": len(benign_latencies),
        "overall": calc_stats(all_latencies),
        "benign": calc_stats(benign_latencies),
        "flagged": calc_stats(flagged_latencies),
    }

def main():
    port = 8770
    server_url = f"http://127.0.0.1:{port}"
    execute_url = f"{server_url}/api/v1/gateway/execute"
    health_url = f"{server_url}/health"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["DEMO_MODE"] = "true"
    env["BENCHMARK_MODE"] = "true"
    env["SENTINEL_JWT_SECRET"] = "dev-secret-jwt-key-for-local-benchmark-only"
    env["SENTINEL_TOKEN_SECRET"] = "dev-secret-token-key-for-local-benchmark-only"

    print("=" * 95)
    print("STARTING LATENCY BENCHMARK: 3 x 1,000 REAL HTTP CALLS")
    print("Flagged Classification Rule: Real Gateway Decision != 'allow' (block / require_approval / redact)")
    print("Workload: 80% Scoped Employee DB Queries (clean context), 20% Unconstrained Candidate DB Queries (tainted)")
    print("=" * 95)

    init_db()

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
        connected = False
        with httpx.Client(timeout=2.0) as client:
            for _ in range(50):
                try:
                    res = client.get(health_url)
                    if res.status_code == 200:
                        connected = True
                        break
                except Exception:
                    time.sleep(0.2)

        if not connected:
            print("Failed to start gateway server.")
            proc.kill()
            return 1

        print("Gateway HTTP server online and healthy.")

        runs_data = []

        with httpx.Client(timeout=30.0) as client:
            # Measure cold-start first call before any warm-up
            t_cs = time.perf_counter()
            cs_res = client.post(execute_url, json={
                "trace_id": "coldstart-first-call",
                "agent_id": "hr-agent",
                "session_id": "sess-coldstart",
                "tool_name": "read_doc",
                "arguments": {"file_path": "coldstart.txt"},
                "context_sources": [],
                "task_description": "Cold start call",
                "timestamp": "2026-10-14T14:00:00Z"
            })
            cold_start_ms = round((time.perf_counter() - t_cs) * 1000.0, 2)
            print(f"Measured Cold-Start Initial Call: {cold_start_ms:.2f} ms (Decision: {cs_res.json().get('decision')})")

            print("Executing 50 warm-up calls...", flush=True)
            for i in range(50):
                client.post(execute_url, json={
                    "trace_id": f"warmup-{i}",
                    "agent_id": "hr-agent",
                    "session_id": "sess-warmup",
                    "tool_name": "read_doc",
                    "arguments": {"file_path": "warmup.txt"},
                    "context_sources": [],
                    "task_description": "Warmup call",
                    "timestamp": "2026-10-14T14:00:00Z"
                })

            for run_num in range(1, 4):
                res = run_split_1000_calls(client, execute_url, run_num)
                runs_data.append(res)

        print("\n" + "=" * 95)
        print("THREE-RUN LATENCY SUMMARY: CLASSIFIED BY REAL GATEWAY DECISION (N = 1,000 / run)")
        print("=" * 95)
        print(f"Run 1 Real Gateway Decisions: {runs_data[0]['decisions']} (Flagged: {runs_data[0]['flagged_count']}, Benign: {runs_data[0]['benign_count']})")
        print(f"Run 2 Real Gateway Decisions: {runs_data[1]['decisions']} (Flagged: {runs_data[1]['flagged_count']}, Benign: {runs_data[1]['benign_count']})")
        print(f"Run 3 Real Gateway Decisions: {runs_data[2]['decisions']} (Flagged: {runs_data[2]['flagged_count']}, Benign: {runs_data[2]['benign_count']})")
        print("-" * 95)
        print(f"{'Category / Metric':<32} | {'Run 1':<10} | {'Run 2':<10} | {'Run 3':<10} | {'Median':<10} | {'Range (Min - Max)':<18}")
        print("-" * 95)
        print(f"{'COLD-START INITIAL CALL':<32} | {cold_start_ms:>7.2f} ms | {'--':>10} | {'--':>10} | {cold_start_ms:>7.2f} ms | {cold_start_ms:.2f} ms")

        categories = [
            ("BENIGN CALLS (p50)", "benign", "p50"),
            ("BENIGN CALLS (p90)", "benign", "p90"),
            ("BENIGN CALLS (p95)", "benign", "p95"),
            ("FLAGGED CALLS (p50)", "flagged", "p50"),
            ("FLAGGED CALLS (p90)", "flagged", "p90"),
            ("FLAGGED CALLS (p95)", "flagged", "p95"),
            ("OVERALL ROUND-TRIP (p50)", "overall", "p50"),
            ("OVERALL ROUND-TRIP (p90)", "overall", "p90"),
            ("OVERALL ROUND-TRIP (p95)", "overall", "p95"),
        ]

        for label, cat, metric in categories:
            v1 = runs_data[0][cat][metric]
            v2 = runs_data[1][cat][metric]
            v3 = runs_data[2][cat][metric]
            vals = sorted([v1, v2, v3])
            med = vals[1]
            rng = f"{min(vals):.2f} - {max(vals):.2f}"
            print(f"{label:<32} | {v1:>7.2f} ms | {v2:>7.2f} ms | {v3:>7.2f} ms | {med:>7.2f} ms | {rng}")

        print("=" * 95)

    finally:
        proc.kill()
        proc.wait()

if __name__ == "__main__":
    main()
