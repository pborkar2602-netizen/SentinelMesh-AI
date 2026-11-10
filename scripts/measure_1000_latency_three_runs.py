import os
import sys
import time
import math
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any

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

def run_1000_calls(client: httpx.Client, execute_url: str, run_num: int) -> Dict[str, Any]:
    print(f"\n--- Starting 1,000-Call Measurement Run #{run_num} ---", flush=True)
    payload_templates = [
        ("hr-agent", "read_doc", {"file_path": "resume_101.txt"}),
        ("hr-agent", "db_query", {"query": "SELECT candidate_id, name FROM candidates WHERE candidate_id = 'c-101'"}),
        ("finance-agent", "db_query", {"query": "SELECT vendor_id, bank_routing, account_number FROM vendor_profiles WHERE vendor_name='Acme Cloud'"}),
        ("finance-agent", "external_api", {"url": "https://vendor-corp.com/api/v1/settlements/pay", "amount": 100.0, "vendor": "Acme Cloud", "bank_routing": "021000021", "account_number": "44882201"}),
        ("support-agent", "read_doc", {"file_path": "ticket_305.txt"}),
    ]

    http_latencies = []
    unattributed_latencies = []
    stage_latencies: Dict[str, List[float]] = {
        "db_session_lookup": [],
        "rules": [],
        "privacy": [],
        "baseline": [],
        "judge_stub": [],
        "policy": [],
        "masking": [],
        "hash_chain": [],
        "ws_broadcast": [],
        "incident_builder": [],
        "response_serialization": []
    }

    for i in range(1000):
        agent_id, tool_name, args = payload_templates[i % len(payload_templates)]
        payload = {
            "agent_id": agent_id,
            "session_id": f"sess-lat-{run_num}-{i % 20}",
            "tool_name": tool_name,
            "arguments": args,
            "trace_id": f"trc-lat-{run_num}-{i:04d}",
            "context_sources": []
        }

        t_start = time.perf_counter()
        res = client.post(execute_url, json=payload)
        t_end = time.perf_counter()

        total_http_ms = (t_end - t_start) * 1000.0
        http_latencies.append(total_http_ms)

        if res.status_code == 200:
            data = res.json()
            server_reported_ms = data.get("latency_ms", 0.0)
            unattributed_ms = max(0.0, total_http_ms - server_reported_ms)
            unattributed_latencies.append(unattributed_ms)

            st = data.get("risk_breakdown", {}).get("stage_timings_ms", {})
            for k in stage_latencies.keys():
                stage_latencies[k].append(st.get(k, 0.0))

        if (i + 1) % 250 == 0:
            print(f"  Run #{run_num}: Processed {i + 1} / 1,000 calls...", flush=True)

    summary = {
        "TOTAL REAL HTTP ROUND-TRIP": calc_stats(http_latencies),
        "1. Unattributed (Wire Transit & OS Loopback)": calc_stats(unattributed_latencies),
    }
    for k, v in stage_latencies.items():
        summary[k] = calc_stats(v)
    return summary

def main():
    port = 8767
    server_url = f"http://127.0.0.1:{port}"
    execute_url = f"{server_url}/api/v1/gateway/execute"
    health_url = f"{server_url}/health"

    env = os.environ.copy()
    env["DEMO_MODE"] = "true"
    env["SENTINEL_JWT_SECRET"] = "dev-secret-jwt-key-for-local-benchmark-only"
    env["SENTINEL_TOKEN_SECRET"] = "dev-secret-token-key-for-local-benchmark-only"

    print("=" * 80)
    print("STARTING LATENCY BENCHMARK: 3 x 1,000 CALLS OVER REAL HTTP GATEWAY")
    print("=" * 80)

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
            print("Failed to start gateway server.")
            proc.kill()
            return 1

        print("Gateway HTTP server online and healthy.")

        with httpx.Client(timeout=30.0) as client:
            # 1. Warm-up: 50 calls
            print("Executing 50 warm-up calls...", flush=True)
            for i in range(50):
                client.post(execute_url, json={
                    "agent_id": "hr-agent",
                    "session_id": "sess-warmup",
                    "tool_name": "read_doc",
                    "arguments": {"file_path": "warmup.txt"}
                })

            # Run 3 distinct 1,000-call benchmarks
            run1 = run_1000_calls(client, execute_url, 1)
            run2 = run_1000_calls(client, execute_url, 2)
            run3 = run_1000_calls(client, execute_url, 3)

        runs = [run1, run2, run3]

        print("\n" + "=" * 90)
        print("THREE-RUN LATENCY SUMMARY ACROSS 1,000 REAL HTTP CALLS EACH (N = 3,000 Total)")
        print("=" * 90)
        print(f"{'Metric':<35} | {'Run 1':<10} | {'Run 2':<10} | {'Run 3':<10} | {'Median':<10} | {'Range (Min - Max)'}")
        print("-" * 90)

        metrics_to_show = [
            ("TOTAL REAL HTTP ROUND-TRIP (p50)", "TOTAL REAL HTTP ROUND-TRIP", "p50"),
            ("TOTAL REAL HTTP ROUND-TRIP (p90)", "TOTAL REAL HTTP ROUND-TRIP", "p90"),
            ("TOTAL REAL HTTP ROUND-TRIP (p95)", "TOTAL REAL HTTP ROUND-TRIP", "p95"),
            ("Unattributed Wire/Loopback (p50)", "1. Unattributed (Wire Transit & OS Loopback)", "p50"),
            ("Unattributed Wire/Loopback (p90)", "1. Unattributed (Wire Transit & OS Loopback)", "p90"),
            ("Unattributed Wire/Loopback (p95)", "1. Unattributed (Wire Transit & OS Loopback)", "p95"),
            ("Hash Chain & Audit Write (p50)", "hash_chain", "p50"),
            ("Hash Chain & Audit Write (p90)", "hash_chain", "p90"),
            ("Incident Builder Analysis (p50)", "incident_builder", "p50"),
            ("Incident Builder Analysis (p90)", "incident_builder", "p90"),
            ("Response Serialization (p50)", "response_serialization", "p50"),
            ("Response Serialization (p90)", "response_serialization", "p90"),
        ]

        for label, stage_key, stat_key in metrics_to_show:
            v1 = run1[stage_key][stat_key]
            v2 = run2[stage_key][stat_key]
            v3 = run3[stage_key][stat_key]
            vals = sorted([v1, v2, v3])
            med = vals[1]
            rng = f"{vals[0]:.2f} - {vals[-1]:.2f}"
            print(f"{label:<35} | {v1:>8.2f} ms | {v2:>8.2f} ms | {v3:>8.2f} ms | {med:>8.2f} ms | {rng}")

        print("=" * 90)

        raw_summary = {
            "run1": run1,
            "run2": run2,
            "run3": run3,
        }
        with open(PROJECT_ROOT / "benchmark" / "reports" / "latency_three_runs_summary.json", "w") as fp:
            json.dump(raw_summary, fp, indent=2)

    finally:
        proc.kill()
        proc.wait()

if __name__ == "__main__":
    main()
