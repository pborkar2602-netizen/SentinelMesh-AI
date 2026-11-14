#!/usr/bin/env python3
"""
scripts/load_test.py

Reproducible multi-concurrency load testing for SentinelMesh Gateway:
Evaluates concurrency levels: C in {1, 5, 20, 50}
Measures:
- Sustained throughput (req/s)
- Latency percentiles (p50, p90, p95, p99, max)
- Outputs to benchmark/reports/load_test_results.json
"""

import os
import sys
import time
import json
import concurrent.futures
from typing import Dict, Any, List

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)
REPORTS_DIR = os.path.join(ROOT_DIR, "benchmark", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def percentile(arr: List[float], p: float) -> float:
    if not arr:
        return 0.0
    s = sorted(arr)
    idx = int(round((p / 100.0) * (len(s) - 1)))
    return round(s[idx], 3)


def run_benchmark_for_concurrency(concurrency: int, total_requests: int = 250) -> Dict[str, Any]:
    latencies_ms = []
    successes = 0

    def worker(idx: int):
        req_body = {
            "agent_id": f"agent-{idx % concurrency}",
            "session_id": f"load-sess-{idx}",
            "tool_name": "read_doc",
            "arguments": {"path": f"document_{idx}.txt"},
            "context_sources": [],
            "task_description": "Load benchmark task",
        }
        t0 = time.perf_counter()
        resp = client.post("/api/v1/gateway/execute", json=req_body)
        t_el = (time.perf_counter() - t0) * 1000.0
        return resp.status_code, t_el

    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker, i) for i in range(total_requests)]
        for f in concurrent.futures.as_completed(futures):
            status_code, lat = f.result()
            latencies_ms.append(lat)
            if status_code in (200, 429):
                successes += 1

    total_wall_s = time.perf_counter() - t_start
    throughput = round(total_requests / total_wall_s, 2)

    return {
        "concurrency": concurrency,
        "total_requests": total_requests,
        "successful_responses": successes,
        "wall_time_seconds": round(total_wall_s, 3),
        "throughput_req_per_sec": throughput,
        "latency_ms_p50": percentile(latencies_ms, 50),
        "latency_ms_p90": percentile(latencies_ms, 90),
        "latency_ms_p95": percentile(latencies_ms, 95),
        "latency_ms_p99": percentile(latencies_ms, 99),
        "latency_ms_max": round(max(latencies_ms), 3) if latencies_ms else 0.0,
        "latency_ms_mean": round(sum(latencies_ms) / len(latencies_ms), 3) if latencies_ms else 0.0,
    }


def main():
    print("===============================================================")
    print("      SENTINELMESH AI — GATEWAY LOAD BENCHMARK (k6/Locust)     ")
    print("===============================================================")
    concurrency_levels = [1, 5, 20, 50]
    results = {}

    for c in concurrency_levels:
        print(f"Running concurrency = {c}...")
        res = run_benchmark_for_concurrency(c, total_requests=200)
        results[f"concurrency_{c}"] = res
        print(f"  -> Concurrency {c:2d}: {res['throughput_req_per_sec']:6.1f} req/s | p50: {res['latency_ms_p50']:5.2f}ms | p95: {res['latency_ms_p95']:5.2f}ms | p99: {res['latency_ms_p99']:5.2f}ms")

    report_path = os.path.join(REPORTS_DIR, "v3_load_test_results.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved load benchmark report to: {report_path}")


if __name__ == "__main__":
    main()
