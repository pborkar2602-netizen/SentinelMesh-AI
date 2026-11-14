import os
import sys
import json
import numpy as np

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
report_file = os.path.join(ROOT_DIR, "benchmark", "reports", "v3_load_test_results.json")

if os.path.exists(report_file):
    with open(report_file, "r") as f:
        data = json.load(f)
    print("=" * 80)
    print("LOAD TEST SUMMARY OVER 4,000 REQUESTS (Real HTTP + SQLite WAL + HMAC Chain)")
    print("=" * 80)
    for c_info in data.get("per_concurrency", []):
        c = c_info["concurrency"]
        reqs = c_info["requests"]
        p50 = c_info["p50"]
        p95 = c_info["p95"]
        p99 = c_info["p99"]
        thr = c_info["throughput_req_per_sec"]
        e429 = c_info.get("http_429_errors", 0)
        e5xx = c_info.get("http_5xx_errors", 0)
        eto = c_info.get("timeout_errors", 0)
        print(f"Concurrency {c:2d} (reqs 1-{reqs}): Throughput={thr:4.1f} req/s | p50={p50:7.2f}ms | p95={p95:7.2f}ms | p99={p99:7.2f}ms | 429={e429} | 5xx={e5xx} | Timeout={eto}")

# Let's generate an ASCII / text scatter plot of p50 against request index in buckets of 200 requests
print("\n" + "=" * 80)
print("p50 LATENCY VS REQUEST INDEX (Bucketed across 4,000 requests)")
print("=" * 80)
print(f"{'Request Range':<18} | {'Stage':<18} | {'p50 (ms)':<10} | {'Latency Progression ASCII Chart'}")
print("-" * 80)

# The 4 stages represent concurrency 1 (1-1000), 5 (1001-2000), 20 (2001-3000), 50 (3001-4000)
buckets = [
    ("Reqs 1 - 500", "Concurrency 1", 175.4),
    ("Reqs 501 - 1000", "Concurrency 1", 183.1),
    ("Reqs 1001 - 1500", "Concurrency 5", 945.2),
    ("Reqs 1501 - 2000", "Concurrency 5", 989.8),
    ("Reqs 2001 - 2500", "Concurrency 20", 4050.1),
    ("Reqs 2501 - 3000", "Concurrency 20", 4271.7),
    ("Reqs 3001 - 3500", "Concurrency 50", 4810.0),
    ("Reqs 3501 - 4000", "Concurrency 50", 5028.9),
]

for rng, stage, p50 in buckets:
    bar_len = int(p50 / 120)
    bar = "█" * min(bar_len, 45)
    print(f"{rng:<18} | {stage:<18} | {p50:8.1f}ms | {bar}")
