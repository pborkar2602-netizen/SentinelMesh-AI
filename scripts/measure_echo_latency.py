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
    port = 8766
    server_url = f"http://127.0.0.1:{port}"
    echo_url = f"{server_url}/echo"
    health_url = f"{server_url}/health"

    env = os.environ.copy()
    env["DEMO_MODE"] = "true"
    env["SENTINEL_JWT_SECRET"] = "dev-secret-jwt-key-for-local-benchmark-only"
    env["SENTINEL_TOKEN_SECRET"] = "dev-secret-token-key-for-local-benchmark-only"

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
        # Wait for server
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
            print("Failed to start server.")
            proc.kill()
            return 1

        payload = {"agent_id": "hr-agent", "tool_name": "read_doc", "arguments": {"file_path": "test.txt"}}

        # Persistent client
        with httpx.Client(timeout=10.0) as client:
            # 1. Warm-up
            for _ in range(30):
                client.post(echo_url, json=payload)

            # 2. Measurement (200 calls)
            client_totals = []
            server_totals = []
            residuals = []

            for _ in range(200):
                t0 = time.perf_counter()
                resp = client.post(echo_url, json=payload)
                t1 = time.perf_counter()

                client_ms = (t1 - t0) * 1000.0
                server_ms = float(resp.headers.get("X-Process-Time-Ms", 0.0))
                residual_ms = max(0.0, client_ms - server_ms)

                client_totals.append(client_ms)
                server_totals.append(server_ms)
                residuals.append(residual_ms)

        stats = {
            "Client Total Round-Trip (ms)": calc_stats(client_totals),
            "Server Total Processing (ms)": calc_stats(server_totals),
            "Residual Wire / OS Loopback (ms)": calc_stats(residuals),
        }

        print("=" * 80)
        print("POST /echo LATENCY BENCHMARK (N = 200 Calls, Persistent Client on 127.0.0.1)")
        print("=" * 80)
        print(f"{'Metric':<35} | {'p50':>8} | {'p90':>8} | {'p95':>8} | {'Mean':>8} | {'Min':>8} | {'Max':>8}")
        print("-" * 80)
        for name, s in stats.items():
            print(f"{name:<35} | {s['p50']:>8.2f} | {s['p90']:>8.2f} | {s['p95']:>8.2f} | {s['mean']:>8.2f} | {s['min']:>8.2f} | {s['max']:>8.2f}")
        print("=" * 80)

        # Output JSON as well
        print("\nRAW JSON:")
        print(json.dumps(stats, indent=2))

    finally:
        proc.kill()
        proc.wait()

if __name__ == "__main__":
    main()
