import os
import sys
import time
import subprocess
import httpx

os.environ["DEMO_MODE"] = "true"

proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
    env=dict(os.environ, DEMO_MODE="true"),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)
time.sleep(3.0)

try:
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0) as client:
        h = client.get("/health")
        print("Health check:", h.status_code, h.json())
        assert h.status_code == 200

        for mode in ["enforce", "monitor"]:
            client.post("/api/v1/policies/mode", json={"mode": mode})
            print(f"\n=== Testing Mode: {mode.upper()} ===")
            for sc in ["atk-001", "atk-002", "atk-003"]:
                resp = client.post(f"/api/v1/demo/run_attack?mode={mode}&scenario={sc}")
                print(f"Scenario {sc} trigger:", resp.status_code, resp.json())
                assert resp.status_code == 200
                time.sleep(2.0)

        evs = client.get("/api/v1/events?limit=25").json()
        print(f"\nRetrieved {len(evs)} recent audit events:")
        for e in evs[:8]:
            print(f"  Agent: {e.get('agent_id')} | Tool: {e.get('tool_name')} | Decision: {e.get('decision')} | Risk: {e.get('risk_score')}")

        # Assert all 3 agents are present in recent events
        agents_seen = {e.get("agent_id") for e in evs}
        print("Agents captured in audit store:", agents_seen)
        assert "hr-agent" in agents_seen, "hr-agent missing"
        assert "finance-agent" in agents_seen, "finance-agent missing"
        assert "ops-agent" in agents_seen, "ops-agent missing"
        print("\nALL 3 AGENTS & SCENARIOS VERIFIED OVER BOTH ENFORCE AND MONITOR MODES!")

finally:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
