import os, sys, time, subprocess, httpx

proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
    env=dict(os.environ, DEMO_MODE="true"),
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(3.5)

with httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0) as client:
    client.post("/api/v1/policies/mode", json={"mode": "monitor"})
    resp = client.post("/api/v1/demo/run_attack?mode=monitor&scenario=atk-001")
    print("Trigger:", resp.json())
    time.sleep(5.0)
    evs = client.get("/api/v1/events?limit=30").json()
    print(f"Total events: {len(evs)}")
    for e in evs[:20]:
        agent = e.get("agent_id", "?")
        sess = e.get("session_id", "?")
        tool = e.get("tool_name", "?")
        dec = e.get("decision", "?")
        risk = e.get("risk_score", "?")
        print(f"  {agent} | {sess} | {tool} | {dec} | risk:{risk}")

subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
