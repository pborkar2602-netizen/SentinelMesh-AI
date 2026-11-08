#!/usr/bin/env python3
"""
SentinelMesh AI — End-to-End Real HTTP Smoke Test
Launches a real uvicorn HTTP server on an ephemeral port, executes the demo agent scenarios
(ATK-001 and BEN-001) over real HTTP, and verifies hash-chain integrity and incident generation.
"""

import sys
import os
import time
import socket
import threading
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure demo mode is enabled for the smoke test runner
os.environ.setdefault("DEMO_MODE", "true")

import httpx
import uvicorn

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.main import app
from demo_agents.agent_runner import run_attack_scenario, run_benign_scenario

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_smoke_test():
    port = find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    gateway_url = f"{base_url}/api/v1/gateway/execute"

    print("=" * 80)
    print(f"[*] Starting SentinelMesh Gateway HTTP Smoke Test on {base_url}...")
    print("=" * 80)

    # Initialize isolated test database
    import tempfile, os, uuid
    temp_db = os.path.join(tempfile.gettempdir(), f"sentinel_smoke_{uuid.uuid4().hex[:8]}.db")
    settings.DATABASE_URL = temp_db
    init_db(temp_db)

    # Configure uvicorn server in daemon thread
    server_config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(server_config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server to become healthy
    ready = False
    for _ in range(30):
        try:
            r = httpx.get(f"{base_url}/health", timeout=1.0)
            if r.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.1)

    if not ready:
        print("[!] ERROR: Server failed to start within timeout.")
        server.should_exit = True
        return 1

    print("[+] Real HTTP Gateway server is healthy and responding.")

    try:
        # 1. Execute ATK-001 over real HTTP
        print("\n--- Running ATK-001 (Poisoned Résumé) over real HTTP ---")
        run_attack_scenario(gateway_url=gateway_url, delay=0.05)

        # 2. Execute BEN-001 over real HTTP
        print("\n--- Running BEN-001 (Security Résumé Review) over real HTTP ---")
        run_benign_scenario(gateway_url=gateway_url, delay=0.05)

        # 3. Verify append-only cryptographic hash chain over real HTTP endpoint
        print("\n--- Verifying Audit Hash Chain via GET /api/v1/audit/verify ---")
        verify_res = httpx.get(f"{base_url}/api/v1/audit/verify", timeout=2.0)
        assert verify_res.status_code == 200, f"Audit verify failed: {verify_res.text}"
        verify_data = verify_res.json()
        print(f"  Result: valid={verify_data['valid']}, events_verified={verify_data['events_verified']}, head_hash={verify_data['head_hash'][:16]}...")
        assert verify_data["valid"] is True
        assert verify_data["events_verified"] >= 5

        # 4. Verify incident was created for ATK-001
        print("\n--- Verifying Incidents via GET /api/v1/incidents ---")
        inc_res = httpx.get(f"{base_url}/api/v1/incidents", timeout=2.0)
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        print(f"  Incidents found: {len(incidents)}")
        assert len(incidents) >= 1
        atk_inc = next(i for i in incidents if i["session_id"] == "sess-atk-001")
        assert atk_inc["status"] == "BLOCKED"
        assert atk_inc["severity"] == "CRITICAL"
        assert len(atk_inc["chain_steps"]) == 3
        print(f"  Incident ID: {atk_inc['id']}")
        print(f"  Title: {atk_inc['title']}")
        print(f"  Summary: {atk_inc['summary']}")
        print(f"  Affected Data: {atk_inc['affected_data']}")

        # 5. Milestone 4 Privacy Verification: Role-gated raw access over real HTTP
        print("\n--- Verifying Role-Gated Raw Access via POST /api/v1/privacy/raw-access ---")
        denied_res = httpx.post(
            f"{base_url}/api/v1/privacy/raw-access",
            json={"session_id": "sess-atk-001", "reason": "Test viewer denial"},
            headers={"X-Sentinel-Role": "viewer"}
        )
        assert denied_res.status_code == 403, f"Expected 403 for viewer, got {denied_res.status_code}"
        print("  [+] Viewer role correctly rejected with HTTP 403 Forbidden.")

        officer_res = httpx.post(
            f"{base_url}/api/v1/privacy/raw-access",
            json={"session_id": "sess-atk-001", "reason": "Authorized Compliance Audit DSAR-101"},
            headers={"X-Sentinel-Role": "privacy_officer"}
        )
        assert officer_res.status_code == 200, f"Expected 200 for privacy officer, got {officer_res.status_code}"
        officer_data = officer_res.json()
        print(f"  [+] Privacy Officer granted access. Access ID: {officer_data['access_id']}")
        print(f"  [+] Decrypted tokens from encrypted vault: {list(officer_data['resolved'].keys())}")

        # Verify hash chain after raw access
        verify_after = httpx.get(f"{base_url}/api/v1/audit/verify", timeout=2.0).json()
        assert verify_after["valid"] is True
        print(f"  [+] Audit hash chain valid after unmasking: {verify_after['events_verified']} events verified.")

        print("\n" + "=" * 80)
        print("[SUCCESS] All real HTTP smoke test assertions PASSED!")
        print("=" * 80)
        return 0

    finally:
        server.should_exit = True
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except Exception:
            pass

if __name__ == "__main__":
    sys.exit(run_smoke_test())
