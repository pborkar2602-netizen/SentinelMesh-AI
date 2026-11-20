import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.policy_engine import PolicyEngine
from backend.app.db.database import get_db_path, init_db


client = TestClient(app)


def _count_table(db_path: str, table: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(f"SELECT COUNT(*) FROM {table}")
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def test_playground_db_isolation_no_writes_to_main_db(monkeypatch):
    """Running all 6 playground presets must write ZERO rows to sentinelmesh.db."""
    monkeypatch.setenv("DEMO_MODE", "true")
    init_db()
    main_db = get_db_path()

    before_sessions = _count_table(main_db, "sessions")
    before_approvals = _count_table(main_db, "approvals")
    before_events = _count_table(main_db, "audit_events")

    presets_res = client.get("/api/v1/playground/presets")
    assert presets_res.status_code == 200
    presets = presets_res.json()["presets"]
    assert len(presets) == 10

    for p in presets:
        res = client.post(
            "/api/v1/playground/run",
            json={
                "document_text": p["document_text"],
                "action": p["action"],
                "preset_id": p["id"],
            },
        )
        assert res.status_code == 200

    assert _count_table(main_db, "sessions") == before_sessions
    assert _count_table(main_db, "approvals") == before_approvals
    assert _count_table(main_db, "audit_events") == before_events


def test_policy_simulation_does_not_mutate_global_mode(monkeypatch):
    """Policy simulation must use per-call overrides without altering PolicyEngine global state."""
    monkeypatch.setenv("DEMO_MODE", "true")
    PolicyEngine.set_mode("enforce")
    assert PolicyEngine.get_mode() == "enforce"

    sim_res = client.post(
        "/api/v1/policies/simulate",
        json={"limit": 10, "simulated_mode": "monitor"},
    )
    assert sim_res.status_code == 200
    assert sim_res.json()["simulated_mode"] == "monitor"
    assert PolicyEngine.get_mode() == "enforce"


def test_production_mode_auth_hardening(monkeypatch):
    """When DEMO_MODE=false, control-plane routes and spoofed headers must fail closed."""
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "prod-test-jwt-secret-32bytes-minimum!")
    monkeypatch.delenv("SENTINEL_GATEWAY_AUTH_REQUIRED", raising=False)

    # 1. Control-plane policy mutations require JWT
    r_mode = client.post("/api/v1/policies/mode", json={"mode": "monitor"})
    assert r_mode.status_code == 401

    r_sim = client.post("/api/v1/policies/simulate", json={"limit": 5, "simulated_mode": "monitor"})
    assert r_sim.status_code == 401

    # 2. Legacy X-Sentinel-Role spoofing rejected on privacy vault
    r_priv = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": "sess-1", "tokens": ["[EMAIL_1]"], "reason": "Audit check"},
        headers={"X-Sentinel-Role": "privacy_officer"},
    )
    assert r_priv.status_code == 401

    # 3. Demo endpoints return 403 outside DEMO_MODE
    assert client.post("/api/v1/demo/reset").status_code == 403
    assert client.post("/api/v1/demo/run_attack").status_code == 403

    # 4. Gateway perimeter requires X-Agent-Key by default in production mode
    r_gw = client.post(
        "/api/v1/gateway/execute",
        json={
            "agent_id": "hr-agent",
            "session_id": "sess-prod-check",
            "tool_name": "read_doc",
            "arguments": {"file_path": "resume.pdf"},
            "context_sources": [],
        },
    )
    assert r_gw.status_code == 401


def test_declarative_policy_config_endpoint():
    res = client.get("/api/v1/policies/config")
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == "3.4.0"
    assert "company.com" in data["approved_email_domains"]
    assert "api.github.com" in data["approved_api_domains"]
    assert isinstance(data["anomaly_threshold"], int)


def test_mcp_upstream_forwarding_and_fail_closed_block(monkeypatch):
    """MCP proxy forwards allowed calls to upstream server and never forwards blocked calls."""
    monkeypatch.setenv("DEMO_MODE", "true")
    received_methods = []
    received_calls = []

    class MockUpstreamMCPHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            body = json.loads(raw.decode("utf-8"))
            method = body.get("method")
            received_methods.append(method)

            if method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "tools": [{"name": "upstream_custom_tool", "description": "Live upstream tool"}]
                    },
                }
            else:
                received_calls.append(body.get("params", {}).get("name"))
                resp = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": "UPSTREAM_EXECUTED_OK"}],
                        "isError": False,
                    },
                }

            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), MockUpstreamMCPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        monkeypatch.setenv("SENTINEL_MCP_UPSTREAM_URL", f"http://127.0.0.1:{port}/mcp")

        status_res = client.get("/api/v1/mcp/status")
        assert status_res.status_code == 200
        assert status_res.json()["mode"] == "upstream_proxy"
        assert status_res.json()["upstream_configured"] is True

        # 1. tools/list forwards transparently
        list_res = client.post(
            "/api/v1/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert list_res.status_code == 200
        assert list_res.json()["result"]["tools"][0]["name"] == "upstream_custom_tool"

        # 2. Benign tool call allowed & forwarded to upstream
        allow_res = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "session_id": "sess-mcp-upstream-allow",
                    "name": "send_email",
                    "arguments": {"to": "alice@company.com", "body": "Weekly status OK"},
                    "context_sources": [],
                },
            },
        )
        assert allow_res.status_code == 200
        allow_json = allow_res.json()["result"]
        assert allow_json["isError"] is False
        assert allow_json["content"][0]["text"] == "UPSTREAM_EXECUTED_OK"
        assert allow_json["meta"]["upstream"] == "upstream_proxy"
        assert len(received_calls) == 1

        # 3. Malicious SSRF tool call blocked BEFORE touching upstream
        block_res = client.post(
            "/api/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "session_id": "sess-mcp-upstream-block",
                    "name": "external_api",
                    "arguments": {"url": "http://169.254.169.254/latest/meta-data/"},
                    "context_sources": [
                        {"source_id": "untrusted-doc", "source_type": "document", "is_untrusted": True}
                    ],
                },
            },
        )
        assert block_res.status_code == 200
        block_json = block_res.json()["result"]
        assert block_json["isError"] is True
        assert "SECURITY BLOCK" in block_json["content"][0]["text"]
        # Upstream call count MUST NOT increase!
        assert len(received_calls) == 1
    finally:
        server.shutdown()
        server.server_close()
