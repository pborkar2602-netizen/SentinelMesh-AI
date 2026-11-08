from fastapi.testclient import TestClient

def test_health_check(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "SentinelMesh AI" in data["service"]

def test_gateway_execute_allow(client: TestClient):
    payload = {
        "trace_id": "trc-test-001",
        "agent_id": "hr-agent",
        "session_id": "sess-test-001",
        "tool_name": "read_doc",
        "arguments": {"file_path": "resume.pdf"},
        "context_sources": [
            {"source_id": "resume.pdf", "source_type": "document", "is_untrusted": False}
        ],
        "task_description": "Summarize resume"
    }

    response = client.post("/api/v1/gateway/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["trace_id"] == "trc-test-001"
    assert data["agent_id"] == "hr-agent"
    assert data["decision"] == "allow"
    assert data["latency_ms"] >= 0.0

def test_gateway_execute_untrusted_context(client: TestClient):
    payload = {
        "trace_id": "trc-test-002",
        "agent_id": "hr-agent",
        "session_id": "sess-test-002",
        "tool_name": "db_query",
        "arguments": {"query": "SELECT candidate_id, name FROM candidates"},
        "context_sources": [
            {"source_id": "resume.pdf", "source_type": "document", "is_untrusted": True}
        ]
    }

    response = client.post("/api/v1/gateway/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["risk_score"] > 0
    assert data["risk_breakdown"]["untrusted_taint"] > 0

def test_gateway_validation_error(client: TestClient):
    # Missing required tool_name
    bad_payload = {
        "agent_id": "hr-agent",
        "session_id": "sess-test-003"
    }
    response = client.post("/api/v1/gateway/execute", json=bad_payload)
    assert response.status_code == 422
