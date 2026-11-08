from fastapi.testclient import TestClient

def test_event_store_persistence_and_ordering(client: TestClient):
    # Insert 3 sequential tool calls
    for i in range(1, 4):
        payload = {
            "trace_id": f"trc-order-{i:03d}",
            "agent_id": "hr-agent",
            "session_id": "sess-order-001",
            "tool_name": f"mock_tool_{i}",
            "arguments": {"step": i},
            "context_sources": []
        }
        res = client.post("/api/v1/gateway/execute", json=payload)
        assert res.status_code == 200

    # Retrieve events
    events_res = client.get("/api/v1/events?order=asc")
    assert events_res.status_code == 200
    events = events_res.json()

    assert len(events) == 3
    # Verify strict monotonic ordering by ID
    assert events[0]["id"] < events[1]["id"] < events[2]["id"]
    assert events[0]["tool_name"] == "mock_tool_1"
    assert events[1]["tool_name"] == "mock_tool_2"
    assert events[2]["tool_name"] == "mock_tool_3"
    assert events[0]["decision"] == "allow"

def test_agent_registry_and_filtering(client: TestClient):
    # Execute calls from two different agents
    client.post("/api/v1/gateway/execute", json={
        "agent_id": "hr-agent",
        "session_id": "sess-a",
        "tool_name": "read_doc",
        "arguments": {}
    })
    client.post("/api/v1/gateway/execute", json={
        "agent_id": "finance-agent",
        "session_id": "sess-b",
        "tool_name": "db_query",
        "arguments": {}
    })

    # Test filtering by agent_id
    hr_res = client.get("/api/v1/events?agent_id=hr-agent")
    assert hr_res.status_code == 200
    hr_events = hr_res.json()
    assert all(e["agent_id"] == "hr-agent" for e in hr_events)

    fin_res = client.get("/api/v1/events?agent_id=finance-agent")
    assert fin_res.status_code == 200
    fin_events = fin_res.json()
    assert all(e["agent_id"] == "finance-agent" for e in fin_events)

    # Test agent listing
    agents_res = client.get("/api/v1/agents")
    assert agents_res.status_code == 200
    agents = agents_res.json()
    agent_ids = [a["id"] for a in agents]
    assert "hr-agent" in agent_ids
    assert "finance-agent" in agent_ids
