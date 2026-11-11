import pytest
import uuid
from datetime import datetime, timezone
from backend.app.db.database import init_db, get_connection, verify_chain, list_session_events
from demo_agents.gateway_client import GatewayClient
from backend.tests.conftest import DirectClient

def test_demo_agent_posts_tool_return_and_verifies_hash_chain(monkeypatch):
    """
    Verifies that GatewayClient posts tool-return records upon tool completion,
    appends an immutable tool_return event into the audit chain, and that
    verify_chain() validates all cryptographic links intact.
    """
    monkeypatch.setenv("BENCHMARK_MODE", "true")
    init_db()
    session_id = f"sess-test-client-{uuid.uuid4().hex[:6]}"
    client = GatewayClient(
        agent_id="hr-agent",
        session_id=session_id,
        http_client=DirectClient()
    )

    def mock_db_tool(query: str):
        # Returns 4 records
        return [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
            {"id": 3, "name": "Charlie"},
            {"id": 4, "name": "Diana"}
        ]

    # Intercept and execute during business hours
    res = client.intercept_and_execute(
        tool_name="db_query",
        arguments={"query": "SELECT id, name FROM candidates WHERE department='Engineering' LIMIT 4"},
        tool_func=mock_db_tool,
        timestamp=datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    )
    assert len(res) == 4

    # Fetch session events
    events = list_session_events(session_id)
    # Must have 2 events: tool_call event + tool_return event
    assert len(events) == 2, f"Expected 2 events (call + return), found {len(events)}"
    assert events[0]["tool_name"] == "db_query"
    assert events[1]["tool_name"] == "tool_return"
    assert events[1]["decision"] == "recorded"
    assert events[1]["risk_breakdown"]["records_returned"] == 4

    # Cryptographic Hash Chain verification
    is_valid, tampered_id, message = verify_chain()
    assert is_valid is True, f"Hash chain verification failed: {message}"
    assert tampered_id is None
