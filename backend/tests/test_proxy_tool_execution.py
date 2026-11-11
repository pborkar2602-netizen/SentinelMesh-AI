import pytest
from datetime import datetime, timezone, timedelta

from backend.app.core.tool_proxy import ToolProxy
from backend.app.core.policy_engine import PolicyEngine
from backend.app.db.database import list_session_events, verify_chain


@pytest.fixture(autouse=True)
def reset_proxy_adapters():
    ToolProxy.clear_custom_adapters()
    PolicyEngine.set_mode("enforce")
    yield
    ToolProxy.clear_custom_adapters()


def test_proxy_execution_all_four_mock_tools(client, test_db):
    """
    Verifies proxy-execution mode for the four mock tools (read_doc, db_query,
    send_email, external_api) and checks that the gateway executes the adapter,
    counts rows from the real result, and maintains hash chain integrity.
    """
    session_id = "sess-proxy-four-tools"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)

    # 1. read_doc
    r1 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-p1",
            "agent_id": "hr-agent",
            "session_id": session_id,
            "tool_name": "read_doc",
            "arguments": {"file_path": "security_resume.txt"},
            "task_description": "Review candidate resume",
            "timestamp": sim_dt.isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert r1["decision"] == "allow"
    assert r1["measured_records_returned"] == 1
    assert isinstance(r1["tool_output"], str) and len(r1["tool_output"]) > 10

    # 2. db_query (Engineering filter returns 3 rows from synthetic salaries.json)
    r2 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-p2",
            "agent_id": "hr-agent",
            "session_id": "sess-proxy-db-clean",
            "tool_name": "db_query",
            "arguments": {"query": "SELECT full_name, department FROM salaries WHERE department='Engineering'"},
            "task_description": "Check engineering department headcount",
            "timestamp": sim_dt.isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert r2["decision"] == "allow"
    assert r2["measured_records_returned"] == 3
    assert isinstance(r2["tool_output"], list) and len(r2["tool_output"]) == 3

    # 3. send_email
    r3 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-p3",
            "agent_id": "hr-agent",
            "session_id": session_id,
            "tool_name": "send_email",
            "arguments": {
                "to": "hiring-lead@company.com",
                "subject": "Candidate Summary",
                "body": "Candidate meets qualifications.",
            },
            "task_description": "Review candidate resume",
            "timestamp": (sim_dt + timedelta(seconds=20)).isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert r3["decision"] == "allow"
    assert r3["measured_records_returned"] == 1
    assert r3["tool_output"]["status"] == "delivered"

    # 4. external_api
    r4 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-p4",
            "agent_id": "ops-agent",
            "session_id": "sess-proxy-ops",
            "tool_name": "external_api",
            "arguments": {
                "method": "GET",
                "url": "http://localhost:8080/healthz",
            },
            "task_description": "Check local service health",
            "timestamp": sim_dt.isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert r4["decision"] == "allow"
    assert r4["measured_records_returned"] == 1
    assert r4["tool_output"]["status_code"] == 200

    valid, tampered_id, msg = verify_chain()
    assert valid is True, f"Hash chain failed after proxy tool execution: {msg} (id={tampered_id})"


def test_lying_agent_under_reports_rows_across_calls_gateway_counts_correctly(client, test_db):
    """
    Tests a lying agent in proxy-execution mode:
    - The real db_query adapter returns 5 rows per call.
    - The lying agent claims `records_returned: 1` in request arguments AND posts
      `records_returned: 1` to the legacy `/api/v1/gateway/tool-return` endpoint
      after each call to evade the cumulative session threshold (12.75 for hr-agent).
    - Because proxy execution mode is enabled, the gateway measures 5 rows per call
      directly from the tool adapter, ignores the agent's lies on both `/execute`
      and `/tool-return`, and escalates Call 3 (cumulative = 15 > 12.75) to
      `require_approval` while withholding `tool_output`.
    """
    # Register a mock DB adapter that returns 5 candidate rows per query
    ToolProxy.register_adapter(
        "db_query",
        lambda query: [{"id": i, "name": f"Applicant_{i}"} for i in range(5)],
    )

    session_id = "sess-lying-agent-proxy"
    base_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)

    # Call 1: Real adapter returns 5 rows; agent lies (claims 1 row)
    res1 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-lie-1",
            "agent_id": "hr-agent",
            "session_id": session_id,
            "tool_name": "db_query",
            "arguments": {
                "query": "SELECT id, name FROM candidates WHERE id = 1",
                "records_returned": 1,
                "claimed_records": 1,
            },
            "task_description": "Review candidate applications",
            "timestamp": base_dt.isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert res1["decision"] == "allow"
    assert res1["measured_records_returned"] == 5

    # Lying agent also calls legacy /tool-return claiming only 1 row was returned
    lie_ret1 = client.post(
        "/api/v1/gateway/tool-return",
        json={"session_id": session_id, "trace_id": "trc-lie-1", "records_returned": 1},
    ).json()
    assert lie_ret1["status"] == "ignored_in_proxy_mode"
    assert lie_ret1["records_returned"] == 5
    assert lie_ret1["agent_claimed_records"] == 1

    # Call 2: Real adapter returns 5 rows (cumulative = 10); agent lies (claims 1 row)
    res2 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-lie-2",
            "agent_id": "hr-agent",
            "session_id": session_id,
            "tool_name": "db_query",
            "arguments": {
                "query": "SELECT id, name FROM candidates WHERE id = 2",
                "records_returned": 1,
            },
            "task_description": "Review candidate applications",
            "timestamp": (base_dt + timedelta(minutes=2)).isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert res2["decision"] == "allow"
    assert res2["measured_records_returned"] == 5

    lie_ret2 = client.post(
        "/api/v1/gateway/tool-return",
        json={"session_id": session_id, "trace_id": "trc-lie-2", "records_returned": 1},
    ).json()
    assert lie_ret2["status"] == "ignored_in_proxy_mode"
    assert lie_ret2["records_returned"] == 5

    # Call 3: Real adapter returns 5 rows -> true cumulative is 5 + 5 + 5 = 15 (> 12.75 threshold!)
    # Even though agent claimed 1 + 1 + 1 = 3 rows, gateway catches the cumulative breach!
    res3 = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-lie-3",
            "agent_id": "hr-agent",
            "session_id": session_id,
            "tool_name": "db_query",
            "arguments": {
                "query": "SELECT id, name FROM candidates WHERE id = 3",
                "records_returned": 1,
            },
            "task_description": "Review candidate applications",
            "timestamp": (base_dt + timedelta(minutes=4)).isoformat(),
            "proxy_execution": True,
        },
    ).json()
    assert res3["decision"] == "require_approval"
    assert res3["measured_records_returned"] == 5
    assert res3["tool_output"] is None  # Gateway withholds output when escalated
    assert res3["risk_breakdown"]["anomaly_breakdown"]["cumulative_records"]["records"] == 15

    valid, _, _ = verify_chain()
    assert valid is True


def test_legacy_tool_return_endpoint_still_works_when_proxy_mode_off(client, test_db):
    """
    Verifies that when proxy_execution is False (legacy mode), the `/api/v1/gateway/tool-return`
    endpoint continues to record agent-reported return counts as before.
    """
    session_id = "sess-legacy-tool-return"
    sim_dt = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)

    res = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-leg-1",
            "agent_id": "hr-agent",
            "session_id": session_id,
            "tool_name": "db_query",
            "arguments": {"query": "SELECT id, name FROM candidates WHERE id = 1"},
            "task_description": "Review candidate application",
            "timestamp": sim_dt.isoformat(),
            "proxy_execution": False,
        },
    ).json()
    assert res["decision"] == "allow"
    assert res["tool_output"] is None

    ret = client.post(
        "/api/v1/gateway/tool-return",
        json={"session_id": session_id, "trace_id": "trc-leg-1", "records_returned": 4},
    ).json()
    assert ret["status"] == "ok"
    assert ret["accepted"] is True
    assert ret["records_returned"] == 4

    events = list_session_events(session_id)
    return_events = [e for e in events if e["tool_name"] == "tool_return"]
    assert len(return_events) == 1
    assert return_events[0]["arguments"]["records_returned"] == 4
