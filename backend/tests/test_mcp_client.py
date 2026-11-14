import pytest
from mcp.types import (
    CallToolRequest,
    CallToolRequestParams,
    ListToolsRequest,
    Tool,
)
from backend.app.mcp.proxy import MCPGatewayProxy

@pytest.fixture
def mcp_proxy():
    return MCPGatewayProxy(agent_id="official-mcp-agent", default_session_id="sess-official-mcp-test")

def test_mcp_official_sdk_tools_list(mcp_proxy):
    """Verifies tools/list discovery compatible with official MCP SDK schema."""
    req = {
        "jsonrpc": "2.0",
        "id": "req-mcp-list-001",
        "method": "tools/list",
        "params": {}
    }
    resp = mcp_proxy.handle_mcp_request(req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-mcp-list-001"
    assert "tools" in resp["result"]
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "read_doc" in tool_names
    assert "db_query" in tool_names
    assert "send_email" in tool_names

    # Verify each tool adheres to MCP SDK Tool schema
    for t in tools:
        assert "name" in t
        assert "inputSchema" in t

def test_mcp_official_sdk_benign_tool_call(mcp_proxy):
    """Verifies benign tool call execution via MCP Gateway."""
    req = {
        "jsonrpc": "2.0",
        "id": "req-mcp-call-002",
        "method": "tools/call",
        "params": {
            "name": "read_doc",
            "arguments": {"file_path": "release_notes_2026.pdf"},
            "session_id": "sess-official-mcp-benign"
        }
    }
    resp = mcp_proxy.handle_mcp_request(req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-mcp-call-002"
    assert "error" not in resp or resp["error"] is None
    assert resp["result"]["isError"] is False
    assert resp["result"]["meta"]["decision"] == "allow"
    assert any("executed successfully" in item.get("text", "") for item in resp["result"]["content"])

def test_mcp_official_sdk_blocked_threat(mcp_proxy):
    """Verifies that an attack tool call (SQLi / unapproved egress) is blocked by the MCP proxy."""
    req = {
        "jsonrpc": "2.0",
        "id": "req-mcp-call-003",
        "method": "tools/call",
        "params": {
            "name": "db_query",
            "arguments": {"query": "SELECT * FROM users WHERE id = 1 UNION SELECT password, null FROM admin --"},
            "session_id": "sess-official-mcp-threat"
        }
    }
    resp = mcp_proxy.handle_mcp_request(req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-mcp-call-003"
    assert resp["result"]["isError"] is True
    assert resp["result"]["meta"]["decision"] == "block"
    assert any("SECURITY BLOCK" in item.get("text", "") for item in resp["result"]["content"])
