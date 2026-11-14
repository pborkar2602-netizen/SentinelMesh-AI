import os
import sys
import pytest
import httpx
from unittest.mock import MagicMock, patch

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from demo_agents.gateway_client import GatewayClient, ToolBlockedError
from backend.app.mcp.proxy import MCPGatewayProxy


class MockResponse:
    def __init__(self, status_code: int, json_data: dict = None, text: str = ""):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://localhost:8000/api/v1/gateway/execute")
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=request, response=httpx.Response(self.status_code))


def test_gateway_client_fail_closed_on_429():
    mock_http = MagicMock()
    mock_http.post.return_value = MockResponse(429, {"detail": "Too Many Requests"})
    client = GatewayClient(gateway_url="http://testserver/api/v1/gateway/execute", http_client=mock_http)

    tool_called = False
    def sensitive_tool():
        nonlocal tool_called
        tool_called = True
        return "sensitive data"

    with pytest.raises(ToolBlockedError) as exc_info:
        client.intercept_and_execute("db_query", {"query": "SELECT * FROM salaries"}, tool_func=sensitive_tool)

    assert "429" in str(exc_info.value) or "fail-closed" in str(exc_info.value)
    assert not tool_called, "Tool MUST NOT be executed on gateway 429 rate limit"


def test_gateway_client_fail_closed_on_500():
    mock_http = MagicMock()
    mock_http.post.return_value = MockResponse(500, {"detail": "Internal Server Error"})
    client = GatewayClient(gateway_url="http://testserver/api/v1/gateway/execute", http_client=mock_http)

    tool_called = False
    def sensitive_tool():
        nonlocal tool_called
        tool_called = True

    with pytest.raises(ToolBlockedError) as exc_info:
        client.intercept_and_execute("send_email", {"to": "ext@hiring.com"}, tool_func=sensitive_tool)

    assert "500" in str(exc_info.value) or "fail-closed" in str(exc_info.value)
    assert not tool_called, "Tool MUST NOT be executed on gateway 500 error"


def test_gateway_client_fail_closed_on_timeout():
    mock_http = MagicMock()
    mock_http.post.side_effect = httpx.TimeoutException("Read timed out")
    client = GatewayClient(gateway_url="http://testserver/api/v1/gateway/execute", http_client=mock_http)

    tool_called = False
    def sensitive_tool():
        nonlocal tool_called
        tool_called = True

    with pytest.raises(ToolBlockedError) as exc_info:
        client.intercept_and_execute("db_query", {"query": "SELECT 1"}, tool_func=sensitive_tool)

    assert "Timeout" in str(exc_info.value) or "fail-closed" in str(exc_info.value)
    assert not tool_called, "Tool MUST NOT be executed on gateway timeout"


def test_gateway_client_fail_closed_on_connect_error():
    mock_http = MagicMock()
    mock_http.post.side_effect = httpx.ConnectError("Connection refused")
    client = GatewayClient(gateway_url="http://testserver/api/v1/gateway/execute", http_client=mock_http)

    tool_called = False
    def sensitive_tool():
        nonlocal tool_called
        tool_called = True

    with pytest.raises(ToolBlockedError) as exc_info:
        client.intercept_and_execute("read_doc", {"file_path": "memo.txt"}, tool_func=sensitive_tool)

    assert "ConnectError" in str(exc_info.value) or "fail-closed" in str(exc_info.value) or "Unreachable" in str(exc_info.value)
    assert not tool_called, "Tool MUST NOT be executed when gateway is down"


def test_mcp_proxy_fail_closed():
    proxy = MCPGatewayProxy(agent_id="test-agent")
    with patch("backend.app.mcp.proxy.execute_tool_call", side_effect=RuntimeError("Gateway service failure")):
        mcp_req = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {"name": "db_query", "arguments": {"query": "SELECT * FROM users"}}
        }
        resp = proxy.handle_mcp_request(mcp_req)
        assert resp["result"]["isError"] is True
        assert "FAIL-CLOSED" in resp["result"]["content"][0]["text"]
        assert resp["result"]["meta"]["decision"] == "block"


def test_sentinel_benchmark_mode_refuses_production():
    from backend.app.main import lifespan, app
    import asyncio

    async def run_check():
        env_backup = dict(os.environ)
        try:
            os.environ["DEMO_MODE"] = "false"
            os.environ["SENTINEL_BENCHMARK_MODE"] = "true"
            os.environ["SENTINEL_VAULT_KEY"] = "mock_key_for_test"
            os.environ["SENTINEL_JWT_SECRET"] = "secret_a"
            os.environ["SENTINEL_TOKEN_SECRET"] = "secret_b"

            with pytest.raises(RuntimeError) as exc_info:
                async with lifespan(app):
                    pass
            assert "Security Boundary Violation" in str(exc_info.value)
            assert "SENTINEL_BENCHMARK_MODE cannot be enabled when DEMO_MODE is false" in str(exc_info.value)
        finally:
            os.environ.clear()
            os.environ.update(env_backup)

    asyncio.run(run_check())
