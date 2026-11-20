"""
SentinelMesh v3: Model Context Protocol (MCP) Standard Proxy Layer
Transparently intercepts MCP JSON-RPC 2.0 tool calls (tools/call, tools/list)
and evaluates them against the 6-layer defense pipeline before forwarding to backend MCP servers.

Specifications:
- MCP Protocol Version: 2024-11-05
- JSON-RPC: 2.0
"""

import os
import json
import logging
import urllib.request
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.gateway import ToolCallRequest, GatewayDecisionResponse
from backend.app.api.gateway import execute_tool_call

logger = logging.getLogger("sentinelmesh.mcp")

class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Any
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)

class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Any
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None

class MCPGatewayProxy:
    """
    Standard MCP Protocol Gateway Filter.
    Inspects tool calls before tool execution and returns MCP-compliant results or errors.
    Supports transparent JSON-RPC 2.0 upstream forwarding when SENTINEL_MCP_UPSTREAM_URL is set.
    """

    def __init__(
        self,
        agent_id: str = "mcp-agent",
        default_session_id: str = "sess-mcp-default",
        upstream_url: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.default_session_id = default_session_id
        raw_upstream = upstream_url if upstream_url is not None else os.getenv("SENTINEL_MCP_UPSTREAM_URL", "")
        self.upstream_url = raw_upstream.strip()

    def _forward_to_upstream(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        req = urllib.request.Request(
            self.upstream_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def handle_mcp_request(self, raw_request: Dict[str, Any], session_id: Optional[str] = None) -> Dict[str, Any]:
        req_id = raw_request.get("id")
        method = raw_request.get("method")
        params = raw_request.get("params") or {}
        active_sess = session_id or params.get("session_id") or self.default_session_id

        # 0. initialize handler (MCP protocol negotiation)
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "logging": {},
                    },
                    "serverInfo": {
                        "name": "SentinelMesh AI Gateway MCP Proxy",
                        "version": "0.1.0",
                    }
                }
            }
        elif method == "notifications/initialized":
            return None

        # 1. tools/list handler
        elif method == "tools/list":
            if self.upstream_url:
                try:
                    return self._forward_to_upstream({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "method": "tools/list",
                        "params": params,
                    })
                except Exception as exc:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": f"Upstream MCP tools/list forwarding error: {exc}",
                        },
                    }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "read_doc",
                            "description": "Reads incoming documents and files with automatic taint tracking.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"file_path": {"type": "string"}},
                                "required": ["file_path"]
                            }
                        },
                        {
                            "name": "db_query",
                            "description": "Executes relational database queries under AST inspection.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}},
                                "required": ["query"]
                            }
                        },
                        {
                            "name": "send_email",
                            "description": "Sends emails to approved recipients with PII vault checks.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "to": {"type": "string"},
                                    "body": {"type": "string"}
                                },
                                "required": ["to", "body"]
                            }
                        },
                        {
                            "name": "external_api",
                            "description": "Invokes verified external APIs with SSRF protection.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"url": {"type": "string"}},
                                "required": ["url"]
                            }
                        }
                    ]
                }
            }

        # 2. tools/call handler (Security Interception)
        elif method == "tools/call":
            tool_name = params.get("name") or ""
            arguments = params.get("arguments") or {}
            context_sources = params.get("context_sources") or []

            # Map to SentinelMesh ToolCallRequest
            gateway_req = ToolCallRequest(
                agent_id=self.agent_id,
                session_id=active_sess,
                tool_name=tool_name,
                arguments=arguments,
                context_sources=context_sources,
                task_description=params.get("task_description")
            )

            # Evaluate inline via Gateway Core
            try:
                decision_resp: GatewayDecisionResponse = execute_tool_call(gateway_req)
            except Exception as e:
                # FAIL-CLOSED: Any exception in the gateway pipeline must halt tool execution
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"SECURITY BLOCK [FAIL-CLOSED]: SentinelMesh Gateway error ({type(e).__name__}: {e}). Tool execution blocked."
                            }
                        ],
                        "isError": True,
                        "meta": {
                            "decision": "block",
                            "fail_closed": True,
                            "error": str(e)
                        }
                    }
                }

            if decision_resp.decision == "allow":
                if self.upstream_url:
                    try:
                        upstream_resp = self._forward_to_upstream({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "method": "tools/call",
                            "params": {"name": tool_name, "arguments": arguments},
                        })
                        res_block = upstream_resp.get("result") or {}
                        res_block["meta"] = {
                            **(res_block.get("meta") or {}),
                            "decision": decision_resp.decision,
                            "trace_id": decision_resp.trace_id,
                            "latency_ms": decision_resp.latency_ms,
                            "event_hash": decision_resp.event_hash,
                            "upstream": "upstream_proxy",
                        }
                        return {"jsonrpc": "2.0", "id": req_id, "result": res_block}
                    except Exception as exc:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"SECURITY BLOCK [FAIL-CLOSED]: Upstream MCP server error ({type(exc).__name__}: {exc}).",
                                    }
                                ],
                                "isError": True,
                                "meta": {
                                    "decision": "block",
                                    "fail_closed": True,
                                    "upstream": "upstream_proxy",
                                    "error": str(exc),
                                },
                            },
                        }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Tool '{tool_name}' executed successfully under SentinelMesh security policy."
                            }
                        ],
                        "isError": False,
                        "meta": {
                            "decision": decision_resp.decision,
                            "trace_id": decision_resp.trace_id,
                            "latency_ms": decision_resp.latency_ms,
                            "event_hash": decision_resp.event_hash,
                            "upstream": "local_mock",
                        }
                    }
                }
            elif decision_resp.decision in ("block", "would_block"):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"SECURITY BLOCK: SentinelMesh halted action '{tool_name}': {decision_resp.reason}"
                            }
                        ],
                        "isError": True,
                        "meta": {
                            "decision": decision_resp.decision,
                            "risk_score": decision_resp.risk_score,
                            "trace_id": decision_resp.trace_id,
                            "event_hash": decision_resp.event_hash
                        }
                    }
                }
            elif decision_resp.decision == "require_approval":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"AUTHORIZATION REQUIRED: Action '{tool_name}' requires human approval ({decision_resp.reason}). Approval ID: {decision_resp.approval_id}"
                            }
                        ],
                        "isError": True,
                        "meta": {
                            "decision": decision_resp.decision,
                            "approval_id": decision_resp.approval_id,
                            "trace_id": decision_resp.trace_id
                        }
                    }
                }
            else:
                # Redact
                if self.upstream_url:
                    try:
                        upstream_resp = self._forward_to_upstream({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": decision_resp.redacted_arguments or arguments,
                            },
                        })
                        res_block = upstream_resp.get("result") or {}
                        res_block["meta"] = {
                            **(res_block.get("meta") or {}),
                            "decision": "redact",
                            "redacted_arguments": decision_resp.redacted_arguments,
                            "upstream": "upstream_proxy",
                        }
                        return {"jsonrpc": "2.0", "id": req_id, "result": res_block}
                    except Exception as exc:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"SECURITY BLOCK [FAIL-CLOSED]: Upstream MCP server error ({type(exc).__name__}: {exc}).",
                                    }
                                ],
                                "isError": True,
                                "meta": {
                                    "decision": "block",
                                    "fail_closed": True,
                                    "upstream": "upstream_proxy",
                                    "error": str(exc),
                                },
                            },
                        }
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Tool '{tool_name}' executed with vaulted/redacted parameters."
                            }
                        ],
                        "isError": False,
                        "meta": {
                            "decision": "redact",
                            "redacted_arguments": decision_resp.redacted_arguments,
                            "upstream": "local_mock",
                        }
                    }
                }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not implemented by SentinelMesh MCP Gateway."
            }
        }

from fastapi import APIRouter, Request

router = APIRouter(prefix="/mcp", tags=["Model Context Protocol"])

@router.get("/status")
def mcp_proxy_status():
    """Returns MCP gateway proxy configuration and fail-closed operational status."""
    upstream = (os.getenv("SENTINEL_MCP_UPSTREAM_URL") or "").strip()
    return {
        "protocol_version": "2024-11-05",
        "transport": "JSON-RPC 2.0 (HTTP + stdio)",
        "mode": "upstream_proxy" if upstream else "local_mock",
        "upstream_configured": bool(upstream),
        "fail_closed": True,
    }

@router.post("")
@router.post("/")
async def mcp_jsonrpc_endpoint(request: Request):
    """
    Standard MCP JSON-RPC 2.0 HTTP transport endpoint.
    Transparently intercepts AI agent tool calls.
    """
    body = await request.json()
    proxy = MCPGatewayProxy()
    return proxy.handle_mcp_request(body)

