"""
SentinelMesh v3: Model Context Protocol (MCP) Standard Proxy Layer
Transparently intercepts MCP JSON-RPC 2.0 tool calls (tools/call, tools/list)
and evaluates them against the 6-layer defense pipeline before forwarding to backend MCP servers.

Specifications:
- MCP Protocol Version: 2024-11-05
- JSON-RPC: 2.0
"""

import json
import logging
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
    """

    def __init__(self, agent_id: str = "mcp-agent", default_session_id: str = "sess-mcp-default"):
        self.agent_id = agent_id
        self.default_session_id = default_session_id

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
                            "event_hash": decision_resp.event_hash
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
                            "redacted_arguments": decision_resp.redacted_arguments
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

