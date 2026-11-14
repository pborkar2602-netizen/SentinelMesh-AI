#!/usr/bin/env python3
"""
backend/app/mcp/stdio_server.py

Standard MCP JSON-RPC 2.0 stdio server transport for SentinelMesh.
Reads newline-delimited JSON-RPC messages from stdin,
dispatches to MCPGatewayProxy, and writes responses to stdout.
"""

import sys
import json
import logging

from backend.app.mcp.proxy import MCPGatewayProxy

logging.basicConfig(level=logging.ERROR, stream=sys.stderr)

def main():
    proxy = MCPGatewayProxy(agent_id="mcp-agent", default_session_id="sess-mcp-stdio")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = proxy.handle_mcp_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_res = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"}
            }
            sys.stdout.write(json.dumps(err_res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
