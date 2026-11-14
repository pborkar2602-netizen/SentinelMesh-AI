#!/usr/bin/env python3
"""
tests/test_official_mcp_client.py

Tests SentinelMesh's MCP Gateway Proxy using the official Python MCP SDK client session:
1. Connects to stdio server proxy via mcp.client.stdio.stdio_client.
2. Performs session.initialize() protocol handshake.
3. Performs session.list_tools() to retrieve tools.
4. Performs session.call_tool() on a benign tool (read_doc) -> verifies success.
5. Performs session.call_tool() on a dangerous tool (db_query DROP TABLE) -> verifies security block.
"""

import sys
import os
from pathlib import Path
import pytest
import anyio

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

async def run_mcp_client_test():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "backend.app.mcp.stdio_server"],
        env={**os.environ, "PYTHONPATH": str(ROOT_DIR), "DEMO_MODE": "true"},
    )

    print("\n--- Connecting to SentinelMesh MCP Proxy via Official MCP SDK Client ---")
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. Initialize
            print("1. Executing session.initialize()...")
            init_res = await session.initialize()
            print(f"   [SUCCESS] Initialized: protocolVersion={init_res.protocol_version}, server={init_res.server_info.name} v{init_res.server_info.version}")
            assert init_res.protocol_version is not None
            assert "SentinelMesh" in init_res.server_info.name

            # 2. tools/list
            print("2. Executing session.list_tools()...")
            tools_res = await session.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            print(f"   [SUCCESS] Tools retrieved ({len(tool_names)}): {tool_names}")
            assert "read_doc" in tool_names
            assert "db_query" in tool_names
            assert "send_email" in tool_names

            # 3. tools/call (Benign Action)
            print("3. Executing session.call_tool('read_doc') [Benign]...")
            benign_res = await session.call_tool("read_doc", {"file_path": "report.pdf"})
            content_text = benign_res.content[0].text if benign_res.content else ""
            print(f"   [SUCCESS] Benign call result: isError={benign_res.is_error}, text='{content_text[:60]}...'")
            assert benign_res.is_error is False or benign_res.is_error is None

            # 4. tools/call (Destructive DDL Action -> Expected Block)
            print("4. Executing session.call_tool('db_query', query='DROP TABLE users') [Attack -> Block]...")
            block_res = await session.call_tool("db_query", {"query": "DROP TABLE users"})
            block_text = block_res.content[0].text if block_res.content else ""
            print(f"   [SUCCESS] Attack call intercepted: isError={block_res.is_error}, text='{block_text[:70]}...'")
            assert block_res.is_error is True
            assert "SECURITY BLOCK" in block_text or "AUTHORIZATION REQUIRED" in block_text

    print("--- Official MCP SDK Client Integration Test: 100% PASSED ---\n")

def test_mcp_official_sdk():
    anyio.run(run_mcp_client_test)

if __name__ == "__main__":
    test_mcp_official_sdk()
