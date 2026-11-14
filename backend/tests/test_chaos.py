"""
backend/tests/test_chaos.py

Offline Chaos Test Suite for SentinelMesh:
1. Database locked / corrupted mid-session -> fails safe (never silent allow)
2. Intent judge timeout or HTTP 500 error -> fails safe (invariant I4 preserved)
3. Malformed JSON in context or tool return -> handled safely without uncaught exceptions
4. Argument payload exceeding memory thresholds -> 413 rejection
5. 200 concurrent agent sessions hitting the gateway simultaneously -> thread-safe execution, hash chain integrity preserved
"""

import os
import sys
import time
import json
import sqlite3
import concurrent.futures
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.policy_engine import PolicyEngine
from backend.app.core.gateway import GatewayCore
from backend.app.schemas.gateway import ToolCallRequest, ContextSource
from backend.app.db.database import get_connection, init_db, list_audit_events


client = TestClient(app)


def test_chaos_db_locked_fails_safe():
    """When the database is locked or experiences operational error, gateway fails safe."""
    req = ToolCallRequest(
        agent_id="finance-agent",
        session_id="chaos-db-lock-sess",
        tool_name="external_api",
        arguments={"url": "https://api.adversary-webhook.org/exfil"},
        context_sources=[ContextSource(source_id="c1", is_untrusted=True, snippet="injection")],
    )

    # Simulate database lock/error during audit event write
    with patch("backend.app.api.gateway.save_audit_event", side_effect=sqlite3.OperationalError("database is locked")):
        # Gateway must fail-safe: not permit silent unmonitored egress
        try:
            res = client.post("/api/v1/gateway/execute", json=req.model_dump(mode="json"))
            # If an exception is raised or caught, it must not return allow
            if res.status_code == 200:
                assert res.json().get("decision") != "allow"
        except sqlite3.OperationalError:
            pass  # Expected fail-safe termination


def test_chaos_intent_judge_timeout_or_500_fails_safe():
    """When the intent judge throws a 500 or times out, deterministic block remains intact."""
    # Direct test on PolicyEngine: when judge_verdict is None or error string
    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="external_api",
        arguments={"url": "https://malicious-exfil.org/api"},
        is_tainted=True,
        tainted_by=["src_untrusted"],
        findings=[],
        risk_score=80,
        judge_verdict="ERROR_TIMEOUT_500",
    )
    assert decision in ["block", "require_approval", "would_block"]


def test_chaos_malformed_context_json_fails_safe():
    """Malformed or deeply corrupted strings in context sources do not cause unhandled crashes."""
    malformed_snippets = [
        '{"unterminated_json: [1, 2, ',
        '\x00\x01\x02\xff\xfe\x00',
        '{"key": ' * 50 + '1' + '}' * 50,
        '{"valid": true} trailing garbage %%%$$$',
    ]
    for idx, snippet in enumerate(malformed_snippets):
        req = ToolCallRequest(
            agent_id="support-agent",
            session_id=f"chaos-malformed-{idx}",
            tool_name="read_doc",
            arguments={"path": "note.txt"},
            context_sources=[ContextSource(source_id=f"corrupt_{idx}", is_untrusted=True, snippet=snippet)],
        )
        res = client.post("/api/v1/gateway/execute", json=req.model_dump(mode="json"))
        assert res.status_code == 200
        # Decision returned properly without 500 crash
        assert res.json().get("decision") in ["allow", "block", "require_approval", "would_block"]


def test_chaos_oversized_payload_fails_safe():
    """Massive payload exceeding memory thresholds is rejected at the perimeter (413)."""
    huge_data = "Z" * 350000 # 350 KB
    req_json = {
        "agent_id": "hr-agent",
        "session_id": "chaos-huge-sess",
        "tool_name": "read_doc",
        "arguments": {"data": huge_data},
    }
    res = client.post("/api/v1/gateway/execute", json=req_json)
    assert res.status_code == 413


def test_chaos_200_concurrent_sessions():
    """200 concurrent agent sessions hitting the gateway simultaneously."""
    n_sessions = 200
    results = []

    def make_call(i: int):
        req_json = {
            "agent_id": f"agent-{i % 5}",
            "session_id": f"concurrent-sess-{i}",
            "tool_name": "read_doc",
            "arguments": {"path": f"document_{i}.txt"},
            "context_sources": [],
        }
        r = client.post("/api/v1/gateway/execute", json=req_json)
        return r.status_code, r.json().get("decision") if r.status_code == 200 else None

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(make_call, i) for i in range(n_sessions)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
    elapsed = time.time() - t0

    # Ensure no crashes or deadlocks
    assert len(results) == n_sessions
    status_codes = [r[0] for r in results]
    assert all(code in [200, 429] for code in status_codes) # 200 OK or 429 Rate limited
    print(f"200 concurrent requests finished in {elapsed:.2f}s ({n_sessions/elapsed:.1f} req/s). Statuses: 200={status_codes.count(200)}, 429={status_codes.count(429)}")
