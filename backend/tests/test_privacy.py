import pytest
import sqlite3
from backend.app.privacy.detectors import (
    CompositePiiDetector,
    EmailDetector,
    PhoneDetector,
    NationalIdDetector,
    CreditCardDetector,
    IbanDetector,
    ApiKeyDetector,
    SalaryDetector,
    PersonNameDetector,
    PiiFinding,
    luhn_checksum
)
from backend.app.privacy.vault import PrivacyVault
from backend.app.privacy.masker import PrivacyEngine
from backend.app.core.policy_engine import PolicyEngine
from demo_agents.gateway_client import GatewayClient, ToolBlockedError
from demo_agents.tools import send_email

def test_pii_detectors_precision_and_recall():
    """
    Evaluates detector precision and recall on a synthetic labelled dataset.
    Covers emails, phone numbers, fake national IDs, credit cards (Luhn),
    IBANs, API keys, salary amounts, and person names.
    """
    detector = CompositePiiDetector()

    # Synthetic test corpus: (text, expected_types)
    test_cases = [
        ("Contact recruiter at john.doe@partner.org for interview", ["EMAIL"]),
        ("Call mobile line at +1 (555) 234-5678 immediately", ["PHONE"]),
        ("Candidate national identifier is 000-12-3456 verified", ["NATIONAL_ID"]),
        # 4532 0150 0000 0007 is a valid test Visa number passing Luhn
        ("Charge corporate visa 4532 0150 0000 0007 for flight", ["CREDIT_CARD"]),
        # GB82 WEST 1234 5698 7654 32 is a valid test IBAN passing Mod97
        ("Wire funds to GB82WEST12345698765432 via treasury", ["IBAN"]),
        ("Found AWS key AKIAIOSFODNN7EXAMPLE in debug logs", ["API_KEY"]),
        ("Target compensation package is $185,000 base pay", ["SALARY"]),
        ("Applicant Alice Verma submitted references", ["PERSON_NAME"]),
        ("No sensitive personal information in this general sentence.", [])
    ]

    tp = 0
    fp = 0
    fn = 0

    for text, expected in test_cases:
        findings = detector.detect(text)
        detected_types = [f.pii_type for f in findings]

        for exp in expected:
            if exp in detected_types:
                tp += 1
            else:
                fn += 1

        for det in detected_types:
            if det not in expected:
                fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    assert precision >= 0.90, f"Precision was {precision:.2f}"
    assert recall >= 0.90, f"Recall was {recall:.2f}"

def test_credit_card_luhn_rejection():
    """Invalid credit cards failing the Luhn algorithm must not be tagged."""
    detector = CreditCardDetector()
    # 4532 0150 0000 0009 fails Luhn
    findings = detector.detect("Card 4532 0150 0000 0009")
    assert len(findings) == 0

def test_session_consistent_tokenization(test_db):
    """
    Session-consistent tokenization:
    - Same value within a session resolves to the identical token.
    - Multiple distinct values of the same type get sequential tokens [TYPE_1], [TYPE_2].
    - Different sessions get independent scopes.
    """
    session_1 = "sess-token-consist-1"
    session_2 = "sess-token-consist-2"

    t1_a = PrivacyVault.get_or_create_token(session_1, "EMAIL", "alice@company.com")
    t1_b = PrivacyVault.get_or_create_token(session_1, "EMAIL", "alice@company.com")
    assert t1_a == t1_b == "[EMAIL_1]"

    t2 = PrivacyVault.get_or_create_token(session_1, "EMAIL", "bob@company.com")
    assert t2 == "[EMAIL_2]"

    # Distinct session gets independent sequential numbering
    t_other = PrivacyVault.get_or_create_token(session_2, "EMAIL", "alice@company.com")
    assert t_other == "[EMAIL_1]"

def test_zero_raw_pii_in_audit_database(client, test_db):
    """
    DB Scan Requirement:
    Verify that raw sensitive PII (SSNs, salaries, API keys) is NEVER stored
    in the audit_events or incidents tables. Only masked tokens must exist.
    """
    PolicyEngine.set_mode("enforce")
    session_id = "sess-zero-pii-scan"

    raw_ssn = "000-88-9999"
    raw_salary = "$192,000"
    raw_key = "AKIAIOSFODNN7EXAMPLE"

    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="hr-agent",
        session_id=session_id,
        http_client=client
    )

    # Ingest document containing sensitive PII
    agent_client.intercept_and_execute(
        tool_name="read_doc",
        arguments={"file_path": "confidential_offer.txt", "notes": f"SSN: {raw_ssn}, Salary: {raw_salary}"},
        tool_func=lambda **kwargs: "ok",
        context_sources=[{
            "source_id": "confidential_offer.txt",
            "source_type": "document",
            "snippet": f"Secret key {raw_key} for {raw_ssn} at {raw_salary}"
        }]
    )

    # Directly scan the SQLite database at rest
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()

    # Scan audit_events table
    cursor.execute("SELECT arguments, context_sources, reason FROM audit_events WHERE session_id = ?", (session_id,))
    rows = cursor.fetchall()
    assert len(rows) >= 1

    for row in rows:
        combined_text = " ".join([str(col) for col in row])
        assert raw_ssn not in combined_text, "Found raw SSN in audit_events!"
        assert raw_salary not in combined_text, "Found raw salary in audit_events!"
        assert raw_key not in combined_text, "Found raw API key in audit_events!"
        assert "[NATIONAL_ID_1]" in combined_text
        assert "[SALARY_1]" in combined_text

    # Scan incidents table
    cursor.execute("SELECT * FROM incidents WHERE session_id = ?", (session_id,))
    inc_rows = cursor.fetchall()
    for row in inc_rows:
        combined_text = " ".join([str(col) for col in row])
        assert raw_ssn not in combined_text, "Found raw SSN in incidents!"
        assert raw_salary not in combined_text, "Found raw salary in incidents!"
        assert raw_key not in combined_text, "Found raw API key in incidents!"

    conn.close()

def test_role_gated_raw_access_endpoint(client, test_db):
    """
    Role-gated raw PII retrieval:
    - Roles 'viewer' and 'analyst' receive 403 Forbidden.
    - Requests without justification receive 400 Bad Request.
    - Role 'privacy_officer' with justification receives 200 OK with unmasked data.
    - Access creates an immutable audit event in the hash chain.
    """
    session_id = "sess-role-gated"
    tok = PrivacyVault.get_or_create_token(session_id, "EMAIL", "executive@company.com")

    # 1. Viewer role rejected
    res_viewer = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Just checking data"},
        headers={"X-Sentinel-Role": "viewer", "X-Sentinel-User": "viewer_bob"}
    )
    assert res_viewer.status_code == 403
    assert "Forbidden" in res_viewer.json()["detail"]

    # 2. Analyst role rejected
    res_analyst = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Investigating incident #102"},
        headers={"X-Sentinel-Role": "analyst", "X-Sentinel-User": "analyst_carol"}
    )
    assert res_analyst.status_code == 403

    # 3. Privacy officer without valid reason rejected
    res_no_reason = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "   "},
        headers={"X-Sentinel-Role": "privacy_officer", "X-Sentinel-User": "officer_dave"}
    )
    assert res_no_reason.status_code == 400

    # 4. Privacy officer with reason granted access
    res_officer = client.post(
        "/api/v1/privacy/raw-access",
        json={
            "session_id": session_id,
            "tokens": [tok],
            "masked_payload": {"recipient": tok, "msg": f"Hello {tok}"},
            "reason": "Authorized GDPR Article 15 Data Subject Request #DSAR-883"
        },
        headers={"X-Sentinel-Role": "privacy_officer", "X-Sentinel-User": "officer_dave"}
    )
    assert res_officer.status_code == 200
    data = res_officer.json()
    assert data["resolved"][tok] == "executive@company.com"
    assert data["unmasked_payload"]["recipient"] == "executive@company.com"
    assert data["unmasked_payload"]["msg"] == "Hello executive@company.com"
    assert data["role"] == "privacy_officer"
    assert data["access_id"].startswith("RAW-ACC-")

    # 5. Verify raw access was written to append-only audit log
    events_res = client.get("/api/v1/events?order=desc&limit=5")
    assert events_res.status_code == 200
    recent = events_res.json()
    access_ev = next(e for e in recent if e["tool_name"] == "privacy_raw_access")
    assert access_ev["session_id"] == session_id
    assert access_ev["arguments"]["user"] == "officer_dave"
    assert "DSAR-883" in access_ev["reason"]

def test_hash_chain_verification_integrity_with_unmasking(client, test_db):
    """
    Cryptographic verification passes before and after raw PII unmasking,
    proving that raw unmasking never alters or invalidates the hash chain.
    """
    # 1. Verify before
    res_before = client.get("/api/v1/audit/verify")
    assert res_before.status_code == 200
    assert res_before.json()["valid"] is True

    session_id = "sess-chain-verify-test"
    tok = PrivacyVault.get_or_create_token(session_id, "SALARY", "$175,000")

    # 2. Perform raw unmasking request
    client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Compliance verification audit"},
        headers={"X-Sentinel-Role": "privacy_officer", "X-Sentinel-User": "officer_alice"}
    )

    # 3. Verify after: Head hash updates, chain remains 100% valid
    res_after = client.get("/api/v1/audit/verify")
    assert res_after.status_code == 200
    data = res_after.json()
    assert data["valid"] is True
    assert data["events_verified"] >= res_before.json()["events_verified"] + 1

def test_policy_redact_hook(client, test_db):
    """
    Policy 'redact' hook:
    When sensitive PII is dispatched to an approved domain,
    the gateway returns 'redact', masks the outgoing arguments,
    and permits the tool to execute with the sanitized payload.
    """
    PolicyEngine.set_mode("enforce")
    old_action = PolicyEngine._high_sensitivity_external_action
    PolicyEngine.set_high_sensitivity_external_action("redact")
    session_id = "sess-policy-redact"

    captured_payload = {}

    def mock_email_sender(**kwargs):
        captured_payload.update(kwargs)
        return {"status": "sent"}

    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="finance-agent",
        session_id=session_id,
        http_client=client
    )

    # Send to approved vendor with sensitive salary details
    res = agent_client.intercept_and_execute(
        tool_name="send_email",
        arguments={
            "to": "vendor-finance@approved-vendor.com",
            "subject": "Compensation details",
            "body": "Employee compensation is $165,000 base pay"
        },
        tool_func=mock_email_sender,
        context_sources=[]
    )

    assert res == {"status": "sent"}
    # Verify the tool executed with redacted payload
    assert "$165,000" not in captured_payload["body"]
    assert "[SALARY_1]" in captured_payload["body"]
    PolicyEngine.set_high_sensitivity_external_action(old_action)

def test_privacy_risk_score_and_breakdown():
    """
    Verifies that PrivacyEngine produces standardized 0-100 scores
    and human-readable data class breakdowns.
    """
    findings = [
        PiiFinding(pii_type="EMAIL", start=0, end=10, value="a@b.com", confidence=0.98),
        PiiFinding(pii_type="EMAIL", start=15, end=25, value="c@d.com", confidence=0.98),
        PiiFinding(pii_type="SALARY", start=30, end=38, value="$185,000", confidence=0.92),
        PiiFinding(pii_type="NATIONAL_ID", start=40, end=51, value="000-11-2222", confidence=0.95),
    ]

    score, bd = PrivacyEngine.calculate_privacy_risk(findings, is_external=True, is_tainted=True)
    assert 50 <= score <= 100
    assert bd["counts"]["EMAIL"] == 2
    assert bd["counts"]["SALARY"] == 1
    assert bd["counts"]["NATIONAL_ID"] == 1
    assert "2 emails" in bd["summary"]
    assert "1 salary amount" in bd["summary"]
    assert "1 national ID" in bd["summary"]

def test_jwt_login_and_role_gating(client, test_db):
    """
    Tests JWT-based role authentication:
    1. /login issues signed JWT tokens for viewer, analyst, and privacy_officer.
    2. Invalid, forged, or expired tokens are rejected with 401 Unauthorized.
    3. Valid privacy_officer token allows raw access; viewer and analyst get 403.
    """
    from backend.app.api.auth import create_access_token
    from datetime import timedelta

    # 1. Login as viewer
    res_login_viewer = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "viewer123"})
    assert res_login_viewer.status_code == 200
    viewer_token = res_login_viewer.json()["access_token"]

    # 2. Login as privacy_officer
    res_login_officer = client.post("/api/v1/auth/login", json={"username": "privacy_officer", "password": "officer123"})
    assert res_login_officer.status_code == 200
    officer_token = res_login_officer.json()["access_token"]

    session_id = "sess-jwt-test"
    tok = PrivacyVault.get_or_create_token(session_id, "EMAIL", "ceo@company.com")

    # 3. Viewer token gets 403 Forbidden
    res_viewer = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Viewer inspection attempt"},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res_viewer.status_code == 403
    assert "Required role: 'privacy_officer'" in res_viewer.json()["detail"]

    # 4. Forged token gets 401 Unauthorized
    forged_token = viewer_token[:-8] + "ABCDEF12"
    res_forged = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Forged inspection attempt"},
        headers={"Authorization": f"Bearer {forged_token}"}
    )
    assert res_forged.status_code == 401
    assert "Invalid or forged" in res_forged.json()["detail"]

    # 5. Expired token gets 401 Unauthorized
    expired_token = create_access_token("privacy_officer", "privacy_officer", expires_delta=timedelta(seconds=-10))
    res_expired = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Expired token attempt"},
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert res_expired.status_code == 401
    assert "expired" in res_expired.json()["detail"].lower()

    # 6. Valid privacy_officer token gets 200 OK
    res_valid = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Authorized audit investigation"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res_valid.status_code == 200
    assert res_valid.json()["resolved"][tok] == "ceo@company.com"

def test_extended_raw_pii_scan_across_all_surfaces(client, test_db, monkeypatch):
    """
    Extends raw PII scanning to cover:
    - audit_events table
    - incidents table
    - WebSocket broadcast messages
    - Incident narrative summaries
    - Policy decision reason strings
    Asserts zero raw PII leaks across all surfaces.
    """
    from backend.app.api.websocket import ws_manager

    broadcasts = []
    monkeypatch.setattr(ws_manager, "broadcast_sync", lambda payload: broadcasts.append(payload))

    session_id = "sess-extended-scan"
    raw_salary = "$240,000"
    raw_ssn = "000-77-8888"
    raw_card = "4532 0150 0000 0007"

    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="hr-agent",
        session_id=session_id,
        http_client=client
    )

    # Ingest document containing PII
    agent_client.intercept_and_execute(
        tool_name="read_doc",
        arguments={"file_path": "executive_package.txt", "notes": f"Salary: {raw_salary}, Card: {raw_card}, SSN: {raw_ssn}"},
        tool_func=lambda **kwargs: "ok",
        context_sources=[{
            "source_id": "executive_package.txt",
            "source_type": "document",
            "snippet": f"Executive compensation package: {raw_salary}, SSN: {raw_ssn}"
        }]
    )

    # 1. Scan SQLite audit_events
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT arguments, context_sources, reason FROM audit_events WHERE session_id = ?", (session_id,))
    for row in cursor.fetchall():
        row_str = " ".join([str(col) for col in row])
        assert raw_salary not in row_str
        assert raw_ssn not in row_str
        assert raw_card not in row_str

    # 2. Scan SQLite incidents
    cursor.execute("SELECT summary, affected_data, chain_steps FROM incidents WHERE session_id = ?", (session_id,))
    for row in cursor.fetchall():
        row_str = " ".join([str(col) for col in row])
        assert raw_salary not in row_str
        assert raw_ssn not in row_str
        assert raw_card not in row_str

    conn.close()

    # 3. Scan WebSocket broadcast messages
    assert len(broadcasts) >= 1
    for b in broadcasts:
        b_str = str(b)
        assert raw_salary not in b_str, f"Found raw salary in WebSocket broadcast: {b_str}"
        assert raw_ssn not in b_str, f"Found raw SSN in WebSocket broadcast: {b_str}"
        assert raw_card not in b_str, f"Found raw card in WebSocket broadcast: {b_str}"

def test_high_sensitivity_external_egress_requires_approval(client, test_db):
    """
    When an untainted agent attempts to send high-sensitivity personal data
    (e.g. salary, credit card, national ID) to an external destination,
    the gateway returns 'require_approval' instead of an outright allow or block.
    """
    PolicyEngine.set_mode("enforce")
    PolicyEngine.set_high_sensitivity_external_action("require_approval")
    session_id = "sess-high-sens-approval"

    agent_client = GatewayClient(
        gateway_url="/api/v1/gateway/execute",
        agent_id="finance-agent",
        session_id=session_id,
        http_client=client
    )

    # Untainted session sending compensation to external recipient
    res = agent_client.intercept_and_execute(
        tool_name="send_email",
        arguments={
            "to": "partner-payroll@external-payroll-vendor.net",
            "subject": "Executive Compensation",
            "body": "Base salary is $195,000 per annum"
        },
        tool_func=lambda **kwargs: {"status": "sent"},
        context_sources=[]
    )

    assert res["status"] == "pending_human_approval"
    assert "requires human approval" in res["reason"].lower()

def test_vault_retention_expiration(client, test_db, monkeypatch):
    """
    Verifies that raw access for a session whose retention window has expired
    fails with HTTP 410 Gone and generates an audit event on the hash chain.
    """
    from datetime import datetime, timezone, timedelta
    from backend.app.api.auth import create_access_token

    officer_token = create_access_token("privacy_officer", "privacy_officer")
    session_id = "sess-retention-test"

    # Seed an expired vault record (created 40 days ago; retention is 30 days = 720h)
    tok = PrivacyVault.get_or_create_token(session_id, "SALARY", "$210,000")
    expired_time = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()

    conn = sqlite3.connect(test_db)
    conn.execute("UPDATE privacy_vault SET created_at = ? WHERE session_id = ?", (expired_time, session_id))
    conn.commit()
    conn.close()

    # Attempt raw retrieval with valid privacy officer credentials
    res = client.post(
        "/api/v1/privacy/raw-access",
        json={"session_id": session_id, "tokens": [tok], "reason": "Late audit request"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )

    assert res.status_code == 410
    assert "Retention Expired" in res.json()["detail"]

    # Verify that the expired access attempt was audited in audit_events
    events_res = client.get("/api/v1/events?order=desc&limit=5")
    assert events_res.status_code == 200
    expired_event = next(e for e in events_res.json() if e["session_id"] == session_id and e["decision"] == "block")
    assert "retention window" in expired_event["reason"].lower()

