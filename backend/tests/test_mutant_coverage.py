import pytest
from backend.app.core.policy_engine import PolicyEngine
from backend.app.detection.rules import (
    Finding,
    is_approved_api_host,
    is_internal_destination,
    analyze_untasked_sensitive_read,
    is_approved_email_domain,
)

class DummyJudgeVerdict:
    def __init__(self, is_aligned: bool, mismatch_score: int, reasoning: str = ""):
        self.is_aligned = is_aligned
        self.mismatch_score = mismatch_score
        self.reasoning = reasoning

def test_enforce_vs_monitor_unapproved_recipient_untainted():
    """Mutant 14: Verifies enforce vs monitor on untainted unapproved recipient."""
    f_unapproved = [Finding("unapproved_external_recipient", "high", "attacker@unapproved.org", 35)]
    
    PolicyEngine.set_mode("enforce")
    dec_enf, reason_enf = PolicyEngine.evaluate_policy(
        tool_name="send_email",
        arguments={"to": "attacker@unapproved.org", "body": "routine memo"},
        is_tainted=False,
        tainted_by=[],
        findings=f_unapproved,
        risk_score=35,
    )
    assert dec_enf == "block", f"Enforce mode must block unapproved recipient, got {dec_enf}"
    assert "blocked" in reason_enf.lower()

    PolicyEngine.set_mode("monitor")
    dec_mon, reason_mon = PolicyEngine.evaluate_policy(
        tool_name="send_email",
        arguments={"to": "attacker@unapproved.org", "body": "routine memo"},
        is_tainted=False,
        tainted_by=[],
        findings=f_unapproved,
        risk_score=35,
    )
    assert dec_mon == "would_block", f"Monitor mode must would_block unapproved recipient, got {dec_mon}"
    assert "would have blocked" in reason_mon.lower() or "monitor mode" in reason_mon.lower()
    
    # Reset
    PolicyEngine.set_mode("enforce")

def test_enforce_vs_monitor_intent_judge_mismatch():
    """Mutant 20: Verifies enforce vs monitor on high intent judge mismatch."""
    verdict = DummyJudgeVerdict(is_aligned=False, mismatch_score=85, reasoning="Query diverges from task.")
    
    PolicyEngine.set_mode("enforce")
    dec_enf, reason_enf = PolicyEngine.evaluate_policy(
        tool_name="db_query",
        arguments={"query": "SELECT id, name FROM non_sensitive_table"},
        is_tainted=False,
        tainted_by=[],
        findings=[],
        risk_score=20,
        judge_verdict=verdict,
    )
    assert dec_enf == "require_approval", f"Enforce mode must require_approval on mismatch >= 70, got {dec_enf}"

    PolicyEngine.set_mode("monitor")
    dec_mon, reason_mon = PolicyEngine.evaluate_policy(
        tool_name="db_query",
        arguments={"query": "SELECT id, name FROM non_sensitive_table"},
        is_tainted=False,
        tainted_by=[],
        findings=[],
        risk_score=20,
        judge_verdict=verdict,
    )
    assert dec_mon == "would_block", f"Monitor mode must would_block on mismatch >= 70, got {dec_mon}"
    
    PolicyEngine.set_mode("enforce")

def test_local_internal_domain_rules():
    """Mutant 28 & domain boundaries: Verifies .local and .internal host validation and rejects hostile suffix variants."""
    # Direct .local and .internal domains
    assert is_approved_api_host("http://service.local/api") is True
    assert is_approved_api_host("http://infra.internal/health") is True
    assert is_approved_api_host("https://sub.cluster.internal/v1") is True
    assert is_approved_api_host("http://node.corp.local:8080/data") is True
    assert is_approved_api_host("http://localhost:8000") is True
    assert is_approved_api_host("http://127.0.0.1:8000") is True

    # Hostile variations: must be REJECTED (False)
    assert is_approved_api_host("http://evil.internal.example.com/api") is False
    assert is_approved_api_host("http://evil.local.attacker.com/api") is False
    assert is_approved_api_host("https://internal.example.com/api") is False
    assert is_approved_api_host("https://local.untrusted.org/leak") is False
    assert is_approved_api_host("https://evil-internal.com/data") is False
    assert is_approved_api_host("https://attacker.com/path?target=node.internal") is False

    # is_internal_destination behavior
    assert is_internal_destination("http://service.local/api") is True
    assert is_internal_destination("http://infra.internal/health") is True
    assert is_internal_destination("http://evil.internal.example.com/api") is False
    assert is_internal_destination("http://evil.local.attacker.com/api") is False
    assert is_internal_destination("attacker@evil.internal.example.com") is False

def test_column_level_sensitive_read_matching():
    """Mutant 38: Verifies column-level matching in untasked sensitive read when table is not sensitive."""
    res = analyze_untasked_sensitive_read(
        tool_name="db_query",
        arguments={"query": "SELECT salary, bonus FROM public_general_ledger"},
        task_description="Check public general ledger inventory",
    )
    assert res["has_untasked_sensitive_read"] is True
    all_targets = [item for sublist in res["matched_targets"].values() for item in sublist]
    assert any("column:salary" in t for t in all_targets), f"Expected column:salary in matched targets, got {all_targets}"

    # Non-sensitive query must NOT match (kills inverted column guard)
    clean_res = analyze_untasked_sensitive_read(
        tool_name="db_query",
        arguments={"query": "SELECT order_id, product_name FROM store_inventory"},
        task_description="Check store inventory",
    )
    assert clean_res["has_untasked_sensitive_read"] is False
