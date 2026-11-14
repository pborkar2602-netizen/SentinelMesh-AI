"""
backend/tests/test_fuzzing.py

Hypothesis fuzz test suite targeting:
1. SQL Parser & Sensitive Write Analyzer (arbitrary unicode, malformed queries, deep nesting)
2. Domain Matcher (Punycode, Cyrillic lookalikes, malformed URLs, port injections)
3. Approval Token Verifier (malformed payloads, bit-flipped tokens, binary junk)
"""

import pytest
from hypothesis import given, settings, strategies as st
from backend.app.detection.rules import (
    analyze_sql_sensitive_write,
    is_approved_api_host,
    is_approved_email_domain,
    extract_url_hostname,
    run_all_detectors,
)
from backend.app.approvals.tokens import verify_and_consume_approval_token, ApprovalTokenError


# =====================================================================
# 1. SQL Parser Fuzzing
# =====================================================================

@settings(max_examples=100, deadline=1000)
@given(
    fuzz_query=st.text(min_size=0, max_size=500),
)
def test_fuzz_sql_parser_robustness(fuzz_query):
    """SQL parser must never crash or raise unhandled exceptions on arbitrary strings."""
    try:
        res = analyze_sql_sensitive_write(fuzz_query)
        assert isinstance(res, dict)
        assert "is_mutation" in res
        assert "modified_columns" in res
    except Exception as e:
        pytest.fail(f"Unhandled exception in analyze_sql_sensitive_write: {e}")


@settings(max_examples=50, deadline=1000)
@given(
    depth=st.integers(min_value=1, max_value=30),
    col=st.text(alphabet=st.characters(whitelist_categories=("Lu", "Ll")), min_size=1, max_size=10),
)
def test_fuzz_sql_nested_parens_and_quotes(depth, col):
    """Deeply nested parentheses and quotes do not trigger stack overflow or ReDoS."""
    nested = ("(" * depth) + f"SELECT {col} FROM t" + (")" * depth)
    res = analyze_sql_sensitive_write(nested)
    assert isinstance(res, dict)


# =====================================================================
# 2. Domain Matcher Fuzzing (Punycode, Lookalikes, Malformed URLs)
# =====================================================================

@settings(max_examples=100, deadline=1000)
@given(
    fuzz_url=st.text(min_size=0, max_size=300),
)
def test_fuzz_extract_url_hostname_never_crashes(fuzz_url):
    """URL hostname extraction must handle arbitrary strings without unhandled exceptions."""
    try:
        host = extract_url_hostname(fuzz_url)
        assert host is None or isinstance(host, str)
    except Exception as e:
        pytest.fail(f"Unhandled exception in extract_url_hostname: {e}")


@settings(max_examples=50, deadline=1000)
@given(
    lookalike_char=st.sampled_from(["\u0430", "\u043e", "\u0441", "\u0435", "\u0440"]), # Cyrillic a, o, c, e, p
    path=st.text(alphabet=st.characters(whitelist_categories=("Ll", "Nd")), max_size=20),
)
def test_fuzz_homoglyph_lookalike_rejection(lookalike_char, path):
    """Homoglyph lookalike domains (e.g. Cyrillic 'a' in company.com) must never match allowlist."""
    spoofed_domain = f"comp{lookalike_char}ny.com"
    url = f"https://{spoofed_domain}/{path}"
    assert is_approved_api_host(url) is False


@settings(max_examples=50, deadline=1000)
@given(
    puny_domain=st.from_regex(r"xn--[a-z0-9]{4,15}\.com", fullmatch=True),
)
def test_fuzz_punycode_never_matches_ascii_approved_hosts(puny_domain):
    """Punycode domains must never match ASCII approved domains."""
    url = f"https://{puny_domain}/api"
    assert is_approved_api_host(url) is False


@settings(max_examples=50, deadline=1000)
@given(
    fuzz_email=st.text(min_size=0, max_size=200),
)
def test_fuzz_email_domain_matcher(fuzz_email):
    """Email domain validation must never crash on malformed input."""
    try:
        res = is_approved_email_domain(fuzz_email)
        assert isinstance(res, bool)
    except Exception as e:
        pytest.fail(f"Unhandled exception in is_approved_email_domain: {e}")


# =====================================================================
# 3. Approval Token Verifier Fuzzing
# =====================================================================

@settings(max_examples=100, deadline=1000)
@given(
    fuzz_token=st.text(min_size=0, max_size=400),
    tool=st.text(min_size=0, max_size=20),
)
def test_fuzz_approval_token_verifier(fuzz_token, tool):
    """Approval token verifier must gracefully reject malformed tokens with ApprovalTokenError."""
    with pytest.raises(ApprovalTokenError):
        verify_and_consume_approval_token(
            token_str=fuzz_token,
            tool_name=tool,
            arguments={},
            trace_id="fuzz-trace",
        )
