import pytest
from backend.app.detection.rules import (
    extract_email_domain,
    extract_url_hostname,
    is_domain_or_subdomain,
    is_approved_email_domain,
    is_approved_api_host,
    check_unapproved_email_recipient
)

DOMAIN_TEST_CASES = [
    # Lookalike & attack test cases: (input, is_email, expected_approved, description)
    ("company.com.evil.io", False, False, "Subdomain spoof suffix attacking company.com"),
    ("evilcompany.com", False, False, "Prefix lookalike domain evilcompany.com"),
    ("user@company.com.evil.io", True, False, "Email lookalike suffix evil.io"),
    ("user@evilcompany.com", True, False, "Email prefix lookalike evilcompany.com"),
    ("user@company.com@evil.io", True, False, "Dual @ userinfo bypass attempt"),
    ("https://api.github.com@evil.io", False, False, "URL userinfo spoofing (host is evil.io)"),
    ("https://api.github.com@evil.io/path", False, False, "URL userinfo spoof with path"),
    ("https://api.github.com.attacker.com", False, False, "Subdomain spoof of api.github.com"),
    ("user@COMPANY.COM", True, True, "Uppercase approved domain"),
    ("user@company.com.", True, True, "Trailing FQDN dot in email"),
    ("https://company.com./api", False, True, "Trailing FQDN dot in URL"),
    ("https://mail.company.com/v1", False, True, "Legitimate approved subdomain"),
    ("support@mail.company.com", True, True, "Legitimate email on approved subdomain"),
    ("http://service.internal.local:8080", False, True, "Internal .local host"),
    ("audit@sentinelmesh.internal", True, True, "Internal .internal email"),
    ("https://api.github.com/repos", False, True, "Whitelisted partner host"),
    ("invoices@vendor-corp.com", True, True, "Approved vendor domain"),
    ("invoices@notvendor-corp.com", True, False, "Prefix lookalike notvendor-corp.com"),
    ("invoices@vendor-corp.com.phishing.net", True, False, "Suffix lookalike vendor-corp.com.phishing.net"),
]

@pytest.mark.parametrize("target,is_email,expected,desc", DOMAIN_TEST_CASES)
def test_domain_matcher_lookalike_cases(target, is_email, expected, desc):
    if is_email:
        result = is_approved_email_domain(target)
        assert result == expected, f"Failed on [{desc}]: expected {expected} for {target}"
    else:
        result = is_approved_api_host(target)
        assert result == expected, f"Failed on [{desc}]: expected {expected} for {target}"

def test_check_unapproved_email_recipient_tricky_cases():
    # Attack with lookalike domain must produce a finding
    f_lookalike = check_unapproved_email_recipient("send_email", {"to": "user@evilcompany.com"})
    assert len(f_lookalike) == 1
    assert f_lookalike[0].name == "unapproved_external_recipient"

    # Userinfo trick user@company.com@evil.io must produce a finding
    f_userinfo = check_unapproved_email_recipient("send_email", {"to": "user@company.com@evil.io"})
    assert len(f_userinfo) == 1
    assert f_userinfo[0].name == "unapproved_external_recipient"

    # Legitimate uppercase subdomains must pass cleanly
    f_clean = check_unapproved_email_recipient("send_email", {"to": "ALICE@HR.COMPANY.COM"})
    assert len(f_clean) == 0
