import re
import email.utils
import urllib.parse
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class Finding:
    name: str
    severity: str  # "low", "medium", "high", "critical"
    evidence: str
    owasp_category: str

# Configurable Approved Email Domains (exact-or-dot-boundary matching)
APPROVED_EMAIL_DOMAINS = [
    "company.com",
    "approved-vendor.com",
    "verified-client.org",
    "internal.local",
    "sentinelmesh.internal",
    "vendor-corp.com"
]

# Configurable Approved External API Hosts & Domains
APPROVED_API_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "::1",
    "internal.local",
    "company.com",
    "vendor-corp.com",
    "approved-vendor.com",
    "verified-client.org",
    "api.github.com",
    "partner.org",
    "sentinelmesh.internal"
]

def extract_email_domain(email_str: str) -> Optional[str]:
    """
    Extracts the authoritative domain from an email address, defending against
    tricks like user@company.com@evil.io, leading/trailing spaces, trailing dots, etc.
    """
    if not email_str:
        return None
    _, addr = email.utils.parseaddr(email_str)
    addr = (addr or email_str).strip().rstrip('.')
    if "@" not in addr:
        return None
    domain = addr.split("@")[-1].lower().strip().rstrip('.')
    if not domain or "/" in domain or " " in domain or "\\" in domain:
        return None
    return domain

def extract_url_hostname(url_str: str) -> Optional[str]:
    """
    Extracts the authoritative parsed hostname from a URL, defending against
    userinfo spoofing (e.g. https://api.github.com@evil.io -> hostname is evil.io).
    """
    if not url_str:
        return None
    try:
        parsed = urllib.parse.urlsplit(url_str if "://" in url_str else f"http://{url_str}")
        host = (parsed.hostname or "").lower().strip().rstrip('.')
        return host if host else None
    except Exception:
        return None

def is_domain_or_subdomain(target_host: str, approved_domain: str) -> bool:
    """
    Exact-or-dot-boundary match.
    target_host='mail.company.com', approved='company.com' -> True
    target_host='company.com', approved='company.com' -> True
    target_host='evilcompany.com', approved='company.com' -> False
    target_host='company.com.evil.io', approved='company.com' -> False
    """
    if not target_host or not approved_domain:
        return False
    target = target_host.lower().strip().rstrip('.')
    approved = approved_domain.lower().strip().lstrip('@').rstrip('.')
    if target == approved:
        return True
    if target.endswith("." + approved):
        return True
    return False

def is_approved_email_domain(email_str: str) -> bool:
    if not email_str:
        return False
    if "@" in email_str:
        domain = extract_email_domain(email_str)
    else:
        domain = email_str.lower().strip().rstrip('.')
    if not domain:
        return False
    return any(is_domain_or_subdomain(domain, approved) for approved in APPROVED_EMAIL_DOMAINS)

def is_approved_api_host(url: str) -> bool:
    host = extract_url_hostname(url)
    if not host:
        return False
    if host in ["localhost", "127.0.0.1", "::1"]:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    return any(is_domain_or_subdomain(host, approved) for approved in APPROVED_API_DOMAINS)

def is_internal_destination(dest_str: str) -> bool:
    """Returns True if the destination (email or host/url) is internal to the organization."""
    if not dest_str:
        return False
    if "@" in dest_str:
        host = extract_email_domain(dest_str) or dest_str.split("@")[-1].lower().strip().rstrip('.')
    elif "://" in dest_str or "/" in dest_str:
        host = extract_url_hostname(dest_str)
    else:
        host = dest_str.lower().strip().rstrip('.')
    
    if not host:
        return False
    if host in ["localhost", "127.0.0.1", "::1"]:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    return any(is_domain_or_subdomain(host, approved) for approved in ["company.com", "internal.local", "sentinelmesh.internal"])

# SSRF Cloud Metadata IP/Hosts (Precompiled)
SSRF_TARGETS = [
    re.compile(r"169\.254\.169\.254", re.IGNORECASE),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"100\.100\.100\.200", re.IGNORECASE),
    re.compile(r"fd00:ec2::254", re.IGNORECASE)
]

# SQL Injection Patterns (Precompiled)
SQLI_PATTERNS = [
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"'\s*OR\s*['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE),
    re.compile(r";\s*DROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r";\s*DELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r";\s*TRUNCATE\s+TABLE\b", re.IGNORECASE)
]

# Path Traversal Patterns (Precompiled)
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"/etc/shadow", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"c:\\windows\\system32", re.IGNORECASE)
]

# Credential / Secret Patterns (Precompiled)
CREDENTIAL_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{25,}", re.IGNORECASE), "Bearer Token"),
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----", re.IGNORECASE), "Private Key Header"),
    (re.compile(r"(?:api[_-]?key|secret[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]", re.IGNORECASE), "API Secret Assignment")
]

# Overt Prompt Injection Patterns (Precompiled)
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+(?:instruction\s+)?override\s+(?:note|payload)", re.IGNORECASE),
    re.compile(r"system\s+prompt\s+override", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?prior\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+must\s+immediately\s+bypass\s+normal", re.IGNORECASE)
]

def check_unapproved_email_recipient(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    if tool_name == "send_email":
        recipient = arguments.get("to") or arguments.get("recipient") or ""
        recipient = str(recipient).strip()
        if recipient:
            if not is_approved_email_domain(recipient):
                findings.append(Finding(
                    name="unapproved_external_recipient",
                    severity="high",
                    evidence=f"Recipient '{recipient}' does not belong to approved domains ({', '.join(APPROVED_EMAIL_DOMAINS)})",
                    owasp_category="LLM02: Sensitive Info Disclosure"
                ))
    return findings

def check_ssrf_metadata(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    text_content = " ".join([str(v) for v in arguments.values()])
    for pat in SSRF_TARGETS:
        match = pat.search(text_content)
        if match:
            findings.append(Finding(
                name="ssrf_metadata_target",
                severity="critical",
                evidence=f"Arguments contain cloud metadata target: '{match.group(0)}'",
                owasp_category="LLM06: Excessive Agency"
            ))
    return findings

def check_sql_injection(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    # Only inspect db_query to avoid false positives on security docs or support ticket text
    if tool_name == "db_query":
        query_text = arguments.get("query") or arguments.get("sql") or ""
        for pat in SQLI_PATTERNS:
            match = pat.search(query_text)
            if match:
                findings.append(Finding(
                    name="sql_injection_pattern",
                    severity="high",
                    evidence=f"Database query matches SQL injection heuristic: '{match.group(0)}'",
                    owasp_category="LLM02: Sensitive Info Disclosure"
                ))
    return findings

def check_path_traversal(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    text_content = " ".join([str(v) for v in arguments.values()])
    for pat in PATH_TRAVERSAL_PATTERNS:
        match = pat.search(text_content)
        if match:
            findings.append(Finding(
                name="path_traversal",
                severity="high",
                evidence=f"Detected path traversal sequence: '{match.group(0)}'",
                owasp_category="LLM06: Excessive Agency"
            ))
    return findings

def check_credential_leak(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    text_content = " ".join([str(v) for v in arguments.values()])
    for pat, desc in CREDENTIAL_PATTERNS:
        match = pat.search(text_content)
        if match:
            findings.append(Finding(
                name="credential_leak",
                severity="critical",
                evidence=f"Found pattern for {desc} (value redacted)",
                owasp_category="LLM02: Sensitive Info Disclosure"
            ))
    return findings

def check_prompt_injection(context_sources: List[Any], arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    # Inspect arguments and context snippets
    text_snippets = []
    for ctx in context_sources:
        if isinstance(ctx, dict):
            text_snippets.append(ctx.get("snippet") or "")
        else:
            text_snippets.append(getattr(ctx, "snippet", "") or "")
    text_snippets.extend([str(v) for v in arguments.values()])

    combined_text = " ".join(text_snippets)
    for pat in PROMPT_INJECTION_PATTERNS:
        match = pat.search(combined_text)
        if match:
            findings.append(Finding(
                name="prompt_injection_phrase",
                severity="high",
                evidence=f"Identified overt instruction hijacking pattern: '{match.group(0)}'",
                owasp_category="LLM01: Prompt Injection"
            ))
    return findings

# Destructive Database DDL Patterns (Precompiled)
DESTRUCTIVE_DDL_PATTERNS = [
    re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW)\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+(?:TABLE)?\b", re.IGNORECASE),
    re.compile(r"\bALTER\s+TABLE\s+.+?\s+DROP\b", re.IGNORECASE)
]

# Privileged Administrative Operations Patterns
ADMIN_PRIVILEGED_PATTERNS = [
    re.compile(r"\bUPDATE\s+system_configs\b", re.IGNORECASE),
    re.compile(r"\bUPDATE\s+(?:users|permissions|roles|credentials|auth)\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\s+(?:system_configs|users|permissions|roles)\b", re.IGNORECASE),
    re.compile(r"\bINSERT\s+INTO\s+(?:system_configs|users|permissions|roles)\b", re.IGNORECASE),
]

def check_destructive_ddl(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    if tool_name == "db_query":
        query_text = str(arguments.get("query") or arguments.get("sql") or "")
        for pat in DESTRUCTIVE_DDL_PATTERNS:
            match = pat.search(query_text)
            if match:
                findings.append(Finding(
                    name="destructive_ddl_command",
                    severity="critical",
                    evidence=f"Database query contains destructive DDL operation: '{match.group(0)}'",
                    owasp_category="LLM06: Excessive Agency"
                ))
    return findings

def check_privileged_actions(tool_name: str, arguments: Dict[str, Any]) -> List[Finding]:
    findings = []
    if tool_name == "db_query":
        query_text = str(arguments.get("query") or arguments.get("sql") or "")
        for pat in ADMIN_PRIVILEGED_PATTERNS:
            match = pat.search(query_text)
            if match:
                findings.append(Finding(
                    name="privileged_administrative_action",
                    severity="critical",
                    evidence=f"Database query executes privileged administrative mutation: '{match.group(0)}'",
                    owasp_category="LLM06: Excessive Agency"
                ))
    return findings

def run_all_detectors(
    tool_name: str,
    arguments: Dict[str, Any],
    context_sources: List[Any]
) -> List[Finding]:
    """
    Executes all rule detectors sequentially. Simple and auditable line by line.
    """
    findings: List[Finding] = []
    findings.extend(check_unapproved_email_recipient(tool_name, arguments))
    findings.extend(check_ssrf_metadata(tool_name, arguments))
    findings.extend(check_sql_injection(tool_name, arguments))
    findings.extend(check_destructive_ddl(tool_name, arguments))
    findings.extend(check_privileged_actions(tool_name, arguments))
    findings.extend(check_path_traversal(tool_name, arguments))
    findings.extend(check_credential_leak(tool_name, arguments))
    findings.extend(check_prompt_injection(context_sources, arguments))
    return findings
