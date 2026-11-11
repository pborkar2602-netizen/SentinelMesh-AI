import os
import re
import email.utils
import urllib.parse
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set, Tuple

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

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

# Configurable Privileged Database Tables (Overridable via SENTINEL_PRIVILEGED_TABLES)
DEFAULT_PRIVILEGED_TABLES = ["system_configs", "users", "permissions", "roles", "credentials", "auth"]

def get_privileged_tables() -> List[str]:
    raw = os.getenv("SENTINEL_PRIVILEGED_TABLES", "")
    if raw.strip():
        return [t.strip().lower() for t in raw.split(",") if t.strip()]
    return DEFAULT_PRIVILEGED_TABLES

def build_privileged_patterns() -> List[re.Pattern]:
    tables_pipe = "|".join(re.escape(t) for t in get_privileged_tables())
    return [
        re.compile(rf"\bUPDATE\s+(?:{tables_pipe})\b", re.IGNORECASE),
        re.compile(rf"\bDELETE\s+FROM\s+(?:{tables_pipe})\b", re.IGNORECASE),
        re.compile(rf"\bINSERT\s+INTO\s+(?:{tables_pipe})\b", re.IGNORECASE),
        re.compile(rf"\bDROP\s+TABLE\s+(?:{tables_pipe})\b", re.IGNORECASE),
        re.compile(rf"\bALTER\s+TABLE\s+(?:{tables_pipe})\b", re.IGNORECASE),
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
        for pat in build_privileged_patterns():
            match = pat.search(query_text)
            if match:
                findings.append(Finding(
                    name="privileged_administrative_action",
                    severity="critical",
                    evidence=f"Database query executes privileged administrative mutation on protected table: '{match.group(0)}'",
                    owasp_category="LLM06: Excessive Agency"
                ))
    return findings


_SENSITIVE_COL_SYNONYMS: Dict[str, Set[str]] = {
    "password_hash": {"password_hash", "password", "passwd", "passwd_hash", "pwd_hash"},
    "bank_account": {"bank_account", "account_number", "acct_number", "iban", "bank_acct"},
    "routing_number": {"routing_number", "bank_routing", "routing_no", "wire_routing", "aba_routing"},
    "permissions": {"permissions", "permission", "privileges", "privilege", "access_level"},
}


def is_sensitive_write_column(col_name: str, configured_columns: Optional[List[str]] = None) -> bool:
    """
    Determines whether `col_name` matches the configurable list of sensitive write columns
    (exact match, underscore token match, or configured synonym).
    Non-sensitive columns such as `address`, `shipping_address`, `city`, `postal_code` return False.
    """
    if not col_name:
        return False
    c = col_name.lower().strip().strip('"').strip("`").strip("[]")
    if not c:
        return False

    if configured_columns is None:
        from backend.app.config import settings
        configured_columns = getattr(
            settings,
            "SENSITIVE_WRITE_COLUMNS",
            [
                "email",
                "phone",
                "password_hash",
                "role",
                "permissions",
                "bank_account",
                "routing_number",
                "payee",
                "beneficiary",
            ],
        )

    c_tokens = set(c.split("_"))
    for sens in configured_columns:
        s = sens.lower().strip()
        if not s:
            continue
        if c == s or s in c_tokens or c.endswith("_" + s) or c.startswith(s + "_"):
            return True
        for syn in _SENSITIVE_COL_SYNONYMS.get(s, set()):
            if c == syn or syn in c_tokens or c.endswith("_" + syn) or c.startswith(syn + "_"):
                return True
    return False


def _extract_values_from_expr(expr: Optional[exp.Expression]) -> Tuple[List[str], bool]:
    """
    Extracts all literal values (and subquery table/column tokens) from a SQL value expression
    (handles direct literals, CASE expressions, function calls, and subqueries).
    Returns: (values_list, has_subquery)
    """
    if expr is None:
        return ([], False)
    vals: List[str] = []
    has_subq = expr.find(exp.Select) is not None

    for lit in expr.find_all(exp.Literal):
        if lit.this is not None:
            v = str(lit.this).strip()
            if v:
                vals.append(v)

    if has_subq:
        for tbl in expr.find_all(exp.Table):
            if tbl.name:
                vals.append(tbl.name.lower())
        for col in expr.find_all(exp.Column):
            if col.name:
                vals.append(col.name.lower())

    return (vals, has_subq)


def analyze_sql_sensitive_write(
    query: str,
    sensitive_columns: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Uses sqlglot to parse SQL DML statements (UPDATE, INSERT, UPSERT, DELETE, MERGE)
    and identify whether any sensitive columns are modified, along with their assigned values.
    """
    result: Dict[str, Any] = {
        "is_mutation": False,
        "statement_type": None,
        "modified_columns": [],
        "sensitive_modified_columns": [],
        "assigned_values_by_column": {},
        "all_sensitive_assigned_values": [],
        "has_subquery_value": False,
    }
    if not query or not query.strip():
        return result

    if sensitive_columns is None:
        from backend.app.config import settings
        sensitive_columns = getattr(
            settings,
            "SENSITIVE_WRITE_COLUMNS",
            [
                "email",
                "phone",
                "password_hash",
                "role",
                "permissions",
                "bank_account",
                "routing_number",
                "payee",
                "beneficiary",
            ],
        )

    statements: Optional[List[Optional[exp.Expression]]] = None
    for dialect in ("sqlite", "postgres", "mysql", None):
        try:
            parsed = sqlglot.parse(query.strip(), read=dialect, error_level=sqlglot.ErrorLevel.RAISE)
            statements = [s for s in parsed if s is not None]
            if statements:
                break
        except SqlglotError:
            continue
        except Exception:
            continue

    if not statements:
        return result

    modified_cols: List[str] = []
    sensitive_cols: List[str] = []
    assigned_by_col: Dict[str, List[str]] = {}
    has_subq_total = False

    def _record_col_assignment(col_raw: str, val_expr: Optional[exp.Expression]) -> None:
        nonlocal has_subq_total
        col_clean = col_raw.lower().strip().strip('"').strip("`").strip("[]")
        if not col_clean:
            return
        if col_clean not in modified_cols:
            modified_cols.append(col_clean)
        vals, has_subq = _extract_values_from_expr(val_expr)
        assigned_by_col.setdefault(col_clean, []).extend(vals)
        if is_sensitive_write_column(col_clean, sensitive_columns):
            if col_clean not in sensitive_cols:
                sensitive_cols.append(col_clean)
            if has_subq:
                has_subq_total = True

    for stmt in statements:
        if isinstance(stmt, exp.Update):
            result["is_mutation"] = True
            result["statement_type"] = result["statement_type"] or "UPDATE"
            for eq in stmt.expressions or []:
                if isinstance(eq, exp.EQ):
                    if isinstance(eq.this, exp.Column) and eq.this.name:
                        _record_col_assignment(eq.this.name, eq.expression)
                    else:
                        for c in eq.this.find_all(exp.Column):
                            if c.name:
                                _record_col_assignment(c.name, eq.expression)

        elif isinstance(stmt, exp.Insert):
            result["is_mutation"] = True
            conflict = stmt.args.get("conflict")
            is_replace = "replace" in (stmt.sql() or "")[:15].lower()
            result["statement_type"] = "UPSERT" if (conflict is not None or is_replace) else "INSERT"

            schema = stmt.this
            insert_cols: List[str] = []
            if isinstance(schema, exp.Schema):
                for col_expr in schema.expressions or []:
                    c_name = col_expr.name if hasattr(col_expr, "name") else str(col_expr)
                    if c_name:
                        insert_cols.append(c_name.lower().strip().strip('"').strip("`").strip("[]"))

            values_node = stmt.find(exp.Values)
            if values_node is not None and values_node.expressions:
                for tuple_expr in values_node.expressions:
                    row_exprs = tuple_expr.expressions if hasattr(tuple_expr, "expressions") else []
                    for idx, val_expr in enumerate(row_exprs):
                        if idx < len(insert_cols):
                            _record_col_assignment(insert_cols[idx], val_expr)

            # Check INSERT INTO ... SELECT ...
            select_node = stmt.args.get("expression")
            if isinstance(select_node, exp.Select):
                for idx, sel_expr in enumerate(select_node.expressions or []):
                    if idx < len(insert_cols):
                        _record_col_assignment(insert_cols[idx], sel_expr)
                        if is_sensitive_write_column(insert_cols[idx], sensitive_columns):
                            has_subq_total = True

            # Check ON CONFLICT DO UPDATE / ON DUPLICATE KEY UPDATE assignments
            if conflict is not None:
                for eq in conflict.find_all(exp.EQ):
                    if isinstance(eq.this, exp.Column) and eq.this.name:
                        c_clean = eq.this.name.lower().strip().strip('"').strip("`").strip("[]")
                        _record_col_assignment(c_clean, eq.expression)
                        # If RHS references EXCLUDED.<col> or VALUES(<col>), inherit inserted values
                        for ref_col in eq.expression.find_all(exp.Column):
                            ref_name = (ref_col.name or "").lower().strip()
                            if ref_name in assigned_by_col:
                                assigned_by_col.setdefault(c_clean, []).extend(assigned_by_col[ref_name])

        elif isinstance(stmt, exp.Delete):
            result["is_mutation"] = True
            result["statement_type"] = result["statement_type"] or "DELETE"
            where_node = stmt.args.get("where")
            # Inspect columns in WHERE / RETURNING and table name
            for col in stmt.find_all(exp.Column):
                if col.name and is_sensitive_write_column(col.name, sensitive_columns):
                    _record_col_assignment(col.name, where_node)
            for tbl in stmt.find_all(exp.Table):
                if tbl.name:
                    t_clean = tbl.name.lower().strip()
                    for s in sensitive_columns:
                        if s in t_clean or t_clean.rstrip("s") == s.rstrip("s"):
                            _record_col_assignment(s, where_node)

        elif isinstance(stmt, exp.Merge):
            result["is_mutation"] = True
            result["statement_type"] = result["statement_type"] or "MERGE"
            for eq in stmt.find_all(exp.EQ):
                if isinstance(eq.this, exp.Column) and eq.this.name:
                    _record_col_assignment(eq.this.name, eq.expression)

    all_sens_vals: List[str] = []
    for c in sensitive_cols:
        for v in assigned_by_col.get(c, []):
            if v not in all_sens_vals:
                all_sens_vals.append(v)

    result["modified_columns"] = modified_cols
    result["sensitive_modified_columns"] = sensitive_cols
    result["assigned_values_by_column"] = assigned_by_col
    result["all_sensitive_assigned_values"] = all_sens_vals
    result["has_subquery_value"] = has_subq_total
    return result


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
