from typing import List, Dict, Any, Tuple
from backend.app.detection.rules import Finding

def compute_risk_score(
    is_tainted: bool,
    findings: List[Finding],
    tool_name: str,
    arguments: Dict[str, Any]
) -> Tuple[int, Dict[str, int]]:
    """
    Computes composite risk score (0-100) with clear signal attribution breakdown.
    """
    breakdown = {
        "untrusted_taint": 0,
        "rule_findings": 0,
        "external_destination": 0,
        "sensitive_data": 0
    }

    # Signal 1: Untrusted taint in context
    if is_tainted:
        breakdown["untrusted_taint"] = 38

    # Signal 2: Rule findings
    finding_points = 0
    for f in findings:
        if f.severity == "critical":
            finding_points += 50
        elif f.severity == "high":
            finding_points += 35
        elif f.severity == "medium":
            finding_points += 20
        else:
            finding_points += 10
    breakdown["rule_findings"] = min(40, finding_points)

    # Signal 3: External destination
    is_external = False
    if tool_name == "send_email":
        recipient = str(arguments.get("to") or arguments.get("recipient") or "")
        if "@" in recipient and not recipient.endswith("@company.com"):
            is_external = True
    elif tool_name == "external_api":
        url = str(arguments.get("url") or arguments.get("endpoint") or "")
        from backend.app.detection.rules import is_approved_api_host
        if not is_approved_api_host(url):
            is_external = True

    if is_external:
        breakdown["external_destination"] = 25

    # Signal 4: Sensitive data involved (salaries, queries, credentials)
    args_str = " ".join([str(v) for v in arguments.values()]).lower()
    if tool_name == "db_query" or any(k in args_str for k in ["salary", "national_id", "password", "token", "secret"]):
        breakdown["sensitive_data"] = 15

    total_score = min(100, sum(breakdown.values()))
    return total_score, breakdown
