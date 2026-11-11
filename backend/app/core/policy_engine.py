import os
from typing import List, Dict, Any, Tuple, Optional, Set
from backend.app.detection.rules import Finding

class PolicyEngine:
    _current_mode: str = os.getenv("SENTINEL_POLICY_MODE", "enforce").lower()
    _high_sensitivity_external_action: str = os.getenv("SENTINEL_HIGH_SENSITIVITY_EXTERNAL_ACTION", "require_approval").lower()
    _anomaly_threshold: int = int(os.getenv("SENTINEL_ANOMALY_THRESHOLD", "70"))

    @classmethod
    def set_anomaly_threshold(cls, threshold: int) -> int:
        cls._anomaly_threshold = threshold
        return cls._anomaly_threshold

    @classmethod
    def get_mode(cls) -> str:
        return cls._current_mode

    @classmethod
    def set_mode(cls, mode: str) -> str:
        mode_clean = mode.lower().strip()
        if mode_clean in ["enforce", "monitor"]:
            cls._current_mode = mode_clean
        return cls._current_mode

    @classmethod
    def set_high_sensitivity_external_action(cls, action: str) -> str:
        action_clean = action.lower().strip()
        if action_clean in ["require_approval", "block", "redact", "allow"]:
            cls._high_sensitivity_external_action = action_clean
        return cls._high_sensitivity_external_action

    @classmethod
    def evaluate_policy(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        is_tainted: bool,
        tainted_by: List[str],
        findings: List[Finding],
        risk_score: int,
        pii_findings: Any = None,
        judge_verdict: Any = None,
        anomaly_score: int = 0,
        anomaly_reasons: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        untrusted_literals: Optional[Set[str]] = None,
    ) -> Tuple[str, str]:
        """
        Evaluates active security policies against session context, detection findings,
        PII findings, baseline anomaly signals, and Intent Judge verdicts.
        Returns: (decision, explanation_reason)
        Decisions: 'allow', 'block', 'would_block', 'redact', 'require_approval'

        INVARIANT:
        The Intent Judge may raise risk or escalate to require_approval,
        but can NEVER downgrade or override a block determined by rules or taint.
        """
        mode = cls.get_mode()

        # Check if destination is unapproved external
        has_unapproved_recipient = any(f.name == "unapproved_external_recipient" for f in findings)
        
        is_unapproved_destination = False
        is_external_destination = False
        if tool_name == "send_email":
            rec = str(arguments.get("to") or arguments.get("recipient") or "")
            from backend.app.detection.rules import is_approved_email_domain, is_internal_destination
            if has_unapproved_recipient or not is_approved_email_domain(rec):
                is_unapproved_destination = True
            if not is_internal_destination(rec):
                is_external_destination = True
        elif tool_name == "external_api":
            url = str(arguments.get("url") or arguments.get("endpoint") or "")
            from backend.app.detection.rules import is_approved_api_host, is_internal_destination
            if not is_approved_api_host(url):
                is_unapproved_destination = True
            if not is_internal_destination(url):
                is_external_destination = True

        # Policy Rule 1: No external data transfer to unapproved destination from tainted session
        if is_tainted and is_unapproved_destination:
            sources_str = ", ".join(tainted_by) if tainted_by else "untrusted context"
            if mode == "enforce":
                return (
                    "block",
                    f"Policy 'No external data transfer from tainted session' blocked tool '{tool_name}'. "
                    f"Session is tainted by untrusted source: [{sources_str}] and destination is unapproved/external."
                )
            else:
                return (
                    "would_block",
                    f"Policy 'No external data transfer from tainted session' [MONITOR MODE]: "
                    f"Action would have been blocked. Session tainted by [{sources_str}]."
                )

        # Policy Rule 2: High-Sensitivity Data Egress or Financial Transaction Verification
        has_sensitive_pii = any(getattr(f, "pii_type", "") in ["SALARY", "NATIONAL_ID", "CREDIT_CARD", "IBAN", "API_KEY"] for f in (pii_findings or []))
        is_financial_transaction = any(k in arguments for k in ["amount", "bank_routing", "account_number", "wire_routing"])

        if is_financial_transaction:
            # Query vendor master table from database to verify banking profile
            vendor_val = str(arguments.get("vendor") or arguments.get("vendor_name") or "")
            routing_val = str(arguments.get("bank_routing") or arguments.get("wire_routing") or "")
            account_val = str(arguments.get("account_number") or "")

            is_verified_disbursement = False
            if vendor_val and routing_val and account_val:
                from backend.app.db.database import get_vendor_master
                v_master = get_vendor_master(vendor_val)
                if v_master and v_master["bank_routing"] == routing_val and v_master["account_number"] == account_val:
                    is_verified_disbursement = True

            # If routing details do NOT match master record, or if tainted and unverified, require human approval
            if not is_verified_disbursement:
                if is_tainted or is_external_destination:
                    if mode == "enforce":
                        return (
                            "require_approval",
                            "Policy 'High-Sensitivity External Egress': Outgoing transfer with unverified or modified banking routing details requires human approval."
                        )
                    else:
                        return (
                            "would_block",
                            "Policy Alert [MONITOR MODE]: Outgoing transfer with unverified banking routing details."
                        )

        if is_external_destination and has_sensitive_pii and not is_financial_transaction:
            if cls._high_sensitivity_external_action == "require_approval" or is_tainted:
                if mode == "enforce":
                    return (
                        "require_approval",
                        "Policy 'High-Sensitivity External Egress': Outgoing transfer containing sensitive personal data to external destination requires human approval."
                    )
                else:
                    return (
                        "would_block",
                        "Policy 'High-Sensitivity External Egress' [MONITOR MODE]: Outgoing transfer containing sensitive personal data would have required human approval."
                    )

        # Policy Rule 2b: Tainted or Untrusted-Provenance Writes to Sensitive Database Columns
        if tool_name == "db_query":
            query_str = str(arguments.get("query") or arguments.get("sql") or "")
            if query_str:
                from backend.app.detection.rules import analyze_sql_sensitive_write
                from backend.app.core.taint_tracker import value_appears_in_untrusted_session
                write_info = analyze_sql_sensitive_write(query_str)
                sens_cols = write_info.get("sensitive_modified_columns") or []
                if sens_cols:
                    assigned_vals = write_info.get("all_sensitive_assigned_values") or []
                    matched_untrusted_vals = [
                        v for v in assigned_vals
                        if value_appears_in_untrusted_session(
                            v,
                            session_id=session_id,
                            untrusted_literals=untrusted_literals,
                        )
                    ]
                    if is_tainted or bool(matched_untrusted_vals):
                        cols_str = ", ".join(sens_cols)
                        stmt_type = write_info.get("statement_type") or "DML"
                        prov_detail = (
                            f"untrusted value provenance match {matched_untrusted_vals}"
                            if matched_untrusted_vals
                            else f"tainted session [{', '.join(tainted_by) if tainted_by else 'untrusted context'}]"
                        )
                        if mode == "enforce":
                            return (
                                "require_approval",
                                f"Policy 'Sensitive Column Write Protection': SQL {stmt_type} modifies sensitive column(s) [{cols_str}] under {prov_detail}. Human approval required."
                            )
                        else:
                            return (
                                "would_block",
                                f"Policy Alert [MONITOR MODE]: SQL {stmt_type} modifies sensitive column(s) [{cols_str}] under {prov_detail}."
                            )

        # Policy Rule: Destructive Database Operation or Privileged Mutation requires authorized approval
        priv_ops = [f for f in findings if f.name in ["destructive_ddl_command", "privileged_administrative_action"]]
        if priv_ops:
            top_op = priv_ops[0]
            if mode == "enforce":
                return (
                    "require_approval",
                    f"Policy 'Privileged Action Authorization': {top_op.evidence}. Privileged operations require verified approval token or human authorization."
                )
            else:
                return (
                    "would_block",
                    f"Policy Alert [MONITOR MODE]: Privileged operation detected without approval token ({top_op.evidence})."
                )

        # Policy Rule 3: Unapproved email recipient
        if has_unapproved_recipient:
            top_rec = next(f for f in findings if f.name == "unapproved_external_recipient")
            if mode == "enforce":
                return (
                    "block",
                    f"Security Rule Policy blocked action: Unapproved External Recipient ({top_rec.evidence})."
                )
            else:
                return (
                    "would_block",
                    f"Security Rule Alert [MONITOR MODE]: Would have blocked on Unapproved External Recipient ({top_rec.evidence})."
                )

        # Policy Rule 3: High or Critical security finding (SSRF, SQLi, Credential leak, Path traversal)
        actionable_threats = [
            f for f in findings
            if f.name in ["ssrf_metadata_target", "sql_injection_pattern", "path_traversal", "credential_leak"]
        ]
        if actionable_threats:
            top = actionable_threats[0]
            if mode == "enforce":
                return (
                    "block",
                    f"Security Rule Policy blocked action: {top.name.replace('_', ' ').title()} "
                    f"({top.evidence}). OWASP: {top.owasp_category}."
                )
            else:
                return (
                    "would_block",
                    f"Security Rule Alert [MONITOR MODE]: Would have blocked on {top.name.replace('_', ' ').title()} "
                    f"({top.evidence}). Action permitted for monitoring."
                )

        # Policy Rule 4: Intent Judge Divergence Escalation (Mismatch >= 70)
        if judge_verdict and not getattr(judge_verdict, "is_aligned", True) and getattr(judge_verdict, "mismatch_score", 0) >= 70:
            if mode == "enforce":
                return (
                    "require_approval",
                    f"Intent Judge Policy: Task divergence detected (Mismatch: {judge_verdict.mismatch_score}/100). {judge_verdict.reasoning}"
                )
            else:
                return (
                    "would_block",
                    f"Intent Judge Alert [MONITOR MODE]: High intent mismatch ({judge_verdict.mismatch_score}/100). {judge_verdict.reasoning}"
                )

        # Policy Rule 5: Behavioral Baseline Anomaly Escalation (Anomaly >= threshold)
        if anomaly_score >= cls._anomaly_threshold:
            anomaly_str = "; ".join(anomaly_reasons[:2]) if anomaly_reasons else "Significant behavioral outlier"
            # Critical compound anomaly on tainted session (e.g. ATK-009 off-hours bulk dump from injected trigger)
            if is_tainted and anomaly_score >= 85 and any("*" in str(v) for v in arguments.values()):
                if mode == "enforce":
                    return (
                        "block",
                        f"Baseline Anomaly Policy blocked action: Critical compound behavioral anomaly detected from tainted session ({anomaly_str}, Score: {anomaly_score}/100)."
                    )
                else:
                    return (
                        "would_block",
                        f"Baseline Anomaly Alert [MONITOR MODE]: Would have blocked on critical compound anomaly ({anomaly_str})."
                    )
            if mode == "enforce":
                return (
                    "require_approval",
                    f"Baseline Anomaly Policy: Behavioral deviation detected ({anomaly_str}). Action requires human approval."
                )
            else:
                return (
                    "would_block",
                    f"Baseline Anomaly Alert [MONITOR MODE]: Outlier behavior detected ({anomaly_str}). Action permitted for monitoring."
                )

        # Policy Rule 6: PII Redaction for Outgoing Destinations (Legitimate calls with sensitive data)
        if pii_findings and tool_name in ["send_email", "external_api"]:
            has_sensitive_pii = any(getattr(f, "pii_type", "") in ["SALARY", "NATIONAL_ID", "CREDIT_CARD", "IBAN", "API_KEY"] for f in pii_findings)
            if has_sensitive_pii:
                return (
                    "redact",
                    f"Policy 'PII Redaction' applied to tool '{tool_name}': Sensitive data masked prior to transmission."
                )

        # Default Allow
        return (
            "allow",
            f"Action '{tool_name}' permitted: No active policy violations detected."
        )
