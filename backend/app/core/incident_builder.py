import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from backend.app.db.database import list_session_events, save_incident, get_incident_by_session

logger = logging.getLogger(__name__)

class IncidentBuilder:
    """
    Milestone 3 Attack Chain Reconstruction and Incident Generation.
    Reconstructs the full sequence of events within a session, identifies entry points,
    affected data assets, and generates clear plain-language summaries from dynamic templates.
    No scenario-specific strings are hardcoded.
    """

    @staticmethod
    def _format_step(idx: int, ev: dict):
        tool = ev.get("tool_name", "")
        args = ev.get("arguments", {})
        dec = ev.get("decision", "allow")
        score = ev.get("risk_score", 0)
        sources = ev.get("context_sources", [])
        affected_items = set()
        untrusted_src = None

        has_untrusted = any(c.get("is_untrusted") for c in sources if isinstance(c, dict))
        if has_untrusted:
            for c in sources:
                if isinstance(c, dict) and c.get("is_untrusted"):
                    untrusted_src = c.get("source_id", "untrusted source")
                    affected_items.add(f"Ingested Source: {untrusted_src}")
                    break

        if tool == "read_doc":
            icon = "📄"
            file_target = args.get("file_path") or args.get("path") or "document"
            title = f"Document Ingestion: {file_target}"
            step_status = "TAINTED_INGEST" if has_untrusted else "ALLOWED"
            affected_items.add(f"Document ({file_target})")
        elif tool == "db_query":
            icon = "🗄️"
            query_str = str(args.get("query") or args.get("sql") or "")
            title = f"Database Query ({query_str[:45]}...)" if len(query_str) > 45 else f"Database Query ({query_str})"
            step_status = "SENSITIVE_READ"
            table_match = re.search(r"\bFROM\s+([a-zA-Z0-9_\.]+)", query_str, re.IGNORECASE)
            if table_match:
                table_name = table_match.group(1)
                affected_items.add(f"Database Table: {table_name}")
            else:
                affected_items.add("Database Records")
        elif tool == "send_email":
            icon = "📤"
            recipient = args.get("to") or args.get("recipient") or "unknown"
            title = f"Email Dispatch to {recipient}"
            step_status = "BLOCKED_ATTACK" if dec == "block" else ("WOULD_BLOCK" if dec == "would_block" else "ALLOWED")
            affected_items.add(f"Exfiltration Target: {recipient}")
        elif tool == "external_api":
            icon = "🌐"
            endpoint = args.get("url") or args.get("endpoint") or "api"
            title = f"External API Request to {endpoint}"
            step_status = "BLOCKED_ATTACK" if dec == "block" else ("WOULD_BLOCK" if dec == "would_block" else "ALLOWED")
            if "169.254.169.254" in str(endpoint) or "metadata" in str(endpoint).lower():
                affected_items.add(f"Cloud Metadata Endpoint: {endpoint}")
            else:
                affected_items.add(f"API Target: {endpoint}")
        else:
            icon = "⚡"
            title = f"Tool Execution: {tool}"
            step_status = "BLOCKED_ATTACK" if dec == "block" else ("WOULD_BLOCK" if dec == "would_block" else "ALLOWED")

        step = {
            "step_number": idx,
            "tool_name": tool,
            "title": title,
            "icon": icon,
            "arguments": args,
            "decision": dec,
            "status": step_status,
            "risk_score": score,
            "reason": ev.get("reason", ""),
            "timestamp": ev.get("timestamp", datetime.now(timezone.utc).isoformat())
        }
        return step, affected_items, untrusted_src

    @classmethod
    def process_event(
        cls,
        event_dict: Dict[str, Any],
        findings: Optional[List[Any]] = None,
        session_events: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        decision = event_dict.get("decision", "allow")
        risk_score = event_dict.get("risk_score", 0)

        # Skip internal tool_return bookkeeping events
        if event_dict.get("tool_name") == "tool_return":
            return None

        # Trigger incident when an action is blocked/would_block, or if risk exceeds threshold
        if decision not in ["block", "would_block"] and risk_score < 70:
            return None

        session_id = event_dict["session_id"]
        agent_id = event_dict["agent_id"]

        # Check if incident already exists for this session
        existing = get_incident_by_session(session_id)
        incident_id = existing["id"] if existing else f"INC-{uuid.uuid4().hex[:8].upper()}"

        all_findings = list(findings or [])
        attack_category = None

        # Fetch all chronological events for this session
        if session_events is not None:
            events = list(session_events) + [event_dict]
        else:
            events = list_session_events(session_id)
            if not events:
                events = [event_dict]

        chain_steps = []
        entry_point = "Direct Agent Execution"
        affected_data_items = set()
        untrusted_source_id = None

        for idx, ev in enumerate([e for e in events if e.get("tool_name") != "tool_return"], 1):
            step, step_affected, step_untrusted = cls._format_step(idx, ev)
            chain_steps.append(step)
            affected_data_items.update(step_affected)
            if step_untrusted and not untrusted_source_id:
                untrusted_source_id = step_untrusted
                entry_point = f"{ev.get('tool_name', 'tool')} ('{untrusted_source_id}')"
        # Check findings from event breakdown or passed findings
        final_tool = event_dict.get("tool_name", "")
        final_args = event_dict.get("arguments", {})
        final_dec = decision
        final_args_str = " ".join([str(v) for v in final_args.values()])

        finding_names = {getattr(f, "name", "") if hasattr(f, "name") else f.get("name", "") for f in all_findings}

        # Check for privacy data-class breakdown (e.g. '3 emails, 2 salary amounts exposed or attempted')
        for ev in events:
            bd = ev.get("risk_breakdown", {})
            if isinstance(bd, dict) and "privacy_breakdown" in bd:
                pbd = bd["privacy_breakdown"]
                if isinstance(pbd, dict) and pbd.get("summary") and pbd.get("summary") != "No PII detected":
                    affected_data_items.add(f"PII: {pbd['summary']}")

        # Classify attack type dynamically
        if "ssrf_metadata_target" in finding_names or "169.254.169.254" in final_args_str or "metadata.google" in final_args_str:
            attack_category = "SSRF"
            title = f"Server-Side Request Forgery (SSRF) Attempt via {agent_id}"
            severity = "CRITICAL"
        elif "credential_leak" in finding_names or any(k in final_args_str for k in ["Bearer ", "AKIA", "BEGIN PRIVATE KEY", "password="]):
            attack_category = "CREDENTIAL_LEAK"
            title = f"Credential & Secret Exposure Attempt via {agent_id}"
            affected_data_items.add("Authentication Credentials / Secrets")
            severity = "CRITICAL"
        elif "sql_injection_pattern" in finding_names:
            attack_category = "SQL_INJECTION"
            title = f"SQL Injection Attempt via {agent_id}"
            severity = "HIGH"
        elif any("bulk record" in str(ev.get("risk_breakdown", {})).lower() for ev in events):
            attack_category = "BULK_DUMP"
            title = f"Bulk Database Extraction via {agent_id}"
            severity = "CRITICAL"
        elif untrusted_source_id or any(s.get("status") == "TAINTED_INGEST" for s in chain_steps):
            attack_category = "INDIRECT_INJECTION"
            title = f"Indirect Prompt Injection & Data Exfiltration via {agent_id}"
            severity = "CRITICAL" if any(s["status"] == "SENSITIVE_READ" for s in chain_steps) and final_tool in ["send_email", "external_api"] else "HIGH"
        else:
            attack_category = "POLICY_VIOLATION"
            title = f"Security Policy Violation via {agent_id}"
            severity = "HIGH"

        # 4. Generate plain-language summary from templates
        summary = cls._generate_summary(
            agent_id=agent_id,
            attack_category=attack_category,
            entry_point=entry_point,
            untrusted_source=untrusted_source_id,
            chain_steps=chain_steps,
            final_tool=final_tool,
            final_args=final_args,
            final_decision=final_dec,
            risk_breakdown=event_dict.get("risk_breakdown", {})
        )

        status_label = "BLOCKED" if final_dec == "block" else ("WOULD_BLOCK" if final_dec == "would_block" else "OPEN")

        incident = {
            "id": incident_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "title": title,
            "status": status_label,
            "severity": severity,
            "entry_point": entry_point,
            "affected_data": ", ".join(sorted(list(affected_data_items))) if affected_data_items else "System Context",
            "final_decision": final_dec,
            "risk_score": max(event_dict.get("risk_score", 0), max((s["risk_score"] for s in chain_steps), default=0)),
            "risk_breakdown": event_dict.get("risk_breakdown", {}),
            "summary": summary,
            "chain_steps": chain_steps,
            "created_at": existing.get("created_at") if existing else datetime.now(timezone.utc).isoformat()
        }

        # 5. Save incident
        save_incident(incident)
        logger.info(f"Incident {incident_id} processed and saved for session {session_id} (Status: {status_label})")
        return incident

    @classmethod
    def _generate_summary(
        cls,
        agent_id: str,
        attack_category: str,
        entry_point: str,
        untrusted_source: Optional[str],
        chain_steps: List[Dict[str, Any]],
        final_tool: str,
        final_args: Dict[str, Any],
        final_decision: str,
        risk_breakdown: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generates an auditable, deterministic plain-language incident narrative without an LLM.
        Incorporates Intent Judge analysis and Behavioral Baseline signals when present.
        """
        parts = []

        if attack_category == "SSRF":
            endpoint = final_args.get("url") or final_args.get("endpoint") or "cloud metadata service"
            parts.append(f"Agent '{agent_id}' attempted an unauthorized Server-Side Request Forgery (SSRF) request targeting sensitive endpoint '{endpoint}'.")
        elif attack_category == "CREDENTIAL_LEAK":
            dest = final_args.get("to") or final_args.get("url") or final_tool
            parts.append(f"Agent '{agent_id}' attempted to expose sensitive credentials or authentication secrets via '{dest}'.")
        elif attack_category == "BULK_DUMP":
            parts.append(f"Agent '{agent_id}' attempted an anomalous bulk database extraction exceeding learned statistical volume baselines.")
        elif untrusted_source:
            parts.append(f"A document marked untrusted ('{untrusted_source}') entered {agent_id}'s execution session.")
            has_db = any(s["tool_name"] == "db_query" for s in chain_steps)
            if has_db:
                parts.append("The agent then read confidential records from the database via db_query.")
            else:
                parts.append("The agent then performed internal processing on the tainted payload.")
            if final_tool == "send_email":
                recipient = final_args.get("to") or final_args.get("recipient") or "an unapproved external destination"
                parts.append(f"Subsequently, the agent attempted to exfiltrate the data via send_email to unapproved recipient '{recipient}'.")
            elif final_tool == "external_api":
                endpoint = final_args.get("url") or final_args.get("endpoint") or "an external server"
                parts.append(f"Subsequently, the agent attempted an external API egress to '{endpoint}'.")
            else:
                parts.append(f"Subsequently, the agent attempted to execute sensitive tool '{final_tool}'.")
        else:
            parts.append(f"Agent '{agent_id}' attempted an unauthorized invocation of '{final_tool}'.")

        # Milestone 5 Intent Judge and Baseline Anomaly clauses
        if risk_breakdown:
            if risk_breakdown.get("judge_reasoning"):
                mismatch = risk_breakdown.get("judge_mismatch", 0)
                parts.append(f"Intent Judge assessed intent mismatch ({mismatch}/100): {risk_breakdown['judge_reasoning']}")
            if risk_breakdown.get("anomaly_reasons"):
                reasons_str = "; ".join(risk_breakdown["anomaly_reasons"][:2])
                parts.append(f"Behavioral baseline detected statistical anomalies: {reasons_str}.")

        # Enforcement clause
        if final_decision == "block":
            parts.append("SentinelMesh AI detected the attack chain and blocked the action inline, preventing unauthorized disclosure or compromise.")
        else:
            parts.append("SentinelMesh AI identified the attack chain in Monitor mode. The action would have been blocked under Enforce mode.")

        return " ".join(parts)
