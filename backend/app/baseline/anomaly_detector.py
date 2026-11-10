import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from backend.app.baseline.profiler import BaselineProfiler, AgentBaselineProfile

class AnomalyDetector:
    """
    Milestone 5 Learned Behavioral Baseline Anomaly Detector.
    Scores statistical deviations from learned empirical distributions.
    Thresholds are derived entirely from baseline data (median, MAD, percentiles),
    never hand-tuned per scenario.
    """

    @classmethod
    def evaluate(
        cls,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        session_events: Optional[List[Dict[str, Any]]] = None,
        sim_datetime: Optional[datetime] = None,
        tool_result: Optional[Any] = None
    ) -> Tuple[int, List[str], Dict[str, Any]]:
        profile: AgentBaselineProfile = BaselineProfiler.get_profile(agent_id)
        reasons: List[str] = []
        breakdown: Dict[str, Any] = {}
        total_anomaly_score = 0

        # Current timestamp (supports simulated time for instant deterministic tests)
        now_dt = sim_datetime or datetime.now(timezone.utc)
        hour = now_dt.hour
        weekday = now_dt.strftime("%A")

        # 1. Bulk Record Dump Evaluation
        # Prioritize actual result size measured directly by the gateway from tool response
        records_count = 0.0
        if tool_result is not None:
            if isinstance(tool_result, list):
                records_count = float(len(tool_result))
            elif isinstance(tool_result, dict):
                for k in ["rows", "records", "data", "results", "items"]:
                    if k in tool_result and isinstance(tool_result[k], list):
                        records_count = float(len(tool_result[k]))
                        break
                if records_count == 0.0:
                    for k in ["count", "rows_returned", "records_returned", "row_count"]:
                        if k in tool_result and isinstance(tool_result[k], (int, float)):
                            records_count = float(tool_result[k])
                            break
            elif isinstance(tool_result, (int, float)):
                records_count = float(tool_result)

        # Pre-execution structural heuristic for db_query:
        if records_count == 0.0 and tool_name == "db_query":
            q = str(arguments.get("query") or "")
            limit_m = re.search(r"\bLIMIT\s+(\d+)\b", q, re.IGNORECASE)
            if limit_m:
                records_count = float(limit_m.group(1))
            else:
                has_where = bool(re.search(r"\bWHERE\b", q, re.IGNORECASE))
                from backend.app.config import settings
                ref_tables = set(t.lower() for t in getattr(settings, "REFERENCE_TABLES", [
                    "departments", "ticket_statuses", "exchange_rates", "categories", "status_codes", "countries", "currencies"
                ]))
                is_ref_lookup = bool(re.search(rf"\bFROM\s+(?:{'|'.join(ref_tables)})\b", q, re.IGNORECASE))
                is_aggregate = bool(re.search(r"\bSELECT\s+(?:COUNT|SUM|AVG|MIN|MAX)\b", q, re.IGNORECASE))
                has_group_by = bool(re.search(r"\bGROUP\s+BY\b", q, re.IGNORECASE))

                if is_aggregate and not has_group_by:
                    # Aggregate queries (COUNT/SUM/AVG/MIN/MAX) return a single scalar row, not bulk entity dumps
                    records_count = 1.0
                elif is_ref_lookup:
                    records_count = 3.0
                elif not has_where:
                    is_unconstrained_star = bool(re.search(r"\bSELECT\s+\*\s+FROM\b", q, re.IGNORECASE))
                    is_unconstrained_named = bool(re.search(r"\bSELECT\s+[a-zA-Z0-9_,\s*()]+\s+FROM\s+[a-zA-Z0-9_]+\b", q, re.IGNORECASE))
                    if is_unconstrained_star or is_unconstrained_named:
                        records_count = max(profile.threshold_records * 3.0, 500.0)
                    else:
                        records_count = 1.0
                else:
                    for k in ["records_returned", "records_accessed", "count", "rows_returned"]:
                        if k in arguments and isinstance(arguments[k], (int, float)):
                            records_count = float(arguments[k])
                            break
                    if records_count == 0.0:
                        records_count = 1.0

        if records_count > profile.threshold_records:
            median = max(profile.median_records, 1.0)
            ratio = records_count / median
            score_add = min(85, int(30 + ratio * 3))
            total_anomaly_score += score_add
            reasons.append(f"Bulk record query: {int(records_count)} records ({ratio:.1f}x baseline median)")
            breakdown["bulk_dump"] = {"records": int(records_count), "ratio": round(ratio, 1)}

        # Cumulative per-session counters (detects slow/low-volume exfiltration over multiple calls)
        events = session_events or []
        
        # Build map of returned records from appended immutable tool_return events
        tool_returns_by_trace = {}
        for ev in events:
            if ev.get("tool_name") == "tool_return":
                args = ev.get("arguments", {}) if isinstance(ev.get("arguments"), dict) else {}
                rb = ev.get("risk_breakdown", {}) if isinstance(ev.get("risk_breakdown"), dict) else {}
                ptrace = args.get("parent_trace_id") or rb.get("parent_trace_id")
                recs = args.get("records_returned") if args.get("records_returned") is not None else rb.get("records_returned")
                if ptrace:
                    tool_returns_by_trace[ptrace] = float(recs or 0.0)

        past_session_records = 0.0
        tool_call_events = []
        for ev in events:
            if ev.get("tool_name") == "tool_return":
                continue
            tool_call_events.append(ev)
            trace = ev.get("trace_id")
            if trace and trace in tool_returns_by_trace:
                rec = tool_returns_by_trace[trace]
            else:
                bd = ev.get("risk_breakdown", {}) if isinstance(ev.get("risk_breakdown"), dict) else {}
                rec = float(bd.get("records_returned") or ev.get("records_returned") or ev.get("records_accessed") or 0.0)
                if rec == 0.0 and ev.get("tool_name") == "db_query":
                    if "bulk_dump" in bd:
                        rec = float(bd["bulk_dump"].get("records", 0.0))
                    else:
                        rec = 1.0
            past_session_records += rec

        cumulative_session_records = past_session_records + records_count
        if cumulative_session_records > profile.threshold_session_records and len(tool_call_events) >= 2:
            score_add = min(75, int(35 + (cumulative_session_records / max(profile.median_session_records, 1.0)) * 2))
            total_anomaly_score += score_add
            reasons.append(f"Cumulative session records: {int(cumulative_session_records)} exceeds baseline threshold ({profile.threshold_session_records:.1f})")
            breakdown["cumulative_records"] = {"records": int(cumulative_session_records), "threshold": profile.threshold_session_records}

        # 2. Off-Hours Anomaly Evaluation
        is_weekend = weekday in ["Saturday", "Sunday"]
        is_off_hour = hour < profile.min_hour or hour > profile.max_hour

        if is_weekend or is_off_hour:
            total_anomaly_score += 35
            reason_str = f"Off-hours anomaly: Executing at {now_dt.strftime('%A %H:%M UTC')} outside baseline window ({profile.min_hour:02d}:00-{profile.max_hour:02d}:00 Mon-Fri)"
            reasons.append(reason_str)
            breakdown["off_hours"] = {"hour": hour, "weekday": weekday}

        # 3. Burst Rate (Calls Per Minute) Evaluation
        if len(tool_call_events) >= 3:
            try:
                t_first = datetime.fromisoformat(tool_call_events[0]["timestamp"])
                duration_secs = max((now_dt - t_first).total_seconds(), 0.5)
                calls_per_min = (len(tool_call_events) + 1) / (duration_secs / 60.0)

                if calls_per_min > profile.threshold_calls_per_min:
                    total_anomaly_score += 40
                    reasons.append(f"Burst execution rate: {calls_per_min:.1f} calls/min exceeds learned threshold ({profile.threshold_calls_per_min:.1f} calls/min)")
                    breakdown["burst_rate"] = {"cpm": round(calls_per_min, 1), "threshold": round(profile.threshold_calls_per_min, 1)}
            except Exception:
                pass

        # 4. Never-Seen Destination Evaluation
        destination = None
        if tool_name == "send_email":
            to_addr = str(arguments.get("to") or arguments.get("recipient") or "")
            if "@" in to_addr:
                destination = to_addr.split("@")[-1].lower().strip()
        elif tool_name == "external_api":
            url = str(arguments.get("url") or arguments.get("endpoint") or "")
            try:
                parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
                destination = parsed.hostname.lower() if parsed.hostname else None
            except Exception:
                pass

        if destination and profile.usual_destinations:
            # If destination not in usual destinations and not internal
            if destination not in profile.usual_destinations and not destination.endswith(".internal") and not destination.endswith(".local") and destination not in ["localhost", "127.0.0.1"]:
                total_anomaly_score += 30
                reasons.append(f"Never-seen destination '{destination}' for agent '{agent_id}'")
                breakdown["unusual_destination"] = destination

        # 5. Anomalous Tool Sequence Evaluation
        if tool_call_events:
            last_tool = tool_call_events[-1].get("tool_name")
            if last_tool and profile.common_transitions:
                allowed_next = profile.common_transitions.get(last_tool, set())
                if allowed_next and tool_name not in allowed_next:
                    total_anomaly_score += 20
                    reasons.append(f"Rare tool sequence '{last_tool} -> {tool_name}' for agent '{agent_id}'")
                    breakdown["rare_sequence"] = f"{last_tool} -> {tool_name}"

        # Clamped final score
        final_score = min(100, total_anomaly_score)
        breakdown["anomaly_score"] = final_score
        breakdown["reasons"] = reasons

        return final_score, reasons, breakdown
