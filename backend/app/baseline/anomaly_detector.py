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
                # Structural heuristic: unconstrained table scan (SELECT * or SELECT named columns from bulk/sensitive tables with no WHERE and no LIMIT)
                is_unconstrained_star = bool(re.search(r"\bSELECT\s+\*\s+FROM\b", q, re.IGNORECASE))
                is_unconstrained_named = bool(re.search(r"\bSELECT\s+.+?\s+FROM\s+(?:employees|salaries|payroll|enterprise|ledger|general_ledger|transactions|applicant_records|payments|credentials|user_secrets)\b", q, re.IGNORECASE | re.DOTALL))
                if not has_where and (is_unconstrained_star or is_unconstrained_named):
                    records_count = max(profile.threshold_records * 3.0, 500.0)
                else:
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
        past_session_records = 0.0
        for ev in events:
            past_session_records += float(ev.get("records_accessed", 0) or 0.0)
            if ev.get("tool_name") == "db_query":
                bd = ev.get("risk_breakdown", {})
                if "bulk_dump" in bd:
                    past_session_records += float(bd["bulk_dump"].get("records", 0))
                else:
                    past_session_records += 1.0

        cumulative_session_records = past_session_records + records_count
        if cumulative_session_records > profile.threshold_session_records and len(events) >= 2:
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
        events = session_events or []
        if len(events) >= 3:
            try:
                t_first = datetime.fromisoformat(events[0]["timestamp"])
                duration_secs = max((now_dt - t_first).total_seconds(), 0.5)
                calls_per_min = (len(events) + 1) / (duration_secs / 60.0)

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
        if events:
            last_tool = events[-1].get("tool_name")
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
