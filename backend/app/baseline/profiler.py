import json
import math
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple

DEFAULT_DATA_PATH = Path(__file__).resolve().parent / "baseline_data.json"

def calculate_median(values: List[float]) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    mid = n // 2
    if n % 2 == 1:
        return float(sorted_v[mid])
    return (sorted_v[mid - 1] + sorted_v[mid]) / 2.0

def calculate_mad(values: List[float], median: float) -> float:
    """Calculates Median Absolute Deviation (MAD), with a robust relative floor for zero-MAD distributions."""
    if not values or len(values) < 2:
        return max(0.15 * median, 1.0)
    deviations = [abs(v - median) for v in values]
    raw_mad = calculate_median(deviations)
    # Robust floor avoids zero-MAD collapse on constant historical data
    mad_floor = max(0.15 * median, 1.0)
    return max(raw_mad, mad_floor)

class AgentBaselineProfile:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.tool_counts: Dict[str, int] = {}
        self.tool_frequencies: Dict[str, float] = {}
        self.usual_destinations: Set[str] = set()
        self.common_transitions: Dict[str, Set[str]] = {}
        
        # Distributions
        self.records_per_query_dist: List[float] = []
        self.records_per_session_dist: List[float] = []
        self.calls_per_session_dist: List[float] = []
        self.calls_per_minute_dist: List[float] = []
        
        # Learned statistics & thresholds
        self.median_records: float = 0.0
        self.mad_records: float = 1.0
        self.threshold_records: float = 50.0

        self.median_session_records: float = 0.0
        self.mad_session_records: float = 1.0
        self.threshold_session_records: float = 40.0

        self.median_calls_per_min: float = 0.0
        self.mad_calls_per_min: float = 1.0
        self.threshold_calls_per_min: float = 10.0
        self.threshold_calls_per_hour: float = 30.0

        self.min_hour: int = 8
        self.max_hour: int = 18
        self.allowed_weekdays: Set[str] = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}

    def finalize(self):
        """Computes statistical parameters and thresholds from empirical distributions."""
        tot_tools = sum(self.tool_counts.values()) or 1
        self.tool_frequencies = {t: count / tot_tools for t, count in self.tool_counts.items()}

        # 1. Records per query
        if self.records_per_query_dist:
            self.median_records = calculate_median(self.records_per_query_dist)
            self.mad_records = calculate_mad(self.records_per_query_dist, self.median_records)
            # 3.5 * MAD upper threshold for outlier detection
            self.threshold_records = max(self.median_records + 3.5 * self.mad_records, 35.0)

        # 2. Calls per minute (burst threshold)
        if self.calls_per_minute_dist:
            self.median_calls_per_min = calculate_median(self.calls_per_minute_dist)
            self.mad_calls_per_min = calculate_mad(self.calls_per_minute_dist, self.median_calls_per_min)
            self.threshold_calls_per_min = max(self.median_calls_per_min + 3.5 * self.mad_calls_per_min, 6.0)

        # 3. Cumulative records per session threshold
        if self.records_per_session_dist:
            self.median_session_records = calculate_median(self.records_per_session_dist)
            self.mad_session_records = calculate_mad(self.records_per_session_dist, self.median_session_records)
            self.threshold_session_records = max(self.median_session_records + 3.5 * self.mad_session_records, 20.0)

        # 4. Hourly call rate threshold
        self.threshold_calls_per_hour = max(self.threshold_calls_per_min * 20.0, 30.0)

class BaselineProfiler:
    _profiles: Dict[str, AgentBaselineProfile] = {}

    @classmethod
    def get_profile(cls, agent_id: str) -> AgentBaselineProfile:
        if not cls._profiles:
            cls.load_or_train()
        return cls._profiles.get(agent_id, AgentBaselineProfile(agent_id))

    @classmethod
    def load_or_train(cls, data_path: Path = DEFAULT_DATA_PATH) -> Dict[str, AgentBaselineProfile]:
        if not data_path.exists():
            from scripts.seed_baseline_sessions import generate_baseline_sessions
            sessions = generate_baseline_sessions(200)
        else:
            with open(data_path, "r", encoding="utf-8") as f:
                sessions = json.load(f)

        profiles: Dict[str, AgentBaselineProfile] = {}

        for sess in sessions:
            agent_id = sess["agent_id"]
            if agent_id not in profiles:
                profiles[agent_id] = AgentBaselineProfile(agent_id)
            prof = profiles[agent_id]

            events = sess.get("events", [])
            prof.calls_per_session_dist.append(float(len(events)))

            # Calculate calls per minute across session duration
            if len(events) >= 2:
                from datetime import datetime
                t0 = datetime.fromisoformat(events[0]["timestamp"])
                t1 = datetime.fromisoformat(events[-1]["timestamp"])
                dur_secs = max((t1 - t0).total_seconds(), 1.0)
                cpm = (len(events) / dur_secs) * 60.0
                prof.calls_per_minute_dist.append(cpm)

            prev_tool = None
            sess_records = 0.0
            for ev in events:
                tool = ev["tool_name"]
                args = ev.get("arguments", {})
                prof.tool_counts[tool] = prof.tool_counts.get(tool, 0) + 1

                # Transitions
                if prev_tool:
                    if prev_tool not in prof.common_transitions:
                        prof.common_transitions[prev_tool] = set()
                    prof.common_transitions[prev_tool].add(tool)
                prev_tool = tool

                # Destinations
                if tool == "send_email":
                    to_addr = str(args.get("to") or "")
                    if "@" in to_addr:
                        dom = to_addr.split("@")[-1].lower().strip()
                        prof.usual_destinations.add(dom)
                elif tool == "external_api":
                    url = str(args.get("url") or "")
                    import urllib.parse
                    parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
                    if parsed.hostname:
                        prof.usual_destinations.add(parsed.hostname.lower())

                # Records returned
                rec_val = 0.0
                if "records_returned" in args:
                    rec_val = float(args["records_returned"])
                elif tool == "db_query":
                    import re
                    q = str(args.get("query") or "")
                    limit_match = re.search(r"LIMIT\s+(\d+)", q, re.IGNORECASE)
                    if limit_match:
                        rec_val = float(limit_match.group(1))
                    else:
                        rec_val = 1.0
                prof.records_per_query_dist.append(rec_val)
                sess_records += rec_val

            prof.records_per_session_dist.append(sess_records)

        # Finalize all profiles
        for p in profiles.values():
            p.finalize()

        cls._profiles = profiles
        return profiles
