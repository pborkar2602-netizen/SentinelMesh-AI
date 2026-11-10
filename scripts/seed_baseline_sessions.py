#!/usr/bin/env python3
"""
SentinelMesh AI — Baseline Training Data Generator
Generates ~200 realistic, normal synthetic enterprise sessions across monitored agents
(hr-agent, finance-agent, support-agent, code-agent, ops-agent) with business hours timestamps,
normal tool distributions, destination whitelists, and record volume statistics.
"""

import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "backend" / "app" / "baseline" / "baseline_data.json"

AGENT_PROFILES = {
    "hr-agent": {
        "tasks": [
            "Review applicant resume and schedule initial interview",
            "Screen senior engineering candidate portfolio",
            "Verify applicant contact information and references",
            "Archive completed candidate evaluation records",
            "Compare applicant qualifications and verify candidate history"
        ],
        "tools": ["read_doc", "send_email", "db_query"],
        "tool_weights": [0.40, 0.30, 0.30],
        "allowed_email_domains": ["company.com", "partner.org"],
        "records_per_query_range": (1, 4),
        "typical_sequence": [
            ["read_doc", "send_email"],
            ["read_doc", "db_query", "send_email"],
            ["read_doc", "db_query", "db_query", "send_email"],
            ["db_query", "db_query", "send_email"]
        ],
        "calls_per_session_range": (2, 5)
    },
    "finance-agent": {
        "tasks": [
            "Reconcile monthly vendor invoice line items",
            "Generate departmental quarterly expense ledger summary",
            "Validate partner billing statements against purchase orders",
            "Calculate approved payroll tax withholding adjustments",
            "Execute scheduled monthly financial reconciliation batch query"
        ],
        "tools": ["db_query", "send_email", "external_api"],
        "tool_weights": [0.50, 0.30, 0.20],
        "allowed_email_domains": ["company.com", "approved-vendor.com", "vendor-corp.com"],
        "allowed_api_hosts": ["internal.local", "sentinelmesh.internal", "vendor-corp.com", "api.partner-verified.org"],
        "records_per_query_range": (10, 5500),
        "typical_sequence": [["db_query", "send_email"], ["db_query", "external_api"]],
        "calls_per_session_range": (2, 5)
    },
    "support-agent": {
        "tasks": [
            "Triage customer support ticket and reply with solution",
            "Lookup customer account tier in support database",
            "Update resolution notes for closed service requests"
        ],
        "tools": ["read_doc", "db_query", "send_email"],
        "tool_weights": [0.45, 0.35, 0.20],
        "allowed_email_domains": ["company.com", "verified-client.org"],
        "records_per_query_range": (1, 3),
        "typical_sequence": [["read_doc", "db_query", "send_email"], ["read_doc", "send_email"]],
        "calls_per_session_range": (2, 4)
    },
    "code-agent": {
        "tasks": [
            "Review pull request diff and post automated code comments",
            "Fetch repository dependencies from whitelisted package index",
            "Run linting checks on modified codebase modules"
        ],
        "tools": ["read_doc", "external_api"],
        "tool_weights": [0.50, 0.50],
        "allowed_api_hosts": ["api.github.com", "internal.local"],
        "typical_sequence": [["read_doc", "external_api"]],
        "calls_per_session_range": (2, 4)
    },
    "ops-agent": {
        "tasks": [
            "Collect cluster health metrics from internal monitoring daemon",
            "Query service uptime status from local observability endpoint",
            "Dispatch automated ops status digest to platform team"
        ],
        "tools": ["external_api", "send_email"],
        "tool_weights": [0.70, 0.30],
        "allowed_api_hosts": ["localhost", "127.0.0.1", "internal.local"],
        "allowed_email_domains": ["company.com"],
        "typical_sequence": [["external_api", "send_email"]],
        "calls_per_session_range": (2, 3)
    }
}

def generate_baseline_sessions(num_sessions: int = 200, seed: int = 8421) -> List[Dict[str, Any]]:
    random.seed(seed)
    sessions: List[Dict[str, Any]] = []

    # Business hours base: Monday to Friday, 09:00 to 17:00
    base_monday = datetime(2026, 10, 5, 0, 0, 0, tzinfo=timezone.utc)

    agent_names = list(AGENT_PROFILES.keys())

    for i in range(num_sessions):
        agent_id = agent_names[i % len(agent_names)]
        profile = AGENT_PROFILES[agent_id]
        session_id = f"sess-base-{agent_id}-{i+1:04d}"
        task = random.choice(profile["tasks"])

        # Timestamp during normal business days (Mon-Fri) and hours (09:00 - 17:00)
        day_offset = random.randint(0, 20)  # across ~4 work weeks
        # skip weekends
        weekday = (base_monday + timedelta(days=day_offset)).weekday()
        if weekday >= 5:
            day_offset += (7 - weekday)

        hour = random.randint(9, 16)
        minute = random.randint(0, 59)
        session_start = base_monday + timedelta(days=day_offset, hours=hour, minutes=minute)

        # Decide sequence of tool calls
        num_calls = random.randint(*profile.get("calls_per_session_range", (2, 4)))
        seq = random.choice(profile["typical_sequence"])
        # pad or truncate sequence to num_calls
        tool_sequence = []
        for call_idx in range(num_calls):
            t = seq[call_idx % len(seq)]
            tool_sequence.append(t)

        events: List[Dict[str, Any]] = []
        current_time = session_start

        for step_idx, tool_name in enumerate(tool_sequence, 1):
            args: Dict[str, Any] = {}
            if tool_name == "read_doc":
                args = {"file_path": f"document_{random.randint(100, 999)}.txt"}
            elif tool_name == "db_query":
                records = random.randint(*profile.get("records_per_query_range", (1, 10)))
                args = {
                    "query": f"SELECT id, name, status FROM inventory_records LIMIT {records}",
                    "records_returned": records
                }
            elif tool_name == "send_email":
                dom = random.choice(profile.get("allowed_email_domains", ["company.com"]))
                args = {
                    "to": f"team-lead@{dom}",
                    "subject": f"Status Update: {task[:30]}",
                    "body": "Normal operational task summary completed."
                }
            elif tool_name == "external_api":
                host = random.choice(profile.get("allowed_api_hosts", ["internal.local"]))
                args = {
                    "url": f"https://{host}/api/v1/metrics",
                    "method": "GET"
                }

            events.append({
                "step_number": step_idx,
                "tool_name": tool_name,
                "arguments": args,
                "timestamp": current_time.isoformat()
            })
            # Advance simulated time by 5 to 45 seconds between tool calls
            current_time += timedelta(seconds=random.randint(5, 45))

        sessions.append({
            "session_id": session_id,
            "agent_id": agent_id,
            "task_description": task,
            "start_time": session_start.isoformat(),
            "weekday": session_start.strftime("%A"),
            "hour_of_day": session_start.hour,
            "events": events
        })

    return sessions

def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    sessions = generate_baseline_sessions(num_sessions=200, seed=42)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)
    print(f"[+] Successfully generated and seeded {len(sessions)} baseline sessions to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
