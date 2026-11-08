import os
import time
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import httpx
from benchmark.harness.models import (
    BenchmarkScenario,
    InputContextSource,
    ScriptedStep,
    StepExecutionResult,
    ScenarioExecutionResult,
)

class BenchmarkRunner:
    def __init__(
        self,
        gateway_url: str = "http://localhost:8000/api/v1/gateway/execute",
        http_client: Optional[Any] = None,
        simulated_reviewer_decision: str = "deny",
    ):
        self.gateway_url = gateway_url
        self.http_client = http_client
        self.simulated_reviewer_decision = simulated_reviewer_decision
        self._direct_client = None
        self._init_connection()

    def _init_connection(self) -> None:
        if self.http_client is not None:
            return
        try:
            # Quick check if standalone gateway server is active
            probe_url = self.gateway_url.replace("/api/v1/gateway/execute", "/docs")
            with httpx.Client(timeout=0.25) as probe:
                probe.get(probe_url)
            self.http_client = httpx.Client(timeout=10.0)
        except Exception:
            # Fall back to high-performance in-process DirectClient
            from backend.tests.conftest import DirectClient
            from backend.app.db.database import init_db
            init_db()
            self._direct_client = DirectClient()

    def close(self) -> None:
        if self.http_client is not None and hasattr(self.http_client, "close"):
            self.http_client.close()

    @staticmethod
    def load_scenario_from_file(file_path: Path) -> BenchmarkScenario:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        inputs = [
            InputContextSource(
                source_id=i["source_id"],
                source_type=i["source_type"],
                is_untrusted=i["is_untrusted"],
                content=i["content"],
            )
            for i in data.get("input_context", [])
        ]

        steps = [
            ScriptedStep(
                step_index=s["step_index"],
                timestamp_offset_seconds=float(s.get("timestamp_offset_seconds", 0.0)),
                event_type=s.get("event_type", "tool_call"),
                tool_name=s.get("tool_name"),
                arguments=s.get("arguments", {}),
                records_accessed=int(s.get("records_accessed", 0)),
                is_external_destination=bool(s.get("is_external_destination", False)),
                sender_agent=s.get("sender_agent"),
                recipient_agent=s.get("recipient_agent"),
                message_body=s.get("message_body"),
                output_content=s.get("output_content"),
                expected_step_decision=s.get("expected_step_decision", "allow"),
                expected_triggered_layers=s.get("expected_triggered_layers", []),
            )
            for s in data.get("scripted_steps", [])
        ]

        return BenchmarkScenario(
            id=data["id"],
            name=data["name"],
            category=data["category"],
            split=data["split"],
            owasp_category=data["owasp_category"],
            target_agent=data["target_agent"],
            agent_task=data["agent_task"],
            scenario_start_datetime=data["scenario_start_datetime"],
            weekday=data.get("weekday", "Wednesday"),
            input_context=inputs,
            scripted_steps=steps,
            expected_final_decision=data["expected_final_decision"],
            pass_fail_reason=data["pass_fail_reason"],
            matched_pair_id=data.get("matched_pair_id"),
        )

    def execute_single_call(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        context_sources: List[Dict[str, Any]],
        task_description: str,
        timestamp: datetime,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Sends request through the real gateway and measures high-resolution nanosecond latency.
        """
        payload = {
            "trace_id": f"trc-bench-{uuid.uuid4().hex[:10]}",
            "agent_id": agent_id,
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "context_sources": context_sources,
            "task_description": task_description,
            "timestamp": timestamp.isoformat(),
        }

        t_start = time.perf_counter_ns()
        if self._direct_client is not None:
            res = self._direct_client.post("/api/v1/gateway/execute", json=payload)
            t_end = time.perf_counter_ns()
            res_data = res.json()
        elif self.http_client is not None:
            res = self.http_client.post(self.gateway_url, json=payload)
            t_end = time.perf_counter_ns()
            res_data = res.json()
        else:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(self.gateway_url, json=payload)
                t_end = time.perf_counter_ns()
                res_data = res.json()

        latency_ms = round((t_end - t_start) / 1_000_000.0, 3)
        return res_data, latency_ms

    def replay_scenario(self, scenario: BenchmarkScenario) -> ScenarioExecutionResult:
        """
        Replays a benchmark scenario deterministically with a simulated clock.
        """
        session_id = f"sess-bench-{scenario.id.lower()}-{uuid.uuid4().hex[:6]}"
        start_dt = datetime.fromisoformat(scenario.scenario_start_datetime.replace("Z", "+00:00"))

        step_results: List[StepExecutionResult] = []
        stopped_at_step: Optional[int] = None
        final_decision: str = "allow"
        total_records_leaked: int = 0
        total_records_accessed: int = 0
        step_latencies: List[float] = []

        # Prepare context sources with provenance
        active_context_sources = [
            {
                "source_id": inp.source_id,
                "source_type": inp.source_type,
                "is_untrusted": inp.is_untrusted,
                "snippet": inp.content[:200],
            }
            for inp in scenario.input_context
        ]

        for step in scenario.scripted_steps:
            # Advance simulated clock by offset
            simulated_timestamp = start_dt + timedelta(seconds=step.timestamp_offset_seconds)

            # Only tool_call events are evaluated by gateway
            if step.event_type == "tool_call" and step.tool_name:
                total_records_accessed += step.records_accessed

                # Context sources apply on step 0, subsequent steps inherit session taint
                step_sources = active_context_sources if step.step_index == 0 else []

                gateway_resp, latency_ms = self.execute_single_call(
                    agent_id=scenario.target_agent,
                    session_id=session_id,
                    tool_name=step.tool_name,
                    arguments=step.arguments,
                    context_sources=step_sources,
                    task_description=scenario.agent_task,
                    timestamp=simulated_timestamp,
                )

                step_latencies.append(latency_ms)
                decision = gateway_resp.get("decision", "allow")
                reason = gateway_resp.get("reason", "")
                risk_score = gateway_resp.get("risk_score", 0)

                # Prevention and data leakage tracking
                records_leaked_this_step = 0
                if step.is_external_destination:
                    if decision == "allow":
                        records_leaked_this_step = step.records_accessed
                    elif decision == "require_approval":
                        # Simulated human reviewer default (Deny per benchmark spec)
                        if self.simulated_reviewer_decision == "deny":
                            records_leaked_this_step = 0
                        else:
                            records_leaked_this_step = step.records_accessed
                    else:
                        records_leaked_this_step = 0
                total_records_leaked += records_leaked_this_step

                step_res = StepExecutionResult(
                    step_index=step.step_index,
                    tool_name=step.tool_name,
                    simulated_timestamp=simulated_timestamp.isoformat(),
                    actual_decision=decision,
                    expected_decision=step.expected_step_decision,
                    decision_match=(decision == step.expected_step_decision),
                    latency_ms=latency_ms,
                    risk_score=risk_score,
                    reason=reason,
                    records_accessed=step.records_accessed,
                    records_leaked=records_leaked_this_step,
                )
                step_results.append(step_res)

                # Halt chain on security intervention (block or require_approval)
                if decision in ["block", "require_approval", "would_block"]:
                    final_decision = decision
                    stopped_at_step = step.step_index
                    break
                elif decision == "redact":
                    final_decision = "redact"
                else:
                    final_decision = "allow"

        # Determine overall detection and prevention
        if scenario.category == "attack":
            detected = final_decision != "allow"
            prevented = (total_records_leaked == 0)
        else:
            detected = False  # benign
            prevented = True

        decision_match = (final_decision == scenario.expected_final_decision)

        return ScenarioExecutionResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            category=scenario.category,
            split=scenario.split,
            target_agent=scenario.target_agent,
            expected_decision=scenario.expected_final_decision,
            actual_final_decision=final_decision,
            decision_match=decision_match,
            detected=detected,
            prevented=prevented,
            stopped_at_step=stopped_at_step,
            total_steps=len(step_results),
            total_latency_ms=round(sum(step_latencies), 3),
            step_latencies_ms=step_latencies,
            total_records_accessed=total_records_accessed,
            total_records_leaked=total_records_leaked,
            step_results=step_results,
        )
