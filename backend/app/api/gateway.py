import os
import time
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, status, Header
from pydantic import BaseModel
from typing import Optional

from backend.app.schemas.gateway import ToolCallRequest, GatewayDecisionResponse
from backend.app.core.gateway import GatewayCore
from backend.app.core.tool_proxy import ToolProxy
from backend.app.api.websocket import ws_manager
from backend.app.db.database import (
    get_connection,
    set_request_connection,
    reset_request_connection,
    get_agent,
    save_agent,
    get_session,
    save_session,
    save_audit_event,
    record_tool_return_event,
    update_session_event_return,
    list_session_events,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["Gateway"])


@router.post("/execute", response_model=GatewayDecisionResponse, status_code=status.HTTP_200_OK)
def execute_tool_call(
    request: ToolCallRequest,
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
) -> GatewayDecisionResponse:
    start_time = time.perf_counter()

    # 0. Perimeter Defense-in-Depth checks
    from backend.app.core.defense_in_depth import (
        verify_agent_perimeter_auth,
        RateLimiter,
        enforce_payload_caps,
        PrometheusMetrics,
    )
    verify_agent_perimeter_auth(request.agent_id, x_agent_key)
    enforce_payload_caps(request.arguments, request.context_sources)
    RateLimiter.get_instance().check_rate_limit(request.agent_id)
    RateLimiter.get_instance().check_rate_limit(request.session_id)

    req_conn = get_connection()
    token = set_request_connection(req_conn)
    try:
        # 1 & 2. Ensure Agent and Session exist
        t_db_start = time.perf_counter()
        agent = get_agent(request.agent_id)
        if not agent:
            save_agent({
                "id": request.agent_id,
                "name": request.agent_id.replace("-", " ").title(),
                "role": "Autonomous AI Agent",
                "declared_purpose": "Operates authorized enterprise tools",
                "allowed_tools": [request.tool_name],
                "created_at": datetime.now(timezone.utc).isoformat()
            })

        session = get_session(request.session_id)
        if not session:
            save_session({
                "id": request.session_id,
                "agent_id": request.agent_id,
                "task_description": request.task_description or "Autonomous session execution",
                "status": "ACTIVE",
                "is_tainted": False,
                "tainted_by": [],
                "started_at": datetime.now(timezone.utc).isoformat()
            })
        db_write_ms = round((time.perf_counter() - t_db_start) * 1000, 3)

        # 3. Core Gateway Evaluation Pipeline (Trust Labeling + Taint + Rules + Risk + Policy)
        decision, reason, risk_score, risk_breakdown, normalized_sources, findings = GatewayCore.evaluate(request)

        # 4. Milestone 4 Privacy Engine: Session-Consistent Tokenization & Pre-Logging Masking
        t_mask_start = time.perf_counter()
        from backend.app.privacy.masker import PrivacyEngine
        masked_arguments, _ = PrivacyEngine.mask_payload(request.session_id, request.arguments)
        masked_sources, _ = PrivacyEngine.mask_payload(request.session_id, [c.model_dump() for c in normalized_sources])
        # 5. Measure masking latency & record DB/masking timings
        masking_ms = round((time.perf_counter() - t_mask_start) * 1000, 3)
        stage_timings = risk_breakdown.setdefault("stage_timings_ms", {})
        stage_timings["db_session_lookup"] = db_write_ms
        stage_timings["masking"] = masking_ms

        # 5b. Proxy Execution Mode (Gateway executes tool adapter directly and measures return counts)
        from backend.app.config import settings
        is_proxy = (
            bool(request.proxy_execution)
            if request.proxy_execution is not None
            else bool(getattr(settings, "PROXY_TOOL_EXECUTION", False))
        )
        tool_output = None
        measured_records_returned = None

        if is_proxy and decision in ("allow", "redact", "would_block"):
            exec_args = masked_arguments if decision == "redact" else request.arguments
            tool_output, measured_records_returned = ToolProxy.execute_tool(request.tool_name, exec_args)
            risk_breakdown["records_returned"] = measured_records_returned
            risk_breakdown["return_count_source"] = "gateway_proxy"

            # Re-verify behavioral baseline against the real gateway-measured tool result
            if settings.ENABLE_BASELINE_ANOMALY and measured_records_returned > 0:
                from backend.app.baseline.anomaly_detector import AnomalyDetector
                from backend.app.core.policy_engine import PolicyEngine
                session_events = list_session_events(request.session_id, conn=req_conn)
                post_anom_score, post_anom_reasons, post_anom_bd = AnomalyDetector.evaluate(
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    arguments=request.arguments,
                    session_events=session_events,
                    sim_datetime=request.timestamp,
                    tool_result=tool_output,
                    ignore_agent_claimed_count=True,
                )
                if post_anom_score > 0:
                    risk_breakdown["baseline_anomaly"] = post_anom_score
                    risk_breakdown["anomaly_reasons"] = post_anom_reasons
                    risk_breakdown["anomaly_breakdown"] = post_anom_bd
                    risk_score = max(risk_score, post_anom_score)

                if post_anom_score >= PolicyEngine._anomaly_threshold and settings.ENABLE_POLICY_ENGINE:
                    anom_str = "; ".join(post_anom_reasons[:2]) if post_anom_reasons else "Significant behavioral outlier"
                    if PolicyEngine.get_mode() == "enforce":
                        decision = "require_approval"
                        reason = f"Baseline Anomaly Policy (Gateway Proxy Measurement): Behavioral deviation detected ({anom_str}). Action requires human approval."
                        from backend.app.approvals.service import ApprovalService
                        from backend.app.approvals.reviewer import SimulatedReviewer
                        appr = ApprovalService.create_approval_request(
                            session_id=request.session_id,
                            trace_id=request.trace_id,
                            agent_id=request.agent_id,
                            tool_name=request.tool_name,
                            arguments=request.arguments,
                            reason=reason,
                            risk_score=risk_score,
                        )
                        risk_breakdown["approval_id"] = appr["id"]
                        if SimulatedReviewer.is_active():
                            sim_res = SimulatedReviewer.evaluate_and_resolve(
                                approval_id=appr["id"],
                                tool_name=request.tool_name,
                                arguments=request.arguments,
                            )
                            if sim_res and sim_res["status"] == "denied":
                                decision = "block"
                                reason = f"Simulated reviewer denied human approval request [{appr['id']}]: {sim_res.get('resolution_reason')}"
                            elif sim_res and sim_res["status"] == "approved":
                                decision = "allow"
                                reason = f"Simulated reviewer approved human approval request [{appr['id']}]."
                        else:
                            reason = f"{reason} (Approval Request ID: {appr['id']})"
                        if decision in ("require_approval", "block"):
                            tool_output = None
                    else:
                        decision = "would_block"
                        reason = f"Baseline Anomaly Alert [MONITOR MODE]: Outlier behavior detected ({anom_str})."

        is_benchmark_mode = (
            os.getenv("BENCHMARK_MODE", "").lower() in ("true", "1", "yes") or
            os.getenv("SENTINEL_BENCHMARK_MODE", "").lower() in ("true", "1", "yes")
        )
        now_utc = datetime.now(timezone.utc)
        if is_benchmark_mode and hasattr(request, "timestamp") and request.timestamp:
            event_dt = request.timestamp
            event_dt_iso = event_dt if isinstance(event_dt, str) else event_dt.isoformat()
        else:
            # In normal/production mode: server-assigned timestamp always enforced; agent-supplied timestamp ignored
            event_dt_iso = now_utc.isoformat()

        # 6. Persist to Append-Only Audit Log with SHA-256 Hash Chaining (COVERING ONLY MASKED DATA)
        t_hash_start = time.perf_counter()
        prelim_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        event_dict = {
            "trace_id": request.trace_id,
            "agent_id": request.agent_id,
            "session_id": request.session_id,
            "tool_name": request.tool_name,
            "arguments": masked_arguments,
            "context_sources": masked_sources,
            "decision": decision,
            "reason": reason,
            "risk_score": risk_score,
            "risk_breakdown": risk_breakdown,
            "latency_ms": prelim_latency_ms,
            "timestamp": event_dt_iso
        }
        event_id, event_hash = save_audit_event(event_dict)
        if is_proxy and decision in ("allow", "redact", "would_block") and measured_records_returned is not None:
            record_tool_return_event(
                session_id=request.session_id,
                trace_id=request.trace_id,
                records_returned=measured_records_returned,
                conn=req_conn,
                source="gateway_proxy",
            )
        hash_chain_ms = round((time.perf_counter() - t_hash_start) * 1000, 3)
        stage_timings["hash_chain"] = hash_chain_ms

        # 7. Broadcast event over WebSocket to live dashboard
        t_ws_start = time.perf_counter()
        broadcast_payload = {
            "type": "AUDIT_EVENT",
            "id": event_id,
            "event_hash": event_hash,
            "findings": [f.__dict__ for f in findings],
            **event_dict
        }
        ws_manager.broadcast_sync(broadcast_payload)
        ws_broadcast_ms = round((time.perf_counter() - t_ws_start) * 1000, 3)
        stage_timings["ws_broadcast"] = ws_broadcast_ms

        # 8. Milestone 3 Attack Chain Reconstruction & Incident Builder
        t_inc_start = time.perf_counter()
        from backend.app.core.incident_builder import IncidentBuilder
        incident = IncidentBuilder.process_event(event_dict, findings)
        if incident:
            ws_manager.broadcast_sync({
                "type": "INCIDENT_ALERT",
                "incident": incident
            })
        incident_builder_ms = round((time.perf_counter() - t_inc_start) * 1000, 3)
        stage_timings["incident_builder"] = incident_builder_ms

        # In the audit log and dashboard event feed: decision is 'would_block'
        # But to the calling agent: gateway returns 'allow' so execution continues
        agent_decision = "allow" if decision == "would_block" else decision
        redacted_arguments = masked_arguments if decision == "redact" else None

        # 9. Response serialization & total latency
        total_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sum_measured = sum(stage_timings.values())
        response_serialization_ms = round(max(0.001, total_latency_ms - sum_measured), 3)
        stage_timings["response_serialization"] = response_serialization_ms

        PrometheusMetrics.record_decision(decision, total_latency_ms, findings)

        return GatewayDecisionResponse(
            trace_id=request.trace_id,
            agent_id=request.agent_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            decision=agent_decision,
            reason=reason,
            risk_score=risk_score,
            risk_breakdown=risk_breakdown,
            latency_ms=total_latency_ms,
            timestamp=now_utc,
            event_hash=event_hash,
            redacted_arguments=redacted_arguments,
            approval_id=risk_breakdown.get("approval_id"),
            tool_output=tool_output,
            measured_records_returned=measured_records_returned,
        )
    finally:
        reset_request_connection(token)


class ToolReturnRequest(BaseModel):
    session_id: str
    trace_id: str | None = None
    records_returned: int = 0


@router.post("/tool-return", status_code=status.HTTP_200_OK)
def report_tool_return(req: ToolReturnRequest):
    """
    Legacy endpoint for agent-reported tool return row counts.
    If the gateway already measured the return count in proxy execution mode,
    the agent's self-reported count is ignored and the authoritative gateway count is preserved.
    """
    res = update_session_event_return(
        session_id=req.session_id,
        trace_id=req.trace_id,
        records_returned=req.records_returned
    )
    status_str = "ok" if res.get("accepted", True) else "ignored_in_proxy_mode"
    return {"status": status_str, **res}
