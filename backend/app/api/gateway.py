import os
import time
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, status

from backend.app.schemas.gateway import ToolCallRequest, GatewayDecisionResponse
from backend.app.core.gateway import GatewayCore
from backend.app.api.websocket import ws_manager
from backend.app.db.database import (
    get_connection,
    set_request_connection,
    reset_request_connection,
    get_agent,
    save_agent,
    get_session,
    save_session,
    save_audit_event
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["Gateway"])

@router.post("/execute", response_model=GatewayDecisionResponse, status_code=status.HTTP_200_OK)
def execute_tool_call(request: ToolCallRequest) -> GatewayDecisionResponse:
    start_time = time.perf_counter()
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

        import os
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
            "latency_ms": 0.0,
            "timestamp": event_dt_iso
        }
        event_id, event_hash = save_audit_event(event_dict)
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
            approval_id=risk_breakdown.get("approval_id")
        )
    finally:
        reset_request_connection(token)
        req_conn.close()
