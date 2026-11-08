import time
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, status

from backend.app.schemas.gateway import ToolCallRequest, GatewayDecisionResponse
from backend.app.core.gateway import GatewayCore
from backend.app.api.websocket import ws_manager
from backend.app.db.database import get_agent, save_agent, get_session, save_session, save_audit_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["Gateway"])

@router.post("/execute", response_model=GatewayDecisionResponse, status_code=status.HTTP_200_OK)
def execute_tool_call(request: ToolCallRequest) -> GatewayDecisionResponse:
    start_time = time.perf_counter()

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
    masking_ms = round((time.perf_counter() - t_mask_start) * 1000, 3)

    # 5. Measure gateway analysis latency
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    now_utc = datetime.now(timezone.utc)

    # 6. Persist to Append-Only Audit Log with SHA-256 Hash Chaining (COVERING ONLY MASKED DATA)
    t_hash_start = time.perf_counter()
    stage_timings = risk_breakdown.setdefault("stage_timings_ms", {})
    stage_timings["db_write"] = db_write_ms
    stage_timings["masking"] = masking_ms

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
        "latency_ms": latency_ms,
        "timestamp": now_utc.isoformat()
    }
    event_id, event_hash = save_audit_event(event_dict)
    hash_chain_ms = round((time.perf_counter() - t_hash_start) * 1000, 3)
    stage_timings["hash_chain"] = hash_chain_ms

    # 7. Broadcast event over WebSocket to live dashboard
    broadcast_payload = {
        "type": "AUDIT_EVENT",
        "id": event_id,
        "event_hash": event_hash,
        "findings": [f.__dict__ for f in findings],
        **event_dict
    }
    ws_manager.broadcast_sync(broadcast_payload)

    # 8. Milestone 3 Attack Chain Reconstruction & Incident Builder
    from backend.app.core.incident_builder import IncidentBuilder
    incident = IncidentBuilder.process_event(event_dict, findings)
    if incident:
        ws_manager.broadcast_sync({
            "type": "INCIDENT_ALERT",
            "incident": incident
        })

    # In the audit log and dashboard event feed: decision is 'would_block'
    # But to the calling agent: gateway returns 'allow' so execution continues
    agent_decision = "allow" if decision == "would_block" else decision
    redacted_arguments = masked_arguments if decision == "redact" else None

    return GatewayDecisionResponse(
        trace_id=request.trace_id,
        agent_id=request.agent_id,
        session_id=request.session_id,
        tool_name=request.tool_name,
        decision=agent_decision,
        reason=reason,
        risk_score=risk_score,
        risk_breakdown=risk_breakdown,
        latency_ms=latency_ms,
        timestamp=now_utc,
        event_hash=event_hash,
        redacted_arguments=redacted_arguments,
        approval_id=risk_breakdown.get("approval_id")
    )
