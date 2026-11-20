import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Query, Header, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.api.auth import require_control_plane_auth
from backend.app.core.policy_engine import PolicyEngine
from backend.app.db.database import get_connection, list_audit_events
from backend.app.detection.rules import (
    Finding,
    APPROVED_EMAIL_DOMAINS,
    APPROVED_API_DOMAINS,
    load_policy_config,
)

router = APIRouter(prefix="/policies", tags=["Policies"])

class ModeUpdate(BaseModel):
    mode: str = Field(..., description="'enforce' or 'monitor'")

class SimulationRequest(BaseModel):
    limit: int = Field(default=50, ge=1, le=500, description="Number of recent audit events to replay")
    simulated_mode: str = Field(default="enforce", description="Policy mode to simulate: enforce or monitor")
    high_sensitivity_action: Optional[str] = Field(default=None, description="Simulate changed high sensitivity policy (require_approval vs redact)")

@router.get("/config")
def get_policy_config():
    """Returns declarative policy-as-code configuration alongside runtime mode."""
    cfg = load_policy_config()
    return {
        "version": cfg.get("version", "3.4.0"),
        "policy_pack": cfg.get("policy_pack", "sentinelmesh-enterprise-default"),
        "mode": PolicyEngine.get_mode(),
        "anomaly_threshold": PolicyEngine._anomaly_threshold,
        "high_sensitivity_external_action": PolicyEngine._high_sensitivity_external_action,
        "approved_email_domains": APPROVED_EMAIL_DOMAINS,
        "approved_api_domains": APPROVED_API_DOMAINS,
        "active_layers": cfg.get("active_layers", []),
    }

@router.get("/mode")
def get_policy_mode():
    return {"mode": PolicyEngine.get_mode()}

@router.post("/mode")
def set_policy_mode(
    payload: ModeUpdate,
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    require_control_plane_auth(authorization)
    updated = PolicyEngine.set_mode(payload.mode)
    return {"mode": updated}

@router.get("/simulation/stats")
def get_simulation_stats(exclude_benchmark: bool = Query(True)):
    """
    Returns live metrics on monitored vs enforced policies,
    including the counter of 'would have blocked N actions' in monitor mode.
    """
    conn = get_connection()
    base_query = (
        "SELECT decision, COUNT(*) as cnt FROM audit_events "
        "WHERE source != 'benchmark' AND session_id NOT LIKE 'sess-bench-%' AND session_id NOT LIKE 'sess-lat-%' AND tool_name != 'tool_return' "
        "GROUP BY decision"
        if exclude_benchmark
        else "SELECT decision, COUNT(*) as cnt FROM audit_events WHERE tool_name != 'tool_return' GROUP BY decision"
    )
    cur = conn.execute(base_query)
    rows = cur.fetchall()

    counts = {r["decision"]: int(r["cnt"]) for r in rows}
    total_events = sum(counts.values())

    return {
        "current_mode": PolicyEngine.get_mode(),
        "total_events": total_events,
        "would_block_count": counts.get("would_block", 0),
        "blocked_count": counts.get("block", 0),
        "block_count": counts.get("block", 0),
        "allowed_count": counts.get("allow", 0),
        "allow_count": counts.get("allow", 0),
        "require_approval_count": counts.get("require_approval", 0),
        "redacted_count": counts.get("redact", 0),
        "redact_count": counts.get("redact", 0),
        "breakdown": counts
    }

@router.post("/simulate")
def simulate_policy_reevaluation(
    req: SimulationRequest,
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Replays the last N stored events against a simulated policy configuration
    using immutable per-call overrides (zero global state mutation under concurrency).
    """
    require_control_plane_auth(authorization)
    events = list_audit_events(limit=req.limit, order="desc", exclude_benchmark=True, exclude_tool_return=True)
    if not events:
        return {
            "events_replayed": 0,
            "decisions_changed": 0,
            "simulated_mode": req.simulated_mode,
            "simulated_distribution": {"allow": 0, "block": 0, "would_block": 0, "require_approval": 0, "redact": 0},
            "decision_changes": [],
            "changes": []
        }

    changes = []
    sim_dist: Dict[str, int] = {"allow": 0, "block": 0, "would_block": 0, "require_approval": 0, "redact": 0}
    from backend.app.detection.rules import run_all_detectors

    for ev in events:
        trace_id = ev["trace_id"]
        tool_name = ev["tool_name"]
        arguments = ev["arguments"]
        orig_decision = ev["decision"]
        risk_score = ev.get("risk_score", 0)
        risk_breakdown = ev.get("risk_breakdown", {})

        # Reconstruct context signals
        is_tainted = bool(
            risk_breakdown.get("untrusted_taint", 0) > 0 or
            "tainted" in ev.get("reason", "").lower()
        )
        # Re-run rule detectors on arguments and context sources
        context_sources = ev.get("context_sources", [])
        findings = run_all_detectors(tool_name=tool_name, arguments=arguments, context_sources=context_sources)

        anomaly_score = risk_breakdown.get("baseline_anomaly", 0)
        anomaly_reasons = risk_breakdown.get("anomaly_reasons", [])

        sim_decision, sim_reason = PolicyEngine.evaluate_policy(
            tool_name=tool_name,
            arguments=arguments,
            is_tainted=is_tainted,
            tainted_by=["replayed_session_context"] if is_tainted else [],
            findings=findings,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            anomaly_reasons=anomaly_reasons,
            mode_override=req.simulated_mode,
            high_sensitivity_action_override=req.high_sensitivity_action,
        )
        sim_dist[sim_decision] = sim_dist.get(sim_decision, 0) + 1

        if sim_decision != orig_decision:
            changes.append({
                "trace_id": trace_id,
                "agent_id": ev["agent_id"],
                "tool_name": tool_name,
                "original_decision": orig_decision,
                "simulated_decision": sim_decision,
                "simulated_reason": sim_reason,
                "reason": sim_reason,
            })

    return {
        "events_replayed": len(events),
        "decisions_changed": len(changes),
        "simulated_mode": req.simulated_mode,
        "simulated_distribution": sim_dist,
        "decision_changes": changes,
        "changes": changes
    }
