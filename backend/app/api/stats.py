import os
import threading
import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, Query, HTTPException, status

from backend.app.api.auth import is_demo_mode
from backend.app.core.policy_engine import PolicyEngine
from backend.app.db.database import get_dashboard_stats
from backend.app.api.websocket import ws_manager

logger = logging.getLogger("sentinelmesh.demo")
router = APIRouter(tags=["Dashboard Stats & Demo"])


@router.get("/stats", response_model=Dict[str, Any])
def read_dashboard_stats(
    exclude_benchmark: bool = Query(True, description="Exclude benchmark/latency harness events from dashboard stats")
) -> Dict[str, Any]:
    """
    Returns unified, authoritative totals computed directly from the database
    for every counter on the SentinelMesh dashboard.
    """
    stats = get_dashboard_stats(exclude_benchmark=exclude_benchmark)
    demo_mode = is_demo_mode()
    stats["policy_mode"] = PolicyEngine.get_mode()
    stats["demo_mode"] = demo_mode
    return stats


@router.post("/demo/reset", response_model=Dict[str, Any])
def reset_demo_database() -> Dict[str, Any]:
    """
    Resets the demo database to the clean seed state (8 benign allowed calls,
    3 blocked attacks, 1 pending approval, 0 false positives).
    """
    if not is_demo_mode():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo endpoints are disabled outside DEMO_MODE."
        )
    from scripts.demo_reset import seed_clean_demo_db

    res = seed_clean_demo_db()
    ws_manager.broadcast_sync({"type": "DEMO_RESET", "stats": res.get("stats")})
    return res


@router.post("/demo/run_attack", response_model=Dict[str, Any])
def run_live_attack_demo(
    mode: Optional[str] = Query(None, description="Policy mode: enforce or monitor"),
    scenario: Optional[str] = Query("atk-001", description="Scenario: atk-001 (HR Poisoned Resume), atk-002 (Finance Wire Fraud), atk-003 (Ops Cloud SSRF)")
) -> Dict[str, Any]:
    """
    Runs the live demo agent scenario against the real gateway inline.
    Events are logged to the database and broadcasted live via WebSocket to the dashboard.
    """
    if not is_demo_mode():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo endpoints are disabled outside DEMO_MODE."
        )
    if mode in ("enforce", "monitor"):
        PolicyEngine.set_mode(mode)

    active_mode = PolicyEngine.get_mode()
    selected_scenario = (scenario or "atk-001").lower()

    def _worker():
        try:
            gateway_endpoint = os.getenv("SENTINEL_GATEWAY_URL", "http://127.0.0.1:8000/api/v1/gateway/execute")
            if selected_scenario == "atk-002":
                from demo_agents.agent_runner import run_finance_attack_scenario
                run_finance_attack_scenario(gateway_url=gateway_endpoint, delay=0.35)
            elif selected_scenario == "atk-003":
                from demo_agents.agent_runner import run_ops_attack_scenario
                run_ops_attack_scenario(gateway_url=gateway_endpoint, delay=0.35)
            elif selected_scenario == "ben-001":
                from demo_agents.agent_runner import run_benign_scenario
                run_benign_scenario(gateway_url=gateway_endpoint, delay=0.35)
            else:
                from demo_agents.agent_runner import run_attack_scenario
                run_attack_scenario(gateway_url=gateway_endpoint, delay=0.35)
        except Exception as e:
            logger.warning(f"Error running demo attack scenario: {e}")

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    return {
        "status": "started",
        "policy_mode": active_mode,
        "scenario": selected_scenario,
        "message": f"Live scenario {selected_scenario.upper()} triggered in {active_mode} mode"
    }

