import cProfile
import pstats
import io
import sys
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.schemas.gateway import ToolCallRequest
from backend.app.core.gateway import GatewayCore
from backend.app.core.incident_builder import IncidentBuilder
from backend.app.db.database import init_db, get_connection, save_audit_event, get_session, save_session

def profile_gateway_calls(num_calls: int = 100):
    init_db()
    profiler = cProfile.Profile()
    
    # Warm up
    session_id = f"sess-prof-{uuid.uuid4().hex[:6]}"
    save_session({
        "id": session_id,
        "agent_id": "hr-agent",
        "task_description": "Profile session",
        "status": "ACTIVE",
        "is_tainted": False,
        "tainted_by": [],
        "started_at": datetime.now(timezone.utc).isoformat()
    })
    
    print(f"Profiling {num_calls} gateway evaluations with cProfile...")
    profiler.enable()
    t0 = time.perf_counter()
    
    sql_counts = {"select": 0, "insert": 0, "commit": 0}
    
    for i in range(num_calls):
        req = ToolCallRequest(
            trace_id=f"trc-prof-{i}",
            agent_id="hr-agent",
            session_id=session_id,
            tool_name="db_query",
            arguments={"query": f"SELECT employee_id, full_name FROM employees WHERE employee_id={i}"},
            context_sources=[],
            task_description="Profile query execution",
            timestamp=datetime.now(timezone.utc)
        )
        decision, reason, score, bd, norm, findings = GatewayCore.evaluate(req)
        
        # Save audit event
        event_dict = {
            "trace_id": req.trace_id,
            "agent_id": req.agent_id,
            "session_id": req.session_id,
            "tool_name": req.tool_name,
            "arguments": req.arguments,
            "context_sources": [],
            "decision": decision,
            "reason": reason,
            "risk_score": score,
            "risk_breakdown": bd,
            "latency_ms": 0.0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        save_audit_event(event_dict)
        IncidentBuilder.process_event(event_dict, findings)
        
    t1 = time.perf_counter()
    profiler.disable()
    
    total_time_ms = (t1 - t0) * 1000.0
    avg_per_call_ms = total_time_ms / num_calls
    print(f"\nExecution complete: {total_time_ms:.2f} ms total, {avg_per_call_ms:.2f} ms per call")
    
    s = io.StringIO()
    ps = pstats.Stats(profiler, stream=s).sort_stats("cumulative")
    ps.print_stats(25)
    print("\n--- cProfile Cumulative Top 25 ---")
    print(s.getvalue())

if __name__ == "__main__":
    profile_gateway_calls(100)
