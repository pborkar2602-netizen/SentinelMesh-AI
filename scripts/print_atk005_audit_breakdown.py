import sys
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmark.harness.runner import BenchmarkRunner
from backend.app.db.database import get_connection

runner = BenchmarkRunner()
sc = runner.load_scenario_from_file(Path("benchmark/scenarios/dev/atk_005.json"))

conn = get_connection()

sc_res = runner.replay_scenario(sc)
cur = conn.execute("SELECT session_id FROM audit_events WHERE session_id LIKE 'sess-bench-atk-005-%' ORDER BY id DESC LIMIT 1")
row = cur.fetchone()
latest_session_id = row["session_id"] if row else None

# Retrieve actual recorded audit rows for this single session
cur = conn.execute(
    "SELECT id, trace_id, tool_name, decision, risk_score, risk_breakdown FROM audit_events WHERE session_id = ? ORDER BY id ASC",
    (latest_session_id,)
)
rows = cur.fetchall()

print(f"Session ID: {latest_session_id}")
print(f"Total audit rows recorded for this run of ATK-005: {len(rows)}")
for idx, r in enumerate(rows):
    print(f"\n=== ROW {idx} (id={r['id']}, tool={r['tool_name']}, decision={r['decision']}, risk_score={r['risk_score']}) ===")
    rb = json.loads(r["risk_breakdown"])
    print(json.dumps(rb, indent=2))
