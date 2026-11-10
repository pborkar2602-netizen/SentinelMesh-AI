import sys
sys.path.insert(0, ".")
from pathlib import Path
from benchmark.harness.runner import BenchmarkRunner

runner = BenchmarkRunner()

scenarios = [
    "ATK-008", "ATK-009", "ATK-010", "ATK-013",
    "ATK-001", "ATK-002", "ATK-005", "ATK-011",
    "BEN-003"
]

print("=" * 105)
print("PER-STEP DECISION AND RECORD COUNTING BREAKDOWN (RAW RUNNER OUTPUT)")
print("=" * 105)

for sid in scenarios:
    file_path = list(Path("benchmark/scenarios/dev").glob(f"{sid.lower().replace('-', '_')}*.json"))
    if not file_path:
        # Try alternate glob
        file_path = list(Path("benchmark/scenarios/dev").glob(f"*{sid.lower().split('-')[1]}*.json"))
    p = file_path[0]
    sc = runner.load_scenario_from_file(p)
    res = runner.replay_scenario(sc)
    
    print(f"\nScenario: [{res.scenario_id}] {res.scenario_name} (Category: {res.category}, Expected: {res.expected_decision}, Actual: {res.actual_final_decision})")
    print(f"Summary: Exposed to Agent: {res.total_records_exposed_to_agent} | Exfiltrated: {res.total_records_exfiltrated} | Authorized Egress: {res.total_authorized_external_egress} | Total Accessed: {res.total_records_accessed}")
    print("-" * 105)
    print(f"  {'Step':<5} | {'Tool':<15} | {'Decision':<16} | {'Scripted Rec':<13} | {'Exposed':<8} | {'Exfil':<6} | {'AuthEgress':<10} | {'Reason'}")
    print("-" * 105)
    for st in res.step_results:
        print(f"  {st.step_index:<5} | {st.tool_name:<15} | {st.actual_decision:<16} | {st.records_accessed:<13} | {st.records_exposed_to_agent:<8} | {st.records_exfiltrated:<6} | {st.authorized_external_egress:<10} | {st.reason[:50]}")
