import os
import sys
import json
import subprocess
from pathlib import Path

# Paths
V3_ROOT = Path("E:/Sentinel AI").resolve()
V2_ROOT = Path("E:/sentinel-v2-frozen").resolve()

# Script to run inside each directory
RUNNER_CODE = """
import os
import sys
import json
from pathlib import Path

sys.path.insert(0, os.getcwd())
os.environ["SENTINEL_BENCHMARK_MODE"] = "true"
os.environ["SENTINEL_BENCHMARK_DB_PATH"] = "./benchmark_temp.db"

# Remove any existing temp db
if os.path.exists("./benchmark_temp.db"):
    try:
        os.remove("./benchmark_temp.db")
    except Exception:
        pass

from benchmark.harness.runner import BenchmarkRunner

splits = ["dev", "dev_v1_heldout", "held_out_v2"]
runner = BenchmarkRunner()

results = {}

for split in splits:
    split_dir = Path("benchmark/scenarios") / split
    if not split_dir.exists():
        continue
    scenarios = sorted(split_dir.glob("*.json"))
    for sc_file in scenarios:
        sc = runner.load_scenario_from_file(sc_file)
        res = runner.replay_scenario(sc)
        results[sc.id] = {
            "name": sc.name,
            "split": split,
            "category": sc.category,
            "final_decision": res.actual_final_decision,
            "decision_match": res.decision_match,
            "expected_final_decision": sc.expected_final_decision,
            "step_decisions": [s.actual_decision for s in res.step_results],
        }

runner.close()
if os.path.exists("./benchmark_temp.db"):
    try:
        os.remove("./benchmark_temp.db")
    except Exception:
        pass

print(json.dumps(results))
"""

def run_in_dir(target_dir: Path):
    cmd = [sys.executable, "-c", RUNNER_CODE]
    res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error in {target_dir}:", res.stderr)
        raise RuntimeError(f"Failed running in {target_dir}")
    
    # parse the last line of stdout which contains json
    stdout_lines = res.stdout.strip().splitlines()
    for line in reversed(stdout_lines):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)
    raise ValueError(f"Could not find JSON output in stdout from {target_dir}:\n{res.stdout}")

def main():
    print("Running scenarios on HEAD (v3)...")
    v3_results = run_in_dir(V3_ROOT)
    
    print("Running scenarios on rules-v2-frozen...")
    v2_results = run_in_dir(V2_ROOT)
    
    all_scenarios = sorted(set(list(v3_results.keys()) + list(v2_results.keys())))
    
    print("\\n" + "=" * 90)
    print(f"{'SCENARIO ID':<18} | {'SPLIT':<15} | {'EXPECTED':<10} | {'V2 DECISION':<12} | {'V3 DECISION':<12} | {'DIFF?'}")
    print("=" * 90)
    
    diff_count = 0
    splits_count = {"dev": 0, "dev_v1_heldout": 0, "held_out_v2": 0}
    
    for sc_id in all_scenarios:
        v2 = v2_results.get(sc_id, {})
        v3 = v3_results.get(sc_id, {})
        
        split = v3.get("split") or v2.get("split")
        if split in splits_count:
            splits_count[split] += 1
            
        exp = v3.get("expected_final_decision") or v2.get("expected_final_decision")
        v2_dec = v2.get("final_decision", "MISSING")
        v3_dec = v3.get("final_decision", "MISSING")
        
        diff = "DIFF" if v2_dec != v3_dec else "MATCH"
        if diff == "DIFF":
            diff_count += 1
            
        print(f"{sc_id:<18} | {split:<15} | {exp:<10} | {v2_dec:<12} | {v3_dec:<12} | {diff}")
    
    print("=" * 90)
    print(f"Total Scenarios: {len(all_scenarios)} ({splits_count})")
    print(f"Total Decision Differences: {diff_count}")
    print("=" * 90)

if __name__ == "__main__":
    main()
