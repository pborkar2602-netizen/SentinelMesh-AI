import sys
sys.path.insert(0, ".")
from pathlib import Path
from backend.app.core.policy_engine import PolicyEngine
from benchmark.harness.runner import BenchmarkRunner

DEV_DIR = Path("benchmark/scenarios/dev")
scenario_files = sorted(list(DEV_DIR.glob("*.json")))

runner = BenchmarkRunner()

thresholds = [20, 30, 40, 50, 60, 70, 80]

print("=" * 85)
print("BASELINE ACTION THRESHOLD SWEEP (Thresholds 20 to 80)")
print("Suite: All 36 Dev Scenarios (20 Attacks, 16 Benign; matching benchmark_report.json)")
print("=" * 85)
print(f"{'Threshold':<10} | {'Attacks Det':<14} | {'Det Rate':<10} | {'Benign FP':<12} | {'FP Rate':<10} | {'Match Rate':<10}")
print("-" * 85)

for thresh in thresholds:
    PolicyEngine.set_anomaly_threshold(thresh)
    
    attack_count = 0
    attack_detected = 0
    benign_count = 0
    benign_fp = 0
    matches = 0
    total = len(scenario_files)
    
    for f in scenario_files:
        sc = runner.load_scenario_from_file(f)
        res = runner.replay_scenario(sc)
        if sc.category == "attack":
            attack_count += 1
            if res.detected:
                attack_detected += 1
        else:
            benign_count += 1
            # FP: benign blocked or required approval
            if res.actual_final_decision != "allow" and res.actual_final_decision != sc.expected_final_decision:
                benign_fp += 1
        if res.decision_match:
            matches += 1
            
    det_rate = (attack_detected / attack_count) * 100
    fp_rate = (benign_fp / benign_count) * 100
    match_rate = (matches / total) * 100
    print(f"{thresh:<10} | {attack_detected:>2}/{attack_count:<11} | {det_rate:>8.1f}% | {benign_fp:>2}/{benign_count:<9} | {fp_rate:>8.1f}% | {match_rate:>8.1f}%")

# Reset to default
PolicyEngine.set_anomaly_threshold(70)
print("=" * 85)
