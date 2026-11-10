import sys
sys.path.insert(0, ".")
from pathlib import Path
from backend.app.config import settings
from benchmark.harness.runner import BenchmarkRunner

DEV_DIR = Path("benchmark/scenarios/dev")
scenario_files = sorted(list(DEV_DIR.glob("*.json")))

runner = BenchmarkRunner()

def reset_all_flags():
    settings.ENABLE_RULE_DETECTOR = True
    settings.ENABLE_PRIVACY_MODULE = True
    settings.ENABLE_TAINT_TRACKER = True
    settings.ENABLE_BASELINE_ANOMALY = True
    settings.ENABLE_INTENT_JUDGE = True

def run_configuration(config_name: str, description: str):
    attack_count = 0
    attack_detected = 0
    benign_count = 0
    benign_fp = 0
    decision_matches = 0
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
            if res.actual_final_decision != "allow" and res.actual_final_decision != sc.expected_final_decision:
                benign_fp += 1
        if res.decision_match:
            decision_matches += 1
            
    det_rate = (attack_detected / attack_count) * 100.0 if attack_count else 0.0
    fp_rate = (benign_fp / benign_count) * 100.0 if benign_count else 0.0
    match_rate = (decision_matches / total) * 100.0 if total else 0.0
    
    return {
        "config": config_name,
        "description": description,
        "attack_detected": attack_detected,
        "attack_count": attack_count,
        "det_rate": det_rate,
        "benign_fp": benign_fp,
        "benign_count": benign_count,
        "fp_rate": fp_rate,
        "matches": decision_matches,
        "total": total,
        "match_rate": match_rate,
    }

print("=" * 110)
print("PART 1: CUMULATIVE SIX-LAYER ABLATION SWEEP (docs/benchmark_spec.md Section 7)")
print("Suite: All 32 Dev Scenarios (20 Attacks, 12 Benign; matching benchmark_report.json)")
print("Note: Judge is running in offline test stub mode (judge stub: deterministic cassettes, not real LLM)")
print("=" * 110)
print(f"{'Config Layer':<32} | {'Attacks Det':<14} | {'Det Rate':<10} | {'Benign FP':<12} | {'FP Rate':<10} | {'Match Rate':<10}")
print("-" * 110)

cumulative_configs = [
    ("1. rules_only", "Signature and regex rules only", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": False,
        "ENABLE_TAINT_TRACKER": False,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("2. rules_plus_privacy", "Rules + PII detection/masking", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": False,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("3. rules_privacy_taint", "Rules + Privacy + Session Taint", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("4. rules_privacy_taint_baseline", "Rules + Privacy + Taint + Baseline", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("5. full_stack_no_judge", "Full Heuristic Stack (No Judge)", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("6. full_stack_with_judge (stub)", "Full Stack + Intent Judge (judge stub)", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": True,
    }),
]

for name, desc, flags in cumulative_configs:
    reset_all_flags()
    for k, v in flags.items():
        setattr(settings, k, v)
    r = run_configuration(name, desc)
    print(f"{r['config']:<32} | {r['attack_detected']:>2}/{r['attack_count']:<11} | {r['det_rate']:>8.1f}% | {r['benign_fp']:>2}/{r['benign_count']:<9} | {r['fp_rate']:>8.1f}% | {r['match_rate']:>8.1f}%")

print("=" * 110)
print("\n" + "=" * 110)
print("PART 2: LEAVE-ONE-OUT MARGINAL ABLATION SWEEP")
print("Note: Drops each single defense layer from the full stack to measure its marginal impact")
print("=" * 110)
print(f"{'Ablated Configuration':<32} | {'Attacks Det':<14} | {'Det Rate':<10} | {'Benign FP':<12} | {'FP Rate':<10} | {'Match Rate':<10}")
print("-" * 110)

leave_one_out_configs = [
    ("Baseline Full Stack (judge stub)", "All defense layers active", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": True,
    }),
    ("Leave out: Rules Detector", "All layers except Rule Detector", {
        "ENABLE_RULE_DETECTOR": False,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": True,
    }),
    ("Leave out: Privacy Module", "All layers except Privacy Module", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": False,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": True,
    }),
    ("Leave out: Taint Tracker", "All layers except Taint Tracker", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": False,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": True,
    }),
    ("Leave out: Baseline Anomaly", "All layers except Baseline Anomaly", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": True,
    }),
    ("Leave out: Intent Judge (stub)", "All layers except Intent Judge (judge stub)", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": False,
    }),
]

for name, desc, flags in leave_one_out_configs:
    reset_all_flags()
    for k, v in flags.items():
        setattr(settings, k, v)
    r = run_configuration(name, desc)
    print(f"{r['config']:<32} | {r['attack_detected']:>2}/{r['attack_count']:<11} | {r['det_rate']:>8.1f}% | {r['benign_fp']:>2}/{r['benign_count']:<9} | {r['fp_rate']:>8.1f}% | {r['match_rate']:>8.1f}%")

reset_all_flags()
print("=" * 110)
