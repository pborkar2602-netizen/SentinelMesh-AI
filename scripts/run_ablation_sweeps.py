import argparse
import os
import sys
sys.path.insert(0, ".")
from pathlib import Path
from backend.app.config import settings, DEFAULT_SENSITIVE_READ_DATA_CLASSES
from backend.app.judge.intent_judge import IntentJudge
from benchmark.harness.runner import BenchmarkRunner

parser = argparse.ArgumentParser(description="SentinelMesh Defense Layer Ablation Sweeps")
parser.add_argument(
    "--split",
    type=str,
    choices=["dev", "dev_v1_heldout", "held_out_v2"],
    default="dev",
    help="Scenario split to evaluate (default: dev)",
)
args = parser.parse_args()

SCENARIO_DIR = Path("benchmark/scenarios") / args.split
scenario_files = sorted(list(SCENARIO_DIR.glob("*.json")))

# Strictly refuse stub verdicts for all headline/ablation evaluations
IntentJudge.set_mode("recorded_only", refuse_stubs=True)
judge_evaluated = IntentJudge.is_evaluated_for_headline()

runner = BenchmarkRunner()


def reset_all_flags():
    settings.ENABLE_RULE_DETECTOR = True
    settings.ENABLE_PRIVACY_MODULE = True
    settings.ENABLE_TAINT_TRACKER = True
    settings.ENABLE_BASELINE_ANOMALY = True
    settings.SENSITIVE_READ_DATA_CLASSES = dict(DEFAULT_SENSITIVE_READ_DATA_CLASSES)
    settings.ENABLE_INTENT_JUDGE = bool(judge_evaluated)


def apply_flags(flags: dict):
    reset_all_flags()
    for k, v in flags.items():
        if k == "ENABLE_PRE_READ_PROTECTION":
            settings.SENSITIVE_READ_DATA_CLASSES = dict(DEFAULT_SENSITIVE_READ_DATA_CLASSES) if v else {}
        else:
            setattr(settings, k, v)


def run_configuration(config_name: str, description: str):
    attack_count = 0
    attack_detected = 0
    benign_count = 0
    benign_fp = 0
    decision_matches = 0
    records_exposed = 0
    records_exfil = 0
    late_detections = 0
    total = len(scenario_files)

    for f in scenario_files:
        sc = runner.load_scenario_from_file(f)
        res = runner.replay_scenario(sc)
        if sc.category == "attack":
            attack_count += 1
            if res.detected:
                attack_detected += 1
            records_exposed += res.total_records_exposed_to_agent
            records_exfil += res.total_records_exfiltrated
            if res.late_detection:
                late_detections += 1
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
        "exposed": records_exposed,
        "exfil": records_exfil,
        "late_det": late_detections,
    }


split_label = (
    "generalization evidence, small sample, scenarios written by the project author"
    if args.split == "held_out_v2"
    else "dev (seen)"
)

print("=" * 126)
print(f"PART 1: CUMULATIVE ABLATION SWEEP [Split: {args.split} — {split_label}]")
if not judge_evaluated:
    print("Judge Status: judge not evaluated (no SENTINEL_JUDGE_API_KEY; excluded from all results)")
else:
    print("Judge Status: evaluated (real LLM verdicts)")
print("=" * 126)
print(
    f"{'Config Layer':<38} | {'Attacks Det':<12} | {'Det Rate':<9} | {'Benign FP':<10} | {'FP Rate':<8} | {'Match Rate':<10} | {'Exposed':<7} | {'LateDet':<7}"
)
print("-" * 126)

cumulative_configs = [
    ("1. rules_only", "Signature and SQL AST rules only", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": False,
        "ENABLE_TAINT_TRACKER": False,
        "ENABLE_PRE_READ_PROTECTION": False,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("2. rules_plus_privacy", "Rules + PII detection/masking", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": False,
        "ENABLE_PRE_READ_PROTECTION": False,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("3. rules_privacy_taint", "Rules + Privacy + Session Taint", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": False,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("4. pre_read_protection", "Rules + Privacy + Taint + Pre-Read", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": False,
    }),
    ("5. rules_privacy_taint_preread_baseline", "Full Deterministic Stack (+ Baseline)", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": False,
    }),
]

if judge_evaluated:
    cumulative_configs.append(
        ("6. full_stack_with_real_judge", "Full Stack + Real LLM Judge", {
            "ENABLE_RULE_DETECTOR": True,
            "ENABLE_PRIVACY_MODULE": True,
            "ENABLE_TAINT_TRACKER": True,
            "ENABLE_PRE_READ_PROTECTION": True,
            "ENABLE_BASELINE_ANOMALY": True,
            "ENABLE_INTENT_JUDGE": True,
        })
    )

for name, desc, flags in cumulative_configs:
    apply_flags(flags)
    r = run_configuration(name, desc)
    print(
        f"{r['config']:<38} | {r['attack_detected']:>2}/{r['attack_count']:<9} | {r['det_rate']:>7.1f}% | "
        f"{r['benign_fp']:>2}/{r['benign_count']:<7} | {r['fp_rate']:>6.1f}% | {r['match_rate']:>8.1f}% | "
        f"{r['exposed']:>7} | {r['late_det']:>7}"
    )

print("=" * 126)
print("\n" + "=" * 126)
print(f"PART 2: LEAVE-ONE-OUT MARGINAL ABLATION SWEEP [Split: {args.split} — {split_label}]")
if not judge_evaluated:
    print("Judge Status: judge not evaluated (excluded from all results)")
print("=" * 126)
print(
    f"{'Ablated Configuration':<38} | {'Attacks Det':<12} | {'Det Rate':<9} | {'Benign FP':<10} | {'FP Rate':<8} | {'Match Rate':<10} | {'Exposed':<7} | {'LateDet':<7}"
)
print("-" * 126)

leave_one_out_configs = [
    ("Full Active Stack", "All active deterministic layers", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": bool(judge_evaluated),
    }),
    ("Leave out: Rules Detector", "All layers except Rule Detector", {
        "ENABLE_RULE_DETECTOR": False,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": bool(judge_evaluated),
    }),
    ("Leave out: Privacy Module", "All layers except Privacy Module", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": False,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": bool(judge_evaluated),
    }),
    ("Leave out: Taint Tracker", "All layers except Taint Tracker", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": False,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": bool(judge_evaluated),
    }),
    ("Leave out: pre_read_protection", "All layers except pre_read_protection", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": False,
        "ENABLE_BASELINE_ANOMALY": True,
        "ENABLE_INTENT_JUDGE": bool(judge_evaluated),
    }),
    ("Leave out: Baseline Anomaly", "All layers except Baseline Anomaly", {
        "ENABLE_RULE_DETECTOR": True,
        "ENABLE_PRIVACY_MODULE": True,
        "ENABLE_TAINT_TRACKER": True,
        "ENABLE_PRE_READ_PROTECTION": True,
        "ENABLE_BASELINE_ANOMALY": False,
        "ENABLE_INTENT_JUDGE": bool(judge_evaluated),
    }),
]

for name, desc, flags in leave_one_out_configs:
    apply_flags(flags)
    r = run_configuration(name, desc)
    print(
        f"{r['config']:<38} | {r['attack_detected']:>2}/{r['attack_count']:<9} | {r['det_rate']:>7.1f}% | "
        f"{r['benign_fp']:>2}/{r['benign_count']:<7} | {r['fp_rate']:>6.1f}% | {r['match_rate']:>8.1f}% | "
        f"{r['exposed']:>7} | {r['late_det']:>7}"
    )

reset_all_flags()
print("=" * 126)
