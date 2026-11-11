#!/usr/bin/env python3
"""
Evaluates the 60 robustness variant scenarios across the 5 variant families
(column_names, wording, obfuscation_b64_zwsp, destination, split_documents)
and reports detection rate, false positive rate, decision match rate, and
records exposed/exfiltrated per variant family, separately from the main sets.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.judge.intent_judge import IntentJudge
from benchmark.harness.runner import BenchmarkRunner
from benchmark.harness.metrics import compute_benchmark_metrics

VARIANTS_ROOT = PROJECT_ROOT / "benchmark" / "scenarios" / "variants"
FAMILIES = [
    "column_names",
    "wording",
    "obfuscation_b64_zwsp",
    "destination",
    "split_documents",
]


def main() -> int:
    IntentJudge.set_mode("recorded_only", refuse_stubs=True)
    runner = BenchmarkRunner()

    print("=" * 115)
    print("ROBUSTNESS VARIANTS EVALUATION [dev (seen) variants — reported separately from main sets]")
    print("Judge Status:", "evaluated" if IntentJudge.is_evaluated_for_headline() else "judge not evaluated")
    print("=" * 115)
    print(
        f"{'Variant Family':<24} | {'Scenarios':<9} | {'Attacks Det':<13} | {'Det Rate':<9} | "
        f"{'Benign FP':<11} | {'FP Rate':<8} | {'Match Rate':<10} | {'Exposed':<7} | {'Exfil':<5}"
    )
    print("-" * 115)

    all_results = []
    family_summaries = {}
    any_mismatch = False

    for fam in FAMILIES:
        fam_dir = VARIANTS_ROOT / fam
        files = sorted(fam_dir.glob("*.json"))
        fam_results = []
        for f in files:
            sc = runner.load_scenario_from_file(f)
            res = runner.replay_scenario(sc)
            fam_results.append(res)
            all_results.append(res)
            if not res.decision_match:
                any_mismatch = True

        m = compute_benchmark_metrics(fam_results)
        s = m["summary"]
        r = m["rates"]
        rec = m["records"]
        family_summaries[fam] = m

        print(
            f"{fam:<24} | {s['total_scenarios']:>9} | "
            f"{s['attacks_detected']:>2}/{s['attack_count']:<10} | "
            f"{r['detection_rate']['percentage']:>9} | "
            f"{s['benign_false_positives']:>2}/{s['benign_count']:<8} | "
            f"{r['false_positive_rate']['percentage']:>8} | "
            f"{r['decision_match_rate']['percentage']:>10} | "
            f"{rec['total_records_exposed_to_agent']:>7} | "
            f"{rec['total_records_exfiltrated']:>5}"
        )

    overall = compute_benchmark_metrics(all_results)
    os_sum = overall["summary"]
    os_rates = overall["rates"]
    os_rec = overall["records"]
    print("-" * 115)
    print(
        f"{'ALL VARIANTS TOTAL':<24} | {os_sum['total_scenarios']:>9} | "
        f"{os_sum['attacks_detected']:>2}/{os_sum['attack_count']:<10} | "
        f"{os_rates['detection_rate']['percentage']:>9} | "
        f"{os_sum['benign_false_positives']:>2}/{os_sum['benign_count']:<8} | "
        f"{os_rates['false_positive_rate']['percentage']:>8} | "
        f"{os_rates['decision_match_rate']['percentage']:>10} | "
        f"{os_rec['total_records_exposed_to_agent']:>7} | "
        f"{os_rec['total_records_exfiltrated']:>5}"
    )
    print("=" * 115)

    if any_mismatch:
        print("\nMISMATCHED VARIANT SCENARIOS:")
        for r in all_results:
            if not r.decision_match:
                print(
                    f"  - [{r.scenario_id}] {r.scenario_name}: expected={r.expected_decision}, actual={r.actual_final_decision}"
                )

    out_json = PROJECT_ROOT / "benchmark" / "reports" / "variants_report.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(
        json.dumps(
            {
                "label": "dev (seen) robustness variants — separate from main sets",
                "judge_status": "evaluated" if IntentJudge.is_evaluated_for_headline() else "judge not evaluated",
                "families": family_summaries,
                "overall": overall,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\n[+] Saved variants report: {out_json}")
    return 1 if any_mismatch else 0


if __name__ == "__main__":
    raise SystemExit(main())
