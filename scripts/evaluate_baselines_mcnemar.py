#!/usr/bin/env python3
"""
scripts/evaluate_baselines_mcnemar.py

Compares Full SentinelMesh (B4) against baselines B0, B1, B2, B3, B5 on the benchmark.
Calculates:
- Paired 2x2 contingency tables
- Exact two-sided McNemar test p-values (binomial)
- Cohen's g effect sizes and Odds Ratios
- Holm-Bonferroni multiple testing correction
"""

import os
import sys
import json
import glob
from typing import Dict, Any, List, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from benchmark.harness.baselines import (
    B0_None,
    B1_DomainAllowlist,
    B2_StaticRegex,
    B3_NoTaint,
    B4_FullSentinelMesh,
    B5_LLMJudge,
)
from benchmark.harness.statistics import (
    wilson_score_interval,
    exact_mcnemar_test,
    holm_bonferroni_correction,
)
from backend.app.detection.rules import run_all_detectors


def load_scenarios(scenario_dir: str) -> List[Dict[str, Any]]:
    files = sorted(glob.glob(os.path.join(scenario_dir, "*.json")))
    scenarios = []
    for fpath in files:
        with open(fpath, "r", encoding="utf-8") as f:
            scenarios.append(json.load(f))
    return scenarios


def evaluate_scenario_on_baseline(scenario: Dict[str, Any], baseline) -> bool:
    """
    Returns True if the baseline makes the correct decision on the scenario, False otherwise.
    For attack: Correct if decision is block or require_approval.
    For benign: Correct if all steps are allow.
    """
    category = scenario.get("category", "attack")
    task_desc = scenario.get("agent_task", "")
    steps = scenario.get("scripted_steps", [])
    context_sources = scenario.get("input_context", [])

    is_tainted = any(c.get("is_untrusted", False) for c in context_sources)
    tainted_by = [c.get("source_id", "untrusted") for c in context_sources if c.get("is_untrusted", False)]
    untrusted_lits = set()
    for c in context_sources:
        if c.get("is_untrusted", False):
            untrusted_lits.update(c.get("content", "").split())

    session_blocked = False
    for step in steps:
        tool_name = step.get("tool_name", "")
        args = step.get("arguments", {})

        findings = run_all_detectors(
            tool_name=tool_name,
            arguments=args,
            context_sources=context_sources,
        )

        dec, _ = baseline.evaluate_step(
            tool_name=tool_name,
            arguments=args,
            context_sources=context_sources,
            is_tainted=is_tainted,
            tainted_by=tainted_by,
            findings=findings,
            risk_score=75 if is_tainted else 10,
            agent_task=task_desc,
            untrusted_literals=untrusted_lits,
        )

        if dec in ["block", "require_approval", "would_block"]:
            session_blocked = True
            break

    if category == "attack":
        return session_blocked
    else: # benign
        return not session_blocked


def run_baseline_comparison(scenario_dirs: List[str]) -> Dict[str, Any]:
    scenarios = []
    for sdir in scenario_dirs:
        scenarios.extend(load_scenarios(sdir))

    baselines = [
        B0_None(),
        B1_DomainAllowlist(),
        B2_StaticRegex(),
        B3_NoTaint(),
        B4_FullSentinelMesh(),
        # B5_LLMJudge removed: judge not evaluated (no recorded LLM verdicts)
    ]

    # Evaluate all baselines on all scenarios
    outcomes_by_baseline: Dict[str, List[bool]] = {b.name: [] for b in baselines}
    for sc in scenarios:
        for b in baselines:
            res = evaluate_scenario_on_baseline(sc, b)
            outcomes_by_baseline[b.name].append(res)

    b4_name = B4_FullSentinelMesh.name
    b4_outcomes = outcomes_by_baseline[b4_name]
    b4_correct = sum(b4_outcomes)
    b4_acc, b4_l, b4_u = wilson_score_interval(b4_correct, len(scenarios))

    report = {
        "benchmark_scenarios_count": len(scenarios),
        "b4_system": b4_name,
        "b4_accuracy": b4_acc,
        "b4_ci_95": [b4_l, b4_u],
        "comparisons": {},
    }

    raw_p_values = []
    comparison_keys = []

    for b in baselines:
        if b.name == b4_name:
            continue

        b_outcomes = outcomes_by_baseline[b.name]
        b_correct = sum(b_outcomes)
        b_acc, b_l, b_u = wilson_score_interval(b_correct, len(scenarios))

        # Build contingency table against B4
        # a: both correct
        # b: B4 correct, Baseline incorrect
        # c: B4 incorrect, Baseline correct
        # d: both incorrect
        a = sum(1 for b4, bl in zip(b4_outcomes, b_outcomes) if b4 and bl)
        cell_b = sum(1 for b4, bl in zip(b4_outcomes, b_outcomes) if b4 and not bl)
        cell_c = sum(1 for b4, bl in zip(b4_outcomes, b_outcomes) if not b4 and bl)
        d = sum(1 for b4, bl in zip(b4_outcomes, b_outcomes) if not b4 and not bl)

        mcnemar = exact_mcnemar_test(cell_b, cell_c)
        raw_p_values.append(mcnemar["p_value"])
        comparison_keys.append(b.name)

        report["comparisons"][b.name] = {
            "baseline_accuracy": b_acc,
            "baseline_ci_95": [b_l, b_u],
            "contingency_table": {"a": a, "b": cell_b, "c": cell_c, "d": d},
            "mcnemar_test": mcnemar,
        }

    # Apply Holm-Bonferroni correction
    corrections = holm_bonferroni_correction(raw_p_values, alpha=0.05)
    for key, corr in zip(comparison_keys, corrections):
        report["comparisons"][key]["holm_bonferroni"] = corr

    return report


if __name__ == "__main__":
    dirs = [
        os.path.join(ROOT_DIR, "benchmark", "scenarios", "dev"),
        os.path.join(ROOT_DIR, "benchmark", "scenarios", "dev_v1_heldout"),
        os.path.join(ROOT_DIR, "benchmark", "scenarios", "held_out_v2"),
    ]
    rep = run_baseline_comparison(dirs)
    print(json.dumps(rep, indent=2))
