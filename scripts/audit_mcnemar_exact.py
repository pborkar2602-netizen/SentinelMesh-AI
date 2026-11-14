#!/usr/bin/env python3
"""
scripts/audit_mcnemar_exact.py

Recomputes exact McNemar p-values using scipy.stats.binomtest for:
1. 60 Benchmark scenarios (dev + dev_v1_heldout + held_out_v2)
2. 723 InjecAgent test scenarios

Prints exact b, c, n, p, Cohen's g, Odds Ratio, and Holm-Bonferroni correction.
B5 is explicitly marked "judge not evaluated (no recorded verdicts; stub removed)".
"""

import os
import sys
import json
import glob
from scipy.stats import binomtest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from benchmark.harness.baselines import (
    B0_None,
    B1_DomainAllowlist,
    B2_StaticRegex,
    B3_NoTaint,
    B4_FullSentinelMesh,
)
from benchmark.harness.statistics import wilson_score_interval, holm_bonferroni_correction
from benchmark.adapters.injecagent_adapter import map_user_tool, map_attacker_tool
from backend.app.detection.rules import run_all_detectors


def load_scenarios(scenario_dir: str):
    files = sorted(glob.glob(os.path.join(scenario_dir, "*.json")))
    scenarios = []
    for fpath in files:
        with open(fpath, "r", encoding="utf-8") as f:
            scenarios.append(json.load(f))
    return scenarios


def evaluate_scenario_on_baseline(scenario, baseline):
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
    else:
        return not session_blocked


def run_benchmark_mcnemar():
    dirs = [
        os.path.join(ROOT_DIR, "benchmark", "scenarios", "dev"),
        os.path.join(ROOT_DIR, "benchmark", "scenarios", "dev_v1_heldout"),
        os.path.join(ROOT_DIR, "benchmark", "scenarios", "held_out_v2"),
    ]
    scenarios = []
    for d in dirs:
        scenarios.extend(load_scenarios(d))

    baselines = [
        B0_None(),
        B1_DomainAllowlist(),
        B2_StaticRegex(),
        B3_NoTaint(),
    ]
    b4 = B4_FullSentinelMesh()

    b4_outcomes = [evaluate_scenario_on_baseline(sc, b4) for sc in scenarios]
    b4_acc, b4_l, b4_u = wilson_score_interval(sum(b4_outcomes), len(scenarios))

    results = []
    raw_p_values = []
    names = []

    for b in baselines:
        b_outcomes = [evaluate_scenario_on_baseline(sc, b) for sc in scenarios]
        b_acc, b_l, b_u = wilson_score_interval(sum(b_outcomes), len(scenarios))

        a = sum(1 for x, y in zip(b4_outcomes, b_outcomes) if x and y)
        cell_b = sum(1 for x, y in zip(b4_outcomes, b_outcomes) if x and not y)
        cell_c = sum(1 for x, y in zip(b4_outcomes, b_outcomes) if not x and y)
        d = sum(1 for x, y in zip(b4_outcomes, b_outcomes) if not x and not y)
        n = cell_b + cell_c

        k = min(cell_b, cell_c)
        p_val = float(binomtest(k, n, 0.5, alternative="two-sided").pvalue) if n > 0 else 1.0
        cohens_g = abs(cell_b / float(n) - 0.5) if n > 0 else 0.0
        or_val = float("inf") if cell_c == 0 else round(cell_b / float(cell_c), 4)

        raw_p_values.append(p_val)
        names.append(b.name)
        results.append({
            "name": b.name,
            "acc": b_acc,
            "ci": (b_l, b_u),
            "a": a, "b": cell_b, "c": cell_c, "d": d,
            "n": n,
            "p_val": p_val,
            "cohens_g": cohens_g,
            "odds_ratio": or_val,
        })

    # Holm correction
    holm = holm_bonferroni_correction(raw_p_values, alpha=0.05)
    for res, h in zip(results, holm):
        res["holm"] = h

    return len(scenarios), b4.name, b4_acc, (b4_l, b4_u), results


def run_injecagent_mcnemar():
    with open(os.path.join(ROOT_DIR, "benchmark", "data_splits", "test", "injecagent_test.json"), "r", encoding="utf-8") as f:
        cases = json.load(f)

    baselines = [
        B0_None(),
        B1_DomainAllowlist(),
        B2_StaticRegex(),
        B3_NoTaint(),
    ]
    b4 = B4_FullSentinelMesh()

    b4_outcomes = []
    bl_outcomes = {b.name: [] for b in baselines}

    for case in cases:
        attack_cat = case.get("_attack_type", "direct_harm")
        user_inst = case.get("User Instruction", "")
        user_tool = case.get("User Tool", "")
        tool_params = case.get("Tool Parameters", {})
        tool_response = str(case.get("Tool Response", ""))
        attacker_tools = case.get("Attacker Tools", ["UnknownTool"])
        attacker_tool = attacker_tools[0] if attacker_tools else "UnknownTool"
        attacker_inst = case.get("Attacker Instruction", "")

        s0_tool, s0_args = map_user_tool(user_tool, tool_params)
        s1_tool, s1_args = map_attacker_tool(attacker_tool, attacker_inst, attack_cat)

        context_sources = [{
            "source_id": f"injecagent_{user_tool}",
            "source_type": "document",
            "is_untrusted": True,
            "snippet": tool_response[:300]
        }]
        untrusted_lits = set(tool_response.split())

        all_findings = run_all_detectors(
            tool_name=s1_tool,
            arguments=s1_args,
            context_sources=context_sources,
        )

        dec_b4, _ = b4.evaluate_step(
            tool_name=s1_tool,
            arguments=s1_args,
            context_sources=context_sources,
            is_tainted=True,
            tainted_by=[f"injecagent_{user_tool}"],
            findings=all_findings,
            risk_score=75,
            agent_task=user_inst,
            untrusted_literals=untrusted_lits,
        )
        b4_outcomes.append(dec_b4 in ["block", "require_approval", "would_block"])

        for b in baselines:
            dec, _ = b.evaluate_step(
                tool_name=s1_tool,
                arguments=s1_args,
                context_sources=context_sources,
                is_tainted=True,
                tainted_by=[f"injecagent_{user_tool}"],
                findings=all_findings,
                risk_score=75,
                agent_task=user_inst,
                untrusted_literals=untrusted_lits,
            )
            bl_outcomes[b.name].append(dec in ["block", "require_approval", "would_block"])

    b4_acc, b4_l, b4_u = wilson_score_interval(sum(b4_outcomes), len(cases))

    results = []
    raw_p_values = []
    for b in baselines:
        b_res = bl_outcomes[b.name]
        b_acc, b_l, b_u = wilson_score_interval(sum(b_res), len(cases))

        a = sum(1 for x, y in zip(b4_outcomes, b_res) if x and y)
        cell_b = sum(1 for x, y in zip(b4_outcomes, b_res) if x and not y)
        cell_c = sum(1 for x, y in zip(b4_outcomes, b_res) if not x and y)
        d = sum(1 for x, y in zip(b4_outcomes, b_res) if not x and not y)
        n = cell_b + cell_c

        k = min(cell_b, cell_c)
        p_val = float(binomtest(k, n, 0.5, alternative="two-sided").pvalue) if n > 0 else 1.0
        cohens_g = abs(cell_b / float(n) - 0.5) if n > 0 else 0.0
        or_val = float("inf") if cell_c == 0 else round(cell_b / float(cell_c), 4)

        raw_p_values.append(p_val)
        results.append({
            "name": b.name,
            "acc": b_acc,
            "ci": (b_l, b_u),
            "a": a, "b": cell_b, "c": cell_c, "d": d,
            "n": n,
            "p_val": p_val,
            "cohens_g": cohens_g,
            "odds_ratio": or_val,
        })

    holm = holm_bonferroni_correction(raw_p_values, alpha=0.05)
    for res, h in zip(results, holm):
        res["holm"] = h

    return len(cases), b4.name, b4_acc, (b4_l, b4_u), results


if __name__ == "__main__":
    print("================================================================================")
    print("EXACT MCNEMAR TESTS & HOLM-BONFERRONI AUDIT (scipy.stats.binomtest)")
    print("================================================================================")
    
    # 1. 60 Benchmark Scenarios
    n_sc, b4_name, b4_acc, b4_ci, bench_res = run_benchmark_mcnemar()
    print(f"\n--- 1. BENCHMARK SCENARIOS (N={n_sc}) ---")
    print(f"{b4_name}: Accuracy = {b4_acc*100:.1f}% [{b4_ci[0]*100:.1f}%, {b4_ci[1]*100:.1f}%]")
    print(f"{'Baseline':<35} | {'b':<4} | {'c':<4} | {'n':<4} | {'Exact p':<14} | {'Holm alpha':<10} | {'Reject Null?':<12}")
    print("-" * 95)
    for r in bench_res:
        rej = "REJECT NULL" if r["holm"]["reject_null"] else "FAIL REJECT"
        p_str = f"{r['p_val']:.5e}" if r['p_val'] < 0.001 else f"{r['p_val']:.6f}"
        print(f"{r['name']:<35} | {r['b']:<4} | {r['c']:<4} | {r['n']:<4} | {p_str:<14} | {r['holm']['threshold']:<10.4f} | {rej:<12}")

    print("B5: LLM Safety Judge: judge not evaluated (no recorded LLM verdicts; stub removed)")

    # 2. InjecAgent Test Partition (N=723)
    n_inj, _, b4_acc_inj, b4_ci_inj, inj_res = run_injecagent_mcnemar()
    print(f"\n--- 2. INJECAGENT TEST PARTITION (N={n_inj}) ---")
    print(f"B4 Full SentinelMesh: Prevention = {b4_acc_inj*100:.2f}% [{b4_ci_inj[0]*100:.2f}%, {b4_ci_inj[1]*100:.2f}%]")
    print(f"{'Baseline':<35} | {'b':<4} | {'c':<4} | {'n':<4} | {'Exact p (binomtest)':<22} | {'Holm alpha':<10} | {'Reject Null?':<12}")
    print("-" * 105)
    for r in inj_res:
        rej = "REJECT NULL" if r["holm"]["reject_null"] else "FAIL REJECT"
        p_str = f"{r['p_val']:.5e}"
        print(f"{r['name']:<35} | {r['b']:<4} | {r['c']:<4} | {r['n']:<4} | {p_str:<22} | {r['holm']['threshold']:<10.4f} | {rej:<12}")

    print("B5: LLM Safety Judge: judge not evaluated (no recorded LLM verdicts; stub removed)")
    
    # Mathematical proof for b=703, c=0
    proof_p = float(binomtest(0, 703, 0.5, alternative='two-sided').pvalue)
    print(f"\nMathematical check for b=703, c=0: exact p = 2 * 0.5^703 = {proof_p:.5e}")
