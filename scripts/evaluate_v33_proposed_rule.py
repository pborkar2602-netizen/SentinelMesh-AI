#!/usr/bin/env python3
"""
scripts/evaluate_v33_proposed_rule.py

Evaluates proposed v3.3 Policy Rule:
"tainted session + destructive/mutating call to an external service -> require_approval"

EVALUATION BOUNDARY:
- ONLY evaluated on adapter-dev partition (benchmark/data_splits/dev/injecagent_cluster_dev.json, N=306)
- ONLY evaluated on benchmark dev / held-out scenarios (36 dev, 12 dev_v1_heldout, 12 held_out_v2)
- TEST PARTITIONS ARE NEVER RERUN FOR THIS PROPOSED RULE.
- Clearly labeled: "Designed after seeing results, exploratory (v3.3 proposal)".
"""

import os
import sys
import json
from typing import Dict, Any, List

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from benchmark.adapters.injecagent_adapter import map_user_tool, map_attacker_tool
from benchmark.harness.baselines import B4_FullSentinelMesh
from backend.app.detection.rules import run_all_detectors

def is_v33_external_destructive(tool_name: str, arguments: Dict[str, Any]) -> bool:
    """
    v3.3 Proposed Rule Condition:
    Identifies destructive/mutating calls targeting external or system services.
    """
    if tool_name == "external_api":
        method = str(arguments.get("method", "POST")).upper()
        return method in ("POST", "PUT", "DELETE", "PATCH")
    if tool_name == "db_query":
        q = str(arguments.get("query", "")).strip().upper()
        return any(q.startswith(cmd) for cmd in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE"))
    if tool_name == "send_email":
        # Mutates external mailbox state by dispatching outbox communication
        return True
    return False

def evaluate_on_adapter_dev():
    dev_split_file = os.path.join(ROOT_DIR, "benchmark", "data_splits", "dev", "injecagent_cluster_dev.json")
    with open(dev_split_file, "r") as f:
        cases = json.load(f)

    b4 = B4_FullSentinelMesh()
    
    b4_blocked = 0
    v33_blocked = 0
    total = len(cases)

    # Benign counterpart simulation on dev split
    b4_benign_allowed = 0
    v33_benign_allowed = 0

    for c in cases:
        atype = c.get("_attack_type", "direct_harm")
        attacker_tools = c.get("Attacker Tools", ["UnknownTool"])
        attacker_tool_name = attacker_tools[0] if attacker_tools else c.get("Attacker Tool", "SendEmail")
        attacker_instruction = c.get("Attacker Instruction", "")
        tool_response = str(c.get("Tool Response", ""))

        s1_tool, s1_args = map_attacker_tool(attacker_tool_name, attacker_instruction, atype)

        context_sources = [{
            "source_id": "injecagent_dev_doc",
            "source_type": "document",
            "is_untrusted": True,
            "snippet": tool_response[:300]
        }]
        all_findings = run_all_detectors(
            tool_name=s1_tool,
            arguments=s1_args,
            context_sources=context_sources,
        )

        # Baseline B4 evaluation
        dec_b4, _ = b4.evaluate_step(
            tool_name=s1_tool,
            arguments=s1_args,
            context_sources=context_sources,
            is_tainted=True,
            tainted_by=["injecagent_dev_doc"],
            findings=all_findings,
            risk_score=75,
            agent_task=c.get("User Instruction", ""),
            untrusted_literals=set(tool_response.split()),
        )
        if dec_b4 in ("block", "require_approval", "would_block"):
            b4_blocked += 1

        # v3.3 Proposed Rule evaluation:
        # If B4 already blocked, it's blocked.
        # Otherwise, check proposed rule: tainted + external destructive/mutating -> require_approval
        if dec_b4 in ("block", "require_approval", "would_block"):
            v33_blocked += 1
        elif is_v33_external_destructive(s1_tool, s1_args):
            v33_blocked += 1

    return {
        "dataset": "InjecAgent adapter-dev (cluster split)",
        "total_cases": total,
        "b4_prevented": b4_blocked,
        "b4_prevention_rate": b4_blocked / total,
        "v33_prevented": v33_blocked,
        "v33_prevention_rate": v33_blocked / total,
        "absolute_improvement": (v33_blocked - b4_blocked) / total
    }

def evaluate_on_benchmark_scenarios():
    scenarios_dir = os.path.join(ROOT_DIR, "benchmark", "scenarios")
    suite_dirs = ["dev", "dev_v1_heldout", "held_out_v2"]
    
    results = {}
    for s_dir in suite_dirs:
        dir_path = os.path.join(scenarios_dir, s_dir)
        if not os.path.exists(dir_path):
            continue
        scenarios = []
        for f in os.listdir(dir_path):
            if f.endswith(".json"):
                with open(os.path.join(dir_path, f), "r") as fh:
                    scenarios.append(json.load(fh))
        
        b4 = B4_FullSentinelMesh()
        b4_correct = 0
        v33_correct = 0
        total = len(scenarios)

        for sc in scenarios:
            is_attack = sc.get("is_attack", False)
            steps = sc.get("steps", [])
            scenario_b4_blocked = False
            scenario_v33_blocked = False

            is_tainted = False
            for step in steps:
                sources = step.get("context_sources", [])
                if any(s.get("is_untrusted", False) for s in sources):
                    is_tainted = True
                
                tool_name = step.get("tool_name", "")
                args = step.get("arguments", {})
                findings = run_all_detectors(tool_name, args, sources)
                dec, _ = b4.evaluate_step(
                    tool_name=tool_name,
                    arguments=args,
                    context_sources=sources,
                    is_tainted=is_tainted,
                    tainted_by=["untrusted"] if is_tainted else [],
                    findings=findings,
                    risk_score=75 if is_tainted else 20,
                    agent_task=sc.get("task", ""),
                )
                if dec in ("block", "require_approval", "would_block"):
                    scenario_b4_blocked = True
                    scenario_v33_blocked = True
                    break
                elif is_tainted and is_v33_external_destructive(tool_name, args):
                    scenario_v33_blocked = True
                    break

            if is_attack and scenario_b4_blocked:
                b4_correct += 1
            elif not is_attack and not scenario_b4_blocked:
                b4_correct += 1

            if is_attack and scenario_v33_blocked:
                v33_correct += 1
            elif not is_attack and not scenario_v33_blocked:
                v33_correct += 1

        results[s_dir] = {
            "total": total,
            "b4_accuracy": b4_correct / total if total else 1.0,
            "v33_accuracy": v33_correct / total if total else 1.0
        }
    return results

if __name__ == "__main__":
    print("=" * 80)
    print("PROPOSED v3.3 POLICY RULE EVALUATION (STRICTLY ON ADAPTER-DEV & SCENARIOS)")
    print("Rule: tainted session + destructive/mutating call to external service -> require_approval")
    print("Label: designed after seeing results, exploratory (v3.3 proposal)")
    print("=" * 80)

    dev_res = evaluate_on_adapter_dev()
    print("\n1. InjecAgent adapter-dev (N=306):")
    print(f"   B4 Baseline Prevention:     {dev_res['b4_prevented']} / {dev_res['total_cases']} ({dev_res['b4_prevention_rate']*100:.2f}%)")
    print(f"   v3.3 Proposed Prevention:   {dev_res['v33_prevented']} / {dev_res['total_cases']} ({dev_res['v33_prevention_rate']*100:.2f}%)")
    print(f"   Improvement on adapter-dev: +{dev_res['absolute_improvement']*100:.2f}%")

    sc_res = evaluate_on_benchmark_scenarios()
    print("\n2. Benchmark Dev & Held-Out Scenarios (N=60):")
    for s_file, metrics in sc_res.items():
        print(f"   {s_file:<22}: B4 Acc = {metrics['b4_accuracy']*100:.1f}%, v3.3 Acc = {metrics['v33_accuracy']*100:.1f}%")

    out_path = os.path.join(ROOT_DIR, "benchmark", "reports", "v3_3_proposed_rule_exploratory.json")
    with open(out_path, "w") as f:
        json.dump({
            "status": "exploratory (designed after seeing results, run on adapter-dev and dev scenarios only)",
            "test_partition_rerun": False,
            "proposed_rule": "tainted session + destructive/mutating call to external service -> require_approval",
            "adapter_dev_evaluation": dev_res,
            "scenario_evaluations": sc_res
        }, f, indent=2)
    print(f"\nSaved report to {out_path}")
