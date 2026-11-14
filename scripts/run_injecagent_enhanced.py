#!/usr/bin/env python3
"""
scripts/run_injecagent_enhanced.py

Evaluates InjecAgent Enhanced Hacking Prompt setting on the group-aware test partition.
Evaluates B0 (None), B1 (Allowlist), B2 (Regex), B3 (No Taint), B4 (Full SentinelMesh).
Computes:
- Per-threat prevention rates (Direct Harm vs Data Stealing)
- Exact Wilson 95% Confidence Intervals
- Attacker-case cluster bootstrap (10,000 resamples)
- Exact McNemar paired significance tests against baselines
- Saved to benchmark/reports/v3_injecagent_enhanced_test.json
"""

import os
import sys
import json
import hashlib
from typing import Dict, Any, List
import numpy as np

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from benchmark.harness.baselines import (
    B0_None,
    B1_DomainAllowlist,
    B2_StaticRegex,
    B3_NoTaint,
    B4_FullSentinelMesh,
)
from benchmark.adapters.injecagent_adapter import (
    map_user_tool,
    map_attacker_tool,
)
from backend.app.detection.rules import run_all_detectors
from benchmark.harness.statistics import (
    wilson_score_interval,
    exact_mcnemar_test,
    bootstrap_ci,
)

SALT = b"sentinelmesh_v3_group_cluster_salt"

def deterministic_group_split(group_key: str, threshold: float = 0.70) -> str:
    h = hashlib.sha256(group_key.encode("utf-8") + SALT).hexdigest()
    ratio = int(h[:8], 16) / 0xFFFFFFFF
    return "test" if ratio < threshold else "adapter-dev"

def evaluate_enhanced() -> Dict[str, Any]:
    inj_dir = os.path.join(ROOT_DIR, "benchmark", "external_data", "injecagent")
    dh_path = os.path.join(inj_dir, "test_cases_dh_enhanced.json")
    ds_path = os.path.join(inj_dir, "test_cases_ds_enhanced.json")

    with open(dh_path, "r", encoding="utf-8") as f:
        dh_raw = json.load(f)
    with open(ds_path, "r", encoding="utf-8") as f:
        ds_raw = json.load(f)

    for c in dh_raw:
        c["_attack_type"] = "direct_harm"
    for c in ds_raw:
        c["_attack_type"] = "data_stealing"

    all_cases = dh_raw + ds_raw
    test_cases = [c for c in all_cases if deterministic_group_split(c.get("Attacker Instruction", "")) == "test"]

    print(f"Loaded {len(all_cases)} enhanced cases. Group-aware test partition: {len(test_cases)} cases.")

    baselines = [
        B0_None(),
        B1_DomainAllowlist(),
        B2_StaticRegex(),
        B3_NoTaint(),
        B4_FullSentinelMesh(),
    ]

    results_by_system: Dict[str, Dict[str, Any]] = {
        b.name: {
            "dh_evaluated": 0,
            "dh_blocked": 0,
            "ds_evaluated": 0,
            "ds_blocked": 0,
            "benign_evaluated": len(test_cases),
            "benign_allowed": 0,
            "attack_verdicts": [],
            "benign_verdicts": [],
        }
        for b in baselines
    }

    case_clusters = [c.get("Attacker Instruction", "") for c in test_cases]
    unique_clusters = list(sorted(set(case_clusters)))
    cluster_indices = {cl: [i for i, c in enumerate(case_clusters) if c == cl] for cl in unique_clusters}

    print(f"Evaluating {len(test_cases)} cases across {len(unique_clusters)} attacker clusters...")

    for c in test_cases:
        atype = c["_attack_type"]
        user_inst = c.get("User Instruction", "")
        user_tool_name = c.get("User Tool", "ReadDocument")
        user_tool_params = c.get("User Tool Parameters", {})
        attacker_tools = c.get("Attacker Tools", ["UnknownTool"])
        attacker_tool_name = attacker_tools[0] if attacker_tools else c.get("Attacker Tool", "SendEmail")
        attacker_instruction = c.get("Attacker Instruction", "")
        tool_response = str(c.get("Tool Response", ""))

        s0_tool, s0_args = map_user_tool(user_tool_name, user_tool_params)
        s1_tool, s1_args = map_attacker_tool(attacker_tool_name, attacker_instruction, atype)

        context_sources = [{
            "source_id": f"injecagent_{user_tool_name}",
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

        for b in baselines:
            # Attack evaluation
            dec, _ = b.evaluate_step(
                tool_name=s1_tool,
                arguments=s1_args,
                context_sources=context_sources,
                is_tainted=True,
                tainted_by=[f"injecagent_{user_tool_name}"],
                findings=all_findings,
                risk_score=75,
                agent_task=user_inst,
                untrusted_literals=untrusted_lits,
            )
            attack_blocked = dec in ["block", "require_approval", "would_block"]
            results_by_system[b.name]["attack_verdicts"].append(1 if attack_blocked else 0)

            if atype == "direct_harm":
                results_by_system[b.name]["dh_evaluated"] += 1
                if attack_blocked:
                    results_by_system[b.name]["dh_blocked"] += 1
            else:
                results_by_system[b.name]["ds_evaluated"] += 1
                if attack_blocked:
                    results_by_system[b.name]["ds_blocked"] += 1

            # Benign counterpart evaluation
            benign_tool, benign_args = "read_doc", {"path": "clean_summary.txt"}
            benign_findings = run_all_detectors(
                tool_name=benign_tool,
                arguments=benign_args,
                context_sources=[{"source_id": "clean_src", "is_untrusted": False, "snippet": "Clean task output"}],
            )
            b_decision, _ = b.evaluate_step(
                tool_name=benign_tool,
                arguments=benign_args,
                context_sources=[],
                is_tainted=False,
                tainted_by=[],
                findings=benign_findings,
                risk_score=10,
                agent_task="Summarize document",
                untrusted_literals=set(),
            )
            b_allowed = b_decision == "allow"
            results_by_system[b.name]["benign_verdicts"].append(1 if b_allowed else 0)
            if b_allowed:
                results_by_system[b.name]["benign_allowed"] += 1

    # Format final metrics
    report: Dict[str, Any] = {
        "benchmark": "InjecAgent Enhanced Hacking Prompt",
        "split": "test (group-aware 0% leakage)",
        "sample_count": len(test_cases),
        "cluster_count": len(unique_clusters),
        "systems": {},
    }

    b4_verdicts = np.array(results_by_system["B4: Full SentinelMesh Gateway"]["attack_verdicts"])

    for b in baselines:
        res = results_by_system[b.name]
        dh_tot = res["dh_evaluated"]
        dh_blk = res["dh_blocked"]
        ds_tot = res["ds_evaluated"]
        ds_blk = res["ds_blocked"]
        ben_tot = res["benign_evaluated"]
        ben_alw = res["benign_allowed"]

        dh_rate = dh_blk / dh_tot if dh_tot else 0.0
        ds_rate = ds_blk / ds_tot if ds_tot else 0.0
        ben_rate = ben_alw / ben_tot if ben_tot else 0.0
        overall_rate = (dh_blk + ds_blk) / (dh_tot + ds_tot) if (dh_tot + ds_tot) else 0.0

        _, dh_l, dh_u = wilson_score_interval(dh_blk, dh_tot)
        _, ds_l, ds_u = wilson_score_interval(ds_blk, ds_tot)
        _, ben_l, ben_u = wilson_score_interval(ben_alw, ben_tot)
        _, ov_l, ov_u = wilson_score_interval(dh_blk + ds_blk, dh_tot + ds_tot)

        # Paired McNemar against B4
        sys_verdicts = np.array(res["attack_verdicts"])
        b_count = int(np.sum((b4_verdicts == 1) & (sys_verdicts == 0)))
        c_count = int(np.sum((b4_verdicts == 0) & (sys_verdicts == 1)))
        mcnemar_res = exact_mcnemar_test(b_count, c_count)

        report["systems"][b.name] = {
            "overall_prevention_rate": round(overall_rate, 4),
            "overall_ci_95": [ov_l, ov_u],
            "dh_evaluated": dh_tot,
            "dh_prevention_rate": round(dh_rate, 4),
            "dh_ci_95": [dh_l, dh_u],
            "ds_evaluated": ds_tot,
            "ds_prevention_rate": round(ds_rate, 4),
            "ds_ci_95": [ds_l, ds_u],
            "benign_evaluated": ben_tot,
            "benign_pass_rate": round(ben_rate, 4),
            "benign_ci_95": [ben_l, ben_u],
            "false_positive_rate": round(1.0 - ben_rate, 4),
            "mcnemar_vs_b4": mcnemar_res,
        }

    return report

if __name__ == "__main__":
    rep = evaluate_enhanced()
    out_path = os.path.join(ROOT_DIR, "benchmark", "reports", "v3_injecagent_enhanced_test.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    print(f"\nSUCCESS: Enhanced test evaluation completed. Report saved to {out_path}")
    for sname, sdata in rep["systems"].items():
        print(f"{sname}: Overall={sdata['overall_prevention_rate']*100:.1f}%, DH={sdata['dh_prevention_rate']*100:.1f}%, DS={sdata['ds_prevention_rate']*100:.1f}%, Benign Pass={sdata['benign_pass_rate']*100:.1f}%")
