import os
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import psutil
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

from benchmark.harness.models import ScenarioExecutionResult

def get_system_telemetry() -> Dict[str, Any]:
    """Captures runtime hardware and environment telemetry."""
    try:
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:
        ram_gb = "Unknown"

    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count() or 1,
        "ram_gb": ram_gb,
        "python_version": platform.python_version(),
    }

def generate_ascii_report(
    dev_metrics: Dict[str, Any],
    held_out_metrics: Optional[Dict[str, Any]],
    overall_metrics: Dict[str, Any],
    results: List[ScenarioExecutionResult],
    warm_up_calls: int = 10,
) -> str:
    """Formats ASCII report following Section 10.2 of docs/benchmark_spec.md."""
    sys_info = get_system_telemetry()
    now_utc = datetime.now(timezone.utc).isoformat()
    from backend.app.judge.intent_judge import IntentJudge
    judge_evaluated = IntentJudge.is_evaluated_for_headline()
    suite_mode_str = (
        "Live / Recorded Real LLM Judge"
        if judge_evaluated
        else "Deterministic Core Pipeline (judge not evaluated)"
    )
    judge_lat_str = (
        "Evaluated via Recorded / Live LLM"
        if judge_evaluated
        else "judge not evaluated"
    )

    lines = [
        "=" * 100,
        "SENTINELMESH BENCHMARK EVALUATION REPORT",
        "[EVALUATION REPORT - VALUES COMPUTED DYNAMICALLY FROM RUN RESULTS]",
        "(Note: Small sample benchmark suite designed for deterministic regression gating;",
        "95% Confidence Intervals calculated via the Wilson score method)",
        "=" * 100,
        "ENVIRONMENT & HARDWARE",
        f"- Host Platform:       {sys_info['platform']} / {sys_info['processor']} / {sys_info['ram_gb']}GB RAM / Python {sys_info['python_version']}",
        f"- Test Suite Mode:     {suite_mode_str}",
        f"- Intent Judge Status: {'evaluated (real LLM)' if judge_evaluated else 'judge not evaluated'}",
        f"- Date & Time:         {now_utc}",
    ]
    if dev_metrics and dev_metrics['summary']['total_scenarios'] > 0:
        lines.extend([
            "",
            "-" * 100,
            f"DEV SET EVALUATION [dev (seen)] ({dev_metrics['summary']['attack_count']} Attacks, {dev_metrics['summary']['benign_count']} Benign)",
            "* Label: dev (seen) — Tuned Calibration Results (Used for rule/threshold tuning; not generalization evidence)",
            f"- Detection Rate:            {dev_metrics['rates']['detection_rate']['percentage']:>7} ({dev_metrics['summary']['attacks_detected']}/{dev_metrics['summary']['attack_count']})       [95% CI: {dev_metrics['rates']['detection_rate']['ci_95'][0]*100:.1f}% - {dev_metrics['rates']['detection_rate']['ci_95'][1]*100:.1f}%]",
            f"- Decision-Match Rate:       {dev_metrics['rates']['decision_match_rate']['percentage']:>7} ({dev_metrics['summary']['decision_matches']}/{dev_metrics['summary']['total_scenarios']})       [95% CI: {dev_metrics['rates']['decision_match_rate']['ci_95'][0]*100:.1f}% - {dev_metrics['rates']['decision_match_rate']['ci_95'][1]*100:.1f}%]",
            f"- False Positive Rate:       {dev_metrics['rates']['false_positive_rate']['percentage']:>7} ({dev_metrics['summary']['benign_false_positives']}/{dev_metrics['summary']['benign_count']})       [95% CI: {dev_metrics['rates']['false_positive_rate']['ci_95'][0]*100:.1f}% - {dev_metrics['rates']['false_positive_rate']['ci_95'][1]*100:.1f}%]",
            f"- Prevention Rate:           {dev_metrics['rates']['prevention_rate']['percentage']:>7} ({dev_metrics['summary']['attacks_prevented']}/{dev_metrics['summary']['attack_count']})       [95% CI: {dev_metrics['rates']['prevention_rate']['ci_95'][0]*100:.1f}% - {dev_metrics['rates']['prevention_rate']['ci_95'][1]*100:.1f}%]",
            f"- Records Exposed to Agent:  {dev_metrics['records']['total_records_exposed_to_agent']:>7} records across {dev_metrics['records']['attacks_with_exposed_records']} attacks",
            f"- Records Exfiltrated:       {dev_metrics['records']['total_records_exfiltrated']:>7} records (Target: 0)",
            f"- Late Detections:           {dev_metrics['records']['late_detections_count']:>7} attacks blocked at egress after prior read",
        ])

    if held_out_metrics and held_out_metrics['summary']['total_scenarios'] > 0:
        lines.extend([
            "",
            "-" * 100,
            f"HELD-OUT SET EVALUATION ({held_out_metrics['summary']['attack_count']} Attacks, {held_out_metrics['summary']['benign_count']} Benign)",
            "* Label: generalization evidence, small sample, scenarios written by the project author",
            f"- Detection Rate:            {held_out_metrics['rates']['detection_rate']['percentage']:>7} ({held_out_metrics['summary']['attacks_detected']}/{held_out_metrics['summary']['attack_count']})       [95% CI: {held_out_metrics['rates']['detection_rate']['ci_95'][0]*100:.1f}% - {held_out_metrics['rates']['detection_rate']['ci_95'][1]*100:.1f}%]",
            f"- Decision-Match Rate:       {held_out_metrics['rates']['decision_match_rate']['percentage']:>7} ({held_out_metrics['summary']['decision_matches']}/{held_out_metrics['summary']['total_scenarios']})       [95% CI: {held_out_metrics['rates']['decision_match_rate']['ci_95'][0]*100:.1f}% - {held_out_metrics['rates']['decision_match_rate']['ci_95'][1]*100:.1f}%]",
            f"- False Positive Rate:       {held_out_metrics['rates']['false_positive_rate']['percentage']:>7} ({held_out_metrics['summary']['benign_false_positives']}/{held_out_metrics['summary']['benign_count']})       [95% CI: {held_out_metrics['rates']['false_positive_rate']['ci_95'][0]*100:.1f}% - {held_out_metrics['rates']['false_positive_rate']['ci_95'][1]*100:.1f}%]",
            f"- Prevention Rate:           {held_out_metrics['rates']['prevention_rate']['percentage']:>7} ({held_out_metrics['summary']['attacks_prevented']}/{held_out_metrics['summary']['attack_count']})       [95% CI: {held_out_metrics['rates']['prevention_rate']['ci_95'][0]*100:.1f}% - {held_out_metrics['rates']['prevention_rate']['ci_95'][1]*100:.1f}%]",
            f"- Records Exposed to Agent:  {held_out_metrics['records']['total_records_exposed_to_agent']:>7} records across {held_out_metrics['records']['attacks_with_exposed_records']} attacks",
            f"- Records Exfiltrated:       {held_out_metrics['records']['total_records_exfiltrated']:>7} records (Target: 0)",
            f"- Late Detections:           {held_out_metrics['records']['late_detections_count']:>7} attacks blocked at egress after prior read",
        ])

    lat = overall_metrics["latency_ms"]
    total_calls = overall_metrics["summary"]["total_step_calls"]
    lines.extend([
        "",
        "-" * 100,
        f"LATENCY OVER REAL GATEWAY PATH ({total_calls} Calls + {warm_up_calls} Warm-Up)",
        f"- Core Gateway Path (p50 / p90 / p95):     {lat['p50']:.1f} ms / {lat['p90']:.1f} ms / {lat['p95']:.1f} ms  (Target: <= 35.0 ms)",
        f"- Live LLM Judge Isolated (p50 / p95):    {judge_lat_str}",
        "=" * 100,
        "",
        "SCENARIO EXECUTION BREAKDOWN:",
    ])

    for r in results:
        stopped_info = f"Stopped at step {r.stopped_at_step}" if r.stopped_at_step is not None else "Completed all steps"
        match_str = "MATCH" if r.decision_match else "MISMATCH"
        late_str = "LATE_DET" if getattr(r, "late_detection", False) else "EARLY/CLEAN"
        lines.append(
            f"  [{r.scenario_id}] {r.scenario_name:<35} | Cat: {r.category:<6} | Expected: {r.expected_decision:<16} | "
            f"Actual: {r.actual_final_decision:<16} | {match_str} | {stopped_info} | "
            f"Exposed: {r.total_records_exposed_to_agent:>2} | Exfil: {r.total_records_exfiltrated:>2} | {late_str}"
        )
    lines.append("=" * 100)
    return "\n".join(lines)

def save_json_report(
    dev_metrics: Dict[str, Any],
    held_out_metrics: Optional[Dict[str, Any]],
    overall_metrics: Dict[str, Any],
    results: List[ScenarioExecutionResult],
    output_path: Path,
) -> None:
    """Exports structured JSON benchmark report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    from backend.app.judge.intent_judge import IntentJudge
    judge_evaluated = IntentJudge.is_evaluated_for_headline()
    report_data = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "telemetry": get_system_telemetry(),
            "mode": "recorded_llm_replay" if judge_evaluated else "deterministic_core (judge not evaluated)",
            "judge_status": "evaluated" if judge_evaluated else "judge not evaluated",
            "spec_version": "1.0",
        },
        "dev_set": dev_metrics,
        "held_out_set": held_out_metrics,
        "overall": overall_metrics,
        "scenarios": [
            {
                "id": r.scenario_id,
                "name": r.scenario_name,
                "category": r.category,
                "split": r.split,
                "target_agent": r.target_agent,
                "expected_decision": r.expected_decision,
                "actual_final_decision": r.actual_final_decision,
                "decision_match": r.decision_match,
                "detected": r.detected,
                "prevented": r.prevented,
                "stopped_at_step": r.stopped_at_step,
                "total_steps": r.total_steps,
                "total_latency_ms": r.total_latency_ms,
                "total_records_accessed": r.total_records_accessed,
                "total_records_leaked": r.total_records_leaked,
                "step_results": [
                    {
                        "step_index": s.step_index,
                        "tool_name": s.tool_name,
                        "simulated_timestamp": s.simulated_timestamp,
                        "actual_decision": s.actual_decision,
                        "expected_decision": s.expected_decision,
                        "decision_match": s.decision_match,
                        "latency_ms": s.latency_ms,
                        "risk_score": s.risk_score,
                        "reason": s.reason,
                        "records_accessed": s.records_accessed,
                        "records_leaked": s.records_leaked,
                    }
                    for s in r.step_results
                ],
            }
            for r in results
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

def generate_metrics_chart(
    overall_metrics: Dict[str, Any],
    output_path: Path,
) -> None:
    """
    Generates a high-quality 3-panel figure:
    Panel 1: Security Rates (Detection Rate & Prevention Rate with Wilson CIs)
    Panel 2: Operational Quality (False Positive Rate with Wilson CI)
    Panel 3: Real Gateway Latency (p50, p90, p95 with 35ms SLA target line)
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rates = overall_metrics["rates"]
    lat = overall_metrics["latency_ms"]

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle("SentinelMesh AI — Benchmark Evaluation Metrics", fontsize=14, fontweight="bold", y=1.02)

    # Panel 1: Security Rates (Detection & Prevention)
    sec_names = ["Detection Rate", "Prevention Rate"]
    det_val = rates["detection_rate"]["value"] * 100
    prev_val = rates["prevention_rate"]["value"] * 100
    sec_vals = [det_val, prev_val]

    det_ci = [c * 100 for c in rates["detection_rate"]["ci_95"]]
    prev_ci = [c * 100 for c in rates["prevention_rate"]["ci_95"]]
    yerr_lower = [sec_vals[0] - det_ci[0], sec_vals[1] - prev_ci[0]]
    yerr_upper = [det_ci[1] - sec_vals[0], prev_ci[1] - sec_vals[1]]

    bars1 = ax1.bar(
        sec_names,
        sec_vals,
        color=["#2563eb", "#16a34a"],
        yerr=[yerr_lower, yerr_upper],
        capsize=6,
        edgecolor="#1e293b",
        linewidth=1.2,
        width=0.45,
    )
    ax1.set_ylabel("Rate (%)", fontweight="bold")
    ax1.set_ylim(0, 115)
    ax1.set_title("Security Effectiveness\n(Wilson 95% CI)", fontsize=11, fontweight="bold")
    ax1.grid(axis="y", linestyle="--", alpha=0.5)

    for bar, val in zip(bars1, sec_vals):
        ax1.text(bar.get_x() + bar.get_width() / 2, val + 5, f"{val:.1f}%", ha="center", va="bottom", fontweight="bold")

    # Panel 2: False Positive Rate
    fpr_val = rates["false_positive_rate"]["value"] * 100
    fpr_ci = [c * 100 for c in rates["false_positive_rate"]["ci_95"]]
    fpr_yerr = [[fpr_val - fpr_ci[0]], [fpr_ci[1] - fpr_val]]

    bars2 = ax2.bar(
        ["False Positive Rate"],
        [fpr_val],
        color=["#ef4444" if fpr_val > 5 else "#10b981"],
        yerr=fpr_yerr,
        capsize=6,
        edgecolor="#1e293b",
        linewidth=1.2,
        width=0.35,
    )
    ax2.set_ylabel("Rate (%)", fontweight="bold")
    ax2.set_ylim(0, max(25, fpr_ci[1] + 10))
    ax2.set_title("Operational Reliability\n(Wilson 95% CI)", fontsize=11, fontweight="bold")
    ax2.grid(axis="y", linestyle="--", alpha=0.5)

    for bar in bars2:
        ax2.text(bar.get_x() + bar.get_width() / 2, fpr_val + 1, f"{fpr_val:.1f}%", ha="center", va="bottom", fontweight="bold")

    # Panel 3: Latency Telemetry
    lat_names = ["p50", "p90", "p95"]
    lat_vals = [lat["p50"], lat["p90"], lat["p95"]]

    bars3 = ax3.bar(
        lat_names,
        lat_vals,
        color=["#0284c7", "#0369a1", "#075985"],
        edgecolor="#1e293b",
        linewidth=1.2,
        width=0.45,
    )
    ax3.axhline(35.0, color="#dc2626", linestyle="--", linewidth=1.5, label="Target SLA (<=35ms)")
    ax3.set_ylabel("Latency (ms)", fontweight="bold")
    ax3.set_ylim(0, max(45.0, max(lat_vals) + 10.0))
    ax3.set_title("Gateway Path Latency\n(Real HTTP Nanosecond Telemetry)", fontsize=11, fontweight="bold")
    ax3.grid(axis="y", linestyle="--", alpha=0.5)
    ax3.legend(loc="upper left")

    for bar, val in zip(bars3, lat_vals):
        ax3.text(bar.get_x() + bar.get_width() / 2, val + 1, f"{val:.1f}ms", ha="center", va="bottom", fontweight="bold")

    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
