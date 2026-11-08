import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
from typing import List

from benchmark.harness.models import BenchmarkScenario, ScenarioExecutionResult
from benchmark.harness.runner import BenchmarkRunner
from benchmark.harness.metrics import compute_benchmark_metrics
from benchmark.harness.reporter import (
    generate_ascii_report,
    save_json_report,
    generate_metrics_chart,
)

def run_warm_up(runner: BenchmarkRunner, count: int = 10) -> None:
    """Sends warm-up tool calls through the gateway to eliminate cold-start overhead."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    for i in range(count):
        runner.execute_single_call(
            agent_id="warmup-agent",
            session_id=f"sess-warmup-{i}",
            tool_name="read_doc",
            arguments={"file_path": "warmup.txt"},
            context_sources=[],
            task_description="Warm-up gateway connection",
            timestamp=now,
        )

def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelMesh AI Benchmark Harness")
    parser.add_argument(
        "--scenarios-dir",
        type=str,
        default="benchmark/scenarios",
        help="Root directory for scenario JSON files",
    )
    parser.add_argument(
        "--scenario-id",
        type=str,
        default=None,
        help="Run only a specific scenario ID (e.g., ATK-001)",
    )
    parser.add_argument(
        "--split",
        type=str,
        choices=["all", "dev", "held_out"],
        default="all",
        help="Filter scenarios by split",
    )
    parser.add_argument(
        "--gateway-url",
        type=str,
        default="http://localhost:8000/api/v1/gateway/execute",
        help="Gateway execution endpoint",
    )
    parser.add_argument(
        "--warm-up-calls",
        type=int,
        default=10,
        help="Number of initial gateway calls for engine warm-up",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="benchmark/reports",
        help="Directory to save JSON reports and PNG charts",
    )

    args = parser.parse_args()
    base_dir = Path(args.scenarios_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Discover scenario files
    scenario_files: List[Path] = []
    if args.split in ["all", "dev"]:
        dev_dir = base_dir / "dev"
        if dev_dir.exists():
            scenario_files.extend(sorted(dev_dir.glob("*.json")))

    if args.split in ["all", "held_out"]:
        held_out_dir = base_dir / "held_out"
        if held_out_dir.exists():
            scenario_files.extend(sorted(held_out_dir.glob("*.json")))

    if not scenario_files:
        print(f"Error: No scenario files found in {base_dir}")
        return 1

    # Filter by specific ID if requested
    if args.scenario_id:
        scenario_files = [f for f in scenario_files if args.scenario_id.lower() in f.name.lower()]
        if not scenario_files:
            print(f"Error: Scenario '{args.scenario_id}' not found.")
            return 1

    # 2. Initialize Runner and Warm Up
    runner = BenchmarkRunner(gateway_url=args.gateway_url)
    print(f"Executing {args.warm_up_calls} gateway warm-up calls...")
    run_warm_up(runner, count=args.warm_up_calls)
    print("Warm-up complete. Replaying benchmark scenarios...\n")

    # 3. Replay Scenarios
    results: List[ScenarioExecutionResult] = []
    for s_file in scenario_files:
        scenario = runner.load_scenario_from_file(s_file)
        res = runner.replay_scenario(scenario)
        results.append(res)

    # 4. Compute Metrics per Split and Overall
    dev_results = [r for r in results if r.split == "dev"]
    held_out_results = [r for r in results if r.split == "held_out"]

    dev_metrics = compute_benchmark_metrics(dev_results)
    held_out_metrics = compute_benchmark_metrics(held_out_results) if held_out_results else None
    overall_metrics = compute_benchmark_metrics(results)

    # 5. Formatted ASCII Report
    report_text = generate_ascii_report(
        dev_metrics=dev_metrics,
        held_out_metrics=held_out_metrics,
        overall_metrics=overall_metrics,
        results=results,
        warm_up_calls=args.warm_up_calls,
    )
    print(report_text)

    # 6. Save JSON and Chart Artifacts
    json_path = out_dir / "benchmark_report.json"
    save_json_report(
        dev_metrics=dev_metrics,
        held_out_metrics=held_out_metrics,
        overall_metrics=overall_metrics,
        results=results,
        output_path=json_path,
    )
    print(f"\n[+] Saved JSON benchmark report: {json_path}")

    chart_path = out_dir / "benchmark_report_chart.png"
    generate_metrics_chart(overall_metrics=overall_metrics, output_path=chart_path)
    print(f"[+] Saved Metrics Chart: {chart_path}")

    # 7. Check regression / mismatch
    mismatches = [r for r in results if not r.decision_match]
    if mismatches:
        print(f"\n[!] WARNING: {len(mismatches)} scenario(s) failed decision match.")
        return 1

    print("\n[+] All benchmark scenarios passed with 100% decision match fidelity!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
