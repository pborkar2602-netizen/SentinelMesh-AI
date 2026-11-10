import sys
sys.path.insert(0, ".")
import json
from pathlib import Path
from benchmark.harness.runner import BenchmarkRunner
from benchmark.harness.reporter import generate_ascii_report, save_json_report
from benchmark.harness.metrics import compute_benchmark_metrics

DEV_DIR = Path("benchmark/scenarios/dev")
scenario_files = sorted(list(DEV_DIR.glob("*.json")))

runner = BenchmarkRunner()

results = []
for f in scenario_files:
    sc = runner.load_scenario_from_file(f)
    res = runner.replay_scenario(sc)
    results.append(res)

dev_results = [r for r in results if r.split == "dev"]
dev_metrics = compute_benchmark_metrics(dev_results)
overall_metrics = compute_benchmark_metrics(results)

report_text = generate_ascii_report(dev_metrics, None, overall_metrics, results)
print(report_text)

# Save JSON
json_path = Path("benchmark/reports/benchmark_report.json")
save_json_report(dev_metrics, None, overall_metrics, results, json_path)
print(f"\n[+] Saved updated report to {json_path}")
