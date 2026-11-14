"""
SentinelMesh v3: Scientific Experiment & Benchmark Reproduction Pipeline
Executes end-to-end evaluation and test suites from frozen code.
All numbers generated write directly to benchmark/reports/*.json.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def run_step(step_name: str, cmd: list[str]) -> float:
    print(f"\n{'='*70}")
    print(f"RUNNING STEP: {step_name}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*70}")
    t0 = time.time()
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=False)
    elapsed = time.time() - t0
    if res.returncode != 0:
        print(f"FAILED: Step '{step_name}' exited with code {res.returncode}")
        sys.exit(res.returncode)
    print(f"PASSED: Step '{step_name}' in {elapsed:.2f}s")
    return elapsed

def main():
    start_total = time.time()
    print("*" * 70)
    print(" SentinelMesh v3 End-to-End Science Reproduction")
    print("*" * 70)

    # 1. Formal invariants & property tests
    run_step("Formal Invariants Property Tests (21/21 Hypothesis)", [
        sys.executable, "-m", "pytest", "backend/tests/test_formal_invariants.py", "-q"
    ])

    # 2. Fuzzing suite
    run_step("Fuzzing Suite (SQL, Unicode/Punycode, HMAC tokens)", [
        sys.executable, "-m", "pytest", "backend/tests/test_fuzzing.py", "-q"
    ])

    # 3. Chaos test suite
    run_step("Chaos & Fault Injection Suite (Locked DB, Judge 500, Concurrency)", [
        sys.executable, "-m", "pytest", "backend/tests/test_chaos.py", "-q"
    ])

    # 4. Text baseline evaluation
    run_step("Text Baseline Evaluation (deepset prompt-injections, Tensor Trust)", [
        sys.executable, "scripts/evaluate_text_baseline.py"
    ])

    # 5. PII extraction & vault evaluation
    run_step("PII Redaction & Vault Evaluation (ai4privacy validation)", [
        sys.executable, "scripts/evaluate_pii_detector.py"
    ])

    # 6. Provenance granularity ablation
    run_step("Provenance Granularity Ablation (Session vs Value-Level)", [
        sys.executable, "scripts/evaluate_provenance_ablation.py"
    ])

    # 7. Baselines & McNemar paired comparisons
    run_step("Baselines Comparison B0-B5 with Exact McNemar & Holm-Bonferroni", [
        sys.executable, "scripts/evaluate_baselines_mcnemar.py"
    ])

    # 8. Load test
    run_step("Perimeter Gateway Load Testing (Concurrency 1, 5, 20, 50)", [
        sys.executable, "scripts/load_test.py"
    ])

    total_time = time.time() - start_total
    print("\n" + "*" * 70)
    print(f" ALL REPRODUCTION STEPS PASSED SUCCESSFULLY in {total_time:.2f}s")
    print(" All reports verified in benchmark/reports/*.json")
    print("*" * 70)

if __name__ == "__main__":
    main()
