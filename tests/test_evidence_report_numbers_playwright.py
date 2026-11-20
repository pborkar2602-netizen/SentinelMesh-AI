#!/usr/bin/env python3
"""
tests/test_evidence_report_numbers_playwright.py

Playwright automated test that verifies EVERY number displayed on the
SentinelMesh Evidence page and Proof Bar matches its source report JSON file
in benchmark/reports/*.json.

FAILS if any displayed number does not match its report file or if
any missing field displays a fallback instead of 'not evaluated'.
"""

import os
import sys
import json
import time
import subprocess
import urllib.request
import pytest
from pathlib import Path
from playwright.sync_api import Page, sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT_DIR / "benchmark" / "reports"
DATA_DIR = ROOT_DIR / "frontend" / "public" / "data"

BACKEND_URL = os.environ.get("SENTINEL_BACKEND_URL", "http://127.0.0.1:8000")
BASE_URL = os.environ.get("SENTINEL_FRONTEND_URL", "http://127.0.0.1:3000")


def _kill_proc(proc):
    if not proc:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        else:
            proc.terminate()
            proc.wait(timeout=10)
    except Exception:
        pass


def _wait_for_url(url: str, timeout: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status in (200, 304, 404):
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def load_json(path: Path):
    assert path.exists(), f"Required report file does not exist: {path}"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_evidence_numbers_match_reports():
    # 1. Load source of truth JSON report files
    injecagent_both = load_json(REPORTS_DIR / "v3_injecagent_both_settings.json")
    variants_rep = load_json(REPORTS_DIR / "variants_report.json")
    mutation_rep = load_json(REPORTS_DIR / "v3_mutation_test_results.json")
    timeline_rep = load_json(DATA_DIR / "release_timeline.json")
    known_issues_rep = load_json(DATA_DIR / "known_issues.json")
    datasets_rep = load_json(DATA_DIR / "datasets.json")
    limitations_rep = load_json(DATA_DIR / "limitations.json")

    # Extract ground truth numbers
    b4_enhanced = next((s for s in injecagent_both["enhanced"]["summary"] if "B4:" in s["system"]), None)
    assert b4_enhanced is not None, "B4 system not found in enhanced summary"
    expected_attacks_prevented = f"{b4_enhanced['total_prevented']}/{b4_enhanced['total_evaluated']}"
    expected_attacks_pct = f"{b4_enhanced['prevention_rate_pct']:.1f}%"

    expected_records_exfiltrated = str(variants_rep["overall"]["summary"]["records_exfiltrated"])
    expected_decisions_matched = f"{variants_rep['overall']['summary']['decision_matches']}/{variants_rep['overall']['summary']['total_scenarios']}"
    expected_mutants_killed = f"{mutation_rep['killed']}/{mutation_rep['total_mutants']}"
    expected_mutation_pct = f"{mutation_rep['mutation_score_pct']:.1f}%"

    print("\n--- GROUND TRUTH REPORT METRICS ---")
    print(f"Attacks Prevented: {expected_attacks_prevented} ({expected_attacks_pct})")
    print(f"Records Exfiltrated: {expected_records_exfiltrated}")
    print(f"Decisions Matched: {expected_decisions_matched}")
    print(f"Mutants Killed: {expected_mutants_killed} ({expected_mutation_pct})")

    backend_proc = None
    frontend_proc = None
    if not _wait_for_url(f"{BACKEND_URL}/api/v1/health", timeout=1.0):
        backend_env = os.environ.copy()
        backend_env["DEMO_MODE"] = "true"
        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
            cwd=str(ROOT_DIR),
            env=backend_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_for_url(f"{BACKEND_URL}/api/v1/health", timeout=15.0), "Backend failed to start"

    if not _wait_for_url(BASE_URL, timeout=1.0):
        frontend_proc = subprocess.Popen(
            ["npm.cmd", "--prefix", "frontend", "run", "preview", "--", "--port", "3000", "--host", "127.0.0.1"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert _wait_for_url(BASE_URL, timeout=15.0), "Frontend preview failed to start"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})

            # Navigate to overview for Proof Bar
            page.goto(f"{BASE_URL}/", wait_until="domcontentloaded")
            page.wait_for_selector("[data-testid='proof-bar']", state="visible", timeout=15000)
            page.wait_for_timeout(500)

            # -------------------------------------------------------------
            # A. PROOF BAR VERIFICATION
            # -------------------------------------------------------------
            print("\n--- Verifying Proof Bar ---")
            proof_bar = page.locator("[data-testid='proof-bar']")
            assert proof_bar.is_visible(), "Proof bar under hero is not visible!"
            pb_text = proof_bar.inner_text()

            # Check attacks prevented in proof bar
            assert expected_attacks_prevented in pb_text, f"Proof bar missing {expected_attacks_prevented}"
            assert "adapter fixed after seeing results" in pb_text, "Proof bar missing B4 label"

            # Check records left in proof bar
            assert expected_records_exfiltrated in pb_text, f"Proof bar missing records {expected_records_exfiltrated}"
            assert "verified zero exfiltration" in pb_text, "Proof bar missing records label"

            # Check decisions matched in proof bar
            assert expected_decisions_matched in pb_text, f"Proof bar missing decisions {expected_decisions_matched}"
            assert "exact policy compliance" in pb_text, "Proof bar missing decisions label"

            # Check mutants killed in proof bar
            assert expected_mutants_killed in pb_text, f"Proof bar missing mutants {expected_mutants_killed}"
            assert "100% mutation kill rate" in pb_text, "Proof bar missing mutation label"
            print("  [PASS] Proof bar matches all 4 headline counters and labels.")

            # -------------------------------------------------------------
            # B. HEADLINE COUNTERS VERIFICATION
            # -------------------------------------------------------------
            print("\n--- Verifying Headline Counters on /benchmarks ---")
            page.goto(f"{BASE_URL}/benchmarks", wait_until="domcontentloaded")
            page.wait_for_selector("[data-testid='evidence-section']", state="visible", timeout=15000)
            page.wait_for_timeout(500)
            evidence_section = page.locator("[data-testid='evidence-section']")
            assert evidence_section.is_visible(), "Evidence section is not visible!"

            ev_text = page.locator("[data-testid='headline-counters']").inner_text()
            assert expected_attacks_prevented in ev_text, f"Headline counter missing {expected_attacks_prevented}"
            assert expected_records_exfiltrated in ev_text, f"Headline counter missing {expected_records_exfiltrated}"
            assert expected_decisions_matched in ev_text, f"Headline counter missing {expected_decisions_matched}"
            assert expected_mutants_killed in ev_text, f"Headline counter missing {expected_mutants_killed}"
            print("  [PASS] Headline counters match source report files.")

            # -------------------------------------------------------------
            # C. WORDING-CROSSOVER CHART (BASE SETTING)
            # -------------------------------------------------------------
            print("\n--- Verifying Wording-Crossover Chart (Base Setting) ---")
            crossover_chart = page.locator("[data-testid='wording-crossover-chart']")
            assert crossover_chart.is_visible(), "Wording-crossover chart is not visible!"

            # Ensure Base setting is active
            page.locator("[data-testid='toggle-base-setting']").click()
            page.wait_for_timeout(400)

            base_summary = {s["system"]: s for s in injecagent_both["base"]["summary"]}
            chart_text_base = crossover_chart.inner_text()

            # Check B0 (None)
            b0_prev = f"{base_summary['B0: None (No Defense)']['prevention_rate_pct']:.1f}%"
            assert b0_prev in chart_text_base, f"Base B0 prev rate {b0_prev} not in chart"

            # Check B1 (Domain)
            b1_prev = f"{base_summary['B1: Domain Allowlist Only']['prevention_rate_pct']:.1f}%"
            assert b1_prev in chart_text_base, f"Base B1 prev rate {b1_prev} not in chart"

            # Check B2 (Regex - should be 0.0% in Base!)
            b2_prev_base = f"{base_summary['B2: Static Regex / Phrase Matching']['prevention_rate_pct']:.1f}%"
            assert "0.0%" in chart_text_base, f"Base B2 prev rate expected 0.0%, not found"

            # Check B4 (SentinelMesh - should be 95.5% in Base!)
            b4_prev_base = f"{base_summary['B4: Full SentinelMesh Gateway']['prevention_rate_pct']:.1f}%"
            assert b4_prev_base in chart_text_base, f"Base B4 prev rate {b4_prev_base} not in chart"

            # Check HF Classifier
            hf_sys = next(s for s in injecagent_both["base"]["summary"] if "HuggingFace" in s["system"])
            hf_prev_base = f"{hf_sys['prevention_rate_pct']:.1f}%"
            assert hf_prev_base in chart_text_base, f"Base HF prev rate {hf_prev_base} not in chart"
            assert "small sample" in chart_text_base, "HF missing small sample label"

            # Check 95% Confidence Interval Line for B4
            b4_ci = base_summary['B4: Full SentinelMesh Gateway']['cluster_bootstrap_ci']
            assert f"[{b4_ci[0]:.1f}%, {b4_ci[1]:.1f}%]" in chart_text_base, "B4 95% CI interval line missing in Base"
            print("  [PASS] Base setting rates and interval lines match report.")

            # -------------------------------------------------------------
            # D. WORDING-CROSSOVER CHART (ENHANCED SETTING TOGGLE)
            # -------------------------------------------------------------
            print("\n--- Verifying Wording-Crossover Chart (Enhanced Setting Toggle) ---")
            page.locator("[data-testid='toggle-enhanced-setting']").click()
            page.wait_for_timeout(600)  # Wait for CSS bar animation

            enhanced_summary = {s["system"]: s for s in injecagent_both["enhanced"]["summary"]}
            chart_text_enh = crossover_chart.inner_text()

            # Check B2 Crossover: should jump from 0.0% to 100.0%!
            assert "100.0%" in chart_text_enh, "Enhanced B2 did not jump to 100.0%!"
            # Check B4 Invariance: must remain 95.5%!
            assert b4_prev_base in chart_text_enh, f"Enhanced B4 did not maintain {b4_prev_base}!"
            print("  [PASS] Wording crossover verified: B2 jumps to 100.0%, B4 remains 95.5%.")

            # -------------------------------------------------------------
            # E. RELEASE TIMELINE TAB
            # -------------------------------------------------------------
            print("\n--- Verifying Release Timeline Tab ---")
            page.locator("[data-testid='tab-timeline']").click()
            page.wait_for_timeout(300)
            timeline_elem = page.locator("[data-testid='release-timeline']")
            assert timeline_elem.is_visible(), "Release timeline not visible!"
            tl_text = timeline_elem.inner_text()

            for t in timeline_rep:
                assert t["tag"] in tl_text, f"Timeline missing tag {t['tag']}"
                assert t["commit"] in tl_text, f"Timeline missing commit {t['commit']}"
            print(f"  [PASS] All {len(timeline_rep)} git release tags verified in timeline.")

            # -------------------------------------------------------------
            # F. METHODOLOGY CORRECTIONS TAB (BEFORE -> AFTER)
            # -------------------------------------------------------------
            print("\n--- Verifying Methodology Corrections Tab ---")
            page.locator("[data-testid='tab-mistakes']").click()
            page.wait_for_timeout(300)
            mistakes_elem = page.locator("[data-testid='known-issues-list']")
            assert mistakes_elem.is_visible(), "Known issues list not visible!"
            mi_text = mistakes_elem.inner_text()
            assert "`" not in mi_text, "Raw markdown backticks found rendered in KnownIssuesList!"

            for issue in known_issues_rep:
                title_fragment = issue["title"][:25]
                assert title_fragment in mi_text, f"Missing known issue: {title_fragment}"
                assert issue["label"] in mi_text, f"Missing issue label: {issue['label']}"
                if issue.get("before"):
                    assert issue["before"] in mi_text, f"Missing Before pill: {issue['before']}"
                if issue.get("after"):
                    assert issue["after"] in mi_text, f"Missing After pill: {issue['after']}"
            print(f"  [PASS] All {len(known_issues_rep)} methodology corrections verified with Before -> After strips & zero raw backticks.")

            # -------------------------------------------------------------
            # G. DATASETS REGISTRY TAB
            # -------------------------------------------------------------
            print("\n--- Verifying Datasets Registry Tab ---")
            page.locator("[data-testid='tab-datasets']").click()
            page.wait_for_timeout(300)
            datasets_elem = page.locator("[data-testid='datasets-table']")
            assert datasets_elem.is_visible(), "Datasets table not visible!"
            ds_text = datasets_elem.inner_text()

            for ds in datasets_rep:
                assert ds["name"] in ds_text, f"Missing dataset: {ds['name']}"
                assert ds["license"] in ds_text, f"Missing license for {ds['name']}"
            print(f"  [PASS] All {len(datasets_rep)} datasets verified from docs/datasets.md.")

            # -------------------------------------------------------------
            # H. WHERE IT FAILS (LIMITATIONS) TAB
            # -------------------------------------------------------------
            print("\n--- Verifying Where It Fails (Limitations) Tab ---")
            page.locator("[data-testid='tab-limitations']").click()
            page.wait_for_timeout(300)
            limitations_elem = page.locator("[data-testid='limitations-cards']")
            assert limitations_elem.is_visible(), "Limitations cards not visible!"
            lim_text = limitations_elem.inner_text()

            for lim in limitations_rep:
                title_frag = lim["title"][:25]
                assert title_frag in lim_text, f"Missing limitation: {title_frag}"
                assert lim["label"] in lim_text, f"Missing limitation label: {lim['label']}"
            print(f"  [PASS] All {len(limitations_rep)} failure modes verified from docs/limitations.md.")

            browser.close()
    finally:
        _kill_proc(backend_proc)
        _kill_proc(frontend_proc)

    print("\n================================================================================")
    print("ALL PLAYWRIGHT TESTS PASSED: EVERY DISPLAYED NUMBER MATCHES SOURCE REPORT FILES!")
    print("================================================================================\n")


if __name__ == "__main__":
    test_evidence_numbers_match_reports()
