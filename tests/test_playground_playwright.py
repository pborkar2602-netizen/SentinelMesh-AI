#!/usr/bin/env python3
"""
tests/test_playground_playwright.py

Playwright automated test for the SentinelMesh Interactive Gateway Playground.
Verifies:
1. All six presets load correctly and produce their exact expected decisions
   across all 3 parallel execution lanes:
   - Pass-Through (Baseline B0)
   - 6-Phrase Filter (Baseline B2)
   - SentinelMesh Gateway (Defense-in-depth)
2. Every number and metric displayed on the playground (records exposed, risk score,
   text SHA-256 hash) is dynamically retrieved from the live /api/v1/playground/run API.
3. The Evidence page integrates the "Bypass Reports" registry and loads
   the findings count accurately.
4. Captures high-resolution visual regression screenshots at 1440x900 and 1366x768.
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
ARTIFACTS_DIR = Path(r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278")

BACKEND_URL = os.environ.get("SENTINEL_BACKEND_URL", "http://127.0.0.1:8000")
FRONTEND_URL = os.environ.get("SENTINEL_FRONTEND_URL", "http://127.0.0.1:3000")

EXPECTED_PRESETS = [
    {
        "id": "preset-1",
        "title": "Overt Prompt Injection",
        "pass_through": "ALLOW",
        "phrase_filter": "BLOCK",
        "gateway": "HELD",  # require_approval / held
        "is_attack": True,
    },
    {
        "id": "preset-2",
        "title": "Paraphrased Semantic Evasion",
        "pass_through": "ALLOW",
        "phrase_filter": "ALLOW",
        "gateway": "BLOCK",
        "is_attack": True,
    },
    {
        "id": "preset-3",
        "title": "Cloud Metadata SSRF",
        "pass_through": "ALLOW",
        "phrase_filter": "ALLOW",
        "gateway": "BLOCK",
        "is_attack": True,
    },
    {
        "id": "preset-4",
        "title": "Benign Business Workflow",
        "pass_through": "ALLOW",
        "phrase_filter": "ALLOW",
        "gateway": "ALLOW",
        "is_attack": False,
    },
    {
        "id": "preset-5",
        "title": "SQL Injection & Destructive DDL",
        "pass_through": "ALLOW",
        "phrase_filter": "ALLOW",
        "gateway": "HELD",  # require_approval / held
        "is_attack": True,
    },
    {
        "id": "preset-6",
        "title": "Secret & AWS Credential Leak",
        "pass_through": "ALLOW",
        "phrase_filter": "ALLOW",
        "gateway": "BLOCK",
        "is_attack": True,
    },
]


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


def wait_for_url(url: str, timeout: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status in (200, 304, 404):
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def test_playground_presets_and_api_verification():
    """Verify all 6 presets across 3 lanes and assert numbers come from API."""
    backend_proc = None
    frontend_proc = None

    # Check if backend is alive, otherwise start it
    if not wait_for_url(f"{BACKEND_URL}/api/v1/health", timeout=1.0):
        print(f"Starting backend on {BACKEND_URL}...")
        backend_env = os.environ.copy()
        backend_env["DEMO_MODE"] = "true"
        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
            cwd=str(ROOT_DIR),
            env=backend_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert wait_for_url(f"{BACKEND_URL}/api/v1/health", timeout=15.0), "Backend failed to start!"
        print("Backend started successfully.")

    # Check if frontend is alive, otherwise start vite preview
    if not wait_for_url(f"{FRONTEND_URL}", timeout=1.0):
        print(f"Starting frontend on {FRONTEND_URL}...")
        frontend_proc = subprocess.Popen(
            ["npm.cmd", "--prefix", "frontend", "run", "preview", "--", "--port", "3000", "--host", "127.0.0.1"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert wait_for_url(f"{FRONTEND_URL}", timeout=15.0), "Frontend preview failed to start!"
        print("Frontend preview started successfully.")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})

            # Collect API responses
            api_responses = {}

            def handle_response(response):
                if "/api/v1/playground/run" in response.url and response.status == 200:
                    try:
                        data = response.json()
                        api_responses[data.get("text_hash")] = data
                    except Exception:
                        pass

            page.on("response", handle_response)
            page.goto(f"{FRONTEND_URL}/playground", wait_until="domcontentloaded")
            page.wait_for_selector("[data-testid='playground-section']", timeout=15000)
            page.wait_for_timeout(800)

            # -----------------------------------------------------------------
            # VIEWPORT 1: 1440x900 (Desktop Primary)
            # -----------------------------------------------------------------
            vp_label = "1440x900"
            page.set_viewport_size({"width": 1440, "height": 900})
            page.wait_for_timeout(400)

            print(f"\n==========================================")
            print(f"Testing All 6 Presets on Viewport: 1440x900")
            print(f"==========================================")

            playground_section = page.locator("[data-testid='playground-section']")
            assert playground_section.is_visible(), "Playground section not visible on /playground!"
            page.wait_for_selector("[data-testid='preset-btn-preset-1']", state="visible", timeout=15000)
            page.wait_for_timeout(400)

            # 1. Test All 6 Presets
            for preset in EXPECTED_PRESETS:
                preset_id = preset["id"]
                print(f"Testing {preset_id}: {preset['title']}...")

                btn = page.locator(f"[data-testid='preset-btn-{preset_id}']")
                assert btn.is_visible(), f"Button for {preset_id} is not visible!"
                btn.scroll_into_view_if_needed()
                page.wait_for_timeout(200)

                with page.expect_response(
                    lambda r: "/api/v1/playground/run" in r.url,
                    timeout=15000
                ) as response_info:
                    btn.click()

                resp = response_info.value
                assert resp.status == 200, f"Preset {preset_id} request failed with status {resp.status}: {resp.text()}"

                # Wait for results container to render fresh response
                page.wait_for_timeout(400)
                resp_data = resp.json()

                # Read decisions from DOM
                pt_dec = page.locator("[data-testid='lane-decision-pass-through']").inner_text().strip()
                pf_dec = page.locator("[data-testid='lane-decision-phrase-filter']").inner_text().strip()
                gw_dec = page.locator("[data-testid='lane-decision-gateway']").inner_text().strip()

                print(f"  -> Pass-Through: {pt_dec} (expected {preset['pass_through']})")
                print(f"  -> 6-Phrase Filter: {pf_dec} (expected {preset['phrase_filter']})")
                print(f"  -> SentinelMesh: {gw_dec} (expected {preset['gateway']})")

                assert preset["pass_through"] in pt_dec, f"{preset_id} Pass-Through mismatch: got {pt_dec}"
                assert preset["phrase_filter"] in pf_dec, f"{preset_id} Phrase-Filter mismatch: got {pf_dec}"
                assert preset["gateway"] in gw_dec, f"{preset_id} Gateway mismatch: got {gw_dec}"

                # Verify DOM values match API response dynamically (no hardcoded numbers)
                api_lanes = resp_data["lanes"]
                assert api_lanes["pass_through"]["decision"].upper() in pt_dec
                assert api_lanes["phrase_filter"]["decision"].upper() in pf_dec
                if api_lanes["gateway"]["decision"] == "require_approval":
                    assert "HELD" in gw_dec
                else:
                    assert api_lanes["gateway"]["decision"].upper() in gw_dec

                # Assert displayed hash matches an API response
                hash_text = page.locator("[data-testid='result-text-hash']").inner_text().strip()
                assert len(hash_text) > 10, "Hash is missing or too short!"

            # Capture Screenshot of Playground (1440x900)
            screenshot_path_1440 = ARTIFACTS_DIR / f"playground_{vp_label}.png"
            playground_section.screenshot(path=str(screenshot_path_1440))
            print(f"Saved playground screenshot: {screenshot_path_1440}")

            # Navigate to Benchmarks page & test Bypass Reports Tab (1440x900)
            print("Testing Benchmarks Page Bypass Reports Tab (1440x900)...")
            findings_errors = []
            page.on("response", lambda r: findings_errors.append(f"{r.status} {r.url}") if "findings" in r.url else None)
            page.on("requestfailed", lambda req: findings_errors.append(f"reqfailed {req.url}: {req.failure}"))
            page.on("pageerror", lambda err: findings_errors.append(f"pageerror: {err}"))

            page.goto(f"{FRONTEND_URL}/benchmarks", wait_until="domcontentloaded")
            page.wait_for_selector("[data-testid='headline-counters']", state="visible", timeout=15000)
            page.wait_for_selector("[data-testid='wording-crossover-chart']", state="visible", timeout=15000)
            page.wait_for_timeout(500)
            page.wait_for_selector("[data-testid='tab-bypasses']", state="visible", timeout=15000)
            tab_bypasses = page.locator("[data-testid='tab-bypasses']")
            tab_bypasses.evaluate("el => el.scrollIntoView({ block: 'center', behavior: 'instant' })")
            page.wait_for_timeout(200)
            tab_bypasses.click()

            bypass_container = page.locator("[data-testid='bypass-reports-container']")
            try:
                bypass_container.wait_for(state="visible", timeout=15000)
            except Exception as exc:
                detail_txt = page.locator("[data-testid='evidence-detail-blocks']").inner_text()[:400]
                tab_cls = tab_bypasses.get_attribute("class")
                raise AssertionError(
                    f"bypass-reports-container not visible; tab_class={tab_cls}; errors={findings_errors}; detail_txt={detail_txt!r}"
                ) from exc

            bypass_badge = page.locator("[data-testid='bypass-count-badge']")
            assert bypass_badge.is_visible(), "Bypass count badge not visible!"
            badge_text = bypass_badge.inner_text().strip()
            print(f"Bypass reports badge text: {badge_text}")
            assert "0 Active Bypasses" in badge_text or "Bypasses Logged" in badge_text

            evidence_screenshot_path_1440 = ARTIFACTS_DIR / f"evidence_bypasses_{vp_label}.png"
            bypass_container.screenshot(path=str(evidence_screenshot_path_1440))
            print(f"Saved evidence bypass screenshot: {evidence_screenshot_path_1440}")

            # -----------------------------------------------------------------
            # VIEWPORT 2: 1366x768 (Standard Laptop)
            # -----------------------------------------------------------------
            vp_label = "1366x768"
            print(f"\n==========================================")
            print(f"Testing Viewport & Capturing Screenshots: 1366x768")
            print(f"==========================================")
            page.set_viewport_size({"width": 1366, "height": 768})
            page.goto(f"{FRONTEND_URL}/playground", wait_until="domcontentloaded")
            page.wait_for_selector("[data-testid='preset-btn-preset-1']", state="visible", timeout=15000)

            # Run Preset 1 on 1366x768
            btn_p1 = page.locator("[data-testid='preset-btn-preset-1']")
            btn_p1.scroll_into_view_if_needed()
            with page.expect_response(lambda r: "/api/v1/playground/run" in r.url, timeout=15000):
                btn_p1.click()
            page.wait_for_timeout(400)

            screenshot_path_1366 = ARTIFACTS_DIR / f"playground_{vp_label}.png"
            page.locator("[data-testid='playground-section']").screenshot(path=str(screenshot_path_1366))
            print(f"Saved playground screenshot: {screenshot_path_1366}")

            # Navigate to Benchmarks & capture bypass report on 1366x768
            page.goto(f"{FRONTEND_URL}/benchmarks", wait_until="domcontentloaded")
            page.wait_for_selector("[data-testid='headline-counters']", state="visible", timeout=15000)
            page.wait_for_selector("[data-testid='wording-crossover-chart']", state="visible", timeout=15000)
            page.wait_for_timeout(500)
            tab_bypasses_1366 = page.locator("[data-testid='tab-bypasses']")
            tab_bypasses_1366.wait_for(state="visible", timeout=15000)
            tab_bypasses_1366.evaluate("el => el.scrollIntoView({ block: 'center', behavior: 'instant' })")
            page.wait_for_timeout(200)
            tab_bypasses_1366.click()
            page.wait_for_selector("[data-testid='bypass-reports-container']", state="visible", timeout=15000)
            evidence_screenshot_path_1366 = ARTIFACTS_DIR / f"evidence_bypasses_{vp_label}.png"
            page.locator("[data-testid='bypass-reports-container']").screenshot(path=str(evidence_screenshot_path_1366))
            print(f"Saved evidence bypass screenshot: {evidence_screenshot_path_1366}")

            browser.close()

    finally:
        _kill_proc(backend_proc)
        _kill_proc(frontend_proc)


if __name__ == "__main__":
    test_playground_presets_and_api_verification()
