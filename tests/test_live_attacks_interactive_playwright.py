import os
import sys
import time
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = Path(
    r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278"
)

def test_live_attacks_interactive():
    # Start backend in DEMO_MODE
    backend_env = dict(os.environ, DEMO_MODE="true")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
        cwd=str(ROOT_DIR),
        env=backend_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Start frontend preview
    frontend_proc = subprocess.Popen(
        ["npm.cmd", "--prefix", "frontend", "run", "preview", "--", "--port", "3000", "--host", "127.0.0.1"],
        cwd=str(ROOT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3.5)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})

            # Navigate to Console
            page.goto("http://127.0.0.1:3000/console", wait_until="domcontentloaded")
            page.wait_for_timeout(1000)

            # -------------------------------------------------------------
            # TEST 1: ATK-001 in MONITOR mode (HR Agent Exfiltration)
            # -------------------------------------------------------------
            print("\n>>> Testing ATK-001 in MONITOR mode...")
            page.locator("#mM").click()
            page.wait_for_timeout(400)
            
            selector = page.locator("[data-testid='scenario-selector']")
            selector.select_option("atk-001")
            page.wait_for_timeout(200)

            run_btn = page.locator("[data-testid='run-attack-btn']")
            run_btn.click()
            print("Clicked Run Attack Scenario for ATK-001...")

            # Wait for events to flow through WebSocket and animate chain
            page.wait_for_timeout(4000)

            # Assert Step 1 & Step 4 are active
            s0_classes = page.locator("#s0").get_attribute("class") or ""
            s3_classes = page.locator("#s3").get_attribute("class") or ""
            print(f"Step 0 classes: {s0_classes}")
            print(f"Step 3 classes: {s3_classes}")
            assert "on" in s0_classes, "Step 0 did not activate"
            assert "on" in s3_classes, "Step 3 did not activate in Monitor mode"

            # Check verdict
            vd_text = page.locator("#vd").inner_text()
            print(f"Verdict ATK-001 (Monitor): {vd_text}")
            assert "LEAKED" in vd_text.upper() or "recruiter" in vd_text.lower(), f"Unexpected verdict: {vd_text}"

            # Capture screenshot
            shot1 = ARTIFACTS_DIR / "live_atk001_monitor_active_1440x900.png"
            page.screenshot(path=str(shot1))
            print(f"Captured {shot1.name}")

            # -------------------------------------------------------------
            # TEST 2: ATK-002 in ENFORCE mode (Finance Agent Wire Fraud)
            # -------------------------------------------------------------
            print("\n>>> Testing ATK-002 in ENFORCE mode...")
            page.locator("#mE").click()
            page.wait_for_timeout(400)

            selector.select_option("atk-002")
            page.wait_for_timeout(200)

            run_btn.click()
            print("Clicked Run Attack Scenario for ATK-002...")

            page.wait_for_timeout(4000)

            s0_text = page.locator("#s0").inner_text()
            s2_text = page.locator("#s2").inner_text()
            print(f"Step 0 text: {s0_text}")
            print(f"Step 2 text: {s2_text}")
            assert "Invoice" in s0_text or "uploaded" in s0_text, f"Step 0 text mismatch: {s0_text}"
            assert "SQL" in s2_text or "mutation" in s2_text, f"Step 2 text mismatch: {s2_text}"

            vd_text_fin = page.locator("#vd").inner_text()
            print(f"Verdict ATK-002 (Enforce): {vd_text_fin}")
            assert "BLOCKED" in vd_text_fin.upper(), f"Expected BLOCKED verdict, got: {vd_text_fin}"

            shot2 = ARTIFACTS_DIR / "live_atk002_finance_blocked_1440x900.png"
            page.screenshot(path=str(shot2))
            print(f"Captured {shot2.name}")

            # -------------------------------------------------------------
            # TEST 3: ATK-003 in ENFORCE mode (Ops Agent Cloud SSRF)
            # -------------------------------------------------------------
            print("\n>>> Testing ATK-003 in ENFORCE mode...")
            selector.select_option("atk-003")
            page.wait_for_timeout(200)

            run_btn.click()
            print("Clicked Run Attack Scenario for ATK-003...")

            page.wait_for_timeout(4000)

            s0_text_ops = page.locator("#s0").inner_text()
            s1_text_ops = page.locator("#s1").inner_text()
            print(f"Ops Step 0 text: {s0_text_ops}")
            print(f"Ops Step 1 text: {s1_text_ops}")
            assert "log" in s0_text_ops.lower() or "read" in s0_text_ops.lower(), f"Ops step 0 mismatch: {s0_text_ops}"
            assert "ssrf" in s1_text_ops.lower() or "instruction" in s1_text_ops.lower(), f"Ops step 1 mismatch: {s1_text_ops}"

            vd_text_ops = page.locator("#vd").inner_text()
            print(f"Verdict ATK-003 (Enforce): {vd_text_ops}")
            assert "BLOCKED" in vd_text_ops.upper(), f"Expected BLOCKED verdict, got: {vd_text_ops}"

            shot3 = ARTIFACTS_DIR / "live_atk003_ops_ssrf_blocked_1440x900.png"
            page.screenshot(path=str(shot3))
            print(f"Captured {shot3.name}")

            print("\nALL 3 AGENT ATTACK SCENARIOS VERIFIED END-TO-END IN BROWSER WITH REAL WEBSOCKET TELEMETRY!")

    finally:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(backend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    test_live_attacks_interactive()
