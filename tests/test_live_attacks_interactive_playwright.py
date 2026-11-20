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
    backend_env = dict(os.environ, DEMO_MODE="true")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
        cwd=str(ROOT_DIR),
        env=backend_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    frontend_proc = subprocess.Popen(
        ["npm.cmd", "--prefix", "frontend", "run", "preview", "--", "--port", "3000", "--host", "127.0.0.1"],
        cwd=str(ROOT_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(4.0)  # allow both servers to start

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})

            page.goto("http://127.0.0.1:3000/console", wait_until="domcontentloaded")
            page.wait_for_timeout(1500)

            # ----------------------------------------------------------------
            # TEST 1: ATK-001 — Monitor mode (HR Résumé Exfiltration)
            # ----------------------------------------------------------------
            print("\n>>> Testing ATK-001 in MONITOR mode...")
            page.locator("#mM").click()
            page.wait_for_timeout(500)

            selector = page.locator("[data-testid='scenario-selector']")
            selector.select_option("atk-001")
            page.wait_for_timeout(300)

            run_btn = page.locator("[data-testid='run-attack-btn']")
            run_btn.click()
            print("Clicked Run Attack Scenario for ATK-001...")

            page.wait_for_selector("#vd.show", timeout=8000)
            page.wait_for_timeout(300)

            s0_classes = page.locator("#s0").get_attribute("class") or ""
            assert "on" in s0_classes, f"ATK-001 Step 0 did not activate via WS! classes={s0_classes}"

            s0_text = page.locator("#s0").inner_text()
            s4_text = page.locator("#s4").inner_text()
            print(f"ATK-001 Step 0: {s0_text}")
            print(f"ATK-001 Step 4: {s4_text}")

            vd_text = page.locator("#vd").inner_text()
            print(f"Verdict ATK-001 (Monitor): {vd_text}")
            assert vd_text.strip(), "Verdict is empty — real WS event did not populate verdict"
            assert "LEAKED" in vd_text.upper(), f"Expected LEAKED verdict in Monitor mode, got: {vd_text}"

            shot1 = ARTIFACTS_DIR / "live_atk001_monitor_active_1440x900.png"
            page.screenshot(path=str(shot1))
            print(f"Captured {shot1.name}")

            # ----------------------------------------------------------------
            # TEST 2: ATK-002 — Enforce mode (Finance Wire Fraud)
            # ----------------------------------------------------------------
            print("\n>>> Testing ATK-002 in ENFORCE mode...")
            page.locator("#mE").click()
            page.wait_for_timeout(500)

            selector.select_option("atk-002")
            page.wait_for_timeout(300)

            run_btn.click()
            print("Clicked Run Attack Scenario for ATK-002...")

            page.wait_for_selector("#vd.show", timeout=8000)
            page.wait_for_timeout(300)

            s0_classes_fin = page.locator("#s0").get_attribute("class") or ""
            assert "on" in s0_classes_fin, f"ATK-002 Step 0 did not activate via WS! classes={s0_classes_fin}"

            s0_text_fin = page.locator("#s0").inner_text()
            s2_text_fin = page.locator("#s2").inner_text()
            print(f"ATK-002 Step 0: {s0_text_fin}")
            print(f"ATK-002 Step 2: {s2_text_fin}")
            assert "Invoice" in s0_text_fin or "vendor_invoice" in s0_text_fin, f"Step 0 mismatch: {s0_text_fin}"

            vd_text_fin = page.locator("#vd").inner_text()
            print(f"Verdict ATK-002 (Enforce): {vd_text_fin}")
            assert vd_text_fin.strip(), "Verdict empty for ATK-002"
            assert "BLOCKED" in vd_text_fin.upper(), f"Expected BLOCKED verdict in Enforce mode, got: {vd_text_fin}"

            shot2 = ARTIFACTS_DIR / "live_atk002_finance_blocked_1440x900.png"
            page.screenshot(path=str(shot2))
            print(f"Captured {shot2.name}")

            # ----------------------------------------------------------------
            # TEST 3: ATK-003 — Enforce mode (DevOps Cloud SSRF)
            # ----------------------------------------------------------------
            print("\n>>> Testing ATK-003 in ENFORCE mode...")
            selector.select_option("atk-003")
            page.wait_for_timeout(300)

            run_btn.click()
            print("Clicked Run Attack Scenario for ATK-003...")

            page.wait_for_selector("#vd.show", timeout=8000)
            page.wait_for_timeout(300)

            s0_classes_ops = page.locator("#s0").get_attribute("class") or ""
            assert "on" in s0_classes_ops, f"ATK-003 Step 0 did not activate via WS! classes={s0_classes_ops}"

            s0_text_ops = page.locator("#s0").inner_text()
            s1_text_ops = page.locator("#s1").inner_text()
            print(f"ATK-003 Step 0: {s0_text_ops}")
            print(f"ATK-003 Step 1: {s1_text_ops}")

            vd_text_ops = page.locator("#vd").inner_text()
            print(f"Verdict ATK-003 (Enforce): {vd_text_ops}")
            assert vd_text_ops.strip(), "Verdict empty for ATK-003"
            assert "BLOCKED" in vd_text_ops.upper(), f"Expected BLOCKED verdict in Enforce mode, got: {vd_text_ops}"

            shot3 = ARTIFACTS_DIR / "live_atk003_ops_ssrf_blocked_1440x900.png"
            page.screenshot(path=str(shot3))
            print(f"Captured {shot3.name}")

            print("\nALL 3 AGENT ATTACK SCENARIOS VERIFIED END-TO-END VIA REAL WEBSOCKET EVENTS!")

    finally:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(backend_proc.pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


if __name__ == "__main__":
    test_live_attacks_interactive()
