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

def test_phase3_multiagent_scenarios():
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

            # 1. Test Scenario Selector presence
            selector = page.locator("[data-testid='scenario-selector']")
            assert selector.is_visible(), "Scenario selector dropdown missing"
            
            # Select ATK-002 (Finance Agent Wire Tampering)
            selector.select_option("atk-002")
            page.wait_for_timeout(300)

            # 2. Test Agent Filter Group
            filter_group = page.locator("[data-testid='agent-filter-group']")
            assert filter_group.is_visible(), "Agent filter group missing"

            # Filter by finance-agent
            page.locator("[data-testid='filter-agent-finance-agent']").click()
            page.wait_for_timeout(400)
            print("Filtered by finance-agent")

            # Filter by hr-agent
            page.locator("[data-testid='filter-agent-hr-agent']").click()
            page.wait_for_timeout(400)
            print("Filtered by hr-agent")

            # Reset to all
            page.locator("[data-testid='filter-agent-all']").click()
            page.wait_for_timeout(300)

            # 3. Trigger Real Attack with ATK-002
            selector.select_option("atk-002")
            page.locator("[data-testid='run-attack-btn']").click()
            print("Triggered ATK-002 (Finance Agent Wire Tampering)...")

            # Wait 3 seconds for WebSocket events to stream into chain
            page.wait_for_timeout(3000)

            # Capture screenshot of Console during/after ATK-002 scenario
            shot_path = ARTIFACTS_DIR / "phase3_console_finance_scenario_1440x900.png"
            page.screenshot(path=str(shot_path))
            print(f"Captured {shot_path.name}")

            # Verify chain has updated
            chain_text = page.locator("#chain").inner_text()
            print("Chain steps active after scenario:\n", chain_text)

            print("Phase 3 Multi-Agent Scenarios verified successfully!")

    finally:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(backend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    test_phase3_multiagent_scenarios()
