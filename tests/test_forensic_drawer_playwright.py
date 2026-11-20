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

def test_forensic_drawer():
    # Start backend
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

            # 1. Console Page: Click Step in Attack Chain
            page.goto("http://127.0.0.1:3000/console", wait_until="domcontentloaded")
            page.wait_for_timeout(1000)

            # Click Step 2 (Sensitive read requested)
            step2 = page.locator("#s2")
            assert step2.is_visible()
            step2.click()

            drawer = page.locator("[data-testid='forensic-drawer']")
            page.wait_for_selector("[data-testid='forensic-drawer']", state="visible", timeout=3000)
            assert drawer.is_visible(), "Forensic drawer did not open on step click"
            page.wait_for_timeout(300)

            # Screenshot: Step 2 inspection in Console
            page.screenshot(path=str(ARTIFACTS_DIR / "phase2_console_step_drawer_1440x900.png"))
            print("Captured phase2_console_step_drawer_1440x900.png")

            # Click Payload & PII tab
            page.locator("[data-testid='forensic-tab-payload']").click()
            page.wait_for_timeout(300)
            txt = page.locator("[data-testid='forensic-drawer']").inner_text()
            assert "TOOL ARGUMENTS PAYLOAD" in txt.upper()

            # Click Taint Lineage tab
            page.locator("[data-testid='forensic-tab-context']").click()
            page.wait_for_timeout(300)
            assert "SESSION CONTEXT SOURCES" in page.locator("[data-testid='forensic-drawer']").inner_text().upper()

            # Click Hash Chain Proof tab
            page.locator("[data-testid='forensic-tab-crypto']").click()
            page.wait_for_timeout(300)
            assert "SHA-256 DIGEST" in page.locator("[data-testid='forensic-drawer']").inner_text().upper()

            # Close drawer via Escape
            page.keyboard.press("Escape")
            page.wait_for_timeout(300)
            assert not drawer.is_visible(), "Drawer did not close on Escape"

            # 2. Console Page: Click Event Feed Row
            feed_row = page.locator("#fd .ln").first
            if feed_row.is_visible():
                feed_row.click()
                page.wait_for_selector("[data-testid='forensic-drawer']", state="visible", timeout=3000)
                assert drawer.is_visible(), "Drawer did not open on feed row click"
                page.wait_for_timeout(300)
                page.keyboard.press("Escape")
                page.wait_for_timeout(300)

            # 3. Audit Page: Click Hash Chain Block
            page.goto("http://127.0.0.1:3000/audit", wait_until="domcontentloaded")
            page.wait_for_timeout(1000)

            first_block = page.locator("#ch .blk").first
            assert first_block.is_visible(), "Hash chain block not visible"
            first_block.click()

            page.wait_for_selector("[data-testid='forensic-drawer']", state="visible", timeout=3000)
            assert drawer.is_visible(), "Drawer did not open on hash block click"
            page.wait_for_timeout(300)

            # Screenshot: Hash block inspection in Audit Ledger
            page.screenshot(path=str(ARTIFACTS_DIR / "phase2_audit_block_drawer_1440x900.png"))
            print("Captured phase2_audit_block_drawer_1440x900.png")

            print("All Phase 2 Forensic Drawer interactions verified successfully!")

    finally:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(backend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    test_forensic_drawer()
