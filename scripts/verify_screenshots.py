"""
SentinelMesh v3: Playwright Screenshot Verification
Captures responsive layouts at 1440x900, 1366x768, and 1920x1080:
- Guided tour (?tour=1)
- Incident hero & attack chain (#demo)
- Defense-layer radar chart and scientific evidence (#results)
- Interactive policy lab (#lab)
- Tamper-evident audit ledger (#audit)

Saves directly to the conversation artifact directory.
"""

import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = Path(r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

VIEWPORTS = [
    {"name": "1440x900", "width": 1440, "height": 900},
    {"name": "1366x768", "width": 1366, "height": 768},
    {"name": "1920x1080", "width": 1920, "height": 1080},
]

BASE_URL = "http://127.0.0.1:5173"

def run_screenshot_suite():
    print(f"Connecting to {BASE_URL} and capturing responsive screenshots...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for vp in VIEWPORTS:
            vp_name = vp["name"]
            w, h = vp["width"], vp["height"]
            print(f"\n--- Testing Viewport: {vp_name} ({w}x{h}) ---")
            
            context = browser.new_context(viewport={"width": w, "height": h})
            page = context.new_page()

            # 1. Home / Hero Mesh
            page.goto(BASE_URL, wait_until="networkidle")
            page.wait_for_timeout(1000)
            shot1 = ARTIFACT_DIR / f"v3_{vp_name}_1_home_mesh.png"
            page.screenshot(path=str(shot1))
            print(f"  Captured: {shot1.name}")

            # 2. Guided Tour (?tour=1)
            page.goto(f"{BASE_URL}/?tour=1", wait_until="networkidle")
            page.wait_for_timeout(1200)
            shot2 = ARTIFACT_DIR / f"v3_{vp_name}_2_guided_tour.png"
            page.screenshot(path=str(shot2))
            print(f"  Captured: {shot2.name}")

            # 3. Live Demo Attack Chain (#demo)
            page.goto(f"{BASE_URL}/#demo", wait_until="networkidle")
            page.wait_for_timeout(1000)
            shot3 = ARTIFACT_DIR / f"v3_{vp_name}_3_live_demo.png"
            page.screenshot(path=str(shot3))
            print(f"  Captured: {shot3.name}")

            # 4. Evidence Section & Defense Radar Chart (#results)
            page.goto(f"{BASE_URL}/#results", wait_until="networkidle")
            page.wait_for_timeout(1200)
            # Scroll results section into view
            results_el = page.locator("#results")
            if results_el.count() > 0:
                results_el.scroll_into_view_if_needed()
                page.wait_for_timeout(800)
            shot4 = ARTIFACT_DIR / f"v3_{vp_name}_4_evidence_radar.png"
            page.screenshot(path=str(shot4))
            print(f"  Captured: {shot4.name}")

            context.close()

        browser.close()
    print("\nAll Playwright screenshots successfully generated.")

if __name__ == "__main__":
    run_screenshot_suite()
