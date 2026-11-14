#!/usr/bin/env python3
"""
scripts/capture_multi_resolution_audit.py

Captures high-resolution Playwright screenshots across viewports:
- 1440x900 (MacBook / Standard Laptop)
- 1366x768 (Target Standard Desktop / Laptop)
- 1920x1080 (Full HD Monitor)

Verifies:
- All 7 Tour steps (spotlight cutout, tooltip clamping, zero overflow)
- Live demo console (Enforce vs Monitor mode)
- 5-Axis Defense Radar Chart
- Scientific Evidence & Benchmark tables
"""

from pathlib import Path
from playwright.sync_api import sync_playwright

OUTPUT_DIR = Path(r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278")

RESOLUTIONS = [
    ("1440x900", 1440, 900),
    ("1366x768", 1366, 768),
    ("1920x1080", 1920, 1080),
]

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()

        for res_name, width, height in RESOLUTIONS:
            print(f"\n=======================================================")
            print(f"  Capturing Viewport: {res_name} ({width}x{height})")
            print(f"=======================================================")
            
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto("http://localhost:3000")
            page.wait_for_timeout(1000)

            # 1. Live Demo Enforce
            page.locator("#demo").scroll_into_view_if_needed()
            page.wait_for_timeout(600)
            page.screenshot(path=str(OUTPUT_DIR / f"v3_{res_name}_1_live_demo_enforce.png"))
            print(f"  [x] v3_{res_name}_1_live_demo_enforce.png")

            # 2. Live Demo Monitor
            page.locator("#mM").click()
            page.wait_for_timeout(400)
            page.screenshot(path=str(OUTPUT_DIR / f"v3_{res_name}_2_live_demo_monitor.png"))
            print(f"  [x] v3_{res_name}_2_live_demo_monitor.png")

            # Reset back to enforce
            page.locator("#mE").click()
            page.wait_for_timeout(200)

            # 3. Radar Chart & Evidence Section
            page.locator("#results").scroll_into_view_if_needed()
            page.wait_for_timeout(800)
            page.screenshot(path=str(OUTPUT_DIR / f"v3_{res_name}_3_radar_evidence.png"))
            print(f"  [x] v3_{res_name}_3_radar_evidence.png")

            # 4. Tour Steps 1 through 7
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(300)
            page.keyboard.press("t")
            page.wait_for_selector('[data-testid="guided-tour-overlay"]', state='visible', timeout=3000)
            page.wait_for_timeout(500)

            for step_num in range(1, 8):
                page.wait_for_timeout(400)
                img_name = f"v3_{res_name}_tour_step_{step_num}.png"
                page.screenshot(path=str(OUTPUT_DIR / img_name))
                print(f"  [x] {img_name}")
                if step_num < 7:
                    next_btn = page.locator('[data-testid="guided-tour-overlay"] button:has-text("Next")')
                    if next_btn.count() > 0 and next_btn.is_visible():
                        next_btn.click()
                    else:
                        page.keyboard.press("ArrowRight")
                    page.wait_for_timeout(600)

            page.close()

        browser.close()
        print("\nAll multi-resolution screenshots captured successfully!")

if __name__ == "__main__":
    main()
