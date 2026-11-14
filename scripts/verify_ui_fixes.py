"""
Full UI verification capturing all 7 tour steps and live demo states.
"""

from pathlib import Path
from playwright.sync_api import sync_playwright

OUTPUT_DIR = Path(r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278")

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1366, "height": 768})
        page.goto("http://localhost:3000")
        page.wait_for_timeout(1000)

        # 1. Live demo enforce
        page.locator("#demo").scroll_into_view_if_needed()
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUTPUT_DIR / "fix_live_demo_enforce.png"))

        # 2. Live demo monitor
        page.locator("#mM").click()
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUTPUT_DIR / "fix_live_demo_monitor.png"))

        # 3. Switch back to enforce
        page.locator("#mE").click()
        page.wait_for_timeout(300)

        # 4. Tour steps
        page.keyboard.press("t")
        page.wait_for_timeout(600)

        for step in range(1, 8):
            page.screenshot(path=str(OUTPUT_DIR / f"fix_tour_step_{step}.png"))
            print(f"Captured fix_tour_step_{step}.png")
            if step < 7:
                next_btn = page.locator('[data-testid="guided-tour-overlay"] button:has-text("Next")')
                if next_btn.count() > 0 and next_btn.is_visible():
                    next_btn.click()
                else:
                    page.keyboard.press("ArrowRight")
                page.wait_for_timeout(700)

        browser.close()
        print("Done!")

if __name__ == "__main__":
    main()
