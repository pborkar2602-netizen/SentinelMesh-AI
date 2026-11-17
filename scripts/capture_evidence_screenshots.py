import os
import time
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278"
VIEWPORTS = [
    (1440, 900),
    (1366, 768),
    (1920, 1080),
]

def capture_all():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for width, height in VIEWPORTS:
            print(f"\n=== Capturing Viewport {width}x{height} ===")
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto("http://127.0.0.1:3000", wait_until="networkidle")
            page.wait_for_timeout(1000)

            # 1. Hero & Proof Bar
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(400)
            # Scroll so the proof bar under the hero marquee is clearly visible
            proof_bar = page.locator("[data-testid='proof-bar']")
            proof_bar.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            p1 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_01_hero_proofbar.png")
            page.screenshot(path=p1)
            print(f"  Captured: {p1}")

            # Scroll down to Evidence section
            evidence_sec = page.locator("#evidence")
            evidence_sec.scroll_into_view_if_needed()
            page.wait_for_timeout(800)

            # 2. Headline Counters & Radar
            p2 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_02_headline_radar.png")
            page.screenshot(path=p2)
            print(f"  Captured: {p2}")

            # 3. Wording Crossover Chart (Base Setting)
            crossover = page.locator("[data-testid='wording-crossover-chart']")
            crossover.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            p3 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_03_crossover_base.png")
            page.screenshot(path=p3)
            print(f"  Captured: {p3}")

            # 4. Wording Crossover Chart (Enhanced Setting)
            page.locator("[data-testid='toggle-enhanced-setting']").click()
            page.wait_for_timeout(800)
            p4 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_04_crossover_enhanced.png")
            page.screenshot(path=p4)
            print(f"  Captured: {p4}")

            # Toggle back to Base for clean state
            page.locator("[data-testid='toggle-base-setting']").click()
            page.wait_for_timeout(300)

            # 5. Mistakes We Found Tab
            page.locator("[data-testid='tab-mistakes']").click()
            page.wait_for_timeout(600)
            page.locator("[data-testid='known-issues-list']").scroll_into_view_if_needed()
            page.wait_for_timeout(400)
            p5 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_05_mistakes_tab.png")
            page.screenshot(path=p5)
            print(f"  Captured: {p5}")

            # 6. Release Timeline Tab
            page.locator("[data-testid='tab-timeline']").click()
            page.wait_for_timeout(600)
            page.locator("[data-testid='release-timeline']").scroll_into_view_if_needed()
            page.wait_for_timeout(400)
            p6 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_06_timeline_tab.png")
            page.screenshot(path=p6)
            print(f"  Captured: {p6}")

            # 7. Datasets Registry Tab
            page.locator("[data-testid='tab-datasets']").click()
            page.wait_for_timeout(600)
            page.locator("[data-testid='datasets-table']").scroll_into_view_if_needed()
            page.wait_for_timeout(400)
            p7 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_07_datasets_tab.png")
            page.screenshot(path=p7)
            print(f"  Captured: {p7}")

            # 8. Where It Fails (Limitations) Tab
            page.locator("[data-testid='tab-limitations']").click()
            page.wait_for_timeout(600)
            page.locator("[data-testid='limitations-cards']").scroll_into_view_if_needed()
            page.wait_for_timeout(400)
            p8 = os.path.join(ARTIFACT_DIR, f"evidence_{width}x{height}_08_limitations_tab.png")
            page.screenshot(path=p8)
            print(f"  Captured: {p8}")

            page.close()

        browser.close()
    print("\nAll screenshots captured successfully.")

if __name__ == "__main__":
    capture_all()
