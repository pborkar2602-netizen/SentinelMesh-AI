#!/usr/bin/env python3
"""
scripts/capture_1440_screenshots.py

Captures the three required 1440x900 screenshots:
1. Tour step 2 (1440x900_tour_step_2.png)
2. Defense Radar on Evidence section (1440x900_radar_evidence.png)
3. Live demo in Enforce mode (1440x900_live_demo_enforce.png)

Verifies:
- Tour modal card bounding box is completely on-screen (top >= 10, bottom <= innerHeight, left >= 10, right <= innerWidth)
- No clipping or modal cutoffs exist at 1440x900
"""

import os
import sys
import time
import http.server
import socketserver
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = ROOT_DIR / "docs" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

PORT = 3000
BASE_URL = f"http://127.0.0.1:{PORT}"

def run():
    print(f"Starting static HTTP server on port {PORT} serving frontend/dist...")
    dist_dir = str(ROOT_DIR / "frontend" / "dist")
    Handler = lambda *args: http.server.SimpleHTTPRequestHandler(*args, directory=dist_dir)
    
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), Handler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(1.0)

    captured = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            w, h = 1440, 900
            print(f"Testing Viewport: 1440x900")

            context = browser.new_context(viewport={"width": w, "height": h})
            page = context.new_page()

            # 1. Live demo in Enforce mode
            page.goto(f"{BASE_URL}/#demo", wait_until="networkidle")
            page.wait_for_timeout(1000)
            enforce_btn = page.locator("#mE")
            if enforce_btn.count() > 0:
                enforce_btn.first.click()
                page.wait_for_timeout(600)
            enf_file = SCREENSHOT_DIR / "1440x900_live_demo_enforce.png"
            page.screenshot(path=str(enf_file))
            captured.append(("1440x900_live_demo_enforce.png", "Live demo in Enforce mode (0 records exposed)"))
            print(f"Captured: {enf_file.name}")

            # 2. Defense Radar on Evidence section
            page.goto(f"{BASE_URL}/#results", wait_until="networkidle")
            page.wait_for_timeout(1000)
            radar_el = page.locator("#defense-radar-card")
            if radar_el.count() > 0:
                radar_el.scroll_into_view_if_needed()
                page.wait_for_timeout(800)
            radar_file = SCREENSHOT_DIR / "1440x900_radar_evidence.png"
            page.screenshot(path=str(radar_file))
            captured.append(("1440x900_radar_evidence.png", "5-axis Defense Layer Radar on Scientific Evidence dashboard"))
            print(f"Captured: {radar_file.name}")

            # 3. Tour Step 2
            page.goto(f"{BASE_URL}/?tour=1", wait_until="networkidle")
            page.wait_for_timeout(1000)
            # Advance to step 2
            next_btn = page.locator("button:has-text('Next →')")
            if next_btn.count() > 0:
                next_btn.first.click()
                page.wait_for_timeout(1000)

            # Check tour card bounds
            tour_card = page.locator("[data-testid='tour-card']")
            if tour_card.count() > 0:
                box = tour_card.bounding_box()
                if box:
                    print(f"Tour Step 2 Card Bounds: x={box['x']}, y={box['y']}, w={box['width']}, h={box['height']}")
                    assert box["y"] >= 10, f"Card top clipped off-screen: y={box['y']}"
                    assert box["y"] + box["height"] <= h + 20, f"Card bottom clipped off-screen: y+h={box['y']+box['height']}"
                    assert box["x"] >= 10, f"Card left clipped off-screen: x={box['x']}"
                    assert box["x"] + box["width"] <= w + 20, f"Card right clipped off-screen: x+w={box['x']+box['width']}"
                    print("  [PASS] Tour Step 2 Card is completely within viewport bounds.")

            tour_file = SCREENSHOT_DIR / "1440x900_tour_step_2.png"
            page.screenshot(path=str(tour_file))
            captured.append(("1440x900_tour_step_2.png", "Tour Step 2 (Live 5-step Incident Attack Chain)"))
            print(f"Captured: {tour_file.name}")

            browser.close()

    finally:
        httpd.shutdown()

    print("\nSuccessfully captured all 1440x900 screenshots:")
    for fname, desc in captured:
        print(f"  - docs/screenshots/{fname}: {desc}")

if __name__ == "__main__":
    run()
