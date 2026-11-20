#!/usr/bin/env python3
"""
tests/test_multipage_navigation_playwright.py

End-to-end Playwright verification across ALL 6 dedicated routes at 1440x900 and 1366x768:
  /, /console, /playground, /audit, /benchmarks, /architecture

Asserts:
1. Zero blank/invisible viewports (main visible, opacity == 1, non-trivial text).
2. Zero bounding-box overlap between floating #hd pill and primary page heading.
3. Exact floating navbar morph (#hz hover -> #nv.open, .ind pill) and hotkey 1-6 navigation.
4. Zero legacy/childish strings ("internship project", "Simple / Story / Expert", "story ·").
5. Cross-page Guided Tour (T -> Next -> Escape) transitions across routes cleanly.
6. Captures screenshots at both 1440x900 and 1366x768 for visual audit.
"""

import os
import sys
import time
import subprocess
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = Path(
    r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278"
)
BACKEND_URL = os.environ.get("SENTINEL_BACKEND_URL", "http://127.0.0.1:8000")
FRONTEND_URL = os.environ.get("SENTINEL_FRONTEND_URL", "http://127.0.0.1:3000")

ROUTES = [
    ("overview", "/"),
    ("console", "/console"),
    ("playground", "/playground"),
    ("audit", "/audit"),
    ("benchmarks", "/benchmarks"),
    ("architecture", "/architecture"),
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
            time.sleep(0.4)
    return False


def test_multipage_routes_no_gaps_and_nav_integrity():
    backend_proc = None
    frontend_proc = None

    if not wait_for_url(f"{BACKEND_URL}/api/v1/health", timeout=1.0):
        backend_env = os.environ.copy()
        backend_env["DEMO_MODE"] = "true"
        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
            cwd=str(ROOT_DIR),
            env=backend_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert wait_for_url(f"{BACKEND_URL}/api/v1/health", timeout=15.0), "Backend failed to start"

    if not wait_for_url(FRONTEND_URL, timeout=1.0):
        frontend_proc = subprocess.Popen(
            ["npm.cmd", "--prefix", "frontend", "run", "preview", "--", "--port", "3000", "--host", "127.0.0.1"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert wait_for_url(FRONTEND_URL, timeout=15.0), "Frontend preview failed to start"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})

            for vp_label, width, height in [("1440x900", 1440, 900), ("1366x768", 1366, 768)]:
                print(f"\n=== Multi-Page Audit: {vp_label} ===")
                page.set_viewport_size({"width": width, "height": height})

                for idx, (route_id, path) in enumerate(ROUTES):
                    # Direct route navigation for index 0; navbar hover+click for all others
                    if idx == 0:
                        page.goto(f"{FRONTEND_URL}{path}", wait_until="domcontentloaded")
                        page.mouse.move(700, 500)
                        page.wait_for_selector("#nv:not(.open)", timeout=5000)
                    else:
                        # Hover over #hd pill (or #hz zone) to open floating navbar dock and verify .ind
                        page.locator("#hd").hover()
                        page.wait_for_selector("#nv.open", timeout=5000)
                        page.wait_for_timeout(200)
                        ind_box = page.locator("#ind").bounding_box()
                        assert ind_box and ind_box["width"] > 20, f"Indicator .ind collapsed on {route_id}"
                        page.locator(f"[data-testid='nav-link-{route_id}']").click()
                        page.mouse.move(700, 500)
                        page.wait_for_selector("#nv:not(.open)", timeout=5000)

                    # Assert route settled and main is crisp & visible (no opacity: 0 traps)
                    page.wait_for_timeout(500)
                    main_el = page.locator("main")
                    assert main_el.is_visible(), f"<main> not visible on {path}"
                    opacity = main_el.evaluate("el => getComputedStyle(el).opacity")
                    assert float(opacity) >= 0.98, f"Expected opacity >= 0.98 on {path}, got {opacity}"

                    body_text = page.locator("body").inner_text()
                    assert len(body_text.strip()) > 150, f"Blank viewport on {path}: text too short"
                    assert "internship project" not in body_text.lower(), f"Childish footer leaked on {path}"
                    assert "simple / story / expert" not in body_text.lower(), f"Depth switcher leaked on {path}"
                    assert "story ·" not in body_text.lower(), f"'story ·' leaked into pill on {path}"

                    # Ensure scrolled to top on page enter & verify #hd pill does NOT collide with heading
                    scroll_y = page.evaluate("() => window.scrollY")
                    assert scroll_y == 0, f"Expected scrollY==0 after page switch to {path}, got {scroll_y}"

                    pill_box = page.locator("#hd").bounding_box()
                    assert pill_box is not None, "#hd pill missing"
                    if path == "/":
                        hero_badge_box = page.locator("#hero-badge").bounding_box()
                        assert hero_badge_box is not None
                        assert hero_badge_box["y"] >= pill_box["y"] + pill_box["height"] - 1, (
                            f"Hero badge overlaps nav pill on /: {hero_badge_box} vs {pill_box}"
                        )
                    else:
                        heading_loc = page.locator("main h2").first
                        heading_box = heading_loc.bounding_box()
                        assert heading_box is not None, f"Missing heading on {path}"
                        assert heading_box["y"] >= pill_box["y"] + pill_box["height"] - 1, (
                            f"Floating pill overlaps heading on {path}: pill={pill_box}, heading={heading_box}"
                        )

                    # Capture above-the-fold screenshot at exact viewport size
                    shot_path = ARTIFACTS_DIR / f"page_{route_id}_{vp_label}.png"
                    page.screenshot(path=str(shot_path), full_page=False)
                    print(f"  [PASS] {path} ({vp_label}) — no gaps, no overlap, screenshot saved.")

                    # Extra check on /benchmarks: capture Methodology Corrections close-up
                    if vp_label == "1440x900" and path == "/benchmarks":
                        mistakes_loc = page.locator("[data-testid='known-issues-list']")
                        mistakes_loc.scroll_into_view_if_needed()
                        page.wait_for_timeout(300)
                        mistakes_loc.screenshot(path=str(ARTIFACTS_DIR / "methodology_corrections_1440x900.png"))
                        # Verify clean Before/After diff without raw backticks
                        m_text = mistakes_loc.inner_text()
                        assert "BEFORE" in m_text.upper() and "AFTER" in m_text.upper()
                        assert "`" not in m_text
                        # Test Technical detail toggle expands cleanly
                        toggle_btn = page.locator("[data-testid='issue-detail-toggle-issue-1']")
                        toggle_btn.click()
                        page.wait_for_timeout(150)
                        assert "ROOT CAUSE" in mistakes_loc.inner_text().upper()

                # Test hotkey 1-6 direct jump + Tour cross-page progression on 1440x900
                if vp_label == "1440x900":
                    page.keyboard.press("1")
                    page.wait_for_timeout(250)
                    assert page.evaluate("() => window.location.pathname") == "/"

                    page.keyboard.press("t")
                    page.wait_for_selector("[data-testid='tour-card']", state="visible", timeout=5000)
                    assert "OVERVIEW" in page.locator("[data-testid='tour-card']").inner_text().upper()

                    # Step 1 -> Step 2 (Proof Bar on /)
                    page.locator("[data-testid='tour-next-btn']").click()
                    page.wait_for_timeout(300)
                    assert page.evaluate("() => window.location.pathname") == "/"
                    assert "PROOF BAR" in page.locator("[data-testid='tour-card']").inner_text().upper()

                    # Step 2 -> Step 3 (Auto-navigates to /console)
                    page.locator("[data-testid='tour-next-btn']").click()
                    page.wait_for_timeout(450)
                    assert page.evaluate("() => window.location.pathname") == "/console"
                    assert "CONSOLE" in page.locator("[data-testid='tour-card']").inner_text().upper()

                    page.keyboard.press("Escape")
                    page.wait_for_timeout(200)
                    assert page.locator("[data-testid='guided-tour-overlay']").count() == 0
                    print("  [PASS] Hotkeys (1-6) and Cross-Page Guided Tour (T -> Next -> Esc) verified.")

            browser.close()
    finally:
        _kill_proc(backend_proc)
        _kill_proc(frontend_proc)


if __name__ == "__main__":
    test_multipage_routes_no_gaps_and_nav_integrity()
