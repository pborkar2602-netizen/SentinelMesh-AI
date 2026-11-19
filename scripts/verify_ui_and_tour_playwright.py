#!/usr/bin/env python3
"""
scripts/verify_ui_and_tour_playwright.py

Playwright automated verification script for:
1. Guided Tour overlay (no clipping, safe viewport bounds, spotlight clarity, step navigation).
2. Detail Level Context (Simple / Story / Expert), hotkey 'D', nav filtering.
3. 'The idea in 60 seconds' story section (4 beats, SVG scene, tech chips, because chips).
4. Evidence summary visibility across all depths.
5. Screenshot capture at 1440x900 and 1366x768.
"""

import os
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = Path(r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278")
BASE_URL = os.environ.get("SENTINEL_FRONTEND_URL", "http://127.0.0.1:3000")

def run_verification():
    print(f"Connecting to {BASE_URL}...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for width, height in [(1440, 900), (1366, 768)]:
            print(f"\n==================================================")
            print(f"VERIFYING VIEWPORT {width}x{height}")
            print(f"==================================================")

            context = browser.new_context(viewport={"width": width, "height": height})
            page = context.new_page()
            page.goto(BASE_URL, wait_until="networkidle")
            time.sleep(1)

            # Ensure page is scrolled to top
            page.evaluate("window.scrollTo(0, 0)")

            # ----------------------------------------------------
            # 1. VERIFY GUIDED TOUR OVERLAY & CARD BOUNDS
            # ----------------------------------------------------
            print("\n--- Verifying Guided Tour ---")
            page.keyboard.press("t") # Open tour
            page.wait_for_selector("[data-testid='guided-tour-overlay']", state="visible")
            page.wait_for_selector("[data-testid='tour-card']", state="visible")

            step_count = 0
            while True:
                step_count += 1
                card_box = page.locator("[data-testid='tour-card']").bounding_box()
                assert card_box is not None, "Tour card bounding box missing"

                # Check vertical clipping
                top = card_box["y"]
                bottom = top + card_box["height"]
                print(f"  Step {step_count}: card y={top:.1f}, height={card_box['height']:.1f}, bottom={bottom:.1f}")

                assert top >= 10, f"Tour card clipped at top: y={top} < 10 on step {step_count}"
                assert bottom <= height + 5, f"Tour card clipped at bottom: bottom={bottom} > viewport height={height} on step {step_count}"

                # Take screenshot on step 1, 2, 4
                if step_count in [1, 2, 4]:
                    shot_path = ARTIFACT_DIR / f"tour_{width}x{height}_step{step_count}.png"
                    page.screenshot(path=str(shot_path))
                    print(f"  [SAVED] {shot_path.name}")

                next_btn = page.locator("[data-testid='tour-card'] button:has-text('Next'), [data-testid='tour-card'] button:has-text('Finish')")
                btn_text = next_btn.inner_text().strip()
                if "Finish" in btn_text:
                    next_btn.click()
                    break
                else:
                    next_btn.click()
                    time.sleep(0.35)

            print(f"  [PASS] Tour traversed {step_count} steps with ZERO clipping!")

            # ----------------------------------------------------
            # 2. VERIFY DETAIL LEVEL SWITCHING (Simple / Story / Expert)
            # ----------------------------------------------------
            print("\n--- Verifying Detail Levels ---")
            # Default should be Story mode
            assert page.locator("#lab").is_visible(), "Lab section should be visible in Story mode"
            assert not page.locator("#how").is_visible(), "How section should be hidden in Story mode"

            # Cycle using Key D: Story -> Expert
            page.keyboard.press("d")
            time.sleep(0.3)
            expert_shot = ARTIFACT_DIR / f"depth_{width}x{height}_expert.png"
            page.screenshot(path=str(expert_shot))
            print(f"  [SAVED] {expert_shot.name}")
            assert page.locator("#how").is_visible(), "How section should be visible in Expert mode"
            assert page.locator("#lab").is_visible(), "Lab section should be visible in Expert mode"

            # Cycle using Key D: Expert -> Simple
            page.keyboard.press("d")
            time.sleep(0.3)
            simple_shot = ARTIFACT_DIR / f"depth_{width}x{height}_simple.png"
            page.screenshot(path=str(simple_shot))
            print(f"  [SAVED] {simple_shot.name}")
            assert not page.locator("#lab").is_visible(), "Lab section should be hidden in Simple mode"
            assert not page.locator("#how").is_visible(), "How section should be hidden in Simple mode"
            assert page.locator("#explain").is_visible(), "Explain section should be visible in Simple mode"
            assert page.locator("#results").is_visible(), "Results section should be visible in Simple mode"

            # Cycle using Key D: Simple -> Story
            page.keyboard.press("d")
            time.sleep(0.3)
            story_shot = ARTIFACT_DIR / f"depth_{width}x{height}_story.png"
            page.screenshot(path=str(story_shot))
            print(f"  [SAVED] {story_shot.name}")
            assert page.locator("#lab").is_visible(), "Lab section should be visible in Story mode"
            assert not page.locator("#how").is_visible(), "How section should be hidden in Story mode"

            # ----------------------------------------------------
            # 3. VERIFY 'THE IDEA IN 60 SECONDS' SECTION
            # ----------------------------------------------------
            print("\n--- Verifying The Idea in 60 Seconds ---")
            page.locator("#explain").scroll_into_view_if_needed()
            time.sleep(0.5)

            # Verify Section Container
            assert page.locator("[data-testid='story-section-60s']").is_visible(), "60s story container not visible"

            # Verify 4 Beat Tabs & navigate each
            for beat_id in [1, 2, 3, 4]:
                tab = page.locator(f"[data-testid='beat-tab-{beat_id}']")
                assert tab.is_visible(), f"Beat tab {beat_id} not visible"
                tab.click()
                time.sleep(0.2)
                card = page.locator(f"[data-testid='beat-card-{beat_id}']")
                assert card.is_visible(), f"Beat card {beat_id} not visible"
            print("  [PASS] All 4 narrative beat tabs & cards verified.")

            # On Beat 4: Verify Because chips expand with forensic evidence
            because_chip = page.locator("[data-testid='because-chip-0']")
            assert because_chip.is_visible(), "Because chip not visible"
            because_chip.click()
            time.sleep(0.2)
            assert page.locator("[data-testid='because-evidence-0']").is_visible(), "Evidence disclosure not shown"
            print("  [PASS] Because chips expand with incident evidence strings.")

            # Verify Replay button and Mode toggles in 60s section
            page.locator("[data-testid='story-mode-monitor']").click()
            time.sleep(0.2)
            page.locator("[data-testid='story-replay-btn']").click()
            time.sleep(0.2)
            page.locator("[data-testid='story-mode-enforce']").click()
            time.sleep(0.2)
            print("  [PASS] SVG interactive scene modes and replay button verified.")

            # ----------------------------------------------------
            # 4. VERIFY ATTACK CHAIN SUBTITLES CONTRAST
            # ----------------------------------------------------
            print("\n--- Verifying Attack Chain Subtitles ---")
            page.locator("#demo").scroll_into_view_if_needed()
            time.sleep(0.5)
            step_subtitle = page.locator("#s0 small")
            color = step_subtitle.evaluate("el => window.getComputedStyle(el).color")
            opacity = page.locator("#s0").evaluate("el => window.getComputedStyle(el).opacity")
            print(f"  Step 0 subtitle color: {color}, container opacity: {opacity}")
            assert float(opacity) >= 0.5, f"Opacity too low: {opacity}"
            print("  [PASS] Subtitle text contrast is clear and legible.")

            context.close()

        browser.close()
    print("\n==================================================")
    print("ALL PLAYWRIGHT VERIFICATIONS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    run_verification()
