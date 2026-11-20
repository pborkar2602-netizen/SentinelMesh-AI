from playwright.sync_api import sync_playwright
import os

ART = r'C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278'

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    ctx = browser.new_context(viewport={'width': 1440, 'height': 900})
    page = ctx.new_page()

    # Audit page - navigate to Policy & Replay tab
    page.goto('http://localhost:3000/audit', wait_until='domcontentloaded', timeout=12000)
    page.wait_for_timeout(1500)
    page.get_by_test_id('audit-tab-replay').click()
    page.wait_for_timeout(2500)
    page.screenshot(path=os.path.join(ART, 'fix_audit_replay_1440x900.png'))
    print('OK: audit replay tab')

    ctx.close()
    browser.close()
