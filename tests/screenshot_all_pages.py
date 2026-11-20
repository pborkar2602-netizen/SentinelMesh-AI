"""Quick screenshot capture of all 6 pages at both viewport sizes."""
from playwright.sync_api import sync_playwright
import os

ART_DIR = r"C:\Users\Vignaharta Computer\.gemini\antigravity\brain\a80c04ac-89ab-410e-9fde-75a990d41278"
ROUTES = [
    ('overview', '/'),
    ('console', '/console'),
    ('playground', '/playground'),
    ('audit', '/audit'),
    ('benchmarks', '/benchmarks'),
    ('architecture', '/architecture'),
]
VIEWPORTS = [
    ('1440x900', 1440, 900),
    ('1366x768', 1366, 768),
]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
    
    for vp_name, w, h in VIEWPORTS:
        ctx = browser.new_context(viewport={'width': w, 'height': h})
        page = ctx.new_page()
        
        for route_id, path in ROUTES:
            page.goto(f'http://localhost:3000{path}', wait_until='domcontentloaded', timeout=15000)
            page.wait_for_timeout(1500)
            fname = f'page_{route_id}_{vp_name}.png'
            page.screenshot(path=os.path.join(ART_DIR, fname))
            print(f'Captured: {fname}')
        
        ctx.close()
    
    browser.close()
    print('Done.')
