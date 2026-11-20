"""Debug: capture console errors on each page to find black-screen root cause."""
import pytest
from playwright.sync_api import Page, sync_playwright

ROUTES = ['/', '/console', '/playground', '/audit', '/benchmarks', '/architecture']

def test_console_errors():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
        ctx = browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        
        all_errors = []
        page.on('console', lambda msg: all_errors.append(f'[{msg.type.upper()}] {msg.text}') if msg.type in ['error', 'warning'] else None)
        page.on('pageerror', lambda err: all_errors.append(f'[PAGEERROR] {str(err)}'))
        
        page.goto('http://localhost:3000/', wait_until='domcontentloaded', timeout=20000)
        page.wait_for_timeout(2000)
        page.screenshot(path='debug_overview.png', full_page=False)
        
        print('\n=== CONSOLE ERRORS ===')
        for e in all_errors:
            print(e)
        
        # Check DOM state
        root_html = page.evaluate('document.getElementById("root")?.innerHTML?.substring(0, 500)')
        print(f'\nROOT INNER HTML: {root_html}')
        
        main_exists = page.locator('main').count()
        print(f'\nMAIN TAG COUNT: {main_exists}')
        
        if main_exists:
            main_html = page.evaluate('document.querySelector("main")?.innerHTML?.substring(0, 300)')
            print(f'MAIN INNER HTML: {main_html}')
        
        browser.close()

if __name__ == '__main__':
    test_console_errors()
