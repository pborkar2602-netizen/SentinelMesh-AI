import http.server, socketserver, threading, time
from playwright.sync_api import sync_playwright

dist_dir = 'frontend/dist'
Handler = lambda *args: http.server.SimpleHTTPRequestHandler(*args, directory=dist_dir)
socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(('127.0.0.1', 3001), Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
time.sleep(0.5)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.on('console', lambda msg: print('BROWSER CONSOLE:', msg.text))
    page.on('pageerror', lambda err: print('BROWSER PAGE ERROR:', err))
    page.goto('http://127.0.0.1:3001/?tour=1', wait_until='networkidle')
    page.wait_for_timeout(1000)
    print('HTML length:', len(page.content()))
    overlay = page.locator("[data-testid='guided-tour-overlay']")
    print('Guided tour overlay count:', overlay.count())
    card = page.locator("[data-testid='tour-card']")
    print('Tour card count:', card.count())
    if card.count() > 0:
        print('Tour card box:', card.bounding_box())
    browser.close()
httpd.shutdown()
