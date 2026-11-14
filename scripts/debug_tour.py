from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={'width': 1366, 'height': 768})
    page.goto('http://localhost:3000')
    page.wait_for_timeout(1000)
    page.keyboard.press('t')
    page.wait_for_timeout(600)

    for i in range(1, 8):
        card = page.locator('[data-testid="guided-tour-overlay"] > div:last-child')
        card_box = card.bounding_box() if card.count() > 0 else None
        title = card.locator('h3').text_content() if card.count() > 0 else 'none'
        print(f"Step {i}: title='{title}', card_box={card_box}")
        if i < 7:
            next_btn = page.locator('[data-testid="guided-tour-overlay"] button:has-text("Next")')
            if next_btn.count() > 0 and next_btn.is_visible():
                next_btn.click()
            else:
                page.keyboard.press("ArrowRight")
            page.wait_for_timeout(600)
    browser.close()
