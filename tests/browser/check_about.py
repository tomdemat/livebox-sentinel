"""Visual/HTTP checks against the disposable preview, never production.

Requires the test-only Playwright setup used by check_profile_selects.py.
"""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
from check_profile_selects import BASE, run as check_profile

OUT = Path('/tmp/sentinel-about-check')
OUT.mkdir(exist_ok=True)


def run(browser, configuration, name):
    # This suite injects an HTTP outage with page.route. PWA behavior is exercised
    # separately in check_ui; service workers must not handle this fixture.
    context = browser.new_context(**configuration, service_workers="block")
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    assert context.request.get(BASE + '/api/about').status == 401
    page.goto(BASE + '/about')
    page.wait_for_url('**/login?**')
    page.locator('#loginUsername').fill('owner')
    page.locator('#loginPassword').fill('preview-only-password')
    page.locator('#loginSubmit').click()
    page.wait_for_url(BASE + '/about')
    page.locator('#aboutVersion').filter(has_text='0.6.0').wait_for()
    assert page.locator('nav a[aria-current=page]').inner_text() == 'Paramètres'
    assert page.locator('#aboutStorage').inner_text() != '—'
    assert page.locator('#aboutDevices').inner_text() == '5'
    assert page.locator('a[href="https://github.com/p-dor/LiveboxMonitor"]').count() == 1
    symbols = page.locator('#aboutCategories [data-symbol]').evaluate_all('(nodes)=>nodes.map(n=>n.dataset.symbol)')
    assert len(symbols) == len(set(symbols)) == 14, symbols
    assert page.evaluate('''() => {
      const icon = categorySymbol('<img src=x onerror=alert(1)>');
      return icon.dataset.symbol === 'device' && !icon.querySelector('img');
    }''')
    page.route('**/api/about', lambda route: route.fulfill(status=503, body='{}'))
    page.locator('#aboutRefresh').click()
    page.locator('#aboutStatus').filter(has_text='indisponibles').wait_for()
    assert page.locator('#aboutRefresh').is_enabled()
    page.unroute('**/api/about')
    page.locator('#aboutRefresh').click()
    page.locator('#aboutStatus').filter(has_text='actualisées').wait_for()
    for width in (320, 390, 768, 1440):
        page.set_viewport_size({'width': width, 'height': 900})
        for theme in ('light', 'dark'):
            page.evaluate('(theme)=>document.documentElement.dataset.theme=theme', theme)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (name, width, theme)
            if width in (390, 1440):
                page.screenshot(path=str(OUT / f'{name}-{width}-{theme}.png'), full_page=True)
    page.goto(BASE + '/consumption')
    page.locator('#consumptionRows tr').first.wait_for()
    page.locator('#consumptionGroup').select_option('category')
    page.wait_for_function("() => (document.querySelector('#consumptionNameHeader').textContent === 'Catégorie' && document.querySelector('#consumptionRows [data-symbol]'))")
    assert page.locator('#consumptionRows [data-symbol=printer]').count() == 1
    assert not errors, errors
    context.close()
    check_profile(browser, configuration, name + '-profile')


if __name__ == '__main__':
    with sync_playwright() as p:
        webkit = p.webkit.launch()
        run(webkit, p.devices['iPhone 13'], 'webkit-iphone')
        webkit.close()
        chromium = p.chromium.launch(executable_path='/opt/brave.com/brave/brave', args=['--no-sandbox'])
        run(chromium, {'viewport': {'width': 1440, 'height': 900}}, 'chromium')
        chromium.close()
    print(json.dumps({'about': 'OK', 'symbols': 14, 'responsive_themes': 'OK', 'profile_regression': 'OK', 'screenshots': str(OUT)}))
