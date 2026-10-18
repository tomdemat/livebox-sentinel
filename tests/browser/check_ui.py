"""Browser checks for 2.2 against tests/browser/fixture_preview.py only (fictitious data, simulated read-only router).

Chromium (Brave) at desktop width and WebKit with the iPhone 13 profile. WebKit is an
emulation, not a physical iPhone. Never point SENTINEL_TEST_URL at production.
"""
import base64
import hashlib
import hmac
import json
import struct
import time
from pathlib import Path
from playwright.sync_api import sync_playwright
from check_profile_selects import BASE, run as profile_regression

OUT = Path('/tmp/sentinel-ui-check'); OUT.mkdir(exist_ok=True)
PAGES = ['/', '/wifi', '/consumption', '/internet', '/network', '/livebox-health', '/settings', '/backups', '/account', '/about']
IPHONE = 'aa:bb:cc:dd:ee:02'


def otp(secret, step):
    digest = hmac.new(base64.b32decode(secret), struct.pack('>Q', step), hashlib.sha1).digest(); offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def run(browser, configuration, name):
    # Service workers are blocked so page.route can simulate an outage; the PWA shell is not under test here.
    context = browser.new_context(**configuration, service_workers='block'); page = context.new_page(); errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('console', lambda m: errors.append(m.text) if 'Content Security Policy' in m.text or 'Content-Security-Policy' in m.text else None)
    page.goto(BASE + '/login'); page.locator('#loginUsername').fill('owner'); page.locator('#loginPassword').fill('preview-only-password'); page.locator('#loginSubmit').click(); page.wait_for_url(BASE + '/')

    # Navigation: seven entries, no household space; old links land on the dashboard.
    labels = page.locator('.app-nav a').all_inner_texts()
    assert labels == ['Tableau de bord', 'Wi-Fi', 'Consommation', 'Qualité Internet', 'Carte réseau', 'Santé Livebox', 'Paramètres'], labels
    assert page.locator('.header-household').count() == 0

    # No verdict panel; the title bar shows the name only, in a larger size.
    page.locator('#devices tr').first.wait_for()
    assert page.locator('#verdict').count() == 0 and context.request.get(BASE + '/api/health').status == 404
    assert page.locator('.brand small').count() == 0 and 'Supervision' not in page.locator('.app-header').inner_text()
    title = page.locator('.brand strong'); size = float(title.evaluate('e=>parseFloat(getComputedStyle(e).fontSize)'))
    assert size >= (19 if name == 'chromium' else 16), size  # larger than before (17.6 / 15.4 px)
    assert title.evaluate('e=>e.getClientRects().length') == 1, 'title on a single line'
    # A newcomer is highlighted, recognised from its card, and the choice can be undone.
    iphone = page.locator('#devices tr').filter(has_text='iPhone'); assert iphone.locator('.new-device-badge').count() == 1
    page.goto(BASE + '/?device=aa:bb:cc:dd:ee:02&focus=wifi'); page.locator('#deviceDialog').wait_for(state='visible')
    page.locator('#deviceWifi .sn-chart').wait_for(); assert 'Faible' in page.locator('#deviceWifi').inner_text()
    chart = page.locator('#deviceWifi .sn-chart'); chart.scroll_into_view_if_needed(); box = chart.bounding_box()
    (chart.tap if configuration.get('has_touch') else chart.click)(position={'x': box['width'] * .8, 'y': box['height'] / 2})
    assert 'dBm' in page.locator('#deviceWifi .sn-readout').inner_text()
    newcomer = page.locator('#deviceNewcomer'); assert newcomer.is_visible() and 'Je le reconnais' in newcomer.inner_text()
    newcomer.locator('button').click(); page.locator('#snToast').filter(has_text='reconnu').wait_for()
    newcomer.filter(has_text='Reconnu par vous').wait_for()
    page.wait_for_function("() => (![...document.querySelectorAll('#devices tr')].some(r=>r.textContent.includes('iPhone')&&r.querySelector('.new-device-badge')))")
    page.locator('#snToast button').click(); newcomer.filter(has_text='Nouvel équipement').wait_for()
    page.locator('#closeDevice').click(); page.locator('#deviceDialog').wait_for(state='hidden')
    # An Ethernet device has no Wi-Fi section.
    page.goto(BASE + '/?device=aa:bb:cc:dd:ee:01'); page.locator('#deviceDialog').wait_for(state='visible'); page.wait_for_timeout(600)
    assert not page.locator('#deviceWifi').is_visible() and not page.locator('#deviceNewcomer').is_visible(); page.locator('#closeDevice').click()
    resp = context.request.get(BASE + '/workspace', max_redirects=0); assert resp.status == 308 and resp.headers['location'] == '/'

    # WAN chart: periods from one hour to one year, choice remembered, gaps never bridged.
    page.goto(BASE + '/'); page.locator('#devices tr').first.wait_for()
    page.locator('details:has(#wanChart) > summary').first.click()
    page.locator('#wanPeriod').select_option('7d'); page.locator('#wanInfo').filter(has_text='7 jours').wait_for()
    assert page.locator('#wanChart polyline').count() >= 2 and 'moyennes par 30 min' in page.locator('#wanInfo').inner_text()
    page.reload(); page.locator('details:has(#wanChart) > summary').first.click(); page.locator('#wanInfo').filter(has_text='7 jours').wait_for(); assert page.locator('#wanPeriod').input_value() == '7d'
    page.locator('#wanPeriod').select_option('1y'); page.locator('#wanInfo').filter(has_text='1 an').wait_for()
    page.locator('#wanPeriod').select_option('1h'); page.locator('#wanInfo').filter(has_text='dernière heure').wait_for()
    # Connection journal: grouped by day, paged by 20 / 50 / 100, filterable, searchable, sorted by device.
    page.goto(BASE + '/network'); items = page.locator('#journalList .journal-item'); items.first.wait_for()
    journal = page.locator('#journal').inner_text()
    assert 'vap5g0priv' not in journal and 'Wi-Fi 5 GHz' in journal and 'Aujourd’hui' in journal
    # The Chromium pass may have deleted a device before this one runs: count from the range.
    total = int(page.locator('#journalRange').inner_text().split(' sur ')[1])
    assert 20 < total <= 50 and items.count() == 20 and page.locator('#journalRange').inner_text().startswith('1–20 sur')
    assert 'd’absence' in journal or 'en ligne' in journal, 'durations between events are shown'
    page.locator('#journalPages button', has_text='Suivant').click(); page.locator('#journalRange').filter(has_text='21–').wait_for(); assert items.count() == min(20, total - 20)
    page.locator('#journalPageSize').select_option('50'); assert items.count() == total and page.locator('#journalPages button').count() == 0
    page.locator('#journalSort').select_option('device'); assert page.locator('.journal-group h3').first.inner_text() == 'Home Assistant'
    page.locator('#journalSort').select_option('recent')
    page.locator('#journalConnection').select_option('Wi-Fi 5 GHz'); assert items.count() == 3 and all('Wi-Fi 5 GHz' in t for t in items.all_inner_texts())
    page.locator('#journalConnection').select_option(''); page.locator('#journalSearch').fill('Imprimante'); assert items.count() == 3
    page.locator('#journalSearch').fill(''); page.locator('#journalType').select_option('disconnected'); assert all(i.get_attribute('data-event') == 'disconnected' for i in items.all())
    page.locator('#journalType').select_option(''); page.locator('#journalPageSize').select_option('20')
    # Fields of the toolbar share one height; every row stays inside the list, also on a phone.
    heights = page.evaluate("() => [...document.querySelectorAll('.journal-toolbar input, .journal-toolbar select')].map(e => Math.round(e.getBoundingClientRect().height))")
    assert len(set(heights)) == 1, heights
    assert page.evaluate("() => [...document.querySelectorAll('.journal-item')].every(i => i.getBoundingClientRect().right <= document.getElementById('journalList').getBoundingClientRect().right + 1)")
    items.first.locator('.journal-device').click(); page.wait_for_url('**/?device=*'); page.locator('#deviceDialog').wait_for(state='visible'); page.locator('#closeDevice').click()
    # Wi-Fi page: weakest first, filters, a row opens the card on its Wi-Fi section.
    page.goto(BASE + '/wifi'); page.locator('.sn-wifi-row').first.wait_for()
    assert 'iPhone' in page.locator('.sn-wifi-row').first.inner_text() and page.locator('.sn-wifi-row').count() == 1
    page.locator('#wifiShowStale').check(); assert page.locator('.sn-wifi-row').count() == 2
    page.locator('#wifiWeakOnly').check(); assert page.locator('.sn-wifi-row').count() == 1; page.locator('#wifiShowStale').uncheck()
    page.locator('.sn-wifi-row').first.click(); page.wait_for_url(BASE + '/'); page.locator('#deviceDialog').wait_for(state='visible'); page.locator('#deviceWifi .sn-chart').wait_for()
    page.wait_for_function("() => (document.getElementById('deviceWifi').getBoundingClientRect().top < innerHeight)")
    page.locator('#closeDevice').click()

    # Settings: new-device e-mail on, Livebox connection tested read-only then confirmed, then back to .env.
    page.goto(BASE + '/settings'); page.locator('#liveboxSource').filter(has_text='.env').wait_for()
    assert page.locator('#email_alert_new_device').is_checked()
    page.locator('#liveboxUrl').fill('http://192.168.1.1/'); page.locator('#liveboxPassword').fill('fake-router-password'); page.locator('#liveboxTest').click()
    page.locator('.sn-dialog').wait_for(); assert 'démonstration' in page.locator('.sn-dialog').inner_text(); page.locator('.sn-dialog .sn-primary').click()
    page.locator('#liveboxMessage').filter(has_text='enregistrée').wait_for(); page.locator('#liveboxReset').wait_for()
    assert page.locator('#liveboxPassword').input_value() == ''
    page.locator('#liveboxReset').click(); page.locator('.sn-dialog .sn-primary').click(); page.locator('#liveboxSource').filter(has_text='fichier .env').wait_for()
    assert page.locator('.settings-links a[href="/backups"]').count() == 1

    # Deleted devices: one clear action in the card, nothing left in Paramètres.
    assert page.locator('#deletedList').count() == 0 and 'Appareils supprimés' not in page.content()
    if name == 'chromium':
        page.goto(BASE + '/?device=aa:bb:cc:dd:ee:03'); page.locator('#deviceDialog').wait_for(state='visible')
        page.locator('.device-danger summary').click(); assert page.locator('#hideDevice').count() == 0
        assert 'signalé comme nouvel équipement' in page.locator('.device-danger').inner_text()
        page.once('dialog', lambda dialog: dialog.accept()); page.locator('#deleteDevice').click(); page.locator('#deviceDialog').wait_for(state='hidden')
        page.wait_for_function("() => (![...document.querySelectorAll('#devices tr')].some(r=>r.textContent.includes('Télévision')))")
    # Data: retention preview is cancellable and nothing is deleted; the journal is readable.
    page.goto(BASE + '/backups'); page.locator('#auditList li strong').first.wait_for()
    assert 'Connexion Livebox enregistrée' in page.locator('#auditList').inner_text()
    page.locator('#retentionForm button').click(); page.locator('.sn-dialog').wait_for(); assert 'traffic' not in page.locator('.sn-dialog').inner_text()
    page.locator('.sn-dialog button', has_text='Annuler').click(); page.locator('.sn-dialog').wait_for(state='detached')

    # Account: second factor with a wrong then right code, then disabled.
    page.goto(BASE + '/account'); page.locator('#totpSetup').wait_for(state='visible')
    page.locator('#totpSetupPassword').fill('preview-only-password'); page.locator('#totpSetup button').click(); page.locator('#totpConfirm').wait_for(state='visible')
    secret = page.locator('#totpSecret').inner_text().replace(' ', '')
    good = otp(secret, int(time.time()) // 30); bad = '123456' if good != '123456' else '654321'
    page.locator('#totpCode').fill(bad); page.locator('#totpConfirm button').click(); page.locator('#totpMessage').filter(has_text='incorrect').wait_for()
    page.locator('#totpCode').fill(otp(secret, int(time.time()) // 30)); page.locator('#totpConfirm button').click(); page.locator('#totpDisable').wait_for(state='visible')
    page.locator('#totpDisablePassword').fill('preview-only-password'); page.locator('#totpDisableCode').fill(otp(secret, int(time.time()) // 30 + 1)); page.locator('#totpDisable button').click(); page.locator('#totpSetup').wait_for(state='visible')

    # Every page fits from 320 px in both themes; screenshots for review.
    for url in PAGES:
        page.goto(BASE + url); page.wait_for_load_state('networkidle')
        for width in (320, 390, 768, 1440):
            page.set_viewport_size({'width': width, 'height': 900})
            for theme in ('dark', 'light'):
                page.evaluate('(t)=>document.documentElement.dataset.theme=t', theme)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'), (name, url, width, theme)
                if width in (390, 1440) and url in ('/', '/wifi', '/settings', '/backups', '/account'):
                    page.wait_for_timeout(400)  # let colour transitions settle before capturing
                    page.screenshot(path=str(OUT / f"{name}-{url.strip('/') or 'dashboard'}-{width}-{theme}.png"), full_page=True)
    assert not errors, errors
    context.close()
    profile_regression(browser, configuration, name + '-profile')


if __name__ == '__main__':
    with sync_playwright() as p:
        chromium = p.chromium.launch(executable_path='/opt/brave.com/brave/brave', args=['--no-sandbox'])
        run(chromium, {'viewport': {'width': 1440, 'height': 900}}, 'chromium'); chromium.close()
        webkit = p.webkit.launch(); run(webkit, p.devices['iPhone 13'], 'webkit-iphone'); webkit.close()
    print(json.dumps({'ui': 'OK', 'engines': 2, 'pages': len(PAGES), 'widths': [320, 390, 768, 1440], 'themes': 2, 'profile_regression': 'OK', 'screenshots': str(OUT)}))
