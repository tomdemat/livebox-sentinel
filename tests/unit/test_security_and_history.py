"""0.6: WAN periods, connection journal labels and security hardening. Disposable SQLite only."""
import base64
import sqlite3
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_account as harness
import test_advanced as advanced
candidate, client = harness.candidate, harness.client


class SecurityHistoryTests(unittest.TestCase):
    setUpClass = classmethod(harness.AccountTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.AccountTests.tearDownClass.__func__)
    setUp = harness.AccountTests.setUp
    tearDown = harness.AccountTests.tearDown
    request = advanced.AdvancedTests.request
    login = advanced.AdvancedTests.login
    csrf = advanced.AdvancedTests.csrf
    save = advanced.AdvancedTests.save
    seed_device = advanced.AdvancedTests.seed_device

    # ----- WAN periods -----

    def wan(self, rows):
        with candidate.features.db() as con:
            con.executemany('INSERT INTO wan_traffic VALUES(?,?,?)', rows)

    def test_wan_periods_are_validated(self):
        self.login()
        for period in ('1h', '24h', '7d', '30d', '90d', '1y'):
            self.assertEqual(self.request('/api/wan?period=' + period)[0], 200, period)
        self.assertEqual(self.request('/api/wan?period=2y')[0], 400)

    def test_wan_buckets_average_real_deltas_and_skip_resets_and_gaps(self):
        self.login()
        now = int(time.time())
        base = (now - 3 * 3600) // 300 * 300
        # 1 000 000 bytes every 30 s for 5 minutes, then a counter reset, then a 40-minute gap.
        rows = [(base + i * 30, i * 1_000_000, i * 100_000) for i in range(11)]
        rows.append((base + 330, 5, 5))
        rows += [(base + 330 + 2400 + i * 30, 5 + i * 2_000_000, 5) for i in range(3)]
        self.wan(rows)
        data = self.request('/api/wan?period=24h')[1]
        self.assertEqual(data['bucket_seconds'], 300)
        first = data['points'][0]
        self.assertAlmostEqual(first['rx_bps'], 1_000_000 * 8 / 30, delta=1)
        self.assertEqual(first['rx_peak_bps'], round(1_000_000 * 8 / 30, 1))
        self.assertEqual(data['totals']['rx_bytes'], 10_000_000 + 4_000_000, 'reset and gap contribute nothing')
        self.assertLess(data['totals']['coverage'], .02)
        for point in data['points']:
            self.assertGreater(point['coverage'], 0)

    def test_wan_one_hour_keeps_raw_points(self):
        self.login()
        now = int(time.time())
        self.wan([(now - 60, 0, 0), (now - 30, 300, 30), (now, 600, 60)])
        data = self.request('/api/wan')[1]
        self.assertIsNone(data['bucket_seconds'])
        self.assertEqual(len(data['points']), 2)
        self.assertEqual(data['rx_bps'], 80.0)

    # ----- Connection journal -----

    def test_connection_labels_are_plain_language(self):
        label = candidate._feature_module.connection_label
        cases = {('vap5g0priv', ''): 'Wi-Fi 5 GHz', ('vap2g0priv', ''): 'Wi-Fi 2,4 GHz', ('vap6g0priv', ''): 'Wi-Fi 6 GHz',
                 ('vap5g0guest', ''): 'Wi-Fi invité 5 GHz', ('', 'wl0.1'): 'Wi-Fi 2,4 GHz', ('', 'wl1.1'): 'Wi-Fi 5 GHz',
                 ('eth3', ''): 'Ethernet', ('ETH1', ''): 'Ethernet', ('', ''): 'Liaison non communiquée'}
        for (interface, layer), expected in cases.items():
            self.assertEqual(label(interface, layer), expected, (interface, layer))

    def test_journal_lists_labels_and_validates_limit(self):
        self.login()
        mac = self.seed_device()
        with candidate.features.db() as con:
            con.execute("INSERT INTO device_presence_events(mac,ts,event_type,name,ip,interface_name) VALUES(?,?,'connected','iPhone','192.168.1.20','vap5g0priv')", (mac, int(time.time()) - 60))
        data = self.request('/api/device-events?period=7d&limit=2000')[1]
        self.assertEqual(data['events'][0]['connection'], 'Wi-Fi 5 GHz')
        self.assertNotIn('layer2_interface', data['events'][0])
        self.assertEqual(self.request('/api/device-events?limit=5000')[0], 400)
        self.assertEqual(self.request('/api/device-events?limit=0')[0], 400)
        self.assertEqual(self.request('/api/devices')[1][0]['connection'], 'Liaison non communiquée')

    # ----- Security hardening -----

    def test_security_headers_on_pages_and_api(self):
        self.login()
        for path in ('/', '/api/devices', '/login'):
            headers = self.request(path)[2]
            policy = headers['Content-Security-Policy']
            for directive in ("default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'", "connect-src 'self'"):
                self.assertIn(directive, policy, path)
            self.assertEqual(headers['Cross-Origin-Opener-Policy'], 'same-origin')
            self.assertEqual(headers['X-Frame-Options'], 'DENY')

    def test_basic_authentication_is_read_only(self):
        clean, _ = client()
        basic = {'Authorization': 'Basic ' + base64.b64encode(b'owner:initial-test-password').decode()}
        self.assertEqual(self.request('/api/devices', headers=basic, opener=clean)[0], 200)
        mac = self.seed_device()
        self.assertEqual(self.request('/api/devices/' + mac, 'DELETE', headers=basic, opener=clean)[0], 401)
        self.assertEqual(self.request('/api/settings', 'POST', {'smtp_port': 25}, basic, clean)[0], 401)
        with candidate.features.db() as con:
            self.assertIsNotNone(con.execute('SELECT 1 FROM devices WHERE mac=?', (mac,)).fetchone())

    def test_profile_rejects_control_characters(self):
        self.login()
        mac = self.seed_device()
        status = self.request('/api/devices/' + mac + '/profile?custom_name=' + 'Nom%0Aautre', 'PUT', {}, {'X-Sentinel-CSRF': self.csrf()})[0]
        self.assertEqual(status, 400)
        self.assertEqual(self.request('/api/devices/' + mac + '/profile?custom_name=Salon', 'PUT', {}, {'X-Sentinel-CSRF': self.csrf()})[0], 200)

    def test_restore_rejects_databases_with_triggers(self):
        self.login()
        path = Path(candidate.DATABASE_PATH).parent / 'evil.sqlite3'
        evil = sqlite3.connect(path)
        evil.executescript("CREATE TABLE devices(mac,name,ip,active,updated_at); CREATE TABLE traffic(mac,ts,rx,tx); CREATE TRIGGER t AFTER INSERT ON devices BEGIN DELETE FROM traffic; END;")
        evil.close()
        import urllib.request
        request = urllib.request.Request(self.base + '/api/backups/restore-stage', data=path.read_bytes(), method='POST', headers={'Content-Type': 'application/octet-stream', 'Origin': self.base, 'X-Sentinel-CSRF': self.csrf()})
        try:
            status = self.opener.open(request, timeout=15).status
        except urllib.error.HTTPError as error:
            status = error.code
        self.assertEqual(status, 400)
        self.assertFalse((Path(candidate.DATABASE_PATH).parent / 'restore-staged.sqlite3').exists())

    def test_new_device_subject_cannot_carry_header_syntax(self):
        with candidate.features.db() as con:
            for name, value in (('smtp_host', 'smtp.invalid'), ('smtp_from', 's@example.invalid'), ('alert_email_to', 'o@example.invalid')):
                con.execute("INSERT INTO app_settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, value))
        with patch.object(candidate, 'send_smtp_message') as smtp:
            candidate.features.announce_new_devices([{'mac': 'aa:bb:cc:dd:ee:01', 'name': 'Évil\r\nBcc: x@example.invalid', 'ip': '192.168.1.5', 'link': 'Wi-Fi', 'ts': int(time.time())}])
        subject, body = smtp.call_args.args[1], smtp.call_args.args[2]
        self.assertNotIn('\n', subject)
        self.assertNotIn('\r', subject)
        self.assertNotIn('\r', body)

    def test_collection_errors_do_not_log_exception_details(self):
        source = Path(candidate.__file__).read_text()
        self.assertNotIn('repr(error)', source)


if __name__ == '__main__':
    unittest.main()
