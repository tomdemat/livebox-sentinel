"""Real HTTP tests for security, Livebox connection, data and new-device e-mails.

Disposable databases only; the router and SMTP are always fakes. Run with --network none.
"""
import base64
import contextlib
import json
import time
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import test_account as harness
candidate, client = harness.candidate, harness.client


class AdvancedTests(unittest.TestCase):
    setUpClass = classmethod(harness.AccountTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.AccountTests.tearDownClass.__func__)
    setUp = harness.AccountTests.setUp
    tearDown = harness.AccountTests.tearDown
    request = harness.AccountTests.request
    login = harness.AccountTests.login
    csrf = harness.AccountTests.csrf

    def save(self, path, payload, method="POST", opener=None):
        return self.request(path, method, payload, {'X-Sentinel-CSRF': self.csrf(opener)}, opener)

    def seed_device(self, suffix='01'):
        mac = 'aa:bb:cc:dd:ee:' + suffix
        with candidate.features.db() as con:
            con.execute("INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at) VALUES(?,?,'192.168.1.20',1,?,?)", (mac, 'iPhone ' + suffix, int(time.time()), int(time.time())))
        return mac

    def smtp_configured(self, new_device=None):
        with candidate.features.db() as con:
            for name, value in (('smtp_host', 'smtp.invalid'), ('smtp_from', 'sentinel@example.invalid'), ('alert_email_to', 'owner@example.invalid')) + ((('email_alert_new_device', new_device),) if new_device is not None else ()):
                con.execute("INSERT INTO app_settings(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, value))

    # ----- Removed features stay removed -----

    def test_removed_household_routes_are_gone(self):
        self.login()
        for path in ('/api/v2/admin/members', '/api/v2/admin/tokens', '/api/v2/inventory', '/api/v2/report', '/api/v2/automations', '/api/v2/integrations', '/api/v2/notifications', '/api/v2/integration-state', '/api/v2/metrics', '/api/v2/me/push/key', '/assets/workspace.js'):
            self.assertEqual(self.request(path)[0], 404, path)
        for path in ('/api/v2/actions/preview', '/api/v2/admin/members', '/api/v2/connections/test'):
            self.assertIn(self.save(path, {})[0], (404, 405), path)
        status, _, headers = self.request('/workspace')
        self.assertEqual(status, 308)
        self.assertEqual(headers['Location'], '/')

    def test_bearer_tokens_are_no_longer_accepted(self):
        with candidate.features.db() as con:
            con.execute("INSERT INTO api_tokens VALUES('t','HA',?,0,?,NULL)", (candidate._feature_module.hashlib.sha256(b'snt_x').hexdigest(), int(time.time()) + 999))
        clean, _ = client()
        self.assertEqual(self.request('/api/devices', headers={'Authorization': 'Bearer snt_x'}, opener=clean)[0], 401)

    def test_former_members_can_neither_log_in_nor_keep_sessions(self):
        with candidate.features.db() as con:
            con.execute("INSERT INTO household_members VALUES('m1','reader','Invité',?,1,1,0)", (candidate.hash_web_password('reader-test-password'),))
            con.execute("INSERT INTO web_sessions(id,token_hash,csrf_token,auth_version,created_at,seen_at,expires_at,user_agent,member_id) VALUES('s','h','c',1,0,0,?,'ua','m1')", (int(time.time()) + 999,))
            con.execute("DELETE FROM feature_documents WHERE kind='migration' AND id='owner-only-v1'")
            candidate.features.initialize(con)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM web_sessions WHERE member_id='m1'").fetchone()[0], 0)
        other, _ = client()
        self.assertEqual(self.request('/api/auth/login', 'POST', {'username': 'reader', 'password': 'reader-test-password'}, opener=other)[0], 401)

    # ----- Sessions and second factor -----

    def test_migrations_preserve_legacy_sessions_and_are_idempotent(self):
        self.login()
        with candidate.features.db() as con:
            con.execute('ALTER TABLE web_sessions DROP COLUMN member_id')
            candidate.features.initialize(con)
            candidate.features.initialize(con)
            self.assertEqual(con.execute('SELECT COUNT(*) FROM web_sessions').fetchone()[0], 1)
            self.assertEqual(con.execute('SELECT member_id FROM web_sessions').fetchone()[0], 'owner')
        self.assertEqual(self.request('/api/totp')[0], 200)

    def test_new_writes_require_csrf_and_origin(self):
        self.login()
        body = {'raw_days': 30, 'aggregate_days': 365, 'events_days': 365}
        self.assertEqual(self.request('/api/retention/preview', 'POST', body)[0], 403)
        self.assertEqual(self.request('/api/retention/preview', 'POST', body, {'X-Sentinel-CSRF': self.csrf(), 'Origin': 'http://evil.invalid'})[0], 403)
        self.assertEqual(self.save('/api/retention/preview', body)[0], 200)
        basic = 'Basic ' + base64.b64encode(b'owner:initial-test-password').decode()
        clean, _ = client()
        for path in ('/api/totp', '/api/livebox-connection', '/api/retention', '/api/audit'):
            self.assertEqual(self.request(path, headers={'Authorization': basic}, opener=clean)[0], 401, path)

    def test_rfc_totp_vector(self):
        secret = base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual(candidate.features.totp(secret, 59 // 30), '287082')
        self.assertEqual(candidate.features.totp(secret, 1111111109 // 30), '081804')

    def test_totp_activation_requires_proof_and_blocks_password_only_and_replay(self):
        self.login()
        self.assertEqual(self.save('/api/totp/setup', {'password': 'wrong-password-123'})[0], 400)
        status, data, _ = self.save('/api/totp/setup', {'password': 'initial-test-password'})
        self.assertEqual(status, 200)
        code = candidate.features.totp(data['secret'], int(time.time()) // 30)
        self.assertEqual(self.save('/api/totp/confirm', {'otp': 'not-a-code'})[0], 400)
        self.assertFalse(candidate.features.document('totp', 'owner').get('enabled'))
        self.assertEqual(self.save('/api/totp/confirm', {'otp': code})[0], 200)
        self.assertTrue(self.request('/api/totp')[1]['enabled'])
        other, _ = client()
        self.assertEqual(self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password'}, opener=other)[0], 401)
        self.assertEqual(self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password', 'otp': code}, opener=other)[0], 401)
        basic = 'Basic ' + base64.b64encode(b'owner:initial-test-password').decode()
        self.assertEqual(self.request('/api/devices', headers={'Authorization': basic}, opener=other)[0], 401)
        future = (int(time.time()) // 30 + 1) * 30
        with patch.object(candidate._feature_module.time, 'time', return_value=future):
            new_code = candidate.features.totp(data['secret'], future // 30)
            self.assertEqual(self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password', 'otp': new_code}, opener=other)[0], 200)

    def test_totp_disable_needs_password_and_code(self):
        self.login()
        data = self.save('/api/totp/setup', {'password': 'initial-test-password'})[1]
        step = int(time.time()) // 30
        self.assertEqual(self.save('/api/totp/confirm', {'otp': candidate.features.totp(data['secret'], step)})[0], 200)
        self.assertEqual(self.save('/api/totp/disable', {'password': 'initial-test-password', 'otp': '000000' if candidate.features.totp(data['secret'], step + 1) != '000000' else '111111'})[0], 400)
        with patch.object(candidate._feature_module.time, 'time', return_value=(step + 1) * 30):
            self.assertEqual(self.save('/api/totp/disable', {'password': 'initial-test-password', 'otp': candidate.features.totp(data['secret'], step + 1)})[0], 200)
        self.assertFalse(self.request('/api/totp')[1]['enabled'])

    def test_preview_bound_to_actor_kind_expiry_and_single_use(self):
        token = candidate.features.preview('owner', 'test', {'a': 1})
        for actor, kind in [('other', 'test'), ('owner', 'other')]:
            with self.assertRaises(candidate.HTTPException):
                candidate.features.consume_preview(token, actor, kind)
        self.assertEqual(candidate.features.consume_preview(token, 'owner', 'test'), {'a': 1})
        with self.assertRaises(candidate.HTTPException):
            candidate.features.consume_preview(token, 'owner', 'test')
        token = candidate.features.preview('owner', 'test', {})
        with candidate.features.db() as con:
            con.execute('UPDATE action_previews SET expires_at=0')
        with self.assertRaises(candidate.HTTPException):
            candidate.features.consume_preview(token, 'owner', 'test')

    # ----- Livebox connection -----

    def test_connection_test_never_saves_before_confirmation_and_hides_password(self):
        self.login()
        api = MagicMock()
        api._info.get_device_info.return_value = {'ModelName': 'Test box'}
        api._device.get_list.return_value = []

        @contextlib.contextmanager
        def router(config):
            yield api
        with patch.object(candidate.features, 'router', router):
            status, data, _ = self.save('/api/livebox-connection/test', {'url': 'http://192.168.1.1/', 'username': 'admin', 'password': 'box-test-secret'})
        self.assertEqual(status, 200)
        self.assertEqual(candidate.features.document('connection', 'primary'), {})
        self.assertNotIn('box-test-secret', json.dumps(data))
        api._wifi.set_enable.assert_not_called()
        self.assertEqual(self.save('/api/livebox-connection/confirm', {'token': data['token']})[0], 200)
        self.assertNotIn('box-test-secret', json.dumps(candidate.features.document('connection', 'primary')))
        self.assertEqual(candidate.features.site_config()['password'], 'box-test-secret')
        state = self.request('/api/livebox-connection')[1]
        self.assertEqual(state['source'], 'application')
        self.assertNotIn('box-test-secret', json.dumps(state))
        self.assertEqual(self.request('/api/livebox-connection', 'DELETE', headers={'X-Sentinel-CSRF': self.csrf()})[0], 200)
        self.assertEqual(self.request('/api/livebox-connection')[1]['source'], '.env')

    def test_network_urls_refuse_metadata_loopback_userinfo_and_dns(self):
        for url in ['http://127.0.0.1/', 'http://169.254.169.254/', 'http://admin:pw@192.168.1.1/', 'https://example.com/', 'http://192.168.1.1/?x=1', 'http://[', 'http://[::ffff:127.0.0.1]/']:
            with self.assertRaises(candidate.HTTPException):
                candidate._feature_module.lan_url(url)
        self.assertEqual(candidate._feature_module.lan_url('http://192.168.1.1'), 'http://192.168.1.1/')

    # ----- Data -----

    def test_retention_preview_preserves_data_then_only_confirmed_old_rows_removed(self):
        self.login()
        mac = self.seed_device()
        now = int(time.time())
        with candidate.features.db() as con:
            con.executemany('INSERT INTO traffic VALUES(?,?,?,?)', [(mac, now - 10 * 86400, 1, 1), (mac, now, 2, 2)])
        status, data, _ = self.save('/api/retention/preview', {'raw_days': 7, 'aggregate_days': 90, 'events_days': 90})
        self.assertEqual(status, 200)
        self.assertEqual(data['eligible_rows']['traffic'], 1)
        with candidate.features.db() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM traffic').fetchone()[0], 2)
        self.assertEqual(self.save('/api/retention/confirm', {'token': data['token']})[0], 200)
        with candidate.features.db() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM traffic').fetchone()[0], 1)
        self.assertEqual(self.save('/api/retention/preview', {'raw_days': 90, 'aggregate_days': 30, 'events_days': 90})[0], 400)
        self.assertIn('retention.applied', [e['action'] for e in self.request('/api/audit')[1]])

    def test_short_raw_retention_uses_aggregated_history(self):
        self.login()
        mac = self.seed_device()
        now = int(time.time())
        with candidate.features.db() as con:
            candidate.features.put(con, 'retention', 'main', {'raw_days': 7, 'aggregate_days': 365, 'events_days': 365})
            con.executemany('INSERT INTO traffic_15m VALUES(?,?,?,?,?)', [(mac, (now - 20 * 86400) // 900 * 900, now - 20 * 86400, 100, 100), (mac, (now - 19 * 86400) // 900 * 900, now - 19 * 86400, 1100, 1100)])
        status, data, _ = self.request('/api/consumption?period=30d')
        self.assertEqual(status, 200)
        self.assertEqual(data['totals']['total_bytes'], 2000)

    def test_storage_growth_waits_for_sufficient_real_samples(self):
        f = candidate.features
        self.assertIsNone(f.storage_growth()['bytes_per_day'])
        with f.db() as con:
            for i in range(3):
                f.put(con, 'storage-history', f'2026-10-{17 + i}', {'ts': 100000 + i * 86400, 'bytes': 1000 + i * 100})
        self.assertEqual(f.storage_growth()['bytes_per_day'], 100)

    def test_quiet_hours_cross_midnight_and_off_by_default(self):
        f = candidate.features
        tz = ZoneInfo('Europe/Paris')
        s = {'quiet_enabled': True, 'quiet_start': '22:00', 'quiet_end': '08:00'}
        for hour, expected in [(21, False), (22, True), (0, True), (7, True), (8, False)]:
            self.assertEqual(f.quiet(s, datetime(2026, 10, 17, hour, 0, tzinfo=tz)), expected)
        self.assertFalse(f.quiet({}, datetime(2026, 10, 17, 23, 0, tzinfo=tz)))

    def test_quiet_email_queue_reuses_transaction_and_groups_afterwards(self):
        f = candidate.features
        with patch.object(f, 'quiet', return_value=True), patch.object(candidate, 'send_smtp_message') as smtp:
            with f.db() as con:
                candidate.send_alert_email('ouvert', 'router', 'Test incident', 1000, connection=con)
                candidate.send_alert_email('ouvert', 'router', 'Test incident', 1000, connection=con)
                self.assertEqual(con.execute("SELECT COUNT(*) FROM feature_documents WHERE kind='mail-outbox'").fetchone()[0], 1)
            f.deliver_queued_email()
            smtp.assert_not_called()
        with patch.object(f, 'quiet', return_value=False), patch.object(candidate, 'send_smtp_message') as smtp:
            f.deliver_queued_email()
            f.deliver_queued_email()
            self.assertEqual(smtp.call_count, 1)

    # ----- Observations, Wi-Fi samples and new-device e-mails -----

    def test_wifi_missing_signal_stays_null(self):
        device = {'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Phone', 'IPAddress': '192.168.1.21', 'Layer2Interface': 'wl1.1', 'SignalStrength': 'unknown', 'Active': True}
        candidate.features.observe([device])
        with candidate.features.db() as con:
            self.assertIsNone(con.execute('SELECT rssi FROM wifi_samples').fetchone()[0])

    def test_wifi_sampling_is_bounded_and_keeps_real_timestamps(self):
        f = candidate.features
        device = {'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Phone', 'IPAddress': '192.168.1.20', 'Layer2Interface': 'wl1.1', 'SignalStrength': -62, 'Active': True}
        for ts in (1800001, 1800059, 1800301):
            with patch.object(candidate._feature_module.time, 'time', return_value=ts):
                f.observe([device])
        with f.db() as con:
            rows = con.execute('SELECT ts,rssi FROM wifi_samples ORDER BY ts').fetchall()
        self.assertEqual([(r[0], r[1]) for r in rows], [(1800059, -62), (1800301, -62)])

    def test_primary_enrichment_adds_no_router_polling(self):
        api = MagicMock()
        candidate.features.observe([], api=api, wan=(100, 100))
        self.assertEqual(api.mock_calls, [])

    def test_new_device_email_setting_round_trip(self):
        self.login()
        self.assertTrue(self.request('/api/settings')[1]['email_alert_new_device'])
        payload = {**self.request('/api/settings')[1], 'smtp_port': 587, 'alert_confirmation_checks': 2, 'email_alert_new_device': False}
        self.assertEqual(self.save('/api/settings', payload)[0], 200)
        self.assertFalse(self.request('/api/settings')[1]['email_alert_new_device'])
        self.assertFalse(candidate.features.new_device_email_enabled())

    def test_devices_deleted_before_upgrade_return_as_new_when_they_reconnect(self):
        with candidate.features.db() as con:
            con.execute("DROP TABLE ignored_devices")
            con.execute("CREATE TABLE ignored_devices(mac TEXT PRIMARY KEY, ignored_at INTEGER NOT NULL)")
            con.execute("INSERT INTO ignored_devices VALUES('aa:bb:cc:dd:ee:30', 1000)")
            con.execute("DELETE FROM feature_documents WHERE kind='migration' AND id='forget-deleted-v1'")
            candidate.features.initialize(con)
            candidate.features.initialize(con)
            self.assertEqual(tuple(con.execute("SELECT permanent,last_seen_at FROM ignored_devices").fetchone()), (0, None))
            self.assertTrue(candidate.skip_ignored(con, 'aa:bb:cc:dd:ee:30', False, 999999, 'iPhone-1'), 'offline: nothing to show')
            self.assertFalse(candidate.skip_ignored(con, 'aa:bb:cc:dd:ee:30', True, 999999, 'iPhone-1'), 'reconnects: it is new again')
            self.assertIsNone(con.execute("SELECT 1 FROM ignored_devices").fetchone())

    def test_deleted_devices_have_no_listing_or_restore_route(self):
        self.login()
        self.assertEqual(self.request('/api/ignored-devices')[0], 404)
        self.assertIn(self.save('/api/ignored-devices/aa:bb:cc:dd:ee:01/restore', {})[0], (404, 405))
        self.assertNotIn(b'Appareils supprim', self.request('/settings')[1])

    def test_lampe_category_becomes_lumiere_once(self):
        mac = self.seed_device()
        with candidate.features.db() as con:
            con.execute("INSERT INTO device_profiles VALUES(?,?,?,?,?)", (mac, 'Lampe du salon', 'Lampe', 'Salon', 0))
            con.execute("DELETE FROM feature_documents WHERE kind='migration' AND id='lumiere-v1'")
            candidate.features.initialize(con)
            self.assertEqual(con.execute("SELECT category FROM device_profiles WHERE mac=?", (mac,)).fetchone()[0], 'Lumière')

    def test_emails_show_livebox_sentinel_as_sender_name(self):
        sent = []

        class FakeSMTP:
            def __init__(self, *args, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def ehlo(self): pass
            def starttls(self, **kwargs): pass
            def login(self, *args): pass
            def send_message(self, message): sent.append(message)
        with patch.object(candidate.smtplib, 'SMTP', FakeSMTP):
            candidate.send_smtp_message({'smtp_host': 'smtp.invalid', 'smtp_from': 'alertes@example.invalid', 'alert_email_to': 'moi@example.invalid', 'smtp_port': '587', 'smtp_security': 'starttls', 'smtp_username': '', 'smtp_password': ''}, 'Sujet', 'Corps')
        self.assertEqual(sent[0]['From'], 'Livebox Sentinel <alertes@example.invalid>')

    def collect(self, inventory):
        """One full collection against an in-memory Livebox: no network, no real router."""
        api = MagicMock()
        api._device.get_list.return_value = inventory
        api._stats.get_device_list.return_value = {}
        api._stats.get_intf.return_value = {'RxBytes': 1, 'TxBytes': 1}
        api._info.get_device_info.return_value = {}
        session = MagicMock()
        session.signin.return_value = 1
        with patch.object(candidate, 'LmSession', return_value=session), patch.object(candidate, 'ApiRegistry', return_value=api), patch.object(candidate, 'send_smtp_message') as smtp:
            candidate.collect_once()
        return smtp

    def first_seen(self, mac):
        with candidate.features.db() as con:
            return con.execute('SELECT first_seen_at FROM devices WHERE mac=?', (mac,)).fetchone()[0]

    # ----- New devices: first real connection -----

    def test_first_inventory_is_a_baseline_without_email(self):
        self.smtp_configured()
        smtp = self.collect([{'PhysAddress': 'aa:bb:cc:dd:ee:0%d' % i, 'Name': 'Device %d' % i, 'Active': True} for i in range(2, 9)])
        smtp.assert_not_called()

    def test_new_device_email_once_grouped_and_detailed(self):
        self.smtp_configured()
        known = {'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Known', 'Active': True}
        self.collect([known]).assert_not_called()
        arrivals = [known, {'PhysAddress': 'AA:BB:CC:DD:EE:10', 'Name': 'Tablette inconnue', 'IPAddress': '192.168.1.77', 'Layer2Interface': 'wl0', 'Active': True}, {'PhysAddress': 'aa:bb:cc:dd:ee:11', 'Name': 'Console', 'IPAddress': '192.168.1.78', 'Layer2Interface': 'eth1', 'Active': True}]
        smtp = self.collect(arrivals)
        self.assertEqual(smtp.call_count, 1, 'one e-mail per collection')
        subject, body = smtp.call_args.args[1], smtp.call_args.args[2]
        self.assertIn('2 nouveaux équipements', subject)
        for expected in ('Tablette inconnue', '192.168.1.77', 'aa:bb:cc:dd:ee:10', 'Liaison : Wi-Fi', 'Liaison : Ethernet', '/?device=aa%3Abb%3Acc%3Add%3Aee%3A10', '7 jours'):
            self.assertIn(expected, body)
        self.collect(arrivals).assert_not_called()

    def test_device_listed_offline_is_announced_on_its_first_real_connection(self):
        self.smtp_configured()
        self.collect([{'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Known', 'Active': True}])
        sleeping = {'PhysAddress': 'a2:00:00:00:00:07', 'Name': 'PC portable', 'Active': False}
        self.collect([sleeping]).assert_not_called()
        self.assertIsNone(self.first_seen('a2:00:00:00:00:07'), 'listed by the box, never online: not new yet')
        self.login()
        self.assertFalse(next(d for d in self.request('/api/devices')[1] if d['mac'] == 'a2:00:00:00:00:07')['is_new'])
        smtp = self.collect([{**sleeping, 'Active': True}])
        self.assertEqual(smtp.call_count, 1)
        self.assertIn('PC portable', smtp.call_args.args[2])
        self.assertTrue(self.first_seen('a2:00:00:00:00:07'))
        self.assertTrue(next(d for d in self.request('/api/devices')[1] if d['mac'] == 'a2:00:00:00:00:07')['is_new'])
        self.collect([{**sleeping, 'Active': False}]).assert_not_called()
        self.collect([{**sleeping, 'Active': True}]).assert_not_called()

    def test_legacy_rows_are_redated_once_from_real_activity_without_email(self):
        now = int(time.time())
        with candidate.features.db() as con:
            for mac, active in (('aa:bb:cc:dd:ee:01', 1), ('aa:bb:cc:dd:ee:02', 1), ('aa:bb:cc:dd:ee:03', 0)):
                con.execute("INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at) VALUES(?,?,'',?,?,0)", (mac, mac, active, now))
            con.execute("INSERT INTO traffic VALUES('aa:bb:cc:dd:ee:01',?,5,5)", (now - 6 * 86400,))
            con.execute("INSERT INTO traffic VALUES('aa:bb:cc:dd:ee:02',?,5,5)", (now - 3600,))
            con.execute("INSERT INTO device_presence_events(mac,ts,event_type,name) VALUES('aa:bb:cc:dd:ee:02',?,'connected','x')", (now - 3600,))
            con.execute("DELETE FROM feature_documents WHERE kind='migration' AND id='first-activity-v1'")
            candidate.features.initialize(con)
        self.assertEqual(self.first_seen('aa:bb:cc:dd:ee:01'), 0, 'active since the start of the collection: known')
        self.assertEqual(self.first_seen('aa:bb:cc:dd:ee:02'), now - 3600, 'first connected an hour ago: new')
        self.assertIsNone(self.first_seen('aa:bb:cc:dd:ee:03'), 'never online: waits for its first connection')

    def test_new_device_email_respects_setting_and_missing_smtp(self):
        self.collect([{'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Known', 'Active': True}])
        self.collect([{'PhysAddress': 'aa:bb:cc:dd:ee:20', 'Name': 'Sans SMTP', 'Active': True}]).assert_not_called()
        self.smtp_configured(new_device='0')
        self.collect([{'PhysAddress': 'aa:bb:cc:dd:ee:21', 'Name': 'Désactivé', 'Active': True}]).assert_not_called()

    def test_deleted_device_does_not_reappear_or_trigger_email(self):
        self.login()
        self.smtp_configured()
        raw = {'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Phone', 'IPAddress': '192.168.1.20', 'Layer2Interface': 'wl1.1', 'SignalStrength': -62, 'Active': True}
        self.collect([raw, {'PhysAddress': 'aa:bb:cc:dd:ee:02', 'Name': 'Known', 'Active': True}])
        self.assertEqual(self.request('/api/devices/aa:bb:cc:dd:ee:01', 'DELETE', headers={'X-Sentinel-CSRF': self.csrf()})[0], 200)
        self.collect([raw]).assert_not_called()
        with candidate.features.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM wifi_samples WHERE mac='aa:bb:cc:dd:ee:01'").fetchone()[0], 0)
            self.assertIsNone(con.execute("SELECT 1 FROM devices WHERE mac='aa:bb:cc:dd:ee:01'").fetchone())
        self.assertEqual(self.request('/api/wifi/aa:bb:cc:dd:ee:01')[0], 404)

    def test_forgotten_device_returns_as_new_only_after_an_absence(self):
        self.login()
        self.smtp_configured()
        phone = {'PhysAddress': 'aa:bb:cc:dd:ee:01', 'Name': 'Phone', 'IPAddress': '192.168.1.20', 'Active': True}
        self.collect([phone, {'PhysAddress': 'aa:bb:cc:dd:ee:02', 'Name': 'Known', 'Active': True}])
        self.assertEqual(self.request('/api/devices/aa:bb:cc:dd:ee:01', 'DELETE', headers={'X-Sentinel-CSRF': self.csrf()})[0], 200)
        self.collect([phone]).assert_not_called()
        now = int(time.time())
        with candidate.features.db() as con:
            self.assertTrue(candidate.skip_ignored(con, 'aa:bb:cc:dd:ee:01', False, now + 4000, 'Phone'), 'offline: stays out')
            con.execute("UPDATE ignored_devices SET last_seen_at=?", (now - candidate.DELETED_RETURN_AFTER - 10,))
        smtp = self.collect([phone])
        self.assertEqual(smtp.call_count, 1, 'back after an absence: announced as new')
        self.assertTrue(self.first_seen('aa:bb:cc:dd:ee:01'))

    def test_wifi_overview_lists_every_device_weakest_first(self):
        self.login()
        now = int(time.time())
        with candidate.features.db() as con:
            for suffix, rssi in (('01', -55), ('02', -82), ('03', None), ('04', -70)):
                con.execute("INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at) VALUES(?,?,'192.168.1.2',1,?,0)", ('aa:bb:cc:dd:ee:' + suffix, 'Appareil ' + suffix, now))
                con.execute("INSERT INTO wifi_samples VALUES('primary',?,?,?,'wl0','Livebox')", ('aa:bb:cc:dd:ee:' + suffix, now - 60, rssi))
        devices = self.request('/api/wifi')[1]['devices']
        self.assertEqual([d['name'] for d in devices], ['Appareil 02', 'Appareil 04', 'Appareil 01', 'Appareil 03'])
        self.assertEqual([d['quality'] for d in devices], ['Faible', 'Moyen', 'Excellent', 'Non communiqué'])
        detail = self.request('/api/wifi/AA:BB:CC:DD:EE:02')[1]
        self.assertEqual(detail['quality'], 'Faible')
        self.assertIn('Rapprochez', detail['advice'])
        self.assertEqual(self.request('/api/wifi/not-a-mac')[0], 400)
        self.assertEqual(self.request('/api/wifi/aa:bb:cc:dd:ee:99')[0], 404)
        anonymous, _ = client()
        self.assertEqual(self.request('/api/wifi', opener=anonymous)[0], 401)
        self.assertEqual(self.request('/wifi')[0], 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
