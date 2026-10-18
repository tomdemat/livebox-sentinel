"""Security hardening before publication. Disposable SQLite, loopback HTTP only, router and SMTP faked."""
import contextlib
import json
import sqlite3
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import test_account as harness
import test_advanced as advanced
candidate = harness.candidate


class HardeningTests(unittest.TestCase):
    setUpClass = classmethod(harness.AccountTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.AccountTests.tearDownClass.__func__)
    setUp = harness.AccountTests.setUp
    tearDown = harness.AccountTests.tearDown
    request = advanced.AdvancedTests.request
    login = advanced.AdvancedTests.login
    csrf = advanced.AdvancedTests.csrf
    save = advanced.AdvancedTests.save

    def test_first_account_refuses_the_sample_or_a_short_password(self):
        for weak in ('change-me', 'Change-Me', 'court'):
            connection = sqlite3.connect(':memory:')
            with patch.object(candidate, 'WEB_PASSWORD', weak), self.assertRaises(RuntimeError):
                candidate.initialize_web_account(connection)
            connection.close()

    def test_login_never_confirms_the_password_when_the_code_is_wrong(self):
        self.login()
        data = self.save('/api/totp/setup', {'password': 'initial-test-password'})[1]
        self.assertEqual(self.save('/api/totp/confirm', {'otp': candidate.features.totp(data['secret'], int(time.time()) // 30)})[0], 200)
        fresh = harness.client()[0]
        wrong_password = self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'not-the-password-1'}, opener=fresh)
        wrong_code = self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password', 'otp': '000000'}, opener=fresh)
        no_code = self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password'}, opener=fresh)
        self.assertEqual({wrong_password[0], wrong_code[0], no_code[0]}, {401})
        self.assertEqual(wrong_password[1]['detail'], wrong_code[1]['detail'])
        self.assertEqual(wrong_password[1]['detail'], no_code[1]['detail'])

    def test_disabling_the_second_factor_closes_other_sessions(self):
        self.login()
        data = self.save('/api/totp/setup', {'password': 'initial-test-password'})[1]
        step = int(time.time()) // 30
        self.assertEqual(self.save('/api/totp/confirm', {'otp': candidate.features.totp(data['secret'], step)})[0], 200)
        other = harness.client()[0]
        self.assertEqual(self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password', 'otp': candidate.features.totp(data['secret'], step + 1)}, opener=other)[0], 200)
        self.assertEqual(self.request('/api/auth/session', opener=other)[0], 200)
        with patch('time.time', return_value=(step + 2) * 30 + 1):
            self.assertEqual(self.save('/api/totp/disable', {'password': 'initial-test-password', 'otp': candidate.features.totp(data['secret'], step + 2)})[0], 200)
        self.assertEqual(self.request('/api/auth/session', opener=other)[0], 401)
        self.assertEqual(self.request('/api/auth/session')[0], 200, 'the current session stays open')

    def test_saved_smtp_password_is_never_sent_to_another_server(self):
        self.login()
        base = {'smtp_host': 'smtp.example.invalid', 'smtp_port': 465, 'smtp_security': 'ssl', 'smtp_username': 'alerts', 'smtp_password': 'smtp-secret-value', 'smtp_from': 's@example.invalid', 'alert_email_to': 'o@example.invalid'}
        self.assertEqual(self.save('/api/settings', base)[0], 200)
        moved = {**base, 'smtp_host': 'attacker.example.invalid', 'smtp_password': ''}
        status, data, _ = self.save('/api/settings', moved)
        self.assertEqual(status, 400)
        self.assertIn('mot de passe SMTP', data['detail'])
        self.assertEqual(self.save('/api/settings', {**base, 'smtp_port': 8025})[0], 400, 'unusual ports are refused')
        with patch.object(candidate, 'send_smtp_message') as smtp:
            self.save('/api/settings/test-email', moved)
            self.save('/api/settings/test-email', {**base, 'smtp_password': ''})
        self.assertEqual(smtp.call_args_list[0].args[0]['smtp_password'], '', 'another host never receives the saved password')
        self.assertEqual(smtp.call_args_list[1].args[0]['smtp_password'], 'smtp-secret-value')
        with patch.object(candidate, 'send_smtp_message', side_effect=ConnectionRefusedError()):
            refused = self.save('/api/settings/test-email', base)[1]['detail']
        with patch.object(candidate, 'send_smtp_message', side_effect=TimeoutError()):
            timeout = self.save('/api/settings/test-email', base)[1]['detail']
        self.assertEqual(refused, timeout, 'network failures look alike')
        self.assertNotIn('Error', refused)

    def test_saved_livebox_password_only_goes_back_to_the_same_box(self):
        self.login()
        with candidate.features.db() as con:
            candidate.features.put(con, 'connection', 'primary', {'url': 'http://192.168.1.1/', 'username': 'admin', 'password': candidate.features.encrypt('box-secret-value')})
        seen = []

        @contextlib.contextmanager
        def router(config):
            seen.append(config['password'])
            api = MagicMock(); api._info.get_device_info.return_value = {}; api._device.get_list.return_value = []
            yield api
        with patch.object(candidate.features, 'router', router):
            other = self.save('/api/livebox-connection/test', {'url': 'http://192.168.1.50:8080/', 'username': 'admin', 'password': ''})
            same = self.save('/api/livebox-connection/test', {'url': 'http://192.168.1.1/', 'username': 'admin', 'password': ''})
        self.assertEqual(other[0], 400)
        self.assertEqual(same[0], 200)
        self.assertEqual(seen, ['box-secret-value'])

    def test_api_description_is_not_published(self):
        self.assertEqual(self.request('/openapi.json')[0], 404)

    def test_successful_sensitive_actions_do_not_lock_the_owner_out(self):
        self.login()
        for _ in range(10):
            self.assertEqual(self.save('/api/totp/setup', {'password': 'initial-test-password'})[0], 200)
        self.assertEqual(self.request('/api/auth/login', 'POST', {'username': 'owner', 'password': 'initial-test-password'}, opener=harness.client()[0])[0], 200)

    def test_restore_never_writes_a_script_for_the_host(self):
        source = Path(candidate.__file__).read_text()
        self.assertNotIn('script_path.write_text', source)
        self.assertIn('tools/restore.sh', source)


if __name__ == '__main__':
    unittest.main()
