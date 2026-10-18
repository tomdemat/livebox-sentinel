"""Newcomers: highlighted for seven days, recognised on request. Disposable SQLite, loopback HTTP only."""
import json
import time
import unittest

import test_account as harness
import test_advanced as advanced
candidate = harness.candidate


class NewcomerTests(unittest.TestCase):
    setUpClass = classmethod(harness.AccountTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.AccountTests.tearDownClass.__func__)
    setUp = harness.AccountTests.setUp
    tearDown = harness.AccountTests.tearDown
    request = advanced.AdvancedTests.request
    login = advanced.AdvancedTests.login
    csrf = advanced.AdvancedTests.csrf
    seed_device = advanced.AdvancedTests.seed_device

    def device(self, mac):
        return next(d for d in self.request('/api/devices')[1] if d['mac'] == mac)

    def test_verdict_is_gone(self):
        self.login()
        self.assertEqual(self.request('/api/health')[0], 404)

    def test_recognised_newcomer_leaves_the_highlight_reversibly(self):
        mac = self.seed_device('01')
        self.login()
        headers = {'X-Sentinel-CSRF': self.csrf()}
        self.assertTrue(self.device(mac)['is_new'])
        self.assertEqual(self.request('/api/devices/' + mac + '/acknowledge', 'POST', {}, headers)[0], 200)
        self.assertFalse(self.device(mac)['is_new'])
        self.assertTrue(self.device(mac)['acknowledged'])
        self.assertIn('acknowledge', json.dumps(self.request('/api/audit')[1]))
        self.assertEqual(self.request('/api/devices/' + mac + '/acknowledge', 'DELETE', headers=headers)[0], 200)
        self.assertTrue(self.device(mac)['is_new'])

    def test_older_devices_are_not_new(self):
        mac = 'aa:bb:cc:dd:ee:02'
        with candidate.features.db() as con:
            con.execute("INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at) VALUES(?,'Vieux','192.168.1.3',1,?,?)", (mac, int(time.time()), int(time.time()) - 8 * 86400))
        self.login()
        self.assertFalse(self.device(mac)['is_new'])

    def test_acknowledge_is_checked_and_cleaned_with_the_device(self):
        mac = self.seed_device('01')
        self.login()
        headers = {'X-Sentinel-CSRF': self.csrf()}
        self.assertEqual(self.request('/api/devices/aa:bb:cc:dd:ee:99/acknowledge', 'POST', {}, headers)[0], 404)
        self.assertEqual(self.request('/api/devices/not-a-mac/acknowledge', 'POST', {}, headers)[0], 400)
        self.assertEqual(self.request('/api/devices/' + mac + '/acknowledge', 'POST', {})[0], 403, 'CSRF is required')
        self.assertEqual(self.request('/api/devices/' + mac + '/acknowledge', 'POST', {}, headers)[0], 200)
        self.assertEqual(self.request('/api/devices/' + mac, 'DELETE', headers=headers)[0], 200)
        self.assertEqual(candidate.features.document('acknowledged', mac), {})


if __name__ == '__main__':
    unittest.main()
