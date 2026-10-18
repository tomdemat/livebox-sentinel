"""Device recognition: local signals only, suggestions never overwrite the owner. Disposable SQLite, loopback HTTP only."""
import json
import unittest
from unittest.mock import patch

import test_account as harness
import test_advanced as advanced
candidate = harness.candidate
recognition = candidate.recognition

ESP = {'PhysAddress': 'DC:4F:22:00:00:35', 'Name': 'ESP_000035', 'Active': True, 'DHCPOption55': '[1,3,28,6,15,44,46,47,31,33,121,43]',
       'Names': [{'Name': 'Device', 'Source': 'default'}, {'Name': 'ESP_000035', 'Source': 'dhcp'}],
       'DeviceTypes': [{'Type': 'Computer', 'Source': 'default'}]}
HOMEPOD = {'PhysAddress': 'AC:BC:B5:00:00:05', 'Name': 'HP-D', 'Active': True, 'DHCPOption55': '[1,121,3,6,15,108,114,119,162,252]',
           'mDNSService': [{'Name': 'HP D', 'ServiceName': '_airplay._tcp', 'Text': '"acl=0" "model=AudioAccessory6,1" "protovers=1.1"'}],
           'DeviceTypes': [{'Type': 'Computer', 'Source': 'default'}]}
PHONE = {'PhysAddress': 'A2:00:00:00:00:02', 'Name': 'iPhone Camille', 'Active': True, 'DHCPOption55': '[1,121,3,6,15,108,114,119,162,252]',
         'DeviceTypes': [{'Type': 'Mobile', 'Source': 'dhcp'}]}
TV = {'PhysAddress': '64:1C:B0:00:00:04', 'Name': 'Samsung', 'Active': True,
      'Names': [{'Name': '[TV] Samsung Q9', 'Source': 'upnp'}],
      'DeviceTypes': [{'Type': 'Computer', 'Source': 'default'}, {'Type': 'MediaRenderer', 'Source': 'upnp-uuid:x'}, {'Type': 'TV', 'Source': 'dhcp'}]}


class RecognitionRulesTests(unittest.TestCase):
    def guess(self, device, categories=()):
        return recognition.suggest(device['PhysAddress'].lower(), recognition.fingerprint(device), categories)

    def test_chip_vendor_gives_a_family_not_a_certainty(self):
        guess = self.guess(ESP)
        self.assertEqual((guess['category'], guess['confidence'], guess['vendor']), ('Objet connecté', 'moyenne', 'Espressif'))
        self.assertTrue(any('ESP_000035' in reason for reason in guess['reasons']))

    def test_announced_model_and_owner_vocabulary(self):
        guess = self.guess(HOMEPOD, ['Enceinte', 'Lumière'])
        self.assertEqual((guess['category'], guess['model'], guess['vendor']), ('Enceinte', 'HomePod', 'Apple'))
        self.assertEqual(self.guess(HOMEPOD)['category'], 'Audio')

    def test_private_address_has_no_registry_vendor(self):
        guess = self.guess(PHONE)
        self.assertEqual(guess['category'], 'Téléphone')
        self.assertEqual(guess['confidence'], 'élevée')
        self.assertEqual(guess['vendor'], 'Apple (adresse privée)')
        self.assertTrue(recognition.private_mac('a2:00:00:00:00:02'))
        self.assertEqual(recognition.vendor_for('a2:00:00:00:00:02'), '')

    def test_default_livebox_type_is_ignored_and_upnp_name_is_read(self):
        guess = self.guess(TV)
        self.assertEqual((guess['category'], guess['model'], guess['vendor']), ('Télévision', 'Samsung Q9', 'Samsung'))
        unknown = recognition.suggest('02:00:00:00:00:01', recognition.fingerprint({'Name': 'Device', 'DeviceTypes': [{'Type': 'Computer', 'Source': 'default'}]}))
        self.assertEqual((unknown['category'], unknown['vendor']), ('', 'Adresse privée'), 'no signal, no category')

    def test_learned_announcements_survive_a_quiet_collection(self):
        first = recognition.fingerprint(HOMEPOD)
        quiet = recognition.fingerprint({**HOMEPOD, 'mDNSService': None})
        merged = recognition.merge(first, quiet)
        self.assertEqual(merged['models'], ['AudioAccessory6,1'])
        self.assertIn('_airplay._tcp', merged['services'])

    def test_fingerprint_is_bounded_and_printable(self):
        noisy = {'PhysAddress': 'DC:4F:22:00:00:01', 'Name': 'x\r\n' * 200, 'VendorClassID': 'y' * 500,
                 'UserAgents': [{'UserAgent': 'z' * 900}] * 20, 'mDNSService': [{'ServiceName': '_s%d._tcp' % i} for i in range(80)]}
        signals = recognition.fingerprint(noisy)
        self.assertLessEqual(len(json.dumps(signals)), 2500)
        self.assertNotIn('\n', signals['host'])


class RecognitionTests(unittest.TestCase):
    setUpClass = classmethod(harness.AccountTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.AccountTests.tearDownClass.__func__)
    setUp = harness.AccountTests.setUp
    tearDown = harness.AccountTests.tearDown
    request = advanced.AdvancedTests.request
    login = advanced.AdvancedTests.login
    csrf = advanced.AdvancedTests.csrf
    collect = advanced.AdvancedTests.collect
    smtp_configured = advanced.AdvancedTests.smtp_configured

    def device(self, mac):
        return next(d for d in self.request('/api/devices')[1] if d['mac'] == mac)

    def test_suggestion_is_offered_applied_and_never_overwrites(self):
        self.collect([ESP, PHONE])
        self.login()
        headers = {'X-Sentinel-CSRF': self.csrf()}
        esp = self.device('dc:4f:22:00:00:35')
        self.assertEqual(esp['recognition']['vendor'], 'Espressif')
        self.assertEqual(esp['recognition']['suggestion']['category'], 'Objet connecté')
        self.assertEqual(esp['category'], '', 'a suggestion is not applied on its own')
        status, _, _ = self.request('/api/devices/a2:00:00:00:00:02/profile?category=Ordinateur', 'PUT', headers=headers)
        self.assertEqual(status, 200)
        phone = self.device('a2:00:00:00:00:02')
        self.assertEqual(phone['category'], 'Ordinateur')
        self.assertIsNone(phone['recognition']['suggestion'], 'no suggestion once the owner chose')

    def test_dismissed_suggestion_stays_dismissed_until_restored(self):
        self.collect([ESP])
        self.login()
        headers = {'X-Sentinel-CSRF': self.csrf()}
        mac = 'dc:4f:22:00:00:35'
        self.assertEqual(self.request('/api/devices/' + mac + '/suggestion/dismiss', 'POST', {'category': 'Objet connecté'})[0], 403, 'CSRF is required')
        self.assertEqual(self.request('/api/devices/' + mac + '/suggestion/dismiss', 'POST', {'category': ''}, headers)[0], 400)
        self.assertEqual(self.request('/api/devices/aa:bb:cc:dd:ee:99/suggestion/dismiss', 'POST', {'category': 'Objet connecté'}, headers)[0], 404)
        self.assertEqual(self.request('/api/devices/' + mac + '/suggestion/dismiss', 'POST', {'category': 'Objet connecté'}, headers)[0], 200)
        self.collect([ESP])
        self.assertIsNone(self.device(mac)['recognition']['suggestion'])
        self.assertEqual(self.request('/api/devices/' + mac + '/suggestion/dismiss', 'DELETE', headers=headers)[0], 200)
        self.assertIsNotNone(self.device(mac)['recognition']['suggestion'])
        self.assertEqual(self.request('/api/devices/' + mac, 'DELETE', headers=headers)[0], 200)
        self.assertEqual(candidate.features.document('fingerprint', mac), {})

    def test_arrival_email_says_what_it_probably_is(self):
        self.smtp_configured()
        self.collect([PHONE]).assert_not_called()
        smtp = self.collect([PHONE, ESP])
        body = smtp.call_args.args[2]
        self.assertIn('Probablement : objet connecté', body)
        self.assertIn('(Espressif)', body)
        self.assertIn('Indices :', body)

    def test_unchanged_signals_are_not_rewritten(self):
        self.collect([ESP])
        original = candidate.features.put
        with patch.object(candidate.features, 'put', side_effect=original) as put:
            self.collect([ESP])
        self.assertFalse([call for call in put.call_args_list if call.args[1] == 'fingerprint'])

if __name__ == '__main__':
    unittest.main()
