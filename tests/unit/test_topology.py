"""Network map: the Livebox tree, compact and bounded. Disposable SQLite, loopback HTTP only."""
import json
import unittest
import unittest.mock

import test_account as harness
import test_advanced as advanced
candidate = harness.candidate
topology = candidate.network_topology

REPEATER = '2C:08:23:00:00:06'
TREE = [{'Key': 'HGW', 'Tags': 'self physical hgw wan', 'ModelName': 'Livebox test', 'Children': [
    {'Key': 'lan', 'Tags': 'self lan mac nemo interface br', 'Children': [
        {'Key': 'ETH1', 'Tags': 'self lan eth nemo interface', 'Children': [{'Key': 'F0:B3:EC:00:00:01', 'Name': 'AppleTV', 'Tags': 'lan edev mac physical eth'}]},
        {'Key': 'ETH2', 'Tags': 'self lan eth nemo interface', 'Children': []},
        {'Key': 'vap2g0priv', 'Tags': 'self lan vap wifi nemo interface', 'OperatingFrequencyBand': '2.4GHz', 'Children': [{'Key': 'DC:4F:22:00:00:35', 'Name': 'ESP_000035', 'Tags': 'lan edev mac physical wifi'}]},
        {'Key': 'vap5g0priv', 'Tags': 'self lan vap wifi nemo interface', 'OperatingFrequencyBand': '5GHz', 'Children': [
            {'Key': REPEATER, 'Name': 'repeteurwifi6-0006', 'Tags': 'lan mac physical wifi', 'Children': [
                {'Key': '_' + REPEATER + '_vap2g0priv', 'Tags': 'vap wifi interface lan bridge', 'OperatingFrequencyBand': '2.4GHz', 'Children': [{'Key': 'C0:E4:34:00:00:03', 'Name': 'Roomba', 'Tags': 'lan edev mac physical wifi'}]},
                {'Key': '_' + REPEATER + '_ep5g0', 'Tags': 'wifi endpoint interface lan bridge'}]},
            {'Key': '64:1C:B0:00:00:04', 'Name': 'Samsung', 'Tags': 'lan edev mac physical upnp', 'Children': [{'Key': 'uuid:1', 'Name': 'QE55', 'Tags': 'upnp root logical'}]}]}]},
    {'Key': 'DECT', 'Tags': 'voice interface dect physical', 'Children': [{'Key': 'FXS1', 'Tags': 'voice handset physical'}]},
    {'Key': 'sysbus_USBHost', 'Tags': 'self usb interface sysbus'}]}]


class TopologyRulesTests(unittest.TestCase):
    def test_ports_radios_repeater_and_devices(self):
        parsed = topology.parse(TREE)
        root = parsed['root']
        self.assertEqual((root['kind'], root['model']), ('livebox', 'Livebox test'))
        self.assertEqual([child['label'] for child in root['children']], ['Port Ethernet 1', 'Wi-Fi 2,4 GHz', 'Wi-Fi 5 GHz'], 'empty ports, telephony and USB are left out')
        places = topology.placements(parsed)
        self.assertEqual(places['f0:b3:ec:00:00:01'], {'via': 'Livebox', 'via_mac': '', 'link': 'ethernet', 'band': '', 'port': 'Port Ethernet 1'})
        self.assertEqual(places['c0:e4:34:00:00:03']['via_mac'], REPEATER.lower())
        self.assertEqual(places['c0:e4:34:00:00:03']['band'], '2,4 GHz', 'the band of the repeater radio, not of its backhaul')
        self.assertEqual(places[REPEATER.lower()]['band'], '5 GHz')
        repeater = root['children'][2]['children'][0]
        self.assertEqual(repeater['kind'], 'repeater')
        self.assertIn('64:1c:b0:00:00:04', places, 'a device tagged upnp stays, its UPnP services do not')
        self.assertEqual(root['children'][2]['children'][1]['children'], [])

    def test_unknown_answers_and_bounds(self):
        self.assertEqual(topology.parse(None), {})
        self.assertEqual(topology.parse([{'Key': 'x'}]), {})
        wide = [{'Key': 'HGW', 'Tags': 'hgw', 'Children': [{'Key': 'vap5g0priv', 'Tags': 'interface vap', 'OperatingFrequencyBand': '5GHz', 'Children': [
            {'Key': '00:11:22:33:%02X:%02X' % (i // 256, i % 256), 'Name': 'n\r\n' * 50, 'Tags': 'physical mac'} for i in range(2000)]}]}]
        parsed = topology.parse(wide)
        self.assertLessEqual(len(topology.placements(parsed)), topology.MAX_NODES)
        self.assertNotIn('\n', json.dumps(parsed['root']['children'][0]['children'][0]['label']))


class TopologyApiTests(unittest.TestCase):
    setUpClass = classmethod(harness.AccountTests.setUpClass.__func__)
    tearDownClass = classmethod(harness.AccountTests.tearDownClass.__func__)
    setUp = harness.AccountTests.setUp
    tearDown = harness.AccountTests.tearDown
    request = advanced.AdvancedTests.request
    login = advanced.AdvancedTests.login
    collect = advanced.AdvancedTests.collect

    def test_collection_keeps_the_tree_for_the_map(self):
        self.assertEqual(self.request('/api/network/topology')[0], 401)
        self.login()
        self.assertEqual(self.request('/api/network/topology')[1]['available'], False)
        original = advanced.MagicMock
        with unittest.mock.patch.object(advanced, 'MagicMock', side_effect=lambda *a, **k: self.fake(original(*a, **k))):
            self.collect([{'PhysAddress': 'F0:B3:EC:00:00:01', 'Name': 'AppleTV', 'Active': True}])
        body = self.request('/api/network/topology')[1]
        self.assertTrue(body['available'])
        self.assertEqual(body['root']['children'][0]['children'][0]['mac'], 'f0:b3:ec:00:00:01')
        page = self.request('/network', headers={'Accept': 'text/html'})[1].decode()
        self.assertIn('Carte réseau', page)
        self.assertIn('/assets/network-map.js', page)
        for asset in ('/assets/network-map.js', '/assets/network-map.css'):
            status, body, _ = self.request(asset)
            self.assertEqual(status, 200)
            self.assertGreater(len(body), 1000)

    def fake(self, mock):
        mock._device.get_topology.return_value = TREE
        return mock

    def test_a_failing_tree_does_not_stop_the_collection(self):
        self.login()
        smtp = self.collect([{'PhysAddress': 'F0:B3:EC:00:00:01', 'Name': 'AppleTV', 'Active': True}])
        smtp.assert_not_called()
        self.assertEqual(self.request('/api/network/topology')[1]['available'], False, 'a MagicMock answer is not a Livebox tree')
        self.assertTrue(any(d['mac'] == 'f0:b3:ec:00:00:01' for d in self.request('/api/devices')[1]))


if __name__ == '__main__':
    unittest.main()
