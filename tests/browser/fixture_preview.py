"""Disposable preview for browser checks: fictitious data, read-only simulated router, lifespan off.

Run inside the application image, never against production data:
    docker run --rm -p 127.0.0.1:19224:19224 -v "$PWD":/candidate:ro --tmpfs /tmp \
      --entrypoint python sentinel-v2-test /candidate/tests/browser/fixture_preview.py
LIVEBOX_URL points to an unused loopback port so no real box can ever be contacted;
router calls go through the in-memory simulation below. No collector, SMTP, webhook
or Push delivery runs.
"""
import contextlib
import importlib.util
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

os.environ.update(WEB_USERNAME='owner', WEB_PASSWORD='preview-only-password', LIVEBOX_URL='http://127.0.0.1:9/')
directory = tempfile.TemporaryDirectory()
os.environ['DATABASE_PATH'] = str(Path(directory.name) / 'fixture.sqlite3')
spec = importlib.util.spec_from_file_location('candidate', '/candidate/sentinel/main.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
candidate.initialize_db()
candidate.settings_cipher()
now = int(time.time())
con = candidate.connect_db()
fixtures = [('MacBook de Camille', 1, 'Ordinateur', 'Bureau', 'eth0'), ('iPhone', 1, 'Téléphone', 'Salon', 'wl1.1'), ('Télévision du salon', 0, 'Télévision', 'Salon', 'eth0'), ('Home Assistant', 1, 'Serveur', 'Bureau', 'eth0'), ('Imprimante', 0, 'Imprimante', 'Bureau', 'wl0.1')]
with con:
    for index, (name, active, category, location, layer) in enumerate(fixtures, 1):
        mac = f'aa:bb:cc:dd:ee:{index:02x}'
        # The iPhone joined an hour ago: highlighted as new for seven days.
        first_seen = now - 3600 if name == 'iPhone' else now - 1000000
        con.execute('INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at,layer2_interface) VALUES(?,?,?,?,?,?,?)', (mac, name, f'192.168.1.{20 + index}', active, now, first_seen, layer))
        con.execute('INSERT INTO device_profiles VALUES(?,?,?,?,?)', (mac, name, category, location, now))
        for i in range(61):
            con.execute('INSERT INTO traffic VALUES(?,?,?,?)', (mac, now - 3600 + i * 60, i * 15000000 * index, i * 1500000 * index))
        interface = {'wl1.1': 'vap5g0priv', 'wl0.1': 'vap2g0priv'}.get(layer, 'eth' + str(index))
        for hour, kind in ((30, 'connected'), (20, 'disconnected'), (0.2, 'connected' if active else 'disconnected')):
            con.execute('INSERT INTO device_presence_events(mac,ts,event_type,name,ip,interface_name) VALUES(?,?,?,?,?,?)', (mac, int(now - hour * 3600) - index, kind, name, f'192.168.1.{20 + index}', interface))
        if layer.startswith('wl'):
            # The iPhone sits far from the box: a weak but real signal history.
            base = -79 if name == 'iPhone' else -63
            for i in range(48):
                con.execute('INSERT INTO wifi_samples VALUES(?,?,?,?,?,?)', ('primary', mac, now - 86400 + 1800 + i * 1800, base - (i % 4), layer, 'Livebox'))
    # Home Assistant restarted a dozen times this week: enough events for two journal pages.
    for i in range(24):
        con.execute('INSERT INTO device_presence_events(mac,ts,event_type,name,ip,interface_name) VALUES(?,?,?,?,?,?)', ('aa:bb:cc:dd:ee:04', now - 6 * 86400 + i * 14000, 'disconnected' if i % 2 == 0 else 'connected', 'Home Assistant', '192.168.1.24', 'eth4'))
    # A connected object without category: the recognition suggestion is visible on its card.
    esp = 'dc:4f:22:7a:10:c2'
    con.execute("INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at,layer2_interface) VALUES(?,'ESP_7A10C2','192.168.1.60',1,?,?,'wl0.1')", (esp, now, now - 500000))
    candidate.features.put(con, 'fingerprint', esp, candidate.recognition.fingerprint({'Name': 'ESP_7A10C2', 'DHCPOption55': '[1,3,28,6,15,44,46,47,31,33,121,43]', 'Names': [{'Name': 'ESP_7A10C2', 'Source': 'dhcp'}]}))
    # A Wi-Fi repeater on the 5 GHz backhaul, with the iPhone and the connected object behind it.
    repeater = 'aa:bb:cc:dd:ee:50'
    con.execute("INSERT INTO devices(mac,name,ip,active,updated_at,first_seen_at,layer2_interface) VALUES(?,'repeteurwifi6-0000','192.168.1.50',1,?,?,'wl1.1')", (repeater, now, now - 2000000))
    con.execute('INSERT INTO device_profiles VALUES(?,?,?,?,?)', (repeater, 'Répéteur du salon', 'Réseau', 'Salon', now))
    dev = lambda mac, name, tags='lan edev mac physical wifi', **extra: {'Key': mac.upper(), 'Name': name, 'Tags': tags, **extra}
    vap = lambda key, band, children: {'Key': key, 'Tags': 'self lan vap wifi nemo interface', 'OperatingFrequencyBand': band, 'Children': children}
    port = lambda key, children: {'Key': key, 'Tags': 'self lan eth nemo interface', 'Children': children}
    tree = [{'Key': 'HGW', 'Tags': 'self physical hgw wan', 'ModelName': 'Livebox de démonstration', 'Children': [
        {'Key': 'lan', 'Tags': 'self lan mac nemo interface br', 'Children': [
            port('ETH1', [dev('aa:bb:cc:dd:ee:01', 'MacBook de Camille', 'lan edev mac physical eth')]),
            port('ETH2', [dev('aa:bb:cc:dd:ee:04', 'Home Assistant', 'lan edev mac physical eth')]),
            port('ETH3', [dev('aa:bb:cc:dd:ee:03', 'Télévision du salon', 'lan edev mac physical eth upnp', Children=[{'Key': 'uuid:x', 'Tags': 'upnp root logical'}])]),
            port('ETH4', []),
            vap('vap2g0priv', '2.4GHz', [dev('aa:bb:cc:dd:ee:05', 'Imprimante')]),
            vap('vap5g0priv', '5GHz', [dev(repeater, 'repeteurwifi6-0000', Children=[
                vap('_' + repeater.upper() + '_vap5g0priv', '5GHz', [dev('aa:bb:cc:dd:ee:02', 'iPhone')]),
                vap('_' + repeater.upper() + '_vap2g0priv', '2.4GHz', [dev(esp, 'ESP_7A10C2')]),
                {'Key': 'ep5g0', 'Tags': 'wifi endpoint interface lan bridge'}])])]},
        {'Key': 'DECT', 'Tags': 'voice interface dect physical'}]}]
    candidate.features.put(con, 'topology', 'primary', {**candidate.network_topology.parse(tree), 'ts': now})
    # Three days of WAN counters every 30 s (the real collection rhythm), busier in the evening.
    import math
    rx = tx = 0
    for i in range(3 * 2880 - 120):
        ts = now - 3 * 86400 + i * 30
        evening = 1 + math.sin((ts % 86400) / 86400 * 2 * math.pi - 1.6)
        rx += int(4_000_000 * evening); tx += int(400_000 * evening)
        con.execute('INSERT INTO wan_traffic VALUES(?,?,?)', (ts, rx, tx))
    for i in range(120):
        ts = now - 3600 + i * 30
        con.execute('INSERT INTO wan_traffic VALUES(?,?,?)', (ts, rx + i * 10000000, tx + i * 1000000))
        for target, latency in (('livebox', 3 + i % 2), ('google', 18 + i % 7), ('cloudflare', 20 + i % 10)):
            con.execute('INSERT INTO internet_checks(ts,target,ok,latency_ms,status_code,error) VALUES(?,?,?,?,?,NULL)', (ts, target, 1, latency, 204 if target == 'google' else 200))
    con.execute("INSERT INTO internet_events(component,started_at,ended_at,message) VALUES('internet',?,?,'Accès Internet indisponible')", (now - 86400 * 2, now - 86400 * 2 + 420))
    # A device deleted before 2.4 that is connected again: hidden, but listed in Paramètres.
    con.execute("INSERT INTO ignored_devices(mac,ignored_at,permanent,last_seen_at,name) VALUES('aa:bb:cc:dd:ee:40',?,1,?,'Pixel de démonstration')", (now - 9 * 3600, now - 20))
    for index in range(1, len(fixtures) + 1):
        candidate.features.put(con, 'observation', f'primary:aa:bb:cc:dd:ee:{index:02x}', {'ip': f'192.168.1.{20 + index}', 'seen_at': now})
con.close()
candidate.state.update(last_collection=now, devices=5)

fake = MagicMock()
fake._info.get_device_info.return_value = {'ModelName': 'Livebox de démonstration'}
fake._device.get_list.return_value = [{'PhysAddress': f'aa:bb:cc:dd:ee:{i:02x}', 'Name': d[0], 'IPAddress': f'192.168.1.{20 + i}', 'Active': bool(d[1])} for i, d in enumerate(fixtures, 1)]


@contextlib.contextmanager
def simulated_router(config):
    yield fake


candidate.features.router = simulated_router
import uvicorn
print('Fixture on :19224; simulated router, fictitious data, no collector or outbound delivery', flush=True)
uvicorn.run(candidate.app, host='0.0.0.0', port=19224, lifespan='off', log_level='error')
