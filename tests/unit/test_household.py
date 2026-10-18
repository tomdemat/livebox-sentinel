"""Household features against disposable SQLite databases; no router or SMTP calls.

Run in the existing application image with the project mounted read-only at /candidate,
DATABASE_PATH=/tmp/test.sqlite3 and --network none. Import never runs app startup.
"""
import csv
import importlib.util
import io
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_PATH"] = "/tmp/sentinel-test-unused.sqlite3"
os.environ["WEB_PASSWORD"] = "test-only-password"
os.environ["LIVEBOX_URL"] = "http://127.0.0.1/"
spec = importlib.util.spec_from_file_location("candidate", os.environ.get("TEST_APP_PATH", "/candidate/sentinel/main.py"))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
MAC = "aa:bb:cc:dd:ee:01"
OTHER = "aa:bb:cc:dd:ee:02"
NOW = 200000


class HouseholdTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        candidate.DATABASE_PATH = str(Path(self.directory.name) / "test.sqlite3")
        candidate.SETTINGS_KEY_PATH = Path(self.directory.name) / "settings.key"
        candidate.initialize_db()
        self.connection = candidate.connect_db()
        self.connection.execute(
            "INSERT INTO devices(mac, name, ip, active, updated_at, first_seen_at) VALUES (?, 'NAS', '192.168.1.10', 0, ?, 0)", (MAC, NOW)
        )
        self.connection.commit()
        self.smtp = patch.object(candidate, "send_alert_email")
        self.send = self.smtp.start()

    def tearDown(self):
        self.connection.close()
        self.smtp.stop()
        self.directory.cleanup()

    def watch(self, email=False):
        self.connection.execute(
            "INSERT INTO device_watches(mac, enabled, offline_minutes, email_enabled) VALUES (?, 1, 1, ?)", (MAC, int(email))
        )
        self.connection.commit()

    def evaluate(self, ts, observed=None):
        with self.connection:
            return candidate.evaluate_device_watches(self.connection, ts, {MAC} if observed is None else observed)

    def test_defaults_are_opt_in(self):
        config = candidate.get_device_watch(MAC, "test")
        self.assertFalse(config["enabled"])
        self.assertFalse(config["email_enabled"])
        self.assertFalse(config["smtp_ready"])
        self.assertEqual(self.evaluate(NOW), [])
        self.send.assert_not_called()

    def test_delay_deduplication_recovery_and_persistence(self):
        self.watch(email=True)
        self.assertEqual(self.evaluate(NOW), [])
        self.assertEqual(self.evaluate(NOW + 59), [])
        opened = self.evaluate(NOW + 60)
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0][0], "ouvert")
        self.assertEqual(opened[0][3], NOW)
        self.assertEqual(self.evaluate(NOW + 90), [])
        self.connection.close()
        self.connection = candidate.connect_db()
        self.assertEqual(self.evaluate(NOW + 100), [])
        self.connection.execute("UPDATE devices SET active=1 WHERE mac=?", (MAC,))
        resolved = self.evaluate(NOW + 110)
        self.assertEqual(resolved[0][0], "résolu")
        self.assertEqual(self.evaluate(NOW + 120), [])
        incident = self.connection.execute("SELECT * FROM device_incidents").fetchone()
        self.assertEqual(incident["end_reason"], "reconnected")
        self.assertEqual(incident["ended_at"], NOW + 110)

    def test_no_email_when_not_enabled(self):
        self.watch()
        candidate.check_device_watches(NOW, {MAC})
        candidate.check_device_watches(NOW + 60, {MAC})
        self.send.assert_not_called()
        self.assertEqual(self.connection.execute("SELECT count(*) FROM device_incidents").fetchone()[0], 1)

    def test_notifications_are_after_commit(self):
        self.watch(email=True)
        candidate.check_device_watches(NOW, {MAC})
        def verify_committed(*args):
            con = candidate.connect_db()
            try:
                self.assertEqual(con.execute("SELECT count(*) FROM device_incidents").fetchone()[0], 1)
            finally:
                con.close()
        self.send.side_effect = verify_committed
        candidate.check_device_watches(NOW + 60, {MAC})
        self.send.assert_called_once()

    def test_collection_gap_restarts_confirmation(self):
        self.watch()
        self.evaluate(NOW)
        self.evaluate(NOW + 3600)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM device_incidents").fetchone()[0], 0)
        row = self.connection.execute("SELECT missing_since FROM device_watches").fetchone()
        self.assertEqual(row[0], NOW + 3600)
        self.evaluate(NOW + 3660)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM device_incidents").fetchone()[0], 1)

    def test_missing_inventory_is_not_disconnection(self):
        self.watch()
        self.evaluate(NOW)
        self.evaluate(NOW + 60, set())
        self.assertIsNone(self.connection.execute("SELECT missing_since FROM device_watches").fetchone()[0])
        self.evaluate(NOW + 90)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM device_incidents").fetchone()[0], 0)

    def test_failed_collection_interrupts_even_short_confirmation(self):
        self.watch()
        self.evaluate(NOW)
        candidate.suspend_device_watches()
        self.evaluate(NOW + 60)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM device_incidents").fetchone()[0], 0)
        self.assertEqual(self.connection.execute("SELECT missing_since FROM device_watches").fetchone()[0], NOW + 60)

    def test_disabling_does_not_claim_reconnection(self):
        self.watch()
        self.evaluate(NOW)
        self.evaluate(NOW + 60)
        candidate.save_device_watch(MAC, {"enabled": False, "offline_minutes": 1}, "test")
        incident = self.connection.execute("SELECT end_reason, ended_at FROM device_incidents").fetchone()
        self.assertEqual(incident["end_reason"], "disabled")
        self.assertIsNotNone(incident["ended_at"])
        self.send.assert_not_called()

    def test_invalid_settings_and_unknown_devices(self):
        for payload in [{"enabled": "true"}, {"offline_minutes": True}, {"offline_minutes": 0}, {"offline_minutes": 1441},
                        {"enabled": True, "email_enabled": True}]:
            with self.subTest(payload=payload), self.assertRaises(candidate.HTTPException):
                candidate.save_device_watch(MAC, payload, "test")
        with self.assertRaises(candidate.HTTPException) as error:
            candidate.save_device_watch(OTHER, {"enabled": True}, "test")
        self.assertEqual(error.exception.status_code, 404)

    def test_delay_change_restarts_pending_timer(self):
        self.watch()
        self.evaluate(NOW)
        candidate.save_device_watch(MAC, {"enabled": True, "offline_minutes": 10}, "test")
        row = self.connection.execute("SELECT missing_since, last_checked_at FROM device_watches").fetchone()
        self.assertEqual(tuple(row), (None, None))

    def test_get_devices_exposes_watch_and_active_incident(self):
        self.watch()
        self.evaluate(NOW)
        self.evaluate(NOW + 60)
        devices = candidate.get_devices("test")
        self.assertTrue(devices[0]["watch_enabled"])
        self.assertEqual(devices[0]["watch_alert_started_at"], NOW)

    def test_delete_removes_watch_and_incidents(self):
        self.watch()
        self.evaluate(NOW)
        self.evaluate(NOW + 60)
        candidate.delete_device(MAC, "test")
        for table in ("devices", "device_watches", "device_incidents"):
            self.assertEqual(self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_presence_filters_and_limits(self):
        for mac, ts, event in [(OTHER, NOW - 1, "connected"), (MAC, NOW - 90000, "connected")]:
            self.connection.execute("INSERT INTO device_presence_events(mac, ts, event_type) VALUES (?, ?, ?)", (mac, ts, event))
        self.connection.executemany(
            "INSERT INTO device_presence_events(mac, ts, event_type) VALUES (?, ?, 'disconnected')",
            [(MAC, NOW - index) for index in range(105)],
        )
        self.connection.commit()
        with patch.object(candidate.time, "time", return_value=NOW):
            result = candidate.get_device_events("test", MAC.upper(), "24h")
            self.assertEqual(len(result["events"]), 100)
            self.assertTrue(result["truncated"])
            self.assertTrue(all(row["mac"] == MAC for row in result["events"]))
            self.assertEqual(result["events"][0]["ts"], NOW)
            self.assertEqual(candidate.get_device_events("test", "x' OR 1=1 --", "24h")["events"], [])
            with self.assertRaises(candidate.HTTPException):
                candidate.get_device_events("test", MAC, "invalid")

    def test_consumption_groups_names_and_csv(self):
        self.connection.execute("INSERT INTO devices(mac, name, ip, active, updated_at) VALUES (?, 'Console', '', 1, ?)", (OTHER, NOW))
        self.connection.execute("INSERT INTO device_profiles VALUES (?, 'Serveur maison', 'Serveur', '=Bureau', ?)", (MAC, NOW))
        self.connection.executemany("INSERT INTO traffic(mac,ts,rx,tx) VALUES (?,?,?,?)", [
            (MAC, NOW - 1200, 1000, 100), (MAC, NOW - 600, 1500, 200),
            (OTHER, NOW - 1200, 500, 100), (OTHER, NOW - 600, 800, 150),
        ])
        self.connection.commit()
        with patch.object(candidate.time, "time", return_value=NOW):
            data = candidate.get_consumption("24h", "test", "location")
            self.assertEqual(data["totals"]["total_bytes"], 950)
            self.assertEqual(sum(row["total_bytes"] for row in data["groups"]), 950)
            self.assertEqual({row["name"] for row in data["groups"]}, {"=Bureau", "Sans pièce"})
            self.assertIn("Serveur maison", [row["name"] for row in data["devices"]])
            csv_response = candidate.export_consumption_csv("24h", "test", "location")
            rows = list(csv.reader(io.StringIO(csv_response.body.decode("utf-8-sig")), delimiter=";"))
            self.assertEqual(rows[0][1], "Pièce")
            self.assertEqual(rows[1][1], "'=Bureau")
            self.assertEqual(len(rows), 3)
            with self.assertRaises(candidate.HTTPException):
                candidate.get_consumption("24h", "test", "invalid")

    def test_unassigned_group_does_not_collide_with_named_room(self):
        rows = [{"location": "", "rx_bytes": 10, "tx_bytes": 1, "total_bytes": 11},
                {"location": "Sans pièce", "rx_bytes": 20, "tx_bytes": 2, "total_bytes": 22}]
        self.assertEqual(len(candidate.aggregate_consumption(rows, "location")), 2)

    def test_additive_initialization_is_idempotent(self):
        self.connection.execute("INSERT INTO app_settings VALUES ('test-preserved', 'value')")
        self.connection.commit()
        self.connection.execute("DROP TABLE device_watches")
        self.connection.execute("DROP TABLE device_incidents")
        self.connection.execute("DROP INDEX idx_device_presence_mac_ts")
        candidate.initialize_db()
        candidate.initialize_db()
        self.assertEqual(self.connection.execute("SELECT name FROM devices WHERE mac=?", (MAC,)).fetchone()[0], "NAS")
        self.assertEqual(self.connection.execute("SELECT value FROM app_settings WHERE name='test-preserved'").fetchone()[0], "value")

    def test_watch_routes_keep_authentication(self):
        routes = [route for route in candidate.app.routes if getattr(route, "path", "") == "/api/devices/{mac}/watch"]
        self.assertEqual(len(routes), 2)
        for route in routes:
            self.assertIn(candidate.require_auth, [dependency.call for dependency in route.dependant.dependencies])


if __name__ == "__main__":
    unittest.main(verbosity=2)
