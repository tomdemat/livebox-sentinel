"""Real HTTP account tests, confined to disposable SQLite and loopback.

Run in the application image with the project mounted read-only at /candidate;
use --network none. The FastAPI lifespan is disabled: no collector or backup starts.
"""
import base64
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from pathlib import Path

os.environ["DATABASE_PATH"] = "/tmp/account-test-unused.sqlite3"
os.environ["WEB_USERNAME"] = "owner"
os.environ["WEB_PASSWORD"] = "initial-test-password"
os.environ["LIVEBOX_URL"] = "http://127.0.0.1/"
spec = importlib.util.spec_from_file_location("candidate", "/candidate/sentinel/main.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect()), jar


class AccountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cls.base = f"http://127.0.0.1:{port}"
        cls.server = uvicorn.Server(uvicorn.Config(candidate.app, host="127.0.0.1", port=port, lifespan="off", log_level="error"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(.02)
        if not cls.server.started:
            raise RuntimeError("Test server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(10)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        candidate.DATABASE_PATH = str(Path(self.directory.name) / "test.sqlite3")
        candidate.SETTINGS_KEY_PATH = Path(self.directory.name) / "settings.key"
        candidate.login_attempts.clear()
        candidate.initialize_db()
        self.opener, self.jar = client()

    def tearDown(self):
        self.directory.cleanup()

    def request(self, path, method="GET", data=None, headers=None, opener=None):
        supplied = {"Accept": "application/json", "User-Agent": "Sentinel test browser"}
        if data is not None:
            supplied.update({"Content-Type": "application/json", "Origin": self.base})
        supplied.update(headers or {})
        payload = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(self.base + path, data=payload, headers=supplied, method=method)
        try:
            response = (opener or self.opener).open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        response.close()
        if response.headers.get_content_type() == "application/json":
            body = json.loads(body)
        return response.status, body, response.headers

    def login(self, opener=None, **overrides):
        payload = {"username": "owner", "password": "initial-test-password", **overrides}
        status, body, headers = self.request("/api/auth/login", "POST", payload, opener=opener)
        self.assertEqual(status, 200)
        return body, headers

    def csrf(self, opener=None):
        status, data, _ = self.request("/api/auth/session", opener=opener)
        self.assertEqual(status, 200)
        return data["csrf_token"]

    def test_initial_owner_is_hashed_and_not_overwritten(self):
        owner = candidate.read_owner()
        self.assertNotEqual(owner["password_hash"], candidate.WEB_PASSWORD)
        self.assertTrue(candidate.verify_web_password(candidate.WEB_PASSWORD, owner["password_hash"]))
        self.assertFalse(candidate.verify_web_password("incorrect", owner["password_hash"]))
        candidate.initialize_db()
        self.assertEqual(candidate.read_owner()["password_hash"], owner["password_hash"])

    def test_public_login_and_logo_private_pages_redirect(self):
        self.assertEqual(self.request("/login")[0], 200)
        status, body, headers = self.request("/favicon.svg")
        self.assertEqual(status, 200)
        self.assertIn(b"<svg", body)
        self.assertEqual(headers.get_content_type(), "image/svg+xml")
        for path in ("/", "/account", "/settings"):
            with self.subTest(path=path):
                status, _, headers = self.request(path)
                self.assertEqual(status, 303)
                self.assertTrue(headers["Location"].startswith("/login?next="))
        status, _, headers = self.request("/api/devices")
        self.assertEqual(status, 401)
        self.assertIn("WWW-Authenticate", headers)
        _, _, browser_headers = self.request("/api/devices", headers={"Sec-Fetch-Mode": "cors"})
        self.assertNotIn("WWW-Authenticate", browser_headers)

    def test_login_page_keeps_cookie_sent_without_session(self):
        # A navigation that arrives without a usable session (iOS home screen, other app)
        # must not wipe the cookie the browser still holds.
        status, _, headers = self.request("/login", headers={"Cookie": "sentinel_session=unknown"})
        self.assertEqual(status, 200)
        self.assertIsNone(headers.get("Set-Cookie"))

    def test_login_cookie_token_storage_and_csrf(self):
        _, headers = self.login()
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=lax", cookie)
        self.assertNotIn("; Secure", cookie)
        self.assertIn("Max-Age=43200", cookie)
        token = next(iter(self.jar)).value
        connection = candidate.connect_db()
        try:
            row = connection.execute("SELECT * FROM web_sessions").fetchone()
            self.assertEqual(row["token_hash"], hashlib.sha256(token.encode()).hexdigest())
            self.assertNotEqual(row["token_hash"], token)
        finally:
            connection.close()
        self.assertEqual(self.request("/account")[0], 200)
        self.assertEqual(self.request("/api/account")[1]["username"], "owner")
        payload = {"display_name": "Chez Camille"}
        self.assertEqual(self.request("/api/account/profile", "PUT", payload)[0], 403)
        self.assertEqual(self.request("/api/account/profile", "PUT", payload, {"X-Sentinel-CSRF": "wrong"})[0], 403)
        self.assertEqual(self.request("/api/account/profile", "PUT", payload, {"X-Sentinel-CSRF": self.csrf()})[0], 200)

    def test_cross_origin_login_and_write_rejected(self):
        payload = {"username": "owner", "password": "initial-test-password"}
        self.assertEqual(self.request("/api/auth/login", "POST", payload, {"Origin": "https://foreign.example"})[0], 403)
        self.login()
        self.assertEqual(self.request("/api/account/profile", "PUT", {"display_name": "No"},
                         {"Origin": "https://foreign.example", "X-Sentinel-CSRF": self.csrf()})[0], 403)

    def test_credentials_change_rotates_current_and_revokes_others(self):
        self.login()
        other, _ = client()
        self.login(opener=other)
        old_cookie = next(iter(self.jar)).value
        csrf = self.csrf()
        data = {"username": "new-owner", "current_password": "initial-test-password", "new_password": "a-new-test-passphrase"}
        self.assertEqual(self.request("/api/account/credentials", "PUT", data, {"X-Sentinel-CSRF": csrf})[0], 200)
        self.assertNotEqual(next(iter(self.jar)).value, old_cookie)
        self.assertEqual(self.request("/api/auth/session")[1]["username"], "new-owner")
        self.assertEqual(self.request("/api/auth/session", opener=other)[0], 401)
        self.assertEqual(len(self.request("/api/account")[1]["sessions"]), 1)
        candidate.initialize_db()
        self.assertEqual(candidate.read_owner()["username"], "new-owner")
        self.assertTrue(candidate.verify_web_password("a-new-test-passphrase", candidate.read_owner()["password_hash"]))
        self.assertEqual(self.request("/api/auth/login", "POST", {"username": "owner", "password": "initial-test-password"})[0], 401)
        self.assertEqual(self.request("/api/auth/login", "POST", {"username": "new-owner", "password": "a-new-test-passphrase"})[0], 200)

    def test_bad_current_password_does_not_change_account(self):
        self.login()
        data = {"username": "new-owner", "current_password": "wrong", "new_password": "a-new-test-passphrase"}
        self.assertEqual(self.request("/api/account/credentials", "PUT", data, {"X-Sentinel-CSRF": self.csrf()})[0], 400)
        self.assertEqual(candidate.read_owner()["username"], "owner")
        self.assertEqual(self.request("/api/auth/session")[0], 200)

    def test_password_length_and_profile_validation(self):
        self.login()
        headers = {"X-Sentinel-CSRF": self.csrf()}
        data = {"username": "owner", "current_password": "initial-test-password", "new_password": "short"}
        self.assertEqual(self.request("/api/account/credentials", "PUT", data, headers)[0], 400)
        for name in ("", "x" * 81, "bad\nname"):
            self.assertEqual(self.request("/api/account/profile", "PUT", {"display_name": name}, headers)[0], 400)
        self.assertEqual(self.request("/api/account/profile", "PUT", {"display_name": "Théo & Léa"}, headers)[0], 200)
        self.assertEqual(self.request("/api/auth/session")[1]["display_name"], "Théo & Léa")

    def test_session_revocation_and_current_session_guard(self):
        self.login()
        other, _ = client()
        self.login(opener=other)
        account = self.request("/api/account")[1]
        current = next(row for row in account["sessions"] if row["current"])
        target = next(row for row in account["sessions"] if not row["current"])
        headers = {"X-Sentinel-CSRF": self.csrf()}
        self.assertEqual(self.request("/api/account/sessions/" + current["id"], "DELETE", headers=headers)[0], 400)
        self.assertEqual(self.request("/api/account/sessions/" + target["id"], "DELETE", headers=headers)[0], 200)
        self.assertEqual(self.request("/api/auth/session", opener=other)[0], 401)
        self.assertEqual(self.request("/api/auth/session")[0], 200)

    def test_revoke_all_other_devices(self):
        self.login()
        others = [client()[0], client()[0]]
        for opener in others:
            self.login(opener=opener)
        self.assertEqual(self.request("/api/account/sessions/revoke-others", "POST", headers={"X-Sentinel-CSRF": self.csrf()})[0], 200)
        for opener in others:
            self.assertEqual(self.request("/api/auth/session", opener=opener)[0], 401)
        self.assertEqual(self.request("/api/auth/session")[0], 200)

    def test_logout_prevents_cookie_replay_and_basic_page_bypass(self):
        self.login()
        stolen = next(iter(self.jar)).value
        headers = {"X-Sentinel-CSRF": self.csrf()}
        self.assertEqual(self.request("/api/auth/logout", "POST", headers=headers)[0], 200)
        self.assertEqual(self.request("/api/auth/session", headers={"Cookie": candidate.SESSION_COOKIE + "=" + stolen})[0], 401)
        basic = "Basic " + base64.b64encode(b"owner:initial-test-password").decode()
        self.assertEqual(self.request("/", headers={"Authorization": basic})[0], 303)
        self.assertEqual(self.request("/api/account", headers={"Authorization": basic})[0], 401)
        self.assertEqual(self.request("/api/devices", headers={"Authorization": basic})[0], 200)

    def test_expired_session_and_bad_cookie_no_basic_fallback(self):
        self.login()
        con = candidate.connect_db()
        with con:
            con.execute("UPDATE web_sessions SET expires_at=?", (int(time.time()) - 1,))
        con.close()
        self.assertEqual(self.request("/api/auth/session")[0], 401)
        basic = "Basic " + base64.b64encode(b"owner:initial-test-password").decode()
        self.assertEqual(self.request("/api/devices", headers={"Authorization": basic})[0], 401)

    def test_rate_limit_and_open_redirect_protection(self):
        for _ in range(8):
            self.assertEqual(self.request("/api/auth/login", "POST", {"username": "owner", "password": "wrong"})[0], 401)
        status, _, headers = self.request("/api/auth/login", "POST", {"username": "owner", "password": "wrong"})
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)
        candidate.login_attempts.clear()
        body, _ = self.login(next="https://foreign.example")
        self.assertEqual(body["next"], "/")

    def test_remembered_cookie_and_no_credentials_in_responses(self):
        _, headers = self.login(remember=True)
        self.assertIn("Max-Age=604800", headers["Set-Cookie"])
        account = self.request("/api/account")[1]
        self.assertNotIn("password_hash", account)
        self.assertNotIn("token_hash", json.dumps(account))
        self.assertNotIn("csrf_token", json.dumps(account))
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_https_cookie_is_secure(self):
        request = candidate.Request({"type": "http", "method": "GET", "path": "/", "scheme": "https", "headers": [(b"host", b"example.test")], "server": ("example.test", 443)})
        response = candidate.JSONResponse({})
        candidate.set_session_cookie(response, request, "test-token", 100)
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("HttpOnly", response.headers["set-cookie"])

    def test_basic_uses_updated_credentials_only(self):
        self.login()
        self.request("/api/account/credentials", "PUT", {"username": "new-owner", "current_password": "initial-test-password", "new_password": "new-test-passphrase"}, {"X-Sentinel-CSRF": self.csrf()})
        clean, _ = client()
        old = "Basic " + base64.b64encode(b"owner:initial-test-password").decode()
        new = "Basic " + base64.b64encode(b"new-owner:new-test-passphrase").decode()
        self.assertEqual(self.request("/api/devices", headers={"Authorization": old}, opener=clean)[0], 401)
        self.assertEqual(self.request("/api/devices", headers={"Authorization": new}, opener=clean)[0], 200)

    def test_session_limit_preserves_newest_login(self):
        for _ in range(11):
            other, _ = client()
            self.login(opener=other)
        self.login()
        self.assertEqual(self.request("/api/auth/session")[0], 200)
        self.assertEqual(len(self.request("/api/account")[1]["sessions"]), 10)

    def test_about_requires_login_and_supports_return_destination(self):
        self.assertEqual(self.request("/api/about")[0], 401)
        status, _, headers = self.request("/about")
        self.assertEqual(status, 303)
        self.assertIn("/login", headers["Location"])
        self.assertIn("/about", candidate.ACCOUNT_DESTINATIONS)
        self.login()
        status, body, _ = self.request("/about")
        self.assertEqual(status, 200)
        self.assertIn('href="/settings" aria-current="page">Paramètres'.encode(), body)
        self.assertIn('href="/about">À propos'.encode(), body)
        self.assertIn(b'https://github.com/p-dor/LiveboxMonitor', body)

    def test_about_storage_metadata_and_no_credentials(self):
        self.login()
        # Test exact sizes without invoking a SQLite operation that changes WAL.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "storage.sqlite3"
            path.write_bytes(b"a" * 100)
            Path(str(path) + "-wal").write_bytes(b"b" * 40)
            Path(str(path) + "-shm").write_bytes(b"c" * 20)
            with patch.object(candidate, "DATABASE_PATH", str(path)):
                data = candidate.get_about("owner")
            self.assertEqual((data["database_bytes"], data["journal_bytes"], data["shared_memory_bytes"], data["storage_bytes"]), (100, 40, 20, 160))
        status, data, _ = self.request("/api/about")
        self.assertEqual(status, 200)
        self.assertEqual(data["version"], candidate.APP_VERSION)
        self.assertGreater(data["database_bytes"], 0)
        self.assertGreaterEqual(data["uptime_seconds"], 0)
        encoded = json.dumps(data)
        for private in ("password", "username", "token", "LIVEBOX_URL", candidate.DATABASE_PATH):
            self.assertNotIn(private, encoded)

    def test_local_recovery_revokes_sessions_without_changing_username(self):
        self.login()
        package = types.ModuleType("sentinel"); package.main = candidate
        sys.modules["sentinel"], sys.modules["sentinel.main"] = package, candidate
        recovery_spec = importlib.util.spec_from_file_location("account_admin", "/candidate/tools/account_admin.py")
        recovery = importlib.util.module_from_spec(recovery_spec)
        recovery_spec.loader.exec_module(recovery)
        with self.assertRaises(ValueError):
            recovery.reset_owner_password("short")
        recovery.reset_owner_password("local-recovery-passphrase")
        self.assertEqual(self.request("/api/auth/session")[0], 401)
        self.assertEqual(candidate.read_owner()["username"], "owner")
        self.assertTrue(candidate.verify_web_password("local-recovery-passphrase", candidate.read_owner()["password_hash"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
