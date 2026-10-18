import os
import csv
import json
import io
import re
import uuid
import ipaddress
import smtplib
import ssl
import hashlib
from urllib.parse import quote
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from email.utils import formataddr
from cryptography.fernet import Fernet
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, FileResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from LiveboxMonitor.api.LmSession import LmSession
from LiveboxMonitor.api.LmApiRegistry import ApiRegistry


APP_VERSION = "1.0.0"
APP_RELEASE_DATE = "2026-10-18"
STARTED_AT = time.time()
LIVEBOX_URL = os.getenv("LIVEBOX_URL", "http://192.168.1.1/")
LIVEBOX_USERNAME = os.getenv("LIVEBOX_USERNAME", "admin")
LIVEBOX_PASSWORD = os.getenv("LIVEBOX_PASSWORD", "")
WEB_USERNAME = os.getenv("WEB_USERNAME", "admin")
WEB_PASSWORD = os.getenv("WEB_PASSWORD", "")
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
# Address people use to open Sentinel, for links in e-mails (e.g. http://192.168.1.10:8080).
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().rstrip("/")


def public_base_url():
    if PUBLIC_URL:
        return PUBLIC_URL
    host = "localhost" if WEB_HOST in ("0.0.0.0", "::", "") else WEB_HOST
    return f"http://{host}:{WEB_PORT}"
COLLECT_INTERVAL = max(10, int(os.getenv("COLLECT_INTERVAL", "30")))
DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/livebox-sentinel.sqlite3")
SETTINGS_KEY_PATH = Path(DATABASE_PATH).parent / "settings.key"

app = FastAPI(title="Livebox Sentinel", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic(auto_error=False)
state_lock = threading.Lock()
stop_event = threading.Event()
collector_thread = None
backup_thread = None

state = {
    "last_collection": None,
    "last_error": None,
    "devices": 0,
    "samples": 0,
}


def require_auth(request: Request, credentials: HTTPBasicCredentials | None = Depends(security)):
    session = read_web_session(request)
    if session is not None:
        check_request_origin(request)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            supplied = request.headers.get("X-Sentinel-CSRF", "")
            if not secrets.compare_digest(supplied.encode(), session["csrf_token"].encode()):
                raise HTTPException(status_code=403, detail="Votre session doit être actualisée. Rechargez la page.")
        request.state.web_session = session
        return session["username"]
    # Explicit Basic API clients remain compatible. Browser pages and account
    # management always require a revocable session, including after logout.
    basic_allowed = request.url.path.startswith("/api/") and not request.url.path.startswith(("/api/account", "/api/auth", "/api/totp", "/api/livebox-connection", "/api/retention", "/api/audit"))
    basic_allowed = basic_allowed and request.method in ("GET", "HEAD")
    if not request.cookies.get(SESSION_COOKIE) and basic_allowed and credentials is not None:
        check_request_origin(request)
        throttle_login(request)
        owner = read_owner()
        if "features" in globals() and features.document("totp", "owner").get("enabled"):
            raise HTTPException(status_code=401, detail="Utilisez une session avec second facteur ou un jeton d’intégration.")
        valid_name = secrets.compare_digest(credentials.username.encode(), owner["username"].encode())
        valid_password = verify_web_password(credentials.password, owner["password_hash"])
        if valid_name and valid_password:
            clear_login_failures(request)
            return owner["username"]
    challenge = {"WWW-Authenticate": 'Basic realm="Livebox Sentinel"'} if basic_allowed and "sec-fetch-mode" not in request.headers and not request.cookies.get(SESSION_COOKIE) else None
    raise HTTPException(status_code=401, detail="Connectez-vous pour accéder à Livebox Sentinel.", headers=challenge)


SESSION_COOKIE = "sentinel_session"
LOGIN_REFUSED = "Identifiant, mot de passe ou code d’authentification incorrect."
WEAK_PASSWORDS = {"change-me", "changeme", "password", "motdepasse", "admin", "livebox", "sentinel"}
PASSWORD_ITERATIONS = 600000
login_attempts = {}
login_lock = threading.Lock()
ACCOUNT_DESTINATIONS = {"/", "/wifi", "/consumption", "/internet", "/network", "/livebox-health", "/backups", "/settings", "/account", "/about"}


def hash_web_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_web_password(password, encoded):
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(iterations) != PASSWORD_ITERATIONS:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return secrets.compare_digest(digest, bytes.fromhex(expected))
    except (ValueError, TypeError, AttributeError):
        return False


def initialize_web_account(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS web_account (
        id INTEGER PRIMARY KEY CHECK (id=1), username TEXT NOT NULL,
        display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
        auth_version INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login_at INTEGER
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS web_sessions (
        id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, csrf_token TEXT NOT NULL,
        auth_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
        seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, user_agent TEXT NOT NULL
    )""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_web_session_expiry ON web_sessions(expires_at)")
    if not connection.execute("SELECT 1 FROM web_account WHERE id=1").fetchone():
        if not WEB_PASSWORD:
            raise RuntimeError("WEB_PASSWORD est requis pour initialiser le compte propriétaire")
        # The sample value of .env.example, or a short password, would leave the network open.
        if len(WEB_PASSWORD) < 12 or WEB_PASSWORD.strip().lower() in WEAK_PASSWORDS:
            raise RuntimeError("WEB_PASSWORD doit contenir au moins 12 caractères et ne pas reprendre l’exemple de .env.example")
        now = int(time.time())
        connection.execute(
            "INSERT INTO web_account(id, username, display_name, password_hash, created_at, updated_at) VALUES (1, ?, ?, ?, ?, ?)",
            (WEB_USERNAME, WEB_USERNAME, hash_web_password(WEB_PASSWORD), now, now),
        )


def read_owner():
    connection = connect_db()
    try:
        return dict(connection.execute("SELECT * FROM web_account WHERE id=1").fetchone())
    finally:
        connection.close()


def check_request_origin(request):
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin")
    expected = f"{request.url.scheme}://{request.url.netloc}"
    if (origin and origin != expected) or request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(status_code=403, detail="Cette demande doit être effectuée depuis Livebox Sentinel.")


def login_client_key(request):
    return request.client.host if request.client else "local"


def throttle_login(request):
    now = time.monotonic()
    key = login_client_key(request)
    with login_lock:
        for stale in [address for address, values in login_attempts.items() if not values or now - values[-1] >= 900]:
            login_attempts.pop(stale, None)
        attempts = [stamp for stamp in login_attempts.get(key, []) if now - stamp < 900]
        if len(attempts) >= 8:
            retry = max(1, int(900 - (now - attempts[0])))
            raise HTTPException(status_code=429, detail="Trop de tentatives. Réessayez dans quelques minutes.", headers={"Retry-After": str(retry)})
        if len(login_attempts) >= 2048 and key not in login_attempts:
            # Make room by forgetting the oldest address rather than refusing everybody.
            oldest = min(login_attempts, key=lambda address: login_attempts[address][-1])
            login_attempts.pop(oldest, None)
        login_attempts[key] = attempts + [now]


def clear_login_failures(request):
    with login_lock:
        login_attempts.pop(login_client_key(request), None)


def read_web_session(request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token or len(token) > 200:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    connection = connect_db()
    try:
        row = connection.execute(
            """SELECT s.*, a.username, a.display_name, 'owner' AS role FROM web_sessions AS s
               JOIN web_account AS a ON a.id=1 AND a.auth_version=s.auth_version
               WHERE s.member_id='owner' AND s.token_hash=? AND s.expires_at>?""", (digest, now)
        ).fetchone()
        if row is None:
            return None
        if now - row["seen_at"] >= 60:
            with connection:
                connection.execute("UPDATE web_sessions SET seen_at=? WHERE id=?", (now, row["id"]))
        return dict(row)
    finally:
        connection.close()


def create_web_session(connection, request, owner, remember=False):
    now = int(time.time())
    ttl = 7 * 86400 if remember else 12 * 3600
    token = secrets.token_urlsafe(32)
    session_id = uuid.uuid4().hex
    csrf = secrets.token_urlsafe(32)
    member_id = str(owner.get("member_id", "owner"))
    connection.execute("DELETE FROM web_sessions WHERE expires_at<=? OR (member_id=? AND auth_version<>?)", (now, member_id, owner["auth_version"]))
    connection.execute(
        "INSERT INTO web_sessions(id,token_hash,csrf_token,auth_version,created_at,seen_at,expires_at,user_agent,member_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, hashlib.sha256(token.encode()).hexdigest(), csrf, owner["auth_version"], now, now, now + ttl, request.headers.get("user-agent", "Appareil non identifié")[:240], member_id),
    )
    # Keep at most ten active devices, including the newly created session.
    connection.execute(
        "DELETE FROM web_sessions WHERE member_id=? AND id<>? AND id NOT IN (SELECT id FROM web_sessions WHERE member_id=? AND id<>? ORDER BY created_at DESC, rowid DESC LIMIT 9)",
        (member_id, session_id, member_id, session_id),
    )
    if member_id == "owner":
        connection.execute("UPDATE web_account SET last_login_at=? WHERE id=1", (now,))
    return token, csrf, ttl


def set_session_cookie(response, request, token, ttl):
    # Lax, not Strict: iOS WebKit omits Strict cookies when a page is opened from the
    # home screen, another app or a restored tab. Writes stay protected by the CSRF
    # header and the Origin check.
    response.set_cookie(SESSION_COOKIE, token, max_age=ttl, httponly=True,
                        secure=request.url.scheme == "https", samesite="lax", path="/")


@app.exception_handler(HTTPException)
async def web_auth_error(request: Request, exception: HTTPException):
    if exception.status_code == 401 and not request.url.path.startswith("/api/"):
        destination = request.url.path if request.url.path in ACCOUNT_DESTINATIONS else "/"
        return RedirectResponse("/login?next=" + quote(destination, safe=""), status_code=303)
    return JSONResponse({"detail": exception.detail}, status_code=exception.status_code, headers=exception.headers)


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; worker-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


@app.middleware("http")
async def web_response_headers(request: Request, call_next):
    response = await call_next(request)
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api/") and not request.url.path.startswith(("/api/totp", "/api/livebox-connection", "/api/retention")) and 200 <= response.status_code < 300 and hasattr(request.state, "web_session"):
        try:
            with features.db() as connection:
                features.audit(connection, request.state.web_session["username"], request.method.lower() + "." + request.url.path, "Action terminée")
        except Exception as error:
            print("Journal des actions : erreur", type(error).__name__, flush=True)
    if not request.url.path.startswith(("/assets/", "/favicon")):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    # Pages embed their scripts and styles; nothing may be loaded from or sent to another origin.
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    return response


@app.get("/assets/sentinel.svg", include_in_schema=False)
@app.get("/favicon.svg", include_in_schema=False)
@app.get("/favicon.ico", include_in_schema=False)
def sentinel_logo():
    return FileResponse(Path(__file__).parent / "static" / "sentinel.svg", media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if read_web_session(request):
        destination = request.query_params.get("next", "/")
        return RedirectResponse(destination if destination in ACCOUNT_DESTINATIONS else "/", status_code=303)
    # Never clear the cookie here: a navigation that arrived without it must not
    # destroy a session that is still valid.
    return HTMLResponse(LOGIN_PAGE)


@app.post("/api/auth/login")
def login_owner(request: Request, payload: dict):
    check_request_origin(request)
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="Format de connexion invalide")
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 80 or len(password) > 1024:
        raise HTTPException(status_code=401, detail=LOGIN_REFUSED)
    username = username.strip()
    if not isinstance(payload.get("remember", False), bool):
        raise HTTPException(status_code=400, detail="Option de connexion invalide")
    throttle_login(request)
    connection = connect_db()
    try:
        with connection:
            # Serialize login with credential rotation to avoid creating a stale session.
            connection.execute("BEGIN IMMEDIATE")
            owner = dict(connection.execute("SELECT * FROM web_account WHERE id=1").fetchone())
            valid_name = secrets.compare_digest(username.encode(), owner["username"].encode())
            valid_password = verify_web_password(password, owner["password_hash"])
            # One answer for every failure: a refused code must not confirm the password.
            if not valid_name or not valid_password:
                raise HTTPException(status_code=401, detail=LOGIN_REFUSED)
            try:
                features.verify_login_factor(connection, owner, payload.get("otp", ""))
            except HTTPException:
                raise HTTPException(status_code=401, detail=LOGIN_REFUSED)
            old = request.cookies.get(SESSION_COOKIE)
            if old:
                connection.execute("DELETE FROM web_sessions WHERE token_hash=?", (hashlib.sha256(old.encode()).hexdigest(),))
            token, csrf, ttl = create_web_session(connection, request, owner, payload.get("remember", False))
    finally:
        connection.close()
    clear_login_failures(request)
    destination = payload.get("next", "/")
    response = JSONResponse({"next": destination if isinstance(destination, str) and destination in ACCOUNT_DESTINATIONS else "/"})
    set_session_cookie(response, request, token, ttl)
    return response


@app.get("/api/auth/session")
def session_info(request: Request, username: str = Depends(require_auth)):
    session = request.state.web_session
    return {"username": username, "display_name": session["display_name"], "csrf_token": session["csrf_token"], "expires_at": session["expires_at"]}


@app.post("/api/auth/logout")
def logout_owner(request: Request, username: str = Depends(require_auth)):
    connection = connect_db()
    try:
        with connection:
            connection.execute("DELETE FROM web_sessions WHERE id=?", (request.state.web_session["id"],))
    finally:
        connection.close()
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return response


@app.get("/account", response_class=HTMLResponse)
def account_page(username: str = Depends(require_auth)):
    return ACCOUNT_PAGE


@app.get("/api/account")
def get_owner_account(request: Request, username: str = Depends(require_auth)):
    owner = read_owner()
    connection = connect_db()
    try:
        sessions = connection.execute(
            "SELECT id, created_at, seen_at, expires_at, user_agent FROM web_sessions WHERE member_id='owner' AND expires_at>? AND auth_version=? ORDER BY seen_at DESC, rowid DESC",
            (int(time.time()), owner["auth_version"]),
        ).fetchall()
    finally:
        connection.close()
    return {"username": owner["username"], "display_name": owner["display_name"], "created_at": owner["created_at"],
            "updated_at": owner["updated_at"], "last_login_at": owner["last_login_at"],
            "sessions": [dict(row, current=row["id"] == request.state.web_session["id"]) for row in sessions]}


@app.put("/api/account/profile")
def save_owner_profile(payload: dict, username: str = Depends(require_auth)):
    name = payload.get("display_name", "")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(ord(char) < 32 for char in name):
        raise HTTPException(status_code=400, detail="Choisissez un nom de 1 à 80 caractères.")
    connection = connect_db()
    try:
        with connection:
            connection.execute("UPDATE web_account SET display_name=?, updated_at=? WHERE id=1", (name.strip(), int(time.time())))
    finally:
        connection.close()
    return {"saved": True}


@app.put("/api/account/credentials")
def save_owner_credentials(request: Request, payload: dict, username: str = Depends(require_auth)):
    current = payload.get("current_password", "")
    new_password = payload.get("new_password", "")
    new_username = payload.get("username", "")
    if not all(isinstance(value, str) for value in (current, new_password, new_username)) or len(current) > 1024:
        raise HTTPException(status_code=400, detail="Informations de connexion invalides")
    new_username = new_username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._@+\-]{1,80}", new_username):
        raise HTTPException(status_code=400, detail="L’identifiant doit contenir uniquement des lettres non accentuées, chiffres ou . _ @ + - (80 caractères maximum).")
    if new_password and not 12 <= len(new_password) <= 1024:
        raise HTTPException(status_code=400, detail="Utilisez un mot de passe de 12 à 1 024 caractères.")
    throttle_login(request)
    connection = connect_db()
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = dict(connection.execute("SELECT * FROM web_account WHERE id=1").fetchone())
            if owner["auth_version"] != request.state.web_session["auth_version"]:
                raise HTTPException(status_code=401, detail="Votre session a expiré. Reconnectez-vous.")
            if not verify_web_password(current, owner["password_hash"]):
                raise HTTPException(status_code=400, detail="Le mot de passe actuel est incorrect.")
            if not new_password and new_username == owner["username"]:
                raise HTTPException(status_code=400, detail="Modifiez l’identifiant ou renseignez un nouveau mot de passe.")
            if new_password and verify_web_password(new_password, owner["password_hash"]):
                raise HTTPException(status_code=400, detail="Le nouveau mot de passe doit être différent du précédent.")
            encoded = hash_web_password(new_password) if new_password else owner["password_hash"]
            connection.execute(
                "UPDATE web_account SET username=?, password_hash=?, auth_version=auth_version+1, updated_at=? WHERE id=1",
                (new_username, encoded, int(time.time())),
            )
            connection.execute("DELETE FROM web_sessions WHERE member_id='owner'")
            owner = dict(connection.execute("SELECT * FROM web_account WHERE id=1").fetchone())
            token, csrf, ttl = create_web_session(connection, request, owner)
    finally:
        connection.close()
    clear_login_failures(request)
    response = JSONResponse({"saved": True, "reauthenticated": True})
    set_session_cookie(response, request, token, ttl)
    return response


@app.delete("/api/account/sessions/{session_id}")
def revoke_web_session(session_id: str, request: Request, username: str = Depends(require_auth)):
    if session_id == request.state.web_session["id"]:
        raise HTTPException(status_code=400, detail="Utilisez Déconnexion pour fermer cette session.")
    connection = connect_db()
    try:
        with connection:
            connection.execute("DELETE FROM web_sessions WHERE id=?", (session_id,))
    finally:
        connection.close()
    return {"revoked": True}


@app.post("/api/account/sessions/revoke-others")
def revoke_other_web_sessions(request: Request, username: str = Depends(require_auth)):
    connection = connect_db()
    try:
        with connection:
            connection.execute("DELETE FROM web_sessions WHERE member_id='owner' AND id<>?", (request.state.web_session["id"],))
    finally:
        connection.close()
    return {"revoked": True}


def connect_db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def initialize_db():
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = connect_db()
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                name TEXT,
                ip TEXT,
                active INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS device_presence_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ts INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                interface_name TEXT NOT NULL DEFAULT '',
                device_type TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_presence_ts "
            "ON device_presence_events(ts)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_presence_mac_ts "
            "ON device_presence_events(mac, ts DESC, id DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS device_watches (
                mac TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                offline_minutes INTEGER NOT NULL DEFAULT 15,
                email_enabled INTEGER NOT NULL DEFAULT 0,
                missing_since INTEGER,
                last_checked_at INTEGER
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS device_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                opened_at INTEGER NOT NULL,
                ended_at INTEGER,
                end_reason TEXT,
                message TEXT NOT NULL
            )"""
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_device_incident_active "
            "ON device_incidents(mac) WHERE ended_at IS NULL"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS device_profiles (
                mac TEXT PRIMARY KEY,
                custom_name TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL
            )
            """
        )
        device_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(devices)")
        }
        if "first_seen_at" not in device_columns:
            connection.execute(
                "ALTER TABLE devices ADD COLUMN first_seen_at INTEGER"
            )
            connection.execute(
                "UPDATE devices SET first_seen_at=0 WHERE first_seen_at IS NULL"
            )
        for column in ("layer2_interface", "interface_name", "device_type"):
            if column not in device_columns:
                connection.execute(
                    f"ALTER TABLE devices ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
                )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic (
                mac TEXT NOT NULL,
                ts INTEGER NOT NULL,
                rx INTEGER NOT NULL,
                tx INTEGER NOT NULL,
                PRIMARY KEY (mac, ts)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_15m (
                mac TEXT NOT NULL,
                bucket_ts INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                rx INTEGER NOT NULL,
                tx INTEGER NOT NULL,
                PRIMARY KEY (mac, bucket_ts)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(ts)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS internet_checks (
                ts INTEGER NOT NULL,
                target TEXT NOT NULL,
                ok INTEGER NOT NULL,
                latency_ms REAL,
                status_code INTEGER,
                error TEXT,
                PRIMARY KEY (ts, target)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS internet_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                message TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_ts ON internet_checks(ts)"
        )
        if not connection.execute("SELECT 1 FROM traffic_15m LIMIT 1").fetchone():
            connection.execute(
                """
                WITH ranked AS (
                    SELECT mac, (ts / 900) * 900 AS bucket_ts, ts, rx, tx,
                           ROW_NUMBER() OVER (
                               PARTITION BY mac, (ts / 900)
                               ORDER BY ts DESC
                           ) AS position
                    FROM traffic
                )
                INSERT OR IGNORE INTO traffic_15m(mac, bucket_ts, ts, rx, tx)
                SELECT mac, bucket_ts, ts, rx, tx
                FROM ranked
                WHERE position = 1
                """
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS wan_traffic (
                ts INTEGER PRIMARY KEY,
                rx INTEGER NOT NULL,
                tx INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ignored_devices (
                mac TEXT PRIMARY KEY,
                ignored_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS livebox_health (
                ts INTEGER PRIMARY KEY,
                manufacturer TEXT,
                model_name TEXT,
                hardware_version TEXT,
                software_version TEXT,
                modem_firmware_version TEXT,
                device_status TEXT,
                uptime INTEGER,
                reboot_count INTEGER,
                upgrade_occurred INTEGER,
                reset_occurred INTEGER,
                restore_occurred INTEGER,
                wifi_status INTEGER,
                wifi_target_status INTEGER,
                wifi_current_state TEXT,
                wifi_vaps_enabled INTEGER,
                wifi_wps_enabled INTEGER,
                wifi_scheduling_enabled INTEGER
            )
            """
        )
        initialize_web_account(connection)
        features.initialize(connection)
        connection.commit()
    finally:
        connection.close()



def settings_cipher():
    SETTINGS_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            str(SETTINGS_KEY_PATH),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(Fernet.generate_key())
    os.chmod(SETTINGS_KEY_PATH, 0o600)
    return Fernet(SETTINGS_KEY_PATH.read_bytes())


def read_app_settings():
    connection = connect_db()
    try:
        rows = connection.execute("SELECT name, value FROM app_settings").fetchall()
        return {row["name"]: row["value"] for row in rows}
    finally:
        connection.close()


def load_smtp_settings():
    saved = read_app_settings()
    encrypted = saved.get("smtp_password", "")
    password = settings_cipher().decrypt(encrypted.encode()).decode() if encrypted else ""
    return {
        "smtp_host": saved.get("smtp_host", ""),
        "smtp_port": saved.get("smtp_port", "587"),
        "smtp_security": saved.get("smtp_security", "starttls"),
        "smtp_username": saved.get("smtp_username", ""),
        "smtp_password": password,
        "smtp_from": saved.get("smtp_from", ""),
        "alert_email_to": saved.get("alert_email_to", ""),
    }


def send_smtp_message(config, subject, body):
    host = config["smtp_host"].strip()
    sender = config["smtp_from"].strip()
    recipient = config["alert_email_to"].strip()
    if not host or not sender or not recipient:
        raise ValueError("Serveur SMTP, expéditeur et destinataire requis")

    port = int(config["smtp_port"])
    security_mode = config["smtp_security"]
    if security_mode not in ("starttls", "ssl"):
        raise ValueError("Sécurité SMTP invalide")

    email = EmailMessage()
    email["Subject"] = subject
    # The recipient sees « Livebox Sentinel » as the sender name.
    email["From"] = formataddr(("Livebox Sentinel", sender))
    email["To"] = recipient
    email.set_content(body)

    if security_mode == "ssl":
        client = smtplib.SMTP_SSL(
            host, port, timeout=10, context=ssl.create_default_context()
        )
    else:
        client = smtplib.SMTP(host, port, timeout=10)

    with client as server:
        server.ehlo()
        if security_mode == "starttls":
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if config["smtp_username"]:
            server.login(config["smtp_username"], config["smtp_password"])
        server.send_message(email)


def normalize_ip(value):
    candidates = value if isinstance(value, list) else [value]
    matches = []

    for candidate in candidates:
        if isinstance(candidate, dict):
            address = (
                candidate.get("Address")
                or candidate.get("IPv4Address")
                or candidate.get("IPAddress")
            )
            status = str(candidate.get("Status") or "").strip().lower()
        else:
            address = candidate
            status = ""

        if not address:
            continue

        try:
            parsed = ipaddress.ip_address(str(address).strip())
        except ValueError:
            continue

        reachable_rank = (
            0 if status in ("reachable", "active", "up", "connected")
            else 2 if "not reachable" in status
            else 1
        )
        family_rank = 0 if isinstance(parsed, ipaddress.IPv4Address) else 1
        matches.append((reachable_rank, family_rank, str(parsed)))

    return min(matches)[2] if matches else ""


def normalized_mac(value):
    if not value:
        return None
    return str(value).strip().lower()


DELETED_RETURN_AFTER = 3600



def skip_ignored(connection, mac, active, now, name):
    """A deleted device stays out while it remains connected, then comes back as a
    newcomer once it reconnects after an absence. Only its last sighting is kept."""
    row = connection.execute("SELECT permanent, last_seen_at FROM ignored_devices WHERE mac=?", (mac,)).fetchone()
    if row is None:
        return False
    if not row["permanent"] and active and (row["last_seen_at"] is None or now - row["last_seen_at"] > DELETED_RETURN_AFTER):
        connection.execute("DELETE FROM ignored_devices WHERE mac=?", (mac,))
        return False
    if active:
        connection.execute("UPDATE ignored_devices SET last_seen_at=? WHERE mac=?", (now, mac))
    return True


def collect_once():
    connection_config = features.site_config()
    session = LmSession(connection_config["url"])
    api = None
    sample_count = 0
    device_count = 0
    now = int(time.time())
    observed_macs = set()
    # « New » means the first time a device is really connected, not merely listed:
    # the Livebox also remembers devices that have never been online.
    activations = []
    had_devices = True

    try:
        if session.signin(connection_config["username"], connection_config["password"]) != 1:
            raise RuntimeError("Authentification Livebox refusée")

        api = ApiRegistry(session)

        health_snapshot = {
            "manufacturer": None,
            "model_name": None,
            "hardware_version": None,
            "software_version": None,
            "modem_firmware_version": None,
            "device_status": None,
            "uptime": None,
            "reboot_count": None,
            "upgrade_occurred": None,
            "reset_occurred": None,
            "restore_occurred": None,
            "wifi_status": None,
            "wifi_target_status": None,
            "wifi_current_state": None,
            "wifi_vaps_enabled": None,
            "wifi_wps_enabled": None,
            "wifi_scheduling_enabled": None,
        }
        health_available = False

        def health_text(value):
            return str(value).strip()[:160] if value not in (None, "") else None

        def health_int(value):
            try:
                return int(value) if value is not None else None
            except (TypeError, ValueError):
                return None

        def health_bool(value):
            return int(value) if isinstance(value, bool) else None

        try:
            info = api._info.get_device_info() or {}
            health_snapshot.update({
                "manufacturer": health_text(info.get("Manufacturer")),
                "model_name": health_text(info.get("ModelName")),
                "hardware_version": health_text(info.get("HardwareVersion")),
                "software_version": health_text(info.get("SoftwareVersion")),
                "modem_firmware_version": health_text(info.get("ModemFirmwareVersion")),
                "device_status": health_text(info.get("DeviceStatus")),
                "uptime": health_int(info.get("UpTime")),
                "reboot_count": health_int(info.get("NumberOfReboots")),
                "upgrade_occurred": health_bool(info.get("UpgradeOccurred")),
                "reset_occurred": health_bool(info.get("ResetOccurred")),
                "restore_occurred": health_bool(info.get("RestoreOccurred")),
            })
            health_available = True
        except Exception as error:
            print("Lecture santé Livebox : erreur", type(error).__name__, flush=True)

        try:
            wifi = api._wifi.get_status() or {}
            health_snapshot.update({
                "wifi_status": health_bool(wifi.get("Status")),
                "wifi_target_status": health_bool(wifi.get("TargetStatus")),
                "wifi_current_state": health_text(wifi.get("CurrentState")),
                "wifi_vaps_enabled": health_bool(wifi.get("VAPsEnabled")),
                "wifi_wps_enabled": health_bool(wifi.get("WPSEnable")),
                "wifi_scheduling_enabled": health_bool(wifi.get("SchedulingEnabled")),
            })
            health_available = True
        except Exception as error:
            print("Lecture état Wi-Fi : erreur", type(error).__name__, flush=True)

        inventory = api._device.get_list()
        stats_devices = api._stats.get_device_list()
        network_tree = None
        try:
            network_tree = network_topology.parse(api._device.get_topology())
        except Exception as error:
            print("Lecture topologie Livebox : erreur", type(error).__name__, flush=True)
        wan_sample = None
        try:
            interface_stats = api._stats.get_intf("veip0")
            wan_sample = (
                int(interface_stats["RxBytes"]),
                int(interface_stats["TxBytes"]),
            )
        except Exception as error:
            print("Lecture du trafic WAN : erreur", type(error).__name__, flush=True)


        connection = connect_db()
        try:
            with connection:
                if wan_sample is not None:
                    connection.execute(
                        "INSERT OR REPLACE INTO wan_traffic(ts, rx, tx) VALUES (?, ?, ?)",
                        (now, wan_sample[0], wan_sample[1]),
                    )
                if health_available:
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO livebox_health (
                            ts, manufacturer, model_name, hardware_version,
                            software_version, modem_firmware_version, device_status,
                            uptime, reboot_count, upgrade_occurred, reset_occurred,
                            restore_occurred, wifi_status, wifi_target_status,
                            wifi_current_state, wifi_vaps_enabled, wifi_wps_enabled,
                            wifi_scheduling_enabled
                        ) VALUES (
                            :ts, :manufacturer, :model_name, :hardware_version,
                            :software_version, :modem_firmware_version, :device_status,
                            :uptime, :reboot_count, :upgrade_occurred, :reset_occurred,
                            :restore_occurred, :wifi_status, :wifi_target_status,
                            :wifi_current_state, :wifi_vaps_enabled, :wifi_wps_enabled,
                            :wifi_scheduling_enabled
                        )
                        """,
                        {"ts": now, **health_snapshot},
                    )

                connection.execute(
                    "DELETE FROM device_presence_events WHERE ts < ?",
                    (now - features.retention("events_days", 365) * 86400,),
                )
                had_devices = connection.execute("SELECT 1 FROM devices LIMIT 1").fetchone() is not None
                known_categories = None
                for device in inventory:
                    if not isinstance(device, dict):
                        continue

                    mac = normalized_mac(
                        device.get("PhysAddress") or device.get("MACAddress")
                    )
                    if not mac:
                        continue

                    name = device.get("Name") or device.get("Names") or "Inconnu"
                    ip = normalize_ip(device.get("IPAddress")) or normalize_ip(device.get("IPv4Address"))
                    active_value = str(device.get("Active", "")).lower()
                    active = int(active_value in ("1", "true", "yes", "up"))
                    if skip_ignored(connection, mac, bool(active), now, str(name)):
                        continue
                    layer2_interface = str(device.get("Layer2Interface") or "")
                    interface_name = str(device.get("InterfaceName") or "")
                    device_type = str(device.get("DeviceType") or "")
                    signals = None
                    try:
                        previous_signals = features.document("fingerprint", mac, con=connection)
                        signals = recognition.merge(previous_signals, recognition.fingerprint(device))
                        if signals != previous_signals:
                            features.put(connection, "fingerprint", mac, signals)
                    except Exception as error:
                        print("Reconnaissance d’appareil : erreur", type(error).__name__, flush=True)

                    existing_device = connection.execute(
                        "SELECT active, first_seen_at FROM devices WHERE mac=?", (mac,)
                    ).fetchone()
                    first_activation = bool(active) and (existing_device is None or existing_device["first_seen_at"] is None)
                    presence_event = None
                    if existing_device is None and active:
                        presence_event = "connected"
                    elif existing_device is not None and int(existing_device["active"]) != active:
                        presence_event = "connected" if active else "disconnected"
                    if presence_event:
                        connection.execute(
                            """
                            INSERT INTO device_presence_events
                                (mac, ts, event_type, name, ip, interface_name, device_type)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (mac, now, presence_event, str(name), str(ip),
                             interface_name, device_type),
                        )
                    connection.execute(
                        """
                        INSERT INTO devices(
                            mac, name, ip, active, updated_at, first_seen_at,
                            layer2_interface, interface_name, device_type
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(mac) DO UPDATE SET
                            name=excluded.name,
                            ip=excluded.ip,
                            active=excluded.active,
                            updated_at=excluded.updated_at,
                            layer2_interface=excluded.layer2_interface,
                            interface_name=excluded.interface_name,
                            device_type=excluded.device_type
                        """,
                        (
                            mac, str(name), str(ip), active, now,
                            now if first_activation else None,
                            layer2_interface, interface_name, device_type,
                        ),
                    )
                    if first_activation:
                        connection.execute("UPDATE devices SET first_seen_at=? WHERE mac=?", (now, mac))
                        if known_categories is None:
                            known_categories = [row[0] for row in connection.execute("SELECT DISTINCT category FROM device_profiles WHERE category<>''")]
                        try:
                            guess = recognition.suggest(mac, signals, known_categories)
                        except Exception:
                            guess = None
                        activations.append({"mac": mac, "name": str(name)[:100], "ip": ip, "link": _feature_module.connection_label(interface_name, layer2_interface), "ts": now, "suggestion": guess})
                    device_count += 1
                    observed_macs.add(mac)

                if not isinstance(stats_devices, dict):
                    raise RuntimeError("Format inattendu pour les statistiques")

                for device_id, details in stats_devices.items():
                    if not isinstance(details, dict):
                        continue

                    mac = normalized_mac(details.get("MacAddress"))
                    if not mac:
                        continue
                    if connection.execute(
                        "SELECT 1 FROM ignored_devices WHERE mac=?", (mac,)
                    ).fetchone():
                        continue

                    previous = connection.execute(
                        "SELECT MAX(ts) AS last_ts FROM traffic WHERE mac=?",
                        (mac,),
                    ).fetchone()
                    last_ts = previous["last_ts"]

                    connection.execute(
                        """
                        INSERT OR IGNORE INTO devices(mac, name, ip, active, updated_at, first_seen_at)
                        VALUES (?, ?, '', 0, ?, NULL)
                        """,
                        (mac, mac, now),
                    )

                    if last_ts is None:
                        rows = api._stats.get_device_results(str(device_id))
                    else:
                        rows = api._stats.get_device_results(
                            str(device_id), start=int(last_ts), end=int(time.time())
                        )

                    for row in rows or []:
                        if not isinstance(row, dict):
                            continue
                        try:
                            timestamp = int(float(row["Timestamp"]))
                            rx = int(float(row["Rx_Counter"]))
                            tx = int(float(row["Tx_Counter"]))
                        except (KeyError, TypeError, ValueError):
                            continue

                        connection.execute(
                            """
                            INSERT INTO traffic(mac, ts, rx, tx)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(mac, ts) DO UPDATE SET
                                rx=excluded.rx,
                                tx=excluded.tx
                            """,
                            (mac, timestamp, rx, tx),
                        )
                        bucket_ts = (timestamp // 900) * 900
                        connection.execute(
                            """
                            INSERT INTO traffic_15m(mac, bucket_ts, ts, rx, tx)
                            VALUES (?, ?, ?, ?, ?)
                            ON CONFLICT(mac, bucket_ts) DO UPDATE SET
                                ts=excluded.ts,
                                rx=excluded.rx,
                                tx=excluded.tx
                            WHERE excluded.ts > traffic_15m.ts
                            """,
                            (mac, bucket_ts, timestamp, rx, tx),
                        )
                        sample_count += 1
            connection.execute(
                "DELETE FROM traffic WHERE ts < ?", (now - features.retention("raw_days", 30) * 86400,)
            )
            connection.execute(
                "DELETE FROM traffic_15m WHERE bucket_ts < ?",
                (now - features.retention("aggregate_days", 365) * 86400,),
            )
            connection.execute(
                "DELETE FROM wan_traffic WHERE ts < ?",
                (now - features.retention("aggregate_days", 365) * 86400,),
            )
            connection.execute(
                "DELETE FROM livebox_health WHERE ts < ?",
                (now - features.retention("aggregate_days", 365) * 86400,),
            )
            connection.commit()
        finally:
            connection.close()

        with state_lock:
            state["last_collection"] = int(time.time())
            state["last_error"] = None
            state["devices"] = device_count
            state["samples"] = sample_count

        # An unavailable inventory must never be treated as device disconnection.
        # Notifications run only after the collection transaction has committed.
        try:
            check_device_watches(now, observed_macs)
        except Exception as error:
            print("Surveillance des équipements : erreur", type(error).__name__, flush=True)
        try:
            features.observe(inventory, api=api, wan=wan_sample)
            if network_tree:
                with features.db() as tree_connection:
                    features.put(tree_connection, "topology", "primary", {**network_tree, "ts": now})
        except Exception as error:
            print("Inventaire enrichi : erreur", type(error).__name__, flush=True)
        # A first inventory on an empty database is a baseline, never a burst of e-mails.
        if activations and had_devices:
            features.announce_new_devices(activations)

    finally:
        if api is not None:
            api.close()
        else:
            session.close()


def evaluate_device_watches(connection, now, observed_macs):
    """Advance watches only from fresh, successfully collected observations."""
    notifications = []
    max_gap = max(120, COLLECT_INTERVAL * 3)
    watches = connection.execute(
        """SELECT w.*, d.active, COALESCE(NULLIF(p.custom_name, ''), d.name, d.mac) AS name
           FROM device_watches AS w JOIN devices AS d ON d.mac=w.mac
           LEFT JOIN device_profiles AS p ON p.mac=d.mac WHERE w.enabled=1"""
    ).fetchall()
    for watch in watches:
        mac = watch["mac"]
        if mac not in observed_macs:
            connection.execute(
                "UPDATE device_watches SET missing_since=NULL, last_checked_at=NULL WHERE mac=?", (mac,)
            )
            continue
        incident = connection.execute(
            "SELECT * FROM device_incidents WHERE mac=? AND ended_at IS NULL", (mac,)
        ).fetchone()
        if watch["active"]:
            connection.execute(
                "UPDATE device_watches SET missing_since=NULL, last_checked_at=? WHERE mac=?", (now, mac)
            )
            if incident:
                connection.execute(
                    "UPDATE device_incidents SET ended_at=?, end_reason='reconnected' WHERE id=?",
                    (now, incident["id"]),
                )
                if watch["email_enabled"]:
                    notifications.append(("résolu", "équipement", incident["message"], incident["started_at"], now))
            continue
        last_checked = watch["last_checked_at"]
        missing_since = watch["missing_since"]
        if last_checked is None or not 0 <= now - last_checked <= max_gap or missing_since is None:
            missing_since = now
        connection.execute(
            "UPDATE device_watches SET missing_since=?, last_checked_at=? WHERE mac=?",
            (missing_since, now, mac),
        )
        if not incident and now - missing_since >= watch["offline_minutes"] * 60:
            message = f"{watch['name']} est signalé hors ligne par la Livebox"
            connection.execute(
                "INSERT INTO device_incidents(mac, started_at, opened_at, message) VALUES (?, ?, ?, ?)",
                (mac, missing_since, now, message),
            )
            if watch["email_enabled"]:
                notifications.append(("ouvert", "équipement", message, missing_since))
    connection.execute(
        "DELETE FROM device_incidents WHERE ended_at IS NOT NULL AND opened_at < ?", (now - features.retention("events_days", 365) * 86400,)
    )
    return notifications


def check_device_watches(now, observed_macs):
    connection = connect_db()
    try:
        with connection:
            notifications = evaluate_device_watches(connection, now, observed_macs)
    finally:
        connection.close()
    for notification in notifications:
        send_alert_email(*notification)


def suspend_device_watches():
    """A failed collection interrupts pending confirmation, without resolving alerts."""
    connection = connect_db()
    try:
        with connection:
            connection.execute(
                "UPDATE device_watches SET missing_since=NULL, last_checked_at=NULL WHERE enabled=1"
            )
    finally:
        connection.close()


def send_alert_email(status, component, message, started_at, ended_at=None, connection=None):
    try:
        config = load_smtp_settings()
        start_text = datetime.fromtimestamp(
            started_at, timezone.utc
        ).astimezone().strftime("%d/%m/%Y %H:%M:%S %Z")
        body = [
            f"Incident {status} : {message}",
            f"Composant : {component}",
            f"Début : {start_text}",
        ]
        if ended_at is not None:
            end_text = datetime.fromtimestamp(
                ended_at, timezone.utc
            ).astimezone().strftime("%d/%m/%Y %H:%M:%S %Z")
            body.append(f"Fin : {end_text}")
        if features.quiet(features.document("notification-settings", con=connection)):
            features.queue_email(f"Incident {status} : {message}", "\n".join(body), connection)
            return
        send_smtp_message(
            config,
            f"[Livebox Sentinel] Incident {status} : {message}",
            "\n".join(body),
        )
        print(f"E-mail d'alerte envoyé : {status} — {component}", flush=True)
    except Exception as error:
        print("Échec de l'e-mail d'alerte :", type(error).__name__, flush=True)



def update_incidents(connection, now):
    setting = connection.execute(
        "SELECT value FROM app_settings WHERE name='alert_confirmation_checks'"
    ).fetchone()
    try:
        required_checks = int(setting["value"]) if setting else 2
    except (TypeError, ValueError):
        required_checks = 2
    required_checks = min(20, max(2, required_checks))

    batches = connection.execute(
        "SELECT DISTINCT ts FROM internet_checks ORDER BY ts DESC LIMIT ?",
        (required_checks,),
    ).fetchall()
    if len(batches) < required_checks:
        return

    batch_timestamps = [row["ts"] for row in batches]

    def email_enabled(component):
        key = "email_alert_router" if component == "router" else "email_alert_internet"
        row = connection.execute(
            "SELECT value FROM app_settings WHERE name=?", (key,)
        ).fetchone()
        return row is None or row["value"] != "0"

    for component in ("router", "internet"):
        states = []
        for batch_ts in batch_timestamps:
            checks = connection.execute(
                "SELECT target, ok FROM internet_checks WHERE ts=?",
                (batch_ts,),
            ).fetchall()
            by_target = {row["target"]: bool(row["ok"]) for row in checks}
            if component == "router":
                states.append(by_target.get("livebox", False))
            else:
                states.append(
                    by_target.get("google", False)
                    or by_target.get("cloudflare", False)
                )

        active = connection.execute(
            """
            SELECT id, started_at, message FROM internet_events
            WHERE component=? AND ended_at IS NULL
            """,
            (component,),
        ).fetchone()

        if not any(states) and active is None:
            message = (
                "Livebox inaccessible"
                if component == "router"
                else "Accès Internet indisponible"
            )
            started_at = batch_timestamps[-1]
            connection.execute(
                """
                INSERT INTO internet_events(component, started_at, message)
                VALUES (?, ?, ?)
                """,
                (component, started_at, message),
            )
            if email_enabled(component):
                send_alert_email("ouvert", component, message, started_at, connection=connection)
        elif all(states) and active is not None:
            ended_at = batch_timestamps[0]
            connection.execute(
                "UPDATE internet_events SET ended_at=? WHERE id=?",
                (ended_at, active["id"]),
            )
            if email_enabled(component):
                send_alert_email(
                    "résolu", component, active["message"],
                    active["started_at"], ended_at, connection=connection
                )

    connection.execute(
        """
        DELETE FROM internet_events
        WHERE ended_at IS NOT NULL AND started_at < ?
        """,
        (now - features.retention("events_days", 365) * 86400,),
    )

def probe_internet():
    import requests

    targets = [
        ("livebox", features.site_config()["url"], 200),
        ("google", "https://connectivitycheck.gstatic.com/generate_204", 204),
        ("cloudflare", "https://www.cloudflare.com/cdn-cgi/trace", 200),
    ]
    now = int(time.time())
    results = []

    for name, url, expected_status in targets:
        started = time.monotonic()
        status_code = None
        error = None
        try:
            response = requests.get(url, timeout=(3, 5), allow_redirects=True)
            status_code = response.status_code
            ok = status_code == expected_status
            if not ok:
                error = "HTTP " + str(status_code)
        except Exception as exc:
            ok = False
            error = type(exc).__name__

        latency_ms = round((time.monotonic() - started) * 1000, 1)
        results.append(
            (now, name, int(ok), latency_ms, status_code, error)
        )

    connection = connect_db()
    try:
        with connection:
            connection.executemany(
                """
                INSERT OR REPLACE INTO internet_checks
                    (ts, target, ok, latency_ms, status_code, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                results,
            )
            update_incidents(connection, now)
            connection.execute(
                "DELETE FROM internet_checks WHERE ts < ?",
                (now - features.retention("events_days", 365) * 86400,),
            )
    finally:
        connection.close()


def collector_loop():
    while not stop_event.is_set():
        started = time.monotonic()
        try:
            probe_internet()
        except Exception as error:
            print("Test Internet : erreur", type(error).__name__, flush=True)

        try:
            collect_once()
            print("Collecte Livebox Sentinel : OK")
        except Exception as error:
            with state_lock:
                state["last_error"] = type(error).__name__
            print("Collecte Livebox Sentinel : erreur", type(error).__name__, flush=True)
            try:
                suspend_device_watches()
            except Exception as watch_error:
                print("Suspension des surveillances : erreur", type(watch_error).__name__, flush=True)

        elapsed = time.monotonic() - started
        stop_event.wait(max(1, COLLECT_INTERVAL - elapsed))


@app.on_event("startup")
def startup():
    global collector_thread
    initialize_db()
    settings_cipher()
    collector_thread = threading.Thread(
        target=collector_loop,
        name="livebox-collector",
        daemon=True,
    )
    collector_thread.start()
    backup_thread = threading.Thread(
        target=automatic_backup_loop,
        name="livebox-backup-scheduler",
        daemon=True,
    )
    backup_thread.start()
    threading.Thread(target=features.loop, name="sentinel-housekeeping", daemon=True).start()


@app.on_event("shutdown")
def shutdown():
    stop_event.set()


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/status")
def get_status(username: str = Depends(require_auth)):
    with state_lock:
        return dict(state)


@app.get("/api/devices")
def get_devices(username: str = Depends(require_auth)):
    connection = connect_db()
    try:
        devices = connection.execute(
            """
            SELECT d.mac, d.name, d.ip, d.active, d.first_seen_at,
                   p.custom_name, p.category, p.location,
                   d.layer2_interface, d.interface_name, d.device_type,
                   w.enabled AS watch_enabled, i.started_at AS watch_alert_started_at
            FROM devices AS d
            LEFT JOIN device_profiles AS p ON p.mac = d.mac
            LEFT JOIN device_watches AS w ON w.mac=d.mac
            LEFT JOIN device_incidents AS i ON i.mac=d.mac AND i.ended_at IS NULL
            ORDER BY COALESCE(NULLIF(p.custom_name, ''), d.name) COLLATE NOCASE
            """
        ).fetchall()

        acknowledged = {row[0] for row in connection.execute("SELECT id FROM feature_documents WHERE kind='acknowledged'")}
        result = []
        for device in devices:
            points = connection.execute(
                """
                SELECT ts, rx, tx FROM traffic
                WHERE mac=? ORDER BY ts DESC LIMIT 2
                """,
                (device["mac"],),
            ).fetchall()

            rx_bps = None
            tx_bps = None
            latest_ts = None

            if points:
                latest_ts = points[0]["ts"]

            if len(points) == 2:
                elapsed = points[0]["ts"] - points[1]["ts"]
                rx_delta = points[0]["rx"] - points[1]["rx"]
                tx_delta = points[0]["tx"] - points[1]["tx"]
                if elapsed > 0 and rx_delta >= 0 and tx_delta >= 0:
                    rx_bps = round(rx_delta * 8 / elapsed, 1)
                    tx_bps = round(tx_delta * 8 / elapsed, 1)

            result.append(
                {
                    "mac": device["mac"],
                    "name": device["custom_name"] or device["name"],
                    "router_name": device["name"],
                    "custom_name": device["custom_name"] or "",
                    "category": device["category"] or "",
                    "location": device["location"] or "",
                    "layer2_interface": device["layer2_interface"] or "",
                    "interface_name": device["interface_name"] or "",
                    "connection": _feature_module.connection_label(device["interface_name"], device["layer2_interface"]),
                    "device_type": device["device_type"] or "",
                    "ip": device["ip"],
                    "active": bool(device["active"]),
                    # A device the owner recognised is no longer highlighted as new.
                    "is_new": bool(
                        device["first_seen_at"] and
                        device["first_seen_at"] >= int(time.time()) - 7 * 86400
                    ) and device["mac"] not in acknowledged,
                    "acknowledged": device["mac"] in acknowledged,
                    "first_seen_at": device["first_seen_at"] or None,
                    "rx_bps": rx_bps,
                    "tx_bps": tx_bps,
                    "last_sample": latest_ts,
                    "watch_enabled": bool(device["watch_enabled"]),
                    "watch_alert_started_at": device["watch_alert_started_at"],
                }
            )

        for item in result:
            item.update(features.document("inventory", item["mac"], con=connection))
        attach_recognition(connection, result)
        return result
    finally:
        connection.close()


def attach_recognition(connection, devices):
    """Adds the vendor, the announced model and, for a device without category, a suggestion."""
    signals = {row[0]: json.loads(row[1]) for row in connection.execute("SELECT id, value FROM feature_documents WHERE kind='fingerprint'")}
    dismissed = {row[0]: json.loads(row[1]).get("category", "") for row in connection.execute("SELECT id, value FROM feature_documents WHERE kind='suggestion_dismissed'")}
    categories = sorted({device["category"] for device in devices if device.get("category")})
    for device in devices:
        try:
            found = recognition.suggest(device["mac"], signals.get(device["mac"]), categories) or {}
        except Exception as error:
            print("Reconnaissance d’appareil : erreur", type(error).__name__, flush=True)
            found = {}
        offered = bool(found.get("category")) and not device.get("category") and dismissed.get(device["mac"]) != found.get("category")
        device["recognition"] = {
            "vendor": found.get("vendor", ""), "model": found.get("model", ""),
            "suggestion": {key: found[key] for key in ("category", "confidence", "reasons")} if offered else None,
        }


@app.post("/api/devices/{mac}/suggestion/dismiss")
def dismiss_device_suggestion(mac: str, payload: dict, username: str = Depends(require_auth)):
    normalized = normalized_mac(mac)
    category = payload.get("category") if isinstance(payload, dict) else None
    if not normalized or not isinstance(category, str) or not 0 < len(category.strip()) <= 40:
        raise HTTPException(status_code=400, detail="Suggestion invalide")
    with features.db() as connection:
        if not connection.execute("SELECT 1 FROM devices WHERE mac=?", (normalized,)).fetchone():
            raise HTTPException(status_code=404, detail="Appareil introuvable")
        features.put(connection, "suggestion_dismissed", normalized, {"category": category.strip(), "ts": int(time.time())})
    return {"dismissed": True}


@app.delete("/api/devices/{mac}/suggestion/dismiss")
def restore_device_suggestion(mac: str, username: str = Depends(require_auth)):
    normalized = normalized_mac(mac)
    if not normalized:
        raise HTTPException(status_code=400, detail="Adresse MAC invalide")
    with features.db() as connection:
        connection.execute("DELETE FROM feature_documents WHERE kind='suggestion_dismissed' AND id=?", (normalized,))
    return {"dismissed": False}


@app.delete("/api/devices/{mac}")
def delete_device(mac: str, username: str = Depends(require_auth)):
    normalized = normalized_mac(mac)
    if not normalized:
        raise HTTPException(status_code=400, detail="Adresse MAC invalide")

    connection = connect_db()
    try:
        with connection:
            now = int(time.time())
            known = connection.execute(
                "SELECT d.active, COALESCE(NULLIF(p.custom_name, ''), d.name) AS name FROM devices AS d LEFT JOIN device_profiles AS p ON p.mac=d.mac WHERE d.mac=?",
                (normalized,),
            ).fetchone()
            # Everything about the device is erased. A short internal marker keeps a device
            # that is still connected from reappearing at once; once it has been away for an
            # hour, its next connection makes it a new device again, with its e-mail.
            connection.execute(
                """INSERT INTO ignored_devices(mac, ignored_at, permanent, last_seen_at, name) VALUES (?, ?, 0, ?, NULL)
                   ON CONFLICT(mac) DO UPDATE SET permanent=0, last_seen_at=excluded.last_seen_at""",
                (normalized, now, now if known and known["active"] else None),
            )
            connection.execute(
                "DELETE FROM device_presence_events WHERE mac=?", (normalized,)
            )
            connection.execute("DELETE FROM traffic WHERE mac=?", (normalized,))
            connection.execute("DELETE FROM traffic_15m WHERE mac=?", (normalized,))
            connection.execute("DELETE FROM devices WHERE mac=?", (normalized,))
            connection.execute("DELETE FROM device_profiles WHERE mac=?", (normalized,))
            connection.execute("DELETE FROM device_watches WHERE mac=?", (normalized,))
            connection.execute("DELETE FROM device_incidents WHERE mac=?", (normalized,))
            connection.execute("DELETE FROM wifi_samples WHERE site='primary' AND mac=?", (normalized,))
            connection.execute("DELETE FROM feature_documents WHERE kind IN ('fingerprint', 'suggestion_dismissed') AND id=?", (normalized,))
            connection.execute("DELETE FROM feature_documents WHERE (kind IN ('inventory','acknowledged') AND id=?) OR (kind='observation' AND id=?)", (normalized, "primary:" + normalized))
            connection.execute("DELETE FROM notifications WHERE event_key=? OR event_key LIKE ? OR event_key LIKE ?", ("new:primary:" + normalized, "ip:primary:" + normalized + ":%", "watch:" + normalized + ":%"))
            connection.execute("DELETE FROM notification_reads WHERE notification_id NOT IN (SELECT id FROM notifications)")
            import json
            for snapshot in connection.execute("SELECT ts,value FROM site_snapshots WHERE site='primary'").fetchall():
                value = json.loads(snapshot["value"])
                value["devices"] = [d for d in value.get("devices", []) if d.get("mac") != normalized]
                connection.execute("UPDATE site_snapshots SET value=? WHERE site='primary' AND ts=?", (json.dumps(value), snapshot["ts"]))
        return {"deleted": True, "mac": normalized}
    finally:
        connection.close()


def smtp_is_configured(connection):
    saved = dict(connection.execute(
        "SELECT name, value FROM app_settings WHERE name IN ('smtp_host', 'smtp_from', 'alert_email_to')"
    ).fetchall())
    return all(str(saved.get(key, "")).strip() for key in ("smtp_host", "smtp_from", "alert_email_to"))


@app.get("/api/devices/{mac}/watch")
def get_device_watch(mac: str, username: str = Depends(require_auth)):
    mac = normalized_mac(mac)
    connection = connect_db()
    try:
        if not connection.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone():
            raise HTTPException(status_code=404, detail="Appareil introuvable")
        row = connection.execute("SELECT * FROM device_watches WHERE mac=?", (mac,)).fetchone()
        incidents = connection.execute(
            "SELECT started_at, opened_at, ended_at, end_reason, message FROM device_incidents "
            "WHERE mac=? ORDER BY id DESC LIMIT 10", (mac,)
        ).fetchall()
        return {
            "enabled": bool(row["enabled"]) if row else False,
            "offline_minutes": row["offline_minutes"] if row else 15,
            "email_enabled": bool(row["email_enabled"]) if row else False,
            "missing_since": row["missing_since"] if row else None,
            "last_checked_at": row["last_checked_at"] if row else None,
            "smtp_ready": smtp_is_configured(connection),
            "incidents": [dict(item) for item in incidents],
        }
    finally:
        connection.close()


@app.put("/api/devices/{mac}/watch")
def save_device_watch(mac: str, payload: dict, username: str = Depends(require_auth)):
    enabled = payload.get("enabled", False)
    email_enabled = payload.get("email_enabled", False)
    minutes = payload.get("offline_minutes", 15)
    if not isinstance(enabled, bool) or not isinstance(email_enabled, bool):
        raise HTTPException(status_code=400, detail="Options de surveillance invalides")
    if type(minutes) is not int or not 1 <= minutes <= 1440:
        raise HTTPException(status_code=400, detail="Le délai doit être compris entre 1 et 1 440 minutes")
    mac = normalized_mac(mac)
    now = int(time.time())
    connection = connect_db()
    try:
        with connection:
            if not connection.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone():
                raise HTTPException(status_code=404, detail="Appareil introuvable")
            if enabled and email_enabled and not smtp_is_configured(connection):
                raise HTTPException(status_code=400, detail="Configurez d’abord les e-mails dans Paramètres")
            connection.execute(
                """INSERT INTO device_watches(mac, enabled, offline_minutes, email_enabled)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(mac) DO UPDATE SET
                     missing_since=CASE WHEN excluded.enabled=0 OR device_watches.enabled=0
                       OR device_watches.offline_minutes<>excluded.offline_minutes
                       THEN NULL ELSE device_watches.missing_since END,
                     last_checked_at=CASE WHEN excluded.enabled=0 OR device_watches.enabled=0
                       OR device_watches.offline_minutes<>excluded.offline_minutes
                       THEN NULL ELSE device_watches.last_checked_at END,
                     enabled=excluded.enabled, offline_minutes=excluded.offline_minutes,
                     email_enabled=excluded.email_enabled""",
                (mac, int(enabled), minutes, int(email_enabled)),
            )
            if not enabled:
                connection.execute(
                    "UPDATE device_incidents SET ended_at=?, end_reason='disabled' WHERE mac=? AND ended_at IS NULL",
                    (now, mac),
                )
    finally:
        connection.close()
    return {"saved": True}


@app.put("/api/devices/{mac}/profile")
def update_device_profile(
    mac: str,
    custom_name: str = "",
    category: str = "",
    location: str = "",
    username: str = Depends(require_auth),
):
    normalized = normalized_mac(mac)
    if not normalized:
        raise HTTPException(status_code=400, detail="Adresse MAC invalide")

    custom_name = custom_name.strip()
    category = category.strip()
    location = location.strip()
    if len(custom_name) > 80 or len(category) > 40 or len(location) > 80:
        raise HTTPException(status_code=400, detail="Un champ du profil est trop long")
    if any(ord(char) < 32 or ord(char) == 127 for char in custom_name + category + location):
        raise HTTPException(status_code=400, detail="Un champ du profil contient un caractère invalide")

    connection = connect_db()
    try:
        with connection:
            if not connection.execute(
                "SELECT 1 FROM devices WHERE mac=?", (normalized,)
            ).fetchone():
                raise HTTPException(status_code=404, detail="Appareil introuvable")
            connection.execute(
                """
                INSERT INTO device_profiles(mac, custom_name, category, location, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    custom_name=excluded.custom_name,
                    category=excluded.category,
                    location=excluded.location,
                    updated_at=excluded.updated_at
                """,
                (normalized, custom_name, category, location, int(time.time())),
            )
        return {
            "saved": True,
            "mac": normalized,
            "custom_name": custom_name,
            "category": category,
            "location": location,
        }
    finally:
        connection.close()


# Period → (span, bucket). Buckets average real counter deltas only: counter resets and
# collection gaps are excluded, and empty buckets stay empty rather than being invented.
WAN_PERIODS = {
    "1h": (3600, 0), "24h": (86400, 300), "7d": (7 * 86400, 1800),
    "30d": (30 * 86400, 7200), "90d": (90 * 86400, 21600), "1y": (365 * 86400, 86400),
}


@app.get("/api/wan")
def get_wan_traffic(period: str = "1h", username: str = Depends(require_auth)):
    if period not in WAN_PERIODS:
        raise HTTPException(status_code=400, detail="Période invalide")
    span, bucket = WAN_PERIODS[period]
    now = int(time.time())
    start = now - span
    max_gap = max(120, COLLECT_INTERVAL * 3)
    connection = connect_db()
    try:
        deltas = """
            WITH s AS (
                SELECT ts, rx, tx, LAG(ts) OVER w AS pts, LAG(rx) OVER w AS prx, LAG(tx) OVER w AS ptx
                FROM wan_traffic WHERE ts >= ? WINDOW w AS (ORDER BY ts)
            )
            SELECT ts, ts - pts AS dt, rx - prx AS drx, tx - ptx AS dtx FROM s
            WHERE pts IS NOT NULL AND ts > ? AND ts - pts > 0 AND ts - pts <= ? AND rx >= prx AND tx >= ptx
        """
        parameters = (start - max_gap, start, max_gap)
        if bucket:
            rows = connection.execute(
                f"SELECT (ts / {bucket}) * {bucket} AS b, SUM(drx) AS rxb, SUM(dtx) AS txb, SUM(dt) AS covered, "
                f"MAX(drx * 8.0 / dt) AS rx_peak, MAX(dtx * 8.0 / dt) AS tx_peak FROM ({deltas}) GROUP BY b ORDER BY b",
                parameters,
            ).fetchall()
            points = [{
                "ts": int(row["b"]) + bucket // 2,
                "rx_bps": round(row["rxb"] * 8 / row["covered"], 1),
                "tx_bps": round(row["txb"] * 8 / row["covered"], 1),
                "rx_peak_bps": round(row["rx_peak"], 1), "tx_peak_bps": round(row["tx_peak"], 1),
                "coverage": round(min(1, row["covered"] / bucket), 3),
            } for row in rows if row["covered"]]
            received = sum(row["rxb"] for row in rows)
            sent = sum(row["txb"] for row in rows)
            covered = sum(row["covered"] for row in rows)
        else:
            rows = connection.execute(deltas, parameters).fetchall()
            points = [{"ts": int(row["ts"]), "rx_bps": round(row["drx"] * 8 / row["dt"], 1), "tx_bps": round(row["dtx"] * 8 / row["dt"], 1)} for row in rows]
            received = sum(row["drx"] for row in rows)
            sent = sum(row["dtx"] for row in rows)
            covered = sum(row["dt"] for row in rows)
        last = connection.execute("SELECT MAX(ts) FROM wan_traffic").fetchone()[0]
        latest = connection.execute(deltas + " ORDER BY ts DESC LIMIT 1", (now - 3600 - max_gap, now - 3600, max_gap)).fetchone()
        current = latest if latest and last is not None and int(latest["ts"]) == int(last) else None
        return {
            "period": period, "start": start, "end": now, "bucket_seconds": bucket or None,
            "last_sample": int(last) if last is not None else None,
            "rx_bps": round(current["drx"] * 8 / current["dt"], 1) if current else None,
            "tx_bps": round(current["dtx"] * 8 / current["dt"], 1) if current else None,
            "points": points,
            "totals": {"rx_bytes": received, "tx_bytes": sent, "coverage": round(min(1, covered / span), 3)},
        }
    finally:
        connection.close()


INTERNET_QUALITY_PAGE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Qualité Internet — Livebox Sentinel</title>
<style>
body { font: 16px system-ui, sans-serif; max-width: 1100px; margin: 2rem auto;
  padding: 0 1rem; color: #17202a; background: #f5f7fa; }
nav { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
a { color: #1769aa; }
.panel, .card { background: white; border-radius: 12px; padding: 1rem 1.25rem;
  box-shadow: 0 3px 14px #17202a0c; }
.controls { display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 1rem; }
select { padding: .55rem; border: 1px solid #cbd5df; border-radius: 7px; }
.cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0; }
.card span { display: block; color: #52616b; font-size: .9rem; }
.card strong { display: block; margin-top: .35rem; font-size: 1.5rem; }
#qualityChart { width: 100%; height: auto; margin-top: 1rem; }
#events { padding-left: 1.2rem; }
.muted { color: #64727d; }
@media(max-width:700px) { .cards { grid-template-columns: 1fr; } body { margin-top: 1rem; } }
</style>
</head>
<body>
<nav>
  <a href="/">Tableau de bord</a>
  <a href="/consumption">Consommation</a>
  <a href="/livebox-health">Santé Livebox</a><a href="/backups">Sauvegardes</a><a href="/settings">Paramètres</a>
</nav>
<h1>Qualité de la connexion Internet</h1>
<section class="panel">
  <div class="controls">
    <div>Mesures réalisées par Livebox Sentinel, environ toutes les 30 secondes.</div>
    <label>Période
      <select id="period">
        <option value="1h">1 heure</option>
        <option value="24h" selected>24 heures</option>
        <option value="7d">7 jours</option>
        <option value="30d">30 jours</option>
        <option value="90d">90 jours</option>
        <option value="1y">1 an</option>
      </select>
    </label>
  </div>
  <div class="cards">
    <div class="card"><span>Disponibilité Internet observée</span><strong id="availability">—</strong></div>
    <div class="card"><span>Latence moyenne des sondes réussies</span><strong id="averageLatency">—</strong></div>
    <div class="card"><span>Latence maximale observée</span><strong id="maximumLatency">—</strong></div>
  </div>
  <svg id="qualityChart" viewBox="0 0 1000 280" role="img"
       aria-label="Historique de la latence Internet"></svg>
  <p id="chartInfo" class="muted">Chargement des mesures…</p>
</section>
<section class="panel" style="margin-top:1rem">
  <h2>Incidents sur la période</h2>
  <ul id="events"><li>Aucun incident enregistré.</li></ul>
</section>
<script>
const ns = "http://www.w3.org/2000/svg";
function drawChart(points) {
  const svg = document.getElementById("qualityChart");
  svg.replaceChildren();
  const valid = points.filter(point => point.latency_ms !== null);
  if (!valid.length) {
    document.getElementById("chartInfo").textContent =
      "Aucune mesure de latence réussie sur cette période.";
    return;
  }

  const left = 82, right = 970, top = 24, bottom = 224;
  const first = Number(points[0].ts);
  const last = Number(points[points.length - 1].ts);
  const span = Math.max(1, last - first);
  const rawMax = Math.max(1, ...valid.map(point => Number(point.latency_ms)));
  const maxLatency = Math.ceil(rawMax / 10) * 10 || 10;

  function add(tag, attrs, label) {
    const el = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs || {})) el.setAttribute(key, value);
    if (label !== undefined) el.textContent = label;
    svg.appendChild(el);
    return el;
  }
  function x(ts) { return left + (Number(ts) - first) / span * (right - left); }
  function y(value) { return bottom - Number(value) / maxLatency * (bottom - top); }

  for (let i = 0; i <= 4; i++) {
    const fraction = i / 4, yy = bottom - fraction * (bottom - top);
    add("line", {x1:left, y1:yy, x2:right, y2:yy, stroke:"#e4eaf0"});
    add("text", {x:left-10, y:yy+5, "text-anchor":"end",
      fill:"#52616b", "font-size":13}, (maxLatency * fraction).toFixed(0) + " ms");
  }
  const path = [];
  for (const point of points) {
    if (point.latency_ms === null) continue;
    path.push((path.length ? "L" : "M") + x(point.ts) + " " + y(point.latency_ms));
  }
  add("path", {d:path.join(" "), fill:"none", stroke:"#2676d2",
    "stroke-width":3, "stroke-linejoin":"round", "stroke-linecap":"round"});
  for (const point of valid) {
    const circle = add("circle", {cx:x(point.ts), cy:y(point.latency_ms), r:3.5,
      fill:"#2676d2", stroke:"white", "stroke-width":1.5});
    circle.appendChild(document.createElementNS(ns, "title")).textContent =
      new Date(point.ts * 1000).toLocaleString("fr-FR") +
      " — " + Number(point.latency_ms).toFixed(1) + " ms";
  }
  add("line", {x1:left, y1:bottom, x2:right, y2:bottom, stroke:"#52616b"});
  for (let i = 0; i <= 4; i++) {
    const fraction = i / 4, xx = left + fraction * (right - left);
    const ts = first + fraction * span;
    add("text", {x:xx, y:bottom+25, "text-anchor":"middle",
      fill:"#52616b", "font-size":12},
      new Date(ts * 1000).toLocaleString("fr-FR",
        {day:"2-digit", month:"2-digit", hour:"2-digit", minute:"2-digit"}));
  }
  document.getElementById("chartInfo").textContent =
    valid.length + " points de latence. Survole un point pour afficher la date et la valeur.";
}
async function refreshQuality() {
  try {
    const period = document.getElementById("period").value;
    const response = await fetch("/api/internet/history?period=" + encodeURIComponent(period));
    if (!response.ok) throw new Error("Historique indisponible");
    const data = await response.json();
    document.getElementById("availability").textContent =
      data.availability_percent === null ? "—" : data.availability_percent + " %";
    document.getElementById("averageLatency").textContent =
      data.average_latency_ms === null ? "—" : data.average_latency_ms + " ms";
    document.getElementById("maximumLatency").textContent =
      data.maximum_latency_ms === null ? "—" : data.maximum_latency_ms + " ms";
    drawChart(data.points || []);

    const list = document.getElementById("events");
    list.replaceChildren();
    if (!(data.events || []).length) {
      const item = document.createElement("li");
      item.textContent = "Aucun incident enregistré sur cette période.";
      list.appendChild(item);
    } else {
      for (const event of data.events) {
        const item = document.createElement("li");
        const start = new Date(event.started_at * 1000).toLocaleString("fr-FR");
        const end = event.ended_at
          ? " — rétabli le " + new Date(event.ended_at * 1000).toLocaleString("fr-FR")
          : " — en cours";
        item.textContent = start + " — " + event.message + end;
        list.appendChild(item);
      }
    }
  } catch (error) {
    document.getElementById("chartInfo").textContent =
      "Impossible de charger les mesures de qualité Internet.";
  }
}
document.getElementById("period").addEventListener("change", refreshQuality);
refreshQuality();
setInterval(refreshQuality, 30000);
</script>
</body>
</html>
"""

@app.get("/internet", response_class=HTMLResponse)
def internet_quality_page(username: str = Depends(require_auth)):
    return INTERNET_QUALITY_PAGE


@app.get("/api/internet/history")
def get_internet_history(
    period: str = "24h",
    username: str = Depends(require_auth),
):
    periods = {
        "1h": 3600,
        "24h": 86400,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
        "90d": 90 * 86400,
        "1y": 365 * 86400,
    }
    if period not in periods:
        raise HTTPException(status_code=400, detail="Période invalide")

    now = int(time.time())
    start = now - periods[period]
    if period in ("1h", "24h"):
        bucket_seconds = 60
    elif period == "7d":
        bucket_seconds = 300
    elif period == "30d":
        bucket_seconds = 900
    elif period == "90d":
        bucket_seconds = 3600
    else:
        bucket_seconds = 86400

    connection = connect_db()
    try:
        rows = connection.execute(
            """
            WITH batches AS (
                SELECT ts,
                       MAX(CASE
                           WHEN target IN ('google', 'cloudflare') AND ok=1 THEN 1
                           ELSE 0
                       END) AS internet_ok,
                       MAX(CASE WHEN target='livebox' THEN ok END) AS router_ok,
                       AVG(CASE
                           WHEN target IN ('google', 'cloudflare') AND ok=1
                           THEN latency_ms
                       END) AS latency_ms
                FROM internet_checks
                WHERE ts >= ?
                GROUP BY ts
            )
            SELECT (ts / ?) * ? AS bucket_ts,
                   COUNT(*) AS check_count,
                   SUM(internet_ok) AS internet_successes,
                   SUM(COALESCE(router_ok, 0)) AS router_successes,
                   SUM(COALESCE(latency_ms, 0)) AS latency_sum,
                   COUNT(latency_ms) AS latency_count,
                   MAX(latency_ms) AS maximum_latency_ms
            FROM batches
            GROUP BY bucket_ts
            ORDER BY bucket_ts
            """,
            (start, bucket_seconds, bucket_seconds),
        ).fetchall()

        events = connection.execute(
            """
            SELECT component, started_at, ended_at, message
            FROM internet_events
            WHERE (started_at >= ? OR ended_at >= ? OR ended_at IS NULL)
              AND started_at <= ?
            ORDER BY started_at DESC
            """,
            (start, start, now),
        ).fetchall()
    finally:
        connection.close()

    total_checks = sum(row["check_count"] for row in rows)
    internet_successes = sum(row["internet_successes"] for row in rows)
    latency_count = sum(row["latency_count"] for row in rows)
    latency_sum = sum(row["latency_sum"] for row in rows)
    maximum_latency = max(
        (row["maximum_latency_ms"] for row in rows
         if row["maximum_latency_ms"] is not None),
        default=None,
    )
    points = [
        {
            "ts": int(row["bucket_ts"]),
            "availability_percent": round(
                row["internet_successes"] * 100 / row["check_count"], 1
            ),
            "latency_ms": round(row["latency_sum"] / row["latency_count"], 1)
                if row["latency_count"] else None,
        }
        for row in rows
    ]
    return {
        "period": period,
        "availability_percent": round(internet_successes * 100 / total_checks, 2)
            if total_checks else None,
        "average_latency_ms": round(latency_sum / latency_count, 1)
            if latency_count else None,
        "maximum_latency_ms": round(maximum_latency, 1)
            if maximum_latency is not None else None,
        "points": points,
        "events": [dict(row) for row in events],
    }


NETWORK_MAP_PAGE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Carte réseau — Livebox Sentinel</title>
<link rel="stylesheet" href="/assets/network-map.css">
<style>
body { font: 16px system-ui, sans-serif; max-width: 1100px; margin: 2rem auto;
  padding: 0 1rem; color: #17202a; background: #f5f7fa; }
nav { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
a { color: #1769aa; }
.router { width: fit-content; margin: 0 auto 2rem; padding: 1rem 1.5rem;
  border-radius: 14px; background: #173d67; color: white; text-align: center; }
.groups { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; }
.group { background: white; border-radius: 12px; padding: 1rem; box-shadow: 0 3px 14px #17202a0c; }
.group h2 { margin-top: 0; font-size: 1.15rem; }
.device { border: 1px solid #e2e8ef; border-radius: 9px; padding: .75rem; margin: .6rem 0; }
.device.inactive { opacity: .65; }
.name { font-weight: 650; }
.meta { display: block; margin-top: .25rem; color: #52616b; font-size: .86rem; overflow-wrap: anywhere; }
.state { float: right; font-size: .8rem; color: #176b36; }
.inactive .state { color: #687782; }
#summary { color: #52616b; margin-bottom: 1rem; }
@media(max-width:600px) { body { margin-top: 1rem; } }
</style>
</head>
<body>
<nav>
  <a href="/">Tableau de bord</a>
  <a href="/consumption">Consommation</a>
  <a href="/internet">Qualité Internet</a>
  <a href="/livebox-health">Santé Livebox</a><a href="/backups">Sauvegardes</a><a href="/settings">Paramètres</a>
</nav>
<section class="topo-head">
  <div><p class="eyebrow">VOTRE RÉSEAU LOCAL</p><h1>Carte réseau</h1>
  <p class="muted topo-lead">La Livebox au centre, vos répéteurs et chacun de vos équipements en orbite, selon leur liaison : Ethernet, Wi-Fi 5 GHz ou 2,4 GHz. Sur ordinateur, survolez un appareil pour suivre son raccordement et cliquez pour tout savoir.</p></div>
  <p id="topoStatus" class="topo-status" role="status">Chargement de la carte…</p>
</section>
<div id="topoFilters" class="topo-filters" role="group" aria-label="Filtrer par raccordement"></div>
<div class="topo-toolbar">
  <label class="topo-search"><span class="sr-only">Rechercher un équipement</span><input id="topoSearch" type="search" placeholder="Rechercher : nom, adresse IP, MAC…" autocomplete="off"></label>
  <label class="check-row topo-offline"><input id="topoHideOffline" type="checkbox"> Masquer les appareils hors ligne</label>
  <button id="topoExpand" type="button" class="quiet-button topo-expand-button">Tout déplier</button>
  <p class="topo-hint">Molette ou pincement pour zoomer · glisser pour se déplacer · Échap pour fermer</p>
</div>
<section id="orbit" class="orbit" aria-label="Carte orbitale du réseau">
  <canvas id="orbitStars" class="orbit-stars" aria-hidden="true"></canvas>
  <svg id="orbitMap" class="orbit-map" role="group" aria-label="Livebox, répéteurs et équipements"></svg>
  <div id="orbitStats" class="orbit-hud orbit-stats orbit-glass" aria-label="Synthèse du réseau"></div>
  <p id="orbitClock" class="orbit-hud orbit-clock" aria-hidden="true"></p>
  <div class="orbit-hud orbit-legend orbit-glass" aria-hidden="true"><span class="o-lg o-eth">Ethernet</span><span class="o-lg is-wifi o-w5">Wi-Fi 5 GHz</span><span class="o-lg is-wifi o-w24">Wi-Fi 2,4 GHz</span><span class="o-lg is-beam" style="--c:#a77dff">Liaison du répéteur</span><span class="o-lg is-dot" style="--c:#3dffa8">En ligne</span><span class="o-lg is-dot" style="--c:#56637a">Hors ligne</span><span class="o-lg is-dot" style="--c:#ffd166">Nouveau</span></div>
  <div class="orbit-hud orbit-controls orbit-glass" role="toolbar" aria-label="Affichage de la carte">
    <button id="orbitZoomIn" class="o-control" type="button" title="Zoomer" aria-label="Zoomer"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M11 8v6M8 11h6M20 20l-4-4"/></svg></button>
    <button id="orbitZoomOut" class="o-control" type="button" title="Dézoomer" aria-label="Dézoomer"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M8 11h6M20 20l-4-4"/></svg></button>
    <button id="orbitFit" class="o-control" type="button" title="Recentrer" aria-label="Recentrer la carte"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/><circle cx="12" cy="12" r="2.5"/></svg></button>
    <button id="orbitMotion" class="o-control" type="button" aria-pressed="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12c3-6 6-6 9 0s6 6 9 0"/><circle cx="7.5" cy="9" r="1"/><circle cx="16.5" cy="15" r="1"/></svg></button>
    <button id="orbitFull" class="o-control" type="button" title="Plein écran" aria-label="Plein écran" aria-pressed="false"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3H3v5M16 3h5v5M8 21H3v-5M16 21h5v-5"/></svg></button>
  </div>
  <div id="orbitTip" class="orbit-tip orbit-glass" hidden></div>
  <aside id="orbitPanel" class="orbit-panel orbit-glass" aria-label="Détails" aria-hidden="true"></aside>
</section>
<div id="topoList" class="topo-list" aria-label="Arborescence du réseau"></div>
<script src="/assets/network-map.js" defer></script>

<section class="journal" id="journal" aria-labelledby="journalTitle">
  <div class="journal-head"><div><p class="eyebrow">HISTORIQUE</p><h2 id="journalTitle">Connexions récentes</h2></div><p id="journalStatus" role="status" class="journal-status">Chargement de l’historique…</p></div>
  <div id="journalSummary" class="journal-summary" aria-label="Synthèse de la période"></div>
  <div class="journal-toolbar">
    <label class="journal-search"><span>Rechercher</span><input id="journalSearch" type="search" placeholder="Équipement, adresse IP ou MAC" autocomplete="off"></label>
    <label><span>Période</span><select id="journalPeriod"><option value="24h">24 heures</option><option value="7d" selected>7 jours</option><option value="30d">30 jours</option><option value="90d">90 jours</option><option value="1y">1 an</option></select></label>
    <label><span>Connexion</span><select id="journalConnection"><option value="">Toutes</option></select></label>
    <label><span>Événement</span><select id="journalType"><option value="">Tous</option><option value="connected">Connexions</option><option value="disconnected">Déconnexions</option></select></label>
    <label><span>Trier</span><select id="journalSort"><option value="recent">Plus récents d’abord</option><option value="oldest">Plus anciens d’abord</option><option value="device">Par équipement</option></select></label>
  </div>
  <div id="journalList" class="journal-list" aria-live="polite"></div>
  <div class="journal-pager" role="navigation" aria-label="Pages de l’historique">
    <label class="journal-size"><span>Afficher</span><select id="journalPageSize"><option value="20">20</option><option value="50">50</option><option value="100">100</option></select><span>par page</span></label>
    <p id="journalRange" class="journal-range"></p>
    <div id="journalPages" class="journal-pages"></div>
  </div>
</section>

</body>
</html>
"""


@app.get("/api/device-events")
def get_device_events(
    username: str = Depends(require_auth), mac: str | None = None, period: str = "1y", limit: int = 100
):
    periods = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "1y": 365 * 86400}
    if period not in periods:
        raise HTTPException(status_code=400, detail="Période invalide")
    if not 1 <= limit <= 2000:
        raise HTTPException(status_code=400, detail="Limite invalide")
    now = int(time.time())
    parameters = [now - periods[period], now]
    mac_filter = ""
    if mac is not None:
        mac_filter = "AND e.mac=?"
        parameters.append(normalized_mac(mac))
    connection = connect_db()
    try:
        rows = connection.execute(
            f"""
            SELECT e.mac, e.ts, e.event_type,
                   COALESCE(NULLIF(p.custom_name, ''), e.name) AS name,
                   e.ip, e.interface_name, e.device_type, d.layer2_interface,
                   COALESCE(p.category, '') AS category
            FROM device_presence_events AS e
            LEFT JOIN device_profiles AS p ON p.mac = e.mac
            LEFT JOIN devices AS d ON d.mac = e.mac
            WHERE e.ts >= ? AND e.ts <= ? {mac_filter}
            ORDER BY e.ts DESC, e.id DESC
            LIMIT ?
            """,
            parameters + [limit + 1],
        ).fetchall()
        events = []
        for row in rows[:limit]:
            event = dict(row)
            # The event keeps its own interface; the device's band is only a fallback.
            event["connection"] = _feature_module.connection_label(event["interface_name"], "" if event["interface_name"] else event.pop("layer2_interface"))
            event.pop("layer2_interface", None)
            events.append(event)
        return {"events": events, "truncated": len(rows) > limit,
                "period": period, "start": now - periods[period], "end": now}
    finally:
        connection.close()


@app.get("/network", response_class=HTMLResponse)
def network_map_page(username: str = Depends(require_auth)):
    return NETWORK_MAP_PAGE


@app.get("/api/network/topology")
def get_network_topology(username: str = Depends(require_auth)):
    """The last tree read from the Livebox: ports, Wi-Fi radios, repeaters and devices."""
    saved = features.document("topology", "primary")
    if not saved.get("root"):
        return {"available": False, "ts": None, "root": None}
    return {"available": True, "ts": saved.get("ts"), "root": saved["root"]}


@app.get("/api/livebox-health")
def get_livebox_health(username: str = Depends(require_auth)):
    connection = connect_db()
    try:
        row = connection.execute(
            """
            SELECT ts, manufacturer, model_name, hardware_version,
                   software_version, modem_firmware_version, device_status,
                   uptime, reboot_count, wifi_status, wifi_target_status,
                   wifi_current_state, wifi_vaps_enabled, wifi_wps_enabled,
                   wifi_scheduling_enabled
            FROM livebox_health
            ORDER BY ts DESC
            LIMIT 1
            """
        ).fetchone()
        history = connection.execute(
            """
            SELECT COUNT(*) AS samples, MIN(ts) AS first_ts, MAX(ts) AS last_ts
            FROM livebox_health
            """
        ).fetchone()
        return {
            "latest": dict(row) if row else None,
            "history": dict(history),
        }
    finally:
        connection.close()


@app.get("/api/internet")
def get_internet_status(username: str = Depends(require_auth)):
    connection = connect_db()
    try:
        latest = connection.execute(
            "SELECT MAX(ts) AS ts FROM internet_checks"
        ).fetchone()["ts"]
        if latest is None:
            return {
                "last_check": None,
                "router_ok": None,
                "internet_ok": None,
                "latency_ms": None,
                "checks": [],
            }

        rows = connection.execute(
            """
            SELECT target, ok, latency_ms, status_code, error
            FROM internet_checks WHERE ts=? ORDER BY target
            """,
            (latest,),
        ).fetchall()
        checks = [dict(row) for row in rows]
        router = next((item for item in checks if item["target"] == "livebox"), None)
        external = [item for item in checks if item["target"] != "livebox"]
        successful = [
            item["latency_ms"] for item in external
            if item["ok"] and item["latency_ms"] is not None
        ]
        active_alerts = connection.execute(
            """
            SELECT component, started_at, message
            FROM internet_events WHERE ended_at IS NULL
            ORDER BY started_at DESC
            """
        ).fetchall()
        events = connection.execute(
            """
            SELECT component, started_at, ended_at, message
            FROM internet_events ORDER BY started_at DESC LIMIT 10
            """
        ).fetchall()
        return {
            "last_check": latest,
            "router_ok": bool(router["ok"]) if router else None,
            "internet_ok": any(item["ok"] for item in external) if external else None,
            "latency_ms": round(sum(successful) / len(successful), 1)
                if successful else None,
            "checks": checks,
            "active_alerts": [dict(row) for row in active_alerts],
            "events": [dict(row) for row in events],
        }
    finally:
        connection.close()



@app.get("/about", response_class=HTMLResponse)
def about_page(username: str = Depends(require_auth)):
    return ABOUT_PAGE


@app.get("/api/about")
def get_about(username: str = Depends(require_auth)):
    # File metadata only: no scan, checkpoint, maintenance or secret exposure.
    def file_size(path):
        try:
            return Path(path).stat().st_size
        except FileNotFoundError:
            return 0

    database_bytes = file_size(DATABASE_PATH)
    journal_bytes = file_size(DATABASE_PATH + "-wal") + file_size(DATABASE_PATH + "-journal")
    shared_memory_bytes = file_size(DATABASE_PATH + "-shm")
    with state_lock:
        collection = {key: state[key] for key in ("last_collection", "devices", "samples")}
        collection["has_error"] = bool(state["last_error"])
    return {
        "version": APP_VERSION, "release_date": APP_RELEASE_DATE,
        "uptime_seconds": max(0, int(time.time() - STARTED_AT)),
        "database_bytes": database_bytes, "journal_bytes": journal_bytes,
        "shared_memory_bytes": shared_memory_bytes,
        "storage_bytes": database_bytes + journal_bytes + shared_memory_bytes,
        "collection_interval_seconds": COLLECT_INTERVAL, "collection": collection,
        "livebox_monitor_version": "1.7",
    }


@app.get("/settings", response_class=HTMLResponse)
def settings_page(username: str = Depends(require_auth)):
    return SETTINGS_PAGE


@app.get("/api/settings")
def get_settings(username: str = Depends(require_auth)):
    saved = read_app_settings()
    return {
        "smtp_host": saved.get("smtp_host", ""),
        "smtp_port": saved.get("smtp_port", "587"),
        "smtp_security": saved.get("smtp_security", "starttls"),
        "smtp_username": saved.get("smtp_username", ""),
        "smtp_from": saved.get("smtp_from", ""),
        "alert_email_to": saved.get("alert_email_to", ""),
        "smtp_password_set": bool(saved.get("smtp_password", "")),
        "alert_confirmation_checks": saved.get("alert_confirmation_checks", "2"),
        "email_alert_router": saved.get("email_alert_router", "1") != "0",
        "email_alert_internet": saved.get("email_alert_internet", "1") != "0",
        "email_alert_new_device": saved.get("email_alert_new_device", "1") != "0",
    }


SMTP_PORTS = {25, 465, 587, 2525}


@app.post("/api/settings")
def save_settings(payload: dict, username: str = Depends(require_auth)):
    try:
        port = int(payload.get("smtp_port", 587))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Port SMTP invalide")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="Port SMTP invalide")

    try:
        alert_checks = int(payload.get("alert_confirmation_checks", 2))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Nombre de contrôles invalide")
    if not 2 <= alert_checks <= 20:
        raise HTTPException(
            status_code=400,
            detail="Le nombre de contrôles doit être compris entre 2 et 20",
        )

    security_mode = str(payload.get("smtp_security", "starttls"))
    if security_mode not in ("starttls", "ssl"):
        raise HTTPException(status_code=400, detail="Mode de sécurité invalide")
    if port not in SMTP_PORTS:
        raise HTTPException(status_code=400, detail="Port SMTP non pris en charge : utilisez 25, 465, 587 ou 2525")

    values = {
        "smtp_host": str(payload.get("smtp_host") or "").strip(),
        "smtp_port": str(port),
        "smtp_security": security_mode,
        "smtp_username": str(payload.get("smtp_username") or "").strip(),
        "smtp_from": str(payload.get("smtp_from") or "").strip(),
        "alert_email_to": str(payload.get("alert_email_to") or "").strip(),
        "alert_confirmation_checks": str(alert_checks),
        "email_alert_router": "0" if payload.get("email_alert_router") is False else "1",
        "email_alert_internet": "0" if payload.get("email_alert_internet") is False else "1",
        "email_alert_new_device": "0" if payload.get("email_alert_new_device") is False else "1",
    }
    password = str(payload.get("smtp_password") or "")
    saved = load_smtp_settings()
    if password:
        values["smtp_password"] = settings_cipher().encrypt(
            password.encode()
        ).decode()
    elif payload.get("clear_password"):
        values["smtp_password"] = ""
    elif saved["smtp_password"] and not same_smtp_account(saved, values):
        # Never hand the saved password to another server or account without retyping it.
        raise HTTPException(status_code=400, detail="Le serveur ou l’identifiant SMTP a changé : saisissez à nouveau le mot de passe SMTP.")

    connection = connect_db()
    try:
        with connection:
            for name, value in values.items():
                connection.execute(
                    """
                    INSERT INTO app_settings(name, value) VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET value=excluded.value
                    """,
                    (name, value),
                )
    finally:
        connection.close()
    return {"ok": True}


@app.post("/api/settings/test-email")
def test_settings_email(payload: dict, username: str = Depends(require_auth)):
    saved = load_smtp_settings()
    config = {
        "smtp_host": str(payload.get("smtp_host") or "").strip(),
        "smtp_port": payload.get("smtp_port", saved["smtp_port"]),
        "smtp_security": payload.get("smtp_security", saved["smtp_security"]),
        "smtp_username": str(payload.get("smtp_username") or "").strip(),
        "smtp_password": str(payload.get("smtp_password") or ""),
        "smtp_from": str(payload.get("smtp_from") or "").strip(),
        "alert_email_to": str(payload.get("alert_email_to") or "").strip(),
    }
    try:
        port = int(config["smtp_port"])
    except (TypeError, ValueError):
        port = 0
    if port not in SMTP_PORTS:
        raise HTTPException(status_code=400, detail="Port SMTP non pris en charge : utilisez 25, 465, 587 ou 2525")
    if not config["smtp_password"] and same_smtp_account(saved, config):
        config["smtp_password"] = saved["smtp_password"]
    try:
        send_smtp_message(
            config,
            "[Livebox Sentinel] Test de configuration SMTP",
            "Ce message confirme que l'envoi SMTP de Livebox Sentinel fonctionne.",
        )
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=400, detail="Le serveur SMTP a refusé l’identifiant ou le mot de passe.")
    except Exception:
        # One message for every network failure: the test must not reveal which ports answer.
        raise HTTPException(status_code=400, detail="Échec du test SMTP. Vérifiez le serveur, le port, la sécurité et les identifiants.")
    return {"ok": True, "message": "E-mail de test envoyé."}


def same_smtp_account(saved, candidate):
    return (str(saved.get("smtp_host", "")).strip().lower() == str(candidate.get("smtp_host", "")).strip().lower()
            and str(saved.get("smtp_username", "")).strip() == str(candidate.get("smtp_username", "")).strip())


@app.get("/api/history")
def get_history(
    mac: str,
    period: str = "24h",
    username: str = Depends(require_auth),
):
    from fastapi import HTTPException

    periods = {
        "1h": 3600,
        "24h": 86400,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
        "90d": 90 * 86400,
        "1y": 365 * 86400,
    }
    if period not in periods:
        raise HTTPException(status_code=400, detail="Période invalide")

    now = int(time.time())
    start = now - periods[period]
    connection = connect_db()
    try:
        if periods[period] <= features.retention("raw_days", 30) * 86400:
            rows = connection.execute(
                """
                SELECT ts, rx, tx FROM traffic
                WHERE mac=? AND ts >= ?
                ORDER BY ts
                """,
                (mac, start - 60),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT ts, rx, tx FROM traffic_15m
                WHERE mac=? AND ts >= ?
                ORDER BY ts
                """,
                (mac, start - 900),
            ).fetchall()
    finally:
        connection.close()

    points = []
    previous = None
    for row in rows:
        current = {
            "ts": int(row["ts"]),
            "rx": int(row["rx"]),
            "tx": int(row["tx"]),
        }
        if previous is not None:
            elapsed = current["ts"] - previous["ts"]
            rx_delta = current["rx"] - previous["rx"]
            tx_delta = current["tx"] - previous["tx"]
            if elapsed > 0 and rx_delta >= 0 and tx_delta >= 0 and current["ts"] >= start:
                points.append({
                    "ts": current["ts"],
                    "rx_bps": round(rx_delta * 8 / elapsed, 1),
                    "tx_bps": round(tx_delta * 8 / elapsed, 1),
                })
        previous = current

    if len(points) > 1200:
        step = (len(points) + 1199) // 1200
        reduced = []
        for offset in range(0, len(points), step):
            block = points[offset:offset + step]
            reduced.append({
                "ts": block[-1]["ts"],
                "rx_bps": round(sum(point["rx_bps"] for point in block) / len(block), 1),
                "tx_bps": round(sum(point["tx_bps"] for point in block) / len(block), 1),
            })
        points = reduced

    return {"mac": mac, "period": period, "points": points}


def aggregate_consumption(devices, group_by):
    if group_by not in ("location", "category"):
        raise ValueError("Regroupement invalide")
    groups = {}
    for device in devices:
        key = device.get(group_by) or ""
        if key not in groups:
            groups[key] = {"key": key, "name": key or ("Sans pièce" if group_by == "location" else "Sans catégorie"),
                           "device_count": 0, "rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
        group = groups[key]
        group["device_count"] += 1
        for field in ("rx_bytes", "tx_bytes", "total_bytes"):
            group[field] += device[field]
    return sorted(groups.values(), key=lambda item: (-item["total_bytes"], item["name"]))


@app.get("/api/consumption")
def get_consumption(period: str = "24h", username: str = Depends(require_auth), group_by: str = "device"):
    from fastapi import HTTPException

    periods = {
        "1h": 3600,
        "24h": 86400,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
        "90d": 90 * 86400,
        "1y": 365 * 86400,
    }
    if period not in periods:
        raise HTTPException(status_code=400, detail="Période invalide")
    if group_by not in ("device", "location", "category"):
        raise HTTPException(status_code=400, detail="Regroupement invalide")

    now = int(time.time())
    start = now - periods[period]
    table = "traffic" if periods[period] <= features.retention("raw_days", 30) * 86400 else "traffic_15m"
    boundary_limit = 120 if table == 'traffic' else 1800
    connection = connect_db()
    try:
        devices = connection.execute(
            """SELECT d.mac, COALESCE(NULLIF(p.custom_name, ''), d.name) AS name, d.ip, d.active,
                      COALESCE(p.category, '') AS category, COALESCE(p.location, '') AS location
               FROM devices AS d LEFT JOIN device_profiles AS p ON p.mac=d.mac
               ORDER BY name COLLATE NOCASE"""
        ).fetchall()
        earliest = connection.execute(f'SELECT MIN(ts) AS ts FROM {table}').fetchone()
        result = []
        for device in devices:
            mac = device["mac"]
            previous = connection.execute(
                f"SELECT ts, rx, tx FROM {table} WHERE mac=? AND ts < ? ORDER BY ts DESC LIMIT 1",
                (mac, start),
            ).fetchone()
            samples = connection.execute(
                f"SELECT ts, rx, tx FROM {table} WHERE mac=? AND ts >= ? ORDER BY ts",
                (mac, start),
            ).fetchall()
            sequence = ([previous] if previous else []) + samples
            rx_bytes = 0
            tx_bytes = 0
            previous_sample = None
            for sample in sequence:
                if previous_sample is not None:
                    previous_ts = int(previous_sample["ts"])
                    current_ts = int(sample["ts"])
                    elapsed = current_ts - previous_ts
                    if current_ts >= start and elapsed > 0:
                        if previous_ts >= start or elapsed <= boundary_limit:
                            rx_delta = int(sample["rx"]) - int(previous_sample["rx"])
                            tx_delta = int(sample["tx"]) - int(previous_sample["tx"])
                            if rx_delta >= 0:
                                rx_bytes += rx_delta
                            if tx_delta >= 0:
                                tx_bytes += tx_delta
                previous_sample = sample
            result.append({
                "mac": mac,
                "name": device["name"] or "Inconnu",
                "ip": device["ip"] or "",
                "active": bool(device["active"]),
                "category": device["category"],
                "location": device["location"],
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "total_bytes": rx_bytes + tx_bytes,
            })
        return {
            "period": period,
            "start": start,
            "end": now,
            "data_since": int(earliest["ts"]) if earliest["ts"] is not None else None,
            "devices": result,
            "group_by": group_by,
            "groups": aggregate_consumption(result, group_by) if group_by != "device" else [],
            "totals": {
                "rx_bytes": sum(item["rx_bytes"] for item in result),
                "tx_bytes": sum(item["tx_bytes"] for item in result),
                "total_bytes": sum(item["total_bytes"] for item in result),
            },
        }
    finally:
        connection.close()


@app.get("/api/consumption.csv")
def export_consumption_csv(
    period: str = "24h",
    username: str = Depends(require_auth),
    group_by: str = "device",
):
    data = get_consumption(period, username, group_by)
    devices = sorted(
        data["devices"] if group_by == "device" else data["groups"],
        key=lambda device: device["total_bytes"],
        reverse=True,
    )

    def safe_cell(value):
        text = "" if value is None else str(value)
        if text.startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + text
        return text

    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=";", lineterminator="\r\n")
    writer.writerow([
        "Rang", "Appareil", "Adresse IP", "Adresse MAC", "État",
        "Réception (octets)", "Émission (octets)", "Total (octets)",
    ] if group_by == "device" else [
        "Rang", "Pièce" if group_by == "location" else "Catégorie", "Nombre d’appareils",
        "Réception (octets)", "Émission (octets)", "Total (octets)",
    ])
    for rank, device in enumerate(devices, start=1):
        if group_by != "device":
            writer.writerow([rank, safe_cell(device["name"]), device["device_count"],
                             device["rx_bytes"], device["tx_bytes"], device["total_bytes"]])
            continue
        writer.writerow([
            rank,
            safe_cell(device["name"]),
            safe_cell(device["ip"]),
            safe_cell(device["mac"]),
            "Actif" if device["active"] else "Inactif",
            device["rx_bytes"],
            device["tx_bytes"],
            device["total_bytes"],
        ])

    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="livebox-sentinel-consommation-{data["period"]}-{group_by}.csv"'
        },
    )


CONSUMPTION_PAGE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Consommation — Livebox Sentinel</title>
<style>
body { font: 16px system-ui, sans-serif; margin: 2rem auto; padding: 0 1rem; max-width: 1100px; color: #17202a; background: #f5f7fa; }
h1 { margin-bottom: .3rem; }
a { color: #1769aa; }
nav { display: flex; gap: 1rem; margin: 0 0 1.5rem; }
.panel { padding: 1rem; background: white; border-radius: 10px; box-shadow: 0 4px 18px #17202a12; }
.controls { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem; }
.controls label { display: flex; align-items: center; gap: .5rem; }
select { padding: .45rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .8rem; margin: 1rem 0; }
.summary div { padding: .9rem; border-radius: 8px; background: #f3f6fa; }
.summary span, .summary strong { display: block; }
.summary span, .note { color: #52616b; font-size: .9rem; }
.summary strong { margin-top: .3rem; font-size: 1.2rem; }
.note { margin: .8rem 0 1rem; }
.table-wrap { overflow-x: auto; }
table { width: 100%; min-width: 650px; border-collapse: collapse; background: white; }
th, td { text-align: left; padding: .7rem; border-bottom: 1px solid #e4e8ec; }
th { background: #eaf0f5; }
</style>
</head>
<body>
<nav><a href="/">Tableau de bord</a><a href="/livebox-health">Santé Livebox</a><a href="/backups">Sauvegardes</a><a href="/settings">Paramètres</a></nav>
<div class="consumption-page-heading"><div><p class="eyebrow">COMPRENDRE VOS USAGES</p><h1>Analyse des consommations</h1></div><button id="refreshConsumption" type="button">↻ Actualiser</button></div>
<section class="panel">
  <h2 id="consumptionHeading">Consommation par appareil</h2>
  <div class="controls">
    <label>Période
      <select id="consumptionPeriod">
        <option value="1h">1 heure</option>
        <option value="24h" selected>24 heures</option>
        <option value="7d">7 jours</option>
        <option value="30d">30 jours</option>
        <option value="90d">90 jours</option>
        <option value="1y">1 an</option>
      </select>
    </label>
    <label>Regrouper par<select id="consumptionGroup"><option value="device">Appareil</option><option value="location">Pièce</option><option value="category">Catégorie</option></select></label>
    <label>Classement
      <select id="consumptionSort">
        <option value="total_bytes">Volume total</option>
        <option value="rx_bytes">Réception</option>
        <option value="tx_bytes">Émission</option>
      </select>
    </label>
  </div>
  <div class="summary">
    <div><span>Reçu par les appareils</span><strong id="consumptionRx">—</strong></div>
    <div><span>Envoyé par les appareils</span><strong id="consumptionTx">—</strong></div>
    <div><span>Total mesuré</span><strong id="consumptionTotal">—</strong></div>
  </div>
  <p class="note">Volumes estimés à partir des compteurs Livebox. Leur somme peut différer du trafic WAN ; les compteurs réinitialisés et les intervalles incomplets sont écartés.</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Rang</th><th id="consumptionNameHeader">Appareil</th><th id="consumptionMetaHeader">Adresse IP</th><th>Réception</th><th>Émission</th><th>Total</th></tr></thead>
      <tbody id="consumptionRows"></tbody>
    </table>
  </div>
  <p class="note">Les regroupements utilisent les pièces et catégories des profils actuels. Les appareils non classés restent visibles dans « Sans pièce » ou « Sans catégorie ».</p><div class="consumption-tools"><button id="consumptionCsvExport" type="button">Exporter cette vue en CSV</button></div>
  <div id="consumptionInfo" role="status">Chargement des consommations…</div>
</section>
<script>
function addCell(row, value) {
  const cell = document.createElement("td"); cell.textContent = value; row.appendChild(cell); return cell;
}
function formatDataSize(value) {
  let size = Number(value) || 0;
  const units = ["B", "kB", "MB", "GB", "TB"];
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {size /= 1000; unit++;}
  return (unit === 0 ? size.toFixed(0) : size.toFixed(2)) + " " + units[unit];
}
let consumptionData = null;
let consumptionController = null;
function renderConsumption() {
  if (!consumptionData) return;
  const group = consumptionData.group_by || "device";
  const grouped = group !== "device";
  const key = document.getElementById("consumptionSort").value;
  const rows = [...(grouped ? consumptionData.groups || [] : consumptionData.devices || [])]
    .sort((a, b) => (Number(b[key]) || 0) - (Number(a[key]) || 0) || String(a.name).localeCompare(String(b.name), "fr"));
  document.getElementById("consumptionNameHeader").textContent = group === "location" ? "Pièce" : group === "category" ? "Catégorie" : "Appareil";
  document.getElementById("consumptionMetaHeader").textContent = grouped ? "Appareils" : "Adresse IP";
  document.getElementById("consumptionHeading").textContent = "Consommation par " + (group === "location" ? "pièce" : group === "category" ? "catégorie" : "appareil");
  const body = document.getElementById("consumptionRows");
  body.replaceChildren();
  const total = Number(consumptionData.totals?.total_bytes) || 0;
  rows.forEach((item, index) => {
    const row = document.createElement("tr");
    addCell(row, index + 1);
    const name = addCell(row, item.name || "Inconnu");
    if (group === "category" || (!grouped && item.category)) {
      const symbol = categorySymbol(group === "category" ? item.name : item.category);
      symbol.classList.add("consumption-category-symbol");
      name.prepend(symbol);
    }
    const share = total > 0 ? Math.max(0, Math.min(100, (Number(item.total_bytes) || 0) / total * 100)) : 0;
    const meter = document.createElement("div");
    meter.className = "consumption-share";
    meter.title = share.toLocaleString("fr-FR", {maximumFractionDigits: 1}) + " % du volume total mesuré";
    meter.setAttribute("aria-label", meter.title);
    const fill = document.createElement("span"); fill.style.width = share + "%"; meter.appendChild(fill); name.appendChild(meter);
    if (!grouped && (item.category || item.location)) {
      const meta = document.createElement("small"); meta.textContent = [item.category, item.location].filter(Boolean).join(" · "); name.appendChild(meta);
    }
    addCell(row, grouped ? item.device_count : item.ip || "—");
    addCell(row, formatDataSize(item.rx_bytes)); addCell(row, formatDataSize(item.tx_bytes)); addCell(row, formatDataSize(item.total_bytes));
    body.appendChild(row);
  });
  if (!rows.length) {const row = document.createElement("tr"); const cell = addCell(row, "Aucune consommation disponible pour cette période."); cell.colSpan = 6; body.appendChild(row);}
}
async function refreshConsumption() {
  if (consumptionController) consumptionController.abort();
  const controller = new AbortController(); consumptionController = controller;
  const period = document.getElementById("consumptionPeriod").value;
  const group_by = document.getElementById("consumptionGroup").value;
  document.getElementById("consumptionInfo").textContent = "Chargement des consommations…";
  document.getElementById("consumptionCsvExport").disabled = true;
  try {
    const response = await fetch("/api/consumption?" + new URLSearchParams({period, group_by}), {signal: controller.signal});
    if (!response.ok) throw new Error("Consommation indisponible");
    const data = await response.json();
    if (controller.signal.aborted) return;
    consumptionData = data;
    const totals = data.totals || {};
    document.getElementById("consumptionRx").textContent = formatDataSize(totals.rx_bytes);
    document.getElementById("consumptionTx").textContent = formatDataSize(totals.tx_bytes);
    document.getElementById("consumptionTotal").textContent = formatDataSize(totals.total_bytes);
    renderConsumption();
    const since = data.data_since ? new Date(data.data_since * 1000).toLocaleDateString("fr-FR") : null;
    document.getElementById("consumptionInfo").textContent = since
      ? "Premières mesures conservées depuis le " + since + " · les barres indiquent la part du volume mesuré."
      : "Aucune mesure disponible pour le moment.";
    document.getElementById("consumptionCsvExport").disabled = false;
  } catch (error) {
    if (controller.signal.aborted) return;
    document.getElementById("consumptionInfo").textContent = consumptionData
      ? "Actualisation indisponible · les résultats précédents restent affichés."
      : "Impossible de charger les consommations. Réessayez avec Actualiser.";
  }
}
document.getElementById("consumptionPeriod").addEventListener("change", refreshConsumption);
document.getElementById("consumptionGroup").addEventListener("change", refreshConsumption);
document.getElementById("consumptionSort").addEventListener("change", renderConsumption);
document.getElementById("refreshConsumption").addEventListener("click", refreshConsumption);
document.getElementById("consumptionCsvExport").addEventListener("click", () => {
  if (!consumptionData) return;
  const period = document.getElementById("consumptionPeriod").value;
  const group_by = document.getElementById("consumptionGroup").value;
  window.location.href = "/api/consumption.csv?" + new URLSearchParams({period, group_by});
});
refreshConsumption();
setInterval(refreshConsumption, 30000);
</script>
</body>
</html>
"""

@app.get("/consumption", response_class=HTMLResponse)
def consumption_page(username: str = Depends(require_auth)):
    return CONSUMPTION_PAGE


@app.get("/", response_class=HTMLResponse)
def home(username: str = Depends(require_auth)):
    return HTML_PAGE


HTML_PAGE = r"""
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Livebox Sentinel</title>
<style>
body { font: 16px system-ui, sans-serif; margin: 2rem auto; padding: 0 1rem;
       max-width: 1100px; color: #17202a; background: #f5f7fa; }
h1 { margin-bottom: .2rem; }
#status { color: #52616b; margin-bottom: 1.5rem; }
table { width: 100%; border-collapse: collapse; background: white; }
th, td { text-align: left; padding: .7rem; border-bottom: 1px solid #e4e8ec; }
th { background: #eaf0f5; }
small { color: #64727d; }
@media (max-width: 700px) {
  body { margin-top: 1rem; }
  th, td { padding: .45rem; font-size: .85rem; }
  .mac { display: none; }
}

.new-device-row { background: #fff8df; }
.new-device-badge { display: inline-block; margin-left: .45rem; padding: .15rem .4rem; border-radius: 999px; color: #805500; background: #ffe29a; font-size: .72rem; font-weight: 700; }
.history { margin-top: 2rem; padding: 1rem; background: white; border-radius: 8px; }
.history-controls { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem; }
.history-controls label { display: flex; align-items: center; gap: .5rem; }
.history-controls select { padding: .45rem; }
.measurement-note { color: #52616b; font-size: .9rem; margin: .4rem 0 1rem; }
.history-selected { color: #17202a; font-weight: 600; margin: .5rem 0; }
#devices tr { cursor: pointer; }
.device-selected-row { background: #e8f2ff; }
.history-expansion-row > td { padding: .5rem; background: #f5f7fa; }
.history-expansion-row .history { margin-top: 0; }
.consumption-panel { margin-top: 1.5rem; padding: 1rem; background: white; border-radius: 8px; }
.consumption-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .8rem; margin: 1rem 0; }
.consumption-summary div { padding: .9rem; border-radius: 8px; background: #f3f6fa; }
.consumption-summary span, .consumption-summary strong { display: block; }
.consumption-summary span { color: #52616b; font-size: .9rem; }
.consumption-summary strong { margin-top: .3rem; font-size: 1.2rem; }
.consumption-table-wrap { overflow-x: auto; }
.consumption-table { min-width: 650px; }
#historyChart { width: 100%; height: auto; background: #fbfcfe; border: 1px solid #e4e8ec; }
.legend { display: flex; gap: 1rem; margin: .5rem 0; color: #52616b; }
.legend span:first-child { color: #1677ff; }
.legend span:last-child { color: #e67e22; }
.wan-panel { margin: 1rem 0 1.5rem; padding: 1rem; background: white; border-radius: 8px; }
.wan-rates { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; margin: .8rem 0; }
.wan-card { padding: .8rem; background: #f5f7fa; border-radius: 6px; }
.wan-card strong { display: block; color: #52616b; font-size: .9rem; }
.wan-card span { display: block; margin-top: .25rem; font-size: 1.35rem; font-weight: 700; }
#wanChart { width: 100%; height: auto; background: #fbfcfe; border: 1px solid #e4e8ec; }
@media (max-width: 700px) { .wan-card span { font-size: 1.05rem; } }
.wan-panel {
  margin: 1rem 0 1.5rem; padding: 1.25rem;
  background: linear-gradient(145deg, #ffffff, #f6f9fd);
  border: 1px solid #e5ebf2; border-radius: 16px;
  box-shadow: 0 10px 30px rgba(28, 48, 72, .07);
}
.wan-heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.wan-heading h2 { margin: 0; font-size: 1.25rem; }
.wan-heading p { margin: .35rem 0 0; color: #697887; font-size: .9rem; }
.wan-live-badge {
  display: inline-flex; align-items: center; gap: .45rem; white-space: nowrap;
  padding: .4rem .65rem; border-radius: 999px; color: #176b46;
  background: #e8f7ef; font-size: .75rem; font-weight: 700;
}
.wan-live-dot { width: .5rem; height: .5rem; border-radius: 50%; background: #25a768; }
.wan-rates { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .85rem; margin: 1rem 0; }
.wan-card { padding: .9rem 1rem; background: white; border: 1px solid #e8edf3; border-radius: 12px; }
.wan-card strong { display: block; color: #697887; font-size: .82rem; font-weight: 600; }
.wan-card span { display: block; margin-top: .3rem; color: #17202a; font-size: 1.45rem; font-weight: 750; font-variant-numeric: tabular-nums; }
.wan-download { border-left: 4px solid #1677ff; }
.wan-upload { border-left: 4px solid #e67e22; }
.wan-chart-wrap { position: relative; overflow: hidden; border: 1px solid #e8edf3; border-radius: 12px; background: #fff; }
#wanChart { display: block; width: 100%; height: auto; }
.wan-tooltip {
  display: none; position: absolute; z-index: 2; min-width: 190px;
  padding: .7rem .8rem; color: white; background: rgba(21, 34, 50, .96);
  border: 1px solid rgba(255,255,255,.15); border-radius: 10px;
  box-shadow: 0 8px 24px rgba(0,0,0,.2); pointer-events: none;
  font-size: .82rem; line-height: 1.55;
}
.wan-tooltip-time { margin-bottom: .25rem; color: #dce8f5; font-weight: 700; }
.wan-info { margin-top: .65rem; color: #697887; font-size: .82rem; }
.delete-device-button {
  padding: .4rem .65rem; color: #a52a2a; background: #fff;
  border: 1px solid #edcaca; border-radius: 7px; cursor: pointer;
}
.delete-device-button:hover { background: #fff0f0; }
.delete-device-button:disabled { opacity: .55; cursor: wait; }
@media (max-width: 700px) {
  .wan-panel { padding: .8rem; }
  .wan-card span { font-size: 1.1rem; }
  .wan-live-badge { font-size: .68rem; }
}
#internetStatus {
  display: inline-block; margin: .6rem 0 1rem; padding: .55rem .8rem;
  border-radius: 6px; font-weight: 600;
}
#internetStatus[data-state="ok"] { color: #176b36; background: #e4f5e9; }
#internetStatus[data-state="down"] { color: #9b1c1c; background: #fde8e8; }
#internetStatus[data-state="pending"] { color: #52616b; background: #eaf0f5; }
</style>
</head>
<body>
<div class="dashboard-heading">
  <div><p class="eyebrow">VOTRE RÉSEAU LOCAL</p><h1>Vue d’ensemble</h1>
    <p class="dashboard-subtitle">Chaque équipement, à sa place. Toute l’activité, en un regard.</p></div>
  <button id="refreshDevices" type="button"><span aria-hidden="true">↻</span> Actualiser</button>
</div>
<div class="network-health">
  <div id="internetStatus" data-state="pending" role="status">Contrôle de la connexion Internet…</div>
  <a href="/internet">Qualité de la connexion <span aria-hidden="true">↗</span></a>
</div>
<div class="network-overview" aria-label="Vue d’ensemble des équipements">
  <button class="overview-card" type="button" data-device-filter="all" aria-pressed="true">
    <span class="overview-label">Équipements connus</span><strong id="totalDevices">—</strong><span class="overview-foot">L’ensemble de votre parc <span aria-hidden="true">↗</span></span>
  </button>
  <button class="overview-card" type="button" data-device-filter="online" aria-pressed="false">
    <span class="overview-label"><i class="status-dot online" aria-hidden="true"></i> En ligne</span><strong id="onlineDevices">—</strong><span class="overview-foot">Connectés à la Livebox <span aria-hidden="true">↗</span></span>
  </button>
  <button class="overview-card" type="button" data-device-filter="offline" aria-pressed="false">
    <span class="overview-label"><i class="status-dot" aria-hidden="true"></i> Hors ligne</span><strong id="offlineDevices">—</strong><span class="overview-foot">Toujours dans l’inventaire <span aria-hidden="true">↗</span></span>
  </button>
  <button class="overview-card" type="button" data-device-filter="new" aria-pressed="false">
    <span class="overview-label"><i class="status-dot recent" aria-hidden="true"></i> Nouveaux</span><strong id="newDevices">—</strong><span class="overview-foot">Détectés depuis moins de 7 jours <span aria-hidden="true">↗</span></span>
  </button>
</div>
<section id="deviceAlertBanner" class="device-alert-banner" aria-labelledby="deviceAlertTitle" hidden>
  <div><p class="eyebrow">ÉQUIPEMENTS À VÉRIFIER</p><h2 id="deviceAlertTitle">Une absence prolongée a été détectée</h2><p>La Livebox signale ces équipements hors ligne au-delà du délai choisi.</p></div><div id="deviceAlertList"></div>
</section>
<section class="equipment-panel" aria-labelledby="equipmentTitle">
  <div class="equipment-heading">
    <div><p class="eyebrow">INVENTAIRE</p><h2 id="equipmentTitle">Vos équipements <span id="equipmentCount" class="count-pill">—</span></h2></div>
    <div class="view-switch" aria-label="Présentation de l’inventaire">
      <button type="button" data-device-view="list" aria-pressed="true" aria-label="Afficher en liste">☰ <span>Liste</span></button>
      <button type="button" data-device-view="grid" aria-pressed="false" aria-label="Afficher en cartes">▦ <span>Cartes</span></button>
    </div>
  </div>
  <div class="equipment-tools">
    <label class="device-search"><span class="sr-only">Rechercher un équipement</span>
      <span aria-hidden="true">⌕</span><input id="deviceSearch" type="search" placeholder="Nom, adresse IP, MAC, pièce…" autocomplete="off"></label>
    <label><span class="sr-only">Filtrer par liaison</span><select id="deviceConnection"><option value="all">Toutes les liaisons</option><option value="wifi">Wi-Fi</option><option value="ethernet">Ethernet</option><option value="unknown">Liaison inconnue</option></select></label>
    <label><span class="sr-only">Filtrer par catégorie</span><select id="deviceCategory"><option value="">Toutes les catégories</option></select></label>
    <label><span class="sr-only">Filtrer par pièce</span><select id="deviceLocation"><option value="">Toutes les pièces</option></select></label>
    <label><span class="sr-only">Trier les équipements</span><select id="deviceSort"><option value="active">En ligne en premier</option><option value="traffic">Débit décroissant</option><option value="name">Nom : A → Z</option><option value="ip">Adresse IP</option></select></label>
  </div>
  <div class="equipment-filter-line">
    <div class="device-tabs" aria-label="Filtrer les équipements par état">
      <button type="button" data-device-filter="all" aria-pressed="true">Tous</button>
      <button type="button" data-device-filter="online" aria-pressed="false">En ligne</button>
      <button type="button" data-device-filter="offline" aria-pressed="false">Hors ligne</button>
      <button type="button" data-device-filter="new" aria-pressed="false">Nouveaux</button>
      <button type="button" data-device-filter="watched" aria-pressed="false">Surveillés <span id="watchedCount">0</span></button>
      <button type="button" data-device-filter="favorites" aria-pressed="false" title="Favoris conservés dans ce navigateur">☆ Favoris <span id="favoriteCount">0</span></button>
    </div>
    <button id="resetDeviceFilters" type="button" class="quiet-button" hidden>Effacer les filtres</button>
  </div>
  <p id="deviceResults" class="device-results" role="status">Chargement de l’inventaire…</p>
  <div class="equipment-table-wrap">
    <table id="equipmentTable" class="equipment-table" data-view="list">
      <caption class="sr-only">Équipements connus de la Livebox. Ouvrez une fiche pour consulter le profil et l’historique.</caption>
      <thead><tr><th scope="col">Équipement</th><th scope="col">État</th><th scope="col">Liaison</th><th scope="col">Adresse IP</th><th scope="col">↓ Réception</th><th scope="col">↑ Émission</th><th scope="col"><span class="sr-only">Favori</span></th></tr></thead>
      <tbody id="devices"></tbody>
    </table>
  </div>
  <div id="deviceEmpty" class="equipment-empty" hidden><span aria-hidden="true">⌕</span><h3 id="emptyTitle">Aucun équipement trouvé</h3><p id="emptyHint">Essayez une autre recherche ou élargissez vos filtres.</p><button id="emptyReset" type="button">Réinitialiser les filtres</button></div>
  <div class="equipment-footer"><span id="status" role="status">Connexion au collecteur…</span><span>Actualisation toutes les 10 s</span></div>
</section>
<details class="traffic-disclosure">
  <summary><span><strong>Trafic Internet</strong><small>Débits WAN, de la dernière heure à un an</small></span><span class="disclosure-action">Voir le graphe <span aria-hidden="true">⌄</span></span></summary>
  <section class="wan-panel">
  <div class="wan-heading">
    <div>
      <h2>Trafic Internet</h2>
      <p>Débits globaux mesurés par la Livebox</p>
    </div>
    <label class="wan-period"><span>Période</span><select id="wanPeriod"><option value="1h">Dernière heure</option><option value="24h">24 heures</option><option value="7d">7 jours</option><option value="30d">30 jours</option><option value="90d">90 jours</option><option value="1y">1 an</option></select></label>
  </div>
  <div class="wan-rates">
    <div class="wan-card wan-download"><strong>Descendant</strong><span id="wanRx">En attente…</span></div>
    <div class="wan-card wan-upload"><strong>Montant</strong><span id="wanTx">En attente…</span></div>
  </div>
  <div class="legend"><span>Descendant</span><span>Montant</span></div>
  <div id="wanChartWrap" class="wan-chart-wrap">
    <p class="measurement-note">Mesure issue des compteurs WAN de la Livebox. Les pics extrêmes sont l'échelle suit le maximum réel de la période ; survolez un point pour voir sa valeur réelle.</p>
    <svg id="wanChart" viewBox="0 0 1000 320" role="img"
         aria-label="Débits Internet descendant et montant"></svg>
    <div id="wanTooltip" class="wan-tooltip"></div>
  </div>
  <div id="wanInfo" class="wan-info">Attente des premiers relevés Livebox…</div>
</section>
</details>
<details class="alerts-disclosure"><summary>Journal des incidents réseau</summary><ul id="internetEvents"><li>Aucune alerte enregistrée.</li></ul></details>
<dialog id="deviceDialog" class="device-dialog" aria-labelledby="deviceTitle" aria-describedby="deviceSubtitle">
  <div class="drawer-heading"><div><p class="eyebrow">FICHE ÉQUIPEMENT</p><h2 id="deviceTitle">Équipement</h2><p id="deviceSubtitle" class="muted"></p></div><button id="closeDevice" type="button" class="icon-button" aria-label="Fermer la fiche">✕</button></div>
  <div class="drawer-content">
    <div id="deviceFacts" class="device-facts"></div>
    <div id="deviceNewcomer" class="device-newcomer" role="status" hidden></div>
    <div id="deviceSuggestion" class="device-suggestion" hidden></div>
    <section id="deviceWifi" class="device-wifi" aria-labelledby="deviceWifiTitle" hidden>
      <div class="presence-heading"><div><p class="eyebrow">COUVERTURE WI-FI</p><h3 id="deviceWifiTitle">Qualité du signal</h3></div></div>
      <div id="deviceWifiBody"><p class="muted">Chargement du signal…</p></div>
    </section>
    <section class="profile-section"><h3>Un nom qui vous parle</h3><p class="muted">Identifiez cet appareil et retrouvez-le facilement.</p>
      <form id="deviceProfileForm">
        <label for="profileName">Nom personnalisé</label><input id="profileName" maxlength="80" placeholder="Ex. MacBook de Camille" autocomplete="off">
        <div class="profile-fields">
          <div><label for="profileCategoryChoice">Catégorie</label><select id="profileCategoryChoice" aria-controls="profileCategoryCustom"></select><div id="profileCategoryPreview" class="category-preview"></div>
            <div id="profileCategoryCustom" class="profile-custom-field" hidden><label for="profileCategory">Nouvelle catégorie</label><input id="profileCategory" maxlength="40" placeholder="Ex. Enceinte" autocomplete="off"></div>
          </div>
          <div><label for="profileLocationChoice">Pièce</label><select id="profileLocationChoice" aria-controls="profileLocationCustom"></select>
            <div id="profileLocationCustom" class="profile-custom-field" hidden><label for="profileLocation">Nouvelle pièce</label><input id="profileLocation" maxlength="80" placeholder="Ex. Atelier" autocomplete="off"></div>
          </div>
        </div>
        <p class="profile-help muted">Laissez le nom vide pour reprendre celui de la Livebox.</p>
        <button id="saveDeviceProfile" type="submit" class="primary-button">Enregistrer le profil</button>
        <p id="profileMessage" role="status"></p>
      </form>
    </section>
    <details class="drawer-feature" id="deviceWatchSection">
      <summary><span>Veiller sur cet équipement<small id="watchSummary">Surveillance désactivée par défaut</small></span><span aria-hidden="true">⌄</span></summary>
      <p class="muted">Utile pour un NAS, une caméra ou une centrale domotique. Une alerte apparaît sur l’accueil après une absence prolongée.</p>
      <form id="deviceWatchForm"><fieldset id="watchFields" disabled>
        <label class="check-row"><input id="watchEnabled" type="checkbox"> Surveiller les absences de cet appareil</label>
        <label for="watchDelay">Alerter après combien de minutes hors ligne ?</label><input id="watchDelay" type="number" min="1" max="1440" step="1" value="15" required>
        <label class="check-row"><input id="watchEmail" type="checkbox"> Recevoir aussi l’alerte et le retour en ligne par e-mail</label>
        <p id="watchEmailHint" class="muted"></p><p class="muted">Le délai est compté à partir des collectes réussies. Une perte d’accès à la Livebox suspend la détection. Certains appareils en veille sont signalés hors ligne.</p>
        <button id="saveWatch" type="submit" class="primary-button">Enregistrer la surveillance</button>
      </fieldset></form>
      <button id="retryWatch" type="button" hidden>Réessayer le chargement</button><p id="watchMessage" role="status"></p>
      <ol id="watchIncidents" class="watch-incidents" aria-label="Dernières alertes de cet équipement"></ol>
    </details>
    <section class="presence-panel" aria-labelledby="presenceTitle">
      <div class="presence-heading"><div><p class="eyebrow">PRÉSENCE RÉSEAU</p><h3 id="presenceTitle">Connexions & déconnexions</h3></div><label><span class="sr-only">Période de présence</span><select id="devicePresencePeriod"><option value="24h">24 heures</option><option value="7d" selected>7 jours</option><option value="30d">30 jours</option><option value="90d">90 jours</option><option value="1y">1 an</option></select></label></div>
      <p class="muted">Transitions observées par la Livebox ; elles ne permettent pas de déduire la présence d’une personne.</p>
      <p id="devicePresenceInfo" role="status">Chargement des événements…</p><ol id="deviceTimeline" class="device-timeline" aria-label="Historique de présence réseau"></ol>
    </section>
    <section class="history">
  <h2>Historique du trafic</h2>
  <p class="measurement-note">Les débits par appareil sont estimés par la Livebox et peuvent différer du total WAN. Les pics extrêmes sont l'échelle suit le maximum réel de la période ; survolez un point pour sa valeur réelle.</p>
  <div class="history-controls">
    <div id="historySelected" class="history-selected">Cliquez sur un appareil pour afficher son historique.</div>
    <label>Période
      <select id="historyPeriod">
        <option value="1h">1 heure</option>
        <option value="24h" selected>24 heures</option>
        <option value="7d">7 jours</option>
        <option value="30d">30 jours</option>
        <option value="90d">90 jours</option>
        <option value="1y">1 an</option>
      </select>
    </label>
  </div>
  <div class="legend"><span>Réception</span><span>Émission</span></div>
  <svg id="historyChart" viewBox="0 0 1000 320" role="img"
       aria-label="Graphique des débits de réception et d’émission"></svg>
  <div id="historyInfo">Sélectionnez un appareil.</div>
</section>
    <details class="device-danger"><summary>Gestion de l’équipement</summary><p>Supprimer l’appareil efface définitivement sa fiche et tout son historique. S’il se reconnecte après au moins une heure d’absence, il sera signalé comme nouvel équipement, avec e-mail.</p><button id="deleteDevice" type="button" class="delete-device-button">Supprimer l’appareil</button><p id="deleteMessage" role="status"></p></details>
  </div>
</dialog>
<script>
function rate(value) {
  if (value === null || value === undefined) return "—";
  if (value < 1000) return value + " bit/s";
  if (value < 1000000) return (value / 1000).toFixed(1) + " kbit/s";
  return (value / 1000000).toFixed(2) + " Mbit/s";
}
function addCell(row, value, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value;
  row.appendChild(cell);
}
function drawWan(input, view = {}) {
  const svg = document.getElementById("wanChart");
  const wrap = document.getElementById("wanChartWrap");
  const tooltip = document.getElementById("wanTooltip");
  const ns = "http://www.w3.org/2000/svg";
  const width = 1000, height = 280;
  const left = 140, right = 972, top = 24, bottom = 224;
  svg.replaceChildren();
  tooltip.style.display = "none";

  const points = input.filter(point =>
    point.rx_bps !== null || point.tx_bps !== null
  );
  if (!points.length) return;

  const values = points.flatMap(point =>
    [point.rx_bps, point.tx_bps]
      .filter(value => value !== null && Number.isFinite(Number(value)))
      .map(Number)
  );
  if (!values.length) return;

  const startTs = view.start ?? (Number(points[points.length - 1].ts) - 3600);
  const span = Math.max(1, (view.end ?? startTs + 3600) - startTs);
  // A gap longer than one bucket (or three collections) is drawn as a gap, never bridged.
  const gapLimit = (view.bucket_seconds || 120) * 1.6;
  const scaleTarget = Math.max(1, ...values);
  const magnitude = Math.pow(10, Math.floor(Math.log10(scaleTarget)));
  const fraction = scaleTarget / magnitude;
  const niceFactor = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  const maxRate = niceFactor * magnitude;

  function add(tag, attributes, text) {
    const element = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attributes || {})) {
      element.setAttribute(key, value);
    }
    if (text !== undefined) element.textContent = text;
    svg.appendChild(element);
    return element;
  }
  function xFor(ts) {
    return left + (Number(ts) - startTs) / span * (right - left);
  }
  function yFor(value) {
    return bottom - (Number(value) || 0) / maxRate * (bottom - top);
  }

  for (let index = 0; index <= 4; index++) {
    const fraction = index / 4;
    const y = bottom - fraction * (bottom - top);
    add("line", {
      x1: left, y1: y, x2: right, y2: y,
      stroke: "#e9eef4", "stroke-width": 1
    });
    add("text", {
      x: left - 12, y: y + 4, "text-anchor": "end",
      fill: "#728093", "font-size": 12
    }, rate(maxRate * fraction));
  }

  for (let index = 0; index <= 4; index++) {
    const fraction = index / 4;
    const x = left + fraction * (right - left);
    const ts = startTs + fraction * span;
    add("line", {
      x1: x, y1: top, x2: x, y2: bottom,
      stroke: "#f0f3f7", "stroke-width": 1
    });
    add("text", {
      x, y: bottom + 24, "text-anchor": "middle",
      fill: "#728093", "font-size": 12
    }, span <= 86400
      ? new Date(ts * 1000).toLocaleTimeString("fr-FR", {hour: "2-digit", minute: "2-digit"})
      : new Date(ts * 1000).toLocaleDateString("fr-FR", span > 120 * 86400 ? {month: "short", year: "2-digit"} : {day: "2-digit", month: "2-digit"}));
  }

  add("text", {
    x: 18, y: (top + bottom) / 2,
    transform: `rotate(-90 18 ${(top + bottom) / 2})`,
    "text-anchor": "middle", fill: "#728093", "font-size": 13
  }, "Débit");
  add("text", {
    x: (left + right) / 2, y: height - 7,
    "text-anchor": "middle", fill: "#728093", "font-size": 13
  }, span <= 86400 ? "Heure" : "Date");

  const series = [
    {key: "rx_bps", color: "#1677ff", label: "Descendant", gradient: "wanRxFill"},
    {key: "tx_bps", color: "#e67e22", label: "Montant", gradient: "wanTxFill"}
  ];
  const defs = add("defs", {});
  for (const item of series) {
    const gradient = document.createElementNS(ns, "linearGradient");
    gradient.setAttribute("id", item.gradient);
    gradient.setAttribute("x1", "0");
    gradient.setAttribute("x2", "0");
    gradient.setAttribute("y1", "0");
    gradient.setAttribute("y2", "1");
    const start = document.createElementNS(ns, "stop");
    start.setAttribute("offset", "0%");
    start.setAttribute("stop-color", item.color);
    start.setAttribute("stop-opacity", ".18");
    const end = document.createElementNS(ns, "stop");
    end.setAttribute("offset", "100%");
    end.setAttribute("stop-color", item.color);
    end.setAttribute("stop-opacity", "0");
    gradient.append(start, end);
    defs.appendChild(gradient);
  }

  for (const item of series) {
    const valid = points.filter(point =>
      point[item.key] !== null && Number.isFinite(Number(point[item.key]))
    );
    const segments = [];
    for (const point of valid) {
      const current = segments[segments.length - 1];
      if (current && Number(point.ts) - Number(current[current.length - 1].ts) <= gapLimit) current.push(point);
      else segments.push([point]);
    }
    for (const segment of segments) {
      if (segment.length < 2) {
        add("circle", {cx: xFor(segment[0].ts), cy: yFor(segment[0][item.key]), r: 2.5, fill: item.color});
        continue;
      }
      const coords = segment.map(point => `${xFor(point.ts)},${yFor(point[item.key])}`).join(" ");
      const areaPath = `M ${xFor(segment[0].ts)} ${bottom} L ${coords.replaceAll(",", " ")} L ${xFor(segment[segment.length - 1].ts)} ${bottom} Z`;
      add("path", {d: areaPath, fill: `url(#${item.gradient})`});
      add("polyline", {
        points: coords, fill: "none", stroke: item.color,
        "stroke-width": span > 86400 ? 2 : 3, "stroke-linejoin": "round", "stroke-linecap": "round"
      });
    }
  }

  const guide = add("line", {
    x1: left, y1: top, x2: left, y2: bottom,
    stroke: "#8090a3", "stroke-dasharray": "4 5",
    visibility: "hidden", "pointer-events": "none"
  });
  const markers = {};
  for (const item of series) {
    markers[item.key] = add("circle", {
      r: 5, fill: item.color, stroke: "white", "stroke-width": 2,
      visibility: "hidden", "pointer-events": "none"
    });
  }
  const overlay = add("rect", {
    x: left, y: top, width: right - left, height: bottom - top,
    fill: "transparent", "pointer-events": "all"
  });

  overlay.addEventListener("mousemove", event => {
    const bounds = svg.getBoundingClientRect();
    const pointerX = (event.clientX - bounds.left) * width / bounds.width;
    let nearest = points[0];
    for (const point of points) {
      if (Math.abs(xFor(point.ts) - pointerX) <
          Math.abs(xFor(nearest.ts) - pointerX)) nearest = point;
    }

    const x = xFor(nearest.ts);
    guide.setAttribute("x1", x);
    guide.setAttribute("x2", x);
    guide.setAttribute("visibility", "visible");

    const markerYs = [];
    for (const item of series) {
      const value = nearest[item.key];
      const marker = markers[item.key];
      if (value === null || !Number.isFinite(Number(value))) {
        marker.setAttribute("visibility", "hidden");
        continue;
      }
      const y = yFor(value);
      marker.setAttribute("cx", x);
      marker.setAttribute("cy", y);
      marker.setAttribute("visibility", "visible");
      markerYs.push(y);
    }

    tooltip.replaceChildren();
    const time = document.createElement("div");
    time.className = "wan-tooltip-time";
    const bucket = view.bucket_seconds;
    time.textContent = bucket
      ? "Du " + new Date((Number(nearest.ts) - bucket / 2) * 1000).toLocaleString("fr-FR", {dateStyle: "short", timeStyle: "short"}) + " au " + new Date((Number(nearest.ts) + bucket / 2) * 1000).toLocaleString("fr-FR", bucket >= 86400 ? {dateStyle: "short"} : {timeStyle: "short"})
      : new Date(Number(nearest.ts) * 1000).toLocaleString("fr-FR");
    tooltip.appendChild(time);
    for (const item of series) {
      const row = document.createElement("div");
      const peak = nearest[item.key.replace("_bps", "_peak_bps")];
      row.textContent = item.label + " : " + rate(nearest[item.key]) + (bucket ? " en moyenne" + (peak != null ? " · pic " + rate(peak) : "") : "");
      tooltip.appendChild(row);
    }
    if (bucket && nearest.coverage != null && nearest.coverage < 0.95) {
      const row = document.createElement("div");
      row.textContent = "Mesuré sur " + Math.round(nearest.coverage * 100) + " % de l’intervalle";
      tooltip.appendChild(row);
    }
    tooltip.style.display = "block";

    const wrapBounds = wrap.getBoundingClientRect();
    const chartX = (x / width) * bounds.width + bounds.left - wrapBounds.left;
    const chartY = (Math.min(...markerYs) / height) * bounds.height + bounds.top - wrapBounds.top;
    const maxLeft = Math.max(8, wrap.clientWidth - tooltip.offsetWidth - 8);
    tooltip.style.left = Math.min(maxLeft, Math.max(8, chartX + 14)) + "px";
    const maxTop = Math.max(8, wrap.clientHeight - tooltip.offsetHeight - 8);
    tooltip.style.top = Math.min(maxTop, Math.max(8, chartY - tooltip.offsetHeight - 10)) + "px";
  });

  overlay.addEventListener("mouseleave", () => {
    guide.setAttribute("visibility", "hidden");
    for (const marker of Object.values(markers)) {
      marker.setAttribute("visibility", "hidden");
    }
    tooltip.style.display = "none";
  });
}


const WAN_LABELS = {"1h": "la dernière heure", "24h": "24 heures", "7d": "7 jours", "30d": "30 jours", "90d": "90 jours", "1y": "1 an"};
function wanVolume(bytes) {
  if (!bytes) return "0 o";
  const units = ["o", "Ko", "Mo", "Go", "To"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1000)));
  return (bytes / 1000 ** index).toLocaleString("fr-FR", {maximumFractionDigits: 1}) + " " + units[index];
}
let wanRequest = 0;
async function refreshWan() {
  const select = document.getElementById("wanPeriod");
  const period = select.value;
  const request = ++wanRequest;
  try {
    const response = await fetch("/api/wan?" + new URLSearchParams({period}));
    if (!response.ok) throw new Error("API WAN indisponible");
    const data = await response.json();
    if (request !== wanRequest) return;
    document.getElementById("wanRx").textContent = rate(data.rx_bps);
    document.getElementById("wanTx").textContent = rate(data.tx_bps);
    drawWan(data.points || [], data);
    document.getElementById("wanChart").setAttribute("aria-label", "Débits Internet descendant et montant sur " + WAN_LABELS[period]);
    const sampled = data.last_sample
      ? new Date(data.last_sample * 1000).toLocaleString("fr-FR", {dateStyle: "short", timeStyle: "medium"})
      : "en attente";
    const totals = data.totals || {};
    const coverage = totals.coverage != null ? Math.round(totals.coverage * 100) : null;
    document.getElementById("wanInfo").textContent =
      "Sur " + WAN_LABELS[period] + " : " + wanVolume(totals.rx_bytes) + " reçus, " + wanVolume(totals.tx_bytes) + " envoyés" +
      (coverage !== null && coverage < 95 ? " (mesuré sur " + coverage + " % de la période)" : "") +
      (data.bucket_seconds ? " · moyennes par " + (data.bucket_seconds >= 86400 ? "jour" : data.bucket_seconds >= 3600 ? (data.bucket_seconds / 3600) + " h" : (data.bucket_seconds / 60) + " min") : "") +
      " · dernier relevé : " + sampled;
    if (!(data.points || []).length) document.getElementById("wanInfo").textContent = "Pas encore de mesure sur " + WAN_LABELS[period] + ". Dernier relevé : " + sampled;
  } catch (error) {
    document.getElementById("wanInfo").textContent =
      "Statistiques WAN temporairement indisponibles.";
  }
}

async function refreshInternet() {
  const element = document.getElementById("internetStatus");
  try {
    const response = await fetch("/api/internet");
    if (!response.ok) throw new Error("Sonde indisponible");
    const data = await response.json();
    const eventList = document.getElementById("internetEvents");
    eventList.replaceChildren();
    const events = data.events || [];
    if (events.length === 0) {
      const item = document.createElement("li");
      item.textContent = "Aucune alerte enregistrée.";
      eventList.appendChild(item);
    } else {
      for (const event of events) {
        const item = document.createElement("li");
        const started = new Date(event.started_at * 1000).toLocaleString("fr-FR");
        const ending = event.ended_at
          ? " · résolu à " + new Date(event.ended_at * 1000).toLocaleString("fr-FR")
          : " · EN COURS";
        item.textContent = started + " — " + event.message + ending;
        eventList.appendChild(item);
      }
    }
    const checkedAt = data.last_check
      ? new Date(data.last_check * 1000).toLocaleTimeString("fr-FR")
      : "en attente";

    const activeAlerts = data.active_alerts || [];
    if (activeAlerts.length > 0) {
      element.dataset.state = "down";
      element.textContent = "ALERTE : " +
        activeAlerts.map(alert => alert.message).join(" · ") +
        " · depuis " +
        new Date(activeAlerts[0].started_at * 1000).toLocaleTimeString("fr-FR");
      return;
    }

    if (data.router_ok === false) {
      element.dataset.state = "down";
      element.textContent = "Livebox inaccessible · contrôle à " + checkedAt;
    } else if (data.internet_ok === false) {
      element.dataset.state = "down";
      element.textContent = "Internet indisponible · Livebox joignable · contrôle à " + checkedAt;
    } else if (data.internet_ok === true) {
      element.dataset.state = "ok";
      element.textContent = "Internet disponible · latence moyenne " +
        data.latency_ms + " ms · contrôle à " + checkedAt;
    } else {
      element.dataset.state = "pending";
      element.textContent = "Contrôle de la connexion Internet en attente…";
    }
  } catch (error) {
    element.dataset.state = "pending";
    element.textContent = "État Internet temporairement indisponible";
  }
}

function drawHistory(points, period) {
  const svg = document.getElementById("historyChart");
  const ns = "http://www.w3.org/2000/svg";
  const width = 1000, height = 280;
  const left = 140, right = 972, top = 24, bottom = 224;
  svg.replaceChildren();

  if (points.length < 2) {
    document.getElementById("historyInfo").textContent =
      "Pas encore assez de mesures pour cette période.";
    return;
  }

  const firstTs = Number(points[0].ts);
  const lastTs = Number(points[points.length - 1].ts);
  const timeRange = Math.max(1, lastTs - firstTs);
  const values = points.map(point =>
    Math.max(Number(point.rx_bps) || 0, Number(point.tx_bps) || 0)
  );
  const scaleTarget = Math.max(1, ...values);
  const magnitude = Math.pow(10, Math.floor(Math.log10(scaleTarget)));
  const fraction = scaleTarget / magnitude;
  const niceFactor = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  const maxRate = niceFactor * magnitude;

  function add(tag, attributes, text) {
    const element = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attributes || {})) {
      element.setAttribute(key, value);
    }
    if (text !== undefined) element.textContent = text;
    svg.appendChild(element);
    return element;
  }

  function xFor(timestamp) {
    return left + (Number(timestamp) - firstTs) / timeRange * (right - left);
  }

  function yFor(value) {
    return bottom - (Number(value) || 0) / maxRate * (bottom - top);
  }

  function timeLabel(timestamp) {
    const date = new Date(Number(timestamp) * 1000);
    if (period === "1h" || period === "24h") {
      return date.toLocaleTimeString("fr-FR", {hour: "2-digit", minute: "2-digit"});
    }
    return date.toLocaleDateString("fr-FR", {day: "2-digit", month: "2-digit"});
  }

  // Graduations horizontales et échelle des débits.
  for (let index = 0; index <= 4; index++) {
    const fraction = index / 4;
    const y = bottom - fraction * (bottom - top);
    const value = maxRate * fraction;
    add("line", {
      x1: left, y1: y, x2: right, y2: y,
      stroke: "#dfe5eb", "stroke-width": 1
    });
    add("text", {
      x: left - 10, y: y + 5, "text-anchor": "end",
      fill: "#52616b", "font-size": 13
    }, rate(value));
  }

  // Graduations verticales et échelle temporelle.
  for (let index = 0; index <= 4; index++) {
    const fraction = index / 4;
    const x = left + fraction * (right - left);
    const timestamp = firstTs + fraction * timeRange;
    add("line", {
      x1: x, y1: top, x2: x, y2: bottom,
      stroke: "#edf0f3", "stroke-width": 1
    });
    add("text", {
      x, y: bottom + 24, "text-anchor": "middle",
      fill: "#52616b", "font-size": 13
    }, timeLabel(timestamp));
  }

  add("line", {x1: left, y1: top, x2: left, y2: bottom, stroke: "#52616b"});
  add("line", {x1: left, y1: bottom, x2: right, y2: bottom, stroke: "#52616b"});
  add("text", {
    x: 20, y: (top + bottom) / 2,
    transform: `rotate(-90 20 ${(top + bottom) / 2})`,
    "text-anchor": "middle", fill: "#52616b", "font-size": 14
  }, "Débit");
  add("text", {
    x: (left + right) / 2, y: height - 8,
    "text-anchor": "middle", fill: "#52616b", "font-size": 14
  }, "Date et heure");

  for (const [key, color] of [
    ["rx_bps", "#1677ff"],
    ["tx_bps", "#e67e22"]
  ]) {
    const coordinates = points.map(point =>
      `${xFor(point.ts)},${yFor(point[key])}`
    ).join(" ");
    add("polyline", {
      points: coordinates, fill: "none", stroke: color,
      "stroke-width": 3, "stroke-linejoin": "round", "stroke-linecap": "round"
    });
  }

  const guide = add("line", {
    x1: left, y1: top, x2: left, y2: bottom,
    stroke: "#52616b", "stroke-dasharray": "4 4",
    visibility: "hidden", "pointer-events": "none"
  });
  const rxMarker = add("circle", {
    r: 5, fill: "#1677ff", stroke: "white", "stroke-width": 2,
    visibility: "hidden", "pointer-events": "none"
  });
  const txMarker = add("circle", {
    r: 5, fill: "#e67e22", stroke: "white", "stroke-width": 2,
    visibility: "hidden", "pointer-events": "none"
  });

  const tooltip = document.createElementNS(ns, "g");
  tooltip.setAttribute("visibility", "hidden");
  tooltip.setAttribute("pointer-events", "none");
  const tooltipBackground = document.createElementNS(ns, "rect");
  tooltipBackground.setAttribute("width", "248");
  tooltipBackground.setAttribute("height", "82");
  tooltipBackground.setAttribute("rx", "6");
  tooltipBackground.setAttribute("fill", "white");
  tooltipBackground.setAttribute("stroke", "#9aa7b2");
  tooltip.appendChild(tooltipBackground);
  const tooltipText = document.createElementNS(ns, "text");
  tooltipText.setAttribute("x", "10");
  tooltipText.setAttribute("y", "18");
  tooltipText.setAttribute("fill", "#17202a");
  tooltipText.setAttribute("font-size", "13");
  tooltip.appendChild(tooltipText);
  svg.appendChild(tooltip);

  const overlay = document.createElementNS(ns, "rect");
  overlay.setAttribute("x", left);
  overlay.setAttribute("y", top);
  overlay.setAttribute("width", right - left);
  overlay.setAttribute("height", bottom - top);
  overlay.setAttribute("fill", "transparent");
  overlay.setAttribute("pointer-events", "all");
  svg.appendChild(overlay);

  overlay.addEventListener("mousemove", event => {
    const bounds = svg.getBoundingClientRect();
    const pointerX = (event.clientX - bounds.left) * width / bounds.width;
    let nearest = points[0];
    for (const point of points) {
      if (Math.abs(xFor(point.ts) - pointerX) <
          Math.abs(xFor(nearest.ts) - pointerX)) nearest = point;
    }

    const x = xFor(nearest.ts);
    const rxY = yFor(nearest.rx_bps);
    const txY = yFor(nearest.tx_bps);
    guide.setAttribute("x1", x);
    guide.setAttribute("x2", x);
    guide.setAttribute("visibility", "visible");
    rxMarker.setAttribute("cx", x);
    rxMarker.setAttribute("cy", rxY);
    rxMarker.setAttribute("visibility", "visible");
    txMarker.setAttribute("cx", x);
    txMarker.setAttribute("cy", txY);
    txMarker.setAttribute("visibility", "visible");

    tooltipText.replaceChildren();
    const lines = [
      new Date(Number(nearest.ts) * 1000).toLocaleString("fr-FR"),
      "Réception : " + rate(nearest.rx_bps),
      "Émission : " + rate(nearest.tx_bps)
    ];
    lines.forEach((line, index) => {
      const span = document.createElementNS(ns, "tspan");
      span.setAttribute("x", "10");
      span.setAttribute("dy", index === 0 ? "0" : "22");
      span.textContent = line;
      tooltipText.appendChild(span);
    });

    const tooltipX = x > right - 260 ? x - 258 : x + 12;
    const tooltipY = Math.max(top + 4, Math.min(bottom - 88, Math.min(rxY, txY) - 42));
    tooltip.setAttribute("transform", `translate(${tooltipX} ${tooltipY})`);
    tooltip.setAttribute("visibility", "visible");
  });

  overlay.addEventListener("mouseleave", () => {
    guide.setAttribute("visibility", "hidden");
    rxMarker.setAttribute("visibility", "hidden");
    txMarker.setAttribute("visibility", "hidden");
    tooltip.setAttribute("visibility", "hidden");
  });

  const first = new Date(firstTs * 1000);
  const last = new Date(lastTs * 1000);
  document.getElementById("historyInfo").textContent =
    points.length + " points · " +
    first.toLocaleString("fr-FR") + " → " +
    last.toLocaleString("fr-FR");
}
let selectedMac = null;
let allDevices = [];
let inventoryLoaded = false;
let deviceFilter = "all";
let refreshVersion = 0;
let historyController = null;
let presenceController = null;
let watchController = null;
let watchSmtpReady = false;
let favorites = new Set();
let deviceView = "list";
const deviceDialog = document.getElementById("deviceDialog");
const historyPanel = document.querySelector(".history");
try {
  const saved = JSON.parse(localStorage.getItem("sentinel-favorites") || "[]");
  if (Array.isArray(saved)) favorites = new Set(saved.filter(value => typeof value === "string"));
  if (localStorage.getItem("sentinel-device-view") === "grid") deviceView = "grid";
} catch (_) {}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function normalizeSearch(value) {
  return String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLocaleLowerCase("fr");
}
function deviceConnection(device) {
  const layer = String(device.layer2_interface || "").toLowerCase();
  const intf = String(device.interface_name || "").toLowerCase();
  if (layer.startsWith("wl") || /wi-?fi|wireless|wlan/.test(intf)) {
    const label = layer === "wl0.1" ? "Wi-Fi 2,4 GHz" : layer === "wl1.1" ? "Wi-Fi 5 GHz" : "Wi-Fi";
    return {key: "wifi", label};
  }
  if (layer.startsWith("eth") || intf.startsWith("eth")) return {key: "ethernet", label: "Ethernet"};
  return {key: "unknown", label: "Non identifiée"};
}
function deviceIcon(device) {
  return categorySymbol(device.category || device.device_type, device.symbol);
}
function updateCategoryPreview() {
  const target = document.getElementById("profileCategoryPreview");
  const value = document.getElementById("profileCategory").value.trim();
  target.replaceChildren(categorySymbol(value), document.createTextNode(value || "Équipement sans catégorie"));
}
function trafficTotal(device) {
  return (Number(device.rx_bps) || 0) + (Number(device.tx_bps) || 0);
}
function setDeviceFilter(filter) {
  deviceFilter = filter;
  renderDevices();
}
function resetDeviceFilters() {
  deviceFilter = "all";
  document.getElementById("deviceSearch").value = "";
  document.getElementById("deviceConnection").value = "all";
  document.getElementById("deviceCategory").value = "";
  document.getElementById("deviceLocation").value = "";
  renderDevices();
}
function updateFilterOptions(id, field, label) {
  const select = document.getElementById(id);
  const selected = select.value;
  const values = [...new Set(allDevices.map(device => device[field]).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, "fr", {sensitivity: "base"}));
  // Keep the chosen filter even if a device changes profile during refresh.
  if (selected && !values.includes(selected)) values.push(selected);
  const expected = [["", label], ...values.map(value => [value, value])];
  if (select.options.length === expected.length && expected.every(([value, text], index) =>
    select.options[index].value === value && select.options[index].text === text)) return;
  // Native iOS pickers must keep their option nodes while the user is choosing.
  if (document.activeElement === select || select.dataset.pickerOpen === "true") return;
  select.replaceChildren(...expected.map(([value, text]) => new Option(text, value)));
  select.value = selected;
}

function prepareProfileChoice(field, initial, presets) {
  const input = document.getElementById("profile" + field);
  const select = document.getElementById("profile" + field + "Choice");
  const panel = document.getElementById("profile" + field + "Custom");
  const property = field === "Category" ? "category" : "location";
  const values = [...new Set([...presets, ...allDevices.map(device => device[property]), initial].filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, "fr", {sensitivity: "base"}));
  // Prefix real values so a custom label can never collide with the Add action.
  select.replaceChildren(new Option("Non renseignée", "value:"), ...values.map(value => new Option(value, "value:" + value)),
    new Option(field === "Category" ? "Ajouter une catégorie…" : "Ajouter une pièce…", "custom"));
  input.value = initial || "";
  select.value = "value:" + (initial || "");
  panel.hidden = true;
  input.required = false;
  if (field === "Category") updateCategoryPreview();
}

for (const field of ["Category", "Location"]) {
  const select = document.getElementById("profile" + field + "Choice");
  select.addEventListener("change", () => {
    const input = document.getElementById("profile" + field);
    const custom = select.value === "custom";
    document.getElementById("profile" + field + "Custom").hidden = !custom;
    input.required = custom;
    input.value = custom ? "" : select.value.slice("value:".length);
    if (field === "Category") updateCategoryPreview();
    if (custom) input.focus();
  });
}
document.getElementById("profileCategory").addEventListener("input", updateCategoryPreview);
function renderDevices() {
  const focusKey = document.activeElement?.dataset.focusKey;
  const query = normalizeSearch(document.getElementById("deviceSearch").value.trim());
  const connection = document.getElementById("deviceConnection").value;
  const category = document.getElementById("deviceCategory").value;
  const location = document.getElementById("deviceLocation").value;
  const sort = document.getElementById("deviceSort").value;
  const shown = allDevices.filter(device => {
    if (deviceFilter === "online" && !device.active) return false;
    if (deviceFilter === "offline" && device.active) return false;
    if (deviceFilter === "new" && !device.is_new) return false;
    if (deviceFilter === "favorites" && !favorites.has(device.mac)) return false;
    if (deviceFilter === "watched" && !device.watch_enabled) return false;
    if (connection !== "all" && deviceConnection(device).key !== connection) return false;
    if (category && device.category !== category) return false;
    if (location && device.location !== location) return false;
    const haystack = normalizeSearch([device.name, device.router_name, device.mac, device.ip,
      device.category, device.location, device.device_type, deviceConnection(device).label].join(" "));
    return query.split(/\s+/).every(term => haystack.includes(term));
  });
  const collator = new Intl.Collator("fr", {numeric: true, sensitivity: "base"});
  shown.sort((a, b) => {
    let order = 0;
    if (sort === "active") order = Number(b.active) - Number(a.active);
    if (sort === "traffic") order = trafficTotal(b) - trafficTotal(a);
    if (sort === "ip") order = Number(!a.ip) - Number(!b.ip) || collator.compare(a.ip || "", b.ip || "");
    return order || collator.compare(a.name || a.mac, b.name || b.mac);
  });
  const online = allDevices.filter(device => device.active).length;
  for (const [id, count] of Object.entries({totalDevices: allDevices.length, onlineDevices: online,
    offlineDevices: allDevices.length - online, newDevices: allDevices.filter(device => device.is_new).length})) {
    document.getElementById(id).textContent = inventoryLoaded ? count : "—";
  }
  document.getElementById("favoriteCount").textContent = allDevices.filter(device => favorites.has(device.mac)).length;
  document.getElementById("watchedCount").textContent = allDevices.filter(device => device.watch_enabled).length;
  renderDeviceAlerts();
  document.getElementById("equipmentCount").textContent = inventoryLoaded ? allDevices.length : "—";
  document.querySelectorAll("[data-device-filter]").forEach(button => {
    button.setAttribute("aria-pressed", String(button.dataset.deviceFilter === deviceFilter));
  });
  document.querySelectorAll("[data-device-view]").forEach(button => {
    button.setAttribute("aria-pressed", String(button.dataset.deviceView === deviceView));
  });
  const filtered = Boolean(query || connection !== "all" || category || location || deviceFilter !== "all");
  document.getElementById("resetDeviceFilters").hidden = !filtered;
  document.getElementById("deviceResults").textContent = inventoryLoaded
    ? shown.length + " équipement" + (shown.length > 1 ? "s" : "") + " affiché" + (shown.length > 1 ? "s" : "") +
      " sur " + allDevices.length + " · Ouvrez une fiche pour explorer son activité."
    : "Chargement de l’inventaire…";
  document.getElementById("equipmentTable").dataset.view = deviceView;
  document.getElementById("equipmentTable").hidden = !shown.length;
  document.getElementById("deviceEmpty").hidden = !inventoryLoaded || Boolean(shown.length);
  const noWatches = deviceFilter === "watched" && !allDevices.some(device => device.watch_enabled);
  const noFavorites = deviceFilter === "favorites" && !allDevices.some(device => favorites.has(device.mac));
  document.getElementById("emptyTitle").textContent = !allDevices.length ? "Votre inventaire attend ses premiers équipements"
    : noWatches ? "Choisissez les appareils sur lesquels veiller" : noFavorites ? "Vos essentiels, toujours à portée de main" : "Aucun équipement ne correspond";
  document.getElementById("emptyHint").textContent = !allDevices.length
    ? "Les appareils apparaîtront ici dès qu’une collecte Livebox les aura détectés."
    : noWatches ? "Ouvrez la fiche d’un équipement, puis « Veiller sur cet équipement » pour activer le suivi."
    : noFavorites ? "Utilisez l’étoile d’un équipement pour le retrouver dans vos favoris."
    : "Essayez une autre recherche ou élargissez vos filtres.";
  document.getElementById("emptyReset").hidden = !filtered;
  const body = document.getElementById("devices");
  const fragment = document.createDocumentFragment();
  for (const device of shown) {
    const row = element("tr", device.mac === selectedMac ? "device-selected-row" : "");
    row.dataset.mac = device.mac;
    const nameCell = element("td", "equipment-name-cell");
    const openButton = element("button", "device-open");
    openButton.type = "button";
    openButton.dataset.focusKey = "open:" + device.mac;
    openButton.setAttribute("aria-label", "Ouvrir la fiche de " + (device.name || device.mac));
    openButton.setAttribute("aria-haspopup", "dialog");
    openButton.appendChild(deviceIcon(device));
    const identity = element("span", "equipment-identity");
    identity.appendChild(element("strong", "", device.name || "Appareil sans nom"));
    identity.appendChild(element("small", "", [device.category, device.location].filter(Boolean).join(" · ") || device.mac));
    openButton.appendChild(identity);
    openButton.addEventListener("click", () => selectDevice(device.mac));
    nameCell.appendChild(openButton);
    if (device.is_new) nameCell.appendChild(element("span", "new-device-badge", "Nouveau"));
    if (device.watch_enabled) nameCell.appendChild(element("span", "watched-device-badge", device.watch_alert_started_at ? "À vérifier" : "Surveillé"));
    row.appendChild(nameCell);
    const stateCell = element("td", "equipment-state");
    stateCell.dataset.label = "État";
    const badge = element("span", "device-state-badge" + (device.active ? " is-online" : ""));
    const dot = element("i", "status-dot" + (device.active ? " online" : ""));
    dot.setAttribute("aria-hidden", "true");
    badge.append(dot, document.createTextNode(device.active ? "En ligne" : "Hors ligne"));
    stateCell.appendChild(badge);
    row.appendChild(stateCell);
    for (const [value, label, className] of [[deviceConnection(device).label, "Liaison", "equipment-connection"],
      [device.ip || "—", "IP", "equipment-ip"], [rate(device.rx_bps), "↓ Réception", "equipment-rate"],
      [rate(device.tx_bps), "↑ Émission", "equipment-rate"]]) {
      const cell = element("td", className, value);
      cell.dataset.label = label;
      if (className === "equipment-rate") cell.title = device.last_sample
        ? "Dernier relevé de trafic : " + new Date(device.last_sample * 1000).toLocaleString("fr-FR")
        : "Aucun relevé de trafic";
      row.appendChild(cell);
    }
    const favoriteCell = element("td", "equipment-favorite");
    const favorite = element("button", "favorite-button", favorites.has(device.mac) ? "★" : "☆");
    favorite.type = "button";
    favorite.dataset.focusKey = "favorite:" + device.mac;
    favorite.setAttribute("aria-label", (favorites.has(device.mac) ? "Retirer des favoris : " : "Ajouter aux favoris : ") + (device.name || device.mac));
    favorite.setAttribute("aria-pressed", String(favorites.has(device.mac)));
    favorite.addEventListener("click", () => {
      if (favorites.has(device.mac)) favorites.delete(device.mac); else favorites.add(device.mac);
      try { localStorage.setItem("sentinel-favorites", JSON.stringify([...favorites])); } catch (_) {}
      renderDevices();
    });
    favoriteCell.appendChild(favorite);
    row.appendChild(favoriteCell);
    row.addEventListener("click", event => {
      if (!event.target.closest("button") && !window.getSelection()?.toString()) selectDevice(device.mac);
    });
    fragment.appendChild(row);
  }
  body.replaceChildren(fragment);
  if (focusKey) {
    const target = [...body.querySelectorAll("[data-focus-key]")].find(node => node.dataset.focusKey === focusKey);
    (target || document.getElementById("deviceSearch")).focus({preventScroll: true});
  }
}

function renderDeviceFacts(device) {
  document.getElementById("deviceTitle").textContent = device.name || "Appareil sans nom";
  document.getElementById("deviceSubtitle").textContent = (device.active ? "En ligne" : "Hors ligne") + " · " + deviceConnection(device).label;
  document.getElementById("historySelected").textContent = "Débits estimés par appareil";
  const facts = document.getElementById("deviceFacts");
  facts.replaceChildren();
  const sampled = device.last_sample ? new Date(device.last_sample * 1000).toLocaleString("fr-FR") : "Aucun relevé";
  for (const [label, value] of [["Adresse IP", device.ip || "Non attribuée"], ["Adresse MAC", device.mac],
    ["↓ Réception", rate(device.rx_bps)], ["↑ Émission", rate(device.tx_bps)],
    ["Nom Livebox", device.router_name || device.name || "Non communiqué"],
    ...(device.recognition?.vendor ? [["Fabricant", device.recognition.vendor]] : []),
    ...(device.recognition?.model ? [["Modèle annoncé", device.recognition.model]] : []),
    ["Dernier relevé de trafic", sampled]]) {
    const fact = element("div", "device-fact");
    fact.append(element("span", "", label), element("strong", "", value));
    facts.appendChild(fact);
  }
}
function selectDevice(mac) {
  const device = allDevices.find(item => item.mac === mac);
  if (!device) return;
  selectedMac = mac;
  renderDeviceFacts(device);
  document.getElementById("profileName").value = device.custom_name || "";
  prepareProfileChoice("Category", device.category, CATEGORY_PRESETS);
  prepareProfileChoice("Location", device.location, ["Bureau", "Salon", "Chambre", "Cuisine", "Entrée", "Garage"]);
  document.getElementById("profileMessage").textContent = "";
  document.getElementById("deleteMessage").textContent = "";
  document.querySelector(".device-danger").open = false;
  document.getElementById("deviceWatchSection").open = false;
  document.getElementById("historyChart").replaceChildren();
  document.getElementById("historyInfo").textContent = "Chargement de l’historique…";
  if (!deviceDialog.open) deviceDialog.showModal();
  document.getElementById("closeDevice").focus({preventScroll: true});
  deviceDialog.scrollTop = 0;
  renderDevices();
  refreshHistory();
  refreshDevicePresence();
  loadDeviceWatch();
  if (typeof window.loadDeviceWifi === "function") window.loadDeviceWifi(mac);
  if (typeof window.renderNewcomer === "function") window.renderNewcomer(device);
  if (typeof window.renderSuggestion === "function") window.renderSuggestion(device);
}
function closeDeviceHistory() {
  if (deviceDialog.open) deviceDialog.close();
}
deviceDialog.addEventListener("close", () => {
  const mac = selectedMac;
  selectedMac = null;
  if (historyController) historyController.abort();
  if (presenceController) presenceController.abort();
  if (watchController) watchController.abort();
  document.querySelectorAll(".device-selected-row").forEach(row => row.classList.remove("device-selected-row"));
  const target = [...document.querySelectorAll(".device-open")].find(node => node.dataset.focusKey === "open:" + mac);
  (target || document.getElementById("deviceSearch")).focus({preventScroll: true});
});
document.getElementById("closeDevice").addEventListener("click", closeDeviceHistory);
deviceDialog.addEventListener("keydown", event => {
  if (event.key !== "Tab" || event.ctrlKey || event.metaKey || event.altKey) return;
  const controls = [...deviceDialog.querySelectorAll('button, input, select, textarea, summary, a[href], [tabindex="0"]')]
    .filter(node => {
      const collapsed = node.closest("details:not([open])");
      return !node.matches(":disabled") && node.getClientRects().length &&
        (!collapsed || (node.tagName === "SUMMARY" && node.parentElement === collapsed));
    });
  const first = controls[0], last = controls[controls.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault(); last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault(); first.focus();
  }
});
deviceDialog.addEventListener("click", event => {
  const bounds = deviceDialog.getBoundingClientRect();
  if (event.target === deviceDialog && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) closeDeviceHistory();
});

async function refreshHistory() {
  const mac = selectedMac;
  const period = document.getElementById("historyPeriod").value;
  if (!mac) return;
  if (historyController) historyController.abort();
  const controller = new AbortController();
  historyController = controller;
  try {
    const response = await fetch("/api/history?" + new URLSearchParams({mac, period}), {signal: controller.signal});
    if (!response.ok) throw new Error("Historique indisponible");
    const history = await response.json();
    if (controller.signal.aborted || selectedMac !== mac) return;
    drawHistory(history.points || [], period);
  } catch (error) {
    if (error.name === "AbortError" || controller.signal.aborted || selectedMac !== mac) return;
    document.getElementById("historyChart").replaceChildren();
    document.getElementById("historyInfo").textContent = "Historique indisponible. Réessayez ou choisissez une autre période.";
  }
}

async function refresh() {
  const version = ++refreshVersion;
  const button = document.getElementById("refreshDevices");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    const [deviceResponse, statusResponse] = await Promise.all([fetch("/api/devices"), fetch("/api/status")]);
    if (!deviceResponse.ok || !statusResponse.ok) throw new Error("Collecteur indisponible");
    const [devices, status] = await Promise.all([deviceResponse.json(), statusResponse.json()]);
    if (version !== refreshVersion) return;
    allDevices = devices;
    inventoryLoaded = true;
    if (selectedMac) {
      const selected = allDevices.find(device => device.mac === selectedMac);
      if (selected) renderDeviceFacts(selected); else closeDeviceHistory();
    }
    updateFilterOptions("deviceCategory", "category", "Toutes les catégories");
    updateFilterOptions("deviceLocation", "location", "Toutes les pièces");
    renderDevices();
    const collected = status.last_collection ? new Date(status.last_collection * 1000).toLocaleString("fr-FR") : "en attente";
    const statusElement = document.getElementById("status");
    statusElement.textContent = "Dernière collecte : " + collected + (status.last_error ? " · erreur : " + status.last_error : "");
    statusElement.dataset.state = status.last_error ? "error" : "ok";
  } catch (error) {
    if (version !== refreshVersion) return;
    const statusElement = document.getElementById("status");
    statusElement.dataset.state = "error";
    statusElement.textContent = inventoryLoaded ? "Actualisation interrompue · les dernières données reçues restent affichées." : "Collecteur indisponible · réessayez avec Actualiser.";
    if (!inventoryLoaded) document.getElementById("deviceResults").textContent = "L’inventaire n’a pas encore pu être chargé.";
  } finally {
    if (version === refreshVersion) {
      button.disabled = false;
      button.setAttribute("aria-busy", "false");
    }
  }
}

document.getElementById("deviceProfileForm").addEventListener("submit", async event => {
  event.preventDefault();
  const mac = selectedMac;
  if (!mac) return;
  const button = document.getElementById("saveDeviceProfile");
  const message = document.getElementById("profileMessage");
  const query = new URLSearchParams({custom_name: document.getElementById("profileName").value.trim(),
    category: document.getElementById("profileCategory").value.trim(), location: document.getElementById("profileLocation").value.trim()});
  button.disabled = true;
  message.textContent = "Enregistrement…";
  try {
    const response = await fetch("/api/devices/" + encodeURIComponent(mac) + "/profile?" + query, {method: "PUT"});
    if (!response.ok) throw new Error("Enregistrement impossible");
    if (selectedMac === mac) message.textContent = "Profil enregistré.";
    await refresh();
  } catch (error) {
    if (selectedMac === mac) message.textContent = "Le profil n’a pas pu être enregistré. Vos modifications sont conservées dans le formulaire.";
  } finally {
    button.disabled = false;
  }
});
document.getElementById("deleteDevice").addEventListener("click", async event => {
  const mac = selectedMac;
  const device = allDevices.find(item => item.mac === mac);
  if (!device || !window.confirm("Supprimer définitivement « " + (device.name || mac) + " » et tout son historique ? S’il se reconnecte après au moins une heure d’absence, il sera signalé comme nouvel équipement.")) return;
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const response = await fetch("/api/devices/" + encodeURIComponent(mac), {method: "DELETE"});
    if (!response.ok) throw new Error("Suppression impossible");
    favorites.delete(mac);
    try { localStorage.setItem("sentinel-favorites", JSON.stringify([...favorites])); } catch (_) {}
    if (selectedMac === mac) closeDeviceHistory();
    await refresh();
  } catch (error) {
    if (selectedMac === mac) document.getElementById("deleteMessage").textContent = "La suppression a échoué. Réessayez.";
  } finally {
    button.disabled = false;
  }
});
document.querySelectorAll("[data-device-filter]").forEach(button => button.addEventListener("click", () => setDeviceFilter(button.dataset.deviceFilter)));
document.querySelectorAll("[data-device-view]").forEach(button => button.addEventListener("click", () => {
  deviceView = button.dataset.deviceView;
  try { localStorage.setItem("sentinel-device-view", deviceView); } catch (_) {}
  renderDevices();
}));
document.getElementById("deviceSearch").addEventListener("input", renderDevices);
for (const id of ["deviceConnection", "deviceCategory", "deviceLocation", "deviceSort"]) document.getElementById(id).addEventListener("change", renderDevices);
for (const [id, field, label] of [["deviceCategory", "category", "Toutes les catégories"], ["deviceLocation", "location", "Toutes les pièces"]]) {
  const select = document.getElementById(id);
  select.addEventListener("pointerdown", () => {select.dataset.pickerOpen = "true";});
  select.addEventListener("blur", () => {
    select.dataset.pickerOpen = "false";
    updateFilterOptions(id, field, label);
  });
}
for (const id of ["resetDeviceFilters", "emptyReset"]) document.getElementById(id).addEventListener("click", resetDeviceFilters);
document.getElementById("refreshDevices").addEventListener("click", () => {refresh(); refreshInternet(); refreshWan();});
document.addEventListener("keydown", event => {
  if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !deviceDialog.open && !event.target.closest("input, select, textarea, [contenteditable]")) {
    event.preventDefault(); document.getElementById("deviceSearch").focus();
  }
});
renderDevices();

function renderDeviceAlerts() {
  const alerts = allDevices.filter(device => device.watch_enabled && device.watch_alert_started_at != null);
  const banner = document.getElementById("deviceAlertBanner");
  banner.hidden = !alerts.length;
  const list = document.getElementById("deviceAlertList");
  const signature = JSON.stringify(alerts.map(device => [device.mac, device.name, device.watch_alert_started_at]));
  if (list.dataset.signature === signature) return;
  list.dataset.signature = signature;
  list.replaceChildren();
  for (const device of alerts) {
    const button = element("button", "alert-device-link");
    button.type = "button";
    button.append(element("strong", "", device.name || device.mac), element("span", "",
      "Hors ligne depuis le " + new Date(device.watch_alert_started_at * 1000).toLocaleString("fr-FR")));
    button.addEventListener("click", () => selectDevice(device.mac));
    list.appendChild(button);
  }
}

async function refreshDevicePresence() {
  const mac = selectedMac;
  if (!mac) return;
  if (presenceController) presenceController.abort();
  const controller = new AbortController();
  presenceController = controller;
  const period = document.getElementById("devicePresencePeriod").value;
  const info = document.getElementById("devicePresenceInfo");
  info.textContent = "Chargement des transitions…";
  try {
    const response = await fetch("/api/device-events?" + new URLSearchParams({mac, period}), {signal: controller.signal});
    if (!response.ok) throw new Error("Présence indisponible");
    const data = await response.json();
    if (controller.signal.aborted || selectedMac !== mac) return;
    const events = data.events || [];
    const list = document.getElementById("deviceTimeline");
    const scroll = list.scrollTop;
    list.replaceChildren();
    for (const event of events) {
      const connected = event.event_type === "connected";
      const item = element("li", connected ? "presence-connected" : "presence-disconnected");
      const time = element("time", "", new Date(event.ts * 1000).toLocaleString("fr-FR"));
      time.dateTime = new Date(event.ts * 1000).toISOString();
      item.append(element("strong", "", connected ? "Connexion au réseau" : "Déconnexion du réseau"), time);
      const meta = [event.ip, event.connection].filter(Boolean).join(" · ");
      if (meta) item.appendChild(element("small", "", meta));
      list.appendChild(item);
    }
    list.scrollTop = scroll;
    info.textContent = events.length
      ? (data.truncated ? "Les 100 dernières transitions de cette période." : events.length + " transition" + (events.length > 1 ? "s observées." : " observée."))
      : "Aucune transition enregistrée sur cette période. L’état peut être resté stable.";
  } catch (error) {
    if (controller.signal.aborted || selectedMac !== mac) return;
    document.getElementById("deviceTimeline").replaceChildren();
    info.textContent = "Historique de présence indisponible. Changez de période ou rouvrez la fiche pour réessayer.";
  }
}

function updateWatchControls() {
  const enabled = document.getElementById("watchEnabled").checked;
  document.getElementById("watchDelay").disabled = !enabled;
  document.getElementById("watchEmail").disabled = !enabled || !watchSmtpReady;
}
let watchSaving = false;
async function loadDeviceWatch(preserveForm = false) {
  const mac = selectedMac;
  if (!mac || (preserveForm && watchSaving)) return;
  if (watchController) watchController.abort();
  const controller = new AbortController();
  watchController = controller;
  const fields = document.getElementById("watchFields");
  const summary = document.getElementById("watchSummary");
  if (!preserveForm) {
    fields.disabled = true;
    fields.dataset.ready = "false";
    summary.textContent = "Chargement de la surveillance…";
    document.getElementById("watchMessage").textContent = "";
    document.getElementById("watchIncidents").replaceChildren();
  }
  document.getElementById("retryWatch").hidden = true;
  try {
    const response = await fetch("/api/devices/" + encodeURIComponent(mac) + "/watch", {signal: controller.signal});
    if (!response.ok) throw new Error("Surveillance indisponible");
    const data = await response.json();
    if (controller.signal.aborted || selectedMac !== mac) return;
    watchSmtpReady = Boolean(data.smtp_ready);
    if (!preserveForm || fields.dataset.ready !== "true") {
      document.getElementById("watchEnabled").checked = Boolean(data.enabled);
      document.getElementById("watchDelay").value = data.offline_minutes || 15;
      document.getElementById("watchEmail").checked = Boolean(data.email_enabled);
      fields.disabled = false;
      fields.dataset.ready = "true";
    }
    updateWatchControls();
    const hint = document.getElementById("watchEmailHint");
    hint.replaceChildren();
    if (!watchSmtpReady) {
      hint.append(document.createTextNode("Pour recevoir des e-mails, "));
      const link = element("a", "", "configurez l’envoi dans Paramètres");
      link.href = "/settings";
      hint.append(link, document.createTextNode(". Les alertes sur l’accueil restent disponibles."));
    } else hint.textContent = "Les e-mails utilisent le destinataire défini dans Paramètres.";
    const active = (data.incidents || []).find(incident => incident.ended_at == null);
    summary.textContent = !data.enabled ? "Désactivée · aucun suivi des absences"
      : active ? "Absence prolongée à vérifier"
      : data.missing_since ? "Absence en cours de confirmation · seuil " + data.offline_minutes + " min"
      : "Activée · seuil " + data.offline_minutes + " min";
    if (data.enabled && data.last_checked_at == null) summary.textContent += " · en attente d’une observation Livebox";
    const list = document.getElementById("watchIncidents");
    list.replaceChildren();
    for (const incident of data.incidents || []) {
      const label = incident.ended_at == null ? "Absence prolongée en cours"
        : incident.end_reason === "disabled" ? "Surveillance désactivée" : "Retour en ligne observé";
      const item = element("li");
      item.append(element("strong", "", label), element("small", "", "Début : " + new Date(incident.started_at * 1000).toLocaleString("fr-FR") +
        (incident.ended_at != null ? " · Fin : " + new Date(incident.ended_at * 1000).toLocaleString("fr-FR") : "")));
      list.appendChild(item);
    }
  } catch (error) {
    if (controller.signal.aborted || selectedMac !== mac) return;
    summary.textContent = "Surveillance temporairement indisponible";
    document.getElementById("retryWatch").hidden = false;
  }
}
document.getElementById("watchEnabled").addEventListener("change", updateWatchControls);
document.getElementById("retryWatch").addEventListener("click", () => loadDeviceWatch());
document.getElementById("devicePresencePeriod").addEventListener("change", refreshDevicePresence);
document.getElementById("deviceWatchForm").addEventListener("submit", async event => {
  event.preventDefault();
  const mac = selectedMac;
  const fields = document.getElementById("watchFields");
  if (!mac || fields.dataset.ready !== "true" || watchSaving) return;
  const message = document.getElementById("watchMessage");
  const payload = {enabled: document.getElementById("watchEnabled").checked,
    offline_minutes: Number(document.getElementById("watchDelay").value),
    email_enabled: document.getElementById("watchEmail").checked};
  watchSaving = true;
  fields.disabled = true;
  message.textContent = "Enregistrement…";
  try {
    const response = await fetch("/api/devices/" + encodeURIComponent(mac) + "/watch", {
      method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(typeof detail.detail === "string" ? detail.detail : "Enregistrement impossible. Réessayez.");
    }
    if (selectedMac === mac) {
      await loadDeviceWatch();
      message.textContent = "Surveillance enregistrée.";
    }
    await refresh();
  } catch (error) {
    if (selectedMac === mac) message.textContent = error.message || "La surveillance n’a pas pu être enregistrée.";
  } finally {
    watchSaving = false;
    if (selectedMac === mac) fields.disabled = fields.dataset.ready !== "true";
  }
});
setInterval(() => {refreshDevicePresence(); loadDeviceWatch(true);}, 30000);

document.getElementById("historyPeriod")
  .addEventListener("change", refreshHistory);
refresh();
setInterval(refresh, 10000);
refreshInternet();
(() => {
  const select = document.getElementById("wanPeriod");
  try { const saved = localStorage.getItem("sentinel-wan-period"); if (saved && [...select.options].some(o => o.value === saved)) select.value = saved; } catch (_) {}
  select.addEventListener("change", () => { try { localStorage.setItem("sentinel-wan-period", select.value); } catch (_) {} refreshWan(); });
})();
refreshWan();
// Live periods refresh every 10 s; long periods change slowly and are refreshed every 5 min.
let wanLastLong = 0;
setInterval(() => {
  const period = document.getElementById("wanPeriod").value;
  if (["1h", "24h"].includes(period) || Date.now() - wanLastLong > 300000) { if (!["1h", "24h"].includes(period)) wanLastLong = Date.now(); refreshWan(); }
}, 10000);
setInterval(refreshHistory, 30000);
setInterval(refreshInternet, 30000);
</script>
</body>
</html>
"""


SETTINGS_PAGE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Paramètres — Livebox Sentinel</title>
<style>
body { font: 16px system-ui, sans-serif; max-width: 760px; margin: 2rem auto;
  padding: 0 1rem; color: #17202a; background: #f5f7fa; }
header { display: flex; justify-content: space-between; align-items: center; }
section { background: white; padding: 1.25rem; border-radius: 8px; margin-top: 1rem; }
label { display: block; margin: .9rem 0 .25rem; }
input, select { box-sizing: border-box; width: 100%; padding: .65rem; }
button { margin: 1rem .5rem 0 0; padding: .65rem 1rem; cursor: pointer; }
small, #message { color: #52616b; }
.check-row { display: flex; align-items: center; gap: .6rem; margin: .8rem 0; }
.check-row input { width: auto; }
</style>
</head>
<body>
<header><h1>Paramètres</h1><a href="/">Retour au tableau de bord</a></header>
<section>
<h2>Alertes par e-mail (SMTP)</h2>
<p>Ces paramètres servent aux notifications d’ouverture et de résolution d’incident.</p>
<label for="smtp_host">Serveur SMTP</label>
<input id="smtp_host" autocomplete="url" placeholder="smtp.exemple.fr">
<label for="smtp_port">Port</label>
<input id="smtp_port" type="number" min="1" max="65535" value="587">
<label for="smtp_security">Sécurité de la connexion</label>
<select id="smtp_security">
  <option value="starttls">STARTTLS (souvent port 587)</option>
  <option value="ssl">SSL/TLS (souvent port 465)</option>
</select>
<label for="smtp_username">Identifiant SMTP</label>
<input id="smtp_username" autocomplete="username">
<label for="smtp_password">Mot de passe SMTP</label>
<input id="smtp_password" type="password" autocomplete="new-password"
  placeholder="Vide = conserver le mot de passe enregistré">
<small id="password_state"></small>
<label for="smtp_from">Adresse expéditeur</label>
<input id="smtp_from" type="email" autocomplete="email">
<label for="alert_email_to">Adresse destinataire des alertes</label>
<input id="alert_email_to" type="email" autocomplete="email">
<div>
  <button id="save">Enregistrer</button>
  <button id="test">Enregistrer et tester l’envoi</button>
</div>
<p id="message" role="status"></p>
</section>
<section>
<h2>Alertes réseau</h2>
<p>Les incidents restent enregistrés dans l’historique, même si leur e-mail est désactivé.</p>
<label for="alert_confirmation_checks">
  Contrôles consécutifs requis avant de déclarer une coupure ou un rétablissement
</label>
<input id="alert_confirmation_checks" type="number" min="2" max="20" value="2">
<small>La valeur 2 conserve le comportement actuel.</small>
<label class="check-row">
  <input id="email_alert_router" type="checkbox">
  Envoyer les e-mails pour les alertes de la Livebox
</label>
<label class="check-row">
  <input id="email_alert_internet" type="checkbox">
  Envoyer les e-mails pour les alertes de connexion Internet
</label>
<label class="check-row">
  <input id="email_alert_new_device" type="checkbox">
  Envoyer un e-mail quand un nouvel équipement se connecte
</label>
<small>Un seul e-mail par relevé, même si plusieurs appareils arrivent ensemble. Les appareils déjà connus ne déclenchent rien. Ils restent signalés « Nouveau » pendant 7 jours sur le tableau de bord.</small>
</section>
<section id="livebox" class="settings-livebox">
<h2>Connexion à la Livebox</h2>
<p>Le compte d’administration de la box, distinct de votre compte Sentinel. Le test se fait en lecture seule ; rien n’est enregistré avant votre confirmation.</p>
<form id="liveboxForm" novalidate>
<label for="liveboxUrl">Adresse de la box</label><input id="liveboxUrl" name="url" type="url" inputmode="url" autocomplete="off" required placeholder="http://192.168.1.1/">
<label for="liveboxUser">Identifiant</label><input id="liveboxUser" name="username" autocomplete="off" required value="admin">
<label for="liveboxPassword">Mot de passe d’administration</label><input id="liveboxPassword" name="password" type="password" maxlength="1024" autocomplete="new-password" placeholder="Vide = conserver le mot de passe actuel">
<p id="liveboxSource" class="field-hint"></p>
<div class="settings-actions"><button type="submit" id="liveboxTest">Tester la connexion</button><button type="button" id="liveboxReset" hidden>Revenir au fichier .env</button></div>
<p id="liveboxMessage" role="status"></p>
</form>
</section>
<section class="settings-more">
<h2>Données & informations</h2>
<div class="settings-links"><a href="/backups"><strong>Données & sauvegardes</strong><span>Sauvegardes, durée de conservation, journal des actions</span></a><a href="/about"><strong>À propos</strong><span>Version, stockage et crédits</span></a></div>
</section>
<script>
const fieldIds = [
  "smtp_host", "smtp_port", "smtp_security", "smtp_username",
  "smtp_from", "alert_email_to", "alert_confirmation_checks"
];
function formValues() {
  const values = {};
  for (const id of fieldIds) values[id] = document.getElementById(id).value;
  values.smtp_password = document.getElementById("smtp_password").value;
  values.email_alert_router = document.getElementById("email_alert_router").checked;
  values.email_alert_internet = document.getElementById("email_alert_internet").checked;
  values.email_alert_new_device = document.getElementById("email_alert_new_device").checked;
  return values;
}
function showMessage(text) {
  document.getElementById("message").textContent = text;
}
async function loadSettings() {
  const response = await fetch("/api/settings");
  if (!response.ok) throw new Error("Chargement impossible");
  const settings = await response.json();
  for (const id of fieldIds) {
    document.getElementById(id).value = settings[id] || "";
  }
  document.getElementById("email_alert_router").checked =
    settings.email_alert_router !== false;
  document.getElementById("email_alert_internet").checked =
    settings.email_alert_internet !== false;
  document.getElementById("email_alert_new_device").checked =
    settings.email_alert_new_device !== false;
  document.getElementById("password_state").textContent =
    settings.smtp_password_set
      ? "Un mot de passe est enregistré et chiffré sur le serveur."
      : "Aucun mot de passe n’est enregistré.";
}
async function saveSettings() {
  const response = await fetch("/api/settings", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(formValues())
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.detail || "Enregistrement impossible");
  document.getElementById("smtp_password").value = "";
  await loadSettings();
}
document.getElementById("save").addEventListener("click", async () => {
  try {
    await saveSettings();
    showMessage("Paramètres enregistrés.");
  } catch (error) {
    showMessage(error.message);
  }
});
document.getElementById("test").addEventListener("click", async () => {
  try {
    const response = await fetch("/api/settings/test-email", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(formValues())
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Test SMTP en échec");
    await saveSettings();
    showMessage(result.message + " Paramètres enregistrés.");
  } catch (error) {
    showMessage(error.message);
  }
});
loadSettings().catch(error => showMessage(error.message));
</script>
</body>
</html>
"""



LIVEBOX_HEALTH_PAGE = r"""
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Santé Livebox — Livebox Sentinel</title>
<style>
body { font: 16px system-ui, sans-serif; margin: 2rem auto; padding: 0 1rem;
       max-width: 1100px; color: #17202a; background: #f5f7fa; }
nav { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
a { color: #1769aa; }
h1 { margin-bottom: .3rem; }
.muted { color: #64727d; }
.badge { display: inline-block; padding: .35rem .7rem; border-radius: 999px;
         font-weight: 650; background: #eaf0f5; color: #52616b; }
.badge[data-state="ok"] { background: #e4f5e9; color: #176b36; }
.badge[data-state="warn"] { background: #fff2d8; color: #805400; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
         gap: 1rem; margin-top: 1.2rem; }
.card { background: white; border: 1px solid #e4e8ec; border-radius: 12px;
        padding: 1rem; box-shadow: 0 3px 12px #17202a0a; }
.card h2 { margin: 0 0 .5rem; font-size: .95rem; color: #64727d; font-weight: 600; }
.card strong { font-size: 1.15rem; overflow-wrap: anywhere; }
.panel { margin-top: 1rem; padding: 1rem; background: white; border-radius: 12px; }
@media(max-width:650px) { body { margin-top: 1rem; } }
</style>
</head>
<body>
<nav>
  <a href="/">Tableau de bord</a>
  <a href="/consumption">Consommation</a>
  <a href="/internet">Qualité Internet</a>
  <a href="/network">Carte réseau</a>
  <a href="/livebox-health">Santé Livebox</a>
  <a href="/backups">Sauvegardes</a><a href="/settings">Paramètres</a>
</nav>
<h1>Santé Livebox</h1>
<p><span id="routerStatus" class="badge">Lecture en cours…</span></p>
<p id="lastCheck" class="muted">En attente de la première mesure.</p>

<div class="cards">
  <section class="card"><h2>Modèle</h2><strong id="model">—</strong></section>
  <section class="card"><h2>État déclaré par la Livebox</h2><strong id="deviceStatus">—</strong></section>
  <section class="card"><h2>Durée de fonctionnement</h2><strong id="uptime">—</strong></section>
  <section class="card"><h2>Redémarrages déclarés</h2><strong id="reboots">—</strong></section>
  <section class="card"><h2>Version logicielle</h2><strong id="software">—</strong></section>
  <section class="card"><h2>Version matérielle</h2><strong id="hardware">—</strong></section>
  <section class="card"><h2>Wi-Fi activé</h2><strong id="wifi">—</strong></section>
  <section class="card"><h2>État radio communiqué</h2><strong id="wifiState">—</strong></section>
  <section class="card"><h2>VAP Wi-Fi activés, selon la Livebox</h2><strong id="vaps">—</strong></section>
  <section class="card"><h2>WPS activé</h2><strong id="wps">—</strong></section>
</div>

<section class="panel">
  <h2>Historique de collecte</h2>
  <p id="history">Aucune mesure enregistrée.</p>
  <p class="muted">Les états Wi-Fi sont affichés tels que rapportés par la Livebox. Ils ne constituent pas, à eux seuls, un diagnostic de panne.</p>
</section>

<script>
function valueOrDash(value) {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}
function yesNo(value) {
  if (value === 1 || value === true) return "Oui";
  if (value === 0 || value === false) return "Non";
  return "Non communiqué";
}
function formatUptime(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days + " j " + hours + " h " + minutes + " min";
}
async function refreshHealth() {
  const badge = document.getElementById("routerStatus");
  try {
    const response = await fetch("/api/livebox-health");
    if (!response.ok) throw new Error("API indisponible");
    const data = await response.json();
    const item = data.latest;

    if (!item) {
      badge.dataset.state = "warn";
      badge.textContent = "Aucune mesure santé";
      return;
    }

    const declared = String(item.device_status || "").trim();
    badge.dataset.state = declared.toLowerCase() === "up" ? "ok" : "warn";
    badge.textContent = declared ? "État Livebox : " + declared : "État non communiqué";

    document.getElementById("model").textContent =
      [item.manufacturer, item.model_name].filter(Boolean).join(" ") || "—";
    document.getElementById("deviceStatus").textContent = valueOrDash(declared);
    document.getElementById("uptime").textContent = formatUptime(item.uptime);
    document.getElementById("reboots").textContent = valueOrDash(item.reboot_count);
    document.getElementById("software").textContent = valueOrDash(item.software_version);
    document.getElementById("hardware").textContent = valueOrDash(item.hardware_version);
    document.getElementById("wifi").textContent = yesNo(item.wifi_status);
    document.getElementById("wifiState").textContent = valueOrDash(item.wifi_current_state);
    document.getElementById("vaps").textContent = yesNo(item.wifi_vaps_enabled);
    document.getElementById("wps").textContent = yesNo(item.wifi_wps_enabled);

    const sampled = new Date(item.ts * 1000).toLocaleString("fr-FR");
    document.getElementById("lastCheck").textContent = "Dernière mesure : " + sampled;

    const history = data.history || {};
    const first = history.first_ts
      ? new Date(history.first_ts * 1000).toLocaleString("fr-FR")
      : "—";
    document.getElementById("history").textContent =
      (history.samples || 0) + " mesures depuis le " + first;
  } catch (error) {
    badge.dataset.state = "warn";
    badge.textContent = "Mesures santé indisponibles";
  }
}
refreshHealth();
setInterval(refreshHealth, 30000);
</script>
</body>
</html>
"""

@app.get("/livebox-health", response_class=HTMLResponse)
def livebox_health_page(username: str = Depends(require_auth)):
    return LIVEBOX_HEALTH_PAGE



BACKUP_DIR = Path("/data/backups")
BACKUP_PATTERN = re.compile(
    r"livebox-sentinel-\d{8}-\d{6}-[a-f0-9]{8}\.sqlite3"
)
MAX_BACKUPS = 30



def read_backup_schedule():
    connection = connect_db()
    try:
        rows = connection.execute(
            "SELECT name, value FROM app_settings "
            "WHERE name IN ('backup_auto_enabled', 'backup_auto_time', 'backup_auto_last_date')"
        ).fetchall()
        values = {row["name"]: row["value"] for row in rows}
        return {
            "enabled": values.get("backup_auto_enabled", "0") == "1",
            "time": values.get("backup_auto_time", "03:00"),
            "last_date": values.get("backup_auto_last_date", ""),
        }
    finally:
        connection.close()


def write_backup_settings(values):
    connection = connect_db()
    try:
        with connection:
            for name, value in values.items():
                connection.execute(
                    """
                    INSERT INTO app_settings(name, value) VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET value=excluded.value
                    """,
                    (name, value),
                )
    finally:
        connection.close()


@app.get("/api/backups/settings")
def get_backup_settings(username: str = Depends(require_auth)):
    return read_backup_schedule()


@app.post("/api/backups/settings")
async def save_backup_settings(
    request: Request,
    username: str = Depends(require_auth),
):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Paramètres invalides.")

    enabled = payload.get("enabled")
    backup_time = payload.get("time")
    if not isinstance(enabled, bool):
        raise HTTPException(status_code=400, detail="État d'activation invalide.")
    if not isinstance(backup_time, str) or not re.fullmatch(
        r"(?:[01]\d|2[0-3]):[0-5]\d", backup_time
    ):
        raise HTTPException(status_code=400, detail="Heure invalide.")

    write_backup_settings({
        "backup_auto_enabled": "1" if enabled else "0",
        "backup_auto_time": backup_time,
    })
    return read_backup_schedule()


def automatic_backup_loop():
    while not stop_event.is_set():
        try:
            schedule = read_backup_schedule()
            now = datetime.now(ZoneInfo("Europe/Paris"))
            today = now.date().isoformat()
            if (
                schedule["enabled"]
                and now.strftime("%H:%M") >= schedule["time"]
                and schedule["last_date"] != today
            ):
                result = create_backup(username="automatic")
                write_backup_settings({"backup_auto_last_date": today})
                print(
                    "Sauvegarde automatique créée : " + result["filename"],
                    flush=True,
                )
        except Exception as error:
            print(
                "Sauvegarde automatique : erreur " + type(error).__name__,
                flush=True,
            )
        stop_event.wait(30)


@app.post("/api/backups")
def create_backup(username: str = Depends(require_auth)):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_DIR, 0o700)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"livebox-sentinel-{stamp}-{uuid.uuid4().hex[:8]}.sqlite3"
    destination_path = BACKUP_DIR / filename
    temporary_path = BACKUP_DIR / (filename + ".tmp")

    source_db = connect_db()
    target_db = None
    try:
        target_db = sqlite3.connect(str(temporary_path), timeout=60)
        source_db.backup(target_db)
        integrity = target_db.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise RuntimeError("La sauvegarde SQLite n’est pas intègre")
        target_db.close()
        target_db = None
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination_path)
    finally:
        if target_db is not None:
            target_db.close()
        source_db.close()
        if temporary_path.exists():
            temporary_path.unlink()

    backups = sorted(
        BACKUP_DIR.glob("livebox-sentinel-*.sqlite3"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for old_backup in backups[MAX_BACKUPS:]:
        old_backup.unlink(missing_ok=True)

    return {
        "filename": filename,
        "size_bytes": destination_path.stat().st_size,
        "created_at": int(destination_path.stat().st_mtime),
    }


@app.get("/api/backups")
def list_backups(username: str = Depends(require_auth)):
    if not BACKUP_DIR.exists():
        return {"backups": []}

    backups = []
    for item in sorted(
        BACKUP_DIR.glob("livebox-sentinel-*.sqlite3"),
        key=lambda candidate: candidate.stat().st_mtime,
        reverse=True,
    ):
        if not BACKUP_PATTERN.fullmatch(item.name):
            continue
        backups.append({
            "filename": item.name,
            "size_bytes": item.stat().st_size,
            "created_at": int(item.stat().st_mtime),
        })
    return {"backups": backups}



@app.post("/api/backups/restore-stage")
async def stage_backup_restore(
    request: Request,
    username: str = Depends(require_auth),
):
    data_dir = Path(DATABASE_PATH).parent
    data_dir.mkdir(parents=True, exist_ok=True)
    upload_path = data_dir / "restore-upload.tmp"
    staged_path = data_dir / "restore-staged.sqlite3"
    max_bytes = 512 * 1024 * 1024

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(status_code=413, detail="Fichier trop volumineux (512 Mo maximum).")
        except ValueError:
            raise HTTPException(status_code=400, detail="Taille de fichier invalide.")

    size = 0
    try:
        with upload_path.open("wb") as output:
            async for chunk in request.stream():
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(status_code=413, detail="Fichier trop volumineux (512 Mo maximum).")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())

        with upload_path.open("rb") as uploaded:
            if uploaded.read(16) != b"SQLite format 3" + bytes((0,)):
                raise HTTPException(status_code=400, detail="Ce fichier n'est pas une base SQLite valide.")

        check_db = sqlite3.connect("file:" + str(upload_path) + "?mode=ro", uri=True)
        try:
            check_db.execute("PRAGMA trusted_schema=OFF")
            # Sentinel never creates triggers or views: a file that has some is not one of its backups.
            if check_db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view') OR sql LIKE 'CREATE VIRTUAL%'").fetchone()[0]:
                raise HTTPException(status_code=400, detail="Cette base contient des éléments inattendus et ne peut pas être restaurée.")
            integrity = check_db.execute("PRAGMA quick_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise HTTPException(status_code=400, detail="La vérification SQLite a échoué.")
            tables = {
                row[0] for row in check_db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not {"devices", "traffic"}.issubset(tables):
                raise HTTPException(status_code=400, detail="Cette base ne semble pas être une sauvegarde Livebox Sentinel.")
            device_columns = {
                row[1] for row in check_db.execute("PRAGMA table_info(devices)")
            }
            traffic_columns = {
                row[1] for row in check_db.execute("PRAGMA table_info(traffic)")
            }
            if not {"mac", "name", "ip", "active", "updated_at"}.issubset(device_columns):
                raise HTTPException(status_code=400, detail="Schéma de la table des appareils incompatible.")
            if not {"mac", "ts", "rx", "tx"}.issubset(traffic_columns):
                raise HTTPException(status_code=400, detail="Schéma de la table du trafic incompatible.")
        finally:
            check_db.close()

        os.replace(upload_path, staged_path)
        os.chmod(staged_path, 0o600)

        # The host-side script ships with Sentinel (tools/restore.sh): the application never writes code for the host.
        (data_dir / "restore-staged.sh").unlink(missing_ok=True)

        return {
            "ok": True,
            "filename": staged_path.name,
            "size_bytes": size,
            "instructions": (
                "Fichier vérifié. Pour appliquer la restauration, exécutez sur le serveur, dans le dossier de Sentinel : "
                "docker compose down && sh tools/restore.sh"
            ),
        }
    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Impossible de lire cette base SQLite.")
    finally:
        upload_path.unlink(missing_ok=True)


@app.get("/api/backups/{filename}")
def download_backup(
    filename: str,
    username: str = Depends(require_auth),
):
    if not BACKUP_PATTERN.fullmatch(filename):
        raise HTTPException(status_code=404, detail="Sauvegarde introuvable")

    backup_path = BACKUP_DIR / filename
    if not backup_path.is_file():
        raise HTTPException(status_code=404, detail="Sauvegarde introuvable")

    return FileResponse(
        path=backup_path,
        media_type="application/vnd.sqlite3",
        filename=filename,
    )


BACKUPS_PAGE = r"""
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Données & sauvegardes — Livebox Sentinel</title>
<style>
body { font: 16px system-ui, sans-serif; margin: 2rem auto; padding: 0 1rem;
       max-width: 1000px; color: #17202a; background: #f5f7fa; }
nav { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
a { color: #1769aa; }
.panel { padding: 1.2rem; background: white; border-radius: 12px;
         box-shadow: 0 4px 18px #17202a12; }
button { padding: .65rem 1rem; border: 0; border-radius: 8px;
         background: #1769aa; color: white; font-weight: 650; cursor: pointer; }
button:disabled { opacity: .6; cursor: wait; }
.muted { color: #64727d; }
ul { padding-left: 1.2rem; }
li { margin: .8rem 0; overflow-wrap: anywhere; }
</style>
</head>
<body>
<nav>
  <a href="/">Tableau de bord</a>
  <a href="/consumption">Consommation</a>
  <a href="/internet">Qualité Internet</a>
  <a href="/network">Carte réseau</a>
  <a href="/livebox-health">Santé Livebox</a>
  <a href="/backups">Sauvegardes</a>
  <a href="/settings">Paramètres</a>
</nav>
<h1>Données & sauvegardes</h1>
<section class="panel">
  <p>Crée une copie cohérente de la base Livebox Sentinel et télécharge-la pour la conserver ailleurs.</p>
  <button id="createBackup" type="button">Créer une sauvegarde</button>
  <p id="backupStatus" class="muted">Chargement des sauvegardes…</p>
  <h2>Copies disponibles</h2>
  <ul id="backupList"></ul>
  <p class="muted">Les 30 copies les plus récentes sont conservées sur le serveur, dans le volume de données de l’application.</p>
</section>


<section class="panel" style="margin-top:1rem">
  <h2>Sauvegarde automatique</h2>
  <label><input id="autoBackupEnabled" type="checkbox"> Activer une sauvegarde quotidienne</label>
  <p>Heure locale de Paris :
    <input id="autoBackupTime" type="time" value="03:00">
    <button id="saveAutoBackup" type="button">Enregistrer</button>
  </p>
  <p id="autoBackupStatus" class="muted" aria-live="polite">Chargement des paramètres…</p>
</section>
<section class="panel" style="margin-top:1rem">
  <h2>Restaurer une sauvegarde</h2>
  <p>Choisis un fichier SQLite de Livebox Sentinel. Il sera vérifié et préparé sans modifier immédiatement la base active.</p>
  <label for="restoreFile">Fichier de sauvegarde</label>
  <input id="restoreFile" type="file" accept=".sqlite3,.db,application/vnd.sqlite3">
  <button id="stageRestore" type="button">Vérifier et préparer</button>
  <p id="restoreStatus" class="muted" aria-live="polite"></p>
</section>
<section class="panel data-section" id="retention" style="margin-top:1rem">
  <h2>Durée de conservation</h2>
  <p id="storageSummary" class="muted">Lecture de l’espace occupé…</p>
  <form id="retentionForm" class="retention-grid" novalidate>
    <label>Mesures détaillées <small>débits par appareil, signal Wi-Fi</small><span class="unit-input"><input type="number" name="raw_days" min="7" max="90" value="30" required inputmode="numeric"> jours</span></label>
    <label>Historiques agrégés <small>graphiques de longue durée</small><span class="unit-input"><input type="number" name="aggregate_days" min="30" max="730" value="365" required inputmode="numeric"> jours</span></label>
    <label>Événements <small>incidents, présence, journal</small><span class="unit-input"><input type="number" name="events_days" min="30" max="730" value="365" required inputmode="numeric"> jours</span></label>
    <button type="submit">Voir ce qui serait supprimé</button>
  </form>
  <p class="muted">Rien n’est supprimé avant votre confirmation. Les sauvegardes ne sont jamais concernées.</p>
  <p id="retentionMessage" role="status"></p>
</section>
<section class="panel data-section" id="journal" style="margin-top:1rem">
  <h2>Journal des actions</h2>
  <p class="muted">Les modifications faites depuis Sentinel : réglages, connexion Livebox, sécurité, sauvegardes.</p>
  <ol id="auditList" class="audit-list"><li class="muted">Chargement…</li></ol>
</section>
<script>
function formatSize(value) {
  if (value < 1024 * 1024) return (value / 1024).toFixed(0) + " Ko";
  return (value / (1024 * 1024)).toFixed(1) + " Mo";
}
async function loadBackups() {
  const list = document.getElementById("backupList");
  const status = document.getElementById("backupStatus");
  try {
    const response = await fetch("/api/backups");
    if (!response.ok) throw new Error("Liste indisponible");
    const data = await response.json();
    list.replaceChildren();

    if (!data.backups.length) {
      status.textContent = "Aucune sauvegarde pour le moment.";
      return;
    }

    status.textContent = data.backups.length + " sauvegarde(s) sur le serveur.";
    for (const backup of data.backups) {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = "/api/backups/" + encodeURIComponent(backup.filename);
      link.textContent = "Télécharger " + backup.filename;
      const details = document.createElement("span");
      details.className = "muted";
      details.textContent =
        " — " + formatSize(backup.size_bytes) +
        " — " + new Date(backup.created_at * 1000).toLocaleString("fr-FR");
      item.append(link, details);
      list.appendChild(item);
    }
  } catch (error) {
    status.textContent = "Impossible de charger les sauvegardes.";
  }
}
document.getElementById("createBackup").addEventListener("click", async event => {
  const button = event.currentTarget;
  const status = document.getElementById("backupStatus");
  button.disabled = true;
  status.textContent = "Création de la sauvegarde…";
  try {
    const response = await fetch("/api/backups", {method: "POST"});
    if (!response.ok) throw new Error("Création impossible");
    const result = await response.json();
    status.textContent = "Sauvegarde créée : " + result.filename;
    await loadBackups();
  } catch (error) {
    status.textContent = "La création de la sauvegarde a échoué.";
  } finally {
    button.disabled = false;
  }
});

document.getElementById("stageRestore").addEventListener("click", async event => {
  const button = event.currentTarget;
  const file = document.getElementById("restoreFile").files[0];
  const status = document.getElementById("restoreStatus");
  if (!file) {
    status.textContent = "Choisis d'abord un fichier de sauvegarde.";
    return;
  }
  button.disabled = true;
  status.textContent = "Envoi et vérification du fichier…";
  try {
    const response = await fetch("/api/backups/restore-stage", {
      method: "POST",
      headers: {"Content-Type": "application/octet-stream"},
      body: file
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Vérification impossible.");
    status.textContent = result.instructions;
  } catch (error) {
    status.textContent = error.message || "La préparation de la restauration a échoué.";
  } finally {
    button.disabled = false;
  }
});


async function loadAutoBackupSettings() {
  const status = document.getElementById("autoBackupStatus");
  try {
    const response = await fetch("/api/backups/settings");
    if (!response.ok) throw new Error("Paramètres indisponibles");
    const settings = await response.json();
    document.getElementById("autoBackupEnabled").checked = settings.enabled;
    document.getElementById("autoBackupTime").value = settings.time || "03:00";
    status.textContent = settings.last_date
      ? "Dernière sauvegarde automatique : " +
        new Date(settings.last_date + "T00:00:00").toLocaleDateString("fr-FR")
      : "Aucune sauvegarde automatique encore réalisée.";
  } catch (error) {
    status.textContent = "Impossible de charger les paramètres automatiques.";
  }
}
document.getElementById("saveAutoBackup").addEventListener("click", async () => {
  const status = document.getElementById("autoBackupStatus");
  const payload = {
    enabled: document.getElementById("autoBackupEnabled").checked,
    time: document.getElementById("autoBackupTime").value
  };
  try {
    const response = await fetch("/api/backups/settings", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Enregistrement impossible.");
    status.textContent = result.enabled
      ? "Sauvegarde quotidienne activée à " + result.time + " (heure de Paris)."
      : "Sauvegarde automatique désactivée.";
  } catch (error) {
    status.textContent = error.message || "Impossible d'enregistrer les paramètres.";
  }
});
loadAutoBackupSettings();
setInterval(loadAutoBackupSettings, 60000);

loadBackups();
</script>
</body>
</html>
"""


@app.get("/backups", response_class=HTMLResponse)
def backups_page(username: str = Depends(require_auth)):
    return BACKUPS_PAGE


# Shared presentation only: no database access or application startup is needed
# to render these pages. Keep the UI embedded for the single-file Docker image.
UI_STYLES = """
:root {
  color-scheme: dark;
  --bg: #0b1120; --surface: #121c2e; --raised: #19263c;
  --text: #e8edf6; --muted: #a4b2c8; --line: #2b3b54;
  --accent: #78b5ff; --selected: #203a5c;
  --green: #86dfb0; --green-bg: #163b30;
  --red: #ffabab; --red-bg: #44262f;
  --amber: #f4d18b; --amber-bg: #3b3220;
}
:root[data-theme="light"] {
  color-scheme: light;
  --bg: #f3f6fb; --surface: #ffffff; --raised: #edf2f8;
  --text: #1c2b42; --muted: #52637b; --line: #d8e1ed;
  --accent: #165eb9; --selected: #e6f0ff;
  --green: #176440; --green-bg: #e4f5eb;
  --red: #a12636; --red-bg: #fce8eb;
  --amber: #77520c; --amber-bg: #fff2d3;
}
* { box-sizing: border-box; }
body { margin: 0; padding: 0; max-width: none; background: var(--bg);
  color: var(--text); font: 14px/1.6 system-ui, sans-serif; }
a { color: var(--accent); text-underline-offset: 3px; }
button, input, select { font: inherit; }
button, select, input:not([type="checkbox"]) {
  padding: .55rem .8rem; border: 1px solid var(--line); border-radius: 9px;
  background: var(--raised); color: var(--text); max-width: 100%;
}
button { cursor: pointer; font-weight: 600; }
button:hover { border-color: var(--accent); }
button:disabled { opacity: .55; cursor: wait; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
[hidden] { display: none !important; }
.app-header { background: var(--surface); border-bottom: 1px solid var(--line); }
.app-bar, .app-nav, main { max-width: 1240px; margin: auto; padding: 1rem 2rem; }
.app-bar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.brand { display: flex; align-items: center; gap: .8rem; text-decoration: none; color: var(--text); }
.brand-mark { display: grid; place-items: center; width: 38px; height: 38px;
  background: var(--selected); color: var(--accent); border: 1px solid var(--line); border-radius: 12px; }
.brand strong { font-size: 1.05rem; letter-spacing: -.025em; }
.brand small { display: block; font-size: .75rem; }
.app-nav { display: flex; gap: .35rem; padding-top: 0; padding-bottom: .7rem;
  overflow-x: auto; white-space: nowrap; }
.app-nav a { padding: .5rem .8rem; text-decoration: none; color: var(--muted); border-radius: 8px; }
.app-nav a:hover, .app-nav a[aria-current="page"] { color: var(--accent); background: var(--selected); }
.skip-link { position: absolute; left: 1rem; top: -100px; z-index: 10; padding: .8rem; background: var(--surface); }
.skip-link:focus { top: 1rem; }
main { padding-top: 1.6rem; padding-bottom: 3rem; min-width: 0; }
h1 { margin: 0 0 1.2rem; font-size: clamp(1.45rem, 3vw, 2rem); letter-spacing: -.04em; line-height: 1.3; }
h2 { margin: 0 0 .65rem; font-size: 1.05rem; letter-spacing: -.015em; }
p { margin: .65rem 0; }
small, .muted, .meta, .note, .measurement-note, #summary, #status,
#historyInfo, .wan-info, #consumptionInfo, #message { color: var(--muted); }
.note, .measurement-note, .wan-info, #historyInfo { font-size: .8rem; }
.panel, .card, .group, .history, .wan-panel, main > section {
  background: var(--surface); border: 1px solid var(--line); border-radius: 14px;
  padding: 1.1rem 1.25rem; box-shadow: 0 4px 18px #00000008;
}
main > section, .history { margin: 1rem 0; }
.cards, .summary, .consumption-summary { display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: .8rem; margin: 1rem 0; }
.summary > div, .consumption-summary > div, .wan-card {
  background: var(--raised); border: 1px solid var(--line); border-radius: 10px; padding: .8rem 1rem;
}
.card span, .summary span, .summary strong, .consumption-summary span,
.consumption-summary strong, .wan-card strong, .wan-card span { display: block; }
.card span, .card h2, .summary span, .consumption-summary span, .wan-card strong {
  color: var(--muted); font-size: .8rem; font-weight: 500;
}
.card strong, .summary strong, .consumption-summary strong, .wan-card span {
  font-size: 1.45rem; font-weight: 700; font-variant-numeric: tabular-nums; overflow-wrap: anywhere;
}
.wan-heading, .controls, .history-controls { display: flex; align-items: center;
  justify-content: space-between; flex-wrap: wrap; gap: .75rem; }
.wan-heading p { margin: .15rem 0 0; color: var(--muted); font-size: .85rem; }
.wan-rates { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .8rem; margin: 1rem 0; }
.wan-download { border-left: 3px solid #1677ff; }
.wan-upload { border-left: 3px solid #e67e22; }
.wan-live-badge, .badge, .new-device-badge { display: inline-flex; align-items: center; gap: .4rem;
  border-radius: 99px; padding: .25rem .65rem; font-size: .75rem; font-weight: 600;
  color: var(--muted); background: var(--raised); }
.wan-live-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.wan-live-badge, .badge[data-state="ok"], #internetStatus[data-state="ok"], .state {
  color: var(--green); background: var(--green-bg);
}
.badge[data-state="warn"], .new-device-badge { color: var(--amber); background: var(--amber-bg); }
.new-device-badge { margin-left: .45rem; }
#internetStatus { margin: .8rem 0; padding: .7rem 1rem; border-radius: 10px; }
#internetStatus[data-state="down"] { color: var(--red); background: var(--red-bg); }
#internetStatus[data-state="pending"] { color: var(--muted); background: var(--raised); }
details { margin-bottom: 1rem; color: var(--muted); }
summary { cursor: pointer; }
#status { margin: 1rem 0 .7rem; font-size: .85rem; }
.table-wrap, .consumption-table-wrap { max-width: 100%; overflow-x: auto;
  border: 1px solid var(--line); border-radius: 12px; background: var(--surface); }
table { width: 100%; min-width: 760px; border-collapse: collapse; background: var(--surface); }
th, td { padding: .8rem .9rem; text-align: left; border-bottom: 1px solid var(--line); }
th { color: var(--muted); background: var(--raised); font-size: .75rem; font-weight: 600; }
td { font-size: .85rem; }
td:first-child { font-weight: 600; }
td:last-child { white-space: nowrap; }
#devices > tr:not(.history-expansion-row) { cursor: pointer; }
#devices > tr:not(.history-expansion-row):hover, .device-selected-row { background: var(--selected); }
.new-device-row td:first-child { border-left: 3px solid var(--amber); }
.delete-device-button { color: var(--red); }
.history-expansion-row > td { padding: .7rem; background: var(--bg); white-space: normal; }
.history-expansion-row .history { margin: 0; }
.history-selected { font-weight: 600; }
.history-controls { margin: .8rem 0; }
.history-controls label, .controls label { display: flex; align-items: center; gap: .5rem; }
.legend { display: flex; gap: 1rem; font-size: .8rem; margin: .6rem 0; }
.legend span::before { content: ''; display: inline-block; width: 8px; height: 8px;
  border-radius: 50%; margin-right: .4rem; background: #1677ff; }
.legend span:last-child::before { background: #e67e22; }
.wan-chart-wrap { position: relative; }
.chart-scroll { overflow-x: auto; }
#wanChart, #historyChart, #qualityChart { display: block; width: 100%; min-width: 620px; height: auto; }
svg text { fill: var(--muted); }
svg line { stroke: var(--line); }
.chart-tooltip rect { fill: var(--surface); stroke: var(--line); }
.chart-tooltip text { fill: var(--text); }
.wan-tooltip { display: none; position: absolute; z-index: 2; pointer-events: none;
  min-width: 185px; padding: .6rem .8rem; font-size: .8rem; color: var(--text);
  background: var(--surface); border: 1px solid var(--line); border-radius: 10px; box-shadow: 0 6px 24px #0003; }
.wan-tooltip-time { font-weight: 600; margin-bottom: .2rem; }
.groups { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 250px), 1fr)); gap: 1rem; }
.router { width: fit-content; text-align: center; padding: 1rem 2rem; margin: 0 auto 1.5rem;
  border: 1px solid var(--line); border-radius: 14px; background: var(--selected); }
.device { padding: .75rem; border: 1px solid var(--line); border-radius: 9px; margin: .6rem 0; }
.name { font-weight: 600; }
.meta { display: block; font-size: .8rem; overflow-wrap: anywhere; }
.state { float: right; border-radius: 6px; padding: 0 .3rem; font-size: .75rem; }
.inactive .state { color: var(--muted); background: var(--raised); }
.settings-content { max-width: 820px; }
.settings-content label { display: block; margin: .9rem 0 .25rem; }
.settings-content input:not([type="checkbox"]), .settings-content select { width: 100%; }
.settings-content button { margin: 1rem .5rem 0 0; }
.settings-content .check-row { display: flex; align-items: center; gap: .6rem; }
li { margin: .5rem 0; overflow-wrap: anywhere; }
@media (max-width: 700px) {
  .app-bar, .app-nav, main { padding-left: 1rem; padding-right: 1rem; }
  main { padding-top: 1.1rem; }
  .brand small { display: none; }
  .panel, .card, .group, .history, .wan-panel, main > section { padding: .85rem; }
  .cards, .summary, .consumption-summary { grid-template-columns: 1fr; }
  .wan-card { padding: .7rem; }
  .wan-card span { font-size: 1.15rem; }
  .wan-heading { align-items: flex-start; }
  th, td { padding: .65rem; }
}
/* Equipment-first dashboard. Scoped classes preserve the other pages. */
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }
.dashboard-heading { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin: .2rem 0 1.4rem; }
.eyebrow { color: var(--accent); font-size: .66rem; font-weight: 750; letter-spacing: .15em; margin: 0 0 .35rem; }
.dashboard-heading h1 { margin: 0; font-size: clamp(1.8rem, 3.5vw, 2.3rem); }
.dashboard-subtitle { color: var(--muted); font-size: .9rem; margin: .4rem 0 0; }
#refreshDevices { display: inline-flex; align-items: center; gap: .55rem; white-space: nowrap; background: var(--surface); }
#refreshDevices > span { font-size: 1.2rem; line-height: 1; }
.network-health { display: flex; justify-content: space-between; align-items: center; gap: 1rem; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: .15rem 1rem; }
.network-health #internetStatus { margin: .6rem 0; padding: 0; background: transparent; font-size: .82rem; }
.network-health > a { font-size: .78rem; white-space: nowrap; text-decoration: none; }
.network-overview { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .8rem; margin: 1rem 0 1.6rem; }
.overview-card { display: flex; flex-direction: column; text-align: left; gap: .4rem; background: var(--surface); border: 1px solid var(--line); padding: 1rem 1.15rem; border-radius: 13px; color: var(--text); font-weight: 400; }
.overview-card[aria-pressed="true"] { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
.overview-label { display: flex; align-items: center; gap: .45rem; color: var(--muted); font-size: .8rem; }
.overview-card strong { font-size: 2rem; letter-spacing: -.05em; line-height: 1.3; font-weight: 650; font-variant-numeric: tabular-nums; }
.overview-foot { display: flex; justify-content: space-between; gap: .3rem; font-size: .7rem; color: var(--muted); width: 100%; }
.status-dot { display: inline-block; width: 6px; height: 6px; flex: 0 0 6px; background: var(--muted); border-radius: 50%; }
.status-dot.online { background: var(--green); box-shadow: 0 0 0 3px var(--green-bg); }
.status-dot.recent { background: var(--amber); }
main > .equipment-panel { padding: 0; overflow: hidden; }
.equipment-heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 1.25rem 1.3rem 1rem; }
.equipment-heading h2 { font-size: 1.15rem; margin: 0; display: flex; align-items: center; gap: .6rem; }
.count-pill { padding: .05rem .5rem; background: var(--raised); color: var(--muted); font-size: .72rem; border-radius: 6px; }
.view-switch { display: flex; padding: 3px; border: 1px solid var(--line); border-radius: 9px; background: var(--bg); }
.view-switch button { padding: .3rem .65rem; border: 0; background: transparent; color: var(--muted); font-size: .75rem; border-radius: 6px; }
.view-switch button[aria-pressed="true"] { background: var(--raised); color: var(--text); }
.equipment-tools { display: flex; flex-wrap: wrap; gap: .5rem; padding: 0 1.3rem 1rem; }
.device-search { position: relative; flex: 1 1 250px; display: flex; min-width: 180px; }
.device-search > span[aria-hidden] { position: absolute; left: .75rem; top: .28rem; color: var(--muted); font-size: 1.25rem; pointer-events: none; }
.device-search input { width: 100%; padding-left: 2.1rem; background: var(--bg); }
.device-search input::placeholder { color: var(--muted); opacity: 1; }
.equipment-tools select { font-size: .78rem; padding: .65rem .6rem; height: 42px; background: var(--surface); }
.equipment-tools input { height: 42px; font-size: .8rem; }
.equipment-filter-line { padding: 0 1.3rem .7rem; display: flex; gap: .6rem; justify-content: space-between; align-items: center; }
.device-tabs { display: flex; gap: .25rem; overflow-x: auto; }
.device-tabs button { background: transparent; color: var(--muted); border: 1px solid transparent; font-size: .78rem; font-weight: 500; padding: .4rem .65rem; white-space: nowrap; }
.device-tabs button[aria-pressed="true"] { background: var(--selected); color: var(--accent); border-color: var(--line); }
#favoriteCount { margin-left: .25rem; font-size: .7rem; }
.quiet-button { background: transparent; color: var(--muted); border: 0; padding: .35rem 0; font-size: .75rem; white-space: nowrap; }
.device-results { margin: 0; padding: .3rem 1.3rem .8rem; color: var(--muted); font-size: .74rem; }
.equipment-table-wrap { overflow-x: auto; }
.equipment-table { min-width: 820px; }
.equipment-table th { position: relative; font-size: .7rem; padding: .65rem 1rem; border-top: 1px solid var(--line); }
.equipment-table td { padding: .85rem 1rem; font-size: .78rem; font-variant-numeric: tabular-nums; }
.equipment-table th:first-child, .equipment-table td:first-child { padding-left: 1.3rem; }
.equipment-table tr:last-child td { border-bottom: 0; }
.equipment-table td.equipment-name-cell { min-width: 250px; max-width: 340px; }
.device-open { display: inline-flex; align-items: center; gap: .7rem; border: 0; background: transparent; padding: 0; text-align: left; max-width: 100%; color: var(--text); vertical-align: middle; }
.equipment-icon { display: grid; place-items: center; background: var(--raised); color: var(--accent); border: 1px solid var(--line); border-radius: 11px; width: 38px; height: 38px; flex: 0 0 38px; }
.equipment-identity { min-width: 0; }
.equipment-identity strong { display: block; font-weight: 600; font-size: .83rem; overflow-wrap: anywhere; }
.equipment-identity small { display: block; font-size: .7rem; font-weight: 400; margin-top: .15rem; overflow-wrap: anywhere; }
.equipment-name-cell .new-device-badge { font-size: .57rem; padding: .05rem .4rem; margin-left: 3rem; margin-top: .4rem; }
.device-state-badge { display: inline-flex; align-items: center; gap: .45rem; font-size: .73rem; color: var(--muted); white-space: nowrap; }
.device-state-badge.is-online { color: var(--green); }
.equipment-connection { color: var(--muted); white-space: nowrap; }
.equipment-ip { font-family: ui-monospace, monospace; white-space: nowrap; }
.equipment-rate { white-space: nowrap; }
.favorite-button { padding: .1rem .35rem; font-size: 1.35rem; line-height: 1.2; color: var(--muted); border: 1px solid transparent; background: transparent; }
.favorite-button[aria-pressed="true"] { color: var(--amber); }
.equipment-empty { text-align: center; padding: 2rem 1rem 2.5rem; }
.equipment-empty > span { font-size: 2.5rem; color: var(--muted); }
.equipment-empty h3 { font-size: 1rem; margin: .5rem 0; }
.equipment-empty p { color: var(--muted); font-size: .85rem; }
.equipment-footer { display: flex; justify-content: space-between; gap: 1rem; padding: .75rem 1.3rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .7rem; }
.equipment-footer #status { margin: 0; font-size: inherit; }
.equipment-footer #status[data-state="error"] { color: var(--amber); }
.equipment-footer > span:last-child { white-space: nowrap; }
.traffic-disclosure { border: 1px solid var(--line); border-radius: 13px; background: var(--surface); margin: 1.2rem 0; color: var(--text); }
.traffic-disclosure > summary { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 1rem 1.3rem; list-style: none; }
.traffic-disclosure > summary::-webkit-details-marker { display: none; }
.traffic-disclosure > summary strong { display: block; font-size: .9rem; font-weight: 600; }
.traffic-disclosure > summary small { display: block; font-size: .73rem; margin-top: .15rem; }
.disclosure-action { color: var(--accent); font-size: .75rem; white-space: nowrap; }
.traffic-disclosure[open] > summary { border-bottom: 1px solid var(--line); }
.traffic-disclosure .wan-panel { margin: 0; border: 0; box-shadow: none; background: transparent; }
.alerts-disclosure { font-size: .8rem; padding: .3rem 0; }
body:has(.device-dialog[open]) { overflow: hidden; }
.device-dialog { position: fixed; inset: 0 0 0 auto; width: min(720px, 100%); height: 100dvh; max-width: 100%; max-height: 100dvh; margin: 0; padding: 0; border: 0; border-left: 1px solid var(--line); background: var(--bg); color: var(--text); overflow-y: auto; overscroll-behavior: contain; }
.device-dialog::backdrop { background: #02061799; backdrop-filter: blur(4px); }
.drawer-heading { position: sticky; top: 0; z-index: 3; display: flex; justify-content: space-between; gap: 1rem; padding: 1.25rem 1.5rem; background: var(--surface); border-bottom: 1px solid var(--line); }
.drawer-heading h2 { font-size: 1.35rem; margin: .1rem 0; overflow-wrap: anywhere; }
.drawer-heading p.muted { font-size: .8rem; margin: .3rem 0 0; }
.icon-button { flex: 0 0 36px; height: 36px; padding: 0; }
.drawer-content { padding: 1.25rem 1.5rem 2rem; }
.device-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem .75rem; padding-bottom: 1.25rem; }
.device-fact { min-width: 0; }
.device-fact span { display: block; color: var(--muted); font-size: .72rem; margin-bottom: .2rem; }
.device-fact strong { font-size: .86rem; font-weight: 550; overflow-wrap: anywhere; }
.profile-section { padding: 1.1rem; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; }
.profile-section h3 { font-size: 1rem; margin: 0; }
.profile-section p { font-size: .78rem; }
#deviceProfileForm label { display: block; font-size: .76rem; color: var(--muted); margin: .8rem 0 .3rem; }
#deviceProfileForm input { width: 100%; background: var(--bg); }
#deviceProfileForm select { width: 100%; min-height: 44px; background: var(--bg); }
.profile-custom-field { margin-top: .5rem; }
.profile-fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .7rem; }
.primary-button { background: var(--selected); color: var(--accent); border-color: var(--accent); }
#profileMessage, #deleteMessage { font-size: .78rem; margin-bottom: 0; }
#profileMessage:empty, #deleteMessage:empty { display: none; }
.device-dialog .history { padding: 1rem 0; border: 0; box-shadow: none; background: transparent; margin: 1rem 0; }
.device-dialog .history h2 { font-size: 1rem; }
.device-dialog .history-selected { color: var(--muted); font-size: .75rem; font-weight: 400; }
.device-dialog .history-controls { gap: .5rem; }
.device-dialog .history-controls label { font-size: .75rem; }
.device-dialog .measurement-note { font-size: .75rem; }
.device-dialog #historyChart { min-width: 560px; }
.device-danger { border-top: 1px solid var(--line); padding-top: 1rem; color: var(--muted); font-size: .78rem; }
.device-danger summary { color: var(--muted); }
/* The same semantic table becomes a card layout without duplicating data. */
.equipment-table[data-view="grid"], .equipment-table[data-view="grid"] tbody { display: block; min-width: 0; }
.equipment-table[data-view="grid"] thead { display: none; }
.equipment-table[data-view="grid"] tbody { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: .8rem; padding: .2rem 1.3rem 1.2rem; }
.equipment-table[data-view="grid"] tr { position: relative; display: grid; grid-template-columns: 1fr 1fr; border: 1px solid var(--line); border-radius: 12px; padding: 1rem; background: var(--bg); }
.equipment-table[data-view="grid"] td { display: block; border: 0; padding: .45rem 0; min-width: 0; }
.equipment-table[data-view="grid"] td.equipment-name-cell { grid-column: 1 / -1; max-width: none; min-width: 0; padding: 0 1.7rem .7rem 0; }
.equipment-table[data-view="grid"] .equipment-favorite { position: absolute; right: .6rem; top: .6rem; padding: 0; }
.equipment-table[data-view="grid"] td.equipment-ip::before,
.equipment-table[data-view="grid"] td.equipment-rate::before { content: attr(data-label); display: block; color: var(--muted); font: .65rem system-ui, sans-serif; margin-bottom: .2rem; }
.equipment-table[data-view="grid"] td.equipment-ip { grid-column: 1 / -1; display: flex; align-items: center; gap: .5rem; }
.equipment-table[data-view="grid"] td.equipment-ip::before { margin-bottom: 0; }
@media (max-width: 1000px) {
  .equipment-tools > label:not(.device-search) { flex: 1 1 130px; }
  .equipment-tools select { width: 100%; }
  .device-search { flex-basis: 100%; }
}
@media (max-width: 700px) {
  .dashboard-heading { align-items: flex-start; }
  .dashboard-subtitle { font-size: .8rem; max-width: 240px; }
  #refreshDevices { font-size: .73rem; padding: .45rem .6rem; margin-top: 1.7rem; }
  .network-health { align-items: flex-start; flex-direction: column; gap: 0; padding: .65rem .8rem; }
  .network-health #internetStatus { margin: 0 0 .4rem; }
  .network-health > a { font-size: .72rem; }
  .network-overview { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .6rem; margin-bottom: 1.1rem; }
  .overview-card { padding: .8rem; gap: .25rem; }
  .overview-card strong { font-size: 1.65rem; }
  .overview-label { font-size: .72rem; }
  .overview-foot { font-size: .62rem; }
  main > .equipment-panel { padding: 0; }
  .equipment-heading { padding: 1rem .85rem .8rem; }
  .equipment-heading h2 { font-size: 1.05rem; }
  .view-switch { display: none; }
  .equipment-tools { padding: 0 .85rem .8rem; gap: .4rem; }
  .equipment-tools > label:not(.device-search) { flex: 1 1 calc(50% - .4rem); min-width: 0; }
  .equipment-tools select { font-size: .73rem; }
  .equipment-filter-line { display: block; padding: 0 .65rem .4rem; }
  .device-tabs button { padding: .4rem .55rem; font-size: .72rem; }
  .quiet-button { margin: .3rem .2rem; }
  .device-results { padding: .3rem .85rem .8rem; font-size: .68rem; }
  .equipment-table, .equipment-table tbody { display: block; min-width: 0; }
  .equipment-table thead { display: none; }
  .equipment-table tbody, .equipment-table[data-view="grid"] tbody { display: grid; grid-template-columns: 1fr; gap: .6rem; padding: 0 .85rem 1rem; }
  .equipment-table tr { position: relative; display: grid; grid-template-columns: 1fr 1fr; border: 1px solid var(--line); border-radius: 12px; padding: .85rem; background: var(--bg); }
  .equipment-table td { display: block; border: 0; padding: .4rem 0; min-width: 0; }
  .equipment-table td.equipment-name-cell { grid-column: 1 / -1; max-width: none; min-width: 0; padding: 0 1.7rem .6rem 0; }
  .equipment-table .equipment-favorite { position: absolute; right: .6rem; top: .6rem; padding: 0; }
  .equipment-table td.equipment-ip::before, .equipment-table td.equipment-rate::before { content: attr(data-label); display: block; color: var(--muted); font: .65rem system-ui, sans-serif; margin-bottom: .2rem; }
  .equipment-table td.equipment-ip { grid-column: 1 / -1; display: flex; align-items: center; gap: .5rem; }
  .equipment-table td.equipment-ip::before { margin-bottom: 0; }
  .equipment-table .favorite-button { width: 44px; height: 44px; }
  .equipment-table .equipment-favorite { top: .2rem; right: .2rem; }
  .equipment-table td.equipment-name-cell { padding-right: 2.5rem; }
  .equipment-footer { display: block; padding: .7rem .85rem; }
  .equipment-footer > span { display: block; }
  .equipment-footer > span:last-child { margin-top: .2rem; opacity: .8; }
  .traffic-disclosure > summary { padding: .85rem; }
  .disclosure-action { font-size: .68rem; }
  .traffic-disclosure > summary small { max-width: 170px; }
  .drawer-heading { padding: 1rem; }
  .drawer-content { padding: 1rem; }
  .drawer-heading h2 { font-size: 1.15rem; }
  .device-fact strong { font-size: .8rem; }
}
@media (prefers-reduced-motion: no-preference) {
  .overview-card, .favorite-button { transition: border-color .15s, background-color .15s; }
  .device-dialog[open] { animation: drawer-in .2s ease-out; }
  @keyframes drawer-in { from { transform: translateX(30px); opacity: .5; } to { transform: translateX(0); opacity: 1; } }
}

/* Household views: presence, opt-in monitoring and grouped consumption. */
.device-alert-banner { border-color: var(--amber); background: var(--surface); }
.device-alert-banner .eyebrow { color: var(--amber); }
.device-alert-banner h2 { font-size: 1rem; }
.device-alert-banner p:not(.eyebrow) { color: var(--muted); font-size: .8rem; }
#deviceAlertList { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .8rem; }
.alert-device-link { display: flex; flex-direction: column; text-align: left; gap: .15rem; background: var(--amber-bg); border-color: var(--amber); color: var(--amber); }
.alert-device-link span { font-size: .7rem; font-weight: 400; }
.watched-device-badge { display: inline-block; font-size: .6rem; margin-left: .5rem; color: var(--accent); }
.drawer-feature { margin: 1rem 0; padding: 1rem; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; color: var(--text); }
.drawer-feature > summary { display: flex; justify-content: space-between; align-items: center; gap: .7rem; font-weight: 600; list-style: none; }
.drawer-feature > summary::-webkit-details-marker { display: none; }
.drawer-feature > summary small { display: block; color: var(--muted); font-size: .72rem; font-weight: 400; margin-top: .2rem; }
.drawer-feature p { font-size: .75rem; }
#deviceWatchForm fieldset { margin: 0; padding: 0; border: 0; min-width: 0; }
#deviceWatchForm label { display: block; color: var(--text); margin: .75rem 0 .35rem; font-size: .8rem; }
#deviceWatchForm .check-row { display: flex; align-items: flex-start; gap: .6rem; }
#deviceWatchForm input[type="checkbox"] { flex: 0 0 auto; margin: .3rem 0 0; }
#watchDelay { width: 100%; }
#watchMessage { font-size: .78rem; color: var(--muted); }
#watchMessage:empty { display: none; }
.watch-incidents { padding-left: 1rem; max-height: 220px; overflow-y: auto; }
.watch-incidents:empty { display: none; }
.watch-incidents strong, .watch-incidents small { display: block; font-size: .72rem; }
.presence-panel { padding: 1rem 0; margin-top: 1rem; }
.presence-heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .6rem; }
.presence-heading h3 { font-size: 1rem; margin: 0; }
.presence-heading select { font-size: .75rem; }
.presence-panel > p { font-size: .75rem; }
#devicePresenceInfo { color: var(--muted); font-size: .72rem; }
.device-timeline { max-height: 260px; overflow-y: auto; list-style: none; padding: 0 .5rem 0 1.15rem; margin: .8rem 0 0; }
.device-timeline li { position: relative; margin: 0; padding: 0 0 1rem 1rem; border-left: 1px solid var(--line); }
.device-timeline li::before { content: ''; position: absolute; width: 7px; height: 7px; left: -4px; top: .35rem; background: var(--muted); border: 2px solid var(--bg); border-radius: 50%; box-sizing: content-box; }
.device-timeline li.presence-connected::before { background: var(--green); }
.device-timeline strong { display: block; font-size: .78rem; font-weight: 550; }
.device-timeline time, .device-timeline small { display: block; font-size: .7rem; color: var(--muted); }
.consumption-share { width: 100%; min-width: 60px; max-width: 180px; height: 4px; background: var(--raised); border-radius: 9px; overflow: hidden; margin: .45rem 0; }
.consumption-share span { display: block; height: 100%; background: var(--accent); border-radius: inherit; }
.consumption-tools { display: flex; flex-wrap: wrap; gap: .5rem; margin: .8rem 0; }
.consumption-page-heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.consumption-page-heading h1 { margin-bottom: .4rem; }
@media (max-width: 700px) {
  .consumption-page-heading { align-items: flex-start; }
  .consumption-page-heading button { font-size: .75rem; }
  .alert-device-link { width: 100%; }
  .device-tabs { scrollbar-width: thin; }
  .equipment-tools select, #deviceProfileForm select, #deviceProfileForm input { font-size: 16px; min-height: 44px; }
  .profile-fields { grid-template-columns: minmax(0, 1fr); }
}

/* Identity: a precise emblem, quiet controls and a single account space. */
.brand-logo { display: block; flex: 0 0 auto; filter: drop-shadow(0 3px 7px #00122228); }
.brand { gap: .7rem; }
.brand strong { font-size: 1.4rem; font-weight: 700; letter-spacing: -.04em; line-height: 1.15; white-space: nowrap; }
.brand small { font-size: .69rem; letter-spacing: .025em; }
.header-actions { display: flex; align-items: center; gap: .65rem; flex: 0 0 auto; }
.theme-toggle { position: relative; display: grid; place-items: center; width: 42px; height: 42px; padding: 0; border-radius: 50%; background: var(--bg); color: var(--accent); border: 1px solid var(--line); }
.theme-toggle:hover { background: var(--selected); }
.theme-toggle::after { content: attr(data-tooltip); position: absolute; top: calc(100% + 10px); right: 0; padding: .35rem .65rem; border-radius: 7px; border: 1px solid var(--line); background: var(--surface); color: var(--text); font-size: .7rem; white-space: nowrap; opacity: 0; pointer-events: none; z-index: 10; visibility: hidden; }
.theme-toggle:hover::after, .theme-toggle:focus-visible::after { opacity: 1; visibility: visible; }
.theme-sun, .theme-moon { transform-origin: 12px 12px; }
.theme-moon { opacity: 0; transform: rotate(-35deg) scale(.6); }
:root[data-theme="light"] .theme-sun { opacity: 0; transform: rotate(70deg) scale(.6); }
:root[data-theme="light"] .theme-moon { opacity: 1; transform: rotate(0) scale(1); }
.header-account-menu { position: relative; margin: 0; color: var(--text); }
.header-account-menu > summary { display: flex; align-items: center; gap: .6rem; list-style: none; font-size: .8rem; padding: 3px 8px 3px 3px; border: 1px solid transparent; border-radius: 99px; }
.header-account-menu > summary::-webkit-details-marker { display: none; }
.header-account-menu[open] > summary, .header-account-menu > summary:hover { background: var(--raised); border-color: var(--line); }
.header-avatar { display: grid; place-items: center; width: 34px; height: 34px; border: 1px solid var(--line); border-radius: 50%; background: var(--selected); color: var(--accent); font-size: .72rem; font-weight: 650; }
#headerAccountName { max-width: 145px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.account-popover { position: absolute; top: calc(100% + 12px); right: 0; width: 230px; padding: .55rem; background: var(--surface); border: 1px solid var(--line); border-radius: 13px; box-shadow: 0 14px 42px #0003; z-index: 12; }
.popover-label { display: block; color: var(--muted); font-size: .6rem; letter-spacing: .12em; padding: .5rem .6rem; }
.account-popover a, .account-popover button { display: flex; justify-content: space-between; width: 100%; text-align: left; font-size: .8rem; border: 0; background: transparent; color: var(--text); padding: .6rem; border-radius: 7px; text-decoration: none; font-weight: 500; }
.account-popover a:hover, .account-popover button:hover { background: var(--raised); }
.account-popover button { color: var(--red); }
#headerLogoutMessage { color: var(--red); font-size: .7rem; padding: 0 .6rem; margin: .3rem 0; }
#headerLogoutMessage:empty { display: none; }
.account-page-heading { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin: .4rem 0 1.7rem; }
.account-page-heading h1 { margin-bottom: .35rem; }
.account-page-heading p { margin: .3rem 0; }
.owner-badge { display: inline-flex; align-items: center; width: fit-content; white-space: nowrap; padding: .3rem .65rem; border-radius: 99px; color: var(--accent); border: 1px solid var(--line); background: var(--selected); font-size: .7rem; }
.account-layout { display: grid; grid-template-columns: 260px minmax(0, 1fr); align-items: start; gap: 1.25rem; }
.account-identity { position: sticky; top: 1.25rem; padding: 1.5rem 1.2rem; border: 1px solid var(--line); border-radius: 15px; background: var(--surface); }
.account-large-avatar { display: grid; place-items: center; width: 70px; height: 70px; border: 1px solid var(--line); border-radius: 22px; background: var(--selected); color: var(--accent); font-size: 1.4rem; font-weight: 600; margin-bottom: 1rem; }
.account-identity h2 { font-size: 1.1rem; overflow-wrap: anywhere; margin: 0; }
.account-identity > p { font-size: .8rem; overflow-wrap: anywhere; }
.account-section-nav { display: grid; gap: .35rem; margin: 1.5rem -.4rem; }
.account-section-nav a { display: flex; justify-content: space-between; gap: .5rem; text-decoration: none; font-size: .8rem; color: var(--muted); padding: .5rem .4rem; border-radius: 7px; }
.account-section-nav a:hover { color: var(--accent); background: var(--raised); }
.account-sections { display: grid; gap: 1rem; }
.account-section { padding: 1.35rem 1.5rem; border: 1px solid var(--line); background: var(--surface); border-radius: 15px; scroll-margin-top: 1.5rem; }
.account-section-title { display: flex; align-items: flex-start; gap: .8rem; margin-bottom: 1.1rem; }
.account-section-title h2 { margin: .1rem 0; font-size: 1rem; }
.account-section-title p { margin: .25rem 0 0; font-size: .78rem; }
.account-section-number { display: grid; place-items: center; flex: 0 0 30px; width: 30px; height: 30px; border-radius: 9px; border: 1px solid var(--line); color: var(--accent); background: var(--bg); font-size: .65rem; }
.account-section fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
.account-section label, .login-card label { display: block; color: var(--text); font-size: .8rem; margin: .9rem 0 .35rem; }
.account-section input:not([type="checkbox"]), .login-card input:not([type="checkbox"]) { width: 100%; background: var(--bg); padding: .7rem .85rem; border-radius: 9px; }
.account-section input:disabled { opacity: .6; }
.account-form-actions { display: flex; align-items: center; flex-wrap: wrap; gap: .6rem 1rem; margin-top: 1.1rem; }
.account-primary { display: inline-flex; align-items: center; justify-content: center; gap: .6rem; color: var(--bg); background: var(--accent); border: 1px solid var(--accent); padding: .65rem .9rem; border-radius: 9px; font-size: .8rem; font-weight: 650; }
.account-primary:hover { filter: brightness(1.07); }
:root[data-theme="light"] .account-primary { color: white; }
.field-hint { color: var(--muted); font-size: .72rem; line-height: 1.6; }
.optional-label { color: var(--muted); font-size: .69rem; font-weight: 400; margin-left: .2rem; }
.password-field { position: relative; display: flex; align-items: center; }
.password-field input { padding-right: 5rem !important; }
.password-field button { position: absolute; right: .45rem; padding: .35rem .4rem; border: 0; background: transparent; color: var(--muted); font-size: .67rem; font-weight: 500; }
.password-field button:hover { color: var(--accent); }
.password-length { display: flex; align-items: center; gap: .7rem; margin-top: .55rem; }
.password-length meter { width: 80px; height: 5px; flex: 0 0 80px; appearance: none; }
.password-length meter::-webkit-meter-bar { background: var(--raised); border: 0; border-radius: 99px; }
.password-length meter::-webkit-meter-optimum-value { background: var(--accent); border-radius: 99px; }
.password-length span { color: var(--muted); font-size: .67rem; }
.account-security-note { color: var(--muted); font-size: .75rem; padding: .7rem .8rem; background: var(--bg); border-left: 2px solid var(--accent); border-radius: 0 7px 7px 0; margin-top: 1rem; }
.form-message { color: var(--red); font-size: .78rem; margin: .5rem 0; overflow-wrap: anywhere; }
.form-message[data-state="success"] { color: var(--green); }
.form-notice { border: 1px solid var(--line); border-radius: 9px; padding: .8rem 1rem; background: var(--green-bg); color: var(--green); font-size: .8rem; margin: 0 0 1.2rem; }
.owner-session { display: flex; align-items: flex-start; gap: .75rem; padding: 1rem 0; border-top: 1px solid var(--line); }
.session-symbol { display: grid; place-items: center; width: 34px; height: 34px; flex: 0 0 34px; border: 1px solid var(--line); background: var(--raised); color: var(--accent); border-radius: 10px; }
.session-description { flex: 1; min-width: 0; }
.session-title { display: flex; align-items: center; flex-wrap: wrap; gap: .45rem; }
.session-title strong { font-size: .8rem; font-weight: 550; overflow-wrap: anywhere; }
.current-session-badge { font-size: .6rem; padding: .1rem .4rem; border-radius: 5px; color: var(--green); background: var(--green-bg); white-space: nowrap; }
.session-description p { margin: .3rem 0 .2rem; color: var(--muted); font-size: .72rem; }
.session-description small { font-size: .65rem; }
.owner-session button { flex: 0 0 auto; font-size: .7rem; color: var(--red); }
.account-session-footer { border-top: 1px solid var(--line); padding-top: .8rem; }
.account-session-footer > button { font-size: .75rem; }
/* Sign-in is intentionally spacious; the application remains information-dense. */
.login-content { max-width: 1180px; }
.login-layout { min-height: calc(100dvh - 150px); display: grid; grid-template-columns: 1fr .9fr; align-items: center; gap: 4rem; padding: 1.5rem 0 3rem; }
.login-story { padding: 1rem 0; min-width: 0; }
.login-story h1 { margin: .8rem 0 1rem; font-size: clamp(1.8rem, 3vw, 2.65rem); line-height: 1.25; letter-spacing: -.045em; }
.login-story h1 span { color: var(--muted); }
.login-story > p:not(.eyebrow) { color: var(--muted); font-size: .9rem; max-width: 410px; }
.brand-orbit { position: relative; height: 270px; width: 300px; max-width: 100%; display: grid; place-items: center; margin: 1rem auto; }
.brand-orbit img { z-index: 1; filter: drop-shadow(0 15px 25px #07283c55); }
.orbit-ring { position: absolute; border: 1px solid var(--line); border-radius: 50%; aspect-ratio: 1; }
.orbit-one { width: 150px; border-color: var(--accent); opacity: .35; }
.orbit-two { width: 220px; }
.orbit-three { width: 270px; opacity: .4; }
.orbit-node { position: absolute; width: 8px; height: 8px; background: var(--accent); border: 3px solid var(--bg); box-sizing: content-box; border-radius: 50%; }
.node-a { top: 36px; right: 76px; }
.node-b { left: 27px; bottom: 78px; background: var(--green); }
.node-c { right: 75px; bottom: 64px; width: 5px; height: 5px; }
.login-values { display: flex; flex-wrap: wrap; align-items: center; gap: .7rem 1.4rem; font-size: .7rem; color: var(--muted); }
.login-values span { display: inline-flex; align-items: center; gap: .5rem; }
.login-card { background: var(--surface); padding: 2rem; border: 1px solid var(--line); border-radius: 20px; box-shadow: 0 18px 50px #0000000d; }
.login-card-symbol { display: grid; place-items: center; width: 40px; height: 40px; border: 1px solid var(--line); border-radius: 13px; background: var(--selected); color: var(--accent); margin-bottom: 1.6rem; font-size: 1.3rem; }
.login-card h2 { font-size: 1.55rem; margin: .4rem 0 .35rem; letter-spacing: -.04em; }
.login-card > p.muted { font-size: .82rem; margin-bottom: 1.5rem; }
.login-card .account-check { display: flex; align-items: flex-start; gap: .6rem; color: var(--muted); font-size: .74rem; margin: 1rem 0; }
.account-check input { flex: 0 0 auto; margin: .3rem 0 0; accent-color: var(--accent); }
.login-card .account-primary { display: flex; justify-content: space-between; width: 100%; margin-top: 1.2rem; padding: .8rem 1rem; }
.login-help { margin: 1.3rem 0; border-top: 1px solid var(--line); padding-top: 1rem; font-size: .73rem; }
.login-help p { color: var(--muted); }
.login-footnote { font-size: .65rem; color: var(--muted); margin: 1.5rem 0 0; text-align: center; }
@media (max-width: 900px) {
  .account-layout { grid-template-columns: 210px minmax(0,1fr); }
  .account-section { padding: 1.1rem; }
  .login-layout { gap: 2rem; }
  .login-card { padding: 1.5rem; }
}
@media (max-width: 700px) {
  .brand-logo { width: 38px; height: 38px; }
  .brand { gap: .5rem; }
  .brand strong { font-size: clamp(1rem, 4.6vw, 1.2rem); }
  .header-actions { gap: .35rem; }
  .theme-toggle { width: 38px; height: 38px; }
  #headerAccountName, .header-account-menu summary > svg { display: none; }
  .header-account-menu > summary { padding: 0; }
  .header-avatar { width: 36px; height: 36px; }
  .account-popover { width: 220px; }
  .account-page-heading { align-items: flex-start; flex-direction: column; gap: .4rem; margin-bottom: 1.2rem; }
  .account-page-heading > .owner-badge { display: none; }
  .account-layout { grid-template-columns: minmax(0,1fr); gap: 1rem; }
  .account-identity { position: static; padding: 1rem; }
  .account-large-avatar { width: 52px; height: 52px; border-radius: 16px; font-size: 1.05rem; margin-bottom: .7rem; }
  .account-section-nav { display: flex; flex-wrap: wrap; margin: 1rem 0 0; gap: .2rem .8rem; }
  .account-section-nav a { font-size: .72rem; padding: .3rem 0; gap: .3rem; }
  #accountCreated { display: none; }
  .account-section { padding: 1rem; }
  .account-section-title { gap: .6rem; }
  .owner-session { flex-wrap: wrap; gap: .6rem; }
  .owner-session > button { margin-left: 2.7rem; }
  .password-length { align-items: flex-start; }
  .password-length meter { margin-top: .3rem; }
  .optional-label { display: block; margin: .2rem 0 0; }
  .login-layout { grid-template-columns: minmax(0,1fr); gap: 1rem; padding: .5rem 0 2rem; min-height: 0; }
  .login-story { padding: .5rem .3rem; }
  .login-story h1 { font-size: 1.65rem; margin: .5rem 0; }
  .login-story > p:not(.eyebrow), .brand-orbit, .login-values { display: none; }
  .login-card { padding: 1.35rem; border-radius: 16px; }
  .login-card-symbol { display: none; }
  .login-card h2 { font-size: 1.35rem; }
}
@media (prefers-reduced-motion: no-preference) {
  .theme-sun, .theme-moon { transition: transform .3s ease, opacity .2s ease; }
  .theme-toggle { transition: background-color .2s, border-color .2s; }
}

"""

LOGIN_PAGE = r"""
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Connexion — Livebox Sentinel</title></head><body>
<div class="login-layout">
  <section class="login-story" aria-labelledby="loginStoryTitle">
    <p class="eyebrow">UN REGARD SUR VOTRE RÉSEAU</p><h1 id="loginStoryTitle">Votre maison connectée.<br><span>Simplement, sous vos yeux.</span></h1>
    <p>Retrouvez vos équipements, comprenez leur activité et veillez sur ceux qui comptent.</p>
    <div class="brand-orbit" aria-hidden="true"><div class="orbit-ring orbit-one"></div><div class="orbit-ring orbit-two"></div><div class="orbit-ring orbit-three"></div><i class="orbit-node node-a"></i><i class="orbit-node node-b"></i><i class="orbit-node node-c"></i><img src="/assets/sentinel.svg" width="100" height="100" alt=""></div>
    <div class="login-values"><span><i class="status-dot online"></i> Votre réseau en un coup d’œil</span><span>Vos données sur votre serveur</span></div>
  </section>
  <section class="login-card" aria-labelledby="loginTitle"><span class="login-card-symbol" aria-hidden="true">↗</span><p class="eyebrow">VOTRE ESPACE PERSONNEL</p><h2 id="loginTitle">Bienvenue chez vous.</h2><p class="muted">Connectez-vous pour retrouver votre réseau.</p>
    <p id="loginNotice" class="form-notice" role="status" hidden></p>
    <form id="loginForm">
      <label for="loginUsername">Identifiant</label><input id="loginUsername" name="username" autocomplete="username" maxlength="80" required autofocus placeholder="Votre identifiant">
      <label for="loginPassword">Mot de passe</label><div class="password-field"><input id="loginPassword" name="password" type="password" autocomplete="current-password" maxlength="1024" required placeholder="Votre mot de passe"><button type="button" data-toggle-password="loginPassword" aria-pressed="false" aria-label="Afficher le mot de passe">Afficher</button></div>
      <p id="capsLockHint" class="field-hint" hidden>Le verrouillage des majuscules est activé.</p>
      <details id="loginFactor" class="login-help"><summary>J’utilise un second facteur</summary><label for="loginOtp">Code d’authentification</label><input id="loginOtp" name="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="Code à six chiffres"></details>
      <label class="account-check"><input id="rememberLogin" type="checkbox"> Garder ma session sur cet appareil pendant 7 jours</label>
      <p id="loginMessage" class="form-message" role="alert" hidden></p><button id="loginSubmit" type="submit" class="account-primary">Se connecter <span aria-hidden="true">→</span></button>
    </form>
    <details class="login-help"><summary>Besoin d’aide pour vous connecter ?</summary><p>Lors de la première connexion, utilisez les identifiants habituels de Sentinel. Si vous les avez modifiés depuis Mon compte, utilisez les nouveaux.</p><p>En cas de mot de passe oublié, une récupération reste possible depuis le serveur où Sentinel est installé.</p></details>
    <p class="login-footnote">Livebox Sentinel · Votre réseau, votre espace.</p>
  </section>
</div>
<script>
(() => {
  try { localStorage.removeItem('sentinel-offline-summary'); localStorage.removeItem('sentinel-offline-optin'); } catch (_) {}
  const form = document.getElementById('loginForm');
  const query = new URLSearchParams(location.search);
  if (query.has('logged_out')) {document.getElementById('loginNotice').hidden = false; document.getElementById('loginNotice').textContent = 'Vous êtes déconnecté de cet appareil.';}
  const password = document.getElementById('loginPassword');
  for (const event of ['keydown', 'keyup']) password.addEventListener(event, e => {document.getElementById('capsLockHint').hidden = !e.getModifierState('CapsLock');});
  password.addEventListener('blur', () => {document.getElementById('capsLockHint').hidden = true;});
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = document.getElementById('loginSubmit');
    const message = document.getElementById('loginMessage');
    button.disabled = true; button.setAttribute('aria-busy', 'true'); message.hidden = true;
    try {
      const response = await fetch('/api/auth/login', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:document.getElementById('loginUsername').value, password:password.value, otp:document.getElementById('loginOtp').value, remember:document.getElementById('rememberLogin').checked, next:query.get('next') || '/'})});
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Connexion impossible. Vérifiez vos informations.');
      location.replace(data.next || '/');
    } catch (error) {
      message.textContent = error instanceof TypeError ? 'Le serveur ne répond pas. Vérifiez la connexion et réessayez.' : error.message;
      message.hidden = false;
      if (/code|facteur/i.test(message.textContent)) {document.getElementById('loginFactor').open=true;document.getElementById('loginOtp').focus();}
    } finally {button.disabled = false; button.setAttribute('aria-busy', 'false');}
  });
})();
</script></body></html>
"""

ACCOUNT_PAGE = r"""
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Mon compte — Livebox Sentinel</title></head><body>
<div class="account-page-heading"><div><p class="eyebrow">VOTRE ESPACE</p><h1>Mon compte</h1><p class="muted">Vos informations, vos accès et les appareils connectés.</p></div><span class="owner-badge">Compte propriétaire</span></div>
<p id="accountNotice" class="form-notice" role="status" hidden></p><p id="accountLoadError" class="form-message" role="alert" hidden></p>
<div class="account-layout">
  <aside class="account-identity" aria-label="Votre profil"><div id="accountAvatar" class="account-large-avatar" aria-hidden="true">·</div><h2 id="accountDisplayName">Chargement du profil…</h2><p id="accountUsername" class="muted"></p><span class="owner-badge">Propriétaire du foyer</span><div class="account-section-nav" role="navigation" aria-label="Sections du compte"><a href="#profileSection">Profil <span aria-hidden="true">↗</span></a><a href="#securitySection">Connexion & sécurité <span aria-hidden="true">↗</span></a><a href="#sessionsSection">Appareils connectés <span aria-hidden="true">↗</span></a></div><p id="accountCreated" class="field-hint"></p></aside>
  <div class="account-sections">
    <section id="profileSection" class="account-section"><div class="account-section-title"><span class="account-section-number">01</span><div><h2>Un espace à votre nom</h2><p class="muted">Le nom affiché dans votre compte et dans l’en-tête.</p></div></div>
      <form id="ownerProfileForm"><fieldset id="ownerProfileFields" disabled><label for="ownerDisplayName">Nom affiché</label><input id="ownerDisplayName" maxlength="80" autocomplete="nickname" required placeholder="Ex. Camille"><div class="account-form-actions"><button type="submit" class="account-primary">Enregistrer le profil</button><p id="ownerProfileMessage" class="form-message" role="status" hidden></p></div></fieldset></form>
    </section>
    <section id="securitySection" class="account-section"><div class="account-section-title"><span class="account-section-number">02</span><div><h2>Connexion & sécurité</h2><p class="muted">Un identifiant et un mot de passe réservés à cet espace.</p></div></div>
      <form id="ownerCredentialsForm"><fieldset id="ownerCredentialsFields" disabled>
        <label for="ownerLoginName">Identifiant de connexion</label><input id="ownerLoginName" maxlength="80" autocomplete="username" pattern="[A-Za-z0-9._@+\-]+" required><p class="field-hint">Lettres non accentuées, chiffres ou . _ @ + - sans espace. Cet identifiant peut être différent du nom affiché.</p>
        <label for="ownerCurrentPassword">Mot de passe actuel</label><div class="password-field"><input id="ownerCurrentPassword" type="password" maxlength="1024" autocomplete="current-password" required><button type="button" data-toggle-password="ownerCurrentPassword" aria-pressed="false" aria-label="Afficher le mot de passe actuel">Afficher</button></div>
        <label for="ownerNewPassword">Nouveau mot de passe <span class="optional-label">facultatif si vous changez seulement l’identifiant</span></label><div class="password-field"><input id="ownerNewPassword" type="password" minlength="12" maxlength="1024" autocomplete="new-password" aria-describedby="passwordLengthHint"><button type="button" data-toggle-password="ownerNewPassword" aria-pressed="false" aria-label="Afficher le nouveau mot de passe">Afficher</button></div>
        <div class="password-length"><meter id="passwordLength" min="0" max="12" value="0" aria-label="Longueur du nouveau mot de passe, minimum 12 caractères"></meter><span id="passwordLengthHint">12 caractères minimum · une phrase convient très bien.</span></div>
        <label for="ownerConfirmPassword">Confirmer le nouveau mot de passe</label><div class="password-field"><input id="ownerConfirmPassword" type="password" maxlength="1024" autocomplete="new-password"><button type="button" data-toggle-password="ownerConfirmPassword" aria-pressed="false" aria-label="Afficher la confirmation du mot de passe">Afficher</button></div>
        <p class="account-security-note">Vous resterez connecté ici. Les autres appareils devront se reconnecter avec vos nouveaux identifiants.</p>
        <div class="account-form-actions"><button type="submit" class="account-primary">Mettre à jour les accès</button><p id="ownerCredentialsMessage" class="form-message" role="status" hidden></p></div>
      </fieldset></form>
    </section>
    <section id="totpSection" class="account-section"><div class="account-section-title"><span class="account-section-number">03</span><div><h2>Validation en deux étapes</h2><p class="muted">Un code à six chiffres de votre application d’authentification, demandé à chaque connexion.</p></div></div>
      <p id="totpStatus" class="field-hint">Lecture de l’état…</p>
      <form id="totpSetup" hidden><label for="totpSetupPassword">Mot de passe actuel</label><input id="totpSetupPassword" name="password" type="password" autocomplete="current-password" required><div class="account-form-actions"><button type="submit" class="account-primary">Activer la validation en deux étapes</button></div></form>
      <form id="totpConfirm" hidden><p>Ajoutez cette clé dans votre application d’authentification (saisie manuelle), puis indiquez le code affiché.</p><output id="totpSecret" class="totp-secret"></output><label for="totpCode">Code à six chiffres</label><input id="totpCode" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><div class="account-form-actions"><button type="submit" class="account-primary">Confirmer l’activation</button></div></form>
      <form id="totpDisable" hidden><label for="totpDisablePassword">Mot de passe actuel</label><input id="totpDisablePassword" name="password" type="password" autocomplete="current-password" required><label for="totpDisableCode">Code à six chiffres</label><input id="totpDisableCode" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required><div class="account-form-actions"><button type="submit" class="quiet-button">Désactiver</button></div></form>
      <p id="totpMessage" class="form-message" role="status" hidden></p>
      <p class="field-hint">En cas de perte du téléphone, l’accès se récupère depuis le serveur avec <code>tools/account_admin.py</code>.</p>
    </section>
    <section id="sessionsSection" class="account-section"><div class="account-section-title"><span class="account-section-number">04</span><div><h2>Vos appareils connectés <span id="sessionCount" class="count-pill">—</span></h2><p class="muted">Les navigateurs qui ont une session active sur votre compte.</p></div></div><div id="ownerSessions" class="owner-sessions"></div><div class="account-session-footer"><p class="field-hint">Les noms sont estimés à partir du navigateur. Une session peut rester active après la fermeture d’un onglet, jusqu’à son expiration.</p><button id="revokeOtherSessions" type="button" disabled>Déconnecter les autres appareils</button><p id="ownerSessionsMessage" class="form-message" role="status" hidden></p></div></section>
  </div>
</div>
<script>
(() => {
  let ownerData = null;
  const byId = id => document.getElementById(id);
  function node(tag, className, text) {const el=document.createElement(tag); if(className)el.className=className; if(text!==undefined)el.textContent=text; return el;}
  function message(id, text, success=false) {const el=byId(id); el.textContent=text; el.hidden=!text; el.dataset.state=success?'success':'error';}
  function date(value) {return value ? new Date(value*1000).toLocaleString('fr-FR') : 'Non renseignée';}
  function browserName(agent) {
    const browser = /Edg\//.test(agent)?'Edge':/Firefox\//.test(agent)?'Firefox':/Chrome\//.test(agent)?'Chrome':/Safari\//.test(agent)?'Safari':'Navigateur';
    const system = /iPad/.test(agent)?'iPad':/iPhone/.test(agent)?'iPhone':/Android/.test(agent)?'Android':/Windows/.test(agent)?'Windows':/Macintosh/.test(agent)?'Mac':/Linux/.test(agent)?'Linux':'Appareil non identifié';
    return browser+' · '+system;
  }
  async function api(url, options={}) {const response=await fetch(url,options); const data=await response.json().catch(()=>({})); if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Cette opération n’a pas abouti. Réessayez.'); return data;}
  function renderSessions() {
    const list=byId('ownerSessions'); list.replaceChildren();
    const sessions=ownerData.sessions||[]; byId('sessionCount').textContent=sessions.length;
    for(const session of sessions) {
      const row=node('div','owner-session');
      const symbol=node('span','session-symbol','↗'); symbol.setAttribute('aria-hidden','true');
      const content=node('div','session-description'); const title=node('div','session-title'); title.appendChild(node('strong','',browserName(session.user_agent)));
      if(session.current)title.appendChild(node('span','current-session-badge','Cet appareil'));
      content.append(title,node('p','','Dernière activité : '+date(session.seen_at)),node('small','','Connexion : '+date(session.created_at)+' · Expiration : '+date(session.expires_at)));
      row.append(symbol,content);
      if(!session.current){const button=node('button','quiet-button','Déconnecter'); button.type='button'; button.setAttribute('aria-label','Déconnecter '+browserName(session.user_agent)); button.addEventListener('click',async()=>{button.disabled=true; try{await api('/api/account/sessions/'+encodeURIComponent(session.id),{method:'DELETE'}); await loadAccount(true); message('ownerSessionsMessage','Cet appareil devra se reconnecter.',true);}catch(error){message('ownerSessionsMessage',error.message);}finally{button.disabled=false;}}); row.appendChild(button);}
      list.appendChild(row);
    }
    byId('revokeOtherSessions').disabled=!sessions.some(session=>!session.current);
  }
  async function loadAccount(preserveForm=false) {
    try {
      ownerData=await api('/api/account');
      byId('accountDisplayName').textContent=ownerData.display_name; byId('accountUsername').textContent='@'+ownerData.username;
      byId('accountAvatar').textContent=ownerData.display_name.trim().split(/\s+/).filter(part=>/[\p{L}\p{N}]/u.test(part)).slice(0,2).map(part=>Array.from(part)[0]).join('').toLocaleUpperCase('fr');
      byId('accountCreated').textContent='Votre espace depuis le '+new Date(ownerData.created_at*1000).toLocaleDateString('fr-FR');
      if(!preserveForm){byId('ownerDisplayName').value=ownerData.display_name; byId('ownerLoginName').value=ownerData.username;}
      byId('ownerProfileFields').disabled=false; byId('ownerCredentialsFields').disabled=false;
      renderSessions(); byId('accountLoadError').hidden=true;
    } catch(error){message('accountLoadError','Le compte n’a pas pu être chargé. Rechargez la page pour réessayer.');}
  }
  byId('ownerProfileForm').addEventListener('submit',async event=>{
    event.preventDefault(); const fields=byId('ownerProfileFields'); fields.disabled=true; message('ownerProfileMessage','Enregistrement…',true);
    try{await api('/api/account/profile',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({display_name:byId('ownerDisplayName').value})}); await loadAccount(true); if(window.refreshAccountMenu)await window.refreshAccountMenu(); message('ownerProfileMessage','Votre profil a été enregistré.',true);}catch(error){message('ownerProfileMessage',error.message);}finally{fields.disabled=false;}
  });
  byId('ownerNewPassword').addEventListener('input',()=>{const length=Array.from(byId('ownerNewPassword').value).length; byId('passwordLength').value=Math.min(12,length); byId('passwordLengthHint').textContent=length?length+' caractères · '+(length>=12?'minimum atteint':'12 minimum'):'12 caractères minimum · une phrase convient très bien.'; byId('ownerConfirmPassword').required=length>0;});
  byId('ownerCredentialsForm').addEventListener('submit',async event=>{
    event.preventDefault(); if(byId('ownerNewPassword').value!==byId('ownerConfirmPassword').value){message('ownerCredentialsMessage','Les deux nouveaux mots de passe ne correspondent pas.'); byId('ownerConfirmPassword').focus(); return;}
    const payload={username:byId('ownerLoginName').value,current_password:byId('ownerCurrentPassword').value,new_password:byId('ownerNewPassword').value};
    const fields=byId('ownerCredentialsFields'); fields.disabled=true; message('ownerCredentialsMessage','Mise à jour des accès…',true);
    try{await api('/api/account/credentials',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}); location.replace('/account?updated=security');}catch(error){message('ownerCredentialsMessage',error.message); fields.disabled=false;}
  });
  byId('revokeOtherSessions').addEventListener('click',async event=>{
    if(!window.confirm('Déconnecter les autres appareils ? Ils devront saisir à nouveau les identifiants du compte.'))return;
    const button=event.currentTarget; button.disabled=true;
    try{await api('/api/account/sessions/revoke-others',{method:'POST'}); await loadAccount(true); message('ownerSessionsMessage','Les autres appareils ont été déconnectés.',true);}catch(error){message('ownerSessionsMessage',error.message); button.disabled=false;}
  });
  if(new URLSearchParams(location.search).get('updated')==='security'){byId('accountNotice').hidden=false; byId('accountNotice').textContent='Vos accès ont été mis à jour. Vous êtes connecté ici ; les autres sessions ont été fermées.'; history.replaceState(null,'','/account');}
  loadAccount();
})();
</script></body></html>
"""

AUTH_CLIENT = r"""
<script>
(() => {
  const originalFetch=window.fetch.bind(window);
  function reconnect(){location.replace('/login?next='+encodeURIComponent(location.pathname));}
  async function sessionInfo(){const response=await originalFetch('/api/auth/session'); if(response.status===401){reconnect(); return null;} if(!response.ok)throw new Error('Session temporairement indisponible. Rechargez la page.'); return response.json();}
  let sessionPromise=sessionInfo().catch(()=>null);
  window.fetch=async (input,options={})=>{
    const url=new URL(typeof input==='string'?input:input.url,location.href);
    const local=url.origin===location.origin;
    const method=(options.method||(input instanceof Request?input.method:'GET')).toUpperCase();
    if(local&&!['GET','HEAD','OPTIONS'].includes(method)){
      let session=await sessionPromise;
      if(!session){sessionPromise=sessionInfo().catch(()=>null);session=await sessionPromise;}
      if(!session)throw new Error('Votre session doit être renouvelée. Reconnectez-vous.');
      const headers=new Headers(options.headers||(input instanceof Request?input.headers:undefined)); headers.set('X-Sentinel-CSRF',session.csrf_token); options={...options,headers};
    }
    const response=await originalFetch(input,options);
    if(local&&url.pathname.startsWith('/api/')&&response.status===401)reconnect();
    return response;
  };
  window.refreshAccountMenu=async()=>{
    sessionPromise=sessionInfo().catch(()=>null); const session=await sessionPromise; if(!session)return;
    const name=document.getElementById('headerAccountName'); const avatar=document.getElementById('headerAccountAvatar');
    if(name)name.textContent=session.display_name;
    if(avatar)avatar.textContent=session.display_name.trim().split(/\s+/).filter(part=>/[\p{L}\p{N}]/u.test(part)).slice(0,2).map(part=>Array.from(part)[0]).join('').toLocaleUpperCase('fr');
  };
  function ready(){
    sessionPromise.then(session=>{if(!session)return; const name=document.getElementById('headerAccountName'); const avatar=document.getElementById('headerAccountAvatar'); if(name)name.textContent=session.display_name; if(avatar)avatar.textContent=session.display_name.trim().split(/\s+/).filter(part=>/[\p{L}\p{N}]/u.test(part)).slice(0,2).map(part=>Array.from(part)[0]).join('').toLocaleUpperCase('fr');});
    const menu=document.getElementById('headerAccountMenu');
    document.addEventListener('click',event=>{if(menu&&!menu.contains(event.target))menu.open=false;});
    document.addEventListener('keydown',event=>{if(event.key==='Escape'&&menu?.open){menu.open=false; menu.querySelector('summary').focus();}});
    document.getElementById('headerLogout')?.addEventListener('click',async event=>{const button=event.currentTarget; button.disabled=true;try{const response=await fetch('/api/auth/logout',{method:'POST'});if(!response.ok)throw new Error();location.replace('/login?logged_out=1');}catch(_){button.disabled=false;document.getElementById('headerLogoutMessage').textContent='Déconnexion impossible. Réessayez.';}});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',ready);else ready();
})();
</script>
"""


THEME_INIT = """
<script>
(() => {
  let theme = 'dark';
  try { const saved = localStorage.getItem('sentinel-theme');
    if (saved === 'light' || saved === 'dark') theme = saved;
  } catch (_) {}
  document.documentElement.dataset.theme = theme;
})();
</script>
"""

THEME_CONTROLS = """
<script>
(() => {
  const button = document.getElementById('themeToggle');
  function update() {
    const dark = document.documentElement.dataset.theme === 'dark';
    button.setAttribute('aria-label', dark ? 'Mode sombre activé. Passer au mode clair' : 'Mode clair activé. Passer au mode sombre');
    button.dataset.tooltip = dark ? 'Passer au mode clair' : 'Passer au mode sombre';
    button.setAttribute('aria-pressed', String(dark));
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0b1120' : '#f3f6fb');
  }
  button.addEventListener('click', () => {
    const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('sentinel-theme', theme); } catch (_) {}
    update();
  });
  update();
  document.querySelectorAll('[data-toggle-password]').forEach(control => {
    control.addEventListener('click', () => {
      const input = document.getElementById(control.dataset.togglePassword);
      const visible = input.type === 'password';
      input.type = visible ? 'text' : 'password';
      control.textContent = visible ? 'Masquer' : 'Afficher';
      control.setAttribute('aria-pressed', String(visible));
      control.setAttribute('aria-label', visible ? 'Masquer le mot de passe' : 'Afficher le mot de passe');
    });
  });
})();
</script>
"""


CATEGORY_VISUALS = r"""
<script>
const CATEGORY_PRESETS = ["Ordinateur", "Téléphone", "Tablette", "Télévision", "Console", "Objet connecté", "Lumière", "Imprimante", "Serveur", "Stockage réseau", "Caméra", "Audio", "Réseau", "Domotique"];
function categorySymbol(label, override = "") {
  const value = String(label || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  const definitions = [
    [/tablette|tablet|ipad/, "tablet", '<rect x="4" y="2" width="16" height="20" rx="3"/><path d="M10 18h4"/>'],
    [/telephon|phone|mobile/, "phone", '<rect x="7" y="2" width="10" height="20" rx="3"/><path d="M10 5h4M11 18h2"/>'],
    [/televis|smarttv|\btv\b/, "tv", '<rect x="2" y="4" width="20" height="14" rx="3"/><path d="M8 22h8M12 18v4m-7-15 3 3"/>'],
    [/console|gaming|playstation|xbox|nintendo/, "console", '<path d="M7 7h10c3 0 4 4 4 8 0 3-2 4-4 1l-1-1H8l-1 1c-2 3-4 2-4-1 0-4 1-8 4-8Z"/><path d="M6 11h4M8 9v4m8-2h.01M18 13h.01M10 7V4h4"/>'],
    [/imprim|printer/, "printer", '<path d="M6 8V2h12v6M6 18H3V8h18v10h-3M6 14h12v8H6zM17 11h1"/>'],
    [/stockage|\bnas\b|disque|storage/, "storage", '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0M8 17h.01"/>'],
    [/serveur|server/, "server", '<rect x="4" y="2" width="16" height="8" rx="2"/><rect x="4" y="14" width="16" height="8" rx="2"/><path d="M8 6h.01M8 18h.01M13 6h4M13 18h4M12 10v4"/>'],
    [/camera|webcam/, "camera", '<path d="M8 5 10 2h4l2 3h4v15H4V5Z"/><circle cx="12" cy="12" r="4"/>'],
    [/audio|enceinte|speaker|sonos|hifi|casque/, "audio", '<rect x="6" y="2" width="12" height="20" rx="3"/><circle cx="12" cy="15" r="3"/><circle cx="12" cy="6" r="1"/>'],
    [/reseau|routeur|router|repet|switch|accesspoint/, "network", '<rect x="3" y="12" width="18" height="8" rx="2"/><path d="M6 12V7M18 12V7M7 16h.01M11 16h.01M9 7a5 5 0 0 1 6 0M6 4a10 10 0 0 1 12 0"/>'],
    [/domoti|home.?assistant|maison/, "home", '<path d="m2 11 10-9 10 9M5 9v13h14V9M9 22v-7h6v7"/><path d="M10 9h4"/>'],
    [/ordinateur|computer|desktop|laptop|macbook|pc\b/, "computer", '<rect x="3" y="3" width="18" height="14" rx="2"/><path d="M8 22h8M12 17v5M6 6h4"/>'],
    [/lumiere|lampe|ampoule|eclairage|luminaire|light|bulb|\bhue\b/, "light", '<path d="M9 19h6M10 22h4M8 14a6 6 0 1 1 8 0l-1 2H9Z"/><path d="M10.5 16v-3.5L12 11l1.5 1.5V16"/>'],
    [/objet|connect|iot|smart|capteur|sensor/, "iot", '<rect x="6" y="10" width="12" height="11" rx="3"/><path d="M10 15.5h4M12 10V7"/><path d="M9.2 4.8a4 4 0 0 1 5.6 0M6.8 2.6a7.4 7.4 0 0 1 10.4 0"/>'],
  ];
  const match = override ? definitions.find(([, key]) => key === override) : definitions.find(([pattern]) => pattern.test(value));
  const icon = document.createElement("span");
  icon.className = "equipment-icon";
  icon.dataset.symbol = match ? match[1] : "device";
  icon.setAttribute("aria-hidden", "true");
  // Labels never enter markup. Only the static paths above can enter this SVG.
  const path = match ? match[2] : '<rect x="4" y="4" width="16" height="16" rx="5"/><path d="M9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M20 9h3M1 15h3M20 15h3"/>';
  icon.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' + path + '</svg>';
  return icon;
}
</script>
"""

ABOUT_PAGE = r"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>À propos · Livebox Sentinel</title></head><body>
<section class="about-hero"><div><p class="eyebrow">VOTRE RÉSEAU, EN TOUTE CLARTÉ</p><h1>À propos de Sentinel</h1><p class="about-lead">Une fenêtre claire sur votre réseau domestique : comprendre, organiser et surveiller, depuis votre navigateur.</p><span class="about-version" id="aboutVersion">Version en cours de lecture…</span></div><img src="/assets/sentinel.svg" width="116" height="116" alt="" class="about-emblem"></section>
<p id="aboutStatus" role="status">Lecture des informations de cette installation…</p>
<section class="about-stats" aria-label="Cette installation">
<article class="panel"><span>Stockage SQLite total</span><strong id="aboutStorage">—</strong><small>Espace occupé par la base sur le disque</small></article>
<article class="panel"><span>Équipements au dernier relevé</span><strong id="aboutDevices">—</strong><small id="aboutCollection">En attente du premier relevé</small></article>
<article class="panel"><span>Depuis le dernier démarrage</span><strong id="aboutUptime">—</strong><small id="aboutInterval">Collecte périodique</small></article>
</section>
<div class="about-grid"><section class="panel"><p class="eyebrow">PENSÉ POUR LE QUOTIDIEN</p><h2>Ce que Sentinel vous apporte</h2><div class="about-features">
<article><h3>Être averti des arrivées</h3><p>Chaque nouvel équipement est annoncé par e-mail dès sa première connexion, puis signalé pendant 7 jours sur le tableau de bord. Un appareil supprimé redevient nouveau s’il revient.</p></article>
<article><h3>Identifier & organiser</h3><p>Noms personnalisés, catégories illustrées et pièces. Les nouveaux équipements sont annoncés par e-mail et signalés pendant 7 jours, sauf si vous indiquez les reconnaître.</p></article>
<article><h3>Comprendre le Wi-Fi et les usages</h3><p>Couverture Wi-Fi appareil par appareil, historique du signal en dBm, débits Internet de la dernière heure à un an, journal des connexions triable, consommation par appareil, pièce ou catégorie. Graphiques à échelles réelles et infobulles.</p></article>
<article><h3>Garder la maîtrise</h3><p>Application en lecture seule vis-à-vis de la Livebox. Sauvegardes, restauration, conservation prévisualisée, journal des actions, sessions révocables et validation en deux étapes.</p></article>
</div></section>
<section class="panel about-credit"><p class="eyebrow">ORIGINES & RECONNAISSANCE</p><h2>Inspiré par Livebox Monitor</h2><p>Livebox Sentinel s’inspire de <strong>Livebox Monitor</strong>, créé par <strong>p-dor</strong>, et utilise directement ses modules Python pour communiquer avec la Livebox.</p><p>Merci à son auteur et aux contributeurs pour ce travail qui rend ce projet possible. Sentinel propose une interface web et ses propres fonctions de suivi du foyer.</p><a href="https://github.com/p-dor/LiveboxMonitor" target="_blank" rel="noopener noreferrer">Découvrir le projet original ↗</a><p class="muted">Dépendance intégrée : Livebox Monitor 1.7 · licence MIT. Livebox Sentinel est un projet indépendant, sans affiliation avec Orange.</p></section>
<section class="panel"><p class="eyebrow">REPÈRES TECHNIQUES</p><h2>Votre installation</h2><dl class="about-details"><div><dt>Application</dt><dd id="aboutRelease">—</dd></div><div><dt>Base principale</dt><dd id="aboutDatabase">—</dd></div><div><dt>Socle</dt><dd>Python · FastAPI · SQLite · Docker Compose</dd></div><div><dt>Collecte</dt><dd id="aboutHealth">—</dd></div></dl><p class="muted">Le stockage indiqué exclut les sauvegardes. Ces tailles peuvent varier pendant la collecte ; il s’agit d’un instantané.</p><button id="aboutRefresh" type="button">Actualiser les informations</button></section>
<section class="panel"><p class="eyebrow">INSTALLATION & CHANGEMENT DE BOX</p><h2>Connecter votre Livebox</h2><p>Utilisez <a href="/settings#livebox">Paramètres → Connexion à la Livebox</a> pour tester puis enregistrer les accès de la box, sans redémarrer Sentinel. Ces paramètres chiffrés prennent priorité sur le fichier <code>.env</code>. Son authentification reste distincte de votre compte Sentinel.</p><dl class="about-details"><div><dt><code>LIVEBOX_URL</code></dt><dd>Adresse de la box, par exemple <code>http://192.168.1.1/</code></dd></div><div><dt><code>LIVEBOX_USERNAME</code></dt><dd>Identifiant d’administration de la box, généralement <code>admin</code></dd></div><div><dt><code>LIVEBOX_PASSWORD</code></dt><dd>Mot de passe d’administration de cette Livebox</dd></div></dl><p>Si vous préférez modifier uniquement le fichier <code>.env</code>, choisissez d’abord « Revenir au fichier .env » dans Paramètres, puis recréez le service avec <code>docker compose up -d --force-recreate livebox-sentinel</code>. Un simple redémarrage ne recharge pas les variables du fichier.</p><p class="muted"><code>PUBLIC_URL</code> est l’adresse à laquelle vous ouvrez Sentinel (par exemple <code>http://192.168.1.10:8080</code>) : elle sert aux liens des e-mails. Si le serveur change d’adresse, adaptez-la. Le serveur doit pouvoir joindre la box sur le réseau local.</p><a href="/settings">Ouvrir les paramètres de l’application →</a></section></div>
<section class="panel"><p class="eyebrow">UNE SIGNATURE POUR CHAQUE USAGE</p><h2>Les catégories, en un regard</h2><p class="muted">Des pictogrammes vectoriels discrets, adaptés aux deux thèmes. Une catégorie personnalisée conserve un symbole universel si son nom n’est pas reconnu.</p><div id="aboutCategories" class="category-gallery"></div></section>
<script>
for (const label of CATEGORY_PRESETS) {
  const item = document.createElement("div"); item.className = "category-gallery-item";
  item.append(categorySymbol(label), document.createTextNode(label)); document.getElementById("aboutCategories").appendChild(item);
}
function aboutSize(bytes) { if (!bytes) return "0 o"; const units = ["o", "Kio", "Mio", "Gio", "Tio"]; const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024))); return (bytes / 1024 ** i).toLocaleString("fr-FR", {maximumFractionDigits: i ? 2 : 0}) + " " + units[i]; }
async function loadAbout() {
  const button = document.getElementById("aboutRefresh"); button.disabled = true;
  try {
    const response = await fetch("/api/about", {cache: "no-store"}); if (!response.ok) throw new Error(); const data = await response.json();
    const set = (id, value) => { document.getElementById(id).textContent = value; };
    set("aboutVersion", "Version " + data.version); set("aboutRelease", data.version + " · " + new Date(data.release_date + "T12:00:00").toLocaleDateString("fr-FR"));
    set("aboutStorage", aboutSize(data.storage_bytes)); set("aboutDatabase", aboutSize(data.database_bytes)); 
    set("aboutDevices", data.collection.last_collection ? data.collection.devices.toLocaleString("fr-FR") : "—");
    set("aboutCollection", data.collection.last_collection ? "Dernier relevé : " + new Date(data.collection.last_collection * 1000).toLocaleString("fr-FR") : "En attente du premier relevé");
    const minutes = Math.floor(data.uptime_seconds / 60); set("aboutUptime", minutes < 1 ? "Moins d’une minute" : minutes < 60 ? minutes + " min" : Math.floor(minutes / 60) + " h " + minutes % 60 + " min");
    set("aboutInterval", "Un relevé toutes les " + data.collection_interval_seconds + " secondes");
    set("aboutHealth", data.collection.has_error ? "À vérifier dans le tableau de bord" : data.collection.last_collection ? "Dernier relevé réussi" : "En attente du premier relevé");
    set("aboutStatus", "Informations actualisées à " + new Date().toLocaleTimeString("fr-FR"));
  } catch (_) { document.getElementById("aboutStatus").textContent = "Informations indisponibles. Réessayez avec le bouton d’actualisation."; }
  finally { button.disabled = false; }
}
document.getElementById("aboutRefresh").addEventListener("click", loadAbout); loadAbout();
</script></body></html>"""

UI_STYLES += r"""
.category-preview { display: flex; align-items: center; gap: .6rem; margin-top: .6rem; color: var(--muted); font-size: .82rem; overflow-wrap: anywhere; }
.category-preview .equipment-icon, .consumption-category-symbol { width: 28px; height: 28px; flex-basis: 28px; border-radius: 8px; }
.category-preview svg, .consumption-category-symbol svg { width: 18px; height: 18px; }
.consumption-category-symbol { display: inline-grid; vertical-align: middle; margin-right: .55rem; }
.about-hero { display: flex; align-items: center; justify-content: space-between; gap: 2rem; padding: 1.5rem; }
.about-hero h1 { margin: .3rem 0; font-size: clamp(1.9rem, 4vw, 3rem); letter-spacing: -.04em; }
.about-lead { max-width: 650px; color: var(--muted); font-size: 1.05rem; }
.about-emblem { flex: 0 0 auto; filter: drop-shadow(0 12px 22px #1673bc22); }
.about-version { display: inline-block; padding: .25rem .7rem; color: var(--accent); background: var(--selected); border: 1px solid var(--line); border-radius: 30px; font-size: .8rem; }
.about-stats { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 1rem; }
.about-stats article { display: flex; flex-direction: column; gap: .35rem; }
.about-stats strong { font-size: clamp(1.4rem, 2.8vw, 2rem); letter-spacing: -.03em; }
.about-stats small, .about-stats article > span { color: var(--muted); }
.about-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 1rem; margin: 1rem 0; }
.about-grid > .panel { margin: 0; min-width: 0; }
.about-grid h2 { margin-top: .3rem; }
.about-features { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: .6rem 1.2rem; }
.about-features h3 { font-size: .92rem; margin-bottom: .3rem; }
.about-features p { color: var(--muted); font-size: .86rem; margin-top: 0; }
.about-credit { background: linear-gradient(145deg,var(--selected),var(--surface)); }
.about-details { margin: 1rem 0; }
.about-details > div { display: flex; justify-content: space-between; gap: 1rem; padding: .65rem 0; border-bottom: 1px solid var(--line); }
.about-details dt { color: var(--muted); flex-shrink: 0; }
.about-details dt code { white-space: nowrap; }
.about-details dd { margin: 0; text-align: right; }
.about-details code, .about-grid code { overflow-wrap: anywhere; }
.category-gallery { display: grid; grid-template-columns: repeat(auto-fit,minmax(175px,1fr)); gap: .75rem; }
.category-gallery-item { display: flex; align-items: center; gap: .7rem; padding: .65rem; border: 1px solid var(--line); border-radius: 12px; }
@media(max-width:700px) {
  .about-hero { gap: .7rem; align-items: flex-start; }
  .about-emblem { width: 56px; height: 56px; margin-top: 1rem; }
  .about-stats, .about-grid { grid-template-columns: minmax(0,1fr); }
  .about-features { grid-template-columns: minmax(0,1fr); }
  .about-details > div { flex-direction: column; gap: .15rem; }
  .about-details dd { text-align: left; }
  .category-gallery { grid-template-columns: repeat(2,minmax(0,1fr)); gap: .5rem; }
  .category-gallery-item { font-size: .8rem; padding: .5rem; gap: .4rem; overflow-wrap: break-word; hyphens: auto; min-width: 0; }
}
"""


WIFI_PAGE = r"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wi-Fi · Livebox Sentinel</title></head><body>
<div class="wifi-heading"><div><p class="eyebrow">COUVERTURE SANS FIL</p><h1>Wi-Fi</h1><p class="muted">Le signal de chaque appareil, du plus faible au meilleur. Touchez un appareil pour voir son historique et des conseils.</p></div></div>
<div class="wifi-summary" id="wifiSummary" aria-live="polite"><p class="muted">Lecture des mesures…</p></div>
<div class="wifi-toolbar"><label class="check-row"><input type="checkbox" id="wifiWeakOnly"> Uniquement les signaux faibles</label><label class="check-row"><input type="checkbox" id="wifiShowStale"> Inclure les appareils non mesurés récemment</label></div>
<ul id="wifiList" class="wifi-list" aria-label="Appareils en Wi-Fi"></ul>
<p id="wifiNote" class="field-hint"></p>
</body></html>"""


def apply_interface(page, current_path):
    """Apply the same navigation and theme to every embedded HTML page."""
    page = re.sub(r"<style>.*?</style>", "", page, flags=re.S)
    page = re.sub(r"<nav\b[^>]*>.*?</nav>", "", page, flags=re.S)
    page = re.sub(r'<div style="text-align:right">.*?</div>', "", page)
    page = page.replace('<header><h1>Paramètres</h1><a href="/">Retour au tableau de bord</a></header>',
                        '<h1>Paramètres</h1>')
    if current_path == "/":
        page = page.replace('<h1>Livebox Sentinel</h1>', '<h1>Tableau de bord</h1>')
        page = page.replace("Les pics extrêmes sont l'échelle suit", "L’échelle suit")
        page = page.replace('viewBox="0 0 1000 320"', 'viewBox="0 0 1000 280"')
        page = page.replace('const tooltip = document.createElementNS(ns, "g");',
                            'const tooltip = document.createElementNS(ns, "g");\n  tooltip.setAttribute("class", "chart-tooltip");')
        # Pointer events support mouse, pen and touch without changing the data.
        page = page.replace('"mousemove"', '"pointermove"').replace('"mouseleave"', '"pointerleave"')
    for chart_id in ("wanChart", "historyChart", "qualityChart"):
        page = re.sub(r'(<svg id="' + chart_id + r'".*?</svg>)',
                      r'<div class="chart-scroll" tabindex="0" role="region" aria-label="Graphique défilant horizontalement">\1</div>',
                      page, flags=re.S)
    links = (("/", "Tableau de bord"), ("/wifi", "Wi-Fi"), ("/consumption", "Consommation"),
             ("/internet", "Qualité Internet"), ("/network", "Carte réseau"),
             ("/livebox-health", "Santé Livebox"), ("/settings", "Paramètres"))
    # Data, backups and About live under Paramètres.
    section = "/settings" if current_path in ("/backups", "/about") else current_path
    navigation = ''.join(
        f'<a href="{path}"' + (' aria-current="page"' if path == section else '')
        + f'>{label}</a>' for path, label in links
    )
    theme_button = ('<button id="themeToggle" class="theme-toggle" type="button" aria-label="Activer le mode clair" aria-pressed="true" data-tooltip="Passer au mode clair">'
                    '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true">'
                    '<g class="theme-sun"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.93 4.93l1.42 1.42M17.65 17.65l1.42 1.42M4.93 19.07l1.42-1.42M17.65 6.35l1.42-1.42"/></g>'
                    '<path class="theme-moon" d="M20.4 13.1A8.5 8.5 0 0 1 10.9 3.6a8.5 8.5 0 1 0 9.5 9.5Z"/></svg></button>')
    account_menu = ('<details class="header-account-menu" id="headerAccountMenu"><summary aria-label="Menu du compte">'
                    '<span id="headerAccountAvatar" class="header-avatar" aria-hidden="true">·</span><span id="headerAccountName">Mon compte</span>'
                    '<svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" aria-hidden="true"><path d="m4 6 4 4 4-4"/></svg></summary>'
                    '<div class="account-popover"><span class="popover-label">VOTRE ESPACE</span><a href="/account">Mon compte <span aria-hidden="true">↗</span></a><a href="/about">À propos <span aria-hidden="true">↗</span></a>'
                    '<button id="headerLogout" type="button">Se déconnecter</button><p id="headerLogoutMessage" role="status"></p></div></details>')
    public = current_path == "/login"
    shell = ('<a class="skip-link" href="#content">Aller au contenu</a>'
             '<header class="app-header"><div class="app-bar">'
             '<a class="brand" href="/" aria-label="Livebox Sentinel, accueil"><img class="brand-logo" src="/assets/sentinel.svg" width="44" height="44" alt="">'
             '<span><strong>Livebox Sentinel</strong></span></a>'
             '<div class="header-actions">' + theme_button + ('' if public else account_menu) + '</div></div>'
             + ('' if public else '<nav class="app-nav" aria-label="Navigation principale">' + navigation + '</nav>') + '</header>')
    content_class = ' class="settings-content"' if current_path == '/settings' else ' class="login-content"' if public else ''
    page = page.replace('</head>', '<link rel="icon" type="image/svg+xml" href="/favicon.svg"><link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" sizes="180x180" href="/assets/sentinel-180.png"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="theme-color" content="#101d30"><style>' + UI_STYLES + '</style>' + THEME_INIT + CATEGORY_VISUALS + ('' if public else AUTH_CLIENT + '<link rel="stylesheet" href="/assets/sentinel.css"><script src="/assets/sentinel.js" defer></script>') + '</head>')
    page = page.replace('<body>', '<body>' + shell + '<main id="content"' + content_class + '>')
    return page.replace('</body>', '</main>' + THEME_CONTROLS + '</body>')


HTML_PAGE = apply_interface(HTML_PAGE, "/")
CONSUMPTION_PAGE = apply_interface(CONSUMPTION_PAGE, "/consumption")
INTERNET_QUALITY_PAGE = apply_interface(INTERNET_QUALITY_PAGE, "/internet")
NETWORK_MAP_PAGE = apply_interface(NETWORK_MAP_PAGE, "/network")
LIVEBOX_HEALTH_PAGE = apply_interface(LIVEBOX_HEALTH_PAGE, "/livebox-health")
BACKUPS_PAGE = apply_interface(BACKUPS_PAGE, "/backups")
SETTINGS_PAGE = apply_interface(SETTINGS_PAGE, "/settings")
LOGIN_PAGE = apply_interface(LOGIN_PAGE, "/login")
ACCOUNT_PAGE = apply_interface(ACCOUNT_PAGE, "/account")
ABOUT_PAGE = apply_interface(ABOUT_PAGE, "/about")
WIFI_PAGE = apply_interface(WIFI_PAGE, "/wifi")

# Load the sibling modules by path, including in disposable test checkouts.
import importlib.util as _module_loader
_feature_spec = _module_loader.spec_from_file_location("sentinel_features", Path(__file__).with_name("features.py"))
_feature_module = _module_loader.module_from_spec(_feature_spec)
_feature_spec.loader.exec_module(_feature_module)
_recognition_spec = _module_loader.spec_from_file_location("sentinel_recognition", Path(__file__).with_name("recognition.py"))
recognition = _module_loader.module_from_spec(_recognition_spec)
_recognition_spec.loader.exec_module(recognition)
_topology_spec = _module_loader.spec_from_file_location("sentinel_topology", Path(__file__).with_name("topology.py"))
network_topology = _module_loader.module_from_spec(_topology_spec)
_topology_spec.loader.exec_module(network_topology)


class _FeatureCore:
    def __getattr__(self, name):
        return globals()[name]


features = _feature_module.Features(_FeatureCore())
