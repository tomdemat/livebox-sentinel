"""Wi-Fi, newcomers, second factor, Livebox connection and data retention.

No I/O at import; all tests use disposable databases. The household workspace,
members, router commands, schedules and integrations were removed in 2.2: their
tables stay in place (additive schema) but nothing reads or writes them any more.
"""
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import struct
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, quote
from zoneinfo import ZoneInfo

from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response


PARIS = ZoneInfo("Europe/Paris")
WEAK_SIGNAL_DBM = -75
NEW_DEVICE_DAYS = 7
ASSETS = Path(__file__).parent / "static"


def text(value, limit=100, empty=True, multiline=False):
    if not isinstance(value, str) or len(value.strip()) > limit or any(ord(c) < 32 and not (multiline and c in "\n\r\t") for c in value):
        raise HTTPException(400, "Texte invalide ou trop long.")
    value = value.strip()
    if not empty and not value:
        raise HTTPException(400, "Ce champ est requis.")
    return value


def integer(value, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise HTTPException(400, f"Choisissez un entier entre {minimum} et {maximum}.")
    return value


def clock(ts, now=None, absolute=False):
    """Short French wall-clock time, Europe/Paris. Mailed texts use the absolute form."""
    moment = datetime.fromtimestamp(ts, PARIS)
    today = datetime.fromtimestamp(now or time.time(), PARIS).date()
    return ("à " if moment.date() == today and not absolute else "le " + moment.strftime("%d/%m") + " à ") + moment.strftime("%H:%M")


def since(ts, now=None):
    return clock(ts, now).removeprefix("à ")


def duration(seconds):
    seconds = max(0, int(seconds))
    if seconds < 90:
        return "moins de 2 min"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    if seconds < 86400:
        hours, minutes = divmod(round(seconds / 60), 60)
        return f"{hours} h {minutes:02d}" if minutes else f"{hours} h"
    days = round(seconds / 86400, 1)
    return (str(int(days)) if days == int(days) else str(days).replace(".", ",")) + " j"


def plural(count, singular, many=None):
    return f"{count} {singular if count == 1 else many or singular + 's'}"


def signal_quality(rssi):
    """Common Wi-Fi reading bands, in dBm as reported by the Livebox."""
    if rssi is None:
        return "Non communiqué"
    if rssi >= -60:
        return "Excellent"
    if rssi >= -67:
        return "Bon"
    if rssi > WEAK_SIGNAL_DBM:
        return "Moyen"
    return "Faible"


def connection_label(interface="", layer2=""):
    """Plain connection type from the Livebox interface names (vap5g0priv, wl1.1, eth3…)."""
    name, layer = (interface or "").lower(), (layer2 or "").lower()
    if name.startswith("vap") or layer.startswith("wl") or "wifi" in name or name.startswith("wl"):
        band = "6 GHz" if "6g" in name else "5 GHz" if "5g" in name else "2,4 GHz" if "2g" in name else None
        if band is None:
            band = {"wl0": "2,4 GHz", "wl1": "5 GHz", "wl2": "6 GHz"}.get((layer or name).split(".")[0])
        return ("Wi-Fi invité" if "guest" in name else "Wi-Fi") + (" " + band if band else "")
    if "eth" in name or "eth" in layer or name.startswith("lan"):
        return "Ethernet"
    return "Liaison non communiquée"


def link_type(interface):
    return connection_label(interface, interface)


def lan_url(value):
    try:
        parsed = urlsplit(text(value, 220, False))
        address = ipaddress.ip_address(parsed.hostname or "")
        address = getattr(address, "ipv4_mapped", None) or address
        if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/") or not address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
    except ValueError:
        raise HTTPException(400, "Utilisez l’IP locale de la box, par exemple http://192.168.1.1/.")
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def recognition_lines(guess):
    """« Probably a … » lines for an arrival e-mail; a weak guess is left out."""
    if not guess:
        return []
    lines = []
    if guess.get("category") and guess.get("confidence") in ("élevée", "moyenne"):
        detail = " ".join(part for part in (guess.get("model"), f"({guess['vendor']})" if guess.get("vendor") else "") if part)
        lines.append(f"  Probablement : {guess['category'].lower()}{' · ' + detail if detail else ''}")
        if guess.get("reasons"):
            lines.append("  Indices : " + ", ".join(guess["reasons"][:3]))
    elif guess.get("vendor"):
        lines.append(f"  Fabricant : {guess['vendor']}")
    return ["".join(c for c in line if c.isprintable())[:200] for line in lines]


class Features:
    def __init__(self, core):
        self.c = core
        self.tick_lock = threading.Lock()
        self.last_tick = 0
        self.register()

    @contextlib.contextmanager
    def db(self):
        connection = self.c.connect_db()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self, con):
        # Additive schema: tables of removed features are kept so data is never lost.
        for sql in (
            "CREATE TABLE IF NOT EXISTS feature_documents(kind TEXT NOT NULL,id TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(kind,id))",
            "CREATE TABLE IF NOT EXISTS activity_log(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_log(ts)",
            "CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,event_key TEXT UNIQUE NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,level TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_notification_time ON notifications(ts)",
            "CREATE TABLE IF NOT EXISTS notification_reads(member_id TEXT NOT NULL,notification_id INTEGER NOT NULL,PRIMARY KEY(member_id,notification_id))",
            "CREATE TABLE IF NOT EXISTS wifi_samples(site TEXT NOT NULL,mac TEXT NOT NULL,ts INTEGER NOT NULL,rssi REAL,band TEXT NOT NULL,access_point TEXT NOT NULL,PRIMARY KEY(site,mac,ts))",
            "CREATE INDEX IF NOT EXISTS idx_wifi_time ON wifi_samples(ts)",
            "CREATE TABLE IF NOT EXISTS site_snapshots(site TEXT NOT NULL,ts INTEGER NOT NULL,value TEXT NOT NULL,PRIMARY KEY(site,ts))",
            "CREATE TABLE IF NOT EXISTS action_previews(token TEXT PRIMARY KEY,actor TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,expires_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS household_members(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,display_name TEXT NOT NULL,password_hash TEXT NOT NULL,auth_version INTEGER NOT NULL DEFAULT 1,enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS api_tokens(id TEXT PRIMARY KEY,name TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,last_used_at INTEGER)",
        ):
            con.execute(sql)
        columns = {row[1] for row in con.execute("PRAGMA table_info(web_sessions)")}
        if "member_id" not in columns:
            con.execute("ALTER TABLE web_sessions ADD COLUMN member_id TEXT NOT NULL DEFAULT 'owner'")
        if not self.document("migration", "observations-v1", con=con):
            # Existing devices are a baseline, not a wave of new-device alerts.
            for row in con.execute("SELECT mac,ip,updated_at FROM devices").fetchall():
                self.put(con, "observation", "primary:" + row["mac"], {"ip": row["ip"], "seen_at": row["updated_at"]})
            self.put(con, "migration", "observations-v1", {"done": True})
        ignored = {row[1] for row in con.execute("PRAGMA table_info(ignored_devices)")}
        if ignored:
            # Columns added in 0.4; « permanent » is no longer offered and is cleared below.
            for column, sql in (("permanent", "INTEGER NOT NULL DEFAULT 1"), ("last_seen_at", "INTEGER"), ("name", "TEXT")):
                if column not in ignored:
                    con.execute(f"ALTER TABLE ignored_devices ADD COLUMN {column} {sql}")
        if not self.document("migration", "first-activity-v1", con=con):
            self.migrate_first_activity(con)
            self.put(con, "migration", "first-activity-v1", {"done": True})
        if ignored and not self.document("migration", "forget-deleted-v1", con=con):
            # Deleted devices are no longer hidden for good: each one returns as new when it reconnects.
            con.execute("UPDATE ignored_devices SET permanent=0")
            self.put(con, "migration", "forget-deleted-v1", {"done": True})
        if not self.document("migration", "lumiere-v1", con=con):
            con.execute("UPDATE device_profiles SET category='Lumière' WHERE category='Lampe'")
            self.put(con, "migration", "lumiere-v1", {"done": True})
        if not self.document("migration", "owner-only-v1", con=con):
            # Read-only members were removed: close any of their sessions once.
            con.execute("DELETE FROM web_sessions WHERE member_id<>'owner'")
            self.put(con, "migration", "owner-only-v1", {"done": True})

    def migrate_first_activity(self, con):
        """« New » used to mean « first listed by the Livebox ». It now means « first really
        connected ». Legacy rows are re-dated once from recorded activity, without e-mails."""
        now = int(time.time())
        starts = [con.execute(sql).fetchone()[0] for sql in ("SELECT MIN(ts) FROM traffic", "SELECT MIN(bucket_ts) FROM traffic_15m", "SELECT MIN(ts) FROM device_presence_events")]
        starts = [s for s in starts if s]
        if not starts:
            return
        collection_start = min(starts)
        for row in con.execute("SELECT mac,active FROM devices WHERE first_seen_at=0").fetchall():
            mac = row["mac"]
            activity = [v for v in (
                con.execute("SELECT MIN(ts) FROM device_presence_events WHERE mac=? AND event_type='connected'", (mac,)).fetchone()[0],
                con.execute("SELECT MIN(ts) FROM traffic WHERE mac=? AND (rx>0 OR tx>0)", (mac,)).fetchone()[0],
                con.execute("SELECT MIN(bucket_ts) FROM traffic_15m WHERE mac=?", (mac,)).fetchone()[0],
            ) if v]
            first = min(activity) if activity else None
            if first is None and not row["active"]:
                # Listed by the box but never seen online: it will be announced on its first connection.
                con.execute("UPDATE devices SET first_seen_at=NULL WHERE mac=?", (mac,))
            elif first and first >= now - NEW_DEVICE_DAYS * 86400 and first > collection_start + 86400:
                con.execute("UPDATE devices SET first_seen_at=? WHERE mac=?", (first, mac))

    def document(self, kind, identifier="main", default=None, con=None):
        if con is None:
            with self.db() as db:
                return self.document(kind, identifier, default, db)
        row = con.execute("SELECT value FROM feature_documents WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        return json.loads(row[0]) if row else ({} if default is None else default)

    def put(self, con, kind, identifier, value):
        con.execute("INSERT INTO feature_documents VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET value=excluded.value", (kind, identifier, json.dumps(value, ensure_ascii=False)))

    def audit(self, con, actor, action, detail=""):
        con.execute("INSERT INTO activity_log(ts,actor,action,detail) VALUES(?,?,?,?)", (int(time.time()), actor, action, detail[:500]))

    def encrypt(self, value):
        return self.c.settings_cipher().encrypt(value.encode()).decode()

    def decrypt(self, value):
        return self.c.settings_cipher().decrypt(value.encode()).decode() if value else ""

    def preview(self, actor, kind, value):
        token = secrets.token_urlsafe(32)
        with self.db() as con:
            con.execute("DELETE FROM action_previews WHERE expires_at<?", (int(time.time()),))
            con.execute("INSERT INTO action_previews VALUES(?,?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), actor, kind, json.dumps(value), int(time.time()) + 120))
        return token

    def consume_preview(self, token, actor, kind):
        if not isinstance(token, str):
            raise HTTPException(400, "Confirmation invalide.")
        with self.db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT value FROM action_previews WHERE token=? AND actor=? AND kind=? AND expires_at>?", (hashlib.sha256(token.encode()).hexdigest(), actor, kind, int(time.time()))).fetchone()
            if not row:
                raise HTTPException(409, "Aperçu expiré ou déjà utilisé. Recommencez.")
            con.execute("DELETE FROM action_previews WHERE token=?", (hashlib.sha256(token.encode()).hexdigest(),))
            return json.loads(row[0])

    @staticmethod
    def totp(secret, counter):
        key = base64.b32decode(secret, casefold=True)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 15
        return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)

    def verify_login_factor(self, con, owner, supplied):
        factor = self.document("totp", "owner", con=con)
        if not factor.get("enabled"):
            return
        if not isinstance(supplied, str) or not re.fullmatch(r"\d{6}", supplied):
            raise HTTPException(401, "Saisissez votre code d’authentification à six chiffres.")
        counter = int(time.time()) // 30
        secret = self.decrypt(factor["secret"])
        match = next((step for step in range(counter - 1, counter + 2) if step > factor.get("last_counter", -1) and hmac.compare_digest(self.totp(secret, step), supplied)), None)
        if match is None:
            raise HTTPException(401, "Code incorrect ou déjà utilisé.")
        factor["last_counter"] = match
        self.put(con, "totp", "owner", factor)

    def site_config(self, site="primary"):
        saved = self.document("connection", "primary")
        return {"id": "primary", "name": saved.get("name", "Livebox"), "url": saved.get("url", self.c.LIVEBOX_URL), "username": saved.get("username", self.c.LIVEBOX_USERNAME), "password": self.decrypt(saved["password"]) if saved.get("password") else self.c.LIVEBOX_PASSWORD, "enabled": True}

    @contextlib.contextmanager
    def router(self, config):
        session = self.c.LmSession(config["url"])
        api = None
        try:
            if session.signin(config["username"], config["password"]) != 1:
                raise HTTPException(400, "La Livebox a refusé l’authentification.")
            api = self.c.ApiRegistry(session)
            yield api
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(502, "La Livebox ne répond pas à cette adresse.")
        finally:
            if api is not None:
                api.close()
            else:
                session.close()

    # ----- Wi-Fi ---------------------------------------------------------

    def wifi_overview(self, now=None):
        now = int(now or time.time())
        with self.db() as con:
            rows = con.execute("""SELECT w.mac,w.ts,w.rssi,w.band,w.access_point,d.active,d.ip,
                   COALESCE(NULLIF(p.custom_name,''),d.name,w.mac) name,COALESCE(p.category,'') category,COALESCE(p.location,'') location
                   FROM wifi_samples w JOIN (SELECT mac,MAX(ts) ts FROM wifi_samples WHERE site='primary' AND ts>=? GROUP BY mac) l ON l.mac=w.mac AND l.ts=w.ts
                   JOIN devices d ON d.mac=w.mac LEFT JOIN device_profiles p ON p.mac=w.mac WHERE w.site='primary'""", (now - 86400,)).fetchall()
        devices = []
        for r in rows:
            fresh = bool(r["active"]) and now - r["ts"] <= 900
            devices.append({"mac": r["mac"], "name": r["name"], "category": r["category"], "location": r["location"], "ip": r["ip"], "active": bool(r["active"]), "fresh": fresh, "ts": r["ts"], "rssi": r["rssi"], "quality": signal_quality(r["rssi"]), "interface": r["band"], "connection": link_type(r["band"]), "access_point": r["access_point"]})
        devices.sort(key=lambda d: (not d["fresh"], d["rssi"] is None, d["rssi"] if d["rssi"] is not None else 0, d["name"].lower()))
        return {"devices": devices, "threshold": WEAK_SIGNAL_DBM, "ts": now, "note": "Signal en dBm tel que rapporté par la Livebox, dernière mesure réelle par tranche de cinq minutes. Plus la valeur est proche de 0, meilleur est le signal."}

    def wifi_device(self, mac, now=None):
        now = int(now or time.time())
        with self.db() as con:
            device = con.execute("SELECT d.mac,d.active,d.layer2_interface,COALESCE(NULLIF(p.custom_name,''),d.name,d.mac) name FROM devices d LEFT JOIN device_profiles p ON p.mac=d.mac WHERE d.mac=?", (mac,)).fetchone()
            if device is None:
                raise HTTPException(404, "Équipement introuvable.")
            history = [dict(r) for r in con.execute("SELECT ts,rssi,band,access_point FROM wifi_samples WHERE site='primary' AND mac=? AND ts>=? ORDER BY ts", (mac, now - 86400))]
        latest = history[-1] if history else None
        measured = [h for h in history if h["rssi"] is not None]
        rssi = latest["rssi"] if latest else None
        if not history:
            advice = "Aucune mesure Wi-Fi sur 24 h : cet appareil est probablement relié par câble ou hors ligne." if not link_type(device["layer2_interface"]).startswith("Wi-Fi") else "Aucune mesure sur 24 h : l’appareil est peut-être en veille ou éteint."
        elif rssi is None:
            advice = "La Livebox ne communique pas le niveau de signal de cet appareil."
        elif rssi <= WEAK_SIGNAL_DBM:
            advice = "Signal faible : débit réduit et coupures possibles. Rapprochez l’appareil de la box ou d’un répéteur, ou reliez-le par câble s’il est fixe."
        elif rssi <= -67:
            advice = "Signal correct pour la navigation ; la vidéo en haute définition peut ralentir. Éviter murs épais et électroménager entre l’appareil et la box aide."
        else:
            advice = "Bon signal : la couverture Wi-Fi n’est pas en cause en cas de lenteur."
        roaming = len({h["access_point"] for h in history if h["access_point"]}) > 1
        return {"mac": mac, "name": device["name"], "active": bool(device["active"]), "link": link_type(latest["band"] if latest else device["layer2_interface"]), "connection": link_type(latest["band"] if latest else device["layer2_interface"]),
                "latest": latest, "quality": signal_quality(rssi), "advice": advice, "roaming": roaming,
                "min": min((h["rssi"] for h in measured), default=None), "max": max((h["rssi"] for h in measured), default=None),
                "history": history, "threshold": WEAK_SIGNAL_DBM}

    # ----- New devices ---------------------------------------------------

    def set_acknowledged(self, mac, recognised):
        """The owner recognises a newcomer: it leaves the « new » highlight, reversibly."""
        normalized = self.c.normalized_mac(mac)
        if not normalized or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", normalized):
            raise HTTPException(400, "Adresse MAC invalide.")
        with self.db() as con:
            if not con.execute("SELECT 1 FROM devices WHERE mac=?", (normalized,)).fetchone():
                raise HTTPException(404, "Équipement introuvable.")
            if recognised:
                self.put(con, "acknowledged", normalized, {"ts": int(time.time())})
            else:
                con.execute("DELETE FROM feature_documents WHERE kind='acknowledged' AND id=?", (normalized,))
        return {"mac": normalized, "acknowledged": recognised}

    def observe(self, inventory, site="primary", api=None, wan=None, poll_wan=False):
        """Record Wi-Fi samples from the inventory already collected (first connections are detected by the collector)."""
        now = int(time.time())
        with self.db() as con:
            for device in inventory:
                if not isinstance(device, dict):
                    continue
                mac = self.c.normalized_mac(device.get("PhysAddress") or device.get("MACAddress"))
                if not mac or con.execute("SELECT 1 FROM ignored_devices WHERE mac=?", (mac,)).fetchone():
                    continue
                name = str(device.get("Name") or mac)[:100]
                ip = self.c.normalize_ip(device.get("IPAddress")) or self.c.normalize_ip(device.get("IPv4Address"))
                active = str(device.get("Active", "")).lower() in ("1", "true", "yes", "up")
                band = str(device.get("Layer2Interface") or device.get("InterfaceName") or "")[:100]
                self.put(con, "observation", "primary:" + mac, {"ip": ip, "seen_at": now})
                rssi = device.get("SignalStrength", device.get("RSSI"))
                try:
                    rssi = float(rssi)
                    if not math.isfinite(rssi) or not -130 <= rssi <= -1:
                        rssi = None
                except (TypeError, ValueError):
                    rssi = None
                access_point = str(device.get("AccessPoint") or device.get("Parent") or "")[:100]
                if active and ("wl" in band.lower() or "wifi" in band.lower() or rssi is not None):
                    # Keep the actual timestamp of the last sample in each 5m window.
                    con.execute("DELETE FROM wifi_samples WHERE site='primary' AND mac=? AND ts>=?", (mac, now // 300 * 300))
                    con.execute("INSERT OR REPLACE INTO wifi_samples VALUES('primary',?,?,?,?,?)", (mac, now, rssi, band, access_point))
            con.execute("DELETE FROM wifi_samples WHERE ts<?", (now - self.retention("raw_days", 30) * 86400,))

    def new_device_email_enabled(self):
        # Like the other network alerts, enabled unless explicitly switched off.
        return self.c.read_app_settings().get("email_alert_new_device", "1") != "0"

    def announce_new_devices(self, arrivals):
        try:
            if not arrivals or not self.new_device_email_enabled():
                return
            config = self.c.load_smtp_settings()
            if not config.get("smtp_host") or not config.get("alert_email_to"):
                return
            base = self.c.public_base_url()
            shown = arrivals[:20]
            # Device names come from the network itself: keep them out of header syntax.
            safe_name = "".join(c for c in shown[0]["name"] if c.isprintable())[:60].strip() or shown[0]["mac"]
            subject = f"[Livebox Sentinel] Nouvel équipement : {safe_name}" if len(arrivals) == 1 else f"[Livebox Sentinel] {len(arrivals)} nouveaux équipements sur votre réseau"
            lines = ["Un nouvel équipement vient de se connecter à votre réseau." if len(arrivals) == 1 else f"{len(arrivals)} nouveaux équipements viennent de se connecter à votre réseau.", ""]
            for device in shown:
                lines += ["".join(c for c in device["name"] if c.isprintable() or c == " ")[:100], *recognition_lines(device.get("suggestion")), f"  Adresse IP : {device['ip'] or 'non communiquée'}", f"  Adresse MAC : {device['mac']}", f"  Liaison : {device['link']}", f"  Repéré {clock(device['ts'], absolute=True)}", f"  Fiche : {base}/?device={quote(device['mac'])}", ""]
            if len(arrivals) > len(shown):
                lines.append(f"… et {len(arrivals) - len(shown)} autre(s), visibles sur le tableau de bord.")
            lines += [f"Ces équipements restent signalés « Nouveau » pendant {NEW_DEVICE_DAYS} jours sur le tableau de bord.", "Si vous ne les reconnaissez pas, changez le mot de passe Wi-Fi depuis l’interface de la Livebox.", "Ces e-mails se désactivent dans Paramètres › Alertes réseau."]
            self.c.send_smtp_message(config, subject, "\n".join(lines))
            print(f"E-mail nouvel équipement envoyé : {len(arrivals)}", flush=True)
        except Exception as error:
            print("Échec de l'e-mail nouvel équipement :", type(error).__name__, flush=True)

    # ----- Background housekeeping --------------------------------------

    def retention(self, key, fallback):
        return self.document("retention").get(key, fallback)

    def tick(self):
        if time.monotonic() - self.last_tick < 60 or not self.tick_lock.acquire(False):
            return
        self.last_tick = time.monotonic()
        try:
            try:
                self.deliver_queued_email()
            except Exception as error:
                print("E-mails regroupés : erreur", type(error).__name__, flush=True)
            with self.db() as con:
                con.execute("DELETE FROM action_previews WHERE expires_at<?", (int(time.time()),))
                today = datetime.now(PARIS).date().isoformat()
                if not self.document("storage-history", today, con=con):
                    storage = self.c.get_about("features")
                    self.put(con, "storage-history", today, {"ts": int(time.time()), "bytes": storage["storage_bytes"]})
                settings = self.document("retention", con=con)
                if settings:
                    for table in ("notifications", "activity_log"):
                        con.execute(f"DELETE FROM {table} WHERE ts<?", (int(time.time()) - settings["events_days"] * 86400,))
                    con.execute("DELETE FROM notification_reads WHERE notification_id NOT IN(SELECT id FROM notifications)")
                con.execute("DELETE FROM feature_documents WHERE kind='storage-history' AND id<?", ((datetime.now(PARIS) - timedelta(days=90)).date().isoformat(),))
        finally:
            self.tick_lock.release()

    def loop(self):
        while not self.c.stop_event.is_set():
            try:
                self.tick()
            except Exception as error:
                print("Tâches de fond : erreur", type(error).__name__, flush=True)
            self.c.stop_event.wait(30)

    def quiet(self, settings, now=None):
        now = now or datetime.now(PARIS)
        start, end = settings.get("quiet_start", "22:00"), settings.get("quiet_end", "08:00")
        current = now.strftime("%H:%M")
        return bool(settings.get("quiet_enabled", False) and ((start <= current < end) if start < end else (current >= start or current < end)))

    def queue_email(self, subject, body, con=None):
        if con is None:
            with self.db() as connection:
                self.queue_email(subject, body, connection)
            return
        identifier = hashlib.sha256((subject + body).encode()).hexdigest()
        self.put(con, "mail-outbox", identifier, {"subject": subject, "body": body, "ts": int(time.time())})

    def deliver_queued_email(self):
        if self.quiet(self.document("notification-settings")):
            return
        with self.db() as con:
            rows = [(r[0], json.loads(r[1])) for r in con.execute("SELECT id,value FROM feature_documents WHERE kind='mail-outbox' ORDER BY rowid LIMIT 20")]
        if not rows:
            return
        body = "Alertes regroupées après les heures calmes\n\n" + "\n\n".join(item["body"] for _, item in rows)
        self.c.send_smtp_message(self.c.load_smtp_settings(), "[Livebox Sentinel] Vos alertes regroupées", body)
        with self.db() as con:
            con.executemany("DELETE FROM feature_documents WHERE kind='mail-outbox' AND id=?", [(identifier,) for identifier, _ in rows])

    # ----- Routes --------------------------------------------------------

    def register(self):
        app, auth = self.c.app, self.c.require_auth

        @app.get("/manifest.webmanifest", include_in_schema=False)
        def manifest():
            return Response(json.dumps({"id": "/", "name": "Livebox Sentinel", "short_name": "Sentinel", "lang": "fr", "start_url": "/", "scope": "/", "display": "standalone", "background_color": "#0c1220", "theme_color": "#101d30", "icons": [{"src": "/assets/sentinel-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"}, {"src": "/assets/sentinel-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"}]}), media_type="application/manifest+json")

        @app.get("/sw.js", include_in_schema=False)
        def service_worker():
            return FileResponse(ASSETS / "sw.js", media_type="text/javascript", headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})

        @app.get("/offline", response_class=HTMLResponse, include_in_schema=False)
        def offline():
            return (ASSETS / "offline.html").read_text()

        for name, media_type in (("sentinel.js", "text/javascript"), ("sentinel.css", "text/css"), ("network-map.js", "text/javascript"), ("network-map.css", "text/css"), ("sentinel-180.png", "image/png"), ("sentinel-192.png", "image/png"), ("sentinel-512.png", "image/png")):
            # Fixed asset routes: filenames cannot be supplied by the client.
            def route_for(filename, content_type):
                def get_asset():
                    return FileResponse(ASSETS / filename, media_type=content_type, headers={"Cache-Control": "no-cache"})
                return get_asset
            app.add_api_route("/assets/" + name, route_for(name, media_type), methods=["GET"], include_in_schema=False)

        @app.get("/workspace", include_in_schema=False)
        def former_workspace():
            # Bookmarks and installed shortcuts from 2.0/2.1 land on the dashboard.
            return RedirectResponse("/", status_code=308)

        @app.get("/wifi", response_class=HTMLResponse)
        def wifi_page(username: str = Depends(auth)):
            return self.c.WIFI_PAGE

        @app.get("/api/wifi")
        def wifi(username: str = Depends(auth)):
            return self.wifi_overview()

        @app.get("/api/wifi/{mac}")
        def wifi_device(mac: str, username: str = Depends(auth)):
            normalized = self.c.normalized_mac(mac)
            if not normalized or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", normalized):
                raise HTTPException(400, "Adresse MAC invalide.")
            return self.wifi_device(normalized)

        @app.post("/api/devices/{mac}/acknowledge")
        def acknowledge(mac: str, username: str = Depends(auth)):
            return self.set_acknowledged(mac, True)

        @app.delete("/api/devices/{mac}/acknowledge")
        def unacknowledge(mac: str, username: str = Depends(auth)):
            return self.set_acknowledged(mac, False)

        self.register_security()
        self.register_connection()
        self.register_data()

    def register_security(self):
        app, auth = self.c.app, self.c.require_auth

        def require_password(con, request, password):
            owner = con.execute("SELECT * FROM web_account WHERE id=1").fetchone()
            self.c.throttle_login(request)
            if not owner or not isinstance(password, str) or len(password) > 1024 or not self.c.verify_web_password(password, owner["password_hash"]):
                raise HTTPException(400, "Mot de passe actuel incorrect.")
            # Only failures count: sensitive actions must not lock the owner out.
            self.c.clear_login_failures(request)

        @app.get("/api/totp")
        def totp_state(username: str = Depends(auth)):
            return {"enabled": bool(self.document("totp", "owner").get("enabled"))}

        @app.post("/api/totp/setup")
        def totp_setup(payload: dict, request: Request, username: str = Depends(auth)):
            with self.db() as con:
                require_password(con, request, payload.get("password"))
                if self.document("totp", "owner", con=con).get("enabled"):
                    raise HTTPException(409, "Désactivez d’abord la validation actuelle.")
                secret = base64.b32encode(secrets.token_bytes(20)).decode()
                self.put(con, "totp-pending", "owner", {"secret": self.encrypt(secret), "expires_at": int(time.time()) + 600})
            return {"secret": secret, "uri": "otpauth://totp/" + quote("Livebox Sentinel:" + username) + "?secret=" + secret + "&issuer=Livebox%20Sentinel&algorithm=SHA1&digits=6&period=30"}

        @app.post("/api/totp/confirm")
        def totp_confirm(payload: dict, request: Request, username: str = Depends(auth)):
            with self.db() as con:
                con.execute("BEGIN IMMEDIATE")
                self.c.throttle_login(request)
                pending = self.document("totp-pending", "owner", con=con)
                if pending.get("expires_at", 0) <= time.time():
                    raise HTTPException(409, "La préparation a expiré. Recommencez.")
                self.put(con, "totp", "owner", {"secret": pending["secret"], "enabled": True, "last_counter": -1})
                try:
                    self.verify_login_factor(con, {}, payload.get("otp", ""))
                except HTTPException as error:
                    raise HTTPException(400, error.detail)
                con.execute("DELETE FROM feature_documents WHERE kind='totp-pending' AND id='owner'")
                con.execute("DELETE FROM web_sessions WHERE id<>?", (request.state.web_session["id"],))
                self.audit(con, username, "account.totp-enabled")
            self.c.clear_login_failures(request)
            return {"saved": True}

        @app.post("/api/totp/disable")
        def totp_disable(payload: dict, request: Request, username: str = Depends(auth)):
            with self.db() as con:
                con.execute("BEGIN IMMEDIATE")
                require_password(con, request, payload.get("password"))
                try:
                    self.verify_login_factor(con, {}, payload.get("otp", ""))
                except HTTPException as error:
                    raise HTTPException(400, error.detail)
                con.execute("DELETE FROM feature_documents WHERE kind='totp' AND id='owner'")
                # Like enabling it, a change of protection closes the other devices' sessions.
                con.execute("DELETE FROM web_sessions WHERE id<>?", (request.state.web_session["id"],))
                self.audit(con, username, "account.totp-disabled")
            return {"saved": True}

    def register_connection(self):
        app, auth = self.c.app, self.c.require_auth

        @app.get("/api/livebox-connection")
        def connection(username: str = Depends(auth)):
            config = self.site_config()
            return {"url": config["url"], "username": config["username"], "password_set": bool(config["password"]), "source": "application" if self.document("connection", "primary") else ".env"}

        @app.post("/api/livebox-connection/test")
        def connection_test(payload: dict, username: str = Depends(auth)):
            old = self.site_config()
            password = payload.get("password", "")
            if not isinstance(password, str) or len(password) > 1024:
                raise HTTPException(400, "Mot de passe invalide.")
            config = {"id": "primary", "name": "Livebox", "url": lan_url(payload.get("url", "")), "username": text(payload.get("username", "admin"), 80, False), "password": password, "enabled": True}
            # The saved password only goes back to the box it was saved for.
            if not password and urlsplit(config["url"]).netloc == urlsplit(old["url"]).netloc and config["username"] == old["username"]:
                config["password"] = old["password"]
            if not config["password"]:
                raise HTTPException(400, "Renseignez le mot de passe d’administration de la Livebox (obligatoire quand l’adresse ou l’identifiant change).")
            with self.router(config) as api:
                info = api._info.get_device_info() or {}
                devices = api._device.get_list()
            token = self.preview(username, "connection", {**config, "password": self.encrypt(config["password"])})
            return {"token": token, "model": str(info.get("ModelName") or "Livebox")[:100], "devices": len(devices), "message": "Connexion réussie, en lecture seule. Confirmez pour utiliser ces paramètres."}

        @app.post("/api/livebox-connection/confirm")
        def confirm_connection(payload: dict, username: str = Depends(auth)):
            config = self.consume_preview(payload.get("token"), username, "connection")
            with self.db() as con:
                self.put(con, "connection", "primary", config)
                self.audit(con, username, "connection.updated", config["url"])
            return {"saved": True, "message": "Connexion enregistrée. Elle sera utilisée au prochain relevé."}

        @app.delete("/api/livebox-connection")
        def delete_connection(username: str = Depends(auth)):
            with self.db() as con:
                con.execute("DELETE FROM feature_documents WHERE kind='connection' AND id='primary'")
                self.audit(con, username, "connection.removed")
            return {"saved": True, "message": "Les paramètres du fichier .env seront utilisés au prochain relevé."}

    def register_data(self):
        app, auth = self.c.app, self.c.require_auth

        @app.get("/api/retention")
        def retention(username: str = Depends(auth)):
            settings = self.document("retention", default={"raw_days": 30, "aggregate_days": 365, "events_days": 365})
            return {"settings": settings, "storage": self.c.get_about("features"), "growth": self.storage_growth()}

        @app.post("/api/retention/preview")
        def retention_preview(payload: dict, username: str = Depends(auth)):
            settings = {key: integer(payload.get(key, fallback), minimum, maximum) for key, fallback, minimum, maximum in (("raw_days", 30, 7, 90), ("aggregate_days", 365, 30, 730), ("events_days", 365, 30, 730))}
            if settings["aggregate_days"] < settings["raw_days"]:
                raise HTTPException(400, "L’historique agrégé doit couvrir au moins l’historique détaillé.")
            return {"token": self.preview(username, "retention", settings), "eligible_rows": self.retention_counts(settings), "settings": settings}

        @app.post("/api/retention/confirm")
        def retention_confirm(payload: dict, username: str = Depends(auth)):
            settings = self.consume_preview(payload.get("token"), username, "retention")
            with self.db() as con:
                self.put(con, "retention", "main", settings)
                for table, column, key, condition in self.retention_tables():
                    con.execute(f"DELETE FROM {table} WHERE {condition} {column}<?", (int(time.time()) - settings[key] * 86400,))
                con.execute("DELETE FROM notification_reads WHERE notification_id NOT IN(SELECT id FROM notifications)")
                self.audit(con, username, "retention.applied", json.dumps(settings))
            return {"saved": True, "message": "Durées de conservation appliquées."}

        @app.get("/api/audit")
        def audit(username: str = Depends(auth)):
            with self.db() as con:
                return [dict(r) for r in con.execute("SELECT id,ts,action,detail FROM activity_log ORDER BY id DESC LIMIT 150")]

    @staticmethod
    def retention_tables():
        return (("wifi_samples", "ts", "raw_days", ""), ("traffic", "ts", "raw_days", ""), ("traffic_15m", "bucket_ts", "aggregate_days", ""), ("wan_traffic", "ts", "aggregate_days", ""), ("livebox_health", "ts", "aggregate_days", ""), ("internet_checks", "ts", "events_days", ""), ("internet_events", "started_at", "events_days", "ended_at IS NOT NULL AND"), ("device_incidents", "opened_at", "events_days", "ended_at IS NOT NULL AND"), ("notifications", "ts", "events_days", ""), ("activity_log", "ts", "events_days", ""), ("device_presence_events", "ts", "events_days", ""))

    def retention_counts(self, settings):
        with self.db() as con:
            return {table: con.execute(f"SELECT COUNT(*) FROM {table} WHERE {condition} {column}<?", (int(time.time()) - settings[key] * 86400,)).fetchone()[0] for table, column, key, condition in self.retention_tables()}

    def storage_growth(self):
        with self.db() as con:
            points = [json.loads(r[0]) for r in con.execute("SELECT value FROM feature_documents WHERE kind='storage-history' ORDER BY id DESC LIMIT 30")]
        points.sort(key=lambda p: p["ts"])
        if len(points) < 3 or points[-1]["ts"] - points[0]["ts"] < 2 * 86400:
            return {"bytes_per_day": None, "note": "La tendance apparaîtra après au moins trois jours de relevés. Les sauvegardes sont exclues."}
        rate = (points[-1]["bytes"] - points[0]["bytes"]) / ((points[-1]["ts"] - points[0]["ts"]) / 86400)
        return {"bytes_per_day": round(rate), "projection_30d": max(0, round(points[-1]["bytes"] + rate * 30)), "note": "Projection indicative fondée sur l’espace occupé, susceptible de varier avec les purges et les usages."}
