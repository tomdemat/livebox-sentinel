"""Local device recognition: suggests a category, a vendor and a readable name.

Everything is computed from what the Livebox already reports (host name, DHCP
fingerprint, mDNS and UPnP announcements, types it detected) and from the IEEE
vendor registry shipped with the image. Nothing leaves the server, and a
suggestion never overwrites what the owner entered.
"""
import gzip
import json
import re
import threading
from pathlib import Path

OUI_PATH = Path(__file__).parent / "resources" / "oui.tsv.gz"
_oui = None
_oui_lock = threading.Lock()

# Categories match CATEGORY_PRESETS of the interface.
PRESETS = ("Ordinateur", "Téléphone", "Tablette", "Télévision", "Console", "Objet connecté", "Lumière",
           "Imprimante", "Serveur", "Stockage réseau", "Caméra", "Audio", "Réseau", "Domotique")
# A label the owner already uses for the same idea wins over the preset.
SYNONYMS = {
    "Audio": ("enceinte", "enceintes", "son", "hi-fi", "hifi", "speaker"),
    "Télévision": ("tv", "télé", "tele", "televiseur", "téléviseur"),
    "Téléphone": ("smartphone", "mobile", "portable"),
    "Ordinateur": ("pc", "laptop", "ordinateur portable"),
    "Objet connecté": ("objet", "iot", "objets connectés"),
    "Montre": ("montre", "montres", "watch"),
}
BRANDS = {
    "Lumi United": "Aqara (Lumi)", "BSH Hausgeräte": "Bosch / Siemens", "Raspberry Pi Foundation": "Raspberry Pi",
    "Raspberry Pi Trading": "Raspberry Pi", "Sercomm France": "Sercomm (Orange)", "Signify Netherlands": "Philips Hue (Signify)",
    "Philips Lighting BV": "Philips Hue", "Hon Hai Precision Ind": "Foxconn", "Intel Corporate": "Intel", "iRobot": "iRobot", "Sony Interactive Entertainment": "Sony PlayStation",
}

# (pattern on host and announced names, category, weight, readable reason)
NAME_RULES = [
    (r"iphone|android|galaxy-?[asmz]\d|pixel-?\d|redmi|oneplus|xiaomi-?\d|huawei-p", "Téléphone", 3),
    (r"ipad|galaxy-?tab|\btab-|tablet", "Tablette", 3),
    (r"watch", "Montre", 3),
    (r"macbook|imac|mac-?mini|mac-?studio|desktop-|laptop|^lt-|^pc-|thinkpad|surface|chromebook", "Ordinateur", 3),
    (r"xbox|ps[345]\b|ps[345]-|playstation|nintendo|switch", "Console", 3),
    (r"apple-?tv|bravia|webos|lgwebos|\[tv\]|chromecast|fire-?tv|android-?tv|\btv\b|-tv\b|^tv-|freebox-?player|decodeur|uhd86", "Télévision", 3),
    (r"homepod|sonos|echo-|alexa|bose|denon|marantz|yamaha|nest-?(mini|audio)|google-?home", "Audio", 3),
    (r"cam(era)?\b|camera-|ipcam|doorbell|ring-|arlo|reolink|hikvision|dahua|imou|ezviz|blink", "Caméra", 3),
    (r"repeteur|repeater|extender|mesh|deco-|wifi-?ap|airport|\bap\b", "Réseau", 3),
    (r"printer|imprim|officejet|deskjet|laserjet|envy|epson|brother|canon|^hp[0-9a-f]{6}", "Imprimante", 3),
    (r"synology|diskstation|qnap|\bnas\b|-nas|nas-|freenas|truenas", "Stockage réseau", 3),
    (r"raspberry|raspberrypi|\bserver\b|serveur|proxmox|unraid|homeassistant|home-assistant|jeedom|domoticz", "Serveur", 3),
    (r"hue|philips-hue|lifx|nanoleaf|yeelight|wiz|lampe|light|bulb|ampoule", "Lumière", 3),
    (r"tado|netatmo|thermostat|somfy|tahoma|homey|zigbee|deconz|conbee|bridge|hub", "Domotique", 2),
    (r"dishwasher|washer|dryer|lave|roomba|dyson|vacuum|aspirateur|purifier|fridge|oven|tesla|wallbox", "Objet connecté", 3),
    (r"^esp[_-]|espressif|^ty_|tuya|shelly|sonoff|tasmota|wled|smart-?plug|^plug", "Objet connecté", 2),
]
# Types reported by the Livebox, whatever detected them.
TYPE_RULES = {
    "mobile": "Téléphone", "mobile ios": "Téléphone", "mobile android": "Téléphone", "smartphone": "Téléphone",
    "tablet": "Tablette", "tablet ios": "Tablette", "tablet android": "Tablette",
    "tv": "Télévision", "apple tv": "Télévision", "mediarenderer": "Télévision", "set-top box": "Télévision", "settopbox": "Télévision",
    "laptop": "Ordinateur", "laptop linux": "Ordinateur", "laptop windows": "Ordinateur", "desktop": "Ordinateur",
    "desktop ios": "Ordinateur", "desktop windows": "Ordinateur", "desktop linux": "Ordinateur",
    "game console": "Console", "gameconsole": "Console", "printer": "Imprimante", "nas": "Stockage réseau",
    "domestic robot": "Objet connecté", "ac outlet": "Objet connecté", "homepoint": "Objet connecté",
    "homeplug": "Lumière", "homelibrary": "Domotique", "webcam": "Caméra", "camera": "Caméra",
    "speaker": "Audio", "repeteurwifi6": "Réseau", "repeteurwifi": "Réseau", "sah ap": "Réseau", "wifi bridge": "Réseau",
}
VENDOR_RULES = [
    (r"espressif|tuya|shelly|itead|azurewave|hui zhou gaoshengda|beken|realtek semiconductor", "Objet connecté", 1, "puce d’objet connecté"),
    (r"sonos|bose|denon|harman|bang & olufsen|devialet|marantz", "Audio", 3, None),
    (r"philips|signify|lifx|nanoleaf|yeelight", "Lumière", 3, None),
    (r"netatmo|tado|somfy|aqara|lumi|athom|ecobee|nest", "Domotique", 2, None),
    (r"synology|qnap|western digital", "Stockage réseau", 3, None),
    (r"raspberry", "Serveur", 2, None),
    (r"brother|epson|canon|lexmark|kyocera|xerox", "Imprimante", 2, None),
    (r"nintendo|sony interactive|playstation", "Console", 3, None),
    (r"irobot|dyson|bsh|miele|ecovacs|roborock|dreame|neato", "Objet connecté", 3, None),
    (r"hikvision|dahua|reolink|ring|arlo|ezviz|imou|wyze|axis communications", "Caméra", 3, None),
    (r"sercomm|arcadyan|sagemcom|ubiquiti|tp-link|netgear|devolo|zyxel|eero", "Réseau", 1, None),
    (r"roku|amazon technologies", "Télévision", 1, None),
]
APPLE_MODELS = [
    (r"^audioaccessory", "Audio", "HomePod"), (r"^appletv", "Télévision", "Apple TV"),
    (r"^macbook", "Ordinateur", "MacBook"), (r"^(imac|macmini|macpro|mac\d)", "Ordinateur", "Mac"),
    (r"^iphone", "Téléphone", "iPhone"), (r"^ipad", "Tablette", "iPad"), (r"^watch", "Montre", "Apple Watch"),
]
MDNS_RULES = [
    ("_googlecast._tcp", "Télévision", 2, "diffusion Chromecast"),
    ("_ipp._tcp", "Imprimante", 3, "service d’impression"), ("_ipps._tcp", "Imprimante", 3, "service d’impression"),
    ("_printer._tcp", "Imprimante", 3, "service d’impression"), ("_pdl-datastream._tcp", "Imprimante", 3, "service d’impression"),
    ("_scanner._tcp", "Imprimante", 1, "service de numérisation"),
    ("_hap._tcp", "Domotique", 2, "accessoire HomeKit"), ("_hap._udp", "Domotique", 2, "accessoire HomeKit"),
    ("_spotify-connect._tcp", "Audio", 2, "Spotify Connect"), ("_sonos._tcp", "Audio", 3, "service Sonos"),
    ("_smb._tcp", "Stockage réseau", 1, "partage de fichiers"), ("_afpovertls._tcp", "Stockage réseau", 1, "partage de fichiers"),
    ("_home-assistant._tcp", "Serveur", 3, "Home Assistant"), ("_ssh._tcp", "Serveur", 1, "accès SSH"),
    ("_amzn-wplay._tcp", "Télévision", 2, "Fire TV"), ("_androidtvremote2._tcp", "Télévision", 3, "Android TV"),
]
# DHCP parameter request lists (option 55) typical of a family of systems.
DHCP_FAMILIES = [
    ("1,121,3,6,15,108,114,119,162", "Apple", None, 0, "empreinte DHCP Apple"),
    ("1,3,28,6,15,44,46,47,31,33,121,43", "ESP", "Objet connecté", 2, "empreinte DHCP d’un module ESP"),
    ("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows", "Ordinateur", 2, "empreinte DHCP Windows"),
    ("1,3,6,15,26,28,51,58,59,43", "Android", "Téléphone", 2, "empreinte DHCP Android"),
    ("1,3,28,6", "Embarqué", "Objet connecté", 1, "empreinte DHCP d’un appareil embarqué"),
]
VCI_RULES = [
    (r"xbox", "Console", 4, "système Xbox annoncé"), (r"^msft", "Ordinateur", 2, "système Windows annoncé"),
    (r"^android-dhcp", "Téléphone", 2, "système Android annoncé"), (r"^udhcp", "Objet connecté", 1, "Linux embarqué annoncé"),
    (r"sercomm|arcadyan|sagem", "Réseau", 2, "équipement réseau annoncé"),
]
UA_RULES = [
    (r"apple tv", "Télévision", 2, "navigation d’une Apple TV"), (r"watch ?os", "Montre", 1, "trafic watchOS"),
    (r"debian apt|ubuntu|apt-http|yum|dnf", "Serveur", 2, "mises à jour Linux"), (r"playstation|ps5", "Console", 3, "navigation PlayStation"),
    (r"tizen|webos|smart-?tv|bravia|hbbtv", "Télévision", 3, "navigation d’un téléviseur"),
]
APPLE_PREFIX = DHCP_FAMILIES[0][0]


def _vendors():
    global _oui
    with _oui_lock:
        if _oui is None:
            table = {}
            try:
                with gzip.open(OUI_PATH, "rt", encoding="utf-8") as source:
                    for line in source:
                        if not line.startswith("#") and "\t" in line:
                            prefix, name = line.rstrip("\n").split("\t", 1)
                            table[prefix] = name
            except OSError as error:
                print("Liste des fabricants indisponible :", type(error).__name__, flush=True)
            _oui = table
        return _oui


def private_mac(mac):
    try:
        return bool(int(mac.replace(":", "")[:2], 16) & 2)
    except ValueError:
        return False


def vendor_for(mac):
    digits = mac.replace(":", "").replace("-", "").upper()
    if len(digits) != 12 or private_mac(digits):
        return ""
    table = _vendors()
    for size in (9, 7, 6):
        name = table.get(digits[:size])
        if name:
            return BRANDS.get(name, name)
    return ""


def _text(value, limit=120):
    return "".join(c for c in str(value or "") if c.isprintable()).strip()[:limit]


def _txt_models(text):
    return re.findall(r'"(?:model|am|md)=([A-Za-z][A-Za-z0-9 ,._-]{1,40})"', str(text or ""))


def fingerprint(device):
    """Keeps only the identifying signals of a Livebox inventory entry, compact and bounded."""
    names = []
    for entry in device.get("Names") or []:
        if isinstance(entry, dict) and entry.get("Source") not in (None, "", "default"):
            names.append([_text(entry.get("Source"), 40), _text(entry.get("Name"), 80)])
    types = []
    for entry in device.get("DeviceTypes") or []:
        if isinstance(entry, dict) and entry.get("Source") not in (None, "", "default") and entry.get("Type"):
            source = _text(entry.get("Source"), 40)
            types.append(["upnp" if source.startswith("upnp") else source, _text(entry.get("Type"), 60)])
    services, models = [], []
    for entry in device.get("mDNSService") or []:
        if isinstance(entry, dict):
            if entry.get("ServiceName"):
                services.append(_text(entry["ServiceName"], 60))
            models += _txt_models(entry.get("Text"))
    agents = [_text(entry.get("UserAgent"), 120) for entry in device.get("UserAgents") or [] if isinstance(entry, dict) and entry.get("UserAgent")]
    return {
        "host": _text(device.get("Name"), 80),
        "names": names[:8], "types": types[:8],
        "vci": _text(device.get("VendorClassID"), 80),
        "dhcp55": re.sub(r"[^0-9,]", "", str(device.get("DHCPOption55") or ""))[:120],
        "services": sorted(set(services))[:16], "models": sorted(set(models))[:4], "agents": agents[:4],
    }


def merge(previous, current):
    """Announcements come and go (mDNS, user agents): keep what was already learned."""
    if not previous:
        return current
    merged = dict(current)
    for key in ("services", "models"):
        merged[key] = sorted(set(previous.get(key, [])) | set(current.get(key, [])))[:16 if key == "services" else 4]
    for key, limit in (("names", 8), ("types", 8), ("agents", 4)):
        seen, values = set(), []
        for item in current.get(key, []) + previous.get(key, []):
            marker = json.dumps(item, ensure_ascii=False)
            if marker not in seen:
                seen.add(marker)
                values.append(item)
        merged[key] = values[:limit]
    for key in ("vci", "dhcp55", "host"):
        merged[key] = current.get(key) or previous.get(key, "")
    return merged


def _model_name(signals):
    """A readable product name announced by the device itself, when there is one."""
    for source, name in signals.get("names", []):
        if source == "upnp" and name:
            return re.sub(r"^\[[^\]]+\]\s*", "", name)[:60]
    for model in signals.get("models", []):
        for pattern, _, label in APPLE_MODELS:
            if re.match(pattern, model, re.I):
                return label
    return ""


def suggest(mac, signals, existing_categories=()):
    """Returns {category, confidence, vendor, model, reasons} or None without useful signal."""
    signals = signals or {}
    scores, reasons = {}, {}

    specific = set()

    def vote(category, weight, reason, generic=False):
        if weight <= 0:
            return
        if not generic:
            specific.add(category)
        scores[category] = scores.get(category, 0) + weight
        bucket = reasons.setdefault(category, [])
        if reason not in bucket:
            bucket.append(reason)

    announced = [signals.get("host", "")] + [name for _, name in signals.get("names", [])]
    for pattern, category, weight in NAME_RULES:
        hit = next((name for name in announced if name and re.search(pattern, name, re.I)), None)
        if hit:
            vote(category, weight, f"le nom « {hit[:40]} »", generic=weight < 3)
            break
    for source, kind in signals.get("types", []):
        category = TYPE_RULES.get(kind.strip().lower())
        if category:
            label = "type choisi dans la Livebox" if source == "webui" else f"type « {kind} » détecté par la Livebox"
            vote(category, 4 if source == "webui" else 3, label)
    vci = signals.get("vci", "")
    for pattern, category, weight, reason in VCI_RULES:
        if re.search(pattern, vci, re.I):
            vote(category, weight, reason)
            break
    dhcp = signals.get("dhcp55", "")
    family = ""
    for prefix, name, category, weight, reason in DHCP_FAMILIES:
        if dhcp == prefix or dhcp.startswith(prefix + ","):
            family = name
            if category:
                vote(category, weight, reason, generic=True)
            break
    for model in signals.get("models", []):
        for pattern, category, label in APPLE_MODELS:
            if re.match(pattern, model, re.I):
                vote(category, 4, f"modèle {label} annoncé")
                break
    services = set(signals.get("services", []))
    for service, category, weight, reason in MDNS_RULES:
        if service in services:
            vote(category, weight, reason)
    if "_airplay._tcp" in services and not scores:
        vote("Audio", 1, "réception AirPlay")
    for agent in signals.get("agents", []):
        for pattern, category, weight, reason in UA_RULES:
            if re.search(pattern, agent, re.I):
                vote(category, weight, reason)

    private = private_mac(mac)
    vendor = vendor_for(mac)
    if vendor:
        for pattern, category, weight, reason in VENDOR_RULES:
            if re.search(pattern, vendor, re.I):
                vote(category, weight, reason or f"fabricant {vendor}", generic=reason is not None)
                break
    elif family == "Apple" or any(re.match(pattern, model, re.I) for model in signals.get("models", []) for pattern, _, _ in APPLE_MODELS):
        vendor = "Apple"
    vendor_note = f"{vendor} (adresse privée)" if private and vendor else ("Adresse privée" if private else vendor)
    if not scores:
        return {"category": "", "confidence": "", "vendor": vendor_note, "model": _model_name(signals), "reasons": []} if vendor_note else None

    ranked = sorted(scores.items(), key=lambda item: -item[1])
    category, score = ranked[0]
    margin = score - (ranked[1][1] if len(ranked) > 1 else 0)
    confidence = "élevée" if score >= 4 and margin >= 2 else ("moyenne" if score >= 2 else "faible")
    if confidence == "élevée" and category not in specific:
        # A Wi-Fi chip says « connected object », not which one (light, plug, sensor…).
        confidence = "moyenne"
    why = list(reasons[category])
    if vendor and not any(vendor in reason for reason in why) and not any(reason in why for *_, reason in VENDOR_RULES if reason):
        why.append(f"fabricant {vendor}")
    return {"category": label_for(category, existing_categories), "confidence": confidence,
            "vendor": vendor_note, "model": _model_name(signals), "reasons": why[:4]}


def label_for(category, existing_categories):
    """Uses the owner's own label for the same idea (« Enceinte » rather than « Audio »)."""
    existing = [value for value in existing_categories if value]
    lowered = {value.strip().lower(): value for value in existing}
    if category.lower() in lowered:
        return lowered[category.lower()]
    for synonym in SYNONYMS.get(category, ()):
        if synonym in lowered:
            return lowered[synonym]
    if category == "Montre":
        return "Objet connecté"
    return category
