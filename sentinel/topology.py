"""Network topology: who is connected to what, from the Livebox's own tree.

TopologyDiagnostics:buildTopology returns the Livebox, its Ethernet ports and Wi-Fi
radios, the Wi-Fi repeaters and the devices behind each of them. This keeps only that
structure, compact and bounded: names, categories and states come from Sentinel itself.
"""
import re

MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
MAX_NODES = 600
MAX_DEPTH = 10


def _tags(node):
    return set(str(node.get("Tags") or "").split())


def _text(value, limit=80):
    return "".join(c for c in str(value or "") if c.isprintable()).strip()[:limit]


def _band(value):
    value = str(value or "").replace(" ", "").lower()
    return {"2.4ghz": "2,4 GHz", "5ghz": "5 GHz", "6ghz": "6 GHz"}.get(value, "")


def _port_label(key):
    match = re.fullmatch(r"eth(\d+)", str(key or ""), re.I)
    return f"Port Ethernet {match.group(1)}" if match else (_text(key, 30) or "Port Ethernet")


def parse(tree):
    """Returns {"root": node} or {} when the answer is not a Livebox topology.

    A node is {"kind", "label", "children"} plus, depending on the kind:
    livebox (model), port (port), wifi (band, guest), repeater and device (mac, link, band, port).
    """
    roots = tree if isinstance(tree, list) else [tree]
    root = next((node for node in roots if isinstance(node, dict) and "hgw" in _tags(node)), None)
    if root is None:
        return {}
    count = [0]

    def visit(node, depth, link):
        """Returns the list of nodes this Livebox entry stands for (bridges are flattened)."""
        if not isinstance(node, dict) or depth > MAX_DEPTH or count[0] >= MAX_NODES:
            return []
        tags = _tags(node)
        key = str(node.get("Key") or "")
        device = bool(MAC.match(key)) and "physical" in tags
        # A device can carry an « upnp » tag; its UPnP services are separate logical nodes.
        if tags & {"voice", "usb", "endpoint"} or (not device and tags & {"logical", "upnp"}):
            return []
        if "interface" in tags and "eth" in tags:
            label = _port_label(key)
            here = {"kind": "port", "label": label, "port": label}
            child_link = {"link": "ethernet", "port": label, "band": ""}
        elif "interface" in tags and "vap" in tags:
            band = _band(node.get("OperatingFrequencyBand"))
            guest = "guest" in key.lower()
            here = {"kind": "wifi", "label": ("Wi-Fi invité " if guest else "Wi-Fi ") + (band or ""), "band": band, "guest": guest}
            child_link = {"link": "wifi", "port": "", "band": band}
        elif device:
            mac = key.lower()
            here = {"kind": "device", "mac": mac, "label": _text(node.get("Name")) or mac, **link}
            child_link = {"link": "", "port": "", "band": ""}
        else:
            # The Livebox's LAN and guest bridges only group interfaces.
            flattened = []
            for child in node.get("Children") or []:
                flattened += visit(child, depth + 1, link)
            return flattened
        count[0] += 1
        children = []
        for child in node.get("Children") or []:
            children += visit(child, depth + 1, child_link)
        if here["kind"] == "device" and any(child["kind"] in ("wifi", "port") for child in children):
            here["kind"] = "repeater"
        if here["kind"] in ("port", "wifi") and not children:
            return []
        here["children"] = children
        return [here]

    children = []
    for child in root.get("Children") or []:
        children += visit(child, 1, {"link": "", "port": "", "band": ""})
    model = _text(root.get("ModelName") or root.get("ProductClass") or root.get("DeviceType"), 60)
    return {"root": {"kind": "livebox", "label": "Livebox", "model": model, "children": children}}


def placements(parsed):
    """{mac: {"via": access point label, "via_mac", "link", "band", "port"}} for every device."""
    found = {}

    def walk(node, access_point):
        for child in node.get("children", []):
            if child["kind"] in ("device", "repeater"):
                found[child["mac"]] = {"via": access_point["label"], "via_mac": access_point.get("mac", ""),
                                       "link": child.get("link", ""), "band": child.get("band", ""), "port": child.get("port", "")}
            walk(child, child if child["kind"] == "repeater" else access_point)

    if parsed.get("root"):
        walk(parsed["root"], parsed["root"])
    return found
