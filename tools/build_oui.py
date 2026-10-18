"""Rebuilds sentinel/resources/oui.tsv.gz, the vendor table used by device recognition.

Source: the IEEE registry as published by Wireshark (https://www.wireshark.org/download/automated/data/manuf).
    curl -L -o /tmp/manuf https://www.wireshark.org/download/automated/data/manuf
    python3 tools/build_oui.py /tmp/manuf sentinel/resources/oui.tsv.gz "$(date +%F)"
"""
import gzip, re, sys
SUFFIX = re.compile(r"[\s,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|sas|sarl|s\.a|s\.p\.a|spa|bv|b\.v|nv|ab|oy|as|a/s|kg|plc|pte|pty|srl|s\.r\.l|kk|k\.k|technology|technologies|electronics|international|holdings?|group|communication|communications)\b\.?$", re.I)
def clean(name):
    name = re.sub(r"\s+", " ", name).strip()
    for _ in range(6):
        stripped = SUFFIX.sub("", name).strip(" ,.-")
        if stripped == name or len(stripped) < 2: break
        name = stripped
    return name[:40]
rows = []
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("#") or not line.strip(): continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2: continue
    block = parts[0].strip(); full = (parts[2] if len(parts) > 2 else parts[1]).strip()
    if not full: continue
    prefix, _, bits = block.partition("/")
    hexa = prefix.replace(":", "").replace("-", "").upper()
    bits = int(bits) if bits else 24
    hexa = hexa[: bits // 4]
    if not re.fullmatch(r"[0-9A-F]{6,9}", hexa): continue
    rows.append(f"{hexa}\t{clean(full)}")
with gzip.open(sys.argv[2], "wt", encoding="utf-8", compresslevel=9) as out:
    out.write("# Source: IEEE registry via Wireshark manuf, " + sys.argv[3] + "\n" + "\n".join(sorted(set(rows))) + "\n")
print(len(rows))
