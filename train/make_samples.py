"""samples/ papkasidagi namunaviy fayllarni yaratish (real vositalar formatida)."""
import json
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from netguard.parsers import to_eve, to_host_events, to_zeek_dns, to_zeek_tsv  # noqa: E402
from netguard.simulator import generate  # noqa: E402

OUT = os.path.join(ROOT, "samples")


def w(name, text):
    with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    b = generate(None, minutes=10, seed=7, start=datetime(2026, 5, 18, 10, 0).timestamp())
    w("hujumlar_conn.log", to_zeek_tsv(b.conns))
    w("hujumlar_dns.log", to_zeek_dns(b.conns))
    w("hujumlar_eve.json", to_eve(b.eve))
    w("hujumlar_host_events.jsonl", to_host_events(b.host))
    n = generate([], minutes=30, seed=202, start=datetime(2026, 5, 18, 9, 0).timestamp())
    w("normal_conn.log", to_zeek_tsv(n.conns))
    # Wazuh alerts.json (haqiqiy format namunasi): RDP parol tanlash va muvaffaqiyatli kirish
    t0 = datetime(2026, 5, 18, 11, 0).timestamp()
    rows = []
    for i in range(25):
        rows.append({"timestamp": datetime.fromtimestamp(t0 + i * 2).astimezone().isoformat(timespec="milliseconds"),
                     "rule": {"level": 5, "description": "Windows: Logon failure - Unknown user or bad password.",
                              "id": "60122", "groups": ["windows", "windows_security", "authentication_failed"]},
                     "agent": {"id": "003", "name": "dc-01", "ip": "10.0.1.30"},
                     "decoder": {"name": "windows_eventchannel"},
                     "data": {"srcip": "185.220.101.47", "dstuser": "administrator", "win": {"system": {"eventID": "4625"}}}})
    rows.append({"timestamp": datetime.fromtimestamp(t0 + 55).astimezone().isoformat(timespec="milliseconds"),
                 "rule": {"level": 3, "description": "Windows Logon Success", "id": "60106",
                          "groups": ["windows", "authentication_success"]},
                 "agent": {"id": "003", "name": "dc-01", "ip": "10.0.1.30"}, "decoder": {"name": "windows_eventchannel"},
                 "data": {"srcip": "185.220.101.47", "dstuser": "administrator", "win": {"system": {"eventID": "4624"}}}})
    w("wazuh_alerts.json", "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")
    src = os.path.join(ROOT, "data", "nsl-kdd", "KDDTest-21.txt")
    if os.path.exists(src):
        with open(src, encoding="utf-8") as f:
            w("nsl_kdd_test21_2000.txt", "".join(f.readlines()[:2000]))
    print("Tayyor:", sorted(os.listdir(OUT)))
