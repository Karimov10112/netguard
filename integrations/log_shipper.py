"""Log yetkazuvchi (1-qatlam): sensor jurnallarini kuzatib, yangi yozuvlarni NetGuard serveriga yuboradi.

Zeek JSON formatda yozishi kerak (local.zeek:  @load policy/tuning/json-logs.zeek).
Ishga tushirish:
    NETGUARD_API_KEY=... python3 log_shipper.py --server http://soc.local:5000 \
        /opt/zeek/logs/current/conn.log /opt/zeek/logs/current/dns.log \
        /var/log/suricata/eve.json /var/ossec/logs/alerts/alerts.json
Har --interval soniyada yig‘ilgan yangi qatorlar bitta paket sifatida /api/v1/ingest ga yuboriladi.
"""
import argparse
import logging
import os
import time
import urllib.request


def post(server, key, lines):
    body = "\n".join(lines).encode("utf-8")
    headers = {"Content-Type": "application/x-ndjson"}
    if key:
        headers["X-API-Key"] = key
    req = urllib.request.Request(server.rstrip("/") + "/api/v1/ingest", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    ap.add_argument("--interval", type=float, default=5)
    ap.add_argument("--from-start", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    key = os.environ.get("NETGUARD_API_KEY", "")
    handles = {}
    for p in a.files:
        f = open(p, encoding="utf-8", errors="replace")
        if not a.from_start:
            f.seek(0, 2)
        handles[p] = f
    while True:
        batch = []
        for p, f in handles.items():
            while True:
                line = f.readline()
                if not line:
                    break
                if line.strip().startswith("{"):
                    batch.append(line.strip())
        if batch:
            try:
                logging.info("%d yozuv yuborildi: %s", len(batch), post(a.server, key, batch))
            except Exception as e:  # noqa: BLE001
                logging.warning("yuborib bo‘lmadi: %s", e)
        time.sleep(a.interval)
