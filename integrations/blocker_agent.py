"""Bloklash agenti (4-qatlam): NetGuard serveridagi faol choralarni chegara shlyuziga / Linux xostga qo‘llaydi.

Agent har N soniyada /api/v1/blocklist ni so‘raydi va ipset ro‘yxatlarini sinxronlaydi:
  block_ip        → ipset blocklist   (timeout = qolgan muddat)
  quarantine_host → ipset quarantine
  rate_limit      → ipset ratelimit
Server tomonda bekor qilingan yoki muddati tugagan yozuvlar ro‘yxatdan o‘chiriladi.

Oldindan bir marta (root):
    ipset create blocklist hash:ip timeout 86400
    ipset create quarantine hash:ip
    ipset create ratelimit hash:ip timeout 86400
    iptables -I FORWARD -m set --match-set blocklist src -j DROP
    iptables -I FORWARD -m set --match-set blocklist dst -j DROP
    iptables -I FORWARD -m set --match-set quarantine src -j DROP      # yoki karantin VLAN ga yo‘naltirish
Ishga tushirish:
    sudo NETGUARD_API_KEY=... python3 blocker_agent.py --server http://soc.local:5000
    python3 blocker_agent.py --server http://127.0.0.1:5000 --dry-run --once
"""
import argparse
import json
import logging
import os
import subprocess
import time
import urllib.request

SETS = {"block_ip": "blocklist", "quarantine_host": "quarantine", "rate_limit": "ratelimit"}


def fetch(server, key):
    req = urllib.request.Request(server.rstrip("/") + "/api/v1/blocklist", headers={"X-API-Key": key} if key else {})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def run(cmd, dry):
    if dry:
        logging.info("[dry-run] %s", " ".join(cmd))
        return
    subprocess.run(cmd, check=False)


def sync(state, data, dry):
    want = {}
    for it in data.get("items", []):
        s = SETS.get(it["action"])
        if s:
            want[(s, it["ip"])] = it.get("timeout", 0)
    for (s, ip), timeout in want.items():
        if (s, ip) not in state:
            cmd = ["ipset", "-exist", "add", s, ip] + (["timeout", str(max(int(timeout), 1))] if timeout and s != "quarantine" else [])
            run(cmd, dry)
            logging.info("qo‘shildi: %s %s", s, ip)
    for (s, ip) in set(state) - set(want):
        run(["ipset", "-exist", "del", s, ip], dry)
        logging.info("o‘chirildi (bekor qilingan / muddati tugagan): %s %s", s, ip)
    return set(want)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    key = os.environ.get("NETGUARD_API_KEY", "")
    state = set()
    while True:
        try:
            data = fetch(a.server, key)
            if data.get("mode") == "ids":
                logging.info("server IDS (monitoring) rejimida — choralar qo‘llanmaydi")
                data = {"items": []}
            state = sync(state, data, a.dry_run)
        except Exception as e:  # noqa: BLE001 — tarmoq xatolarida agent to‘xtamasligi kerak
            logging.warning("server bilan aloqa yo‘q: %s", e)
        if a.once:
            break
        time.sleep(a.interval)
