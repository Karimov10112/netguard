"""Diplom ishi B-ilovasidagi mustaqil avtomatik bloklash skripti (Suricata EVE jurnali → ipset/iptables).

NetGuard serverisiz ishlaydi: eve.json dagi yangi ogohlantirishlarni o‘qiydi, risk ballini (3.2) hisoblaydi va
yuqori xavfli manbalarni 24 soatga bloklaydi. Bloklash ipset ro‘yxati orqali, muddat tugagach qoida avtomatik o‘chadi.

Oldindan bir marta (root):
    ipset create blocklist hash:ip timeout 86400
    iptables -I INPUT -m set --match-set blocklist src -j DROP
    iptables -I FORWARD -m set --match-set blocklist src -j DROP
Ishga tushirish:
    sudo python3 eve_blocker.py --eve /var/log/suricata/eve.json            # haqiqiy bloklash
    python3 eve_blocker.py --eve eve.json --dry-run --from-start            # sinov (buyruqlar faqat jurnalga yoziladi)
"""
import argparse
import ipaddress
import json
import logging
import subprocess
import time

WHITELIST = [ipaddress.ip_network(n) for n in ("10.0.0.0/24", "192.168.10.5/32")]
SEVERITY = {1: 1.0, 2: 0.6, 3: 0.3}                  # Suricata severity -> S_sig
ASSET = {"10.0.1.10": 1.0, "10.0.1.20": 0.8}         # muhim serverlar -> S_aktiv


def risk(ev, p_xgb=0.0, s_if=0.0):
    s_sig = SEVERITY.get(ev["alert"].get("severity", 3), 0.3)
    s_akt = ASSET.get(ev.get("dest_ip"), 0.3)
    return 0.4 * s_sig + 0.3 * p_xgb + 0.2 * s_if + 0.1 * s_akt   # (3.2)


def block(ip, dry_run=False, blocked=None):
    addr = ipaddress.ip_address(ip)
    if any(addr in n for n in WHITELIST):
        logging.info("oq ro'yxatda, bloklanmadi: %s", ip)
        return
    if blocked is not None:
        if ip in blocked:
            return
        blocked.add(ip)
    cmd = ["ipset", "-exist", "add", "blocklist", ip]
    if dry_run:
        logging.info("[dry-run] %s", " ".join(cmd))
    else:
        subprocess.run(cmd, check=True)
    logging.info("BLOKLANDI (24 soat): %s", ip)


def handle(ev, args, blocked):
    if ev.get("event_type") != "alert":
        return
    r = risk(ev, args.p_xgb, args.s_if)     # ML ballari NetGuard serveridan (SIEM) qo‘shiladi
    if r >= 0.8:
        block(ev["src_ip"], args.dry_run, blocked)
    elif r >= 0.5:
        logging.info("SOC ga (risk %.2f): %s -> %s %s", r, ev["src_ip"], ev.get("dest_ip"), ev["alert"].get("signature"))
    else:
        logging.info("jurnalga (risk %.2f): %s %s", r, ev["src_ip"], ev["alert"].get("signature"))


def follow(args):
    blocked = set()
    with open(args.eve, encoding="utf-8") as f:
        if not args.from_start:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                if args.from_start and args.once:
                    return
                time.sleep(0.5)
                continue
            try:
                handle(json.loads(line), args, blocked)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logging.warning("o‘tkazib yuborildi: %s", e)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--log", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--from-start", action="store_true", help="faylni boshidan o‘qish")
    ap.add_argument("--once", action="store_true", help="fayl oxiriga yetganda to‘xtash (--from-start bilan)")
    ap.add_argument("--p-xgb", type=float, default=0.0)
    ap.add_argument("--s-if", type=float, default=0.0)
    a = ap.parse_args()
    logging.basicConfig(filename=a.log or None, level=logging.INFO, format="%(asctime)s %(message)s")
    follow(a)
