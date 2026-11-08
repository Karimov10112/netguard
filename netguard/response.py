"""4-qatlam (javob): risk darajasi va korrelyatsiya qoidalariga ko‘ra avtomatik choralar (3.8-jadval, 3.3-band).

Himoya choralari (diplom, «Avtomatik bloklashdagi himoya choralari»):
  1) oq ro‘yxatdagi IP-manzillar avtomatik bloklanmaydi;
  2) bloklash muddatli (TTL = 24 soat) va avtomatik bekor bo‘ladi;
  3) har bir avtomatik harakat jurnalga yoziladi, tahlilchi uni bir tugma bilan bekor qila oladi;
  4) «ids» (monitoring) rejimida choralar faqat tavsiya sifatida yoziladi, tarmoqqa qo‘llanmaydi.
"""
from __future__ import annotations

import ipaddress

from . import config as C
from .storage import Storage

TTL = {"block_ip": C.BLOCK_TTL_H, "block_domain": C.BLOCK_TTL_H, "rate_limit": C.BLOCK_TTL_H}


def commands(action: str, target: str, ttl_h: int = C.BLOCK_TTL_H) -> list[str]:
    """Chorani qo‘llash uchun buyruqlar (B-ilova: ipset/iptables; NGFW/AD/DNS uchun namunalar)."""
    sec = ttl_h * 3600
    if action == "block_ip":
        return [f"ipset -exist add blocklist {target} timeout {sec}"]
    if action == "quarantine_host":
        return [f"ipset -exist add quarantine {target}",
                f"# kommutator: {target} ulangan portni karantin VLAN 999 ga o‘tkazish (NAC/802.1X)"]
    if action == "rate_limit":
        return [f"ipset -exist add ratelimit {target} timeout {sec}",
                "iptables -I FORWARD -m set --match-set ratelimit src -m hashlimit --hashlimit-above 1mb/s "
                "--hashlimit-mode srcip --hashlimit-name exfil -j DROP"]
    if action == "block_domain":
        return [f"# BIND RPZ: {target} CNAME .", f"# {'*.' + target} CNAME ."]
    if action == "disable_account":
        return [f"Disable-ADAccount -Identity {target}   # PowerShell, domen kontrolleri"]
    if action == "unblock":
        return [f"ipset del blocklist {target}"]
    return []


def undo_commands(action: str, target: str) -> list[str]:
    return {"block_ip": [f"ipset del blocklist {target}"], "quarantine_host": [f"ipset del quarantine {target}"],
            "rate_limit": [f"ipset del ratelimit {target}"], "block_domain": [f"# RPZ dan {target} yozuvini o‘chirish"],
            "disable_account": [f"Enable-ADAccount -Identity {target}"]}.get(action, [])


class Responder:
    def __init__(self, store: Storage):
        self.store = store
        self.mode = store.mode
        self.white = store.whitelist_nets()

    def whitelisted(self, target: str) -> bool:
        try:
            a = ipaddress.ip_address(target)
        except ValueError:
            return False
        return any(a in n for n in self.white)

    def decide(self, ts: float, action: str, target: str, reason: str) -> dict | None:
        """Bitta chora bo‘yicha qaror: holat (active / simulated / skipped / done). Takroriy faol choralar qaytarilmaydi."""
        if not target:
            return None
        if action in ("block_ip", "quarantine_host", "rate_limit") and self.whitelisted(target):
            status = "skipped"
        elif action == "notify_soc":
            status = "done"
        elif self.store.is_active(action, target):
            return None
        else:
            status = "active" if self.mode == "ips" else "simulated"
        return {"ts": ts, "action": action, "target": target, "reason": reason, "status": status, "mode": self.mode,
                "ttl_h": TTL.get(action)}

    def for_level(self, ts: float, entity: str, reason: str) -> dict | None:
        """Risk ≥ 0,8: tashqi manba — IP ni bloklash, ichki xost — karantin VLAN."""
        action = "quarantine_host" if C.is_internal(entity) else "block_ip"
        return self.decide(ts, action, entity, reason)
