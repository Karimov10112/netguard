"""1-qatlam (signatura moduli): C-ilovadagi Suricata qoidalarining ulanishlar oqimidagi ekvivalenti + IoC + Suricata EVE importi.

Qoidalar (sid diplomdagi local.rules bilan bir xil):
  1000010  Ichki port skanerlash        — bir manbadan 30 s da ≥ 50 ulanish urinishi (≥ 20 xil port/xost)
  1000011  RDP brute force              — bir manbadan 60 s da ≥ 15 ulanish 3389-portga (SSH 22 uchun 1000014)
  1000012  Stansiyalararo SMB ulanish   — $USER_NET → $USER_NET:445, manba bo‘yicha 300 s da bir marta
  1000013  Shubhali uzun DNS so‘rovi    — so‘rovning birinchi qismi ^[a-z0-9]{50,}\\.
  1000015  SYN flood                    — 2 s da bitta xostga ≥ 100 yarim ochiq (S0) ulanish
  1000020  IoC mosligi                  — tahdid indikatorlari ro‘yxatidagi IP yoki domen
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

from . import config as C
from .features import Conn

LONG_DNS = re.compile(r"^[a-z0-9]{%d,}\." % C.DNS_LONG_LABEL, re.I)


@dataclass
class Hit:
    ts: float
    sid: int
    name: str
    severity: float           # S_sig (0..1)
    src: str
    dst: str
    dport: int = 0
    category: str = ""
    mitre: str = ""
    module: str = "sig"       # sig | suricata
    domain: str = ""
    detail: dict = field(default_factory=dict)


# MITRE ATT&CK texnikalari (nom, taktika)
MITRE = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1499.001": ("Endpoint DoS: OS Exhaustion Flood (SYN flood)", "Impact"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1078": ("Valid Accounts", "Defense Evasion / Initial Access"),
}
TACTIC_UZ = {"Reconnaissance": "Razvedka", "Discovery": "Tarmoqni o‘rganish", "Credential Access": "Hisob ma’lumotlarini qo‘lga kiritish",
             "Lateral Movement": "Gorizontal harakat", "Command and Control": "Boshqaruv (C2)", "Initial Access": "Dastlabki kirish",
             "Impact": "Zarar yetkazish", "Privilege Escalation": "Imtiyozlarni oshirish", "Exfiltration": "Ma’lumotlarni chiqarish",
             "Defense Evasion / Initial Access": "Himoyani chetlab o‘tish"}


def tactic(technique: str) -> str:
    return MITRE.get(technique, ("", ""))[1]


def base_domain(q: str) -> str:
    parts = [p for p in q.lower().strip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else q.lower()


class Signatures:
    def __init__(self, ioc: dict[str, tuple[str, str]] | None = None):
        self.ioc = ioc or {}                       # qiymat → (tur, izoh)
        self.ioc_domains = {k for k, (t, _) in self.ioc.items() if t == "domain"}
        self.scan: dict[str, deque] = defaultdict(deque)       # src → (ts, dst, dport)
        self.brute: dict[tuple, deque] = defaultdict(deque)    # (src, port) → ts
        self.syn: dict[str, deque] = defaultdict(deque)        # dst → (ts, src)
        self.last: dict[tuple, float] = {}                     # (sid, kalit) → oxirgi ishga tushish (threshold/limit)

    def _limit(self, key: tuple, ts: float, seconds: float) -> bool:
        """Suricata `threshold: type limit/both` — bitta kalit uchun `seconds` ichida bir marta."""
        last = self.last.get(key)
        if last is not None and ts - last < seconds:
            return False
        self.last[key] = ts
        return True

    def check(self, c: Conn) -> list[Hit]:
        hits: list[Hit] = []
        ts, src, dst = c.ts, c.src, c.dst
        proto = (c.proto or "").lower()

        # 1000010 — port skanerlash
        if proto == "tcp":
            q = self.scan[src]
            q.append((ts, dst, c.dport))
            while q and ts - q[0][0] > C.SCAN_SECONDS:
                q.popleft()
            if len(q) >= C.SCAN_COUNT and len({(d, p) for _, d, p in q}) >= C.SCAN_DISTINCT \
                    and self._limit((1000010, src), ts, C.SCAN_SECONDS):
                ports = len({p for _, _, p in q})
                hosts = len({d for _, d, _ in q})
                hits.append(Hit(ts, 1000010, "Port skanerlash", C.SURICATA_SEVERITY[2], src, dst, c.dport,
                                "attempted-recon", "T1046", detail={"connections_30s": len(q), "ports": ports, "hosts": hosts}))

        # 1000011 / 1000014 — RDP / SSH brute force
        if proto == "tcp" and c.dport in (3389, 22):
            q = self.brute[(src, c.dport)]
            q.append(ts)
            while q and ts - q[0] > C.BRUTE_SECONDS:
                q.popleft()
            if len(q) >= C.BRUTE_COUNT and self._limit((1000011, src, c.dport), ts, C.BRUTE_SECONDS):
                name, sid = ("RDP brute force", 1000011) if c.dport == 3389 else ("SSH brute force", 1000014)
                hits.append(Hit(ts, sid, name, C.SURICATA_SEVERITY[1], src, dst, c.dport, "attempted-admin", "T1110",
                                detail={"attempts_60s": len(q)}))

        # 1000012 — stansiyalararo SMB
        if proto == "tcp" and c.dport == 445 and C.segment(src) == "user" and C.segment(dst) == "user" \
                and c.conn_state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR") \
                and self._limit((1000012, src), ts, C.SMB_LIMIT_SECONDS):
            hits.append(Hit(ts, 1000012, "Stansiyalararo SMB ulanish", C.SURICATA_SEVERITY[2], src, dst, 445,
                            "policy-violation", "T1021.002"))

        # 1000013 — uzun DNS so‘rovi
        if c.query and LONG_DNS.match(c.query):
            dom = base_domain(c.query)
            if self._limit((1000013, src, dom), ts, 60):
                hits.append(Hit(ts, 1000013, "Shubhali uzun DNS so‘rovi", C.SURICATA_SEVERITY[2], src, dst, c.dport,
                                "bad-unknown", "T1071.004", domain=dom, detail={"query": c.query[:120]}))

        # 1000015 — SYN flood
        if proto == "tcp" and c.conn_state == "S0":
            q = self.syn[dst]
            q.append((ts, src))
            while q and ts - q[0][0] > C.SYNFLOOD_SECONDS:
                q.popleft()
            if len(q) >= C.SYNFLOOD_COUNT and self._limit((1000015, dst), ts, 10):
                top, n = Counter(s for _, s in q).most_common(1)[0]
                hits.append(Hit(ts, 1000015, "SYN flood", C.SURICATA_SEVERITY[1], top, dst, c.dport, "attempted-dos",
                                "T1499.001", detail={"half_open_2s": len(q), "sources": len({s for _, s in q}),
                                                     "top_source_share": round(n / len(q), 2)}))

        # 1000020 — IoC
        for val, role in ((dst, "dst"), (src, "src")):
            if val in self.ioc and self._limit((1000020, src, val), ts, 300):
                t, note = self.ioc[val]
                hits.append(Hit(ts, 1000020, f"IoC: {note}", C.SURICATA_SEVERITY[1], src, dst, c.dport, "trojan-activity",
                                "T1071", detail={"ioc": val, "role": role}))
        if c.query and self.ioc_domains:
            q = c.query.lower().strip(".")
            for d in self.ioc_domains:
                if (q == d or q.endswith("." + d)) and self._limit((1000020, src, d), ts, 300):
                    hits.append(Hit(ts, 1000020, f"IoC: {self.ioc[d][1]}", C.SURICATA_SEVERITY[1], src, dst, c.dport,
                                    "trojan-activity", "T1071.004", domain=d, detail={"ioc": d, "query": c.query[:120]}))
        return hits


# ---------------------------------------------------------------------- Suricata EVE
_CATEGORY_MITRE = [
    (("web application attack", "web-application-attack"), "T1190"),
    (("administrator privilege", "attempted-admin", "user privilege"), "T1110"),
    (("network scan", "information leak", "attempted-recon"), "T1046"),
    (("denial of service", "attempted-dos"), "T1499"),
    (("trojan", "command and control", "malware"), "T1071"),
    (("policy violation", "policy-violation"), "T1021"),
]
_SIG_MITRE = [("sql", "T1190"), ("scan", "T1046"), ("brute", "T1110"), ("smb", "T1021.002"), ("dns", "T1071.004"),
              ("c2", "T1071"), ("cobalt", "T1071"), ("exploit", "T1190"), ("flood", "T1499")]


def from_eve(ev: dict) -> Hit | None:
    """Suricata eve.json `alert` hodisasi → Hit (B-ilova: severity → S_sig)."""
    if ev.get("event_type") != "alert" or "alert" not in ev:
        return None
    a = ev["alert"]
    sev = int(a.get("severity", 3) or 3)
    sig = str(a.get("signature", "Suricata ogohlantirishi"))
    cat = str(a.get("category", ""))
    tech = ""
    low = sig.lower()
    for kw, t in _SIG_MITRE:
        if kw in low:
            tech = t
            break
    if not tech:
        for kws, t in _CATEGORY_MITRE:
            if any(k in cat.lower() for k in kws):
                tech = t
                break
    return Hit(float(ev["ts"]), int(a.get("signature_id", 0) or 0), sig, C.SURICATA_SEVERITY.get(sev, 0.3),
               str(ev.get("src_ip", "")), str(ev.get("dest_ip", "")), int(ev.get("dest_port", 0) or 0), cat, tech,
               module="suricata", detail={"severity": sev})


def is_exploit(h: Hit) -> bool:
    """2-korrelyatsiya qoidasi uchun: ekspluatatsiya/hujum turidagi Suricata qoidasi."""
    low = (h.name + " " + h.category).lower()
    return h.module == "suricata" and any(k in low for k in ("web application attack", "exploit", "sql", "attempted-admin",
                                                             "administrator privilege", "rce", "injection"))
