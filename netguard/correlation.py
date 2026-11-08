"""3-qatlam (korrelyatsiya): SIEM korrelyatsiya qoidalari (diplom, 3.9-jadval) + ikkita qo‘shimcha qoida.

Har bir qoida MITRE ATT&CK texnikasi va javob chorasi bilan bog‘langan. Qoidalar hodisa vaqti (ts) bo‘yicha
ishlaydi, shuning uchun real vaqt rejimida ham, yuklangan jurnallarni qayta tahlil qilishda ham bir xil natija beradi.
"""
from __future__ import annotations

import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from . import config as C
from .features import Conn
from .signatures import Hit, base_domain, is_exploit

CFG = C.CORR
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 88, 110, 123, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433,
                3306, 3389, 5432, 5985, 8080, 8443}

# id: (nomi, shart, ATT&CK, javob, javob kodi, risk)
RULES = {
    "R1": ("Parol tanlashdan keyin muvaffaqiyatli kirish",
           f"{CFG['auth_fail_window'] // 60} daqiqada ≥ {CFG['auth_fail_count']} muvaffaqiyatsiz kirish, so‘ng muvaffaqiyatli kirish (AD, Wazuh)",
           ["T1110", "T1078"], "Hisobni bloklash, manba IP ni bloklash, SOC ga", ["disable_account", "block_ip"], 0.95),
    "R2": ("Skanerlashdan keyin ekspluatatsiya",
           "Probe ogohlantirishi + 1 soat ichida shu manbadan Suricata eksployt qoidasi",
           ["T1595", "T1190"], "IP ni bloklash", ["block_ip"], 0.9),
    "R3": ("Gorizontal harakat",
           f"Ishchi stansiyadan {CFG['lateral_window'] // 60} daqiqada ≥ {CFG['lateral_hosts']} ta boshqa stansiyaga SMB/RDP (Zeek)",
           ["T1021"], "Xostni karantin VLAN ga", ["quarantine_host"], 0.85),
    "R4": ("C2 beaconing",
           "Bir xostdan bir tashqi manzilga muntazam intervalli ulanishlar, anomaliya balli yuqori yoki IoC (Zeek, IF)",
           ["T1071"], "Domen/IP ni bloklash", ["block_ip"], 0.85),
    "R5": ("Ma’lumotlarni chiqarish",
           f"Ish vaqtidan tashqari ({CFG['work_hours'][1]}:00–{CFG['work_hours'][0]:02d}:00) 1 soatda > 1 GB chiquvchi trafik (NetFlow/Zeek)",
           ["T1041"], "SOC ga, ulanishni cheklash", ["rate_limit"], 0.7),
    "R6": ("Ransomware belgisi",
           f"Fayl serverida {CFG['ransom_window']} s da ≥ {CFG['ransom_fim']} fayl o‘zgarishi (Wazuh FIM) + SMB faolligi",
           ["T1486"], "Xostni zudlik bilan izolyatsiya", ["quarantine_host"], 0.95),
    "R7": ("DNS tunnel (qo‘shimcha)",
           f"{CFG['dns_tunnel_window'] // 60} daqiqada bitta domenga ≥ {CFG['dns_tunnel_count']} ta uzun so‘rov (Zeek dns.log, 4-qoida)",
           ["T1071.004"], "Domenni bloklash (DNS RPZ)", ["block_domain"], 0.85),
    "R8": ("Takroriy anomal aloqa (qo‘shimcha)",
           "10 daqiqada bir manzilning bitta nostandart portiga ≥ 5 ta IF anomaliyasi",
           ["T1571"], "SOC ga yo‘naltirish", ["notify_soc"], 0.6),
}


@dataclass
class CorrHit:
    ts: float
    rule: str
    entity: str               # insident subyekti (odatda hujum manbasi yoki zararlangan xost)
    target: str               # javob nishoni (IP / xost / domen / hisob)
    detail: dict = field(default_factory=dict)

    @property
    def title(self) -> str:
        return RULES[self.rule][0]

    @property
    def mitre(self) -> list[str]:
        return RULES[self.rule][2]

    @property
    def risk(self) -> float:
        return RULES[self.rule][5]

    @property
    def actions(self) -> list[str]:
        return RULES[self.rule][4]


def off_hours(ts: float) -> bool:
    d = datetime.fromtimestamp(ts)
    a, b = CFG["work_hours"]
    return d.weekday() >= 5 or not (a <= d.hour < b)


class Correlator:
    def __init__(self, ioc: set[str] | None = None):
        self.ioc = ioc or set()
        self.fired: dict[tuple, float] = {}
        self.auth_fail: dict[str, deque] = defaultdict(deque)
        self.probe: dict[str, float] = {}
        self.lateral: dict[str, deque] = defaultdict(deque)
        self.beacon: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=40))
        self.dst_srcs: dict[str, set] = defaultdict(set)
        self.exfil: dict[tuple, deque] = defaultdict(deque)
        self.fim: dict[tuple, deque] = defaultdict(deque)
        self.smb_seen: dict[tuple, float] = {}
        self.dns: dict[tuple, deque] = defaultdict(deque)
        self.anom: dict[tuple, deque] = defaultdict(deque)

    def _once(self, key: tuple, ts: float, seconds: float = 3600) -> bool:
        last = self.fired.get(key)
        if last is not None and ts - last < seconds:
            return False
        self.fired[key] = ts
        return True

    # ------------------------------------------------------------------ ulanishlar (Zeek)
    def on_conn(self, c: Conn, p_xgb: float, s_if: float, cls: str) -> list[CorrHit]:
        out: list[CorrHit] = []
        ts, src, dst = c.ts, c.src, c.dst
        src_seg, dst_seg = C.segment(src), C.segment(dst)
        ok = c.conn_state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR")

        if p_xgb >= C.P_XGB_THRESHOLD and cls == "Probe":
            self.probe[src] = ts

        # R3 — gorizontal harakat
        if src_seg == "user" and dst_seg == "user" and c.dport in (445, 3389, 135, 5985) and ok:
            q = self.lateral[src]
            q.append((ts, dst))
            while q and ts - q[0][0] > CFG["lateral_window"]:
                q.popleft()
            hosts = {d for _, d in q}
            if len(hosts) >= CFG["lateral_hosts"] and self._once(("R3", src), ts):
                out.append(CorrHit(ts, "R3", src, src, {"targets": sorted(hosts), "connections": len(q)}))

        # R4 — beaconing
        if C.is_internal(src) and not C.is_internal(dst):
            self.dst_srcs[dst].add(src)
            q = self.beacon[(src, dst, c.dport)]
            if (c.orig_bytes or 0) <= 100_000:             # beacon — kichik hajmli muntazam so‘rovlar
                q.append((ts, s_if))
            if len(q) >= CFG["beacon_min"] and q[-1][0] == ts:
                times = [t for t, _ in q]
                iv = [b - a for a, b in zip(times, times[1:])][-20:]
                mean = statistics.fmean(iv)
                if mean >= 5:
                    cv = statistics.pstdev(iv) / mean
                    mean_if = statistics.fmean(s for _, s in q)
                    rare = len(self.dst_srcs[dst]) == 1
                    if cv < CFG["beacon_cv"] and (dst in self.ioc or mean_if >= C.S_IF_THRESHOLD or rare) \
                            and self._once(("R4", src, dst), ts):
                        out.append(CorrHit(ts, "R4", src, dst, {"interval_s": round(mean, 1), "cv": round(cv, 3),
                                                                 "connections": len(q), "ioc": dst in self.ioc,
                                                                 "mean_s_if": round(mean_if, 2), "rare_destination": rare,
                                                                 "port": c.dport}))

            # R5 — tungi eksfiltratsiya
            if off_hours(ts) and c.orig_bytes:
                q = self.exfil[(src, dst)]
                q.append((ts, c.orig_bytes))
                while q and ts - q[0][0] > CFG["exfil_window"]:
                    q.popleft()
                total = sum(b for _, b in q)
                if total > CFG["exfil_bytes"] and self._once(("R5", src, dst), ts):
                    out.append(CorrHit(ts, "R5", src, src, {"bytes": total, "destination": dst,
                                                             "time": datetime.fromtimestamp(ts).strftime("%H:%M")}))

        # R6 uchun: SMB faolligi
        if c.dport == 445:
            self.smb_seen[(src, dst)] = ts

        # R7 — DNS tunnel
        if c.query:
            first = c.query.split(".", 1)[0]
            if len(first) >= C.DNS_LONG_LABEL and first.isalnum():
                dom = base_domain(c.query)
                q = self.dns[(src, dom)]
                q.append(ts)
                while q and ts - q[0] > CFG["dns_tunnel_window"]:
                    q.popleft()
                if len(q) >= CFG["dns_tunnel_count"] and self._once(("R7", src, dom), ts):
                    out.append(CorrHit(ts, "R7", src, dom, {"queries_5min": len(q), "domain": dom}))

        # R8 — takroriy anomaliya nostandart portga
        if s_if >= C.S_IF_THRESHOLD and (c.proto or "").lower() in ("tcp", "udp") and c.dport not in COMMON_PORTS:
            q = self.anom[(src, dst, c.dport)]
            q.append(ts)
            while q and ts - q[0] > 600:
                q.popleft()
            if len(q) >= 5 and self._once(("R8", src, dst), ts):
                out.append(CorrHit(ts, "R8", src, src, {"destination": dst, "port": c.dport, "anomalies_10min": len(q)}))
        return out

    # ------------------------------------------------------------------ signatura / Suricata ogohlantirishlari
    def on_hit(self, h: Hit) -> list[CorrHit]:
        out: list[CorrHit] = []
        if h.sid == 1000010 or h.mitre in ("T1046", "T1595"):
            self.probe[h.src] = h.ts
        if is_exploit(h):
            t = self.probe.get(h.src)
            if t is not None and 0 <= h.ts - t <= CFG["scan_exploit_window"] and self._once(("R2", h.src), h.ts):
                out.append(CorrHit(h.ts, "R2", h.src, h.src, {"probe_at": t, "exploit": h.name, "target": h.dst}))
        return out

    # ------------------------------------------------------------------ xost hodisalari (Wazuh)
    def on_host(self, ev: dict) -> list[CorrHit]:
        out: list[CorrHit] = []
        ts = float(ev["ts"])
        if ev.get("type") == "auth":
            src = ev.get("src", "")
            q = self.auth_fail[src]
            while q and ts - q[0] > CFG["auth_fail_window"]:
                q.popleft()
            if ev.get("result") == "failure":
                q.append(ts)
            elif ev.get("result") == "success" and len(q) >= CFG["auth_fail_count"] and self._once(("R1", src), ts):
                out.append(CorrHit(ts, "R1", src, src, {"failures_5min": len(q), "account": ev.get("user", ""),
                                                         "host": ev.get("host", ""), "protocol": ev.get("proto", "")}))
        elif ev.get("type") == "fim":
            host, src = ev.get("host", ""), ev.get("src", "")
            q = self.fim[(host, src)]
            q.append(ts)
            while q and ts - q[0] > CFG["ransom_window"]:
                q.popleft()
            smb = self.smb_seen.get((src, host))
            if len(q) >= CFG["ransom_fim"] and smb is not None and ts - smb <= 300 and self._once(("R6", src), ts):
                out.append(CorrHit(ts, "R6", src, src, {"file_changes_60s": len(q), "file_server": host,
                                                         "example": ev.get("path", "")[-80:], "account": ev.get("user", "")}))
        return out
