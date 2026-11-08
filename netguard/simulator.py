"""Korxona tarmog‘i trafigi simulyatori: normal ish trafigi va diplomdagi sinov hujumlari (3.10-jadval).

Simulyator Zeek conn.log / dns.log, Suricata EVE va Wazuh (auth, FIM) hodisalariga o‘xshash yozuvlar hosil qiladi.
U real laboratoriya (Kali Linux, nmap, hydra, hping3, sqlmap ...) o‘rnini bosmaydi, balki tizim modullarini
namoyish qilish va avtomatik testlar uchun mo‘ljallangan. Har bir stsenariy uchun kutilgan natija SCENARIOS’da.
"""
from __future__ import annotations

import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .features import Conn

# Tarmoq topologiyasi (config.DEFAULT_ASSETS bilan mos)
DC, DB, FS, MAIL, WEB, VPN, GW, DNS = ("10.0.1.30", "10.0.1.10", "10.0.1.20", "10.0.1.40", "10.0.2.10", "10.0.2.20",
                                       "10.0.0.1", "10.0.0.53")
APP = "10.0.1.50"  # ilova serveri (1C/ERP) — MBBT ga murojaat qiladi
WORKSTATIONS = [f"10.0.10.{i}" for i in range(11, 61)]
INTERNET = ["142.250.74.46", "13.107.42.14", "151.101.1.69", "104.18.32.7", "172.217.16.142", "20.190.159.0",
            "52.114.128.10", "217.12.218.5", "185.8.212.30", "95.46.98.40", "87.237.34.1", "40.126.31.1"]
CLIENTS = [f"{a}.{b}.{c}.{d}" for a, b, c, d in
           [(84, 54, 113, 9), (213, 230, 66, 12), (195, 158, 30, 5), (37, 110, 214, 77), (82, 215, 99, 8),
            (89, 236, 222, 41), (94, 158, 52, 3), (185, 74, 5, 120), (178, 218, 202, 14), (91, 212, 89, 30)]]
DOMAINS = ["google.com", "office.com", "teams.microsoft.com", "gov.uz", "my.gov.uz", "lex.uz", "kun.uz", "1c.ru",
           "github.com", "windowsupdate.com", "outlook.office365.com", "soliq.uz", "bank.uz", "yandex.ru"]

ATTACKER_SCAN = "45.155.205.233"
ATTACKER_BRUTE = "185.220.101.47"
ATTACKER_DOS = "91.240.118.172"
C2 = "193.42.33.14"
EXFIL = "104.21.65.120"
ODD = "198.51.100.77"


@dataclass
class Batch:
    conns: list = field(default_factory=list)       # Conn
    eve: list = field(default_factory=list)         # Suricata EVE alert (dict)
    host: list = field(default_factory=list)        # Wazuh: auth / fim (dict)
    truth: dict = field(default_factory=dict)       # stsenariy → hujumchi manbasi (baholash uchun)

    def extend(self, other: "Batch") -> None:
        self.conns += other.conns
        self.eve += other.eve
        self.host += other.host
        self.truth.update(other.truth)

    def sort(self) -> "Batch":
        self.conns.sort(key=lambda c: c.ts)
        self.eve.sort(key=lambda e: e["ts"])
        self.host.sort(key=lambda e: e["ts"])
        return self


class Sim:
    def __init__(self, seed: int = 7, start: float | None = None):
        self.r = random.Random(seed)
        self.start = start if start is not None else time.time() - 900
        self.n = 0

    def uid(self) -> str:
        self.n += 1
        return "C" + "".join(self.r.choices(string.ascii_letters + string.digits, k=14))

    def sport(self) -> int:
        return self.r.randint(49152, 65535)

    def conn(self, ts, src, dst, dport, proto="tcp", service="", dur=0.0, ob=0, rb=0, state="SF", query="", sport=None):
        return Conn(ts=ts, src=src, sport=sport or self.sport(), dst=dst, dport=dport, proto=proto, service=service,
                    duration=round(dur, 6), orig_bytes=int(ob), resp_bytes=int(rb), conn_state=state, uid=self.uid(),
                    query=query)

    # ------------------------------------------------------------------ normal trafik
    def normal(self, minutes: float = 10, rate: float = 6.0) -> Batch:
        """Ish kunidagi odatiy trafik: veb, DNS, SMB, AD, pochta, MBBT, mijozlarning veb-portalga murojaati."""
        b = Batch()
        r = self.r
        t, end = self.start, self.start + minutes * 60
        while t < end:
            t += r.expovariate(rate)
            ws = r.choice(WORKSTATIONS)
            k = r.random()
            if k < 0.30:      # DNS so‘rovi + HTTPS
                dom = r.choice(DOMAINS)
                q = r.choice(["", "www.", "api.", "login."]) + dom
                b.conns.append(self.conn(t, ws, DNS, 53, "udp", "dns", r.uniform(0.001, 0.05), r.randint(28, 60),
                                         r.randint(60, 300), "SF", q))
                b.conns.append(self.conn(t + 0.05, ws, r.choice(INTERNET), 443, "tcp", "ssl", r.uniform(0.2, 30),
                                         r.randint(400, 3000), r.randint(2000, 400000), "SF"))
            elif k < 0.42:    # HTTP
                b.conns.append(self.conn(t, ws, r.choice(INTERNET), 80, "tcp", "http", r.uniform(0.05, 4),
                                         r.randint(180, 500), r.randint(300, 60000), "SF"))
            elif k < 0.55:    # fayl server (SMB) — faqat ishchi stansiya → server
                b.conns.append(self.conn(t, ws, FS, 445, "tcp", "smb", r.uniform(0.5, 120), r.randint(500, 200000),
                                         r.randint(1000, 2000000), "SF"))
            elif k < 0.65:    # AD: Kerberos / LDAP
                port, svc = r.choice([(88, "krb_tcp"), (389, "ldap"), (445, "smb"), (135, "dce_rpc")])
                b.conns.append(self.conn(t, ws, DC, port, "tcp", svc, r.uniform(0.01, 2), r.randint(200, 3000),
                                         r.randint(200, 6000), "SF"))
                if r.random() < 0.15:
                    b.host.append({"ts": t, "type": "auth", "result": "success", "user": f"user{WORKSTATIONS.index(ws):02d}",
                                   "src": ws, "host": DC, "proto": "kerberos"})
            elif k < 0.72:    # pochta
                b.conns.append(self.conn(t, ws, MAIL, r.choice([993, 587]), "tcp", "ssl", r.uniform(0.3, 20),
                                         r.randint(300, 40000), r.randint(500, 80000), "SF"))
            elif k < 0.80:    # ilova serveri → MBBT
                b.conns.append(self.conn(t, APP, DB, 1433, "tcp", "", r.uniform(0.01, 3), r.randint(200, 5000),
                                         r.randint(300, 200000), "SF"))
            elif k < 0.93:    # mijozlar → veb-portal
                b.conns.append(self.conn(t, r.choice(CLIENTS), WEB, r.choice([443, 443, 80]), "tcp", "ssl",
                                         r.uniform(0.1, 15), r.randint(300, 4000), r.randint(1500, 300000), "SF"))
            elif k < 0.97:    # NTP / ICMP ping (monitoring)
                if r.random() < 0.5:
                    b.conns.append(self.conn(t, ws, GW, 123, "udp", "ntp", 0.01, 48, 48, "SF"))
                else:
                    b.conns.append(self.conn(t, "10.0.99.5", r.choice([DB, FS, DC, WEB]), 8, "icmp", "", 0.001, 64, 64,
                                             "OTH", sport=8))
            else:             # normal xatolar: yopiq portga tasodifiy urinish
                b.conns.append(self.conn(t, ws, r.choice(INTERNET), 443, "tcp", "", r.uniform(0, 3), 0, 0,
                                         r.choice(["S0", "REJ", "SF"])))
            if r.random() < 0.02:
                b.host.append({"ts": t, "type": "auth", "result": "failure", "user": f"user{r.randint(0, 49):02d}",
                               "src": ws, "host": DC, "proto": "kerberos"})
            if r.random() < 0.05:
                b.host.append({"ts": t, "type": "fim", "host": FS, "path": f"\\\\fs-01\\docs\\hisobot_{r.randint(1, 300)}.xlsx",
                               "action": "modified", "src": ws, "user": f"user{r.randint(0, 49):02d}"})
        return b

    # ------------------------------------------------------------------ sinov stsenariylari (3.10-jadval)
    def portscan(self, t0: float, src: str = ATTACKER_SCAN, dst: str = WEB) -> Batch:
        """1. nmap -sS: 1000 ta port, ~ 10 s. Ochiq portlar SF, yopiqlari REJ/S0."""
        b = Batch(truth={"portscan": src})
        ports = self.r.sample(range(1, 10000), 980) + [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080,
                                                        8443, 5432, 1433, 23, 111, 995, 993]
        for i, p in enumerate(ports):
            t = t0 + i * 0.01
            state = "SF" if p in (80, 443) else self.r.choice(["REJ", "REJ", "S0", "RSTOS0"])
            b.conns.append(self.conn(t, src, dst, p, "tcp", "", 0.0 if state != "SF" else 0.001, 0, 0, state,
                                     sport=self.r.choice([40123, 40124])))
        b.eve.append(self.eve(t0 + 2, src, dst, 0, 1000010, "Ichki port skanerlash", "Attempted Information Leak", 2))
        return b

    def bruteforce(self, t0: float, src: str = ATTACKER_BRUTE, dst: str = DC, port: int = 3389) -> Batch:
        """2. hydra: RDP ga parol tanlash, 120 urinish, oxirida muvaffaqiyatli kirish (Wazuh 4625/4624)."""
        b = Batch(truth={"bruteforce": src})
        for i in range(120):
            t = t0 + i * 0.5
            b.conns.append(self.conn(t, src, dst, port, "tcp", "rdp", self.r.uniform(0.3, 1.2), self.r.randint(1100, 1700),
                                     self.r.randint(1500, 3500), "SF"))
            b.host.append({"ts": t + 0.2, "type": "auth", "result": "failure", "user": "administrator", "src": src,
                           "host": dst, "proto": "rdp", "event_id": 4625})
        b.host.append({"ts": t0 + 61, "type": "auth", "result": "success", "user": "administrator", "src": src,
                       "host": dst, "proto": "rdp", "event_id": 4624})
        b.eve.append(self.eve(t0 + 8, src, dst, port, 1000011, "RDP brute force", "Attempted Administrator Privilege Gain", 1))
        return b

    def synflood(self, t0: float, src: str = ATTACKER_DOS, dst: str = WEB) -> Batch:
        """3. hping3 -S --flood: 1500 ta yarim ochiq ulanish, 3 s."""
        b = Batch(truth={"synflood": src})
        for i in range(1500):
            b.conns.append(self.conn(t0 + i * 0.002, src, dst, 80, "tcp", "", 0, 0, 0, "S0"))
        return b

    def sqli(self, t0: float, src: str = ATTACKER_SCAN, dst: str = WEB) -> Batch:
        """4. sqlmap: veb-ilovaga SQL in’eksiya (Suricata ET WEB_SERVER qoidalari)."""
        b = Batch(truth={"sqli": src})
        for i in range(60):
            t = t0 + i * 0.7
            b.conns.append(self.conn(t, src, dst, 80, "tcp", "http", self.r.uniform(0.05, 0.6), self.r.randint(400, 1400),
                                     self.r.randint(200, 9000), "SF"))
            if i % 6 == 0:
                sig = self.r.choice(["ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
                                     "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI",
                                     "ET SCAN Sqlmap SQL Injection Scan"])
                b.eve.append(self.eve(t, src, dst, 80, 2006446 + i, sig, "Web Application Attack", 1))
        return b

    def lateral(self, t0: float, src: str = "10.0.10.23") -> Batch:
        """5. PsExec / smbclient: ishchi stansiyadan 7 ta boshqa stansiyaga SMB."""
        b = Batch(truth={"lateral": src})
        targets = self.r.sample([w for w in WORKSTATIONS if w != src], 7)
        for i, dst in enumerate(targets):
            t = t0 + i * 20
            for j in range(3):
                b.conns.append(self.conn(t + j, src, dst, 445, "tcp", "smb", self.r.uniform(1, 6),
                                         self.r.randint(3000, 300000), self.r.randint(2000, 20000), "SF"))
            b.conns.append(self.conn(t + 4, src, dst, 135, "tcp", "dce_rpc", 0.4, 900, 700, "SF"))
        return b

    def dnstunnel(self, t0: float, src: str = "10.0.10.37", domain: str = "tunnel-c2.xyz") -> Batch:
        """6. dnscat2 / iodine: uzun base32 subdomenli so‘rovlar."""
        b = Batch(truth={"dnstunnel": src})
        alphabet = string.ascii_lowercase + "234567"
        for i in range(60):
            label = "".join(self.r.choices(alphabet, k=self.r.randint(52, 63)))
            q = f"{label}.{''.join(self.r.choices(alphabet, k=8))}.{domain}"
            b.conns.append(self.conn(t0 + i * 1.5, src, DNS, 53, "udp", "dns", 0.03, len(q) + 30,
                                     self.r.randint(120, 260), "SF", q))
        return b

    def unknown(self, t0: float, src: str = "10.0.10.52", dst: str = ODD) -> Batch:
        """7. Noma’lum protokol: nostandart port, noodatiy hajm va holatlar (maxsus skript)."""
        b = Batch(truth={"unknown": src})
        for i in range(40):
            b.conns.append(self.conn(t0 + i * 3, src, dst, 31337, self.r.choice(["tcp", "tcp", "udp"]), "",
                                     self.r.uniform(30, 900), self.r.randint(150000, 4000000), self.r.randint(0, 64),
                                     self.r.choice(["RSTR", "RSTO", "SH", "OTH", "S1"])))
        return b

    def beaconing(self, t0: float, src: str = "10.0.10.18", dst: str = C2) -> Batch:
        """C2 beaconing (T1071): har 30 s da kichik HTTPS ulanish."""
        b = Batch(truth={"beaconing": src})
        for i in range(24):
            b.conns.append(self.conn(t0 + i * 30 + self.r.uniform(-1.5, 1.5), src, dst, 443, "tcp", "ssl",
                                     self.r.uniform(0.1, 0.3), self.r.randint(180, 260), self.r.randint(90, 140), "SF"))
        return b

    def exfiltration(self, src: str = "10.0.10.29", dst: str = EXFIL) -> Batch:
        """Ish vaqtidan tashqari (soat 02:40) ~1,6 GB chiquvchi trafik (T1041)."""
        b = Batch(truth={"exfiltration": src})
        night = datetime.fromtimestamp(self.start).replace(hour=2, minute=40, second=0, microsecond=0)
        if night.timestamp() > self.start:
            night -= timedelta(days=1)
        t0 = night.timestamp()
        for i in range(16):
            b.conns.append(self.conn(t0 + i * 90 + self.r.uniform(-35, 35), src, dst, 443, "tcp", "ssl", self.r.uniform(60, 85),
                                     self.r.randint(95_000_000, 110_000_000), self.r.randint(8000, 30000), "SF"))
        return b

    def ransomware(self, t0: float, src: str = "10.0.10.41", dst: str = FS) -> Batch:
        """Ransomware: fayl serverida 60 s ichida 400 ta fayl o‘zgarishi (Wazuh FIM) + SMB faolligi."""
        b = Batch(truth={"ransomware": src})
        for i in range(400):
            t = t0 + i * 0.12
            if i % 4 == 0:
                b.conns.append(self.conn(t, src, dst, 445, "tcp", "smb", self.r.uniform(0.2, 2), self.r.randint(50000, 900000),
                                         self.r.randint(2000, 9000), "SF"))
            b.host.append({"ts": t, "type": "fim", "host": dst, "action": "modified", "src": src, "user": "user30",
                           "path": f"\\\\fs-01\\docs\\{self.r.choice(['hisobot', 'shartnoma', 'buyruq'])}_{i}.docx.locked"})
        return b

    def eve(self, ts, src, dst, dport, sid, sig, category, severity) -> dict:
        return {"ts": ts, "event_type": "alert", "src_ip": src, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
                "alert": {"signature_id": sid, "signature": sig, "category": category, "severity": severity}}


SCENARIOS = {
    # kalit: (nomi, vosita, kutilgan aniqlovchi modul, kutilgan javob) — 3.10-jadval + qo‘shimcha
    "portscan": ("Port skanerlash", "nmap -sS", "Signatura (1-qoida), ML (Probe)", "Ogohlantirish, risk ≥ 0,5"),
    "bruteforce": ("RDP parol tanlash", "hydra", "Signatura (2-qoida), SIEM korrelyatsiyasi", "Manba IP bloklanadi"),
    "synflood": ("SYN flood", "hping3", "ML (DoS), signatura", "IP bloklanadi"),
    "sqli": ("Veb-ilovaga SQL in’eksiya", "sqlmap", "Suricata ET qoidalari", "Ogohlantirish, WAF ga"),
    "lateral": ("Stansiyalararo SMB harakati", "PsExec / smbclient", "Signatura (3-qoida), Zeek, korrelyatsiya", "Xost karantinga"),
    "dnstunnel": ("DNS tunnel", "dnscat2 / iodine", "Signatura (4-qoida), korrelyatsiya", "Domen bloklanadi"),
    "unknown": ("Noma’lum protokol orqali aloqa", "maxsus skript", "Anomaliya moduli (IF)", "SOC ga yo‘naltiriladi"),
    "beaconing": ("C2 beaconing", "Cobalt Strike imitatsiyasi", "Korrelyatsiya (Zeek + IF), IoC", "Domen/IP bloklanadi"),
    "exfiltration": ("Ma’lumotlarni chiqarish (tunda)", "rclone imitatsiyasi", "Korrelyatsiya (NetFlow)", "SOC ga, ulanishni cheklash"),
    "ransomware": ("Ransomware belgisi", "FIM + SMB imitatsiyasi", "Korrelyatsiya (Wazuh FIM + SMB)", "Xost izolyatsiya qilinadi"),
}


def generate(scenarios: list[str] | None = None, minutes: float = 10, seed: int = 7, start: float | None = None,
             normal: bool = True) -> Batch:
    """Normal trafik + tanlangan stsenariylar (bo‘sh ro‘yxat — faqat normal trafik, None — hammasi)."""
    s = Sim(seed, start if start is not None else time.time() - minutes * 60 - 720)
    b = s.normal(minutes) if normal else Batch()
    chosen = list(SCENARIOS) if scenarios is None else [x for x in scenarios if x in SCENARIOS]
    span = minutes * 60
    offs = {k: s.start + span * (0.08 + 0.85 * i / max(len(chosen), 1)) for i, k in enumerate(chosen)}
    for k in chosen:
        if k == "exfiltration":
            b.extend(s.exfiltration())
        elif k == "sqli" and "portscan" in chosen:
            b.extend(s.sqli(offs["portscan"] + 120))      # skanerlashdan keyin ekspluatatsiya (korrelyatsiya qoidasi 2)
        else:
            b.extend(getattr(s, k)(offs[k]))
    return b.sort()
