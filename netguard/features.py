"""NSL-KDD xususiyatlari va Zeek conn.log yozuvlaridan ularni hisoblash (diplom ishi, 2.3-jadval va D-ilova).

NSL-KDD ulanish yozuvi 41 ta xususiyatdan iborat:
  * asosiy (9): duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent;
  * mazmun (13): hot, num_failed_logins, logged_in, ... — faqat paket ichidagi ma’lumotdan olinadi;
  * vaqt bo‘yicha (9): so‘nggi 2 soniyadagi shu xostga / shu xizmatga ulanishlar statistikasi;
  * xost bo‘yicha (10): shu xostga oxirgi 100 ta ulanish statistikasi.

Zeek conn.log’dan asosiy, vaqt va xost bo‘yicha xususiyatlarni hisoblash mumkin; mazmun xususiyatlari 0 deb olinadi.
Shu sababli real trafik uchun alohida “zeek” modeli faqat hisoblanadigan xususiyatlarda o‘qitiladi.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

NSL_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
NSL_ALL = NSL_COLUMNS + ["label", "difficulty"]
CATEGORICAL = ["protocol_type", "service", "flag"]

BASIC = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent"]
CONTENT = NSL_COLUMNS[9:22]
TIME_BASED = NSL_COLUMNS[22:31]
HOST_BASED = NSL_COLUMNS[31:41]
# Zeek conn.log’dan hisoblanadigan xususiyatlar (wrong_fragment va urgent conn.log’da yo‘q)
ZEEK_FEATURES = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land"] + TIME_BASED + HOST_BASED

ATTACK_CLASS = {
    "normal": "Normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS",
    "mailbomb": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    # Probe
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    # R2L
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L", "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L",
    "snmpguess": "R2L", "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L", "httptunnel": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R", "ps": "U2R", "sqlattack": "U2R",
    "xterm": "U2R",
}
CLASSES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
CLASS_UZ = {"Normal": "Normal trafik", "DoS": "Xizmatni ishdan chiqarish (DoS)", "Probe": "Razvedka / skanerlash (Probe)",
            "R2L": "Masofadan kirish (R2L)", "U2R": "Huquqlarni oshirish (U2R)"}

# Port → NSL-KDD xizmat nomi (Zeek service maydoni bo‘sh bo‘lsa ishlatiladi)
TCP_PORTS = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 43: "whois", 53: "domain", 70: "gopher",
    79: "finger", 80: "http", 109: "pop_2", 110: "pop_3", 111: "sunrpc", 113: "auth", 119: "nntp", 139: "netbios_ssn",
    143: "imap4", 179: "bgp", 194: "IRC", 389: "ldap", 443: "http_443", 445: "netbios_ssn", 512: "exec", 513: "login",
    514: "shell", 515: "printer", 543: "klogin", 544: "kshell", 1521: "sql_net", 1433: "sql_net", 3306: "sql_net",
    3389: "remote_job", 5432: "sql_net", 6000: "X11", 6667: "IRC", 8001: "http_8001", 8080: "http", 8443: "http_443",
}
UDP_PORTS = {53: "domain_u", 69: "tftp_u", 123: "ntp_u", 137: "netbios_ns", 138: "netbios_dgm"}
ZEEK_SERVICE = {
    "http": "http", "ssl": "http_443", "dns": "domain_u", "ssh": "ssh", "ftp": "ftp", "ftp-data": "ftp_data",
    "smtp": "smtp", "pop3": "pop_3", "imap": "imap4", "irc": "IRC", "ntp": "ntp_u", "ldap": "ldap", "smb": "netbios_ssn",
    "krb": "other", "rdp": "remote_job", "dce_rpc": "netbios_ssn", "telnet": "telnet", "mysql": "sql_net",
}
# Zeek conn_state → NSL-KDD flag
ZEEK_FLAG = {"SF": "SF", "S0": "S0", "REJ": "REJ", "RSTO": "RSTO", "RSTR": "RSTR", "RSTOS0": "RSTOS0", "RSTRH": "RSTR",
             "SH": "SH", "SHR": "SH", "S1": "S1", "S2": "S2", "S3": "S3", "OTH": "OTH"}
SYN_ERR = {"S0", "S1", "S2", "S3"}
REJ_ERR = {"REJ"}


def nsl_service(proto: str, dport: int, zeek_service: str = "", icmp_type: int | None = None) -> str:
    proto = (proto or "").lower()
    if proto == "icmp":
        return {8: "eco_i", 0: "ecr_i", 13: "tim_i", 5: "red_i"}.get(icmp_type if icmp_type is not None else dport, "urp_i")
    zs = (zeek_service or "").split(",")[0].strip().lower()
    if zs in ZEEK_SERVICE:
        return ZEEK_SERVICE[zs]
    table = UDP_PORTS if proto == "udp" else TCP_PORTS
    if dport in table:
        return table[dport]
    return "private" if dport < 49152 else "other"


@dataclass
class Conn:
    """Normallashtirilgan ulanish yozuvi (Zeek conn.log’ga mos)."""
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    proto: str = "tcp"
    service: str = ""
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = "SF"
    uid: str = ""
    query: str = ""         # DNS so‘rovi (dns.log’dan, ixtiyoriy)

    @property
    def flag(self) -> str:
        return ZEEK_FLAG.get((self.conn_state or "OTH").upper(), "OTH")


class FeatureExtractor:
    """Ulanishlar oqimidan NSL-KDD vaqt (2 s) va xost (100 ulanish) xususiyatlarini hisoblaydi.

    Ulanishlar vaqt bo‘yicha tartiblangan holda beriladi. Xotira cheklangan: har bir xost uchun 100 ta yozuv.
    """

    def __init__(self, window_s: float = 2.0, host_n: int = 100):
        self.window_s = window_s
        self.recent: deque = deque(maxlen=1000)            # (ts, dst, svc, flag, src) — oxirgi 2 s (ko‘pi bilan 1000)
        self.by_host: dict[str, deque] = defaultdict(lambda: deque(maxlen=host_n))  # dst → (svc, flag, src, sport)

    def features(self, c: Conn) -> dict:
        svc = nsl_service(c.proto, c.dport, c.service)
        flag = c.flag
        # --- vaqt bo‘yicha (oxirgi 2 soniya)
        while self.recent and c.ts - self.recent[0][0] > self.window_s:
            self.recent.popleft()
        same_host = [r for r in self.recent if r[1] == c.dst]
        same_srv = [r for r in self.recent if r[2] == svc]
        count = min(len(same_host) + 1, 511)              # NSL-KDD’da ham 511 bilan cheklangan
        srv_count = min(len(same_srv) + 1, 511)

        def rate(rows, cond, cur):
            n = len(rows) + 1
            return round((sum(1 for r in rows if cond(r)) + (1 if cur else 0)) / n, 2)

        f = {
            "duration": float(c.duration or 0), "protocol_type": (c.proto or "tcp").lower(), "service": svc, "flag": flag,
            "src_bytes": float(c.orig_bytes or 0), "dst_bytes": float(c.resp_bytes or 0),
            "land": int(c.src == c.dst and c.sport == c.dport), "wrong_fragment": 0, "urgent": 0,
            "count": count, "srv_count": srv_count,
            "serror_rate": rate(same_host, lambda r: r[3] in SYN_ERR, flag in SYN_ERR),
            "srv_serror_rate": rate(same_srv, lambda r: r[3] in SYN_ERR, flag in SYN_ERR),
            "rerror_rate": rate(same_host, lambda r: r[3] in REJ_ERR, flag in REJ_ERR),
            "srv_rerror_rate": rate(same_srv, lambda r: r[3] in REJ_ERR, flag in REJ_ERR),
            "same_srv_rate": rate(same_host, lambda r: r[2] == svc, True),
            "diff_srv_rate": rate(same_host, lambda r: r[2] != svc, False),
            "srv_diff_host_rate": rate(same_srv, lambda r: r[1] != c.dst, False),
        }
        # --- xost bo‘yicha (shu xostga oxirgi 100 ulanish)
        h = self.by_host[c.dst]
        hn = len(h) + 1
        hs = [r for r in h if r[0] == svc]
        hsn = len(hs) + 1
        f.update({
            "dst_host_count": hn,
            "dst_host_srv_count": hsn,
            "dst_host_same_srv_rate": round(hsn / hn, 2),
            "dst_host_diff_srv_rate": round((hn - hsn) / hn, 2),
            "dst_host_same_src_port_rate": round((sum(1 for r in h if r[3] == c.sport) + 1) / hn, 2),
            "dst_host_srv_diff_host_rate": round(sum(1 for r in hs if r[2] != c.src) / hsn, 2),
            "dst_host_serror_rate": round((sum(1 for r in h if r[1] in SYN_ERR) + (flag in SYN_ERR)) / hn, 2),
            "dst_host_srv_serror_rate": round((sum(1 for r in hs if r[1] in SYN_ERR) + (flag in SYN_ERR)) / hsn, 2),
            "dst_host_rerror_rate": round((sum(1 for r in h if r[1] in REJ_ERR) + (flag in REJ_ERR)) / hn, 2),
            "dst_host_srv_rerror_rate": round((sum(1 for r in hs if r[1] in REJ_ERR) + (flag in REJ_ERR)) / hsn, 2),
        })
        for k in CONTENT:
            f[k] = 0
        self.recent.append((c.ts, c.dst, svc, flag, c.src))
        h.append((svc, flag, c.src, c.sport))
        return f
