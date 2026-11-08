"""Tizim sozlamalari: korxona tarmog‘i segmentlari, risk formulasi vaznlari, javob chegaralari.

Qiymatlar diplom ishining 3.2–3.3-bandlari va B-ilovasiga mos. Korxonaga moslash uchun shu faylni
yoki muhit o‘zgaruvchilarini (NETGUARD_*) o‘zgartiring; aktivlar, oq ro‘yxat va IoC esa veb-konsoldan boshqariladi.
"""
from __future__ import annotations

import ipaddress
import os

# --- Tarmoq segmentlari (1.1-rasm: perimetr, DMZ, ichki tarmoq, monitoring zonasi)
HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
SEGMENTS = {
    "infra": "10.0.0.0/24",      # shlyuz, DNS, kommutatorlar
    "server": "10.0.1.0/24",     # ichki serverlar (AD, MBBT, fayl server, pochta)
    "dmz": "10.0.2.0/24",        # veb-portal, pochta shlyuzi
    "user": "10.0.10.0/23",      # xodimlar ishchi stansiyalari ($USER_NET)
    "soc": "10.0.99.0/24",       # monitoring zonasi
}
SEGMENT_UZ = {"infra": "Infratuzilma", "server": "Ichki serverlar", "dmz": "DMZ", "user": "Ishchi stansiyalar",
              "soc": "Monitoring (SOC)", "internal": "Ichki tarmoq", "external": "Tashqi (Internet)"}

_HOME = [ipaddress.ip_network(n) for n in HOME_NET]
_SEG = {k: ipaddress.ip_network(v) for k, v in SEGMENTS.items()}


def ip(addr: str):
    try:
        return ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return None


def is_internal(addr: str) -> bool:
    a = ip(addr)
    return bool(a) and any(a in n for n in _HOME)


def segment(addr: str) -> str:
    a = ip(addr)
    if a is None:
        return "external"
    for k, n in _SEG.items():
        if a in n:
            return k
    return "internal" if is_internal(addr) else "external"


# --- Risk formulasi (3.2): Risk = 0,4·S_sig + 0,3·P_XGB + 0,2·S_IF + 0,1·S_aktiv
WEIGHTS = {"sig": 0.4, "xgb": 0.3, "if": 0.2, "asset": 0.1}
LEVEL_HIGH = float(os.environ.get("NETGUARD_HIGH", 0.8))     # ≥ 0,8 — avtomatik bloklash
LEVEL_MEDIUM = float(os.environ.get("NETGUARD_MEDIUM", 0.5))  # 0,5–0,8 — SOC tahlilchisiga
P_XGB_THRESHOLD = 0.5                                         # (3.1): [P_XGB ≥ 0,5]
S_IF_THRESHOLD = 0.5                                          # (3.1): [IF anomaliya]
DEFAULT_ASSET = 0.3                                           # B-ilova: ASSET.get(ip, 0.3)
SURICATA_SEVERITY = {1: 1.0, 2: 0.6, 3: 0.3}                  # B-ilova: Suricata severity → S_sig

# --- Javob (3.3-band, himoya choralari)
BLOCK_TTL_H = int(os.environ.get("NETGUARD_TTL_H", 24))       # bloklash muddati (ipset timeout 86400)
DEFAULT_MODE = os.environ.get("NETGUARD_MODE", "ips")         # ips — faol himoya, ids — faqat monitoring
ALERT_MERGE_S = 600                                           # bir manbadan bir xil ogohlantirishlarni 10 daqiqa birlashtirish
INCIDENT_MERGE_H = 24

DEFAULT_WHITELIST = [
    ("10.0.0.0/24", "Tarmoq infratuzilmasi (shlyuz, DNS)"),
    ("10.0.99.0/24", "Monitoring zonasi (SOC)"),
    ("192.168.10.5/32", "Hamkor tashkilot (B-ilova namunasi)"),
]

# --- Aktivlar (S_aktiv) — B-ilova: ASSET = {"10.0.1.10": 1.0, "10.0.1.20": 0.8}
DEFAULT_ASSETS = [
    # ip, nom, vazifa, muhimlik
    ("10.0.1.10", "db-01", "Ma’lumotlar bazasi serveri (1C, ERP)", 1.0),
    ("10.0.1.20", "fs-01", "Fayl server (SMB)", 0.8),
    ("10.0.1.30", "dc-01", "Active Directory domen kontrolleri", 1.0),
    ("10.0.1.40", "mail-01", "Pochta serveri", 0.7),
    ("10.0.2.10", "web-01", "Korxona veb-portali (mijozlar ma’lumotlari)", 1.0),
    ("10.0.2.20", "vpn-01", "VPN shlyuzi", 0.8),
    ("10.0.0.1", "gw-01", "Chegara marshrutizatori / NGFW", 0.9),
    ("10.0.0.53", "dns-01", "Ichki DNS server", 0.7),
]

# --- Tahdid indikatorlari (IoC) — namuna; real tizimda tahdidlar razvedkasi lentasidan yangilanadi
DEFAULT_IOC = [
    ("193.42.33.14", "ip", "C2 server (namuna IoC)"),
    ("tunnel-c2.xyz", "domain", "DNS tunnel domeni (namuna IoC)"),
    ("update-microsoft-cdn.top", "domain", "Zararli domen (namuna IoC)"),
]

# --- Signatura chegaralari (C-ilova)
SCAN_COUNT, SCAN_SECONDS, SCAN_DISTINCT = 50, 30, 20     # 1-qoida: 30 s da 50+ SYN
BRUTE_COUNT, BRUTE_SECONDS = 15, 60                      # 2-qoida: 60 s da 15+ ulanish (RDP/SSH)
SMB_LIMIT_SECONDS = 300                                  # 3-qoida: threshold type limit, 300 s
DNS_LONG_LABEL = 50                                      # 4-qoida: pcre ^[a-z0-9]{50,}\.
SYNFLOOD_COUNT, SYNFLOOD_SECONDS = 100, 2                # SYN flood: 2 s da bitta xostga 100+ yarim ochiq ulanish

# --- Korrelyatsiya chegaralari (3.9-jadval)
CORR = {
    "auth_fail_count": 20, "auth_fail_window": 300,      # 5 daqiqada ≥ 20 muvaffaqiyatsiz kirish
    "scan_exploit_window": 3600,                          # 1 soat
    "lateral_hosts": 5, "lateral_window": 600,            # ≥ 5 ta boshqa stansiya, 10 daqiqa
    "beacon_min": 8, "beacon_cv": 0.15,                   # muntazam interval: variatsiya koeffitsiyenti < 0,15
    "exfil_bytes": 1_000_000_000, "exfil_window": 3600,   # > 1 GB, ish vaqtidan tashqari
    "work_hours": (8, 19),
    "ransom_fim": 100, "ransom_window": 60,               # 60 s da ≥ 100 fayl o‘zgarishi
    "dns_tunnel_count": 20, "dns_tunnel_window": 300,     # qo‘shimcha qoida: 5 daqiqada bitta domenga ≥ 20 uzun so‘rov
}
