"""NetGuard — korxona tarmog‘ida kiberhujumlarni aniqlash va oldini olish tizimi.

To‘rt qatlamli gibrid arxitektura (diplom ishi, 3.1-rasm):
  1. Yig‘ish       — Zeek conn.log, Suricata eve.json, Wazuh/AD autentifikatsiya va FIM hodisalari;
  2. Aniqlash      — signatura moduli, XGBoost klassifikatori, Isolation Forest anomaliya moduli;
  3. Korrelyatsiya — SIEM qoidalari, MITRE ATT&CK, risk balli;
  4. Javob         — avtomatik bloklash (ipset/iptables, TTL 24 soat), SOC’ga yo‘naltirish, jurnalga yozish.
"""

__version__ = "1.0.0"
