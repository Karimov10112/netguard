"""SIEM ma’lumotlar ombori (SQLite): ogohlantirishlar, insidentlar, javob choralari, aktivlar, oq ro‘yxat, IoC.

Vaqt maydonlari: `*_ts` — hodisa vaqti (epoch, s), `created` / `expires` — tizim (devor soati) vaqti.
"""
from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import config as C

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_ts REAL NOT NULL, last_ts REAL NOT NULL,
    src TEXT, dst TEXT, dport INTEGER, proto TEXT,
    name TEXT NOT NULL, module TEXT NOT NULL, category TEXT, sid INTEGER,
    mitre TEXT, attack_class TEXT,
    s_sig REAL DEFAULT 0, p_xgb REAL DEFAULT 0, s_if REAL DEFAULT 0, s_akt REAL DEFAULT 0,
    risk REAL NOT NULL, level TEXT NOT NULL, count INTEGER DEFAULT 1,
    dsts TEXT DEFAULT '[]', detail TEXT DEFAULT '{}',
    incident_id INTEGER, batch_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_alerts_src ON alerts(src, name, last_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(last_ts);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_ts REAL NOT NULL, last_ts REAL NOT NULL, created REAL NOT NULL,
    entity TEXT NOT NULL, title TEXT NOT NULL, rules TEXT DEFAULT '[]', mitre TEXT DEFAULT '[]',
    s_sig REAL DEFAULT 0, p_xgb REAL DEFAULT 0, s_if REAL DEFAULT 0, s_akt REAL DEFAULT 0,
    risk REAL NOT NULL, level TEXT NOT NULL, status TEXT DEFAULT 'open',
    assignee TEXT DEFAULT '', notes TEXT DEFAULT '', detail TEXT DEFAULT '{}', batch_id INTEGER,
    detected_ts REAL, responded_ts REAL
);
CREATE INDEX IF NOT EXISTS ix_inc_entity ON incidents(entity, status);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, created REAL NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
    reason TEXT, incident_id INTEGER, status TEXT NOT NULL, mode TEXT, actor TEXT DEFAULT 'auto',
    expires REAL, revoked REAL, revoked_by TEXT
);
CREATE INDEX IF NOT EXISTS ix_actions_target ON actions(target, status);
CREATE TABLE IF NOT EXISTS assets (ip TEXT PRIMARY KEY, name TEXT, role TEXT, criticality REAL NOT NULL);
CREATE TABLE IF NOT EXISTS whitelist (cidr TEXT PRIMARY KEY, note TEXT);
CREATE TABLE IF NOT EXISTS ioc (value TEXT PRIMARY KEY, type TEXT NOT NULL, note TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL NOT NULL, source TEXT, name TEXT,
    n_conns INTEGER DEFAULT 0, n_eve INTEGER DEFAULT 0, n_host INTEGER DEFAULT 0,
    n_alerts INTEGER DEFAULT 0, n_incidents INTEGER DEFAULT 0, dropped INTEGER DEFAULT 0,
    seconds REAL DEFAULT 0, summary TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS traffic (bucket INTEGER PRIMARY KEY, conns INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
                                    alerts INTEGER DEFAULT 0, dropped INTEGER DEFAULT 0);
"""

ACTION_UZ = {"block_ip": "IP manzilni bloklash", "quarantine_host": "Xostni karantin VLAN ga o‘tkazish",
             "block_domain": "Domenni bloklash (DNS RPZ)", "disable_account": "Hisob yozuvini bloklash",
             "rate_limit": "Ulanishni cheklash", "notify_soc": "SOC tahlilchisiga yuborish", "unblock": "Blokdan chiqarish"}
STATUS_UZ = {"active": "Faol", "simulated": "Tavsiya (monitoring rejimi)", "skipped": "O‘tkazib yuborildi (oq ro‘yxat)",
             "revoked": "Bekor qilingan", "expired": "Muddati tugagan", "done": "Bajarildi"}
INC_STATUS_UZ = {"open": "Yangi", "investigating": "Tekshirilmoqda", "resolved": "Hal qilingan",
                 "false_positive": "Soxta trevoga"}


def _j(v):
    return json.dumps(v, ensure_ascii=False)


class Storage:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)
            if not c.execute("SELECT 1 FROM settings WHERE key='seeded'").fetchone():
                c.executemany("INSERT OR IGNORE INTO assets VALUES (?,?,?,?)", C.DEFAULT_ASSETS)
                c.executemany("INSERT OR IGNORE INTO whitelist VALUES (?,?)", C.DEFAULT_WHITELIST)
                c.executemany("INSERT OR IGNORE INTO ioc VALUES (?,?,?)", C.DEFAULT_IOC)
                c.execute("INSERT OR REPLACE INTO settings VALUES ('mode', ?)", (C.DEFAULT_MODE,))
                c.execute("INSERT OR REPLACE INTO settings VALUES ('seeded', '1')")

    @contextmanager
    def conn(self):
        with _lock:
            c = sqlite3.connect(self.path, timeout=30)
            c.row_factory = sqlite3.Row
            try:
                yield c
                c.commit()
            finally:
                c.close()

    # ------------------------------------------------------------------ sozlamalar
    def get_setting(self, key: str, default: str = "") -> str:
        with self.conn() as c:
            r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def set_setting(self, key: str, value: str) -> None:
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))

    @property
    def mode(self) -> str:
        return self.get_setting("mode", C.DEFAULT_MODE)

    # ------------------------------------------------------------------ aktivlar, oq ro‘yxat, IoC
    def assets(self) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM assets ORDER BY criticality DESC, ip")]

    def asset_map(self) -> dict[str, float]:
        return {a["ip"]: a["criticality"] for a in self.assets()}

    def upsert_asset(self, ip: str, name: str, role: str, crit: float) -> None:
        ipaddress.ip_address(ip)
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO assets VALUES (?,?,?,?)", (ip, name, role, max(0.0, min(1.0, crit))))

    def delete_asset(self, ip: str) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM assets WHERE ip=?", (ip,))

    def whitelist(self) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM whitelist ORDER BY cidr")]

    def whitelist_nets(self):
        return [ipaddress.ip_network(w["cidr"], strict=False) for w in self.whitelist()]

    def add_whitelist(self, cidr: str, note: str) -> None:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO whitelist VALUES (?,?)", (str(net), note))

    def delete_whitelist(self, cidr: str) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM whitelist WHERE cidr=?", (cidr,))

    def ioc(self) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM ioc ORDER BY type, value")]

    def ioc_map(self) -> dict[str, tuple[str, str]]:
        return {i["value"]: (i["type"], i["note"] or "IoC") for i in self.ioc()}

    def add_ioc(self, value: str, note: str) -> str:
        value = value.strip().lower().strip(".")
        try:
            ipaddress.ip_address(value)
            t = "ip"
        except ValueError:
            if not value or " " in value or "." not in value:
                raise ValueError("IP manzil yoki domen kiriting")
            t = "domain"
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO ioc VALUES (?,?,?)", (value, t, note))
        return t

    def delete_ioc(self, value: str) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM ioc WHERE value=?", (value,))

    # ------------------------------------------------------------------ ogohlantirishlar
    def save_alert(self, a: dict, batch_id: int | None) -> int:
        """Bir manbadan bir xil nomdagi ogohlantirish 10 daqiqa ichida takrorlansa — mavjudiga qo‘shiladi."""
        with self.conn() as c:
            row = c.execute("SELECT * FROM alerts WHERE src=? AND name=? AND last_ts>=? AND first_ts<=? "
                            "ORDER BY last_ts DESC LIMIT 1",
                            (a["src"], a["name"], a["first_ts"] - C.ALERT_MERGE_S, a["last_ts"] + C.ALERT_MERGE_S)).fetchone()
            if row:
                dsts = sorted(set(json.loads(row["dsts"])) | set(a["dsts"]))[:50]
                keep = {k: max(row[k], a[k]) for k in ("s_sig", "p_xgb", "s_if", "s_akt", "risk")}
                lvl = a["level"] if keep["risk"] == a["risk"] else row["level"]
                c.execute("UPDATE alerts SET first_ts=?, last_ts=?, count=count+?, dsts=?, s_sig=?, p_xgb=?, s_if=?, s_akt=?,"
                          " risk=?, level=? WHERE id=?",
                          (min(row["first_ts"], a["first_ts"]), max(row["last_ts"], a["last_ts"]), a["count"], _j(dsts),
                           keep["s_sig"], keep["p_xgb"], keep["s_if"], keep["s_akt"], keep["risk"], lvl, row["id"]))
                return row["id"]
            cur = c.execute(
                "INSERT INTO alerts (first_ts,last_ts,src,dst,dport,proto,name,module,category,sid,mitre,attack_class,"
                "s_sig,p_xgb,s_if,s_akt,risk,level,count,dsts,detail,batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["first_ts"], a["last_ts"], a["src"], a["dst"], a["dport"], a["proto"], a["name"], a["module"],
                 a.get("category", ""), a.get("sid", 0), a.get("mitre", ""), a.get("attack_class", ""), a["s_sig"],
                 a["p_xgb"], a["s_if"], a["s_akt"], a["risk"], a["level"], a["count"], _j(sorted(a["dsts"])[:50]),
                 _j(a.get("detail", {})), batch_id))
            return cur.lastrowid

    def link_alerts(self, alert_ids: list[int], incident_id: int) -> None:
        with self.conn() as c:
            c.executemany("UPDATE alerts SET incident_id=? WHERE id=?", [(incident_id, i) for i in alert_ids])

    def alerts(self, level: str = "", src: str = "", q: str = "", incident_id: int | None = None, limit: int = 300,
               offset: int = 0) -> list[dict]:
        sql, args = "SELECT * FROM alerts WHERE 1=1", []
        if level:
            sql += " AND level=?"
            args.append(level)
        if src:
            sql += " AND (src=? OR dst=?)"
            args += [src, src]
        if q:
            sql += " AND (name LIKE ? OR src LIKE ? OR dst LIKE ? OR mitre LIKE ?)"
            args += [f"%{q}%"] * 4
        if incident_id is not None:
            sql += " AND incident_id=?"
            args.append(incident_id)
        sql += " ORDER BY last_ts DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self.conn() as c:
            return [self._alert(r) for r in c.execute(sql, args)]

    def alert(self, aid: int) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return self._alert(r) if r else None

    @staticmethod
    def _alert(r) -> dict:
        d = dict(r)
        d["dsts"] = json.loads(d["dsts"] or "[]")
        d["detail"] = json.loads(d["detail"] or "{}")
        return d

    # ------------------------------------------------------------------ insidentlar
    def open_incident(self, entity: str, ts: float):
        with self.conn() as c:
            return c.execute("SELECT * FROM incidents WHERE entity=? AND status IN ('open','investigating') AND last_ts>=? "
                             "ORDER BY id DESC LIMIT 1", (entity, ts - C.INCIDENT_MERGE_H * 3600)).fetchone()

    def save_incident(self, inc: dict, batch_id: int | None) -> int:
        row = self.open_incident(inc["entity"], inc["first_ts"])
        with self.conn() as c:
            if row:
                rules = sorted(set(json.loads(row["rules"])) | set(inc["rules"]))
                mitre = sorted(set(json.loads(row["mitre"])) | set(inc["mitre"]))
                detail = json.loads(row["detail"])
                detail.update(inc.get("detail", {}))
                title = inc["title"] if inc["risk"] >= row["risk"] or inc["rules"] else row["title"]
                c.execute("UPDATE incidents SET first_ts=?, last_ts=?, title=?, rules=?, mitre=?, s_sig=?, p_xgb=?, s_if=?,"
                          " s_akt=?, risk=?, level=?, detail=?, detected_ts=COALESCE(detected_ts, ?),"
                          " responded_ts=COALESCE(responded_ts, ?) WHERE id=?",
                          (min(row["first_ts"], inc["first_ts"]), max(row["last_ts"], inc["last_ts"]), title, _j(rules),
                           _j(mitre), max(row["s_sig"], inc["s_sig"]), max(row["p_xgb"], inc["p_xgb"]),
                           max(row["s_if"], inc["s_if"]), max(row["s_akt"], inc["s_akt"]), max(row["risk"], inc["risk"]),
                           inc["level"] if inc["risk"] >= row["risk"] else row["level"], _j(detail),
                           inc.get("detected_ts"), inc.get("responded_ts"), row["id"]))
                return row["id"]
            cur = c.execute(
                "INSERT INTO incidents (first_ts,last_ts,created,entity,title,rules,mitre,s_sig,p_xgb,s_if,s_akt,risk,level,"
                "detail,batch_id,detected_ts,responded_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc["first_ts"], inc["last_ts"], time.time(), inc["entity"], inc["title"], _j(sorted(inc["rules"])),
                 _j(sorted(inc["mitre"])), inc["s_sig"], inc["p_xgb"], inc["s_if"], inc["s_akt"], inc["risk"],
                 inc["level"], _j(inc.get("detail", {})), batch_id, inc.get("detected_ts"), inc.get("responded_ts")))
            return cur.lastrowid

    def incidents(self, status: str = "", level: str = "", limit: int = 300) -> list[dict]:
        sql, args = "SELECT * FROM incidents WHERE 1=1", []
        if status:
            sql += " AND status=?"
            args.append(status)
        if level:
            sql += " AND level=?"
            args.append(level)
        sql += " ORDER BY CASE level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, last_ts DESC LIMIT ?"
        args.append(limit)
        with self.conn() as c:
            return [self._inc(r) for r in c.execute(sql, args)]

    def incident(self, iid: int) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        return self._inc(r) if r else None

    @staticmethod
    def _inc(r) -> dict:
        d = dict(r)
        for k in ("rules", "mitre"):
            d[k] = json.loads(d[k] or "[]")
        d["detail"] = json.loads(d["detail"] or "{}")
        return d

    def update_incident(self, iid: int, status: str | None = None, assignee: str | None = None,
                        notes: str | None = None) -> None:
        with self.conn() as c:
            if status in INC_STATUS_UZ:
                c.execute("UPDATE incidents SET status=? WHERE id=?", (status, iid))
            if assignee is not None:
                c.execute("UPDATE incidents SET assignee=? WHERE id=?", (assignee[:80], iid))
            if notes is not None:
                c.execute("UPDATE incidents SET notes=? WHERE id=?", (notes[:4000], iid))

    # ------------------------------------------------------------------ javob choralari
    def add_action(self, ts: float, action: str, target: str, reason: str, incident_id: int | None, status: str,
                   mode: str, actor: str = "auto", ttl_h: float | None = None) -> int:
        now = time.time()
        expires = now + ttl_h * 3600 if ttl_h else None
        with self.conn() as c:
            cur = c.execute("INSERT INTO actions (ts,created,action,target,reason,incident_id,status,mode,actor,expires) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (ts, now, action, target, reason, incident_id, status, mode, actor, expires))
            return cur.lastrowid

    def expire_actions(self) -> int:
        with self.conn() as c:
            return c.execute("UPDATE actions SET status='expired' WHERE status='active' AND expires IS NOT NULL AND expires<?",
                             (time.time(),)).rowcount

    def actions(self, status: str = "", incident_id: int | None = None, limit: int = 500) -> list[dict]:
        self.expire_actions()
        sql, args = "SELECT * FROM actions WHERE 1=1", []
        if status:
            sql += " AND status=?"
            args.append(status)
        if incident_id is not None:
            sql += " AND incident_id=?"
            args.append(incident_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.conn() as c:
            return [dict(r) for r in c.execute(sql, args)]

    def active_targets(self, action: str | None = None) -> set[str]:
        self.expire_actions()
        with self.conn() as c:
            if action:
                rows = c.execute("SELECT target FROM actions WHERE status='active' AND action=?", (action,))
            else:
                rows = c.execute("SELECT target FROM actions WHERE status='active'")
            return {r["target"] for r in rows}

    def is_active(self, action: str, target: str) -> bool:
        with self.conn() as c:
            return bool(c.execute("SELECT 1 FROM actions WHERE action=? AND target=? AND status IN ('active','simulated') "
                                  "AND (expires IS NULL OR expires>?)", (action, target, time.time())).fetchone())

    def revoke(self, aid: int, by: str = "analyst") -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM actions WHERE id=?", (aid,)).fetchone()
            if not r or r["status"] not in ("active", "simulated"):
                return None
            c.execute("UPDATE actions SET status='revoked', revoked=?, revoked_by=? WHERE id=?", (time.time(), by, aid))
            return dict(r)

    def blocklist(self) -> list[dict]:
        """Agent (integrations/blocker_agent.py) uchun faol bloklashlar: IP, qolgan muddat."""
        now = time.time()
        return [{"ip": a["target"], "action": a["action"], "timeout": int(a["expires"] - now) if a["expires"] else 0,
                 "reason": a["reason"], "id": a["id"]}
                for a in self.actions("active") if a["action"] in ("block_ip", "quarantine_host", "rate_limit")]

    # ------------------------------------------------------------------ paketlar va trafik statistikasi
    def new_batch(self, source: str, name: str) -> int:
        with self.conn() as c:
            return c.execute("INSERT INTO batches (created, source, name) VALUES (?,?,?)",
                             (time.time(), source, name)).lastrowid

    def finish_batch(self, bid: int, **kw) -> None:
        summary = kw.pop("summary", {})
        sets = ", ".join(f"{k}=?" for k in kw)
        with self.conn() as c:
            c.execute(f"UPDATE batches SET {sets}, summary=? WHERE id=?", (*kw.values(), _j(summary), bid))

    def batches(self, limit: int = 30) -> list[dict]:
        with self.conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM batches ORDER BY id DESC LIMIT ?", (limit,))]
        for r in rows:
            r["summary"] = json.loads(r["summary"] or "{}")
        return rows

    def batch(self, bid: int) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM batches WHERE id=?", (bid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["summary"] = json.loads(d["summary"] or "{}")
        return d

    def add_traffic(self, buckets: dict[int, list[int]]) -> None:
        with self.conn() as c:
            c.executemany("INSERT INTO traffic (bucket, conns, bytes, alerts, dropped) VALUES (?,?,?,?,?) "
                          "ON CONFLICT(bucket) DO UPDATE SET conns=conns+excluded.conns, bytes=bytes+excluded.bytes, "
                          "alerts=alerts+excluded.alerts, dropped=dropped+excluded.dropped",
                          [(k, *v) for k, v in buckets.items()])

    def traffic(self, since: float) -> list[dict]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM traffic WHERE bucket>=? ORDER BY bucket", (int(since),))]

    # ------------------------------------------------------------------ boshqaruv paneli
    def open_counts(self) -> dict:
        with self.conn() as c:
            return {r["level"]: r["n"] for r in c.execute(
                "SELECT level, COUNT(*) n FROM incidents WHERE status IN ('open','investigating') GROUP BY level")}

    def stats(self) -> dict:
        with self.conn() as c:
            q = lambda s, *a: c.execute(s, a).fetchone()[0]  # noqa: E731
            levels = {r["level"]: r["n"] for r in c.execute("SELECT level, COUNT(*) n FROM alerts GROUP BY level")}
            inc_lv = {r["level"]: r["n"] for r in c.execute(
                "SELECT level, COUNT(*) n FROM incidents WHERE status IN ('open','investigating') GROUP BY level")}
            out = {
                "alerts": q("SELECT COUNT(*) FROM alerts"), "alert_levels": levels,
                "incidents_open": q("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')"),
                "incidents_total": q("SELECT COUNT(*) FROM incidents"), "incident_levels": inc_lv,
                "conns": q("SELECT COALESCE(SUM(conns),0) FROM traffic"),
                "dropped": q("SELECT COALESCE(SUM(dropped),0) FROM traffic"),
                "bytes": q("SELECT COALESCE(SUM(bytes),0) FROM traffic"),
                "top_src": [dict(r) for r in c.execute(
                    "SELECT src, MAX(risk) risk, SUM(count) n, COUNT(*) k FROM alerts GROUP BY src ORDER BY risk DESC, n DESC LIMIT 8")],
                "by_module": {r["module"]: r["n"] for r in c.execute("SELECT module, COUNT(*) n FROM alerts GROUP BY module")},
                "by_class": {r["attack_class"]: r["n"] for r in c.execute(
                    "SELECT attack_class, COUNT(*) n FROM alerts WHERE attack_class<>'' GROUP BY attack_class")},
                "mitre": [dict(r) for r in c.execute(
                    "SELECT mitre, COUNT(*) n FROM alerts WHERE mitre<>'' GROUP BY mitre ORDER BY n DESC LIMIT 12")],
                "mttd": q("SELECT AVG(detected_ts-first_ts) FROM incidents WHERE detected_ts IS NOT NULL"),
                "mttr": q("SELECT AVG(responded_ts-detected_ts) FROM incidents WHERE responded_ts IS NOT NULL"),
            }
        self.expire_actions()
        with self.conn() as c:
            out["actions_active"] = c.execute("SELECT COUNT(*) FROM actions WHERE status='active'").fetchone()[0]
            out["actions_by"] = {r["action"]: r["n"] for r in c.execute(
                "SELECT action, COUNT(*) n FROM actions WHERE status IN ('active','simulated','done') GROUP BY action")}
        return out

    def reset(self) -> None:
        """Hodisalarni tozalash (aktivlar, oq ro‘yxat, IoC va sozlamalar saqlanadi)."""
        with self.conn() as c:
            for t in ("alerts", "incidents", "actions", "batches", "traffic"):
                c.execute(f"DELETE FROM {t}")
            c.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts','incidents','actions','batches')")
