"""Tizim yadrosi: to‘rt qatlamli gibrid quvur (diplom, 3.1-band).

  1. Ma’lumot yig‘ish — Zeek conn/dns, Suricata EVE, Wazuh (auth, FIM) yozuvlari (parsers.py, simulator.py)
  2. Aniqlash       — signatura moduli (signatures.py) + ML modul: XGBoost va Isolation Forest (models.py)
  3. Korrelyatsiya   — gibrid qoida (3.1), risk balli (3.2), SIEM qoidalari (correlation.py), insidentlar
  4. Javob          — avtomatik bloklash / karantin / SOC (response.py)

Ogohlantirishlar manba (subyekt) bo‘yicha birlashtiriladi: subyektning risk balli uning barcha ogohlantirishlaridagi
eng yuqori S_sig, P_XGB, S_IF va S_aktiv qiymatlaridan (3.2) formula bo‘yicha hisoblanadi.
"""
from __future__ import annotations

import heapq
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import config as C
from .correlation import RULES, CorrHit, Correlator
from .features import CLASS_UZ, Conn, FeatureExtractor
from .models import Detector
from .response import Responder
from .risk import is_alert, level, risk
from .signatures import Hit, Signatures, from_eve
from .storage import Storage

CLASS_MITRE = {"DoS": "T1499", "Probe": "T1046", "R2L": "T1110", "U2R": "T1068"}


@dataclass
class Entity:
    key: str
    first_ts: float
    last_ts: float
    s_sig: float = 0.0
    p_xgb: float = 0.0
    s_if: float = 0.0
    s_akt: float = 0.0
    risk: float = 0.0
    level: str = "low"
    rules: list = field(default_factory=list)
    mitre: set = field(default_factory=set)
    alerts: list = field(default_factory=list)       # alert kalitlari
    corr: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    detected_ts: float | None = None
    responded_ts: float | None = None
    title: str = ""
    classes: Counter = field(default_factory=Counter)


class State:
    """Oqim holati (real vaqt rejimida so‘rovlar orasida saqlanadi)."""

    def __init__(self, ioc: dict):
        self.fx = FeatureExtractor()
        self.sigs = Signatures(ioc)
        self.corr = Correlator({k for k, (t, _) in ioc.items() if t == "ip"})
        self.last_score: dict[tuple, tuple] = {}


class Engine:
    def __init__(self, store: Storage, detector: Detector):
        self.store = store
        self.det = detector
        self.live: State | None = None

    def reset_live(self) -> None:
        self.live = None

    # ------------------------------------------------------------------ asosiy quvur
    def process(self, conns: list[Conn] | None = None, eve: list[dict] | None = None, host: list[dict] | None = None,
                source: str = "upload", name: str = "", fresh: bool = True, truth: dict | None = None) -> dict:
        t_start = time.perf_counter()
        conns = sorted(conns or [], key=lambda c: c.ts)
        eve = sorted(eve or [], key=lambda e: float(e["ts"]))
        host = sorted(host or [], key=lambda e: float(e["ts"]))
        ioc = self.store.ioc_map()
        if fresh or self.live is None:
            st = State(ioc)
            if not fresh:
                self.live = st
        else:
            st = self.live
            st.sigs.ioc = ioc
        assets = self.store.asset_map()
        resp = Responder(self.store)
        bid = self.store.new_batch(source, name)

        # 2-qatlam (ML): xususiyatlar va baholash — paket bo‘yicha
        feats = [st.fx.features(c) for c in conns]
        sc = self.det.score(feats)

        alerts: dict[tuple, dict] = {}
        ents: dict[str, Entity] = {}
        blocked: dict[str, float] = {t: 0.0 for t in self.store.active_targets("block_ip")} if resp.mode == "ips" else {}
        quarantined: set[str] = self.store.active_targets("quarantine_host") if resp.mode == "ips" else set()
        buckets: dict[int, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
        dropped = 0

        def s_akt(src: str, dst: str) -> float:
            if C.is_internal(dst):
                return assets.get(dst, C.DEFAULT_ASSET)
            if C.is_internal(src):
                return assets.get(src, C.DEFAULT_ASSET)
            return C.DEFAULT_ASSET

        def entity(key: str, ts: float) -> Entity:
            e = ents.get(key)
            if e is None:
                e = ents[key] = Entity(key, ts, ts)
            e.first_ts, e.last_ts = min(e.first_ts, ts), max(e.last_ts, ts)
            return e

        def act(e: Entity, d: dict | None) -> None:
            if not d:
                return
            if any(a["action"] == d["action"] and a["target"] == d["target"] for a in e.actions):
                return
            e.actions.append(d)
            if d["status"] in ("active", "simulated", "done") and e.responded_ts is None:
                e.responded_ts = d["ts"]
            if d["status"] == "active" and d["action"] == "block_ip":
                blocked[d["target"]] = d["ts"]
            if d["status"] == "active" and d["action"] == "quarantine_host":
                quarantined.add(d["target"])

        def evaluate(e: Entity, ts: float, reason: str) -> None:
            r = risk(e.s_sig, e.p_xgb, e.s_if, e.s_akt)
            forced = max((RULES[x][5] for x in e.rules), default=0.0)
            new = max(r, forced)
            e.risk = round(max(e.risk, new), 4)
            lv = level(e.risk)
            if lv != "low" and e.detected_ts is None:
                e.detected_ts = ts
            if lv == "high" and e.level != "high":
                act(e, resp.for_level(ts, e.key, f"Risk {e.risk:.2f} ≥ {C.LEVEL_HIGH}: {reason}"))
            e.level = lv if lv != "low" or e.level == "low" else e.level

        def add_alert(ts, src, dst, dport, proto, name, module, s_sig, p, s, cls="", mitre="", sid=0, category="",
                      detail=None, ent=None, floor=0.0):
            akt = s_akt(src, dst)
            key = (src, name)
            a = alerts.get(key)
            if a and ts - a["last_ts"] > C.ALERT_MERGE_S:
                alerts[(src, name, a["first_ts"])] = alerts.pop(key)
                a = None
            if a is None:
                a = alerts[key] = {"first_ts": ts, "last_ts": ts, "src": src, "dst": dst, "dport": dport, "proto": proto,
                                   "name": name, "module": module, "sid": sid, "category": category, "mitre": mitre,
                                   "attack_class": cls, "s_sig": 0.0, "p_xgb": 0.0, "s_if": 0.0, "s_akt": 0.0,
                                   "count": 0, "dsts": set(), "detail": detail or {}, "entity": ent or src}
            a["last_ts"] = ts
            a["count"] += 1
            a["dsts"].add(dst)
            a["s_sig"], a["p_xgb"] = max(a["s_sig"], s_sig), max(a["p_xgb"], p)
            a["s_if"], a["s_akt"] = max(a["s_if"], s), max(a["s_akt"], akt)
            if detail:
                a["detail"].update(detail)
            a["risk"] = max(risk(a["s_sig"], a["p_xgb"], a["s_if"], a["s_akt"]), floor, a.get("floor", 0.0))
            a["floor"] = max(floor, a.get("floor", 0.0))
            a["level"] = level(a["risk"])
            buckets[int(ts // 60 * 60)][2] += 1
            e = entity(ent or src, ts)
            e.s_sig, e.p_xgb = max(e.s_sig, s_sig), max(e.p_xgb, p)
            e.s_if, e.s_akt = max(e.s_if, s), max(e.s_akt, akt)
            if mitre:
                e.mitre.add(mitre)
            if cls:
                e.classes[cls] += 1
            if key not in e.alerts:
                e.alerts.append(key)
            evaluate(e, ts, name)

        def on_corr(ch: CorrHit) -> None:
            e = entity(ch.entity, ch.ts)
            if ch.rule not in e.rules:
                e.rules.append(ch.rule)
            e.corr[ch.rule] = ch.detail
            e.mitre.update(ch.mitre)
            add_alert(ch.ts, ch.entity, ch.detail.get("destination", ch.detail.get("target", ch.target)), 0, "",
                      f"SIEM: {ch.title}", "corr", 0.0, 0.0, 0.0, mitre=ch.mitre[0], category=ch.rule, detail=ch.detail,
                      floor=ch.risk)
            evaluate(e, ch.ts, ch.title)
            reason = f"{ch.rule} «{ch.title}»"
            for action in ch.actions:
                target = ch.target
                if action == "disable_account":
                    target = ch.detail.get("account", "")
                elif action == "block_domain":
                    target = ch.detail.get("domain", ch.target)
                elif action == "rate_limit":
                    target = ch.entity
                act(e, resp.decide(ch.ts, action, target, reason))

        def on_hit(h: Hit, p: float, s: float) -> None:
            add_alert(h.ts, h.src, h.dst, h.dport, "tcp", h.name, h.module, h.severity, p, s, mitre=h.mitre, sid=h.sid,
                      category=h.category, detail={**h.detail, **({"domain": h.domain} if h.domain else {})})
            for ch in st.corr.on_hit(h):
                on_corr(ch)

        # 1–3-qatlamlar: hodisalarni vaqt bo‘yicha birlashtirib qayta ishlash
        stream = heapq.merge(((c.ts, 0, i) for i, c in enumerate(conns)), ((float(e["ts"]), 1, i) for i, e in enumerate(eve)),
                             ((float(e["ts"]), 2, i) for i, e in enumerate(host)))
        for ts, kind, i in stream:
            if kind == 0:
                c = conns[i]
                b = buckets[int(ts // 60 * 60)]
                b[0] += 1
                b[1] += int(c.orig_bytes or 0) + int(c.resp_bytes or 0)
                if (c.src in blocked and blocked[c.src] <= ts) or (c.src in quarantined) or \
                        (c.dst in blocked and blocked[c.dst] <= ts and C.is_internal(c.src)):
                    dropped += 1          # IPS: bloklangan manbadan/manzilga trafik to‘xtatildi
                    b[3] += 1
                    continue
                p, s, cls = float(sc["p"][i]), float(sc["s"][i]), sc["cls"][i]
                st.last_score[(c.src, c.dst, c.dport)] = (ts, p, s)
                hits = st.sigs.check(c)
                for h in hits:
                    on_hit(h, p, s)
                if not hits and is_alert(False, p, s):
                    if p >= C.P_XGB_THRESHOLD:
                        cls_ = cls if cls != "Normal" else "DoS" if c.conn_state == "S0" else "Probe"
                        add_alert(ts, c.src, c.dst, c.dport, c.proto, f"ML: {CLASS_UZ.get(cls_, cls_)} ({cls_})", "ml",
                                  0.0, p, s, cls=cls_, mitre=CLASS_MITRE.get(cls_, ""))
                    else:
                        add_alert(ts, c.src, c.dst, c.dport, c.proto, "Anomaliya: noodatiy ulanish (Isolation Forest)",
                                  "anomaly", 0.0, p, s, detail={"port": c.dport, "service": c.service or c.proto})
                for ch in st.corr.on_conn(c, p, s, cls):
                    on_corr(ch)
            elif kind == 1:
                h = from_eve(eve[i])
                if h and h.src in blocked and blocked[h.src] <= h.ts:
                    dropped += 1          # IPS: bloklangan manbaning keyingi hujum urinishlari tarmoqqa yetib bormadi
                    buckets[int(ts // 60 * 60)][3] += 1
                    continue
                if h:
                    ls = st.last_score.get((h.src, h.dst, h.dport))
                    p, s = (ls[1], ls[2]) if ls and abs(ls[0] - h.ts) <= 30 else (0.0, 0.0)
                    on_hit(h, p, s)
            else:
                for ch in st.corr.on_host(host[i]):
                    on_corr(ch)

        # Saqlash: ogohlantirishlar → insidentlar → choralar
        alert_ids: dict[tuple, int] = {}
        for k, a in alerts.items():
            alert_ids[k] = self.store.save_alert(a, bid)
        n_inc = 0
        inc_ids = {}
        for key, e in ents.items():
            if e.level == "low" and not e.rules:
                continue
            ea = [alerts[k] for k in alerts if alerts[k]["entity"] == key]
            top = max(ea, key=lambda a: a["risk"]) if ea else None
            if e.rules:
                e.title = max(e.rules, key=lambda r: RULES[r][5])
                e.title = RULES[e.title][0]
            else:
                e.title = top["name"] if top else "Shubhali faollik"
            detail = {"alerts": sorted({a["name"] for a in ea}), "targets": sorted({d for a in ea for d in a["dsts"]})[:30],
                      "correlation": e.corr, "classes": dict(e.classes)}
            iid = self.store.save_incident({"entity": key, "first_ts": e.first_ts, "last_ts": e.last_ts, "title": e.title,
                                            "rules": e.rules, "mitre": sorted(e.mitre), "s_sig": e.s_sig, "p_xgb": e.p_xgb,
                                            "s_if": e.s_if, "s_akt": e.s_akt, "risk": e.risk, "level": e.level,
                                            "detail": detail, "detected_ts": e.detected_ts,
                                            "responded_ts": e.responded_ts}, bid)
            inc_ids[key] = iid
            n_inc += 1
            self.store.link_alerts([alert_ids[k] for k in alert_ids if alerts[k]["entity"] == key], iid)
            if e.level in ("medium",) and not e.actions:
                e.actions.append({"ts": e.detected_ts or e.first_ts, "action": "notify_soc", "target": key,
                                  "reason": f"Risk {e.risk:.2f} (o‘rta): hodisa kartasi yaratildi", "status": "done",
                                  "mode": resp.mode, "ttl_h": None})
            for d in e.actions:
                self.store.add_action(d["ts"], d["action"], d["target"], d["reason"], iid, d["status"], d["mode"],
                                      ttl_h=d["ttl_h"])
        self.store.add_traffic(buckets)

        lv = Counter(a["level"] for a in alerts.values())
        summary = {"levels": dict(lv), "modules": dict(Counter(a["module"] for a in alerts.values())),
                   "entities": {k: {"risk": e.risk, "level": e.level, "rules": e.rules, "title": e.title,
                                    "incident": inc_ids.get(k), "actions": [(a["action"], a["target"], a["status"])
                                                                            for a in e.actions],
                                    "mttd": round(e.detected_ts - e.first_ts, 1) if e.detected_ts else None,
                                    "mttr": round(e.responded_ts - e.detected_ts, 1) if e.responded_ts and e.detected_ts else None}
                                for k, e in ents.items() if e.level != "low" or e.rules},
                   "mode": resp.mode}
        if truth:
            summary["scenarios"] = self._evaluate(truth, ents)
        seconds = round(time.perf_counter() - t_start, 2)
        self.store.finish_batch(bid, n_conns=len(conns), n_eve=len(eve), n_host=len(host), n_alerts=len(alerts),
                                n_incidents=n_inc, dropped=dropped, seconds=seconds, summary=summary)
        return {"batch_id": bid, "conns": len(conns), "eve": len(eve), "host": len(host), "alerts": len(alerts),
                "incidents": n_inc, "dropped": dropped, "seconds": seconds, **summary}

    @staticmethod
    def _evaluate(truth: dict, ents: dict[str, Entity]) -> dict:
        out = {}
        for scen, src in truth.items():
            e = ents.get(src)
            out[scen] = {"source": src, "detected": bool(e and (e.level != "low" or e.rules)),
                         "level": e.level if e else "—", "risk": e.risk if e else 0.0, "rules": e.rules if e else [],
                         "actions": [(a["action"], a["target"], a["status"]) for a in e.actions] if e else [],
                         "mttd": round(e.detected_ts - e.first_ts, 1) if e and e.detected_ts else None}
        return out


def evaluate_nsl(store: Storage, det: Detector, df, name: str = "NSL-KDD") -> dict:
    """NSL-KDD faylini 41 xususiyatli modellar bilan baholash (yorliq bo‘lsa — metrikalar ham)."""
    import numpy as np
    from sklearn.metrics import confusion_matrix, f1_score

    from .features import ATTACK_CLASS, CLASSES
    t0 = time.perf_counter()
    bid = store.new_batch("nsl-kdd", name)
    sc = det.score_nsl(df)
    p, s = sc["p"], sc["s"]
    pred = ((p >= C.P_XGB_THRESHOLD) | (s >= C.S_IF_THRESHOLD)).astype(int)
    r = np.array([risk(0.0, a, b, C.DEFAULT_ASSET) for a, b in zip(p, s)])
    summary: dict = {"n": int(len(df)), "flagged": int(pred.sum()), "flagged_xgb": int((p >= 0.5).sum()),
                     "flagged_if_only": int(((s >= 0.5) & (p < 0.5)).sum()),
                     "classes_pred": dict(Counter(sc["cls"])),
                     "risk_levels": dict(Counter(level(x) for x in r))}
    if "label" in df.columns:
        y = (df["label"].astype(str) != "normal").astype(int).values
        yc = df["label"].astype(str).map(lambda v: "Normal" if v == "normal" else ATTACK_CLASS.get(v, "R2L")).values

        def mm(pr):
            tn, fp, fn, tp = confusion_matrix(y, pr, labels=[0, 1]).ravel()
            return {"accuracy": round((tp + tn) / len(y), 4), "precision": round(tp / max(tp + fp, 1), 4),
                    "recall": round(tp / max(tp + fn, 1), 4), "f1": round(f1_score(y, pr, zero_division=0), 4),
                    "fpr": round(fp / max(fp + tn, 1), 4), "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}

        summary["metrics"] = {"XGBoost": mm((p >= 0.5).astype(int)), "Isolation Forest": mm((s >= 0.5).astype(int)),
                              "Gibrid (XGBoost + IF)": mm(pred)}
        pc = np.array(sc["cls"])
        summary["by_class"] = {c: {"n": int((yc == c).sum()), "detected": int(pred[yc == c].sum()) if c != "Normal" else None,
                                   "type_correct": int((pc[yc == c] == c).sum())} for c in CLASSES if (yc == c).any()}
        summary["labels_top"] = Counter(df["label"].astype(str)).most_common(12)
    rows = []
    for i in np.argsort(-r)[:25]:
        rows.append({"i": int(i), "protocol": str(df.iloc[i]["protocol_type"]), "service": str(df.iloc[i]["service"]),
                     "flag": str(df.iloc[i]["flag"]), "src_bytes": int(df.iloc[i]["src_bytes"]),
                     "p": round(float(p[i]), 3), "s": round(float(s[i]), 3), "cls": sc["cls"][i], "risk": round(float(r[i]), 3),
                     "label": str(df.iloc[i]["label"]) if "label" in df.columns else ""})
    summary["top"] = rows
    seconds = round(time.perf_counter() - t0, 2)
    summary["ms_per_1000"] = round(seconds / max(len(df), 1) * 1e6, 1)
    store.finish_batch(bid, n_conns=len(df), n_alerts=int(pred.sum()), seconds=seconds, summary={"nsl": summary})
    return {"batch_id": bid, **summary}
