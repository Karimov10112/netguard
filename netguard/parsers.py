"""Ma’lumot manbalarini o‘qish (1-qatlam): Zeek, Suricata, Wazuh va NSL-KDD formatlari.

Qo‘llab-quvvatlanadigan fayllar (format avtomatik aniqlanadi):
  * Zeek conn.log — TSV (#fields sarlavhasi bilan) yoki JSON-lines (LogAscii::use_json=T)
  * Zeek dns.log  — TSV yoki JSON-lines (DNS so‘rovlari 4-qoida va R7 uchun)
  * Suricata eve.json — `alert` (signatura moduli) va `flow` (ML moduli uchun ulanishlar) hodisalari
  * Wazuh alerts.json — autentifikatsiya (rule.groups: authentication_failed/success) va FIM (syscheck)
  * NetGuard host-events JSONL — {"ts","type":"auth"|"fim",...} (simulyator formati)
  * NSL-KDD — KDDTrain+.txt / KDDTest+.txt yoki 41 ustunli CSV (alohida baholash rejimi)
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime

import pandas as pd

from .features import NSL_ALL, NSL_COLUMNS, Conn

ZEEK_CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
                    "orig_bytes", "resp_bytes", "conn_state"]


class ParseError(ValueError):
    pass


def _num(v, default=0.0):
    if v in (None, "", "-", "(empty)"):
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _ts(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v)
    try:
        return float(s)
    except ValueError:
        pass
    s = s.replace("Z", "+00:00")
    if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":        # 2024-01-01T10:00:00.000+0500
        s = s[:-2] + ":" + s[-2:]
    return datetime.fromisoformat(s).timestamp()


def _conn_from(d: dict, query: str = "") -> Conn:
    return Conn(ts=_ts(d["ts"]), src=str(d["id.orig_h"]), sport=int(_num(d.get("id.orig_p"))), dst=str(d["id.resp_h"]),
                dport=int(_num(d.get("id.resp_p"))), proto=str(d.get("proto") or "tcp").lower(),
                service=str(d.get("service") or "").replace("-", ""), duration=_num(d.get("duration")),
                orig_bytes=int(_num(d.get("orig_bytes"))), resp_bytes=int(_num(d.get("resp_bytes"))),
                conn_state=str(d.get("conn_state") or "OTH").replace("-", "OTH"), uid=str(d.get("uid") or ""),
                query=query)


def _zeek_tsv(text: str) -> tuple[str, list[dict]]:
    fields, path, rows = None, "", []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#path"):
            path = line.split("\t", 1)[1].strip()
        elif line.startswith("#") or not line.strip():
            continue
        else:
            if fields is None:
                fields = ZEEK_CONN_FIELDS                    # sarlavhasiz conn.log (D-ilova formati)
            vals = line.split("\t")
            rows.append(dict(zip(fields, vals)))
    return path, rows


def parse(text: str, filename: str = "") -> dict:
    """Matn → {"kind": ..., "conns": [...], "eve": [...], "host": [...], "nsl": DataFrame|None}."""
    out = {"kind": "", "conns": [], "eve": [], "host": [], "nsl": None, "skipped": 0}
    head = text.lstrip()[:4000]
    if not head:
        raise ParseError("Fayl bo‘sh")

    # --- JSON-lines
    if head.startswith("{"):
        kinds = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                out["skipped"] += 1
                continue
            if "event_type" in d:                                       # Suricata EVE
                kinds.add("suricata")
                if d["event_type"] == "alert":
                    d = dict(d)
                    d["ts"] = _ts(d.get("timestamp", d.get("ts", 0)))
                    out["eve"].append(d)
                elif d["event_type"] == "flow" and "flow" in d:
                    f = d["flow"]
                    state = {"closed": "SF", "established": "SF", "new": "S0"}.get(f.get("state"), "OTH")
                    if f.get("reason") == "timeout" and f.get("state") == "new":
                        state = "S0"
                    if f.get("pkts_toclient", 1) == 0 and (d.get("proto") or "").upper() == "TCP":
                        state = "S0"
                    start, end = _ts(f.get("start", d.get("timestamp"))), _ts(f.get("end", f.get("start", d.get("timestamp"))))
                    out["conns"].append(Conn(ts=start, src=d.get("src_ip", ""), sport=int(d.get("src_port", 0) or 0),
                                             dst=d.get("dest_ip", ""), dport=int(d.get("dest_port", 0) or 0),
                                             proto=str(d.get("proto", "tcp")).lower(), service=str(d.get("app_proto", "") or ""),
                                             duration=max(0.0, end - start), orig_bytes=int(f.get("bytes_toserver", 0)),
                                             resp_bytes=int(f.get("bytes_toclient", 0)), conn_state=state,
                                             uid=str(d.get("flow_id", ""))))
                elif d["event_type"] == "dns" and d.get("dns", {}).get("type") == "query":
                    out["conns"].append(Conn(ts=_ts(d.get("timestamp")), src=d.get("src_ip", ""), sport=int(d.get("src_port", 0) or 0),
                                             dst=d.get("dest_ip", ""), dport=int(d.get("dest_port", 53) or 53), proto="udp",
                                             service="dns", query=str(d["dns"].get("rrname", "")), conn_state="SF"))
            elif "id.orig_h" in d:                                      # Zeek JSON
                if "query" in d and "conn_state" not in d:
                    kinds.add("zeek-dns")
                    out["conns"].append(_conn_from({**d, "service": "dns", "conn_state": "SF"}, str(d.get("query") or "")))
                else:
                    kinds.add("zeek-conn")
                    out["conns"].append(_conn_from(d))
            elif "rule" in d and ("agent" in d or "syscheck" in d):     # Wazuh alerts.json
                kinds.add("wazuh")
                ev = _wazuh(d)
                if ev:
                    out["host"].append(ev)
            elif d.get("type") in ("auth", "fim") and "ts" in d:        # NetGuard host-events
                kinds.add("host-events")
                d = dict(d)
                d["ts"] = _ts(d["ts"])
                out["host"].append(d)
            else:
                out["skipped"] += 1
        if not kinds:
            raise ParseError("JSON yozuvlari tanilmadi (Zeek, Suricata EVE yoki Wazuh formatida bo‘lishi kerak)")
        out["kind"] = "+".join(sorted(kinds))
        return out

    # --- Zeek TSV
    if head.startswith("#separator") or head.startswith("#fields") or "\tS0\t" in head or "\tSF\t" in head:
        path, rows = _zeek_tsv(text)
        for r in rows:
            try:
                if "query" in r and "conn_state" not in r:
                    out["conns"].append(_conn_from({**r, "service": "dns", "conn_state": "SF", "proto": r.get("proto", "udp")},
                                                   "" if r.get("query") in ("-", None) else r["query"]))
                else:
                    out["conns"].append(_conn_from(r))
            except (KeyError, ValueError):
                out["skipped"] += 1
        out["kind"] = "zeek-" + (path or ("dns" if rows and "query" in rows[0] else "conn"))
        if not out["conns"]:
            raise ParseError("Zeek jurnalida yozuv topilmadi")
        return out

    # --- NSL-KDD
    first = next(csv.reader(io.StringIO(head.splitlines()[0])))
    if len(first) in (41, 42, 43) or set(NSL_COLUMNS[:5]) <= set(first):
        has_header = "duration" in first
        df = pd.read_csv(io.StringIO(text), header=0 if has_header else None)
        if not has_header:
            df.columns = NSL_ALL[:df.shape[1]] if df.shape[1] <= 43 else df.columns
        missing = [c for c in NSL_COLUMNS if c not in df.columns]
        if missing:
            raise ParseError(f"NSL-KDD ustunlari yetishmaydi: {', '.join(missing[:5])}")
        out["nsl"], out["kind"] = df, "nsl-kdd"
        return out
    raise ParseError("Fayl formati aniqlanmadi. Zeek conn.log/dns.log, Suricata eve.json, Wazuh alerts.json yoki NSL-KDD yuklang.")


def _wazuh(d: dict) -> dict | None:
    groups = set(d.get("rule", {}).get("groups", []))
    ts = _ts(d.get("timestamp", 0))
    data = d.get("data", {}) or {}
    host = (d.get("agent") or {}).get("ip") or (d.get("agent") or {}).get("name", "")
    if groups & {"authentication_failed", "authentication_failures", "win_authentication_failed"}:
        return {"ts": ts, "type": "auth", "result": "failure", "user": data.get("dstuser") or data.get("srcuser", ""),
                "src": data.get("srcip", ""), "host": host, "proto": d.get("decoder", {}).get("name", "")}
    if groups & {"authentication_success"}:
        return {"ts": ts, "type": "auth", "result": "success", "user": data.get("dstuser") or data.get("srcuser", ""),
                "src": data.get("srcip", ""), "host": host, "proto": d.get("decoder", {}).get("name", "")}
    if "syscheck" in groups or "syscheck" in d:
        sc = d.get("syscheck", {})
        if sc.get("event") in ("modified", "added", "deleted"):
            return {"ts": ts, "type": "fim", "host": host, "path": sc.get("path", ""), "action": sc.get("event"),
                    "src": (sc.get("audit", {}) or {}).get("remote_ip", "") or data.get("srcip", ""),
                    "user": (sc.get("audit", {}) or {}).get("user", {}).get("name", "")}
    return None


# ---------------------------------------------------------------------- eksport (namunaviy fayllar)
def to_zeek_tsv(conns: list[Conn]) -> str:
    lines = ["#separator \\x09", "#path\tconn", "#fields\t" + "\t".join(ZEEK_CONN_FIELDS),
             "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring"]
    for c in conns:
        lines.append("\t".join(map(str, [f"{c.ts:.6f}", c.uid, c.src, c.sport, c.dst, c.dport, c.proto, c.service or "-",
                                         f"{c.duration:.6f}", c.orig_bytes, c.resp_bytes, c.conn_state])))
    return "\n".join(lines) + "\n"


def to_zeek_dns(conns: list[Conn]) -> str:
    f = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query"]
    lines = ["#separator \\x09", "#path\tdns", "#fields\t" + "\t".join(f)]
    for c in conns:
        if c.query:
            lines.append("\t".join(map(str, [f"{c.ts:.6f}", c.uid, c.src, c.sport, c.dst, c.dport, c.proto, c.query])))
    return "\n".join(lines) + "\n"


def to_eve(events: list[dict]) -> str:
    out = []
    for e in events:
        d = {k: v for k, v in e.items() if k != "ts"}
        d["timestamp"] = datetime.fromtimestamp(e["ts"]).astimezone().isoformat(timespec="microseconds")
        out.append(json.dumps(d, ensure_ascii=False))
    return "\n".join(out) + "\n"


def to_host_events(events: list[dict]) -> str:
    return "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n"


def merge_dns(conns: list[Conn]) -> list[Conn]:
    """conn.log va dns.log birga yuklanganda: bir xil uid li DNS yozuvining so‘rovini ulanishga qo‘shib, takrorini olib tashlaydi."""
    by_uid = {c.uid: c for c in conns if c.uid and not c.query}
    out = []
    for c in conns:
        if c.query and c.uid in by_uid:
            if not by_uid[c.uid].query:
                by_uid[c.uid].query = c.query
            continue
        out.append(c)
    return out
