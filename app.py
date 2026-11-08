"""NetGuard — korxona tarmog‘ida kiberhujumlarni aniqlash va oldini olish tizimi: SOC veb-konsoli (Flask).

Ishga tushirish:
    pip install -r requirements.txt
    python app.py                       # http://127.0.0.1:5000

Muhit o‘zgaruvchilari (ixtiyoriy):
    NETGUARD_API_KEY   — REST API kaliti (X-API-Key sarlavhasi); berilmasa API ochiq (faqat laboratoriya uchun!)
    NETGUARD_DB        — SQLite fayl yo‘li (standart: instance/netguard.db)
    NETGUARD_MODE      — boshlang‘ich rejim: ips (faol himoya) yoki ids (faqat monitoring)
    NETGUARD_SECRET    — sessiya kaliti
    PORT               — port (standart 5000)
"""
from __future__ import annotations

import json
import os
import secrets
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlsplit

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for

from netguard import __version__
from netguard import config as C
from netguard.correlation import RULES
from netguard.engine import Engine, evaluate_nsl
from netguard.features import CLASS_UZ, FeatureExtractor
from netguard.models import Detector
from netguard.parsers import ParseError, merge_dns, parse, to_eve, to_host_events, to_zeek_dns, to_zeek_tsv
from netguard.response import commands, undo_commands
from netguard.risk import LEVEL_ACTION_UZ, LEVEL_UZ, explain
from netguard.signatures import MITRE, TACTIC_UZ
from netguard.simulator import SCENARIOS, generate
from netguard.storage import ACTION_UZ, INC_STATUS_UZ, STATUS_UZ, Storage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
MODULE_UZ = {"sig": "Signatura", "suricata": "Suricata", "ml": "ML (XGBoost)", "anomaly": "Anomaliya (IF)",
             "corr": "SIEM korrelyatsiyasi"}


def load_metrics() -> dict | None:
    p = os.path.join(MODELS_DIR, "metrics.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return None


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get("NETGUARD_SECRET") or secrets.token_hex(16),
                      MAX_CONTENT_LENGTH=200 * 1024 * 1024)
    app.json.ensure_ascii = False
    store = Storage(db_path or os.environ.get("NETGUARD_DB") or os.path.join(BASE_DIR, "instance", "netguard.db"))
    det = Detector(MODELS_DIR)
    engine = Engine(store, det)
    app.extensions.update(store=store, engine=engine, detector=det)
    api_key = os.environ.get("NETGUARD_API_KEY")
    metrics = load_metrics()

    @app.after_request
    def add_api_cors(response):
        """Allow the separately served frontend to call the backend API."""
        if request.path.startswith("/api/"):
            allowed_origin = os.environ.get("NETGUARD_FRONTEND_ORIGIN", "")
            origin = request.headers.get("Origin", "")
            if not allowed_origin and origin:
                parsed_origin = urlsplit(origin)
                if parsed_origin.scheme in {"http", "https"} and parsed_origin.hostname in {
                    "127.0.0.1",
                    "localhost",
                }:
                    allowed_origin = origin
            if allowed_origin:
                response.headers["Access-Control-Allow-Origin"] = allowed_origin
                response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    # ------------------------------------------------------------------ yordamchilar
    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf"], "version": __version__, "mode": store.mode, "LEVEL_UZ": LEVEL_UZ,
                "ACTION_UZ": ACTION_UZ, "STATUS_UZ": STATUS_UZ, "INC_STATUS_UZ": INC_STATUS_UZ, "MODULE_UZ": MODULE_UZ,
                "MITRE": MITRE, "TACTIC_UZ": TACTIC_UZ, "RULES": RULES, "C": C, "CLASS_UZ": CLASS_UZ,
                "LEVEL_ACTION_UZ": LEVEL_ACTION_UZ, "open_badge": store.open_counts()}

    def check_csrf():
        if request.form.get("csrf") != session.get("csrf"):
            abort(400, "CSRF tekshiruvi muvaffaqiyatsiz — sahifani yangilab, qayta urinib ko‘ring")

    def require_api_key(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if api_key and request.headers.get("X-API-Key") != api_key:
                return jsonify({"error": "unauthorized", "message": "X-API-Key noto‘g‘ri yoki berilmagan"}), 401
            return fn(*a, **kw)
        return wrapper

    @app.template_filter("t")
    def fmt_t(v, full=True):
        if not v:
            return "—"
        return datetime.fromtimestamp(float(v)).strftime("%Y-%m-%d %H:%M:%S" if full else "%H:%M:%S")

    @app.template_filter("ts")
    def fmt_short(v):
        return datetime.fromtimestamp(float(v)).strftime("%d.%m %H:%M:%S") if v else "—"

    @app.template_filter("hm")
    def fmt_hm(v):
        return datetime.fromtimestamp(float(v)).strftime("%H:%M") if v else ""

    @app.template_filter("pct")
    def pct(v):
        return f"{float(v or 0) * 100:.1f}%"

    @app.template_filter("f2")
    def f2(v):
        return f"{float(v or 0):.2f}"

    @app.template_filter("size")
    def size(v):
        v = float(v or 0)
        for u in ("B", "KB", "MB", "GB", "TB"):
            if v < 1024:
                return f"{v:.0f} {u}" if u == "B" else f"{v:.1f} {u}"
            v /= 1024
        return f"{v:.1f} PB"

    @app.template_filter("dur")
    def dur(v):
        if v is None:
            return "—"
        v = float(v)
        if v < 60:
            return f"{v:.0f} s"
        if v < 3600:
            return f"{v / 60:.1f} daq"
        return f"{v / 3600:.1f} soat"

    @app.template_filter("seg")
    def seg(ip):
        return C.SEGMENT_UZ.get(C.segment(ip), "") if C.ip(ip) else ""

    @app.template_filter("num")
    def num(v):
        return f"{int(v or 0):,}".replace(",", " ")

    # ------------------------------------------------------------------ boshqaruv paneli
    @app.route("/")
    def dashboard():
        s = store.stats()
        incs = [i for i in store.incidents(limit=50) if i["status"] in ("open", "investigating")][:8]
        last = store.traffic(0)
        traffic = last[-90:]
        tactics: dict[str, int] = {}
        for m in s["mitre"]:
            t = MITRE.get(m["mitre"], ("", "Boshqa"))[1] or "Boshqa"
            tactics[t] = tactics.get(t, 0) + m["n"]
        return render_template("dashboard.html", s=s, incs=incs, traffic=traffic, tactics=tactics,
                               batches=store.batches(5), assets={a["ip"]: a for a in store.assets()},
                               profile=det.info()["profile"])

    # ------------------------------------------------------------------ ogohlantirishlar
    @app.route("/alerts")
    def alerts():
        lv, q, src = request.args.get("level", ""), request.args.get("q", "").strip(), request.args.get("src", "").strip()
        page = max(int(request.args.get("page", 1) or 1), 1)
        rows = store.alerts(level=lv, src=src, q=q, limit=101, offset=(page - 1) * 100)
        return render_template("alerts.html", rows=rows[:100], more=len(rows) > 100, page=page, level=lv, q=q, src=src)

    @app.route("/alerts/<int:aid>")
    def alert(aid):
        a = store.alert(aid)
        if not a:
            abort(404, "Ogohlantirish topilmadi")
        inc = store.incident(a["incident_id"]) if a["incident_id"] else None
        return render_template("alert.html", a=a, inc=inc, parts=explain(a["s_sig"], a["p_xgb"], a["s_if"], a["s_akt"]))

    # ------------------------------------------------------------------ insidentlar
    @app.route("/incidents")
    def incidents():
        st, lv = request.args.get("status", ""), request.args.get("level", "")
        return render_template("incidents.html", rows=store.incidents(status=st, level=lv), status=st, level=lv)

    @app.route("/incidents/<int:iid>")
    def incident(iid):
        inc = store.incident(iid)
        if not inc:
            abort(404, "Insident topilmadi")
        acts = store.actions(incident_id=iid)
        for a in acts:
            a["cmds"] = commands(a["action"], a["target"]) if a["status"] in ("active", "simulated") else []
        return render_template("incident.html", inc=inc, alerts=store.alerts(incident_id=iid, limit=200), acts=acts,
                               parts=explain(inc["s_sig"], inc["p_xgb"], inc["s_if"], inc["s_akt"]),
                               forced=max((RULES[r][5] for r in inc["rules"] if r in RULES), default=None),
                               assets={a["ip"]: a for a in store.assets()})

    @app.post("/incidents/<int:iid>/update")
    def incident_update(iid):
        check_csrf()
        store.update_incident(iid, request.form.get("status"), request.form.get("assignee"), request.form.get("notes"))
        flash("Insident yangilandi", "ok")
        return redirect(url_for("incident", iid=iid))

    @app.post("/incidents/<int:iid>/respond")
    def incident_respond(iid):
        check_csrf()
        inc = store.incident(iid)
        if not inc:
            abort(404)
        action = request.form.get("action", "")
        target = request.form.get("target", "").strip() or inc["entity"]
        if action not in ACTION_UZ or action == "unblock":
            abort(400, "Noma’lum chora")
        manual(action, target, f"Tahlilchi qarori (insident #{iid})", iid)
        return redirect(url_for("incident", iid=iid))

    def manual(action: str, target: str, reason: str, iid: int | None = None):
        from netguard.response import TTL, Responder
        r = Responder(store)
        if action in ("block_ip", "quarantine_host", "rate_limit"):
            if not C.ip(target):
                flash("IP manzil noto‘g‘ri", "error")
                return
            if r.whitelisted(target):
                flash(f"{target} oq ro‘yxatda — avval oq ro‘yxatdan chiqaring", "error")
                return
        if store.is_active(action, target):
            flash(f"{ACTION_UZ[action]}: {target} allaqachon faol", "error")
            return
        status = "done" if action == "notify_soc" else ("active" if store.mode == "ips" else "simulated")
        store.add_action(time.time(), action, target, reason, iid, status, store.mode, actor="analyst", ttl_h=TTL.get(action))
        flash(f"{ACTION_UZ[action]}: {target} — {STATUS_UZ[status].lower()}", "ok")

    # ------------------------------------------------------------------ javob va bloklash
    @app.route("/response")
    def response():
        acts = store.actions(limit=400)
        active = [a for a in acts if a["status"] in ("active", "simulated")]
        for a in active:
            a["cmds"] = commands(a["action"], a["target"])
            a["undo"] = undo_commands(a["action"], a["target"])
        return render_template("response.html", acts=acts, active=active, white=store.whitelist(),
                               blocklist=store.blocklist())

    @app.post("/response/mode")
    def response_mode():
        check_csrf()
        m = request.form.get("mode")
        if m in ("ips", "ids"):
            store.set_setting("mode", m)
            flash("Rejim o‘zgartirildi: " + ("IPS — faol himoya (choralar avtomatik qo‘llanadi)" if m == "ips"
                                             else "IDS — faqat monitoring (choralar tavsiya sifatida yoziladi)"), "ok")
        return redirect(request.referrer or url_for("response"))

    @app.post("/response/revoke/<int:aid>")
    def response_revoke(aid):
        check_csrf()
        a = store.revoke(aid, "analyst")
        flash(f"Bekor qilindi: {ACTION_UZ.get(a['action'], a['action'])} — {a['target']}" if a else "Chora topilmadi yoki faol emas",
              "ok" if a else "error")
        return redirect(request.referrer or url_for("response"))

    @app.post("/response/manual")
    def response_manual():
        check_csrf()
        action = request.form.get("action", "")
        if action not in ACTION_UZ or action == "unblock":
            abort(400)
        manual(action, request.form.get("target", "").strip(), request.form.get("reason", "").strip() or "Qo‘lda kiritilgan")
        return redirect(url_for("response"))

    @app.post("/whitelist/add")
    def whitelist_add():
        check_csrf()
        try:
            store.add_whitelist(request.form.get("cidr", ""), request.form.get("note", "").strip())
            flash("Oq ro‘yxatga qo‘shildi", "ok")
        except ValueError:
            flash("Tarmoq manzili noto‘g‘ri (masalan, 10.0.1.0/24 yoki 192.168.10.5/32)", "error")
        return redirect(url_for("response") + "#whitelist")

    @app.post("/whitelist/delete")
    def whitelist_delete():
        check_csrf()
        store.delete_whitelist(request.form.get("cidr", ""))
        flash("Oq ro‘yxatdan o‘chirildi", "ok")
        return redirect(url_for("response") + "#whitelist")

    # ------------------------------------------------------------------ aktivlar va IoC
    @app.route("/assets")
    def assets():
        return render_template("assets.html", assets=store.assets(), ioc=store.ioc(), segments=C.SEGMENTS)

    @app.post("/assets/save")
    def assets_save():
        check_csrf()
        try:
            crit = float(request.form.get("criticality", "0.3").replace(",", "."))
            store.upsert_asset(request.form.get("ip", "").strip(), request.form.get("name", "").strip(),
                               request.form.get("role", "").strip(), crit)
            flash("Aktiv saqlandi", "ok")
        except ValueError:
            flash("IP manzil yoki muhimlik qiymati noto‘g‘ri", "error")
        return redirect(url_for("assets"))

    @app.post("/assets/delete")
    def assets_delete():
        check_csrf()
        store.delete_asset(request.form.get("ip", ""))
        flash("Aktiv o‘chirildi", "ok")
        return redirect(url_for("assets"))

    @app.post("/ioc/add")
    def ioc_add():
        check_csrf()
        try:
            t = store.add_ioc(request.form.get("value", ""), request.form.get("note", "").strip() or "IoC")
            engine.reset_live()
            flash(f"IoC qo‘shildi ({t})", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("assets") + "#ioc")

    @app.post("/ioc/delete")
    def ioc_delete():
        check_csrf()
        store.delete_ioc(request.form.get("value", ""))
        engine.reset_live()
        flash("IoC o‘chirildi", "ok")
        return redirect(url_for("assets") + "#ioc")

    # ------------------------------------------------------------------ ma’lumot yuklash va simulyatsiya
    @app.route("/data")
    def data():
        samples = sorted(f for f in os.listdir(SAMPLES_DIR) if not f.startswith(".")) if os.path.isdir(SAMPLES_DIR) else []
        return render_template("data.html", scenarios=SCENARIOS, batches=store.batches(30), samples=samples,
                               profile=det.info()["profile"])

    @app.post("/data/upload")
    def data_upload():
        check_csrf()
        files = [f for f in request.files.getlist("files") if f and f.filename]
        if not files:
            flash("Fayl tanlanmagan", "error")
            return redirect(url_for("data"))
        conns, eve, host, kinds, nsl = [], [], [], [], None
        for f in files:
            raw = f.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
            try:
                r = parse(text, f.filename)
            except ParseError as e:
                flash(f"{f.filename}: {e}", "error")
                return redirect(url_for("data"))
            kinds.append(f"{f.filename} ({r['kind']})")
            if r["nsl"] is not None:
                nsl = (r["nsl"], f.filename)
            conns += r["conns"]
            eve += r["eve"]
            host += r["host"]
        if nsl is not None:
            res = evaluate_nsl(store, det, nsl[0], nsl[1])
            flash(f"NSL-KDD baholandi: {res['n']} yozuv", "ok")
            return redirect(url_for("batch", bid=res["batch_id"]))
        conns = merge_dns(conns)
        if request.form.get("as_profile"):
            return train_profile(conns, "Yuklangan fayl: " + ", ".join(kinds))
        res = engine.process(conns, eve, host, source="upload", name=", ".join(kinds), fresh=True)
        flash(f"Tahlil qilindi: {res['conns']} ulanish, {res['eve']} Suricata, {res['host']} xost hodisasi → "
              f"{res['alerts']} ogohlantirish, {res['incidents']} insident", "ok")
        return redirect(url_for("batch", bid=res["batch_id"]))

    @app.post("/data/simulate")
    def data_simulate():
        check_csrf()
        chosen = [k for k in request.form.getlist("scenario") if k in SCENARIOS]
        minutes = min(max(int(request.form.get("minutes", 10) or 10), 2), 60)
        seed = int(request.form.get("seed", 7) or 7)
        b = generate(chosen, minutes=minutes, seed=seed, normal=bool(request.form.get("normal")))
        name = f"Simulyatsiya: {minutes} daq normal trafik" if request.form.get("normal") else "Simulyatsiya"
        name += (" + " + ", ".join(SCENARIOS[k][0] for k in chosen)) if chosen else ""
        res = engine.process(b.conns, b.eve, b.host, source="simulation", name=name, fresh=True, truth=b.truth)
        flash(f"Simulyatsiya tahlil qilindi: {res['conns']} ulanish → {res['alerts']} ogohlantirish, {res['incidents']} insident", "ok")
        return redirect(url_for("batch", bid=res["batch_id"]))

    def train_profile(conns, source: str):
        if len(conns) < 500:
            flash("Normal profil uchun kamida 500 ta ulanish kerak", "error")
            return redirect(url_for("data"))
        fx = FeatureExtractor()
        cont = float(request.form.get("contamination", 0.01) or 0.01)
        p = det.train_profile([fx.features(c) for c in sorted(conns, key=lambda c: c.ts)], min(max(cont, 0.001), 0.1), source)
        flash(f"Normal profil o‘qitildi: {p['n']} ulanish, contamination = {p['contamination']}", "ok")
        return redirect(url_for("data") + "#profile")

    @app.post("/data/profile")
    def data_profile():
        check_csrf()
        if request.form.get("reset"):
            det.reset_profile()
            flash("Normal profil o‘chirildi — NSL-KDD normal trafigidagi Isolation Forest ishlatiladi", "ok")
            return redirect(url_for("data") + "#profile")
        minutes = min(max(int(request.form.get("minutes", 60) or 60), 10), 240)
        b = generate([], minutes=minutes, seed=101)
        return train_profile(b.conns, f"Simulyatsiya qilingan normal trafik ({minutes} daq)")

    @app.post("/data/reset")
    def data_reset():
        check_csrf()
        store.reset()
        engine.reset_live()
        flash("Hodisalar, insidentlar va choralar tozalandi (aktivlar, oq ro‘yxat va IoC saqlandi)", "ok")
        return redirect(url_for("dashboard"))

    @app.route("/data/sample/<path:name>")
    def data_sample(name):
        path = os.path.join(SAMPLES_DIR, os.path.basename(name))
        if not os.path.isfile(path):
            abort(404)
        with open(path, "rb") as f:
            return Response(f.read(), mimetype="text/plain; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename={os.path.basename(name)}"})

    @app.route("/data/export/<kind>")
    def data_export(kind):
        """Simulyatsiya trafigini real vositalar formatida yuklab olish (Zeek / Suricata / Wazuh)."""
        b = generate(None, minutes=10, seed=int(request.args.get("seed", 7)))
        body, fn = {"conn": (to_zeek_tsv(b.conns), "conn.log"), "dns": (to_zeek_dns(b.conns), "dns.log"),
                    "eve": (to_eve(b.eve), "eve.json"), "host": (to_host_events(b.host), "host_events.jsonl")}.get(kind, (None, None))
        if body is None:
            abort(404)
        return Response(body, mimetype="text/plain; charset=utf-8", headers={"Content-Disposition": f"attachment; filename={fn}"})

    @app.route("/batches/<int:bid>")
    def batch(bid):
        b = store.batch(bid)
        if not b:
            abort(404, "Tahlil topilmadi")
        return render_template("batch.html", b=b, scenarios=SCENARIOS)

    # ------------------------------------------------------------------ modellar
    @app.route("/models")
    def models():
        return render_template("models.html", m=metrics, info=det.info())

    # ------------------------------------------------------------------ REST API
    @app.route("/api")
    def api_docs():
        return render_template("api.html", api_key_set=bool(api_key))

    @app.get("/api/v1/health")
    def api_health():
        return jsonify({"status": "ok", "version": __version__, "mode": store.mode, "models": det.info()})

    @app.route("/api/v1/<path:_resource>", methods=["OPTIONS"])
    def api_options(_resource):
        return ("", 204)

    @app.post("/api/v1/ingest")
    @require_api_key
    def api_ingest():
        """Real vaqt rejimi: Zeek / Suricata / Wazuh yozuvlari (JSON-lines yoki {"events": [...]})."""
        if request.is_json:
            body = request.get_json(silent=True) or {}
            events = body.get("events", body if isinstance(body, list) else [])
            text = "\n".join(json.dumps(e) for e in events)
        else:
            text = request.get_data(as_text=True)
        if not text.strip():
            return jsonify({"error": "empty", "message": "Yozuvlar yo‘q"}), 400
        try:
            r = parse(text)
        except ParseError as e:
            return jsonify({"error": "parse", "message": str(e)}), 400
        if r["nsl"] is not None:
            return jsonify({"error": "format", "message": "NSL-KDD fayllarini veb-konsol orqali yuklang"}), 400
        res = engine.process(merge_dns(r["conns"]), r["eve"], r["host"], source="api", name=f"API ({r['kind']})", fresh=False)
        return jsonify({k: res[k] for k in ("batch_id", "conns", "eve", "host", "alerts", "incidents", "dropped", "levels", "mode")})

    @app.post("/api/v1/simulate")
    @require_api_key
    def api_simulate():
        body = request.get_json(silent=True) or {}
        try:
            minutes = min(max(int(body.get("minutes", 10) or 10), 2), 60)
            seed = int(body.get("seed", 7) or 7)
        except (TypeError, ValueError):
            return jsonify({"error": "invalid_input", "message": "minutes va seed son bo‘lishi kerak"}), 400
        b = generate(list(SCENARIOS), minutes=minutes, seed=seed, normal=True)
        name = f"Simulyatsiya: {minutes} daq normal trafik + barcha sinov hujumlari"
        res = engine.process(b.conns, b.eve, b.host, source="simulation", name=name, fresh=True, truth=b.truth)
        return jsonify({k: res[k] for k in ("batch_id", "conns", "eve", "host", "alerts", "incidents", "dropped", "levels", "mode")})

    @app.get("/api/v1/blocklist")
    @require_api_key
    def api_blocklist():
        return jsonify({"mode": store.mode, "generated": time.time(), "items": store.blocklist()})

    @app.get("/api/v1/alerts")
    @require_api_key
    def api_alerts():
        lv = request.args.get("level", "")
        return jsonify({"items": store.alerts(level=lv, limit=min(int(request.args.get("limit", 100)), 1000))})

    @app.get("/api/v1/incidents")
    @require_api_key
    def api_incidents():
        return jsonify({"items": store.incidents(status=request.args.get("status", ""))})

    @app.get("/api/v1/incidents/<int:iid>")
    @require_api_key
    def api_incident(iid):
        inc = store.incident(iid)
        if not inc:
            return jsonify({"error": "not_found"}), 404
        return jsonify({**inc, "alerts": store.alerts(incident_id=iid), "actions": store.actions(incident_id=iid)})

    @app.post("/api/v1/actions/<int:aid>/revoke")
    @require_api_key
    def api_revoke(aid):
        a = store.revoke(aid, "api")
        return (jsonify({"revoked": a["id"]}), 200) if a else (jsonify({"error": "not_active"}), 404)

    @app.get("/api/v1/stats")
    @require_api_key
    def api_stats():
        return jsonify(store.stats())

    # ------------------------------------------------------------------ boshqa
    @app.route("/about")
    def about():
        return render_template("about.html", m=metrics)

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def err(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": e.name, "message": getattr(e, "description", "")}), e.code
        return render_template("error.html", e=e), e.code

    return app


if __name__ == "__main__":
    create_app().run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
