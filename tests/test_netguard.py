"""NetGuard avtomatik testlari:  python -m pytest -q"""
import io
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from netguard import config as C  # noqa: E402
from netguard.correlation import Correlator  # noqa: E402
from netguard.engine import Engine  # noqa: E402
from netguard.features import Conn, FeatureExtractor  # noqa: E402
from netguard.models import Detector  # noqa: E402
from netguard.parsers import merge_dns, parse, to_eve, to_host_events, to_zeek_dns, to_zeek_tsv  # noqa: E402
from netguard.risk import is_alert, level, risk  # noqa: E402
from netguard.signatures import Signatures, from_eve  # noqa: E402
from netguard.simulator import SCENARIOS, generate  # noqa: E402
from netguard.storage import Storage  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")


@pytest.fixture(scope="session")
def det():
    return Detector()


@pytest.fixture()
def store(tmp_path):
    return Storage(str(tmp_path / "t.db"))


# ---------------------------------------------------------------- formulalar (3.1), (3.2)
def test_risk_formula_and_levels():
    assert risk(1, 1, 1, 1) == 1.0
    assert risk(1.0, 0, 0, 0.3) == pytest.approx(0.43)
    assert risk(0.6, 0.9, 0.5, 1.0) == pytest.approx(0.24 + 0.27 + 0.1 + 0.1)
    assert level(0.8) == "high" and level(0.79) == "medium" and level(0.5) == "medium" and level(0.49) == "low"


def test_hybrid_rule():
    assert is_alert(True, 0, 0)
    assert is_alert(False, 0.5, 0)
    assert is_alert(False, 0.1, 0.6)
    assert not is_alert(False, 0.49, 0.49)


def test_segments():
    assert C.segment("10.0.10.15") == "user" and C.segment("10.0.1.10") == "server"
    assert C.is_internal("192.168.5.1") and not C.is_internal("8.8.8.8")


# ---------------------------------------------------------------- xususiyatlar va ML
def test_feature_extractor_time_window():
    fx = FeatureExtractor()
    f = None
    for i in range(30):
        f = fx.features(Conn(ts=100 + i * 0.01, src="1.2.3.4", sport=40000, dst="10.0.2.10", dport=i + 1, conn_state="REJ"))
    assert f["count"] == 30 and f["rerror_rate"] == 1.0 and f["dst_host_count"] == 30
    f = fx.features(Conn(ts=200, src="1.2.3.4", sport=40000, dst="10.0.2.10", dport=80))
    assert f["count"] == 1                                        # 2 soniyalik oyna tozalandi
    assert f["service"] == "http" and f["flag"] == "SF"


def test_models_detect_synflood_not_normal(det):
    b = generate(["synflood"], minutes=5, seed=3)
    fx = FeatureExtractor()
    rows = [fx.features(c) for c in b.conns]
    sc = det.score(rows)
    attack = [p for c, p in zip(b.conns, sc["p"]) if c.src == b.truth["synflood"]]
    normal = [p for c, p in zip(b.conns, sc["p"]) if c.src != b.truth["synflood"]]
    assert sum(p >= 0.5 for p in attack) / len(attack) > 0.95
    assert sum(p >= 0.5 for p in normal) / len(normal) < 0.02


def test_metrics_reproduce_diploma():
    with open(os.path.join(ROOT, "models", "metrics.json"), encoding="utf-8") as f:
        m = json.load(f)
    assert m["binary"]["XGBoost"]["f1"] == pytest.approx(0.788, abs=0.01)
    assert m["binary"]["Gibrid (XGBoost + IF)"]["f1"] == pytest.approx(0.848, abs=0.01)
    assert m["novel_detection"]["Gibrid (XGBoost + IF)"] > m["novel_detection"]["XGBoost"]


# ---------------------------------------------------------------- signaturalar va korrelyatsiya
def test_portscan_signature():
    s = Signatures()
    hits = []
    for i in range(60):
        hits += s.check(Conn(ts=i * 0.1, src="45.1.1.1", sport=5000, dst="10.0.2.10", dport=1000 + i, conn_state="REJ"))
    assert [h.sid for h in hits] == [1000010]                     # threshold: bir marta


def test_long_dns_and_ioc():
    s = Signatures({"evil.top": ("domain", "test")})
    q = "a" * 55 + ".x.evil.top"
    hits = s.check(Conn(ts=1, src="10.0.10.5", sport=5353, dst="10.0.0.53", dport=53, proto="udp", query=q))
    assert {h.sid for h in hits} == {1000013, 1000020}


def test_smb_between_workstations_only():
    s = Signatures()
    assert s.check(Conn(ts=1, src="10.0.10.5", sport=50000, dst="10.0.1.20", dport=445)) == []
    assert s.check(Conn(ts=2, src="10.0.10.5", sport=50001, dst="10.0.10.9", dport=445))[0].sid == 1000012


def test_eve_severity_mapping():
    h = from_eve({"ts": 1, "event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "10.0.2.10", "dest_port": 80,
                  "alert": {"signature": "ET WEB_SERVER SQL Injection", "category": "Web Application Attack", "severity": 1}})
    assert h.severity == 1.0 and h.mitre == "T1190"
    assert from_eve({"ts": 1, "event_type": "flow"}) is None


def test_bruteforce_then_success_rule():
    cr = Correlator()
    out = []
    for i in range(25):
        out += cr.on_host({"ts": i, "type": "auth", "result": "failure", "src": "6.6.6.6", "user": "admin"})
    out += cr.on_host({"ts": 30, "type": "auth", "result": "success", "src": "6.6.6.6", "user": "admin"})
    assert [o.rule for o in out] == ["R1"] and out[0].detail["account"] == "admin"


def test_beaconing_rule():
    cr = Correlator({"203.0.113.9"})
    out = []
    for i in range(10):
        out += cr.on_conn(Conn(ts=i * 60.0, src="10.0.10.7", sport=50000 + i, dst="203.0.113.9", dport=443, orig_bytes=200),
                          0.0, 0.0, "Normal")
    assert [o.rule for o in out] == ["R4"] and out[0].target == "203.0.113.9"


# ---------------------------------------------------------------- to‘liq quvur (3.10-jadval)
@pytest.fixture(scope="module")
def full_run(det, tmp_path_factory):
    st = Storage(str(tmp_path_factory.mktemp("db") / "full.db"))
    b = generate(None, minutes=10, seed=7)
    return st, b, Engine(st, det).process(b.conns, b.eve, b.host, "simulation", "test", truth=b.truth)


def test_all_scenarios_detected(full_run):
    _, _, r = full_run
    assert set(r["scenarios"]) == set(SCENARIOS)
    missed = [k for k, v in r["scenarios"].items() if not v["detected"]]
    assert missed == []


@pytest.mark.parametrize("scen,rule,action", [
    ("bruteforce", "R1", "block_ip"), ("lateral", "R3", "quarantine_host"), ("beaconing", "R4", "block_ip"),
    ("exfiltration", "R5", "rate_limit"), ("ransomware", "R6", "quarantine_host"), ("dnstunnel", "R7", "block_domain"),
    ("unknown", "R8", "notify_soc"), ("synflood", None, "block_ip")])
def test_expected_response(full_run, scen, rule, action):
    _, _, r = full_run
    s = r["scenarios"][scen]
    if rule:
        assert rule in s["rules"]
    assert action in [a[0] for a in s["actions"]]


def test_ips_drops_traffic_after_block(full_run):
    _, _, r = full_run
    assert r["dropped"] > 1000


def test_normal_traffic_no_incidents(det, store):
    b = generate([], minutes=20, seed=55)
    r = Engine(store, det).process(b.conns, b.eve, b.host, "simulation", "normal")
    assert r["incidents"] == 0


def test_ids_mode_only_simulates(det, store):
    store.set_setting("mode", "ids")
    b = generate(["synflood"], minutes=3, seed=4)
    r = Engine(store, det).process(b.conns, b.eve, b.host, "simulation", "ids", truth=b.truth)
    assert r["dropped"] == 0
    assert all(a["status"] == "simulated" for a in store.actions() if a["action"] == "block_ip")


def test_whitelist_prevents_block(det, store):
    store.add_whitelist("91.240.118.0/24", "test")
    b = generate(["synflood"], minutes=3, seed=4)
    Engine(store, det).process(b.conns, b.eve, b.host, "simulation", "wl", truth=b.truth)
    acts = [a for a in store.actions() if a["target"] == "91.240.118.172"]
    assert acts and all(a["status"] == "skipped" for a in acts)


def test_revoke_and_blocklist(det, store):
    b = generate(["synflood"], minutes=3, seed=4)
    Engine(store, det).process(b.conns, b.eve, b.host, "simulation", "rv")
    bl = store.blocklist()
    assert bl and bl[0]["timeout"] > 23 * 3600
    store.revoke(bl[0]["id"])
    assert store.blocklist() == []


# ---------------------------------------------------------------- parserlar
def test_parsers_roundtrip():
    b = generate(None, minutes=3, seed=9)
    assert len(parse(to_zeek_tsv(b.conns))["conns"]) == len(b.conns)
    assert parse(to_zeek_dns(b.conns))["kind"] == "zeek-dns"
    assert len(parse(to_eve(b.eve))["eve"]) == len(b.eve)
    assert len(parse(to_host_events(b.host))["host"]) == len(b.host)
    merged = merge_dns(parse(to_zeek_tsv(b.conns))["conns"] + parse(to_zeek_dns(b.conns))["conns"])
    assert len(merged) == len(b.conns) and any(c.query for c in merged)


def test_wazuh_and_zeek_json():
    with open(os.path.join(SAMPLES, "wazuh_alerts.json"), encoding="utf-8") as f:
        r = parse(f.read())
    assert r["kind"] == "wazuh" and r["host"][-1]["result"] == "success" and r["host"][0]["src"] == "185.220.101.47"
    z = json.dumps({"ts": 1700000000.5, "uid": "C1", "id.orig_h": "1.2.3.4", "id.orig_p": 1, "id.resp_h": "10.0.2.10",
                    "id.resp_p": 22, "proto": "tcp", "conn_state": "REJ"})
    assert parse(z)["conns"][0].flag == "REJ"


def test_suricata_flow_events():
    ev = {"timestamp": "2026-05-18T10:00:00.000000+0500", "event_type": "flow", "src_ip": "1.2.3.4", "src_port": 5,
          "dest_ip": "10.0.2.10", "dest_port": 80, "proto": "TCP", "app_proto": "http",
          "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 300, "bytes_toclient": 900,
                   "start": "2026-05-18T10:00:00.000000+0500", "end": "2026-05-18T10:00:01.500000+0500", "state": "closed"}}
    c = parse(json.dumps(ev))["conns"][0]
    assert c.duration == pytest.approx(1.5) and c.orig_bytes == 300


# ---------------------------------------------------------------- veb-konsol va API
@pytest.fixture()
def client(tmp_path):
    from app import create_app
    app = create_app(str(tmp_path / "web.db"))
    app.config["TESTING"] = True
    c = app.test_client()
    c.get("/")
    with c.session_transaction() as s:
        c.csrf = s["csrf"]
    return c


def test_pages(client):
    for u in ["/", "/alerts", "/incidents", "/response", "/assets", "/data", "/models", "/api", "/about"]:
        assert client.get(u).status_code == 200, u
    assert client.get("/incidents/999").status_code == 404


def test_csrf_required(client):
    assert client.post("/response/mode", data={"mode": "ids"}).status_code == 400


def test_simulation_flow(client):
    r = client.post("/data/simulate", data={"csrf": client.csrf, "normal": "1", "minutes": "5",
                                            "scenario": ["synflood", "lateral"]})
    assert r.status_code == 302
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "aniqlandi" in page
    for u in ["/", "/incidents", "/incidents/1", "/alerts/1", "/response"]:
        assert client.get(u).status_code == 200, u


def test_upload_samples(client):
    files = [(open(os.path.join(SAMPLES, n), "rb"), n) for n in
             ("hujumlar_conn.log", "hujumlar_dns.log", "hujumlar_eve.json", "wazuh_alerts.json")]
    r = client.post("/data/upload", data={"csrf": client.csrf, "files": files}, content_type="multipart/form-data")
    assert r.status_code == 302 and "/batches/" in r.headers["Location"]
    assert client.get(r.headers["Location"]).status_code == 200
    inc = client.get("/api/v1/incidents").get_json()["items"]
    assert any("R1" in i["rules"] for i in inc)


def test_upload_nsl(client):
    with open(os.path.join(SAMPLES, "nsl_kdd_test21_2000.txt"), "rb") as f:
        r = client.post("/data/upload", data={"csrf": client.csrf, "files": (io.BytesIO(f.read()), "t.txt")},
                        content_type="multipart/form-data")
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "Gibrid" in page and "F1" in page


def test_api_ingest_and_blocklist(client):
    b = generate(["synflood"], minutes=2, seed=5, normal=False)
    lines = [json.dumps({"ts": c.ts, "uid": c.uid, "id.orig_h": c.src, "id.orig_p": c.sport, "id.resp_h": c.dst,
                         "id.resp_p": c.dport, "proto": c.proto, "duration": c.duration, "orig_bytes": c.orig_bytes,
                         "resp_bytes": c.resp_bytes, "conn_state": c.conn_state}) for c in b.conns]
    r = client.post("/api/v1/ingest", data="\n".join(lines), content_type="application/x-ndjson")
    assert r.status_code == 200 and r.get_json()["incidents"] >= 1
    items = client.get("/api/v1/blocklist").get_json()["items"]
    assert any(i["ip"] == "91.240.118.172" for i in items)
    assert client.post("/api/v1/ingest", data="salom", content_type="text/plain").status_code == 400
    assert client.get("/api/v1/health").get_json()["status"] == "ok"
