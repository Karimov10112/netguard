"""Isolation Forest «normal profili»ni o‘qitish (diplom, 3.4-band).

Ishlatish:
    python train/train_profile.py                       # simulyatsiya qilingan normal trafik (namoyish uchun)
    python train/train_profile.py --conn conn.log       # korxonaning hujumsiz deb tekshirilgan Zeek conn.log fayli
    python train/train_profile.py --reset               # profilni o‘chirish (NSL-KDD standart IF)
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from netguard.features import FeatureExtractor  # noqa: E402
from netguard.models import Detector  # noqa: E402
from netguard.parsers import parse  # noqa: E402
from netguard.simulator import generate  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", nargs="*", default=[])
    ap.add_argument("--minutes", type=int, default=60)
    ap.add_argument("--contamination", type=float, default=0.01)
    ap.add_argument("--reset", action="store_true")
    a = ap.parse_args()
    det = Detector()
    if a.reset:
        det.reset_profile()
        sys.exit("Profil o‘chirildi")
    if a.conn:
        conns = []
        for p in a.conn:
            with open(p, encoding="utf-8", errors="replace") as f:
                conns += parse(f.read())["conns"]
        source = "Zeek: " + ", ".join(os.path.basename(p) for p in a.conn)
    else:
        conns = generate([], minutes=a.minutes, seed=101).conns
        source = f"Simulyatsiya qilingan normal trafik ({a.minutes} daq)"
    fx = FeatureExtractor()
    rows = [fx.features(c) for c in sorted(conns, key=lambda c: c.ts)]
    p = det.train_profile(rows, a.contamination, source)
    print(f"Normal profil o‘qitildi: {p['n']} ulanish, contamination={p['contamination']} → models/profile.joblib")
