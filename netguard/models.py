"""ML modullarini yuklash va baholash: XGBoost (P_XGB), Isolation Forest (S_IF), besh sinfli XGBoost (hujum turi).

Ikki to‘plam ishlatiladi (train/train_models.py):
  zeek.joblib   — Zeek conn.log / Suricata flow / simulyatordan hisoblanadigan 26 xususiyat (asosiy + vaqt + xost);
  full41.joblib — NSL-KDD formatidagi to‘liq 41 xususiyat (yuklangan NSL-KDD fayllarini baholash uchun).
Korxona o‘z normal trafigida Isolation Forest’ni qayta o‘qitishi mumkin («normal profil», 3.4-band) —
natija models/profile.joblib ga yoziladi va zeek-modelining IF qismini almashtiradi.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import CLASSES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.environ.get("NETGUARD_MODELS", os.path.join(ROOT, "models"))


def _sif(iso, cal, X) -> np.ndarray:
    a = -iso.score_samples(X)
    return 1.0 / (1.0 + np.exp(-(a - cal["threshold"]) / cal["scale"]))


def calibrate(iso, X) -> dict:
    a = -iso.score_samples(X)
    return {"threshold": float(-iso.offset_), "scale": float(np.std(a) * 0.5) or 0.05}


class Detector:
    def __init__(self, models_dir: str = MODELS_DIR):
        self.dir = models_dir
        self._lock = threading.Lock()
        self.zeek = joblib.load(os.path.join(models_dir, "zeek.joblib"))
        self._full = None
        self.profile = None
        pp = os.path.join(models_dir, "profile.joblib")
        if os.path.exists(pp):
            self.profile = joblib.load(pp)

    @property
    def full(self):
        if self._full is None:
            self._full = joblib.load(os.path.join(self.dir, "full41.joblib"))
        return self._full

    def info(self) -> dict:
        z = self.zeek
        return {"zeek_trained": z.get("trained_at"), "features": len(z["features"]),
                "profile": ({"trained_at": self.profile["trained_at"], "n": self.profile["n"],
                             "contamination": self.profile["contamination"], "source": self.profile.get("source", "")}
                            if self.profile else None)}

    # ------------------------------------------------------------------ baholash
    def score(self, rows: list[dict]) -> dict:
        """Xususiyatlar lug‘atlari ro‘yxati → {"p": P_XGB, "s": S_IF, "cls": hujum turi} massivlari."""
        if not rows:
            return {"p": np.zeros(0), "s": np.zeros(0), "cls": []}
        z = self.zeek
        X = z["pre"].transform(pd.DataFrame(rows)[z["features"]])
        p = z["xgb"].predict_proba(X)[:, 1]
        if self.profile:
            s = _sif(self.profile["iso"], self.profile["cal"], X)
        else:
            s = _sif(z["iso"], z["iso_cal"], X)
        cls_idx = z["xgb5"].predict_proba(X)
        cls = [CLASSES[i] for i in cls_idx.argmax(1)]
        return {"p": p, "s": s, "cls": cls}

    def score_nsl(self, df: pd.DataFrame) -> dict:
        f = self.full
        X = f["pre"].transform(df[f["features"]])
        p = f["xgb"].predict_proba(X)[:, 1]
        s = _sif(f["iso"], f["iso_cal"], X)
        cls = [CLASSES[i] for i in f["xgb5"].predict(X)]
        return {"p": p, "s": s, "cls": cls}

    # ------------------------------------------------------------------ normal profil
    def train_profile(self, rows: list[dict], contamination: float = 0.01, source: str = "") -> dict:
        z = self.zeek
        X = z["pre"].transform(pd.DataFrame(rows)[z["features"]])
        iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42, n_jobs=-1).fit(X)
        prof = {"iso": iso, "cal": calibrate(iso, X), "n": len(rows), "contamination": contamination,
                "trained_at": datetime.now().isoformat(timespec="seconds"), "source": source}
        with self._lock:
            joblib.dump(prof, os.path.join(self.dir, "profile.joblib"), compress=3)
            self.profile = prof
        return self.info()["profile"]

    def reset_profile(self) -> None:
        with self._lock:
            pp = os.path.join(self.dir, "profile.joblib")
            if os.path.exists(pp):
                os.remove(pp)
            self.profile = None
