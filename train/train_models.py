"""NSL-KDD eksperimenti va ishchi modellarni o‘qitish (diplom ishi, 3.2-band va A-ilova).

Ishlatish:   python train/train_models.py               (≈ 3–6 daqiqa)
             python train/train_models.py --fast        (MLP va xususiyat guruhlari tajribasisiz)

Ma’lumotlar: data/nsl-kdd/KDDTrain+.txt, KDDTest+.txt, KDDTest-21.txt  (python train/download_data.py)

Natijalar (models/):
  metrics.json         — diplomdagi 3.2–3.7-jadvallarga mos barcha natijalar
  full41.joblib        — 41 xususiyatli XGBoost + Isolation Forest + 5 sinfli XGBoost (NSL-KDD formatidagi ma’lumotlar uchun)
  zeek.joblib          — Zeek conn.log’dan hisoblanadigan 26 xususiyatli modellar (real/simulyatsiya trafigi uchun)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text
from xgboost import XGBClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from netguard.features import (ATTACK_CLASS, BASIC, CATEGORICAL, CLASSES, CONTENT, HOST_BASED, NSL_ALL,  # noqa: E402
                               NSL_COLUMNS, TIME_BASED, ZEEK_FEATURES)

DATA = os.path.join(ROOT, "data", "nsl-kdd")
OUT = os.path.join(ROOT, "models")
RS = 42


def load(name: str) -> pd.DataFrame:
    d = pd.read_csv(os.path.join(DATA, name), names=NSL_ALL)
    d["y"] = (d.label != "normal").astype(int)
    d["cls"] = d.label.map(ATTACK_CLASS).fillna("R2L")
    return d


def preprocessor(features: list[str]) -> ColumnTransformer:
    cat = [c for c in CATEGORICAL if c in features]
    num = [c for c in features if c not in cat]
    return ColumnTransformer([("cat", OneHotEncoder(handle_unknown="ignore"), cat), ("num", StandardScaler(), num)], sparse_threshold=0)


def m(y, pred, score=None, ms_per_1k=None, train_s=None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {"accuracy": round(accuracy_score(y, pred), 4), "precision": round(precision_score(y, pred, zero_division=0), 4),
           "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
           "fpr": round(fp / (fp + tn), 4), "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
    if score is not None:
        out["roc_auc"] = round(roc_auc_score(y, score), 4)
        f, t, _ = roc_curve(y, score)
        idx = np.unique(np.linspace(0, len(f) - 1, min(60, len(f))).astype(int))
        out["roc"] = {"fpr": [round(float(x), 4) for x in f[idx]], "tpr": [round(float(x), 4) for x in t[idx]]}
    if ms_per_1k is not None:
        out["ms_per_1000"] = round(ms_per_1k, 2)
    if train_s is not None:
        out["train_s"] = round(train_s, 1)
    return out


def iso_calibration(iso: IsolationForest, X_normal) -> dict:
    """Isolation Forest balini 0..1 oralig‘iga keltirish: S_IF = sigmoid((a − t) / s), a = −score_samples."""
    a = -iso.score_samples(X_normal)
    t = float(-iso.offset_)
    s = float(np.std(a) * 0.5) or 0.05
    return {"threshold": t, "scale": s}


def s_if(iso, cal, X) -> np.ndarray:
    a = -iso.score_samples(X)
    return 1.0 / (1.0 + np.exp(-(a - cal["threshold"]) / cal["scale"]))


def timed(fn, X):
    t = time.perf_counter()
    r = fn(X)
    return r, (time.perf_counter() - t) / X.shape[0] * 1e6  # ms / 1000 yozuv


def make_xgb(n=300, depth=8):
    return XGBClassifier(n_estimators=n, max_depth=depth, learning_rate=0.1, subsample=0.8, tree_method="hist",
                         eval_metric="logloss", random_state=RS, n_jobs=-1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    print("1) NSL-KDD yuklanmoqda")
    tr, te, te21 = load("KDDTrain+.txt"), load("KDDTest+.txt"), load("KDDTest-21.txt")
    novel = sorted(set(te.label) - set(tr.label))
    print(f"   o‘quv {len(tr)} (hujum {tr.y.sum()}), test {len(te)} (hujum {te.y.sum()}), test-21 {len(te21)}; "
          f"yangi hujum turlari: {len(novel)}")

    pre = preprocessor(NSL_COLUMNS)
    Xtr, Xte, X21 = pre.fit_transform(tr[NSL_COLUMNS]), pre.transform(te[NSL_COLUMNS]), pre.transform(te21[NSL_COLUMNS])
    print(f"   vektor o‘lchami: {Xtr.shape[1]}")
    Xtr_d, Xte_d, X21_d = Xtr, Xte, X21

    models = {
        "Logistic Regression": LogisticRegression(C=1.0, max_iter=2000),
        "Decision Tree": DecisionTreeClassifier(max_depth=20, random_state=RS),
        "Random Forest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RS),
        "XGBoost": make_xgb(),
    }
    if not args.fast:
        models["MLP"] = MLPClassifier(hidden_layer_sizes=(128, 64), early_stopping=True, max_iter=200, random_state=RS)

    res, res21, novel_rate, probas, probas21 = {}, {}, {}, {}, {}
    novel_mask = te.label.isin(novel).values
    print("2) Modellarni o‘qitish (ikkilik tasnif)")
    for name, mdl in models.items():
        t0 = time.perf_counter()
        mdl.fit(Xtr_d if name == "MLP" else Xtr, tr.y)
        tt = time.perf_counter() - t0
        p, ms = timed(lambda X: mdl.predict_proba(X)[:, 1], Xte_d if name == "MLP" else Xte)
        p21 = mdl.predict_proba(X21_d if name == "MLP" else X21)[:, 1]
        probas[name], probas21[name] = p, p21
        res[name] = m(te.y, (p >= 0.5).astype(int), p, ms, tt)
        res21[name] = m(te21.y, (p21 >= 0.5).astype(int))
        novel_rate[name] = round(float(((p >= 0.5) & novel_mask).sum() / novel_mask.sum()), 4)
        print(f"   {name:20s} Acc={res[name]['accuracy']:.3f} F1={res[name]['f1']:.3f} R={res[name]['recall']:.3f} "
              f"FPR={res[name]['fpr']:.4f} AUC={res[name]['roc_auc']:.3f} yangi={novel_rate[name]:.3f}")

    print("3) Isolation Forest (faqat normal trafikda) va gibrid (3.1)")
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=RS, n_jobs=-1)
    t0 = time.perf_counter()
    iso.fit(Xtr_d[(tr.y == 0).values])
    tt = time.perf_counter() - t0
    cal = iso_calibration(iso, Xtr_d[(tr.y == 0).values])
    sif, ms = timed(lambda X: s_if(iso, cal, X), Xte_d)
    sif21 = s_if(iso, cal, X21_d)
    if_pred, if21 = (sif >= 0.5).astype(int), (sif21 >= 0.5).astype(int)
    res["Isolation Forest"] = m(te.y, if_pred, sif, ms, tt)
    res21["Isolation Forest"] = m(te21.y, if21)
    novel_rate["Isolation Forest"] = round(float((if_pred.astype(bool) & novel_mask).sum() / novel_mask.sum()), 4)
    pxgb = probas["XGBoost"]
    hyb = np.maximum((pxgb >= 0.5).astype(int), if_pred)
    hyb_score = np.maximum(pxgb, sif)
    res["Gibrid (XGBoost + IF)"] = m(te.y, hyb, hyb_score)
    res21["Gibrid (XGBoost + IF)"] = m(te21.y, np.maximum((probas21["XGBoost"] >= 0.5).astype(int), if21))
    novel_rate["Gibrid (XGBoost + IF)"] = round(float((hyb.astype(bool) & novel_mask).sum() / novel_mask.sum()), 4)
    for n in ("Isolation Forest", "Gibrid (XGBoost + IF)"):
        print(f"   {n:20s} Acc={res[n]['accuracy']:.3f} F1={res[n]['f1']:.3f} R={res[n]['recall']:.3f} "
              f"FPR={res[n]['fpr']:.4f} yangi={novel_rate[n]:.3f}")

    print("4) Chegara tahlili (XGBoost)")
    thresholds = []
    for th in (0.05, 0.1, 0.2, 0.3, 0.5, 0.7):
        r = m(te.y, (pxgb >= th).astype(int))
        thresholds.append({"threshold": th, "recall": r["recall"], "fpr": r["fpr"], "f1": r["f1"]})

    print("5) Besh sinfli tasnif")
    cls_map = {c: i for i, c in enumerate(CLASSES)}
    ytr5, yte5 = tr.cls.map(cls_map).values, te.cls.map(cls_map).values
    rf5 = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RS).fit(Xtr, ytr5)
    xgb5 = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8, tree_method="hist",
                         objective="multi:softprob", random_state=RS, n_jobs=-1).fit(Xtr, ytr5)
    multi = {}
    for name, mdl in (("Random Forest", rf5), ("XGBoost", xgb5)):
        pr = mdl.predict(Xte)
        multi[name] = {
            "accuracy": round(accuracy_score(yte5, pr), 4), "macro_f1": round(f1_score(yte5, pr, average="macro"), 4),
            "recall_by_class": {c: round(float(((pr == i) & (yte5 == i)).sum() / max((yte5 == i).sum(), 1)), 4)
                                for c, i in cls_map.items()},
            "confusion": confusion_matrix(yte5, pr, labels=list(range(5))).tolist(),
        }
    multi["test_counts"] = {c: int((yte5 == i).sum()) for c, i in cls_map.items()}

    groups = {}
    if not args.fast:
        print("6) Xususiyatlar guruhlari (XGBoost)")
        for gname, feats in (("Asosiy (9)", BASIC), ("Asosiy + mazmun (22)", BASIC + CONTENT),
                             ("Asosiy + vaqt bo‘yicha (18)", BASIC + TIME_BASED),
                             ("Asosiy + xost bo‘yicha (19)", BASIC + HOST_BASED), ("Barcha 41 ta xususiyat", NSL_COLUMNS)):
            pg = preprocessor(feats)
            mdl = make_xgb().fit(pg.fit_transform(tr[feats]), tr.y)
            pp = mdl.predict_proba(pg.transform(te[feats]))[:, 1]
            r = m(te.y, (pp >= 0.5).astype(int))
            groups[gname] = {"f1": r["f1"], "recall": r["recall"], "fpr": r["fpr"]}
            print(f"   {gname:28s} F1={r['f1']:.3f} R={r['recall']:.3f} FPR={r['fpr']:.4f}")

    print("7) Xususiyatlar muhimligi va 3 darajali qaror daraxti qoidalari")
    names = pre.get_feature_names_out()
    clean = [n.split("__", 1)[-1] for n in names]
    rf = models["Random Forest"]
    imp = sorted(zip(clean, rf.feature_importances_), key=lambda t: -t[1])[:12]
    raw_num = [c for c in NSL_COLUMNS if c not in CATEGORICAL]
    dt3 = DecisionTreeClassifier(max_depth=3, random_state=RS).fit(tr[raw_num], tr.y)
    p_dt3 = dt3.predict(te[raw_num])
    rules = export_text(dt3, feature_names=raw_num)
    dt3_res = m(te.y, p_dt3)

    print("8) Ishchi modellar: full41 va zeek")
    xgb_full = models["XGBoost"]
    joblib.dump({"pre": pre, "xgb": xgb_full, "iso": iso, "iso_cal": cal, "xgb5": xgb5, "features": NSL_COLUMNS,
                 "classes": CLASSES, "trained_at": datetime.now().isoformat(timespec="seconds")},
                os.path.join(OUT, "full41.joblib"), compress=3)
    pz = preprocessor(ZEEK_FEATURES)
    Ztr, Zte = pz.fit_transform(tr[ZEEK_FEATURES]), pz.transform(te[ZEEK_FEATURES])
    xgb_z = make_xgb().fit(Ztr, tr.y)
    iso_z = IsolationForest(n_estimators=200, contamination=0.05, random_state=RS, n_jobs=-1).fit(Ztr[(tr.y == 0).values])
    cal_z = iso_calibration(iso_z, Ztr[(tr.y == 0).values])
    xgb5_z = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8, tree_method="hist",
                           objective="multi:softprob", random_state=RS, n_jobs=-1).fit(Ztr, ytr5)
    pz_x = xgb_z.predict_proba(Zte)[:, 1]
    sz = s_if(iso_z, cal_z, Zte)
    zeek_res = {"XGBoost": m(te.y, (pz_x >= 0.5).astype(int), pz_x),
                "Isolation Forest": m(te.y, (sz >= 0.5).astype(int), sz),
                "Gibrid (XGBoost + IF)": m(te.y, np.maximum((pz_x >= 0.5), (sz >= 0.5)).astype(int), np.maximum(pz_x, sz))}
    for v in zeek_res.values():
        v.pop("roc", None)
    print(f"   zeek-modeli: XGB F1={zeek_res['XGBoost']['f1']:.3f}, gibrid F1={zeek_res['Gibrid (XGBoost + IF)']['f1']:.3f}")
    joblib.dump({"pre": pz, "xgb": xgb_z, "iso": iso_z, "iso_cal": cal_z, "xgb5": xgb5_z, "features": ZEEK_FEATURES,
                 "classes": CLASSES, "trained_at": datetime.now().isoformat(timespec="seconds"), "iso_source": "NSL-KDD normal"},
                os.path.join(OUT, "zeek.joblib"), compress=3)

    info = {
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": {"train": len(tr), "train_attacks": int(tr.y.sum()), "test": len(te), "test_attacks": int(te.y.sum()),
                    "test21": len(te21), "novel_types": novel, "novel_records": int(novel_mask.sum()), "vector_dim": int(Xtr.shape[1])},
        "binary": res, "test21": {k: {kk: v[kk] for kk in ("accuracy", "recall", "f1", "fpr")} for k, v in res21.items()},
        "novel_detection": novel_rate, "thresholds": thresholds, "multiclass": multi, "feature_groups": groups,
        "feature_importance": [{"feature": f, "importance": round(float(v), 4)} for f, v in imp],
        "dt3": {"rules": rules, "f1": dt3_res["f1"], "recall": dt3_res["recall"], "fpr": dt3_res["fpr"]},
        "zeek_model": zeek_res,
    }
    with open(os.path.join(OUT, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=1)
    print(f"Saqlandi: {OUT}")


if __name__ == "__main__":
    main()
