"""Gibrid qaror qoidasi (3.1) va risk balli (3.2), javob darajalari (3.8-jadval)."""
from __future__ import annotations

from . import config as C

LEVELS = ("low", "medium", "high")
LEVEL_UZ = {"high": "Yuqori", "medium": "O‘rta", "low": "Past"}
LEVEL_ACTION_UZ = {
    "high": "Avtomatik bloklash (24 soat) / xostni karantinga, SOC xabardor qilinadi",
    "medium": "Hodisa kartasi yaratiladi, tahlilchi 30 daqiqa ichida ko‘rib chiqadi",
    "low": "Faqat SIEM jurnaliga yoziladi, haftalik tahlil",
}


def is_alert(sig: bool, p_xgb: float, s_if: float) -> bool:
    """(3.1): Ogohlantirish = Sig ∨ [P_XGB ≥ 0,5] ∨ [IF anomaliya]."""
    return bool(sig) or p_xgb >= C.P_XGB_THRESHOLD or s_if >= C.S_IF_THRESHOLD


def risk(s_sig: float, p_xgb: float, s_if: float, s_akt: float) -> float:
    """(3.2): Risk = 0,4·S_sig + 0,3·P_XGB + 0,2·S_IF + 0,1·S_aktiv."""
    w = C.WEIGHTS
    r = w["sig"] * s_sig + w["xgb"] * p_xgb + w["if"] * s_if + w["asset"] * s_akt
    return round(min(max(r, 0.0), 1.0), 4)


def level(r: float) -> str:
    if r >= C.LEVEL_HIGH:
        return "high"
    if r >= C.LEVEL_MEDIUM:
        return "medium"
    return "low"


def explain(s_sig: float, p_xgb: float, s_if: float, s_akt: float) -> list[tuple[str, float, float, float]]:
    """Risk tarkibi: (komponent, qiymat, vazn, hissa) — konsolda «nima uchun» bo‘limi uchun."""
    w = C.WEIGHTS
    return [("S_sig — signatura jiddiyligi", s_sig, w["sig"], round(w["sig"] * s_sig, 4)),
            ("P_XGB — XGBoost ehtimoli", p_xgb, w["xgb"], round(w["xgb"] * p_xgb, 4)),
            ("S_IF — Isolation Forest anomaliya balli", s_if, w["if"], round(w["if"] * s_if, 4)),
            ("S_aktiv — aktiv muhimligi", s_akt, w["asset"], round(w["asset"] * s_akt, 4))]
