"""Load RF model and produce risk predictions for SecureRotate."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from config import META_PATH, MODEL_PATH, MODEL_VERSION, RISK_THRESHOLDS

logger = logging.getLogger("securerotate.ml")

_RF_MODEL = None
_RF_NUMERIC: list[str] = []
_RF_CATEGORICAL: list[str] = ["database_name"]
_RF_IMPORTANCES: dict[str, float] = {}
_LOADED_VERSION = MODEL_VERSION


def load_model() -> bool:
    global _RF_MODEL, _RF_NUMERIC, _RF_CATEGORICAL, _RF_IMPORTANCES, _LOADED_VERSION
    try:
        if not MODEL_PATH.exists():
            logger.error("Model file missing: %s", MODEL_PATH)
            return False
        _RF_MODEL = joblib.load(MODEL_PATH)
        if META_PATH.exists():
            meta = json.loads(META_PATH.read_text())
            _RF_NUMERIC = meta.get("numeric_features", _RF_NUMERIC)
            _RF_CATEGORICAL = meta.get("categorical_features", _RF_CATEGORICAL)
            _RF_IMPORTANCES = meta.get("feature_importances", {})
            _LOADED_VERSION = meta.get("model_version", MODEL_VERSION)
        logger.info("Loaded model %s from %s", _LOADED_VERSION, MODEL_PATH)
        return True
    except Exception as exc:
        logger.error("Failed to load model: %s", exc)
        _RF_MODEL = None
        return False


def model_version() -> str:
    return _LOADED_VERSION


def classify_risk(probability: float) -> tuple[int, str]:
    """Map probability [0,1] → (risk_score 0-100, risk_level)."""
    score = int(round(max(0.0, min(1.0, probability)) * 100))
    if probability >= RISK_THRESHOLDS["HIGH"]:
        level = "Critical"
    elif probability >= RISK_THRESHOLDS["MEDIUM"]:
        level = "High"
    elif probability >= RISK_THRESHOLDS["LOW"]:
        level = "Medium"
    else:
        level = "Low"
    return score, level


def predict_proba(features: dict[str, Any]) -> float:
    """Return P(breach) using the trained pipeline. Features must include numeric + database_name."""
    if _RF_MODEL is None:
        raise RuntimeError("ML model not loaded")
    row = {}
    for c in _RF_NUMERIC:
        row[c] = features.get(c, 0)
    for c in _RF_CATEGORICAL:
        row[c] = features.get(c, "MySQL")
    X = pd.DataFrame([row])
    return float(_RF_MODEL.predict_proba(X)[0, 1])


def build_factors(features: dict[str, Any], probability: float) -> list[dict]:
    """Heuristic explainability ranked by model importances + directional evidence."""
    days = int(features.get("days_to_expiry", 0))
    factors: list[dict] = []

    if days < 0:
        factors.append({"label": "Expired password", "weight": round(min(0.55, 0.35 + (-days) * 0.01), 3),
                        "evidence": f"Expired {-days} days ago"})
    elif days <= 3:
        factors.append({"label": "Expiry window", "weight": 0.35, "evidence": f"{days} days remaining"})
    elif days <= 7:
        factors.append({"label": "Expiry window", "weight": 0.25, "evidence": f"{days} days remaining"})
    elif days <= 30:
        factors.append({"label": "Expiry window", "weight": 0.08, "evidence": f"{days} days remaining"})
    else:
        factors.append({"label": "Expiry window", "weight": -0.05, "evidence": "Healthy expiry horizon"})

    ri = int(features.get("reminders_ignored", 0))
    if ri > 0:
        factors.append({"label": "Reminders ignored", "weight": round(min(0.45, ri * 0.08), 3),
                        "evidence": f"{ri} unacknowledged alerts"})

    fr = int(features.get("failed_rotations", 0))
    if fr > 0:
        factors.append({"label": "Failed rotations", "weight": round(min(0.30, fr * 0.08), 3),
                        "evidence": f"{fr} failed rotations"})

    sr = int(features.get("successful_rotations", 0))
    if sr > 0:
        factors.append({"label": "Successful rotations", "weight": round(-min(0.25, sr * 0.04), 3),
                        "evidence": f"{sr} verified rotations"})

    if not int(features.get("uses_mfa", 0)):
        factors.append({"label": "No MFA", "weight": 0.12, "evidence": "MFA disabled"})
    else:
        factors.append({"label": "MFA enabled", "weight": -0.10, "evidence": "MFA active"})

    if int(features.get("is_privileged", 0)):
        factors.append({"label": "Privileged account", "weight": 0.10, "evidence": "Elevated privilege"})
    if int(features.get("is_production", 0)):
        factors.append({"label": "Production system", "weight": 0.08, "evidence": "Production environment"})

    db = str(features.get("database_name", ""))
    if db:
        factors.append({"label": f"Engine: {db}", "weight": 0.03, "evidence": f"Monitored engine {db}"})

    ps = int(features.get("password_strength_score", 5))
    factors.append({"label": "Password strength", "weight": round(-ps * 0.02, 3),
                    "evidence": f"Score {ps}/10"})

    factors.append({"label": "Model confidence", "weight": round(probability * 0.12, 3),
                    "evidence": f"RF P(breach)={round(probability*100)}% ({_LOADED_VERSION})"})

    factors.sort(key=lambda f: abs(f["weight"]), reverse=True)
    return factors


# Load on import
load_model()
