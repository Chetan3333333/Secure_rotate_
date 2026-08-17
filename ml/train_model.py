"""
Train SecureRotate Random Forest model on the synthetic multi-DB dataset.

This is a training script only. Run once when you change the dataset:
    python ml/train_model.py

The trained pipeline is saved to ml/model/rf_breach_model.joblib
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "dataset" / "ml_training_data_5000.csv"
MODEL_DIR = ROOT / "model"
MODEL_PATH = MODEL_DIR / "rf_breach_model.joblib"
META_PATH = MODEL_DIR / "model_meta.json"

NUMERIC = [
    "days_to_expiry",
    "total_rotations",
    "successful_rotations",
    "failed_rotations",
    "reminders_ignored",
    "avg_response_hours",
    "login_frequency_per_week",
    "password_strength_score",
    "uses_mfa",
    "is_privileged",
    "is_production",
]
CATEGORICAL = ["database_name"]
TARGET = "caused_breach"


def train() -> None:
    print(f"Loading {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    # Drop unused columns that are not model features (avoid accidental leakage)
    # employee_id, department, role, breach_risk_score are NOT used by the model.
    print(f"Rows: {len(df)} | Engines: {sorted(df['database_name'].unique())}")
    print(f"Class distribution (caused_breach):\n{df[TARGET].value_counts()}")
    print(f"Breach rate: {df[TARGET].mean():.3f}")

    X = df[NUMERIC + CATEGORICAL]
    y = df[TARGET].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    pipe = Pipeline([
        ("prep", ColumnTransformer([
            ("num", "passthrough", NUMERIC),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL),
        ])),
        ("rf", RandomForestClassifier(
            n_estimators=250,
            max_depth=14,
            min_samples_leaf=4,
            min_samples_split=8,
            max_features="sqrt",
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("Training Random Forest pipeline...")
    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    y_proba = pipe.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print("\n=== Hold-out Test Performance (synthetic data) ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1       : {f1:.4f}")
    print(f"ROC-AUC  : {auc:.4f}")
    print("Confusion matrix [[TN FP],[FN TP]]:")
    print(cm)
    print(classification_report(y_test, y_pred, target_names=["No Breach", "Breach"]))

    ohe = pipe.named_steps["prep"].named_transformers_["cat"]
    names = NUMERIC + list(ohe.get_feature_names_out(CATEGORICAL))
    imp = dict(zip(names, pipe.named_steps["rf"].feature_importances_.round(4).tolist()))

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)

    meta = {
        "model_version": "rf-breach-2.0-multidb",
        "algorithm": "RandomForestClassifier + OneHotEncoder pipeline",
        "n_estimators": 250,
        "max_depth": 14,
        "numeric_features": NUMERIC,
        "categorical_features": CATEGORICAL,
        "all_feature_names": names,
        "target": TARGET,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "dataset_rows": int(len(df)),
        "test_accuracy": round(float(acc), 4),
        "test_precision": round(float(prec), 4),
        "test_recall": round(float(rec), 4),
        "test_f1": round(float(f1), 4),
        "test_roc_auc": round(float(auc), 4),
        "confusion_matrix": cm.tolist(),
        "feature_importances": imp,
        "database_engines": sorted(df["database_name"].unique().tolist()),
        "note": "Evaluated on SYNTHETIC data only. Not real-world breach prediction performance.",
        "sklearn_version": __import__("sklearn").__version__,
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print(f"\nSaved model -> {MODEL_PATH}")
    print("Training complete.")


if __name__ == "__main__":
    train()
