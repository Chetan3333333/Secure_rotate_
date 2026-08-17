"""SecureRotate configuration — MySQL only. All secrets from environment."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# --- MySQL (mandatory) ---
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "securerotate")

# --- App ---
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-use-long-random-string")
FLASK_HOST = os.environ.get("HOST", "127.0.0.1")
FLASK_PORT = int(os.environ.get("PORT", "8000"))
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

# --- SMTP (optional; emails skipped if unset) ---
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

# --- Auth / tokens ---
TOKEN_EXPIRY_MINUTES = int(os.environ.get("TOKEN_EXPIRY_MINUTES", "15"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@securedb.com")
# Prefer ADMIN_PASSWORD_HASH in production; plaintext only for first-run demo
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# --- ML ---
MODEL_PATH = ROOT / "ml" / "model" / "rf_breach_model.joblib"
META_PATH = ROOT / "ml" / "model" / "model_meta.json"
MODEL_VERSION = "rf-breach-2.0-multidb"

# --- Risk thresholds (probability 0-1 → level) ---
RISK_THRESHOLDS = {
    "LOW": 0.30,
    "MEDIUM": 0.60,
    "HIGH": 0.80,
    # above HIGH → CRITICAL
}

# --- Notification day thresholds ---
NOTIFY_DAYS = [30, 14, 7, 3, 1, 0]  # 0 = expired

PUBLIC = ROOT / "public"
SCHEMA_PATH = ROOT / "database" / "schema_mysql.sql"
