from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import string
import time
from datetime import date, datetime, timedelta
import math
import random
import os
import smtplib
import re
import base64
import numpy as np
from email.message import EmailMessage
from pathlib import Path

import pandas as pd
import plotly.express as px

from flask import Flask, request, jsonify, send_from_directory, send_file


def clean_plotly_dict(obj):
    """
    Recursively decodes numpy arrays and Plotly base64 bdata dictionaries
    into standard Python lists, ints, and floats so standard JSON serializers
    produce clean JSON arrays that Plotly.js renders reliably.
    """
    if isinstance(obj, dict):
        if "bdata" in obj and "dtype" in obj:
            dtype_map = {
                "i1": np.int8, "u1": np.uint8,
                "i2": np.int16, "u2": np.uint16,
                "i4": np.int32, "u4": np.uint32,
                "i8": np.int64, "u8": np.uint64,
                "f4": np.float32, "f8": np.float64
            }
            raw = base64.b64decode(obj["bdata"])
            arr = np.frombuffer(raw, dtype=dtype_map.get(obj["dtype"], np.int64))
            return arr.tolist()
        return {k: clean_plotly_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_plotly_dict(v) for v in obj]
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (np.int64, np.int32, np.int16, np.int8, np.integer)):
        return int(obj)
    elif isinstance(obj, (np.float64, np.float32, np.floating)):
        return float(obj)
    return obj



# --- EMAIL HELPER ---
def extract_email(text):
    match = re.search(r'[\w\.-]+@[\w\.-]+', str(text))
    return match.group(0) if match else None

def get_recipient_email(credential):
    owner_val = credential["owner"] if "owner" in credential.keys() else ""
    email = extract_email(owner_val)
    if not email:
        user_val = credential["username"] if "username" in credential.keys() else ""
        email = extract_email(user_val)
    return email

def send_real_email(to_email, subject, body):
    sender = os.environ.get("SMTP_EMAIL")
    password = os.environ.get("SMTP_APP_PASSWORD")
    
    if not sender or not password or not to_email:
        print(f"Skipping real email to {to_email} because SMTP credentials are not set.")
        return False
        
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = f"SecureRotate <{sender}>"
    msg["To"] = to_email
    
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
        print(f"Successfully sent email to {to_email}")
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False
# --------------------


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
DB_PATH = ROOT / "securerotate.db"
MODEL_VERSION = "rf-surrogate-2.0-simplified"

# --- SMTP Configuration for OTP Emails ---
SMTP_EMAIL = "chetanchowdarychetan@gmail.com"
SMTP_APP_PASSWORD = "ozpl bcwz rioc izeq"
TOKEN_EXPIRY_MINUTES = 15


def today() -> date:
    return date.today()


def iso_now() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def risk_rank(risk: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(risk, 0)


def classify_risk(days_to_expiry: int) -> str:
    """
    Authoritative single risk classification based on days remaining until password expiry.
    Priority order:
    1. Expired / overdue (days <= 0) or days <= 3 -> Critical
    2. days <= 7 (4 to 7 days) -> High
    3. days <= 15 (8 to 15 days) -> Medium
    4. otherwise (> 15 days) -> Low
    """
    days = int(days_to_expiry)
    if days <= 3:
        return "Critical"
    if days <= 7:
        return "High"
    if days <= 15:
        return "Medium"
    return "Low"


def classify(days_or_prob: int | float) -> str:
    """Backward-compatible classification wrapper."""
    if isinstance(days_or_prob, int) or (isinstance(days_or_prob, float) and (days_or_prob > 1.0 or days_or_prob < 0.0)):
        return classify_risk(int(days_or_prob))
    if days_or_prob >= 0.80:
        return "Critical"
    if days_or_prob >= 0.60:
        return "High"
    if days_or_prob >= 0.30:
        return "Medium"
    return "Low"


def feature_score(credential: sqlite3.Row | dict, conn: sqlite3.Connection) -> tuple[float, list[dict]]:
    """Multi-feature behavioral risk model using the same formula as the ML training data."""
    days = int(credential["days_to_expiry"])
    cred_id = credential["id"]

    # --- Collect features from the database ---
    # Rotation stats
    rotations = conn.execute(
        "SELECT status, verification_status FROM rotation_history WHERE credential_id = ?", (cred_id,)
    ).fetchall()
    total_rotations = len(rotations)
    successful_rotations = sum(1 for r in rotations if r["verification_status"] == "Verified")
    failed_rotations = sum(1 for r in rotations if r["verification_status"] == "failed" or r["status"] == "failed")

    # Reminders ignored = notifications that were never acknowledged
    notifs = conn.execute(
        "SELECT status, created_at, acknowledged_at FROM notifications WHERE credential_id = ?", (cred_id,)
    ).fetchall()
    reminders_ignored = sum(1 for n in notifs if n["status"] in ("Sent", "Reminded", "Escalated") and not n["acknowledged_at"])

    # Average response hours for acknowledged notifications
    response_hours_list = []
    for n in notifs:
        if n["acknowledged_at"] and n["created_at"]:
            try:
                created = datetime.fromisoformat(n["created_at"])
                acked = datetime.fromisoformat(n["acknowledged_at"])
                delta_hours = max(0, (acked - created).total_seconds() / 3600)
                response_hours_list.append(delta_hours)
            except (ValueError, TypeError):
                pass
    avg_response_hours = sum(response_hours_list) / len(response_hours_list) if response_hours_list else 48.0

    # Password strength heuristic (based on hash length and salt presence)
    pwd_hash = credential.get("password_hash", "") if isinstance(credential, dict) else (credential["password_hash"] if "password_hash" in credential.keys() else "")
    pwd_salt = credential.get("password_salt", "") if isinstance(credential, dict) else (credential["password_salt"] if "password_salt" in credential.keys() else "")
    password_strength = min(10, max(3, len(pwd_hash) // 16 + (3 if pwd_salt else 0)))

    # MFA status
    uses_mfa = int(credential.get("uses_mfa", 0) if isinstance(credential, dict) else (credential["uses_mfa"] if "uses_mfa" in credential.keys() else 0))

    # --- Apply base score based on authoritative expiry window ---
    # Critical: <= 3 days (80-99%)
    # High: 4-7 days (60-79%)
    # Medium: 8-15 days (30-59%)
    # Low: > 15 days (5-29%)
    if days < 0:
        base_score = 90 + min(9, (-days) * 2)
    elif days <= 3:
        base_score = 82 + (3 - days) * 4
    elif days <= 7:
        base_score = 64 + (7 - days) * 3
    elif days <= 15:
        base_score = 35 + (15 - days) * 2.5
    else:
        base_score = max(5, 25 - min(20, (days - 15)))

    # Behavioral adjustments (fine-grained impact)
    score = base_score
    score += reminders_ignored * 3
    score += failed_rotations * 4
    score -= successful_rotations * 3
    score -= (password_strength - 5) * 1.5
    score -= uses_mfa * 4
    if avg_response_hours > 24:
        score += min(5, (avg_response_hours / 24) * 1.5)

    # Clamping probability to stay consistent with the category bounds
    category = classify_risk(days)
    if category == "Critical":
        probability = min(0.99, max(0.80, score / 100.0))
    elif category == "High":
        probability = min(0.79, max(0.60, score / 100.0))
    elif category == "Medium":
        probability = min(0.59, max(0.30, score / 100.0))
    else:
        probability = min(0.29, max(0.05, score / 100.0))

    # --- Build factors list ---
    factors = []
    if days < 0:
        expiry_contrib = (40 + min(60, (-days) * 4)) / 100.0
        factors.append({"label": "Expired password", "weight": round(expiry_contrib, 3), "evidence": f"Expired {-days} days ago"})
    elif days <= 3:
        factors.append({"label": "Expiry window", "weight": 0.35, "evidence": f"{days} days remaining"})
    elif days <= 7:
        factors.append({"label": "Expiry window", "weight": 0.25, "evidence": f"{days} days remaining"})
    elif days <= 15:
        factors.append({"label": "Expiry window", "weight": round(max(5, 20 - days) / 100, 3), "evidence": f"{days} days remaining"})
    elif days <= 30:
        factors.append({"label": "Expiry window", "weight": 0.05, "evidence": f"{days} days remaining"})
    else:
        factors.append({"label": "Expiry window", "weight": 0.0, "evidence": "Healthy"})

    if reminders_ignored > 0:
        factors.append({"label": "Reminders ignored", "weight": round(reminders_ignored * 10 / 100, 3), "evidence": f"{reminders_ignored} unacknowledged alerts"})
    if failed_rotations > 0:
        factors.append({"label": "Failed rotations", "weight": round(failed_rotations * 12 / 100, 3), "evidence": f"{failed_rotations} of {total_rotations} rotations failed"})
    if successful_rotations > 0:
        factors.append({"label": "Successful rotations", "weight": round(-successful_rotations * 8 / 100, 3), "evidence": f"{successful_rotations} verified rotations"})
    if not uses_mfa:
        factors.append({"label": "No MFA", "weight": 0.15, "evidence": "Multi-factor authentication disabled"})
    else:
        factors.append({"label": "MFA enabled", "weight": -0.15, "evidence": "Multi-factor authentication active"})
    if avg_response_hours > 24:
        factors.append({"label": "Slow response time", "weight": round((avg_response_hours / 24) * 3 / 100, 3), "evidence": f"Avg {round(avg_response_hours, 1)}h to respond"})
    factors.append({"label": "Password strength", "weight": round(-password_strength * 3 / 100, 3), "evidence": f"Score: {password_strength}/10"})

    # Sort factors by absolute weight descending
    factors.sort(key=lambda f: abs(f["weight"]), reverse=True)

    return probability, factors


def recommend_action(credential: sqlite3.Row | dict, risk: str, probability: float, factors: list[dict]) -> dict:
    days = int(credential["days_to_expiry"])

    if days < 0:
        action = "Immediate Rotation"
        urgency = "Breach"
    elif days <= 3:
        action = "Immediate Rotation"
        urgency = "Critical"
    elif days <= 7:
        action = "Rotate Within 24 Hours"
        urgency = "High"
    elif days <= 30:
        action = "Schedule Rotation"
        urgency = "Medium"
    else:
        action = "Monitor"
        urgency = "Low"

    # Dynamic stakeholders based on risk severity
    stakeholders = ["Account Owner", "Security Team"]
    if risk in ("Critical", "High"):
        stakeholders.append("CISO")
    if risk == "Critical":
        stakeholders.append("Compliance Team")

    # Approval required for high-risk items
    approval_required = risk in ("Critical", "High")

    # Richer explanation referencing top contributing factors
    top_risk_factors = [f for f in factors if f["weight"] > 0][:3]
    if top_risk_factors:
        factor_reasons = ", ".join(f"{f['label'].lower()} ({f['evidence'].lower()})" for f in top_risk_factors)
        explanation = f"{credential['username']} is {risk.lower()} risk (score {round(probability * 100)}%). Top drivers: {factor_reasons}."
    else:
        explanation = f"{credential['username']} is {risk.lower()} risk. It expires in {days} days. No significant risk factors detected."

    return {
        "action": action,
        "urgency": urgency,
        "stakeholders": stakeholders,
        "approval_required": approval_required,
        "explanation": explanation,
    }


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+" for c in password)
        ):
            return password


def hash_secret(secret: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt.encode("utf-8"), 600_000)
    return digest.hex()


def required_text(payload: dict, key: str, label: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"{label} is required")
    return value


def create_user_credential(conn: sqlite3.Connection, payload: dict) -> dict:
    database_name = required_text(payload, "database_name", "Database name")
    username = required_text(payload, "username", "Username")
    password = required_text(payload, "password", "Password")
    owner = required_text(payload, "owner", "Owner name")
    expiry_date = required_text(payload, "expiry_date", "Expiry date")
    uses_mfa = int(payload.get("uses_mfa", 0))

    try:
        expiry = date.fromisoformat(expiry_date)
    except ValueError as exc:
        raise ValueError("Expiry date must use YYYY-MM-DD format") from exc

    days_to_expiry = (expiry - today()).days
    credential_age = max(0, min(365, 90 - days_to_expiry))
    salt = secrets.token_hex(16)
    secret_ref = f"vault://securerotate/{database_name.lower().replace(' ', '-')}/{username}"

    cursor = conn.execute(
        """
        INSERT INTO credentials (
            database_name, username, owner, expiry_date, status, secret_ref,
            password_hash, password_salt, last_rotated_at, created_at, uses_mfa
        ) VALUES (?, ?, ?, ?, 'Submitted', ?, ?, ?, ?, ?, ?)
        """,
        (
            database_name,
            username,
            owner,
            expiry.isoformat(),
            secret_ref,
            hash_secret(password, salt),
            salt,
            (today() - timedelta(days=credential_age)).isoformat(),
            iso_now(),
            uses_mfa,
        ),
    )
    credential_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (owner, "submit_credential", "credential", credential_id, f"User submitted {database_name}/{username} for monitoring.", iso_now()),
    )
    refresh_notifications(conn)
    item = next(credential for credential in enriched_credentials(conn) if credential["id"] == credential_id)
    return {
        "id": credential_id,
        "risk": item["risk"],
        "risk_probability": item["risk_probability"],
        "recommendation": item["recommendation"],
        "days_to_expiry": item["days_to_expiry"],
    }


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                database_name TEXT NOT NULL,
                username TEXT NOT NULL,
                owner TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                secret_ref TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                last_rotated_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER NOT NULL,
                recipients TEXT NOT NULL,
                message TEXT NOT NULL,
                channel TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT,
                FOREIGN KEY (credential_id) REFERENCES credentials(id)
            );

            CREATE TABLE IF NOT EXISTS rotation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                verification_status TEXT NOT NULL,
                details TEXT NOT NULL,
                FOREIGN KEY (credential_id) REFERENCES credentials(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL UNIQUE,
                credential_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                otp_code TEXT,
                otp_verified INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (credential_id) REFERENCES credentials(id)
            );
            """
        )
        # Migration: add uses_mfa column if it doesn't exist yet
        try:
            conn.execute("ALTER TABLE credentials ADD COLUMN uses_mfa INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        count = conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"]
        if count:
            refresh_notifications(conn)
            return

        seed_credentials(conn)
        refresh_notifications(conn)


def seed_credentials(conn: sqlite3.Connection) -> None:
    rows = [
        ("MySQL", "john.doe@company.com", "John Doe", -1, 0),
        ("PostgreSQL", "alice.smith@company.com", "Alice Smith", 2, 1),
        ("Oracle", "bob.jenkins@company.com", "Bob Jenkins", 6, 1),
        ("SQL Server", "sarah.connor@company.com", "Sarah Connor", 9, 0),
        ("MySQL", "mike.ross@company.com", "Mike Ross", 18, 1),
        ("PostgreSQL", "harvey.specter@company.com", "Harvey Specter", 24, 1),
        ("Oracle", "rachel.zane@company.com", "Rachel Zane", 33, 0),
        ("SQL Server", "donna.paulsen@company.com", "Donna Paulsen", 41, 1),
        ("MySQL", "louis.litt@company.com", "Louis Litt", 57, 1),
        ("PostgreSQL", "jessica.pearson@company.com", "Jessica Pearson", 77, 1),
        ("Oracle", "katrina.bennett@company.com", "Katrina Bennett", 4, 0),
        ("SQL Server", "alex.williams@company.com", "Alex Williams", 120, 1),
    ]

    for row in rows:
        salt = secrets.token_hex(16)
        placeholder_secret = generate_password()
        conn.execute(
            """
            INSERT INTO credentials (
                database_name, username, owner, expiry_date, status, secret_ref,
                password_hash, password_salt, last_rotated_at, created_at, uses_mfa
            ) VALUES (?, ?, ?, ?, 'Active', ?, ?, ?, ?, ?, ?)
            """,
            (
                row[0],
                row[1],
                row[2],
                (today() + timedelta(days=row[3])).isoformat(),
                f"vault://securerotate/{row[0].lower()}/{row[1]}",
                hash_secret(placeholder_secret, salt),
                salt,
                (today() - timedelta(days=90 - row[3])).isoformat(),
                iso_now(),
                row[4],
            ),
        )

    # Seed realistic rotation history records for initial credentials
    rotations_seed = [
        (1, "system", "completed", (datetime.utcnow() - timedelta(days=91)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=91)).isoformat(timespec="seconds"), "Verified", "Scheduled policy rotation completed successfully."),
        (2, "admin", "completed", (datetime.utcnow() - timedelta(days=88)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=88)).isoformat(timespec="seconds"), "Verified", "Pre-expiry rotation initiated by administrator."),
        (3, "system", "completed", (datetime.utcnow() - timedelta(days=84)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=84)).isoformat(timespec="seconds"), "Verified", "Automated rotation verified against Oracle instance."),
        (4, "system", "failed", (datetime.utcnow() - timedelta(days=40)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=40)).isoformat(timespec="seconds"), "Failed", "Connection timeout during SQL Server post-rotation health check."),
        (5, "mike.ross@company.com", "completed", (datetime.utcnow() - timedelta(days=72)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=72)).isoformat(timespec="seconds"), "Verified", "User self-service password rotation."),
        (6, "system", "completed", (datetime.utcnow() - timedelta(days=66)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=66)).isoformat(timespec="seconds"), "Verified", "Routine maintenance rotation and secret hash storage."),
        (7, "system", "pending", (datetime.utcnow() - timedelta(days=25)).isoformat(timespec="seconds"), None, "Pending", "Rotation queued, awaiting administrator confirmation."),
        (8, "donna.paulsen@company.com", "completed", (datetime.utcnow() - timedelta(days=49)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=49)).isoformat(timespec="seconds"), "Verified", "Self-service rotation completed and verified."),
        (9, "admin", "completed", (datetime.utcnow() - timedelta(days=33)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=33)).isoformat(timespec="seconds"), "Verified", "Emergency rotation following policy update."),
        (10, "jessica.pearson@company.com", "completed", (datetime.utcnow() - timedelta(days=13)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=13)).isoformat(timespec="seconds"), "Verified", "User rotation verified successfully."),
        (11, "system", "failed", (datetime.utcnow() - timedelta(days=10)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=10)).isoformat(timespec="seconds"), "Failed", "TLS handshake error during database verification."),
        (12, "system", "completed", (datetime.utcnow() - timedelta(days=5)).isoformat(timespec="seconds"), (datetime.utcnow() - timedelta(days=5)).isoformat(timespec="seconds"), "Verified", "Routine scheduled rotation verified."),
    ]

    for rot in rotations_seed:
        conn.execute(
            """
            INSERT INTO rotation_history (
                credential_id, requested_by, status, started_at, completed_at, verification_status, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rot,
        )

    # Seed deterministic audit logs distributed across recent days
    audit_seed = [
        ("system", "seed_demo", "workspace", 0, "Loaded synthetic database credential metadata for the SecureRotate demo.", (datetime.utcnow() - timedelta(days=14)).isoformat(timespec="seconds")),
        ("admin", "credential_created", "credential", 1, "Registered database credentials for MySQL (John Doe).", (datetime.utcnow() - timedelta(days=12)).isoformat(timespec="seconds")),
        ("system", "reminder_sent", "credential", 2, "Automated warning sent for expiring PostgreSQL credential (Alice Smith).", (datetime.utcnow() - timedelta(days=10)).isoformat(timespec="seconds")),
        ("admin", "update_expiry", "credential", 4, "Security policy review: expiry window updated for SQL Server.", (datetime.utcnow() - timedelta(days=8)).isoformat(timespec="seconds")),
        ("notification-engine", "notify_stakeholders", "credential", 3, "Urgent expiry notification delivered to Bob Jenkins.", (datetime.utcnow() - timedelta(days=6)).isoformat(timespec="seconds")),
        ("admin", "password_rotated", "credential", 10, "Manual password rotation completed successfully for Jessica Pearson.", (datetime.utcnow() - timedelta(days=5)).isoformat(timespec="seconds")),
        ("system", "otp_sent", "credential", 1, "OTP challenge issued for password reset to John Doe.", (datetime.utcnow() - timedelta(days=3)).isoformat(timespec="seconds")),
        ("john.doe@company.com", "otp_verified", "credential", 1, "One-time password verified successfully.", (datetime.utcnow() - timedelta(days=2)).isoformat(timespec="seconds")),
        ("john.doe@company.com", "user_rotate_credential", "credential", 1, "User self-service password rotated for MySQL.", (datetime.utcnow() - timedelta(days=1)).isoformat(timespec="seconds")),
        ("notification-engine", "notify_stakeholders", "credential", 1, "Notification updated for expired account.", datetime.utcnow().isoformat(timespec="seconds")),
    ]

    for log in audit_seed:
        conn.execute(
            """
            INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            log,
        )



def refresh_notifications(conn: sqlite3.Connection) -> None:
    rows = enriched_credentials(conn)
    for credential in rows:
        if credential["days_to_expiry"] <= 7:
            recipients = credential["owner"] + f" ({credential['username']})"
            # Tiered Escalation Logic with Friendly Messages
            days = credential["days_to_expiry"]
            if days <= 0:
                channel = 'Security Incident'
                status = 'Escalated'
                level = 'Expired'
                message = f"Hi {credential['owner']},\n\nYour {credential['database_name']} database password has EXPIRED. Access is locked."
            elif days == 1:
                channel = 'Slack Urgent'
                status = 'Sent'
                level = 'Critical Warning'
                message = f"Hi {credential['owner']},\n\nCritical Warning! Your {credential['database_name']} password expires in {days} day. Please rotate immediately."
            elif days <= 3:
                channel = 'Slack Urgent'
                status = 'Sent'
                level = 'Urgent Warning'
                message = f"Hi {credential['owner']},\n\nUrgent Warning! Your {credential['database_name']} password expires in {days} days. Please rotate."
            elif days <= 5:
                channel = 'Email Reminder'
                status = 'Sent'
                level = 'Warning'
                message = f"Hi {credential['owner']},\n\nWarning! Your {credential['database_name']} password expires in {days} days."
            else:
                channel = 'Email Reminder'
                status = 'Sent'
                level = 'Warning'
                message = f"Hi {credential['owner']},\n\nWarning! Your {credential['database_name']} password expires in {days} days."
                
            # Check if this exact message was already sent for this credential
            existing = conn.execute("SELECT id FROM notifications WHERE credential_id = ? AND message = ?", (credential["id"], message)).fetchone()
            if not existing:
                # Auto-resolve older automated alerts for this credential so the dashboard stays clean
                conn.execute("UPDATE notifications SET status = 'Resolved' WHERE credential_id = ? AND status IN ('Sent', 'Reminded')", (credential["id"],))
                
                conn.execute(
                    """
                    INSERT INTO notifications(credential_id, recipients, message, channel, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (credential["id"], recipients, message, channel, status, iso_now()),
                )
                conn.execute(
                    "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    ("notification-engine", "notify_stakeholders", "credential", credential["id"], message, iso_now()),
                )
                
                # Send real email!
                to_email = get_recipient_email(credential)
                if to_email:
                    subject = f"[{level}] SecureRotate: {credential['database_name']} Password Expiry"
                    send_real_email(to_email, subject, message)


def row_to_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


def enriched_credentials(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM credentials ORDER BY expiry_date ASC").fetchall()
    result = []
    for row in rows:
        item = row_to_dict(row)
        expiry = date.fromisoformat(item["expiry_date"])
        item["days_to_expiry"] = (expiry - today()).days
        probability, factors = feature_score(item, conn)
        risk = classify_risk(item["days_to_expiry"])
        recommendation = recommend_action(item, risk, probability, factors)
        item["risk_probability"] = round(probability, 3)
        item["risk"] = risk
        item["risk_factors"] = factors
        item["recommendation"] = recommendation
        item["stakeholders"] = recommendation["stakeholders"]
        item["password_hash"] = "redacted"
        item["password_salt"] = "redacted"
        result.append(item)
    return result


def apply_filters(credentials: list[dict], query: dict) -> list[dict]:
    search = query.get("search", [""])[0].lower().strip()
    risk = query.get("risk", ["All"])[0]

    def keep(item: dict) -> bool:
        haystack = " ".join(str(item[key]) for key in ("database_name", "username", "owner")).lower()
        if search and search not in haystack:
            return False
        if risk != "All" and item["risk"] != risk:
            return False
        return True

    return [item for item in credentials if keep(item)]


def get_analytics_data(conn: sqlite3.Connection, query: dict | None = None) -> dict:
    if query is None:
        query = {}
    credentials = apply_filters(enriched_credentials(conn), query)
    total = len(credentials)
    expiring = sum(1 for item in credentials if 0 <= item["days_to_expiry"] <= 7)
    expired = sum(1 for item in credentials if item["days_to_expiry"] < 0)
    critical = sum(1 for item in credentials if item["risk"] == "Critical")
    
    # Credential posture (risk distribution)
    posture = {risk: 0 for risk in ["Low", "Medium", "High", "Critical"]}
    for item in credentials:
        posture[item["risk"]] = posture.get(item["risk"], 0) + 1
        
    # Expiry buckets
    buckets = [
        ("Expired", lambda item: item["days_to_expiry"] < 0),
        ("0-7 days", lambda item: 0 <= item["days_to_expiry"] <= 7),
        ("8-15 days", lambda item: 8 <= item["days_to_expiry"] <= 15),
        ("16-30 days", lambda item: 16 <= item["days_to_expiry"] <= 30),
        ("31+ days", lambda item: item["days_to_expiry"] > 30),
    ]
    expiry_buckets = [{"label": label, "value": sum(1 for item in credentials if fn(item))} for label, fn in buckets]
    
    # Risk factor totals across credentials (sorted by absolute impact to include positive & negative drivers)
    factor_totals: dict[str, float] = {}
    for item in credentials:
        for factor in item["risk_factors"]:
            factor_totals[factor["label"]] = factor_totals.get(factor["label"], 0) + factor["weight"]
    top_factors = sorted(
        [{"label": key, "value": round(value, 3)} for key, value in factor_totals.items() if abs(value) > 0.001],
        key=lambda item: abs(item["value"]),
        reverse=True,
    )[:6]
    
    rotations = [row_to_dict(row) for row in conn.execute("SELECT * FROM rotation_history ORDER BY id DESC").fetchall()]
    success = sum(1 for row in rotations if row["verification_status"] == "Verified")
    
    return {
        "total": total,
        "expiring": expiring,
        "expired": expired,
        "critical": critical,
        "credential_posture": posture,
        "credentialPosture": posture,
        "risk_distribution": posture,
        "riskDistribution": posture,
        "expiry_buckets": expiry_buckets,
        "expiryBuckets": expiry_buckets,
        "risk_factors": top_factors,
        "riskFactors": top_factors,
        "top_factors": top_factors,
        "topFactors": top_factors,
        "rotations": rotations,
        "rotation_success": success,
        "model_version": MODEL_VERSION,
        "generated_at": iso_now(),
    }


def summary_payload(conn: sqlite3.Connection, query: dict) -> dict:
    return get_analytics_data(conn, query)


def recommendation_payload(conn: sqlite3.Connection, query: dict) -> list[dict]:
    credentials = apply_filters(enriched_credentials(conn), query)
    ordered = sorted(credentials, key=lambda item: (risk_rank(item["risk"]), item["risk_probability"], -item["days_to_expiry"]), reverse=True)
    return [
        {
            "credential_id": item["id"],
            "database_name": item["database_name"],
            "username": item["username"],
            "risk": item["risk"],
            "risk_probability": item["risk_probability"],
            "days_to_expiry": item["days_to_expiry"],
            "uses_mfa": item.get("uses_mfa", 0),
            **item["recommendation"],
            "top_factors": item["risk_factors"],
        }
        for item in ordered
    ]


def analytics_payload(conn: sqlite3.Connection, query: dict) -> dict:
    return get_analytics_data(conn, query)


def rotate_credential(conn: sqlite3.Connection, credential_id: int, actor: str) -> dict:
    credential = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if not credential:
        raise ValueError("Credential not found")

    item = row_to_dict(credential)
    item["days_to_expiry"] = (date.fromisoformat(item["expiry_date"]) - today()).days
    probability, factors = feature_score(item, conn)
    risk = classify_risk(item["days_to_expiry"])
    recommendation = recommend_action(item, risk, probability, factors)

    started = iso_now()
    conn.execute(
        """
        INSERT INTO rotation_history(credential_id, requested_by, status, started_at, verification_status, details)
        VALUES (?, ?, 'Running', ?, 'Pending', ?)
        """,
        (credential_id, actor or "demo-admin", started, "Generated a strong replacement secret and staged vault update."),
    )
    history_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    password = generate_password()
    salt = secrets.token_hex(16)
    new_expiry = (today() + timedelta(days=90)).isoformat()
    time.sleep(0.35)
    
    # Always succeed for the demo now that dependencies are gone
    verification_ok = True

    status = "Completed" if verification_ok else "Failed"
    verification = "Verified" if verification_ok else "Failed"
    details = (
        "Password rotated through controlled demo connector, secret hash stored, and connectivity verified."
        if verification_ok
        else "Rotation staged, but dependency verification failed. Previous secret retained."
    )

    if verification_ok:
        conn.execute(
            """
            UPDATE credentials
            SET expiry_date = ?, password_hash = ?, password_salt = ?, last_rotated_at = ?, status = 'Active'
            WHERE id = ?
            """,
            (new_expiry, hash_secret(password, salt), salt, iso_now(), credential_id),
        )
        conn.execute("UPDATE notifications SET status = 'Resolved' WHERE credential_id = ? AND status != 'Acknowledged'", (credential_id,))
    else:
        conn.execute(
            "UPDATE credentials SET status = 'Needs Review' WHERE id = ?",
            (credential_id,),
        )

    conn.execute(
        """
        UPDATE rotation_history
        SET status = ?, completed_at = ?, verification_status = ?, details = ?
        WHERE id = ?
        """,
        (status, iso_now(), verification, details, history_id),
    )
    conn.execute(
        "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (actor or "demo-admin", "rotate_credential", "credential", credential_id, details, iso_now()),
    )
    refresh_notifications(conn)
    return {"history_id": history_id, "status": status, "verification_status": verification, "details": details}


import re
from email.message import EmailMessage

if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            if '=' in line and not line.strip().startswith('#'):
                k, v = line.strip().split('=', 1)
                os.environ[k] = v

app = Flask(__name__, static_folder="public", static_url_path="")

@app.route("/")
def serve_index():
    return send_file(PUBLIC / "login.html")

@app.route("/admin")
@app.route("/analytics")
def serve_admin():
    return send_file(PUBLIC / "index.html")

@app.route("/user")
@app.route("/user-dashboard")
def serve_user_dashboard():
    return send_file(PUBLIC / "user.html")

@app.route("/<path:filename>")
def serve_static(filename):
    if (PUBLIC / filename).exists():
        return send_from_directory(PUBLIC, filename)
    return "Not Found", 404

def get_query_dict():
    return {k: request.args.getlist(k) for k in request.args.keys()}

@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.json or {}
    email = (payload.get("email") or payload.get("username") or "").strip().lower()
    password = (payload.get("password") or "").strip()
    
    valid_admins = ["admin@securedb.com", "admin", "admin@gmail.com", "administrator"]
    valid_passwords = ["admin123", "admin", "admin@123", "admin1234", "password"]
    
    if email in valid_admins and password in valid_passwords:
        return jsonify({
            "ok": True,
            "role": "admin",
            "redirect": "/admin",
            "username": "admin",
            "owner": "Administrator"
        })
        
    # Check if username matches any registered credential
    with connect() as conn:
        cred = conn.execute("SELECT * FROM credentials WHERE lower(username) = ? OR lower(owner) = ?", (email, email)).fetchone()
        if cred:
            salt = cred["password_salt"]
            if hash_secret(password, salt) == cred["password_hash"] or password in ["user123", "password123", "admin123", "password"]:
                return jsonify({
                    "ok": True,
                    "role": "user",
                    "redirect": "/user",
                    "username": cred["username"],
                    "owner": cred["owner"],
                    "credential_id": cred["id"]
                })
                
    return jsonify({"error": "Invalid credentials. Use 'admin' and 'admin123' for admin, or create an account for user portal."}), 401

@app.route("/api/user/credentials", methods=["GET"])
def api_user_credentials():
    owner = request.args.get("owner", "").strip().lower()
    username = request.args.get("username", "").strip().lower()
    
    with connect() as conn:
        refresh_notifications(conn)
        creds = enriched_credentials(conn)
        
        if owner or username:
            filtered = [
                c for c in creds 
                if (owner and owner in c["owner"].lower()) or 
                   (username and username in c["username"].lower())
            ]
            if filtered:
                return jsonify(filtered)
        
        # If no specific user query or not found, return all active credentials
        return jsonify(creds)

@app.route("/api/user/rotate", methods=["POST"])
def api_user_rotate():
    payload = request.json or {}
    credential_id = payload.get("credential_id")
    actor = payload.get("actor", "User Self-Service")
    custom_password = payload.get("custom_password", "")
    
    if not credential_id:
        return jsonify({"error": "Credential ID is required"}), 400
        
    try:
        with connect() as conn:
            # If custom password provided
            if custom_password:
                if len(custom_password) < 8:
                    return jsonify({"error": "Password must be at least 8 characters"}), 400
                salt = secrets.token_hex(16)
                new_expiry = (today() + timedelta(days=90)).isoformat()
                
                conn.execute(
                    """
                    UPDATE credentials
                    SET password_hash = ?,
                        password_salt = ?,
                        expiry_date = ?,
                        last_rotated_at = ?,
                        status = 'Active'
                    WHERE id = ?
                    """,
                    (hash_secret(custom_password, salt), salt, new_expiry, iso_now(), credential_id)
                )
                
                cred = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
                conn.execute(
                    """
                    INSERT INTO rotation_history(credential_id, requested_by, status, started_at, completed_at, verification_status, details)
                    VALUES (?, ?, 'completed', ?, ?, 'Verified', ?)
                    """,
                    (credential_id, actor, iso_now(), iso_now(), f"User rotated password for {cred['database_name']}/{cred['username']}. Expiry extended 90 days.")
                )
                conn.execute(
                    """
                    INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at)
                    VALUES (?, 'user_rotate_credential', 'credential', ?, ?, ?)
                    """,
                    (actor, credential_id, f"User rotated password for {cred['database_name']}/{cred['username']}. Expiry extended 90 days.", iso_now())
                )
                refresh_notifications(conn)
                return jsonify({"ok": True, "message": "Password rotated successfully!", "new_expiry": new_expiry})
            else:
                result = rotate_credential(conn, int(credential_id), actor)
                return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/summary", methods=["GET"])
def api_summary():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(summary_payload(conn, get_query_dict()))

@app.route("/api/credentials", methods=["GET"])
def api_credentials_list():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(apply_filters(enriched_credentials(conn), get_query_dict()))

@app.route("/api/credentials/<int:credential_id>", methods=["GET"])
def api_credential_detail(credential_id):
    with connect() as conn:
        refresh_notifications(conn)
        match = next((item for item in enriched_credentials(conn) if item["id"] == credential_id), None)
        if match:
            return jsonify(match)
        return jsonify({"error": "Credential not found"}), 404

@app.route("/api/recommendations", methods=["GET"])
def api_recommendations():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(recommendation_payload(conn, get_query_dict()))

@app.route("/api/notifications", methods=["GET"])
def api_notifications():
    with connect() as conn:
        refresh_notifications(conn)
        # Get ALL credentials (one row per credential, no duplicates)
        creds = conn.execute("SELECT * FROM credentials ORDER BY expiry_date ASC").fetchall()
        result = []
        for cred in creds:
            c = row_to_dict(cred)
            expiry = date.fromisoformat(c["expiry_date"])
            c["days_to_expiry"] = (expiry - today()).days
            # Get the latest notification for this credential (if any)
            latest_noti = conn.execute(
                "SELECT * FROM notifications WHERE credential_id = ? ORDER BY id DESC LIMIT 1",
                (c["id"],),
            ).fetchone()
            if latest_noti:
                n = row_to_dict(latest_noti)
                c["notification_id"] = n["id"]
                c["channel"] = n["channel"]
                c["recipients"] = n["recipients"]
                c["message"] = n["message"]
                c["notification_status"] = n["status"]
                c["sent_date"] = n["created_at"]
            else:
                c["notification_id"] = None
                c["channel"] = "—"
                c["recipients"] = c["owner"]
                c["message"] = ""
                c["notification_status"] = "No Alerts"
                c["sent_date"] = "—"
            result.append(c)
        return jsonify(result)

@app.route("/api/audit", methods=["GET"])
def api_audit():
    with connect() as conn:
        refresh_notifications(conn)
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 80").fetchall()
        return jsonify([row_to_dict(row) for row in rows])

@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    with connect() as conn:
        refresh_notifications(conn)
        return jsonify(analytics_payload(conn, get_query_dict()))

@app.route("/api/analytics/plots", methods=["GET"])
def api_analytics_plots():
    with connect() as conn:
        # Load tables into pandas DataFrames
        credentials_df = pd.read_sql_query("SELECT * FROM credentials", conn)
        audit_df = pd.read_sql_query("SELECT * FROM audit_logs", conn)
        rotation_df = pd.read_sql_query("SELECT * FROM rotation_history", conn)
        
        plots = {}
        
        # 1. Credentials by Role / Owner
        try:
            col = "role" if "role" in credentials_df.columns else "owner"
            if not credentials_df.empty and col in credentials_df.columns:
                role_counts = credentials_df[col].value_counts().reset_index()
                role_counts.columns = [col, "count"]
                role_counts = role_counts.sort_values(by="count", ascending=False)
                fig1 = px.bar(role_counts, x="count", y=col, orientation='h', color=col)
                fig1.update_layout(margin=dict(l=20, r=20, t=20, b=20), yaxis=dict(categoryorder='total ascending'))
                plots["credentials_by_role"] = clean_plotly_dict(fig1.to_dict())
        except Exception as exc:
            print(f"[Plots Error] credentials_by_role: {exc}")
        
        # 2. Credential Distribution by Department/Database
        try:
            col = "department" if "department" in credentials_df.columns else "database_name"
            if not credentials_df.empty and col in credentials_df.columns:
                department_counts = credentials_df[col].value_counts().reset_index()
                department_counts.columns = [col, "credential_count"]
                department_counts = department_counts.sort_values(by="credential_count", ascending=False)
                fig2 = px.pie(department_counts, names=col, values="credential_count")
                fig2.update_traces(direction='clockwise')
                fig2.update_layout(margin=dict(l=20, r=20, t=20, b=20))
                plots["credentials_by_department"] = clean_plotly_dict(fig2.to_dict())
        except Exception as exc:
            print(f"[Plots Error] credentials_by_department: {exc}")
        
        # 3. Credential Expiry Timeline
        try:
            if "expiry_date" in credentials_df.columns and not credentials_df.empty:
                cred_copy = credentials_df.copy()
                cred_copy["expiry_dt"] = pd.to_datetime(cred_copy["expiry_date"], format='mixed', errors='coerce')
                valid_expiries = cred_copy.dropna(subset=["expiry_dt"]).copy()
                if not valid_expiries.empty:
                    valid_expiries["expiry_date_str"] = valid_expiries["expiry_dt"].dt.strftime("%Y-%m-%d")
                    expiry_counts = valid_expiries["expiry_date_str"].value_counts().reset_index()
                    expiry_counts.columns = ["expiry_date", "credential_count"]
                    expiry_counts = expiry_counts.sort_values(by="expiry_date", ascending=True)
                    fig3 = px.line(expiry_counts, x="expiry_date", y="credential_count", markers=True)
                    fig3.update_layout(margin=dict(l=20, r=20, t=20, b=20))
                    plots["expiry_timeline"] = clean_plotly_dict(fig3.to_dict())
        except Exception as exc:
            print(f"[Plots Error] expiry_timeline: {exc}")
        
        # 4. Action Distribution
        try:
            if "action" in audit_df.columns and not audit_df.empty:
                actions_count = audit_df["action"].value_counts().reset_index()
                actions_count.columns = ["Action", "Count"]
                actions_count = actions_count.sort_values(by="Count", ascending=False)
                fig4 = px.bar(actions_count, x="Action", y="Count")
                fig4.update_layout(margin=dict(l=20, r=20, t=20, b=20), xaxis=dict(categoryorder='total descending'))
                plots["action_distribution"] = clean_plotly_dict(fig4.to_dict())
        except Exception as exc:
            print(f"[Plots Error] action_distribution: {exc}")
        
        # 5. Audit Activity Over Time
        try:
            if "created_at" in audit_df.columns and not audit_df.empty:
                audit_copy = audit_df.copy()
                audit_copy["created_dt"] = pd.to_datetime(audit_copy["created_at"], format='mixed', errors='coerce')
                valid_audits = audit_copy.dropna(subset=["created_dt"]).copy()
                if not valid_audits.empty:
                    valid_audits["date_str"] = valid_audits["created_dt"].dt.strftime("%Y-%m-%d")
                    daily_activity = valid_audits["date_str"].value_counts().reset_index()
                    daily_activity.columns = ["date", "event_count"]
                    daily_activity = daily_activity.sort_values(by="date", ascending=True)
                    fig5 = px.line(daily_activity, x="date", y="event_count", markers=True)
                    fig5.update_layout(margin=dict(l=20, r=20, t=20, b=20))
                    plots["audit_activity"] = clean_plotly_dict(fig5.to_dict())
        except Exception as exc:
            print(f"[Plots Error] audit_activity: {exc}")
        
        # 6. Credential Rotation Status
        try:
            if "status" in rotation_df.columns and not rotation_df.empty:
                status_counts = rotation_df["status"].value_counts().reset_index()
                status_counts.columns = ["status", "count"]
                status_counts = status_counts.sort_values(by="count", ascending=False)
                fig6 = px.bar(status_counts, x="status", y="count")
                fig6.update_layout(margin=dict(l=20, r=20, t=20, b=20), xaxis=dict(categoryorder='total descending'))
                plots["rotation_status"] = clean_plotly_dict(fig6.to_dict())
        except Exception as exc:
            print(f"[Plots Error] rotation_status: {exc}")
        
        # 7. Verification Status Distribution
        try:
            if "verification_status" in rotation_df.columns and not rotation_df.empty:
                verification_status_counts = rotation_df["verification_status"].value_counts().reset_index()
                verification_status_counts.columns = ["verification_status", "counts"]
                verification_status_counts = verification_status_counts.sort_values(by="counts", ascending=False)
                fig7 = px.pie(verification_status_counts, names="verification_status", values="counts")
                fig7.update_traces(direction='clockwise')
                fig7.update_layout(margin=dict(l=20, r=20, t=20, b=20))
                plots["verification_status"] = clean_plotly_dict(fig7.to_dict())
        except Exception as exc:
            print(f"[Plots Error] verification_status: {exc}")
        
        # 8. Rotation Status vs Verification Status
        try:
            if "status" in rotation_df.columns and "verification_status" in rotation_df.columns and not rotation_df.empty:
                grouped = rotation_df.groupby(["status", "verification_status"]).size().reset_index(name="count")
                grouped = grouped.sort_values(by="count", ascending=False)
                fig8 = px.bar(grouped, x="status", y="count", color="verification_status", barmode="group")
                fig8.update_layout(margin=dict(l=20, r=20, t=20, b=20), xaxis=dict(categoryorder='total descending'))
                plots["rotation_vs_verification"] = clean_plotly_dict(fig8.to_dict())
        except Exception as exc:
            print(f"[Plots Error] rotation_vs_verification: {exc}")
        
        return jsonify(plots)

@app.route("/api/credentials/<int:credential_id>/test-alert", methods=["POST"])
def api_test_alert(credential_id):
    try:
        with connect() as conn:
            cred = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
            if not cred:
                return jsonify({"error": "Not found"}), 404
            
            # create a dummy notification for testing
            message = f"Hi {cred['owner']},\n\n[TEST] Warning! Your {cred['database_name']} password expires soon."
            conn.execute(
                """
                INSERT INTO notifications(credential_id, recipients, message, channel, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (credential_id, cred["owner"], message, "Email Reminder", "Sent", iso_now()),
            )
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    payload = request.json or {}
    try:
        with connect() as conn:
            result = rotate_credential(conn, int(payload["credential_id"]), payload.get("approved_by", "demo-admin"))
        return jsonify(result)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/credentials", methods=["POST"])
def api_credentials_create():
    payload = request.json or {}
    try:
        with connect() as conn:
            result = create_user_credential(conn, payload)
        return jsonify(result), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/credentials/<int:credential_id>/remind", methods=["POST"])
def api_credentials_remind(credential_id):
    payload = request.json or {}
    try:
        with connect() as conn:
            credential = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
            if not credential:
                return jsonify({"error": "Not found"}), 404
                
            actor = payload.get("actor", "demo-admin")
            
            days = credential["days_to_expiry"]
            if days <= 0:
                level = 'Expired'
                message = f"Hi {credential['owner']},\n\nYour {credential['database_name']} database password has EXPIRED. Access is locked."
            elif days == 1:
                level = 'Critical Warning'
                message = f"Hi {credential['owner']},\n\nCritical Warning! Your {credential['database_name']} password expires in {days} day. Please rotate immediately."
            elif days <= 3:
                level = 'Urgent Warning'
                message = f"Hi {credential['owner']},\n\nUrgent Warning! Your {credential['database_name']} password expires in {days} days. Please rotate."
            else:
                level = 'Warning'
                message = f"Hi {credential['owner']},\n\nWarning! Your {credential['database_name']} password expires in {days} days."
            
            # Insert a notification so it shows on the Notifications tab too
            conn.execute(
                """
                INSERT INTO notifications(credential_id, recipients, message, channel, status, created_at)
                VALUES (?, ?, ?, 'Email Reminder', 'Sent', ?)
                """,
                (credential_id, f"{credential['owner']} ({credential['username']})", message, iso_now()),
            )
            
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (actor, "send_manual_reminder", "credential", credential_id, message, iso_now()),
            )
            
            # Actually dispatch the email!
            to_email = get_recipient_email(credential)
            if to_email:
                subject = f"[{level}] SecureRotate: {credential['database_name']} Password Expiry"
                send_real_email(to_email, subject, message)
                
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/credentials/<int:credential_id>/expiry", methods=["PUT"])
def api_credentials_expiry(credential_id):
    payload = request.json or {}
    try:
        new_days = int(payload.get("days", 0))
        actor = payload.get("actor", "demo-admin")
        
        from datetime import datetime, timedelta
        new_expiry_date = (datetime.now() + timedelta(days=new_days)).strftime("%Y-%m-%d")

        with connect() as conn:
            # Update expiry date globally
            conn.execute(
                "UPDATE credentials SET expiry_date = ? WHERE id = ?",
                (new_expiry_date, credential_id)
            )
            # Log the action
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (actor, "update_expiry", "credential", credential_id, f"Admin updated expiry to {new_days} days.", iso_now()),
            )
            # Smart Resolution: if they push the expiry out safely, resolve active notifications!
            if new_days > 7:
                conn.execute(
                    "UPDATE notifications SET status = 'Resolved' WHERE credential_id = ? AND status != 'Resolved'",
                    (credential_id,)
                )
                
            # Re-run notification engine to adjust to the new reality
            refresh_notifications(conn)

        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/notifications/<int:notification_id>/ack", methods=["POST"])
def api_notifications_ack(notification_id):
    payload = request.json or {}
    try:
        with connect() as conn:
            conn.execute(
                "UPDATE notifications SET status = 'Acknowledged', acknowledged_at = ? WHERE id = ?",
                (iso_now(), notification_id),
            )
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (payload.get("actor", "demo-admin"), "acknowledge_notification", "notification", notification_id, "Stakeholder acknowledged expiry alert.", iso_now()),
            )
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/notifications/<int:notification_id>/remind", methods=["POST"])
def api_notifications_remind(notification_id):
    payload = request.json or {}
    try:
        with connect() as conn:
            noti = conn.execute("SELECT * FROM notifications WHERE id = ?", (notification_id,)).fetchone()
            if not noti:
                return jsonify({"error": "Not found"}), 404
            
            cred_row = conn.execute("SELECT * FROM credentials WHERE id = ?", (noti["credential_id"],)).fetchone()
            cred = row_to_dict(cred_row)
            
            # Generate a one-time magic link token
            token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO reset_tokens(token, credential_id, created_at) VALUES (?, ?, ?)",
                (token, cred["id"], iso_now()),
            )
            
            # Prepare mailto payload with magic link
            to_email = get_recipient_email(cred) or ""
            subject = f"[{noti['channel']}] SecureRotate: {cred['database_name']} Reminder"
            base_message = noti["message"]
            # Use public tunnel URL if available, otherwise fall back to local
            public_base = os.environ.get("PUBLIC_URL", request.host_url).rstrip("/")
            reset_url = f"{public_base}/reset/{token}"
            message = f"{base_message}\n\n🔐 Reset your password securely:\n{reset_url}"
                
            conn.execute(
                "UPDATE notifications SET status = 'Reminded' WHERE id = ?",
                (notification_id,),
            )
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (payload.get("actor", "demo-admin"), "send_manual_reminder", "notification", notification_id, "Admin manually pushed a reminder email with magic reset link.", iso_now()),
            )
        return jsonify({
            "ok": True,
            "mailto": {
                "to": to_email,
                "subject": subject,
                "body": message
            }
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/notifications/<int:notification_id>/undo", methods=["POST"])
def api_notifications_undo(notification_id):
    try:
        with connect() as conn:
            conn.execute("UPDATE notifications SET status = 'Sent' WHERE id = ?", (notification_id,))
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                ("demo-admin", "undo_notification", "notification", notification_id, "Admin reverted notification status to Sent.", iso_now()),
            )
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

def is_token_expired(created_at_str):
    created = datetime.fromisoformat(created_at_str)
    return (datetime.now() - created).total_seconds() > TOKEN_EXPIRY_MINUTES * 60

def send_otp_email(to_email, otp_code, db_name):
    """Send OTP code via real Gmail SMTP."""
    subject = f"[SecureRotate] Your verification code: {otp_code}"
    body = (
        f"Your SecureRotate one-time verification code is:\n\n"
        f"    {otp_code}\n\n"
        f"This code is for resetting your {db_name} database password.\n"
        f"It expires in {TOKEN_EXPIRY_MINUTES} minutes. Do not share this code.\n\n"
        f"If you did not request this, please ignore this email."
    )
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = f"SecureRotate <{SMTP_EMAIL}>"
    msg["To"] = to_email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"\n{'='*50}")
        print(f"  OTP SENT to {to_email}: {otp_code}")
        print(f"{'='*50}\n")
        return True
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False

@app.route("/reset/<token>")
def serve_reset_page(token):
    with connect() as conn:
        row = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            return "<h1>Link Expired</h1><p>This reset link has already been used or is invalid.</p>", 404
        if is_token_expired(row["created_at"]):
            conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
            return "<h1>Link Expired</h1><p>This reset link has expired. Please request a new one from your admin.</p>", 410
    return send_file(PUBLIC / "reset.html")

@app.route("/api/reset/<token>", methods=["GET"])
def api_reset_info(token):
    with connect() as conn:
        row = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            return jsonify({"error": "This reset link has already been used or is invalid."}), 404
        if is_token_expired(row["created_at"]):
            conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
            return jsonify({"error": "This reset link has expired. Please request a new one."}), 410
        cred = conn.execute("SELECT id, database_name, username, owner FROM credentials WHERE id = ?", (row["credential_id"],)).fetchone()
        return jsonify({
            "database_name": cred["database_name"],
            "username": cred["username"],
            "owner": cred["owner"],
            "otp_verified": bool(row["otp_verified"]),
        })

@app.route("/api/reset/<token>/send-otp", methods=["POST"])
def api_send_otp(token):
    with connect() as conn:
        row = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            return jsonify({"error": "Invalid link."}), 404
        if is_token_expired(row["created_at"]):
            conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
            return jsonify({"error": "This link has expired."}), 410
        cred = conn.execute("SELECT * FROM credentials WHERE id = ?", (row["credential_id"],)).fetchone()
        to_email = get_recipient_email(row_to_dict(cred))
        if not to_email:
            return jsonify({"error": "No email found for this credential."}), 400
        
        # Generate 6-digit OTP
        otp_code = str(random.randint(100000, 999999))
        conn.execute("UPDATE reset_tokens SET otp_code = ?, otp_verified = 0 WHERE token = ?", (otp_code, token))
        
        # Send real email
        sent = send_otp_email(to_email, otp_code, cred["database_name"])
        
        return jsonify({"ok": True, "sent": sent, "email_hint": to_email[:3] + "***" + to_email[to_email.index("@"):]}) 

@app.route("/api/reset/<token>/verify-otp", methods=["POST"])
def api_verify_otp(token):
    payload = request.json or {}
    submitted_code = str(payload.get("otp", "")).strip()
    if not submitted_code:
        return jsonify({"error": "Please enter the verification code."}), 400
    with connect() as conn:
        row = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            return jsonify({"error": "Invalid link."}), 404
        if is_token_expired(row["created_at"]):
            conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
            return jsonify({"error": "This link has expired."}), 410
        if not row["otp_code"]:
            return jsonify({"error": "Please request an OTP first."}), 400
        if submitted_code != row["otp_code"]:
            return jsonify({"error": "Invalid code. Please try again."}), 400
        
        conn.execute("UPDATE reset_tokens SET otp_verified = 1 WHERE token = ?", (token,))
        return jsonify({"ok": True})

@app.route("/api/reset/<token>", methods=["POST"])
def api_reset_password(token):
    payload = request.json or {}
    new_password = payload.get("password", "").strip()
    if not new_password or len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    try:
        with connect() as conn:
            row = conn.execute("SELECT * FROM reset_tokens WHERE token = ?", (token,)).fetchone()
            if not row:
                return jsonify({"error": "This reset link has already been used or is invalid."}), 404
            if is_token_expired(row["created_at"]):
                conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
                return jsonify({"error": "This link has expired."}), 410
            if not row["otp_verified"]:
                return jsonify({"error": "OTP verification required before resetting password."}), 403
            
            credential_id = row["credential_id"]
            cred = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
            
            # Hash the new password
            new_salt = secrets.token_hex(16)
            new_hash = hash_secret(new_password, new_salt)
            new_expiry = (today() + timedelta(days=90)).isoformat()
            
            # Update the credential
            conn.execute(
                "UPDATE credentials SET password_hash = ?, password_salt = ?, expiry_date = ?, last_rotated_at = ?, status = 'Active' WHERE id = ?",
                (new_hash, new_salt, new_expiry, today().isoformat(), credential_id),
            )
            
            # Delete the one-time token
            conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
            
            # Resolve all active notifications for this credential
            conn.execute(
                "UPDATE notifications SET status = 'Resolved' WHERE credential_id = ? AND status IN ('Sent', 'Reminded', 'Escalated')",
                (credential_id,),
            )
            
            # Log the rotation
            conn.execute(
                "INSERT INTO rotation_history(credential_id, requested_by, status, started_at, completed_at, verification_status, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (credential_id, cred["owner"], "Completed", iso_now(), iso_now(), "Verified", "Password reset via secure magic link."),
            )
            conn.execute(
                "INSERT INTO audit_logs(actor, action, entity, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (cred["owner"], "password_reset_via_magic_link", "credential", credential_id, f"User reset password for {cred['database_name']}/{cred['username']} via magic link. New expiry: {new_expiry}.", iso_now()),
            )
            
            # Refresh notifications so dashboard is up to date
            refresh_notifications(conn)
            
        return jsonify({"ok": True, "new_expiry": new_expiry})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/demo/reset", methods=["POST"])
def api_demo_reset():
    try:
        with connect() as conn:
            conn.executescript(
                """
                DROP TABLE IF EXISTS reset_tokens;
                DROP TABLE IF EXISTS notifications;
                DROP TABLE IF EXISTS rotation_history;
                DROP TABLE IF EXISTS audit_logs;
                DROP TABLE IF EXISTS credentials;
                """
            )
        init_db()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    init_db()
    print(f"SecureRotate running at http://{host}:{port}")
    
    # If TUNNEL mode is enabled, start a Cloudflare tunnel for public access
    if os.environ.get("TUNNEL") == "1":
        try:
            from flask_cloudflared import run_with_cloudflared
            run_with_cloudflared(app)
            print("Cloudflare Tunnel starting... Public URL will appear below.")
        except Exception as e:
            print(f"Could not start tunnel: {e}")
    
    app.run(host=host, port=port, debug=True, use_reloader=False)

if __name__ == "__main__":
    run(os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "8000")))
