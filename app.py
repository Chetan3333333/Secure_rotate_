"""
SecureRotate — MySQL-only application.
Credential expiry monitoring, RF risk scoring, notifications, controlled rotation.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import string
from datetime import date, datetime, timedelta
from typing import Any, Optional

from flask import Flask, jsonify, request, send_file, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from config import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    DEBUG,
    FLASK_HOST,
    FLASK_PORT,
    MODEL_VERSION,
    NOTIFY_DAYS,
    PUBLIC,
    SECRET_KEY,
    SMTP_APP_PASSWORD,
    SMTP_EMAIL,
    SMTP_HOST,
    SMTP_PORT,
    TOKEN_EXPIRY_MINUTES,
    OTP_MAX_ATTEMPTS,
)
from database.connection import DatabaseError, db_connection, db_cursor, execute, init_schema, ping
from ml.predict import build_factors, classify_risk, model_version, predict_proba

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("securerotate")

app = Flask(__name__, static_folder=str(PUBLIC), static_url_path="")
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Secure flag only when not running local HTTP debug
app.config["SESSION_COOKIE_SECURE"] = not DEBUG
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def today() -> date:
    return date.today()


def iso_now() -> str:
    return datetime.now().replace(microsecond=0).isoformat(sep=" ")


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


def hash_secret(secret: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt.encode(), 600_000).hex()


def extract_email(text: str) -> Optional[str]:
    m = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", str(text or ""))
    return m.group(0) if m else None


def require_admin():
    """Simple session gate for admin APIs."""
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    return None


def risk_rank(level: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(level, 0)


# ---------------------------------------------------------------------------
# Feature extraction + ML scoring
# ---------------------------------------------------------------------------

def collect_features(cred: dict, conn) -> dict:
    cid = cred["id"]
    with conn.cursor() as cur:
        cur.execute(
            "SELECT status, verification_status FROM rotation_history WHERE credential_id = %s",
            (cid,),
        )
        rotations = cur.fetchall()
        cur.execute(
            "SELECT status, created_at, acknowledged_at FROM notifications WHERE credential_id = %s",
            (cid,),
        )
        notifs = cur.fetchall()

    total = len(rotations)
    successful = sum(1 for r in rotations if r.get("verification_status") == "Verified")
    failed = sum(1 for r in rotations if (r.get("verification_status") or "").lower() == "failed"
                 or (r.get("status") or "").lower() == "failed")
    reminders_ignored = sum(
        1 for n in notifs
        if n.get("status") in ("Sent", "Reminded", "Escalated") and not n.get("acknowledged_at")
    )

    response_hours = []
    for n in notifs:
        if n.get("acknowledged_at") and n.get("created_at"):
            try:
                created = n["created_at"] if isinstance(n["created_at"], datetime) else datetime.fromisoformat(str(n["created_at"]))
                acked = n["acknowledged_at"] if isinstance(n["acknowledged_at"], datetime) else datetime.fromisoformat(str(n["acknowledged_at"]))
                response_hours.append(max(0.0, (acked - created).total_seconds() / 3600))
            except Exception:
                pass
    avg_resp = sum(response_hours) / len(response_hours) if response_hours else 48.0

    pwd_hash = cred.get("password_hash") or ""
    pwd_salt = cred.get("password_salt") or ""
    strength = min(10, max(3, len(pwd_hash) // 16 + (3 if pwd_salt else 0)))

    expiry = cred["expiry_date"]
    if isinstance(expiry, str):
        expiry = date.fromisoformat(expiry[:10])
    days = (expiry - today()).days

    # login_frequency_per_week is not stored in the credentials table yet.
    # Use a simple, explainable proxy for the prototype (production would
    # pull real telemetry). Privileged accounts tend to be used less often.
    login_freq = 8 if int(cred.get("is_privileged") or 0) else 18

    return {
        "days_to_expiry": days,
        "total_rotations": total,
        "successful_rotations": successful,
        "failed_rotations": failed,
        "reminders_ignored": reminders_ignored,
        "avg_response_hours": round(avg_resp, 1),
        "login_frequency_per_week": login_freq,
        "password_strength_score": strength,
        "uses_mfa": int(cred.get("uses_mfa") or 0),
        "is_privileged": int(cred.get("is_privileged") or 0),
        "is_production": int(cred.get("is_production") or 0),
        "database_name": cred.get("database_name") or "MySQL",
    }


def score_credential(cred: dict, conn) -> dict:
    features = collect_features(cred, conn)
    try:
        proba = predict_proba(features)
    except Exception as exc:
        logger.warning("ML predict failed for cred %s: %s", cred.get("id"), exc)
        # Safe fallback based on expiry only
        days = features["days_to_expiry"]
        if days < 0:
            proba = 0.85
        elif days <= 3:
            proba = 0.70
        elif days <= 7:
            proba = 0.55
        elif days <= 30:
            proba = 0.30
        else:
            proba = 0.10
    score, level = classify_risk(proba)
    factors = build_factors(features, proba)
    return {
        "risk_probability": round(proba, 4),
        "risk_score": score,
        "risk_level": level,
        "days_to_expiry": features["days_to_expiry"],
        "factors": factors,
        "model_version": model_version(),
        "features": features,
    }


def recommend_action(days: int, level: str) -> dict:
    """Return a recommendation dict that matches what the dashboard UI expects."""
    if days < 0 or level == "Critical":
        action, urgency = "Immediate Rotation", "Critical" if days >= 0 else "Breach"
        explanation = (
            "Credential is expired or scored Critical. Rotate now and verify connectivity."
            if days >= 0 else
            "Credential has already expired. Immediate remediation is required."
        )
    elif days <= 3 or level == "High":
        action, urgency = "Rotate Within 24 Hours", "High"
        explanation = "High risk or very short expiry window. Schedule controlled rotation within a day."
    elif days <= 7:
        action, urgency = "Rotate Within 24 Hours", "High"
        explanation = "Expiry is inside the seven-day window. Prefer rotation within 24 hours."
    elif days <= 30:
        action, urgency = "Schedule Rotation", "Medium"
        explanation = "Expiry is approaching. Plan rotation with the owner and security team."
    else:
        action, urgency = "Monitor", "Low"
        explanation = "Risk and expiry look healthy. Continue monitoring and keep owners notified."
    stakeholders = ["Account Owner", "Security Team"]
    if level in ("Critical", "High"):
        stakeholders.append("CISO")
    if level == "Critical":
        stakeholders.append("Compliance Team")
    return {
        "action": action,
        "urgency": urgency,
        "explanation": explanation,
        "stakeholders": stakeholders,
        "approval_required": level in ("Critical", "High"),
    }


# ---------------------------------------------------------------------------
# Seed + notifications
# ---------------------------------------------------------------------------

def seed_if_empty(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS c FROM credentials")
        if cur.fetchone()["c"] > 0:
            return
        rows = [
            ("MySQL", "john.doe@company.com", "John Doe", -1, 0, 0, 1),
            ("PostgreSQL", "alice.smith@company.com", "Alice Smith", 2, 1, 0, 1),
            ("Oracle", "bob.jenkins@company.com", "Bob Jenkins", 6, 1, 1, 1),
            ("SQL Server", "sarah.connor@company.com", "Sarah Connor", 9, 0, 0, 1),
            ("MySQL", "mike.ross@company.com", "Mike Ross", 18, 1, 0, 0),
            ("PostgreSQL", "harvey.specter@company.com", "Harvey Specter", 24, 1, 1, 1),
            ("Oracle", "rachel.zane@company.com", "Rachel Zane", 33, 0, 0, 0),
            ("SQL Server", "donna.paulsen@company.com", "Donna Paulsen", 41, 1, 0, 1),
            ("MySQL", "louis.litt@company.com", "Louis Litt", 57, 1, 0, 0),
            ("PostgreSQL", "jessica.pearson@company.com", "Jessica Pearson", 77, 1, 1, 1),
            ("Oracle", "katrina.bennett@company.com", "Katrina Bennett", 4, 0, 1, 1),
            ("MariaDB", "alex.williams@company.com", "Alex Williams", 120, 1, 0, 0),
        ]
        for db, user, owner, days, mfa, priv, prod in rows:
            salt = secrets.token_hex(16)
            secret = generate_password()
            exp = (today() + timedelta(days=days)).isoformat()
            ref = f"vault://securerotate/{db.lower()}/{user}"
            cur.execute(
                """INSERT INTO credentials
                   (database_name, username, owner, expiry_date, status, secret_ref,
                    password_hash, password_salt, last_rotated_at, created_at, uses_mfa, is_privileged, is_production)
                   VALUES (%s,%s,%s,%s,'Active',%s,%s,%s,NULL,%s,%s,%s,%s)""",
                (db, user, owner, exp, ref, hash_secret(secret, salt), salt, iso_now(), mfa, priv, prod),
            )
        # Admin user
        cur.execute("SELECT COUNT(*) AS c FROM app_users WHERE email = %s", (ADMIN_EMAIL,))
        if cur.fetchone()["c"] == 0:
            pwd = ADMIN_PASSWORD
            if not pwd:
                logger.error(
                    "ADMIN_PASSWORD env var is required to seed admin user. "
                    "Credentials were seeded but no admin account was created."
                )
            else:
                cur.execute(
                    "INSERT INTO app_users (email, password_hash, role, status) VALUES (%s,%s,'admin','active')",
                    (ADMIN_EMAIL, generate_password_hash(pwd)),
                )
                logger.warning("Seeded admin user %s — change password in production", ADMIN_EMAIL)
    conn.commit()
    logger.info("Seeded demo credentials")


def refresh_notifications(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM credentials")
        creds = cur.fetchall()
        for cred in creds:
            exp = cred["expiry_date"]
            if isinstance(exp, str):
                exp = date.fromisoformat(exp[:10])
            days = (exp - today()).days
            # Determine threshold
            threshold = None
            for t in sorted(NOTIFY_DAYS):
                if days <= t:
                    threshold = t
                    break
            if threshold is None:
                continue
            # Idempotency: skip if open notification already exists for this threshold
            cur.execute(
                """SELECT id FROM notifications
                   WHERE credential_id = %s AND threshold_days = %s
                     AND status IN ('Sent','Reminded','Escalated') AND acknowledged_at IS NULL
                   LIMIT 1""",
                (cred["id"], threshold),
            )
            if cur.fetchone():
                continue
            if days < 0:
                msg = f"Hi {cred['owner']}, your {cred['database_name']} password has EXPIRED. Access may be locked."
                level = "EXPIRED"
            elif days <= 1:
                msg = f"Hi {cred['owner']}, CRITICAL: {cred['database_name']} password expires in {days} day(s)."
                level = "CRITICAL"
            elif days <= 7:
                msg = f"Hi {cred['owner']}, URGENT: {cred['database_name']} password expires in {days} days."
                level = "URGENT"
            else:
                msg = f"Hi {cred['owner']}, reminder: {cred['database_name']} password expires in {days} days."
                level = "WARNING"
            cur.execute(
                """INSERT INTO notifications
                   (credential_id, recipients, channel, message, status, threshold_days, created_at)
                   VALUES (%s,%s,'email',%s,'Sent',%s,%s)""",
                (cred["id"], f"{cred['owner']} ({cred['username']})", msg, threshold, iso_now()),
            )
            logger.info("Notification created credential=%s threshold=%s level=%s", cred["id"], threshold, level)
    conn.commit()


# ---------------------------------------------------------------------------
# Routes — pages
# ---------------------------------------------------------------------------

@app.route("/")
def serve_index():
    return send_file(PUBLIC / "login.html")



@app.route("/reset")
@app.route("/reset.html")
@app.route("/reset/<token>")
def serve_reset(token=None):
    return send_file(PUBLIC / "reset.html")


@app.route("/user")
def serve_user():
    return send_file(PUBLIC / "user.html")


@app.route("/api/user/profile", methods=["GET"])
def api_user_profile():
    if not session.get("user_id") or session.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "email": session.get("email"),
        "role": session.get("role"),
    })


@app.route("/admin")
def serve_admin():
    return send_file(PUBLIC / "admin.html")


@app.route("/<path:filename>")
def serve_static(filename):
    if (PUBLIC / filename).exists():
        return send_from_directory(PUBLIC, filename)
    return "Not Found", 404


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.json or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    try:
        row = execute(
            "SELECT id, email, password_hash, role, status FROM app_users WHERE email = %s",
            (email,),
            fetch="one",
        )
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503
    if not row or row.get("status") != "active":
        return jsonify({"error": "Invalid credentials"}), 401
    if not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    session.clear()
    session["user_id"] = row["id"]
    session["email"] = row["email"]
    session["role"] = row["role"]
    logger.info("Login success user=%s role=%s", row["email"], row["role"])
    return jsonify({"ok": True, "role": row["role"], "email": row["email"]})



@app.route("/api/register", methods=["POST"])
def api_register():
    """Create a standard user account. Admin accounts are never created here."""
    payload = request.json or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid email address"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    try:
        existing = execute(
            "SELECT id FROM app_users WHERE email = %s",
            (email,),
            fetch="one",
        )
        if existing:
            return jsonify({"error": "An account with this email already exists"}), 409

        execute(
            """INSERT INTO app_users (email, password_hash, role, status)
               VALUES (%s, %s, 'user', 'active')""",
            (email, generate_password_hash(password)),
        )
        return jsonify({"ok": True, "role": "user", "email": email}), 201
    except DatabaseError:
        logger.exception("User registration failed")
        return jsonify({"error": "Unable to create account"}), 503


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me", methods=["GET"])
def api_me():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"email": session.get("email"), "role": session.get("role")})


# ---------------------------------------------------------------------------
# Credentials / dashboard APIs
# ---------------------------------------------------------------------------

@app.route("/api/summary", methods=["GET"])
def api_summary():
    """Dashboard summary. Shape matches what public/app.js expects."""
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            refresh_notifications(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credentials")
                creds = cur.fetchall()
            risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            total = 0
            expired = 0
            expiring = 0  # inside 7-day window (including already expired)
            critical = 0
            for c in creds:
                scored = score_credential(c, conn)
                level = scored["risk_level"]
                risk_distribution[level] = risk_distribution.get(level, 0) + 1
                total += 1
                days = scored["days_to_expiry"]
                if days < 0:
                    expired += 1
                if days <= 7:
                    expiring += 1
                if level == "Critical":
                    critical += 1
            return jsonify({
                "total": total,
                "expiring": expiring,
                "critical": critical,
                "expired": expired,
                "risk_distribution": risk_distribution,
                "model_version": model_version(),
            })
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/credentials", methods=["GET"])
def api_credentials_list():
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            refresh_notifications(conn)
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credentials ORDER BY expiry_date ASC")
                creds = cur.fetchall()
            out = []
            for c in creds:
                scored = score_credential(c, conn)
                item = {k: c[k] for k in c if k not in ("password_hash", "password_salt")}
                item.update(scored)
                rec = recommend_action(scored["days_to_expiry"], scored["risk_level"])
                item.update(rec)
                # Aliases expected by public/app.js
                item["risk"] = scored["risk_level"]
                item["risk_factors"] = scored.get("factors") or []
                item["recommendation"] = rec
                # Approximate credential age from created_at when available
                created = c.get("created_at")
                age = None
                if created:
                    try:
                        if isinstance(created, str):
                            created_dt = datetime.fromisoformat(created.replace(" ", "T"))
                        else:
                            created_dt = created
                        age = max(0, (datetime.now() - created_dt).days)
                    except Exception:
                        age = None
                item["credential_age"] = age if age is not None else "—"
                item["secret_ref"] = item.get("secret_ref", "")
                out.append(item)
            # Optional filters
            risk = request.args.get("risk")
            if risk and risk != "All":
                out = [x for x in out if x.get("risk_level") == risk]
            q = (request.args.get("q") or "").lower()
            if q:
                out = [x for x in out if q in str(x.get("database_name", "")).lower()
                       or q in str(x.get("username", "")).lower()
                       or q in str(x.get("owner", "")).lower()]
            return jsonify(out)
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/credentials", methods=["POST"])
def api_credentials_create():
    deny = require_admin()
    if deny:
        return deny
    payload = request.json or {}
    required = ["database_name", "username", "owner", "expiry_date"]
    for k in required:
        if not str(payload.get(k, "")).strip():
            return jsonify({"error": f"{k} is required"}), 400
    salt = secrets.token_hex(16)
    # Client may send a password for initial hash; never store plaintext
    raw = payload.get("password") or generate_password()
    if len(raw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    ref = f"vault://securerotate/{payload['database_name'].lower()}/{payload['username']}"
    try:
        rid = execute(
            """INSERT INTO credentials
               (database_name, username, owner, expiry_date, status, secret_ref,
                password_hash, password_salt, created_at, uses_mfa, is_privileged, is_production)
               VALUES (%s,%s,%s,%s,'Active',%s,%s,%s,%s,%s,%s,%s)""",
            (
                payload["database_name"].strip(),
                payload["username"].strip(),
                payload["owner"].strip(),
                payload["expiry_date"][:10],
                ref,
                hash_secret(raw, salt),
                salt,
                iso_now(),
                int(payload.get("uses_mfa") or 0),
                int(payload.get("is_privileged") or 0),
                int(payload.get("is_production") or 0),
            ),
            fetch="lastrowid",
        )
        execute(
            """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
               VALUES (%s,'create_credential','credential',%s,%s,%s)""",
            (session.get("email") or "admin", rid, f"Created {payload['database_name']}/{payload['username']}", iso_now()),
        )
        return jsonify({"ok": True, "id": rid})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/recommendations", methods=["GET"])
def api_recommendations():
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credentials")
                creds = cur.fetchall()
            out = []
            for c in creds:
                scored = score_credential(c, conn)
                rec = recommend_action(scored["days_to_expiry"], scored["risk_level"])
                factors = scored["factors"][:5]
                out.append({
                    "id": c["id"],
                    "database_name": c["database_name"],
                    "username": c["username"],
                    "owner": c["owner"],
                    "risk": scored["risk_level"],
                    "risk_level": scored["risk_level"],
                    "risk_score": scored["risk_score"],
                    "risk_probability": scored["risk_probability"],
                    "days_to_expiry": scored["days_to_expiry"],
                    "factors": factors,
                    "top_factors": factors,
                    "risk_factors": factors,
                    "recommendation": rec,
                    **rec,
                })
            out.sort(key=lambda x: -risk_rank(x["risk_level"]))
            return jsonify(out)
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/notifications", methods=["GET"])
def api_notifications():
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            refresh_notifications(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT n.*, c.database_name, c.username, c.owner, c.expiry_date
                       FROM notifications n
                       JOIN credentials c ON c.id = n.credential_id
                       ORDER BY n.id DESC LIMIT 200"""
                )
                rows = cur.fetchall()
            out = []
            for row in rows:
                item = dict(row)
                exp = item.get("expiry_date")
                if isinstance(exp, str):
                    try:
                        exp = date.fromisoformat(exp[:10])
                    except Exception:
                        exp = None
                days = (exp - today()).days if exp else None
                item["days_to_expiry"] = days
                # Aliases expected by the dashboard
                item["notification_id"] = item.get("id")
                item["notification_status"] = item.get("status")
                out.append(item)
            return jsonify(out)
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/notifications/<int:nid>/ack", methods=["POST"])
def api_notif_ack(nid):
    deny = require_admin()
    if deny:
        return deny
    try:
        execute(
            "UPDATE notifications SET status='Acknowledged', acknowledged_at=%s WHERE id=%s",
            (iso_now(), nid),
        )
        execute(
            """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
               VALUES (%s,'acknowledge_notification','notification',%s,%s,%s)""",
            (session.get("email") or "admin", nid, "Notification acknowledged", iso_now()),
        )
        return jsonify({"ok": True})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/audit", methods=["GET"])
def api_audit():
    deny = require_admin()
    if deny:
        return deny
    try:
        rows = execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200", fetch="all")
        return jsonify(rows or [])
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    """Simple analytics for the dashboard bar charts (no Plotly dependency)."""
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credentials")
                creds = cur.fetchall()
            by_engine: dict[str, int] = {}
            by_risk: dict[str, int] = {}
            expiry_buckets = {"Expired": 0, "0-7 days": 0, "8-15 days": 0, "16-30 days": 0, "31+ days": 0}
            factor_counts: dict[str, int] = {}
            for c in creds:
                eng = c.get("database_name") or "Unknown"
                by_engine[eng] = by_engine.get(eng, 0) + 1
                scored = score_credential(c, conn)
                level = scored["risk_level"]
                by_risk[level] = by_risk.get(level, 0) + 1
                days = scored["days_to_expiry"]
                if days < 0:
                    expiry_buckets["Expired"] += 1
                elif days <= 7:
                    expiry_buckets["0-7 days"] += 1
                elif days <= 15:
                    expiry_buckets["8-15 days"] += 1
                elif days <= 30:
                    expiry_buckets["16-30 days"] += 1
                else:
                    expiry_buckets["31+ days"] += 1
                for f in scored.get("factors") or []:
                    label = f.get("label") or "Other"
                    factor_counts[label] = factor_counts.get(label, 0) + 1
            # Top factors as list of {label, value} for the bar renderer
            top_factors = sorted(
                [{"label": k, "value": v} for k, v in factor_counts.items()],
                key=lambda x: -x["value"],
            )[:8]
            return jsonify({
                "by_engine": by_engine,
                "by_risk": by_risk,
                "expiry_buckets": [{"label": k, "value": v} for k, v in expiry_buckets.items()],
                "top_factors": top_factors,
                "model_version": model_version(),
                "total": len(creds),
            })
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    deny = require_admin()
    if deny:
        return deny
    payload = request.json or {}
    cid = payload.get("credential_id")
    if not cid:
        return jsonify({"error": "credential_id required"}), 400
    actor = session.get("email") or payload.get("approved_by") or "admin"
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credentials WHERE id = %s", (cid,))
                cred = cur.fetchone()
                if not cred:
                    return jsonify({"error": "Credential not found"}), 404
                # Simulated controlled rotation — never returns plaintext
                new_secret = generate_password()
                salt = secrets.token_hex(16)
                new_hash = hash_secret(new_secret, salt)
                new_expiry = (today() + timedelta(days=90)).isoformat()
                started = iso_now()
                cur.execute(
                    """UPDATE credentials
                       SET password_hash=%s, password_salt=%s, expiry_date=%s,
                           last_rotated_at=%s, status='Active', updated_at=%s
                       WHERE id=%s""",
                    (new_hash, salt, new_expiry, started, started, cid),
                )
                cur.execute(
                    """INSERT INTO rotation_history
                       (credential_id, requested_by, status, started_at, completed_at, verification_status, details)
                       VALUES (%s,%s,'Completed',%s,%s,'Verified',%s)""",
                    (cid, actor, started, iso_now(),
                     "Simulated rotation: new secret hashed (PBKDF2), vault ref retained, connectivity verified."),
                )
                cur.execute(
                    """UPDATE notifications SET status='Resolved'
                       WHERE credential_id=%s AND status IN ('Sent','Reminded','Escalated')""",
                    (cid,),
                )
                scored = score_credential({**cred, "expiry_date": new_expiry, "password_hash": new_hash, "password_salt": salt}, conn)
                cur.execute(
                    """INSERT INTO audit_logs (actor, action, entity, entity_id, details, risk_score, created_at)
                       VALUES (%s,'rotate_credential','credential',%s,%s,%s,%s)""",
                    (actor, cid, f"Rotated {cred['database_name']}/{cred['username']}; new expiry {new_expiry}",
                     scored["risk_probability"], iso_now()),
                )
            conn.commit()
            # new_secret intentionally discarded — not returned
            return jsonify({
                "ok": True,
                "credential_id": cid,
                "new_expiry": new_expiry,
                "verification_status": "Verified",
                "note": "Rotation simulated; plaintext secret is not returned or logged.",
            })
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503




# ---------------------------------------------------------------------------
# Additional dashboard APIs (compat with frontend)
# ---------------------------------------------------------------------------

@app.route("/api/demo/reset", methods=["POST"])
def api_demo_reset():
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                for table in ("ml_predictions", "reset_tokens", "notifications",
                              "rotation_history", "audit_logs", "credentials"):
                    cur.execute(f"DELETE FROM {table}")
            conn.commit()
            seed_if_empty(conn)
            refresh_notifications(conn)
            execute(
                """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
                   VALUES (%s,'demo_reset','system',0,%s,%s)""",
                (session.get("email") or "admin", "Demo data reset", iso_now()),
            )
        return jsonify({"ok": True})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/credentials/<int:cid>/test-alert", methods=["POST"])
def api_test_alert(cid):
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credentials WHERE id=%s", (cid,))
                cred = cur.fetchone()
                if not cred:
                    return jsonify({"error": "Not found"}), 404
                msg = f"[TEST] Warning for {cred['database_name']}/{cred['username']}"
                cur.execute(
                    """INSERT INTO notifications
                       (credential_id, recipients, channel, message, status, threshold_days, created_at)
                       VALUES (%s,%s,'email',%s,'Sent',NULL,%s)""",
                    (cid, cred["owner"], msg, iso_now()),
                )
                cur.execute(
                    """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
                       VALUES (%s,'test_alert','credential',%s,%s,%s)""",
                    (session.get("email") or "admin", cid, "Test alert sent", iso_now()),
                )
            conn.commit()
        return jsonify({"ok": True})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/credentials/<int:cid>/expiry", methods=["POST"])
def api_set_expiry(cid):
    deny = require_admin()
    if deny:
        return deny
    payload = request.json or {}
    exp = str(payload.get("expiry_date") or "")[:10]
    if not exp:
        return jsonify({"error": "expiry_date required"}), 400
    try:
        execute(
            "UPDATE credentials SET expiry_date=%s, updated_at=%s WHERE id=%s",
            (exp, iso_now(), cid),
        )
        execute(
            """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
               VALUES (%s,'update_expiry','credential',%s,%s,%s)""",
            (session.get("email") or "admin", cid, f"Expiry set to {exp}", iso_now()),
        )
        return jsonify({"ok": True, "expiry_date": exp})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/notifications/<int:nid>/remind", methods=["POST"])
def api_notif_remind(nid):
    deny = require_admin()
    if deny:
        return deny
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM notifications WHERE id=%s", (nid,))
                noti = cur.fetchone()
                if not noti:
                    return jsonify({"error": "Not found"}), 404
                cur.execute("SELECT * FROM credentials WHERE id=%s", (noti["credential_id"],))
                cred = cur.fetchone()
                if not cred:
                    return jsonify({"error": "Credential missing"}), 404
                # Create single-use reset token
                token = secrets.token_urlsafe(32)
                expires = (datetime.now() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
                cur.execute(
                    """INSERT INTO reset_tokens (token, credential_id, created_at, expires_at, used, otp_verified)
                       VALUES (%s,%s,%s,%s,0,0)""",
                    (token, cred["id"], iso_now(), expires),
                )
                cur.execute("UPDATE notifications SET status='Reminded' WHERE id=%s", (nid,))
                cur.execute(
                    """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
                       VALUES (%s,'send_reminder','notification',%s,%s,%s)""",
                    (session.get("email") or "admin", nid, "Manual reminder with reset token issued", iso_now()),
                )
            conn.commit()
        public_base = request.host_url.rstrip("/")
        reset_url = f"{public_base}/reset.html?token={token}"
        # Do not log token
        logger.info("Reminder issued for notification=%s credential=%s", nid, cred["id"])
        return jsonify({"ok": True, "reset_url": reset_url})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/notifications/<int:nid>/undo", methods=["POST"])
def api_notif_undo(nid):
    deny = require_admin()
    if deny:
        return deny
    try:
        execute(
            "UPDATE notifications SET status='Sent', acknowledged_at=NULL WHERE id=%s",
            (nid,),
        )
        return jsonify({"ok": True})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503


# ---------------------------------------------------------------------------
# Secure OTP / magic-link password reset (managed credential rotation by owner)
# ---------------------------------------------------------------------------

def _get_valid_token(token: str):
    row = execute(
        "SELECT * FROM reset_tokens WHERE token=%s",
        (token,),
        fetch="one",
    )
    if not row:
        return None, "Invalid or unknown token"
    if row.get("used"):
        return None, "Token already used"
    exp = row.get("expires_at")
    if exp:
        if isinstance(exp, str):
            exp = datetime.fromisoformat(exp.replace(" ", "T"))
        if datetime.now() > exp:
            return None, "Token expired"
    return row, None


@app.route("/api/reset/<token>", methods=["GET"])
def api_reset_get(token):
    """Validate token and return non-sensitive credential context."""
    row, err = _get_valid_token(token)
    if err:
        return jsonify({"error": err}), 400
    cred = execute(
        "SELECT id, database_name, username, owner, expiry_date FROM credentials WHERE id=%s",
        (row["credential_id"],),
        fetch="one",
    )
    if not cred:
        return jsonify({"error": "Credential not found"}), 404
    return jsonify({
        "ok": True,
        "otp_verified": bool(row.get("otp_verified")),
        "database_name": cred["database_name"],
        "username": cred["username"],
        "owner": cred["owner"],
    })


@app.route("/api/reset/<token>/send-otp", methods=["POST"])
def api_reset_send_otp(token):
    row, err = _get_valid_token(token)
    if err:
        return jsonify({"error": err}), 400
    # Generate 6-digit OTP, store HASH only
    otp_plain = f"{secrets.randbelow(1000000):06d}"
    otp_hash = generate_password_hash(otp_plain)
    execute(
        "UPDATE reset_tokens SET otp_code_hash=%s, otp_attempts=0, otp_verified=0 WHERE token=%s",
        (otp_hash, token),
    )
    # In production send email; for demo log only a redacted notice (never log OTP)
    logger.info("OTP generated for token prefix=%s... (not logged)", token[:6])
    # Optional real email if SMTP configured
    cred = execute(
        "SELECT owner, username, database_name FROM credentials WHERE id=%s",
        (row["credential_id"],),
        fetch="one",
    )
    to_email = extract_email(cred["owner"] if cred else "") or extract_email(cred["username"] if cred else "")
    if to_email and SMTP_EMAIL and SMTP_APP_PASSWORD:
        try:
            import smtplib
            from email.message import EmailMessage
            msg = EmailMessage()
            msg["Subject"] = "SecureRotate verification code"
            msg["From"] = SMTP_EMAIL
            msg["To"] = to_email
            msg.set_content(f"Your SecureRotate verification code is: {otp_plain}\nIt expires in {TOKEN_EXPIRY_MINUTES} minutes.")
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls()
                s.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
                s.send_message(msg)
            logger.info("OTP email sent to %s", to_email)
        except Exception as exc:
            logger.warning("OTP email failed: %s", exc)
    # For local demo without SMTP, return otp ONLY in debug mode
    resp = {"ok": True, "message": "If email is configured, a code was sent."}
    if DEBUG:
        resp["debug_otp"] = otp_plain
    return jsonify(resp)


@app.route("/api/reset/<token>/verify-otp", methods=["POST"])
def api_reset_verify_otp(token):
    row, err = _get_valid_token(token)
    if err:
        return jsonify({"error": err}), 400
    if int(row.get("otp_attempts") or 0) >= OTP_MAX_ATTEMPTS:
        return jsonify({"error": "Too many attempts. Request a new code."}), 429
    payload = request.json or {}
    code = str(payload.get("otp") or "").strip()
    if not code:
        return jsonify({"error": "OTP required"}), 400
    stored_hash = row.get("otp_code_hash")
    if not stored_hash or not check_password_hash(stored_hash, code):
        execute(
            "UPDATE reset_tokens SET otp_attempts=otp_attempts+1 WHERE token=%s",
            (token,),
        )
        return jsonify({"error": "Invalid code"}), 400
    execute(
        "UPDATE reset_tokens SET otp_verified=1, otp_attempts=0 WHERE token=%s",
        (token,),
    )
    return jsonify({"ok": True})


@app.route("/api/reset/<token>", methods=["POST"])
def api_reset_password(token):
    """After OTP verified, set a new managed credential secret (hashed) and extend expiry."""
    row, err = _get_valid_token(token)
    if err:
        return jsonify({"error": err}), 400
    if not row.get("otp_verified"):
        return jsonify({"error": "OTP verification required"}), 403
    payload = request.json or {}
    new_password = str(payload.get("password") or "")
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    salt = secrets.token_hex(16)
    new_hash = hash_secret(new_password, salt)
    new_expiry = (today() + timedelta(days=90)).isoformat()
    try:
        with db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE credentials
                       SET password_hash=%s, password_salt=%s, expiry_date=%s,
                           last_rotated_at=%s, status='Active', updated_at=%s
                       WHERE id=%s""",
                    (new_hash, salt, new_expiry, iso_now(), iso_now(), row["credential_id"]),
                )
                cur.execute(
                    "UPDATE reset_tokens SET used=1 WHERE token=%s",
                    (token,),
                )
                cur.execute(
                    """UPDATE notifications SET status='Resolved'
                       WHERE credential_id=%s AND status IN ('Sent','Reminded','Escalated')""",
                    (row["credential_id"],),
                )
                cur.execute(
                    """INSERT INTO rotation_history
                       (credential_id, requested_by, status, started_at, completed_at, verification_status, details)
                       VALUES (%s,%s,'Completed',%s,%s,'Verified',%s)""",
                    (row["credential_id"], "owner-reset", iso_now(), iso_now(),
                     "SIMULATED ROTATION via secure OTP reset; secret hashed, not logged."),
                )
                cur.execute(
                    """INSERT INTO audit_logs (actor, action, entity, entity_id, details, created_at)
                       VALUES (%s,'password_reset_otp','credential',%s,%s,%s)""",
                    ("owner", row["credential_id"], f"OTP reset; new expiry {new_expiry}", iso_now()),
                )
            conn.commit()
        return jsonify({"ok": True, "new_expiry": new_expiry})
    except DatabaseError as exc:
        return jsonify({"error": str(exc)}), 503



@app.route("/api/health", methods=["GET"])
def api_health():
    ok = ping()
    return jsonify({
        "status": "ok" if ok else "degraded",
        "mysql": ok,
        "model_version": model_version(),
    }), 200 if ok else 503


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def bootstrap() -> None:
    logger.info("Bootstrapping SecureRotate (MySQL-only)")
    if not ping():
        raise SystemExit(
            "FATAL: MySQL is not reachable. Set MYSQL_HOST, MYSQL_PORT, MYSQL_USER, "
            "MYSQL_PASSWORD, MYSQL_DATABASE and ensure the server is running. "
            "SQLite is not supported."
        )
    init_schema()
    with db_connection() as conn:
        seed_if_empty(conn)
        refresh_notifications(conn)
    logger.info("Bootstrap complete. Model=%s", model_version())


if __name__ == "__main__":
    try:
        bootstrap()
    except SystemExit as e:
        print(e)
        raise
    except DatabaseError as e:
        print(f"FATAL database error: {e}")
        raise SystemExit(1)
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=DEBUG, use_reloader=False)
