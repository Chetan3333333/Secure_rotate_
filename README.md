# SecureRotate

**Enterprise database credential lifecycle & security-risk management (prototype)**

SecureRotate helps security teams monitor database credentials that are about to expire, estimate relative security risk with a simple machine-learning model, notify owners, and record simulated rotations and audit events.

> **Important honesty notes**
> - Application data is stored **only in MySQL**.
> - Managed database password rotation is **SIMULATED** (hashes and expiry are updated; no live Oracle/PostgreSQL/etc. password is changed).
> - The ML model was trained and evaluated on a **synthetic** dataset. Metrics are for prototype evaluation only.

---

## 1. Problem

Database credentials (service accounts, admin users, application DB users) often:

- expire without enough warning,
- stay on production systems with weak MFA / privilege posture,
- accumulate ignored reminders,
- lack a clear risk ranking when many credentials exist.

Manual spreadsheets do not scale. Teams need a single place to see expiry, risk, recommended action, and history.

## 2. Solution (what this project does)

1. Admin and regular users log in with session-based authentication.
2. Credentials (engine type, owner, expiry, MFA, privilege, production flag) live in **MySQL**.
3. A **Random Forest** model scores each credential → probability → risk level.
4. Deterministic rules combine ML level + days-to-expiry → recommended action.
5. Notifications are created for expiry thresholds (30 / 14 / 7 / 3 / 1 / 0 days).
6. Owners can complete a secure OTP-based reset (token + hashed OTP).
7. Admin can trigger a **simulated** rotation; history and audit logs are written.
8. Dashboard shows counts, risk distribution, recommendations, notifications, audit.

## 3. Features

| Feature | Status |
|---------|--------|
| User + Admin login | Working |
| User registration | Working |
| MySQL-only storage | Working |
| Credential monitoring | Working |
| Random Forest risk score | Working |
| Risk factor explanations | Working (rule-based + model probability) |
| Recommendations | Working |
| Expiry notifications (idempotent) | Working |
| OTP password reset for owners | Working |
| Simulated rotation + history | Working |
| Audit log | Working |
| Admin dashboard | Working |
| Multi-engine metadata (MySQL, Oracle, PostgreSQL, SQL Server, MariaDB, MongoDB) | Working |

## 4. Architecture

```
Browser (login.html / admin.html / user.html / reset.html)
        │  session cookie + JSON APIs
        ▼
Flask (app.py)
        │
        ├── config.py          environment settings
        ├── database/          MySQL connection + schema
        └── ml/                Random Forest load + predict
                │
                ▼
         MySQL 8.x (application database only)
```

Monitored engines (Oracle, PostgreSQL, …) are **metadata** on credential rows. They are not alternative backends for the app.

## 5. Technology stack (and why)

| Technology | Why it is used |
|------------|----------------|
| **Python + Flask** | Simple, readable web API that a student can explain end-to-end |
| **MySQL** | Reliable relational store for users, credentials, audit; industry standard |
| **PyMySQL** | Lightweight pure-Python MySQL driver |
| **Werkzeug** | Secure password hashing already used by Flask |
| **scikit-learn + joblib** | Classic Random Forest pipeline, easy to train and load |
| **pandas / NumPy** | Dataset handling and feature tables for training |
| **HTML / CSS / JavaScript** | No heavy frontend framework — keeps the demo explainable |

No React, Docker, Redis, Kafka, GraphQL, FastAPI, TensorFlow, etc. Those would add complexity without improving the core demo.

## 6. Database design (MySQL only)

| Table | Purpose |
|-------|---------|
| `app_users` | Login accounts (email, password hash, role, status) |
| `credentials` | Monitored DB accounts (engine, owner, expiry, MFA, privilege, production, hashed secret + salt, vault-style ref) |
| `notifications` | Expiry / risk alerts (threshold, status, ack time) |
| `rotation_history` | Simulated rotation records |
| `audit_logs` | Important actions (no secrets) |
| `reset_tokens` | Single-use reset tokens + hashed OTP + attempt counter |
| `ml_predictions` | Optional stored prediction history |

Foreign keys and indexes are defined in `database/schema_mysql.sql`.

There is **no SQLite** path. If MySQL is unreachable the process exits with a clear error.

## 7. Authentication

- Passwords stored with Werkzeug `generate_password_hash` / `check_password_hash` (PBKDF2).
- Session cookie: `HttpOnly`, `SameSite=Lax`, `Secure` when not in debug mode.
- Role stored in session (`admin` or `user`).
- Admin APIs call `require_admin()` and return 401 if the session is not admin.
- Users cannot call admin endpoints.

## 8. OTP / secure reset flow

1. Admin issues a reminder → single-use time-limited token created.
2. Owner opens `/reset.html?token=...`.
3. Owner requests OTP → 6-digit code generated, **only the hash** is stored.
4. OTP has max attempts (`OTP_MAX_ATTEMPTS`) and token expiry (`TOKEN_EXPIRY_MINUTES`).
5. After successful OTP, owner sets a new secret → hashed, expiry extended, token marked used, rotation history + audit written.
6. Plain OTP is never written to logs. In `FLASK_DEBUG=1` only, the API may return a `debug_otp` field for local testing.

## 9. ML pipeline

**Features used**

- days_to_expiry  
- total / successful / failed rotations  
- reminders_ignored  
- avg_response_hours  
- login_frequency_per_week (proxy in live app; real values in training CSV)  
- password_strength_score  
- uses_mfa, is_privileged, is_production  
- database_name (one-hot)

**Model**

- `RandomForestClassifier` inside a sklearn `Pipeline` with `OneHotEncoder`
- Saved with joblib as `ml/model/rf_breach_model.joblib`
- Version string: `rf-breach-2.0-multidb`

**How probability becomes risk**

| Probability | Risk level |
|-------------|------------|
| < 0.30 | Low |
| < 0.60 | Medium |
| < 0.80 | High |
| ≥ 0.80 | Critical |

**Why Random Forest?**

- Works well on mixed numeric + categorical features  
- Handles non-linear interactions (expiry × ignored reminders × production)  
- Feature importances are easy to inspect  
- No deep-learning stack required for a student project  

**Why ML at all if expiry is deterministic?**

Expiry alone does not capture posture (MFA off, privileged, many ignored reminders, failed past rotations). The model ranks *relative* risk so the team can prioritise. Final actions still use deterministic rules on top of the ML level.

## 10. Dataset (synthetic — be honest)

File: `ml/dataset/ml_training_data_5000.csv` (~5,500 rows).

- Labels (`caused_breach`) are **synthetic** (formula + noise), not real breach cases.
- Columns such as `employee_id`, `department`, `role`, `breach_risk_score` exist in the CSV for context but are **not** fed into the model (avoids leakage).
- Reported test metrics (accuracy ~0.92, ROC-AUC ~0.95, etc.) are **on this synthetic hold-out only**. They must **not** be presented as real-world breach-prediction performance.

Before any production use the model must be retrained on real enterprise telemetry.

## 11. Risk engine (ML + rules)

```
ML probability → risk level
        +
days_to_expiry + criticality flags
        ↓
Recommended action (Monitor / Notify / Schedule rotation / Immediate remediation)
```

Examples:

- Expired or Critical → Immediate Rotation  
- High or ≤ 3 days → Rotate within 24 hours  
- ≤ 30 days → Schedule rotation  
- Otherwise → Monitor  

Stakeholders (owner, security team, CISO, compliance) are attached according to urgency.

## 12. Notifications

Thresholds: **30, 14, 7, 3, 1, 0 (expired)** days.

Before creating a notification the code checks whether an open notification already exists for the same credential + threshold (idempotent).

## 13. Rotation (simulated)

Admin calls `/api/rotate`. The system:

1. Generates a new random secret  
2. Stores PBKDF2 hash + salt only  
3. Extends expiry (e.g. +90 days)  
4. Writes `rotation_history` and `audit_logs`  
5. Marks related notifications resolved  

**Plaintext is never returned or logged.** The UI and API clearly state that rotation is simulated.

## 14. Security measures (practical)

- Parameterized SQL only (PyMySQL)  
- No plaintext application or managed passwords stored  
- OTP hashed; attempt limit; single-use token; time limit  
- Session role checks on admin routes  
- Secrets and tokens not written to audit details or logs  
- Environment-based configuration (`.env`)  

This is a **prototype**. It is not a hardened production product (no full CSRF middleware, rate limiting, WAF, etc.).

## 15. Project structure

```
SecureRotate/
├── app.py                 # Flask routes + business logic
├── config.py              # Settings from environment
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── database/
│   ├── connection.py      # MySQL helpers (no SQLite)
│   └── schema_mysql.sql
├── ml/
│   ├── train_model.py     # Offline training script
│   ├── predict.py         # Load model + score + factors
│   ├── dataset/
│   │   └── ml_training_data_5000.csv
│   └── model/
│       ├── rf_breach_model.joblib
│       └── model_meta.json
└── public/
    ├── login.html         # Unified user + admin login
    ├── admin.html         # Admin dashboard
    ├── user.html          # Simple user portal
    ├── reset.html         # OTP reset flow
    ├── app.js             # Dashboard logic
    └── styles.css
```

## 16. Installation & run (Windows CMD)

### Prerequisites

- Python 3.10+  
- MySQL 8.x running locally  
- Git (optional)

### Steps

```cmd
cd SecureRotate

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

copy .env.example .env
notepad .env
```

Edit `.env` and set at least:

```
MYSQL_PASSWORD=your_mysql_password
SECRET_KEY=some-long-random-string
ADMIN_PASSWORD=ChangeMeNow123!
```

Create the database and load schema:

```cmd
mysql -u root -p -e "CREATE DATABASE securerotate CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p securerotate < database\schema_mysql.sql
```

Run:

```cmd
python app.py
```

Open: http://127.0.0.1:8000

- Default admin email comes from `ADMIN_EMAIL` (default `admin@securedb.com`).
- Register a normal user from the login page if needed.

## 17. Demo workflow for Cognizant

1. Start MySQL and `python app.py`.
2. Open login page → Admin login with seeded credentials.
3. Dashboard: total / expiring / critical / expired metrics and risk bars.
4. Open Recommendations → show risk level, factors, suggested action.
5. Open Notifications → acknowledge or send reminder (creates reset link).
6. Copy reset URL → open in another browser/incognito → request OTP (debug mode shows OTP if `FLASK_DEBUG=1`) → verify → set new password.
7. Back in admin → trigger **Simulated Rotation** on a credential → show rotation history + audit entry.
8. Explicitly say: “Rotation is simulated; the model was trained on synthetic data.”

## 18. Limitations (say these in the interview)

- MySQL must be available; no SQLite fallback.  
- Rotation does not change real remote database passwords.  
- ML metrics are on synthetic data only.  
- `login_frequency_per_week` is a simple proxy in the live app (real telemetry would replace it).  
- No full rate limiting / CSRF token framework / multi-factor for the app itself.  
- Frontend is vanilla JS (intentionally simple).  

## 19. Future improvements (realistic)

- Real rotation connectors (per engine) behind a clear interface  
- Retrain on real security telemetry  
- Rate limiting and stronger session controls  
- Optional SHAP or richer explanations once data is real  
- Email delivery as the default path for OTP and alerts  

## 20. License / academic use

Built as a student / hackathon prototype for learning and demonstration. Not for production deployment without substantial hardening and real data.
