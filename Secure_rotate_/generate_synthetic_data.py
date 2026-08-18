"""
SecureRotate - Synthetic Data Generator
========================================
This script does TWO things:
1. Inserts realistic dummy data into securerotate.db (the project database)
2. Exports the exact same data as CSV files so your teammate can use it for ML

Run this script ONCE:  python generate_synthetic_data.py
"""

import sqlite3
import secrets
import hashlib
import os
import csv
import random
from datetime import date, datetime, timedelta

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DB_PATH = "securerotate.db"
OUTPUT_DIR = "datasets"  # Folder where CSV files will be saved

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS (same as app.py so the data is compatible)
# ---------------------------------------------------------------------------
def today():
    return date.today()

def iso_now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def hash_secret(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt.encode(), 600_000).hex()

def generate_password():
    return secrets.token_urlsafe(16)

# ---------------------------------------------------------------------------
# REALISTIC EMPLOYEE DATA
# ---------------------------------------------------------------------------
EMPLOYEES = [
    # (name, email, department, role)
    ("Arjun Mehta", "arjun.mehta@techcorp.in", "Engineering", "Senior Developer"),
    ("Priya Sharma", "priya.sharma@techcorp.in", "Engineering", "Junior Developer"),
    ("Rahul Gupta", "rahul.gupta@techcorp.in", "Engineering", "DevOps Engineer"),
    ("Sneha Patel", "sneha.patel@techcorp.in", "Engineering", "Backend Developer"),
    ("Vikram Singh", "vikram.singh@techcorp.in", "Engineering", "Tech Lead"),
    ("Ananya Reddy", "ananya.reddy@techcorp.in", "Data Science", "Data Analyst"),
    ("Karthik Nair", "karthik.nair@techcorp.in", "Data Science", "ML Engineer"),
    ("Deepika Iyer", "deepika.iyer@techcorp.in", "QA", "QA Engineer"),
    ("Rohit Kumar", "rohit.kumar@techcorp.in", "QA", "QA Lead"),
    ("Meera Joshi", "meera.joshi@techcorp.in", "Infrastructure", "DBA"),
    ("Sanjay Verma", "sanjay.verma@techcorp.in", "Infrastructure", "SysAdmin"),
    ("Neha Agarwal", "neha.agarwal@techcorp.in", "Infrastructure", "Cloud Engineer"),
    ("Amit Tiwari", "amit.tiwari@techcorp.in", "Security", "Security Analyst"),
    ("Pooja Mishra", "pooja.mishra@techcorp.in", "Security", "CISO"),
    ("Rajesh Khanna", "rajesh.khanna@techcorp.in", "Finance", "Finance Manager"),
    ("Divya Saxena", "divya.saxena@techcorp.in", "HR", "HR Manager"),
    ("Manish Dubey", "manish.dubey@techcorp.in", "Engineering", "Intern"),
    ("Kavita Rao", "kavita.rao@techcorp.in", "Engineering", "Intern"),
    ("Suresh Pandey", "suresh.pandey@techcorp.in", "Operations", "Ops Manager"),
    ("Lakshmi Menon", "lakshmi.menon@techcorp.in", "Data Science", "Senior Analyst"),
]

DATABASE_TYPES = ["MySQL", "PostgreSQL", "Oracle", "SQL Server", "MongoDB", "Redis", "MariaDB", "CockroachDB"]

NOTIFICATION_STATUSES = ["Pending", "Sent", "Reminded", "Escalated", "Secure"]
CHANNELS = ["Email Reminder", "Slack Urgent", "Security Incident", "Teams Alert"]

# ---------------------------------------------------------------------------
# STEP 1: Generate Credentials (50 database entries)
# ---------------------------------------------------------------------------
def generate_credentials():
    """Create 50 realistic database credentials with varied expiry dates."""
    credentials = []
    
    for i in range(50):
        emp = random.choice(EMPLOYEES)
        db_type = random.choice(DATABASE_TYPES)
        
        # Create varied expiry dates:
        # - Some already expired (negative days) -> Critical
        # - Some expiring very soon (1-7 days) -> Warning  
        # - Some expiring in 2-4 weeks -> Caution
        # - Some safe (30+ days) -> Safe
        expiry_distribution = random.choices(
            ["expired", "critical", "warning", "caution", "safe"],
            weights=[15, 10, 15, 20, 40],  # 15% expired, 10% critical, etc.
            k=1
        )[0]
        
        if expiry_distribution == "expired":
            days_offset = random.randint(-30, -1)      # Already expired
        elif expiry_distribution == "critical":
            days_offset = random.randint(1, 3)          # 1-3 days left
        elif expiry_distribution == "warning":
            days_offset = random.randint(4, 7)          # 4-7 days left
        elif expiry_distribution == "caution":
            days_offset = random.randint(8, 30)         # 8-30 days left
        else:
            days_offset = random.randint(31, 120)       # Safe (31-120 days)
        
        expiry_date = (today() + timedelta(days=days_offset)).isoformat()
        created_days_ago = random.randint(30, 365)      # Created 1-12 months ago
        created_at_date = today() - timedelta(days=created_days_ago)
        last_rotated_days_ago = random.randint(1, created_days_ago)
        last_rotated_date = today() - timedelta(days=last_rotated_days_ago)
        
        salt = secrets.token_hex(16)
        password = generate_password()
        
        credentials.append({
            "database_name": db_type,
            "username": emp[1],
            "owner": emp[0],
            "expiry_date": expiry_date,
            "status": "Active",
            "secret_ref": f"vault://securerotate/{db_type.lower().replace(' ', '_')}/{emp[1]}",
            "password_hash": hash_secret(password, salt),
            "password_salt": salt,
            "last_rotated_at": last_rotated_date.isoformat(),
            "created_at": datetime.combine(created_at_date, datetime.min.time()).isoformat(timespec="seconds") + "Z",
            "days_to_expiry": days_offset,
            # Extra fields for ML dataset (not stored in DB, only in CSV)
            "department": emp[2],
            "role": emp[3],
            "email": emp[1],
        })
    
    return credentials


# ---------------------------------------------------------------------------
# STEP 2: Generate Rotation History (past password changes)
# ---------------------------------------------------------------------------
def generate_rotation_history(credentials):
    """For each credential, generate 0-5 past rotation events over 6 months."""
    history = []
    
    for i, cred in enumerate(credentials):
        num_rotations = random.choices([0, 1, 2, 3, 4, 5], weights=[10, 25, 30, 20, 10, 5], k=1)[0]
        
        for j in range(num_rotations):
            days_ago = random.randint(7, 180)   # Happened 1 week to 6 months ago
            started = today() - timedelta(days=days_ago)
            completed = started + timedelta(minutes=random.randint(1, 30))
            
            status = random.choices(["completed", "failed", "timeout"], weights=[80, 15, 5], k=1)[0]
            verification = "passed" if status == "completed" else "failed"
            
            actors = ["system", "admin", cred["owner"], "cron_worker"]
            
            history.append({
                "credential_id": i + 1,
                "requested_by": random.choice(actors),
                "status": status,
                "started_at": datetime.combine(started, datetime.min.time()).isoformat(timespec="seconds") + "Z",
                "completed_at": datetime.combine(completed, datetime.min.time()).isoformat(timespec="seconds") + "Z" if status != "timeout" else None,
                "verification_status": verification,
                "details": f"Password rotation {status} for {cred['database_name']} ({cred['owner']})",
            })
    
    return history


# ---------------------------------------------------------------------------
# STEP 3: Generate Audit Logs (admin actions over 6 months)
# ---------------------------------------------------------------------------
def generate_audit_logs(credentials):
    """Generate realistic audit trail entries."""
    logs = []
    actions = [
        ("credential_created", "Created new database credential"),
        ("reminder_sent", "Sent expiry reminder email"),
        ("password_rotated", "Password was successfully rotated"),
        ("magic_link_generated", "Generated a magic reset link"),
        ("otp_sent", "OTP verification code sent via email"),
        ("otp_verified", "OTP verified successfully"),
        ("login_attempt", "Admin login attempt"),
        ("alert_triggered", "Security alert triggered for expired credential"),
    ]
    
    for i in range(120):  # 120 audit log entries over 6 months
        cred = random.choice(credentials)
        cred_index = credentials.index(cred) + 1
        action_type, detail = random.choice(actions)
        days_ago = random.randint(0, 180)
        
        logs.append({
            "actor": random.choice(["admin", "system", "cron_worker", cred["owner"]]),
            "action": action_type,
            "entity": "credential",
            "entity_id": cred_index,
            "details": f"{detail} - {cred['database_name']} ({cred['owner']})",
            "created_at": (datetime.utcnow() - timedelta(days=days_ago)).isoformat(timespec="seconds") + "Z",
        })
    
    return logs


# ---------------------------------------------------------------------------
# STEP 4: Generate ML Training Dataset (the smart part!)
# ---------------------------------------------------------------------------
def generate_ml_dataset(credentials, rotation_history):
    """
    Create the ML-ready dataset.
    Each row represents ONE employee's behavior profile.
    The ML model will use these features to predict breach risk.
    """
    ml_data = []
    
    for i, cred in enumerate(credentials):
        cred_id = i + 1
        
        # Count how many times this credential was rotated
        rotations_for_cred = [r for r in rotation_history if r["credential_id"] == cred_id]
        total_rotations = len(rotations_for_cred)
        successful_rotations = len([r for r in rotations_for_cred if r["status"] == "completed"])
        failed_rotations = len([r for r in rotations_for_cred if r["status"] == "failed"])
        
        # Calculate behavioral features
        days_to_expiry = cred["days_to_expiry"]
        
        # Simulate how many reminders were ignored (realistic pattern)
        if days_to_expiry < 0:
            reminders_ignored = random.randint(3, 8)    # Expired = ignored many
        elif days_to_expiry <= 7:
            reminders_ignored = random.randint(1, 4)    # About to expire = ignored some
        else:
            reminders_ignored = random.randint(0, 2)    # Safe = ignored few
        
        # Average response time (hours to respond to reminder)
        if cred["role"] in ["Intern", "Junior Developer"]:
            avg_response_hours = random.randint(24, 168)  # Interns take 1-7 days
        elif cred["role"] in ["Senior Developer", "Tech Lead", "CISO"]:
            avg_response_hours = random.randint(1, 24)    # Seniors respond quickly
        else:
            avg_response_hours = random.randint(6, 72)    # Middle = 6h to 3 days
        
        # Login frequency (times per week)
        login_frequency = random.randint(1, 25)
        
        # Password strength score (1-10)
        password_strength = random.randint(3, 10)
        
        # Has the employee used MFA? (0 or 1)
        uses_mfa = random.choices([0, 1], weights=[30, 70], k=1)[0]
        
        # THE LABEL: Did this behavior pattern cause a breach? (0 or 1)
        # We simulate this realistically based on the features
        breach_score = 0
        breach_score += reminders_ignored * 12        # Ignoring reminders is dangerous
        breach_score += max(0, -days_to_expiry) * 5   # Expired passwords are dangerous
        breach_score += failed_rotations * 15          # Failed rotations are a red flag
        breach_score -= successful_rotations * 10      # Good rotations reduce risk
        breach_score -= password_strength * 3          # Strong passwords help
        breach_score -= uses_mfa * 20                  # MFA significantly reduces risk
        breach_score += (avg_response_hours / 24) * 5  # Slow responders are risky
        
        # Convert score to probability (0 or 1)
        breach_probability = min(100, max(0, breach_score))
        caused_breach = 1 if breach_probability > 50 else 0
        
        ml_data.append({
            "employee_name": cred["owner"],
            "email": cred["email"],
            "department": cred["department"],
            "role": cred["role"],
            "database_name": cred["database_name"],
            "days_to_expiry": days_to_expiry,
            "total_rotations": total_rotations,
            "successful_rotations": successful_rotations,
            "failed_rotations": failed_rotations,
            "reminders_ignored": reminders_ignored,
            "avg_response_hours": avg_response_hours,
            "login_frequency_per_week": login_frequency,
            "password_strength_score": password_strength,
            "uses_mfa": uses_mfa,
            "breach_risk_score": round(breach_probability, 2),
            "caused_breach": caused_breach,
        })
    
    return ml_data


# ---------------------------------------------------------------------------
# STEP 5: Insert into Database
# ---------------------------------------------------------------------------
def insert_into_database(credentials, rotation_history, audit_logs):
    """Insert all synthetic data into securerotate.db"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print(f"Connected to {DB_PATH}")
    
    # Check current count
    current_count = cursor.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    print(f"Current credentials in DB: {current_count}")
    
    # Insert credentials
    for cred in credentials:
        cursor.execute("""
            INSERT INTO credentials (
                database_name, username, owner, expiry_date, status, secret_ref,
                password_hash, password_salt, last_rotated_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cred["database_name"],
            cred["username"],
            cred["owner"],
            cred["expiry_date"],
            cred["status"],
            cred["secret_ref"],
            cred["password_hash"],
            cred["password_salt"],
            cred["last_rotated_at"],
            cred["created_at"],
        ))
    
    print(f"Inserted {len(credentials)} credentials")
    
    # Insert rotation history
    for rot in rotation_history:
        cursor.execute("""
            INSERT INTO rotation_history (
                credential_id, requested_by, status, started_at, completed_at,
                verification_status, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            rot["credential_id"] + current_count,  # Offset by existing IDs
            rot["requested_by"],
            rot["status"],
            rot["started_at"],
            rot["completed_at"],
            rot["verification_status"],
            rot["details"],
        ))
    
    print(f"Inserted {len(rotation_history)} rotation history records")
    
    # Insert audit logs
    for log in audit_logs:
        cursor.execute("""
            INSERT INTO audit_logs (
                actor, action, entity, entity_id, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            log["actor"],
            log["action"],
            log["entity"],
            log["entity_id"] + current_count,
            log["details"],
            log["created_at"],
        ))
    
    print(f"Inserted {len(audit_logs)} audit log entries")
    
    conn.commit()
    conn.close()
    print("Database updated successfully!\n")


# ---------------------------------------------------------------------------
# STEP 6: Export as CSV files
# ---------------------------------------------------------------------------
def export_to_csv(credentials, rotation_history, audit_logs, ml_data):
    """Export all data as CSV files for your teammate."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 1. Credentials CSV
    cred_file = os.path.join(OUTPUT_DIR, "credentials_data.csv")
    with open(cred_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "database_name", "username", "owner", "expiry_date", "status",
            "last_rotated_at", "created_at", "days_to_expiry", "department", "role", "email"
        ])
        writer.writeheader()
        for cred in credentials:
            writer.writerow({k: cred[k] for k in writer.fieldnames})
    print(f"Exported: {cred_file} ({len(credentials)} rows)")
    
    # 2. Rotation History CSV
    rot_file = os.path.join(OUTPUT_DIR, "rotation_history.csv")
    with open(rot_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "credential_id", "requested_by", "status", "started_at",
            "completed_at", "verification_status", "details"
        ])
        writer.writeheader()
        writer.writerows(rotation_history)
    print(f"Exported: {rot_file} ({len(rotation_history)} rows)")
    
    # 3. Audit Logs CSV
    audit_file = os.path.join(OUTPUT_DIR, "audit_logs.csv")
    with open(audit_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "actor", "action", "entity", "entity_id", "details", "created_at"
        ])
        writer.writeheader()
        writer.writerows(audit_logs)
    print(f"Exported: {audit_file} ({len(audit_logs)} rows)")
    
    # 4. ML Training Dataset CSV (THE IMPORTANT ONE!)
    ml_file = os.path.join(OUTPUT_DIR, "ml_training_data.csv")
    with open(ml_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "employee_name", "email", "department", "role", "database_name",
            "days_to_expiry", "total_rotations", "successful_rotations",
            "failed_rotations", "reminders_ignored", "avg_response_hours",
            "login_frequency_per_week", "password_strength_score", "uses_mfa",
            "breach_risk_score", "caused_breach"
        ])
        writer.writeheader()
        writer.writerows(ml_data)
    print(f"Exported: {ml_file} ({len(ml_data)} rows)")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("  SecureRotate - Synthetic Data Generator")
    print("=" * 60)
    print()
    
    # Generate all data
    print("[1/4] Generating 50 credentials...")
    credentials = generate_credentials()
    
    print("[2/4] Generating rotation history...")
    rotation_history = generate_rotation_history(credentials)
    
    print("[3/4] Generating audit logs...")
    audit_logs = generate_audit_logs(credentials)
    
    print("[4/4] Generating ML training dataset...")
    ml_data = generate_ml_dataset(credentials, rotation_history)
    
    print()
    
    # Insert into database
    print("--- Inserting into Database ---")
    insert_into_database(credentials, rotation_history, audit_logs)
    
    # Export as CSV
    print("--- Exporting CSV Files ---")
    export_to_csv(credentials, rotation_history, audit_logs, ml_data)
    
    print()
    print("=" * 60)
    print("  DONE! Summary:")
    print(f"  - {len(credentials)} credentials added to DB")
    print(f"  - {len(rotation_history)} rotation history records added")
    print(f"  - {len(audit_logs)} audit log entries added")
    print(f"  - {len(ml_data)} ML training rows exported")
    print(f"  - CSV files saved in: ./{OUTPUT_DIR}/")
    print("=" * 60)
