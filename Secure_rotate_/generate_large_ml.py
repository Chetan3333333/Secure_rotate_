import csv
import random
import os

OUTPUT_DIR = "datasets"
NUM_ROWS = 3000

DEPARTMENTS = ["Engineering", "Data Science", "QA", "Infrastructure", "Security", "Finance", "HR", "Operations"]
ROLES = ["Intern", "Junior Developer", "Developer", "Senior Developer", "Tech Lead", "Manager", "Analyst", "Engineer"]
DATABASES = ["MySQL", "PostgreSQL", "Oracle", "SQL Server", "MongoDB", "Redis", "MariaDB", "CockroachDB"]

def generate_large_ml_dataset():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ml_file = os.path.join(OUTPUT_DIR, "ml_training_data_3000.csv")
    
    with open(ml_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "employee_id", "department", "role", "database_name",
            "days_to_expiry", "total_rotations", "successful_rotations",
            "failed_rotations", "reminders_ignored", "avg_response_hours",
            "login_frequency_per_week", "password_strength_score", "uses_mfa",
            "breach_risk_score", "caused_breach"
        ])
        writer.writeheader()
        
        for i in range(1, NUM_ROWS + 1):
            department = random.choice(DEPARTMENTS)
            role = random.choice(ROLES)
            db_type = random.choice(DATABASES)
            
            # Weighted random expiry
            days_to_expiry = random.randint(-40, 150)
            
            # Base rotation stats
            total_rotations = random.randint(0, 15)
            failed_rotations = random.randint(0, int(total_rotations / 2)) if total_rotations > 0 else 0
            successful_rotations = total_rotations - failed_rotations
            
            # Simulate behavioral patterns
            if days_to_expiry < 0:
                reminders_ignored = random.randint(3, 12)
            elif days_to_expiry <= 7:
                reminders_ignored = random.randint(1, 5)
            else:
                reminders_ignored = random.randint(0, 2)
                
            # Response times
            if role in ["Intern", "Junior Developer"]:
                avg_response_hours = random.randint(24, 168)
            elif role in ["Tech Lead", "Senior Developer", "Manager"]:
                avg_response_hours = random.randint(1, 36)
            else:
                avg_response_hours = random.randint(12, 72)
                
            login_frequency = random.randint(1, 40)
            password_strength = random.randint(2, 10)
            uses_mfa = random.choices([0, 1], weights=[40, 60], k=1)[0]
            
            # Logic to calculate realistic breach correlation
            breach_score = 0
            breach_score += reminders_ignored * 10
            breach_score += max(0, -days_to_expiry) * 4
            breach_score += failed_rotations * 12
            breach_score -= successful_rotations * 8
            breach_score -= password_strength * 4
            breach_score -= uses_mfa * 25
            breach_score += (avg_response_hours / 24) * 4
            
            # Convert to probability and boolean
            breach_probability = min(100, max(0, breach_score))
            
            # Add some randomness so the model actually has to work
            if random.random() < 0.05:  # 5% random noise
                caused_breach = 1 if random.random() > 0.5 else 0
            else:
                caused_breach = 1 if breach_probability > 60 else 0
                
            writer.writerow({
                "employee_id": f"EMP-{str(i).zfill(4)}",
                "department": department,
                "role": role,
                "database_name": db_type,
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
            
    print(f"Successfully generated {NUM_ROWS} rows in {ml_file}")

if __name__ == "__main__":
    generate_large_ml_dataset()
