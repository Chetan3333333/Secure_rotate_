import string
import math
import re
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import random
import os

COMMON_PASSWORDS = ["password", "123456", "admin", "qwerty", "letmein", "welcome"]
DICTIONARY_WORDS = ["dragon", "football", "baseball", "monkey", "shadow", "summer", "winter"]

def get_feature_names():
    return [
        "length", "uppercase_count", "lowercase_count", "digit_count", 
        "special_count", "unique_ratio", "repetition_ratio", "entropy",
        "seq_patterns", "key_patterns", "year_patterns", "is_common", 
        "has_dict", "substitution_patterns"
    ]

def extract_features(password: str) -> dict:
    if not password:
        return {k: 0 for k in get_feature_names()}
        
    length = len(password)
    upper_count = sum(1 for c in password if c.isupper())
    lower_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    special_count = sum(1 for c in password if c in string.punctuation)
    
    unique_ratio = len(set(password)) / length if length > 0 else 0
    
    repetition_count = sum(1 for i in range(1, length) if password[i] == password[i-1])
    repetition_ratio = repetition_count / length if length > 0 else 0
    
    # 1. Entropy calculation
    pool_size = 0
    if upper_count > 0: pool_size += 26
    if lower_count > 0: pool_size += 26
    if digit_count > 0: pool_size += 10
    if special_count > 0: pool_size += 32
    entropy = length * math.log2(pool_size) if pool_size > 0 else 0
    
    # 2. Pattern Detection
    seq_patterns = 1 if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg)', password.lower()) else 0
    key_patterns = 1 if re.search(r'(qwe|wer|ert|asd|sdf|zxc|xcv)', password.lower()) else 0
    year_patterns = 1 if re.search(r'(19|20)\d{2}$', password) else 0
    
    # 3. Dictionary & Common checks
    is_common = 1 if password.lower() in COMMON_PASSWORDS else 0
    has_dict = 1 if any(word in password.lower() for word in DICTIONARY_WORDS) else 0
    
    # 4. Substitution (a->@, o->0, i->1, e->3, s->$)
    sub_pattern = 1 if re.search(r'[@013$]', password) else 0
    
    return {
        "length": length,
        "uppercase_count": upper_count,
        "lowercase_count": lower_count,
        "digit_count": digit_count,
        "special_count": special_count,
        "unique_ratio": unique_ratio,
        "repetition_ratio": repetition_ratio,
        "entropy": entropy,
        "seq_patterns": seq_patterns,
        "key_patterns": key_patterns,
        "year_patterns": year_patterns,
        "is_common": is_common,
        "has_dict": has_dict,
        "substitution_patterns": sub_pattern
    }

def generate_synthetic_data(n_samples=3000):
    data = []
    labels = []
    
    for _ in range(n_samples // 3):
        # 1. Weak Generator
        pwd = random.choice(COMMON_PASSWORDS) + str(random.randint(1, 99))
        if random.random() > 0.5: pwd = "a" * random.randint(4, 8)
        data.append(extract_features(pwd))
        labels.append("Weak")
        
        # 2. Medium Generator
        word = random.choice(DICTIONARY_WORDS).capitalize()
        pwd = word + str(random.randint(100, 999)) + random.choice(["!", "@", "#", "$"])
        data.append(extract_features(pwd))
        labels.append("Medium")
        
        # 3. Strong Generator
        chars = string.ascii_letters + string.digits + string.punctuation
        pwd = "".join(random.choice(chars) for _ in range(random.randint(12, 24)))
        data.append(extract_features(pwd))
        labels.append("Strong")
        
    return pd.DataFrame(data), labels

def train_and_save_model():
    print("Generating synthetic data (10,000 samples)...")
    X, y = generate_synthetic_data(10000)
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # Save the 'Brain'
    joblib.dump(model, "password_model.pkl")
    print("Success! Model saved to password_model.pkl")

def predict_strength(password: str):
    if not os.path.exists("password_model.pkl"):
        return {"label": "Unknown", "score": 0, "details": {}}
        
    # 1. Live Feature Extraction
    model = joblib.load("password_model.pkl")
    features = extract_features(password)
    df = pd.DataFrame([features])
    
    # 2. Get Probabilities from Random Forest
    classes = model.classes_  # e.g., ['Medium', 'Strong', 'Weak']
    probs = model.predict_proba(df)[0]
    prob_dict = dict(zip(classes, probs))
    
    weak_pct = prob_dict.get("Weak", 0)
    medium_pct = prob_dict.get("Medium", 0)
    strong_pct = prob_dict.get("Strong", 0)
    
    # 3. The Final Score Calculation
    score = (strong_pct * 100) + (medium_pct * 60) + (weak_pct * 15)
    
    # Apply Bonuses and Penalties
    if features["length"] >= 16: score += 8
    if features["special_count"] == 0: score -= 15
    
    # Clamp score between 0 and 100
    score = max(0, min(100, score))
    
    # Re-classify label purely based on final score for consistency
    if score >= 80:
        label = "Strong"
    elif score >= 50:
        label = "Medium"
    else:
        label = "Weak"
        
    return {
        "label": label,
        "score": round(score, 1),
        "details": {
            "entropy": round(features["entropy"], 1),
            "length": features["length"]
        }
    }

if __name__ == "__main__":
    train_and_save_model()
