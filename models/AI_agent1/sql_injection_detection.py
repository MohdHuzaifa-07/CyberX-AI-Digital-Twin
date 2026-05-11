# ============================================
# SQL Injection Detection Module
# Author: Mohammed Huzaifa
# Project: Cyber Sentinel - AI Cybersecurity Digital Twin
# Description: ML-based SQL injection detection using TF-IDF + Random Forest
# ============================================

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# -------------------- PATHS --------------------
MODEL_PATH = "models/AI_agent1/sql_model.pkl"
VECTORIZER_PATH = "models/AI_agent1/sql_vectorizer.pkl"
DATA_PATH = "models/AI_agent1/advanced_generated_sql_injections.csv"

# -------------------- SAFE SAMPLES --------------------
SAFE_QUERIES = [
    "SELECT * FROM users WHERE id = 1",
    "SELECT name FROM products WHERE price < 100",
    "INSERT INTO orders (user_id, item) VALUES (1, 'book')",
    "UPDATE users SET email = 'test@example.com' WHERE id = 5",
    "DELETE FROM cart WHERE session_id = 'abc123'",
    "SELECT COUNT(*) FROM logs WHERE date = '2024-01-01'",
    "SELECT id, name FROM customers WHERE country = 'India'",
    "SELECT * FROM products WHERE category = 'electronics'",
    "SELECT email FROM users WHERE username = 'john'",
    "INSERT INTO messages (sender, receiver, text) VALUES ('a', 'b', 'hello')",
    "SELECT * FROM orders WHERE status = 'pending'",
    "UPDATE products SET stock = 50 WHERE id = 10",
    "SELECT * FROM employees WHERE department = 'HR'",
    "SELECT salary FROM employees WHERE name = 'Alice'",
    "SELECT * FROM students WHERE grade = 'A'",
    "INSERT INTO feedback (user, comment) VALUES ('bob', 'great service')",
    "SELECT * FROM inventory WHERE quantity > 0",
    "UPDATE accounts SET balance = 1000 WHERE id = 3",
    "SELECT * FROM transactions WHERE amount < 500",
    "SELECT * FROM users WHERE active = 1",
]

# -------------------- TRAIN MODEL --------------------
def train_model():
    print("[*] Training SQL Injection Detection Model...")

    # Load injection payloads
    df_attack = pd.read_csv(DATA_PATH)
    df_attack = df_attack[['Payload']].dropna()
    df_attack['Label'] = 1  # 1 = Attack

    # Create safe samples
    df_safe = pd.DataFrame({'Payload': SAFE_QUERIES, 'Label': 0})  # 0 = Safe

    # Combine
    df = pd.concat([df_attack, df_safe], ignore_index=True).sample(frac=1, random_state=42)

    X = df['Payload']
    y = df['Label']

    # TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4), max_features=5000)
    X_vec = vectorizer.fit_transform(X)

    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

    # Train Random Forest
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[✓] Model Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Attack"]))

    # Save model and vectorizer
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)

    print("[✓] Model saved successfully!")
    return model, vectorizer, acc

# -------------------- LOAD MODEL --------------------
def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        return train_model()

    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)

    return model, vectorizer, None

# -------------------- RUN ON DATASET --------------------
def run_sql_model():
    model, vectorizer, _ = load_model()

    df = pd.read_csv(DATA_PATH)
    df = df[['Payload']].dropna().head(10)

    X_vec = vectorizer.transform(df['Payload'])
    predictions = model.predict(X_vec)
    probabilities = model.predict_proba(X_vec)

    results = []
    for i, row in df.iterrows():
        pred = predictions[i] if i < len(predictions) else 0
        prob = probabilities[i][1] * 100 if i < len(probabilities) else 0
        results.append({
            "Payload": row['Payload'],
            "Result": f"SQL Injection Detected 🚨 ({prob:.1f}%)" if pred == 1 else f"Safe ✅ ({(1-prob/100)*100:.1f}%)"
        })

    return results

# -------------------- LIVE PAYLOAD PREDICTION --------------------
def predict_sql_payload(payload):
    model, vectorizer, _ = load_model()

    X_vec = vectorizer.transform([payload])
    prediction = model.predict(X_vec)[0]
    probability = model.predict_proba(X_vec)[0]

    is_attack = bool(prediction == 1)
    confidence = round(probability[1] * 100 if is_attack else probability[0] * 100, 2)

    return {
        "payload": payload,
        "prediction": "SQL Injection Detected 🚨" if is_attack else "Safe ✅",
        "is_attack": is_attack,
        "confidence": confidence
    }

# -------------------- MAIN --------------------
if __name__ == "__main__":
    train_model()