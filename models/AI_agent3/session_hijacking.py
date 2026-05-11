# ============================================
# Session Hijacking Detection Module
# Author: Mohd Huzaifa
# Project: Cyber Sentinel - AI Cybersecurity Digital Twin
# Description: ML-based session hijacking detection using RandomForest
# ============================================

import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score

base_dir = os.path.dirname(__file__)
model_path = os.path.join(base_dir, "session_model.pkl")
vectorizer_path = os.path.join(base_dir, "session_vectorizer.pkl")
data_path = os.path.join(base_dir, "LDAP.csv")


# -------------------- TRAIN & SAVE --------------------
def train_session_model():
    if not os.path.exists(data_path):
        return None, None, 0.0, 0.0

    df = pd.read_csv(data_path)
    df.columns = df.columns.str.strip()

    required_columns = ['Flow ID', 'Source IP', 'Destination IP', 'Protocol', 'Label']
    for col in required_columns:
        if col not in df.columns:
            return None, None, 0.0, 0.0

    df['logs'] = df[['Flow ID', 'Source IP', 'Destination IP', 'Protocol']].astype(str).agg(' '.join, axis=1)
    df['label'] = df['Label'].apply(lambda x: 1 if x != 'Normal' else 0)

    vectorizer = CountVectorizer(max_features=500)
    X = vectorizer.fit_transform(df['logs'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100, random_state=42, class_weight='balanced'
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    # Save model and vectorizer separately
    joblib.dump((model, acc, f1), model_path)
    joblib.dump(vectorizer, vectorizer_path)

    return model, vectorizer, acc, f1


# -------------------- LOAD --------------------
def load_session_model():
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        model, acc, f1 = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
        return model, vectorizer, acc, f1

    # Train if not found
    return train_session_model()


# -------------------- RUN ON DATASET --------------------
def run_session_model():
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        model, acc, f1 = joblib.load(model_path)
        return {
            "accuracy": acc,
            "f1_score": f1,
            "model": "RandomForest (loaded)"
        }

    if not os.path.exists(data_path):
        return {
            "accuracy": 0.0,
            "f1_score": 0.0,
            "model": "Not Loaded",
            "error": "LDAP.csv not found"
        }

    model, vectorizer, acc, f1 = train_session_model()

    if model is None:
        return {
            "accuracy": 0.0,
            "f1_score": 0.0,
            "model": "Failed",
            "error": "Training failed"
        }

    return {
        "accuracy": acc,
        "f1_score": f1,
        "model": "RandomForest"
    }


# -------------------- LIVE PAYLOAD PREDICTION --------------------
def predict_session_payload(payload):
    model, vectorizer, acc, f1 = load_session_model()

    if model is None or vectorizer is None:
        # Fallback to keyword matching if model unavailable
        suspicious_keywords = [
            'hijack', 'stolen', 'forged', 'replay', 'fixation',
            'unauthorized', 'anomalous', 'malicious', 'spoofed',
            'csrf', 'xsrf', 'token theft', 'session riding'
        ]
        is_attack = any(k in payload.lower() for k in suspicious_keywords)
        return {
            "payload": payload,
            "prediction": "Session Hijack Detected 🚨" if is_attack else "Safe ✅",
            "is_attack": is_attack,
            "confidence": 75.0
        }

    X_vec = vectorizer.transform([payload])
    prediction = model.predict(X_vec)[0]
    probability = model.predict_proba(X_vec)[0]

    is_attack = bool(prediction == 1)
    confidence = round(probability[1] * 100 if is_attack else probability[0] * 100, 2)

    return {
        "payload": payload,
        "prediction": "Session Hijack Detected 🚨" if is_attack else "Safe ✅",
        "is_attack": is_attack,
        "confidence": confidence
    }


# -------------------- MAIN --------------------
if __name__ == "__main__":
    result = run_session_model()
    print(result)