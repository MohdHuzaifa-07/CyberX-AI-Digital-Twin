import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
import pickle

base_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(base_dir, "Data_66_featurs.csv")

df = pd.read_csv(file_path)

# All columns except Label are features
X = df.drop("Label", axis=1)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"✅ F1 Score: {f1_score(y_test, y_pred, average='weighted'):.4f}")

# Save model — no vectorizer needed (numeric data, not text)
with open(os.path.join(base_dir, "model.pkl"), "wb") as f:
    pickle.dump(model, f)

# Save feature column names (important for prediction later)
with open(os.path.join(base_dir, "vectorizer.pkl"), "wb") as f:
    pickle.dump(list(X.columns), f)

print("✅ model.pkl and vectorizer.pkl saved!")
