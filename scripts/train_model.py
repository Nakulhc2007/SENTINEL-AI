"""
SENTINEL-AI — Simple Model Trainer
====================================
Trains a RandomForest classifier on synthetic security logs.
Run AFTER: python scripts/dataset_preparation/run_all.py --only-synthetic

Usage:
    python scripts/train_model.py

Output:
    models/sentinel_model.pkl   ← trained model
    models/model_report.txt     ← accuracy report
"""

import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT      = Path(__file__).resolve().parent.parent
NORM_DIR  = ROOT / "data" / "processed" / "normalized"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

print("\n" + "="*60)
print("  SENTINEL-AI — Model Trainer")
print("="*60)

# ── Step 1: Load all normalized CSV files ─────────────────────────────────────
print("\n[1/5] Loading training data...")
csv_files = list(NORM_DIR.glob("*_ces.csv"))

if not csv_files:
    print("\n  ERROR: No training data found!")
    print("  Run first: python scripts/dataset_preparation/run_all.py --only-synthetic")
    exit(1)

dfs = []
for f in csv_files:
    df = pd.read_csv(f)
    dfs.append(df)
    print(f"  Loaded: {f.name}  ({len(df)} rows)")

data = pd.concat(dfs, ignore_index=True)
print(f"\n  Total rows: {len(data):,}")
print(f"  Attacks   : {data['is_attack'].sum():,}")
print(f"  Normal    : {(~data['is_attack']).sum():,}")

# ── Step 2: Build features ────────────────────────────────────────────────────
print("\n[2/5] Building features...")

# Encode text columns as numbers
le_domain   = LabelEncoder()
le_action   = LabelEncoder()
le_severity = LabelEncoder()
le_domain_val = LabelEncoder()

data["domain_enc"]    = le_domain.fit_transform(data["domain"].fillna("unknown"))
data["action_enc"]    = le_action.fit_transform(data["action"].fillna("unknown"))
data["severity_enc"]  = data["severity"].fillna(0).astype(int)
data["is_attack_int"] = data["is_attack"].astype(int)

# Extract numeric features from extra_fields JSON
def get_extra(row, key, default=0):
    try:
        d = json.loads(row) if isinstance(row, str) else {}
        val = d.get(key, default)
        return float(val) if val is not None else default
    except Exception:
        return default

data["packets"]    = data["extra_fields"].apply(lambda x: get_extra(x, "packets", 0))
data["bytes_val"]  = data["extra_fields"].apply(lambda x: get_extra(x, "bytes", 0))
data["risk_score"] = data["extra_fields"].apply(lambda x: get_extra(x, "risk_score", 0))
data["hour"]       = data["extra_fields"].apply(lambda x: get_extra(x, "hour_of_day", 12))

# Final feature set
FEATURES = [
    "domain_enc",
    "action_enc",
    "severity_enc",
    "packets",
    "bytes_val",
    "risk_score",
    "hour",
]

X = data[FEATURES].fillna(0)
y = data["is_attack_int"]

print(f"  Features used: {FEATURES}")

# ── Step 3: Split into train and test ──────────────────────────────────────────
print("\n[3/5] Splitting data (80% train, 20% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"  Train size : {len(X_train):,}")
print(f"  Test size  : {len(X_test):,}")

# ── Step 4: Train the model ───────────────────────────────────────────────────
print("\n[4/5] Training RandomForest model...")
model = RandomForestClassifier(
    n_estimators=100,   # 100 decision trees
    max_depth=10,
    random_state=42,
    n_jobs=-1,          # use all CPU cores
    class_weight="balanced",  # handles imbalanced attack/normal ratio
)
model.fit(X_train, y_train)
print("  Training complete!")

# ── Step 5: Evaluate and save ─────────────────────────────────────────────────
print("\n[5/5] Evaluating & saving...")
y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=["Normal", "Attack"])

print(f"\n  Accuracy: {acc*100:.1f}%")
print("\n  Classification Report:")
print(report)

# Save the model
model_path = MODEL_DIR / "sentinel_model.pkl"
joblib.dump(model, model_path)
print(f"  Model saved → {model_path}")

# Save metadata alongside model
meta = {
    "features": FEATURES,
    "domain_classes": list(le_domain.classes_),
    "action_classes": list(le_action.classes_),
    "accuracy": round(acc, 4),
    "train_rows": len(X_train),
    "test_rows": len(X_test),
}
joblib.dump(meta, MODEL_DIR / "sentinel_model_meta.pkl")

# Save report
report_path = MODEL_DIR / "model_report.txt"
with open(report_path, "w") as f:
    f.write(f"SENTINEL-AI Model Report\n")
    f.write(f"Accuracy: {acc*100:.1f}%\n\n")
    f.write(report)
print(f"  Report saved → {report_path}")

print("\n" + "="*60)
print(f"  DONE! Model accuracy: {acc*100:.1f}%")
print(f"  Model file: models/sentinel_model.pkl")
print("="*60 + "\n")
