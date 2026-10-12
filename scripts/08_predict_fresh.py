import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

MODEL_DIR = Path.home() / "ids-project" / "models"
LOG_PATH = Path.home() / "ids-project" / "zeek_out" / "final_test" / "flowmeter.log"

model = joblib.load(MODEL_DIR / "best_model.joblib")
feature_cols = joblib.load(MODEL_DIR / "feature_cols.joblib")

rows = []
with open(LOG_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

df = pd.DataFrame(rows)
print("Flows loaded:", len(df))

for c in feature_cols:
    if c not in df.columns:
        df[c] = 0

X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

probs = model.predict_proba(X)[:, 1]
preds = (probs >= 0.5).astype(int)

print("\nPredicted attack:", (preds == 1).sum())
print("Predicted benign:", (preds == 0).sum())
print("Detection rate (recall, assuming this whole file is attack traffic):",
      round((preds == 1).mean(), 4))
print("\nProbability distribution:")
print(pd.Series(probs).describe())
