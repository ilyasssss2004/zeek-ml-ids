import json, random
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

MODEL_DIR = Path.home() / "ids-project" / "models"
BASE = Path.home() / "ids-project" / "zeek_out" / "lab"
MAX_ROWS = 20000
random.seed(42)

model = joblib.load(MODEL_DIR / "best_model.joblib")
feature_cols = joblib.load(MODEL_DIR / "feature_cols.joblib")

def read_jsonl_capped(path, cap):
    reservoir = []
    total = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            if len(reservoir) < cap:
                reservoir.append(json.loads(line))
            else:
                j = random.randint(0, total - 1)
                if j < cap:
                    reservoir[j] = json.loads(line)
    return reservoir

results = []
for folder in sorted(BASE.iterdir()):
    if not folder.is_dir():
        continue
    log_path = folder / "flowmeter.log"
    if not log_path.exists():
        continue
    rows = read_jsonl_capped(log_path, MAX_ROWS)
    if not rows:
        continue
    df = pd.DataFrame(rows)
    del rows
    for c in feature_cols:
        if c not in df.columns:
            df[c] = 0
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)
    is_benign = folder.name.startswith("benign_")
    if is_benign:
        rate = (preds == 0).mean()
        results.append((folder.name, len(df), round(1 - rate, 4), "FP_rate(lower=better)"))
    else:
        rate = (preds == 1).mean()
        results.append((folder.name, len(df), round(rate, 4), "recall(higher=better)"))
    del df, X, probs, preds
    print(f"done: {folder.name}")

res_df = pd.DataFrame(results, columns=["run", "n_flows", "rate", "metric"])
res_df = res_df.sort_values("rate")
pd.set_option("display.width", 120)
pd.set_option("display.max_rows", 100)
print("\n" + res_df.to_string(index=False))

print("\n--- WORST 10 (lowest rate = weakest) ---")
print(res_df.head(10).to_string(index=False))
