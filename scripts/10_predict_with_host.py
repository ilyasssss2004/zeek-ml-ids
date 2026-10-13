import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

MODEL_DIR = Path.home() / "ids-project" / "models"
TEST_DIR = Path.home() / "ids-project" / "zeek_out" / "stealth_test" / "stealth_test_slow"
WINDOWS = [10, 30]

def read_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def compute_host_features(conn_df):
    conn_df = conn_df.sort_values("ts").reset_index(drop=True)
    conn_df["ts"] = conn_df["ts"].astype(float)
    for w in WINDOWS:
        conn_df[f"_conn_count_{w}"] = 0
        conn_df[f"_distinct_ports_{w}"] = 0
    for src_ip, group in conn_df.groupby("id.orig_h"):
        idx = group.index.to_numpy()
        ts = group["ts"].to_numpy()
        ports = group["id.resp_p"].to_numpy()
        n = len(ts)
        for w in WINDOWS:
            counts = np.zeros(n, dtype=int)
            distinct = np.zeros(n, dtype=int)
            start = 0
            seen_ports = {}
            for i in range(n):
                while ts[start] < ts[i] - w:
                    p = ports[start]
                    seen_ports[p] = seen_ports.get(p, 0) - 1
                    if seen_ports[p] <= 0:
                        del seen_ports[p]
                    start += 1
                p = ports[i]
                seen_ports[p] = seen_ports.get(p, 0) + 1
                counts[i] = i - start + 1
                distinct[i] = len(seen_ports)
            conn_df.loc[idx, f"_conn_count_{w}"] = counts
            conn_df.loc[idx, f"_distinct_ports_{w}"] = distinct
    return conn_df

model = joblib.load(MODEL_DIR / "best_model.joblib")
feature_cols = joblib.load(MODEL_DIR / "feature_cols.joblib")

flow_df = pd.DataFrame(read_jsonl(TEST_DIR / "flowmeter.log"))
conn_df = pd.DataFrame(read_jsonl(TEST_DIR / "conn.log"))

conn_df = compute_host_features(conn_df)
host_cols = ["uid", "_conn_count_10", "_distinct_ports_10", "_conn_count_30", "_distinct_ports_30"]
merged = flow_df.merge(conn_df[host_cols], on="uid", how="left")
for c in ["_conn_count_10", "_distinct_ports_10", "_conn_count_30", "_distinct_ports_30"]:
    merged[c] = merged[c].fillna(0)

for c in feature_cols:
    if c not in merged.columns:
        merged[c] = 0

X = merged[feature_cols].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

probs = model.predict_proba(X)[:, 1]
preds = (probs >= 0.5).astype(int)

print("Flows:", len(merged))
print("Predicted attack:", (preds == 1).sum())
print("Predicted benign:", (preds == 0).sum())
print("Recall (assuming all rows are attack):", round((preds == 1).mean(), 4))
print("\nHost-window feature values per flow:")
print(merged[["uid", "_conn_count_10", "_distinct_ports_10", "_conn_count_30", "_distinct_ports_30"]])
print("\nProbability distribution:")
print(pd.Series(probs).describe())
