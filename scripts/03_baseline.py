import time
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import average_precision_score, confusion_matrix

df = pd.read_parquet("data/clean/cic_clean.parquet")
ALL = [c for c in df.columns if c not in ("label_family", "label_binary", "source_file")]
FS = {
    "all": ALL,
    "no_dport": [c for c in ALL if c != "Destination Port"],
    "no_dport_no_initwin": [c for c in ALL if c not in
        ("Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward")],
}

def cap_train(d, n_benign=250000, n_attack=150000, seed=42):
    b = d[d.label_binary == 0]
    a = d[d.label_binary == 1]
    b = b.sample(min(len(b), n_benign), random_state=seed)
    a = a.sample(min(len(a), n_attack), random_state=seed)
    return pd.concat([b, a])

def fit(X, y):
    m = lgb.LGBMClassifier(n_estimators=150, learning_rate=0.1, num_leaves=63,
                           subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                           n_jobs=-1, verbose=-1, random_state=42)
    m.fit(X, y)
    return m

def evaluate(m, X, y):
    p = m.predict_proba(X)[:, 1]
    pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "attacks": int(tp + fn),
        "recall": round(tp / max(tp + fn, 1), 4),
        "fpr": round(fp / max(fp + tn, 1), 4),
        "precision": round(tp / max(tp + fp, 1), 4),
        "pr_auc": round(average_precision_score(y, p), 4) if y.nunique() > 1 else np.nan,
    }

rows = []
holdouts = [
    "Friday-Afternoon-PortScan", "Friday-Afternoon-DDoS", "Friday-Morning-Bot",
    "Thursday-Morning-WebAttacks", "Tuesday-WorkingHours", "Wednesday-WorkingHours",
]

for fs_name, cols in FS.items():
    # Split A: random, stratified by family
    tr, te = train_test_split(df, test_size=0.3, random_state=42,
                              stratify=df["label_family"])
    tr = cap_train(tr)
    t0 = time.time()
    m = fit(tr[cols], tr["label_binary"])
    r = evaluate(m, te[cols], te["label_binary"])
    r.update(featureset=fs_name, split="random", test_on="all")
    rows.append(r)
    print(r, f"[{time.time()-t0:.0f}s]", flush=True)

    # Split B: leave one file out
    for f in holdouts:
        te = df[df.source_file == f]
        tr = cap_train(df[df.source_file != f])
        t0 = time.time()
        m = fit(tr[cols], tr["label_binary"])
        r = evaluate(m, te[cols], te["label_binary"])
        r.update(featureset=fs_name, split="holdout_file", test_on=f)
        rows.append(r)
        print(r, f"[{time.time()-t0:.0f}s]", flush=True)

res = pd.DataFrame(rows)[["featureset", "split", "test_on", "attacks",
                          "recall", "fpr", "precision", "pr_auc"]]
res.to_csv("reports/03_baseline_results.csv", index=False)
print("\n", res.to_string(index=False))
