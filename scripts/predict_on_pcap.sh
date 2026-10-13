#!/bin/bash
# usage: ./predict_on_pcap.sh <pcap_path> <label>
PCAP=$1
LABEL=$2
OUTDIR=~/ids-project/zeek_out/fresh_tests/$LABEL

mkdir -p "$OUTDIR"
cd "$OUTDIR"
zeek -C -r "$PCAP" \
  ~/zeek-ml/tools/zeek-flowmeter/scripts/__load__.zeek \
  policy/tuning/json-logs
cd ~/ids-project

python3 - << PYEOF
import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

MODEL_DIR = Path.home() / "ids-project" / "models"
LOG_PATH = Path("$OUTDIR") / "flowmeter.log"

model = joblib.load(MODEL_DIR / "best_model.joblib")
feature_cols = joblib.load(MODEL_DIR / "feature_cols.joblib")

rows = []
with open(LOG_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

if not rows:
    print("NO FLOWS EXTRACTED for $LABEL")
else:
    df = pd.DataFrame(rows)
    for c in feature_cols:
        if c not in df.columns:
            df[c] = 0
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)
    print(f"[$LABEL] flows={len(df)}  predicted_attack={(preds==1).sum()}  predicted_benign={(preds==0).sum()}  recall={round((preds==1).mean(),4)}")
PYEOF
