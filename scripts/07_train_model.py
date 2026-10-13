import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    average_precision_score, roc_auc_score
)
import lightgbm as lgb
import xgboost as xgb

DATA = Path.home() / "ids-project" / "data" / "clean" / "lab_merged_http.parquet"
MODEL_DIR = Path.home() / "ids-project" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_parquet(DATA)
print("Loaded:", df.shape)
print("Columns:", list(df.columns))

# families held out entirely from training -> true generalization test
HOLDOUT_FAMILIES = ["hydra_ssh", "nmap_slow", "nikto", "hydra_ftp", "hping_icmpflood", "mixed_idle"]

non_feature_cols = {"uid", "ts", "id.orig_h", "id.resp_h", "label_binary", "label_family", "source_run"}
# keep proto as a categorical feature if present
cat_cols = [c for c in df.columns if df[c].dtype == object and c not in non_feature_cols]
print("Categorical columns to encode:", cat_cols)

for c in cat_cols:
    df[c] = df[c].astype(str)
    le = LabelEncoder()
    df[c] = le.fit_transform(df[c])

feature_cols = [c for c in df.columns if c not in non_feature_cols]
print("Feature count:", len(feature_cols))

df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")
df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
df[feature_cols] = df[feature_cols].fillna(0)

holdout = df[df["label_family"].isin(HOLDOUT_FAMILIES)]
trainable = df[~df["label_family"].isin(HOLDOUT_FAMILIES)]

print(f"\nTrainable rows: {len(trainable)}  Holdout rows: {len(holdout)}")
print("Trainable binary balance:\n", trainable["label_binary"].value_counts().to_string())

X = trainable[feature_cols]
y = trainable["label_binary"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

n_pos = (y_train == 1).sum()
n_neg = (y_train == 0).sum()
scale_pos_weight = n_neg / max(n_pos, 1)
print(f"\nTrain pos={n_pos} neg={n_neg} scale_pos_weight(for weighting benign up)={1/scale_pos_weight:.2f}")

models = {
    "logistic_regression": LogisticRegression(
        max_iter=2000, class_weight="balanced", n_jobs=-1
    ),
    "random_forest": RandomForestClassifier(
        n_estimators=200, max_depth=12, class_weight="balanced",
        n_jobs=-1, random_state=42
    ),
    "lightgbm": lgb.LGBMClassifier(
        n_estimators=300, learning_rate=0.05, num_leaves=63,
        class_weight="balanced", n_jobs=-1, random_state=42, verbose=-1
    ),
    "xgboost": xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=8,
        scale_pos_weight=1/scale_pos_weight, n_jobs=-1, random_state=42,
        eval_metric="logloss"
    ),
}

results = {}
for name, model in models.items():
    print(f"\n=== Training {name} ===")
    model.fit(X_train, y_train)

    p_test = model.predict_proba(X_test)[:, 1]
    pred_test = (p_test >= 0.5).astype(int)
    pr_auc = average_precision_score(y_test, p_test)
    roc_auc = roc_auc_score(y_test, p_test)
    print(f"Internal test  PR-AUC={pr_auc:.4f}  ROC-AUC={roc_auc:.4f}")
    print(classification_report(y_test, pred_test, target_names=["benign", "attack"]))

    if len(holdout) > 0:
        Xh = holdout[feature_cols]
        yh = holdout["label_binary"]
        ph = model.predict_proba(Xh)[:, 1]
        predh = (ph >= 0.5).astype(int)
        print("Holdout families performance (never trained on):")
        for fam in HOLDOUT_FAMILIES:
            mask = holdout["label_family"] == fam
            if mask.sum() == 0:
                continue
            fam_true = yh[mask]
            fam_pred = predh[mask]
            recall = (fam_pred[fam_true == 1] == 1).mean() if (fam_true == 1).any() else np.nan
            print(f"  {fam:<20} n={mask.sum():<6} recall={recall}")

    results[name] = {
        "model": model,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
    }

best_name = max(results, key=lambda k: results[k]["pr_auc"])
best_model = results[best_name]["model"]
print(f"\n=== WINNER: {best_name} (PR-AUC={results[best_name]['pr_auc']:.4f}) ===")

joblib.dump(best_model, MODEL_DIR / "best_model.joblib")
joblib.dump(feature_cols, MODEL_DIR / "feature_cols.joblib")
print("Saved model to:", MODEL_DIR / "best_model.joblib")

summary = {k: {"pr_auc": v["pr_auc"], "roc_auc": v["roc_auc"]} for k, v in results.items()}
with open(MODEL_DIR / "model_comparison.json", "w") as f:
    json.dump(summary, f, indent=2)
print("\nAll model scores:")
for k, v in summary.items():
    print(f"  {k:<20} PR-AUC={v['pr_auc']:.4f}  ROC-AUC={v['roc_auc']:.4f}")
