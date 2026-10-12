import glob, re
import numpy as np
import pandas as pd

files = sorted(glob.glob("data/raw/*.parquet"))
frames = []
for f in files:
    df = pd.read_parquet(f)
    df.columns = df.columns.astype(str).str.strip()
    df["source_file"] = f.split("/")[-1].replace(".parquet", "")
    frames.append(df)
data = pd.concat(frames, ignore_index=True)
print("Start:", data.shape)

# 1. drop the duplicated column
data = data.drop(columns=["Fwd Header Length_duplicated_0"], errors="ignore")

# 2. normalize labels (fix the broken character in Web Attack names)
data["Label"] = data["Label"].astype(str).apply(
    lambda s: re.sub(r"Web Attack\W+", "Web Attack - ", s).strip()
)
data = data.rename(columns={"Label": "label_family"})
data["label_binary"] = (data["label_family"] != "BENIGN").astype(int)

feature_cols = [c for c in data.columns
                if c not in ("label_family", "label_binary", "source_file")]

# 3. inf -> NaN, then drop rows with NaN
data[feature_cols] = data[feature_cols].replace([np.inf, -np.inf], np.nan)
n_nan = data[feature_cols].isna().any(axis=1).sum()
data = data.dropna(subset=feature_cols)
print(f"Dropped {n_nan} rows with inf/NaN")

# 4. drop exact duplicates (features + label)
before = len(data)
data = data.drop_duplicates(subset=feature_cols + ["label_family"])
print(f"Dropped {before - len(data)} duplicate rows")

# 5. report negative values (known CICFlowMeter bug), no action yet
neg = (data[feature_cols] < 0).sum()
neg = neg[neg > 0].sort_values(ascending=False)
print("\nColumns with negative values:")
print(neg.to_string())

# 6. downcast to save memory
data[feature_cols] = data[feature_cols].astype("float32")

data.to_parquet("data/clean/cic_clean.parquet", index=False)
print("\nFinal shape:", data.shape)
print("\nLabel family counts:")
print(data["label_family"].value_counts().to_string())
print("\nBinary balance:")
print(data["label_binary"].value_counts(normalize=True).round(4).to_string())
print("\nFamilies per source file:")
print(pd.crosstab(data["source_file"], data["label_family"]).T.to_string())
