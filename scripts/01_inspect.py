import glob
import numpy as np
import pandas as pd

files = sorted(glob.glob("data/raw/*.parquet"))
print("Files found:", len(files))

frames = []
for f in files:
    df = pd.read_parquet(f)
    df.columns = df.columns.astype(str).str.strip()
    df["source_file"] = f.split("/")[-1]
    print(f"{f.split('/')[-1]:<50} rows={len(df):>8} cols={df.shape[1]}")
    frames.append(df)

data = pd.concat(frames, ignore_index=True)
print("\nTotal shape:", data.shape)

label_col = [c for c in data.columns if c.lower() == "label"]
print("Label column:", label_col)
if label_col:
    print(data[label_col[0]].value_counts())

num = data.select_dtypes(include=[np.number])
print("\ninf values:", int(np.isinf(num).sum().sum()))
print("NaN values:", int(data.isna().sum().sum()))
print("Duplicate rows:", int(data.drop(columns="source_file").duplicated().sum()))

print("\nColumns:")
for i, c in enumerate(data.columns):
    print(i, c, data[c].dtype)
