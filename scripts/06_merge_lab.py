import re, json, random
from pathlib import Path
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

BASE = Path.home() / "ids-project" / "zeek_out" / "lab"
OUT_PATH = Path.home() / "ids-project" / "data" / "clean" / "lab_merged.parquet"
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
MAX_ROWS_PER_FILE = 30000
random.seed(42)

def label_from_name(name):
    is_benign = name.startswith("benign_")
    binary = 0 if is_benign else 1
    family = re.sub(r"^(attack_|benign_)", "", name)
    family = re.sub(r"_run\d+$", "", family)
    return binary, family

def sample_jsonl(path, cap):
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
    return reservoir, total

writer = None
for folder in sorted(BASE.iterdir()):
    if not folder.is_dir():
        continue
    if folder.name.startswith("fresh_") or folder.name.startswith("final_test_"):
        print(f"SKIP (held-out test set, excluded from training): {folder.name}")
        continue
    log_path = folder / "flowmeter.log"
    if not log_path.exists():
        print(f"SKIP (no flowmeter.log): {folder.name}")
        continue
    binary, family = label_from_name(folder.name)
    rows, total = sample_jsonl(log_path, MAX_ROWS_PER_FILE)
    note = f"(sampled {len(rows)} of {total})" if total > MAX_ROWS_PER_FILE else ""

    df = pd.DataFrame(rows)
    del rows
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            df[col] = df[col].astype("float64")
    df["label_binary"] = binary
    df["label_family"] = family
    df["source_run"] = folder.name
    print(f"{folder.name:<35} family={family:<20} binary={binary}  flows={len(df)} {note}")

    table = pa.Table.from_pandas(df, preserve_index=False)
    if writer is None:
        writer = pq.ParquetWriter(OUT_PATH, table.schema)
    else:
        table = table.select(writer.schema.names)
    writer.write_table(table)
    del df, table

if writer is not None:
    writer.close()
print("\nDone. Saved to:", OUT_PATH)

check = pd.read_parquet(OUT_PATH, columns=["label_binary", "label_family"])
print("\nFinal shape:", check.shape)
print("\nBinary balance:")
print(check["label_binary"].value_counts().to_string())
print("\nFamily counts:")
print(check["label_family"].value_counts().to_string())
