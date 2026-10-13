import json, re, random
from pathlib import Path
import pandas as pd
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

BASE = Path.home() / "ids-project" / "zeek_out" / "lab"
OUT_PATH = Path.home() / "ids-project" / "data" / "clean" / "lab_merged_http.parquet"
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
MAX_ROWS_PER_FILE = 20000
random.seed(42)
HTTP_COLS = ["_uri_len_max", "_uri_len_avg", "_http_req_count", "_distinct_methods", "_has_known_scanner_ua"]

def label_from_name(name):
    is_benign = name.startswith("benign_")
    binary = 0 if is_benign else 1
    family = re.sub(r"^(attack_|benign_)", "", name)
    family = re.sub(r"_run\d+$", "", family)
    return binary, family

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

def read_jsonl_filtered(path, wanted_uids):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("uid") in wanted_uids:
                rows.append(rec)
    return rows

def compute_http_features(http_rows):
    if not http_rows:
        return pd.DataFrame({"uid": pd.Series(dtype="object"),
                              **{c: pd.Series(dtype="float64") for c in HTTP_COLS}})
    df = pd.DataFrame(http_rows)
    df["uri"] = df.get("uri", "").astype(str)
    df["method"] = df.get("method", "").astype(str)
    df["user_agent"] = df.get("user_agent", "").astype(str)
    df["_uri_len"] = df["uri"].str.len()

    scanner_markers = ["nikto", "gobuster", "dirb", "sqlmap", "nmap", "curl", "python-requests"]
    df["_is_scanner_ua"] = df["user_agent"].str.lower().apply(
        lambda ua: any(m in ua for m in scanner_markers)
    ).astype(int)

    agg = df.groupby("uid").agg(
        _uri_len_max=("_uri_len", "max"),
        _uri_len_avg=("_uri_len", "mean"),
        _http_req_count=("uri", "count"),
        _distinct_methods=("method", "nunique"),
        _has_known_scanner_ua=("_is_scanner_ua", "max"),
    ).reset_index()
    return agg

writer = None
for folder in sorted(BASE.iterdir()):
    if not folder.is_dir():
        continue
    if folder.name.startswith("fresh_") or folder.name.startswith("final_test_"):
        print(f"SKIP (held-out test set): {folder.name}")
        continue
    flow_path = folder / "flowmeter.log"
    http_path = folder / "http.log"
    if not flow_path.exists():
        print(f"SKIP (no flowmeter.log): {folder.name}")
        continue

    binary, family = label_from_name(folder.name)
    flow_rows = read_jsonl_capped(flow_path, MAX_ROWS_PER_FILE)
    flow_df = pd.DataFrame(flow_rows)
    del flow_rows
    if "uid" not in flow_df.columns:
        print(f"SKIP (no uid): {folder.name}")
        continue
    wanted_uids = set(flow_df["uid"])

    if http_path.exists():
        http_rows = read_jsonl_filtered(http_path, wanted_uids)
    else:
        http_rows = []

    http_feats = compute_http_features(http_rows)
    del http_rows

    merged = flow_df.merge(http_feats, on="uid", how="left")
    for c in HTTP_COLS:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").fillna(0).astype("float64")

    for col in merged.columns:
        if col in HTTP_COLS:
            continue
        if pd.api.types.is_numeric_dtype(merged[col]):
            merged[col] = merged[col].astype("float64")

    merged["label_binary"] = binary
    merged["label_family"] = family
    merged["source_run"] = folder.name

    print(f"{folder.name:<35} family={family:<20} binary={binary}  flows={len(merged)}  http_rows_matched={len(http_feats)}")

    table = pa.Table.from_pandas(merged, preserve_index=False)
    if writer is None:
        writer = pq.ParquetWriter(OUT_PATH, table.schema)
    else:
        table = table.select(writer.schema.names)
    writer.write_table(table)
    del flow_df, http_feats, merged, table

if writer is not None:
    writer.close()
print("\nDone. Saved to:", OUT_PATH)

check = pd.read_parquet(OUT_PATH, columns=["label_binary", "label_family"])
print("\nFinal shape:", check.shape)
print(check["label_binary"].value_counts().to_string())
