import json, re
from pathlib import Path
import pandas as pd
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

BASE = Path.home() / "ids-project" / "zeek_out" / "lab"
OUT_PATH = Path.home() / "ids-project" / "data" / "clean" / "lab_merged_host.parquet"
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
MAX_ROWS_PER_FILE = 30000
WINDOWS = [10, 30]

def label_from_name(name):
    is_benign = name.startswith("benign_")
    binary = 0 if is_benign else 1
    family = re.sub(r"^(attack_|benign_)", "", name)
    family = re.sub(r"_run\d+$", "", family)
    return binary, family

def read_jsonl_capped(path, cap):
    import random
    random.seed(42)
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

writer = None
for folder in sorted(BASE.iterdir()):
    if not folder.is_dir():
        continue
    if folder.name.startswith("fresh_") or folder.name.startswith("final_test_"):
        print(f"SKIP (held-out test set): {folder.name}")
        continue
    flow_path = folder / "flowmeter.log"
    conn_path = folder / "conn.log"
    if not flow_path.exists() or not conn_path.exists():
        print(f"SKIP (missing logs): {folder.name}")
        continue

    binary, family = label_from_name(folder.name)

    flow_rows = read_jsonl_capped(flow_path, MAX_ROWS_PER_FILE)
    flow_df = pd.DataFrame(flow_rows)
    del flow_rows
    if "uid" not in flow_df.columns:
        print(f"SKIP (no uid in flowmeter): {folder.name}")
        continue
    wanted_uids = set(flow_df["uid"])

    conn_rows = []
    with open(conn_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("uid") in wanted_uids:
                conn_rows.append(rec)
    conn_df = pd.DataFrame(conn_rows)
    del conn_rows

    if conn_df.empty or "uid" not in conn_df.columns or "ts" not in conn_df.columns:
        print(f"SKIP (conn.log missing uid/ts or empty after filter): {folder.name}")
        continue

    conn_df = compute_host_features(conn_df)
    host_cols = ["uid", "_conn_count_10", "_distinct_ports_10", "_conn_count_30", "_distinct_ports_30"]
    conn_small = conn_df[host_cols]

    merged = flow_df.merge(conn_small, on="uid", how="left")
    for c in ["_conn_count_10", "_distinct_ports_10", "_conn_count_30", "_distinct_ports_30"]:
        merged[c] = merged[c].fillna(0)

    for col in merged.columns:
        if pd.api.types.is_numeric_dtype(merged[col]):
            merged[col] = merged[col].astype("float64")

    merged["label_binary"] = binary
    merged["label_family"] = family
    merged["source_run"] = folder.name

    print(f"{folder.name:<35} family={family:<20} binary={binary}  flows={len(merged)}")

    table = pa.Table.from_pandas(merged, preserve_index=False)
    if writer is None:
        writer = pq.ParquetWriter(OUT_PATH, table.schema)
    else:
        table = table.select(writer.schema.names)
    writer.write_table(table)
    del flow_df, conn_df, merged, table

if writer is not None:
    writer.close()
print("\nDone. Saved to:", OUT_PATH)

check = pd.read_parquet(OUT_PATH, columns=["label_binary", "label_family"])
print("\nFinal shape:", check.shape)
print(check["label_binary"].value_counts().to_string())
