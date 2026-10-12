import numpy as np
import pandas as pd

cic = pd.read_parquet("data/clean/cic_clean.parquet")
kali = pd.read_csv("/home/vboxuser/zeek-ml/reports/kali_nmap_predictions_features.csv")
kali.columns = kali.columns.astype(str).str.strip()

print("Kali file shape:", kali.shape)
print("Kali columns:", list(kali.columns))

feats = [c for c in cic.columns if c not in ("label_family", "label_binary", "source_file")]
shared = [c for c in feats if c in kali.columns]
missing = [c for c in feats if c not in kali.columns]
print(f"\nShared with CIC: {len(shared)}   Missing in Kali file: {len(missing)}")
print("Missing:", missing)

scan = cic[cic.label_family == "PortScan"]
benign = cic[cic.label_family == "BENIGN"]

rows = []
for c in shared:
    k = pd.to_numeric(kali[c], errors="coerce")
    rows.append({
        "feature": c,
        "cic_scan_median": scan[c].median(),
        "cic_benign_median": benign[c].median(),
        "kali_median": k.median(),
        "kali_pct_zero": round((k == 0).mean() * 100, 1),
    })
out = pd.DataFrame(rows)
pd.set_option("display.width", 200)
print("\n", out.to_string(index=False))
out.to_csv("reports/04_compare.csv", index=False)
