# Zeek-ML: Network Anomaly Detection with Zeek + Machine Learning

A supervised ML pipeline for detecting network attacks from Zeek flow features. The project centers on a key diagnostic finding — **models trained on public datasets using one feature-extraction tool fail almost completely when deployed with a different tool**, even when both claim to produce "the same" features — and documents the full fix: a self-captured lab dataset, feature engineering, and honest, multi-layered validation.

## The problem

A model trained on CIC-IDS2017 (using the dataset's CICFlowMeter-derived features) scored 99.9% accuracy in standard evaluation. Tested against real attacks generated in a local Kali/Metasploitable lab, it classified **100% of real port scans, DoS attacks, and brute-force attempts as benign**.

## Root cause

The live pipeline extracted features using Zeek + a Zeek flowmeter plugin, then renamed Zeek's fields to match CIC's column names. Zeek and CICFlowMeter compute several features differently (packet-length semantics, flag counting, window-size handling, timing) — a column rename doesn't reconcile this. Confirmed two ways:
1. **Held-out generalization test on CIC itself**: recall on a held-out attack day dropped from 99.9% (random split) to **0.6%**, showing the original model memorized dataset-specific patterns.
2. **Direct feature comparison**: Kali scan traffic, mapped through the old pipeline, showed systematically different values from CIC's own rows for the same attack type.

## The fix

Rebuilt the pipeline so **training and live inference use the exact same tool** end to end (Zeek + zeek-flowmeter), using a self-captured lab dataset instead of relying solely on CIC-IDS2017.

## Dataset

Captured in a Kali Linux → Metasploitable2 lab over multiple sessions:

- **19 distinct attack families**: port scans (SYN, connect, FIN, NULL, Xmas, slow/T1), floods (SYN, UDP, ICMP, HTTP), brute force (Hydra — FTP/SSH/Telnet, Medusa FTP), web attacks (sqlmap, nikto, gobuster, dirb), service enumeration (enum4linux)
- **10 benign traffic families** across 6 services: HTTP (3 variants), FTP, SSH, Telnet, MySQL, SMB, plus idle/background traffic
- Large flood captures (600K–1.6M raw flows) downsampled via reservoir sampling to keep training memory-bounded
- A set of fresh, independently captured pcaps (never touched during training) held out for final validation

## Feature engineering

Beyond Zeek-flowmeter's ~80 native flow statistics, two additional feature sets were engineered and evaluated:

- **Host-level time-window features** (`_conn_count_10/30`, `_distinct_ports_10/30`) — connections and distinct ports touched by a source IP in rolling 10s/30s windows. Result: improved the weaker logistic regression model (benign precision 0.45 → 0.85) but did not move the already-strong tree-based models, and was confirmed ineffective against a genuinely slow (`-T1`, ~16s between probes) scan, since the attack's pacing exceeded the window length. A documented, honest negative/neutral result.
- **HTTP payload-derived features** (`_uri_len_max/avg`, `_http_req_count`, `_distinct_methods`, `_has_known_scanner_ua`) — derived from Zeek's `http.log`, joined by flow UID. Result: **directly closed the model's main blind spot** — nikto recall went from 93.9% to **100%**, hydra_ftp to 100%, with no regression elsewhere.

## Results (current model: Random Forest)

| Attack family | Recall | Notes |
|---|---|---|
| Scans (SYN/connect/FIN/NULL/Xmas) | 100% | |
| Floods (SYN/UDP/ICMP/HTTP) | 100% | |
| sqlmap, gobuster, dirb, medusa_ftp, hydra_telnet, enum4linux | 100% | |
| nikto | 100% | was 0% before HTTP features, 93.9% after first fix |
| nmap_slow (T1 timing) | 99.1% | |
| hydra_ftp | 100% | |
| hydra_ssh | 80% | n=30; smallest category, legitimate remaining weak point |

**Benign false-positive rate: 0%** across every captured benign run (web, FTP, SSH, Telnet, MySQL, SMB, idle).

**Fresh, independent validation** (captures made after the model was saved, never touched during training): 99.95%+ detection rate maintained.

## Methodology notes

- **Three layers of testing**: internal test split (25%, same families as training) → held-out families (never trained on) → fresh independent captures (captured in separate sessions). Each layer asks a progressively harder generalization question.
- **No formal hyperparameter tuning** — 4 models (Logistic Regression, Random Forest, LightGBM, XGBoost) compared with reasonable default settings to select a winner; a validation-based tuning pass is a known limitation / future improvement.
- **Full weakness audit**: the saved model was run against every single captured run (attack and benign) to confirm no undetected blind spots beyond the two documented above.

## Known limitations

- `hydra_ssh` recall (80%) is based on a still-relatively-small sample (n=30) and is the main remaining weak point.
- Host-level time-window features (10s/30s) do not help against attacks deliberately paced slower than the window — a fundamental trade-off of fixed-window detection, not specific to this implementation.
- Lab-only traffic from a 2-host topology; broader network conditions and adversarial evasion are not tested.

## Repository structure
scripts/ - Pipeline scripts (cleaning, extraction, feature engineering, training, evaluation)
reports/ - Logged output from every pipeline stage
models/ - Trained model, feature list, model comparison results
capture.sh - Manual single-capture helper
run_all.sh - Automated multi-capture runner (requires SSH setup)

## Scope note

This project focuses on supervised detection. An unsupervised anomaly-detection component (Isolation Forest) was considered and descoped due to time constraints. A Suricata signature-based baseline comparison is planned as a follow-up.

## Requirements

- Zeek with the zeek-flowmeter plugin
- Python 3.12, scikit-learn, LightGBM, XGBoost, pandas, pyarrow
