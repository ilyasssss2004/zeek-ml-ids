# Zeek-ML: Network Anomaly Detection with Zeek + Machine Learning

A supervised ML pipeline for detecting network attacks from Zeek flow features, built around a key diagnostic finding: **models trained on public datasets (CIC-IDS2017) using one feature-extraction tool fail almost completely when deployed with a different tool**, even when both claim to produce "the same" features.

## The problem

An initial model trained on CIC-IDS2017 (using the dataset's original CICFlowMeter-derived features) scored 99.9% accuracy in standard evaluation. When tested against real attacks generated in a local Kali/Metasploitable lab, it classified **100% of real port scans, DoS attacks, and brute-force attempts as benign**.

## Root cause

The live pipeline extracted features using **Zeek + a Zeek flowmeter plugin**, then renamed Zeek's fields to match CIC's column names. This masked a deeper problem: Zeek and CICFlowMeter compute several features differently (packet-length semantics, flag counting, window-size handling, timing). A column rename does not reconcile these differences — the model received numerically different inputs than it was trained on.

This was confirmed two ways:
1. **Held-out generalization test on CIC itself** — training on 7 days of CIC-IDS2017 and testing on a held-out attack day (e.g., Friday's PortScan) dropped recall from 99.9% (random split) to **0.6%** (held-out day), showing the original model memorized dataset-specific patterns rather than learning generalizable attack behavior.
2. **Direct feature comparison** — Kali scan traffic, once mapped through the old pipeline, showed systematically different values from CIC's own PortScan rows for the same attack type (duration, window size, flag counts).

## The fix

Rebuilt the pipeline so **training and live inference use the exact same tool** (Zeek + zeek-flowmeter) end to end:

1. Captured labeled attack and benign traffic in a Kali → Metasploitable lab (port scans in multiple variants, brute force, floods, web attacks, plus benign traffic across 5 services)
2. Extracted features with Zeek-flowmeter (never CICFlowMeter) for both training and evaluation
3. Trained and compared 4 models: Logistic Regression, Random Forest, LightGBM, XGBoost
4. Validated on attack families **held out entirely from training**, and on a **fresh capture made after the model was saved**

## Results

| Model | Internal PR-AUC | Internal ROC-AUC |
|---|---|---|
| Logistic Regression | 1.0000 | 0.9987 |
| **Random Forest (winner)** | 1.0000 | **1.0000** |
| LightGBM | 1.0000 | 0.9999 |
| XGBoost | 1.0000 | 0.9998 |

**Generalization to never-trained-on attack families:**

| Family | Recall |
|---|---|
| hydra_ftp (brute force) | ~99% |
| nmap_slow (slow scan) | ~98% |
| hydra_ssh | ~80-100% (n=5, low confidence) |
| nikto (web scanner) | **0%** — known limitation, see below |

**Fresh, independent validation** (a scan captured after training, never touched by any part of the pipeline): **99.95% detection rate** (2000/2001 flows correctly flagged as attack).

## Known limitation

The model consistently fails to detect `nikto`-style web attacks. These generate many individual HTTP requests that, at the flow level, closely resemble benign sequential browsing — a structural limitation of flow-based (vs. content-based) detection, not a training bug. This is a legitimate finding about the boundary of what flow statistics can distinguish.

## Repository structure
scripts/ - Pipeline scripts (data cleaning, extraction, training, evaluation)
reports/ - Logged output from each pipeline stage
models/ - Trained model, feature list, model comparison results
capture.sh - Manual single-capture helper
run_all.sh - Automated multi-capture runner (requires SSH setup)

## Scope note

This project focuses on supervised detection. An unsupervised anomaly-detection component (Isolation Forest) and a Suricata signature-based baseline comparison were considered as extensions but are not yet included.

## Requirements

- Zeek with the zeek-flowmeter plugin
- Python 3.12, scikit-learn, LightGBM, XGBoost, pandas, pyarrow
