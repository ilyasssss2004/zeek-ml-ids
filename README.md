# Zeek-ML: Network Anomaly Detection with Zeek + Machine Learning

A supervised ML pipeline for detecting network attacks from Zeek flow features. The project centers on a diagnosed-and-fixed methodological bug — **models trained on public datasets using one feature-extraction tool fail almost completely when deployed with a different tool** — and documents the full fix: a self-captured lab dataset, feature engineering, and honest, multi-layered validation.

## The problem

A model trained on CIC-IDS2017 (using the dataset's CICFlowMeter-derived features) scored 99.9% accuracy in standard evaluation. Tested against real attacks generated in a local Kali/Metasploitable lab, it classified **100% of real port scans, DoS attacks, and brute-force attempts as benign**.

## Root cause

The live pipeline extracted features using Zeek + a Zeek flowmeter plugin, then renamed Zeek's fields to match CIC's column names. Zeek and CICFlowMeter compute several features differently — a column rename doesn't reconcile this. Confirmed two ways:
1. **Held-out generalization test on CIC itself**: recall on a held-out attack day dropped from 99.9% (random split) to **0.6%**, proving the model had memorized dataset-specific patterns, not general attack behavior.
2. **Direct feature comparison**: Kali scan traffic, mapped through the old pipeline, showed systematically different values from CIC's own rows for the same attack type.

## The fix

Rebuilt the pipeline so **training and live inference use the exact same tool** end to end (Zeek + zeek-flowmeter), using a self-captured lab dataset instead of relying on CIC-IDS2017.

## Dataset

Captured in a Kali Linux → Metasploitable2 lab over multiple sessions:
- **19 distinct attack families**: port scans (SYN, connect, FIN, NULL, Xmas, slow/T1), floods (SYN, UDP, ICMP, HTTP), brute force (Hydra — FTP/SSH/Telnet, Medusa FTP), web attacks (sqlmap, nikto, gobuster, dirb), service enumeration (enum4linux)
- **10 benign traffic families** across 6 services: HTTP, FTP, SSH, Telnet, MySQL, SMB, plus idle/background traffic
- Large flood captures (600K–5.8M raw packets) downsampled via reservoir sampling to keep training memory-bounded
- A set of fresh, independently captured pcaps (never touched during training) held out for final validation

## Feature engineering

Beyond Zeek-flowmeter's ~80 native flow statistics, two additional feature sets were engineered and evaluated:

- **Host-level time-window features** (connections / distinct ports per 10s and 30s window) — improved the weaker logistic regression model but did not move the already-strong tree models, and was confirmed ineffective against a genuinely slow (`-T1`, ~16s between probes) scan, since the attack's pacing exceeded the window length. Documented as an honest negative/neutral result.
- **HTTP payload-derived features** (URI length, request count, method diversity, known-scanner User-Agent flag) — derived from Zeek's `http.log`. **Directly closed the model's main blind spot**: nikto recall went from 0% → 93.9% → **100%** across two rounds of improvement.

## Model comparison

Four models were trained and compared on the same dataset (reasonable default settings, no hyperparameter search):

| Model | Internal PR-AUC | Internal ROC-AUC | Benign precision | Strengths | Weaknesses |
|---|---|---|---|---|---|
| Logistic Regression | 0.9999 | 0.9962–0.9986 | 0.44–0.85 | Fast, interpretable, baseline | Struggles with benign precision as benign class grew more diverse; needed engineered features (host-window) to compensate for inability to learn complex interactions |
| Random Forest | **1.0000** | **1.0000** | **0.99–1.00** | Best overall recall and precision across nearly every attack family; most robust to feature additions | Larger model file than linear baseline; less interpretable than logistic regression |
| LightGBM | 1.0000 | 0.9999–1.0000 | 0.99–1.00 | Fast training, strong recall on most families | Unstable on smallest category (hydra_ssh: 0–3% in some runs) |
| XGBoost | 1.0000 | 0.9998–1.0000 | 0.99–1.00 | Strong recall on most families | Also unstable on hydra_ssh; occasionally missed hping_icmpflood (n=1 sample) |

**Winner: Random Forest** — selected for highest and most consistent PR-AUC, and the strongest, most stable holdout-family generalization across every round of retraining as the dataset and features evolved.

## Results (final model: Random Forest)

| Attack family | Recall |
|---|---|
| Scans (SYN/connect/FIN/NULL/Xmas) | 100% |
| Floods (SYN/UDP/ICMP/HTTP) | 100% |
| sqlmap, gobuster, dirb, medusa_ftp, hydra_telnet, enum4linux, nikto, hydra_ftp | 100% |
| nmap_slow (T1 timing) | 99.1% |
| hydra_ssh | 80% (n=30; smallest category, remaining known weak point) |

**Benign false-positive rate: 0%** across every captured benign run.
**Fresh, independent validation** (captures made after the model was saved, never touched during training): 99.95%+ detection rate maintained.

## Methodology notes

- **Three layers of testing**: internal test split (25%) → held-out families (never trained on) → fresh independent captures (separate sessions). Each layer asks a progressively harder generalization question.
- **No formal hyperparameter tuning** — models compared with default settings to select a winner; a validation-based tuning pass is a known limitation / future improvement.
- **Full weakness audit**: the saved model was run against every captured run (attack and benign) to confirm no undetected blind spots beyond hydra_ssh.

## Suricata comparison (partial, descoped)

A comparison against Suricata (Emerging Threats Open ruleset, 69K rules) was attempted on the same captured pcaps. Initial results: Suricata fired alerts on 5 of 19 attack families (signature-based hits on SQL injection, SMB enumeration, and a rate-based flood rule), missing scans and most brute-force/enumeration tools entirely. This is likely influenced by the lab's attacker and victim sharing a private subnet, which affects how Suricata's `HOME_NET`/`EXTERNAL_NET`-scoped rules apply — a full, fair comparison would require lab network reconfiguration and rule tuning beyond this project's scope. Kept here as an honest, partial finding rather than a completed deliverable.

## Repository structure
scripts/ - Pipeline scripts (cleaning, extraction, feature engineering, training, evaluation)
reports/ - Logged output from every pipeline stage
models/ - Trained model, feature list, model comparison results
capture.sh - Manual single-capture helper
run_all.sh - Automated multi-capture runner (requires SSH setup)

## Scope / out of scope

This project focuses on supervised detection, built and validated end-to-end. The following were considered and explicitly descoped due to time constraints:
- Unsupervised anomaly detection (Isolation Forest)
- A fully fair, tuned Suricata baseline comparison
- Live detection dashboard
- Formal hyperparameter tuning

## Requirements

- Zeek with the zeek-flowmeter plugin
- Python 3.12, scikit-learn, LightGBM, XGBoost, pandas, pyarrow
- Suricata 7.0.3 (optional, for the partial signature-based comparison)
