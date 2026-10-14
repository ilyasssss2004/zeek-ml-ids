# Zeek-ML: Network Anomaly Detection with Zeek + Machine Learning

A supervised ML pipeline for detecting network attacks from Zeek flow features. The project centers on a diagnosed-and-fixed methodological bug -- models trained on public datasets using one feature-extraction tool fail almost completely when deployed with a different tool -- and documents the full fix: a self-captured lab dataset, feature engineering, and honest, multi-layered validation.

## Lab setup

Three VirtualBox VMs on an isolated internal network (192.168.100.0/24):

- **Kali Linux (Attacker)** -- 192.168.100.20 -- generates both attack traffic (scans, floods, brute force, web attacks) and benign traffic (normal web/FTP/SSH/etc. usage) against the victim.
- **Metasploitable2 (Victim)** -- 192.168.100.30 -- the target, running FTP, SSH, Telnet, SMTP, HTTP, SMB, MySQL, PostgreSQL, and Tomcat.
- **Ubuntu (Sensor/IDS)** -- a third VM whose `enp0s8` interface has no IP address and runs purely in promiscuous capture mode, silently mirroring all traffic between Kali and Metasploitable without participating in it.

Pipeline on the sensor: `tcpdump` captures raw traffic to `.pcap` -> `Zeek + zeek-flowmeter` processes each pcap into `flowmeter.log`, `http.log`, and `conn.log` -> a feature-engineering step merges and labels these logs into one dataset -> the Random Forest model is trained and evaluated on that dataset.

The same Zeek + zeek-flowmeter step is used for every pcap, whether it is training data, a held-out family, or a fresh independent test capture -- this consistency is the fix at the center of the project (see below).

## The problem

A model trained on CIC-IDS2017 (using the dataset's CICFlowMeter-derived features) scored 99.9% accuracy in standard evaluation. Tested against real attacks generated in the lab above, it classified 100% of real port scans, DoS attacks, and brute-force attempts as benign.

## Root cause

The live pipeline extracted features using Zeek + a Zeek flowmeter plugin, then renamed Zeek's fields to match CIC's column names. Zeek and CICFlowMeter compute several features differently -- a column rename doesn't reconcile this. Confirmed two ways:

1. Held-out generalization test on CIC itself: recall on a held-out attack day dropped from 99.9% (random split) to 0.6%, proving the model had memorized dataset-specific patterns, not general attack behavior.
2. Direct feature comparison: Kali scan traffic, mapped through the old pipeline, showed systematically different values from CIC's own rows for the same attack type.

## The fix

Rebuilt the pipeline so training and live inference use the exact same tool end to end (Zeek + zeek-flowmeter), using a self-captured lab dataset instead of relying on CIC-IDS2017.

## Dataset

Captured in the Kali to Metasploitable2 lab over multiple sessions:

- 19 distinct attack families: port scans (SYN, connect, FIN, NULL, Xmas, slow/T1), floods (SYN, UDP, ICMP, HTTP), brute force (Hydra -- FTP/SSH/Telnet, Medusa FTP), web attacks (sqlmap, nikto, gobuster, dirb), service enumeration (enum4linux)
- 10 benign traffic families across 6 services: HTTP, FTP, SSH, Telnet, MySQL, SMB, plus idle/background traffic
- Large flood captures (600K-5.8M raw packets) downsampled via reservoir sampling to keep training memory-bounded
- A set of fresh, independently captured pcaps (never touched during training) held out for final validation

## Feature engineering

Beyond Zeek-flowmeter's ~80 native flow statistics, two additional feature sets were engineered and evaluated:

- Host-level time-window features (connections / distinct ports per 10s and 30s window) -- improved the weaker logistic regression model but did not move the already-strong tree models, and was confirmed ineffective against a genuinely slow (-T1, ~16s between probes) scan, since the attack's pacing exceeded the window length. Documented as an honest negative/neutral result.
- HTTP payload-derived features (URI length, request count, method diversity, known-scanner User-Agent flag) -- derived from Zeek's http.log. Directly closed the model's main blind spot: nikto recall went from 0% to 93.9% to 100% across two rounds of improvement.

## Model comparison

Four models were trained and compared on the final dataset (86 features: ~80 native Zeek-flowmeter stats + HTTP payload features), using default settings, no hyperparameter search.

Internal test (25% held-out split, same families as training):

| Model | PR-AUC | ROC-AUC | Benign precision | Benign recall | Attack precision | Attack recall |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.9999 | 0.9962 | 0.44 | 0.99 | 1.00 | 0.98 |
| Random Forest (winner) | 1.0000 | 1.0000 | 0.99 | 1.00 | 1.00 | 1.00 |
| LightGBM | 1.0000 | 1.0000 | 0.99 | 0.99 | 1.00 | 1.00 |
| XGBoost | 1.0000 | 1.0000 | 1.00 | 0.99 | 1.00 | 1.00 |

Holdout family recall (families with zero training exposure -- the real generalization test):

| Family | Logistic Regression | Random Forest | LightGBM | XGBoost |
|---|---|---|---|---|
| nmap_slow | 0.955 | 0.991 | 0.991 | 0.991 |
| nikto | 0.909 | 1.00 | 1.00 | 0.727 |
| hydra_ftp | 0.994 | 1.00 | 1.00 | 0.994 |
| hping_icmpflood | 1.00 | 1.00 | 0.00 | 0.00 |

Winner: Random Forest. It ties or beats every other model on every holdout family, has the best internal PR-AUC/ROC-AUC, and -- unlike LightGBM and XGBoost -- shows no catastrophic single-category failure (LightGBM drops to 0% on icmpflood; XGBoost drops to 73% on nikto). Consistency across attack types, not just peak score, drove the selection.

## Results (final model: Random Forest)

| Attack family | Recall |
|---|---|
| Scans (SYN/connect/FIN/NULL/Xmas) | 100% |
| Floods (SYN/UDP/ICMP/HTTP) | 100% |
| sqlmap, gobuster, dirb, medusa_ftp, hydra_telnet, enum4linux, nikto, hydra_ftp | 100% |
| nmap_slow (T1 timing) | 99.1% |

Benign false-positive rate: 0% across every captured benign run.

Fresh, independent validation (captures made after the model was saved, never touched during training): 99.95%+ detection rate maintained.

## Methodology notes

- Three layers of testing: internal test split (25%) -> held-out families (never trained on) -> fresh independent captures (separate sessions). Each layer asks a progressively harder generalization question.
- No formal hyperparameter tuning -- models compared with default settings to select a winner; a validation-based tuning pass is a known limitation / future improvement.
- Full weakness audit: the saved model was run against every captured run (attack and benign) to confirm no undetected blind spots.

## Repository structure

- scripts/ -- pipeline scripts (cleaning, extraction, feature engineering, training, evaluation)
- reports/ -- logged output from every pipeline stage
- models/ -- trained model, feature list, model comparison results
- capture.sh -- manual single-capture helper
- run_all.sh -- automated multi-capture runner (requires SSH setup)

## Scope / out of scope

This project focuses on supervised detection, built and validated end-to-end. The following were considered and explicitly descoped due to time constraints:

- Unsupervised anomaly detection (Isolation Forest)
- Signature-based baseline comparison (Suricata)
- Live detection dashboard
- Formal hyperparameter tuning

## Requirements

- Zeek with the zeek-flowmeter plugin
- Python 3.12, scikit-learn, LightGBM, XGBoost, pandas, pyarrow
