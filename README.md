
# Python-Based Threat Intelligence and Network Anomaly Detection

A defensive cybersecurity research prototype that combines threat intelligence, behavioural rules, and machine-learning-based anomaly detection to identify suspicious network traffic. Includes IOC collection, risk scoring, alert storage, a REST API, and a Streamlit dashboard.

> **Project status:** Functional prototype. Synthetic evaluation and automated testing completed. Real-world CIC-IDS2017 evaluation and live-feed verification are still pending, and will be added soon.
>
> **Important:** All performance metrics currently reported below come from synthetic data. They demonstrate that the software pipeline works, not that the system achieves the same performance on real network traffic.

## Key features

- **Threat intelligence integration:** IOC ingestion and matching using URLhaus and AlienVault OTX collectors.
- **IOC freshness checks:** Expiry and age-based filtering of threat indicators.
- **Behavioural detection:** Rule-based detection of suspicious network activity.
- **Machine learning:** Isolation Forest anomaly detection.
- **Hybrid risk scoring:** Combines IOC confidence, anomaly scores, and behavioural rules.
- **Model versioning:** Saves model bundles with feature schemas, metadata, and SHA-256 integrity checks.
- **Unlabelled detection:** Analyses new traffic without requiring ground-truth labels.
- **Alert management:** Stores and deduplicates alerts using SQLite.
- **REST API:** Provides an interface for accessing detection results.
- **Dashboard:** Streamlit-based interface for reviewing alerts and detection activity.
- **Automated testing:** Tests data validation, detection, model bundles, IOC handling, and evaluation workflows.

## Detection architecture

The system uses three complementary detection signals:

| Detection method | Purpose | Limitation |
|---|---|---|
| IOC matching | Identifies traffic associated with known malicious indicators | Depends on feed coverage and indicator freshness |
| Behavioural rules | Detects suspicious patterns such as scanning and unusually high traffic | Depends on rules and thresholds |
| Isolation Forest | Identifies unusual network behaviour without requiring attack labels | Anomalous activity is not necessarily malicious |

These signals are combined into a hybrid risk score. Alerts include the detection evidence that contributed to the score.

## Project workflow

```text
                    THREAT INTELLIGENCE
                  URLhaus / AlienVault OTX
                            |
                            v
                       IOC Database
                            |
                            v
Network Flows ---> Preprocessing ---> Feature Engineering
                            |
              +-------------+-------------+
              |             |             |
              v             v             v
          IOC Matching   Rule-Based   Isolation Forest
                         Detection    Anomaly Detection
              |             |             |
              +-------------+-------------+
                            |
                            v
                    Hybrid Risk Scoring
                            |
                            v
                     Alert Generation
                            |
                            v
                      SQLite Storage
                            |
                 +----------+----------+
                 |                     |
                 v                     v
             REST API            Streamlit Dashboard
```

## Technology stack

| Category | Technologies |
|---|---|
| Programming language | Python |
| Data processing | Pandas, NumPy |
| Machine learning | Scikit-learn, Isolation Forest |
| Threat intelligence | URLhaus, AlienVault OTX |
| Database | SQLite |
| API | Flask |
| Dashboard | Streamlit |
| Testing | Pytest |
| Model integrity | SHA-256 |
| Version control | Git, GitHub |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/aryanoff2112-art/python-threat-intelligence.git
cd python-threat-intelligence
```

Replace the repository URL above if your actual GitHub repository has a different name.

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Running the project

### Run the synthetic end-to-end demonstration

```bash
python main.py demo
```

The demo:

1. Generates labelled synthetic network traffic.
2. Generates unlabelled synthetic network traffic.
3. Loads sample threat intelligence indicators.
4. Evaluates multiple detection approaches.
5. Calibrates the hybrid risk-scoring model.
6. Saves a versioned model bundle.
7. Analyses unseen, unlabelled traffic.
8. Stores generated alerts in the database.

### Run automated tests

```bash
python -m pytest -q -rs
```

Latest verified result:

```text
82 passed in 40.79s
```

All 82 tests passed with no failures or skips in the latest local run.

### Run detection on a CSV file

```bash
python main.py detect --flows path/to/traffic.csv
```

To provide earlier traffic as context for completing the first time window:

```bash
python main.py detect --flows path/to/traffic.csv --context path/to/earlier.csv
```

### Run the dashboard

```bash
streamlit run dashboard/app.py
```

### Run the API

```bash
python -m api.app
```

Check the API implementation for the available routes and request formats.

## Synthetic evaluation results

**Latest synthetic evaluation — November 10, 2026**

The demonstration generated:

- 21,200 labelled synthetic network flows.
- 5,300 unlabelled synthetic network flows.
- 148 synthetic threat intelligence indicators.

The following results were produced by the evaluation pipeline:

| Model | Precision | Recall | F1-score | FPR | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| Behavioural Rules | 0.730 | 0.637 | 0.680 | 0.0183 | 0.811 |
| IOC Matching | 1.000 | 0.249 | 0.399 | 0.0000 | 0.625 |
| Isolation Forest (Benign-only) | 0.832 | 0.511 | 0.633 | 0.0080 | 0.843 |
| Hybrid (Prior Weights) | 0.850 | 0.770 | 0.808 | 0.0105 | 0.929 |
| Hybrid (Validation Threshold) | 0.841 | 0.786 | 0.813 | 0.0115 | 0.929 |
| **Hybrid (Calibrated)** | **0.846** | **0.803** | **0.824** | **0.0113** | **0.931** |
| Isolation Forest (Unsupervised) | 1.000 | 0.091 | 0.166 | 0.0000 | 0.839 |
| Random Forest (Supervised Baseline) | 0.997 | 0.952 | 0.974 | 0.0003 | 1.000 |

**Interpretation:**

- The calibrated hybrid model achieved an F1-score of 0.824 on the synthetic test dataset.
- Its ROC-AUC was 0.931.
- Its test false-positive rate was 1.13%, slightly above the 1% validation target.
- The Random Forest is a supervised baseline and should not be described as an unsupervised detector.
- These metrics are not evidence of equivalent performance on real-world network traffic.

## Latest end-to-end demonstration

| Metric | Result |
|---|---:|
| Automated tests passed | 82 |
| Automated tests failed | 0 |
| Labelled flows generated | 21,200 |
| Unlabelled flows analysed | 5,300 |
| IOC indicators loaded | 148 |
| New alerts stored | 324 |
| Duplicate alerts skipped | 0 |
| Detection time for 5,300 flows | 0.16 seconds |
| Measured throughput | 26,680 flows/second |
| High-severity alerts | 176 |
| Critical-severity alerts | 96 |
| Medium-severity alerts | 33 |
| Low-severity alerts | 19 |
| Drift-check result | 3.98% above benign-baseline 99th percentile |

The throughput measurement is from a single synthetic demo run on the local development environment. It is not a production capacity benchmark.

## Model calibration

The hybrid model uses validation data to learn risk-scoring weights and select an alert threshold.

Latest demo calibration:

| Parameter | Value |
|---|---:|
| Method | Calibrated |
| Target validation FPR | 1% |
| Alert threshold | 21.2786 |
| Validation rows used | 4,259 |
| Validation attack rows | 182 |
| Validation IOC hits | 25 |
| Validation FPR at threshold | 0.981% |
| Validation recall at threshold | 88.46% |

The test set is not used for model calibration. Learned coefficients are dataset-dependent and should not be interpreted as universal probabilities.

## Model bundle and integrity

The project saves versioned model bundles containing:

- Model parameters.
- Feature names and ordering.
- Training and evaluation metadata.
- Detection thresholds.
- Risk-scoring configuration.
- Library and version information.
- SHA-256 checksums.

The bundle loader verifies file integrity and compatibility before loading.

**Security note:** SHA-256 checksums detect corruption or unexpected modification; they do not prove that a model bundle is trustworthy. Only load bundles from trusted sources.

## Threat intelligence configuration

The project supports URLhaus and AlienVault OTX integration.

Configure credentials through environment variables rather than hardcoding API keys.

PowerShell example:

```powershell
$env:URLHAUS_AUTH_KEY = "YOUR_URLHAUS_KEY"
$env:OTX_API_KEY = "YOUR_OTX_KEY"
```

Run the live-feed verification script:

```bash
python scripts/verify_live_feeds.py
```

**Live-feed verification is still pending.** The collectors have automated tests, but successful mocked-response tests do not establish that the live services have been verified.

The latest synthetic demo loaded 148 indicators, but all 148 were undated. Their current validity could therefore not be established through indicator timestamps.

## Real-world evaluation: CIC-IDS2017

The next major milestone is evaluating the system using the CIC-IDS2017 intrusion detection dataset.

The experiment protocol is documented in:

`docs/CICIDS2017_EXPERIMENT.md`

It includes:

- Dataset download and checksum verification.
- Cross-day train/test evaluation.
- Historical IOC exclusion using `--no-ioc`.
- Temporal leakage checks.
- Multiple random seeds.
- Per-attack performance analysis.
- A results-reporting template.

**Status: Not yet completed.**

Synthetic results must remain separate from future real-world benchmark results.

## Known limitations

- Current performance metrics are based on synthetic data.
- Live URLhaus and OTX integration still needs independent verification.
- All 148 indicators in the latest demo were undated.
- The first and last batch time windows can have incomplete per-source aggregates.
- Persistent cross-run streaming window state is not implemented.
- Anomaly detection can flag legitimate unusual behaviour.
- Risk scores are model outputs, not guaranteed real-world probabilities.
- CIC-IDS2017 cross-day generalisation has not yet been measured.

## Repository structure

```text
python-threat-intelligence/
│
├── intelligence/
│   ├── collectors/
│   ├── matcher.py
│   └── ...
│
├── detection/
│   ├── preprocessing.py
│   ├── features.py
│   ├── anomaly.py
│   ├── rules.py
│   ├── scoring.py
│   ├── evaluation.py
│   └── ...
│
├── database/
├── alerts/
├── api/
├── dashboard/
├── scripts/
├── docs/
├── tests/
├── models/
├── data/
│   ├── raw/
│   ├── processed/
│   └── samples/
│
├── config/
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

Some subdirectories and filenames may differ depending on the current repository version.

## Future improvements

- Complete CIC-IDS2017 real-world evaluation.
- Verify live URLhaus and OTX feed integration.
- Evaluate detection across multiple datasets.
- Improve persistent streaming-window state.
- Add more robust drift monitoring.
- Evaluate false-positive rates under realistic traffic distributions.
- Improve alert prioritisation and analyst workflows.

## Disclaimer

This project is developed for defensive cybersecurity research and educational purposes. It is not a replacement for a production SIEM, IDS, or professional security operations workflow. Detection alerts require investigation and validation.

## Author

**Aryan Upadhyay**

GitHub: https://github.com/aryanoff2112-art

