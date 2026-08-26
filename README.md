# Cyber Triage Tool

AI-assisted cyber triage tool for early-stage digital forensic analysis.

Cyber Triage Tool for Digital Forensic Investigation
(National Investigation Agency, Anti-Cyber Terrorism Division). See
[plan.md](plan.md) for the full requirement breakdown and roadmap.

## Tech Stack

**Implemented**

- Python, scikit-learn, pandas — preprocessing, anomaly detection, risk scoring
- Flask + flask-cors — backend API
- React 19 + Vite + react-router-dom — investigator frontend
- Plain CSS with custom properties — no CSS framework

**Planned, not yet wired up** (present in the root `requirements.txt` for later phases)

- ReportLab — PDF reports (`backend/report_generator.py` is still empty)
- MongoDB / pymongo — case persistence (no code uses it yet)
- python-evtx, xmltodict — Windows Event Log parsing

## Setup

### Backend

```bash
cd backend && pip install -r requirements.txt && python app.py
```

Serves on `http://localhost:5000`. `backend/requirements.txt` is the minimal set
needed to run the API; the root `requirements.txt` also includes dependencies for
unbuilt phases.

### Frontend

```bash
cd frontend && npm install && npm run dev
```

Serves on `http://localhost:5173`. The Vite dev server proxies `/api/*` to Flask
on port 5000, so run the backend too if you need live data.

Production build:

```bash
cd frontend && npm run build
```

## API Endpoints

| Method | Endpoint        | Status                                                                      |
| ------ | --------------- | --------------------------------------------------------------------------- |
| GET    | `/api/health`   | Working — service liveness check                                            |
| POST   | `/api/analyze`  | Working — upload a CSV, returns priority summary + top 100 scored artifacts |
| POST   | `/api/evaluate` | Working — train/test split on a labeled CSV, returns classification metrics |
| POST   | `/api/report`   | **501 stub** — not implemented                                              |

`/api/analyze` and `/api/evaluate` both take a multipart upload in the form field
named `file`. See [docs/flask_api.md](docs/flask_api.md) for request and response
details.

## Project Layout

```
backend/     Flask API (app.py) and the empty report generator stub
ml/          Preprocessing, IsolationForest detector, risk scorer
frontend/    React + Vite investigator UI
docs/        Per-module design notes
data/        Datasets (gitignored — never commit CSVs)
models/      Persisted .pkl models (gitignored)
reports/     Generated PDFs (gitignored)
evaluation/  evaluate.py — currently empty
```

## How Scoring Works

A CSV is cleaned and scaled, an IsolationForest produces an anomaly score, and a
rule engine adds artifact-specific signals (failed logins, executables in temp,
autorun registry keys, and so on). The two are combined 60/40 into a 0–100 risk
score, which maps to a priority band:

| Risk score | Priority |
| ---------- | -------- |
| ≥ 75       | CRITICAL |
| ≥ 50       | HIGH     |
| ≥ 25       | MEDIUM   |
| < 25       | LOW      |

The model trains on first use and is cached to `models/isolation_forest.pkl`.
See [docs/risk_scoring.md](docs/risk_scoring.md) and
[docs/anomaly_detection.md](docs/anomaly_detection.md).

## Dataset Setup

This project uses the CICIDS2017 dataset.

1. Download from Kaggle:
   https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed

2. Place the file in the `data/` folder:
   `cyber-triage-tool/data/cicids2017_cleaned.csv`

3. The `data/` folder is gitignored — never commit CSV files to this repo

## Current Limitations

- The frontend renders authored sample data. It is not yet connected to
  `/api/analyze`; a service layer exists so it can be.
- Only network-flow CSVs are supported. Disk image, registry, EVTX and PCAP
  ingestion are not built.
- There is no authentication. The login screen is a UI prototype only.
- `app.py` runs with `debug=True` — turn this off before any demo or deployment.

## Contributors

Pull requests welcome. Please open an issue first to discuss changes.
