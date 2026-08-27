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
- MongoDB / pymongo — case persistence and dashboard data
- ReportLab — PDF triage report generation

**Planned, not yet wired up** (present in the root `requirements.txt` for later phases)

- python-evtx, xmltodict — Windows Event Log parsing

## Setup

### Prerequisites

- Python 3.9+
- Node.js 18+
- MongoDB 8+ (install with `brew install mongodb-community` on macOS)

### MongoDB

Start the MongoDB service before running the backend:

```bash
brew services start mongodb-community
```

The backend connects to `mongodb://localhost:27017` by default. Set the
`MONGO_URI` environment variable to use a different connection string (e.g.
MongoDB Atlas). On first startup the backend seeds four sample cases into the
database automatically.

### Backend

```bash
cd backend && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt && python app.py
```

Serves on `http://localhost:5001`. `backend/requirements.txt` is the minimal set
needed to run the API; the root `requirements.txt` also includes dependencies for
unbuilt phases.

### Frontend

```bash
cd frontend && npm install && npm run dev
```

Serves on `http://localhost:5173`. The Vite dev server proxies `/api/*` to Flask
on port 5001, so run the backend too if you need live data.

Production build:

```bash
cd frontend && npm run build
```

## API Endpoints

| Method | Endpoint              | Status                                                                      |
| ------ | --------------------- | --------------------------------------------------------------------------- |
| GET    | `/api/health`         | Working — service liveness check (includes MongoDB status)                  |
| POST   | `/api/analyze`        | Working — upload a CSV, returns priority summary + top 100 scored artifacts |
| POST   | `/api/evaluate`       | Working — train/test split on a labeled CSV, returns classification metrics |
| GET    | `/api/cases`          | Working — list all cases from MongoDB                                       |
| GET    | `/api/cases/:caseId`  | Working — fetch a single case by ID                                         |
| POST   | `/api/cases`          | Working — create a new case                                                 |
| PUT    | `/api/cases/:caseId`  | Working — update an existing case                                           |
| GET    | `/api/dashboard`      | Working — metrics, investigations, triage summaries, recent activity        |
| POST   | `/api/report`         | Working — generate and download a PDF report for a case                     |
| GET    | `/api/report/:caseId` | Working — direct PDF download link                                          |
| GET    | `/api/reports/:caseId`| Working — list previously generated reports for a case                      |
| GET    | `/api/triage/:caseId` | Working — triage summary for a case                                         |

`/api/analyze` and `/api/evaluate` both take a multipart upload in the form field
named `file`. See [docs/flask_api.md](docs/flask_api.md) for request and response
details.

## Frontend Screens

| Route            | Status                                                                  |
| ---------------- | ----------------------------------------------------------------------- |
| `/`              | Landing page                                                            |
| `/login`         | Login screen — UI prototype, no authentication behind it                 |
| `/dashboard`     | Investigation overview: metrics, active cases, triage preview, activity  |
| `/cases/:caseId` | **Case workspace** — Overview and Reports tabs implemented               |
| everything else  | Placeholder telling you which phase builds that module                   |

### Case Workspace (`/cases/:caseId`)

Opened from the dashboard: in **Active Investigations**, click a case ID or the
**Open** control at the end of the row — for example `CASE-2026-0147` navigates to
`/cases/CASE-2026-0147`. Clicking anywhere else in the row still just selects the
case so its triage preview loads beside the list, as before. **Back to Dashboard**
at the top left of the workspace returns to `/dashboard`.

The workspace shows a case header (ID, description, threat score, severity,
status, evidence / artifact / IOC counts, last activity) above an eight-tab strip:
`Overview · Evidence · Artifacts · Analysis · AI Triage · Timeline · IOC Graph ·
Reports`.

**`Overview` and `Reports` are implemented.** The other six tabs are visible but
disabled, each labelled `Planned` with a tooltip naming what it is waiting on.
They are not clickable and there is no code behind them.

Overview contains six sections:

1. **Investigation Summary** — written narrative plus fixed case metadata
2. **Threat Assessment** — weighted score composition, artifact priority
   distribution, indicator split, MITRE tactic coverage
3. **Priority Findings** — findings ranked by severity then risk score, each with
   its rationale, source artifact, host and technique
4. **Recommended Next Action** — what to do, and separately why it comes first
5. **Recent Activity** — case event feed, newest first
6. **Evidence Status** — acquired sources with hash, custodian and processing
   state, plus outstanding acquisitions listed separately

Reports allows the investigator to generate a comprehensive PDF triage report
containing: cover page, case summary, threat assessment, priority findings table,
recommended actions, evidence status, and activity log. Previously generated
reports are listed for download.

### Data Flow

Case data flows from **MongoDB → Flask API → React frontend**. The frontend
services (`caseService.js`, `dashboardService.js`) call the backend API first and
fall back to local mock fixtures (`frontend/src/data/`) when the backend is
unreachable, so the UI always renders something.

Four sample cases exist (`CASE-2026-0147`, `-0143`, `-0139`, `-0136`). They are
seeded into MongoDB on first startup. The two that the sample data marks as still
ingesting or correlating deliberately show no assessment and no ranked findings,
rather than inventing them. Any other case ID renders a "no case matches" screen
with a link back to the dashboard.

## Project Layout

```
backend/     Flask API (app.py), MongoDB helper (db.py), report generator
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
- Inside the case workspace only the `Overview` and `Reports` tabs are built.
  Evidence, Artifacts, Analysis, AI Triage, Timeline, and IOC Graph are disabled
  placeholders.
- Only network-flow CSVs are supported. Disk image, registry, EVTX and PCAP
  ingestion are not built.
- There is no authentication. The login screen is a UI prototype only.
- `app.py` runs with `debug=True` — turn this off before any demo or deployment.

## Contributors

Pull requests welcome. Please open an issue first to discuss changes.
