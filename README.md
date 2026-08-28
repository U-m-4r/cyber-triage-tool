# Cyber Triage Tool

AI-assisted cyber triage tool for early-stage digital forensic analysis.

Cyber Triage Tool for Digital Forensic Investigation
(National Investigation Agency, Anti-Cyber Terrorism Division). See
[plan.md](plan.md) for the full requirement breakdown and roadmap.

## Codebase Verification & Testing Suite

All machine learning algorithms, forensic parsers, risk scoring models, chain-of-custody hashing, and backend API endpoints are actively covered and validated with a comprehensive test suite.

### Quick Verification Commands

```bash
# 1. Full Verification: Live pytest execution + Live in-memory triage demo + Model evaluation audit
python scripts/verify_results.py

# 2. Run only live unit and integration tests across all Python modules
python scripts/verify_results.py --tests-only

# 3. Direct pytest execution across the 45-item test suite
python -m pytest -v
```

### Tested Modules & Behaviors

| Test Module | Component Description & Verified Behaviors |
| :--- | :--- |
| [`tests/test_ml_core.py`](tests/test_ml_core.py) | **ML Pipeline Core**: `ForensicPreprocessor` NaN/inf drop and StandardScaler z-score normalization; `AnomalyDetector` batch min-max score mapping to [0, 100]; `RiskScorer` 60/40 ML-rule weighted fusion; CVSS v3.1 qualitative priority banding (LOW / MEDIUM / HIGH / CRITICAL). |
| [`tests/test_parsers.py`](tests/test_parsers.py) | **Forensic Artifact Parsers**: Windows EVTX logs (Event ID 4625 brute force aggregation), Windows Registry `.reg` hives & hex data, Network flow CSV column mappings, File system directory listings (CSV/JSON), and parser dispatcher auto-sniffing. |
| [`tests/test_scoring.py`](tests/test_scoring.py) | **Risk Scoring Engine**: Priority triage ranking, 0–100 risk score bounds enforcement, sorting by descending risk, and rule-only fallback scoring. |
| [`tests/test_chain_of_custody.py`](tests/test_chain_of_custody.py) | **Forensic Chain of Custody**: SHA-256 evidence hashing (NIST FIPS 180-4), chunked streaming, deterministic re-reads, tamper verification, and hash injection into analysis responses. |
| [`tests/test_forensics.py`](tests/test_forensics.py) | **Forensics Capabilities & Reputation**: Threat-intel provider fallbacks (OTX/VirusTotal), rule weight bumping on malicious reputation verdicts, EVTX flattening, and `/api/forensics/capabilities` reporting. |
| [`tests/test_evaluation.py`](tests/test_evaluation.py) | **Evaluation Mathematics**: Ground truth extraction for CICIDS2017 schema, Top-K triage lift calculation, confusion matrix precision/recall/F1/accuracy recomputation, and ROC-AUC curve generation. |
| [`tests/test_endpoints.py`](tests/test_endpoints.py) | **Backend REST API**: Flask `/api/ingest`, `/api/analyze`, `/api/health`, `/api/cases`, authentication token validation, and MongoDB artifact persistence. |

## Tech Stack

**Implemented**

- Python, scikit-learn, pandas — preprocessing, anomaly detection, risk scoring
- Flask + flask-cors — backend API
- React 19 + Vite + react-router-dom — investigator frontend
- Plain CSS with custom properties — no CSS framework
- MongoDB / pymongo — case persistence and dashboard data
- ReportLab — PDF triage report generation
- python-evtx + xmltodict, python-registry, yara-python, pytsk3 — forensic
  artifact parsing (Windows Event Logs, registry hives, YARA IOC scanning, disk
  images). Each is an optional dependency: the API degrades gracefully and
  reports capability via `/api/forensics/capabilities` if a library is absent.
- requests — OTX / VirusTotal threat-intel lookups (API keys via `OTX_API_KEY` /
  `VT_API_KEY`; skipped when unset)

**Planned, not yet wired up**

- Live frontend consumption of `/api/forensics/ingest` for disk-image uploads

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
| GET    | `/api/forensics/capabilities` | Working — reports which optional forensic parsers/providers are available |
| POST   | `/api/forensics/ingest` | Working — ingest EVTX / registry hive / disk image → parsed records, rule scoring, YARA IOCs, threat-intel |

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

**`Overview`, `Reports`, `Evidence`, `Timeline` and `IOC Graph` are implemented.**
The remaining tabs (`Artifacts`, `Analysis`, `AI Triage`) are visible but disabled,
each labelled `Planned` with a tooltip naming what it is waiting on.

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
forensics/   Optional parsers: EVTX, registry hive, YARA, threat intel, disk image
rules/       YARA rule files (*.yar) compiled by the IOC scanner
frontend/    React + Vite investigator UI
docs/        Per-module design notes
scripts/     run_evaluation.py — offline reproducible evaluation
tests/       pytest suite (ML core, chain of custody, forensics, evaluation)
data/        Datasets (gitignored — never commit the CSV/zip)
models/      Persisted .pkl models (gitignored)
reports/     Generated PDFs (gitignored)
evaluation/  evaluate.py (pure metric logic) + committed results.json / artifacts
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

## Extracted Features

The preprocessor scores on 11 numeric CICIDS2017 network-flow features. Rows with
`NaN`/`±inf` (e.g. divide-by-zero rate artifacts) are dropped rather than imputed,
then de-duplicated, and each column is standardized with a z-score.

| Feature | Description |
| ------- | ----------- |
| `Flow Duration` | Total lifetime of the bidirectional flow (microseconds). |
| `Total Fwd Packets` | Number of packets sent in the forward (client→server) direction. |
| `Total Length of Fwd Packets` | Sum of payload bytes across all forward packets. |
| `Fwd Packet Length Max` | Largest forward-packet size (bytes). |
| `Fwd Packet Length Min` | Smallest forward-packet size (bytes). |
| `Fwd Packet Length Mean` | Mean forward-packet size (bytes). |
| `Bwd Packet Length Max` | Largest backward-packet (server→client) size (bytes). |
| `Bwd Packet Length Min` | Smallest backward-packet size (bytes). |
| `Flow Bytes/s` | Byte throughput = total bytes / flow duration. |
| `Flow Packets/s` | Packet rate = total packets / flow duration. |
| `Packet Length Mean` | Mean size of all packets (both directions) in the flow. |

## Formulae and References

| Stage | Formula | Reference |
| ----- | ------- | --------- |
| Feature scaling (z-score) | `z = (x − μ) / σ` per column (mean 0, unit variance) | Han, Kamber & Pei, *Data Mining* 3rd ed. §3.5; sklearn `StandardScaler` |
| Isolation Forest score (canonical) | `s(x, n) = 2^(−E(h(x)) / c(n))` — `E(h(x))` mean path length across iTrees, `c(n)` avg unsuccessful-BST-search length; `s → 1` anomalous | Liu, Ting & Zhou, "Isolation Forest", ICDM 2008 |
| Batch score normalization | `a = −d(x)`; `score = (a − min a) / (max a − min a) · 100` (0 for a degenerate batch) | this repo — `ml/detector.py` |
| Hybrid risk fusion | `Risk = w_ml·anomaly + w_rule·(rule_score·100)`, capped at 100; default `w_ml = 0.6`, `w_rule = 0.4` (configurable) | Kittler et al. 1998 (classifier combination); NIST SP 800-30 Rev. 1 |
| Priority band | 0–100 risk → CRITICAL ≥ 75 / HIGH ≥ 50 / MEDIUM ≥ 25 / LOW below | CVSS v3.1 §5 qualitative severity scale |
| Precision / Recall / F1 | `P = TP/(TP+FP)`, `R = TP/(TP+FN)`, `F1 = 2·P·R/(P+R)` | Sokolova & Lapalme 2009 |
| Accuracy | `(TP + TN) / (TP + TN + FP + FN)` | — |
| ROC-AUC | area under the TPR-vs-FPR curve, computed on `−d(x)` | Fawcett 2006 |
| Top-K triage | `precision@k = hits / k_count`, `recall@k = hits / total_attacks` over the anomaly-ranked queue at k = 10 %, 25 % | information-retrieval precision@k / recall@k |
| Chain of custody | `SHA-256` digest of each uploaded file, streamed in 1 MiB chunks, opened read-only | NIST FIPS 180-4 |

## Dataset Setup

This project uses the CICIDS2017 dataset for evaluation.

1. Download from Kaggle:
   https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed

2. Place the file in the `data/` folder:
   `cyber-triage-tool/data/cicids2017_cleaned.csv`
   (label column: `Attack Type`; benign rows are `Normal Traffic`).

3. The `data/` folder is gitignored — never commit the CSV (~717 MB, 2.52M rows)
   or its `.zip` to this repo.

## Reproducible Evaluation

`scripts/run_evaluation.py` runs the exact evaluation logic used by the Flask
`/api/evaluate` endpoint (`evaluation/evaluate.py`) against the real, labeled
CICIDS2017 dataset — no mock data — and writes committed evidence:

```bash
python scripts/run_evaluation.py                 # full dataset (~2.52M rows)
python scripts/run_evaluation.py --rows 400000   # faster subset for iteration
```

Outputs (committed):

- `evaluation/results.json` — full metric bundle (accuracy, precision, recall,
  F1, ROC-AUC, confusion matrix, Top-K triage recall) + run metadata
- `evaluation/artifacts/confusion_matrix.png`
- `evaluation/artifacts/roc_curve.png`
- `evaluation/artifacts/topk_recall_curve.png`

Metric references: ROC-AUC — T. Fawcett, "An introduction to ROC analysis"
(2006); precision/recall/F1 — Sokolova & Lapalme, "A systematic analysis of
performance measures for classification tasks" (2009).

Latest committed run (full dataset, 1,829,580 rows after cleaning; unsupervised
IsolationForest on the 11 features above): accuracy **0.746**, ROC-AUC **0.620**,
top-25 % triage recall **0.304**. These are the honest unsupervised numbers on a
small feature subset — not a bug and not tuned to look better.

## Current Limitations

- The frontend renders authored sample data by default; a service layer exists to
  connect it to `/api/analyze` and `/api/forensics/*`.
- Disk-image upload has a backend endpoint (`/api/forensics/ingest`) but no
  dedicated frontend upload UI yet.
- PCAP parsing is not built.
- Threat-intel lookups (OTX / VirusTotal) require `OTX_API_KEY` / `VT_API_KEY`;
  without them those providers are skipped.
- Forensic parsers depend on optional native libraries (yara-python, pytsk3,
  python-registry, python-evtx); `/api/forensics/capabilities` reports what is
  available on the host.
- There is no authentication, and CORS is wide open. The login screen is a UI
  prototype only.
- `app.py` runs with `debug=True` — turn this off before any demo or deployment.

## Contributors

Pull requests welcome. Please open an issue first to discuss changes.
