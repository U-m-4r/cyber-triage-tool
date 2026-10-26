# Cyber Triage Tool - Current Implementation Context

Updated: 2026-10-24

This file is the current implementation snapshot for the repository. It is
intended to complement the longer historical handoff in
[`CLAUDE_CONTEXT.md`](./CLAUDE_CONTEXT.md).

## Project purpose

Cyber Triage Tool is an AI-assisted early-stage digital-forensics triage
application for SIH1744. It ranks suspicious evidence so an investigator can
review the highest-risk artifacts first.

## Implemented backend

- Flask API entry point: [`backend/app.py`](./backend/app.py)
- Network-flow CSV analysis:
  - [`ml/preprocessor.py`](./ml/preprocessor.py) cleans and standardizes the
    11 CICIDS2017 network features.
  - [`ml/detector.py`](./ml/detector.py) uses a persisted
    `IsolationForest`, with batch anomaly scores normalized to 0-100.
  - [`ml/risk_scorer.py`](./ml/risk_scorer.py) combines anomaly and rule scores
    using configurable 60/40 default weights and maps artifacts to LOW,
    MEDIUM, HIGH, or CRITICAL.
- Evaluation:
  - [`evaluation/evaluate.py`](./evaluation/evaluate.py) provides shared
    classification, confusion-matrix, ROC-AUC, and top-K triage metrics.
  - [`scripts/run_evaluation.py`](./scripts/run_evaluation.py) runs the
    reproducible CICIDS2017 evaluation and writes results and chart artifacts.
- Forensic ingestion:
  - [`ml/ingestion/base.py`](./ml/ingestion/base.py) dispatches normalized
    artifacts by explicit kind or file extension.
  - EVTX, registry, PCAP/text export, and file-listing parsers are present under
    [`ml/ingestion/`](./ml/ingestion/).
  - Optional native forensic integrations are present under
    [`forensics/`](./forensics/): EVTX, registry, YARA, threat intelligence,
    and disk-image enumeration through `pytsk3`.
  - Missing optional native libraries are reported through the capabilities
    endpoint instead of preventing application startup.
- Evidence integrity:
  - Uploaded evidence is hashed with SHA-256 in read-only, 1 MiB chunks before
    parsing.
  - The custody record is returned in API responses and persisted to a linked
    case when MongoDB is available.
- Persistence and reporting:
  - [`backend/db.py`](./backend/db.py) provides MongoDB initialization, seeding,
    and connectivity helpers.
  - [`backend/report_generator.py`](./backend/report_generator.py) generates
    ReportLab PDF triage reports.

## Implemented API surface

| Endpoint | Status |
| --- | --- |
| `GET /api/health` | Implemented |
| `POST /api/analyze` | Implemented; CSV analysis and top 100 artifacts |
| `POST /api/evaluate` | Implemented; labeled CSV evaluation |
| `POST /api/ingest` | Implemented; normalized log, registry, PCAP, and file-listing artifacts |
| `GET /api/artifacts` | Implemented; MongoDB-backed filtering and pagination limit |
| `GET/POST /api/cases` | Implemented; list and create cases |
| `GET/PUT /api/cases/:caseId` | Implemented; retrieve and update cases |
| `GET /api/dashboard` | Implemented; dashboard metrics and activity |
| `POST /api/report` | Implemented; generate a PDF report |
| `GET /api/report/:caseId` | Implemented; download a case report |
| `GET /api/reports/:caseId` | Implemented; list generated reports |
| `GET /api/triage/:caseId` | Implemented; retrieve triage data |
| `GET /api/forensics/capabilities` | Implemented; optional dependency capability report |
| `POST /api/forensics/ingest` | Implemented; forensic parsing, rule scoring, YARA, and threat-intel enrichment |

Authentication is conditional: setting `CYBER_TRIAGE_API_TOKEN` enables bearer
token or `X-API-Key` checks on protected endpoints. Without it, the application
logs that authentication is disabled for local development. CORS is controlled
by `CORS_ALLOWED_ORIGINS` and defaults to the permissive development setting.

## Implemented frontend

The frontend is React 19 + Vite + JSX with plain CSS. It does not use
TypeScript, Tailwind, or a charting library.

- Routes and shell: [`frontend/src/App.jsx`](./frontend/src/App.jsx)
- Landing page and login prototype
- Dashboard with sample investigation list, metrics, activity feed, and triage
  preview
- Case workspace at `/cases/:caseId`
- Implemented case tabs:
  - Overview
  - Evidence
  - Artifacts
  - Timeline
  - IOC Graph
  - Reports
- The Analysis and AI Triage case tabs are visible but intentionally disabled.
- Frontend services call the backend first and fall back to clearly labelled
  local fixtures when the backend is unavailable.
- The workspace is currently fixture-oriented; it does not yet provide a
  complete live evidence-ingestion workflow from the UI.

## Explicitly incomplete or deferred

- Live frontend upload and progress UI for `/api/forensics/ingest`, especially
  disk-image intake.
- Generalized ML feature extraction for non-network artifacts. Those artifacts
  currently use rule-based scoring in the ingestion path; the network CSV path
  uses IsolationForest plus rules.
- Full PCAP packet capture parsing beyond supported normalized/text exports.
- Interactive timeline zooming and richer visual analytics.
- IOC relationship graph backed by a graph data store.
- JSON/CSV report export; PDF reporting is implemented.
- Production identity/authentication, authorization, rate limiting, and
  deployment hardening.
- MongoDB is optional at runtime; case and artifact persistence is unavailable
  when MongoDB is not reachable.

## Verification status

- Frontend production build: **passed** with `cd frontend; npm run build`.
- Python test suite: **not collected in the current interpreter** because the
  active Python 3.14 environment is missing `numpy`. The dependency is declared
  in both [`requirements.txt`](./requirements.txt) and
  [`backend/requirements.txt`](./backend/requirements.txt). Install the project
  dependencies in the intended virtual environment, then run:

  ```bash
  python -m pytest -q
  ```

- Test modules cover ML core, parsers, scoring, chain of custody, forensics,
  evaluation, and API endpoints under [`tests/`](./tests/).

## Operational notes

- The backend listens on port 5001 when run directly.
- `models/isolation_forest.pkl` is reused once loaded; remove it when a fresh
  model is required.
- Sample frontend data must remain visibly labelled as sample data and must not
  be presented as live model output.
- Do not commit datasets, generated reports, temporary uploads, or persisted
  model artifacts.
