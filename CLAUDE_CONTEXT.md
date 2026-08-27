# CLAUDE_CONTEXT.md

Handoff notes for a fresh Claude Code session. Written 2026-08-26 after building
the Phase 1 frontend; updated 2026-08-27 after building the case workspace,
MongoDB integration, and PDF reporting. Read this instead of re-scanning the repo.

---

## 1. Project Overview

Cyber Triage Tool — AI-assisted triage for early-stage digital forensic
investigation. Academic/hackathon project for problem statement **SIH1744**
(National Investigation Agency, Anti-Cyber Terrorism Division).

An investigator uploads forensic data; the tool ranks artifacts by risk so the
highest-value evidence is looked at first.

**Stack:** Python (scikit-learn, pandas) + Flask backend · React 19 + Vite
frontend · plain CSS · MongoDB (persistence) · ReportLab (PDFs). No TypeScript, no Tailwind.

**Architecture:**

```
CSV upload → ForensicPreprocessor → IsolationForest (AnomalyDetector)
           → RiskScorer (ML score 60% + rule score 40%) → ranked artifacts + priority band
```

Flask is a thin HTTP layer; all real logic lives in `ml/`. Processing is
per-request and stateless — nothing is persisted between calls except the
trained model pickle.

**Scope reality check:** the repo currently satisfies only requirement #4
(AI/ML anomaly scoring) against network-flow CSVs. Disk imaging, log/registry/
PCAP parsing, IOC matching and reporting are unbuilt. `plan.md` has the full
breakdown.

---

## 2. Repository Structure

| Path | Contents |
|---|---|
| `backend/app.py` | **Entry point.** Entire Flask API in one file. |
| `backend/db.py` | MongoDB integration (cases, reports, activity feed). |
| `backend/report_generator.py` | PDF generation using ReportLab. |
| `ml/preprocessor.py` | `ForensicPreprocessor` — load, clean, extract features, scale |
| `ml/detector.py` | `AnomalyDetector` — IsolationForest wrapper + joblib persistence |
| `ml/risk_scorer.py` | `RiskScorer` — rule engine, risk score, priority bands |
| `frontend/src/` | **Entry point** `main.jsx` → `App.jsx` (routes) |
| `evaluation/evaluate.py` | **Empty file.** |
| `docs/*.md` | Per-module design notes — read before changing `ml/` |
| `plan.md` | Roadmap + requirement-by-requirement TODO list |
| `data/`, `models/`, `reports/`, `temp/` | Gitignored working dirs (`.gitkeep` only) |

There is no `backend/tests/`, no pytest config and no ESLint config — see §4.

### Frontend layout (`frontend/src/`)

| Path | Contents |
|---|---|
| `App.jsx` | All routes |
| `routes/` | `LandingPage`, `LoginPage`, `DashboardPage`, `CaseWorkspacePage`, `ModulePlaceholder` (+ co-located CSS) |
| `components/dashboard/` | `AppShell`, `Sidebar`, `TopBar`, `Panel`, `StatCard`, `InvestigationRow`, `AiTriagePanel`, `ActivityFeed` |
| `components/case/` | `CaseHeader`, `CaseTabs`, `CaseOverview`, `InvestigationSummary`, `ThreatAssessment`, `PriorityFindings`, `RecommendedAction`, `EvidenceStatus` |
| `components/landing/` | `SiteHeader`, `CinematicBackground` |
| `components/ui/` | `Icon` (hand-rolled SVG set), `SeverityBadge` |
| `services/` | `apiClient` + `authService`, `dashboardService`, `triageService`, `caseService` |
| `data/` | `mockDashboard.js` (dashboard fixtures), `mockCases.js` (case-workspace fixtures), `navigation.js` (`NAV_ITEMS` sidebar + `CASE_TABS` workspace tabs) |
| `styles/` | `tokens.css`, `global.css`, `page.css`, `cinematic.css` |
| `hooks/` | `useEntranceMotion`, `useRouteMode` |
| `config/media.js` | Background video URL — see known issues |

---

## 3. How It Works

### Backend request flow (`/api/analyze`)

1. Multipart upload in form field **`file`**, saved to `temp/` with a UUID prefix.
2. `preprocessor.run_pipeline(path)` → returns `(df_scaled, df_raw, df_clean)`.
3. `_ensure_detector_loaded_or_trained` — loads `models/isolation_forest.pkl` if
   present, otherwise **trains on the uploaded data and saves it**. Guarded by a
   module-level `DETECTOR_READY` flag, so the first upload defines the model for
   the process lifetime.
4. `scorer.score_dataframe(df_clean, scores)` → risk-sorted DataFrame.
5. Returns `{summary: {total_records, critical, high, medium, low}, artifacts: [top 100]}`.
6. If a label column is found, adds an `evaluation` block.
7. `finally` deletes the temp file.

### Scoring specifics

- Anomaly score normalized via `1 / (1 + exp(raw * 10)) * 100`.
- `risk = anomaly * 0.6 + rule_score * 100 * 0.4`, capped at 100.
- Priority bands: **CRITICAL ≥ 75 · HIGH ≥ 50 · MEDIUM ≥ 25 · LOW below.**
  The frontend severity colours mirror these exact thresholds — change one, change both.
- Artifact type is sniffed from column names (`Flow Duration` → network,
  `EventID` → system_log, `FileName` → file, `RegistryKey` → registry), defaulting
  to `network`. Rule weights live in the `RULES` dict at the top of `risk_scorer.py`.
- IsolationForest convention: `predict` returns `-1` for anomaly, `1` for normal;
  `decision_function` is **higher = more normal**, so the code negates it for
  ranking and ROC AUC. Easy to get backwards.

### Feature coupling

`preprocessor.extract_features` hardcodes 11 CICIDS2017 network-flow column names
and silently drops any that are missing. Non-network artifacts therefore score on
whatever subset happens to match — generalizing this is a known TODO.

### Frontend flow

`/` landing → GET STARTED → `/login` → Authenticate → `/dashboard`.
Sidebar destinations other than `/dashboard` render a shared `ModulePlaceholder`
that names the phase which will fill it. Unknown paths redirect to `/`.

`/dashboard` → click a case ID or the row-tail **Open** control in Active
Investigations → `/cases/:caseId` (`CaseWorkspacePage`) → **Back to Dashboard**.
Clicking anywhere else in an `InvestigationRow` still only *selects* the case so
`AiTriagePanel` loads beside the list — the row therefore has two targets, and the
`/cases/:caseId` route is declared **before** the `NAV_ITEMS` placeholder routes in
`App.jsx` so it wins over the `/cases` placeholder.

Inside the workspace the tab is local component state, not a nested route, because
only `Overview` exists. When the other tabs are built they should become child
routes so a specific tab can be linked.

Components never call `fetch` directly: **components → services → `apiClient`**.
`apiClient` normalizes both backend error shapes (`{error: {code, message}}` and
`{error: "string"}`) into an `ApiError`.

### Case workspace data

`caseService.fetchCase(caseId)` now attempts to hit the backend API
(`apiClient.get(\`/cases/${caseId}\`)`) backed by MongoDB, and falls back to
`data/mockCases.js` fixtures if the API is unreachable. This ensures the UI
always renders something.

Each record carries: identity + counts (mirroring `ACTIVE_INVESTIGATIONS` so the
dashboard row and the workspace header can never disagree), `summary`,
`assessment`, `findings`, `recommendation`, `activity` (same shape `ActivityFeed`
consumes) and `evidence.sources` / `evidence.pending`.

Cases the sample data marks `INGESTING` or `CORRELATING` carry `assessment: null`
and `findings: []` on purpose, matching how `AiTriagePanel` already refuses to
invent results — the workspace renders honest pending states instead.

---

## 4. Development

```bash
cd backend && pip install -r requirements.txt && python app.py
```

```bash
cd frontend && npm install && npm run dev
```

Backend on `:5001` (see `app.py:634`), frontend on `:5173`. Frontend build: `npm run build`.
Preview a build: `npm run preview`.

**There are no test, lint or type-check commands.** Nothing to run before
committing except the frontend build, which is the only automated check that
exists. Do not tell the user tests pass — there are none.

Two requirements files: `backend/requirements.txt` is the minimal runtime set;
root `requirements.txt` adds pymongo, reportlab, python-evtx, xmltodict for
unbuilt phases.

---

## 5. Configuration

**Environment variables:** the Python side reads **none** — no `os.getenv`,
`os.environ` or dotenv usage anywhere. `.env.example` exists but is empty.

The only env var in the project is frontend-side:

| Variable | Purpose |
|---|---|
| `VITE_API_BASE_URL` | Overrides the API base. Defaults to `/api`, which Vite proxies to `http://localhost:5001`. |

**Config files:** `frontend/vite.config.js` — sets the port and the `/api` proxy.

**External services:** MongoDB is now integrated as the primary data store. CORS is
wide open (`CORS(app)`). No auth, no threat-intel API. The dataset is downloaded
manually from Kaggle.

---

## 6. Current State

### Implemented

- Working `/api/health`, `/api/analyze`, `/api/evaluate` with real metrics
  (accuracy, precision, recall, F1, per-class, confusion matrix, ROC AUC, and
  top-10%/top-25% triage precision/recall).
- Full preprocessing → detection → scoring pipeline for network-flow CSVs.
- Phase 1 frontend: landing, login, dashboard, module placeholders, service
  layer, design-token system. Verified end to end in the browser.
- Case workspace at `/cases/:caseId` — header, eight-tab strip, and the
  **Overview** tab (Investigation Summary, Threat Assessment, Priority Findings,
  Recommended Next Action, Recent Activity, Evidence Status). Reached from the
  dashboard; `Back to Dashboard` returns.
- **MongoDB persistence**: Implemented in `backend/db.py` for cases, analysis
  results, reports, and activity feed.
- **PDF Reporting**: Implemented via `backend/report_generator.py` using ReportLab,
  accessible via `/api/report` (or similar endpoints).

### Not implemented (deliberately deferred)

The workspace's Evidence, Artifacts, Analysis, AI Triage, Timeline, IOC Graph and
Reports tabs are disabled placeholders (though report generation exists on the backend) ·
no RAW/E01 disk imaging · no EVTX, registry or PCAP parsing · no IOC feeds or YARA
· no real auth · no graph database.

### Known issues

1. **`frontend/src/config/media.js` points the landing background video at a
   third-party CloudFront URL** taken from the design reference. Self-host it
   before any deployment. `CinematicBackground` falls back to a CSS gradient if
   it fails, so this is not load-bearing.
2. **`app.py` runs `debug=True`** — must be off for any demo or deployment.
3. **First upload defines the cached model.** If the first `/api/analyze` call
   receives an unrepresentative CSV, that model is pickled and reused. Delete
   `models/isolation_forest.pkl` to retrain.
4. **No auth on any endpoint**, and CORS allows all origins.
5. `plan.md`'s "Current State" table says the frontend is a placeholder — stale,
   the frontend now exists. Its target architecture also names Next.js +
   TypeScript, which was **not** the direction taken (see below).

### Decisions that should not be undone

- **The frontend is Vite + React 19 + JSX with plain CSS.** `plan.md` proposes
  Next.js + TypeScript and the old README claimed Tailwind + Recharts; both are
  superseded. Only 3 runtime dependencies (react, react-dom, react-router-dom).
  Charts, icons and score meters were hand-rolled rather than adding libraries.
- **Dashboard colour policy: hue carries severity and nothing else.** The
  `--accent*` tokens were deliberately *deleted* from `tokens.css` so accent
  creep fails at the token level. Interaction states, focus rings, active
  markers and progress meters are neutral greys. A red or orange element always
  means "more serious", never "clickable". `--sev-low` and `--sev-info` are
  colourless on purpose — nothing to decide. Do not reintroduce accent colours.
- **Sample data must stay labelled as such.** The header comment in
  `mockDashboard.js`, the `AiTriagePanel` footer disclaimer, and the dashboard
  page notice ("Sample data — no evidence has been parsed") are all intentional.
  Never present fixtures as real model output. The case workspace adds three more:
  the header comment in `mockCases.js`, the same notice in `CaseHeader`, and the
  `RecommendedAction` footer stating the recommendation was written by hand. The
  recommendations in particular must never be described as AI-generated.
- **A case's `severity` is the examiner's classification of the whole case, not a
  band derived from its score.** That is why `CASE-2026-0147` reads HIGH at a score
  of 87. The `ml/risk_scorer.py` thresholds apply to *individual artifacts*, which
  is where `assessment.artifactPriorities` uses them. Findings show risk as a bare
  number with no on-screen claim that the band follows from it, and they are sorted
  by severity rank first so no band inversion is ever visible. Do not "fix" this by
  rebanding the case fixtures.
- **`InvestigationRow` has two click targets on purpose.** The full-row hit area
  selects the case (cheap, reversible, keeps the big target); the case ID and the
  row-tail Open link navigate to the workspace. `InvestigationRow.css` sets
  `pointer-events: none` on all row content so clicks fall through to that hit
  area, so any new link inside a row must set `pointer-events: auto` or it will be
  dead.
- The landing page deliberately has **exactly one CTA** (GET STARTED) and no
  fake dashboard preview, fake metrics or second login link.
- `--sev-low` and `--sev-info` are intentionally colourless — nothing to decide.

---

## 7. Coding Conventions

**Python (`ml/`, `backend/`)**

- Classes wrap each pipeline stage; no framework abstractions.
- Progress reported with `print("[+] ...")` in `ml/`, `logging` in `backend/`.
  Match whichever file you are in.
- `backend/app.py` uses `_leading_underscore` module-level helpers and returns
  errors via `_api_error(message, status, code)`.
- Never let an exception body reach the client — `app.py` catches, logs with
  `logger.exception`, and returns a generic message.
- `risk_scorer.py` uses preallocated lists/arrays and `itertuples` because it
  runs over millions of rows. Do not rewrite as `iterrows` or `apply`.

**Frontend**

- One component per file, CSS co-located as `Component.css`, imported by the
  component. Never import a stylesheet from another stylesheet — it double-inlines.
- Token layering: `tokens.css` → `page.css` / `cinematic.css` → `global.css` →
  component CSS. Put new shared values in `tokens.css`.
- Mock data stays in `data/`, never inline in components.
- Comments explain *why* a rule exists, not what it does. Follow that register.

**Avoid changing**

- The priority thresholds in `assign_priority` and their frontend mirrors.
- `run_pipeline`'s 3-tuple return `(df_scaled, df_raw, df_clean)` — `app.py`
  depends on the order.
- The `file` form-field name — `apiClient.postFile` and the backend agree on it.
- The `--accent*` deletion and the severity-only colour policy.

---

## 8. Read These First

| Task | Read in this order |
|---|---|
| Backend / API work | `backend/app.py`, then `docs/flask_api.md` |
| Scoring or detection logic | `ml/risk_scorer.py`, `ml/detector.py`, `docs/risk_scoring.md` |
| New artifact types / features | `ml/preprocessor.py`, `docs/preprocessing.md`, then `RiskScorer.detect_artifact_type` |
| Metrics / evaluation | `_evaluate_predictions` in `app.py`, `docs/evaluation_metrics.md` |
| Frontend feature | `frontend/src/App.jsx`, the relevant `routes/` file, then `services/` |
| Case workspace work | `routes/CaseWorkspacePage.jsx`, `data/mockCases.js`, `components/case/CaseOverview.jsx` |
| Frontend styling | `frontend/src/styles/tokens.css` first — it documents the colour policy |
| Connecting UI to backend | `services/apiClient.js`, `services/dashboardService.js`, `vite.config.js` |
| Planning next phase | `plan.md` §2 (workstreams) and §4 (sequencing) |

Skip `evaluation/evaluate.py` — it is an empty stub. `backend/report_generator.py` is fully implemented.

---

## 9. Git / Workflow

- Single `main` branch; PRs merge into it.
- `frontend/` **is** tracked — it was committed in `7822302` (PR #19). An earlier
  version of this file claimed it was still untracked; that was stale.
- Never commit datasets, `.pkl` models, or generated PDFs. `.gitignore` covers
  `data/*.csv`, `models/*.pkl`, `reports/*.pdf`, `temp/`, `node_modules/`.
- Before committing frontend changes, run `cd frontend && npm run build` — the
  only automated check in the repo.

---

## 10. Next Planned Phase

The foundational end-to-end flow is complete (React UI → Flask API → ML Analysis
→ MongoDB → PDF Report). The next phase involves extending ingestion beyond network
CSV flows to unlock new artifact types. In order of priority:

1. **Log/registry/PCAP parsing**: Add `python-evtx`, `python-registry`, `pyshark`/`scapy`
   to feed more artifact types into the existing scorer.
2. **IOC matching**: Integrate YARA and a threat-intel API for file and network indicators.
3. **Evidence & Artifacts tabs**: Build out the frontend data tables for the newly
   ingested multi-format data.
4. **Disk image ingestion (pytsk3)**: Raw image mount and read-only extraction (often
   time-consuming, sequence near the end).
5. **Timeline and Graph visualizations**: Polish the UI with temporal and relationship
   views.

Make sure to generalize `ml/preprocessor.py` to handle non-network features as part
of step 1.
