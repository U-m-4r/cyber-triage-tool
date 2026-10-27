# Cyber Triage Tool — Project Plan (SIH1744)

**Problem Statement:** SIH1744 — Cyber Triage Tool for Digital Forensic Investigation
**Organization:** National Investigation Agency (NIA), Anti-Cyber Terrorism Division

## 0. Current State (as of last repo audit)

> Historical roadmap/status below. For the current foundation and measured checks,
> see [Phase 1 progress](docs/phase1-progress.md) and [development setup](docs/development.md).
> This table predates native parsers, fixed-baseline inference and the startup overhaul.

| Component | Status |
|---|---|
| Flask backend (`backend/app.py`) | Working — comprehensive API for cases, dashboard, analyze, evaluate, and reports |
| Preprocessing (`ml/preprocessor.py`) | Working — CICIDS2017-specific cleaning, feature extraction, scaling |
| Anomaly detection (`ml/detector.py`) | Working — IsolationForest wrapper, joblib persistence |
| Risk scoring (`ml/risk_scorer.py`) | Working — wired into backend analysis endpoint |
| Report generation (`backend/report_generator.py`) | **Working** — Implemented using ReportLab, accessible via UI and API |
| Frontend | **Working** — React 19 + Vite UI, featuring Dashboard, Case Workspace (Overview, Analysis, Reports tabs) |
| MongoDB persistence (`backend/db.py`) | **Working** — Implemented for cases, analysis results, reports, and activity feed |
| Disk image ingestion (Sleuth Kit / pytsk3) | **Not present** |
| Log/registry/PCAP parsing (EVTX, registry hives, pcap) | **Not present** |
| IOC / threat-intel matching (YARA, OTX, VirusTotal) | **Not present** |

**Bottom line:** The repo currently solves requirement #4 (AI/ML anomaly scoring) against network-flow CSVs, and requirement #5 (Reporting) via PDF generation. The application features a robust End-to-End backbone (Seed case → open case → view evidence/findings → run analysis → save results → generate PDF). Requirements #1, #2, and #3 are unbuilt.

## 1. Target Architecture

```
[ Frontend: React 19 + Vite ]
       │  REST API
       ▼
[ Backend: Python — Flask ] ──▶ [ Forensic Engines: Sleuth Kit / pytsk3, python-evtx, python-registry, pyshark/scapy ]
       │
       ▼
[ AI Engine: scikit-learn IsolationForest (existing) → extend to Autoencoder / PyTorch (stretch) ]
       │
       ▼
[ Data Store: MongoDB ] ◀── [ Reporting: ReportLab (PDF) ]
```

## 2. Workstreams by Requirement

### Requirement 1 — Automated data collection from RAW images
- [ ] Add `pytsk3` to backend deps; write `ml/ingestion/disk_image.py` to mount/parse `.raw`, `.dd`, `.e01` read-only (write-blocking — never modify source metadata, preserve chain of custody)
- [ ] Add an ingestion manifest (hash of source image, timestamp, examiner ID) written before any parsing starts, for chain-of-custody
- [ ] Backend endpoint: `POST /api/ingest/image` — accepts upload or path, streams progress via SSE/WebSocket
- [ ] Frontend: drag-and-drop upload component + live progress bar

### Requirement 2 — Automated scanning of files, logs, registry, network
- [ ] `python-evtx` integration for Windows Event Log parsing
- [ ] `python-registry` (or shell out to RegRipper) for registry hive parsing
- [ ] `pyshark` or `scapy` for PCAP parsing → normalize to the same flow-feature schema `ml/preprocessor.py` already expects, so the existing IsolationForest pipeline can score it
- [ ] Consider `celery` + `redis` for parallel/background extraction jobs on large images
- [ ] Backend endpoint: `GET /api/artifacts?category=&risk_level=&from=&to=` for filterable log/artifact retrieval
- [ ] Frontend: dashboard view, filterable by category / timestamp / risk level

### Requirement 3 — IOC identification
- [ ] YARA rule integration (`yara-python`) for local signature matching against extracted files
- [ ] Threat-intel client for AlienVault OTX and/or VirusTotal (hash/IP/domain lookups) — cache results locally to avoid rate-limit issues during demo
- [ ] Backend endpoint: `POST /api/ioc/check` — batch-checks extracted hashes/IPs/domains
- [ ] Merge IOC hits into the same artifact schema used by the risk scorer, so a single priority score reflects both ML anomaly and IOC match

### Requirement 4 — AI/ML anomaly detection & scoring
- [x] Integrate ML pipeline into an End-to-End workflow (Upload -> Analyze -> Map findings -> Update case).
- [ ] Generalize `ml/preprocessor.py` beyond the CICIDS2017-specific feature list so registry/log/file artifacts (not just network flow) can be scored — likely needs per-artifact-type feature extractors feeding a shared scoring interface
- [ ] Implement `_extract_binary_ground_truth` equivalent for non-network artifacts if labeled data becomes available for those types
- [ ] Stretch: add an autoencoder (PyTorch) as an alternative detector, A/B against IsolationForest using existing `/api/evaluate` metrics (precision, recall, F1, ROC AUC, top-k triage metrics)

### Requirement 5 — Interactive timelines, graphical summaries, reporting
- [x] Implement `backend/report_generator.py` using ReportLab — PDF triage summary with: case metadata, top-N artifacts, priority breakdown
- [x] Wire `/api/report` to the new generator
- [ ] Frontend: timeline component (Vis.js Timeline or Recharts) with zoom-to-second on attack windows
- [ ] Frontend: pie charts / heatmaps (Shadcn UI + Tailwind + Recharts) summarizing compromised categories

## 3. Cross-Cutting / Infra
- [x] Decide on MongoDB now vs. later — implemented as the primary data store
- [ ] Add auth (even basic) before this touches anything resembling real evidence — currently no auth layer visible in `app.py`
- [ ] Turn off `debug=True` before anything resembling a demo/production run
- [ ] CI: at minimum, lint + a smoke test hitting `/api/health`, `/api/analyze` with a small fixture CSV

## 4. Suggested Sequencing (for a hackathon timeline)

1. **[DONE] Foundation:** React+Vite frontend talking to existing backend ML analysis. MongoDB persistence. ReportLab PDF generation. End-to-End flow.
2. **Log/registry/PCAP parsing:** extend ingestion beyond CSV — this unlocks requirement #2 and feeds more artifact types into the existing scorer.
3. **IOC matching:** YARA + one threat-intel API — requirement #3.
4. **Disk image ingestion:** pytsk3 — requirement #1 (often the most time-consuming; sequence last unless a judge demo specifically needs raw image upload).
5. **Timelines/visualizations:** polish pass on the frontend once real artifact data is flowing.

## 5. Phase 17 & Phase 18 Status: Advanced Triage, Calibration & Integrity

### Phase 17: Attack-Family Attribution & Triage Signal Engine [COMPLETED]
- [x] Supervised 6-family attribution model (Random Forest, 11-feature contract)
- [x] Conditional triage architecture separating binary detection from attribution
- [x] Structured triage signal schema (`ml/triage_engine.py`) with provisional prioritization
- [x] Baseline macro-F1: 0.9995, Weighted-F1: 0.9997 on held-out test partition
- [x] Historical benchmark artifact: `reports/attack_family_benchmark.json`

### Phase 18A: Confidence Calibration, Reliability Benchmarking & Attack-Family Integrity [COMPLETED]
**Status:** COMPLETE (All implementation, test, documentation, and benchmark gates verified).

#### Implementation & Calibration Summary
- [x] **Split Protocol & Leakage Controls:**
  - 70% Train (254,181 rows) split strictly internally into Train-Base (80%, 203,344 rows) and Train-Cal (20%, 50,837 rows).
  - Base `RandomForestClassifier` fitted exclusively on Train-Base.
  - Candidate calibrators (`CalibratedClassifierCV` with Platt Sigmoid and Isotonic Regression via `FrozenEstimator`) fitted on Train-Cal.
  - Validation partition (15%, 54,468 rows) used exclusively for calibration candidate selection; held-out Test partition (15%, 54,468 rows) kept strictly untouched until final evaluation.
- [x] **Calibrator Selection (Validation Evidence):**
  - Uncalibrated (Raw): Val Log Loss 0.00317, Val Brier 0.00082, Val ECE 0.00030
  - Platt Sigmoid: Val Log Loss 0.00328, Val Brier 0.00085, Val ECE 0.00011
  - **Isotonic Regression (Selected):** Val Log Loss 0.00563, **Val Brier 0.00079**, Val ECE 0.00025. Selected on lowest multiclass Brier score.
- [x] **Final Held-Out Test Calibration Results:**
  - Test Calibrated Brier Score: `0.00044` (improved from raw `0.00053`)
  - Test Calibrated ECE (10 bins): `0.00009` (a **5x error reduction** from raw `0.00045`)
  - Test Calibrated Log Loss: `0.00225`
  - Test Macro-F1: `0.9995` | Test Weighted-F1: `0.9998` | Test Accuracy: `99.98%`
- [x] **Duplicate Vector & Leakage Audit Findings:**
  - *Confirmed findings:* 6,161 test rows (11.3% of test partition) share an identical 11-feature vector with at least one Train row. Overlap is concentrated almost entirely in Port Scanning (96.9% overlap) due to repetitive single-packet SYN scanner probes with identical flow metrics in the dataset capture.
  - *Generalization proof on novel data:* Evaluated exclusively on the 48,307 test flows with ZERO feature overlap in Train: Accuracy **99.97%**, Macro-F1 **99.56%**, Weighted-F1 **99.97%** (Bots Recall 100%, Web Attacks Recall 99.66%). Confirms reported high performance is genuine generalization, not cross-partition memorization.
- [x] **Triage & API Semantics Integration:**
  - Preserved dual score reporting (`raw_confidence`, `calibrated_confidence`, `raw_margin`, `calibrated_margin`, `raw_scores`, `calibrated_scores`).
  - Abstention policy (`min_confidence=0.50`, `min_margin=0.05`) evaluates against calibrated confidence with graceful fallback to raw scores if calibration fails.
  - Attribution failures never override the independent binary detector; benign traffic remains `NOT_APPLICABLE`.
- [x] **Test Suite & Verification:**
  - Added unit and regression tests in `tests/test_attack_family.py` covering score properties (sum to 1 within numerical tolerance), class order stability, safe calibrator failure fallback, and Brier/ECE metric math.
  - Test execution: `C:\Python314\python.exe -m pytest` -> **292 passed, 2 skipped** (MongoDB integration skipped) in 26.86s.
- [x] **Artifact Paths:**
  - Model Bundle: `models/attack_family_bundle.joblib`
  - Calibration Benchmark Report: `reports/attack_family_calibration_benchmark.json`
  - Historical Baseline Report: `reports/attack_family_benchmark.json`
  - Documentation: `docs/attack_family.md`

### Phase 18B: Case-Management Persistence & Analyst Review Workflow [PENDING]
- [ ] MongoDB schema extensions for storing structured triage signals and calibration diagnostics
- [ ] Analyst review audit trail (provisional priority confirmation/override, triage notes, reviewer signature)
- [ ] Backend API endpoints for triage case review and status transition

### Phase 18C: Frontend Interactive Triage Workspace & Evidence Timeline [PENDING]
- [ ] React 19 triage dashboard components displaying multi-detector signal cards
- [ ] Confidence calibration indicator and candidate family margin visualizer
- [ ] Forensic evidence timeline with packet inspection drill-down

## 6. Phase 19 Status: Digital Forensics Disk Image Research & Ingestion

### Phase 19A: Find, Verify, and Acquire a Digital Forensics Disk Image [COMPLETED]
**Status:** COMPLETE (All research, acquisition, integrity hashing, validation, and test gates verified).

#### Multi-Source Candidate Research & Evaluation
- [x] **Kaggle Candidates Evaluated:**
  - `divyanshuprakash/cybercrime-forensic-dataset`: Evaluated for disk images; rejected because contents are tabular CSV event logs, not a binary filesystem capture.
  - `hiwotyirga/the-digital-forensics-2023-dataset-df2023`: Evaluated; rejected because contents are multimedia computer vision images (JPEG/PNG) for forgery detection, not storage volumes.
  - `ahmedashrafabdelmaksoud/memory-based-malware-artifacts`: Evaluated; rejected because contents are extracted Volatility tabular metrics, not a raw disk image.
  - `blackgaurd3/digital-corpora-pdfs-as-images`: Evaluated; rejected because contents are rendered JPGs of GovDocs1 PDFs.
- [x] **Digital Corpora Candidates Evaluated:**
  - **M57-Jean Scenario (`nps-2008-jean`)**: Windows XP corporate data exfiltration scenario. Evaluated; rejected due to multi-volume split E01 archive (`.E01` + `.E02`) requiring multi-gigabyte downloads and a 10 GB uncompressed storage footprint, exceeding practical limits for rapid local development and automated CI.
  - **NPS DOMEX Users (`nps-2009-domexusers`)**: Windows XP SP3 IM/email activity capture. Evaluated; rejected due to 8.2 GB uncompressed footprint and distribution as an encrypted or heavily redacted container requiring external key management.
- [x] **Kaggle Platform & Access Blockers:**
  - Kaggle does not host binary sector-level disk captures (`.dd`, `.raw`, `.E01`) due to storage policies and machine-learning focus.
  - Client environment blockers: `kagglehub` package not installed (`KAGGLEHUB_MISSING`), and Kaggle credentials unconfigured (`CREDENTIALS_MISSING`).

#### Primary Selected Dataset & Source
- [x] **Dataset Identity & Authority:**
  - **Dataset Name:** NIST CFReDS Deleted File Recovery Reference Test Image (DFR-01-NTFS)
  - **Identifier:** `nist-cfreds/dfr-01-ntfs`
  - **Canonical URL:** `https://cfreds-archive.nist.gov/dfr-images/dfr-01-ntfs.dd.bz2`
  - **Documentation URL:** `https://cfreds-archive.nist.gov/dfr-test-images.html`
  - **Organization:** National Institute of Standards and Technology (NIST), Law Enforcement Standards Office (OLES)
  - **License:** US Government Work / Public Domain (Unrestricted research and tool benchmarking)
  - **Selection Rationale:** Optimal balance of authentic Windows NTFS internal filesystem structures ($MFT, $LogFile, $Bitmap, $Boot, $AttrDef), manageable compressed size (2.15 MB), public domain license, and 100% native compatibility with `pytsk3.Img_Info`.

#### Download, Storage & Integrity Manifest
- [x] **Acquisition Execution:**
  - **Acquisition Command:** `python scripts/acquire_forensic_image.py`
  - **Storage Location:** `data/forensics/disk_images/` (ignored by `.gitignore`)
  - **Archive Path:** `data/forensics/disk_images/dfr-01-ntfs.dd.bz2` (2,257,102 bytes)
    - Archive SHA-256: `9625d8946bc7712953d0ca7e73e4eaeff26381006951d3f7603d1797b50d19e0`
  - **Extracted Disk Image:** `data/forensics/disk_images/dfr-01-ntfs.dd` (1,073,742,336 bytes, 1.0 GB)
    - Image SHA-256: `c863ccad01804b840a6dfa623a94996ca876e15ded41c6c0d8ae148620eb6493`
    - Format: RAW_DD (single-volume partition formatted with Microsoft NTFS)
    - Immutability: File permissions marked read-only (`chmod -w`) to preserve forensic chain of custody
  - **Provenance Manifest:** `data/provenance/forensic_disk_image.provenance.json` and `data/forensics/disk_images/manifest.json`

#### Validation & Pipeline Compatibility
- [x] **Direct Ingestion Verification:**
  - Evaluated via `forensics.disk_image.ingest_disk_image` (SleuthKit / pytsk3): Successfully parsed partition and directory tree, extracting 21 file records with valid timestamps and sizes ($AttrDef, $BadClus, $Bitmap, $Boot, $ObjId, $Quota, $Reparse, $Repair, $Tops, $TxfLog.blf, etc.).
  - Verified backend routing: `backend.app._dispatch_forensic_parser` recognizes `.dd` format and routes to `disk_image.ingest_disk_image`.
  - Verification command: `python scripts/acquire_forensic_image.py --verify-only` -> `valid: true, files_enumerated: 21`.

#### Automated Tests Executed
- [x] **Test Results:**
  - `tests/test_forensics.py`: 16 passed in 8.52s (covering Kaggle blocker diagnostics, candidate metadata, Digital Corpora candidate metadata, SHA-256 streaming, dry-run mode, tampering detection, and primary disk image parsing).
  - Full test suite: **298 passed, 2 skipped** (MongoDB integration skipped) in 24.33s.
  - Formatting & diff checks: `git diff --check` passed cleanly.

### Phase 19B: Disk-Image File Extraction, YARA Rule Matching & Forensics Ingestion Integration [PENDING]
- [ ] Implement file carving and extraction helper in `forensics/disk_image.py` for target artifact inspection
- [ ] Connect disk-image extracted files into YARA IOC scanning and rule scoring pipeline
- [ ] Add integration test verifying end-to-end disk image upload via `POST /api/forensics/ingest`
