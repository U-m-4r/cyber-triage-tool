# Cyber Triage Tool — Project Plan (SIH1744)

**Problem Statement:** SIH1744 — Cyber Triage Tool for Digital Forensic Investigation
**Organization:** National Investigation Agency (NIA), Anti-Cyber Terrorism Division

## 0. Current State (as of last repo audit)

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
