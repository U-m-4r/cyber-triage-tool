# Cyber Triage Tool — Project Plan (SIH1744)

**Problem Statement:** SIH1744 — Cyber Triage Tool for Digital Forensic Investigation
**Organization:** National Investigation Agency (NIA), Anti-Cyber Terrorism Division

## 0. Current State (as of last repo audit)

| Component | Status |
|---|---|
| Flask backend (`backend/app.py`) | Working — `/api/health`, `/api/analyze`, `/api/evaluate`; `/api/report` is a 501 stub |
| Preprocessing (`ml/preprocessor.py`) | Working — CICIDS2017-specific cleaning, feature extraction, scaling |
| Anomaly detection (`ml/detector.py`) | Working — IsolationForest wrapper, joblib persistence |
| Risk scoring (`ml/risk_scorer.py`) | Present, wired into backend, not yet inspected in detail |
| Report generation (`backend/report_generator.py`) | **Empty file** — not implemented despite ReportLab in requirements |
| Frontend | **Placeholder only** — `.gitkeep`, no actual UI code |
| Disk image ingestion (Sleuth Kit / pytsk3) | **Not present** |
| Log/registry/PCAP parsing (EVTX, registry hives, pcap) | **Not present** |
| IOC / threat-intel matching (YARA, OTX, VirusTotal) | **Not present** |
| MongoDB persistence | Listed in README, no `pymongo` usage found in code |

**Bottom line:** the repo currently solves only requirement #4 (AI/ML anomaly scoring) against network-flow CSVs. Requirements #1, #2, #3, and #5 are unbuilt.

## 1. Target Architecture

```
[ Frontend: Next.js + TypeScript ]
       │  REST + WebSockets/SSE (live progress)
       ▼
[ Backend: Python — FastAPI or Flask ] ──▶ [ Forensic Engines: Sleuth Kit / pytsk3, python-evtx, python-registry, pyshark/scapy ]
       │
       ▼
[ AI Engine: scikit-learn IsolationForest (existing) → extend to Autoencoder / PyTorch (stretch) ]
       │
       ▼
[ Reporting: ReportLab (PDF) + native JSON/CSV export ]
```

Decision needed early: **keep Flask or migrate to FastAPI.** FastAPI gives native async + WebSocket support and typed request/response models, which pairs well with a TypeScript frontend. Flask is faster to keep given the existing working code. Recommendation: keep Flask for now, add `flask-sock` or SSE for progress streaming, revisit FastAPI only if async ingestion becomes a bottleneck.

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

### Requirement 4 — AI/ML anomaly detection & scoring (mostly done)
- [ ] Finish inspecting/documenting `ml/risk_scorer.py` — confirm priority thresholds (CRITICAL/HIGH/MEDIUM/LOW) and output schema
- [ ] Generalize `ml/preprocessor.py` beyond the CICIDS2017-specific feature list so registry/log/file artifacts (not just network flow) can be scored — likely needs per-artifact-type feature extractors feeding a shared scoring interface
- [ ] Implement `_extract_binary_ground_truth` equivalent for non-network artifacts if labeled data becomes available for those types
- [ ] Stretch: add an autoencoder (PyTorch) as an alternative detector, A/B against IsolationForest using existing `/api/evaluate` metrics (precision, recall, F1, ROC AUC, top-k triage metrics)

### Requirement 5 — Interactive timelines, graphical summaries, reporting
- [ ] Implement `backend/report_generator.py` (currently empty) using ReportLab — PDF triage summary with: case metadata, top-N artifacts, priority breakdown, evaluation metrics if available
- [ ] Wire `/api/report` (currently 501) to the new generator; support PDF, and reuse Python's `csv`/`json` for those export formats
- [ ] Frontend: timeline component (Vis.js Timeline or Recharts) with zoom-to-second on attack windows
- [ ] Frontend: pie charts / heatmaps (Shadcn UI + Tailwind + Recharts) summarizing compromised categories
- [ ] Frontend: "Top Suspicious Artifacts" panel surfaced immediately on analysis completion

## 3. Cross-Cutting / Infra
- [ ] Decide on MongoDB now vs. later — README references it but no code uses it yet; needed once you persist case history across sessions rather than per-request processing
- [ ] Add auth (even basic) before this touches anything resembling real evidence — currently no auth layer visible in `app.py`
- [ ] Turn off `debug=True` before anything resembling a demo/production run
- [ ] CI: at minimum, lint + a smoke test hitting `/api/health`, `/api/analyze` with a small fixture CSV

## 4. Suggested Sequencing (for a hackathon timeline)

1. **Foundation:** Next.js scaffold + TypeScript interfaces (`ForensicArtifact`, `IocHit`, `TimelineEvent`) talking to existing `/api/analyze` — get an end-to-end demo working with what already exists (network-flow anomaly detection)
2. **Reporting:** implement `report_generator.py` — cheapest way to close a fully-stubbed requirement (#5's export piece)
3. **Log/registry/PCAP parsing:** extend ingestion beyond CSV — this unlocks requirement #2 and feeds more artifact types into the existing scorer
4. **IOC matching:** YARA + one threat-intel API — requirement #3
5. **Disk image ingestion:** pytsk3 — requirement #1 (often the most time-consuming; sequence last unless a judge demo specifically needs raw image upload)
6. **Timelines/visualizations:** polish pass on the frontend once real artifact data is flowing

## 5. Open Questions to Resolve Early
- Flask vs. FastAPI for the backend, given WebSocket/SSE needs
- Which threat-intel API to standardize on (rate limits matter for a live demo)
- Whether MongoDB is needed for the MVP or can wait
- Target disk image formats to actually support at launch (.raw/.dd only, or also .e01)
