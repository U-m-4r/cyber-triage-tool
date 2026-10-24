# ML baseline and multi-source detection roadmap

## Phase 1 — fixed, reproducible network baseline (this change)

- Train explicitly from the Kaggle CICIDS2017 cleaned CSV with `python scripts/train_baseline.py`.
- Save one versioned artifact containing the Isolation Forest, fitted StandardScaler, exact feature order, source name, dataset SHA-256, row count, and reference feature statistics.
- The API loads only `models/cicids2017_baseline.joblib` (or `CYBER_TRIAGE_MODEL_PATH`). It never trains from an uploaded CSV. Missing baseline returns HTTP 503; incompatible network feature schema returns HTTP 400.
- Inference uses the scaler fitted on the baseline training data. It does not refit normalization on each upload.
- Drift reports are monitoring signals only. A suspected shift does not trigger model updates or change the model.

## Learning strategy: unsupervised adaptation with strict controls

Unlabelled traffic is not automatically safe training data: an attacker can poison an adaptive baseline by repeatedly submitting crafted observations. For the first phase, automatic retraining is intentionally disabled. Future adaptation should be a separate scheduled job with all of these gates:

1. Keep the deployed baseline immutable and retain a known-good rollback artifact.
2. Maintain time-windowed drift metrics and a quarantine pool; never train on a single request or the same request that is being scored.
3. Require minimum sample counts, source diversity, rate limits, and outlier/contamination bounds before building a candidate.
4. Train a candidate artifact separately; run regression checks against a fixed CICIDS2017 holdout and a curated adversarial/host-artifact suite.
5. Promote only when metrics and alert-volume guardrails pass; retain automatic rollback and a complete model/version audit log.
6. Because labels are absent, describe outcomes as anomaly-detection performance and drift—not verified attack accuracy. Add analyst-confirmed labels later when available.

## Multi-source detection scope

The product target is a unified case-level triage view across:

- **Network flows:** CICIDS2017-compatible flow schema and unsupervised baseline.
- **Windows event logs (EVTX):** event IDs, logon/process/service activity and temporal counts.
- **Registry:** persistence, autoruns, service and security-configuration changes.
- **File artifacts:** metadata, hashes, YARA findings, signer/extension mismatches and suspicious paths.
- **Disk-image findings:** parsed filesystem metadata and recoverable artifact findings.

These sources do not share one meaningful numeric feature space. The current repository already has ingestion/parser and rule-scoring paths for several host artifact types; Phase 1 does not claim they are all covered by the network ML model. Next, define a versioned feature schema and separate detector/calibration per artifact family, preserve source provenance, and combine their outputs at the case-risk layer. Raw disk images and event logs must remain evidence; never mutate source files for feature extraction.

## Train the baseline

1. Download the Kaggle dataset documented in `scripts/train_baseline.py` and place it at `data/cicids2017_cleaned.csv`.
2. Install `requirements.txt`.
3. Run `python scripts/train_baseline.py`.
4. Confirm `models/cicids2017_baseline.joblib` exists, then start the backend.
5. For a quick smoke run only, `python scripts/train_baseline.py --rows 50000 --model-out models/cicids2017_smoke.joblib`; point `CYBER_TRIAGE_MODEL_PATH` at that smoke artifact only for local testing.

The dataset is not committed to Git. Do not use the smoke artifact as a production baseline. A model artifact created with joblib should only be loaded from a trusted local source.
