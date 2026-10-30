# Phase 2 Review 2 — presentation content

## Slide A — External dataset
Two official CSE-CIC-IDS2018 daily flow CSVs: web attacks (22 February) and bots (2 March). Chosen before predictions to test known weak categories. Include benign traffic; evaluate every eligible row. Evidence: PROTOCOL.md, dataset-manifest.json, data-quality.json.

## Slide B — Methodology
Official CSV → explicit versioned feature adapter → validity ledger → original saved scaler → frozen XGBoost / Isolation Forest → unchanged threshold → predictions → ground-truth metrics. No training, calibration or tuning. Ground truth remains separate. Compatibility is conditional on documented CICFlowMeter family definitions, not a proved identical extractor build. Evidence: FEATURE_COMPATIBILITY.md, frozen-model-verification.json.

## Slide C — Results
Use external-confusion.png and attack-family-recall.png. Cite evaluation.json for every value.
- supervised: n=2,087,481, accuracy=77.8550%, recall=0.0133%, balanced accuracy=45.1270%, FPR=9.7593%. Evidence: evaluation.json models.supervised.overall.
- baseline: n=2,087,481, accuracy=80.3074%, recall=0.0607%, balanced accuracy=46.5682%, FPR=6.9243%. Evidence: evaluation.json models.baseline.overall.

## Slide D — Internal vs external
Use internal-vs-external.png and false-positive-negative-rates.png. Different populations/prevalence; do not attribute the entire difference to domain shift or call it a controlled experiment. Evidence: Issue 3 evaluation.json and Issue 4 evaluation.json.

## Slide E — Observations and limits
Use feature-distribution-shifts.png and class-distribution.png. PSI measures distribution changes against the frozen training reference. Explain per-family misses and false alarms. Mention conditional feature compatibility, related dataset origins, limited two-day coverage, retained duplicates, representation overlap and unknown live-network performance. No threshold adjustment was made. Evidence: drift.json, overlap.json, FEATURE_COMPATIBILITY.md.

## Live demonstration
Run verify_issue4 --serve, start React with BACKEND_PROXY_TARGET=http://127.0.0.1:5049 on 5219. Open Cases → a generated external case → Evidence → select CSE-CIC-IDS2018 external network-flow CSV → choose detector → choose .test-artifacts/issue4/demo.csv → Upload and process. Open Artifacts to inspect ID, score, fixed threshold and risk; refresh/reopen; open Reports and generate the saved-case PDF. Repeat for the other detector. Compare genuine labels only in the separate demo metrics. Do not cite the small stratified demo accuracy as dataset accuracy.

Future work only: establish exact extractor provenance, expand scenario/host/time-separated evaluation, and preregister any new model-training study separately. None of those activities was started during Issue 4.
