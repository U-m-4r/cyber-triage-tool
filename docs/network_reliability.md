# Network detector deployment and evidence

Issue 3's measured results, audit, limitations and commands are in
[the review report](../test-results/issue-3/REPORT.md). These are internal held-out
CICIDS2017 results, not independent external-network validation. In particular,
production XGBoost detected only 20 of 272 Web Attack flows in that test partition.

## Install the frozen detectors

Use the project Python environment (Python 3.14, scikit-learn 1.8.0 and XGBoost
3.4.1 for these reviewed bundles):

```powershell
python -m pip install -r requirements/dev.txt -r requirements/network-ml.txt
python -m scripts.acquire_network_models
```

The downloader retrieves only two project-owned joblib bundles from the versioned
`network-models-v1` GitHub release. It verifies exact lengths and SHA-256 hashes
against `models/network-artifacts.json` before saving. Joblib can execute code:
never deserialize uploaded models or substitute a third-party pickle. Offline
copies can be verified with `--source-dir <approved-directory>`. Existing files
with a different checksum are rejected rather than overwritten. These historical
bundles were verified unchanged; Issue 3 does not train a replacement model.

The PE malware classifier has separate setup and provenance; these two artifacts
are exclusively network detectors. Large datasets and model files stay outside
Git source history. Benchmark experiment estimators are optional local research
artifacts and are not selectable production detectors.

## Select and identify the detector

`GET /api/model` returns `models.baseline` and `models.supervised`, each with
availability, model identifier, artifact SHA-256, feature schema, provenance and
actual decision threshold. `GET /api/model/supervised` retains the supervised
status API. `NETWORK_DEFAULT_DETECTOR=baseline|supervised` sets the default;
baseline remains the compatibility default. The legacy supervised-enabled flag
continues to select the supervised default when no explicit setting is supplied.
A missing configured default is reported; the UI does not select an alternative.

`POST /api/analyze` accepts multipart `file`, optional `caseId`, and
`detector=baseline|supervised` (also supported as a query parameter). Network
ingestion through `/api/ingest` uses the same selector. Unknown selections return
400; a missing selected model returns 503 and an incompatible supervised model
returns a structured validation error. Uploads never fit a scaler,
train a model, or fall back to a different detector. `/api/evaluate` also respects
selection; its metrics describe the uploaded labeled data, not an assumed test set.

The Evidence tab lists only available detectors, shows the selection and exact
threshold, and displays measured attack/normal counts after processing. Artifacts
show each prediction, model score, threshold, model ID and separate triage risk.
Ingestion history, MongoDB case sources and PDFs preserve the selection.

## Input and score contract

Provide the eleven features in `ml.preprocessor.NETWORK_FEATURES`, in their saved
order. Duration is **microseconds**, packet counts are counts, packet lengths and
forward totals are bytes, and rates are bytes/second and packets/second. Real PE
files and disk images are not inputs to these detectors. Each selected bundle's
own fitted scaler transforms raw numeric features exactly once. Evaluation must
pass raw records to `infer_network`, never a supervised-scaled frame.

Isolation Forest's decision margin is negative for anomalies, with threshold 0;
it is not a probability. XGBoost's attack-class score uses the frozen validation
threshold 0.4343418846451664. It is not calibrated confidence or accuracy. The
saved numeric classes are 0 (BENIGN) and 1 (ATTACK).

Network triage retains the existing empirical policy: 60% ML severity plus 40%
rule severity. Supervised severity is 100 times the attack score; it must not be
negated as an anomaly margin. Missing ML uses existing rule-only scoring. Baseline
severity retains its legacy within-batch normalization of negative decision
margins, so baseline triage priorities can depend on the batch. Neither fusion
weight is a measured probability. Prediction counts use the model decision,
never the final risk band. Host/PE/YARA scoring is unchanged.

## Verification without training

```powershell
python scripts/check.py --all --no-training
python -m pytest --no-training --run-integration -q
python -m scripts.verify_network_models
python -m scripts.verify_network_threshold
python -m scripts.network_overlap_sensitivity --audit-db <generated-scratch.sqlite>
python -m scripts.verify_issue3 --serve
```

The full evaluation requires the exact approved local CSV and cleaning ledger
recorded in the review report. It will not download a dataset or train a model.
Scratch evaluation data lives in ignored `.test-artifacts/issue3/`; result JSONs
live in `test-results/issue-3/`. Reproduction replaces Issue 3's working outputs;
copy that directory before a new experiment if retaining multiple runs. Historical
`evaluation/benchmark/benchmark_results.json` is never overwritten by these tools.
The training benchmark requires explicit `--train-candidates` and refuses to
overwrite its previous results or model directory.

The real HTTP demo requires the dedicated local MongoDB test service on port
27018, owns a fresh UUID test database, and binds backend port 5039. Run a frontend
with its API proxy pointed to 5039 and open the generated case's Evidence,
Artifacts and Reports tabs. Upload the generated `demo.csv`, select each detector,
then reopen the case. The 84-row fixture is a class-stratified demonstration,
not a representative accuracy sample.
