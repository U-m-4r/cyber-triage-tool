# Issue #2: real PE malware ML verification

**Completion: PASS for the declared native PE inference scope.** Real model,
disk-image ingestion, independent YARA, MongoDB retrieval, React display/refresh,
PDF export and integrity checks all executed. Two-class benchmark performance is
not measured; positive-only challenge recall is measured below. No model training.

## 1. Preserved checkpoint and implementation

Issue #1 checkpoint commit: `4701b7d99fb3d22168031312353686e2a15f7a28`
(`Checkpoint verified Issue 1 file-level forensic integration`). Its branch remains
`codex/issue-1-file-yara`. Issue #2 branch: `codex/issue-2-pe-malware-ml`.
Current HEAD is the checkpoint; Issue #2 changes remain uncommitted. Only known
Issue #1 code, tests, documentation and small synthetic verification reports were
checkpointed. The existing untracked `dfr-01-ntfs.dd/` folder was excluded and
untouched. No forensic images, executables, model credentials or large datasets
were committed. Downloaded models and generated image fixtures are Git-ignored.

The read-only pytsk3 pipeline now passes each completely read file independently
to YARA and a dedicated PE malware classifier. Structural checks inspect MZ/PE
headers, machine, optional-header magic, subsystem, section table and bounds.
File extensions do not decide eligibility. Unsupported variants, extraction
failures, missing models and worker timeouts produce explicit per-file statuses.
No raw executable content is persisted in MongoDB.

## 2. Official model and dataset

Authoritative sources inspected:

- Project/code: https://github.com/FutureComputing4AI/EMBER2024
- Official model repository linked by the project:
  https://huggingface.co/joyce8/EMBER2024-benchmark-models
- Dataset: https://huggingface.co/datasets/joyce8/EMBER2024

Chosen artifact: `EMBER2024_PE.model`, official binary malicious/benign PE
LightGBM text model. Not a network model and not a pickle. Its objective is binary,
and max feature index 2567 matches the 2,568-dimensional official extractor.

Model repository revision: `e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2`.
Model size: 3,756,042 bytes. SHA-256:
`4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99`.
This matches the official Hugging Face LFS manifest and is verified before load.
Pinned official API manifests are saved beside this report.

Code, model card and dataset card declare Apache-2.0. Upstream LICENSE and research
attribution are retained under `third_party/ember2024`. The authors pretrained the
model on EMBER2024; this project did not train or fine-tune it. Official data uses
time-separated training/test partitions and a separate challenge partition. No
published benchmark numbers are presented here as reproduced measurements.

Initial resource assessment: 12 logical CPUs, 8.30 GB RAM total, approximately
0.813 GB RAM available, 53.46 GB storage free. Consequently only one small model
and the 32.14 MB challenge-feature archive were downloaded. No multi-gigabyte
training/test archive or raw malware was downloaded. Evaluation streams archive
records without expanding the full dataset or allocating a full feature matrix.

## 3. Feature compatibility and application support

Unmodified upstream extractor: EMBER2024 package 1.0.0, feature version 3, commit
`0ef753e81d98bf209f71b03cd331dfc190b5b54d`.
Source and warning vocabulary checksums are in `model-manifest.json`; runtime
checks enforce them. `.gitattributes` preserves those exact upstream bytes even
on Windows with Git autocrlf enabled.

Feature ordering is the official 12-block ordering (general, byte histogram,
byte entropy, strings, headers, sections, imports, exports, data directories,
Rich header, Authenticode, parser warnings). It produces 2,568 float32 values.
Normalization and hashing are performed by the upstream code; no additional
scaler, selection or reordering is applied. Dimensions and finite values are
checked before inference. Benchmark raw features use that same official
`process_raw_features` implementation.

Verified runtime: Windows AMD64, Python 3.14.7, LightGBM 4.6.0, pefile 2024.8.26,
signify 0.7.1, numpy 2.5.4, scikit-learn 1.8.0. Signify 0.9.1 was tested and found
incompatible because it removed SignedPEFile; the original compatible API is
explicitly pinned. A real feature/inference regression compares the worker score
with direct inference on the same official feature vector.

The upstream PE model includes Win32, Win64 and .NET. Application scope is
intentionally narrower: native I386 PE32 and AMD64 PE32+ Windows GUI/console
EXE/DLL. Actual x86 and AMD64 launcher executables were verified. ARM, CLR-managed,
drivers/native subsystem, EFI and other unverified variants are NOT_APPLICABLE.
Unpartitioned FAT12 raw images were used for live integration. E01 is not claimed.

## 4. Classification and risk policy

`pe_ml` records model ID/revision/checksum, extractor version, file SHA-256, file
type, actual model output, threshold, prediction/status and processing duration.
The returned `model_score` is LightGBM's direct binary sigmoid output, not a logit,
calibrated confidence, per-file accuracy or final risk score. API/persistence
retain full float precision; the dashboard rounds display to six decimals.

Threshold is fixed at **0.5**, selected before evaluation; no evaluation labels
are used for training or threshold tuning. For a CLASSIFIED malicious prediction,
file risk is `max(existing rule risk, PE_MALICIOUS_RISK_FLOOR)`. Default floor 50
uses the existing HIGH review band. This is a configurable review policy, not a
learned weight. It avoids adding YARA and ML scores together. Benign, unavailable
and failed ML results never lower existing forensic rule risk. Original rule
scores and network anomaly outputs remain distinct.

YARA failures do not block PE classification, and ML failures do not suppress
YARA results. Both directions are tested. Non-PE artifacts retain rule-only
scoring. A successful benign prediction is not a guarantee of safety.

ML input is capped at 2 MiB (configurable downward), subprocess duration defaults
to 20 seconds and is capped by remaining disk duration, and numeric threads are
limited to one. Existing file-count, total-read-byte and image-duration budgets
also apply. Each worker is killable on timeout; an actual timeout test executed.
There is no OS-level RAM quota, and concurrent deployment requests must be bounded.
The underlying pytsk3 calls still have cooperative rather than hard deadlines.

## 5. Independently reproduced evaluation

Dataset revision: `3d23efef7c0f0b702c5024400cfff4c3744a3832`.
Archive: official `challenge.zip`, 32,144,161 bytes, SHA-256
`dd215997b10596e4397d2b305d54afe9678e91e3051918262f0172b36e40baf1`.
This archive contains feature/label records, not executable malware bytes.

Predeclared scope: **all Win32/Win64 rows** in the official held-out challenge
partition. No prediction-based or label-based subsampling. 6,315 archive records
were inspected and duplicate sample hashes checked. 4,039 were evaluated (3,225
Win32; 814 Win64). All 4,039 have genuine official malicious labels. The other
2,276 were explicitly excluded by type: 829 Dot_Net, 805 PDF, 386 ELF and 256 APK.
Every exclusion is listed with its reason. There were **zero extraction/scoring
errors**, and no sample was silently discarded. Independence relies on the
authors' designated held-out challenge partition; we did not download all training
records to independently audit cross-partition duplicate hashes.
This is model evaluation on official feature records, not a test of raw-binary
parser coverage or application eligibility for every challenge sample.

| Metric | Actual result |
|---|---:|
| Evaluated malicious examples | 4,039 |
| Evaluated benign examples | 0 |
| True positives | 2,730 |
| False negatives | 1,309 |
| Recall | 0.6759098786828422 (67.59%) |
| False negative rate | 0.3240901213171577 (32.41%) |
| Threshold | 0.5 |
| Evaluation time, including retrieval/setup | 13.862 seconds |

Accuracy, precision, F1, ROC-AUC, false positive rate and specificity are **not
reported** from a positive-only partition. Their JSON values are null, not zero.
The confusion matrix displays only the observed malicious-label row; TN/FP are
unobserved. This deliberately difficult challenge measures recall on evasive
malware, not general-population accuracy. These false negatives demonstrate why
the model must not be treated as a definitive malware verdict.

Reproducible metrics, all 4,039 predictions, all 2,276 exclusions and the confusion
matrix are under `evaluation-v1/`. Full two-class benchmark evaluation remains
pending; it was not replaced by published scores or the harmless demo results.

## 6. Real disk-image demonstration

Selected final run: `d518cd32746749d3b322553f23c82caa/`.
Case: `CASE-5D4ADFE5E217`.
Owned MongoDB: `cyber_triage_test_d518cd32746749d3b322553f23c82caa`, port 27018.
HTTP backend: port 5029; React frontend: port 5199.

Harmless PE sources are the existing PyPA distlib console launchers bundled with
pip. Their license is copied into the evidence bundle; source paths, sizes and
hashes are recorded. They were never executed. They were placed in a controlled
FAT12 image alongside ordinary files and the harmless YARA test marker.

| File recovered from image | Type | Actual prediction | Actual model score | YARA matches | Risk / priority |
|---|---|---|---:|---:|---|
| /LAUNCH64.BIN | PE32+ AMD64 | benign | 0.012141118467631745 | 0 | 0 / LOW |
| /LAUNCH32.EXE | PE32 I386 | benign | 0.015420592563593584 | 0 | 0 / LOW |
| /POSITIVE.TXT | ordinary text | NOT_APPLICABLE | none | 1 | 25 / MEDIUM |

The .BIN filename demonstrates content-based PE recognition. The marker matched
`Harmless_File_Marker`; it is a test indicator, not known malware. The harmless
PEs demonstrate inference plumbing, not malicious-file detection accuracy.

Image: `harmless-fat12.img`, 1,474,560 bytes. SHA-256 before and after ingestion:
`bf113cc5fb48fe0e08f6568f5b7d6c077e91961dfc5efa6a4623200fc2e2f174`.

Recovered AMD64 bytes (108,032 bytes):
`81a618f21cb87db9076134e70388b6e9cb7c2106739011b6a51772d22cae06b7`.
Recovered I386 bytes (97,792 bytes):
`6b4195e640a85ac32eb6f9628822a622057df1e459df7c17a12f97aeabc9415b`.
These match the source launcher bytes, ML result hashes, artifact hashes and API
retrievals. Image integrity assertions passed.

Measured: 11 entries, six regular files, six YARA scans, five ignored non-file
entries, two PEs classified, two benign predictions, zero malicious predictions,
four ordinary NOT_APPLICABLE files, zero exclusions/errors, one YARA-matched file,
one rule match. Combined completion: **COMPLETE**.

| Timing scope | Seconds |
|---|---:|
| File reads and hashing | 0.000456 |
| YARA execution | 0.001377 |
| PE ML including worker startup/imports | 12.051435 |
| Disk analysis component | 12.058339 |
| Backend analysis before persistence | 12.095775 |
| Full HTTP upload through response, including persistence | 12.133063 |

Disk timing starts after model metadata preflight; backend timing includes that
preflight. HTTP timing includes middleware, upload, persistence and serialization.
These are measured single-run timings, not a throughput benchmark. The startup
cost reflects conservative process isolation on a memory-constrained machine.

## 7. MongoDB, React and PDF proof

Real HTTP requests created the isolated case, uploaded the image, then retrieved
case, artifact and ingestion records from MongoDB. Assertions compare full `pe_ml`
results, hashes, evidence SHA-256, intake ID, file paths and YARA findings. UUID
ownership checks and a per-run HTTP identity endpoint guard the test destination.
No existing investigation cases were updated or deleted. Test database and fixture
are retained for demonstration; fixture executables are not stored in MongoDB.

Actual React verification: saved PE predictions, model score/threshold, type,
path, hash, volume/inode, independent YARA result, priority and risk rationale
display correctly. Browser refresh retrieves the same six artifacts. Search
LAUNCH returns exactly the two PEs. The text marker retains YARA detection with
ML NOT_APPLICABLE. No browser console errors were observed. Screenshots and DOM
snapshots are saved in the selected run directory.

The actual report API generated the PDF from the persisted case. Final report
has five pages and was reopened, text-extracted, rendered and visually inspected.
The file-level model scores, model identity/checksum/extractor, YARA match, evidence
hashes, risk classification, coverage statistics and limitations are present.
The final scoring-engine heading includes the PE classifier, and finding headings
stay with their details. No benign prediction or no-match result is called safe.
The PDF text and per-page renderings are saved with the report.

## 8. Regression results

| Run | Passed | Skipped | Failures/errors |
|---|---:|---:|---:|
| Previous Issue #1 baseline | 319 | 46 | 0 |
| Issue #2 full suite, no training, real MongoDB | 336 | 46 | 0 |
| Focused PE/scoring/forensic checks | 39 | 1 | 0 |
| React service tests | 17 | 0 | 0 |

Runs overlap; do not sum them. Seventeen new PE tests cover real feature/inference,
structural validation, non-PE/malformed/ARM inputs, oversize, missing/tampered
models, actual worker timeout, explicitly injected extractor failure, configurable
risk policy, real image/database/report integration, reduced ML coverage and YARA
unavailability with continued genuine ML inference. The final added guard rejects
the upstream extractor's non-PE fallback if actual PE parsing fails; it is covered
by the final full suite. The earlier focused run preceded that added guard.
Policy/fault unit tests are
not counted as real model evaluation; the real experiment and challenge run are
separate evidence. Frontend production build and `git diff --check` passed.

The unchanged 46 baseline skips are 45 model/scaler-fitting-dependent tests and
one absent configured NTFS reference image. No Isolation Forest or XGBoost was
retrained. Warnings are existing sklearn feature-name notices plus test-only
pyfatfs/pkg_resources deprecation notices. All execution logs and JUnit results
are saved here. Existing CICIDS2017 evaluation files/model artifacts were untouched.

## 9. Files and functions

- `.gitattributes`: byte-exact upstream checkout handling.
- `.gitignore`: ignore downloaded PE text models.
- `ml/pe_features.py`: `identify_pe`, `get_extractor`, `extract_features`.
- `ml/pe_malware_detector.py`: `get_model_metadata`, `load_model`, `predict_file`,
  `_predict_local`, killable internal inference worker.
- `third_party/ember2024/features.py`, `pefile_warnings.txt`, `LICENSE`, `NOTICE.md`:
  pinned official extractor and attribution.
- `forensics/disk_image.py`: `analyze_disk_image`, independent ML dispatch, timers,
  per-file statuses and measured ML coverage counters.
- `ml/risk_scorer.py`: `score_records`, non-additive configurable PE review floor.
- `backend/app.py`: `forensics_capabilities`, `forensics_ingest`; preserves raw
  score precision and includes ML-only malicious findings in flagged artifacts.
- `backend/integration.py`: `finding`, preserves separate ML/rule explanations.
- `backend/report_generator.py`: `_build_threat_assessment`, `_build_findings`,
  `_build_evidence`, persisted ML provenance and findings.
- `frontend/src/components/case/CaseArtifacts.jsx`, `CaseArtifacts.css`: distinct
  model outputs, priorities, hashes and explanatory copy.
- `frontend/src/components/case/IntakeHistory.jsx`, `IntakePanel.jsx`: model
  availability, measured summary and upload explanation.
- `requirements/pe-malware.txt`: optional pinned inference dependencies.
- `scripts/acquire_pe_model.py`: explicit authentic model retrieval.
- `scripts/evaluate_pe_challenge.py`: genuine positive-only held-out evaluation.
- `scripts/verify_issue2.py`: harmless PE fixture and live HTTP/database/PDF proof.
- `tests/test_pe_malware.py`: seventeen new regression checks.
- `docs/pe_malware.md` and `test-results/issue-2/`: documentation and real evidence.

## 10. Exact reproduction commands

From repository root, with the existing project environment and native forensic
dependencies installed:

```powershell
rtk proxy .venv\Scripts\python.exe -m pip install -r requirements/pe-malware.txt
rtk proxy .venv\Scripts\python.exe -m scripts.acquire_pe_model
rtk proxy .venv\Scripts\python.exe -m scripts.evaluate_pe_challenge
```

Start the isolated MongoDB only if it is not already running on 27018:

```powershell
rtk proxy powershell -NoProfile -Command 'New-Item -ItemType Directory -Force .test-artifacts/issue1b-mongo | Out-Null; Start-Process -FilePath "C:\Program Files\MongoDB\Server\9.0\bin\mongod.exe" -ArgumentList "--dbpath", ".test-artifacts/issue1b-mongo", "--port", "27018", "--bind_ip", "127.0.0.1", "--logpath", ".test-artifacts/issue1b-mongo/mongod.log" -WindowStyle Hidden'
rtk proxy .venv\Scripts\python.exe -m scripts.verify_issue2 --serve
```

Demo extras, already installed in this environment: pyfatfs==1.1.0,
setuptools<81, requests and pypdf. Optional PDF rendering uses pymupdf.
`--serve` retains the test backend on 5029; stop that run-owned process before
rerunning. Each run creates a new UUID-owned database and fixture directory,
prints new case IDs and writes evidence under its own result directory.

In a separate terminal:

```powershell
rtk proxy powershell -NoProfile -Command '$env:BACKEND_PROXY_TARGET="http://127.0.0.1:5029"; npm --prefix frontend run dev -- --host 127.0.0.1 --port 5199'
rtk proxy .venv\Scripts\python.exe -m pytest --no-training --run-integration -q --junitxml=test-results/issue-2/regression-reproduced.xml
rtk proxy .venv\Scripts\python.exe -m pytest tests/test_pe_malware.py tests/test_scoring.py tests/test_forensics.py --no-training --run-integration -q
rtk proxy npm --prefix frontend run check
```

Open http://127.0.0.1:5199, enter an investigator display label and leave the token
blank for this loopback-only test app. Open the printed case. Capture Artifacts
filtered to LAUNCH with the AMD64 content status expanded, the POSITIVE marker
with its YARA rule, Evidence ingestion history with two classified files, and the
downloaded PDF. Refresh the case to show persistence. No recovered file needs to
be run. The live test app intentionally uses a missing network-model path so the
demo cannot accidentally invoke network inference; the PE model is independent.

## 11. PPT description and remaining limitations

LightGBM combines many decision trees trained on static file characteristics.
The official extractor summarizes bytes, strings, PE headers, sections, imports
and signature metadata into 2,568 features. The pretrained model outputs a score
that is compared with a fixed threshold. Independent YARA indicators and model
predictions then inform a transparent investigator-review priority. File execution
is never required.

Limitations: measured challenge recall is 67.59%, with 1,309 missed positive
samples; this is not a comprehensive detector. No independent two-class accuracy,
precision, F1, ROC-AUC, FPR or calibration study. No managed/ARM/driver support
claim, no E01 verification, no nested archive unpacking, no alternate-stream or
deleted-file guarantee. Files above the ML cap are explicitly excluded. Worker
startup adds latency. Strict native-parser preemption and process RAM quotas
remain deployment work; ordinary pytsk3 resource checks are cooperative. The
existing reference-image test remains skipped. Those limits are explicit and do
not replace the verified native PE pipeline with fabricated results.

Stop point: Issue #2 only. No subsequent issue or model training was started.
