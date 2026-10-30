# Issue7 — completed frozen PE classifier evaluation

**PASS for the frozen-model statistical evaluation and native application verification. Browser interaction remains UNVERIFIED. All work is local; no commits, pushes, branches, tags, releases or remote changes.**

Authoritative results: [corrected full evaluation](evaluation-v3/REPORT.md), [metrics](evaluation-v3/metrics.json), [unique-identity audit](evaluation-v3/unique-identity-analysis.json), [confidence intervals](evaluation-v3/confidence-intervals.json), [source hashes](source-lock.json), [feature compatibility](feature-compatibility.json).

## Sample accounting

All 960,000 records in both official archives were evaluated, with zero extraction/prediction errors and no exclusions. They represent **479,987 unique identities** (239,987 benign,240,000 malicious). 479,974 identities appear twice;13appear four times. Duplicate identities have identical labels and scores. Archive-row and unique-file metrics are both reported; repeated observations are not independent samples. The official balanced benchmark does not represent deployment prevalence.

## Primary unique-file results

| Metric | Actual |
|---|---:|
| accuracy | 0.981239075 |
| precision | 0.987037357 |
| recall | 0.975287500 |
| f1 | 0.981127251 |
| balanced_accuracy | 0.981239236 |
| specificity | 0.987190973 |
| false_positive_rate | 0.012809027 |
| false_negative_rate | 0.024712500 |
| roc_auc | 0.998320903 |
| average_precision | 0.998453037 |

Confusion matrix: TN=236,913; FP=3,074; FN=5,931; TP=234,069.

## Architecture and false-positive findings

Unique Win32:359,994 files; recall97.2783%, FPR1.1878%. Unique Win64:119,993 files; recall98.2800%, FPR1.5602%. Win64 has better recall but higher FPR; report both rather than concealing the tradeoff. Wilson intervals are descriptive IID approximations, not session/family-independent guarantees.
False-positive files have larger median sizes in both architectures (Win32 513,439 versus134,656bytes; Win64 528,608 versus297,984bytes). Win32 FP median section count6versus5; Win64 both7. Entropy patterns differ between categories; these associations do not prove a cause or establish packing. FP model-score medians:0.6845Win32 and0.7185Win64. Actual feature quantiles are in metrics.json. At this benchmark FPR, approximately12.81per1,000benign files are flagged for review, not proven malicious.

## Size cap and challenge comparison

Unique files above2MiB: 112,556/479,987 (23.4498%). Counts by label and header/size eligibility proxy are in input-limit-analysis.json. Retain the2MiB cap and20-second subprocess timeout; precomputed-feature evaluation does not verify resource costs of extracting larger raw files. Unknown/skipped results remain unclassified and coverage remains explicit.
Ordinary malware recall97.52875% versus preserved challenge2730/4039=67.59099% (1309misses). The challenge is evasive and positive-only: no challenge accuracy, precision, specificity or FPR is claimed. These numbers do not establish new-malware or deployment performance.

## Application / regression / presentation

Fresh harmless FAT12 demonstration:6files scanned,2realPE classifications,1independentYARA marker. Scores equal direct pinned-extractor/model inference; identity/threshold0.5match. Both launcher predictions were benign. MongoDB storage/retrieval and original evidence hash passed. The actual five-page PDF contains the saved findings; every page rendered, geometry checked and the PE summary visually inspected. RawPDF/image/executables stay ignored. demo/ contains genuine API/case/artifact/history outputs.
Actual React ArtifactTable server-rendering of the saved six-row API result passed, including both real PE predictions, model IDs, scores and paths. This is component verification, not browser acceptance. Exact browser limitation: **Local browser use is disabled in Work settings.** No bypass, repeated permission request or screenshots.
Current backend:415passed,46skipped,0failures/errors. Frontend:19passed; production build PASS. Static checks PASS. Skips include prohibited disposable training fixtures and absent primary forensic image; real controlled native PE/YARA/FAT12/MongoDB/PDF regressions ran. No network model behavior changed. Existing risk keeps YARA, ML and triage separate; malicious prediction applies max(rule risk,50), while benign or unavailable ML cannot lower rule risk.
Six readable benchmark figures are under evaluation-v3/. Dataset/model/count/threshold appear on each figure. All chart values are actual measurements. PDF summary sample: pdf-pe-summary.png.

## Preserved unsuccessful attempts

Initial root metrics.json is explicitly incomplete and is NOT the final result: optional COFF metadata and duplicated identities were incorrectly treated as fatal record errors. Its original implementation, receipt and full error ledger are preserved. evaluation-v2 was stopped with partial files preserved after duplicate handling was diagnosed. evaluation-v3 corrects reporting/accounting only; same source features, official processor, model and0.5threshold. No retraining, calibration or prediction-based exclusion occurred. This is a corrected computation on the same disclosed benchmark, not additional independent validation.

## Reproduction and manual review

Use the exact prerequisites, source revision and first-run commands in evaluation-v3/REPORT.md. For corrected evaluation in a fresh directory, copy the unchanged protocol/source-lock/API manifests and set PE_TEST_RESULTS and PE_TEST_WORK to that fresh namespace before running evaluate/report. Keep archives at .test-artifacts/issue7. Write-once receipts prevent accidental overwrites. Original and corrected code snapshots/receipts remain preserved.
Actual corrected commands:
```powershell
$env:PE_TEST_RESULTS='test-results/issue-7/evaluation-v3'
$env:PE_TEST_WORK='.test-artifacts/issue7/evaluation-v3'
rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_pe_test evaluate
rtk proxy .venv/Scripts/python.exe -m scripts.report_pe_test
```
For manual browser acceptance, run verify_issue7 --serve in a terminal with the owned local MongoDB on27018, start the frontend with BACKEND_PROXY_TARGET=http://127.0.0.1:5089, and open the emitted case ID. Inspect Evidence/Artifacts, verify model IDs/scores/YARA separation, refresh/reopen, then download the report. These interactions have not been claimed as tested.

## Local scope

Issue6B and all historical Issue2 results are preserved. Complete modified/new-file hashes and ignored artifact locations are in FILE_MANIFEST.json; final integrity/test checks are in verification.json. No source binaries, model files, datasets, credentials or databases belong in the eventual combined commit. No publication was performed. Stop after Issue7.
