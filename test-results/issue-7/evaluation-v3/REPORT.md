# Issue7 — frozen PE classifier evaluation

## Model, features and dataset

Official sources: https://github.com/FutureComputing4AI/EMBER2024 and https://huggingface.co/datasets/joyce8/EMBER2024 . Dataset/model/code declare Apache-2.0. Cite Joyce et al., EMBER2024 — A Benchmark Dataset for Holistic Evaluation of Malware Classifiers, KDD2025. Model and extractor were pretrained/authored upstream, never retrained here.
Exact deployed model: EMBER2024_PE.model; SHA256 `4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99`; model revision e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2. Frozen threshold0.5. Sigmoid score is not calibrated confidence.
Extractor v3 at 0ef753e81d98bf209f71b03cd331dfc190b5b54d: 2568float32 values, original twelve-block order, official hashing/normalization; no extra scaling, padding, imputation or truncation. Production checksum/dependency checks and direct model dimensionality assertions ran. Missing or nonfinite vectors produce explicit evaluation errors, not substitutions.
Full ordinary Win32 and Win64 test archives, revision3d23efef7c0f0b702c5024400cfff4c3744a3832. All12official testweeks, no sampling or prevalence balancing. Sources/source hashes and sizes: protocol.json and source-lock.json. All predictions preserve source identity, original label, week and first-submission date in the ignored ledger. Test labels never changed threshold or model. Benchmark prevalence is not deployment prevalence.

## Actual binary results

| Population | N | Benign | Malicious | Accuracy | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All | 960000 | 480000 | 480000 | 0.9812395833333334 | 0.9870373572064113 | 0.9752875 | 0.9811272511595056 | 0.01280833333333331 |
| Win32 | 720000 | 360000 | 360000 | 0.9804527777777777 | 0.9879371921529686 | 0.9727833333333333 | 0.9803017027816112 | 0.011877777777777765 |
| Win64 | 240000 | 120000 | 120000 | 0.9836 | 0.984375 | 0.9828 | 0.9835868694955965 | 0.015599999999999947 |

Malware prevalence: 0.500000. Complete metrics including balanced accuracy, specificity, FNR, ROC-AUC, AP and confusion matrices are in metrics.json. 95% Wilson recall/FPR intervals are in confidence-intervals.json. Correlation and sampling design limit nominal IID interval interpretation.
Repeated sample identities are retained in archive-row metrics; unique_identity_metrics in metrics.json reports deterministic first-observation deduplication separately. Label-conflict counts are explicit. Repetitions do not constitute independent observations, so row-based intervals may overstate precision.

## False positives and input-size coverage

False positives add review workload; they do not prove malware. false_positive_analysis in metrics.json compares benign FP/TN score, size, entropy, import-count and section-count quantiles separately by type. These feature associations are descriptive; no unknown binaries were obtained, inspected dynamically or executed. Architecture differences are reported without a causal claim or independent significance assertion.
The live cap remains2MiB with a killable20-second worker. It is a conservative resource policy, not a model dimension limit. The benchmark intentionally measures larger files too; metrics.json reports size counts by label and a separate application-header/size proxy subset. Existing SKIPPED_TOO_LARGE statuses retain null predictions and partial coverage. No unsafe increase is justified merely by feature-only throughput. The metadata proxy cannot verify section bounds, full parse success, worker duration or raw-byte integrity; benchmark accuracy is not full live-upload coverage.

## Ordinary versus challenge

Ordinary malware recall: 0.97528750. Preserved positive-only challenge: 2730/4039 detected, 1309missed, recall 0.67590988. Challenge accuracy/precision/specificity/FPR are undefined without negatives. Evasive-challenge construction differs from ordinary testing; no ordinary result guarantees evasive detection. Harmless launcher demos verify inference integration, not malware ground truth.

## Real disk-image / risk / persistence / reporting

Fresh verify_issue7 run creates a UUID-owned MongoDB and harmless FAT12 fixture. Two PyPA native launcher PEs are read through pytsk3, independently scanned by YARA and the actual classifier. Each model score matches direct extraction/inference, model identity and threshold are checked, MongoDB retrieval agrees, and original evidence SHA256 is unchanged. One separate harmless marker file matches YARA. Raw executables and PDFs stay ignored. Actual summary/upload/artifact/history/case records are under demo/. The genuine report was rendered on all pages, checked for off-page text, and its PE summary visually inspected. Browser interactions remain UNVERIFIED: Local browser use is disabled in Work settings.
Risk review found the existing policy separates ML predictions, YARA and forensic indicators. Malicious PE prediction sets max(existing rule risk,50), a documented HIGH-review floor; no scores are added and benign/unavailable results cannot reduce existing risk. Model scores are neither per-file accuracy nor proof of malware. Network inference is unchanged.

## Reproduction / slide notes

All commands use the existing pinned native environment. Data preparation is streaming with256-row batches; only feature JSON archives are downloaded. First-run commands:
```powershell
rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_pe_test download
rtk proxy .venv/Scripts/python.exe -m scripts.evaluate_pe_test evaluate
rtk proxy .venv/Scripts/python.exe -m scripts.verify_issue7
rtk proxy .venv/Scripts/python.exe -m scripts.report_pe_test
rtk proxy .venv/Scripts/python.exe -m pytest -q --no-training --run-integration
rtk proxy npm --prefix frontend run check
rtk proxy .venv/Scripts/python.exe scripts/check.py
```
Write-once protocol/receipt prevents overwriting this experiment. To reproduce, use a fresh output namespace in a separate checkout with the same verified sources; do not delete original receipts. No training or threshold selection is performed. All changes remain local, with no Git mutation or publication.
Slide: LightGBM combines static file statistics and PE structure through boosted decision trees. A fixed threshold yields a prediction for review; YARA provides independent signature evidence. The model does not execute files. Present ordinary two-class performance, evasive challenge recall and harmless integration demonstrations separately.

## Limitations / verification

Live scope is native I386 PE32/AMD64 PE32+ GUI/console only. .NET/ARM/drivers/EFI remain unsupported. Ordinary benchmark type metadata covers a broader group than byte-validated upload eligibility. Scores are uncalibrated. Dataset results do not establish new malware or real-world prevalence performance. Regression logs, final integrity checks and complete file inventory are recorded separately after execution. No historical network/PE results or Issue6B work are changed.
