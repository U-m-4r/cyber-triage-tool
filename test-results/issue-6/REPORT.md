# Issue 6 — real recall gains, deployment rejected

**Completion: PARTIAL for the operational model-improvement objective.** The complete research workflow ran, but the selected challenger failed prespecified FPR and family-coverage gates. No incumbent model, scaler, threshold, detector default, historical result or forensic pipeline was changed.

## 1. Root-cause investigation / existing weaknesses

The historical Issue 4 archived population contains 2,087,481 rows and is diagnostic only. Its archives were verified against the previously published SHA-256 before analysis.
High ROC-AUC does not imply useful recall at a specific FPR or review budget. The external attack score median is 0.0016083799, while the frozen threshold is 0.43434188. The benign score distribution has a large high-score plateau. This is not solely an easily repairable threshold offset.

| Historical model | Retrospective recall @1% FPR | @5% FPR | @10% FPR |
|---|---:|---:|---:|
| supervised | 0.011516% | 0.011516% | 0.039434% |
| baseline | 0.036642% | 0.049555% | 0.107484% |

These operating points use already inspected labels and are **not deployed or used to select the new threshold**. Historical high-score benign ties limit low-FPR/top-K behavior even though many low-scoring attacks outrank other benign flows. Nine figures and the score/curve JSONs show this directly.
Measured evidence also supports representation and label limitations: the final audit found 6,889 identical float32 input groups carrying both labels, covering 372,711 rows. Even an otherwise perfect deterministic classifier of these eleven inputs must misclassify at least 32,568 observed records (1.5572%). This does not identify whether the publisher labels, information loss, or traffic construction is responsible.
Issue 4 measured feature shift and source-rate units; the candidate training/final feature histograms also differ. Exact CICFlowMeter binary/build equivalence remains unproven. This study does not establish a unique causal explanation or claim that distribution shift alone caused failure. Production inference still scales exactly once; the previously corrected benchmark double-scaling defect was not reintroduced.

## 2. Datasets, feature engineering and leakage prevention

Official dataset origin: [UNB/CIC documentation](https://www.unb.ca/cic/datasets/ids-2018.html) and [AWS open-data registry](https://registry.opendata.aws/cse-cic-ids2018/). Source selection and gates were committed in cb47698; source hashes/implementation in cd68caa; validation selection in 567f3ac, all before final label evaluation. Exact lock and receipt timestamps/hashes are in JSON.

| Locked final source | Bytes | SHA-256 |
|---|---:|---|
| Friday-16-02-2018_TrafficForML_CICFlowMeter.csv | 333,723,605 | `1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b` |
| Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | 382,840,456 | `d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b` |

The previously inspected Feb 22 web and Mar 2 bot days are development only. CICIDS2017 uses only its existing eligible training mask. Alternating whole 10-minute blocks on the development days separate train/validation; training boundary minutes are embargoed. Deterministic bottom-hash family caps are declared in PROTOCOL.md. No final-test labels, model predictions, port/IP/day identifiers or timestamp enter training features.
Before training, **unlabeled final features** informed a conservative quarantine of development vectors. This is explicitly transductive overlap control, not an untouched-covariate or independent-site test. Training was also purged against validation; exact float32 and rounded-log-bin overlap counts are all zero. These 64-bit hashes/bin relations do not prove all session/host/near-duplicate separation. The two new days can share the 2018 testbed; independent bot scenario validation is unavailable.

| Partition | Sampled | Purged against final features | Retained |
|---|---:|---:|---:|
| train | 123,663 | 46,514 | 53,972 |
| validation | 60,189 | 35,467 | 24,722 |

Training additionally lost 11,759 validation-overlap rows and 11,418 duplicate model-input rows; 0 conflicting-label training rows were excluded. Full group distributions/identities, quality and stage counts are recorded in prepared.json. Development is quota sampled, so validation precision reflects its selected prevalence.
Candidate schema `network-generalization-11-v1`: the same ordered eleven measured features; identity float32 preprocessing, no scaler fitting, imputation, calibration or guessed features. Expanded Candidate B was not approved because the reviewed 2017 source and supported application uploads do not supply the additional 2018 IAT/flag fields. The incumbent validation path restores original float64 source values before applying its own saved scaler; it does not mistakenly standardize already rounded candidate input.

## 3. Candidate training and validation-only selection

Exactly two candidates, seed 42, two threads, at most 300 rounds, fixed regularization and 30-round validation-logloss early stopping. Training-only source/family sample weights give each observed training group equal total weight; metadata records all weights. No hyperparameter or seed search. Class balancing changes score semantics; outputs remain uncalibrated.

| Candidate | Fit seconds | Best round (zero based) | Validation threshold | Recall | Precision | FPR | AP |
|---|---:|---:|---:|---:|---:|---:|---:|
| xgboost | 4.3069 | 299 | 0.0922404826 | 1.000000 | 0.937663 | 0.045753 | 0.999949126 |
| lightgbm | 2.8019 | 297 | 0.137265888 | 1.000000 | 0.963204 | 0.026291 | 0.999955549 |

Validation N=24,722, benign=14,644, attacks=10,078. Threshold maximizes recall under empirical FPR <=5%, preserving entire score ties; ties prefer precision and higher threshold. Candidate selection maximizes validation macro original-attack-label recall, then AP, then FPR/name. Both reached macro family recall 1; the prespecified AP tie-break selected **lightgbm**. The tiny AP difference is not evidence of stable algorithm superiority. Rare validation web counts are 28 brute-force, 20 XSS, 14 SQL; bot validation shares a known capture scenario.

| Candidate | Recall @validation FPR 1% | @5% | @10% |
|---|---:|---:|---:|
| xgboost | 0.999008 | 1.000000 | 1.000000 |
| lightgbm | 0.998909 | 1.000000 | 1.000000 |

The frozen incumbent was also diagnosed at validation-only retuned points (never deployed):

| Validation FPR budget | Threshold | Recall | Actual FPR |
|---|---:|---:|---:|
| 0.01 | 0.0571883954 | 0.004068 | 0.009833 |
| 0.05 | 0.00205539097 | 0.012701 | 0.047460 |
| 0.1 | 0.00137417414 | 0.017960 | 0.084471 |

Training memory observation correction: the original monitor saw the Windows venv launcher, not the worker. The sealed selection resource field is mislabeled and **not a valid training RSS measurement**. resource-observation-note.json records this; no refit was performed to hide the issue. A separate actual-process, validation-only inference memory measurement is in candidate-performance.json. The future watchdog now includes recursive child processes.

## 4. One-shot final results

Common final population: **2,091,441**, including 1,489,073 benign and 602,368 attacks. Only the sealed challenger and frozen production incumbent were evaluated. No final threshold/model tuning or XGBoost-challenger final evaluation was performed.

| Metric | Frozen incumbent XGBoost | Selected research LightGBM |
|---|---:|---:|
| accuracy | 0.653543179 | 0.734422821 |
| precision | 0.000196280 | 0.563527281 |
| recall | 0.000039843 | 0.345544584 |
| f1 | 0.000066240 | 0.428401334 |
| macro_f1 | 0.395269714 | 0.627714754 |
| balanced_accuracy | 0.458970893 | 0.618639284 |
| roc_auc | 0.741025445 | 0.772177073 |
| average_precision | 0.468640273 | 0.517277101 |
| specificity | 0.917901943 | 0.891733985 |
| false_positive_rate | 0.082098057 | 0.108266015 |
| false_negative_rate | 0.999960157 | 0.654455416 |

| Model | TN | FP | FN | TP |
|---|---:|---:|---:|---:|
| incumbent | 1,366,823 | 122,250 | 602,344 | 24 |
| challenger | 1,327,857 | 161,216 | 394,223 | 208,145 |

| Final source | Original rows | Eligible | Excluded |
|---|---:|---:|---:|
| Friday-16-02-2018_TrafficForML_CICFlowMeter.csv | 1,048,575 | 1,048,574 | 1 |
| Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | 1,048,575 | 1,042,867 | 5,708 |

All exclusions and original label/reason counts are explicit in final-results.json and the ignored row ledger. One Feb 16 repeated-header/invalid measurement row and 5,708 invalid-measurement Feb 23 rows were excluded. No difficult attacks were selectively removed. 817,528 duplicate copies and 6,889 conflicting binary-label groups are retained. The initial feature audit had unused zero rate-check placeholders; its initial record is preserved, and the corrected audit removes those unmeasured fields without changing any ambiguity counts.

## 5. Attack-family and capture-day performance

| Publisher attack label | N | Incumbent TP / FN | Challenger TP / FN | Incumbent recall | Challenger recall |
|---|---:|---:|---:|---:|---:|
| DoS attacks-SlowHTTPTest | 139,890 | 0 / 139,890 | 0 / 139,890 | 0.000000 | 0.000000 |
| DoS attacks-Hulk | 461,912 | 0 / 461,912 | 207,690 / 254,222 | 0.000000 | 0.449631 |
| Brute Force -Web | 362 | 21 / 341 | 286 / 76 | 0.058011 | 0.790055 |
| Brute Force -XSS | 151 | 0 / 151 | 133 / 18 | 0.000000 | 0.880795 |
| SQL Injection | 53 | 3 / 50 | 36 / 17 | 0.056604 | 0.679245 |

These are **binary** detection recalls grouped by genuine labels, not implemented attack-family classification. SQL N=53 and other web counts are limited; session/testbed dependence limits statistical certainty. SlowHTTPTest remains 0/139,890 despite aggregate gains. There is no new independent bot result.

| Final day | Model | Recall | Precision | FPR |
|---|---|---:|---:|---:|
| Friday-16-02-2018_TrafficForML_CICFlowMeter.csv | incumbent | 0.000000 | 0.000000 | 0.000369 |
| Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | incumbent | 0.042403 | 0.000197 | 0.117130 |
| Friday-16-02-2018_TrafficForML_CICFlowMeter.csv | challenger | 0.345114 | 0.993062 | 0.003248 |
| Friday-23-02-2018_TrafficForML_CICFlowMeter.csv | challenger | 0.803887 | 0.002840 | 0.153281 |

## 6. Operating budget, performance and deployment decision

| Final model | Load seconds | Chunk inference seconds | Flows/second |
|---|---:|---:|---:|
| incumbent | Not measured in final harness | 6.177079 | 338,581 |
| challenger | 0.532419 (challenger only) | 17.286177 | 120,989 |

Observed final-process RSS was 315,019,264 bytes (sampled observation, not an OS-enforced quota); complete final evaluation elapsed 95.564s. Inference timings exclude CSV IO and metric computation. Candidate validation-only memory/load timing is separate. Top-K recall uses conservative bounds when a review boundary intersects tied scores; no labels are used to break ranking ties.

| Prespecified gate | Result |
|---|---|
| recall_gain_at_least_10pp | PASS |
| overall_fpr_at_most_5pct | FAIL |
| every_day_fpr_at_most_5pct | FAIL |
| precision_at_least_20pct | PASS |
| balanced_accuracy_at_least_60pct | PASS |
| supported_family_recall_at_least_10pct | FAIL |
| inference_at_least_1000_flows_per_second | PASS |
| loading_under_5seconds | PASS |

**Decision: RETAIN INCUMBENTS.** New optional deployment is disallowed because the challenger fails overall/per-day FPR and family coverage gates. No application schema/default/threshold changes, no misleading fallback and no challenger selection in React. The new model is an experimental text artifact only. Research packaging/acquisition is opt-in, hash-pinned, and explicitly marked rejected; it never replaces production files. Further improvement requires another protocol and newly unused test source, not continued tuning against these final results.

## 7. Application and regression verification

Real HTTP demo run `d581b403c70d4964920d10875710ec37`, separate owned MongoDB `cyber_triage_test_d581b403c70d4964920d10875710ec37`. Both retained detectors process the same real 84-row, source-order-selected CICIDS2017 fixture. Predictions and scores exactly match direct saved-bundle inference, persisted cases retain model IDs, thresholds, custody and screening, and actual PDFs contain the saved results.

| Retained detector | Case | Model ID | Direct inference | MongoDB | PDF |
|---|---|---|---|---|---|
| supervised | CASE-87934C83D864 | xgb-bin-12ad91fa39 | PASS | PASS | PASS |
| baseline | CASE-584157EF1469 | iforest-65dd0b57a2b1a2020a0b | PASS | PASS | PASS |

Backend: **408 passed, 46 skipped, 0 failures, 0 errors**. Frontend: **19 passed**, production build succeeded. Regression fitting was disabled; the two explicit research candidates were trained only by the budgeted research stage. Skip reasons are preserved, including disposable fitting fixtures and the absent primary forensic image; real controlled FAT12/PE/YARA/MongoDB/PDF tests ran.
**Browser UNVERIFIED:** “Local browser use is disabled in Work settings.” Existing permission limitation preserved, no repeated request, bypass, screenshot fabrication or claim of actual React interactions. Automated React tests/build are distinct from browser acceptance. Rendered genuine PDF sample pages and geometry checks are recorded; raw PDFs remain ignored.

## 8. Reproducibility, figures and known limits

Fresh-checkout CI initially exposed two eager optional psutil imports before sealed-test guards (367 passed, 85 skipped, two failures). Imports now occur only when research work starts; guard tests additionally simulate absent psutil without skipping or weakening assertions. The original CI failure transcript is preserved; research dependencies are separately pinned.
[Exact commands, input setup, optional artifact download and non-overwriting replay](../../docs/network-generalization.md). The original stages are write-once; final label receipt prevents another final evaluation or fitting under the same experiment. Replay is labeled already-disclosed reproduction, not new validation. Raw datasets, NPZ score/identity archives, exclusion ledgers, models and databases stay outside Git.
Figures: model-comparison.png, confusion-matrices.png, final-roc-pr.png, attack-family-recall.png, feature-distributions.png, top-k-recall.png, inference-throughput.png, historical-score-diagnosis.png, historical-threshold-review.png. Figures contain actual populations/protocols, never illustrative values.
Limits: no independent site/bot scenario; conditional extractor semantics; quota-sampled validation; tiny rare-class training counts; finite one-seed/two-model budget; incomplete session/host independence; unmeasured training peak RSS; browser interactions unavailable. High recall on the known development scenario did not transfer under the fixed FPR gate. The original 2017 cleaned source has historical label-conflict cleaning and partition limitations documented in Issue 3; they are not erased here.
Current production model hashes and all historical Issue 3–5 scientific files are verified against checkpoint.json. Research code and honest negative deployment results may be published, as authorized. Final commit/remote SHA is reported from Git after publication; no self-referential hash is embedded here. No further development issue was started.
