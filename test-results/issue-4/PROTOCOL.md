# Issue 4 protocol — declared before external inference

Starting commit: 365e5568fa97c573307da02f10b84ae49040674d.
Frozen detectors: the exact two checksum-pinned artifacts in models/network-artifacts.json.
No fitting, calibration, threshold changes, or model selection is permitted.

Select Thursday-22-02-2018 (earlier of the two documented web-attack days) and
Friday-02-03-2018 (documented bot day) from the official anonymous CSE-CIC-IDS2018
S3 bucket. This choice targets the two known weak Issue 3 categories rather than
choosing dates from model predictions. Sizes inspected first: 382636202 and
352368373 bytes. Evaluate all objectively eligible rows, not a performance-selected
sample. This is a two-day, scenario-targeted external subset, not the entire dataset.

Use chunks of 25000 rows. Preserve source-row identities and original labels.
Reject missing/ambiguous feature columns; exclude required measurements that are
missing, nonnumeric, NaN, infinite, negative or overflow the saved model transform.
Do not exclude finite zero-duration rows, duplicates, outliers, label-conflicting
vectors, or misclassified examples. Unknown labels are explicitly excluded from
evaluation and reported; do not infer their class. Source schema rows repeated in
the body are recorded as invalid rows. No imputation, clipping or new scaling.
Run the primary comparison only after documenting feature compatibility; extractor
version uncertainty must be carried into every interpretation.

Measure binary, per-day and original-label results for both models. Keep labels
outside inference frames. Compute exact ROC-AUC/AP from saved scores; unsupported
single-class metrics are null. Report exclusions by label and reason, duplicates
and zero durations separately. Audit numeric/model-input overlap against approved
2017 data without removing overlapping examples. Use the frozen PSI reference.

Demo: first 10 eligible rows per original label per selected source, before model
predictions. Keep original source columns/values and source-row manifest; labels
are retained separately. Demo accuracy is not a population estimate. Do not commit
source rows, complete ledgers, raw daily CSVs or full prediction arrays.

Resources inspected: Windows 11, 12 logical CPUs, approximately 8.3 GB physical
RAM (Issue 3 environment), 49.6 GB free storage at start. Use streaming downloads,
SQLite duplicate/overlap audit and disk-backed result arrays as needed. No PCAP
downloads, dataset-wide download or training jobs.
