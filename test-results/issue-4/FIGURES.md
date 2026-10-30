# Figure guide

All figures use actual eligible records from the two predeclared CSE-CIC-IDS2018 daily CSVs. Frozen 2017-trained XGBoost and Isolation Forest, original fitted scalers and thresholds; conditional extractor compatibility. External n=2087481. Internal n=345892 where compared. No illustrative data or fitted external normalization.

- internal-vs-external.png: Accuracy, precision, recall, F1, ROC-AUC and balanced accuracy across different test populations; not a controlled causal comparison.
- external-confusion.png: Exact TN/FP/FN/TP counts for each unchanged detector. The large false-negative counts are visible.
- attack-family-recall.png: Original attack-label recall and sample counts; binary detection, not multiclass predictions. Tiny bot recall must not be hidden by overall accuracy.
- false-positive-negative-rates.png: FP/benign and FN/attack, comparing internal and selected external datasets.
- class-distribution.png: Eligible class counts with retained duplicates; explains why accuracy can be misleading.
- feature-distribution-shifts.png: All eligible external flows compared with saved 2017 benign-training reference bins; PSI measures distribution change, not attack confidence. Attack prevalence confounds this descriptive comparison.

Evidence: evaluation.json, data-quality.json, drift.json, and Issue 3 evaluation.json. All six rendered figures were visually reviewed.
