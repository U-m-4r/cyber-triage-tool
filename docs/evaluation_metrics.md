# Evaluation Metrics — Cyber Triage Tool

## What We Built

A full model evaluation system that measures how well the Isolation Forest anomaly detector performs against real labeled network traffic data (CICIDS2017). The metrics go beyond basic accuracy — they include per-class breakdown, confusion matrix, ROC-AUC, and triage-specific Top-K metrics designed for real incident response scenarios.

---

## Why These Metrics Matter

Anomaly detection on network traffic is an imbalanced problem — most traffic is benign. Plain accuracy is misleading here (a model that labels everything as normal can still hit 90%+ accuracy). So we use a combination of metrics that together give a complete picture.

---

## Metrics Explained

### Core Classification Metrics

| Metric | What It Tells You |
|---|---|
| Accuracy | % of all records correctly classified |
| Precision | Of all records flagged as attacks, how many actually were |
| Recall | Of all actual attacks, how many did we catch |
| F1 Score | Harmonic mean of precision and recall — best single number for imbalanced data |
| ROC-AUC | How well the model separates normal from attack across all thresholds (1.0 = perfect) |

---

### Per-Class Metrics (`class_metrics`)

We break down precision, recall, and F1 separately for:

- `normal_0` — benign traffic (class 0)
- `attack_1` — malicious traffic (class 1)

This tells you whether the model is biased. For example, high recall on `attack_1` but low precision means too many false alarms. High precision but low recall means attacks are being missed.

```json
"class_metrics": {
  "normal_0": { "precision": 0.95, "recall": 0.92, "f1_score": 0.93, "support": 1200 },
  "attack_1": { "precision": 0.88, "recall": 0.85, "f1_score": 0.86, "support": 800 }
}
```

---

### Confusion Matrix

Shows the raw counts of correct and incorrect predictions:

```json
"confusion_matrix": {
  "true_negative": 1104,   // benign correctly identified
  "false_positive": 96,    // benign wrongly flagged as attack
  "false_negative": 120,   // attacks missed
  "true_positive": 680     // attacks correctly caught
}
```

In a triage context, false negatives (missed attacks) are more dangerous than false positives (extra alerts).

---

### Top-K Triage Metrics (`triage_top_k`)

This is the most practical metric for a SOC analyst. Instead of evaluating all predictions, it asks:

> "If an analyst only has time to review the top 10% or 25% most suspicious records, how many real attacks would they find?"

```json
"triage_top_k": {
  "top_10_percent": {
    "records_considered": 200,
    "attack_hits": 175,
    "precision": 0.875,
    "recall": 0.72
  },
  "top_25_percent": {
    "records_considered": 500,
    "attack_hits": 230,
    "precision": 0.46,
    "recall": 0.95
  }
}
```

Records are ranked by anomaly score (most anomalous first). High precision at top-10% means the model surfaces real attacks at the top of the queue — exactly what you want in a triage tool.

---

## How the Evaluation Works (Train/Test Split)

When you call `/api/evaluate`, the backend:

1. Loads and preprocesses your labeled CSV.
2. Splits it 70/30 (train/test) using stratified sampling so both splits have proportional attack/normal ratios.
3. Trains a fresh Isolation Forest on the 70% training set.
4. Runs predictions on the 30% test set.
5. Computes all metrics above and returns them as JSON.

This gives an honest estimate of how the model performs on unseen data.

---

## Label Column Detection

The system auto-detects these column names as ground truth:
`Label`, `label`, `Class`, `class`, `Target`, `target`

- Values `benign`, `normal`, `0` → mapped to class `0` (normal)
- Everything else → mapped to class `1` (attack)

You can override the column name with `?label_column=YourColumn` query param.

---

## How to Run Evaluation

### Via API
```bash
curl -X POST \
  -F "file=@data/sample/cicids_sample_2000.csv" \
  http://localhost:5000/api/evaluate
```

With a custom label column:
```bash
curl -X POST \
  -F "file=@data/sample/cicids_sample_2000.csv" \
  "http://localhost:5000/api/evaluate?label_column=Traffic_Label"
```

### What a Good Result Looks Like
- F1 Score > 0.80 on `attack_1` — model is reliably catching attacks
- ROC-AUC > 0.90 — strong separation between normal and attack
- Top-10% precision > 0.80 — analyst reviewing top alerts will mostly see real threats
