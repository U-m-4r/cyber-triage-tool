"""Reproducible evaluation of the anomaly-detection triage engine on CICIDS2017.

Runs the SAME evaluation logic used by the Flask ``/api/evaluate`` endpoint
(``evaluation.evaluate``) against the real, labeled CICIDS2017-cleaned dataset —
no mock data — and writes committed evidence backing the presentation's results:

  * evaluation/results.json            full metric bundle + run metadata
  * evaluation/artifacts/confusion_matrix.png
  * evaluation/artifacts/roc_curve.png
  * evaluation/artifacts/topk_recall_curve.png

Dataset (NOT committed — ~717 MB; see README "Dataset" section):
  Kaggle: ericanacletoribeiro/cicids2017-cleaned-and-preprocessed
  -> data/cicids2017_cleaned.csv  (label column: "Attack Type")

Usage:
  python scripts/run_evaluation.py                 # full dataset (~2.52M rows)
  python scripts/run_evaluation.py --rows 400000   # faster subset for iteration
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")  # headless: render straight to PNG files
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.preprocessor import ForensicPreprocessor
from ml.detector import AnomalyDetector
from evaluation.evaluate import extract_binary_ground_truth, evaluate_predictions

# The 11 flow features the ForensicPreprocessor scores on (see ml/preprocessor.py).
FEATURE_COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Flow Bytes/s",
    "Flow Packets/s", "Packet Length Mean",
]

DEFAULT_DATA = os.path.join(ROOT_DIR, "data", "cicids2017_cleaned.csv")
DEFAULT_LABEL = "Attack Type"
ARTIFACT_DIR = os.path.join(ROOT_DIR, "evaluation", "artifacts")
RESULTS_JSON = os.path.join(ROOT_DIR, "evaluation", "results.json")


def load_dataset(path, label_column, rows=None):
    """Load only the feature + label columns (memory-light) from the CSV."""
    if not os.path.exists(path):
        sys.exit(
            f"[!] Dataset not found: {path}\n"
            "    Download it (see README > Dataset) and place it at data/cicids2017_cleaned.csv"
        )
    usecols = [c for c in FEATURE_COLUMNS if c] + [label_column]
    print(f"[+] Loading {path} (cols={len(usecols)}, rows={'all' if rows is None else rows})")
    df = pd.read_csv(path, usecols=lambda c: c in usecols, nrows=rows)
    df.columns = df.columns.str.strip()
    print(f"[+] Loaded {len(df):,} rows")
    return df


def plot_confusion_matrix(cm, out_path):
    tn, fp = cm["true_negative"], cm["false_positive"]
    fn, tp = cm["false_negative"], cm["true_positive"]
    matrix = np.array([[tn, fp], [fn, tp]])
    fig, ax = plt.subplots(figsize=(5, 4.2))
    im = ax.imshow(matrix, cmap="Blues")
    ax.set_xticks([0, 1], labels=["Pred BENIGN", "Pred ATTACK"])
    ax.set_yticks([0, 1], labels=["Actual BENIGN", "Actual ATTACK"])
    total = matrix.sum()
    for i in range(2):
        for j in range(2):
            val = matrix[i, j]
            ax.text(j, i, f"{val:,}\n({val/total:.1%})", ha="center", va="center",
                    color="white" if val > matrix.max() / 2 else "black", fontsize=10)
    ax.set_title("Confusion Matrix — Isolation Forest (test split)")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140)
    plt.close(fig)
    print(f"[+] Wrote {out_path}")


def plot_roc_curve(y_true, anomaly_scores, auc, out_path):
    fpr, tpr, _ = roc_curve(y_true, anomaly_scores)
    fig, ax = plt.subplots(figsize=(5, 4.2))
    ax.plot(fpr, tpr, color="#1e3a8a", lw=2, label=f"ROC (AUC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], color="#94a3b8", lw=1, linestyle="--", label="Random")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve — Isolation Forest")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=140)
    plt.close(fig)
    print(f"[+] Wrote {out_path}")


def plot_topk_recall(y_true, anomaly_scores, out_path):
    order = np.argsort(-anomaly_scores)
    y_sorted = np.asarray(y_true)[order]
    total_attacks = max(1, int((y_sorted == 1).sum()))
    cum_recall = np.cumsum(y_sorted == 1) / total_attacks
    pct_inspected = np.arange(1, len(y_sorted) + 1) / len(y_sorted) * 100.0
    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    ax.plot(pct_inspected, cum_recall * 100.0, color="#065f46", lw=2)
    for k in (10, 25):
        idx = max(0, int(len(y_sorted) * k / 100.0) - 1)
        ax.axvline(k, color="#94a3b8", lw=1, linestyle="--")
        ax.annotate(f"{cum_recall[idx]*100:.1f}% @ {k}%",
                    xy=(k, cum_recall[idx] * 100.0), xytext=(k + 2, cum_recall[idx] * 100.0 - 8),
                    fontsize=9)
    ax.set_xlabel("% of ranked queue inspected")
    ax.set_ylabel("Cumulative attack recall (%)")
    ax.set_title("Top-K Triage Recall — cumulative attack capture")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 101)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140)
    plt.close(fig)
    print(f"[+] Wrote {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=DEFAULT_DATA)
    parser.add_argument("--label-column", default=DEFAULT_LABEL)
    parser.add_argument("--rows", type=int, default=None, help="limit rows (default: all)")
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    os.makedirs(ARTIFACT_DIR, exist_ok=True)

    df = load_dataset(args.data, args.label_column, rows=args.rows)

    pre = ForensicPreprocessor()
    df_clean = pre.clean_data(df)
    y_true, label_column = extract_binary_ground_truth(df_clean, override=args.label_column)
    if y_true is None:
        sys.exit(f"[!] Label column '{args.label_column}' not usable in dataset")

    class_counts = {
        "benign": int((y_true == 0).sum()),
        "attack": int((y_true == 1).sum()),
    }
    print(f"[+] Class distribution: {class_counts}")

    df_features = pre.extract_features(df_clean)
    df_scaled = pre.scale_features(df_features)

    # Stratified split (same params as /api/evaluate) so we retain arrays for plots.
    from sklearn.model_selection import train_test_split
    idx = np.arange(len(df_scaled))
    train_idx, test_idx = train_test_split(
        idx, test_size=args.test_size, random_state=args.seed, stratify=y_true
    )
    detector = AnomalyDetector(contamination=args.contamination)
    detector.train(df_scaled.iloc[train_idx])
    predictions, scores = detector.predict(df_scaled.iloc[test_idx])
    y_test = y_true[test_idx]

    metrics = evaluate_predictions(y_test, predictions, scores)
    anomaly_scores = -np.asarray(scores)  # higher = more anomalous

    # --- plots ---
    plot_confusion_matrix(metrics["confusion_matrix"], os.path.join(ARTIFACT_DIR, "confusion_matrix.png"))
    if metrics["roc_auc"] is not None:
        plot_roc_curve(y_test, anomaly_scores, metrics["roc_auc"], os.path.join(ARTIFACT_DIR, "roc_curve.png"))
    plot_topk_recall(y_test, anomaly_scores, os.path.join(ARTIFACT_DIR, "topk_recall_curve.png"))

    # --- results.json ---
    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "source": "Kaggle: ericanacletoribeiro/cicids2017-cleaned-and-preprocessed",
            "path": os.path.relpath(args.data, ROOT_DIR).replace(os.sep, "/"),
            "label_column": label_column,
            "total_rows_loaded": int(len(df)),
            "rows_after_clean": int(len(df_clean)),
            "class_distribution": class_counts,
        },
        "config": {
            "model": "IsolationForest",
            "n_estimators": 100,
            "contamination": args.contamination,
            "random_state": args.seed,
            "test_size": args.test_size,
            "scaler": "StandardScaler (z-score)",
        },
        "records": {
            "train": int(len(train_idx)),
            "test": int(len(test_idx)),
        },
        "metrics": metrics,
        "artifacts": [
            "evaluation/artifacts/confusion_matrix.png",
            "evaluation/artifacts/roc_curve.png",
            "evaluation/artifacts/topk_recall_curve.png",
        ],
    }
    with open(RESULTS_JSON, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"[+] Wrote {RESULTS_JSON}")
    print("\n=== SUMMARY ===")
    print(json.dumps({k: metrics[k] for k in ("accuracy", "precision", "recall", "f1_score", "roc_auc")}, indent=2))
    print("triage_top_k:", json.dumps(metrics["triage_top_k"], indent=2))


if __name__ == "__main__":
    main()
