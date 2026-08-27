"""Evaluation metrics for the anomaly-detection triage engine.

This module holds the *pure* (framework-independent) evaluation logic so it can be
reused by both the Flask ``/api/evaluate`` endpoint and the offline reproducibility
script ``scripts/run_evaluation.py``. ``backend/app.py`` imports from here.

Metric references:
  * Precision / Recall / F1 for imbalanced classification:
      M. Sokolova & G. Lapalme, "A systematic analysis of performance measures for
      classification tasks", Information Processing & Management 45(4), 2009.
  * ROC-AUC as a threshold-independent ranking measure:
      T. Fawcett, "An introduction to ROC analysis", Pattern Recognition Letters
      27(8), 2006.
  * Top-K triage recall (precision/recall within the top K% of a ranked queue) is a
      standard information-retrieval "precision@k / recall@k" measure, motivated here
      by forensic triage where analysts inspect only the highest-ranked artifacts.
"""
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    precision_recall_fscore_support,
)

# Column names that, when present, carry the attack/benign ground-truth label.
# "Attack Type" is the CICIDS2017-cleaned (Kaggle: ericanacletoribeiro) label column.
LABEL_COLUMN_CANDIDATES = [
    "Label", "label", "Class", "class", "Target", "target",
    "Attack Type", "attack_type", "Attack",
]

# Labels that denote a non-attack (benign) record; everything else is an attack.
# "normal traffic" is the benign label used by the CICIDS2017-cleaned dataset.
BENIGN_TOKENS = ["benign", "normal", "0", "normal traffic", "benign traffic"]


def extract_binary_ground_truth(df, override=None):
    """Derive a binary attack (1) / benign (0) vector from a labeled DataFrame.

    ``override`` optionally names the label column explicitly. Returns
    ``(y_true, label_column)`` or ``(None, None)`` when no usable label exists.
    """
    if override:
        if override not in df.columns:
            return None, None
        label_col = override
    else:
        label_col = next((c for c in LABEL_COLUMN_CANDIDATES if c in df.columns), None)

    if not label_col:
        return None, None

    labels = df[label_col].astype(str).str.strip().str.lower()
    y_true = np.where(labels.isin(BENIGN_TOKENS), 0, 1)
    return y_true, label_col


def compute_top_k_metrics(y_true, decision_scores, ks=(10, 25)):
    """Precision@k / recall@k over the anomaly-ranked queue for each k (percent).

    Triage effectiveness measure: how many true attacks surface in the top K% of
    artifacts ranked most-anomalous first.
    """
    y_true = np.asarray(y_true)
    if len(y_true) == 0:
        return {}

    # decision_function: higher = more normal, so negate to rank most-anomalous first.
    anomaly_scores = -np.asarray(decision_scores, dtype=float)
    ranked_idx = np.argsort(-anomaly_scores)
    total_attacks = int((y_true == 1).sum())
    metrics = {}

    for k in ks:
        k_count = max(1, int(len(y_true) * (k / 100.0)))
        top_idx = ranked_idx[:k_count]
        top_hits = int((y_true[top_idx] == 1).sum())
        precision_at_k = top_hits / k_count if k_count else 0.0
        recall_at_k = top_hits / total_attacks if total_attacks else 0.0
        metrics[f"top_{k}_percent"] = {
            "records_considered": int(k_count),
            "attack_hits": int(top_hits),
            "precision": round(float(precision_at_k), 4),
            "recall": round(float(recall_at_k), 4),
        }
    return metrics


def evaluate_predictions(y_true, predictions, decision_scores):
    """Full classification + triage metric bundle for Isolation Forest output.

    ``predictions`` are sklearn IsolationForest labels (-1 anomaly / 1 normal);
    ``decision_scores`` are the raw ``decision_function`` values.
    """
    y_true = np.asarray(y_true)
    # IsolationForest: -1 anomaly -> attack (1); 1 normal -> benign (0).
    y_pred = np.where(np.asarray(predictions) == -1, 1, 0)

    # Precision/Recall/F1 — Sokolova & Lapalme 2009.
    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }

    p, r, f, s = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    metrics["class_metrics"] = {
        "normal_0": {
            "precision": round(float(p[0]), 4),
            "recall": round(float(r[0]), 4),
            "f1_score": round(float(f[0]), 4),
            "support": int(s[0]),
        },
        "attack_1": {
            "precision": round(float(p[1]), 4),
            "recall": round(float(r[1]), 4),
            "f1_score": round(float(f[1]), 4),
            "support": int(s[1]),
        },
    }

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics["confusion_matrix"] = {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }

    # ROC-AUC — Fawcett 2006. Negate decision scores so higher = more likely attack.
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, -np.asarray(decision_scores))), 4)
    else:
        metrics["roc_auc"] = None

    metrics["triage_top_k"] = compute_top_k_metrics(y_true, decision_scores, ks=(10, 25))
    return metrics


def run_split_evaluation(df_scaled, y_true, detector, test_size=0.3, random_state=42):
    """Stratified train/test split, fit the detector, and evaluate on the test set.

    Preserves the benign/attack class ratio via stratified sampling. Returns a dict
    with record counts and the full metric bundle.
    """
    y_true = np.asarray(y_true)
    indices = np.arange(len(df_scaled))
    stratify = y_true if len(np.unique(y_true)) > 1 else None
    train_idx, test_idx = train_test_split(
        indices, test_size=test_size, random_state=random_state, stratify=stratify
    )

    X_train = df_scaled.iloc[train_idx]
    X_test = df_scaled.iloc[test_idx]
    y_test = y_true[test_idx]

    detector.train(X_train)
    predictions, scores = detector.predict(X_test)
    metrics = evaluate_predictions(y_test, predictions, scores)

    return {
        "records": {
            "total": int(len(df_scaled)),
            "train": int(len(train_idx)),
            "test": int(len(test_idx)),
        },
        "metrics": metrics,
    }
