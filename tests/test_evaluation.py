"""Tests for PART D — pure evaluation metric logic (evaluation/evaluate.py)."""
import numpy as np
import pandas as pd

from evaluation.evaluate import (
    extract_binary_ground_truth,
    compute_top_k_metrics,
    evaluate_predictions,
)


def test_extract_ground_truth_recognizes_cicids_schema():
    # CICIDS2017-cleaned uses "Attack Type" with "Normal Traffic" as benign.
    df = pd.DataFrame({"Attack Type": ["Normal Traffic", "DoS", "Normal Traffic", "DDoS"]})
    y, col = extract_binary_ground_truth(df)
    assert col == "Attack Type"
    assert list(y) == [0, 1, 0, 1]


def test_extract_ground_truth_override_and_missing():
    df = pd.DataFrame({"Label": ["BENIGN", "ATTACK"]})
    y, col = extract_binary_ground_truth(df, override="Label")
    assert list(y) == [0, 1]
    # override naming a non-existent column -> (None, None)
    y2, col2 = extract_binary_ground_truth(df, override="Nope")
    assert y2 is None and col2 is None


def test_top_k_metrics_rank_attacks_first():
    # decision_function: higher = more normal. Make the two attacks the most
    # anomalous (lowest raw scores) so they land in the top of the ranked queue.
    y_true = np.array([0, 0, 1, 1])
    decision_scores = np.array([0.9, 0.8, -0.5, -0.4])  # attacks are most negative
    m = compute_top_k_metrics(y_true, decision_scores, ks=(25, 50))
    # top 50% (2 records) should be exactly the two attacks -> recall 1.0
    assert m["top_50_percent"]["attack_hits"] == 2
    assert m["top_50_percent"]["recall"] == 1.0


def test_evaluate_predictions_full_bundle():
    y_true = np.array([0, 0, 1, 1])
    # IsolationForest labels: 1 normal, -1 anomaly. Predict both attacks correctly.
    predictions = np.array([1, 1, -1, -1])
    decision_scores = np.array([0.9, 0.8, -0.5, -0.4])
    metrics = evaluate_predictions(y_true, predictions, decision_scores)
    assert metrics["accuracy"] == 1.0
    assert metrics["recall"] == 1.0
    cm = metrics["confusion_matrix"]
    assert cm["true_positive"] == 2 and cm["true_negative"] == 2
    assert cm["false_positive"] == 0 and cm["false_negative"] == 0
    assert metrics["roc_auc"] == 1.0
    assert "triage_top_k" in metrics


def test_evaluate_predictions_single_class_roc_none():
    # All benign -> ROC-AUC undefined -> None (not a crash).
    y_true = np.array([0, 0, 0])
    predictions = np.array([1, 1, -1])
    decision_scores = np.array([0.5, 0.4, -0.1])
    metrics = evaluate_predictions(y_true, predictions, decision_scores)
    assert metrics["roc_auc"] is None
