"""Unit tests for validation-only threshold selection."""
import numpy as np
import pytest

from ml.thresholding import (
    ThresholdSelectionError,
    compute_binary_metrics_at_threshold,
    select_validation_threshold,
)


def test_metrics_at_threshold_perfect_split():
    y_true = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    m = compute_binary_metrics_at_threshold(y_true, scores, threshold=0.5)

    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["false_positive_rate"] == 0.0
    assert m["confusion_matrix"] == {
        "true_negative": 2,
        "false_positive": 0,
        "false_negative": 0,
        "true_positive": 2,
    }


def test_metrics_at_threshold_all_predicted_negative():
    y_true = np.array([0, 1])
    scores = np.array([0.1, 0.2])
    m = compute_binary_metrics_at_threshold(y_true, scores, threshold=0.5)

    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1_score"] == 0.0
    assert m["false_positive_rate"] == 0.0
    assert m["confusion_matrix"]["false_negative"] == 1
    assert m["confusion_matrix"]["true_negative"] == 1


def test_select_threshold_fpr_constrained():
    # 10 benign, 10 attacks
    y_val = np.array([0] * 10 + [1] * 10)
    # Benign scores: 8 are low (0.05), 2 are elevated (0.25, 0.35)
    # Attack scores: all high (0.6 - 0.9)
    benign_scores = [0.05] * 8 + [0.25, 0.35]
    attack_scores = [0.60] * 10
    val_scores = np.array(benign_scores + attack_scores)

    # Max FPR = 0.0: threshold must be > 0.35
    result_zero_fpr = select_validation_threshold(
        y_val, val_scores, max_fpr=0.0, objective="f1_score", candidate_thresholds=[0.1, 0.3, 0.5]
    )
    assert not result_zero_fpr["fallback"]
    assert result_zero_fpr["selected_threshold"] >= 0.5
    assert result_zero_fpr["metrics"]["false_positive_rate"] == 0.0
    assert result_zero_fpr["metrics"]["recall"] == 1.0

    # Max FPR = 0.2: allows up to 2 false positives out of 10
    result_loose_fpr = select_validation_threshold(
        y_val, val_scores, max_fpr=0.2, objective="f1_score", candidate_thresholds=[0.1, 0.3, 0.5]
    )
    assert not result_loose_fpr["fallback"]
    assert result_loose_fpr["metrics"]["false_positive_rate"] <= 0.2


def test_select_threshold_fallback_when_constraint_unachievable():
    # All benign samples have score 0.8; attack samples have score 0.9
    y_val = np.array([0, 0, 1, 1])
    val_scores = np.array([0.8, 0.8, 0.9, 0.9])

    # If candidate thresholds are <= 0.8, FPR is 1.0. If max_fpr=0.05, and candidate array only has [0.5],
    # constraint cannot be satisfied.
    res = select_validation_threshold(
        y_val, val_scores, max_fpr=0.05, candidate_thresholds=[0.5]
    )
    assert res["fallback"] is True
    assert "NO_THRESHOLD_SATISFIED" in res["fallback_reason"]


def test_select_threshold_degenerate_inputs():
    # Empty data
    res_empty = select_validation_threshold(np.array([]), np.array([]))
    assert res_empty["fallback"] is True
    assert res_empty["fallback_reason"] == "EMPTY_VALIDATION_DATA"

    # Single class
    res_single = select_validation_threshold(np.array([0, 0, 0]), np.array([0.1, 0.2, 0.3]))
    assert res_single["fallback"] is True
    assert res_single["fallback_reason"] == "DEGENERATE_SCORES_OR_SINGLE_CLASS"

    # Degenerate identical scores
    res_ident = select_validation_threshold(np.array([0, 1]), np.array([0.5, 0.5]))
    assert res_ident["fallback"] is True

    # Invalid non-binary labels raise error
    with pytest.raises(ThresholdSelectionError):
        select_validation_threshold(np.array([0, 2]), np.array([0.1, 0.9]))

    # Non-finite scores raise error
    with pytest.raises(ThresholdSelectionError):
        select_validation_threshold(np.array([0, 1]), np.array([np.nan, 0.9]))
