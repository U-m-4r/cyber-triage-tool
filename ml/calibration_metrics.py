"""Calibration and reliability metrics for multiclass attack attribution.

This module provides standard, framework-independent implementations of:
- Multiclass Brier Score (Brier, 1950)
- Multiclass Logarithmic Loss (Cross-Entropy)
- Expected Calibration Error (ECE) with reliability-bin statistics (Naeini et al., 2015)
- Per-class calibration diagnostics
- Abstention-aware classification performance

Mathematical formulations:
1. Multiclass Brier Score:
   BS = (1 / N) * sum_{i=1}^N sum_{c=1}^C (p_{ic} - y_{ic})^2
   where y_{ic} in {0, 1} is one-hot ground truth and p_{ic} is predicted probability.
   Range: [0, 2], lower is better. Normalized Brier = BS / 2 in [0, 1].

2. Expected Calibration Error (ECE):
   Partition samples into M equal-width confidence bins B_m in (0, 1].
   Let conf(B_m) = (1 / |B_m|) * sum_{i in B_m} max_c p_{ic}
   Let acc(B_m)  = (1 / |B_m|) * sum_{i in B_m} I(argmax_c p_{ic} == y_i)
   ECE = sum_{m=1}^M (|B_m| / N) * |acc(B_m) - conf(B_m)|
"""
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    log_loss,
)
from sklearn.preprocessing import label_binarize


def compute_multiclass_brier_score(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    classes: List[str],
) -> Dict[str, Any]:
    """Calculate the multiclass Brier score and per-class Brier scores.

    Parameters
    ----------
    y_true : array-like of shape (N,)
        True class labels.
    probabilities : array-like of shape (N, C)
        Predicted class probability distributions.
    classes : list of str
        Authoritative class names in column order.

    Returns
    -------
    dict
        Total Brier score, normalized Brier score, and per-class Brier contributions.
    """
    y_true_arr = np.asarray(y_true)
    probs_arr = np.asarray(probabilities, dtype=np.float64)

    if len(y_true_arr) == 0:
        return {"brier_score": 0.0, "normalized_brier_score": 0.0, "per_class": {}}

    # One-hot encode ground truth
    y_onehot = label_binarize(y_true_arr, classes=classes)
    if len(classes) == 2 and y_onehot.shape[1] == 1:
        y_onehot = np.hstack([1 - y_onehot, y_onehot])

    squared_errors = (probs_arr - y_onehot) ** 2
    brier_total = float(np.mean(np.sum(squared_errors, axis=1)))
    per_class_brier = {
        cls: round(float(np.mean(squared_errors[:, idx])), 6)
        for idx, cls in enumerate(classes)
    }

    return {
        "brier_score": round(brier_total, 6),
        "normalized_brier_score": round(brier_total / 2.0, 6),
        "formula": "mean(sum((p_ic - y_ic)^2)) across classes",
        "per_class": per_class_brier,
    }


def compute_multiclass_log_loss(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    classes: List[str],
    eps: float = 1e-15,
) -> float:
    """Calculate multiclass logarithmic loss with explicit probability clipping."""
    y_true_arr = np.asarray(y_true)
    probs_arr = np.clip(np.asarray(probabilities, dtype=np.float64), eps, 1.0 - eps)
    # Renormalize rows after clipping
    probs_arr = probs_arr / probs_arr.sum(axis=1, keepdims=True)

    try:
        loss = log_loss(y_true_arr, probs_arr, labels=classes)
        return round(float(loss), 6)
    except Exception:
        # Fallback manual calculation
        y_onehot = label_binarize(y_true_arr, classes=classes)
        if len(classes) == 2 and y_onehot.shape[1] == 1:
            y_onehot = np.hstack([1 - y_onehot, y_onehot])
        loss = -float(np.mean(np.sum(y_onehot * np.log(probs_arr), axis=1)))
        return round(loss, 6)


def compute_expected_calibration_error(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    classes: List[str],
    n_bins: int = 10,
) -> Tuple[float, List[Dict[str, Any]]]:
    """Calculate top-class Expected Calibration Error (ECE) and bin reliability stats.

    Parameters
    ----------
    y_true : array-like of shape (N,)
        True class labels.
    probabilities : array-like of shape (N, C)
        Predicted class probabilities.
    classes : list of str
        Authoritative class names.
    n_bins : int, default=10
        Number of equal-width bins in (0, 1].

    Returns
    -------
    tuple of (ece, bin_statistics)
    """
    y_true_arr = np.asarray(y_true)
    probs_arr = np.asarray(probabilities, dtype=np.float64)

    if len(y_true_arr) == 0:
        return 0.0, []

    confidences = np.max(probs_arr, axis=1)
    predicted_indices = np.argmax(probs_arr, axis=1)
    predicted_labels = np.array([classes[idx] for idx in predicted_indices])
    correct = (predicted_labels == y_true_arr).astype(np.float64)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    total_samples = len(y_true_arr)
    ece = 0.0
    bin_stats = []

    for i in range(n_bins):
        low, high = bin_boundaries[i], bin_boundaries[i + 1]
        if i == 0:
            mask = (confidences >= low) & (confidences <= high)
        else:
            mask = (confidences > low) & (confidences <= high)

        count = int(np.sum(mask))
        if count > 0:
            observed_acc = float(np.mean(correct[mask]))
            mean_conf = float(np.mean(confidences[mask]))
            abs_err = abs(observed_acc - mean_conf)
            weight = count / total_samples
            ece += weight * abs_err

            bin_stats.append({
                "bin_number": i + 1,
                "bin_range": [round(low, 2), round(high, 2)],
                "sample_count": count,
                "sample_share": round(weight, 4),
                "observed_accuracy": round(observed_acc, 4),
                "mean_confidence": round(mean_conf, 4),
                "calibration_gap": round(abs_err, 4),
            })
        else:
            bin_stats.append({
                "bin_number": i + 1,
                "bin_range": [round(low, 2), round(high, 2)],
                "sample_count": 0,
                "sample_share": 0.0,
                "observed_accuracy": None,
                "mean_confidence": None,
                "calibration_gap": 0.0,
            })

    return round(float(ece), 6), bin_stats


def evaluate_full_reliability_metrics(
    y_true: np.ndarray,
    raw_probabilities: np.ndarray,
    calibrated_probabilities: Optional[np.ndarray],
    classes: List[str],
    abstention_policy: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Compute comprehensive classification, calibration, and abstention metrics.

    Parameters
    ----------
    y_true : array-like of shape (N,)
    raw_probabilities : array-like of shape (N, C)
    calibrated_probabilities : array-like of shape (N, C), optional
    classes : list of str
    abstention_policy : dict, optional
        {'min_confidence': float, 'min_margin': float}

    Returns
    -------
    dict
        Structured evaluation bundle containing uncalibrated, calibrated, and
        abstention-filtered performance metrics.
    """
    classes_list = list(classes)
    y_true_arr = np.asarray(y_true)
    raw_probs = np.asarray(raw_probabilities, dtype=np.float64)

    policy = abstention_policy or {"min_confidence": 0.50, "min_margin": 0.05}
    min_conf = float(policy.get("min_confidence", 0.50))
    min_margin = float(policy.get("min_margin", 0.05))

    # Evaluate Raw / Uncalibrated Probabilities
    raw_brier = compute_multiclass_brier_score(y_true_arr, raw_probs, classes_list)
    raw_logloss = compute_multiclass_log_loss(y_true_arr, raw_probs, classes_list)
    raw_ece, raw_bins = compute_expected_calibration_error(y_true_arr, raw_probs, classes_list)

    raw_preds = [classes_list[idx] for idx in np.argmax(raw_probs, axis=1)]
    raw_report = classification_report(
        y_true_arr, raw_preds, labels=classes_list, output_dict=True, zero_division=0
    )

    uncalibrated_summary = {
        "log_loss": raw_logloss,
        "brier_score": raw_brier["brier_score"],
        "normalized_brier_score": raw_brier["normalized_brier_score"],
        "expected_calibration_error": raw_ece,
        "per_class_brier": raw_brier["per_class"],
        "reliability_bins": raw_bins,
        "accuracy": round(float(accuracy_score(y_true_arr, raw_preds)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true_arr, raw_preds)), 4),
        "macro_f1": round(raw_report["macro avg"]["f1-score"], 4),
        "weighted_f1": round(raw_report["weighted avg"]["f1-score"], 4),
    }

    # Evaluate Calibrated Probabilities if available
    calibrated_summary = None
    eval_probs_for_abstention = raw_probs

    if calibrated_probabilities is not None:
        cal_probs = np.asarray(calibrated_probabilities, dtype=np.float64)
        cal_brier = compute_multiclass_brier_score(y_true_arr, cal_probs, classes_list)
        cal_logloss = compute_multiclass_log_loss(y_true_arr, cal_probs, classes_list)
        cal_ece, cal_bins = compute_expected_calibration_error(y_true_arr, cal_probs, classes_list)

        cal_preds = [classes_list[idx] for idx in np.argmax(cal_probs, axis=1)]
        cal_report = classification_report(
            y_true_arr, cal_preds, labels=classes_list, output_dict=True, zero_division=0
        )

        calibrated_summary = {
            "log_loss": cal_logloss,
            "brier_score": cal_brier["brier_score"],
            "normalized_brier_score": cal_brier["normalized_brier_score"],
            "expected_calibration_error": cal_ece,
            "per_class_brier": cal_brier["per_class"],
            "reliability_bins": cal_bins,
            "accuracy": round(float(accuracy_score(y_true_arr, cal_preds)), 4),
            "balanced_accuracy": round(float(balanced_accuracy_score(y_true_arr, cal_preds)), 4),
            "macro_f1": round(cal_report["macro avg"]["f1-score"], 4),
            "weighted_f1": round(cal_report["weighted avg"]["f1-score"], 4),
            "per_class": {
                cls: {
                    "precision": round(cal_report[cls]["precision"], 4),
                    "recall": round(cal_report[cls]["recall"], 4),
                    "f1": round(cal_report[cls]["f1-score"], 4),
                    "support": int(cal_report[cls]["support"]),
                }
                for cls in classes_list
            },
            "confusion_matrix": confusion_matrix(y_true_arr, cal_preds, labels=classes_list).tolist(),
        }
        eval_probs_for_abstention = cal_probs

    # Abstention analysis under policy
    top_scores = np.max(eval_probs_for_abstention, axis=1)
    sorted_probs = np.sort(eval_probs_for_abstention, axis=1)
    margins = sorted_probs[:, -1] - sorted_probs[:, -2]

    low_conf_mask = top_scores < min_conf
    low_margin_mask = (top_scores >= min_conf) & (margins < min_margin)
    abstained_mask = low_conf_mask | low_margin_mask
    covered_mask = ~abstained_mask

    total_n = len(y_true_arr)
    covered_n = int(np.sum(covered_mask))
    abstained_n = int(np.sum(abstained_mask))

    if covered_n > 0:
        cov_true = y_true_arr[covered_mask]
        cov_probs = eval_probs_for_abstention[covered_mask]
        cov_preds = [classes_list[idx] for idx in np.argmax(cov_probs, axis=1)]
        cov_acc = round(float(accuracy_score(cov_true, cov_preds)), 4)
        cov_macro_f1 = round(float(classification_report(cov_true, cov_preds, labels=classes_list, output_dict=True, zero_division=0)["macro avg"]["f1-score"]), 4)
    else:
        cov_acc = 0.0
        cov_macro_f1 = 0.0

    abstention_report = {
        "policy": {
            "min_confidence": min_conf,
            "min_margin": min_margin,
            "score_type_used": "calibrated" if calibrated_probabilities is not None else "raw",
        },
        "total_records": total_n,
        "attributed_count": covered_n,
        "abstained_count": abstained_n,
        "coverage": round(covered_n / total_n, 4) if total_n else 0.0,
        "abstention_rate": round(abstained_n / total_n, 4) if total_n else 0.0,
        "abstention_reasons": {
            "low_confidence_count": int(np.sum(low_conf_mask)),
            "ambiguous_margin_count": int(np.sum(low_margin_mask)),
        },
        "covered_subset_accuracy": cov_acc,
        "covered_subset_macro_f1": cov_macro_f1,
    }

    return {
        "uncalibrated": uncalibrated_summary,
        "calibrated": calibrated_summary,
        "abstention_analysis": abstention_report,
    }
