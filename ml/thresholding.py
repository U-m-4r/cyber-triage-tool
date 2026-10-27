"""Validation-only decision threshold selection for binary classification.

Provides deterministic, FPR-constrained or objective-maximizing threshold selection
strictly evaluated on validation data.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np


class ThresholdSelectionError(ValueError):
    """Raised when threshold selection input is fundamentally invalid."""


def compute_binary_metrics_at_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
) -> Dict[str, Any]:
    """Calculate precision, recall, F1, FPR, accuracy, and confusion matrix at a threshold.

    Labels:
        y_true: binary ground truth where 1 = positive (attack) and 0 = negative (benign).
        scores: continuous prediction scores where higher values indicate higher positive likelihood.
    """
    y_true = np.asarray(y_true, dtype=np.int64)
    scores = np.asarray(scores, dtype=np.float64)

    if len(y_true) != len(scores):
        raise ThresholdSelectionError("y_true and scores must have the same length.")

    y_pred = (scores >= threshold).astype(np.int64)

    # Confusion matrix elements
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))

    total = len(y_true)
    positives = tp + fn
    negatives = tn + fp

    accuracy = float((tp + tn) / total) if total > 0 else 0.0
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / positives) if positives > 0 else 0.0
    f1 = (
        float(2.0 * precision * recall / (precision + recall))
        if (precision + recall) > 0.0
        else 0.0
    )
    fpr = float(fp / negatives) if negatives > 0 else 0.0

    return {
        "threshold": float(threshold),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
        "support": {
            "total": total,
            "positives": positives,
            "negatives": negatives,
        },
    }


def select_validation_threshold(
    y_val: np.ndarray,
    val_scores: np.ndarray,
    *,
    max_fpr: Optional[float] = 0.002,
    objective: str = "f1_score",
    candidate_thresholds: Optional[Union[int, np.ndarray, List[float]]] = 200,
    default_fallback_threshold: float = 0.5,
) -> Dict[str, Any]:
    """Select an optimal decision threshold from validation data under optional FPR constraint.

    Args:
        y_val: Validation ground truth (0 = benign, 1 = attack).
        val_scores: Validation continuous model scores (higher = more likely attack).
        max_fpr: Maximum acceptable false-positive rate constraint (e.g., 0.002 = 0.2%).
            This is a configurable provisional constraint, not an absolute operational requirement.
            If None, no FPR constraint is enforced.
        objective: Metric to maximize ('f1_score', 'recall', 'precision', 'accuracy').
        candidate_thresholds: Number of quantile/linear candidate points or explicit array.
        default_fallback_threshold: Threshold to use if data is degenerate or empty.

    Returns:
        Dict containing selected threshold, metrics, candidate evaluations, and selection metadata.
    """
    y_val = np.asarray(y_val, dtype=np.int64)
    val_scores = np.asarray(val_scores, dtype=np.float64)

    if len(y_val) == 0:
        return {
            "selected_threshold": default_fallback_threshold,
            "fallback": True,
            "fallback_reason": "EMPTY_VALIDATION_DATA",
            "max_fpr_constraint": max_fpr,
            "objective": objective,
            "selected_at": datetime.now(timezone.utc).isoformat(),
            "metrics": compute_binary_metrics_at_threshold(
                np.array([0]), np.array([default_fallback_threshold]), default_fallback_threshold
            ),
        }

    # Validate labels are binary
    unique_labels = set(np.unique(y_val))
    if not unique_labels.issubset({0, 1}):
        raise ThresholdSelectionError(f"y_val contains invalid labels: {unique_labels}. Must be 0 and/or 1.")

    # Validate scores are finite
    if not np.isfinite(val_scores).all():
        raise ThresholdSelectionError("val_scores contains non-finite values (NaN or inf).")

    # Handle degenerate case: all scores identical or only single class
    min_score, max_score = float(np.min(val_scores)), float(np.max(val_scores))
    if min_score == max_score or len(unique_labels) < 2:
        metrics = compute_binary_metrics_at_threshold(y_val, val_scores, default_fallback_threshold)
        return {
            "selected_threshold": default_fallback_threshold,
            "fallback": True,
            "fallback_reason": "DEGENERATE_SCORES_OR_SINGLE_CLASS",
            "max_fpr_constraint": max_fpr,
            "objective": objective,
            "selected_at": datetime.now(timezone.utc).isoformat(),
            "metrics": metrics,
        }

    # Generate candidate thresholds
    if isinstance(candidate_thresholds, (int, np.integer)):
        n_candidates = max(10, int(candidate_thresholds))
        # Mix uniform linspace across [min, max] with quantiles for fine resolution in dense score regions
        quantiles = np.linspace(0.001, 0.999, n_candidates // 2)
        q_thresh = np.quantile(val_scores, quantiles)
        lin_thresh = np.linspace(min_score, max_score, n_candidates // 2)
        candidates = np.unique(np.concatenate(([0.5], q_thresh, lin_thresh)))
        candidates.sort()
    else:
        candidates = np.unique(np.asarray(candidate_thresholds, dtype=np.float64))
        candidates.sort()

    valid_candidates = []
    all_evaluated = []

    for thresh in candidates:
        m = compute_binary_metrics_at_threshold(y_val, val_scores, float(thresh))
        all_evaluated.append(m)

        if max_fpr is not None and m["false_positive_rate"] > max_fpr:
            continue
        valid_candidates.append(m)

    # Determine selection
    if not valid_candidates:
        # Fallback: no candidate threshold satisfied the max_fpr constraint.
        # Find candidate with the lowest FPR, tie-breaking by highest score.
        fallback_m = min(all_evaluated, key=lambda x: (x["false_positive_rate"], -x["threshold"]))
        return {
            "selected_threshold": float(fallback_m["threshold"]),
            "fallback": True,
            "fallback_reason": f"NO_THRESHOLD_SATISFIED_MAX_FPR_{max_fpr}",
            "max_fpr_constraint": max_fpr,
            "objective": objective,
            "selected_at": datetime.now(timezone.utc).isoformat(),
            "metrics": fallback_m,
            "candidate_count": len(all_evaluated),
        }

    # Maximize objective with deterministic tie-breaking (prefer higher threshold to minimize false positives)
    def objective_key(cand):
        val = cand.get(objective, cand["f1_score"])
        # Primary: objective value; Secondary: lower FPR; Tertiary: higher threshold
        return (val, -cand["false_positive_rate"], cand["threshold"])

    best_candidate = max(valid_candidates, key=objective_key)

    return {
        "selected_threshold": float(best_candidate["threshold"]),
        "fallback": False,
        "fallback_reason": None,
        "max_fpr_constraint": max_fpr,
        "objective": objective,
        "selected_at": datetime.now(timezone.utc).isoformat(),
        "metrics": best_candidate,
        "candidate_count": len(all_evaluated),
        "feasible_candidate_count": len(valid_candidates),
    }
