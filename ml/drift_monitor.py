"""Conservative drift checks for the CICIDS2017 network-flow baseline.

Drift is a review signal only. This module never retrains, changes thresholds, or
promotes a model automatically; that prevents an attacker from poisoning the
baseline with a stream of crafted uploads.
"""
import numpy as np


def assess_feature_drift(features, reference_stats, z_threshold=4.0, max_feature_fraction=0.25):
    """Compare batch feature means to baseline means in baseline-standard-deviation units.

    Returns a JSON-serialisable report. This is a deliberately simple guardrail,
    not a substitute for production drift tests (e.g. PSI/KS and time-windowed
    monitoring). A report is flagged when too many feature means shift materially.
    """
    if features is None or len(features) == 0 or not reference_stats:
        return {
            "status": "insufficient_data",
            "drift_detected": False,
            "features_checked": 0,
            "shifted_features": [],
            "message": "No batch or reference statistics available.",
        }

    shifted = []
    checked = 0
    for column in features.columns:
        stats = reference_stats.get(column)
        if not stats:
            continue
        mean = float(stats.get("mean", 0.0))
        scale = float(stats.get("std", 0.0))
        if not np.isfinite(scale) or scale <= 1e-12:
            continue
        batch_mean = float(np.asarray(features[column], dtype=float).mean())
        if not np.isfinite(batch_mean):
            continue
        checked += 1
        z_shift = abs(batch_mean - mean) / scale
        if z_shift >= z_threshold:
            shifted.append({"feature": column, "mean_shift_std": round(z_shift, 3)})

    fraction = len(shifted) / checked if checked else 0.0
    detected = bool(checked and fraction >= max_feature_fraction)
    return {
        "status": "drift_suspected" if detected else ("checked" if checked else "insufficient_data"),
        "drift_detected": detected,
        "features_checked": checked,
        "shifted_features": shifted,
        "shifted_feature_fraction": round(fraction, 4),
        "action": "review_and_collect_evidence" if detected else "monitor_only",
        "automatic_retraining": False,
    }
