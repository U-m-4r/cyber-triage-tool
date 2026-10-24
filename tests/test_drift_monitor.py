import pandas as pd

from ml.drift_monitor import assess_feature_drift


def test_drift_monitor_flags_large_shift_without_retraining():
    reference = {
        "Flow Duration": {"mean": 10.0, "std": 2.0},
        "Total Fwd Packets": {"mean": 5.0, "std": 1.0},
    }
    batch = pd.DataFrame({
        "Flow Duration": [30.0, 31.0, 29.0],
        "Total Fwd Packets": [20.0, 21.0, 19.0],
    })

    report = assess_feature_drift(batch, reference)

    assert report["drift_detected"] is True
    assert report["status"] == "drift_suspected"
    assert report["automatic_retraining"] is False
    assert report["action"] == "review_and_collect_evidence"


def test_drift_monitor_handles_missing_reference():
    report = assess_feature_drift(pd.DataFrame({"x": [1, 2]}), {})

    assert report["status"] == "insufficient_data"
    assert report["drift_detected"] is False
