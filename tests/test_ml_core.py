"""Tests for PART A — formula/reference consistency in the ML core."""
import numpy as np
import pandas as pd

from ml.preprocessor import ForensicPreprocessor
from ml.detector import minmax_normalize_scores, AnomalyDetector
from ml.risk_scorer import RiskScorer


# --- preprocessor: StandardScaler (z-score) + row dropping (PART A1) -----------

def test_clean_data_drops_nan_and_inf_rows():
    pre = ForensicPreprocessor()
    df = pd.DataFrame({"a": [1.0, np.inf, 3.0, np.nan, 3.0], "b": [1.0, 2.0, 3.0, 4.0, 3.0]})
    cleaned = pre.clean_data(df)
    # inf row and nan row dropped; duplicate (3,3) collapsed -> 2 rows remain
    assert len(cleaned) == 2
    assert np.isfinite(cleaned.to_numpy()).all()


def test_scale_features_is_zscore_standardization():
    pre = ForensicPreprocessor()
    df = pd.DataFrame({"x": [10.0, 20.0, 30.0, 40.0], "y": [1.0, 2.0, 3.0, 4.0]})
    scaled = pre.scale_features(df)
    # z-score => per-column mean ~0 and (population) std ~1, NOT bounded to [0,1]
    assert np.allclose(scaled.mean().to_numpy(), 0.0, atol=1e-9)
    assert np.allclose(scaled.std(ddof=0).to_numpy(), 1.0, atol=1e-9)
    assert scaled.min().min() < 0.0  # min-max would never produce negatives


# --- detector: batch min-max normalization to [0,100] (PART A2) ---------------

def test_minmax_normalize_maps_extremes():
    # decision_function: higher = more normal, so the LOWEST raw value is the most
    # anomalous and must map to 100; the highest maps to 0.
    raw = np.array([0.3, 0.1, -0.2, 0.0])
    out = minmax_normalize_scores(raw)
    assert out.min() == 0.0
    assert out.max() == 100.0
    assert out[np.argmin(raw)] == 100.0
    assert out[np.argmax(raw)] == 0.0


def test_minmax_normalize_degenerate_batch():
    out = minmax_normalize_scores(np.array([0.5, 0.5, 0.5]))
    assert np.all(out == 0.0)  # no relative anomalies when all scores identical


def test_detector_exposes_normalize_scores():
    det = AnomalyDetector()
    out = det.normalize_scores(np.array([0.2, -0.1, 0.0]))
    assert out.min() == 0.0 and out.max() == 100.0


# --- risk scorer: configurable weights + CVSS bands (PART A3) ------------------

def test_default_weights_are_60_40():
    s = RiskScorer()
    assert s.ml_weight == 0.6
    assert s.rule_weight == 0.4


def test_weights_are_configurable():
    s = RiskScorer(ml_weight=0.5, rule_weight=0.5)
    # pure ML 100, no rules -> 100*0.5 = 50
    assert s.compute_risk_score(100.0, 0.0) == 50.0
    # pure rules 1.0, no ML -> 100*0.5 = 50
    assert s.compute_risk_score(0.0, 1.0) == 50.0


def test_priority_bands_cvss_aligned():
    s = RiskScorer()
    assert s.assign_priority(90) == "CRITICAL"
    assert s.assign_priority(60) == "HIGH"
    assert s.assign_priority(30) == "MEDIUM"
    assert s.assign_priority(10) == "LOW"


def test_score_dataframe_end_to_end():
    s = RiskScorer()
    df = pd.DataFrame({
        "Flow Packets/s": [20000.0, 1.0, 5.0],
        "Packet Length Mean": [5.0, 500.0, 50.0],
        "Flow Duration": [1.0, 1.0, 1.0],
        "Flow Bytes/s": [1.0, 1.0, 1.0],
    })
    raw_scores = np.array([0.3, 0.1, -0.2])
    res = s.score_dataframe(df, raw_scores)
    assert set(["record_id", "artifact_type", "anomaly_score", "rule_score",
                "risk_score", "priority", "matched_rules"]).issubset(res.columns)
    assert len(res) == 3
    assert res["risk_score"].max() <= 100.0
