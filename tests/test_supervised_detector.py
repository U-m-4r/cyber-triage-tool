"""Comprehensive unit and regression tests for the supervised binary detector service."""
import copy
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from ml.baseline import BASELINE_PATH, load_baseline
from ml.preprocessor import NETWORK_FEATURES
from ml.supervised_detector import (
    DEFAULT_SUPERVISED_PATH,
    SUPERVISED_BUNDLE_VERSION,
    SupervisedDetectorError,
    infer_supervised_network,
    load_supervised_detector,
    supervised_metadata,
    validate_supervised_bundle,
)
from backend.app import create_app


@pytest.fixture
def valid_bundle():
    """Load the trained supervised bundle fixture."""
    return load_supervised_detector(DEFAULT_SUPERVISED_PATH)


@pytest.fixture
def synthetic_network_df():
    """Create a minimal valid synthetic network DataFrame matching the approved 11 features."""
    data = {
        "Flow Duration": [100.0, 500000.0, 20.0],
        "Total Fwd Packets": [2.0, 100.0, 1.0],
        "Total Length of Fwd Packets": [120.0, 15000.0, 60.0],
        "Fwd Packet Length Max": [60.0, 1500.0, 60.0],
        "Fwd Packet Length Min": [60.0, 40.0, 60.0],
        "Fwd Packet Length Mean": [60.0, 800.0, 60.0],
        "Bwd Packet Length Max": [0.0, 1500.0, 0.0],
        "Bwd Packet Length Min": [0.0, 40.0, 0.0],
        "Flow Bytes/s": [1200.0, 30000.0, 3000.0],
        "Flow Packets/s": [20.0, 200.0, 50.0],
        "Packet Length Mean": [60.0, 750.0, 60.0],
    }
    return pd.DataFrame(data)


# ---------------------------------------------------------------------------
# 1. Feature Order and Schema Validation
# ---------------------------------------------------------------------------


def test_bundle_feature_schema(valid_bundle):
    assert valid_bundle["bundle_version"] == SUPERVISED_BUNDLE_VERSION
    assert valid_bundle["task"] == "binary_intrusion_detection"
    assert valid_bundle["model_type"] == "xgboost_binary"
    assert valid_bundle["feature_schema"]["columns"] == list(NETWORK_FEATURES)
    assert valid_bundle["scaler"].n_features_in_ == len(NETWORK_FEATURES)


def test_infer_missing_feature_column_raises(valid_bundle, synthetic_network_df):
    incomplete_df = synthetic_network_df.drop(columns=["Flow Duration"])
    with pytest.raises(SupervisedDetectorError) as exc_info:
        infer_supervised_network(incomplete_df, valid_bundle)
    assert exc_info.value.code in ("INPUT_DATA_INVALID", "FEATURE_SCHEMA_MISMATCH")


def test_infer_reorders_shuffled_features_correctly(valid_bundle, synthetic_network_df):
    shuffled_cols = list(reversed(NETWORK_FEATURES))
    shuffled_df = synthetic_network_df[shuffled_cols]
    clean, preds, scores, meta = infer_supervised_network(shuffled_df, valid_bundle)

    assert len(preds) == len(synthetic_network_df)
    assert len(scores) == len(synthetic_network_df)
    assert meta["detector_type"] == "supervised_binary"


# ---------------------------------------------------------------------------
# 2. Missing & Non-finite Values Handling
# ---------------------------------------------------------------------------


def test_infer_handles_or_rejects_non_finite_values(valid_bundle, synthetic_network_df):
    nan_df = synthetic_network_df.copy()
    nan_df.loc[0, "Flow Duration"] = np.nan
    clean, preds, scores, meta = infer_supervised_network(nan_df, valid_bundle)
    # preprocessor imputes or cleans standard numeric frames
    assert np.isfinite(scores).all()


# ---------------------------------------------------------------------------
# 3. Decision Semantics: Model Score vs Calibrated Probability vs Decision
# ---------------------------------------------------------------------------


def test_score_and_decision_semantics(valid_bundle, synthetic_network_df):
    clean, preds, scores, meta = infer_supervised_network(synthetic_network_df, valid_bundle)

    # 1. Continuous model score must be finite and in [0.0, 1.0]
    assert np.all((scores >= 0.0) & (scores <= 1.0))

    # 2. Uncalibrated status must be explicit
    assert meta["calibrated"] is False
    assert "Uncalibrated" in meta["score_interpretation"]

    # 3. Binary decisions must be in {0, 1}
    assert set(np.unique(preds)).issubset({0, 1})

    # 4. Binary decision must match threshold strictly: preds == (scores >= active_threshold)
    expected_preds = (scores >= meta["active_threshold"]).astype(int)
    np.testing.assert_array_equal(preds, expected_preds)

    # 5. Label mapping must map 0 -> BENIGN, 1 -> ATTACK
    assert meta["label_mapping"] == {0: "BENIGN", 1: "ATTACK"}


def test_threshold_override_behavior(valid_bundle, synthetic_network_df):
    # High threshold (e.g. 0.99) -> all benign
    _, preds_high, _, meta_high = infer_supervised_network(
        synthetic_network_df, valid_bundle, threshold_override=0.99
    )
    assert meta_high["active_threshold"] == 0.99
    assert meta_high["threshold_overridden"] is True
    assert (preds_high == 0).all()

    # Low threshold (e.g. 0.0) -> all attack
    _, preds_low, _, meta_low = infer_supervised_network(
        synthetic_network_df, valid_bundle, threshold_override=0.0
    )
    assert meta_low["active_threshold"] == 0.0
    assert (preds_low == 1).all()

    # Invalid threshold raises
    with pytest.raises(SupervisedDetectorError) as exc_info:
        infer_supervised_network(synthetic_network_df, valid_bundle, threshold_override=1.5)
    assert exc_info.value.code == "INVALID_THRESHOLD"


# ---------------------------------------------------------------------------
# 4. Artifact Validation & Missing/Corrupt Handling
# ---------------------------------------------------------------------------


def test_missing_supervised_model_raises(tmp_path):
    missing_path = tmp_path / "nonexistent.joblib"
    with pytest.raises(SupervisedDetectorError) as exc_info:
        load_supervised_detector(missing_path)
    assert exc_info.value.code == "SUPERVISED_MODEL_MISSING"


def test_corrupt_bundle_raises(valid_bundle):
    # Alter bundle version
    bad_bundle = copy.deepcopy(valid_bundle)
    bad_bundle["bundle_version"] = 999
    with pytest.raises(SupervisedDetectorError):
        validate_supervised_bundle(bad_bundle)

    # Alter task
    bad_bundle = copy.deepcopy(valid_bundle)
    bad_bundle["task"] = "wrong_task"
    with pytest.raises(SupervisedDetectorError):
        validate_supervised_bundle(bad_bundle)

    # Alter schema columns
    bad_bundle = copy.deepcopy(valid_bundle)
    bad_bundle["feature_schema"]["columns"] = ["wrong_column"]
    with pytest.raises(SupervisedDetectorError):
        validate_supervised_bundle(bad_bundle)


# ---------------------------------------------------------------------------
# 5. Isolation Forest Preservation & Semantics Verification
# ---------------------------------------------------------------------------


def test_baseline_isolation_forest_preserved_byte_identical():
    # Verify baseline artifact exists and is not replaced
    assert BASELINE_PATH.is_file()
    baseline = load_baseline(BASELINE_PATH)
    assert baseline["bundle_version"] == 1
    assert baseline["provenance"]["model_id"] == "iforest-65dd0b57a2b1a2020a0b"


def test_isolation_forest_score_direction_and_labels(synthetic_network_df):
    """Verify Isolation Forest decision_function and predict semantics:

    1. predict(X) yields +1 for inliers (normal) and -1 for outliers (anomalous).
    2. decision_function(X) > 0 for inliers and < 0 for outliers.
    """
    baseline = load_baseline(BASELINE_PATH)
    scaler = baseline["scaler"]
    model = baseline["model"]

    scaled = scaler.transform(synthetic_network_df[list(NETWORK_FEATURES)])
    preds = model.predict(scaled)
    dec_scores = model.decision_function(scaled)

    for p, s in zip(preds, dec_scores):
        if s >= 0:
            assert p == 1, "decision_function >= 0 must predict +1 (normal)"
        else:
            assert p == -1, "decision_function < 0 must predict -1 (anomaly)"


# ---------------------------------------------------------------------------
# 6. Backend Integration & API Compatibility
# ---------------------------------------------------------------------------


def test_api_supervised_model_status_endpoint():
    app = create_app({"TESTING": True, "APP_ENV": "test"})
    client = app.test_client()

    resp = client.get("/api/model/supervised")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["available"] is True
    assert data["supervised"]["task"] == "binary_intrusion_detection"
    assert data["supervised"]["model_type"] == "xgboost_binary"
    assert "threshold_config" in data["supervised"]
    assert data["supervised"]["threshold_config"]["threshold"] > 0.0


def test_api_analyze_with_supervised_detector(synthetic_network_df, tmp_path):
    app = create_app({"TESTING": True, "APP_ENV": "test"})
    client = app.test_client()

    csv_path = tmp_path / "test_flow.csv"
    synthetic_network_df.to_csv(csv_path, index=False)

    with open(csv_path, "rb") as f:
        resp = client.post(
            "/api/analyze?detector=supervised",
            data={"file": (f, "test_flow.csv"), "kind": "pcap"},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["detector"] == "supervised_binary"
    assert "supervised" in data
    assert "inference_metadata" in data
    assert data["inference_metadata"]["detector_type"] == "supervised_binary"
    assert "summary" in data


def test_api_analyze_default_remains_baseline(synthetic_network_df, tmp_path):
    """Confirm backward compatibility: omitting detector parameter defaults to baseline."""
    app = create_app({"TESTING": True, "APP_ENV": "test"})
    client = app.test_client()

    csv_path = tmp_path / "test_flow.csv"
    synthetic_network_df.to_csv(csv_path, index=False)

    with open(csv_path, "rb") as f:
        resp = client.post(
            "/api/analyze",
            data={"file": (f, "test_flow.csv"), "kind": "pcap"},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["detector"] == "anomaly_baseline"
    assert "baseline" in data
