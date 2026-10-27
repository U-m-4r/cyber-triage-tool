"""Unit and integration tests for attack-family attribution and uncertainty handling.

All tests here run against isolated, fast synthetic fixtures without requiring the
full 717 MB CICIDS2017 dataset.
"""
import copy
import io
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from ml.attack_family import (
    ATTACK_FAMILIES,
    BUNDLE_VERSION,
    AttackFamilyError,
    attribute_attack_family,
    load_attack_family_model,
    validate_attack_family_bundle,
)
from ml.preprocessor import NETWORK_FEATURES


@pytest.fixture
def synthetic_attack_bundle(tmp_path):
    """Create a fully valid synthetic attack-family bundle for testing."""
    classes = sorted(list(ATTACK_FAMILIES))
    np.random.seed(42)
    # Generate distinct synthetic clusters per class
    n_samples_per_class = 20
    X_parts = []
    y_parts = []
    for idx, cls in enumerate(classes):
        cluster = np.random.randn(n_samples_per_class, len(NETWORK_FEATURES)) * 0.5 + (idx * 3.0)
        X_parts.append(cluster)
        y_parts.extend([cls] * n_samples_per_class)

    X = np.vstack(X_parts)
    y = np.array(y_parts)

    scaler = StandardScaler()
    X_df = pd.DataFrame(X, columns=list(NETWORK_FEATURES))
    scaler.fit(X_df)
    X_scaled = scaler.transform(X_df)

    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_scaled, y)

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "model_family": "attack_attribution",
        "model_id": "attack-family-test-v1",
        "model_type": "RandomForestClassifier",
        "model": model,
        "scaler": scaler,
        "feature_schema": {
            "version": 1,
            "artifact_type": "network",
            "columns": list(NETWORK_FEATURES),
            "dtype": "float64",
            "flow_duration_unit": "microseconds",
        },
        "classes": classes,
        "versions": {
            "scikit_learn": "test",
            "numpy": "test",
            "pandas": "test",
        },
        "provenance": {
            "task": "conditional_attack_family_attribution",
            "dataset_path": "synthetic",
            "training_policy": "attack_only",
            "training_rows": len(X),
            "trained_at": "2026-10-27T00:00:00Z",
        },
        "abstention_policy": {
            "min_confidence": 0.50,
            "min_margin": 0.05,
        },
    }

    path = tmp_path / "test_attack_family_bundle.joblib"
    joblib.dump(bundle, path)
    return path, bundle


def test_bundle_validation_success(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    validated = validate_attack_family_bundle(bundle)
    assert validated["bundle_version"] == BUNDLE_VERSION
    assert validated["classes"] == sorted(list(ATTACK_FAMILIES))


@pytest.mark.parametrize(
    "flaw",
    [
        "wrong_version",
        "wrong_family",
        "missing_model",
        "unfitted_model",
        "missing_columns",
        "wrong_classes",
        "scaler_mismatch",
        "missing_provenance",
    ],
)
def test_bundle_validation_failures(synthetic_attack_bundle, flaw):
    _, original = synthetic_attack_bundle
    corrupt = copy.deepcopy(original)

    if flaw == "wrong_version":
        corrupt["bundle_version"] = 999
    elif flaw == "wrong_family":
        corrupt["model_family"] = "binary_detector"
    elif flaw == "missing_model":
        del corrupt["model"]
    elif flaw == "unfitted_model":
        corrupt["model"] = RandomForestClassifier()
    elif flaw == "missing_columns":
        corrupt["feature_schema"]["columns"] = ["Flow Duration"]
    elif flaw == "wrong_classes":
        corrupt["classes"] = ["BENIGN", "DoS"]
    elif flaw == "scaler_mismatch":
        corrupt["scaler"] = StandardScaler()  # unfitted
    elif flaw == "missing_provenance":
        corrupt["provenance"] = {}

    with pytest.raises(AttackFamilyError) as exc:
        validate_attack_family_bundle(corrupt)
    assert exc.value.code == "MODEL_INVALID"


def test_load_attack_family_missing_fails_closed(tmp_path):
    missing_path = tmp_path / "non_existent.joblib"
    with pytest.raises(AttackFamilyError) as exc:
        load_attack_family_model(missing_path)
    assert exc.value.code == "MODEL_MISSING"


def test_feature_schema_and_column_ordering(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle

    # Generate synthetic input row with reversed columns and extra columns
    cols = list(NETWORK_FEATURES)
    values = [100.0 + i for i in range(len(cols))]
    row_ordered = dict(zip(cols, values))

    # Reversed order + extra unmodeled columns (e.g. Source IP, Label)
    shuffled_cols = list(reversed(cols))
    row_shuffled = {c: row_ordered[c] for c in shuffled_cols}
    row_shuffled["Source IP"] = "192.168.1.100"
    row_shuffled["Label"] = "DDoS"

    res1 = attribute_attack_family(row_ordered, bundle)
    res2 = attribute_attack_family(row_shuffled, bundle)

    assert len(res1) == 1 and len(res2) == 1
    assert res1[0]["confidence"] == pytest.approx(res2[0]["confidence"], rel=1e-4)
    assert res1[0]["predicted_family"] == res2[0]["predicted_family"]


def test_missing_features_raises_error(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    incomplete_record = {"Flow Duration": 1000, "Total Fwd Packets": 5}
    with pytest.raises(AttackFamilyError) as exc:
        attribute_attack_family(incomplete_record, bundle)
    assert exc.value.code == "MISSING_FEATURES"


def test_empty_input_returns_empty_list(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    assert attribute_attack_family([], bundle) == []
    assert attribute_attack_family(pd.DataFrame(), bundle) == []


def test_output_structure_and_calibration_honesty(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    row = {col: 10.0 for col in NETWORK_FEATURES}
    res = attribute_attack_family(row, bundle)
    assert len(res) == 1
    item = res[0]

    # Required fields
    assert "predicted_family" in item
    assert "status" in item
    assert "confidence" in item
    assert "calibrated" in item
    assert "margin" in item
    assert "ranked_candidates" in item
    assert "raw_scores" in item
    assert "model_metadata" in item

    # Must be explicitly uncalibrated
    assert item["calibrated"] is False
    assert item["model_metadata"]["calibrated"] is False
    assert len(item["ranked_candidates"]) == len(ATTACK_FAMILIES)
    # Ranked candidates must be sorted descending by score
    scores = [c["score"] for c in item["ranked_candidates"]]
    assert scores == sorted(scores, reverse=True)


class MockClassifier:
    def __init__(self, probs):
        self.classes_ = np.array(sorted(list(ATTACK_FAMILIES)))
        self._probs = np.array(probs)
        self.n_features_in_ = len(NETWORK_FEATURES)

    def predict_proba(self, X):
        return np.tile(self._probs, (len(X), 1))

    def predict(self, X):
        return np.tile(self.classes_[np.argmax(self._probs)], len(X))


def test_abstention_policy_low_confidence(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    test_bundle = copy.deepcopy(bundle)
    # Max probability across 6 classes is 0.20, well below default 0.50 threshold
    test_bundle["model"] = MockClassifier([0.20, 0.20, 0.20, 0.15, 0.15, 0.10])
    row = {col: 10.0 for col in NETWORK_FEATURES}

    res = attribute_attack_family(row, test_bundle)
    assert len(res) == 1
    assert res[0]["status"] == "ABSTAINED"
    assert res[0]["predicted_family"] is None
    assert "is below policy threshold" in res[0]["abstention_reason"]


def test_abstention_policy_ambiguous_margin(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    test_bundle = copy.deepcopy(bundle)
    # Top score 0.60 >= 0.50, but runner up is 0.58 -> margin 0.02 < 0.05 default margin
    test_bundle["model"] = MockClassifier([0.60, 0.58, 0.01, 0.01, 0.0, 0.0])
    row = {col: 10.0 for col in NETWORK_FEATURES}

    res = attribute_attack_family(row, test_bundle)
    assert len(res) == 1
    assert res[0]["status"] == "ABSTAINED"
    assert res[0]["predicted_family"] is None
    assert "Confidence margin" in res[0]["abstention_reason"]


def test_attack_family_api_endpoint(client, synthetic_attack_bundle):
    path, _ = synthetic_attack_bundle
    client.application.config["ATTACK_FAMILY_MODEL_PATH"] = str(path)

    # 1. Test JSON features payload
    record = {col: 10.0 for col in NETWORK_FEATURES}
    resp = client.post("/api/model/attack-family", json={"features": record})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert len(data["attributions"]) == 1

    # 2. Test CSV upload
    csv_content = ",".join(NETWORK_FEATURES) + "\n" + ",".join(["10.0"] * len(NETWORK_FEATURES)) + "\n"
    resp = client.post(
        "/api/model/attack-family",
        data={"file": (io.BytesIO(csv_content.encode("utf-8")), "test.csv")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert len(data["attributions"]) == 1
    assert "evidence" in data  # SHA-256 chain of custody

    # 3. Test missing model returns 503
    client.application.config["ATTACK_FAMILY_MODEL_PATH"] = "non_existent.joblib"
    resp = client.post("/api/model/attack-family", json={"features": record})
    assert resp.status_code == 503


def test_calibrated_bundle_dual_scores_and_sum_to_one(synthetic_attack_bundle):
    from sklearn.calibration import CalibratedClassifierCV
    try:
        from sklearn.frozen import FrozenEstimator
        def freeze(est):
            return FrozenEstimator(est)
    except ImportError:
        def freeze(est):
            return est

    _, bundle = synthetic_attack_bundle
    calibrated_bundle = copy.deepcopy(bundle)

    # Fit a simple synthetic calibrator on dummy data with 10 samples per class
    classes = sorted(list(ATTACK_FAMILIES))
    X_cal = np.random.randn(len(classes) * 10, len(NETWORK_FEATURES))
    X_cal_df = pd.DataFrame(X_cal, columns=list(NETWORK_FEATURES))
    y_cal = np.repeat(classes, 10)
    calibrator = CalibratedClassifierCV(estimator=freeze(bundle["model"]), method="sigmoid")
    calibrator.fit(bundle["scaler"].transform(X_cal_df), y_cal)

    calibrated_bundle["calibrator"] = calibrator
    calibrated_bundle["calibration_metadata"] = {
        "method": "sigmoid",
        "fitted_on": "synthetic_calibration_fold",
    }

    # Validate bundle passes
    validated = validate_attack_family_bundle(calibrated_bundle)
    assert "calibrator" in validated

    row = {col: 10.0 for col in NETWORK_FEATURES}
    res = attribute_attack_family(row, calibrated_bundle)
    assert len(res) == 1
    item = res[0]

    assert item["calibrated"] is True
    assert item["raw_confidence"] is not None
    assert item["calibrated_confidence"] is not None
    assert item["calibrated_scores"] is not None
    assert item["raw_scores"] is not None

    # Calibrated probabilities must sum to 1.0 within numerical tolerance
    cal_sum = sum(item["calibrated_scores"].values())
    raw_sum = sum(item["raw_scores"].values())
    assert cal_sum == pytest.approx(1.0, abs=1e-3)
    assert raw_sum == pytest.approx(1.0, abs=1e-3)

    # Verify ranked candidates contain both raw and calibrated fields
    for cand in item["ranked_candidates"]:
        assert "family" in cand
        assert "score" in cand
        assert "raw_score" in cand
        assert "calibrated_score" in cand


def test_class_order_stability(synthetic_attack_bundle):
    _, bundle = synthetic_attack_bundle
    expected_order = sorted(list(ATTACK_FAMILIES))
    assert list(bundle["classes"]) == expected_order

    row = {col: 10.0 for col in NETWORK_FEATURES}
    res = attribute_attack_family(row, bundle)
    item = res[0]

    assert list(item["raw_scores"].keys()) == expected_order
    candidate_families = [c["family"] for c in item["ranked_candidates"]]
    assert set(candidate_families) == set(expected_order)


def test_calibrator_inference_failure_safe_degradation(synthetic_attack_bundle):
    """If calibrator throws an error during inference, fall back safely to raw scores."""
    _, bundle = synthetic_attack_bundle
    broken_bundle = copy.deepcopy(bundle)

    class BrokenCalibrator:
        def predict_proba(self, X):
            raise RuntimeError("Corrupt calibrator tensor")

    broken_bundle["calibrator"] = BrokenCalibrator()
    row = {col: 10.0 for col in NETWORK_FEATURES}

    res = attribute_attack_family(row, broken_bundle)
    assert len(res) == 1
    item = res[0]
    # Successfully degrades to uncalibrated
    assert item["calibrated"] is False
    assert item["confidence"] == item["raw_confidence"]
    assert item["calibrated_scores"] is None


def test_calibration_metrics_brier_and_ece():
    from ml.calibration_metrics import (
        compute_expected_calibration_error,
        compute_multiclass_brier_score,
        compute_multiclass_log_loss,
    )

    classes = ["A", "B", "C"]
    y_true = np.array(["A", "B", "A", "C"])
    # Perfect probabilities:
    perfect_probs = np.array([
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0],
    ])

    brier_perfect = compute_multiclass_brier_score(y_true, perfect_probs, classes)
    assert brier_perfect["brier_score"] == pytest.approx(0.0)

    ece_perfect, bins = compute_expected_calibration_error(y_true, perfect_probs, classes, n_bins=5)
    assert ece_perfect == pytest.approx(0.0)
    assert len(bins) == 5

    # Imperfect probabilities:
    probs = np.array([
        [0.8, 0.1, 0.1],
        [0.2, 0.7, 0.1],
        [0.6, 0.2, 0.2],
        [0.3, 0.3, 0.4],
    ])
    loss = compute_multiclass_log_loss(y_true, probs, classes)
    assert loss > 0.0

    brier = compute_multiclass_brier_score(y_true, probs, classes)
    assert brier["brier_score"] > 0.0

    ece, bin_stats = compute_expected_calibration_error(y_true, probs, classes, n_bins=10)
    assert 0.0 <= ece <= 1.0
    for b in bin_stats:
        if b["sample_count"] > 0:
            assert b["calibration_gap"] == pytest.approx(
                abs(b["observed_accuracy"] - b["mean_confidence"]), abs=1e-4
            )

