"""Supervised binary network intrusion detector service.

Loads and evaluates the approved supervised binary detector (XGBoost) with explicit
feature schema validation, fitted scaling, continuous model score extraction, and
validation-selected decision thresholding.
"""
from pathlib import Path
import re
import io
import hashlib
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted

from ml.cleaning import CLEANING_POLICY_ID, CLEANING_POLICY_VERSION
from ml.dataset_source import DATASET_HANDLE, DATASET_PAGE_URL
from ml.preprocessor import (
    NETWORK_FEATURES,
    NetworkInputError,
    prepare_network_frame,
    read_network_csv,
)

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SUPERVISED_PATH = ROOT_DIR / "models" / "supervised_binary.joblib"
SUPERVISED_BUNDLE_VERSION = 1


class SupervisedDetectorError(RuntimeError):
    """Raised when the supervised detector is missing, invalid, or receives incompatible data."""

    def __init__(self, message: str, code: str = "SUPERVISED_MODEL_INVALID"):
        super().__init__(message)
        self.code = code


def validate_supervised_bundle(bundle: Any) -> Dict[str, Any]:
    """Validate completeness, feature contract, fitted status, and provenance of the bundle."""

    def require(condition: bool, msg: str = "Invalid supervised model bundle component"):
        if not condition:
            raise ValueError(msg)

    try:
        require(isinstance(bundle, dict), "Bundle must be a dictionary")
        require(
            bundle.get("bundle_version") == SUPERVISED_BUNDLE_VERSION,
            f"Unsupported bundle version: {bundle.get('bundle_version')}",
        )
        require(
            bundle.get("task") == "binary_intrusion_detection",
            "Bundle task must be 'binary_intrusion_detection'",
        )

        # Feature schema validation
        schema = bundle.get("feature_schema", {})
        require(schema.get("version") == 1, "Feature schema version must be 1")
        require(schema.get("artifact_type") == "network", "Artifact type must be 'network'")
        require(
            schema.get("columns") == list(NETWORK_FEATURES),
            "Feature schema columns must strictly match approved NETWORK_FEATURES in order",
        )
        require(schema.get("dtype") == "float64", "Feature dtype must be float64")
        require(schema.get('flow_duration_unit') == 'microseconds', 'Flow duration unit mismatch')
        require(bundle.get('versions', {}).get('scikit_learn') == sklearn.__version__, 'scikit-learn version mismatch')

        # Estimator & Scaler validation
        model = bundle.get("model")
        scaler = bundle.get("scaler")
        require(model is not None, "Model estimator is missing")
        from xgboost import XGBClassifier, __version__ as xgb_version
        require(isinstance(model, XGBClassifier) and bundle.get('model_type') == 'xgboost_binary', 'Expected XGBoost binary estimator')
        require(bundle.get('versions', {}).get('xgboost') == xgb_version, 'XGBoost runtime version mismatch')
        check_is_fitted(model)
        require(model.n_features_in_ == len(NETWORK_FEATURES), 'Model feature count mismatch')
        require(list(model.classes_) == [0, 1], 'Expected labels 0=BENIGN, 1=ATTACK')
        require(isinstance(scaler, StandardScaler), "Scaler must be a fitted StandardScaler")

        check_is_fitted(scaler)
        require(scaler.n_features_in_ == len(NETWORK_FEATURES), "Scaler feature count mismatch")
        if hasattr(scaler, 'feature_names_in_'):
            require(list(scaler.feature_names_in_) == list(NETWORK_FEATURES), 'Scaler feature order mismatch')
        require(
            np.isfinite(scaler.mean_).all() and np.isfinite(scaler.scale_).all(),
            "Scaler parameters must be finite",
        )
        require((scaler.scale_ > 0).all(), "Scaler scale must be positive")

        # Threshold configuration validation
        t_cfg = bundle.get("threshold_config")
        require(isinstance(t_cfg, dict), "threshold_config must be a dictionary")
        thresh = t_cfg.get("threshold")
        require(isinstance(thresh, (int, float)) and 0.0 <= float(thresh) <= 1.0, "Invalid threshold")
        require(t_cfg.get('calibrated') is False, 'This XGBoost bundle has no probability calibrator')

        # Provenance validation
        prov = bundle.get("provenance", {})
        require(prov.get("dataset_id") == DATASET_HANDLE, "dataset_id mismatch")
        require(prov.get("source_url") == DATASET_PAGE_URL, "source_url mismatch")
        require(re.fullmatch(r"[0-9a-f]{64}", str(prov.get("sha256") or "")), "Dataset sha256 mismatch")
        require(isinstance(prov.get("model_id"), str) and len(prov.get("model_id")) > 0, "Invalid model_id")
        require(prov.get('positive_class') == 'ATTACK' and prov.get('negative_class') == 'BENIGN', 'Label semantics mismatch')

    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SupervisedDetectorError(
            f"Supervised model bundle is incomplete, incompatible, or invalid: {exc}",
            code="SUPERVISED_MODEL_INVALID",
        ) from exc

    return bundle


def load_supervised_detector(path: Union[str, Path] = DEFAULT_SUPERVISED_PATH) -> Dict[str, Any]:
    """Load and validate an approved supervised binary detector bundle."""
    p = Path(path)
    if not p.is_file():
        raise SupervisedDetectorError(
            f"Approved supervised detector is missing at '{p}'. Uploaded evidence cannot train a model.",
            code="SUPERVISED_MODEL_MISSING",
        )
    try:
        payload = p.read_bytes()
        bundle = joblib.load(io.BytesIO(payload))
    except Exception as exc:
        raise SupervisedDetectorError(
            f"Could not load the supervised model artifact from '{p}': {exc}",
            code="SUPERVISED_MODEL_INVALID",
        ) from exc

    bundle = validate_supervised_bundle(bundle)
    bundle['_artifact_sha256'] = hashlib.sha256(payload).hexdigest()
    return bundle


def infer_supervised_network(
    frame: Union[pd.DataFrame, list, dict],
    bundle: Dict[str, Any],
    *,
    threshold_override: Optional[float] = None,
) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray, Dict[str, Any]]:
    """Execute supervised binary network inference.

    Produces:
    1. Continuous model score in [0.0, 1.0] (raw tree probability estimate, NOT calibrated posterior).
    2. Binary classification decision (1 = ATTACK, 0 = BENIGN) by applying the threshold.
    3. Transparent decision and provenance metadata.

    Args:
        frame: Raw network flow records or DataFrame.
        bundle: Validated supervised model bundle.
        threshold_override: Optional manual threshold override; defaults to validation-selected threshold.

    Returns:
        (clean_df, binary_predictions, continuous_scores, metadata)
    """
    expected_cols = bundle["feature_schema"]["columns"]
    try:
        clean, features, preprocessing = prepare_network_frame(frame, expected_cols)
    except NetworkInputError as exc:
        raise SupervisedDetectorError(str(exc), code="INPUT_DATA_INVALID") from exc

    # Feature order and alignment
    missing = [col for col in expected_cols if col not in features.columns]
    if missing:
        raise SupervisedDetectorError(
            f"Input is missing required network features: {missing}",
            code="FEATURE_SCHEMA_MISMATCH",
        )

    features_ordered = features[expected_cols]

    # Transform features with fitted training scaler
    try:
        scaled_values = bundle["scaler"].transform(features_ordered)
    except Exception as exc:
        raise SupervisedDetectorError(
            f"Feature scaling failed: {exc}", code="INPUT_DATA_INVALID"
        ) from exc

    if not np.isfinite(scaled_values).all():
        raise SupervisedDetectorError(
            "Network values produced non-finite values after scaling; verify feature ranges and units.",
            code="INPUT_DATA_INVALID",
        )

    # Inference: continuous model score
    model = bundle["model"]
    try:
        if hasattr(model, "predict_proba"):
            # Probability for class 1 (attack)
            scores = model.predict_proba(scaled_values)[:, 1]
        elif hasattr(model, "decision_function"):
            raw = model.decision_function(scaled_values)
            # Sigmoid mapping for unbounded decision function if present
            scores = 1.0 / (1.0 + np.exp(-raw))
        else:
            scores = model.predict(scaled_values).astype(float)
    except Exception as exc:
        raise SupervisedDetectorError(
            f"Supervised model prediction failed: {exc}", code="PREDICTION_FAILED"
        ) from exc

    scores = np.asarray(scores, dtype=np.float64)
    if scores.shape != (len(clean),) or not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
        raise SupervisedDetectorError('Invalid binary model score output', code='PREDICTION_FAILED')

    # Threshold application
    configured_threshold = float(bundle["threshold_config"]["threshold"])
    active_threshold = (
        float(threshold_override) if threshold_override is not None else configured_threshold
    )

    if not (0.0 <= active_threshold <= 1.0):
        raise SupervisedDetectorError(
            f"Decision threshold must be within [0.0, 1.0], got {active_threshold}",
            code="INVALID_THRESHOLD",
        )

    binary_predictions = (scores >= active_threshold).astype(np.int64)

    metadata = {
        "detector_type": "supervised_binary",
        "model_id": bundle["provenance"].get("model_id"),
        "model_type": bundle.get("model_type", "unknown"),
        "active_threshold": active_threshold,
        "configured_threshold": configured_threshold,
        "threshold_overridden": threshold_override is not None,
        "calibrated": bundle["threshold_config"].get("calibrated", False),
        "score_interpretation": (
            "Calibrated posterior probability"
            if bundle["threshold_config"].get("calibrated", False)
            else "Uncalibrated continuous tree ensemble score in [0, 1]; not posterior probability"
        ),
        "label_mapping": {0: "BENIGN", 1: "ATTACK"},
        "preprocessing": preprocessing,
        "threshold_selection": bundle["threshold_config"],
    }

    return clean, binary_predictions, scores, metadata


def infer_supervised_network_csv(
    path: Union[str, Path],
    bundle: Dict[str, Any],
    *,
    threshold_override: Optional[float] = None,
) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray, Dict[str, Any]]:
    """Inference helper for network CSV files."""
    df = read_network_csv(path)
    return infer_supervised_network(df, bundle, threshold_override=threshold_override)


def supervised_metadata(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Extract public metadata dictionary for API responses."""
    return {
        "bundle_version": bundle.get("bundle_version"),
        "task": bundle.get("task"),
        "model_type": bundle.get("model_type"),
        "feature_schema": bundle.get("feature_schema"),
        "threshold_config": bundle.get("threshold_config"),
        "provenance": bundle.get("provenance"),
        "versions": bundle.get("versions"),
    }
