"""Attack-family attribution service and bundle validation.

This module provides a dedicated classifier to attribute attack traffic to
one of six attack families:
  ['Bots', 'Brute Force', 'DDoS', 'DoS', 'Port Scanning', 'Web Attacks']

Crucial principles:
1. Conditional attribution: Designed for traffic already flagged or suspicious.
2. Honest uncertainty: Distinguishes raw model confidence from calibrated
   probabilities, supporting an explicit abstention policy (low confidence
   or ambiguous margins).
3. Fail closed: Verifies bundle integrity, feature contract, and scikit-learn
   compatibility before inference.
"""
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.utils.validation import check_is_fitted

from ml.preprocessor import (
    NETWORK_FEATURES,
    NetworkInputError,
    prepare_network_frame,
)

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_ATTACK_FAMILY_MODEL_PATH = ROOT_DIR / "models" / "attack_family_bundle.joblib"
BUNDLE_VERSION = 1

# The authoritative 6 attack families in the CICIDS2017 dataset (excluding BENIGN/Normal Traffic)
ATTACK_FAMILIES = (
    "Bots",
    "Brute Force",
    "DDoS",
    "DoS",
    "Port Scanning",
    "Web Attacks",
)

DEFAULT_MIN_CONFIDENCE = 0.50
DEFAULT_MIN_MARGIN = 0.05


class AttackFamilyError(RuntimeError):
    """Exception raised for attack family attribution errors."""

    def __init__(self, message: str, code: str = "ATTRIBUTION_ERROR"):
        super().__init__(message)
        self.code = code


def validate_attack_family_bundle(bundle: Any) -> Dict[str, Any]:
    """Validate the integrity, schema, and provenance of an attack-family bundle."""

    def require(condition: bool, msg: str = "Invalid attack family bundle component"):
        if not condition:
            raise ValueError(msg)

    try:
        require(isinstance(bundle, dict), "Bundle must be a dict")
        require(
            bundle.get("bundle_version") == BUNDLE_VERSION,
            f"Unsupported bundle version: {bundle.get('bundle_version')}",
        )
        require(bundle.get("model_family") == "attack_attribution", "Invalid model_family")

        # Feature Schema
        schema = bundle.get("feature_schema", {})
        require(schema.get("version") == 1, "Schema version must be 1")
        require(schema.get("artifact_type") == "network", "Artifact type must be network")
        require(
            list(schema.get("columns", [])) == list(NETWORK_FEATURES),
            "Schema columns must match NETWORK_FEATURES",
        )
        require(schema.get("flow_duration_unit") == "microseconds", "Invalid flow duration unit")

        # Classes
        classes = list(bundle.get("classes", []))
        require(classes == sorted(list(ATTACK_FAMILIES)), f"Classes must match {sorted(list(ATTACK_FAMILIES))}")

        # Model and Scaler
        model = bundle.get("model")
        scaler = bundle.get("scaler")
        require(model is not None, "Model is missing from bundle")
        require(hasattr(model, "predict_proba"), "Model must support predict_proba")
        check_is_fitted(model)

        if scaler is not None:
            check_is_fitted(scaler)
            require(
                scaler.n_features_in_ == len(NETWORK_FEATURES),
                "Scaler features count mismatch",
            )
            require(
                np.isfinite(scaler.mean_).all() and np.isfinite(scaler.scale_).all(),
                "Scaler non-finite parameters",
            )
            require((scaler.scale_ > 0).all(), "Scaler non-positive scale")

        # Provenance & Metadata
        provenance = bundle.get("provenance", {})
        require(isinstance(provenance, dict), "Provenance must be a dict")
        require(provenance.get("task") == "conditional_attack_family_attribution", "Invalid task")
        require(provenance.get("training_policy") == "attack_only", "Training policy must be attack_only")
        require(provenance.get("training_rows", 0) >= len(ATTACK_FAMILIES), "Insufficient training rows")
        require(bool(provenance.get("trained_at")), "trained_at timestamp required")

        # Optional Calibrator & Calibration Metadata
        calibrator = bundle.get("calibrator")
        if calibrator is not None:
            require(hasattr(calibrator, "predict_proba"), "Calibrator must support predict_proba")
            check_is_fitted(calibrator)

        calibration_meta = bundle.get("calibration_metadata")
        if calibration_meta is not None:
            require(isinstance(calibration_meta, dict), "Calibration metadata must be a dict")
            require("method" in calibration_meta, "Calibration metadata requires 'method'")

        # Abstention Policy Defaults
        abstention = bundle.get("abstention_policy", {})
        require(isinstance(abstention, dict), "Abstention policy must be a dict")
        require(
            0.0 <= abstention.get("min_confidence", DEFAULT_MIN_CONFIDENCE) <= 1.0,
            "Invalid min_confidence",
        )
        require(
            0.0 <= abstention.get("min_margin", DEFAULT_MIN_MARGIN) <= 1.0,
            "Invalid min_margin",
        )

    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise AttackFamilyError(
            f"Attack family bundle is incomplete, incompatible, or invalid: {exc}",
            code="MODEL_INVALID",
        ) from exc

    return bundle


def load_attack_family_model(path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load and validate an approved attack-family attribution bundle."""
    target_path = Path(path if path is not None else DEFAULT_ATTACK_FAMILY_MODEL_PATH)
    if not target_path.is_file():
        raise AttackFamilyError(
            f"Attack family model bundle not found at {target_path}. Train it with "
            "scripts/train_attack_family.py using the approved dataset.",
            code="MODEL_MISSING",
        )
    try:
        bundle = joblib.load(target_path)
    except Exception as exc:
        raise AttackFamilyError(
            f"Could not load attack family bundle at {target_path}: {exc}",
            code="MODEL_INVALID",
        ) from exc
    return validate_attack_family_bundle(bundle)


def attribute_attack_family(
    frame_or_records: Union[pd.DataFrame, List[Dict[str, Any]], Dict[str, Any]],
    bundle: Dict[str, Any],
    abstention_policy: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Attribute network flow records to likely attack families.

    Parameters
    ----------
    frame_or_records : DataFrame, dict, or list of dicts
        Input network flow features.
    bundle : dict
        Validated attack family bundle.
    abstention_policy : dict, optional
        Custom abstention thresholds: {'min_confidence': float, 'min_margin': float}

    Returns
    -------
    list of dict
        Attribution results per record.
    """
    if isinstance(frame_or_records, dict):
        frame = pd.DataFrame([frame_or_records])
    elif isinstance(frame_or_records, list):
        if not frame_or_records:
            return []
        frame = pd.DataFrame(frame_or_records)
    elif isinstance(frame_or_records, pd.DataFrame):
        frame = frame_or_records.copy()
    else:
        raise AttackFamilyError(
            "Input must be a pandas DataFrame, dictionary, or list of dictionaries.",
            code="INVALID_INPUT_TYPE",
        )

    if len(frame) == 0:
        return []

    # Clean and extract features matching feature schema
    expected_columns = bundle["feature_schema"]["columns"]
    try:
        clean_df, feature_df, _ = prepare_network_frame(frame, expected_columns)
    except NetworkInputError as exc:
        raise AttackFamilyError(f"Feature contract validation failed: {exc}", code=exc.code) from exc

    scaler = bundle.get("scaler")
    if scaler is not None:
        scaled_vals = scaler.transform(feature_df)
        if not np.isfinite(scaled_vals).all():
            raise AttackFamilyError(
                "Network values overflowed scaler; verify feature units.",
                code="NUMERIC_OVERFLOW",
            )
        model_input = scaled_vals
    else:
        model_input = feature_df.to_numpy(dtype=np.float64)

    model = bundle["model"]
    classes = list(bundle["classes"])

    # Predict probabilities (raw tree/model scores)
    try:
        raw_probabilities = model.predict_proba(model_input)
    except Exception as exc:
        raise AttackFamilyError(f"Model inference failed: {exc}", code="INFERENCE_FAILED") from exc

    # Optional calibrated probabilities
    calibrator = bundle.get("calibrator")
    calibrated_probabilities = None
    if calibrator is not None:
        try:
            calibrated_probabilities = calibrator.predict_proba(model_input)
        except Exception:
            # Safe degradation: fall back to raw probabilities
            calibrated_probabilities = None

    policy = dict(bundle.get("abstention_policy", {}))
    if abstention_policy:
        policy.update(abstention_policy)

    use_calibrated = policy.get(
        "use_calibrated_confidence",
        calibrated_probabilities is not None,
    )

    if use_calibrated and calibrated_probabilities is not None:
        eval_probs = calibrated_probabilities
        is_calibrated = True
        score_semantics = "calibrated_posterior_probability_estimate"
        cal_method = bundle.get("calibration_metadata", {}).get("method", "calibrated")
    else:
        eval_probs = raw_probabilities
        is_calibrated = False
        score_semantics = "uncalibrated_class_probability_estimate"
        cal_method = "none"

    min_conf = float(policy.get("min_confidence", DEFAULT_MIN_CONFIDENCE))
    min_margin = float(policy.get("min_margin", DEFAULT_MIN_MARGIN))

    results = []
    model_meta = {
        "model_id": bundle.get("model_id", "attack-family-classifier"),
        "model_type": bundle.get("model_type", type(model).__name__),
        "bundle_version": bundle.get("bundle_version", BUNDLE_VERSION),
        "classes": classes,
        "calibrated": is_calibrated,
        "calibration_method": cal_method,
        "score_semantics": score_semantics,
    }

    for row_idx, probs in enumerate(eval_probs):
        raw_p = raw_probabilities[row_idx]
        cal_p = calibrated_probabilities[row_idx] if calibrated_probabilities is not None else None

        # Sort candidates descending by evaluated probability
        ranked_indices = np.argsort(-probs)
        top_idx = ranked_indices[0]
        top_family = classes[top_idx]
        top_score = float(probs[top_idx])

        runner_up_score = float(probs[ranked_indices[1]]) if len(ranked_indices) > 1 else 0.0
        margin = top_score - runner_up_score

        # Raw specifics
        raw_ranked_idx = np.argsort(-raw_p)
        top_raw_score = float(raw_p[raw_ranked_idx[0]])
        runner_up_raw = float(raw_p[raw_ranked_idx[1]]) if len(raw_ranked_idx) > 1 else 0.0
        raw_margin = top_raw_score - runner_up_raw

        # Calibrated specifics
        if cal_p is not None:
            cal_ranked_idx = np.argsort(-cal_p)
            top_cal_score = float(cal_p[cal_ranked_idx[0]])
            runner_up_cal = float(cal_p[cal_ranked_idx[1]]) if len(cal_ranked_idx) > 1 else 0.0
            cal_margin = top_cal_score - runner_up_cal
            cal_scores_dict = {classes[i]: round(float(cal_p[i]), 4) for i in range(len(classes))}
        else:
            top_cal_score = None
            cal_margin = None
            cal_scores_dict = None

        ranked_candidates = [
            {
                "family": classes[i],
                "score": round(float(probs[i]), 4),
                "raw_score": round(float(raw_p[i]), 4),
                "calibrated_score": round(float(cal_p[i]), 4) if cal_p is not None else None,
            }
            for i in ranked_indices
        ]
        raw_scores = {classes[i]: round(float(raw_p[i]), 4) for i in range(len(classes))}

        # Evaluate abstention policy
        if top_score < min_conf:
            status = "ABSTAINED"
            predicted_family = None
            score_label = "calibrated confidence" if is_calibrated else "raw confidence"
            abstention_reason = (
                f"Top candidate {score_label} {top_score:.4f} is below policy threshold {min_conf:.4f}"
            )
        elif margin < min_margin:
            status = "ABSTAINED"
            predicted_family = None
            score_label = "calibrated" if is_calibrated else "raw"
            abstention_reason = (
                f"Confidence margin {margin:.4f} ({score_label}) between top candidates '{top_family}' "
                f"({top_score:.4f}) and '{classes[ranked_indices[1]]}' ({runner_up_score:.4f}) "
                f"is below threshold {min_margin:.4f}"
            )
        else:
            status = "ATTRIBUTED"
            predicted_family = top_family
            abstention_reason = None

        record = {
            "record_index": int(clean_df.index[row_idx]),
            "predicted_family": predicted_family,
            "status": status,
            "confidence": round(top_score, 4),
            "calibrated": is_calibrated,
            "margin": round(margin, 4),
            "raw_confidence": round(top_raw_score, 4),
            "calibrated_confidence": round(top_cal_score, 4) if top_cal_score is not None else None,
            "raw_margin": round(raw_margin, 4),
            "calibrated_margin": round(cal_margin, 4) if cal_margin is not None else None,
            "abstention_reason": abstention_reason,
            "ranked_candidates": ranked_candidates,
            "raw_scores": raw_scores,
            "calibrated_scores": cal_scores_dict,
            "model_metadata": model_meta,
        }
        results.append(record)

    return results
