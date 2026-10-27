"""Train and package the approved supervised binary detector (XGBoost).

Strictly fits StandardScaler and XGBoost on the training partition only, selects the
decision threshold on the validation partition only under a configurable FPR constraint,
and packages a verified bundle without touching the test partition or overwriting
the existing Isolation Forest baseline.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.baseline import BASELINE_PATH
from ml.cleaning import (
    CLEANING_POLICY_ID,
    CLEANING_POLICY_VERSION,
    DEFAULT_LEDGER_PATH,
    DEFAULT_RECORD_PATH,
    load_cleaning_record,
    load_eligible_frame,
    verify_cleaning_record,
)
from ml.dataset_source import DATASET_HANDLE, DATASET_PAGE_URL
from ml.holdout import split_masks, split_metadata
from ml.preprocessor import NETWORK_FEATURES, prepare_network_frame
from ml.supervised_detector import (
    DEFAULT_SUPERVISED_PATH,
    SUPERVISED_BUNDLE_VERSION,
    validate_supervised_bundle,
)
from ml.thresholding import select_validation_threshold

APPROVED_DATASET_PATH = ROOT_DIR / "data" / "sample" / "cicids2017_cleaned.csv"
BENIGN_LABEL = "Normal Traffic"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def train_and_package_supervised(
    dataset_path: Path = APPROVED_DATASET_PATH,
    record_path: Path = DEFAULT_RECORD_PATH,
    output_path: Path = DEFAULT_SUPERVISED_PATH,
    *,
    max_fpr: float = 0.002,
    objective: str = "f1_score",
    random_state: int = 42,
) -> Path:
    """Train XGBoost binary detector and select threshold strictly on validation data."""
    output_path = Path(output_path)
    if output_path.resolve() == BASELINE_PATH.resolve():
        raise ValueError(
            "Output path cannot be the baseline Isolation Forest path! "
            "The baseline model must be preserved byte-for-byte."
        )

    print("=" * 70)
    print("TRAINING APPROVED SUPERVISED BINARY DETECTOR (XGBOOST)")
    print("=" * 70)

    # Provenance and cleaning checks
    print(f"Dataset path: {dataset_path}")
    source_sha = file_sha256(dataset_path)
    ledger_sha = file_sha256(DEFAULT_LEDGER_PATH)
    rec = load_cleaning_record(record_path)
    verify_cleaning_record(rec, expected_source_sha=source_sha, expected_ledger_sha=ledger_sha)
    record_sha = file_sha256(record_path)
    print(f"Dataset SHA-256 verified: {source_sha}")
    print(f"Ledger SHA-256 verified:  {ledger_sha}")

    # Load eligible frame
    cols = list(NETWORK_FEATURES) + ["Attack Type"]
    raw_df = load_eligible_frame(
        source=dataset_path, record_path=record_path, usecols=lambda c: c.strip() in cols
    )
    frame, _, _ = prepare_network_frame(raw_df)
    total_rows = len(frame)
    print(f"Total eligible clean rows: {total_rows:,}")

    # Derive leakage-aware split masks
    masks = split_masks(frame)
    train_mask = masks["train"]
    val_mask = masks["validation"]
    test_mask = masks["test"]

    print(
        f"Partitions: Train={train_mask.sum():,}, Val={val_mask.sum():,}, "
        f"Test={test_mask.sum():,} (STRICTLY HELD OUT)"
    )

    # Derive binary labels: 0 = Benign, 1 = Attack
    raw_labels = frame["Attack Type"].astype(str).str.strip()
    y_binary = (raw_labels != BENIGN_LABEL).to_numpy(dtype=np.int64)

    X_raw = frame[list(NETWORK_FEATURES)].to_numpy(dtype=np.float64)

    X_train_raw = X_raw[train_mask]
    y_train = y_binary[train_mask]

    X_val_raw = X_raw[val_mask]
    y_val = y_binary[val_mask]

    # Preprocessing: StandardScaler fitted strictly on training partition only
    print("\nFitting StandardScaler strictly on training partition...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_val_scaled = scaler.transform(X_val_raw)

    # Model training: XGBoost on training partition only
    print("Fitting XGBoost Classifier on training partition...")
    clf = xgb.XGBClassifier(
        n_estimators=200,
        learning_rate=0.08,
        max_depth=8,
        tree_method="hist",
        random_state=random_state,
        n_jobs=-1,
        eval_metric="logloss",
    )
    t0 = datetime.now()
    clf.fit(X_train_scaled, y_train)
    fit_duration = (datetime.now() - t0).total_seconds()
    print(f"XGBoost fit completed in {fit_duration:.2f}s")

    # Threshold selection strictly on validation data
    print(f"\nSelecting decision threshold on validation partition (max FPR constraint: {max_fpr:.4%})...")
    val_scores = clf.predict_proba(X_val_scaled)[:, 1]
    threshold_result = select_validation_threshold(
        y_val, val_scores, max_fpr=max_fpr, objective=objective, candidate_thresholds=200
    )

    selected_thresh = threshold_result["selected_threshold"]
    val_metrics = threshold_result["metrics"]
    print(f"Selected Threshold: {selected_thresh:.4f}")
    print(
        f"Validation Metrics at Threshold: Acc={val_metrics['accuracy']:.4f}, "
        f"Recall={val_metrics['recall']:.4f}, Precision={val_metrics['precision']:.4f}, "
        f"F1={val_metrics['f1_score']:.4f}, FPR={val_metrics['false_positive_rate']:.4%}"
    )
    if threshold_result["fallback"]:
        print(f"Note: Fallback triggered: {threshold_result['fallback_reason']}")

    # Assemble bundle
    bundle_hash_seed = hashlib.sha256(
        f"xgb-bin-{source_sha}-{fit_duration}-{selected_thresh}".encode()
    ).hexdigest()
    model_id = f"xgb-bin-{bundle_hash_seed[:10]}"

    bundle = {
        "bundle_version": SUPERVISED_BUNDLE_VERSION,
        "task": "binary_intrusion_detection",
        "model_type": "xgboost_binary",
        "feature_schema": {
            "version": 1,
            "artifact_type": "network",
            "columns": list(NETWORK_FEATURES),
            "dtype": "float64",
            "flow_duration_unit": "microseconds",
        },
        "model": clf,
        "scaler": scaler,
        "threshold_config": {
            "threshold": selected_thresh,
            "max_fpr_constraint": max_fpr,
            "objective": objective,
            "fallback": threshold_result["fallback"],
            "fallback_reason": threshold_result.get("fallback_reason"),
            "calibrated": False,
            "score_semantics": (
                "Uncalibrated continuous XGBoost score in [0.0, 1.0]; higher = attack likelihood"
            ),
            "validation_metrics": val_metrics,
            "selected_at": threshold_result["selected_at"],
        },
        "provenance": {
            "model_id": model_id,
            "dataset_id": DATASET_HANDLE,
            "source_url": DATASET_PAGE_URL,
            "sha256": source_sha,
            "dataset_version": "1.0",
            "training_rows": int(len(y_train)),
            "validation_rows": int(len(y_val)),
            "label_column": "Attack Type",
            "positive_class": "ATTACK",
            "negative_class": "BENIGN",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "fit_duration_seconds": fit_duration,
            "split": split_metadata(frame, masks),
            "cleaning": {
                "policy_id": CLEANING_POLICY_ID,
                "policy_version": CLEANING_POLICY_VERSION,
                "ledger_sha256": ledger_sha,
                "record_sha256": record_sha,
                "exclusions": rec.get("exclusions", {}),
            },
        },
        "versions": {
            "xgboost": xgb.__version__,
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "python": platform.python_version(),
        },
    }

    # Validate bundle before saving
    validate_supervised_bundle(bundle)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path)
    bundle_sha = file_sha256(output_path)
    bundle_size_kb = output_path.stat().st_size / 1024

    print(f"\nBundle saved successfully:")
    print(f"  Path:     {output_path}")
    print(f"  Size:     {bundle_size_kb:.1f} KB")
    print(f"  SHA-256:  {bundle_sha}")
    print(f"  Model ID: {model_id}")

    return output_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=APPROVED_DATASET_PATH)
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_SUPERVISED_PATH)
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.002,
        help="Provisional max false positive rate constraint on validation data (default: 0.002 = 0.2%%)",
    )
    parser.add_argument("--objective", type=str, default="f1_score")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_and_package_supervised(
        dataset_path=args.data,
        record_path=args.record,
        output_path=args.output,
        max_fpr=args.max_fpr,
        objective=args.objective,
        random_state=args.seed,
    )


if __name__ == "__main__":
    main()
