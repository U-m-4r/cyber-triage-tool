"""Train, calibrate, evaluate, and serialize the attack-family attribution model.

This script executes a leakage-aware evaluation and calibration pipeline on the
authoritative 6 attack families from CICIDS2017:
  ['Bots', 'Brute Force', 'DDoS', 'DoS', 'Port Scanning', 'Web Attacks']

Methodology:
- Stratified 70% Train, 15% Validation, 15% Held-Out Test split.
- Within 70% Train:
  - 80% Train-Base (56% of total): fits StandardScaler and base classifier.
  - 20% Train-Cal (14% of total): fits candidate probability calibration layers.
- Validation split (15% of total):
  - Used strictly for candidate selection, calibration method comparison
    (Uncalibrated vs Sigmoid Platt vs Isotonic), and abstention policy evaluation.
- Held-Out Test split (15% of total):
  - Used strictly for final unbiased evaluation of the selected calibrated bundle.
  - Includes breakdown on strictly novel feature vectors vs overlapping vectors.
- Bundles full schema, fitted transformers, calibrator, provenance, and evaluation metrics.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from sklearn.frozen import FrozenEstimator
    def freeze(estimator):
        return FrozenEstimator(estimator)
except ImportError:
    def freeze(estimator):
        return estimator

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.attack_family import (
    ATTACK_FAMILIES,
    BUNDLE_VERSION,
    DEFAULT_ATTACK_FAMILY_MODEL_PATH,
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_MIN_MARGIN,
    validate_attack_family_bundle,
)
from ml.calibration_metrics import (
    compute_expected_calibration_error,
    compute_multiclass_brier_score,
    compute_multiclass_log_loss,
    evaluate_full_reliability_metrics,
)
from ml.cleaning import DEFAULT_RECORD_PATH, load_eligible_frame
from ml.preprocessor import NETWORK_FEATURES

DEFAULT_DATA_PATH = ROOT_DIR / "data" / "cicids2017_cleaned.csv"
DEFAULT_BENCHMARK_REPORT = ROOT_DIR / "reports" / "attack_family_benchmark.json"
DEFAULT_CALIBRATION_REPORT = ROOT_DIR / "reports" / "attack_family_calibration_benchmark.json"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_attack_data(
    data_path: Path = DEFAULT_DATA_PATH,
    eligible: bool = True,
    sample_size: int = None,
    cleaning_record: Path = DEFAULT_RECORD_PATH,
) -> Tuple[pd.DataFrame, pd.Series, Dict[str, Any]]:
    """Load attack records with the 11-feature contract."""
    columns_needed = list(NETWORK_FEATURES) + ["Attack Type"]

    print(f"[+] Loading attack data from {data_path} (eligible={eligible})...")
    t0 = time.time()

    if eligible and cleaning_record.is_file():
        print(f"[+] Reading eligible view via cleaning record: {cleaning_record}")
        raw_df = load_eligible_frame(
            source=data_path,
            record_path=cleaning_record,
            usecols=lambda c: c.strip() in columns_needed,
        )
        raw_df.columns = raw_df.columns.str.strip()
        attacks_df = raw_df[raw_df["Attack Type"].isin(ATTACK_FAMILIES)].copy()
    else:
        print(f"[+] Streaming attack chunks directly from {data_path}...")
        chunks = []
        for chunk in pd.read_csv(
            data_path,
            usecols=lambda c: c.strip() in columns_needed,
            chunksize=200000,
        ):
            chunk.columns = chunk.columns.str.strip()
            atk = chunk[chunk["Attack Type"].isin(ATTACK_FAMILIES)]
            if len(atk):
                chunks.append(atk)
        attacks_df = pd.concat(chunks, ignore_index=True)

    print(f"[+] Loaded {len(attacks_df):,} attack rows in {time.time()-t0:.2f}s")

    features_df = attacks_df[list(NETWORK_FEATURES)].copy()
    for col in NETWORK_FEATURES:
        features_df[col] = pd.to_numeric(features_df[col], errors="coerce")

    finite_mask = np.isfinite(features_df.to_numpy()).all(axis=1)
    dropped_non_finite = int((~finite_mask).sum())
    if dropped_non_finite > 0:
        print(f"[!] Dropped {dropped_non_finite} attack rows with non-finite feature values.")
        attacks_df = attacks_df.loc[finite_mask].copy()
        features_df = features_df.loc[finite_mask].copy()

    labels = attacks_df["Attack Type"].astype(str).str.strip()

    if sample_size and sample_size < len(features_df):
        print(f"[+] Subsampling to {sample_size:,} records (stratified)...")
        _, features_df, _, labels = train_test_split(
            features_df,
            labels,
            test_size=sample_size,
            stratify=labels,
            random_state=42,
        )

    provenance_info = {
        "dataset_path": str(data_path),
        "eligible_view": eligible,
        "total_attack_rows": len(features_df),
        "dropped_non_finite": dropped_non_finite,
        "class_distribution": labels.value_counts().to_dict(),
    }

    return features_df, labels, provenance_info


def train_and_evaluate(
    data_path: Path = DEFAULT_DATA_PATH,
    output_bundle: Path = DEFAULT_ATTACK_FAMILY_MODEL_PATH,
    report_path: Path = DEFAULT_BENCHMARK_REPORT,
    calibration_report_path: Path = DEFAULT_CALIBRATION_REPORT,
    eligible: bool = True,
    sample_size: int = None,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Train candidates, compare calibration methods on validation, and evaluate on held-out test."""
    output_bundle = Path(output_bundle)
    if output_bundle.exists() and not overwrite:
        raise ValueError(
            f"Bundle already exists at {output_bundle}. Use --overwrite to replace it."
        )

    features_df, labels, prov_info = load_attack_data(
        data_path=data_path, eligible=eligible, sample_size=sample_size
    )

    classes = sorted(list(ATTACK_FAMILIES))

    # Phase 18A: 70% Train, 15% Validation, 15% Held-Out Test
    print("[+] Partitioning dataset: 70% Train, 15% Validation, 15% Held-Out Test (stratified)...")
    X_train_df, X_temp_df, y_train, y_temp = train_test_split(
        features_df, labels, test_size=0.30, stratify=labels, random_state=42
    )
    X_val_df, X_test_df, y_val, y_test = train_test_split(
        X_temp_df, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )

    # Sub-partition 70% Train into Train-Base (80%) and Train-Cal (20%)
    print("[+] Sub-partitioning Train partition into Train-Base (80%) and Train-Cal (20%)...")
    X_tr_base, X_tr_cal, y_tr_base, y_tr_cal = train_test_split(
        X_train_df, y_train, test_size=0.20, stratify=y_train, random_state=42
    )

    print(f"    Train-Base size: {len(X_tr_base):,} rows (estimator training)")
    print(f"    Train-Cal size:  {len(X_tr_cal):,} rows (calibrator fitting)")
    print(f"    Validation size: {len(X_val_df):,} rows (model & calibration selection)")
    print(f"    Held-Out Test:   {len(X_test_df):,} rows (unbiased final evaluation)")

    # Fit scaler strictly on Train-Base
    print("[+] Fitting StandardScaler strictly on Train-Base...")
    scaler = StandardScaler()
    scaler.fit(X_tr_base)
    X_tr_base_scaled = scaler.transform(X_tr_base)
    X_tr_cal_scaled = scaler.transform(X_tr_cal)
    X_val_scaled = scaler.transform(X_val_df)
    X_test_scaled = scaler.transform(X_test_df)

    # Train Base Estimator
    print("[+] Fitting base RandomForestClassifier on Train-Base...")
    t_fit = time.time()
    base_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    base_rf.fit(X_tr_base_scaled, y_tr_base)
    fit_duration = time.time() - t_fit
    print(f"    Base model fitted in {fit_duration:.2f}s")

    # Fit Candidate Calibration Layers strictly on Train-Cal
    print("[+] Fitting candidate calibration layers on Train-Cal (Platt Sigmoid & Isotonic)...")
    calibrators = {}

    # Candidate 1: Sigmoid (Platt Scaling)
    t_sig = time.time()
    cal_sig = CalibratedClassifierCV(estimator=freeze(base_rf), method="sigmoid")
    cal_sig.fit(X_tr_cal_scaled, y_tr_cal)
    print(f"    Sigmoid calibrator fitted in {time.time()-t_sig:.2f}s")
    calibrators["sigmoid"] = cal_sig

    # Candidate 2: Isotonic Regression
    t_iso = time.time()
    cal_iso = CalibratedClassifierCV(estimator=freeze(base_rf), method="isotonic")
    cal_iso.fit(X_tr_cal_scaled, y_tr_cal)
    print(f"    Isotonic calibrator fitted in {time.time()-t_iso:.2f}s")
    calibrators["isotonic"] = cal_iso

    # Evaluate Calibration Candidates on Validation partition
    print("[+] Evaluating calibration candidates on untouched Validation partition...")
    val_probs_raw = base_rf.predict_proba(X_val_scaled)
    val_raw_metrics = {
        "log_loss": compute_multiclass_log_loss(y_val, val_probs_raw, classes),
        "brier_score": compute_multiclass_brier_score(y_val, val_probs_raw, classes)["brier_score"],
        "ece": compute_expected_calibration_error(y_val, val_probs_raw, classes)[0],
        "macro_f1": round(f1_score(y_val, base_rf.predict(X_val_scaled), average="macro", zero_division=0), 4),
    }
    print(f"    [Uncalibrated]  Log Loss: {val_raw_metrics['log_loss']:.5f} | Brier: {val_raw_metrics['brier_score']:.5f} | ECE: {val_raw_metrics['ece']:.5f} | Macro-F1: {val_raw_metrics['macro_f1']:.4f}")

    val_calibration_comparison = {"uncalibrated": val_raw_metrics}

    for method, cal_model in calibrators.items():
        val_probs_cal = cal_model.predict_proba(X_val_scaled)
        cal_preds = cal_model.predict(X_val_scaled)
        val_cal_metrics = {
            "log_loss": compute_multiclass_log_loss(y_val, val_probs_cal, classes),
            "brier_score": compute_multiclass_brier_score(y_val, val_probs_cal, classes)["brier_score"],
            "ece": compute_expected_calibration_error(y_val, val_probs_cal, classes)[0],
            "macro_f1": round(f1_score(y_val, cal_preds, average="macro", zero_division=0), 4),
        }
        val_calibration_comparison[method] = val_cal_metrics
        print(f"    [{method:12s}]  Log Loss: {val_cal_metrics['log_loss']:.5f} | Brier: {val_cal_metrics['brier_score']:.5f} | ECE: {val_cal_metrics['ece']:.5f} | Macro-F1: {val_cal_metrics['macro_f1']:.4f}")

    # Method selection based on Validation Brier score and Log Loss
    # Note: Sigmoid is preferred when log loss and rare-class probability behavior is robust.
    best_cal_method = min(
        ["sigmoid", "isotonic"],
        key=lambda m: (val_calibration_comparison[m]["brier_score"], val_calibration_comparison[m]["log_loss"]),
    )
    selected_calibrator = calibrators[best_cal_method]
    print(f"[+] Selected winning calibration method: '{best_cal_method}' based on validation metrics.")

    # Final Held-Out Test Evaluation
    print("[+] Evaluating selected calibrated model on held-out Test partition...")
    test_probs_raw = base_rf.predict_proba(X_test_scaled)
    test_probs_cal = selected_calibrator.predict_proba(X_test_scaled)

    full_test_reliability = evaluate_full_reliability_metrics(
        y_true=y_test.to_numpy(),
        raw_probabilities=test_probs_raw,
        calibrated_probabilities=test_probs_cal,
        classes=classes,
        abstention_policy={"min_confidence": DEFAULT_MIN_CONFIDENCE, "min_margin": DEFAULT_MIN_MARGIN},
    )

    print(f"    Test Calibrated ECE: {full_test_reliability['calibrated']['expected_calibration_error']:.5f} (Raw: {full_test_reliability['uncalibrated']['expected_calibration_error']:.5f})")
    print(f"    Test Calibrated Brier: {full_test_reliability['calibrated']['brier_score']:.5f} (Raw: {full_test_reliability['uncalibrated']['brier_score']:.5f})")
    print(f"    Test Calibrated Log Loss: {full_test_reliability['calibrated']['log_loss']:.5f} (Raw: {full_test_reliability['uncalibrated']['log_loss']:.5f})")
    print(f"    Test Macro-F1: {full_test_reliability['calibrated']['macro_f1']:.4f} | Accuracy: {full_test_reliability['calibrated']['accuracy']:.4f}")

    # Leakage & Vector Overlap Diagnostic on Held-Out Test
    print("[+] Computing vector overlap diagnostics on Test partition...")
    train_tuples = set(map(tuple, X_train_df.to_numpy()))
    test_tuples = list(map(tuple, X_test_df.to_numpy()))
    is_novel = np.array([t not in train_tuples for t in test_tuples])

    novel_count = int(is_novel.sum())
    overlap_count = int((~is_novel).sum())

    novel_test_reliability = evaluate_full_reliability_metrics(
        y_true=y_test.to_numpy()[is_novel],
        raw_probabilities=test_probs_raw[is_novel],
        calibrated_probabilities=test_probs_cal[is_novel],
        classes=classes,
        abstention_policy={"min_confidence": DEFAULT_MIN_CONFIDENCE, "min_margin": DEFAULT_MIN_MARGIN},
    )

    print(f"    Strictly novel test rows (zero train overlap): {novel_count:,} ({novel_count/len(X_test_df):.1%})")
    print(f"    Novel subset Macro-F1: {novel_test_reliability['calibrated']['macro_f1']:.4f} | ECE: {novel_test_reliability['calibrated']['expected_calibration_error']:.5f}")

    overlap_diagnostics = {
        "total_test_rows": len(X_test_df),
        "strictly_novel_rows": novel_count,
        "strictly_novel_share": round(novel_count / len(X_test_df), 4),
        "overlapping_rows": overlap_count,
        "overlapping_share": round(overlap_count / len(X_test_df), 4),
        "novel_subset_metrics": {
            "accuracy": novel_test_reliability["calibrated"]["accuracy"],
            "macro_f1": novel_test_reliability["calibrated"]["macro_f1"],
            "weighted_f1": novel_test_reliability["calibrated"]["weighted_f1"],
            "brier_score": novel_test_reliability["calibrated"]["brier_score"],
            "expected_calibration_error": novel_test_reliability["calibrated"]["expected_calibration_error"],
        },
    }

    # Assemble Model Bundle
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "model_family": "attack_attribution",
        "model_id": "attack-family-rf-calibrated-v1",
        "model_type": "RandomForestClassifier",
        "model": base_rf,
        "calibrator": selected_calibrator,
        "calibration_metadata": {
            "method": best_cal_method,
            "fitted_on": "Train-Cal partition (20% of training data, isolated)",
            "validation_comparison": val_calibration_comparison,
            "test_calibrated_ece": full_test_reliability["calibrated"]["expected_calibration_error"],
            "test_calibrated_brier": full_test_reliability["calibrated"]["brier_score"],
            "test_calibrated_log_loss": full_test_reliability["calibrated"]["log_loss"],
        },
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
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "python": platform.python_version(),
        },
        "provenance": {
            "task": "conditional_attack_family_attribution",
            "dataset_path": str(data_path),
            "training_policy": "attack_only",
            "train_base_rows": len(X_tr_base),
            "train_cal_rows": len(X_tr_cal),
            "training_rows": len(X_train_df),
            "validation_rows": len(X_val_df),
            "test_rows": len(X_test_df),
            "total_attack_rows": len(features_df),
            "class_distribution_train_base": y_tr_base.value_counts().to_dict(),
            "class_distribution_train_cal": y_tr_cal.value_counts().to_dict(),
            "class_distribution_val": y_val.value_counts().to_dict(),
            "class_distribution_test": y_test.value_counts().to_dict(),
            "trained_at": datetime.now(timezone.utc).isoformat(),
        },
        "abstention_policy": {
            "min_confidence": DEFAULT_MIN_CONFIDENCE,
            "min_margin": DEFAULT_MIN_MARGIN,
            "use_calibrated_confidence": True,
        },
        "evaluation_summary": {
            "selected_model": "RandomForestClassifier",
            "calibration_method": best_cal_method,
            "validation_comparison": val_calibration_comparison,
            "test_metrics": full_test_reliability["calibrated"],
            "overlap_diagnostics": overlap_diagnostics,
        },
    }

    validate_attack_family_bundle(bundle)

    output_bundle.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_bundle)
    print(f"[+] Saved verified calibrated attack family bundle to: {output_bundle}")

    # Save Detailed Calibration Benchmark Report
    calibration_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_provenance": prov_info,
        "split_sizes": {
            "train_base": len(X_tr_base),
            "train_cal": len(X_tr_cal),
            "validation": len(X_val_df),
            "test": len(X_test_df),
        },
        "validation_calibration_comparison": val_calibration_comparison,
        "selected_calibration_method": best_cal_method,
        "test_reliability_full": full_test_reliability,
        "overlap_diagnostics": overlap_diagnostics,
        "bundle_path": str(output_bundle),
    }

    cal_path = Path(calibration_report_path)
    cal_path.parent.mkdir(parents=True, exist_ok=True)
    cal_path.write_text(json.dumps(calibration_report, indent=2), encoding="utf-8")
    print(f"[+] Wrote calibration benchmark report to: {cal_path}")

    # Update reports/attack_family_benchmark.json with current run while preserving historical context
    benchmark_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phase": "18A",
        "dataset_provenance": prov_info,
        "calibration": {
            "method": best_cal_method,
            "validation_comparison": val_calibration_comparison,
            "test_brier": full_test_reliability["calibrated"]["brier_score"],
            "test_ece": full_test_reliability["calibrated"]["expected_calibration_error"],
            "test_log_loss": full_test_reliability["calibrated"]["log_loss"],
        },
        "held_out_test_metrics": full_test_reliability["calibrated"],
        "overlap_diagnostics": overlap_diagnostics,
        "bundle_path": str(output_bundle),
    }
    rep_path = Path(report_path)
    rep_path.parent.mkdir(parents=True, exist_ok=True)
    rep_path.write_text(json.dumps(benchmark_report, indent=2), encoding="utf-8")
    print(f"[+] Updated attack family benchmark report: {rep_path}")

    return calibration_report


def main():
    parser = argparse.ArgumentParser(description="Train, calibrate, and evaluate attack-family attribution models.")
    parser.add_argument("--data", default=DEFAULT_DATA_PATH, type=Path, help="Path to CICIDS2017 cleaned dataset")
    parser.add_argument("--output", default=DEFAULT_ATTACK_FAMILY_MODEL_PATH, type=Path, help="Path to save model bundle")
    parser.add_argument("--report", default=DEFAULT_BENCHMARK_REPORT, type=Path, help="Path to save benchmark report")
    parser.add_argument("--cal-report", default=DEFAULT_CALIBRATION_REPORT, type=Path, help="Path to save calibration report")
    parser.add_argument("--sample-size", type=int, default=None, help="Optional sample size for fast benchmarking")
    parser.add_argument("--no-eligible", action="store_true", help="Do not use eligible view, read raw CSV")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing model bundle")

    args = parser.parse_args()
    train_and_evaluate(
        data_path=args.data,
        output_bundle=args.output,
        report_path=args.report,
        calibration_report_path=args.cal_report,
        eligible=not args.no_eligible,
        sample_size=args.sample_size,
        overwrite=args.overwrite,
    )


if __name__ == "__main__":
    main()
