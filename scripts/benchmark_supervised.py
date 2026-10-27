"""Controlled benchmark of supervised models for CICIDS2017 intrusion detection.

Evaluates 5 candidates across two leakage-resistant tasks on identical approved
features and fixed data partitions:
1. LightGBM
2. XGBoost
3. Extra Trees
4. Random Forest
5. CatBoost

Also benchmarks the established unsupervised Isolation Forest baseline for reference.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.baseline import BASELINE_PATH, load_baseline, infer_network
from ml.cleaning import DEFAULT_RECORD_PATH, load_eligible_frame
from ml.holdout import split_masks
from ml.preprocessor import NETWORK_FEATURES

CLASS_NAMES = [
    "Normal Traffic",
    "DoS",
    "DDoS",
    "Port Scanning",
    "Brute Force",
    "Web Attacks",
    "Bots",
]
CLASS_TO_IDX = {name: idx for idx, name in enumerate(CLASS_NAMES)}
BENIGN_LABEL = "Normal Traffic"


def load_dataset_and_partitions(data_path=None, record_path=DEFAULT_RECORD_PATH):
    """Load the eligible view and derive strict feature-group holdouts."""
    print("Loading eligible frame from approved dataset...")
    cols = list(NETWORK_FEATURES) + ["Attack Type"]
    df = load_eligible_frame(source=data_path, record_path=record_path,
                             usecols=lambda c: c.strip() in cols)
    print(f"Total rows: {len(df):,}")

    masks = split_masks(df)
    train_mask = masks["train"]
    val_mask = masks["validation"]
    test_mask = masks["test"]

    print(f"Partitions: Train={train_mask.sum():,}, Val={val_mask.sum():,}, Test={test_mask.sum():,}")

    raw_labels = df["Attack Type"].astype(str).str.strip()
    y_multiclass = raw_labels.map(CLASS_TO_IDX).to_numpy(dtype=np.int64)
    y_binary = (raw_labels != BENIGN_LABEL).to_numpy(dtype=np.int64)

    X_raw = df[list(NETWORK_FEATURES)].to_numpy(dtype=np.float64)

    # Preprocessing: StandardScaler fitted ONLY on training partition
    scaler = StandardScaler()
    print("Fitting StandardScaler on training partition only...")
    X_train_scaled = scaler.fit_transform(X_raw[train_mask])
    X_val_scaled = scaler.transform(X_raw[val_mask])
    X_test_scaled = scaler.transform(X_raw[test_mask])

    return {
        "scaler": scaler,
        "feature_names": list(NETWORK_FEATURES),
        "X_train": X_train_scaled,
        "y_train_bin": y_binary[train_mask],
        "y_train_multi": y_multiclass[train_mask],
        "X_val": X_val_scaled,
        "y_val_bin": y_binary[val_mask],
        "y_val_multi": y_multiclass[val_mask],
        "X_test": X_test_scaled,
        "y_test_bin": y_binary[test_mask],
        "y_test_multi": y_multiclass[test_mask],
    }


def evaluate_binary(y_true, y_pred, y_prob):
    """Compute comprehensive binary intrusion detection metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        roc_auc = None

    try:
        pr_auc = float(average_precision_score(y_true, y_prob))
    except Exception:
        pr_auc = None

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "macro_f1": macro_f1,
        "fpr": fpr,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def evaluate_multiclass(y_true, y_pred, y_prob):
    """Compute comprehensive multiclass attack classification metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    prec, rec, f1_per, supp = precision_recall_fscore_support(
        y_true, y_pred, labels=list(range(len(CLASS_NAMES))), zero_division=0
    )

    per_class = {}
    for idx, name in enumerate(CLASS_NAMES):
        per_class[name] = {
            "precision": float(prec[idx]),
            "recall": float(rec[idx]),
            "f1": float(f1_per[idx]),
            "support": int(supp[idx]),
        }

    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(CLASS_NAMES))))
    cm_dict = {
        row_name: {col_name: int(cm[i, j]) for j, col_name in enumerate(CLASS_NAMES)}
        for i, row_name in enumerate(CLASS_NAMES)
    }

    try:
        # Multiclass OvR ROC-AUC
        roc_auc = float(roc_auc_score(y_true, y_prob, multi_class="ovr", average="macro"))
    except Exception:
        roc_auc = None

    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "roc_auc_ovr_macro": roc_auc,
        "per_class": per_class,
        "confusion_matrix": cm_dict,
    }


def get_model_size_kb(model):
    """Estimate model artifact size in KB using joblib dump in a temp buffer."""
    import io
    buf = io.BytesIO()
    joblib.dump(model, buf, compress=3)
    return round(len(buf.getvalue()) / 1024, 2)


def get_candidate_models(task="binary"):
    """Instantiate candidate models with documented, leakage-safe hyperparameters."""
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    import lightgbm as lgb
    import xgboost as xgb
    from catboost import CatBoostClassifier

    if task == "binary":
        return {
            "LightGBM": lgb.LGBMClassifier(
                n_estimators=200,
                learning_rate=0.08,
                max_depth=10,
                num_leaves=63,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
                verbose=-1,
            ),
            "XGBoost": xgb.XGBClassifier(
                n_estimators=200,
                learning_rate=0.08,
                max_depth=8,
                tree_method="hist",
                random_state=42,
                n_jobs=-1,
                eval_metric="logloss",
            ),
            "Extra Trees": ExtraTreesClassifier(
                n_estimators=100,
                max_depth=18,
                bootstrap=True,
                max_samples=0.25,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=18,
                bootstrap=True,
                max_samples=0.25,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
            "CatBoost": CatBoostClassifier(
                iterations=200,
                learning_rate=0.08,
                depth=7,
                auto_class_weights="Balanced",
                random_seed=42,
                thread_count=-1,
                verbose=False,
            ),
        }
    else:  # multiclass
        return {
            "LightGBM": lgb.LGBMClassifier(
                n_estimators=200,
                learning_rate=0.08,
                max_depth=10,
                num_leaves=63,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
                verbose=-1,
            ),
            "XGBoost": xgb.XGBClassifier(
                n_estimators=200,
                learning_rate=0.08,
                max_depth=8,
                tree_method="hist",
                random_state=42,
                n_jobs=-1,
                eval_metric="mlogloss",
            ),
            "Extra Trees": ExtraTreesClassifier(
                n_estimators=100,
                max_depth=18,
                bootstrap=True,
                max_samples=0.25,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=18,
                bootstrap=True,
                max_samples=0.25,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
            "CatBoost": CatBoostClassifier(
                iterations=200,
                learning_rate=0.08,
                depth=7,
                auto_class_weights="Balanced",
                random_seed=42,
                thread_count=-1,
                verbose=False,
            ),
        }


def benchmark_binary_task(data, models_dir):
    """Run controlled benchmark for Task 1: Binary Intrusion Detection."""
    print("\n" + "=" * 70)
    print("TASK 1: BINARY INTRUSION DETECTION (BENIGN vs ATTACK)")
    print("=" * 70)

    X_train, y_train = data["X_train"], data["y_train_bin"]
    X_val, y_val = data["X_val"], data["y_val_bin"]
    X_test, y_test = data["X_test"], data["y_test_bin"]

    candidates = get_candidate_models("binary")
    results = {}

    for name, model in candidates.items():
        print(f"\n--- Training {name} ---")
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        fit_time = time.perf_counter() - t0
        print(f"Fit completed in {fit_time:.2f}s")

        # Evaluate on Validation
        val_pred = model.predict(X_val)
        val_prob = model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else val_pred
        val_metrics = evaluate_binary(y_val, val_pred, val_prob)

        # Evaluate on Test (once, strictly held out)
        t_infer = time.perf_counter()
        test_pred = model.predict(X_test)
        infer_time = time.perf_counter() - t_infer
        throughput = len(X_test) / infer_time if infer_time > 0 else 0.0

        test_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else test_pred
        test_metrics = evaluate_binary(y_test, test_pred, test_prob)

        model_size_kb = get_model_size_kb(model)

        # Save artifact in experiments dir
        art_path = models_dir / f"binary_{name.lower().replace(' ', '_')}.joblib"
        joblib.dump(model, art_path)

        results[name] = {
            "fit_time_sec": round(fit_time, 2),
            "infer_time_sec": round(infer_time, 3),
            "throughput_samples_per_sec": round(throughput, 1),
            "model_size_kb": model_size_kb,
            "artifact_path": str(art_path),
            "validation": val_metrics,
            "test": test_metrics,
        }

        print(f"Test Accuracy: {test_metrics['accuracy']:.4f} | Recall: {test_metrics['recall']:.4f} | "
              f"Precision: {test_metrics['precision']:.4f} | Macro-F1: {test_metrics['macro_f1']:.4f} | "
              f"FPR: {test_metrics['fpr']:.4%}")

    # Also evaluate baseline Isolation Forest for reference
    print("\n--- Evaluating Baseline Isolation Forest (Unsupervised) ---")
    if BASELINE_PATH.is_file():
        bundle = load_baseline(BASELINE_PATH)
        df_val = pd.DataFrame(data["X_val"], columns=NETWORK_FEATURES)
        df_test = pd.DataFrame(data["X_test"], columns=NETWORK_FEATURES)

        _, iforest_pred_test, iforest_scores_test, _, _ = infer_network(df_test, bundle)
        # Convert -1 (anomaly/attack) / 1 (normal) to 1 / 0
        bin_iforest_pred = (iforest_pred_test == -1).astype(int)
        norm_scores = -iforest_scores_test  # higher = more anomalous

        iforest_metrics = evaluate_binary(y_test, bin_iforest_pred, norm_scores)
        results["Isolation Forest (Baseline)"] = {
            "fit_time_sec": None,
            "infer_time_sec": None,
            "throughput_samples_per_sec": None,
            "model_size_kb": round(BASELINE_PATH.stat().st_size / 1024, 2),
            "artifact_path": str(BASELINE_PATH),
            "validation": None,
            "test": iforest_metrics,
            "note": "Unsupervised anomaly detection baseline trained on benign flows only",
        }
        print(f"IForest Test Accuracy: {iforest_metrics['accuracy']:.4f} | Recall: {iforest_metrics['recall']:.4f} | "
              f"Precision: {iforest_metrics['precision']:.4f} | Macro-F1: {iforest_metrics['macro_f1']:.4f} | "
              f"FPR: {iforest_metrics['fpr']:.4%}")

    return results


def benchmark_multiclass_task(data, models_dir):
    """Run controlled benchmark for Task 2: Multiclass Attack Classification."""
    print("\n" + "=" * 70)
    print("TASK 2: MULTICLASS ATTACK CLASSIFICATION (7 CLASSES)")
    print("=" * 70)

    X_train, y_train = data["X_train"], data["y_train_multi"]
    X_val, y_val = data["X_val"], data["y_val_multi"]
    X_test, y_test = data["X_test"], data["y_test_multi"]

    candidates = get_candidate_models("multiclass")
    results = {}

    for name, model in candidates.items():
        print(f"\n--- Training {name} (Multiclass) ---")
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        fit_time = time.perf_counter() - t0
        print(f"Fit completed in {fit_time:.2f}s")

        # Evaluate on Validation
        val_pred = model.predict(X_val)
        val_prob = model.predict_proba(X_val) if hasattr(model, "predict_proba") else None
        val_metrics = evaluate_multiclass(y_val, val_pred, val_prob)

        # Evaluate on Test
        t_infer = time.perf_counter()
        test_pred = model.predict(X_test)
        infer_time = time.perf_counter() - t_infer
        throughput = len(X_test) / infer_time if infer_time > 0 else 0.0

        test_prob = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
        test_metrics = evaluate_multiclass(y_test, test_pred, test_prob)

        model_size_kb = get_model_size_kb(model)

        art_path = models_dir / f"multiclass_{name.lower().replace(' ', '_')}.joblib"
        joblib.dump(model, art_path)

        results[name] = {
            "fit_time_sec": round(fit_time, 2),
            "infer_time_sec": round(infer_time, 3),
            "throughput_samples_per_sec": round(throughput, 1),
            "model_size_kb": model_size_kb,
            "artifact_path": str(art_path),
            "validation": val_metrics,
            "test": test_metrics,
        }

        print(f"Test Accuracy: {test_metrics['accuracy']:.4f} | Macro-F1: {test_metrics['macro_f1']:.4f} | "
              f"Weighted-F1: {test_metrics['weighted_f1']:.4f}")

    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=None,
                        help="Path to reviewed CICIDS2017 dataset CSV")
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD_PATH,
                        help="Path to cleaning record JSON")
    parser.add_argument("--output-dir", type=Path, default=ROOT_DIR / "evaluation" / "benchmark",
                        help="Directory to save benchmark metrics and summaries")
    parser.add_argument("--models-dir", type=Path, default=ROOT_DIR / "models" / "experiments",
                        help="Directory to store experimental model artifacts")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.models_dir.mkdir(parents=True, exist_ok=True)

    data = load_dataset_and_partitions(args.data, args.record)

    binary_results = benchmark_binary_task(data, args.models_dir)
    multiclass_results = benchmark_multiclass_task(data, args.models_dir)

    full_report = {
        "benchmark_metadata": {
            "date": pd.Timestamp.now(tz="UTC").isoformat(),
            "python_version": platform.python_version(),
            "system": f"{platform.system()} {platform.release()}",
            "train_rows": int(len(data["X_train"])),
            "val_rows": int(len(data["X_val"])),
            "test_rows": int(len(data["X_test"])),
            "features": list(NETWORK_FEATURES),
            "classes": CLASS_NAMES,
        },
        "binary_task": binary_results,
        "multiclass_task": multiclass_results,
    }

    report_path = args.output_dir / "benchmark_results.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"\n[OK] Benchmark results saved to {report_path}")


if __name__ == "__main__":
    main()
