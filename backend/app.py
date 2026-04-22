import os
import sys
import uuid
import logging

import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    precision_recall_fscore_support,
)
from werkzeug.utils import secure_filename

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.detector import AnomalyDetector
from ml.preprocessor import ForensicPreprocessor
from ml.risk_scorer import RiskScorer

app = Flask(__name__)
CORS(app)
TEMP_DIR = os.path.join(ROOT_DIR, "temp")
os.makedirs(TEMP_DIR, exist_ok=True)
MODEL_PATH = os.path.join(ROOT_DIR, "models", "isolation_forest.pkl")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

preprocessor = ForensicPreprocessor()
detector = AnomalyDetector(contamination=0.1)
scorer = RiskScorer()
DETECTOR_READY = False

LABEL_COLUMN_CANDIDATES = ["Label", "label", "Class", "class", "Target", "target"]


def _save_uploaded_file():
    if "file" not in request.files:
        return None, (jsonify({"error": "No file uploaded"}), 400)

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return None, (jsonify({"error": "Uploaded filename is empty"}), 400)

    # Sanitize incoming filename before writing to disk.
    safe_name = secure_filename(uploaded_file.filename)
    ext = os.path.splitext(uploaded_file.filename)[1].lower() or ".csv"
    if safe_name:
        filename = f"{uuid.uuid4().hex}_{safe_name}"
    else:
        filename = f"{uuid.uuid4().hex}{ext}"

    filepath = os.path.join(TEMP_DIR, filename)
    uploaded_file.save(filepath)
    return filepath, None


def _api_error(message, status_code, code):
    return jsonify({"error": {"code": code, "message": message}}), status_code


def _extract_binary_ground_truth(df):
    override = request.args.get("label_column")
    if override and override in df.columns:
        label_col = override
    else:
        label_col = next((c for c in LABEL_COLUMN_CANDIDATES if c in df.columns), None)

    if override and override not in df.columns:
        return None, None

    if not label_col:
        return None, None

    labels = df[label_col].astype(str).str.strip().str.lower()
    # CICIDS2017-style labels: benign/normal/0 -> normal, everything else -> attack.
    y_true = np.where(labels.isin(["benign", "normal", "0"]), 0, 1)
    return y_true, label_col


def _compute_top_k_metrics(y_true, decision_scores, ks=(10, 25)):
    if len(y_true) == 0:
        return {}

    # Higher anomaly_score (-decision_function) means more anomalous.
    anomaly_scores = -decision_scores
    ranked_idx = np.argsort(-anomaly_scores)
    total_attacks = int((y_true == 1).sum())
    metrics = {}

    for k in ks:
        k_count = max(1, int(len(y_true) * (k / 100.0)))
        top_idx = ranked_idx[:k_count]
        top_hits = int((y_true[top_idx] == 1).sum())
        precision_at_k = top_hits / k_count if k_count else 0.0
        recall_at_k = top_hits / total_attacks if total_attacks else 0.0

        metrics[f"top_{k}_percent"] = {
            "records_considered": int(k_count),
            "attack_hits": int(top_hits),
            "precision": round(float(precision_at_k), 4),
            "recall": round(float(recall_at_k), 4),
        }

    return metrics


def _evaluate_predictions(y_true, predictions, decision_scores):
    # IsolationForest returns -1 for anomaly and 1 for normal.
    y_pred = np.where(predictions == -1, 1, 0)
    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }

    # Per-class performance helps explain false positives/false negatives in viva.
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=[0, 1], zero_division=0)
    metrics["class_metrics"] = {
        "normal_0": {
            "precision": round(float(p[0]), 4),
            "recall": round(float(r[0]), 4),
            "f1_score": round(float(f[0]), 4),
            "support": int(s[0]),
        },
        "attack_1": {
            "precision": round(float(p[1]), 4),
            "recall": round(float(r[1]), 4),
            "f1_score": round(float(f[1]), 4),
            "support": int(s[1]),
        },
    }

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics["confusion_matrix"] = {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }

    if len(np.unique(y_true)) > 1:
        # IsolationForest decision_function: higher = more normal.
        # Negate so higher means more likely attack/anomaly.
        auc_score = roc_auc_score(y_true, -decision_scores)
        metrics["roc_auc"] = round(float(auc_score), 4)
    else:
        metrics["roc_auc"] = None

    metrics["triage_top_k"] = _compute_top_k_metrics(y_true, decision_scores, ks=(10, 25))
    return metrics


def _ensure_detector_loaded_or_trained(df_scaled):
    global DETECTOR_READY

    if DETECTOR_READY:
        return

    if os.path.exists(MODEL_PATH):
        detector.load_model(MODEL_PATH)
        DETECTOR_READY = True
        return

    detector.train(df_scaled)
    detector.save_model(MODEL_PATH)
    DETECTOR_READY = True

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "cyber-triage-backend"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Main analysis endpoint."""
    filepath, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    try:
        # run_pipeline returns (scaled, raw, clean)
        df_scaled, df_raw, df_clean = preprocessor.run_pipeline(filepath)

        _ensure_detector_loaded_or_trained(df_scaled)
        predictions, scores = detector.predict(df_scaled)
        results_df = scorer.score_dataframe(df_clean, scores)

        top_results = results_df.head(100).to_dict(orient="records")
        summary = {
            "total_records": int(len(results_df)),
            "critical": int((results_df["priority"] == "CRITICAL").sum()),
            "high": int((results_df["priority"] == "HIGH").sum()),
            "medium": int((results_df["priority"] == "MEDIUM").sum()),
            "low": int((results_df["priority"] == "LOW").sum()),
        }

        response_payload = {"summary": summary, "artifacts": top_results}
        # Add metrics when a supported label column is available.
        y_true, label_column = _extract_binary_ground_truth(df_clean)
        if y_true is not None:
            response_payload["evaluation"] = {
                "label_column": label_column,
                "metrics": _evaluate_predictions(y_true, predictions, scores),
            }

        return jsonify(response_payload)
    except Exception:
        logger.exception("Analysis request failed")
        return _api_error("Analysis failed. Please check input data and try again.", 500, "ANALYSIS_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/api/report", methods=["POST"])
def generate_report():
    """Generate PDF report."""
    return jsonify({"message": "Report generation will be added in a later phase."}), 501


@app.route("/api/evaluate", methods=["POST"])
def evaluate_model():
    """
    Evaluate anomaly model using uploaded labeled dataset.
    Returns classic classification metrics for project reporting.
    """
    filepath, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    try:
        df_scaled, _, df_clean = preprocessor.run_pipeline(filepath)
        y_true, label_column = _extract_binary_ground_truth(df_clean)
        if y_true is None:
            return _api_error(
                "No supported label column found.",
                400,
                "MISSING_LABEL_COLUMN",
            )

        indices = np.arange(len(df_scaled))
        stratify = y_true if len(np.unique(y_true)) > 1 else None
        train_idx, test_idx = train_test_split(
            indices,
            test_size=0.3,
            random_state=42,
            stratify=stratify,
        )

        X_train = df_scaled.iloc[train_idx]
        X_test = df_scaled.iloc[test_idx]
        y_test = y_true[test_idx]

        detector.train(X_train)
        predictions, scores = detector.predict(X_test)
        metrics = _evaluate_predictions(y_test, predictions, scores)

        return jsonify(
            {
                "status": "ok",
                "label_column": label_column,
                "records": {
                    "total": int(len(df_clean)),
                    "train": int(len(train_idx)),
                    "test": int(len(test_idx)),
                },
                "metrics": metrics,
            }
        )
    except Exception:
        logger.exception("Evaluation request failed")
        return _api_error("Evaluation failed. Please verify your labeled dataset.", 500, "EVALUATION_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
