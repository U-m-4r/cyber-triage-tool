"""Train and save the approved CICIDS2017 network-flow baseline.

This is an explicit offline training command. The live API never trains from an
investigator's uploaded evidence. The saved artifact bundles the fitted scaler,
feature schema, Isolation Forest, and provenance metadata so inference is stable.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.preprocessor import ForensicPreprocessor

DEFAULT_DATA = os.path.join(ROOT_DIR, "data", "cicids2017_cleaned.csv")
DEFAULT_MODEL = os.path.join(ROOT_DIR, "models", "cicids2017_baseline.joblib")
FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=DEFAULT_DATA, help="CICIDS2017 cleaned CSV path")
    parser.add_argument("--model-out", default=DEFAULT_MODEL, help="Output model bundle path")
    parser.add_argument("--rows", type=int, default=None, help="Optional row limit for smoke tests only")
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--estimators", type=int, default=100)
    args = parser.parse_args()

    if not os.path.isfile(args.data):
        parser.error(f"Dataset not found: {args.data}. Download the Kaggle CICIDS2017 cleaned CSV first.")
    if not 0.0 < args.contamination <= 0.5:
        parser.error("--contamination must be in (0, 0.5].")
    if args.estimators < 1:
        parser.error("--estimators must be positive.")

    print(f"[+] Loading CICIDS2017 dataset: {args.data}")
    # Load only the features required by the currently supported network detector.
    available = pd.read_csv(args.data, nrows=0).columns.str.strip().tolist()
    missing = [column for column in FEATURE_COLUMNS if column not in available]
    if missing:
        parser.error(f"Dataset is missing required CICIDS2017 features: {missing}")

    df = pd.read_csv(
        args.data,
        usecols=lambda column: column.strip() in FEATURE_COLUMNS,
        nrows=args.rows,
    )
    df.columns = df.columns.str.strip()
    preprocessor = ForensicPreprocessor()
    clean = preprocessor.clean_data(df)
    features = clean.loc[:, FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    features = features.replace([float("inf"), float("-inf")], pd.NA).dropna()
    if len(features) < 100:
        parser.error(f"Only {len(features)} valid rows remain; need at least 100 to train safely.")

    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)
    model = IsolationForest(
        n_estimators=args.estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    print(f"[+] Training Isolation Forest on {len(features):,} clean records...")
    model.fit(scaled)

    bundle = {
        "artifact_type": "cyber-triage-network-baseline",
        "artifact_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "training_mode": "unsupervised",
        "dataset": {
            "name": "CICIDS2017 cleaned and preprocessed",
            "source": "Kaggle: ericanacletoribeiro/cicids2017-cleaned-and-preprocessed",
            "path_at_training": os.path.relpath(os.path.abspath(args.data), ROOT_DIR).replace(os.sep, "/")
                if os.path.abspath(args.data).startswith(ROOT_DIR + os.sep) else os.path.basename(args.data),
            "sha256": sha256_file(args.data),
            "rows_used": int(len(features)),
            "rows_requested": args.rows,
        },
        "feature_columns": FEATURE_COLUMNS,
        "scaler": scaler,
        "model": model,
        "config": {
            "algorithm": "IsolationForest",
            "n_estimators": args.estimators,
            "contamination": args.contamination,
            "random_state": 42,
        },
    }

    output = os.path.abspath(args.model_out)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    temporary = output + ".tmp"
    joblib.dump(bundle, temporary)
    os.replace(temporary, output)
    print(f"[+] Saved baseline bundle: {output}")
    print(json.dumps({
        "dataset_sha256": bundle["dataset"]["sha256"],
        "rows_used": bundle["dataset"]["rows_used"],
        "features": len(FEATURE_COLUMNS),
        "model": bundle["config"],
    }, indent=2))


if __name__ == "__main__":
    main()
