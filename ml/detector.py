import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib


def minmax_normalize_scores(raw_scores):
    """Normalize a batch of Isolation Forest decision-function scores to [0, 100].

    The canonical Isolation Forest anomaly score for an instance x over n samples is

        s(x, n) = 2 ** ( -E(h(x)) / c(n) )

    where E(h(x)) is the expected path length of x across the iTrees and c(n) is the
    average path length of an unsuccessful BST search. s -> 1 means anomalous, s -> 0
    means normal. Ref: F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation Forest", ICDM 2008.

    scikit-learn exposes ``decision_function`` (higher = more normal), so we negate it
    to get an "anomaly-ness" ordering, then apply batch min-max normalization
    (x - min) / (max - min) so scores are comparable within a single analysis batch.
    """
    a = -np.asarray(raw_scores, dtype=float)  # higher => more anomalous
    lo = a.min()
    hi = a.max()
    if hi - lo < 1e-12:  # degenerate batch (all identical) -> no relative anomalies
        return np.zeros_like(a)
    return (a - lo) / (hi - lo) * 100.0


class AnomalyDetector:

    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.contamination = contamination

    def train(self, X_train):
        print("[+] Training Isolation Forest...")
        self.model.fit(X_train)
        print("[+] Training complete")

    def predict(self, X):
        predictions = self.model.predict(X)
        scores = self.model.decision_function(X)
        anomaly_count = (predictions == -1).sum()
        normal_count = (predictions == 1).sum()
        print(f"[+] Anomalies found: {anomaly_count}")
        print(f"[+] Normal records: {normal_count}")
        return predictions, scores

    def normalize_scores(self, raw_scores):
        """Batch min-max normalization of decision-function scores to [0, 100].

        Replaces the previous fixed sigmoid 1/(1+e^{10*d(x)}); min-max keeps the
        mapping relative to the actual score distribution of each analysis batch.
        See ``minmax_normalize_scores`` for the reference (Liu, Ting, Zhou 2008).
        """
        return minmax_normalize_scores(raw_scores)

    def save_model(self, path='models/isolation_forest.pkl'):
        joblib.dump(self.model, path)
        print(f"[+] Model saved to {path}")

    def load_model(self, path='models/isolation_forest.pkl'):
        self.model = joblib.load(path)
        print(f"[+] Model loaded from {path}")