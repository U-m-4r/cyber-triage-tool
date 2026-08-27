import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

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
    
    def get_anomaly_score_normalized(self, raw_score):
        # Formula: Anomaly-score normalization (logistic squash) | Ref: logistic function, gain project-tuned | see FORMULAS.md#anomaly-normalization
        normalized = 1 / (1 + np.exp(raw_score * 10))
        return round(normalized * 100, 2)
    
    def save_model(self, path='models/isolation_forest.pkl'):
        joblib.dump(self.model, path)
        print(f"[+] Model saved to {path}")
    
    def load_model(self, path='models/isolation_forest.pkl'):
        self.model = joblib.load(path)
        print(f"[+] Model loaded from {path}")