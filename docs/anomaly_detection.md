# Network anomaly detection

Production network detection uses a reviewed CICIDS2017 baseline bundle at
`models/cicids2017_baseline.joblib`. See [baseline setup](baseline.md) for the
training command, provenance, trust boundary, and drift policy.

The offline trainer fits `StandardScaler` and an `IsolationForest` with 100 trees,
contamination 0.1, seed 42, and all CPU cores. It trains on valid, distinct benign
rows in the approved dataset. Attack labels and other metadata are never model
features. Contamination controls the training outlier threshold; it is not an
observed attack rate or an accuracy metric. No Phase 1 production metrics are
available until the real dataset has been supplied and training has succeeded.

The model returns 1 for normal and -1 for anomalous records, plus decision scores
(lower means more anomalous). Existing network risk scoring retains batch min-max
normalization to 0-100 and the 60/40 ML/rule fusion. These are relative triage
scores, not calibrated probabilities: a singleton or identical-score batch has
zero relative anomaly score, and scores are not comparable between batches.
Predictions and fixed-baseline drift comparisons do not use that normalization.

All network API paths load the complete bundle and transform with its fitted
scaler. They never train, save, or update the model. A missing or invalid bundle
returns a clear 503; a bare legacy `isolation_forest.pkl` is insufficient because
it has no fitted scaler, feature contract, or provenance.

Windows logs, registry artifacts, files, disk-image inventories, YARA hits, and
threat-intel findings keep their existing source-specific forensic paths. They
are not inputs to the CICIDS2017 model. Dedicated host anomaly models and broader
parser improvements remain future work.

Reference: Liu, Ting & Zhou, "Isolation Forest", ICDM 2008.
