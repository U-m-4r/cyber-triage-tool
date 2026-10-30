# Frozen network inference bundles v1

Two project-owned, historically trained CICIDS2017 bundles, verified unchanged
during Issue 3. This release stores deployment artifacts outside Git source
history. It contains no network-flow records, evidence images or credentials.

- `cicids2017_baseline.joblib`: IsolationForest and benign-training fitted scaler;
  ID `iforest-65dd0b57a2b1a2020a0b`, 760117 bytes, SHA-256
  `8602d9e6f57d347a10ebbca7290ad2bc75892f9c7f8b29dcc97c2fea20035c0d`.
- `supervised_binary.joblib`: XGBClassifier and all-training fitted scaler;
  ID `xgb-bin-12ad91fa39`, 1299382 bytes, SHA-256
  `ee4bc46fee3d1957bd080246c84bf6dedee246b25d29c1ecd6dfaf63d2100e3f`.

Use Python 3.14, scikit-learn 1.8.0, XGBoost 3.4.1 and the repository's pinned
dependencies. Follow `models/network-artifacts.json` and
`python -m scripts.acquire_network_models` to verify lengths and checksums before
loading. Joblib is executable serialization: accept only these reviewed assets,
never uploaded model files. The release tag identifies the artifact set; it does
not replace the Issue 3 source branch.

Dataset: Kaggle `ericanacletoribeiro/cicids2017-cleaned-and-preprocessed`, local
approved CSV SHA-256
`0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292`.
Training policy and fitted parameters are in each bundle and the Issue 3 report.
No models were retrained for Issue 3. Thresholds are 0 decision margin (baseline)
and 0.4343418846451664 uncalibrated attack score (supervised). These internal
held-out results do not establish external-network performance. Production
XGBoost's Web Attack recall is particularly weak (20/272 flows); read the report
before making performance claims.
