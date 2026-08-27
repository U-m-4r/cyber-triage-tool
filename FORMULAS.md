# FORMULAS.md

Single source of truth for every mathematical formula, scoring weight, threshold,
and statistical method used in this project. Each entry gives the formula, its
plain-English meaning, where it is used (`file:line`), and a citation.

**Rule:** every formula introduced or modified in code carries an inline comment
`# Formula: <name> | Ref: <citation> | see FORMULAS.md#<anchor>` pointing to the
matching section here. Standard methods reuse standard citations; project-tuned
constants are labelled as such and never presented as externally derived.

## References list

Citations reuse the project IEEE references where possible; sources found for this
work are listed with full detail inline.

- **[Liu2008]** F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation Forest," 2008 Eighth
  IEEE International Conference on Data Mining, pp. 413–422, 2008. doi:10.1109/ICDM.2008.17
- **[Fawcett2006]** T. Fawcett, "An introduction to ROC analysis," Pattern
  Recognition Letters, vol. 27, no. 8, pp. 861–874, 2006. doi:10.1016/j.patrec.2005.10.010
- **[sklearn-scaler]** scikit-learn, "StandardScaler,"
  https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html
- **[sklearn-iforest]** scikit-learn, "IsolationForest,"
  https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- **[Sokolova2009]** M. Sokolova, G. Lapalme, "A systematic analysis of performance
  measures for classification tasks," Information Processing & Management, vol. 45,
  no. 4, pp. 427–437, 2009. doi:10.1016/j.ipm.2009.03.002
- **[Manning2008]** C. D. Manning, P. Raghavan, H. Schütze, "Introduction to
  Information Retrieval," Cambridge University Press, 2008 — Ch. 8 (precision@k,
  recall@k for ranked retrieval).
- **[Ross2016]** A. Ross, K. Nandakumar, A. K. Jain, "Score-level fusion," in
  Handbook of Multibiometrics / "Score normalization and fusion," Pattern
  Recognition, weighted-sum fusion of normalized scores.
- **[NIST-SP800-86]** K. Kent, S. Chevalier, T. Grance, H. Dang, "Guide to
  Integrating Forensic Techniques into Incident Response," NIST SP 800-86, 2006.
- **[NIST-FIPS180-4]** NIST, "Secure Hash Standard (SHS)," FIPS PUB 180-4, 2015 —
  SHA-256 / SHA-1 definitions.
- **[MITRE-ATTACK]** MITRE ATT&CK, https://attack.mitre.org/ — technique taxonomy.
- **[Sharafaldin2018]** I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward
  Generating a New Intrusion Detection Dataset and Intrusion Traffic
  Characterization," Proc. 4th Int. Conf. on Information Systems Security and Privacy
  (ICISSP), pp. 108–116, 2018. doi:10.5220/0006639801080116 — CICIDS2017 dataset and
  the CICFlowMeter flow-feature definitions.

## Existing formulas (Requirements #4 and #5 — the validated core)

### <a name="isolation-forest"></a>1. Isolation Forest anomaly detection
- **Formula:** anomaly path-length scoring; `predict` returns `-1` (anomaly) / `+1`
  (normal); `decision_function` is higher = more normal.
- **Meaning:** anomalies are isolated in fewer random splits, so they sit closer to
  the root of random trees. `contamination=0.1` sets the expected anomaly fraction.
- **Used in:** `ml/detector.py:9` (model config), `ml/detector.py:22` (predict).
- **Citation:** [Liu2008]; parameters per [sklearn-iforest].

### <a name="anomaly-normalization"></a>2. Anomaly-score normalization (logistic squash)
- **Formula:** `score = 1 / (1 + exp(raw * 10)) * 100`
- **Meaning:** maps the unbounded IsolationForest raw score to a 0–100 scale where
  higher = more anomalous. The logistic (sigmoid) function is the standard bounded
  squashing transform; the `*10` gain is a **project-tuned constant** (steepness of
  the curve near the decision boundary), not an externally derived value — labelled
  as such here.
- **Used in:** `ml/detector.py:32`, `ml/risk_scorer.py:113`.
- **Citation:** logistic function (standard); gain constant is project-tuned.

### <a name="risk-fusion"></a>3. Risk-score fusion (weighted sum)
- **Formula:** `risk = anomaly_score * 0.6 + (rule_score * 100) * 0.4`, capped at 100.
- **Meaning:** weighted-sum score-level fusion of two normalized 0–100 signals — the
  ML anomaly score (60%) and the rule-engine score (40%). Weighted-sum fusion of
  normalized scores is a standard fusion method [Ross2016]; the specific **60/40
  split is a project-tuned operational weight** (validated empirically on
  CICIDS2017), not derived from the citation. Do not silently re-weight — see the
  IOC fusion note in section 10.
- **Used in:** `ml/risk_scorer.py:117`.
- **Citation:** [Ross2016] for the method; 60/40 weights project-tuned.

### <a name="priority-bands"></a>4. Priority bands
- **Formula:** CRITICAL ≥ 75 · HIGH ≥ 50 · MEDIUM ≥ 25 · LOW < 25 (on the 0–100 risk).
- **Meaning:** operational triage thresholds mapping a continuous score to four
  action bands. These are **project-defined operational thresholds** (quartile-style
  cut points), mirrored exactly by the frontend severity colours.
- **Used in:** `ml/risk_scorer.py:120`.
- **Citation:** operational thresholds (project-defined); no external formula claimed.

### <a name="standard-scaler"></a>5. Feature scaling (z-score standardization)
- **Formula:** `z = (x - mean) / std` per feature.
- **Meaning:** centres each feature to mean 0, unit variance so no single large-range
  feature dominates the distance-based isolation.
- **Used in:** `ml/preprocessor.py` (`scale_features`).
- **Citation:** [sklearn-scaler].

### <a name="classification-metrics"></a>6. Classification metrics (accuracy/precision/recall/F1)
- **Formula:** precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2·P·R/(P+R).
- **Meaning:** standard binary-classification quality measures, computed per class.
- **Used in:** `backend/app.py:148` (`_evaluate_predictions`).
- **Citation:** [Sokolova2009].

### <a name="roc-auc"></a>7. ROC AUC
- **Formula:** area under the TPR-vs-FPR curve over all thresholds, scored on
  `-decision_function` so higher = more anomalous.
- **Meaning:** threshold-independent separability of attack vs normal.
- **Used in:** `backend/app.py:186`.
- **Citation:** [Fawcett2006].

### <a name="top-k"></a>8. Triage precision@k / recall@k
- **Formula:** rank by anomaly score, take top k% ; precision@k = hits/k_count,
  recall@k = hits/total_attacks.
- **Meaning:** how much of the analyst's limited attention (top 10% / 25%) lands on
  real attacks — the metric that matters for triage.
- **Used in:** `backend/app.py:121` (`_compute_top_k_metrics`).
- **Citation:** [Manning2008] Ch. 8.

## Phase A formulas (Requirement #2 — ingestion parsers + rules-only interim scoring)

### <a name="flow-features"></a>9. Network-flow features (CICFlowMeter methodology)
- **Formula:** for each bidirectional flow keyed by the 5-tuple —
  - `Flow Duration = (last_ts − first_ts) × 1e6` (microseconds)
  - `Flow Bytes/s = total_bytes / duration_s`
  - `Flow Packets/s = total_packets / duration_s`
  - `Fwd/Bwd Packet Length {Max,Min,Mean}` = per-direction aggregates
  - `Packet Length Mean = total_bytes / total_packets`
- **Meaning:** reconstructs the same statistical flow features the CICIDS2017
  dataset was built from, so PCAP/flow-export artifacts score through the identical
  IsolationForest + rule pipeline the `/api/analyze` CSV path uses. Duration is
  expressed in microseconds to match the CICIDS2017 unit convention; a `1e-6`
  duration floor avoids divide-by-zero for single-packet flows (implementation
  guard, not a modelled quantity).
- **Used in:** `ml/ingestion/pcap_parser.py:81` (`_flows_from_packets`),
  `ml/ingestion/pcap_parser.py:56` (`_parse_csv` column aliasing).
- **Citation:** [Sharafaldin2018] — the CICFlowMeter feature definitions and the
  CICIDS2017 dataset; feature list matches [sklearn-iforest] input the existing
  model already consumes.

### <a name="rules-only-risk"></a>10. Rules-only interim risk (Phase A)
- **Formula:** `risk = min(rule_score × 100, 100)`, with `anomaly_score = None`.
- **Meaning:** ingested artifacts are scored by the rule engine alone until Phase B
  generalizes `ml/preprocessor.py` to emit per-artifact-type features for the
  IsolationForest model. This is the `anomaly_scores is None` branch of
  `score_records`; it is a **deliberate interim state**, not a new weighting — the
  validated 60/40 fusion (section 3) is applied unchanged the moment anomaly scores
  are supplied. No new constant is introduced: `×100` only rescales the rule score's
  0–1 output onto the shared 0–100 risk scale, and the cap mirrors section 3.
- **Used in:** `ml/risk_scorer.py:196` (`score_records`, interim branch);
  full-fusion branch at `ml/risk_scorer.py:192` reuses section 3.
- **Citation:** no new formula — rescale + cap of the existing rule score; fusion
  weights per [Ross2016] and section 3 when anomaly scores are present.

