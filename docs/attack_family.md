# Phase 17: Attack-Family Attribution & Triage Signal Engine

## 1. Architectural Role & Philosophy

The Cyber Triage Tool operates as an **investigator-in-the-loop triage platform**. Its design philosophy is rooted in forensic rigor:
1. **Model predictions are hypotheses, not proof of compromise.** The human forensic investigator retains ultimate authority.
2. **Conditional Attribution:** Binary detection determines whether traffic resembles an attack. If and only if traffic is flagged as an attack or explicitly queued for threat investigation, the attack-family attribution classifier estimates its likely attack profile.
3. **No Overrides:** Family attribution cannot override or reverse a primary detector's determination. If traffic is classified as `BENIGN`, attribution is marked `NOT_APPLICABLE` and never presented as a confirmed threat family.
4. **Honest Uncertainty & Abstention:** When model confidence is low or when multiple candidate families produce ambiguous margins, the system explicitly abstains (`status: "ABSTAINED"`), rather than inventing a confident label.
5. **Independent Signals:** Supervised attribution, unsupervised Isolation Forest anomaly scoring, and deterministic domain forensic rules operate independently. Model scores are never combined into arbitrary pseudo-probabilities.

---

## 2. Attack-Family Classification

### The 6 Attack Families
The attribution engine classifies traffic across the six authoritative attack families present in CICIDS2017 (excluding benign/normal traffic):
- `Bots`
- `Brute Force`
- `DDoS`
- `DoS`
- `Port Scanning`
- `Web Attacks`

### The 11-Feature Contract
The classifier strictly operates on the versioned 11-feature production schema:
1. `Flow Duration` (microseconds)
2. `Total Fwd Packets`
3. `Total Length of Fwd Packets`
4. `Fwd Packet Length Max`
5. `Fwd Packet Length Min`
6. `Fwd Packet Length Mean`
7. `Bwd Packet Length Max`
8. `Bwd Packet Length Min`
9. `Flow Bytes/s`
10. `Flow Packets/s`
11. `Packet Length Mean`

---

## 3. Leakage-Aware Training & Benchmark Evidence

### Methodology
- **Source:** The verified eligible view of `data/cicids2017_cleaned.csv` (excluding exporter defect negative measurements and duplicate vector label conflicts documented in `data/provenance/cicids2017_cleaning.json`).
- **Eligible Attack Population:** 363,117 attack rows.
- **Data Splitting:** Stratified 70% Train (254,181 rows), 15% Validation (54,468 rows), 15% Test (54,468 rows) with seed 42.
- **Preprocessing Isolation:** `StandardScaler` is fitted strictly on the Train partition; Validation and Test partitions are transform-only.
- **Candidate Evaluation:** Conducted exclusively on the Validation partition.

### Validation Candidate Results

| Candidate Model | Val Macro-F1 | Val Weighted-F1 | Web Attacks Recall | Bots Recall | Fit Time (s) |
|---|---|---|---|---|---|
| **RandomForestClassifier (selected)** | **0.9972** | **0.9994** | **99.33%** | **99.44%** | **8.21s** |
| `HistGradientBoostingClassifier` | 0.9970 | 0.9992 | 99.33% | 99.44% | 7.15s |

### Winning Candidate Held-Out Test Evaluation

The selected `RandomForestClassifier` bundle was evaluated on the completely untouched, held-out Test partition (54,468 rows):

- **Overall Test Accuracy:** `99.97%`
- **Macro-Averaged F1:** `99.95%`
- **Weighted F1:** `99.97%`

#### Per-Family Test Performance & Support

| Attack Family | Precision | Recall | F1-Score | Test Support |
|---|---|---|---|---|
| **Bots** | 1.0000 | 1.0000 | 1.0000 | 180 |
| **Brute Force** | 1.0000 | 0.9993 | 0.9996 | 1,338 |
| **DDoS** | 0.9999 | 0.9998 | 0.9999 | 19,194 |
| **DoS** | 0.9998 | 0.9998 | 0.9998 | 28,743 |
| **Port Scanning** | 0.9989 | 0.9996 | 0.9993 | 4,715 |
| **Web Attacks** | 1.0000 | 0.9966 | 0.9983 | 298 |

#### Key Architectural Discovery
In legacy multiclass setups where benign traffic (~2.1M rows) is included directly in the multiclass objective, minority attack classes (Web Attacks at ~2k rows and Bots at ~1.9k rows) are severely overwhelmed, yielding abysmal recalls (e.g. 7.72% for Web Attacks). Under the **conditional triage architecture**, decoupling binary attack detection from attack-family attribution eliminates this class imbalance penalty, enabling the attribution model to achieve 99.66% recall on Web Attacks and 100% recall on Bots.

---


---

## 4. Phase 18A: Confidence Calibration & Reliability Benchmarking

### Architectural Rationale
Raw tree ensemble outputs (`predict_proba`) represent empirical tree voting fractions, not calibrated posterior probabilities. In high-stakes cyber triage, raw voting margins can be overconfident or poorly calibrated near decision boundaries. Phase 18A introduces safe probability calibration to ensure that confidence estimates $\hat{p} \in [0, 1]$ reliably reflect the true empirical likelihood of correct family attribution without corrupting the underlying classification accuracy or violating data partitions.

### Split Protocol & Leakage Safeguards
To prevent calibration leakage and data contamination:
1. **Outer Partitions:** The eligible dataset (363,117 attack flows) is partitioned into 70% Train (254,181 rows), 15% Validation (54,468 rows), and 15% Test (54,468 rows) with seed 42.
2. **Internal Calibration Split:** The 70% Train partition is split internally into **Train-Base (80%, 203,344 rows)** and **Train-Cal (20%, 50,837 rows)** using stratified sampling.
3. **Training Order:**
   - The base `RandomForestClassifier` is fitted exclusively on `Train-Base`.
   - Candidate calibrators (Platt Sigmoid and Isotonic Regression) are fitted on `Train-Cal` using predictions generated by the prefit base estimator via `FrozenEstimator`.
4. **Validation Selection:** Calibration candidate selection is performed exclusively on the 15% Validation partition. The held-out Test partition is never touched during calibration fitting or model selection.
5. **Final Evaluation:** The selected calibrated bundle is evaluated on the untouched 15% held-out Test partition.

### Candidate Calibration Benchmark (Validation Partition)

Evaluated on 54,468 validation rows:

| Calibration Method | Val Log Loss | Val Brier Score | Val ECE (10 bins) | Val Macro-F1 | Selection Decision |
|---|---|---|---|---|---|
| **Uncalibrated (Raw)** | 0.00317 | 0.00082 | 0.00030 | 0.9978 | Baseline |
| **Platt Sigmoid** | 0.00328 | 0.00085 | **0.00011** | 0.9978 | Rejected (higher Brier) |
| **Isotonic Regression** | 0.00563 | **0.00079** | 0.00025 | 0.9974 | **Selected (Lowest Brier)** |

**Decision Rationale:** Isotonic regression achieved the lowest multi-class Brier score (0.00079) while preserving classification fidelity across all six attack families.

### Final Held-Out Test Calibration Results

Evaluated on the 54,468 held-out test rows:

- **Test Calibrated Brier Score:** `0.00044` (down from raw `0.00053`)
- **Test Calibrated Expected Calibration Error (ECE):** `0.00009` (a **5x error reduction** from raw `0.00045`)
- **Test Calibrated Log Loss:** `0.00225`
- **Test Accuracy:** `99.98%`
- **Test Macro-F1:** `0.9995` | **Weighted-F1:** `0.9998`

#### Reliability Bin Distribution (10 Equal-Width Bins)
- Over 99.8% of test samples fall into Bin [0.9, 1.0] with mean confidence of `0.9999` and empirical accuracy of `0.9999` (absolute calibration gap $< 0.0001$).
- Low-confidence bins ([0.5, 0.6) and below) represent $< 0.1\%$ of test traffic, where the triage abstention policy triggers.

---

## 5. Duplicate Vector & Leakage Investigation

### Background & Objective
Phase 17 reported exceptionally high held-out performance (~0.9995 Macro-F1). To ensure this was not an artifact of data leakage, repeated network flows, or memorization of duplicate feature vectors across partitions, an empirical partition overlap audit was conducted across all 363,117 attack flows in `data/cicids2017_cleaned.csv`.

### Empirical Overlap Findings
- **Total Unique 11-Feature Attack Vectors:** 324,661 (89.4% uniqueness across dataset).
- **Test Partition Feature Vectors:** 48,938 unique vectors across 54,468 test rows.
- **Cross-Partition Overlap:** 1,341 unique feature vectors in Test also appear in Train (2.7% of unique Test vectors).
- **Affected Test Rows:** 6,161 test rows (11.3% of test rows) share an identical 11-feature vector with at least one Train row.
- **Distribution of Overlap by Family:**
  - `Port Scanning`: 96.9% of test rows share an identical vector with Train. Port scans generated by automated scanners (e.g. Nmap) emit identical single-packet probes with fixed duration (0 µs), packet count (1), and length (0 bytes), yielding millions of identical feature vectors in the capture.
  - `DDoS` / `DoS`: 0.05% - 5.1% row overlap.
  - `Bots`: 0.0% row overlap.
  - `Web Attacks`: 0.0% row overlap.

### Rigorous Generalization Proof: Novel-Vector Test Evaluation
To confirm whether the model truly generalizes to unseen network traffic or relies on memorization, the model was evaluated exclusively on the **48,307 test flows that have ZERO feature overlap with the training set**:

| Metric | All Test Rows (54,468) | Strictly Novel Test Rows (48,307) |
|---|---|---|
| **Overall Accuracy** | 99.98% | **99.97%** |
| **Macro-F1** | 0.9995 | **0.9956** |
| **Weighted-F1** | 0.9998 | **0.9997** |
| **Web Attacks Recall** | 99.66% | **99.66%** |
| **Bots Recall** | 100.00% | **100.00%** |
| **Calibrated ECE** | 0.00009 | **0.00009** |

**Conclusion:** The high reported performance is **confirmed genuine generalization**. While Port Scanning contains synthetic packet repetition inherent to the underlying dataset, the model generalizes with $>99.5\%$ Macro-F1 on completely novel flow vectors across all attack families.

---

## 6. Uncertainty, Calibration & Abstention Policy

### Dual Score Architecture
The model service produces distinct, non-conflated confidence scores:
1. `raw_confidence` and `raw_margin`: Empirical tree vote proportions and top margin.
2. `calibrated_confidence` and `calibrated_margin`: Isotonic calibrated probabilities and top margin.
3. `confidence`: Exposed calibrated probability (or raw if uncalibrated).
4. `calibrated`: Boolean flag indicating whether calibration was applied.
5. `ranked_candidates`: List of candidate families containing both `score` (calibrated) and `raw_score`.

### Abstention Policy
- `min_confidence` (default: `0.50`): Abstains if top probability $< 0.50$ (`status: "ABSTAINED"`, `reason: "LOW_CONFIDENCE"`).
- `min_margin` (default: `0.05`): Abstains if difference between 1st and 2nd candidate $< 0.05$ (`status: "ABSTAINED"`, `reason: "AMBIGUOUS_MARGIN"`).
- On abstention, `predicted_family = null`, while all candidate scores are retained for human review.
- Fallback Safety: If the calibrator fails or is absent, the engine falls back safely to raw scores with `calibrated: false` and logs a warning. Calibration failure never causes a false benign verdict.

---

## 7. Mathematical Metric Definitions

1. **Multiclass Brier Score:**
   $$\text{Brier} = \frac{1}{N} \sum_{i=1}^N \sum_{k=1}^K (p_{ik} - y_{ik})^2$$
   where $K=6$, $y_{ik} \in \{0, 1\}$ is the one-hot ground-truth indicator, and $p_{ik}$ is the predicted probability for class $k$. Measures mean squared probability error across all classes.

2. **Multiclass Log Loss:**
   $$\text{LogLoss} = -\frac{1}{N} \sum_{i=1}^N \sum_{k=1}^K y_{ik} \ln(p_{ik})$$
   with probabilities clipped to $[10^{-15}, 1 - 10^{-15}]$.

3. **Expected Calibration Error (ECE):**
   $$\text{ECE} = \sum_{b=1}^B \frac{|B_b|}{N} |\text{acc}(B_b) - \text{conf}(B_b)|$$
   using $B=10$ equal-width bins on top predicted confidence $\hat{p}_i = \max_k p_{ik}$.

---

## 8. Structured Triage Signal Contract

Implemented in `ml/triage_engine.py`, the triage engine synthesizes signals into a unified document:

```json
{
  "signals": {
    "binary_detection": {
      "status": "EVALUATED",
      "detector_id": "isolation_forest_baseline",
      "decision": "ATTACK",
      "continuous_score": 78.4,
      "threshold": 50.0,
      "calibrated": false
    },
    "anomaly_detection": {
      "status": "EVALUATED",
      "detector_id": "isolation_forest",
      "is_anomaly": true,
      "normalized_score": 82.5
    },
    "attack_family": {
      "status": "ATTRIBUTED",
      "predicted_family": "DoS",
      "confidence": 0.998,
      "calibrated": true,
      "calibration_method": "isotonic",
      "raw_confidence": 0.990,
      "ranked_candidates": [...]
    },
    "forensic_evidence": {
      "status": "EVALUATED",
      "matched_rules": ["High Packet Rate"],
      "yara_matches": [],
      "rule_score": 80.0
    },
    "data_quality": {
      "status": "VALID",
      "missing_inputs": [],
      "non_finite_dropped": 0
    }
  },
  "explanation": {
    "summary": "High-confidence compromise indicators require immediate triage.",
    "reasons": [...]
  },
  "recommendation": {
    "provisional_priority": "CRITICAL",
    "recommended_action": "RECOMMEND_IMMEDIATE_TRIAGE",
    "rationale": "...",
    "is_automated_verdict": false,
    "disclaimer": "This is a provisional recommendation. The analyst retains final authority."
  },
  "analyst_review": {
    "status": "PENDING_REVIEW",
    "analyst_assessment": null,
    "analyst_decision": null,
    "reviewed_by": null,
    "reviewed_at": null,
    "analyst_notes": null
  }
}
```

---

## 9. API Integration

Endpoints exposed by Flask in `backend/app.py`:
- `POST /api/model/attack-family`: Accepts either a multipart CSV upload or JSON features (`{"features": {...}}` or `{"records": [...]}`). Returns calibrated attribution results, ranked candidates, and abstention status.
- `POST /api/triage/signals`: Accepts multi-detector inputs and generates the structured triage contract with explanation and deterministic priority recommendation.
- `POST /api/analyze`: Backward-compatible enhancement; when the attack-family bundle exists, top suspicious artifacts are conditionally attributed and enriched with `attack_family` and `triage` assessment without modifying existing fields.
- `GET /api/ready`: Inspects and reports readiness of `network_baseline`, `mongo`, and `attack_family_model`.

---

## 10. Artifact Locations & Reproduction Commands

### Serialized Artifacts
- Model Bundle: `models/attack_family_bundle.joblib` (contains base model, scaler, class names, schema version, calibrator, and calibration metadata)
- Phase 17 Uncalibrated Benchmark: `reports/attack_family_benchmark.json`
- Phase 18A Calibrated Benchmark: `reports/attack_family_calibration_benchmark.json`

### Reproduction Commands

```bash
# Run full model training and probability calibration:
C:\Python314\python.exe scripts/train_attack_family.py --overwrite

# Run the complete test suite:
C:\Python314\python.exe -m pytest
```

