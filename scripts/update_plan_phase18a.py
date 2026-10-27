"""
Deterministic in-place updater for plan.md to document Phase 18A completion.
"""
from pathlib import Path

plan_path = Path("plan.md")
assert plan_path.is_file(), "plan.md not found"

content = plan_path.read_text(encoding="utf-8")

phase18a_section = """
## 5. Phase 17 & Phase 18 Status: Advanced Triage, Calibration & Integrity

### Phase 17: Attack-Family Attribution & Triage Signal Engine [COMPLETED]
- [x] Supervised 6-family attribution model (Random Forest, 11-feature contract)
- [x] Conditional triage architecture separating binary detection from attribution
- [x] Structured triage signal schema (`ml/triage_engine.py`) with provisional prioritization
- [x] Baseline macro-F1: 0.9995, Weighted-F1: 0.9997 on held-out test partition
- [x] Historical benchmark artifact: `reports/attack_family_benchmark.json`

### Phase 18A: Confidence Calibration, Reliability Benchmarking & Attack-Family Integrity [COMPLETED]
**Status:** COMPLETE (All implementation, test, documentation, and benchmark gates verified).

#### Implementation & Calibration Summary
- [x] **Split Protocol & Leakage Controls:**
  - 70% Train (254,181 rows) split strictly internally into Train-Base (80%, 203,344 rows) and Train-Cal (20%, 50,837 rows).
  - Base `RandomForestClassifier` fitted exclusively on Train-Base.
  - Candidate calibrators (`CalibratedClassifierCV` with Platt Sigmoid and Isotonic Regression via `FrozenEstimator`) fitted on Train-Cal.
  - Validation partition (15%, 54,468 rows) used exclusively for calibration candidate selection; held-out Test partition (15%, 54,468 rows) kept strictly untouched until final evaluation.
- [x] **Calibrator Selection (Validation Evidence):**
  - Uncalibrated (Raw): Val Log Loss 0.00317, Val Brier 0.00082, Val ECE 0.00030
  - Platt Sigmoid: Val Log Loss 0.00328, Val Brier 0.00085, Val ECE 0.00011
  - **Isotonic Regression (Selected):** Val Log Loss 0.00563, **Val Brier 0.00079**, Val ECE 0.00025. Selected on lowest multiclass Brier score.
- [x] **Final Held-Out Test Calibration Results:**
  - Test Calibrated Brier Score: `0.00044` (improved from raw `0.00053`)
  - Test Calibrated ECE (10 bins): `0.00009` (a **5x error reduction** from raw `0.00045`)
  - Test Calibrated Log Loss: `0.00225`
  - Test Macro-F1: `0.9995` | Test Weighted-F1: `0.9998` | Test Accuracy: `99.98%`
- [x] **Duplicate Vector & Leakage Audit Findings:**
  - *Confirmed findings:* 6,161 test rows (11.3% of test partition) share an identical 11-feature vector with at least one Train row. Overlap is concentrated almost entirely in Port Scanning (96.9% overlap) due to repetitive single-packet SYN scanner probes with identical flow metrics in the dataset capture.
  - *Generalization proof on novel data:* Evaluated exclusively on the 48,307 test flows with ZERO feature overlap in Train: Accuracy **99.97%**, Macro-F1 **99.56%**, Weighted-F1 **99.97%** (Bots Recall 100%, Web Attacks Recall 99.66%). Confirms reported high performance is genuine generalization, not cross-partition memorization.
- [x] **Triage & API Semantics Integration:**
  - Preserved dual score reporting (`raw_confidence`, `calibrated_confidence`, `raw_margin`, `calibrated_margin`, `raw_scores`, `calibrated_scores`).
  - Abstention policy (`min_confidence=0.50`, `min_margin=0.05`) evaluates against calibrated confidence with graceful fallback to raw scores if calibration fails.
  - Attribution failures never override the independent binary detector; benign traffic remains `NOT_APPLICABLE`.
- [x] **Test Suite & Verification:**
  - Added unit and regression tests in `tests/test_attack_family.py` covering score properties (sum to 1 within numerical tolerance), class order stability, safe calibrator failure fallback, and Brier/ECE metric math.
  - Test execution: `C:\\Python314\\python.exe -m pytest` -> **292 passed, 2 skipped** (MongoDB integration skipped) in 26.86s.
- [x] **Artifact Paths:**
  - Model Bundle: `models/attack_family_bundle.joblib`
  - Calibration Benchmark Report: `reports/attack_family_calibration_benchmark.json`
  - Historical Baseline Report: `reports/attack_family_benchmark.json`
  - Documentation: `docs/attack_family.md`

### Phase 18B: Case-Management Persistence & Analyst Review Workflow [PENDING]
- [ ] MongoDB schema extensions for storing structured triage signals and calibration diagnostics
- [ ] Analyst review audit trail (provisional priority confirmation/override, triage notes, reviewer signature)
- [ ] Backend API endpoints for triage case review and status transition

### Phase 18C: Frontend Interactive Triage Workspace & Evidence Timeline [PENDING]
- [ ] React 19 triage dashboard components displaying multi-detector signal cards
- [ ] Confidence calibration indicator and candidate family margin visualizer
- [ ] Forensic evidence timeline with packet inspection drill-down
"""

if "## 5. Phase 17 & Phase 18 Status" not in content:
    updated_content = content.rstrip() + "\n" + phase18a_section
    plan_path.write_text(updated_content, encoding="utf-8")
    print("plan.md successfully updated with Phase 18A status.")
else:
    print("Phase 18 section already present in plan.md.")
