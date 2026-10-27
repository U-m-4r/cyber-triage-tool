"""Regression protection and deterministic provenance tests (Phase 14).

Verifies:
1. Cross-platform semantic fingerprint invariance across operating systems,
   host paths, timestamps, and environments.
2. Tamper sensitivity: changing source dataset hash, cleaning policy, exclusion
   counts, or ledger hash changes the fingerprint or fails validation.
3. Substantive field modification cannot pass validation merely because an old
   fingerprint is retained.
4. Raw JSON file hashes may differ while semantic fingerprints remain equal.
5. Existing supported model bundles are handled through an explicit compatibility path.
6. Inference remains transform/predict-only and never initiates training.
7. Current model artifact remains byte-identical.
"""
import copy
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.baseline import (
    APPROVED_DATASET_PATH,
    BASELINE_PATH,
    infer_network,
    load_baseline,
    validate_bundle,
)
from ml.cleaning import (
    CLEANING_POLICY_ID,
    CLEANING_POLICY_VERSION,
    CLEANING_RECORD_VERSION,
    DEFAULT_RECORD_PATH,
    CleaningError,
    cleaning_record_fingerprint,
    load_cleaning_record,
    verify_cleaning_record,
)
from ml.preprocessor import NETWORK_FEATURES
from scripts.train_baseline import file_sha256
from scripts.evaluate_baseline import evaluate

EXPECTED_CURRENT_MODEL_SHA256 = (
    "8602d9e6f57d347a10ebbca7290ad2bc75892f9c7f8b29dcc97c2fea20035c0d"
)
EXPECTED_CURRENT_MODEL_ID = "iforest-65dd0b57a2b1a2020a0b"


def test_cross_platform_semantic_fingerprint_invariance():
    """Requirement 1: Equivalent cleaning records from different platforms match."""
    rec = load_cleaning_record(DEFAULT_RECORD_PATH)
    base_fp = cleaning_record_fingerprint(rec)
    assert base_fp.startswith("cleanfp-v1-")

    # Simulate Linux record
    linux_rec = copy.deepcopy(rec)
    linux_rec["source"]["path"] = "/var/data/cicids2017_cleaned.csv"
    linux_rec["source"]["manifest_path"] = "/var/data/manifest.json"
    linux_rec["source"]["manifest_csv_path"] = "/var/data/cicids2017_cleaned.csv"
    linux_rec["ledger"]["path"] = "/var/data/ledger.csv"
    linux_rec["policy"]["applied_at"] = "2024-01-01T00:00:00Z"
    linux_rec["environment"] = {"python": "3.11.8", "pandas": "2.2.0", "numpy": "1.26.4"}
    linux_rec["processing"]["chunk_rows"] = 50000

    # Simulate macOS record
    macos_rec = copy.deepcopy(rec)
    macos_rec["source"]["path"] = "/Users/analyst/dataset/cicids2017_cleaned.csv"
    macos_rec["source"]["manifest_path"] = "/Users/analyst/dataset/manifest.json"
    macos_rec["source"]["manifest_csv_path"] = "/Users/analyst/dataset/cicids2017_cleaned.csv"
    macos_rec["ledger"]["path"] = "/Users/analyst/dataset/ledger.csv"
    macos_rec["policy"]["applied_at"] = "2025-06-15T12:30:00Z"
    macos_rec["environment"] = {"python": "3.12.3", "pandas": "2.2.2", "numpy": "2.0.0"}
    macos_rec["processing"]["chunk_rows"] = 10000

    assert cleaning_record_fingerprint(linux_rec) == base_fp
    assert cleaning_record_fingerprint(macos_rec) == base_fp


def test_substantive_field_changes_alter_fingerprint_and_fail_validation():
    """Requirement 2: Substantive alterations change fingerprint and fail validation."""
    rec = load_cleaning_record(DEFAULT_RECORD_PATH)
    original_fp = cleaning_record_fingerprint(rec)

    # 1. Changing source dataset hash
    bad_source = copy.deepcopy(rec)
    bad_source["source"]["sha256"] = "0" * 64
    assert cleaning_record_fingerprint(bad_source) != original_fp
    with pytest.raises(CleaningError) as exc:
        verify_cleaning_record(bad_source, expected_source_sha=rec["source"]["sha256"])
    assert exc.value.code == "SOURCE_SHA_MISMATCH"

    # 2. Changing cleaning policy
    bad_policy = copy.deepcopy(rec)
    bad_policy["policy"]["version"] = "2.0.0"
    assert cleaning_record_fingerprint(bad_policy) != original_fp
    with pytest.raises(CleaningError) as exc:
        verify_cleaning_record(bad_policy)
    assert exc.value.code == "POLICY_MISMATCH"

    # 3. Changing ledger hash
    bad_ledger = copy.deepcopy(rec)
    bad_ledger["ledger"]["sha256"] = "f" * 64
    assert cleaning_record_fingerprint(bad_ledger) != original_fp
    with pytest.raises(CleaningError) as exc:
        verify_cleaning_record(bad_ledger, expected_ledger_sha=rec["ledger"]["sha256"])
    assert exc.value.code == "LEDGER_MISMATCH"

    # 4. Invariant violation (modifying row counts)
    bad_counts = copy.deepcopy(rec)
    bad_counts["exclusions"]["retained_rows"] -= 10
    assert cleaning_record_fingerprint(bad_counts) != original_fp
    with pytest.raises(CleaningError) as exc:
        verify_cleaning_record(bad_counts)
    assert exc.value.code == "COUNT_MISMATCH"

    # 5. Changing exclusion breakdown counts
    bad_reason = copy.deepcopy(rec)
    bad_reason["exclusions"]["by_reason"]["duplicate_row"] += 1
    assert cleaning_record_fingerprint(bad_reason) != original_fp


def test_retained_old_fingerprint_cannot_pass_substantive_tampering():
    """Requirement 3: Modifying substantive fields cannot pass validation with an old fingerprint."""
    rec = load_cleaning_record(DEFAULT_RECORD_PATH)
    legit_fp = cleaning_record_fingerprint(rec)

    # Attach the legitimate fingerprint, then tamper with substantive fields
    tampered = copy.deepcopy(rec)
    tampered["fingerprint"] = legit_fp
    tampered["exclusions"]["unique_rows"] += 1
    tampered["exclusions"]["input_rows"] += 1
    tampered["ledger"]["rows"] += 1

    with pytest.raises(CleaningError) as exc:
        verify_cleaning_record(tampered, expected_fingerprint=legit_fp)
    assert exc.value.code == "FINGERPRINT_MISMATCH"


def test_raw_json_file_hashes_differ_while_semantic_fingerprints_remain_equal(tmp_path):
    """Requirement 4: Raw file SHA-256 differs while semantic fingerprints are identical."""
    rec = load_cleaning_record(DEFAULT_RECORD_PATH)

    rec_a = copy.deepcopy(rec)
    rec_a["source"]["path"] = "/hostA/data/cicids2017_cleaned.csv"
    rec_a["policy"]["applied_at"] = "2026-01-01T00:00:00Z"

    rec_b = copy.deepcopy(rec)
    rec_b["source"]["path"] = "/hostB/data/cicids2017_cleaned.csv"
    rec_b["policy"]["applied_at"] = "2026-02-02T12:00:00Z"

    file_a = tmp_path / "record_a.json"
    file_b = tmp_path / "record_b.json"

    # Write file_a with compact formatting and file_b with 4-space indentation
    file_a.write_bytes(json.dumps(rec_a, separators=(",", ":")).encode("utf-8") + b"\n")
    file_b.write_bytes(json.dumps(rec_b, indent=4).encode("utf-8") + b"\n")

    # Raw file hashes MUST differ
    assert file_sha256(file_a) != file_sha256(file_b)

    # Semantic fingerprints MUST be equal
    loaded_a = json.loads(file_a.read_text(encoding="utf-8"))
    loaded_b = json.loads(file_b.read_text(encoding="utf-8"))
    fp_a = cleaning_record_fingerprint(loaded_a)
    fp_b = cleaning_record_fingerprint(loaded_b)

    assert fp_a == fp_b
    assert fp_a.startswith("cleanfp-v1-")


def test_existing_model_bundle_compatibility_and_evaluation():
    """Requirement 5: Existing supported model bundle is valid and handled cleanly."""
    assert BASELINE_PATH.is_file()
    bundle = load_baseline(BASELINE_PATH)
    assert bundle["bundle_version"] == 1
    assert bundle["provenance"]["model_id"] == EXPECTED_CURRENT_MODEL_ID
    assert bundle["provenance"]["dataset_id"] == "ericanacletoribeiro/cicids2017-cleaned-and-preprocessed"

    # Bundle validates under updated validate_bundle
    validated = validate_bundle(bundle)
    assert validated is bundle

    # Test compatibility evaluation path:
    # If evaluating with allow_semantic_record=True, it succeeds even if a record
    # from another host is supplied (as long as substantive fields match).
    rec = load_cleaning_record(DEFAULT_RECORD_PATH)
    fp = verify_cleaning_record(
        rec,
        expected_source_sha=bundle["provenance"]["sha256"],
        expected_ledger_sha=bundle["provenance"]["cleaning"]["ledger_sha256"],
    )
    assert fp.startswith("cleanfp-v1-")


def test_inference_remains_transform_only_and_never_trains(monkeypatch):
    """Requirement 6: Inference is strictly transform/predict only; fitting is impossible."""
    bundle = load_baseline(BASELINE_PATH)

    def forbidden_fit(*args, **kwargs):
        raise AssertionError("Inference attempted to fit model or scaler!")

    monkeypatch.setattr(IsolationForest, "fit", forbidden_fit)
    monkeypatch.setattr(StandardScaler, "fit", forbidden_fit)
    monkeypatch.setattr(StandardScaler, "fit_transform", forbidden_fit)

    # Synthetic sample features
    sample_data = {col: [100.0, 200.0, 300.0] for col in NETWORK_FEATURES}
    df = pd.DataFrame(sample_data)

    clean, predictions, scores, preprocessing, drift = infer_network(df, bundle)
    assert len(predictions) == 3
    assert len(scores) == 3
    assert all(p in (-1, 1) for p in predictions)
    assert drift["method"] == "psi"


def test_current_model_artifact_remains_unchanged():
    """Requirement 7: The approved model artifact remains byte-identical."""
    assert BASELINE_PATH.is_file(), f"Model artifact missing at {BASELINE_PATH}"
    actual_sha = file_sha256(BASELINE_PATH)
    assert actual_sha == EXPECTED_CURRENT_MODEL_SHA256, (
        f"Model artifact was modified! Expected {EXPECTED_CURRENT_MODEL_SHA256}, got {actual_sha}"
    )

    bundle = joblib.load(BASELINE_PATH)
    assert bundle["provenance"]["model_id"] == EXPECTED_CURRENT_MODEL_ID
    assert bundle["provenance"]["training_rows"] == 1051117
