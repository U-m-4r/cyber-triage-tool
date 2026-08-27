"""Tests for PART B — SHA-256 chain of custody (NIST FIPS 180-4)."""
import hashlib

import pytest


def test_compute_sha256_matches_known_value(tmp_path):
    from backend.app import compute_sha256

    f = tmp_path / "evidence.bin"
    data = b"forensic evidence payload \x00\x01\x02"
    f.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()
    assert compute_sha256(str(f)) == expected


def test_same_file_yields_same_hash(tmp_path):
    """Determinism: hashing the same bytes twice yields the identical digest."""
    from backend.app import compute_sha256

    f = tmp_path / "a.csv"
    f.write_text("Flow Duration,Label\n100,BENIGN\n", encoding="utf-8")

    h1 = compute_sha256(str(f))
    h2 = compute_sha256(str(f))
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest length


def test_stored_hash_matches_on_reread(tmp_path):
    """Integrity: an unchanged file re-hashes to the stored digest; a modified
    file does not (tamper detection)."""
    from backend.app import compute_sha256

    f = tmp_path / "image.dd"
    f.write_bytes(b"A" * 4096)
    stored = compute_sha256(str(f))

    # re-read, unchanged -> matches
    assert compute_sha256(str(f)) == stored

    # tamper -> digest diverges
    f.write_bytes(b"A" * 4095 + b"B")
    assert compute_sha256(str(f)) != stored


def test_analyze_response_includes_evidence_hash(tiny_flow_csv):
    """The /api/analyze response must carry the chain-of-custody digest."""
    from backend.app import app

    client = app.test_client()
    with open(tiny_flow_csv, "rb") as fh:
        resp = client.post(
            "/api/analyze",
            data={"file": (fh, "flows.csv")},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    body = resp.get_json()
    assert "evidence" in body
    custody = body["evidence"]
    assert custody["algorithm"] == "SHA-256"
    assert len(custody["sha256"]) == 64
    assert custody["original_filename"] == "flows.csv"
    assert custody["size_bytes"] > 0
