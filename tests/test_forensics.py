"""Tests for PART C — forensic artifact parsers, IOC scanning, threat intel."""
import os

import pytest


# --- capabilities endpoint --------------------------------------------------

def test_capabilities_endpoint_shape():
    from backend.app import app

    client = app.test_client()
    resp = client.get("/api/forensics/capabilities")
    assert resp.status_code == 200
    body = resp.get_json()
    for key in ("evtx", "registry", "yara", "disk_image", "threat_intel"):
        assert key in body


def test_ingest_rejects_unsupported_type(tmp_path):
    from backend.app import app

    f = tmp_path / "notes.txt"
    f.write_text("just text", encoding="utf-8")
    client = app.test_client()
    with open(f, "rb") as fh:
        resp = client.post(
            "/api/forensics/ingest",
            data={"file": (fh, "notes.txt")},
            content_type="multipart/form-data",
        )
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "UNSUPPORTED_FILE_TYPE"


# --- EVTX normalization (pure helper, no real file needed) -------------------

def test_evtx_flatten_system_normalizes_fields():
    from forensics import evtx_parser

    system = {
        "EventID": {"#text": "4625", "@Qualifiers": "0"},
        "TimeCreated": {"@SystemTime": "2026-01-02T03:04:05.000Z"},
        "Channel": "Security",
        "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"},
        "Computer": "DESKTOP-1",
        "EventRecordID": "9001",
        "Level": "0",
    }
    row = evtx_parser._flatten_system(system)
    assert row["EventID"] == "4625"
    assert row["TimeCreated"] == "2026-01-02T03:04:05.000Z"
    assert row["Channel"] == "Security"
    assert row["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert row["RecordID"] == "9001"
    assert set(evtx_parser.COLUMNS) == set(row.keys())


# --- registry value stringification -----------------------------------------

def test_registry_columns_and_bytes_hex():
    from forensics import registry_parser

    assert registry_parser.COLUMNS[0] == "RegistryKey"

    class _FakeVal:
        def value(self):
            return b"\x00\x01\xff"

    assert registry_parser._value_data_to_str(_FakeVal()) == "0001ff"


# --- YARA IOC scanning ------------------------------------------------------

@pytest.mark.skipif(
    not __import__("forensics.yara_scanner", fromlist=["AVAILABLE"]).AVAILABLE,
    reason="yara-python not installed",
)
def test_yara_scan_surfaces_powershell_ioc(tmp_path):
    from forensics import yara_scanner

    f = tmp_path / "cmd.log"
    f.write_text(
        "powershell.exe -ExecutionPolicy Bypass -EncodedCommand ZQBjAGgAbwA=",
        encoding="utf-8",
    )
    matches = yara_scanner.scan_file(str(f))
    rules = {m["rule"] for m in matches}
    assert "Suspicious_PowerShell_EncodedCommand" in rules
    hit = next(m for m in matches if m["rule"] == "Suspicious_PowerShell_EncodedCommand")
    assert hit["meta"].get("severity") == "medium"
    assert "target" in hit and "matched_strings" in hit


def test_yara_scan_no_rules_dir_returns_empty(tmp_path):
    from forensics import yara_scanner

    if not yara_scanner.AVAILABLE:
        pytest.skip("yara-python not installed")
    target = tmp_path / "clean.txt"
    target.write_text("nothing to see", encoding="utf-8")
    empty_rules = tmp_path / "no_rules"
    empty_rules.mkdir()
    assert yara_scanner.scan_file(str(target), rules_dir=str(empty_rules)) == []


def test_yara_does_not_disclose_server_path_and_is_bounded(tmp_path):
    from forensics import yara_scanner
    from unittest.mock import Mock
    if not yara_scanner.AVAILABLE:
        pytest.skip('yara-python not installed')
    target = tmp_path / 'safe.txt'
    target.write_text('powershell.exe -EncodedCommand ZQBjAGgAbwA=')
    hits = yara_scanner.scan_file(str(target))
    assert hits and all(hit['target'] == 'safe.txt' for hit in hits)
    rules = Mock()
    rules.match.return_value = []
    yara_scanner.scan_file(str(target), compiled_rules=rules)
    rules.match.assert_called_once_with(str(target), timeout=10)


# --- threat intel (graceful no-op without API keys) --------------------------

def test_threat_intel_no_keys_is_noop(monkeypatch):
    from forensics import threat_intel

    monkeypatch.setattr(threat_intel, "OTX_API_KEY", "")
    monkeypatch.setattr(threat_intel, "VT_API_KEY", "")
    verdict = threat_intel.check_indicator("d41d8cd98f00b204e9800998ecf8427e", kind="hash")
    assert verdict["providers"] == []
    assert verdict["malicious"] is False


def test_reputation_rule_bump_maps_verdict():
    from forensics import threat_intel

    assert threat_intel.reputation_rule_bump({"malicious": True}) == 1.0
    assert threat_intel.reputation_rule_bump({"malicious": False}) == 0.0
    assert threat_intel.reputation_rule_bump(None) == 0.0


# --- disk image timestamp helper --------------------------------------------

def test_disk_image_ts_helper():
    from forensics import disk_image

    assert disk_image._ts(0).startswith("1970-01-01")
    assert disk_image._ts("not-an-int") == ""


# --- Phase 19A: forensic acquisition & disk image verification ---------------

def test_kaggle_client_status_diagnostics():
    from forensics.acquisition import check_kaggle_client_status

    status = check_kaggle_client_status()
    assert "kaggle_installed" in status
    assert "kagglehub_installed" in status
    assert "has_credentials" in status
    assert "can_download_kaggle" in status
    assert "blockers" in status
    assert isinstance(status["blockers"], list)


def test_kaggle_candidates_metadata_structure():
    from forensics.acquisition import KAGGLE_CANDIDATES

    assert len(KAGGLE_CANDIDATES) >= 3
    for c in KAGGLE_CANDIDATES:
        assert "id" in c
        assert "title" in c
        assert "url" in c
        assert "has_disk_image" in c
        assert c["has_disk_image"] is False  # Confirmed non-disk datasets
        assert "status" in c
        assert "notes" in c


def test_digital_corpora_candidates_metadata_structure():
    from forensics.acquisition import DIGITAL_CORPORA_CANDIDATES

    assert len(DIGITAL_CORPORA_CANDIDATES) >= 2
    ids = {c["id"] for c in DIGITAL_CORPORA_CANDIDATES}
    assert "digitalcorpora/m57-jean" in ids
    assert "digitalcorpora/nps-2009-domexusers" in ids
    for c in DIGITAL_CORPORA_CANDIDATES:
        assert "id" in c
        assert "title" in c
        assert "url" in c
        assert "uncompressed_size_bytes" in c
        assert c["uncompressed_size_bytes"] > 5 * 1024 * 1024 * 1024  # > 5 GB
        assert "status" in c
        assert "notes" in c



def test_sha256_stream_calculation(tmp_path):
    import hashlib
    from forensics.acquisition import sha256_file

    sample = tmp_path / "sample.bin"
    payload = b"NIST-CFREDS-DIGITAL-FORENSICS-TEST-PAYLOAD" * 1024
    sample.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    actual = sha256_file(sample)
    assert actual == expected


def test_dry_run_acquisition(tmp_path):
    from forensics.acquisition import acquire_primary_forensic_image

    manifest_target = tmp_path / "manifest.json"
    result = acquire_primary_forensic_image(
        output_dir=tmp_path / "images",
        manifest_path=manifest_target,
        dry_run=True,
    )
    assert result["status"] == "DRY_RUN"
    assert "dataset" in result
    assert result["dataset"]["filesystem"] == "NTFS"
    assert not manifest_target.exists()  # Dry run writes no files


def test_synthetic_manifest_and_verification(tmp_path):
    import json
    from forensics.acquisition import sha256_file, verify_disk_image_against_manifest

    fake_img = tmp_path / "fake.dd"
    fake_img.write_bytes(b"\x00" * 4096)
    fake_sha = sha256_file(fake_img)

    fake_manifest = tmp_path / "manifest.json"
    fake_manifest.write_text(json.dumps({
        "image": {
            "filename": "fake.dd",
            "sha256": fake_sha,
            "size_bytes": 4096,
        }
    }), encoding="utf-8")

    report = verify_disk_image_against_manifest(fake_img, fake_manifest)
    assert report["sha256"] == fake_sha
    assert report["sha256_matches_manifest"] is True

    # Test tampering detection
    tampered_manifest = tmp_path / "tampered.json"
    tampered_manifest.write_text(json.dumps({
        "image": {
            "filename": "fake.dd",
            "sha256": "0" * 64,
            "size_bytes": 4096,
        }
    }), encoding="utf-8")
    tampered_report = verify_disk_image_against_manifest(fake_img, tampered_manifest)
    assert tampered_report["sha256_matches_manifest"] is False


def test_acquired_primary_disk_image_integration():
    """Verify the locally acquired NIST reference disk image can be inspected by pytsk3."""
    from pathlib import Path
    from forensics.acquisition import DEFAULT_IMAGE_DIR, DEFAULT_MANIFEST_PATH, verify_disk_image_against_manifest
    from forensics.disk_image import AVAILABLE as TSK_AVAILABLE, ingest_disk_image

    img_path = DEFAULT_IMAGE_DIR / "dfr-01-ntfs.dd"
    if not img_path.is_file():
        pytest.skip("Primary forensic disk image not present locally; run scripts/acquire_forensic_image.py")

    report = verify_disk_image_against_manifest(img_path, DEFAULT_MANIFEST_PATH)
    assert report["valid"] is True
    assert report["sha256_matches_manifest"] is True
    assert report["size_bytes"] == 1073742336

    if TSK_AVAILABLE:
        df = ingest_disk_image(str(img_path), limit=50)
        assert len(df) > 0
        for col in ["FileName", "FilePath", "FileExtension", "FileSizeBytes", "CreatedTime", "ModifiedTime"]:
            assert col in df.columns
        # Verify NTFS system artifacts are surfaced
        file_names = set(df["FileName"].tolist())
        assert any(fn.startswith("$") for fn in file_names)
