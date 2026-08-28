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
