"""Unit tests for the Phase A ingestion parsers (Requirement #2).

Each parser is exercised against a small textual-export fixture written to a temp
file, asserting it normalizes to the shared ArtifactSchema columns the RiskScorer
keys on. Run with:  python3 -m unittest discover -s tests

No third-party test runner is required (pytest is not installed in this offline
environment) — these use the standard-library `unittest`.
"""

import os
import json
import tempfile
import unittest

# Make the repo root importable when run from anywhere.
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.ingestion import parse_file, ParserError, PARSER_REGISTRY
from ml.ingestion.base import ArtifactSchema


def _write(suffix, text, binary=False):
    fd, path = tempfile.mkstemp(suffix=suffix)
    mode = "wb" if binary else "w"
    with os.fdopen(fd, mode) as fh:
        fh.write(text)
    return path


class TestEvtxParser(unittest.TestCase):
    def test_csv_export_failed_logon_aggregation(self):
        # Three failed logons (4625) for the same account then a normal 4624.
        csv_text = (
            "EventID,TimeCreated,Account,LogonType\n"
            "4625,2026-08-24T02:14:01,alice,3\n"
            "4625,2026-08-24T02:14:05,alice,3\n"
            "4625,2026-08-24T02:14:09,alice,3\n"
            "4624,2026-08-24T09:00:00,alice,2\n"
        )
        path = _write(".csv", csv_text)
        try:
            rows = parse_file(path, kind="evtx")
        finally:
            os.remove(path)

        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r["artifact_type"] == "system_log" for r in rows))
        # FailedLogins is a per-account cumulative count of 4625 events.
        self.assertEqual([r["FailedLogins"] for r in rows], [1, 2, 3, 3])
        # LoginHour extracted from the timestamp.
        self.assertEqual(rows[0]["LoginHour"], 2)
        # Every SYSTEM_LOG schema column is present.
        for col in ArtifactSchema.SYSTEM_LOG:
            self.assertIn(col, rows[0])

    def test_xml_export(self):
        xml = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>4672</EventID>"
            '<TimeCreated SystemTime="2026-08-24T03:00:00"/></System>"'
            '<EventData><Data Name="TargetUserName">svc</Data>'
            '<Data Name="LogonType">5</Data></EventData></Event>'
        )
        path = _write(".xml", xml)
        try:
            rows = parse_file(path, kind="evtx")
        finally:
            os.remove(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["EventID"], 4672)
        # 4672 is a privilege-escalation event -> elevated context.
        self.assertEqual(rows[0]["PrivilegeLevel"], "SYSTEM")


class TestRegistryParser(unittest.TestCase):
    def test_reg_export(self):
        reg_text = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
            '"Updater"="C:\\\\Temp\\\\evil.exe"\r\n'
        )
        # .reg exports are conventionally UTF-16LE with a BOM.
        path = _write(".reg", reg_text.encode("utf-16"), binary=True)
        try:
            rows = parse_file(path, kind="registry")
        finally:
            os.remove(path)
        self.assertTrue(rows, "registry parser returned no rows")
        self.assertTrue(all(r["artifact_type"] == "registry" for r in rows))
        for col in ArtifactSchema.REGISTRY:
            self.assertIn(col, rows[0])
        # The Run key should be captured as the RegistryKey.
        self.assertTrue(any("Run" in r["RegistryKey"] for r in rows))


class TestPcapParser(unittest.TestCase):
    def test_flow_csv_alias_mapping(self):
        csv_text = (
            "Flow Duration,Flow Packets/s,Flow Bytes/s,Total Fwd Packets\n"
            "1500000,20.5,4096,12\n"
        )
        path = _write(".csv", csv_text)
        try:
            rows = parse_file(path, kind="pcap")
        finally:
            os.remove(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["artifact_type"], "network")
        self.assertEqual(rows[0]["Flow Duration"], 1500000)
        self.assertEqual(rows[0]["Flow Packets/s"], 20.5)
        # Every NETWORK schema column is present (unmapped ones default to 0).
        for col in ArtifactSchema.NETWORK:
            self.assertIn(col, rows[0])

    def test_unrecognized_columns_raise(self):
        path = _write(".csv", "foo,bar\n1,2\n")
        try:
            with self.assertRaises(ParserError):
                parse_file(path, kind="pcap")
        finally:
            os.remove(path)


class TestFileParser(unittest.TestCase):
    def test_csv_listing(self):
        csv_text = (
            "FileName,FilePath,FileSizeBytes\n"
            "evil.exe,C:\\Temp\\evil.exe,204800\n"
            "notes.txt,C:\\Users\\bob\\notes.txt,1200\n"
        )
        path = _write(".csv", csv_text)
        try:
            rows = parse_file(path, kind="file")
        finally:
            os.remove(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["artifact_type"], "file")
        self.assertEqual(rows[0]["FileExtension"], ".exe")
        for col in ArtifactSchema.FILE:
            self.assertIn(col, rows[0])

    def test_json_listing(self):
        data = {"files": [{"name": "a.dll", "path": "C:\\Windows\\a.dll", "size": 500}]}
        path = _write(".json", json.dumps(data))
        try:
            rows = parse_file(path, kind="file")
        finally:
            os.remove(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["FileName"], "a.dll")


class TestDispatch(unittest.TestCase):
    def test_missing_file_raises(self):
        with self.assertRaises(ParserError):
            parse_file("/nonexistent/path.csv", kind="file")

    def test_all_four_kinds_registered(self):
        self.assertEqual(
            set(PARSER_REGISTRY), {"evtx", "registry", "pcap", "file"}
        )


if __name__ == "__main__":
    unittest.main()
