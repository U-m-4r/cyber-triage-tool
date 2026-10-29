"""Unit tests for RiskScorer.score_records — the Phase A rules-only scoring path
(FORMULAS.md#rules-only-risk) and priority banding (FORMULAS.md#priority-bands).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.risk_scorer import RiskScorer


class TestScoreRecords(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer()

    def test_rules_only_interim_scoring(self):
        # An .exe in a Temp path fires the executable_in_temp rule (weight 0.8),
        # so rules-only risk = min(0.8*100, 100) = 80 -> CRITICAL (>=75).
        records = [{
            "artifact_type": "file",
            "FileName": "evil.exe",
            "FileExtension": ".exe",
            "FilePath": "C:\\Temp\\evil.exe",
            "FileSizeBytes": 204800,
        }]
        scored = self.scorer.score_records(records)
        self.assertEqual(len(scored), 1)
        art = scored[0]
        # Phase A: no anomaly component wired in yet.
        self.assertIsNone(art["anomaly_score"])
        self.assertEqual(art["risk_score"], 80.0)
        self.assertEqual(art["priority"], "CRITICAL")
        self.assertIn("Executable in Temp", art["matched_rules"])

    def test_benign_record_is_low(self):
        records = [{
            "artifact_type": "file",
            "FileName": "notes.txt",
            "FileExtension": ".txt",
            "FilePath": "C:\\Users\\bob\\notes.txt",
            "FileSizeBytes": 1200,
        }]
        scored = self.scorer.score_records(records)
        self.assertEqual(scored[0]["priority"], "LOW")
        self.assertEqual(scored[0]["matched_rules"], "None")

    def test_results_sorted_by_risk_desc(self):
        records = [
            {"artifact_type": "file", "FileName": "a.txt", "FileExtension": ".txt",
             "FilePath": "C:\\a.txt", "FileSizeBytes": 10},
            {"artifact_type": "file", "FileName": "evil.exe", "FileExtension": ".exe",
             "FilePath": "C:\\Temp\\evil.exe", "FileSizeBytes": 999999},
        ]
        scored = self.scorer.score_records(records)
        scores = [a["risk_score"] for a in scored]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_risk_capped_at_100(self):
        for art in self.scorer.score_records([{
            "artifact_type": "file", "FileName": "x.exe", "FileExtension": ".exe",
            "FilePath": "C:\\Temp\\x.exe", "FileSizeBytes": 10 ** 9,
        }]):
            self.assertLessEqual(art["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()


def test_temp_executable_rules_handle_case_and_path_components():
    scorer = RiskScorer()
    for path in [r'C:\Windows\TEMP\UPDATER.EXE', '/tmp/update.exe']:
        row = scorer.score_records([{'FileName': 'UPDATER.EXE', 'FilePath': path}])[0]
        assert row['risk_score'] == 80
        assert 'Executable in Temp' in row['matched_rules']
    for path in ['/Documents/templates/setup.exe', '/Documents/attempt.exe']:
        row = scorer.score_records([{'FileName': 'setup.exe', 'FilePath': path}])[0]
        assert row['risk_score'] == 0


def test_host_and_network_findings_explain_model_applicability():
    from backend.integration import finding
    base = {'artifact_id': 'ART-unit', 'priority': 'LOW', 'risk_score': 0,
            'rule_score': 0, 'anomaly_score': None, 'matched_rules': 'None',
            'ingested_at': '2026-10-29T00:00:00Z'}
    host = finding({**base, 'artifact_type': 'file', 'FilePath': '/$Boot'})
    assert 'No configured rules matched' in host['rationale']
    assert 'not applicable' in host['rationale']
    assert 'None' not in host['rationale']
    network = finding({**base, 'artifact_type': 'network', 'anomaly_score': 72.5})
    assert 'network anomaly score: 72.5' in network['rationale']


def test_report_shortens_file_titles_without_losing_rule_labels():
    from backend.report_generator import _finding_label
    item = {'artifactType': 'file', 'title': '/$Extend/$RmMetadata/$TxfLog/$TxfLogContainer00000000000000000001 (No rule match)'}
    assert _finding_label(item) == '$TxfLogContainer00000000000000000001'
    assert _finding_label({'artifactType': 'file', 'title': '/Windows/Temp/updater.exe: Executable in Temp'}) == 'updater.exe'
    assert _finding_label({'artifactType': 'network', 'title': 'High Packet Rate'}) == 'High Packet Rate'
