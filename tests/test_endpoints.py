"""Endpoint tests for /api/ingest and /api/artifacts (Requirement #2).

Uses Flask's test_client. Real MongoDB tests require explicit --run-integration
and a disposable loopback database; unavailable service is a setup failure.
Authentication is configured per application instance.
"""

import io
import os
import sys
import unittest
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import app as app_module


class TestIngestEndpoint(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self._saved_token = app_module.app.config['API_TOKEN']
        app_module.app.config['API_TOKEN'] = ""

    def tearDown(self):
        app_module.app.config['API_TOKEN'] = self._saved_token

    def _upload(self, filename, content, kind):
        return self.client.post(
            "/api/ingest",
            data={
                "file": (io.BytesIO(content.encode()), filename),
                "kind": kind,
            },
            content_type="multipart/form-data",
        )

    def test_ingest_file_listing_scores_artifacts(self):
        csv_text = (
            "FileName,FilePath,FileSizeBytes\n"
            "evil.exe,C:\\Temp\\evil.exe,204800\n"
        )
        resp = self._upload("listing.csv", csv_text, "file")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["summary"]["total_records"], 1)
        self.assertEqual(body["summary"]["critical"], 1)
        self.assertEqual(body["artifacts"][0]["priority"], "CRITICAL")

    def test_ingest_bad_format_returns_400(self):
        resp = self._upload("junk.csv", "foo,bar\n1,2\n", "pcap")
        self.assertEqual(resp.status_code, 400)

    def test_ingest_requires_auth_when_token_set(self):
        app_module.app.config['API_TOKEN'] = "secret-token"
        resp = self._upload("listing.csv", "FileName\na.txt\n", "file")
        self.assertEqual(resp.status_code, 401)


@pytest.mark.integration
class TestArtifactsEndpoint:
    def test_list_artifacts_returns_shape(self, mongo_app):
        client = mongo_app.test_client()
        response = client.post('/api/ingest', data={
            'file': (io.BytesIO(b'FileName,FilePath\nevil.exe,C:/Temp/evil.exe\n'), 'synthetic.csv'),
            'kind': 'file'}, content_type='multipart/form-data')
        assert response.status_code == 200
        assert response.json['stored'] == 1
        response = client.get('/api/artifacts?limit=5')
        assert response.status_code == 200
        assert response.json['total'] == 1
        assert len(response.json['artifacts']) == 1

    def test_severity_filter_is_uppercased(self, mongo_app):
        from backend.db import get_db
        with mongo_app.app_context():
            get_db().artifacts.insert_many([
                {'priority': 'CRITICAL', 'risk_score': 100},
                {'priority': 'LOW', 'risk_score': 0},
            ])
        response = mongo_app.test_client().get('/api/artifacts?severity=critical&limit=50')
        assert response.status_code == 200
        assert response.json['total'] == 1
        assert [a['priority'] for a in response.json['artifacts']] == ['CRITICAL']


if __name__ == "__main__":
    unittest.main()
