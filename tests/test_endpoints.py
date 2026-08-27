"""Endpoint tests for /api/ingest and /api/artifacts (Requirement #2).

Uses Flask's test_client so no live server is needed. Tests that require MongoDB
are skipped (not failed) when the database is unreachable, so the suite still runs
in a DB-less CI environment. Auth is exercised by toggling the module-level
API_TOKEN.
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import app as app_module
from backend.db import check_connection

MONGO_UP = check_connection()


class TestIngestEndpoint(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self._saved_token = app_module.API_TOKEN
        app_module.API_TOKEN = ""  # auth disabled for the happy-path tests

    def tearDown(self):
        app_module.API_TOKEN = self._saved_token

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
        app_module.API_TOKEN = "secret-token"
        resp = self._upload("listing.csv", "FileName\na.txt\n", "file")
        self.assertEqual(resp.status_code, 401)


class TestArtifactsEndpoint(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self._saved_token = app_module.API_TOKEN
        app_module.API_TOKEN = ""

    def tearDown(self):
        app_module.API_TOKEN = self._saved_token

    @unittest.skipUnless(MONGO_UP, "MongoDB not reachable")
    def test_list_artifacts_returns_shape(self):
        resp = self.client.get("/api/artifacts?limit=5")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("total", body)
        self.assertIn("artifacts", body)
        self.assertIsInstance(body["artifacts"], list)

    @unittest.skipUnless(MONGO_UP, "MongoDB not reachable")
    def test_severity_filter_is_uppercased(self):
        resp = self.client.get("/api/artifacts?severity=critical&limit=50")
        self.assertEqual(resp.status_code, 200)
        for art in resp.get_json()["artifacts"]:
            self.assertEqual(art["priority"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
