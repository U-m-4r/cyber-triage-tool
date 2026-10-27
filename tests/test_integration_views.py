"""Step 9 regressions. Unit doubles are not live database verification."""
import io
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from backend import app as module
from backend.integration import linked_case_query, persist_intake, validated_case
from werkzeug.exceptions import BadRequest


def test_session_checks_token_without_database(client, isolated_app):
    isolated_app.config["API_TOKEN"] = "test-token"
    assert client.get("/api/session").status_code == 401
    response = client.get("/api/session", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert response.json["authMode"] == "shared-token"
    assert "test-token" not in response.text


def test_model_missing_is_explicit_without_fitting(client):
    response = client.get("/api/model")
    assert response.status_code == 200
    assert response.json["available"] is False
    assert response.json["code"] == "MODEL_MISSING"


@pytest.mark.parametrize("data", [
    {"title": ""}, {"title": []}, {"status": []}, {"status": "MADE_UP"},
    {"findings": []}, {"threatScore": 99}, {"custody": []}, {"evidence.sources": []},
])
def test_case_validation_rejects_invalid_or_pipeline_owned_fields(data):
    with pytest.raises(BadRequest):
        validated_case(data)


def test_new_case_requires_title_and_cannot_use_demo_id():
    with pytest.raises(BadRequest):
        validated_case({"description": "test"}, creating=True)
    with pytest.raises(BadRequest):
        validated_case({"title": "test", "id": "CASE-2026-0147"}, creating=True)


def test_explicit_filters_cannot_restore_legacy_demo_records():
    assert linked_case_query("case_id") == {"case_id": {"$nin": module.DEMO_IDS}}
    assert linked_case_query("case_id", module.DEMO_IDS[0]) == {
        "$and": [
            {"case_id": {"$nin": module.DEMO_IDS}},
            {"case_id": module.DEMO_IDS[0]},
        ]
    }


def test_report_history_requires_a_live_case(client, monkeypatch):
    db = MagicMock()
    monkeypatch.setattr(module, "check_connection", lambda: True)
    monkeypatch.setattr(module, "get_db", lambda: db)
    db.cases.find_one.return_value = None
    response = client.get("/api/reports/missing")
    assert response.status_code == 404
    assert response.json["error"]["code"] == "CASE_NOT_FOUND"
    db.reports.find.assert_not_called()


def test_list_pagination_and_search_are_bounded(client, monkeypatch):
    db = MagicMock()
    monkeypatch.setattr(module, "check_connection", lambda: True)
    monkeypatch.setattr(module, "get_db", lambda: db)
    assert client.get('/api/cases?limit=99999').status_code == 400
    assert client.get('/api/artifacts?offset=-1').status_code == 400
    db.cases.count_documents.return_value = 0
    db.cases.find.return_value.sort.return_value.skip.return_value.limit.return_value = []
    response = client.get('/api/cases?q=a.*&limit=10&offset=20')
    assert response.status_code == 200
    query = db.cases.find.call_args.args[0]
    assert query['$or'][0]['id']['$regex'] == r'a\.\*'
    assert query['isDemo'] == {'$ne': True}
    db.cases.find.return_value.sort.return_value.skip.assert_called_once_with(20)


def test_dashboard_uses_database_aggregates_not_seeded_metrics(client, monkeypatch):
    db = MagicMock()
    monkeypatch.setattr(module, "check_connection", lambda: True)
    monkeypatch.setattr(module, "get_db", lambda: db)
    db.cases.find.return_value.sort.return_value.limit.return_value = []
    db.cases.aggregate.return_value = [{"evidence": 2, "iocs": 0}]
    db.cases.count_documents.return_value = 1
    db.artifacts.aggregate.side_effect = [[{"_id": "CRITICAL", "count": 3}], [{"_id": "file", "count": 3}]]
    db.activity.find.return_value.sort.return_value.limit.return_value = []
    response = client.get('/api/dashboard')
    assert response.status_code == 200
    assert {m['id']: m['value'] for m in response.json['metrics']} == {
        'cases': 1, 'evidence': 2, 'artifacts': 3, 'critical': 3}
    db.dashboard.find_one.assert_not_called()


def test_intake_failure_is_not_confirmed_and_keeps_failure_history():
    db = MagicMock()
    db.artifacts.insert_many.side_effect = RuntimeError('write failed')
    custody = {'original_filename': 'unit.csv', 'size_bytes': 12, 'ingested_at': 'test', 'sha256': 'a' * 64}
    with pytest.raises(RuntimeError):
        persist_intake(db, [{'priority': 'LOW'}], None, custody, 'file')
    assert db.ingestions.insert_one.call_args.args[0]['status'] == 'processing'
    assert db.ingestions.update_one.call_args.args[1] == {'$set': {'status': 'failed'}}


def test_case_upload_uses_original_filename_and_shared_intake(client, monkeypatch):
    monkeypatch.setattr(module, "check_connection", lambda: True)
    monkeypatch.setattr(module, "get_db", lambda: SimpleNamespace(cases=SimpleNamespace(find_one=lambda *args: {"id": "UNIT"})))
    persist = MagicMock(return_value=("IN-unit", 1))
    monkeypatch.setattr(module, "persist_intake", persist)
    response = client.post('/api/ingest', data={
        'caseId': 'UNIT', 'kind': 'file', 'file': (io.BytesIO(b'FileName,FilePath\na.txt,C:/a.txt\n'), 'unit.csv')})
    assert response.status_code == 200
    assert response.json['stored'] == 1
    assert persist.call_args.args[3]['original_filename'] == 'unit.csv'
    assert len(persist.call_args.args[3]['sha256']) == 64


def test_pdf_accepts_unmapped_findings_and_escapes_user_text():
    from backend.report_generator import generate_case_report
    result = generate_case_report({'id': 'UNIT', 'title': '<b>Untrusted & text', 'counts': {},
        'findings': [{'id': 'ART-unit', 'title': 'Rule <match>', 'source': 'unit.csv',
                      'technique': None, 'confidence': None, 'severity': 'LOW', 'riskScore': 0}],
        'evidence': {'sources': [], 'pending': []}})
    assert result.startswith(b'%PDF-')


@pytest.mark.integration
def test_persisted_case_upload_notes_dashboard_and_report(mongo_app):
    """Runs only against the fixture-owned, dedicated MongoDB on port 27018."""
    client = mongo_app.test_client()
    record = client.post('/api/cases', json={'title': 'Isolated integration verification'}).json
    case_id = record['id']
    assert record['threatScore'] is None
    response = client.post('/api/ingest', data={'caseId': case_id, 'kind': 'file',
        'file': (io.BytesIO(b'FileName,FilePath\nevil.exe,C:/Temp/evil.exe\n'), 'isolated.csv')})
    assert response.status_code == 200
    assert response.json['stored'] == 1
    assert client.put(f'/api/cases/{case_id}', json={'status': 'REVIEW'}).status_code == 200
    assert client.post(f'/api/cases/{case_id}/notes', json={'text': 'Verified test intake'}).status_code == 201
    refreshed = client.get(f'/api/cases/{case_id}').json
    assert refreshed['status'] == 'REVIEW'
    assert refreshed['notes'][0]['text'] == 'Verified test intake'
    assert refreshed['counts']['evidence'] == 1
    assert refreshed['evidence']['sources'][0]['sha256'] == response.json['evidence']['sha256']
    assert refreshed['evidence']['sources'][0]['integrity'] == 'SHA-256 recorded'
    assert client.get(f'/api/ingestions?case_id={case_id}').json['ingestions'][0]['status'] == 'complete'
    assert client.get(f'/api/artifacts?case_id={case_id}').json['total'] == 1
    metrics = {m['id']: m['value'] for m in client.get('/api/dashboard').json['metrics']}
    assert metrics['evidence'] == metrics['artifacts'] == 1
    assert client.post('/api/report', json={'caseId': case_id}).status_code == 200
