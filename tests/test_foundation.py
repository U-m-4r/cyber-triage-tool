"""Regression coverage for startup, database boundaries and HTTP failure contracts."""

import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pymongo.errors import ServerSelectionTimeoutError
from werkzeug.datastructures import FileStorage

from backend.app import create_app
from backend.config import ConfigurationError, load_config
from backend import db


@pytest.mark.parametrize(
    "uri",
    [
        "mongodb://localhost:27017",
        "mongodb://example.com:27018",
        "mongodb+srv://example.com",
        "mongodb://user:secret@127.0.0.1:27018",
        "mongodb://127.0.0.1:27018/investigations",
        "mongodb://127.0.0.1:27018/?replicaSet=x",
        "mongodb://127.0.0.1:27018,example.com:27018",
        "",
    ],
)
def test_unsafe_test_mongo_uri_rejected_before_client_construction(uri, monkeypatch):
    constructor = Mock(side_effect=AssertionError("Must not construct a client"))
    monkeypatch.setattr(db, "MongoClient", constructor)
    with pytest.raises(ConfigurationError):
        create_app({"DB_MODE": "mongo", "MONGO_URI": uri})
    constructor.assert_not_called()


@pytest.mark.parametrize(
    "name", ["cyber_triage", "production", "admin", "test", "cyber_triage_test_", "cyber_triage_test_real"]
)
def test_test_database_name_guard(name):
    with pytest.raises(ConfigurationError, match="owned"):
        create_app({"MONGO_DB": name})


def test_pytest_cannot_turn_off_test_mode():
    with pytest.raises(ConfigurationError):
        create_app({"TESTING": False, "APP_ENV": "development"})


def test_test_mode_ignores_inherited_investigation_environment(monkeypatch):
    monkeypatch.setenv("MONGO_URI", "mongodb://user:secret@production.invalid")
    monkeypatch.setenv("MONGO_DB", "real_investigations")
    monkeypatch.setenv("CYBER_TRIAGE_API_TOKEN", "real-token")
    monkeypatch.setenv("APP_ENV", "production")
    config = load_config()
    assert config["DB_MODE"] == "disabled"
    assert config["MONGO_URI"] == ""
    assert config["MONGO_DB"].startswith("cyber_triage_test_")
    assert config["API_TOKEN"] == ""


def test_factory_has_no_database_or_filesystem_side_effects(tmp_path, monkeypatch):
    constructor = Mock(side_effect=AssertionError("No connection at startup"))
    monkeypatch.setattr(db, "MongoClient", constructor)
    first = create_app({"TEMP_DIR": str(tmp_path / "first")})
    second = create_app({"TEMP_DIR": str(tmp_path / "second")})
    first.config["API_TOKEN"] = "only-first"
    assert second.config["API_TOKEN"] == ""
    assert not list(tmp_path.iterdir())
    assert not first.extensions and not second.extensions
    constructor.assert_not_called()


def test_disabled_database_never_constructs_client(isolated_app, monkeypatch):
    constructor = Mock(side_effect=AssertionError("No database expected"))
    monkeypatch.setattr(db, "MongoClient", constructor)
    with isolated_app.app_context():
        assert db.check_connection() is False
        with pytest.raises(db.DatabaseUnavailable):
            db.get_db()
    constructor.assert_not_called()


def test_database_guard_rechecked_after_config_mutation(isolated_app, monkeypatch):
    monkeypatch.setattr(db, "MongoClient", Mock(side_effect=AssertionError("Must reject first")))
    isolated_app.config.update(DB_MODE="mongo", MONGO_URI="mongodb://localhost:27017")
    with isolated_app.app_context(), pytest.raises(ConfigurationError):
        db.get_db()


def test_database_client_owned_by_app_and_closed(monkeypatch):
    clients = [Mock(), Mock()]
    constructor = Mock(side_effect=clients)
    monkeypatch.setattr(db, "MongoClient", constructor)
    apps = [create_app({"DB_MODE": "mongo", "MONGO_URI": "mongodb://127.0.0.1:27018"}) for _ in clients]
    for app, client in zip(apps, clients):
        with app.app_context():
            assert db.get_client() is client
            assert db.get_client() is client
        db.close_db(app)
        client.close.assert_called_once()
    assert constructor.call_count == 2


def test_database_outage_can_recover_without_restart(monkeypatch):
    connection = Mock()
    connection.admin.command.side_effect = [ServerSelectionTimeoutError("offline"), {"ok": 1}]
    monkeypatch.setattr(db, "MongoClient", Mock(return_value=connection))
    app = create_app({"DB_MODE": "mongo", "MONGO_URI": "mongodb://127.0.0.1:27018"})
    with app.app_context():
        assert db.check_connection() is False
        assert db.check_connection() is True
    db.close_db(app)


def test_health_and_readiness_are_distinct(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"
    assert response.json["ready"] is False
    assert response.json["mongo"] == "unavailable"
    assert response.json["network_baseline"]["code"] == "MODEL_MISSING"
    assert client.get("/api/ready").status_code == 503


def test_ready_requires_both_model_and_database(baseline_api, monkeypatch):
    from backend import app as module

    client, path, _ = baseline_api
    assert client.get("/api/ready").status_code == 503
    monkeypatch.setattr(module, "check_connection", lambda: True)
    assert client.get("/api/ready").status_code == 200
    path.unlink()
    assert client.get("/api/ready").status_code == 503


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/cases"),
        ("GET", "/api/cases/synthetic"),
        ("GET", "/api/dashboard"),
        ("GET", "/api/report/synthetic"),
        ("GET", "/api/reports/synthetic"),
        ("GET", "/api/triage/synthetic"),
        ("GET", "/api/artifacts"),
        ("POST", "/api/forensics/ingest"),
        ("POST", "/api/analyze"),
        ("POST", "/api/evaluate"),
        ("POST", "/api/ingest"),
        ("POST", "/api/cases"),
        ("PUT", "/api/cases/synthetic"),
        ("POST", "/api/report"),
    ],
)
def test_all_investigation_routes_enforce_configured_token(isolated_app, method, path):
    isolated_app.config["API_TOKEN"] = "synthetic-token"
    response = isolated_app.test_client().open(path, method=method)
    assert response.status_code == 401
    assert response.json["error"]["code"] == "UNAUTHORIZED"


def test_valid_token_reaches_route_and_cors_preflight(isolated_app):
    isolated_app.config["API_TOKEN"] = "synthetic-token"
    client = isolated_app.test_client()
    assert client.get("/api/cases", headers={"Authorization": "Bearer synthetic-token"}).status_code == 503
    assert client.get("/api/cases", headers={"X-API-Key": "synthetic-token"}).status_code == 503
    assert client.options("/api/cases").status_code == 200


@pytest.mark.parametrize("endpoint", ["/api/analyze", "/api/ingest", "/api/forensics/ingest"])
def test_case_intake_refuses_missing_database_before_writing(client, isolated_app, endpoint):
    response = client.post(endpoint, data={"caseId": "synthetic", "file": (io.BytesIO(b"x"), "x.csv")})
    assert response.status_code == 503
    assert response.json["error"]["code"] == "DB_UNAVAILABLE"
    assert not Path(isolated_app.config["TEMP_DIR"]).exists()


def test_case_intake_refuses_unknown_case(client, monkeypatch):
    from backend import app as module

    monkeypatch.setattr(module, "check_connection", lambda: True)
    monkeypatch.setattr(
        module, "get_db", lambda: SimpleNamespace(cases=SimpleNamespace(find_one=lambda *a: None))
    )
    response = client.post("/api/ingest", data={"caseId": "missing"})
    assert response.status_code == 404


def test_failed_upload_cleans_partial_file(client, isolated_app, monkeypatch):
    def broken_save(self, destination, *args, **kwargs):
        destination.write(b"partial")
        raise OSError("synthetic write error")

    monkeypatch.setattr(FileStorage, "save", broken_save)
    response = client.post("/api/ingest", data={"file": (io.BytesIO(b"x"), "x.csv")})
    assert response.status_code == 500
    assert list(Path(isolated_app.config["TEMP_DIR"]).iterdir()) == []


def test_oversized_upload_has_json_error_and_no_tempfile(client, isolated_app):
    isolated_app.config["MAX_CONTENT_LENGTH"] = 64
    response = client.post("/api/ingest", data={"file": (io.BytesIO(b"x" * 128), "x.csv")})
    assert response.status_code == 413
    assert response.json["error"]["code"] == "HTTP_413"
    assert not Path(isolated_app.config["TEMP_DIR"]).exists()


def test_persistence_failure_cannot_return_success(client, isolated_app, monkeypatch):
    from backend import app as module

    monkeypatch.setattr(module, "check_connection", lambda: True)
    monkeypatch.setattr(module, "get_db", Mock(side_effect=ServerSelectionTimeoutError("synthetic secret")))
    response = client.post(
        "/api/ingest", data={"kind": "file", "file": (io.BytesIO(b"FileName\na.txt\n"), "synthetic.csv")}
    )
    assert response.status_code == 503
    assert response.json["error"]["code"] == "PERSISTENCE_FAILED"
    assert "synthetic secret" not in response.text
    assert not list(Path(isolated_app.config["TEMP_DIR"]).iterdir())


def test_config_command_is_read_only_and_secret_free(isolated_app):
    isolated_app.config["API_TOKEN"] = "not-for-logs"
    result = isolated_app.test_cli_runner().invoke(args=["check-config"])
    assert result.exit_code == 0
    assert "auth=enabled" in result.output
    assert "not-for-logs" not in result.output
    assert not isolated_app.extensions


def test_seed_demo_command_rejects_test_database(isolated_app):
    result = isolated_app.test_cli_runner().invoke(args=["seed-demo"])
    assert result.exit_code != 0
    assert "Demo seeding requires" in result.output


@pytest.mark.parametrize(
    "key,value", [("MAX_CONTENT_LENGTH", 0), ("MONGO_TIMEOUT_MS", -1), ("DB_MODE", "fallback")]
)
def test_invalid_runtime_settings_rejected(key, value):
    with pytest.raises(ConfigurationError):
        create_app({key: value})


@pytest.mark.parametrize("path", ["/api/cases", "/api/cases/synthetic"])
def test_case_json_must_be_an_object(client, monkeypatch, path):
    from backend import app as module

    monkeypatch.setattr(module, "check_connection", lambda: True)
    response = client.open(path, method="POST" if path == "/api/cases" else "PUT", json=["bad"])
    assert response.status_code == 400


def test_case_database_failure_after_parsing_is_not_success(client, monkeypatch):
    from backend import app as module

    connections = iter([True, False])
    monkeypatch.setattr(module, "check_connection", lambda: next(connections))
    monkeypatch.setattr(
        module,
        "get_db",
        lambda: SimpleNamespace(cases=SimpleNamespace(find_one=lambda *a: {"id": "synthetic"})),
    )
    response = client.post(
        "/api/ingest",
        data={
            "caseId": "synthetic",
            "kind": "file",
            "file": (io.BytesIO(b"FileName\na.txt\n"), "synthetic.csv"),
        },
    )
    assert response.status_code == 503
    assert response.json["error"]["code"] == "DB_UNAVAILABLE"


def test_legacy_demo_cases_keep_provenance_warning():
    from backend.app import _case_response

    record = {"id": "CASE-2026-0147"}
    assert _case_response(record)["dataMode"] == "demo"
    assert "dataMode" not in record
    assert _case_response({"id": "synthetic-live"})["dataMode"] == "live"


def test_optional_provider_config_is_scoped_to_application(monkeypatch):
    from forensics import threat_intel

    first = create_app({"OTX_API_KEY": "synthetic"})
    second = create_app()
    monkeypatch.setattr(threat_intel, "_REQUESTS_OK", True)
    with first.app_context():
        assert threat_intel.providers_available()["otx"] is True
    with second.app_context():
        assert threat_intel.providers_available()["otx"] is False


def test_pdf_generator_handles_minimal_synthetic_case():
    from backend.report_generator import generate_case_report

    result = generate_case_report(
        {
            "id": "SYNTHETIC-ONLY",
            "title": "Synthetic investigation",
            "status": "INGESTING",
            "severity": "LOW",
            "counts": {},
            "findings": [],
            "activity": [],
            "evidence": {"sources": [], "pending": []},
        }
    )
    assert result.startswith(b"%PDF-")
    assert b"%%EOF" in result[-64:]
