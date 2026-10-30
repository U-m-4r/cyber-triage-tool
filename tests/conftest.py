"""Shared pytest fixtures and path setup for the cyber-triage-tool test suite.

Ensures the repository root is importable (so ``import ml`` / ``import backend``
work regardless of the working directory pytest is invoked from).
"""
import os
import sys
import socket
import tempfile
import uuid
from pathlib import Path

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Plotting caches and pytest output stay inside this repository, never in the user profile.
os.environ["MPLCONFIGDIR"] = str(Path(ROOT_DIR) / ".test-artifacts" / "matplotlib")


def pytest_addoption(parser):
    parser.addoption("--no-training", action="store_true", default=False,
                     help="Skip tests that fit disposable models or scalers; forbid fitting in all remaining tests.")
    parser.addoption("--run-integration", action="store_true", default=False,
                     help="Require disposable loopback MongoDB on port 27018; unavailable service fails.")


def pytest_configure(config):
    # Fresh run-owned path: pytest cannot clean up somebody else's test resources.
    config.option.basetemp = str(Path(ROOT_DIR) / ".test-artifacts" / ("pytest-" + uuid.uuid4().hex))
    guard = pytest.MonkeyPatch()
    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex

    def checked(original):
        def call(sock, address):
            allowed = (config.getoption("--run-integration") and isinstance(address, tuple)
                       and address[0] in {"127.0.0.1", "::1"} and address[1] == 27018)
            if not allowed:
                raise AssertionError("Tests may not access external services or non-test databases.")
            return original(sock, address)
        return call

    guard.setattr(socket.socket, "connect", checked(connect))
    guard.setattr(socket.socket, "connect_ex", checked(connect_ex))
    resolve = socket.getaddrinfo

    def resolve_local(host, port, *args, **kwargs):
        if not (config.getoption("--run-integration") and host in {"localhost", "127.0.0.1", "::1"}
                and port == 27018):
            raise AssertionError("Tests may not resolve external service addresses.")
        return resolve(host, port, *args, **kwargs)

    def deny_datagram(*args, **kwargs):
        raise AssertionError("Tests may not send network datagrams.")

    guard.setattr(socket, "getaddrinfo", resolve_local)
    guard.setattr(socket.socket, "sendto", deny_datagram)
    config.add_cleanup(guard.undo)


def pytest_collection_modifyitems(config, items):
    if config.getoption("--no-training"):
        for item in items:
            fits = (set(item.fixturenames) & {"baseline_bundle", "baseline_api", "real_scaler"}
                    or item.name in {"test_holdout_fits_training_only_and_evaluation_refuses_tampering",
                                     "test_scale_features_is_zscore_standardization",
                                     "test_changed_training_dataset_not_published",
                                     "test_train_baseline_eligible_view_excludes_cleaned_rows"})
            if fits:
                item.add_marker(pytest.mark.skip(reason="Model/scaler fitting prohibited by --no-training"))
            if 'synthetic_attack_bundle' in item.fixturenames:
                item.add_marker(pytest.mark.skip(reason="Synthetic RandomForest/scaler fitting prohibited by --no-training"))
    if not config.getoption("--run-integration"):
        for item in items:
            if item.get_closest_marker("integration"):
                item.add_marker(pytest.mark.skip(reason="Requires --run-integration and dedicated MongoDB on port 27018"))


@pytest.fixture(autouse=True)
def prohibit_training(request, monkeypatch):
    if request.config.getoption("--no-training"):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        def forbidden(*args, **kwargs):
            raise AssertionError("Fitting is prohibited by --no-training.")

        monkeypatch.setattr(IsolationForest, "fit", forbidden)
        monkeypatch.setattr(StandardScaler, "fit", forbidden)
        monkeypatch.setattr(StandardScaler, "fit_transform", forbidden)


@pytest.fixture(autouse=True)
def isolated_app(tmp_path, monkeypatch):
    """No app globals, uploads, credentials or MongoDB clients leak between tests."""
    from backend import app as app_module
    from backend.db import close_db
    from forensics import threat_intel

    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))

    instance = app_module.create_app({
        "TESTING": True, "APP_ENV": "test", "DB_MODE": "disabled",
        "TEMP_DIR": str(tmp_path / "uploads"), "MODEL_PATH": str(tmp_path / "missing.joblib"),
    })
    monkeypatch.setattr(app_module, "app", instance)
    monkeypatch.setattr(threat_intel, "OTX_API_KEY", "")
    monkeypatch.setattr(threat_intel, "VT_API_KEY", "")
    yield instance
    close_db(instance)


@pytest.fixture()
def client(isolated_app):
    return isolated_app.test_client()


@pytest.fixture()
def mongo_app(tmp_path):
    """Own one new UUID database; refuse reuse and drop only our verified database."""
    from backend.app import create_app
    from backend.db import close_db, get_client, get_db, init_db
    from pymongo.errors import PyMongoError

    name = "cyber_triage_test_" + uuid.uuid4().hex
    app = create_app({"TESTING": True, "APP_ENV": "test", "DB_MODE": "mongo",
                      "MONGO_URI": os.getenv("TEST_MONGO_URI", "mongodb://127.0.0.1:27018"),
                      "MONGO_DB": name, "TEMP_DIR": str(tmp_path / "uploads"),
                      "MODEL_PATH": str(tmp_path / "missing.joblib")})
    owned = False
    try:
        with app.app_context():
            connection = get_client()
            try:
                connection.admin.command("ping")
            except PyMongoError:
                pytest.fail("Dedicated test MongoDB is unavailable on loopback port 27018; no integration results verified.", pytrace=False)
            if name in connection.list_database_names():
                pytest.fail("Refusing to reuse an existing database, even in the test namespace.")
            get_db().test_ownership.insert_one({"_id": name})
            owned = True
            init_db()
        yield app
    finally:
        try:
            with app.app_context():
                if owned:
                    database = get_db()
                    if database.name != name or database.test_ownership.find_one({"_id": name}) is None:
                        raise RuntimeError("Test database ownership lost; refusing cleanup.")
                    get_client().drop_database(name)
        finally:
            close_db(app)


@pytest.fixture()
def tiny_flow_csv(tmp_path):
    """A minimal CICIDS2017-shaped flow CSV usable by the preprocessing pipeline."""
    csv = tmp_path / "flows.csv"
    csv.write_text(
        "Flow Duration,Total Fwd Packets,Total Length of Fwd Packets,"
        "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,"
        "Bwd Packet Length Max,Bwd Packet Length Min,Flow Bytes/s,"
        "Flow Packets/s,Packet Length Mean,Label\n"
        "100,5,500,100,20,60,200,10,5000,50,80,BENIGN\n"
        "200,8,800,120,25,70,220,12,6000,60,90,BENIGN\n"
        "5,2,40,20,5,10,30,2,2000000,50000,5,DDoS\n"
        "300,10,1000,130,30,80,240,15,7000,70,95,BENIGN\n"
        "8,3,60,25,6,12,35,3,1500000,40000,6,PortScan\n",
        encoding="utf-8",
    )
    return str(csv)


@pytest.fixture()
def baseline_bundle(tmp_path, monkeypatch, tiny_flow_csv):
    """Synthetic unit fixture, never published at the production model path."""
    from scripts import train_baseline as trainer
    from ml.baseline import load_baseline

    dataset = tmp_path / 'cicids2017_cleaned.csv'
    dataset.write_bytes(Path(tiny_flow_csv).read_bytes())
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', dataset)
    output = tmp_path / 'test_baseline.joblib'
    trainer.train_baseline(dataset_version='synthetic-test-fixture',
                           expected_sha256=trainer.file_sha256(dataset), output=output)
    return output, load_baseline(output)


@pytest.fixture()
def baseline_api(baseline_bundle, tmp_path, monkeypatch):
    from backend import app as app_module

    path, bundle = baseline_bundle
    app_module.app.config.update(MODEL_PATH=str(path), TEMP_DIR=str(tmp_path), API_TOKEN='')
    return app_module.app.test_client(), path, bundle
