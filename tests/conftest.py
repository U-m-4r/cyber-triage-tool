"""Shared pytest fixtures and path setup for the cyber-triage-tool test suite.

Ensures the repository root is importable (so ``import ml`` / ``import backend``
work regardless of the working directory pytest is invoked from).
"""
import os
import sys

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


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
    dataset.write_bytes(open(tiny_flow_csv, 'rb').read())
    monkeypatch.setattr(trainer, 'APPROVED_DATASET_PATH', dataset)
    output = tmp_path / 'test_baseline.joblib'
    trainer.train_baseline(dataset_version='synthetic-test-fixture',
                           expected_sha256=trainer.file_sha256(dataset), output=output)
    return output, load_baseline(output)


@pytest.fixture()
def baseline_api(baseline_bundle, tmp_path, monkeypatch):
    from backend import app as app_module

    path, bundle = baseline_bundle
    monkeypatch.setattr(app_module, 'MODEL_PATH', str(path))
    monkeypatch.setattr(app_module, 'TEMP_DIR', str(tmp_path))
    monkeypatch.setattr(app_module, 'API_TOKEN', '')
    monkeypatch.setattr(app_module, 'MONGO_AVAILABLE', False)
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client(), path, bundle
