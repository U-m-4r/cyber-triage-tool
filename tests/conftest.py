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
