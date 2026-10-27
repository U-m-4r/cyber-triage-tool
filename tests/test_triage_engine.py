"""Unit and integration tests for the multi-signal triage engine and contract.

Validates:
- Multi-signal contract schema and integrity.
- Binary detection remaining authoritative (not overridden by attribution).
- BENIGN traffic never being reported as a confirmed attack family.
- Missing signals represented as UNAVAILABLE/NOT_EVALUATED, never negative findings.
- Deterministic, transparent priority recommendations.
- Analyst review container remaining distinct, pending, and initially unset.
- /api/triage/signals endpoint integration.
"""
import pytest

from ml.triage_engine import (
    ACTION_DISMISS,
    ACTION_IMMEDIATE_TRIAGE,
    ACTION_INVESTIGATION,
    ACTION_MONITOR,
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    REVIEW_PENDING,
    STATUS_ABSTAINED,
    STATUS_ATTRIBUTED,
    STATUS_EVALUATED,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_EVALUATED,
    STATUS_UNAVAILABLE,
    build_anomaly_signal,
    build_attack_family_signal,
    build_binary_signal,
    build_data_quality_signal,
    build_forensic_signal,
    evaluate_triage_signals,
)


def test_triage_signal_contract_schema():
    """Verify all top-level contract keys and sub-signal structures."""
    result = evaluate_triage_signals()

    assert "generated_at" in result
    assert "signals" in result
    assert "explanation" in result
    assert "recommendation" in result
    assert "analyst_review" in result

    signals = result["signals"]
    assert "binary_detection" in signals
    assert "anomaly_detection" in signals
    assert "attack_family" in signals
    assert "forensic_evidence" in signals
    assert "data_quality" in signals


def test_binary_attack_not_overridden_when_family_abstains():
    """If family attribution is abstained or fails, binary ATTACK verdict remains ATTACK."""
    binary = build_binary_signal(decision="ATTACK", score=0.88, threshold=0.50)
    family = build_attack_family_signal(
        attribution_result={
            "status": STATUS_ABSTAINED,
            "predicted_family": None,
            "abstention_reason": "Low confidence",
        },
        binary_decision="ATTACK",
    )

    triage = evaluate_triage_signals(binary_signal=binary, attack_family_signal=family)

    # Binary signal must remain ATTACK
    assert triage["signals"]["binary_detection"]["decision"] == "ATTACK"
    assert triage["signals"]["attack_family"]["status"] == STATUS_ABSTAINED
    # Priority is still at least HIGH because of binary ATTACK
    assert triage["recommendation"]["provisional_priority"] in (PRIORITY_HIGH, PRIORITY_CRITICAL)


def test_benign_traffic_never_reported_as_confirmed_attack_family():
    """When traffic is classified as BENIGN, family attribution is marked NOT_APPLICABLE."""
    binary = build_binary_signal(decision="BENIGN", score=0.12, threshold=0.50)
    # Even if family classifier produced an attribution, the triage engine enforces
    # that BENIGN traffic cannot have a confirmed attack family unless forced.
    family = build_attack_family_signal(
        attribution_result={
            "status": STATUS_ATTRIBUTED,
            "predicted_family": "DoS",
            "confidence": 0.95,
        },
        binary_decision="BENIGN",
        force_evaluation=False,
    )

    triage = evaluate_triage_signals(binary_signal=binary, attack_family_signal=family)

    assert triage["signals"]["attack_family"]["status"] == STATUS_NOT_APPLICABLE
    assert triage["signals"]["attack_family"]["predicted_family"] is None
    assert triage["recommendation"]["provisional_priority"] == PRIORITY_LOW


def test_missing_signals_represented_as_unavailable():
    """Missing signals must be marked UNAVAILABLE or NOT_EVALUATED, never negative."""
    binary = build_binary_signal(status=STATUS_UNAVAILABLE, detector_id="xgboost_binary")
    anomaly = build_anomaly_signal(status=STATUS_UNAVAILABLE)
    family = build_attack_family_signal(attribution_result=None)

    triage = evaluate_triage_signals(
        binary_signal=binary, anomaly_signal=anomaly, attack_family_signal=family
    )

    assert triage["signals"]["binary_detection"]["status"] == STATUS_UNAVAILABLE
    assert triage["signals"]["binary_detection"]["decision"] is None
    assert triage["signals"]["anomaly_detection"]["status"] == STATUS_UNAVAILABLE
    assert triage["signals"]["anomaly_detection"]["is_anomaly"] is None
    assert triage["signals"]["attack_family"]["status"] == STATUS_UNAVAILABLE
    assert triage["signals"]["attack_family"]["predicted_family"] is None


def test_deterministic_priority_recommendations():
    """Test policy rules for priority assignment."""
    # 1. YARA match -> CRITICAL
    forensic_yara = build_forensic_signal(yara_matches=["Ransomware_LockBit_IOC"])
    t1 = evaluate_triage_signals(forensic_signal=forensic_yara)
    assert t1["recommendation"]["provisional_priority"] == PRIORITY_CRITICAL
    assert t1["recommendation"]["recommended_action"] == ACTION_IMMEDIATE_TRIAGE

    # 2. Binary ATTACK + high anomaly + DoS -> CRITICAL
    t2 = evaluate_triage_signals(
        binary_signal=build_binary_signal(decision="ATTACK"),
        anomaly_signal=build_anomaly_signal(is_anomaly=True, normalized_score=85.0),
        attack_family_signal=build_attack_family_signal(
            {"status": STATUS_ATTRIBUTED, "predicted_family": "DoS", "confidence": 0.99},
            binary_decision="ATTACK",
        ),
    )
    assert t2["recommendation"]["provisional_priority"] == PRIORITY_CRITICAL

    # 3. Anomaly score 60 without attack -> MEDIUM
    t3 = evaluate_triage_signals(
        binary_signal=build_binary_signal(decision="BENIGN"),
        anomaly_signal=build_anomaly_signal(is_anomaly=False, normalized_score=60.0),
    )
    assert t3["recommendation"]["provisional_priority"] == PRIORITY_MEDIUM
    assert t3["recommendation"]["recommended_action"] == ACTION_MONITOR

    # 4. Clean baseline -> LOW
    t4 = evaluate_triage_signals(
        binary_signal=build_binary_signal(decision="BENIGN"),
        anomaly_signal=build_anomaly_signal(is_anomaly=False, normalized_score=10.0),
    )
    assert t4["recommendation"]["provisional_priority"] == PRIORITY_LOW
    assert t4["recommendation"]["recommended_action"] == ACTION_DISMISS


def test_analyst_review_container_separation():
    """Analyst review metadata must remain unset and distinct from model output."""
    triage = evaluate_triage_signals(
        binary_signal=build_binary_signal(decision="ATTACK"),
    )

    review = triage["analyst_review"]
    assert review["status"] == REVIEW_PENDING
    assert review["analyst_assessment"] is None
    assert review["analyst_decision"] is None
    assert review["reviewed_by"] is None
    assert review["reviewed_at"] is None

    # Model recommendation must be labeled as NOT an automated verdict
    assert triage["recommendation"]["is_automated_verdict"] is False
    assert "disclaimer" in triage["recommendation"]


def test_triage_signals_api_endpoint(client):
    """Test POST /api/triage/signals endpoint."""
    payload = {
        "binary_detection": {
            "status": "EVALUATED",
            "decision": "ATTACK",
            "continuous_score": 0.92,
            "threshold": 0.50,
        },
        "anomaly_detection": {
            "status": "EVALUATED",
            "is_anomaly": True,
            "normalized_score": 88.0,
        },
        "attack_family": {
            "status": "ATTRIBUTED",
            "predicted_family": "Web Attacks",
            "confidence": 0.97,
        },
        "forensic_evidence": {
            "matched_rules": ["High Packet Rate"],
        },
    }

    resp = client.post("/api/triage/signals", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["recommendation"]["provisional_priority"] == PRIORITY_CRITICAL
    assert len(data["explanation"]["reasons"]) >= 3
    assert data["analyst_review"]["status"] == REVIEW_PENDING
