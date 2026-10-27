"""Structured triage-signal contract and deterministic recommendation engine.

This module implements the multi-signal cyber triage assessment for human-in-the-loop
investigations:
1. Binary detection (supervised or unsupervised attack determination)
2. Attack-family attribution (conditional attribution with uncertainty/abstention)
3. Anomaly detection (Isolation Forest anomaly score & decision)
4. Forensic evidence (YARA rules, EVTX/registry parser outputs, heuristics)
5. Data quality tracking (missing features, non-finite values, schema defects)
6. Structured explanation with explicit links to supporting signals
7. Deterministic, configurable provisional recommendation (never an automated verdict)
8. Analyst review metadata container (initially unset for human verification)

CRITICAL PRINCIPLES:
- The system never treats model outputs as proof of compromise.
- Binary detection is NEVER overridden by family attribution.
- BENIGN traffic is never labeled as a confirmed attack family.
- Missing signals are represented as UNAVAILABLE or NOT_EVALUATED, never as negative.
- Model scores are never combined into arbitrary pseudo-probabilities.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


# Signal statuses
STATUS_EVALUATED = "EVALUATED"
STATUS_ATTRIBUTED = "ATTRIBUTED"
STATUS_ABSTAINED = "ABSTAINED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_NOT_EVALUATED = "NOT_EVALUATED"

# Recommendation Priorities
PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH = "HIGH"
PRIORITY_MEDIUM = "MEDIUM"
PRIORITY_LOW = "LOW"

# Recommended Actions
ACTION_IMMEDIATE_TRIAGE = "RECOMMEND_IMMEDIATE_TRIAGE"
ACTION_INVESTIGATION = "RECOMMEND_INVESTIGATION"
ACTION_MONITOR = "RECOMMEND_MONITOR"
ACTION_DISMISS = "RECOMMEND_DISMISS"

# Analyst Review Statuses
REVIEW_PENDING = "PENDING_REVIEW"
REVIEW_CONFIRMED = "CONFIRMED_ATTACK"
REVIEW_FALSE_POSITIVE = "FALSE_POSITIVE"
REVIEW_DISMISSED = "DISMISSED"
REVIEW_ESCALATED = "ESCALATED"


def build_binary_signal(
    decision: Optional[str] = None,
    score: Optional[float] = None,
    threshold: Optional[float] = None,
    detector_id: str = "isolation_forest_baseline",
    model_metadata: Optional[Dict[str, Any]] = None,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct the binary detection signal contract."""
    if status is None:
        status = STATUS_EVALUATED if decision is not None else STATUS_NOT_EVALUATED

    return {
        "status": status,
        "detector_id": detector_id,
        "decision": decision,  # 'ATTACK', 'BENIGN', or None
        "continuous_score": round(float(score), 4) if score is not None else None,
        "threshold": round(float(threshold), 4) if threshold is not None else None,
        "calibrated": False,
        "model_metadata": model_metadata or {},
    }


def build_attack_family_signal(
    attribution_result: Optional[Dict[str, Any]] = None,
    binary_decision: Optional[str] = None,
    force_evaluation: bool = False,
) -> Dict[str, Any]:
    """Construct the attack-family attribution signal contract.

    Enforces the rule that family attribution is conditional on an ATTACK finding
    unless explicitly forced for suspicious artifact review.
    """
    if attribution_result is None:
        return {
            "status": STATUS_UNAVAILABLE,
            "predicted_family": None,
            "confidence": None,
            "calibrated": False,
            "ranked_candidates": [],
            "raw_scores": {},
            "confidence_semantics": "uncalibrated_class_probability_estimate",
            "abstention_reason": "Attribution model was not evaluated or unavailable",
            "model_metadata": {},
            "condition": "conditional_on_attack",
        }

    # If traffic is evaluated as BENIGN and attribution wasn't explicitly forced,
    # we fail safe: do NOT present an attack family as confirmed.
    if binary_decision == "BENIGN" and not force_evaluation:
        return {
            "status": STATUS_NOT_APPLICABLE,
            "predicted_family": None,
            "confidence": None,
            "calibrated": False,
            "ranked_candidates": [],
            "raw_scores": {},
            "confidence_semantics": "uncalibrated_class_probability_estimate",
            "abstention_reason": "Traffic was classified as BENIGN by primary detector; family attribution not applicable",
            "model_metadata": attribution_result.get("model_metadata", {}),
            "condition": "conditional_on_attack",
        }

    return {
        "status": attribution_result.get("status", STATUS_ATTRIBUTED),
        "predicted_family": attribution_result.get("predicted_family"),
        "confidence": attribution_result.get("confidence"),
        "calibrated": False,
        "margin": attribution_result.get("margin"),
        "ranked_candidates": attribution_result.get("ranked_candidates", []),
        "raw_scores": attribution_result.get("raw_scores", {}),
        "confidence_semantics": "uncalibrated_class_probability_estimate",
        "abstention_reason": attribution_result.get("abstention_reason"),
        "model_metadata": attribution_result.get("model_metadata", {}),
        "condition": "conditional_on_attack",
    }


def build_anomaly_signal(
    is_anomaly: Optional[bool] = None,
    decision_score: Optional[float] = None,
    normalized_score: Optional[float] = None,
    detector_id: str = "isolation_forest",
    model_metadata: Optional[Dict[str, Any]] = None,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct the independent anomaly detection signal contract."""
    if status is None:
        status = STATUS_EVALUATED if decision_score is not None else STATUS_NOT_EVALUATED

    return {
        "status": status,
        "detector_id": detector_id,
        "is_anomaly": is_anomaly,
        "raw_decision_score": round(float(decision_score), 4) if decision_score is not None else None,
        "normalized_score": round(float(normalized_score), 2) if normalized_score is not None else None,
        "score_semantics": "higher_normalized_is_more_anomalous_0_to_100",
        "model_metadata": model_metadata or {},
    }


def build_forensic_signal(
    findings: Optional[List[Dict[str, Any]]] = None,
    matched_rules: Optional[List[str]] = None,
    yara_matches: Optional[List[str]] = None,
    evidence_sources: Optional[List[str]] = None,
    rule_score: Optional[float] = None,
) -> Dict[str, Any]:
    """Construct the forensic evidence signal contract."""
    findings = findings or []
    matched_rules = matched_rules or []
    yara_matches = yara_matches or []
    evidence_sources = evidence_sources or []

    has_content = bool(findings or matched_rules or yara_matches or evidence_sources or rule_score is not None)
    status = STATUS_EVALUATED if has_content else "NO_EVIDENCE"

    return {
        "status": status,
        "findings_count": len(findings),
        "matched_rules": matched_rules,
        "yara_matches": yara_matches,
        "evidence_sources": evidence_sources,
        "rule_score": round(float(rule_score), 2) if rule_score is not None else 0.0,
    }


def build_data_quality_signal(
    missing_inputs: Optional[List[str]] = None,
    non_finite_dropped: int = 0,
    schema_warnings: Optional[List[str]] = None,
    limitations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Construct data quality & limitation report."""
    missing_inputs = missing_inputs or []
    schema_warnings = schema_warnings or []
    limitations = limitations or []

    if missing_inputs or non_finite_dropped > 0:
        quality_status = "ISSUES_DETECTED"
    elif schema_warnings:
        quality_status = "DEGRADED"
    else:
        quality_status = "VALID"

    return {
        "status": quality_status,
        "missing_inputs": missing_inputs,
        "non_finite_dropped": int(non_finite_dropped),
        "schema_warnings": schema_warnings,
        "limitations": limitations,
    }


def evaluate_triage_signals(
    binary_signal: Optional[Dict[str, Any]] = None,
    anomaly_signal: Optional[Dict[str, Any]] = None,
    attack_family_signal: Optional[Dict[str, Any]] = None,
    forensic_signal: Optional[Dict[str, Any]] = None,
    data_quality_signal: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate all independent signals and generate an explained triage synthesis.

    Parameters
    ----------
    binary_signal : dict, optional
    anomaly_signal : dict, optional
    attack_family_signal : dict, optional
    forensic_signal : dict, optional
    data_quality_signal : dict, optional
    context : dict, optional (case metadata, host IP, etc.)

    Returns
    -------
    dict
        Structured triage assessment document.
    """
    binary = binary_signal or build_binary_signal(status=STATUS_NOT_EVALUATED)
    anomaly = anomaly_signal or build_anomaly_signal(status=STATUS_NOT_EVALUATED)
    family = attack_family_signal or build_attack_family_signal(attribution_result=None)
    forensic = forensic_signal or build_forensic_signal()
    quality = data_quality_signal or build_data_quality_signal()

    # Generate explanations
    reasons: List[Dict[str, str]] = []
    contributing_factors: List[str] = []

    # 1. Binary Detector contribution
    if binary.get("status") == STATUS_EVALUATED:
        decision = binary.get("decision")
        score = binary.get("continuous_score")
        thresh = binary.get("threshold")
        if decision == "ATTACK":
            msg = f"Binary detector '{binary.get('detector_id')}' flagged traffic as ATTACK (score: {score}, threshold: {thresh})"
            reasons.append({"source": "binary_detection", "finding": "Attack traffic detected", "detail": msg})
            contributing_factors.append("primary_binary_detector_attack")
        elif decision == "BENIGN":
            msg = f"Binary detector '{binary.get('detector_id')}' classified traffic as BENIGN (score: {score})"
            reasons.append({"source": "binary_detection", "finding": "Normal traffic pattern", "detail": msg})
    elif binary.get("status") == STATUS_UNAVAILABLE:
        reasons.append({"source": "binary_detection", "finding": "Detector unavailable", "detail": "Primary binary detector was unavailable during analysis"})

    # 2. Anomaly Detector contribution
    if anomaly.get("status") == STATUS_EVALUATED:
        is_ano = anomaly.get("is_anomaly")
        norm_score = anomaly.get("normalized_score")
        if is_ano:
            msg = f"Isolation Forest identified statistical outlier (normalized anomaly score: {norm_score}/100)"
            reasons.append({"source": "anomaly_detection", "finding": "Statistical anomaly detected", "detail": msg})
            contributing_factors.append("isolation_forest_anomaly")
        elif norm_score is not None and norm_score >= 50.0:
            msg = f"Elevated anomaly score: {norm_score}/100 (below strict outlier threshold)"
            reasons.append({"source": "anomaly_detection", "finding": "Elevated anomaly score", "detail": msg})
    elif anomaly.get("status") == STATUS_UNAVAILABLE:
        reasons.append({"source": "anomaly_detection", "finding": "Detector unavailable", "detail": "Isolation Forest model was unavailable"})

    # 3. Attack Family Attribution contribution
    fam_status = family.get("status")
    if fam_status == STATUS_ATTRIBUTED:
        pred_fam = family.get("predicted_family")
        conf = family.get("confidence")
        msg = f"Attack family classifier attributed traffic to '{pred_fam}' with confidence {conf:.4f} (uncalibrated)"
        reasons.append({"source": "attack_family", "finding": f"Likely family: {pred_fam}", "detail": msg})
        contributing_factors.append(f"attack_family_{pred_fam.lower().replace(' ', '_')}")
    elif fam_status == STATUS_ABSTAINED:
        reason = family.get("abstention_reason", "Uncertain attribution")
        reasons.append({"source": "attack_family", "finding": "Attribution abstained", "detail": reason})
        contributing_factors.append("attack_family_abstained")
    elif fam_status == STATUS_NOT_APPLICABLE:
        reasons.append({"source": "attack_family", "finding": "Not applicable", "detail": "Primary detector marked traffic as BENIGN; attribution omitted"})

    # 4. Forensic Evidence contribution
    rules = forensic.get("matched_rules", [])
    yara = forensic.get("yara_matches", [])
    rule_score = forensic.get("rule_score", 0.0)
    if yara:
        reasons.append({"source": "forensics", "finding": f"YARA signature hit: {', '.join(yara)}", "detail": "Known malicious pattern matched via YARA"})
        contributing_factors.append("yara_rule_hit")
    if rules:
        reasons.append({"source": "forensics", "finding": f"Forensic rules triggered: {', '.join(rules)}", "detail": f"Domain heuristics fired (rule score: {rule_score}/100)"})
        contributing_factors.append("forensic_rules_triggered")

    # 5. Data Quality warnings
    for warn in quality.get("schema_warnings", []):
        reasons.append({"source": "data_quality", "finding": "Data quality warning", "detail": warn})
    if quality.get("non_finite_dropped", 0) > 0:
        reasons.append({"source": "data_quality", "finding": "Rows dropped", "detail": f"{quality['non_finite_dropped']} rows dropped due to non-finite values"})

    # -------------------------------------------------------------------------
    # Deterministic Provisional Recommendation Policy
    # -------------------------------------------------------------------------
    # The policy is explicit, documented, and deterministic:
    # Priority CRITICAL:
    #   - YARA signature match, OR
    #   - Binary ATTACK + Anomaly score >= 75 + high-impact family (DoS, DDoS, Web Attacks)
    # Priority HIGH:
    #   - Binary ATTACK, OR
    #   - Anomaly score >= 75 + forensic rule matched, OR
    #   - Attribution established with confidence >= 0.80
    # Priority MEDIUM:
    #   - Isolated anomaly score in [40, 75), OR
    #   - Forensic rules triggered without binary ATTACK, OR
    #   - Attribution abstained on anomalous traffic
    # Priority LOW:
    #   - Normal traffic, no anomalies, no forensic rules
    # -------------------------------------------------------------------------
    is_attack = binary.get("decision") == "ATTACK"
    ano_score = anomaly.get("normalized_score") or 0.0
    pred_fam = family.get("predicted_family")
    has_yara = bool(yara)
    has_rules = bool(rules)

    if has_yara or (is_attack and ano_score >= 75.0 and pred_fam in ("DoS", "DDoS", "Web Attacks")):
        priority = PRIORITY_CRITICAL
        action = ACTION_IMMEDIATE_TRIAGE
        rationale = "High-confidence compromise indicators or volumetric attack signatures require immediate analyst triage."
    elif is_attack or (ano_score >= 75.0 and has_rules) or (pred_fam is not None and (family.get("confidence") or 0) >= 0.80):
        priority = PRIORITY_HIGH
        action = ACTION_INVESTIGATION
        rationale = "Multiple corroborating signals indicate suspicious or malicious activity warranting investigation."
    elif (ano_score >= 40.0) or has_rules or (fam_status == STATUS_ABSTAINED and ano_score >= 25.0):
        priority = PRIORITY_MEDIUM
        action = ACTION_MONITOR
        rationale = "Elevated statistical or heuristic anomalies detected without conclusive attack confirmation."
    else:
        priority = PRIORITY_LOW
        action = ACTION_DISMISS
        rationale = "Signals are consistent with baseline normal activity; no evidence of compromise identified."

    recommendation = {
        "provisional_priority": priority,
        "recommended_action": action,
        "rationale": rationale,
        "contributing_factors": contributing_factors,
        "is_automated_verdict": False,
        "disclaimer": (
            "This is a provisional triage recommendation generated by deterministic policy rules. "
            "It does not constitute proof of compromise. The human analyst retains final authority "
            "to confirm, override, escalate, or dismiss."
        ),
    }

    # Analyst Review Container (initially unset)
    analyst_review = {
        "status": REVIEW_PENDING,
        "analyst_assessment": None,
        "analyst_decision": None,
        "reviewed_by": None,
        "reviewed_at": None,
        "analyst_notes": None,
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "signals": {
            "binary_detection": binary,
            "anomaly_detection": anomaly,
            "attack_family": family,
            "forensic_evidence": forensic,
            "data_quality": quality,
        },
        "explanation": {
            "summary": rationale,
            "reasons": reasons,
        },
        "recommendation": recommendation,
        "analyst_review": analyst_review,
        "context": context or {},
    }
