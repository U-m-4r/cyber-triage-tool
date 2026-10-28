"""Persisted workspace views shared by intake and the HTTP handlers."""
import re
import uuid
from datetime import datetime, timezone

from flask import request
from werkzeug.exceptions import BadRequest

STATUSES = {"INGESTING", "ANALYZING", "REVIEW", "CLOSED"}
EDITABLE = {"title": 200, "description": 4000, "primaryHost": 200, "examiner": 200}
DEMO_IDS = ["CASE-2026-0147", "CASE-2026-0143", "CASE-2026-0139", "CASE-2026-0136"]
LIVE_CASES = {"isDemo": {"$ne": True}, "id": {"$nin": DEMO_IDS}}


def now():
    return datetime.now(timezone.utc).isoformat()


def pagination():
    try:
        limit = int(request.args.get("limit", 25))
        offset = int(request.args.get("offset", 0))
        if not 1 <= limit <= 200 or offset < 0:
            raise ValueError
    except ValueError:
        raise BadRequest("limit must be 1–200 and offset must be nonnegative.") from None
    return limit, offset


def case_query():
    query = dict(LIVE_CASES)
    for key in ("status", "severity"):
        if request.args.get(key):
            query[key] = request.args[key]
    search = request.args.get("q", "").strip()[:200]
    if search:
        query["$or"] = [{field: {"$regex": re.escape(search), "$options": "i"}}
                        for field in ("id", "title", "primaryHost", "examiner")]
    return query


def linked_case_query(field, case_id=None):
    """Exclude legacy demo-linked records even when an explicit ID is supplied."""
    query = {field: {"$nin": DEMO_IDS}}
    if case_id:
        query = {"$and": [query, {field: case_id}]}
    return query


def validated_case(data, creating=False):
    if not isinstance(data, dict) or not data:
        raise BadRequest("A JSON object is required.")
    allowed = set(EDITABLE) | {"status"} | ({"id"} if creating else set())
    if set(data) - allowed:
        raise BadRequest("Only case details and status can be edited; evidence and scores are pipeline-owned.")
    result = {}
    for key, maximum in EDITABLE.items():
        if key in data:
            if not isinstance(data[key], str) or len(data[key].strip()) > maximum:
                raise BadRequest(f"{key} must be text of at most {maximum} characters.")
            result[key] = data[key].strip()
    if (creating or "title" in data) and not result.get("title"):
        raise BadRequest("A case title is required.")
    if "status" in data:
        if not isinstance(data["status"], str) or data["status"] not in STATUSES:
            raise BadRequest("Invalid case status.")
        result["status"] = data["status"]
    if creating and "id" in data:
        if not isinstance(data["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", data["id"]):
            raise BadRequest("Invalid case ID.")
        if data["id"] in DEMO_IDS:
            raise BadRequest("This ID is reserved for legacy demo records.")
        result["id"] = data["id"]
    return result


def activity(db, case_id, message, kind="note"):
    event = {"id": "EV-" + uuid.uuid4().hex, "caseId": case_id, "message": message,
             "kind": kind, "severity": "INFO", "at": now(), "actor": "Workspace operator"}
    db.activity.insert_one(dict(event))
    db.cases.update_one({"id": case_id}, {"$set": {"lastActivity": {
        "at": event["at"], "label": message}}, "$push": {"activity": {"$each": [event], "$position": 0, "$slice": 100}}})


def finding(doc):
    rules = doc.get("matched_rules")
    label = doc.get("FilePath") or doc.get("FileName") or doc.get("RegistryKey") or doc.get("Source IP")
    if rules and rules != "None":
        title = f"{label}: {rules}" if label else rules
    else:
        title = f"{label} (No rule match)" if label else "Scored artifact; no rule match"
    rationale = f"Rule score: {doc.get('rule_score')}; anomaly score: {doc.get('anomaly_score')}"
    if doc.get("artifact_type") in ("file", "registry", "system_log"):
        rationale += " (Evaluated via domain heuristic rules; ML anomaly detector applies to network flows)"
    return {"id": doc["artifact_id"], "title": str(title),
            "severity": doc["priority"], "riskScore": doc["risk_score"], "confidence": None,
            "source": doc.get("source_file"), "host": doc.get("Computer") or doc.get("Source IP"),
            "observedAt": doc.get("Timestamp") or doc.get("observed_at") or doc["ingested_at"],
            "technique": None, "rationale": rationale,
            "artifactType": doc["artifact_type"], "reviewed": False}


def persist_intake(db, scored, case_id, custody, kind, metadata=None, iocs=None):
    """All intake paths save the same provenance and reloadable artifact schema.

    The history starts as processing and becomes complete only after every write.
    An interrupted multi-document write remains visible for reconciliation.
    """
    intake_id = "IN-" + uuid.uuid4().hex
    stamp = now()
    history = {"id": intake_id, "case_id": case_id, "kind": kind, "created_at": stamp,
               "evidence": custody, "record_count": len(scored), "status": "processing",
               **(metadata or {})}
    db.ingestions.insert_one(dict(history))
    try:
        docs = []
        for row in scored:
            docs.append({**row, "artifact_id": "ART-" + uuid.uuid4().hex,
                         "model_id": (metadata or {}).get('baseline', {}).get('provenance', {}).get('model_id'),
                         "case_id": case_id, "intake_id": intake_id, "source_kind": kind,
                         "source_file": custody["original_filename"], "ingested_at": stamp})
        if docs:
            db.artifacts.insert_many([dict(d) for d in docs])
        if case_id:
            source = {"id": intake_id, "label": custody["original_filename"], "kind": kind,
                      "size": f"{custody['size_bytes']} bytes", "acquiredAt": custody["ingested_at"],
                      "sha256": custody["sha256"], "integrity": "SHA-256 recorded",
                      "state": "PARSED", "detail": f"{len(scored)} records; original file is not retained"}
            db.cases.update_one({"id": case_id}, {"$push": {
                "custody": custody, "evidence.sources": source, "iocs": {"$each": iocs or []}},
                "$inc": {"counts.evidence": 1, "counts.artifacts": len(docs), "counts.iocs": len(iocs or [])}})
            # Summaries reflect the actual stored population, not just a response's top 100.
            bands = list(db.artifacts.aggregate([
                {"$match": {"case_id": case_id}},
                {"$group": {"_id": "$priority", "count": {"$sum": 1}, "max": {"$max": "$risk_score"}}}]))
            top = list(db.artifacts.find({"case_id": case_id}, {"_id": 0}).sort("risk_score", -1).limit(100))
            maximum = max((band["max"] for band in bands), default=None)
            severity = next((row["priority"] for row in top), "INFO")
            db.cases.update_one({"id": case_id}, {"$set": {
                "findings": [finding(d) for d in top], "threatScore": maximum, "severity": severity,
                "scoredAt": stamp, "counts.criticalFindings": sum(b["count"] for b in bands if b["_id"] == "CRITICAL"),
                "artifactPriorities": [{"severity": b["_id"], "count": b["count"]} for b in bands]}})
            activity(db, case_id, f"Ingested {custody['original_filename']}: {len(docs)} records ({kind}).", "ingest")
        db.ingestions.update_one({"id": intake_id}, {"$set": {"status": "complete", "stored": len(docs)}})
        return intake_id, len(docs)
    except Exception:
        db.ingestions.update_one({"id": intake_id}, {"$set": {"status": "failed"}})
        raise


def triage(case):
    if not case.get("scoredAt"):
        return None
    return {"caseId": case["id"], "threatScore": case.get("threatScore"), "severity": case.get("severity"),
            "confidence": None, "criticalFindings": case.get("counts", {}).get("criticalFindings", 0),
            "artifactsScored": case.get("counts", {}).get("artifacts", 0), "scoredAt": case["scoredAt"],
            "modelLabel": "Persisted artifact risk scores", "findings": case.get("findings", [])[:5],
            "recommendedAction": None}
