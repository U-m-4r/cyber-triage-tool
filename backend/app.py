import os
import sys
import uuid
import hashlib
import hmac
import logging
import tempfile
from datetime import datetime, timezone

import numpy as np  # noqa: F401  (kept for downstream numeric helpers)
from flask import Blueprint, Flask, current_app, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from pymongo.errors import PyMongoError

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd
from ml.baseline import (BASELINE_PATH, BaselineError, load_baseline,
                         infer_network, infer_network_csv, baseline_metadata)
from ml.preprocessor import NetworkInputError
from ml.risk_scorer import RiskScorer
from ml.ingestion import parse_file, ParserError, PARSER_REGISTRY
from backend.db import init_db, seed_if_empty, get_db, check_connection, close_db, DatabaseUnavailable
from backend.config import load_config
from backend.report_generator import generate_case_report
from evaluation.evaluate import (
    extract_binary_ground_truth,
    evaluate_predictions,
)
# PART C forensic parsers. Each self-guards its optional native dependency and
# exposes an ``AVAILABLE`` flag, so importing the package never breaks app boot.
from forensics import (
    evtx_parser,
    registry_parser,
    yara_scanner,
    disk_image,
    threat_intel,
)

api = Blueprint("api", __name__)
logger = logging.getLogger(__name__)
scorer = RiskScorer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming read to bound memory on large images


def compute_sha256(filepath):
    """Compute the SHA-256 digest of a file for chain-of-custody integrity.

    The file is opened strictly read-only ("rb") and read in fixed-size chunks so
    the original evidence is never modified and arbitrarily large images do not have
    to be loaded into memory at once. SHA-256 is the cryptographic hash mandated by
    NIST FIPS 180-4 (Secure Hash Standard); a matching digest on re-read proves the
    evidence has not been altered since intake.
    """
    digest = hashlib.sha256()
    with open(filepath, "rb") as handle:  # read-only: source evidence stays immutable
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _save_uploaded_file():
    if "file" not in request.files:
        return None, None, (jsonify({"error": "No file uploaded"}), 400)

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return None, None, (jsonify({"error": "Uploaded filename is empty"}), 400)

    # Sanitize incoming filename before writing to disk.
    safe_name = secure_filename(uploaded_file.filename)
    ext = os.path.splitext(uploaded_file.filename)[1].lower() or ".csv"
    if safe_name:
        filename = f"{uuid.uuid4().hex}_{safe_name}"
    else:
        filename = f"{uuid.uuid4().hex}{ext}"

    temp_dir = current_app.config["TEMP_DIR"]
    os.makedirs(temp_dir, exist_ok=True)
    fd, filepath = tempfile.mkstemp(suffix="_" + filename, dir=temp_dir)
    try:
        with os.fdopen(fd, "wb") as handle:
            uploaded_file.save(handle)
        digest = compute_sha256(filepath)
    except Exception:
        os.remove(filepath)
        raise

    # Chain of custody: hash the evidence immediately on intake, before any parsing.
    custody = {
        "original_filename": uploaded_file.filename,
        "algorithm": "SHA-256",  # NIST FIPS 180-4
        "sha256": digest,
        "size_bytes": os.path.getsize(filepath),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    return filepath, custody, None


def _api_error(message, status_code, code):
    return jsonify({"error": {"code": code, "message": message}}), status_code


def _request_token():
    """Extract a token from Authorization: Bearer <t> or the X-API-Key header."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("X-API-Key", "").strip()


def _clean_mongo_doc(doc):
    """Remove MongoDB's _id field so the doc is JSON-serialisable."""
    if doc and "_id" in doc:
        del doc["_id"]
    return doc


def _clean_mongo_docs(docs):
    return [_clean_mongo_doc(d) for d in docs]


def _is_demo_case(case):
    # Preserve the warning on legacy auto-seeded records, without rewriting user data.
    return bool(case.get("isDemo")) or case.get("id") in {
        "CASE-2026-0147", "CASE-2026-0143", "CASE-2026-0139", "CASE-2026-0136"
    }


def _case_response(case):
    result = _clean_mongo_doc(dict(case))
    result["dataMode"] = "demo" if _is_demo_case(case) else "live"
    return result


def _intake_database_available():
    available = check_connection()
    if not available and request.form.get("caseId"):
        raise DatabaseUnavailable("Case database became unavailable during processing.")
    return available


def _extract_binary_ground_truth(df):
    """Flask wrapper: read an optional ?label_column override from the request,
    then delegate to the pure evaluation helper."""
    override = request.args.get("label_column")
    return extract_binary_ground_truth(df, override=override)


def _network_csv_inference(filepath):
    # Request data can never choose the baseline path or invoke fitting. Loading
    # one complete bundle per request also avoids mutable shared estimators and
    # ensures a removed/invalid artifact cannot be served from a stale cache.
    bundle = load_baseline(current_app.config.get('MODEL_PATH'))
    return bundle, infer_network_csv(filepath, bundle)


# ---------------------------------------------------------------------------
# Health & analysis endpoints (existing)
# ---------------------------------------------------------------------------

@api.route("/api/health", methods=["GET"])
def health():
    """Liveness stays 200; readiness and component state are explicit."""
    components = _readiness()
    return jsonify({"status": "ok", "service": "cyber-triage-backend", **components})


def _readiness():
    try:
        load_baseline(current_app.config["MODEL_PATH"])
        baseline_status = {"status": "ready"}
    except BaselineError as exc:
        baseline_status = {"status": "unavailable", "code": exc.code}
    database_ready = check_connection()
    return {
        "ready": database_ready and baseline_status["status"] == "ready",
        "mongo": "connected" if database_ready else "unavailable",
        "network_baseline": baseline_status,
    }


@api.route("/api/ready", methods=["GET"])
def readiness():
    components = _readiness()
    return jsonify(components), 200 if components["ready"] else 503


@api.route("/api/analyze", methods=["POST"])
def analyze():
    """Main analysis endpoint."""
    filepath, custody, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    try:
        bundle, (df_clean, predictions, scores, preprocessing, drift) = _network_csv_inference(filepath)
        results_df = scorer.score_dataframe(df_clean, scores)

        top_results = results_df.head(100).to_dict(orient="records")
        summary = {
            "total_records": int(len(results_df)),
            "critical": int((results_df["priority"] == "CRITICAL").sum()),
            "high": int((results_df["priority"] == "HIGH").sum()),
            "medium": int((results_df["priority"] == "MEDIUM").sum()),
            "low": int((results_df["priority"] == "LOW").sum()),
        }

        # Chain-of-custody digest is returned so the investigator can verify the
        # exact evidence file that produced these results (NIST FIPS 180-4).
        response_payload = {"summary": summary, "artifacts": top_results, "evidence": custody,
                            "baseline": baseline_metadata(bundle), "preprocessing": preprocessing,
                            "drift": drift}
        # Add metrics when a supported label column is available.
        y_true, label_column = _extract_binary_ground_truth(df_clean)
        if y_true is not None:
            response_payload["evaluation"] = {
                "label_column": label_column,
                "metrics": evaluate_predictions(y_true, predictions, scores),
            }

        # Persist analysis results to MongoDB if available
        response_payload["persisted"] = False
        if _intake_database_available():
            try:
                db = get_db()
                analysis_doc = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "summary": summary,
                    "top_artifacts_count": len(top_results),
                    "evidence_custody": custody,
                    "baseline": baseline_metadata(bundle),
                    "preprocessing": preprocessing,
                    "drift": drift,
                }

                case_id = request.form.get("caseId")
                if case_id:
                    analysis_doc["case_id"] = case_id

                    case = db.cases.find_one({"id": case_id})
                    if case:
                        # Map top results to findings schema
                        new_findings = []
                        for artifact in top_results:
                            new_findings.append({
                                "id": f"F-{uuid.uuid4().hex[:6].upper()}",
                                "title": f"Anomaly: {artifact.get('Source IP', 'Unknown')}:{artifact.get('Source Port', '')} \u2192 {artifact.get('Destination IP', 'Unknown')}:{artifact.get('Destination Port', '')}",
                                "severity": artifact.get("priority", "LOW"),
                                "riskScore": artifact.get("risk_score", 0),
                                "confidence": None,  # No calibrated confidence is available.
                                "source": "Uploaded Dataset",
                                "host": str(artifact.get("Source IP", "Unknown")),
                                "observedAt": datetime.now(timezone.utc).isoformat(),
                                "technique": {"id": "N/A", "name": "Anomaly Detected"},
                                "rationale": f"Anomaly score: {artifact.get('anomaly_score', 0):.2f}, Rule score: {artifact.get('rule_score', 0)}",
                                "artifactType": "network",
                                "reviewed": False,
                            })
                        
                        # Update case findings and counts
                        existing_findings = case.get("findings", [])
                        updated_findings = new_findings + existing_findings # Newest first
                        
                        counts = case.get("counts", {"evidence": 0, "artifacts": 0, "iocs": 0, "criticalFindings": 0})
                        counts["artifacts"] = counts.get("artifacts", 0) + len(df_clean)
                        counts["criticalFindings"] = len([f for f in updated_findings if f.get("severity") == "CRITICAL"])
                        
                        # Calculate a new threat score based on highest risk finding
                        threat_score = case.get("threatScore", 0)
                        if new_findings:
                            highest_risk = max([f.get("riskScore", 0) for f in new_findings])
                            if highest_risk > threat_score:
                                threat_score = highest_risk
                        
                        # Determine severity based on threat score
                        severity = "LOW"
                        if threat_score >= 75: severity = "CRITICAL"
                        elif threat_score >= 50: severity = "HIGH"
                        elif threat_score >= 25: severity = "MEDIUM"
                        
                        # Chain-of-custody ledger: append this evidence intake
                        # record (filename + SHA-256 + timestamp) to the case.
                        custody_chain = case.get("custody", [])
                        custody_chain = [custody] + custody_chain

                        db.cases.update_one(
                            {"id": case_id},
                            {"$set": {
                                "findings": updated_findings,
                                "counts": counts,
                                "custody": custody_chain,
                                "threatScore": threat_score,
                                "severity": severity,
                                "status": "ANALYZING" if case.get("status") == "INGESTING" else case.get("status")
                            }}
                        )

                db.analysis_results.insert_one(analysis_doc)
                response_payload["persisted"] = True
            except Exception:
                logger.error("Failed to persist analysis results")
                return _api_error("Analysis persistence was not confirmed.", 503, "PERSISTENCE_FAILED")

        return jsonify(response_payload)
    except BaselineError as exc:
        return _api_error(str(exc), 503, exc.code)
    except NetworkInputError as exc:
        return _api_error(str(exc), 400, exc.code)
    except DatabaseUnavailable:
        return _api_error("Case database became unavailable.", 503, "DB_UNAVAILABLE")
    except Exception:
        logger.error("Analysis request failed")
        return _api_error("Analysis failed. Please check input data and try again.", 500, "ANALYSIS_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@api.route("/api/evaluate", methods=["POST"])
def evaluate_model():
    """
    Evaluate the fixed approved baseline on uploaded labeled network evidence.
    No train/test split or fitting is permitted in an upload handler.
    """
    filepath, custody, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    try:
        bundle, (df_clean, predictions, scores, preprocessing, drift) = _network_csv_inference(filepath)
        y_true, label_column = _extract_binary_ground_truth(df_clean)
        if y_true is None:
            return _api_error(
                "No supported label column found.",
                400,
                "MISSING_LABEL_COLUMN",
            )

        return jsonify(
            {
                "status": "ok",
                "label_column": label_column,
                "evidence": custody,
                "records": {"total": len(df_clean), "train": 0, "test": len(df_clean)},
                "metrics": evaluate_predictions(y_true, predictions, scores),
                "evaluation_mode": "fixed_baseline",
                "baseline": baseline_metadata(bundle),
                "preprocessing": preprocessing,
                "drift": drift,
            }
        )
    except BaselineError as exc:
        return _api_error(str(exc), 503, exc.code)
    except NetworkInputError as exc:
        return _api_error(str(exc), 400, exc.code)
    except Exception:
        logger.error("Evaluation request failed")
        return _api_error("Evaluation failed. Please verify your labeled dataset.", 500, "EVALUATION_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


# ---------------------------------------------------------------------------
# Ingestion & artifacts endpoints (NEW — Requirement #2)
# ---------------------------------------------------------------------------

def _persist_artifacts(db, scored, case_id, source_name, kind):
    """Store scored artifacts in the `artifacts` collection and return their docs."""
    now = datetime.now(timezone.utc).isoformat()
    docs = []
    for art in scored:
        doc = dict(art)
        doc["artifact_id"] = f"ART-{uuid.uuid4().hex[:10].upper()}"
        doc["case_id"] = case_id
        doc["source_kind"] = kind
        doc["ingested_at"] = now
        docs.append(doc)
    if docs:
        db.artifacts.insert_many(docs)
    return docs


@api.route("/api/ingest", methods=["POST"])
def ingest():
    """Parse a forensic source (log / registry / pcap / file listing), score the
    artifacts, and persist them. Form fields: `file` (required), `kind`
    (evtx|registry|pcap|file, optional — sniffed from extension otherwise),
    `caseId` (optional — links artifacts to a case and updates its counts)."""
    filepath, custody, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    kind = (request.form.get("kind") or "").strip().lower() or None
    case_id = request.form.get("caseId")
    try:
        try:
            records = parse_file(filepath, kind=kind)
        except ParserError as exc:
            return _api_error(str(exc), 400, "PARSE_FAILED")

        network_metadata = {}
        if kind == 'pcap' or any(r.get('artifact_type') == 'network' for r in records):
            bundle = load_baseline(current_app.config.get('MODEL_PATH'))
            clean, _, scores, preprocessing, drift = infer_network(pd.DataFrame(records), bundle)
            scored = scorer.score_records(clean.to_dict(orient='records'), scores)
            network_metadata = {'baseline': baseline_metadata(bundle),
                                'preprocessing': preprocessing, 'drift': drift}
        else:
            # Host artifacts keep their source-specific rules; the CICIDS model
            # cannot be applied to event IDs, registry values, or file metadata.
            scored = scorer.score_records(records)
        summary = {
            "total_records": len(scored),
            "critical": sum(1 for a in scored if a["priority"] == "CRITICAL"),
            "high": sum(1 for a in scored if a["priority"] == "HIGH"),
            "medium": sum(1 for a in scored if a["priority"] == "MEDIUM"),
            "low": sum(1 for a in scored if a["priority"] == "LOW"),
        }

        stored = 0
        if _intake_database_available():
            try:
                db = get_db()
                source_name = secure_filename(os.path.basename(filepath))
                docs = _persist_artifacts(db, scored, case_id, source_name, kind)
                stored = len(docs)
                if case_id:
                    case = db.cases.find_one({"id": case_id})
                    if case:
                        counts = case.get("counts", {})
                        counts["artifacts"] = counts.get("artifacts", 0) + len(scored)
                        db.cases.update_one({"id": case_id}, {"$set": {"counts": counts}})
            except Exception:
                logger.error("Failed to persist ingested artifacts")
                return _api_error("Artifact persistence was not confirmed.", 503, "PERSISTENCE_FAILED")

        return jsonify({
            "kind": kind or "auto",
            "summary": summary,
            "stored": stored,
            "artifacts": [
                {k: v for k, v in a.items()} for a in scored[:100]
            ],
            "evidence": custody,
            **network_metadata,
        })
    except BaselineError as exc:
        return _api_error(str(exc), 503, exc.code)
    except NetworkInputError as exc:
        return _api_error(str(exc), 400, exc.code)
    except DatabaseUnavailable:
        return _api_error("Case database became unavailable.", 503, "DB_UNAVAILABLE")
    except Exception:
        logger.error("Ingestion failed")
        return _api_error("Ingestion failed. Check the file format and kind.", 500, "INGEST_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@api.route("/api/artifacts", methods=["GET"])
def list_artifacts():
    """Filterable artifact retrieval. Query params: type, severity, case_id (or
    caseId), from, to (ISO timestamps on ingested_at), limit (default 100)."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    query = {}
    artifact_type = request.args.get("type")
    if artifact_type:
        query["artifact_type"] = artifact_type
    severity = request.args.get("severity")
    if severity:
        query["priority"] = severity.upper()
    case_id = request.args.get("case_id") or request.args.get("caseId")
    if case_id:
        query["case_id"] = case_id

    time_filter = {}
    if request.args.get("from"):
        time_filter["$gte"] = request.args.get("from")
    if request.args.get("to"):
        time_filter["$lte"] = request.args.get("to")
    if time_filter:
        query["ingested_at"] = time_filter

    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    except ValueError:
        limit = 100

    db = get_db()
    total = db.artifacts.count_documents(query)
    artifacts = list(
        db.artifacts.find(query, {"_id": 0})
        .sort("risk_score", -1)
        .limit(limit)
    )
    return jsonify({"total": total, "returned": len(artifacts), "artifacts": artifacts})


# ---------------------------------------------------------------------------
# Case endpoints (NEW — MongoDB-backed)
# ---------------------------------------------------------------------------

@api.route("/api/cases", methods=["GET"])
def list_cases():
    """List all cases."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    cases = list(db.cases.find({}, {"_id": 0}).sort("threatScore", -1))
    return jsonify({"cases": [_case_response(case) for case in cases]})


@api.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    """Fetch a single case by ID."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    case = db.cases.find_one({"id": case_id})
    if not case:
        return _api_error(f"Case {case_id} not found", 404, "CASE_NOT_FOUND")

    return jsonify(_case_response(case))


@api.route("/api/cases", methods=["POST"])
def create_case():
    """Create a new case."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return _api_error("Request body must be JSON", 400, "INVALID_BODY")

    # Auto-generate an ID if not provided
    if "id" not in data:
        seq = get_db().counters.find_one_and_update(
            {"_id": "case_seq"},
            {"$inc": {"seq": 1}},
            upsert=True,
            return_document=True,
        )
        data["id"] = f"CASE-{datetime.now().year}-{seq['seq']:04d}"

    data.setdefault("status", "INGESTING")
    data.setdefault("progress", 0)
    data.setdefault("threatScore", 0)
    data.setdefault("severity", "LOW")
    data.setdefault("openedAt", datetime.now(timezone.utc).isoformat())
    data.setdefault("counts", {"evidence": 0, "artifacts": 0, "iocs": 0, "criticalFindings": 0})
    data.setdefault("findings", [])
    data.setdefault("activity", [])

    db = get_db()
    db.cases.insert_one(data)
    return jsonify(_case_response(data)), 201


@api.route("/api/cases/<case_id>", methods=["PUT"])
def update_case(case_id):
    """Update an existing case."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return _api_error("Request body must be JSON", 400, "INVALID_BODY")

    db = get_db()
    # Never let the caller change the case ID
    data.pop("id", None)
    data.pop("_id", None)

    result = db.cases.update_one({"id": case_id}, {"$set": data})
    if result.matched_count == 0:
        return _api_error(f"Case {case_id} not found", 404, "CASE_NOT_FOUND")

    updated = db.cases.find_one({"id": case_id})
    return jsonify(_case_response(updated))


# ---------------------------------------------------------------------------
# Dashboard endpoint (NEW — MongoDB-backed)
# ---------------------------------------------------------------------------

@api.route("/api/dashboard", methods=["GET"])
def dashboard():
    """
    Return all data the dashboard needs in a single call:
    metrics, active investigations, triage summaries, and recent activity.
    """
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()

    # Metrics
    metrics_doc = db.dashboard.find_one({"_type": "metrics"})
    metrics = metrics_doc.get("metrics", []) if metrics_doc else []

    # Active investigations (top-level case list for the dashboard)
    cases = list(db.cases.find({}, {"_id": 0}).sort("threatScore", -1))
    investigations = []
    for c in cases:
        investigations.append({
            "id": c.get("id"),
            "title": c.get("title"),
            "threatScore": c.get("threatScore"),
            "severity": c.get("severity"),
            "status": c.get("status"),
            "progress": c.get("progress"),
            "examiner": c.get("examiner"),
            "openedAt": c.get("openedAt"),
            "lastActivity": c.get("lastActivity", {}).get("relative", ""),
            "evidence": c.get("evidence", {}).get("sources", []),
            "artifacts": c.get("counts", {}).get("artifacts", 0),
            "criticalFindings": c.get("counts", {}).get("criticalFindings", 0),
            "iocHits": c.get("counts", {}).get("iocs", 0),
            "primaryHost": c.get("primaryHost"),
        })

    # Authored demo summaries are available only in the explicit demo database.
    triage_by_case = {}
    if current_app.config["MONGO_DB"] == "cyber_triage_demo":
        from backend.seed_data import TRIAGE_BY_CASE
        triage_by_case = TRIAGE_BY_CASE

    # Recent activity
    activity = list(db.activity.find({}, {"_id": 0}).sort("at", -1).limit(20))

    return jsonify({
        "metrics": metrics,
        "investigations": investigations,
        "triageSummaries": triage_by_case,
        "recentActivity": activity,
        "dataMode": "demo" if current_app.config["MONGO_DB"] == "cyber_triage_demo" else ("mixed" if any(_is_demo_case(c) for c in cases) else "live"),
    })


# ---------------------------------------------------------------------------
# Report endpoints (NEW — ReportLab PDF generation)
# ---------------------------------------------------------------------------

@api.route("/api/report", methods=["POST"])
def generate_report_post():
    """Generate a PDF report for a case (POST with JSON body)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("caseId"), str) or not data["caseId"]:
        return _api_error(
            "Request body must include 'caseId'",
            400,
            "MISSING_CASE_ID",
        )

    case_id = data["caseId"]
    return _generate_and_serve_report(case_id)


@api.route("/api/report/<case_id>", methods=["GET"])
def generate_report_get(case_id):
    """Generate and download a PDF report for a case (GET for direct download)."""
    return _generate_and_serve_report(case_id)


def _generate_and_serve_report(case_id):
    """Shared logic for both POST and GET report endpoints."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    case = db.cases.find_one({"id": case_id})
    if not case:
        return _api_error(f"Case {case_id} not found", 404, "CASE_NOT_FOUND")

    case_record = _clean_mongo_doc(case)

    try:
        pdf_bytes = generate_case_report(case_record)
    except Exception:
        logger.error("Report generation failed for case %s", case_id)
        return _api_error(
            "Report generation failed. Please try again.",
            500,
            "REPORT_FAILED",
        )

    # Record the report generation in MongoDB
    try:
        db.reports.insert_one({
            "case_id": case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "size_bytes": len(pdf_bytes),
        })
    except Exception:
        logger.warning("Failed to record report metadata")
        return _api_error("Report history could not be saved.", 503, "PERSISTENCE_FAILED")

    # Serve the PDF
    import io
    pdf_buffer = io.BytesIO(pdf_bytes)
    filename = f"CyberTriage_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@api.route("/api/reports/<case_id>", methods=["GET"])
def list_reports(case_id):
    """List previously generated reports for a case."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    reports = list(
        db.reports.find({"case_id": case_id}, {"_id": 0})
        .sort("generated_at", -1)
        .limit(20)
    )
    return jsonify({"reports": reports})


# ---------------------------------------------------------------------------
# Triage endpoint (NEW — serves triage summaries per case)
# ---------------------------------------------------------------------------

@api.route("/api/triage/<case_id>", methods=["GET"])
def get_triage_summary(case_id):
    """Return the triage summary for a case, or null if not yet scored."""
    if not check_connection():
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")
    if current_app.config["MONGO_DB"] == "cyber_triage_demo":
        from backend.seed_data import TRIAGE_BY_CASE
        return jsonify(TRIAGE_BY_CASE.get(case_id))
    return jsonify(None)


# ---------------------------------------------------------------------------
# PART C — forensic artifact ingestion (EVTX / registry / disk image / YARA IOC)
# ---------------------------------------------------------------------------

# Map file extension -> (parser callable, human artifact label). Registry hives
# are extension-less on disk (SYSTEM, NTUSER.DAT); ".dat"/".hiv" cover exports.
_DISK_EXTS = {".dd", ".raw", ".img", ".e01", ".001"}
_REGISTRY_EXTS = {".dat", ".hiv", ".hive", ".reg"}


def _dispatch_forensic_parser(filepath, ext):
    """Return (kind, DataFrame) for a supported forensic file, or (None, None)."""
    if ext == ".evtx":
        return "evtx", evtx_parser.parse_evtx(filepath)
    if ext in _REGISTRY_EXTS:
        return "registry", registry_parser.parse_registry_hive(filepath)
    if ext in _DISK_EXTS:
        return "disk_image", disk_image.ingest_disk_image(filepath)
    return None, None


@api.route("/api/forensics/capabilities", methods=["GET"])
def forensics_capabilities():
    """Report which optional forensic parsers/providers are available on this host.

    The frontend uses this to enable/disable ingestion options rather than letting
    an upload fail on a missing native dependency.
    """
    return jsonify({
        "evtx": {"available": evtx_parser.AVAILABLE, "reason": evtx_parser.UNAVAILABLE_REASON},
        "registry": {"available": registry_parser.AVAILABLE, "reason": registry_parser.UNAVAILABLE_REASON},
        "yara": {"available": yara_scanner.AVAILABLE, "reason": yara_scanner.UNAVAILABLE_REASON},
        "disk_image": {"available": disk_image.AVAILABLE, "reason": disk_image.UNAVAILABLE_REASON},
        "threat_intel": threat_intel.providers_available(),
    })


@api.route("/api/forensics/ingest", methods=["POST"])
def forensics_ingest():
    """Ingest a non-network forensic artifact (EVTX / registry hive / disk image).

    Hashes the evidence on intake (chain of custody, NIST FIPS 180-4), parses it
    into normalized records, scores those records with the rule engine, and runs
    YARA over the raw file to surface IOCs. The heavy ML anomaly detector is only
    meaningful for numeric network flows, so parsed host artifacts are scored by
    the domain rules (see ml/risk_scorer.py) which already model system_log / file
    / registry artifact types.
    """
    filepath, custody, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    ext = os.path.splitext(custody["original_filename"])[1].lower()
    try:
        try:
            kind, df = _dispatch_forensic_parser(filepath, ext)
        except RuntimeError as exc:
            # Parser's optional dependency is unavailable on this host.
            return _api_error(str(exc), 503, "PARSER_UNAVAILABLE")

        if kind is None:
            return _api_error(
                f"Unsupported forensic file type '{ext}'. Supported: .evtx, "
                "registry hive (.dat/.hiv/.reg), disk image (.dd/.raw/.img/.e01).",
                400, "UNSUPPORTED_FILE_TYPE",
            )

        records = df.head(500).to_dict(orient="records")

        # Rule-based scoring over the parsed records (no ML anomaly component).
        scored = []
        for i, row in enumerate(df.to_dict(orient="records")):
            artifact_type = scorer.detect_artifact_type(row)
            rule_score, matched = scorer.apply_rules(row, artifact_type)
            risk = scorer.compute_risk_score(0.0, rule_score)
            if matched:
                scored.append({
                    "record_id": i,
                    "artifact_type": artifact_type,
                    "rule_score": round(rule_score * 100, 2),
                    "risk_score": risk,
                    "priority": scorer.assign_priority(risk),
                    "matched_rules": ", ".join(matched),
                })
        scored.sort(key=lambda r: r["risk_score"], reverse=True)

        # IOC surfacing: YARA-scan the raw evidence file if the engine is present.
        iocs = []
        if yara_scanner.AVAILABLE:
            try:
                iocs = yara_scanner.scan_file(filepath)
            except Exception:
                logger.error("YARA scan failed")

        # Optional threat-intel enrichment on the evidence file hash (no-op w/o keys).
        intel = threat_intel.check_indicator(custody["sha256"], kind="hash")

        response_payload = {
            "kind": kind,
            "record_count": int(len(df)),
            "columns": list(df.columns),
            "records": records,
            "flagged_artifacts": scored[:100],
            "iocs": iocs,
            "threat_intel": intel,
            "evidence": custody,
        }

        response_payload["custody_persisted"] = False
        if _intake_database_available():
            case_id = request.form.get("caseId")
            if case_id:
                try:
                    db = get_db()
                    case = db.cases.find_one({"id": case_id})
                    if case:
                        custody_chain = [custody] + case.get("custody", [])
                        db.cases.update_one(
                            {"id": case_id},
                            {"$set": {"custody": custody_chain}},
                        )
                        response_payload["custody_persisted"] = True
                except Exception:
                    logger.error("Failed to persist forensic custody")
                    return _api_error("Custody persistence was not confirmed.", 503, "PERSISTENCE_FAILED")

        return jsonify(response_payload)
    except DatabaseUnavailable:
        return _api_error("Case database became unavailable.", 503, "DB_UNAVAILABLE")
    except Exception:
        logger.error("Forensic ingestion failed")
        return _api_error("Forensic ingestion failed. Check the file and try again.", 500, "INGEST_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


def create_app(config=None):
    """Build an application without network access, schema writes or demo seeding."""
    application = Flask(__name__)
    application.config.update(load_config(config))
    CORS(application, origins=application.config["CORS_ORIGINS"])
    application.register_blueprint(api)

    @application.before_request
    def protect_api():
        # One policy also covers routes added later. Health checks expose no case data.
        if request.path.startswith("/api/") and request.path not in {
            "/api/health", "/api/ready", "/api/forensics/capabilities"
        } and request.method != "OPTIONS":
            token = current_app.config["API_TOKEN"]
            if token and not hmac.compare_digest(_request_token().encode(), token.encode()):
                return _api_error("Missing or invalid API token.", 401, "UNAUTHORIZED")
        if request.path in {"/api/analyze", "/api/ingest", "/api/forensics/ingest"} and request.method == "POST":
            case_id = request.form.get("caseId")
            if case_id:
                if not check_connection():
                    return _api_error("Case intake requires an available database.", 503, "DB_UNAVAILABLE")
                if not get_db().cases.find_one({"id": case_id}, {"_id": 1}):
                    return _api_error("Case not found.", 404, "CASE_NOT_FOUND")

    @application.errorhandler(PyMongoError)
    @application.errorhandler(DatabaseUnavailable)
    def database_error(error):
        logger.warning("Database operation failed (%s)", type(error).__name__)
        return _api_error("Database unavailable; the operation was not confirmed.", 503, "DB_UNAVAILABLE")

    @application.errorhandler(HTTPException)
    def http_error(error):
        return _api_error(error.name, error.code, f"HTTP_{error.code}")

    @application.errorhandler(Exception)
    def unexpected_error(error):
        logger.error("Request failed (%s)", type(error).__name__)
        return _api_error("Request failed. Check server diagnostics.", 500, "INTERNAL_ERROR")

    @application.cli.command("check-config")
    def check_config_command():
        """Validate configuration without connecting to services or printing secrets."""
        import click
        click.echo(f"Configuration valid: environment={application.config['APP_ENV']}, "
                   f"database={application.config['DB_MODE']}, "
                   f"auth={'enabled' if application.config['API_TOKEN'] else 'disabled'}")

    @application.cli.command("init-db")
    def init_database_command():
        """Explicitly create indexes; never insert sample investigations."""
        import click
        try:
            init_db()
            click.echo("Database indexes initialized.")
        except (PyMongoError, DatabaseUnavailable):
            raise click.ClickException("Database unavailable; check configuration and service.") from None
        finally:
            close_db(application)

    @application.cli.command("seed-demo")
    def seed_demo_command():
        """Seed only the explicit, separate cyber_triage_demo database."""
        import click
        if application.config["APP_ENV"] != "development" or application.config["MONGO_DB"] != "cyber_triage_demo":
            raise click.ClickException("Demo seeding requires development and MONGO_DB=cyber_triage_demo.")
        try:
            init_db()
            seed_if_empty()
            click.echo("Demo database seeded if empty.")
        except (PyMongoError, DatabaseUnavailable):
            raise click.ClickException("Demo database unavailable.") from None
        finally:
            close_db(application)

    return application


# Keep the existing WSGI entry point and imports compatible; construction is inert.
app = create_app()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting Cyber Triage: environment=%s, database=%s, auth=%s",
                app.config["APP_ENV"], app.config["DB_MODE"], bool(app.config["API_TOKEN"]))
    try:
        app.run(host="127.0.0.1", port=5001, debug=app.config["DEBUG"])
    finally:
        close_db(app)
