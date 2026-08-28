import os
import sys
import uuid
import hashlib
import logging
from functools import wraps
from datetime import datetime, timezone

import numpy as np  # noqa: F401  (kept for downstream numeric helpers)
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.detector import AnomalyDetector
from ml.preprocessor import ForensicPreprocessor
from ml.risk_scorer import RiskScorer
from ml.ingestion import parse_file, ParserError, PARSER_REGISTRY
from backend.db import init_db, seed_if_empty, get_db, check_connection
from backend.report_generator import generate_case_report
from evaluation.evaluate import (
    extract_binary_ground_truth,
    evaluate_predictions,
    run_split_evaluation,
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

app = Flask(__name__)

# --- Security config (cross-cutting) ------------------------------------------
# CORS is locked to an allowlist from CORS_ALLOWED_ORIGINS (comma-separated).
# Default "*" preserves the original wide-open dev behavior; set the env var to
# lock it down for any shared/demo deployment.
_cors_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "*")
_origins = "*" if _cors_origins.strip() == "*" else [o.strip() for o in _cors_origins.split(",") if o.strip()]
CORS(app, origins=_origins)

# When CYBER_TRIAGE_API_TOKEN is set, protected endpoints require a matching
# bearer token / X-API-Key. When unset, auth is disabled (dev mode) and a warning
# is logged — evidence-handling endpoints must never ship unauthenticated silently.
API_TOKEN = os.environ.get("CYBER_TRIAGE_API_TOKEN", "").strip()
DEBUG_MODE = os.environ.get("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes")

TEMP_DIR = os.path.join(ROOT_DIR, "temp")
os.makedirs(TEMP_DIR, exist_ok=True)
MODEL_PATH = os.path.join(ROOT_DIR, "models", "isolation_forest.pkl")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

preprocessor = ForensicPreprocessor()
detector = AnomalyDetector(contamination=0.1)
scorer = RiskScorer()
DETECTOR_READY = False


# ---------------------------------------------------------------------------
# MongoDB init
# ---------------------------------------------------------------------------

try:
    init_db()
    seed_if_empty()
    MONGO_AVAILABLE = True
    logger.info("MongoDB connected and initialised")
except Exception:
    MONGO_AVAILABLE = False
    logger.warning("MongoDB unavailable — API will still serve analysis endpoints")

if not API_TOKEN:
    logger.warning(
        "AUTH DISABLED: CYBER_TRIAGE_API_TOKEN is not set — evidence endpoints are "
        "open. Set it (and CORS_ALLOWED_ORIGINS) before any shared/demo deployment."
    )


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

    filepath = os.path.join(TEMP_DIR, filename)
    uploaded_file.save(filepath)

    # Chain of custody: hash the evidence immediately on intake, before any parsing.
    custody = {
        "original_filename": uploaded_file.filename,
        "algorithm": "SHA-256",  # NIST FIPS 180-4
        "sha256": compute_sha256(filepath),
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


def require_auth(view):
    """Gate an endpoint behind the shared API token when one is configured.

    No-op when CYBER_TRIAGE_API_TOKEN is unset (dev mode) so local runs and the
    existing regression tests keep working; enforced the moment a token is set.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if API_TOKEN:
            if _request_token() != API_TOKEN:
                return _api_error("Missing or invalid API token.", 401, "UNAUTHORIZED")
        return view(*args, **kwargs)
    return wrapper


def _clean_mongo_doc(doc):
    """Remove MongoDB's _id field so the doc is JSON-serialisable."""
    if doc and "_id" in doc:
        del doc["_id"]
    return doc


def _clean_mongo_docs(docs):
    return [_clean_mongo_doc(d) for d in docs]


def _extract_binary_ground_truth(df):
    """Flask wrapper: read an optional ?label_column override from the request,
    then delegate to the pure evaluation helper."""
    override = request.args.get("label_column")
    return extract_binary_ground_truth(df, override=override)


def _ensure_detector_loaded_or_trained(df_scaled):
    global DETECTOR_READY

    if DETECTOR_READY:
        return

    if os.path.exists(MODEL_PATH):
        detector.load_model(MODEL_PATH)
        DETECTOR_READY = True
        return

    detector.train(df_scaled)
    detector.save_model(MODEL_PATH)
    DETECTOR_READY = True


# ---------------------------------------------------------------------------
# Health & analysis endpoints (existing)
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "cyber-triage-backend",
        "mongo": "connected" if MONGO_AVAILABLE else "unavailable",
    })


@app.route("/api/analyze", methods=["POST"])
@require_auth
def analyze():
    """Main analysis endpoint."""
    filepath, custody, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    try:
        # run_pipeline returns (scaled, raw, clean)
        df_scaled, df_raw, df_clean = preprocessor.run_pipeline(filepath)

        _ensure_detector_loaded_or_trained(df_scaled)
        predictions, scores = detector.predict(df_scaled)
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
        response_payload = {"summary": summary, "artifacts": top_results, "evidence": custody}
        # Add metrics when a supported label column is available.
        y_true, label_column = _extract_binary_ground_truth(df_clean)
        if y_true is not None:
            response_payload["evaluation"] = {
                "label_column": label_column,
                "metrics": evaluate_predictions(y_true, predictions, scores),
            }

        # Persist analysis results to MongoDB if available
        if MONGO_AVAILABLE:
            try:
                db = get_db()
                analysis_doc = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "summary": summary,
                    "top_artifacts_count": len(top_results),
                    "evidence_custody": custody,
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
                                "confidence": 0.85,  # Mocked confidence
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
            except Exception:
                logger.exception("Failed to persist analysis results to MongoDB")

        return jsonify(response_payload)
    except Exception:
        logger.exception("Analysis request failed")
        return _api_error("Analysis failed. Please check input data and try again.", 500, "ANALYSIS_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/api/evaluate", methods=["POST"])
@require_auth
def evaluate_model():
    """
    Evaluate anomaly model using uploaded labeled dataset.
    Returns classic classification metrics for project reporting.
    """
    filepath, custody, error_response = _save_uploaded_file()
    if error_response:
        return error_response

    try:
        df_scaled, _, df_clean = preprocessor.run_pipeline(filepath)
        y_true, label_column = _extract_binary_ground_truth(df_clean)
        if y_true is None:
            return _api_error(
                "No supported label column found.",
                400,
                "MISSING_LABEL_COLUMN",
            )

        # Stratified 70/30 split + fit + evaluate (shared with scripts/run_evaluation.py).
        result = run_split_evaluation(df_scaled, y_true, detector, test_size=0.3, random_state=42)

        return jsonify(
            {
                "status": "ok",
                "label_column": label_column,
                "evidence": custody,
                "records": result["records"],
                "metrics": result["metrics"],
            }
        )
    except Exception:
        logger.exception("Evaluation request failed")
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


@app.route("/api/ingest", methods=["POST"])
@require_auth
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

        # Phase A: rule-engine scoring (anomaly component wired in Phase B once the
        # preprocessor generalizes per-type features).
        scored = scorer.score_records(records)
        summary = {
            "total_records": len(scored),
            "critical": sum(1 for a in scored if a["priority"] == "CRITICAL"),
            "high": sum(1 for a in scored if a["priority"] == "HIGH"),
            "medium": sum(1 for a in scored if a["priority"] == "MEDIUM"),
            "low": sum(1 for a in scored if a["priority"] == "LOW"),
        }

        stored = 0
        if MONGO_AVAILABLE:
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
                logger.exception("Failed to persist ingested artifacts")

        return jsonify({
            "kind": kind or "auto",
            "summary": summary,
            "stored": stored,
            "artifacts": [
                {k: v for k, v in a.items()} for a in scored[:100]
            ],
        })
    except Exception:
        logger.exception("Ingestion failed")
        return _api_error("Ingestion failed. Check the file format and kind.", 500, "INGEST_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/api/artifacts", methods=["GET"])
@require_auth
def list_artifacts():
    """Filterable artifact retrieval. Query params: type, severity, case_id (or
    caseId), from, to (ISO timestamps on ingested_at), limit (default 100)."""
    if not MONGO_AVAILABLE:
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

@app.route("/api/cases", methods=["GET"])
def list_cases():
    """List all cases."""
    if not MONGO_AVAILABLE:
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    cases = list(db.cases.find({}, {"_id": 0}).sort("threatScore", -1))
    return jsonify({"cases": cases})


@app.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    """Fetch a single case by ID."""
    if not MONGO_AVAILABLE:
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    case = db.cases.find_one({"id": case_id})
    if not case:
        return _api_error(f"Case {case_id} not found", 404, "CASE_NOT_FOUND")

    return jsonify(_clean_mongo_doc(case))


@app.route("/api/cases", methods=["POST"])
@require_auth
def create_case():
    """Create a new case."""
    if not MONGO_AVAILABLE:
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    data = request.get_json(silent=True)
    if not data:
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
    return jsonify(_clean_mongo_doc(data)), 201


@app.route("/api/cases/<case_id>", methods=["PUT"])
@require_auth
def update_case(case_id):
    """Update an existing case."""
    if not MONGO_AVAILABLE:
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    data = request.get_json(silent=True)
    if not data:
        return _api_error("Request body must be JSON", 400, "INVALID_BODY")

    db = get_db()
    # Never let the caller change the case ID
    data.pop("id", None)
    data.pop("_id", None)

    result = db.cases.update_one({"id": case_id}, {"$set": data})
    if result.matched_count == 0:
        return _api_error(f"Case {case_id} not found", 404, "CASE_NOT_FOUND")

    updated = db.cases.find_one({"id": case_id})
    return jsonify(_clean_mongo_doc(updated))


# ---------------------------------------------------------------------------
# Dashboard endpoint (NEW — MongoDB-backed)
# ---------------------------------------------------------------------------

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    """
    Return all data the dashboard needs in a single call:
    metrics, active investigations, triage summaries, and recent activity.
    """
    if not MONGO_AVAILABLE:
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

    # Triage summaries
    from backend.seed_data import TRIAGE_BY_CASE
    triage_by_case = TRIAGE_BY_CASE

    # Recent activity
    activity = list(db.activity.find({}, {"_id": 0}).sort("at", -1).limit(20))

    return jsonify({
        "metrics": metrics,
        "investigations": investigations,
        "triageSummaries": triage_by_case,
        "recentActivity": activity,
    })


# ---------------------------------------------------------------------------
# Report endpoints (NEW — ReportLab PDF generation)
# ---------------------------------------------------------------------------

@app.route("/api/report", methods=["POST"])
@require_auth
def generate_report_post():
    """Generate a PDF report for a case (POST with JSON body)."""
    data = request.get_json(silent=True)
    if not data or "caseId" not in data:
        return _api_error(
            "Request body must include 'caseId'",
            400,
            "MISSING_CASE_ID",
        )

    case_id = data["caseId"]
    return _generate_and_serve_report(case_id)


@app.route("/api/report/<case_id>", methods=["GET"])
def generate_report_get(case_id):
    """Generate and download a PDF report for a case (GET for direct download)."""
    return _generate_and_serve_report(case_id)


def _generate_and_serve_report(case_id):
    """Shared logic for both POST and GET report endpoints."""
    if not MONGO_AVAILABLE:
        return _api_error("Database not available", 503, "DB_UNAVAILABLE")

    db = get_db()
    case = db.cases.find_one({"id": case_id})
    if not case:
        return _api_error(f"Case {case_id} not found", 404, "CASE_NOT_FOUND")

    case_record = _clean_mongo_doc(case)

    try:
        pdf_bytes = generate_case_report(case_record)
    except Exception:
        logger.exception("Report generation failed for case %s", case_id)
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


@app.route("/api/reports/<case_id>", methods=["GET"])
def list_reports(case_id):
    """List previously generated reports for a case."""
    if not MONGO_AVAILABLE:
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

@app.route("/api/triage/<case_id>", methods=["GET"])
def get_triage_summary(case_id):
    """Return the triage summary for a case, or null if not yet scored."""
    from backend.seed_data import TRIAGE_BY_CASE
    summary = TRIAGE_BY_CASE.get(case_id)
    if summary is None:
        return jsonify(None)
    return jsonify(summary)


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


@app.route("/api/forensics/capabilities", methods=["GET"])
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


@app.route("/api/forensics/ingest", methods=["POST"])
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
                logger.exception("YARA scan failed")

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

        if MONGO_AVAILABLE:
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
                except Exception:
                    logger.exception("Failed to persist forensic custody to MongoDB")

        return jsonify(response_payload)
    except Exception:
        logger.exception("Forensic ingestion failed")
        return _api_error("Forensic ingestion failed. Check the file and try again.", 500, "INGEST_FAILED")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == "__main__":
    # debug defaults OFF (safe for demo/deploy); enable locally with FLASK_DEBUG=1.
    app.run(host="0.0.0.0", port=5001, debug=DEBUG_MODE)
