"""
MongoDB connection helper for the Cyber Triage backend.

Provides connection management, database initialisation, and seed-data loading
so the dashboard and case workspace work out of the box with zero manual setup.
"""

import os
import logging

from pymongo import MongoClient, DESCENDING

logger = logging.getLogger(__name__)

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB", "cyber_triage")

_client = None
_db = None


def get_client():
    """Return (and lazily create) the singleton MongoClient."""
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client


def get_db():
    """Return the cyber_triage database handle."""
    global _db
    if _db is None:
        _db = get_client()[DB_NAME]
    return _db


def init_db():
    """
    Create collections and indexes on first run.

    Called once at app startup. Safe to call repeatedly — index creation is
    idempotent in MongoDB.
    """
    db = get_db()

    # Cases collection
    db.cases.create_index("id", unique=True)
    db.cases.create_index("status")
    db.cases.create_index("severity")
    db.cases.create_index([("threatScore", DESCENDING)])

    # Activity log
    db.activity.create_index("caseId")
    db.activity.create_index([("at", DESCENDING)])

    # Analysis results (from /api/analyze)
    db.analysis_results.create_index([("created_at", DESCENDING)])
    db.analysis_results.create_index("case_id")

    # Generated reports metadata
    db.reports.create_index("case_id")
    db.reports.create_index([("generated_at", DESCENDING)])

    # Ingested artifacts (from /api/ingest — Requirement #2)
    db.artifacts.create_index("case_id")
    db.artifacts.create_index("artifact_type")
    db.artifacts.create_index("priority")
    db.artifacts.create_index([("risk_score", DESCENDING)])
    db.artifacts.create_index([("ingested_at", DESCENDING)])

    logger.info("MongoDB indexes ensured on database '%s'", DB_NAME)


def seed_if_empty():
    """
    Populate the cases collection with the four sample records when it is empty.

    This keeps the frontend working identically to the mock-data version —
    investigators see the same cases, findings, and recommendations immediately
    after setup.
    """
    db = get_db()

    if db.cases.count_documents({}) > 0:
        logger.info("Cases collection already populated — skipping seed")
        return

    from backend.seed_data import (
        SAMPLE_CASES,
        DASHBOARD_METRICS,
        RECENT_ACTIVITY,
    )

    # Insert cases
    db.cases.insert_many(SAMPLE_CASES)
    logger.info("Seeded %d sample cases", len(SAMPLE_CASES))

    # Insert dashboard metrics (single doc, upsert pattern)
    db.dashboard.replace_one(
        {"_type": "metrics"},
        {"_type": "metrics", "metrics": DASHBOARD_METRICS},
        upsert=True,
    )

    # Insert recent activity
    if RECENT_ACTIVITY:
        db.activity.insert_many(RECENT_ACTIVITY)
        logger.info("Seeded %d activity records", len(RECENT_ACTIVITY))


def check_connection():
    """Return True if MongoDB is reachable, False otherwise."""
    try:
        get_client().admin.command("ping")
        return True
    except Exception:
        return False
