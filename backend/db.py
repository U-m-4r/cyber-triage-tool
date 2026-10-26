"""
MongoDB connection helper for the Cyber Triage backend.

Provides lazy application-owned connections and explicit index/demo commands.
Importing this module never connects, writes indexes or seeds investigations.
"""

import logging

from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError

logger = logging.getLogger(__name__)

class DatabaseUnavailable(RuntimeError):
    pass


def get_client():
    from flask import current_app
    from backend.config import validate_config

    validate_config(current_app.config)
    if current_app.config['DB_MODE'] == 'disabled':
        raise DatabaseUnavailable('Database access is disabled in this configuration.')
    state = current_app.extensions.setdefault('mongo', {})
    identity = (current_app.config['MONGO_URI'], current_app.config['MONGO_DB'])
    if state.get('identity') not in (None, identity):
        raise DatabaseUnavailable('Database configuration changed after connection creation.')
    if 'client' not in state:
        state['client'] = MongoClient(identity[0], connect=False,
                                     serverSelectionTimeoutMS=current_app.config['MONGO_TIMEOUT_MS'],
                                     connectTimeoutMS=current_app.config['MONGO_TIMEOUT_MS'])
        state['identity'] = identity
    return state['client']


def get_db():
    from flask import current_app
    return get_client()[current_app.config['MONGO_DB']]


def close_db(app):
    state = app.extensions.pop('mongo', {})
    if 'client' in state:
        state['client'].close()


def init_db():
    """
    Create collections and indexes on first run.

    Called explicitly by init-db or isolated integration fixtures. Index creation is
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

    logger.info("MongoDB indexes ensured on database '%s'", db.name)


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
    db.cases.insert_many([{**case, "isDemo": True} for case in SAMPLE_CASES])
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
    except (DatabaseUnavailable, PyMongoError):
        return False
