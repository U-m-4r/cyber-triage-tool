"""Validated, secret-free startup configuration; tests fail closed."""

import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationError(ValueError):
    """A safe configuration error; messages must never contain secret values."""


def boolean(value):
    if isinstance(value, bool):
        return value
    value = str(value).strip().lower()
    if value not in {"0", "1", "false", "true", "no", "yes"}:
        raise ConfigurationError("Boolean settings require true/false or 1/0.")
    return value in {"1", "true", "yes"}


def validate_config(config):
    for key in ("TESTING", "DEBUG", "SUPERVISED_DETECTOR_ENABLED"):
        if key in config and not isinstance(config[key], bool):
            raise ConfigurationError(f"{key} must be a boolean.")
    if config["APP_ENV"] not in {"development", "production", "test"}:
        raise ConfigurationError("APP_ENV must be development, production or test.")
    if config["DB_MODE"] not in {"disabled", "mongo"}:
        raise ConfigurationError("DB_MODE must be disabled or mongo.")
    testing = config["TESTING"] or "pytest" in sys.modules
    if testing:
        if not config["TESTING"] or config["APP_ENV"] != "test":
            raise ConfigurationError("Tests must use APP_ENV=test and TESTING=true.")
        if not re.fullmatch(r"cyber_triage_test_[0-9a-f]{32}", config["MONGO_DB"]):
            raise ConfigurationError("Tests require an owned cyber_triage_test_<uuid> database.")
        if config["DB_MODE"] == "mongo" and config["MONGO_URI"] not in {
            "mongodb://127.0.0.1:27018",
            "mongodb://localhost:27018",
        }:
            raise ConfigurationError(
                "Test MongoDB must be loopback on dedicated port 27018, without credentials or options."
            )
    elif config["APP_ENV"] == "test":
        raise ConfigurationError("APP_ENV=test requires TESTING=true.")
    if not config["MONGO_DB"] or any(c in config["MONGO_DB"] for c in '/\\. "$'):
        raise ConfigurationError("MONGO_DB is not a valid database name.")
    if config["DB_MODE"] == "mongo" and not config["MONGO_URI"].startswith(("mongodb://", "mongodb+srv://")):
        raise ConfigurationError("MONGO_URI must use a MongoDB scheme.")
    if config["APP_ENV"] == "production":
        if not config["API_TOKEN"] or config["DEBUG"]:
            raise ConfigurationError("Production requires an API token and debug disabled.")
        if "*" in config["CORS_ORIGINS"]:
            raise ConfigurationError("Production requires explicit CORS_ALLOWED_ORIGINS.")
    for key in ("MAX_CONTENT_LENGTH", "MONGO_TIMEOUT_MS"):
        if not isinstance(config[key], int) or isinstance(config[key], bool) or config[key] <= 0:
            raise ConfigurationError(f"{key} must be a positive integer.")


def load_config(overrides=None):
    overrides = overrides or {}
    testing = (
        "pytest" in sys.modules
        or boolean(os.getenv("CYBER_TRIAGE_TESTING", "false"))
        or boolean(overrides.get("TESTING", False))
    )
    # Never read local credentials or investigation settings into a test process.
    if not testing:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env", override=False)
    config = {
        "APP_ENV": "test" if testing else os.getenv("APP_ENV", "development"),
        "TESTING": testing,
        "DEBUG": False if testing else boolean(os.getenv("FLASK_DEBUG", "false")),
        "DB_MODE": "disabled" if testing else os.getenv("DB_MODE", "mongo"),
        "MONGO_URI": "" if testing else os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017"),
        "MONGO_DB": "cyber_triage_test_" + "0" * 32 if testing else os.getenv("MONGO_DB", "cyber_triage"),
        "MONGO_TIMEOUT_MS": 1500,
        "API_TOKEN": "" if testing else os.getenv("CYBER_TRIAGE_API_TOKEN", "").strip(),
        "OTX_API_KEY": "" if testing else os.getenv("OTX_API_KEY", "").strip(),
        "VT_API_KEY": "" if testing else os.getenv("VT_API_KEY", "").strip(),
        "CORS_ORIGINS": (
            os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
            if not testing
            else []
        ),
        "MAX_CONTENT_LENGTH": 128 * 1024 * 1024,
        "TEMP_DIR": str(ROOT / (".test-artifacts/uploads" if testing else "temp")),
        "MODEL_PATH": str(ROOT / "models/cicids2017_baseline.joblib"),
        "SUPERVISED_MODEL_PATH": str(ROOT / "models/supervised_binary.joblib"),
        "SUPERVISED_DETECTOR_ENABLED": boolean(os.getenv("SUPERVISED_DETECTOR_ENABLED", "false")),
        "ATTACK_FAMILY_MODEL_PATH": os.getenv(
            "ATTACK_FAMILY_MODEL_PATH", str(ROOT / "models/attack_family_bundle.joblib")
        ),
    }
    if not testing:
        for key in ("MAX_CONTENT_LENGTH", "MONGO_TIMEOUT_MS"):
            try:
                config[key] = int(os.getenv(key, str(config[key])))
            except ValueError:
                raise ConfigurationError(f"{key} must be a positive integer.") from None
    config.update(overrides)
    config["CORS_ORIGINS"] = [origin.strip() for origin in config["CORS_ORIGINS"] if origin.strip()]
    validate_config(config)
    return config
