"""
Shared artifact schema + parser dispatch for the ingestion layer.

The schema column names deliberately match what `ml/risk_scorer.py` keys on so
parsed artifacts score through the existing rule engine unchanged:

  network    -> Flow Duration, Flow Packets/s, Flow Bytes/s, Packet Length Mean, ...
  system_log -> EventID, LogonType, FailedLogins, LoginHour, PrivilegeLevel
  file       -> FileName, FileExtension, FilePath, FileSizeBytes
  registry   -> RegistryKey, RegistryValue

Every normalized artifact also carries provenance fields (`artifact_type`,
`source_file`, `observed_at`) so the /api/artifacts endpoint can filter on them.
"""

import os
import importlib


class ParserError(Exception):
    """Raised when a source file cannot be parsed by any available strategy."""


class ArtifactSchema:
    """Canonical column names + the provenance columns every artifact carries."""

    PROVENANCE = ("artifact_type", "source_file", "observed_at")

    NETWORK = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
        "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Flow Bytes/s", "Flow Packets/s", "Packet Length Mean",
    ]
    SYSTEM_LOG = ["EventID", "LogonType", "FailedLogins", "LoginHour", "PrivilegeLevel"]
    FILE = ["FileName", "FileExtension", "FilePath", "FileSizeBytes"]
    REGISTRY = ["RegistryKey", "RegistryValue"]

    @classmethod
    def columns_for(cls, artifact_type):
        return {
            "network": cls.NETWORK,
            "system_log": cls.SYSTEM_LOG,
            "file": cls.FILE,
            "registry": cls.REGISTRY,
        }.get(artifact_type, [])


def optional_import(module_name):
    """Import an optional heavy dependency, returning None if it is not installed.

    Keeps the ingestion layer usable offline: a missing python-evtx / python-registry
    / pyshark simply routes the parser to its textual-export fallback instead of
    crashing at import time.
    """
    try:
        return importlib.import_module(module_name)
    except Exception:
        return None


# Populated by register_parser() as each parser module is imported below.
PARSER_REGISTRY = {}


def register_parser(kind, extensions, func):
    PARSER_REGISTRY[kind] = {"extensions": tuple(extensions), "func": func}


def _kind_from_extension(path):
    ext = os.path.splitext(path)[1].lower()
    for kind, spec in PARSER_REGISTRY.items():
        if ext in spec["extensions"]:
            return kind
    return None


def parse_file(path, kind=None):
    """Dispatch a file to the right parser and return a list of artifact dicts.

    `kind` (evtx|registry|pcap|file) forces a parser; otherwise it is sniffed from
    the file extension. Raises ParserError when no parser matches.
    """
    if not os.path.exists(path):
        raise ParserError(f"File not found: {path}")

    if kind is None:
        kind = _kind_from_extension(path)
    if kind is None or kind not in PARSER_REGISTRY:
        raise ParserError(
            f"No parser for '{os.path.basename(path)}'. "
            f"Supported kinds: {sorted(PARSER_REGISTRY)}"
        )
    return PARSER_REGISTRY[kind]["func"](path)


# Import parser modules so they self-register. Done at the bottom to avoid a
# circular import (each parser imports names from this module).
from . import evtx_parser as _evtx      # noqa: E402,F401
from . import registry_parser as _reg   # noqa: E402,F401
from . import pcap_parser as _pcap      # noqa: E402,F401
from . import file_parser as _file      # noqa: E402,F401
