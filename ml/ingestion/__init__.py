"""
Forensic ingestion parsers (Requirement #2).

Each parser reads a forensic source (Windows Event Log, registry hive, PCAP, or a
filesystem listing) and normalizes it into the *shared artifact schema* the
RiskScorer already understands — the same column names `ml/risk_scorer.py` keys on
for each artifact type. That way parsed artifacts flow through the existing rule
engine and (after Phase B) the existing ML scorer without special-casing.

Design: offline-first. Each parser tries the real binary library (python-evtx,
python-registry, pyshark/scapy) via a guarded import. When that library is not
installed, it falls back to parsing common *textual export* formats (CSV / XML /
JSON / .reg) using only the standard library and pandas, so the pipeline is fully
testable with no extra dependencies. Real binary parsing activates automatically
once the optional library is present.
"""

from .base import (
    ArtifactSchema,
    ParserError,
    optional_import,
    parse_file,
    PARSER_REGISTRY,
)

__all__ = [
    "ArtifactSchema",
    "ParserError",
    "optional_import",
    "parse_file",
    "PARSER_REGISTRY",
]
