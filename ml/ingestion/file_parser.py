"""
Filesystem-listing parser -> file artifacts.

Consumes a CSV or JSON listing of files (e.g. an MFT export, `dir /s`, `ls -lR`
normalized to CSV, or a disk-image file inventory) and normalizes it to
ArtifactSchema.FILE: FileName, FileExtension, FilePath, FileSizeBytes. The
RiskScorer 'executable_in_temp' / 'large_file_created' / 'hidden_file' rules key
on these columns.
"""

import os
import csv
import json

from .base import ParserError, register_parser


def _row(name, path_str, size, source):
    ext = os.path.splitext(name)[1].lower()
    return {
        "artifact_type": "file",
        "source_file": os.path.basename(source),
        "observed_at": "",
        "FileName": name,
        "FileExtension": ext,
        "FilePath": path_str,
        "FileSizeBytes": size,
    }


def _int(v):
    try:
        return int(float(str(v).strip()))
    except (ValueError, TypeError):
        return 0


def _from_record(lc, source):
    path_str = lc.get("filepath") or lc.get("path") or lc.get("fullpath") or ""
    name = lc.get("filename") or lc.get("name") or os.path.basename(path_str)
    size = _int(lc.get("filesizebytes") or lc.get("size") or lc.get("bytes"))
    if not (name or path_str):
        return None
    return _row(name, path_str or name, size, source)


def _parse_csv(path):
    rows = []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        for r in csv.DictReader(fh):
            lc = {k.strip().lower(): (v or "") for k, v in r.items() if k}
            row = _from_record(lc, path)
            if row:
                rows.append(row)
    return rows


def _parse_json(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("files") or data.get("entries") or [data]
    rows = []
    for e in data:
        lc = {str(k).lower(): v for k, v in e.items()}
        row = _from_record(lc, path)
        if row:
            rows.append(row)
    return rows


def parse(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return _parse_json(path)
    if ext == ".csv":
        return _parse_csv(path)
    raise ParserError("File listing must be a .csv or .json inventory.")


# Registered under 'file'; extension dispatch is ambiguous for .csv (also used by
# network/registry), so the ingest endpoint should pass kind='file' explicitly.
register_parser("file", (), parse)
