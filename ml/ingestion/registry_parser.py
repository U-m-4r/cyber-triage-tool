"""
Windows Registry parser -> registry artifacts.

Strategies, in order:
  1. Native hive via python-registry (guarded import; used only if installed).
  2. Textual exports: `.reg` files (regedit / `reg export`), CSV, or JSON dumps
     (e.g. RegRipper output normalized to CSV). Parsed with the standard library.

Normalizes to ArtifactSchema.REGISTRY: RegistryKey, RegistryValue. The RiskScorer
'autorun_entry' / 'suspicious_key' rules key on these two columns.
"""

import os
import csv
import json

from .base import ParserError, optional_import, register_parser


def _row(key, value, source):
    return {
        "artifact_type": "registry",
        "source_file": os.path.basename(source),
        "observed_at": "",
        "RegistryKey": key,
        "RegistryValue": value,
    }


def _parse_reg(path):
    """Parse a regedit `.reg` export: `[Key]` headers followed by "name"=value lines."""
    rows = []
    current_key = ""
    with open(path, encoding="utf-16", errors="replace") as fh:
        try:
            lines = fh.readlines()
        except UnicodeError:
            lines = []
    if not lines:  # Not UTF-16; retry as UTF-8 (some tools export ANSI/UTF-8).
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("Windows Registry Editor"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_key = line[1:-1]
            rows.append(_row(current_key, "", path))  # key itself is an artifact
        elif "=" in line and current_key:
            name, _, value = line.partition("=")
            clean_name = name.strip().strip('"')
            rows.append(_row(f"{current_key}\\{clean_name}", value.strip(), path))
    return rows


def _parse_csv(path):
    rows = []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        for r in csv.DictReader(fh):
            lc = {k.strip().lower(): (v or "") for k, v in r.items() if k}
            key = lc.get("registrykey") or lc.get("key") or lc.get("path") or ""
            value = lc.get("registryvalue") or lc.get("value") or lc.get("data") or ""
            if key:
                rows.append(_row(key, value, path))
    return rows


def _parse_json(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("keys") or data.get("entries") or [data]
    rows = []
    for e in data:
        lc = {str(k).lower(): v for k, v in e.items()}
        key = lc.get("registrykey") or lc.get("key") or lc.get("path") or ""
        value = lc.get("registryvalue") or lc.get("value") or lc.get("data") or ""
        if key:
            rows.append(_row(key, str(value), path))
    return rows


def _parse_native_hive(path):
    """Native hive via python-registry, if installed. Returns None when unavailable."""
    reg_mod = optional_import("Registry.Registry")
    if reg_mod is None:
        return None
    rows = []
    hive = reg_mod.Registry(path)

    def walk(key):
        path_str = key.path()
        for value in key.values():
            rows.append(_row(f"{path_str}\\{value.name()}", str(value.value()), path))
        for sub in key.subkeys():
            walk(sub)

    walk(hive.root())
    return rows


def parse(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".reg":
        return _parse_reg(path)
    if ext == ".csv":
        return _parse_csv(path)
    if ext == ".json":
        return _parse_json(path)
    # No recognized text extension: try a native hive, else give a clear error.
    native = _parse_native_hive(path)
    if native is not None:
        return native
    raise ParserError(
        "Native registry hive parsing needs the optional 'python-registry' package. "
        "Export with `reg export` (.reg) or provide a CSV/JSON dump and re-upload."
    )


register_parser("registry", (".reg",), parse)
