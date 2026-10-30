"""Windows registry hive parsing -> RegistryKey / RegistryValue rows (PART C, item 6).

Uses python-registry (``Registry``) to walk a raw hive file (e.g. NTUSER.DAT,
SYSTEM, SOFTWARE) and emit one row per value with columns aligned to what the
rule engine expects (``RegistryKey`` / ``RegistryValue`` — see ml/risk_scorer.py):
    RegistryKey, RegistryValue, ValueType, ValueData, Timestamp

Reference: Windows registry hive structure — see B. Carrier, "File System
Forensic Analysis" and the python-registry documentation.
"""
import pandas as pd
import time

try:
    from Registry import Registry
    AVAILABLE = True
    UNAVAILABLE_REASON = None
except Exception as exc:  # pragma: no cover - only when dep missing
    Registry = None
    AVAILABLE = False
    UNAVAILABLE_REASON = f"python-registry not available: {exc}"

COLUMNS = ["RegistryKey", "RegistryValue", "ValueType", "ValueData", "Timestamp"]


def _iter_keys(key):
    """Depth-first walk over a registry key and all its subkeys."""
    stack = [key]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.subkeys()))


def _value_data_to_str(value, strict=False):
    """Best-effort string form of a value's data (bytes/lists handled safely)."""
    try:
        data = value.value()
    except Exception:
        if strict:
            raise
        return ""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, (list, tuple)):
        return ", ".join(str(x) for x in data)
    return str(data)


def parse_registry_hive(filepath, limit=None, max_seconds=60):
    """Parse a registry hive into a DataFrame of key/value rows.

    ``limit`` optionally caps the number of value rows emitted. Raises
    RuntimeError if python-registry is unavailable.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)

    reg = Registry.Registry(filepath)
    rows, failures = [], 0
    started = time.monotonic()
    def result(truncated=False):
        frame = pd.DataFrame(rows, columns=COLUMNS + ['artifact_type', 'record_id'])
        frame.attrs['parsing'] = {'status':'PARTIAL' if truncated or failures else 'COMPLETED',
            'skipped':failures, 'enumeration_complete':not truncated, 'skipped_count_exact':not truncated,
            'reason':f'{failures} unreadable entries; enumeration truncated: {truncated}' if truncated or failures else None}
        return frame
    for key in _iter_keys(reg.root()):
        if time.monotonic()-started > max_seconds:
            return result(True)
        key_path = key.path()
        try:
            timestamp = key.timestamp().isoformat()
        except Exception:
            timestamp = ""
        try:
            values = key.values()
        except Exception:
            values = []
            failures += 1
        for value in values:
            if limit is not None and len(rows) >= limit:
                return result(True)
            try:
                value_name = value.name()
                value_type = value.value_type_str()
            except Exception:
                value_name, value_type = "", ""
                failures += 1
            try:
                value_data = _value_data_to_str(value, strict=True)
            except Exception:
                value_data = '[UNREADABLE VALUE DATA]'
                failures += 1
            if len(value_data) > 16384:
                value_data = value_data[:16384] + '[VALUE DATA TRUNCATED: metadata limit]'
                failures += 1
            rows.append({
                "RegistryKey": key_path,
                "RegistryValue": value_name,
                "ValueType": value_type,
                "ValueData": value_data,
                "Timestamp": timestamp,
                'artifact_type':'registry', 'record_id':len(rows),
            })

    return result()
