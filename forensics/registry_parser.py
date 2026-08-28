"""Windows registry hive parsing -> RegistryKey / RegistryValue rows (PART C, item 6).

Uses python-registry (``Registry``) to walk a raw hive file (e.g. NTUSER.DAT,
SYSTEM, SOFTWARE) and emit one row per value with columns aligned to what the
rule engine expects (``RegistryKey`` / ``RegistryValue`` — see ml/risk_scorer.py):
    RegistryKey, RegistryValue, ValueType, ValueData, Timestamp

Reference: Windows registry hive structure — see B. Carrier, "File System
Forensic Analysis" and the python-registry documentation.
"""
import pandas as pd

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
    yield key
    for subkey in key.subkeys():
        yield from _iter_keys(subkey)


def _value_data_to_str(value):
    """Best-effort string form of a value's data (bytes/lists handled safely)."""
    try:
        data = value.value()
    except Exception:
        return ""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, (list, tuple)):
        return ", ".join(str(x) for x in data)
    return str(data)


def parse_registry_hive(filepath, limit=None):
    """Parse a registry hive into a DataFrame of key/value rows.

    ``limit`` optionally caps the number of value rows emitted. Raises
    RuntimeError if python-registry is unavailable.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)

    reg = Registry.Registry(filepath)
    rows = []
    for key in _iter_keys(reg.root()):
        key_path = key.path()
        try:
            timestamp = key.timestamp().isoformat()
        except Exception:
            timestamp = ""
        try:
            values = key.values()
        except Exception:
            values = []
        for value in values:
            try:
                value_name = value.name()
                value_type = value.value_type_str()
            except Exception:
                value_name, value_type = "", ""
            rows.append({
                "RegistryKey": key_path,
                "RegistryValue": value_name,
                "ValueType": value_type,
                "ValueData": _value_data_to_str(value),
                "Timestamp": timestamp,
            })
            if limit is not None and len(rows) >= limit:
                return pd.DataFrame(rows, columns=COLUMNS)

    return pd.DataFrame(rows, columns=COLUMNS)
