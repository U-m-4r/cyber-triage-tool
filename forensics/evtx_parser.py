"""Windows Event Log (.evtx) parsing -> normalized pandas DataFrame (PART C, item 5).

Uses python-evtx to iterate records and xmltodict to turn each record's XML into a
dict, then flattens the standard ``<System>`` block into tidy columns:
    EventID, TimeCreated, Channel, Provider, Computer, RecordID, Level

Reference: Windows Event Log schema — the ``<System>`` element carries EventID,
TimeCreated (@SystemTime), Channel, Provider (@Name) and Computer. See Microsoft
"Event Schema" (schemas.microsoft.com/win/2004/08/events/event).
"""
import pandas as pd
import time

try:
    from Evtx.Evtx import Evtx
    import xmltodict
    AVAILABLE = True
    UNAVAILABLE_REASON = None
except Exception as exc:  # pragma: no cover - only when dep missing
    Evtx = None
    xmltodict = None
    AVAILABLE = False
    UNAVAILABLE_REASON = f"python-evtx/xmltodict not available: {exc}"

COLUMNS = ["EventID", "TimeCreated", "Channel", "Provider", "Computer",
           "RecordID", "Level"]


def _text(value):
    """xmltodict yields either a scalar or a dict with '#text'; normalize to str."""
    if isinstance(value, dict):
        return str(value.get("#text", "")).strip()
    return "" if value is None else str(value).strip()


def _flatten_system(system):
    """Pull the normalized fields out of an Event/System dict."""
    provider = system.get("Provider", {})
    time_created = system.get("TimeCreated", {})
    execution = system.get("Execution", {}) or {}
    return {
        "EventID": _text(system.get("EventID")),
        "TimeCreated": (time_created or {}).get("@SystemTime", "")
        if isinstance(time_created, dict) else _text(time_created),
        "Channel": _text(system.get("Channel")),
        "Provider": (provider or {}).get("@Name", "")
        if isinstance(provider, dict) else _text(provider),
        "Computer": _text(system.get("Computer")),
        "RecordID": _text(system.get("EventRecordID")),
        "Level": _text(system.get("Level")),
    }


def parse_evtx(filepath, limit=None, max_seconds=60):
    """Parse an .evtx file into a DataFrame with the normalized COLUMNS.

    ``limit`` optionally caps the number of records read (useful for large logs).
    Raises RuntimeError if python-evtx is unavailable; malformed individual
    records are skipped rather than aborting the whole parse.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)

    rows, failed, truncated = [], 0, False
    started = time.monotonic()
    with Evtx(filepath) as log:
        for i, record in enumerate(log.records()):
            if (limit is not None and i >= limit) or time.monotonic()-started > max_seconds:
                truncated = True
                break
            try:
                parsed = xmltodict.parse(record.xml())
                system = parsed.get("Event", {}).get("System", {})
                if system:
                    row = _flatten_system(system)
                    row['artifact_type'] = 'system_log'
                    row['record_id'] = i
                    row['EventID'] = int(row['EventID'])
                    # Preserve native EventRecordID; no raw signature is mapped to it.
                    # Hour rules only apply to actual login events with timestamps.
                    if row['EventID'] in (4624, 4625) and len(row['TimeCreated']) >= 13:
                        row['LoginHour'] = int(row['TimeCreated'][11:13])
                    rows.append(row)
                else:
                    failed += 1
            except Exception:
                failed += 1
                continue

    result = pd.DataFrame(rows, columns=list(dict.fromkeys(COLUMNS + ['artifact_type', 'record_id'] +
        [key for row in rows for key in row])))
    result.attrs['parsing'] = {'status':'PARTIAL' if failed or truncated else 'COMPLETED',
        'skipped':failed, 'enumeration_complete':not truncated, 'skipped_count_exact':not truncated,
        'reason':f'{failed} malformed records; enumeration truncated: {truncated}' if failed or truncated else None}
    return result
