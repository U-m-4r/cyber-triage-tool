"""
Windows Event Log parser -> system_log artifacts.

Strategies, in order:
  1. Native .evtx via python-evtx (guarded import; used only if installed).
  2. Textual exports produced by `wevtutil qe`, PowerShell `Get-WinEvent | Export-*`,
     or SIEM dumps: XML, JSON, or CSV. Parsed with the standard library + pandas.

Normalizes to ArtifactSchema.SYSTEM_LOG: EventID, LogonType, FailedLogins, LoginHour,
PrivilegeLevel. FailedLogins is a per-target-account cumulative count of failed-logon
events (EventID 4625), so the RiskScorer 'high_failed_logins' rule (>5) is meaningful.
"""

import os
import re
import csv
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

from .base import ArtifactSchema, ParserError, optional_import, register_parser

# EventIDs that indicate a failed interactive/network logon (Windows Security log).
FAILED_LOGON_IDS = {4625, 529, 4771}
# Special-privileges-assigned event: treat as elevated context.
PRIV_ESCALATION_IDS = {4672, 4673, 4674}


def _login_hour(ts):
    """Return hour-of-day 0-23 from a timestamp string, or 12 (neutral) if absent."""
    if not ts:
        return 12
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
        try:
            return datetime.strptime(str(ts)[:19], fmt).hour
        except ValueError:
            continue
    m = re.search(r"[T ](\d{2}):\d{2}", str(ts))
    return int(m.group(1)) if m else 12


def _row(event_id, logon_type, failed_logins, login_hour, privilege, source, ts):
    return {
        "artifact_type": "system_log",
        "source_file": os.path.basename(source),
        "observed_at": ts or "",
        "EventID": event_id,
        "LogonType": logon_type,
        "FailedLogins": failed_logins,
        "LoginHour": login_hour,
        "PrivilegeLevel": privilege,
    }


def _finalize(records, source):
    """records: list of (event_id, logon_type, account, privilege, ts). Attach the
    cumulative failed-logon count per account and emit normalized rows."""
    failed_by_account = defaultdict(int)
    out = []
    for event_id, logon_type, account, privilege, ts in records:
        if event_id in FAILED_LOGON_IDS:
            failed_by_account[account] += 1
        out.append(_row(
            event_id, logon_type, failed_by_account[account],
            _login_hour(ts), privilege, source, ts,
        ))
    return out


def _int(val, default=0):
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return default


def _privilege_for(event_id, raw_priv=""):
    if raw_priv:
        return str(raw_priv)
    return "SYSTEM" if event_id in PRIV_ESCALATION_IDS else "USER"


def _parse_csv(path):
    records = []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            lc = {k.strip().lower(): (v or "") for k, v in r.items() if k}
            eid = _int(lc.get("eventid") or lc.get("id") or lc.get("event id"))
            ts = lc.get("timecreated") or lc.get("timegenerated") or lc.get("time") or ""
            account = lc.get("account") or lc.get("targetusername") or lc.get("user") or "-"
            logon_type = _int(lc.get("logontype") or lc.get("logon type"), default=0)
            priv = _privilege_for(eid, lc.get("privilegelevel") or lc.get("privileges", ""))
            records.append((eid, logon_type, account, priv, ts))
    return _finalize(records, path)


def _parse_json(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("events") or data.get("Events") or [data]
    records = []
    for e in data:
        lc = {str(k).lower(): v for k, v in e.items()}
        eid = _int(lc.get("eventid") or lc.get("id"))
        ts = lc.get("timecreated") or lc.get("timegenerated") or lc.get("time") or ""
        account = lc.get("account") or lc.get("targetusername") or lc.get("user") or "-"
        logon_type = _int(lc.get("logontype"), default=0)
        priv = _privilege_for(eid, lc.get("privilegelevel", ""))
        records.append((eid, logon_type, account, priv, str(ts)))
    return _finalize(records, path)


def _strip_ns(tag):
    return tag.split("}", 1)[-1]


def _parse_xml(path):
    """Parse EVTX XML export (wevtutil / Get-WinEvent -> XML)."""
    text = open(path, encoding="utf-8", errors="replace").read()
    # Wrap fragments (multiple <Event> without a single root) so ET can parse them.
    wrapped = f"<Events>{text}</Events>" if text.strip().count("<Event") > 1 and \
        not text.strip().startswith("<Events") else text
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        raise ParserError(f"Malformed Event Log XML: {exc}")

    events = [root] if _strip_ns(root.tag) == "Event" else root.iter()
    records = []
    for el in events:
        if _strip_ns(el.tag) != "Event":
            continue
        eid, ts, logon_type, account = 0, "", 0, "-"
        for child in el.iter():
            name = _strip_ns(child.tag)
            if name == "EventID":
                eid = _int(child.text)
            elif name == "TimeCreated":
                ts = child.get("SystemTime", "")
            elif name == "Data":
                dname = (child.get("Name") or "").lower()
                if dname == "logontype":
                    logon_type = _int(child.text, default=0)
                elif dname in ("targetusername", "subjectusername"):
                    account = child.text or account
        records.append((eid, logon_type, account, _privilege_for(eid), ts))
    return _finalize(records, path)


def _parse_native_evtx(path):
    """Native .evtx via python-evtx, if installed. Returns None when unavailable."""
    Evtx = optional_import("Evtx.Evtx")
    if Evtx is None:
        return None
    records = []
    with Evtx.Evtx(path) as log:
        for record in log.records():
            xml = record.xml()
            eid_m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
            ts_m = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml)
            lt_m = re.search(r'<Data Name="LogonType">(\d+)</Data>', xml)
            acct_m = re.search(r'<Data Name="TargetUserName">([^<]*)</Data>', xml)
            eid = _int(eid_m.group(1)) if eid_m else 0
            records.append((
                eid,
                _int(lt_m.group(1)) if lt_m else 0,
                acct_m.group(1) if acct_m else "-",
                _privilege_for(eid),
                ts_m.group(1) if ts_m else "",
            ))
    return _finalize(records, path)


def parse(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".evtx":
        native = _parse_native_evtx(path)
        if native is not None:
            return native
        raise ParserError(
            "Native .evtx parsing needs the optional 'python-evtx' package. "
            "Export the log to XML/CSV/JSON (wevtutil qe / Get-WinEvent) and re-upload."
        )
    if ext == ".json":
        return _parse_json(path)
    if ext == ".xml":
        return _parse_xml(path)
    if ext == ".csv":
        return _parse_csv(path)
    # Fall back to content sniffing for unknown extensions.
    head = open(path, encoding="utf-8", errors="replace").read(256).lstrip()
    if head.startswith("["):
        return _parse_json(path)
    if head.startswith("<"):
        return _parse_xml(path)
    return _parse_csv(path)


register_parser("evtx", (".evtx", ".xml", ".json"), parse)

