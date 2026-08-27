"""Forensic artifact parsers and enrichment for the triage tool (PART C).

Each submodule wraps an optional third-party dependency behind a graceful import
guard: if the library (or a needed system component) is unavailable, the module
still imports and exposes an ``AVAILABLE`` flag plus a human-readable
``UNAVAILABLE_REASON`` instead of raising at import time. Callers check
availability and degrade cleanly, so the Flask app never fails to boot because a
native forensic dependency is missing on the host.

Submodules:
  * evtx_parser     — Windows Event Log (.evtx) -> normalized DataFrame
  * registry_parser — Windows registry hive     -> RegistryKey/Value rows
  * yara_scanner    — YARA rule matching         -> IOC match records
  * threat_intel    — OTX + VirusTotal reputation lookups (env-keyed, no-op safe)
  * disk_image      — raw/E01 disk image ingestion via pytsk3
"""
