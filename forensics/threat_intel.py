"""Threat-intelligence reputation lookups: OTX + VirusTotal (PART C, item 8).

Looks up file hashes / IP addresses / domains against AlienVault OTX and VirusTotal
using API keys supplied via environment variables:
    OTX_API_KEY, VT_API_KEY

If a key is unset the corresponding provider is skipped (graceful no-op) — the
tool degrades to "no intel" rather than failing. Results are folded into a single
reputation verdict that feeds the rule score via ``reputation_rule_bump``.

Uses the ``requests`` library directly (no vendor SDK) to keep dependencies light.
References: AlienVault OTX DirectConnect API; VirusTotal API v3.
"""
import os

try:
    import requests
    _REQUESTS_OK = True
except Exception as exc:  # pragma: no cover
    requests = None
    _REQUESTS_OK = False
    _REQUESTS_ERR = str(exc)

OTX_API_KEY = os.environ.get("OTX_API_KEY", "").strip()
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()

OTX_BASE = "https://otx.alienvault.com/api/v1"
VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 10


def providers_available():
    """Report which providers are configured (env key present + requests import)."""
    return {
        "requests": _REQUESTS_OK,
        "otx": bool(OTX_API_KEY) and _REQUESTS_OK,
        "virustotal": bool(VT_API_KEY) and _REQUESTS_OK,
    }


def _otx_indicator_path(indicator, kind):
    section = {"ip": "IPv4", "domain": "domain", "hash": "file"}.get(kind, kind)
    return f"{OTX_BASE}/indicators/{section}/{indicator}/general"


def lookup_otx(indicator, kind="hash"):
    """Query OTX for an indicator. Returns a dict, or None if unavailable/no key."""
    if not (_REQUESTS_OK and OTX_API_KEY):
        return None
    try:
        resp = requests.get(
            _otx_indicator_path(indicator, kind),
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return {"provider": "otx", "error": f"HTTP {resp.status_code}"}
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        return {
            "provider": "otx",
            "indicator": indicator,
            "pulse_count": int(pulses),
            "malicious": int(pulses) > 0,
        }
    except Exception as exc:  # pragma: no cover - network dependent
        return {"provider": "otx", "error": str(exc)}


def _vt_indicator_path(indicator, kind):
    section = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(kind, "files")
    return f"{VT_BASE}/{section}/{indicator}"


def lookup_virustotal(indicator, kind="hash"):
    """Query VirusTotal v3 for an indicator. Returns a dict, or None if no key."""
    if not (_REQUESTS_OK and VT_API_KEY):
        return None
    try:
        resp = requests.get(
            _vt_indicator_path(indicator, kind),
            headers={"x-apikey": VT_API_KEY},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return {"provider": "virustotal", "error": f"HTTP {resp.status_code}"}
        stats = (resp.json().get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        malicious = int(stats.get("malicious", 0))
        return {
            "provider": "virustotal",
            "indicator": indicator,
            "malicious_count": malicious,
            "suspicious_count": int(stats.get("suspicious", 0)),
            "malicious": malicious > 0,
        }
    except Exception as exc:  # pragma: no cover - network dependent
        return {"provider": "virustotal", "error": str(exc)}


def check_indicator(indicator, kind="hash"):
    """Look the indicator up in every configured provider; aggregate a verdict.

    Returns ``{indicator, kind, providers: [...], malicious: bool}``. With no keys
    configured, ``providers`` is empty and ``malicious`` is False (no-op safe).
    """
    results = []
    for result in (lookup_otx(indicator, kind), lookup_virustotal(indicator, kind)):
        if result is not None:
            results.append(result)
    malicious = any(r.get("malicious") for r in results)
    return {
        "indicator": indicator,
        "kind": kind,
        "providers": results,
        "malicious": malicious,
    }


def reputation_rule_bump(verdict, weight=1.0):
    """Translate a check_indicator verdict into a rule-score contribution (0..weight).

    A malicious verdict from any provider returns ``weight`` (default 1.0, the
    per-row rule-score ceiling in ml/risk_scorer.py); otherwise 0.0. Lets threat
    intel meaningfully raise an artifact's risk without overriding it.
    """
    return float(weight) if verdict and verdict.get("malicious") else 0.0
