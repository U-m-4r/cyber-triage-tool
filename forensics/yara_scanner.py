"""YARA rule scanning -> IOC match records (PART C, item 7).

Compiles every ``*.yar`` / ``*.yara`` file under a rules directory (default:
``<repo>/rules``) and scans a target file, surfacing each match as a normalized
IOC record:
    rule, namespace, tags, target, matched_strings, meta

Reference: YARA — VirusTotal, "YARA: The pattern matching swiss knife for malware
researchers" (virustotal.github.io/yara).
"""
import os

try:
    import yara
    AVAILABLE = True
    UNAVAILABLE_REASON = None
except Exception as exc:  # pragma: no cover - only when dep missing
    yara = None
    AVAILABLE = False
    UNAVAILABLE_REASON = f"yara-python not available: {exc}"

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_RULES_DIR = os.path.join(_REPO_ROOT, "rules")


def _collect_rule_files(rules_dir):
    files = {}
    for root, _dirs, names in os.walk(rules_dir):
        for name in names:
            if name.lower().endswith((".yar", ".yara")):
                # namespace = filename stem; used to disambiguate matches.
                path = os.path.join(root, name)
                files[os.path.splitext(name)[0]] = path
    return files


def compile_rules(rules_dir=DEFAULT_RULES_DIR):
    """Compile all rule files under ``rules_dir`` into a single yara.Rules object.

    Returns None if the directory has no rule files. Raises RuntimeError if
    yara-python is unavailable or a rule fails to compile.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)
    if not os.path.isdir(rules_dir):
        return None
    filepaths = _collect_rule_files(rules_dir)
    if not filepaths:
        return None
    return yara.compile(filepaths=filepaths)


def _match_to_ioc(match, target):
    """Normalize a yara.Match into an IOC dict."""
    strings = []
    for s in getattr(match, "strings", []):
        # yara-python >=4.3 exposes StringMatch objects; older returns tuples.
        identifier = getattr(s, "identifier", None)
        if identifier is not None:
            strings.append(identifier)
        elif isinstance(s, (list, tuple)) and len(s) >= 2:
            strings.append(str(s[1]))
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": list(match.tags),
        "target": target,
        "matched_strings": sorted(set(strings)),
        "meta": dict(match.meta),
    }


def scan_file(filepath, rules_dir=DEFAULT_RULES_DIR, compiled_rules=None):
    """Scan a single file, returning a list of IOC match dicts (possibly empty).

    Pass ``compiled_rules`` to reuse a previously compiled ruleset across many
    files. Raises RuntimeError if yara-python is unavailable.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)
    rules = compiled_rules or compile_rules(rules_dir)
    if rules is None:
        return []
    matches = rules.match(filepath)
    return [_match_to_ioc(m, filepath) for m in matches]
