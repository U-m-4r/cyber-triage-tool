"""Disk-image ingestion via pytsk3 (PART C, item 9).

Opens a raw filesystem image with The Sleuth Kit bindings, walks each
filesystem, and enumerates files into a DataFrame whose columns line up with the
``file`` artifact rules in ml/risk_scorer.py:
    FileName, FilePath, FileExtension, FileSizeBytes, CreatedTime, ModifiedTime

Reference: B. Carrier, "File System Forensic Analysis" (The Sleuth Kit); pytsk3
Python bindings.
"""
import os
import pandas as pd
import hashlib
import time
from dataclasses import dataclass, asdict
from forensics import yara_scanner
from ml import pe_malware_detector
from forensics.image_reader import open_image

try:
    import pytsk3
    AVAILABLE = True
    UNAVAILABLE_REASON = None
except Exception as exc:  # pragma: no cover - only when dep missing
    pytsk3 = None
    AVAILABLE = False
    UNAVAILABLE_REASON = f"pytsk3 not available: {exc}"

COLUMNS = ["FileName", "FilePath", "FileExtension", "FileSizeBytes",
           "CreatedTime", "ModifiedTime"]


def _ts(value):
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _walk_directory(fs, directory, parent_path, rows, limit):
    for entry in directory:
        name = getattr(entry.info, "name", None)
        meta = getattr(entry.info, "meta", None)
        if name is None or name.name in (b".", b".."):
            continue
        fname = name.name.decode("utf-8", errors="replace")
        full_path = f"{parent_path}/{fname}".replace("//", "/")

        is_dir = bool(meta) and meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        if not is_dir and meta is not None:
            _, ext = os.path.splitext(fname)
            rows.append({
                "FileName": fname,
                "FilePath": full_path,
                "FileExtension": ext.lower(),
                "FileSizeBytes": int(getattr(meta, "size", 0) or 0),
                "CreatedTime": _ts(getattr(meta, "crtime", 0)),
                "ModifiedTime": _ts(getattr(meta, "mtime", 0)),
            })
            if limit is not None and len(rows) >= limit:
                return True
        elif is_dir:
            try:
                sub = entry.as_directory()
            except Exception:
                continue
            if _walk_directory(fs, sub, full_path, rows, limit):
                return True
    return False


def ingest_disk_image(filepath, limit=None):
    """Enumerate files in a raw disk image into a normalized DataFrame.

    Walks every partition that carries a filesystem. ``limit`` optionally caps the
    number of file rows. Raises RuntimeError if pytsk3 is unavailable.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)

    img = open_image(filepath, pytsk3)
    rows = []

    # Try a partition table first; fall back to treating the image as a single
    # filesystem (common for extracted single-volume images).
    filesystems = []
    try:
        volume = pytsk3.Volume_Info(img)
        for part in volume:
            if part.len > 0 and b"Unallocated" not in part.desc:
                try:
                    filesystems.append(pytsk3.FS_Info(img, offset=part.start * volume.info.block_size))
                except Exception:
                    continue
    except Exception:
        try:
            filesystems.append(pytsk3.FS_Info(img))
        except Exception as exc:
            raise RuntimeError(f"No filesystem found in image: {exc}")

    for fs in filesystems:
        try:
            root = fs.open_dir(path="/")
        except Exception:
            continue
        if _walk_directory(fs, root, "", rows, limit):
            break

    return pd.DataFrame(rows, columns=COLUMNS)


@dataclass(frozen=True)
class ScanLimits:
    max_files: int = 10000
    max_file_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_seconds: int = 120
    yara_timeout: int = 5
    max_entries: int = 20000
    max_depth: int = 64

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError('Scan limits must be positive integers')


def analyze_disk_image(filepath, limits=None, rules_dir=None, pe_options=None, yara_enabled=True):
    """Read-only raw filesystem analysis. Never scans container bytes as a file.

    Native reads are bounded in size; duration is checked between native calls.
    Findings represent default file streams, not deleted-file recovery or ADS.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)
    limits = limits or ScanLimits()
    pe_options = pe_options or {}
    pe_model = pe_malware_detector.get_model_metadata(pe_options.get('model_path'))
    started = time.monotonic()
    warnings, rows = [], []
    filesystem_details = []
    deleted_ignored = 0
    total_read = attempts = entries = eligible = 0
    discovered_entries = directories = ignored = virtual = metadata_entries = 0
    read_seconds = yara_seconds = 0.0
    ml_seconds = 0.0
    enumeration_complete = True
    directory = rules_dir or os.environ.get('YARA_RULES_DIR', yara_scanner.DEFAULT_RULES_DIR)
    rules, rule_id, rule_error = None, None, None
    engine_status = 'READY'
    if not yara_enabled or not yara_scanner.AVAILABLE:
        engine_status, rule_error = 'YARA_UNAVAILABLE', yara_scanner.UNAVAILABLE_REASON or 'Disabled by deployment configuration'
    else:
        try:
            rules = yara_scanner.compile_rules(directory)
            rule_id = yara_scanner.ruleset_id(directory)
            if rules is None:
                engine_status, rule_error = 'RULES_NOT_CONFIGURED', 'No YARA rules loaded'
        except Exception as exc:
            engine_status, rule_error = 'SCAN_FAILED', f'Rule compilation failed: {exc}'
    if rule_error:
        warnings.append(rule_error)
    compilation_seconds = time.monotonic() - started

    def expired():
        return time.monotonic() - started >= limits.max_seconds

    img = open_image(filepath, pytsk3)
    container_info = {'format': 'EWF' if hasattr(img, 'segments') else 'raw',
                      'segments': getattr(img, 'segments', [str(filepath)]),
                      'logical_media_bytes': int(img.get_size()),
                      'hash_scope': 'Intake evidence SHA256 identifies uploaded container bytes, not decompressed logical media'}
    try:
        filesystems = []
        try:
            volume = pytsk3.Volume_Info(img)
        except Exception:
            volume = None
        if volume is not None:
            for part in volume:
                if part.len > 0 and part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    offset = int(part.start * volume.info.block_size)
                    try:
                        filesystems.append((offset, pytsk3.FS_Info(img, offset=offset)))
                    except Exception as exc:
                        warnings.append(f'Volume at {offset} unsupported/unreadable: {exc}')
        if not filesystems:
            try:
                filesystems.append((0, pytsk3.FS_Info(img)))
            except Exception as exc:
                raise ValueError(f'No supported filesystem: {exc}') from exc

        for offset, fs in filesystems:
            filesystem_details.append({'volume_offset': offset, 'type': int(fs.info.ftype),
                'block_size': int(fs.info.block_size), 'root_inode': int(fs.info.root_inum)})
            seen = set()
            stack = [('/', None, 0)]
            while stack:
                if expired() or entries >= limits.max_entries:
                    warnings.append('Traversal stopped: duration or entry limit; discovery count is a lower bound')
                    enumeration_complete = False
                    break
                parent, inode, depth = stack.pop()
                try:
                    folder = fs.open_dir(inode=inode) if inode is not None else fs.open_dir(path='/')
                    for entry in folder:
                        if expired() or entries >= limits.max_entries:
                            enumeration_complete = False
                            warnings.append('Traversal stopped: duration or entry limit')
                            break
                        entries += 1
                        name = getattr(entry.info, 'name', None)
                        if name is None or name.name in (b'.', b'..'):
                            continue
                        discovered_entries += 1
                        filename = name.name.decode('utf-8', errors='replace')
                        path = parent.rstrip('/') + '/' + filename
                        meta = getattr(entry.info, 'meta', None)
                        # Allocated-only analysis: never treat residual deleted entries
                        # as accessible evidence or recurse into deleted directories.
                        if ((meta is not None and getattr(meta, 'flags', 0) & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                                or getattr(name, 'flags', 0) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC):
                            deleted_ignored += 1
                            ignored += 1
                            continue
                        entry_type = getattr(meta, 'type', None)
                        if entry_type in (pytsk3.TSK_FS_META_TYPE_VIRT, pytsk3.TSK_FS_META_TYPE_VIRT_DIR):
                            virtual += 1
                            ignored += 1
                            continue
                        # TSK synthesizes a regular-type entry for FAT volume labels.
                        if (int(fs.info.ftype) & pytsk3.TSK_FS_TYPE_FAT_DETECT
                                and filename.endswith(' (Volume Label Entry)')):
                            metadata_entries += 1
                            ignored += 1
                            continue
                        if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            directories += 1
                            ignored += 1
                            key = int(meta.addr)
                            if key not in seen:
                                seen.add(key)
                                if depth < limits.max_depth:
                                    stack.append((path, key, depth + 1))
                                else:
                                    warnings.append(f'Directory depth limit: {path}')
                                    enumeration_complete = False
                            continue
                        if meta is not None and meta.type != pytsk3.TSK_FS_META_TYPE_REG:
                            ignored += 1
                            continue
                        size = int(getattr(meta, 'size', 0) or 0)
                        row = {'FileName': filename, 'FilePath': path,
                               'FileExtension': os.path.splitext(filename)[1].lower(),
                               'FileSizeBytes': size, 'inode': int(meta.addr) if meta else None,
                               'volume_offset': offset, 'artifact_type': 'file',
                               'artifact_location': f'volume:{offset}:inode:{getattr(meta, "addr", None)}:{path}',
                               'CreatedTime': _ts(getattr(meta, 'crtime', 0)),
                               'ModifiedTime': _ts(getattr(meta, 'mtime', 0)),
                               'AccessedTime': _ts(getattr(meta, 'atime', 0)),
                               'metadata_flags': int(getattr(meta, 'flags', 0)),
                               'filesystem_type': int(fs.info.ftype),
                               'content_scope': 'allocated default unnamed stream only; no ADS or deleted recovery',
                               'entry_kind': 'regular_file' if meta is not None else 'unknown_unreadable',
                               'sha256': None, 'yara_matches': [], 'bytes_read': 0}
                        row['pe_ml'] = {'status': 'NOT_ANALYZED', 'reason': 'File content not completely read'}
                        rows.append(row)
                        status, reason = 'UNREADABLE', 'Missing metadata or non-regular file'
                        regular = meta is not None and meta.type == pytsk3.TSK_FS_META_TYPE_REG
                        if regular and size <= limits.max_file_bytes:
                            eligible += 1
                        if regular:
                            if size > limits.max_file_bytes:
                                status, reason = 'SKIPPED_TOO_LARGE', 'Individual file byte limit'
                            elif attempts >= limits.max_files or total_read + size > limits.max_total_bytes or expired():
                                status, reason = 'SKIPPED_LIMIT', 'File count, total bytes, or duration limit'
                            else:
                                attempts += 1
                                read_started = time.monotonic()
                                try:
                                    data = bytearray()
                                    while len(data) < size:
                                        if expired():
                                            raise TimeoutError('Processing duration exceeded')
                                        chunk = entry.read_random(len(data), min(1024 * 1024, size - len(data)))
                                        if not chunk:
                                            raise OSError('Short read; file only partially recoverable')
                                        data.extend(chunk)
                                        total_read += len(chunk)
                                        row['bytes_read'] += len(chunk)
                                    row['sha256'] = hashlib.sha256(data).hexdigest()
                                except Exception as exc:
                                    status, reason = 'UNREADABLE', str(exc)
                                    read_seconds += time.monotonic() - read_started
                                else:
                                    read_seconds += time.monotonic() - read_started
                                    yara_started = time.monotonic()
                                    try:
                                        if expired():
                                            raise TimeoutError('Processing duration exceeded')
                                        timeout = min(limits.yara_timeout, max(1, int(limits.max_seconds - (time.monotonic() - started))))
                                        if engine_status == 'READY':
                                            row['yara_matches'] = yara_scanner.scan_bytes(bytes(data), rules, row['artifact_location'], timeout)
                                            status = 'MATCHED' if row['yara_matches'] else 'SCANNED_NO_MATCH'
                                            reason = 'Complete default file stream scanned'
                                        else:
                                            status, reason = engine_status, rule_error
                                    except Exception as exc:
                                        status, reason = 'SCAN_FAILED', str(exc)
                                    finally:
                                        yara_seconds += time.monotonic() - yara_started
                                    ml_started = time.monotonic()
                                    if expired():
                                        row['pe_ml'] = {'status': 'SKIPPED_LIMIT', 'reason': 'Disk processing duration exceeded'}
                                    else:
                                        try:
                                            row['pe_ml'] = pe_malware_detector.predict_file(bytes(data),
                                                **{**pe_options, 'timeout': min(pe_options.get('timeout', 20),
                                                    max(0.01, limits.max_seconds - (time.monotonic() - started)))})
                                        except Exception as exc:
                                            row['pe_ml'] = {'status': 'CLASSIFICATION_FAILED', 'reason': str(exc)}
                                    ml_seconds += time.monotonic() - ml_started
                        row.update(scan_status=status, scan_reason=reason)
                except Exception as exc:
                    warnings.append(f'Traversal error at volume {offset} {parent}: {exc}')
                    enumeration_complete = False
    finally:
        img.close()
    scanned = sum(r['scan_status'] in ('MATCHED', 'SCANNED_NO_MATCH') for r in rows)
    skipped = sum(r['scan_status'].startswith('SKIPPED_') for r in rows)
    failed = len(rows) - scanned - skipped
    if skipped or failed:
        warnings.append(f'Reduced coverage: {skipped} files excluded by limits; {failed} files failed or unavailable')
    duration = time.monotonic() - started
    ml_rows = [r['pe_ml'] for r in rows]
    classified = [r for r in ml_rows if r['status'] == 'CLASSIFIED']
    ml_errors = sum(r['status'] in ('MODEL_UNAVAILABLE', 'EXTRACTION_FAILED', 'CLASSIFICATION_FAILED') for r in ml_rows)
    ml_excluded = sum(r['status'] not in ('CLASSIFIED', 'NOT_APPLICABLE') or
                      (r['status'] == 'NOT_APPLICABLE' and r.get('is_pe', False)) for r in ml_rows)
    ml_summary = {'model': pe_model, 'pe_files_discovered': sum(bool(r.get('is_pe')) for r in ml_rows),
                  'files_classified': len(classified),
                  'malicious': sum(r['prediction'] == 'malicious' for r in classified),
                  'benign': sum(r['prediction'] == 'benign' for r in classified),
                  'files_excluded': ml_excluded, 'classification_errors': ml_errors,
                  'not_applicable': sum(r['status'] == 'NOT_APPLICABLE' for r in ml_rows),
                  'processing_seconds': round(ml_seconds, 6),
                  'coverage_status': 'PARTIAL' if ml_excluded or not enumeration_complete else 'COMPLETE'}
    if ml_excluded:
        warnings.append(f'PE ML coverage reduced: {ml_excluded} artifacts unclassified; {ml_errors} errors')
    return {'findings': rows, 'total_files_discovered': len(rows), 'total_eligible_files': eligible,
            'image_container': container_info,
            'filesystems': filesystem_details, 'deleted_entries_ignored': deleted_ignored,
            'content_scope': 'Allocated default streams; ADS, deleted recovery and reparse targets are outside scope',
            'entries_discovered': discovered_entries, 'regular_files_discovered': sum(r['entry_kind'] == 'regular_file' for r in rows),
            'non_file_entries_ignored': ignored, 'directories_discovered': directories,
            'virtual_entries_ignored': virtual, 'metadata_entries_ignored': metadata_entries,
            'files_skipped_limits': skipped, 'files_failed': failed,
            'files_scanned': scanned, 'files_skipped': len(rows) - scanned,
            'files_with_yara_matches': sum(bool(r['yara_matches']) for r in rows),
            'matched_rules': sum(len(r['yara_matches']) for r in rows), 'bytes_read': total_read,
            'pe_ml': ml_summary,
            'processing_seconds': round(duration, 6),
            'timings': {'rules_compilation_seconds': round(compilation_seconds, 6),
                        'file_read_hash_seconds': round(read_seconds, 6),
                        'yara_execution_seconds': round(yara_seconds, 6),
                        'pe_ml_seconds': round(ml_seconds, 6),
                        'filesystem_enumeration_seconds': round(max(0, duration - compilation_seconds - read_seconds - yara_seconds - ml_seconds), 6),
                        'disk_analysis_seconds': round(duration, 6)},
            'scan_status': 'COMPLETE' if enumeration_complete and not warnings and scanned == len(rows) else 'PARTIAL',
            'enumeration_complete': enumeration_complete, 'warnings': warnings,
            'ruleset_id': rule_id, 'yara_status': engine_status, 'limits': asdict(limits)}
