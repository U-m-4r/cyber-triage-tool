"""Disk-image ingestion via pytsk3 (PART C, item 9).

Opens a raw (dd) or E01 disk image with The Sleuth Kit bindings, walks each
filesystem, and enumerates files into a DataFrame whose columns line up with the
``file`` artifact rules in ml/risk_scorer.py:
    FileName, FilePath, FileExtension, FileSizeBytes, CreatedTime, ModifiedTime

Reference: B. Carrier, "File System Forensic Analysis" (The Sleuth Kit); pytsk3
Python bindings.
"""
import os
import pandas as pd

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
    """Enumerate files in a raw/E01 disk image into a normalized DataFrame.

    Walks every partition that carries a filesystem. ``limit`` optionally caps the
    number of file rows. Raises RuntimeError if pytsk3 is unavailable.
    """
    if not AVAILABLE:
        raise RuntimeError(UNAVAILABLE_REASON)

    img = pytsk3.Img_Info(filepath)
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
