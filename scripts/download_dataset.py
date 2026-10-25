"""Explicit, operator-initiated KaggleHub download with a provenance manifest.

This is the only command in the repository that retrieves the dataset.
Validation, cleaning, and training never call it, so a missing dataset stays a
reported error instead of an implicit network request. The reviewed source CSV
under ``data/sample/`` is never written, replaced, or used as a download target.

Example:

    python scripts/download_dataset.py
    python scripts/download_dataset.py --csv-path raw/part-00007.csv
    python scripts/download_dataset.py --force-download
"""
import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.dataset_source import (DEFAULT_MANIFEST_PATH, DEFAULT_OUTPUT_DIR,
                               DatasetSourceError, download_dataset)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR,
                        help='Directory that receives the downloaded dataset files')
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST_PATH,
                        help='Provenance manifest written after a verified retrieval')
    parser.add_argument('--csv-path', default=None,
                        help='CSV path relative to the download directory; required when the '
                             'download contains more than one CSV')
    parser.add_argument('--force-download', action='store_true',
                        help='Ignore the cached copy and replace a provenance record that does not match')
    args = parser.parse_args(argv)
    try:
        report = download_dataset(output_dir=args.output_dir, manifest_path=args.manifest,
                                  csv_hint=args.csv_path, force_download=args.force_download)
    except DatasetSourceError as exc:
        parser.exit(1, f'Download failed [{exc.code}]: {exc}\n')
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    main()
