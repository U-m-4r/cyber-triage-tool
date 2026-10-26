"""Explicit, operator-initiated dataset provenance.

Two provenance paths share one command:

* ``python scripts/download_dataset.py`` retrieves the reviewed CICIDS2017
  dataset through KaggleHub and records its provenance manifest. This is the
  only command that performs a network request.
* ``python scripts/download_dataset.py --from-local PATH`` records provenance
  for an already-present, operator-verified local CSV instead. It never
  downloads, never imports the Kaggle package, and reads the file read-only
  (streamed SHA-256). Use it when the reviewed copy is already on disk and a
  Kaggle retrieval is unavailable or not desired.

Validation, cleaning, and training never call either path, so a missing
dataset stays a reported error instead of an implicit network request. The
reviewed source CSVs under ``data/sample/`` and ``data/cicids2017_cleaned.csv``
are never written, replaced, or used as a download target.

Example:

    python scripts/download_dataset.py
    python scripts/download_dataset.py --csv-path raw/part-00007.csv
    python scripts/download_dataset.py --force-download
    python scripts/download_dataset.py --from-local data/cicids2017_cleaned.csv
"""
import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.dataset_source import (DEFAULT_MANIFEST_PATH, DEFAULT_OUTPUT_DIR,
                               DatasetSourceError, download_dataset,
                               register_local_dataset)


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
    parser.add_argument('--from-local', type=Path, default=None,
                        help='Record provenance for an already-present, operator-verified local '
                             'CSV instead of downloading. The file is read read-only (streamed '
                             'SHA-256) and never modified; no network request is made.')
    parser.add_argument('--force-download', action='store_true',
                        help='Ignore the cached copy and replace a provenance record that does not match')
    args = parser.parse_args(argv)
    try:
        if args.from_local is not None:
            report = register_local_dataset(local_path=args.from_local,
                                            manifest_path=args.manifest,
                                            force=args.force_download)
        else:
            report = download_dataset(output_dir=args.output_dir, manifest_path=args.manifest,
                                      csv_hint=args.csv_path, force_download=args.force_download)
    except DatasetSourceError as exc:
        action = 'Registration' if args.from_local is not None else 'Download'
        parser.exit(1, f'{action} failed [{exc.code}]: {exc}\n')
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    main()