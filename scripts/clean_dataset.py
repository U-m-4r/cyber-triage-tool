"""Explicit, operator-initiated offline cleaning of the reviewed CICIDS2017 source.

Separation of duties: download, validation, cleaning, and training are four
commands with one job each. This command never downloads, never fits a model,
and never rewrites the source CSV. It verifies the provenance manifest and the
source SHA-256, applies policy ``cicids2017-offline-cleaning`` v1.0.0, and
publishes two derived artifacts under ``data/provenance/``:

* an exclusion ledger (source row index + reason codes, deterministic bytes), and
* a cleaning record (policy, source identity, per-column issue counts, the
  unique excluded-row union with overlap pairs, retained rows, ledger SHA-256).

The eligible training/evaluation view is derived at load time from the
immutable source via ``ml.cleaning.load_eligible_frame``; no cleaned CSV is
materialised here.

Example:

    python scripts/clean_dataset.py
    python scripts/clean_dataset.py --data data/kaggle/download.csv --chunk-rows 20000
    python scripts/clean_dataset.py --force     # replace a mismatching ledger/record
"""
import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.cleaning import (DEFAULT_CHUNK_ROWS, DEFAULT_LEDGER_PATH, DEFAULT_RECORD_PATH,
                         CleaningError, clean_dataset)
from ml.dataset_source import DEFAULT_MANIFEST_PATH


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, default=None,
                        help='Source CSV to clean (read-only); defaults to the path recorded in '
                             'the provenance manifest')
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST_PATH,
                        help='Provenance manifest that must match the source')
    parser.add_argument('--ledger', type=Path, default=DEFAULT_LEDGER_PATH,
                        help='Exclusion ledger written next to the provenance manifest')
    parser.add_argument('--record', type=Path, default=DEFAULT_RECORD_PATH,
                        help='Cleaning record written next to the provenance manifest')
    parser.add_argument('--chunk-rows', type=int, default=DEFAULT_CHUNK_ROWS,
                        help='Rows read per chunk; counts and the ledger do not depend on it')
    parser.add_argument('--force', action='store_true',
                        help='Replace a ledger or cleaning record that does not match this run')
    args = parser.parse_args(argv)
    try:
        report = clean_dataset(source=args.data, manifest_path=args.manifest,
                               ledger_path=args.ledger, record_path=args.record,
                               chunk_rows=args.chunk_rows, force=args.force)
    except CleaningError as exc:
        parser.exit(1, f'Cleaning failed [{exc.code}]: {exc}\n')
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    main()
