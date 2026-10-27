"""Command-line interface for forensic disk image acquisition and verification.

Usage:
    # Run acquisition of the primary reference image (NIST DFR-01-NTFS):
    python scripts/acquire_forensic_image.py

    # Verify existing downloaded image without re-downloading:
    python scripts/acquire_forensic_image.py --verify-only

    # Dry-run / metadata-only inspection:
    python scripts/acquire_forensic_image.py --dry-run

    # Force re-download and re-extraction:
    python scripts/acquire_forensic_image.py --force
"""

import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from forensics.acquisition import (
    DEFAULT_IMAGE_DIR,
    DEFAULT_MANIFEST_PATH,
    ForensicAcquisitionError,
    acquire_primary_forensic_image,
    verify_disk_image_against_manifest,
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Acquire, verify, and document provenance for digital forensic disk images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_IMAGE_DIR,
        help="Directory to store the acquired disk images and local manifest",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path where provenance manifest JSON is written",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Display prospective metadata and research findings without downloading",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download and re-extraction even if image already exists",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify integrity and readability of existing image against manifest",
    )

    args = parser.parse_args(argv)

    try:
        if args.verify_only:
            image_path = args.output_dir / "dfr-01-ntfs.dd"
            report = verify_disk_image_against_manifest(image_path, args.manifest)
        else:
            report = acquire_primary_forensic_image(
                output_dir=args.output_dir,
                manifest_path=args.manifest,
                force=args.force,
                dry_run=args.dry_run,
            )
    except ForensicAcquisitionError as exc:
        parser.exit(1, f"Forensic acquisition failed [{exc.code}]: {exc}\n")

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
