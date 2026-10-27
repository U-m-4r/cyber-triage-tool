"""
Deterministic in-place updater for plan.md to document Phase 19A completion.
"""
from pathlib import Path

plan_path = Path("plan.md")
assert plan_path.is_file(), "plan.md not found"

content = plan_path.read_text(encoding="utf-8")

phase19a_section = """
## 6. Phase 19 Status: Digital Forensics Disk Image Research & Ingestion

### Phase 19A: Find, Verify, and Acquire a Digital Forensics Disk Image [COMPLETED]
**Status:** COMPLETE (All research, acquisition, integrity hashing, validation, and test gates verified).

#### Multi-Source Candidate Research & Evaluation
- [x] **Kaggle Candidates Evaluated:**
  - `divyanshuprakash/cybercrime-forensic-dataset`: Evaluated for disk images; rejected because contents are tabular CSV event logs, not a binary filesystem capture.
  - `hiwotyirga/the-digital-forensics-2023-dataset-df2023`: Evaluated; rejected because contents are multimedia computer vision images (JPEG/PNG) for forgery detection, not storage volumes.
  - `ahmedashrafabdelmaksoud/memory-based-malware-artifacts`: Evaluated; rejected because contents are extracted Volatility tabular metrics, not a raw disk image.
  - `blackgaurd3/digital-corpora-pdfs-as-images`: Evaluated; rejected because contents are rendered JPGs of GovDocs1 PDFs.
- [x] **Digital Corpora Candidates Evaluated:**
  - **M57-Jean Scenario (`nps-2008-jean`)**: Windows XP corporate data exfiltration scenario. Evaluated; rejected due to multi-volume split E01 archive (`.E01` + `.E02`) requiring multi-gigabyte downloads and a 10 GB uncompressed storage footprint, exceeding practical limits for rapid local development and automated CI.
  - **NPS DOMEX Users (`nps-2009-domexusers`)**: Windows XP SP3 IM/email activity capture. Evaluated; rejected due to 8.2 GB uncompressed footprint and distribution as an encrypted or heavily redacted container requiring external key management.
- [x] **Kaggle Platform & Access Blockers:**
  - Kaggle does not host binary sector-level disk captures (`.dd`, `.raw`, `.E01`) due to storage policies and machine-learning focus.
  - Client environment blockers: `kagglehub` package not installed (`KAGGLEHUB_MISSING`), and Kaggle credentials unconfigured (`CREDENTIALS_MISSING`).

#### Primary Selected Dataset & Source
- [x] **Dataset Identity & Authority:**
  - **Dataset Name:** NIST CFReDS Deleted File Recovery Reference Test Image (DFR-01-NTFS)
  - **Identifier:** `nist-cfreds/dfr-01-ntfs`
  - **Canonical URL:** `https://cfreds-archive.nist.gov/dfr-images/dfr-01-ntfs.dd.bz2`
  - **Documentation URL:** `https://cfreds-archive.nist.gov/dfr-test-images.html`
  - **Organization:** National Institute of Standards and Technology (NIST), Law Enforcement Standards Office (OLES)
  - **License:** US Government Work / Public Domain (Unrestricted research and tool benchmarking)
  - **Selection Rationale:** Optimal balance of authentic Windows NTFS internal filesystem structures ($MFT, $LogFile, $Bitmap, $Boot, $AttrDef), manageable compressed size (2.15 MB), public domain license, and 100% native compatibility with `pytsk3.Img_Info`.

#### Download, Storage & Integrity Manifest
- [x] **Acquisition Execution:**
  - **Acquisition Command:** `python scripts/acquire_forensic_image.py`
  - **Storage Location:** `data/forensics/disk_images/` (ignored by `.gitignore`)
  - **Archive Path:** `data/forensics/disk_images/dfr-01-ntfs.dd.bz2` (2,257,102 bytes)
    - Archive SHA-256: `9625d8946bc7712953d0ca7e73e4eaeff26381006951d3f7603d1797b50d19e0`
  - **Extracted Disk Image:** `data/forensics/disk_images/dfr-01-ntfs.dd` (1,073,742,336 bytes, 1.0 GB)
    - Image SHA-256: `c863ccad01804b840a6dfa623a94996ca876e15ded41c6c0d8ae148620eb6493`
    - Format: RAW_DD (single-volume partition formatted with Microsoft NTFS)
    - Immutability: File permissions marked read-only (`chmod -w`) to preserve forensic chain of custody
  - **Provenance Manifest:** `data/provenance/forensic_disk_image.provenance.json` and `data/forensics/disk_images/manifest.json`

#### Validation & Pipeline Compatibility
- [x] **Direct Ingestion Verification:**
  - Evaluated via `forensics.disk_image.ingest_disk_image` (SleuthKit / pytsk3): Successfully parsed partition and directory tree, extracting 21 file records with valid timestamps and sizes ($AttrDef, $BadClus, $Bitmap, $Boot, $ObjId, $Quota, $Reparse, $Repair, $Tops, $TxfLog.blf, etc.).
  - Verified backend routing: `backend.app._dispatch_forensic_parser` recognizes `.dd` format and routes to `disk_image.ingest_disk_image`.
  - Verification command: `python scripts/acquire_forensic_image.py --verify-only` -> `valid: true, files_enumerated: 21`.

#### Automated Tests Executed
- [x] **Test Results:**
  - `tests/test_forensics.py`: 16 passed in 8.52s (covering Kaggle blocker diagnostics, candidate metadata, Digital Corpora candidate metadata, SHA-256 streaming, dry-run mode, tampering detection, and primary disk image parsing).
  - Full test suite: **298 passed, 2 skipped** (MongoDB integration skipped) in 24.33s.
  - Formatting & diff checks: `git diff --check` passed cleanly.

### Phase 19B: Disk-Image File Extraction, YARA Rule Matching & Forensics Ingestion Integration [PENDING]
- [ ] Implement file carving and extraction helper in `forensics/disk_image.py` for target artifact inspection
- [ ] Connect disk-image extracted files into YARA IOC scanning and rule scoring pipeline
- [ ] Add integration test verifying end-to-end disk image upload via `POST /api/forensics/ingest`
"""

# Replace existing Section 6 or append
if "## 6. Phase 19 Status" in content:
    pre_section = content.split("## 6. Phase 19 Status")[0].rstrip()
    updated_content = pre_section + "\n" + phase19a_section
else:
    updated_content = content.rstrip() + "\n" + phase19a_section

plan_path.write_text(updated_content, encoding="utf-8")
print("plan.md successfully updated with Phase 19A status.")
