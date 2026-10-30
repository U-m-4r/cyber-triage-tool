# Allocated NTFS and physical EWF scope

The existing pytsk3 reader handles raw whole disks and unpartitioned filesystems.
Issue8 verifies NIST DFR01 NTFS, a controlled64MiB NTFS filesystem, the same
filesystem behind an MBR at1048576bytes, and a genuine five-segment EWF acquisition.
Only allocated regular default unnamed streams are analyzed. Deleted entries are
excluded and counted. ADS, deleted recovery, reparse targets, encrypted content,
slack and journal reconstruction are outside coverage. Compression, sparse data
and deliberate fragmentation are not independently verified by this fixture.

Install the optional native binding with `pip install -r requirements/ewf.txt`.
`forensics.image_reader.open_image` recognizes physical EVF signatures and uses
pyewf in read-only mode behind a pytsk3 external image interface. Segments must
already exist together in a trusted local directory. No conversion or whole-image
RAM allocation occurs. Logical LEF is explicitly rejected. Ex01 is unverified.

The web endpoint accepts a single file. It does not transfer multipart E01 segment
sets. Use the bounded local analysis function on a complete segment set:

```python
from forensics.disk_image import analyze_disk_image, ScanLimits
result = analyze_disk_image('local/acquisition.E01', limits=ScanLimits())
```

Do not upload only E01 from a segmented acquisition and claim full coverage.
Missing/corrupt segment sets must surface open/read failures or partial findings.
An intake hash identifies the uploaded container, not its decompressed image.
Hash every segment separately, then stream logical bytes if a media SHA256 is
required. Stored EWF hashes and external ewfverify results are separate checks.
Issue8's logical SHA256 equals the controlled source raw hash; stored MD5 also
matches. This is technical integrity evidence, not a legally complete custody claim.

The normal upload limit remains128MiB. The controlled64MiB image was ingested by
the normal HTTP route; the1GiB public reference was processed locally under the
same file/total-byte/time limits. No general path-ingestion web endpoint or upload
limit bypass is introduced. Local callers are responsible for access control and
trusted segment selection. Native TSK deadlines are cooperative, not hard process
termination. PE input remains2MiB/20seconds with one killable worker per file;
concurrent requests still require deployment controls.

See [actual results](../test-results/issue-8/REPORT.md) for provenance, hashes,
coverage, timings, source commands and remaining browser limitations.
