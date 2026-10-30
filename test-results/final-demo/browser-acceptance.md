# Browser acceptance and manual presentation checklist

Actually observed with approved in-app browser on2026-10-30/31:
- PASS local development sign-in (no token required by isolated test app).
- PASS evaluation page displays real saved metrics/confusion counts and limitations.
- PASS case list contains16genuine populated investigations.
- PASS NTFS marker search shows exact path and Harmless_NTFS_Marker rule.
- PASS launcher filter shows genuine0.012141score,modelID,0.5threshold and independentYARA indicator.
- PASS refresh/reopening retains saved NTFS case.
- PASS partial-case evidence row and expanded coverage show PARTIAL and no safety claim.
- PASS network artifact view shows actual modelID,ATTACK decision,threshold and risk separately.
- PASS Reports→GeneratePDF produced visible generated/downloaded success and report history.
- PASS ordinaryPE evaluation view shows unique-file counts and benchmark-vs-coverage limitations.

Not claimed: browser uploads of every evidence type, all responsive sizes, exhaustive cross-browser testing, segmented browser upload, a timed narrated college rehearsal. API/MongoDB/PDF checks covered everycase; UI smoke checks above are narrower.

Manual before presentation:
1. Open http://127.0.0.1:5259/cases; sign in with a display label.
2. Open CASE-E042AF39B2C3 Artifacts; search positive.txt; expand identity andYARA details. Then launcher.bin and negative.txt.
3. Open CASE-639E1724B463; explain E01 was processed locally as a complete segment set, never browseruploaded.
4. Open CASE-F0A7D56A1116 and CASE-1F8449428D92; show the distinct saved detectors; do not call risk or flag proportion accuracy.
5. Open CASE-6E87BD593EAA and live-labeled-network.json:2/40attacks detected,1falsepositive; not the full external evaluation.
6. Open /evaluations. Show internal/external differences, research NOTDEPLOYED, PEconfusionmatrix, challenge positive-only restrictions. Expand provenance.
7. Open CASE-0DAA7F525B35 Evidence and expand coverage. Contrast unavailable caseCASE-9E450E7C0284.
8. Open Reports and generate/download the real current report. Inspect backupPDF if network/browser delivery fails.
9. Reopen/refresh at least onecase. Confirm localhostservices/Mongo running before reviewer arrives.

Duration: no complete timed spoken rehearsal performed; no invented duration estimate. Most saved-case steps do not rerun inference. Schedule and time a manual narrated rehearsal using this checklist.

Offline screenshots and PDFs are PREVIOUSLY CAPTURED EXECUTION EVIDENCE, not a live dashboard. Files under backup/ are ignored and may contain native fixture host records; do not publish them blindly.

Timed automated navigation smoke12seconds (18:34:59–18:35:11UTC); saveddata only. Full narrated college demonstration timing remains unmeasured.


Continued session: browser reconnection failed with `browser.user is unavailable`. Earlier PASS evidence is preserved; refreshed provenance controls remain interactively UNVERIFIED. Manually expand Evidence/provenance, click Inspect saved metrics and supporting manifests, check model checksums/receipt dates, and hide the source again. These requests use the configured authenticated API client. Latest automated result:426backend passed/46skipped;19frontend passed; build/static PASS.
