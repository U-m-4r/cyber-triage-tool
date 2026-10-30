# Issue 1 actual execution

| Metric | Actual Result |
|---|---|
| Disk image name | harmless-fat12.img |
| Disk image SHA-256 | 9bd3977ad31217bc71bfff4d6eaedbc7a955a147952a0dd8d379b3e377cbf6fb |
| Disk image size | 1474560 |
| Files discovered | 9 |
| Files eligible | 5 |
| Files scanned | 5 |
| Files skipped | 4 |
| Files with YARA matches | 1 |
| Matched YARA rules | 1 |
| Processing time (seconds) | 0.004567 |
| Scan status | PARTIAL |

Integrity verified: True. Persistence: False.

Positive: /POSITIVE.TXT matched Harmless_File_Marker. Negative and empty files scanned without matches. Four virtual/nonregular TSK entries are explicitly UNREADABLE, so status is PARTIAL.

Focused tests: 55 passed, 4 skipped. Skips: immutable native type prevents read fault injection; primary reference image absent at configured path; model fitting prohibited; dedicated MongoDB integration disabled. YARA timeout handling uses fault injection, not a naturally timed-out rule.

Frontend production build passed. MongoDB loopback access failed in the sandbox; persistence, browser reopening, dashboard and PDF end-to-end verification remain unverified. Native calls have cooperative duration checks, not hard preemption.

See ../../docs/issue-1-file-yara.md for exact commands and demo steps. Full suite output and JUnit are saved alongside this report.

Full suite: 313 passed, 30 skipped, 1 failed, 19 errors. The failure and setup errors attempt scaler fitting blocked by --no-training (attack-family synthetic fixtures and holdout test). No production models were replaced.
