# Phase 1 foundation overhaul

In progress. Branch: main, starting commit: 459fdce. No commits or branch changes.

- [x] Inspect current checkout and record protected source fingerprints.
- [x] Create project-local `.venv` (Python 3.14.7).
- [ ] Install and lock runtime/development dependencies.
- [ ] Isolate tests from investigation databases and external services.
- [ ] Execute and repair backend tests.
- [ ] Stabilize configuration, startup, health and readiness.
- [ ] Add lightweight quality commands and verify frontend.
- [ ] Update developer instructions and inspect final diff.

Protected files before work:
- `context.md`: 6,552 bytes; SHA-256 `5acd8d78d76d4ee9fc179a8ebfa3927c53650002212917bf9996a6c014079fb6` (untracked).
- `data/sample/cicids2017_cleaned.csv`: 717,247,573 bytes; SHA-256 `0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292`.

No dataset downloads or production model training are authorized in this phase.
Existing synthetic lifecycle tests may fit tiny disposable test estimators only.
