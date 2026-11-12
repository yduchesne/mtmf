# PR 23 — Final SHA and Push Status

**Branch:** `dev/pr23-verified-subject-stewardship`
**Base:** `1bb46af8a8fe780be23521954e130ef895906ab9` (`main`, merged PR #74)

## Commits

| Purpose | SHA |
| --- | --- |
| Initial implementation, SQL, migration, tests, docs, reports | `7325c1d3a2083b013993cb3fdffb5fdf2cf69471` |
| Final content under test: live fixture selection correction (`mtmf-dev`), passed live/Rust/QA-count evidence, updated verdict | `32e1060f90ae4d3b960071905a0e36ecb9864efe` |
| Final artifact-SHA follow-up (this file) | recorded by the follow-up commit; see `git log -1 -- docs/pr-artifacts/pr-23/PR23_FINAL_SHA.md` |

`32e1060…` is the reviewed state for which the reported final evidence was
collected:

- `./build.sh --qa`: 2490 passed, 0 skipped, 90.30% coverage
- `./build.sh --sec`: 0 findings
- `./build.sh --rust`: passed with rustup stable 1.99.1
- `./build.sh --integration`: 628 passed, 94 skipped
- PR 23 live L01–L04: 4 passed, 0 skipped
- PR 14 live regression: 22 passed, 0 skipped
- `main` QA in the same environment: 2472 passed, 90.32% (branch delta = 18 new tests)
- `scripts/mtmf-provision-roles.py --verify`: passed

Adding this report changes no code, SQL, migration, test, or shared normative
document.

## Push status

Not pushed. No pull request was opened. Per the execution plan, pushing and
opening a PR require explicit maintainer authorization.

## Verdict

`PR23_COMPLETE_INTERNAL_ONLY` — DONE — INTERNAL PARTICIPANT ONLY. See
[PR23_FINAL_ACCEPTANCE_REPORT.md](PR23_FINAL_ACCEPTANCE_REPORT.md).
