# PR 23 — Final SHA and Push Status

**Branch:** `dev/pr23-verified-subject-stewardship`
**Base:** `1bb46af8a8fe780be23521954e130ef895906ab9` (`main`, merged PR #74)

## Commits

| Purpose | SHA |
| --- | --- |
| Original implementation, SQL, migration, tests, docs, reports | `7325c1d3a2083b013993cb3fdffb5fdf2cf69471` |
| Live fixture selection / Rust / QA-count evidence and first DONE verdict | `32e1060f90ae4d3b960071905a0e36ecb9864efe` |
| Artifact-only final-SHA follow-up | `227fbcb6981bacb4509d7ecde1bce244f367af96` |
| **Independent-review F1/F2 fix (content under test)** | **`a68177edddef46a077bf4942fbcd455cdd8a9428`** |
| Final fixup artifact follow-up (this report and reconciled artifacts) | recorded by the follow-up commit; see `git log -1 -- docs/pr-artifacts/pr-23/PR23_FINAL_SHA.md` |

`a68177e…` is the reviewed state for which the final fixup evidence was
collected:

- `./build.sh --qa`: 2490 passed, 0 skipped, 90.30% coverage
- `./build.sh --sec`: 0 findings
- `./build.sh --rust`: passed
- `./build.sh --integration`: 646 passed, 94 skipped
- PR 23 targeted real-PostgreSQL suite: 40 passed
- PR 23 live L01–L04: 4 passed, 0 skipped
- PR 14 live regression: 22 passed, 0 skipped
- `scripts/mtmf-provision-roles.py --verify`: passed
- `uv run --no-sync pre-commit run --all-files`: passed
- `git diff --check`, `git fsck --full`: clean

Adding this report changes no code, SQL, migration, or test.

## Push status

Not pushed beyond the existing reviewed branch state. No pull request was
opened. Pushing, force-pushing, or opening a PR requires explicit maintainer
authorization.

## Verdict

`PR23_COMPLETE_INTERNAL_ONLY` — DONE — INTERNAL PARTICIPANT ONLY. See
[PR23_FINAL_ACCEPTANCE_REPORT.md](PR23_FINAL_ACCEPTANCE_REPORT.md) and
[PR23_INDEPENDENT_REVIEW_FIXUP_REPORT.md](PR23_INDEPENDENT_REVIEW_FIXUP_REPORT.md).
