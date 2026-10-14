# PR19C_AMENDMENT05_TEST_EVIDENCE

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

## Canonical gates (final HEAD)

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | PASS — 2448 passed, coverage 90.45% |
| `./build.sh --sec` | PASS — 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — 574 passed, 90 opt-in live skipped |
| `scripts/mtmf-pr19c-live.py acceptance-pr19c` | PASS — COLD/REPEAT/RECREATE, 4 passed / 0 skipped each |

## DS unit matrix

| ID | Coverage | Result |
| --- | --- | --- |
| DS-U01 | `_test_env` fixed service URL wins over hostile inherited value | PASS |
| DS-U02 | missing/stopped service container fails before pytest | PASS (`_verify_deployed_service`) |
| DS-U03 | wrong project label / wrong host port fails | PASS |
| DS-U04 | service health non-200/refused fails | PASS (`_verify_deployed_service` + `_wait_http`) |
| DS-U05 | four passed / zero skips succeeds | PASS |
| DS-U06 | skips/xfail/wrong count (`3 passed,1 skipped`, `4 passed,1 skipped`, `14 passed`) fail | PASS |
| DS-U07 | live module requires the exact fixed service URL | PASS |
| DS-U08 | live module source has no test-owned server / global-count audit | PASS |
| DS-U09 | repeated invocation with persisted fixtures | PASS (REPEAT-01 live) |
| DS-U10 | default-stack inventory unchanged | PASS (live) |

## Skips classification

The 90 skipped cases inside `--integration` are the opt-in live suites (including PR 19C). They are deliberately opt-in for `--integration` and were executed separately by `acceptance-pr19c` with zero skips.

## Failure classification

The earlier transient `URLError: Connection reset by peer` during container recreation was an environment/timing artifact immediately after `up`; a re-run passed and the orchestrator now verifies service readiness before pytest. No introduced regression or feature defect.
