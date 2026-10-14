# PR19C_AMENDMENT03_TEST_EVIDENCE

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

## Executed

| Suite | Command | Result |
| --- | --- | --- |
| Unit (QA) | `./build.sh --qa` | PASS — 2437 passed, coverage 90.45% |
| Live H01–H05 | `MTMF_PR19C_LIVE=1 pytest tests/integration/postgres/test_pr19c_live_management.py` on the canonical `mtmf-dev` Keycloak + PostgreSQL 18 | PASS — 4 passed, 0 skipped |
| Orchestrator unit | `tests/unit/service/test_pr19c_live_orchestrator.py` | PASS — OR-U01/U03/U04/U05/U08/U10 |

## Not executed

| Suite | Reason |
| --- | --- |
| COLD-01 / REPEAT-01 / RECREATE-01 | disposable Keycloak realm isolation blocked (see STOP report) |
| NEG-01/NEG-03 live | depend on the disposable harness |
| OR-U02/U06/U07/U09 | not implemented as separate cases in this pass |

## Failure classification

- COLD-01: **environment/harness/topology limitation** (`compose.dev.yaml` global Keycloak volume name; `podman-compose` override behaviour). Not a feature defect. Recorded in `PR19C_AMENDMENT03_STOP_REPORT.md`.
- No introduced regression or feature defect was observed; `--qa` and the live H01–H05 run are green.

## Code-exists vs executed vs passed

- Code exists: orchestrator, override, live tests, unit tests.
- Executed: live H01–H05 (PASS); orchestrator helpers (PASS); COLD-01 (executed, FAILED to complete — classified environment).
- Passed in required topology: H01–H05 (PASS on the canonical issuer/DB); COLD/REPEAT/RECREATE (NOT PASSED).
