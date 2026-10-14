# PR19C_AMENDMENT03_BASELINE_RECONCILIATION

**PR:** roadmap PR 19C. **Date:** 2026-10-14.
**Branch:** `dev/mgmt-mutation`. **Base (origin/main):** `0f6d3fe`. **Tip before this amendment:** `0f03824`.
**Migration head:** `0012_security_mutation_audit`. Clean tree at Phase 0.

| Capability | File / function | Implemented | Executed | Passed in real topology |
| --- | --- | --- | --- | --- |
| Management HTTP route + DTO/adapter | `mtmf-api`, `mtmf-service` | YES | YES (unit) | YES (live H01–H05) |
| v012 audited mutation | `sql/v012/*`, `migrations/versions/0012*` | YES | YES | YES |
| Runtime privilege closure | `roles.py`, `sql/v012/04*` | YES | YES | YES |
| Concurrency proof | `PR19C_CONCURRENCY_PROOF.md` | YES | YES | YES |
| Canonical dev stack | `scripts/mtmf-dev-stack.py` | YES | YES | YES |
| Live H01–H05 | `tests/integration/postgres/test_pr19c_live_management.py` | YES | YES | **YES** |
| Acceptance orchestrator | `scripts/mtmf-pr19c-live.py`, `acceptance-pr19c` | YES | PARTIAL | **NO — cold-start isolation blocked** |
| COLD/REPEAT/RECREATE | orchestrator | YES | **NO** | **NO** |
| OR-U unit tests | `tests/unit/service/test_pr19c_live_orchestrator.py` | YES | PARTIAL (U01/U03/U04/U05/U08/U10) | n/a |

## Authoritative commands

`uv sync --locked`; `./build.sh --qa`; `./build.sh --sec`; `./build.sh --rust`; `./build.sh --integration`; live opt-in `MTMF_PR19C_LIVE=1 pytest tests/integration/postgres/test_pr19c_live_management.py`.

## Missing pieces

A genuinely disposable Keycloak realm. `compose.dev.yaml` names the Keycloak data volume globally (`mtmf-dev-keycloak-data`), so every Compose project shares the operator realm; the acceptance-only override (`compose.pr19c-acceptance.yaml`) could not produce a reliably isolated fresh realm under `podman-compose` 1.0.6. See `PR19C_AMENDMENT03_STOP_REPORT.md`.
