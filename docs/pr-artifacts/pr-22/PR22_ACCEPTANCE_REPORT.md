# PR22_ACCEPTANCE_REPORT

**PR:** roadmap PR 22 — Transactional Tenant Provisioning and Subscription Foundation
**Status:** **PARTIAL — BLOCKED.** Isolated onboarding-entitlement foundation
implemented and verified; first-Tenant composite BLOCKED (STOP-P22-A/B). PR 22
is **NOT DONE** and the v0.1 onboarding capability is NOT complete.

## 1. Implemented vs verified vs deferred

| Area | State |
| --- | --- |
| Onboarding entitlement schema + operator-only grant/revoke/read + append-only history | **Implemented + verified** (revision `0014`) |
| Single-ACTIVE uniqueness, terminal revocation, immutable provenance, explicit positive quota | **Implemented + verified** |
| Restricted-runtime denial of every v014 function and table | **Implemented + verified** |
| Migration postflight + unchanged 78-signature runtime allowlist | **Implemented + verified** |
| Quota/replay ledger and first-Tenant composite (Tenant + Identity/Principal/steward + initial pair) | **BLOCKED — not implemented** |
| Runtime admission read surface | **BLOCKED** (part of the composite seam) |
| HTTP onboarding / operator sign-in / privileged adapter | **Out of scope** (PR 24 / prerequisite) |

## 2. Changed files (implementation)

- `packages/mtmf-core/src/mtmf_core/domain/onboarding_entitlement.py` (new)
- `packages/mtmf-core/src/mtmf_core/domain/errors.py` (new error type)
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v014/` (new: schema,
  functions, grants, assertions, `__init__.py`)
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/migrations/versions/0014_pr22_onboarding_entitlement.py` (new)
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/migration.py` (`HEAD_REVISION = "0014"`)
- `tests/unit/core/test_onboarding_entitlement.py` (new)
- `tests/integration/postgres/test_pr22_onboarding_entitlement.py` (new)
- Head-constant updates in existing unit/integration tests (`0013` → `0014`) and
  the exact function manifest in `tests/integration/postgres/test_migrations.py`.

No change to `mtmf-api`, `mtmf-client`, `mtmf-service` routing, the PR 14 token
verifier, the Rust engine, `0006`/`0012`, or Compose.

## 3. Tests executed

| Gate | Command | Result |
| --- | --- | --- |
| Unit + coverage | `./build.sh --qa` | PASS — 2472 passed, 3 warnings, 90.32% coverage |
| Security | `./build.sh --sec` | PASS — Bandit no issues; Semgrep 297 rules / 0 findings |
| Rust | `./build.sh --rust` | PASS |
| Integration | `./build.sh --integration` | PASS — 603 passed, 90 skipped |

New feature-specific integration evidence: 10 real-PostgreSQL tests
(`test_pr22_onboarding_entitlement.py`). Feature/E2E tests **NOT RUN**: the
blocked composite cases P22-07..P22-15 and the quota-exhaustion slice of
P22-06 (see `PR22_SECURITY_MATRIX.md`).

## 4. STOP status

- **STOP-P22-A (privilege boundary) — FIRED.**
- **STOP-P22-B (atomic stewardship/composite) — FIRED.**
- STOP-P22-C/D/E/F — not fired.

The composite must not be implemented without the explicit architectural
decision recorded in `PR22_STOP_REPORT.md`.

## 5. Roadmap

PR 22 is marked **`[PARTIAL — BLOCKED]`**; PRs 23–26 remain `[PLANNED]`. PR 22
must not be marked DONE while STOP-P22-A/B remain.

## 6. Verdict

- **Entitlement foundation acceptance: PASS.**
- **PR 22: PARTIAL — BLOCKED.**
- **v0.1 onboarding: NOT DONE.**
