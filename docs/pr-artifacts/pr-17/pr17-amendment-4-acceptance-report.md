# PR 17 — Amendment #4 acceptance report

**Branch:** `dev/pr17-http-service`. **Base:** `4eea688`; prior head `df2b8a7`.
**Amendment #4 feature commit:** `__FILL_AFTER_COMMIT__` (all gates and the
pre-commit hook ran on this tree).
**Disposition: IMPLEMENTATION COMPLETE — ACCEPTANCE COMPLETE — READY FOR HUMAN REVIEW.**
(No self-merge; PR 17 is not marked DONE until a human reviews this branch.)

## 1. Human approvals (recorded 2026-10-12)

| Gate | Decision | Reference |
| --- | --- | --- |
| D1 acting-user carrier | **APPROVE** | `pr17-amendment-4-decision-register.md` |
| D2 attestation architecture | **APPROVE** | same |
| D3 development topology | **APPROVE (dev only)** | same |
| V13 conditional destructive testing | **APPROVE (new disposable MTMF-only resources)** | same |

## 2. Implementation

- **D2:** realm-security projection + independently approved expected-client
  policy + effective-client verification + explicit duplicate rejection, all
  through the existing PR 14 seam; fresh per-authentication, no cache, no
  live-derived baseline, no auto-repair. Initializer validates against the
  policy before creating and fails closed on drift. See
  `pr17-amendment-4-attestation-implementation.md`.
- **D3:** development-only `--network=host` launcher path bound to `127.0.0.1`
  with only runtime + attestation-reader env. See
  `pr17-amendment-4-deployment-evidence.md`.
- **V12:** two genuine Keycloak clients/Applications, CL01–CL07.
- **V13:** isolated disposable MTMF-only PostgreSQL project created, destroyed,
  recreated; shared resources untouched. See
  `pr17-amendment-4-v12-v13-evidence.md`.

## 3. Final gates

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 1775 passed, 0 skipped, coverage 89.98% |
| Security | `./build.sh --sec` | PASS (0 findings) |
| Rust | `./build.sh --rust` | PASS (pre-commit hook) |
| Integration | `./build.sh --integration` | PASS — 564 passed, 48 skipped (the 48 = PR 14 live 22 + PR 17 live 26, run separately and passing) |
| PR 14 live actor | opt-in `MTMF_PR14_LIVE` | PASS — 22 passed |
| PR 17 live HTTP | opt-in `MTMF_PR17_LIVE` | PASS — 26 passed (incl. CL01–CL07) |
| Runtime timeouts | `test_pr17_runtime_timeouts.py` | 5 passed |
| Initializer | `test_pr17_dev_initializer.py` | 3 passed |
| Pre-commit | commit hook | PASS |

## 4. Acceptance criteria

| ID | Status | Note |
| --- | --- | --- |
| A4-01 | PASS | baseline §1; branch/head verified |
| A4-02 | PASS | drift + field inventory reproduced |
| A4-03 | PASS | D2 approved before implementation |
| A4-04 | PASS | realm-security projection + prior client checks retained |
| A4-05 | PASS | effective client scopes/mappers verified |
| A4-06 | PASS | unknown/duplicate/drifted/malformed fail closed |
| A4-07 | PASS | no live-derived baseline, no cache, no alias/TLS bypass |
| A4-08 | PASS | initializer creates only approved clients; drift fails closed |
| A4-09 | PASS | AT01–AT18 (one partial, AT16 curated allowlist) |
| A4-10 | PASS | D1 recorded; header tests |
| A4-11 | PASS | D3 recorded |
| A4-12 | PASS | container loopback-bound, ready, real ALLOW/DENY |
| A4-13 | PASS | runtime env excludes privileged credentials (residual reader) |
| A4-14 | PASS | V12 two clients, CL01–CL07 |
| A4-15 | PASS | V13 isolated disposal + ownership inventory |
| A4-16 | PASS | V13 destroy/recreate; shared untouched |
| A4-17 | PASS | V08 live outage/recovery |
| A4-18 | PASS | V01–V16 |
| A4-19 | PASS | PR 14 22/22, PR 17 26/26 |
| A4-20 | PASS | QA/sec/Rust/integration/pre-commit |
| A4-21 | PASS | nine reports + shared docs |
| A4-22 | PASS | approvals linked; residuals recorded; no self-merge |

## 5. Files changed

```
packages/mtmf-service/src/mtmf_service/authentication/attestation.py
packages/mtmf-service/src/mtmf_service/authentication/config.py
packages/mtmf-service/src/mtmf_service/authentication/composition.py
packages/mtmf-core/src/mtmf_core/authentication/ports.py
packages/mtmf-core/src/mtmf_core/application/authentication.py
dev/keycloak/expected-realm-security.json        (new)
dev/keycloak/expected-client-policy.json         (new)
dev/keycloak/setup-realm.py
scripts/mtmf-dev-initialize.py
scripts/mtmf-dev-stack.py
compose.dev.yaml, .env.example
tests/unit/authentication/test_attestation.py
tests/unit/authentication/test_actor_context.py
tests/unit/service/conftest.py
tests/integration/postgres/test_pr14_live_actor_context.py
tests/integration/postgres/test_pr17_live_http.py
docs/pr-artifacts/pr-17/pr17-amendment-4-*.md
docs/ARCHITECTURE.md, docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md, docs/ROADMAP_V01.md
```

## 6. Residuals and disposition

Residuals recorded in `pr17-amendment-4-stop-deviation-register.md` (read-only
attestation reader, curated realm-field allowlist, per-batch downstream budget,
host-network isolation, V13 Keycloak-state reuse, initializer user subject).

**Disposition:** IMPLEMENTATION COMPLETE — ACCEPTANCE COMPLETE — READY FOR HUMAN
REVIEW. PR 17 is **not** merged and is **not** marked DONE pending human review.
