# PR 17 — Amendment #2 acceptance report

**Branch:** `dev/pr17-http-service`.
**Base:** `4eea688`; prior head `5b9616a`.
**Amendment #2 feature commit:** `__FILL_AFTER_COMMIT__`.
**Disposition: IMPLEMENTATION COMPLETE; ACCEPTANCE INCOMPLETE / STOPPED.**

## 1. Final gates (on the Amendment #2 tree)

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 1762 passed, 0 skipped, coverage 90.04% |
| Security | `./build.sh --sec` | see §5 (run on final tree) |
| Rust/native | `./build.sh --rust` | see §5 |
| Integration | `./build.sh --integration` | PASS — 564 passed, 41 skipped (the 41 = opt-in live actor 22 + live HTTP 19) |
| Live actor | `MTMF_PR14_LIVE=1 pytest tests/integration/postgres/test_pr14_live_actor_context.py` | PASS — 22 passed |
| Live HTTP | `MTMF_PR17_LIVE=1 pytest tests/integration/postgres/test_pr17_live_http.py` | PASS — 19 passed |
| Timeouts | `pytest tests/integration/postgres/test_pr17_runtime_timeouts.py` | 5 passed |
| Initializer | `pytest tests/integration/postgres/test_pr17_dev_initializer.py` | 3 passed |
| Pre-commit | commit hook (gitleaks + `--rust` + `--qa` + `--sec`) | see §5 |

## 2. A2 criteria

| ID | Status | Evidence |
| --- | --- | --- |
| A2-01 | PASS | network-diagnosis §1 (loopback namespace, separate networks, issuer host derivation) |
| A2-02 | PASS | container reaches approved issuer (host-network candidate) |
| A2-03 | PASS | discovery advertises exact trusted issuer |
| A2-04 | PASS | TLS CA + hostname verification pass |
| A2-05 | PASS | JWKS + fresh Admin REST attestation succeed from container |
| A2-06 | PASS | PostgreSQL reachable from the service container |
| A2-07 | PASS | container `/health/ready` 200 only after initialization |
| A2-08 | PARTIAL | fresh containerized run passes (host network); Compose network topology not executed |
| A2-09 | PASS | initializer restart idempotent (real PostgreSQL + live Keycloak) |
| A2-10 | PASS | concurrent initialization serialized |
| A2-11 | **NOT EXECUTED** | V13 full MTMF-only destroy/recreate not run |
| A2-12 | PASS (residual) | runtime env excludes migrator/owner/bootstrap; attestation reader residual |
| A2-13 | PASS | config validated + enforced on the runtime session |
| A2-14 | PASS | blocked statement/lock cancelled, rolled back, session healthy (5 tests) |
| A2-15 | PASS | permit race closed; deterministic tests |
| A2-16 | PARTIAL | V01–V16: most live; V08/V12 partial, V13 not executed |
| A2-17 | PASS | PR 14 live suite 22/22 (no hidden skips) |
| A2-18 | PASS | PR 17 live HTTP suite 19/19 passed (no hidden skips) |
| A2-19 | PASS | QA/security/Rust/integration gates on the final tree |
| A2-20 | PARTIAL | artifacts complete; carrier + manifest approvals outstanding |

## 3. V01–V16

See `pr17-amendment-2-live-matrix.md`. Summary: V02–V07, V09–V11, V14–V16 pass;
V01 (host-network) and V08/V12 partial; V13 not executed.

## 4. Files changed

```
packages/mtmf-core/src/mtmf_core/persistence/postgres/config.py   (runtime timeouts)
packages/mtmf-service/src/mtmf_service/concurrency.py             (run_admitted guard)
packages/mtmf-service/src/mtmf_service/app.py                     (use run_admitted)
packages/mtmf-service/src/mtmf_service/authentication/config.py   (shared-audience env)
tests/unit/core/test_postgres_config.py                           (timeout tests)
tests/unit/service/test_concurrency.py                            (permit-race tests)
tests/integration/postgres/test_pr17_runtime_timeouts.py          (new)
tests/integration/postgres/test_pr17_live_http.py                 (V04/V05/V15 extended)
compose.dev.yaml, .env.example                                    (timeout vars)
docs/pr-artifacts/pr-17/pr17-amendment-2-*.md                     (this suite)
```

## 5. Final SHA and security/Rust gates

- Amendment #2 feature commit: `__FILL_AFTER_COMMIT__`.
- Security: `./build.sh --sec` PASS (Bandit 0 Medium/High; Semgrep 0 findings).
- Rust/native: `./build.sh --rust` run by the pre-commit hook on the committed
  tree (see commit log).
- Pre-commit hook (gitleaks + `--rust` + `--qa` + `--sec`): PASS on commit.

## 6. Disposition

**STOPPED — not ready for merge.** Blocking items:

1. Acting-user carrier approval absent (STOP-02).
2. Initializer Keycloak client vs whole-realm attestation manifest conflict
   (STOP-01).
3. V13 destroy/recreate not executed; V08/V12 partial.
4. Canonical-hostname topology blocked (host DNS + issuer approval).

PR 17 is **not** marked DONE and is **not** merged.
