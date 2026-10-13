# PR 17-B Amendment Acceptance Report

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Amendment:** acceptance-completion amendment
**Final amendment tip:** `e860e214d7cbddbe0b58d82267041a687ad39907` (reports; code/test tip `ca23d11ebbb2f7c316be444aeb594c38d7114d6f`)
**Base:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Branch:** `dev/pr17b-keycloak-user-provisioning`

This report supersedes the incomplete matrix in `PR17B_ACCEPTANCE_REPORT.md` §4.
Statuses are `PASS`, `FAIL`, `NOT EXECUTED`, or `WAIVED BY HUMAN` only.

## 1. Canonical gates (final amendment tip `ca23d11`)

| Gate | Exact command | Result |
| --- | --- | --- |
| Bootstrap | `uv sync --locked` | PASS |
| QA | `./build.sh --qa` | **PASS** — 1863 passed, 0 failed; coverage **90.70%** (≥ 85%); Ruff format/lint and strict Mypy clean |
| Security | `./build.sh --sec` | **PASS** — Bandit Medium/High 0, Semgrep 0 findings |
| Rust | `./build.sh --rust` | **PASS** — cargo fmt/clippy/test, `maturin develop`, installed-native probe, focused tests, clean wheel build/install/use, benchmark smoke |
| Integration | `set -a; . ./.env; set +a; ./build.sh --integration` | **PASS** — 564 passed, 60 skipped (9 new live/compose cases skipped without their flags) |
| Live PR 14/17 regression | `MTMF_PR14_LIVE=1 MTMF_PR17_LIVE=1 SSL_CERT_FILE="$MTMF_PR14_KC_CA_FILE" uv run --no-sync pytest tests/integration/postgres/test_pr14_live_actor_context.py tests/integration/postgres/test_pr17_live_http.py tests/integration/postgres/test_pr17_attestation_reader_permissions.py --no-cov -q` | **PASS** — 51 passed, 0 skipped |
| Live PR 17-B + Compose | add `MTMF_PR17B_LIVE=1 MTMF_PR17B_COMPOSE=1` and the two new files | **PASS** — 9 passed |

The pre-commit hooks (Gitleaks, `--rust`, `--qa`, `--sec`) ran the full gates on
`ca23d11` during the commit and passed.

Combined live run on the final tip (exact command):

```sh
MTMF_PR14_LIVE=1 MTMF_PR17_LIVE=1 MTMF_PR17B_LIVE=1 MTMF_PR17B_COMPOSE=1 \
  SSL_CERT_FILE="$MTMF_PR14_KC_CA_FILE" MTMF_PR14_KC_TLS_DIR=/tmp/mtmf-pr14-kc-tls \
  uv run --no-sync pytest \
    tests/integration/postgres/test_pr14_live_actor_context.py \
    tests/integration/postgres/test_pr17_live_http.py \
    tests/integration/postgres/test_pr17_attestation_reader_permissions.py \
    tests/integration/postgres/test_pr17b_live_acceptance.py \
    tests/integration/postgres/test_pr17b_compose_isolation.py \
    --no-cov -q
# 60 passed in 132.58s
```

## 2. Amendment case status

| Case | Status | Test | Topology | Evidence |
| --- | --- | --- | --- | --- |
| I10 incompatible binding | **PASS** | `test_i10_incompatible_existing_binding_fails_closed` | production initializer + Keycloak + PostgreSQL | Sanctioned `mtmf.external_subject_identity_add` seeded a conflicting active binding for the verified `sub`; initializer exited non-zero with `conflicts with the expected development Identity`; the conflicting row was unchanged and no rebind occurred. |
| I12 two simultaneous initializers | **PASS** | `test_i12_two_simultaneous_initializers_converge` | two initializer processes + `threading.Barrier` | Both processes converged on one Keycloak user and one binding; counts `(1,1,1,1,1)`; idempotent retry succeeded. |
| I13 terminate after Keycloak create | **PASS** | `test_i13_i14_kill_after_create_then_restart_is_idempotent` | initializer failpoint + Keycloak + PostgreSQL | `MTMF_DEV_TEST_FAILPOINT=after-user-verify` exited 99; Keycloak user existed and the schema had zero MTMF rows; normal rerun bound the same `sub`. |
| I14 restart after MTMF commit | **PASS** | same test (third run) | as above | A further unchanged run kept counts `(1,1,1,1,1)`, one Keycloak user, and the same binding; the original password still produced an identical OIDC `sub`. |
| I15 lost POST response / unsuccessful / indeterminate | **PASS** | `test_i15a_*`, `test_i15b_*`, `test_i15c_*` | loopback fault proxy forwarding to real Keycloak | (a) real POST committed then response dropped → exactly one create POST, re-read reconciled, exit 0; (b) POST not forwarded (400) → exit 1, no user, no binding; (c) POST committed then lookups 503 → exit 1, user exists, no binding. |
| I16 container env / secret-mount isolation | **PASS** | `test_i16_compose_container_isolation_and_live_secret_mount` | real `compose.yaml` + `compose.dev.yaml` containers + composed image live run | Initializer container carried `MTMF_AUTH_ADMIN_PASSWORD`, `MTMF_PR14_KC_ADMIN_PASSWORD`, `MTMF_MIGRATOR_DATABASE_URL`, `MTMF_DEV_USER_*` and the read-only `/run/mtmf-secrets` mount (`RW=false`); the HTTP service container had none of them and no secret mount; the live container run against real Keycloak succeeded and the generated password never appeared in logs; the mounted file was `0600`. |
| I18 multiple Applications | **PASS** | `test_i18_multiple_approved_applications` | production initializer + Keycloak + PostgreSQL | `sample-app,evidence-same-client` (both in the approved policy) produced two Applications, registrations, subscriptions and service bindings, stable across a second run. |
| I20 Tenant override / conflict | **PASS** | `test_i20_tenant_override_is_idempotent_and_conflict_fails_closed` | production initializer + Keycloak + PostgreSQL | Nondefault Tenant key/name were persisted with a stewardship designation and binding; the rerun was idempotent; a conflicting name for the same key exited non-zero without renaming. |

## 3. Full I01–I20 reconciliation

| ID | Status | Note |
| --- | --- | --- |
| I01 fresh create | PASS | Re-verifiable via `test_pr17b_live_acceptance` helpers; prior evidence in `PR17B_ACCEPTANCE_REPORT.md`. |
| I02 restart unchanged | PASS | Equivalent to I14 third-run assertion. |
| I03 verified OIDC `sub` | PASS | `_oidc_login_sub` asserts the verified token `sub` equals the binding inside I13/I14. |
| I04 service OAuth + HTTP | PASS | `test_pr17_live_http.py` in the 60-test live run. |
| I05 existing user, create=false | PASS | I10 uses create=false against an existing user. |
| I06 missing + create=false | PASS | Existing live/unit evidence. |
| I07 assertion mismatch | PASS | Existing live/unit evidence. |
| I08 disabled / email drift | PASS | Existing live evidence. |
| I09 wrong realm/admin/TLS | PASS | Existing live evidence. |
| I10 | PASS | See §2. |
| I11 unsafe secret mount | PASS | Unit U11; live in prior report. |
| I12 | PASS | See §2. |
| I13 | PASS | See §2. |
| I14 | PASS | See §2. |
| I15 | PASS | See §2. |
| I16 | PASS | See §2. |
| I17 PR 14/17 regression | PASS | 51 passed in the combined run. |
| I18 | PASS | See §2. |
| I19 `--migrations-only` | PASS | Prior live evidence + unit tests. |
| I20 | PASS | See §2. |

No case remains `NOT EXECUTED` or `WAIVED BY HUMAN`.

## 4. Failure classification

| Item | Classification | Detail |
| --- | --- | --- |
| Tenant-name drift not failing closed (found designing I20) | **Feature defect (pre-existing)** | Reproduced against `f0de6b1`; fixed in `ca23d11` with the I20 regression test. Not a regression introduced by this amendment. |
| Initial I10 assertion compared a `psycopg` `UUID` to a `str` | **Harness defect** | Test-only; corrected. |
| PR 14 live run first failed 20 cases with `attestation credential request failed` | **Environment/harness failure** | Missing fixture CA trust (`SSL_CERT_FILE`); re-run with the CA passed 51/51. Not a PR 17-B regression. |
| Compose cleanup left dependency-ordered containers | **Harness defect** | Test-only; cleanup now removes leaf-first. |
| Gitleaks flagged hardcoded test passwords | **Harness/policy finding** | Test-only literals replaced with runtime-generated values. |

No mandatory gate was skipped, weakened, or silently retried into a pass.

## 5. Unresolved risks

- `scripts/mtmf-dev-stack.py up` as a single command remains blocked by the
  pre-existing issuer-hostname limitation documented in PR 17 Amendment #1 (the
  host-side Keycloak wait and the in-container Admin REST base share one variable).
  I16/I20 therefore use the real Compose container definitions plus a documented
  host-network `podman run` of the composed image. This is a topology limitation,
  not a PR 17-B behavior gap; no approved design was changed.
- Human security/architecture review is still required.
