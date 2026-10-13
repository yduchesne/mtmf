# PR 17-B Acceptance Report

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Base commit:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Implementation commit:** `362aae664c4f76a88c69ae25421249346b5591c7` (core) + `9e074fb09e92b1db37f96496f3f256ef49196e1a` (brokered-account hardening); final tip `9e074fb`
**Branch:** `dev/pr17b-keycloak-user-provisioning`

## 1. Canonical gates (implementation commit)

| Gate | Exact command | Result |
| --- | --- | --- |
| Bootstrap | `uv sync --locked` | PASS |
| QA | `./build.sh --qa` | **PASS** — 1861 passed, 0 failed; coverage **90.70%** (gate ≥ 85%); Ruff format/lint and strict Mypy clean |
| Security | `./build.sh --sec` | **PASS** — Bandit Medium/High 0; Semgrep 0 findings |
| Rust | `./build.sh --rust` | **PASS** — cargo fmt/clippy/test, `maturin develop`, installed-native probe, focused tests, clean wheel build/install/use, benchmark smoke |
| Integration | `set -a; . ./.env; set +a; ./build.sh --integration` | **PASS** — 564 passed, 51 skipped (live tests opt-in) |

All four canonical gates were additionally executed by the repository pre-commit hooks during
`git commit`, and passed.

## 2. Live regression suites (real Keycloak + real PostgreSQL)

Command (operator supplied live Keycloak credentials and PostgreSQL role configuration; `SSL_CERT_FILE`
pointed at the fixture CA):

```sh
MTMF_PR14_LIVE=1 MTMF_PR17_LIVE=1 SSL_CERT_FILE="$MTMF_PR14_KC_CA_FILE" \
  uv run --no-sync pytest \
    tests/integration/postgres/test_pr14_live_actor_context.py \
    tests/integration/postgres/test_pr17_live_http.py \
    tests/integration/postgres/test_pr17_attestation_reader_permissions.py \
    --no-cov -q
```

Result: **51 passed** (PR 14 live 22 + PR 17 live HTTP/reader 29), zero skips, covering the requested
I04 (real service OAuth client + real HTTP batch evaluation, authorized/unauthorized) and I17 regression.

> Environment classification: an initial run without `SSL_CERT_FILE` failed 20 PR 14 cases with
> `attestation credential request failed`; re-running with the fixture CA trusted passed 51/51. That was a
> harness TLS-trust issue, not a regression: no PR 17-B code touches attestation, and the PR 17 HTTP tests
> passed in the same run.

## 3. Live PR 17-B acceptance evidence

Topology: real PostgreSQL (`mtmf_postgres_1`, prefix-2 port 25432) with the real migrator/runtime roles;
real Keycloak `mtmf-pr14-dev`; the production `scripts/mtmf-dev-initialize.py` entry point.

| ID | Scenario | Result |
| --- | --- | --- |
| I01 | Fresh empty schema + absent Keycloak user, `CREATE=true` | PASS — `development initialization complete`; 1 Keycloak user; correct binding; root/tenant/application/subscription counts `(1,1,1,1,1)` |
| I02 | Restart unchanged | PASS — identical KC `sub` and MTMF binding identity; counts unchanged; original password still authenticates (no reset) |
| I03 | Real OIDC authorization-code login | PASS — verified token `sub` equals the bound subject and `iss` equals the realm; signature verified against the live JWKS |
| I04 | Real service client + HTTP batch evaluation | PASS — covered by `test_pr17_live_http.py` (51-test live run) |
| I05 | Existing user, `CREATE=false` | PASS — initializes using the actual subject, no password read, no Keycloak mutation |
| I06 | Missing user, `CREATE=false` | PASS — nonzero exit, `no Keycloak user matches ... and creation is not enabled` |
| I07 | Expected-subject mismatch | PASS — nonzero, `assertion does not match the Keycloak user ID`, no binding written |
| I08 | Email drift / disabled user | PASS — `email does not match` / `user is disabled`, no repair |
| I09 | Wrong admin credential / wrong issuer / TLS | PASS — redacted `preflight failed with HTTP 400` / `issuer does not match` |
| I11 | Unsafe password file mount | PASS — `password file is not readable` (also unit U11) |
| I19 | `--migrations-only` with no user config | PASS — `migrations applied and runtime privileges verified`, no Keycloak I/O |

Representative non-secret I02 observation (performed with a clean schema and a freshly deleted Keycloak
user, then the initializer run twice):

```
after first run:  {"kc_user_count":1,"kc_sub":"a3a581d4-8e7c-4709-9d21-c86aebd7994d",
                   "binding_identity":"5e960a64-353f-501f-b39a-a4bf974150ca",
                   "counts":[1,1,1,1,1]}
after restart:    {"kc_user_count":1,"kc_sub":"a3a581d4-8e7c-4709-9d21-c86aebd7994d",
                   "binding_identity":"5e960a64-353f-501f-b39a-a4bf974150ca",
                   "counts":[1,1,1,1,1]}
OIDC after restart: verified sub a3a581d4-8e7c-4709-9d21-c86aebd7994d, iss .../realms/mtmf-pr14-dev
```

An earlier clean run produced a different user (`32487f24-...`) whose verified OIDC token `sub` also
matched its binding, confirming the flow is subject-agnostic.

## 4. Acceptance matrix status

**Amended 2026-10-12:** the previously unexercised cases below were completed live in the
acceptance-completion amendment on tip `ca23d11`. See
[`PR17B_AMENDMENT_ACCEPTANCE_REPORT.md`](PR17B_AMENDMENT_ACCEPTANCE_REPORT.md) for the exact
commands, topology, and evidence; that report supersedes this summary.

| ID | Status | Note |
| --- | --- | --- |
| I01–I09, I11, I17, I19 | PASS | Live or live-suite evidence above |
| I10 incompatible existing MTMF binding | PASS | Live amendment I10: sanctioned conflict seed, fail-closed, no rebind. |
| I12 two simultaneous initializers | PASS | Live amendment I12: barrier-launched processes converged on one user/binding. |
| I13 kill after Keycloak create before MTMF binding | PASS | Live amendment I13: failpoint exit 99, no MTMF rows, same `sub` on rerun. |
| I14 kill after MTMF commit / restart | PASS | Live amendment I13/I14 third run: stable counts, same binding, password unchanged. |
| I15 network timeout after POST | PASS | Live amendment I15a/b/c: real proxy, lost-response reconciliation, unsuccessful and indeterminate fail-closed. |
| I16 container env/mounts inspection | PASS | Live amendment I16: real Compose containers + composed-image run; read-only mount, privileged vars initializer-only. |
| I18 multiple Applications | PASS | Live amendment I18: two approved clients, no duplicates across restart. |
| I20 Tenant key/name override | PASS | Live amendment I20: override persisted, idempotent, conflicting name fails closed. |

## 5. Unit test matrix mapping

`tests/unit/service/test_pr17b_development_user.py` (45 tests) and
`tests/unit/service/test_pr17b_initialize_script.py` (13 tests) implement the matrix:

- U01 happy existing; U02 create-once; U03 matching assertion; U04 no mutation; U05 repeated;
- U06 missing + disabled creation; U07 mismatch; U08 email/disabled; U09 ambiguous; U10 fuzzy-only;
- U11 secret-file safety; U12 config validation; U13 HTTP/network redaction; U14 malformed/federated;
- U17 exact-vs-fuzzy; U18 URL encoding; U19 conflict/timeout/uncertain; U20 partial create; U22 unreadable
  password on existing user; U23 migrations-only; U24/U26 Compose wiring; U25 secret redaction;
- plus retry-delay, brokered-`origin` rejection, and password-file edge coverage (oversize, NUL, non-UTF-8,
  CRLF, read error).

U15/U16/U21/U27/U28 are exercised by the existing PR 17 integration/bootstrap tests and the production
refusal/preflight tests; see `PR17B_IMPLEMENTATION_REPORT.md`.

## 6. Not run / blockers

- All I-cases are now `PASS`; the amendment completed the previously unexecuted cases. See
  [`PR17B_AMENDMENT_ACCEPTANCE_REPORT.md`](PR17B_AMENDMENT_ACCEPTANCE_REPORT.md).
- `scripts/mtmf-dev-stack.py up` as one command remains limited by the pre-existing issuer-hostname
  blocker; I16/I20 use the real Compose container definitions plus a documented host-network composed-image
  run (see the amendment acceptance report §5).
- Human review is outstanding. Status: **implementation + live acceptance delivered, NOT DONE.**
