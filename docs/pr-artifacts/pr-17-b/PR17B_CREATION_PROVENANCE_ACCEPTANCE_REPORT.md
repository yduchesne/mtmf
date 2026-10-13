# PR 17-B Creation-Provenance Acceptance Report

**PR:** PR 17-B — strict created-resource provenance follow-up
**Amended code tip:** `acddeb3f3c8caabc631ab577729df0fb236fd0f5`
**Starting tip:** `f84cadd371a3f889fe79fd98464908b3a88b4225`
**Base (`origin/main`):** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Branch:** `dev/pr17b-keycloak-user-provisioning`
**Working tree:** clean.

## 1. Canonical gates (amended code tip)

| Gate | Exact command | Result |
| --- | --- | --- |
| Bootstrap | `uv sync --locked` | PASS |
| QA | `./build.sh --qa` | **PASS** — 1913 passed, 0 failed; coverage **90.75%** (≥ 85%); Ruff format/lint and strict Mypy clean |
| Security | `./build.sh --sec` | **PASS** — Bandit Medium/High 0, Semgrep 0 findings |
| Rust | `./build.sh --rust` | **PASS** — cargo fmt/clippy/test, `maturin develop`, native probe, focused tests, clean wheel build/install/use, benchmark smoke |
| Integration | `set -a; . ./.env; set +a; ./build.sh --integration` | **PASS** — 564 passed, 65 skipped |

The pre-commit hooks (Gitleaks, `--rust`, `--qa`, `--sec`) ran on `acddeb3`.

## 2. Live acceptance (real Keycloak + real PostgreSQL)

Topology: MTMF-owned PostgreSQL `mtmf_postgres_1` on prefix-2 loopback `25432`;
MTMF-owned Keycloak project `mtmf-pr14-keycloak`, realm `mtmf-pr14-dev`, loopback
`28080`/`28443`, self-signed TLS from `/tmp/mtmf-pr14-kc-tls/server.crt`;
initializer image `localhost/mtmf_initializer:latest`.

Exact command:

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
# 65 passed in 202.30s
```

- PR 14 live actor trust: 22 passed.
- PR 17 live HTTP/reader: 29 passed.
- PR 17-B live acceptance: **13 passed**, including the four new PV live cases.
- PR 17-B Compose isolation: 1 passed.

### New PV live evidence

| Test | Result | Evidence |
| --- | --- | --- |
| `test_pv_live_real_location_shape` | PASS | Real Keycloak `POST /admin/realms/{realm}/users` returns `201` with `Location: https://<admin-origin>/admin/realms/<realm>/users/<id>`; the lookup returns the same immutable id. |
| `test_pv_live_valid_location_via_proxy_succeeds` | PASS | Positive control through the real Keycloak + loopback proxy: a valid same-origin location is accepted and bound. |
| `test_pv_live_stripped_location_fails_closed_then_reconciles` | PASS | Real Keycloak committed the create but the proxy stripped `Location`; the initializer failed closed with "creation provenance could not be verified", wrote **zero** MTMF rows, and a rerun reused the now-existing account. |
| `test_pv_live_wrong_realm_location_fails_closed` | PASS | Real Keycloak committed; the proxy returned a wrong-realm location; the initializer failed closed with no MTMF binding. |

### Regression confirmations

I12 (two simultaneous initializers) PASS; I15a/I15b/I15c PASS; SH16
(unverified-email OIDC login) PASS; I01–I20 PASS.

## 3. Failures and classification

None on the amended tip. No test was skipped, xfailed, weakened, or replaced
with a fake. No STOP condition was triggered.

## 4. Remaining limitations

- The standard Compose `up` issuer-hostname limitation remains a **separate
  infrastructure PR**; unchanged and not claimed fixed.
- `_created_subject` validates only the final created-user resource; it does not
  attempt to validate arbitrary Keycloak URL grammars beyond this endpoint.
- Human security/architecture review is still required.

## 5. Status

**PR 17-B is NOT DONE and must not be merged until human approval.** All
mandatory evidence is committed; the roadmap remains `AWAITING HUMAN REVIEW —
NOT DONE`.
