# PR 17-B Security-Hardening Acceptance Report

**PR:** PR 17-B — security-hardening amendment
**Amended code tip:** `6471e392d4b2f0ecc617ced9c70e33ef10c489ba`
**Starting tip:** `0c9ee1e6ae75d41b56d4353c85c65060a0432f64`
**Base (`origin/main`):** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Branch:** `dev/pr17b-keycloak-user-provisioning`
**Working tree:** clean.

## 1. Canonical gates (amended code tip)

| Gate | Exact command | Result |
| --- | --- | --- |
| Bootstrap | `uv sync --locked` | PASS |
| QA | `./build.sh --qa` | **PASS** — 1878 passed, 0 failed; coverage **90.76%** (≥ 85%); Ruff format/lint and strict Mypy clean |
| Security | `./build.sh --sec` | **PASS** — Bandit Medium/High 0, Semgrep 0 findings |
| Rust | `./build.sh --rust` | **PASS** — cargo fmt/clippy/test, `maturin develop`, installed-native probe, focused tests, clean wheel build/install/use, benchmark smoke |
| Integration | `set -a; . ./.env; set +a; ./build.sh --integration` | **PASS** — 564 passed, 61 skipped |

The pre-commit hooks (Gitleaks, `--rust`, `--qa`, `--sec`) also ran on `6471e39`.

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
# 61 passed in 179.74s
```

- PR 14 live actor trust: 22 passed.
- PR 17 live HTTP/reader: 29 passed.
- PR 17-B live acceptance (`test_pr17b_live_acceptance.py`): **9 passed**,
  including the new SH16 unverified-email OIDC login and the hardened I15a.
- PR 17-B Compose isolation: 1 passed.
- The full live I01–I20 matrix remains PASS (with the documented I15a change).

## 3. Focused hardening evidence

- **Email (SH01/SH16):** live `test_sh16_created_user_with_unverified_email_can_login`
  asserts the created Keycloak user has `emailVerified=False` and completes the
  approved real OIDC authorization-code login (verified `sub` equals the binding).
- **Provenance (SH04–SH11):** unit tests prove a definite 4xx is never converted
  to success, a successful create binds only the `Location`-provenanced id, and a
  conflict/uncertain outcome requires an explicit subject assertion. Live
  `test_i15a_lost_create_response_fails_closed_then_reconciles` and
  `test_i15b/c` confirm the behavior through the real fault proxy and real
  Keycloak.
- **TOCTOU (SH13):** deterministic same-descriptor test, oversize-after-`fstat`
  rejection, and descriptor-close-on-failure test.
- **Failpoint (SH15):** absent/near-miss/different-value inert; exact value exits
  before any MTMF write. No failpoint in `compose.dev.yaml`.
- **Isolation (SH18):** real Compose container inspection confirms privileged
  secrets only in the initializer.

## 4. Failures and classification

| Item | Classification | Detail |
| --- | --- | --- |
| None | — | No gate or live test failed on the amended tip. |

No test was skipped, weakened, xfailed, waived, or replaced with a fake. The only
intentional expectation change is I15a, required by the new policy and documented
in `PR17B_SECURITY_HARDENING_RECONCILIATION_DECISION.md` §6.

## 5. Remaining limitations

- The standard Compose `up` issuer-hostname limitation remains a **separate
  infrastructure PR** (Option A). It was not modified or claimed fixed.
- `O_NOFOLLOW` protects only the final path component; ancestor-directory and
  pre-open path attacks remain out of scope for this small fix and are not
  claimed.
- Human security/architecture review is still required.

## 6. Status

**PR 17-B is NOT DONE and must not be merged until human approval.** All
mandatory evidence is committed; the roadmap remains `AWAITING HUMAN REVIEW —
NOT DONE`.
