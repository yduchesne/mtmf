# PR20A_FINAL_ACCEPTANCE_REPORT

**PR:** roadmap PR 20A — MTMF Reference Application Foundation
**Branch:** `dev/pr20a-reference-app`
**Baseline SHA:** `56695c08e5b71a032877f319aa05193db31a47ec` (`origin/main`)
**Final SHA:** the commit on `dev/pr20a-reference-app` that contains this report.
**Status:** **DONE** (all required acceptance criteria met).

## 1. Outcome

An independently packaged, independently deployed reference consumer
(`mtmf-reference-app`) now proves one complete production-path read vertical
slice: cryptographic end-user authentication at the app boundary, Tenant-scoped
local resource lookup, a real outbound MTMF `/v1/authorization/evaluate` decision
through the official `mtmf-client`, exact local `require` enforcement, and an
observable ALLOW **and** policy DENY for the same seeded document. No ATI
dependency; PR 20B remains PLANNED.

## 2. Objective acceptance criteria

| # | Criterion | Result |
| --- | --- | --- |
| 1 | P0 policy-registration gate resolved with evidence | RESOLVED via existing privileged primitives; see [PR20A_BASELINE_RECONCILIATION.md](PR20A_BASELINE_RECONCILIATION.md) §3 |
| 2 | Independently packaged/deployed app, official client only, no private MTMF dependency | `examples/mtmf-reference-app`, Dockerfile, no `mtmf-core`/`mtmf-service` import |
| 3 | Real Keycloak user tokens and real OAuth2 service credentials verified on the correct boundaries | L01/L02 with scripted Authorization Code + PKCE and client-credentials service token |
| 4 | Real deployed MTMF ALLOW **and** DENY for the same document | L01 → 200 exact body; L02 → 403 with evaluate+`access_denied` evidence |
| 5 | Invalid auth / missing resource / cross-Tenant deny without leaking | L03 → 401, L04/L05 → 404, no body, no evaluation |
| 6 | COLD/REPEAT/RECREATE each execute L01–L05, no skips/retries | 3 × 5 = 15 checks, 0 skipped; see [PR20A_DEPLOYED_ACCEPTANCE_REPORT.md](PR20A_DEPLOYED_ACCEPTANCE_REPORT.md) |
| 7 | Canonical gates pass; example coverage reported | `--qa`, `--sec`, `--rust`, `--integration` pass; example 89.6% |
| 8 | Default stack and unrelated resources untouched | launcher inventory check passed |
| 9 | Reports committed under `docs/pr-artifacts/pr-20a/`, roadmap marks only PR 20A DONE | this directory; `docs/ROADMAP_V01.md` updated |

## 3. Canonical gate results (executed)

| Gate | Command | Observed result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | Ruff format/lint clean, strict Mypy clean, **2448 passed**, coverage **90.36%** (≥ 85) |
| Security | `./build.sh --sec` | Bandit + Semgrep, **0 findings** |
| Rust/native | `./build.sh --rust` | cargo fmt/clippy/test, `maturin develop`, probe, focused native tests, clean wheel, benchmark smoke — **PASS** |
| Integration | `set -a; source .env; set +a; ./build.sh --integration` | **593 passed, 90 skipped** (opt-in live tests) |
| Example package | `uv run pytest examples/mtmf-reference-app/tests --cov=mtmf_reference_app --cov-fail-under=85` | **66 tests passed**, coverage **89.6%** |
| Live E2E | `scripts/pr20a-reference-acceptance.py acceptance` | **3 cycles × 5 passed, 0 skipped** |

Skipped integration tests are the documented opt-in live suites (PR 17/18/19C),
not new PR 20A skips.

## 4. Example unit-test matrix

| ID | Test(s) | Result |
| --- | --- | --- |
| U01 | invalid issuer/audience/secret/CA/UUID/timeout config | pass |
| U02 | schema initialization twice, no data loss | pass |
| U03 | same document id, wrong Tenant → no row | pass |
| U04 | missing/malformed/expired/wrong-audience/wrong-issuer/ID/refresh JWT → 401/503 fail closed, no PDP call | pass |
| U05 | verified subject absent from fixture mapping → deny, no PDP call | pass |
| U06 | malformed/noncanonical document id → 404 without leakage | pass |
| U07 | policy DENY → 403, body absent | pass |
| U08 | remote error/timeout/protocol failure → no 200 or body | pass |
| U09 | `ResourceTarget` derived from the loaded row; `require` exact tuple | pass |
| U10 | request-local session context (process-local keyed digest, per-token) | pass |
| U11 | fixture loader re-run consistent/inconsistent | pass |

## 5. Diff inventory

**New:**

```text
examples/mtmf-reference-app/pyproject.toml
examples/mtmf-reference-app/Dockerfile
examples/mtmf-reference-app/src/mtmf_reference_app/{__init__,__main__,config,models,store,auth,app,fixture_loader}.py
examples/mtmf-reference-app/tests/{conftest,helpers,test_config,test_store,test_auth,test_pep}.py
compose.pr20a-acceptance.yaml
scripts/pr20a-initialize.py
scripts/pr20a_reference_fixture.py
scripts/pr20a-reference-acceptance.py
scripts/pr20a-service-tls-proxy.py
tests/e2e/reference_app/test_pr20a_live_reference_app.py
docs/pr-artifacts/pr-20a/PR20A_BASELINE_RECONCILIATION.md
docs/pr-artifacts/pr-20a/PR20A_SECURITY_BOUNDARY_REVIEW.md
docs/pr-artifacts/pr-20a/PR20A_DEPLOYED_ACCEPTANCE_REPORT.md
docs/pr-artifacts/pr-20a/PR20A_FINAL_ACCEPTANCE_REPORT.md
```

**Narrowly modified:**

```text
docs/ROADMAP_V01.md        (PR 20A marked DONE; PR 20B left PLANNED)
docs/DEVELOPMENT_SETUP.md  (link to the reference-app instructions)
```

**Deliberately unchanged:** `packages/mtmf-api`, `packages/mtmf-client`,
`packages/mtmf-core`, `packages/mtmf-service`, `sql/v001`–`v013`,
`compose.yaml`, `compose.dev.yaml`, `compose.pr19c-acceptance.yaml`,
`dev/keycloak/expected-*.json`. The v1 wire schema, authorization semantics,
protected built-in policy, and `mtmf_runtime` grants are untouched.

## 6. Design decisions worth recording

- **Reference OAuth client.** The reference app uses the already-approved
  `mtmf-evidence-same-client` (audience mapper `mtmf-same-client-api`, client
  credentials + standard flow). The canonical approved Application `sample-app`
  is additionally registered by the initializer so the reviewed realm
  attestation (which attests every approved client) holds. Registering an
  approved client is the sanctioned initializer behavior; no client is created
  outside `expected-client-policy.json`.
- **Internal TLS terminator.** `ClientConfig` requires HTTPS. A small
  development-only TLS terminator (`scripts/pr20a-service-tls-proxy.py`) fronts
  the plaintext MTMF service on an internal alias (`mtmf.mtmf.test:29501`) with a
  leaf signed by the same development CA. TLS verification is never disabled.
- **Reference app privilege.** The reference app runs as an unprivileged
  in-container user (`uid 10001`). The privileged initializer hands the 0600
  client secret to that UID, and the acceptance secret directory is
  traverse-only (0711). The app mounts no MTMF DB volume/socket and holds no
  privileged MTMF credential.

## 7. Known limitations and PR 20B deferrals

PR 20B explicitly owns the broader conformance/resilience matrix: subscribed/
unsubscribed/suspended Tenant behavior; user/application/Tenant spoofing;
cross-Tenant isolation breadth; mixed-batch ALLOW/DENY; snapshot context binding,
default DENY, expiration and bounded revocation staleness; MTMF unavailability,
malformed responses and timeouts; concurrency/request isolation; and Rust/Python
parity and contract/migration regressions. PR 20A deliberately does **not**
claim production root recovery conformance, generic management CRUD, ATI
integration, durable cross-boundary IdP workflows, or production TLS termination.
