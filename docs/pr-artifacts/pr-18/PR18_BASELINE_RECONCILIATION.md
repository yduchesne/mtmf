# PR 18 — Baseline Reconciliation

**Roadmap ID:** PR 18 — Official Python HTTP client and scoped authorization helper
**Branch:** `dev/mtmf-client-impl`
**Baseline commit (`origin/main` at start):** `ad30ff50feb84d8e2e9a15f6ca01b2ac01ec05c7`
**Date:** 2026-10-13
**Status of this report:** baseline only; no PR 18 implementation is claimed here.

## 1. Repository state at start

| Item | Value |
| --- | --- |
| Branch | `dev/mtmf-client-impl` |
| HEAD / `origin/main` | `ad30ff50feb84d8e2e9a15f6ca01b2ac01ec05c7` |
| `git status --short` | clean |
| Last merged PR | Merge PR #53 `dev/pr17c-keycloak-issuer` |
| Latest worktree commit | `212dee1 PR 17-C Fixup 3: clean-reset execution report` |

The branch point equals fresh `origin/main`; the dedicated PR 18 branch was created from
fresh `origin/main` and is **not** a continuation of `dev/pr17c-keycloak-issuer`.

## 2. Authoritative references inspected

- `AGENTS.md`
- `docs/SECURITY_MODEL.md`
- `docs/AUTHORIZATION.md`
- `docs/DOMAIN_MODEL.md`
- `docs/ARCHITECTURE.md`
- `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`
- `docs/pr-artifacts/pr-12/PR12_INTEGRATION_SECURITY_DECISIONS.md`
- `docs/pr-artifacts/pr-15/PR15_HTTP_API_V1_CONTRACT.md`
- `docs/ROADMAP_V01.md`
- `docs/DEVELOPMENT_SETUP.md`
- `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`

## 3. Existing contracts reused unchanged

- `packages/mtmf-api/src/mtmf_api/authorization.py` — immutable detached DTOs
  (`ActionRequest`, `ResourceTarget`, `ResourceKind`, `AuthorizationBatchRequest`,
  `AuthorizationBatchResponse`, `AuthorizationEffect`, `DecisionReason`), TTL constants
  (`SNAPSHOT_DEFAULT_TTL = 60s`, `SNAPSHOT_MAX_TTL = 300s`,
  `SNAPSHOT_SENSITIVE_MAX_TTL = 15s`), Action URN validation.
- `packages/mtmf-api/src/mtmf_api/json_codec.py` — `serialize_request`,
  `parse_response_json`, `parse_error_json`; strict duplicate-member/unknown-field/
  non-finite rejection.
- `packages/mtmf-api/src/mtmf_api/conformance.py` — `validate_response_for_request`
  (exact ordered `request_id` correlation plus Tenant/Organization equality).
- `packages/mtmf-api/src/mtmf_api/errors.py` — stable `ApiErrorCode` catalog and
  `ERROR_HTTP_STATUS` mapping.

## 4. Real server-side wire contract evidence

Inspected live `main` server adapter rather than stale status prose:

- Route: `POST /v1/authorization/evaluate` (`packages/mtmf-service/src/mtmf_service/app.py`).
- Service credential header: `Authorization: Bearer <service>`
  (`transport.extract_service_token`).
- Acting-user header: `X-MTMF-User-Authorization: Bearer <user>`
  (`settings.USER_AUTHORIZATION_HEADER`, `transport.extract_user_token`).
- Request media type: exactly one `application/json`; no content-encoding
  (`transport.enforce_json_content_type`).
- Success: HTTP 200 `application/json`, `Cache-Control: no-store`, exact PR 15 ordered
  response (`serialize_response`).
- Errors: HTTP status from `ERROR_HTTP_STATUS` with the static PR 15 error envelope.
- 401 (`UNAUTHENTICATED`, message "Service authentication failed") carries **no
  machine-readable service-token-expiry signal**. There is no header or code that
  distinguishes "expired service token" from any other authentication failure, so the
  controlled 401 retry is **NOT APPLICABLE — deferred by contract** (plan §6 Step 4 and
  §7 CL-U24). No unsafe 401 retry is implemented.
- Sensitivity: `packages/mtmf-service/src/mtmf_service/sensitivity.py` uses the
  `ConservativeSensitiveActionClassifier`, which classifies **every** Action as
  sensitive, bounding every response to 15 seconds. There is no public sensitivity
  contract in `mtmf-api`. PR 18 therefore conservatively caps the whole client snapshot
  at 15 seconds (plan §6 Step 9, STOP condition 5 not triggered because the conservative
  cap is accepted).

## 5. Baseline test execution

Command (canonical unit gate executor, run at baseline):

```bash
uv run --no-sync pytest tests/unit -q
```

Result: **2153 passed**, total coverage **90.75%** (gate `>= 85%`). No PR 18 code exists
at baseline, so `mtmf-client` contributed only its trivial `__init__` module.

## 6. Baseline delta classification (PR 18 scope)

| Capability | Baseline status | PR 18 action |
| --- | --- | --- |
| `mtmf-api` immutable DTOs / strict codecs / conformance | DONE + VERIFIED | Reuse unchanged |
| PR 17 authenticated HTTP endpoint and error envelope | DONE + VERIFIED | Reuse unchanged |
| `mtmf-client` package scaffold | DONE, NOT A CLIENT | Extend in place |
| OAuth2 service client-credentials acquisition/renewal | NOT STARTED | Implement |
| Explicit verified-user token propagation | NOT STARTED | Implement |
| Strict remote batch evaluation and error handling | NOT STARTED | Implement |
| Scoped monotonic snapshot and `is_allowed`/`require` | NOT STARTED | Implement |
| PR 18 production-path live acceptance | NOT STARTED | Implement |
| PR 20 ATI integration | OUT OF SCOPE | Do not implement |

## 7. Environmental facts

- Python 3.14.7, `httpx` 0.28.1 available in the locked environment.
- Podman development stack running at baseline: `mtmf_postgres_1` (PostgreSQL 18,
  host `127.0.0.1:25432`), `mtmf_keycloak_1` (Keycloak 26.8.0-1, host `127.0.0.1:28080`
  and `127.0.0.1:28443`), `mtmf_forwarder_1`, `mtmf_service_1`.
- Development CA material present at `/tmp/mtmf-dev-ca/` (`dev-ca.crt`).
- No PR 14 live Keycloak credentials are present in the checked-in `.env`; live PR 18
  acceptance therefore depends on the operator-supplied PR 14 environment described in
  `tests/integration/postgres/test_pr17_live_http.py`. See `PR18_LIVE_ACCEPTANCE_REPORT.md`
  for the actual execution disposition.

## 8. Divergences / STOP conditions found

None at baseline. The frozen v1 headers, DTOs, strict codec, conformance check and error
catalog agree with the plan. No `mtmf-api` or PR 17 change is required.
