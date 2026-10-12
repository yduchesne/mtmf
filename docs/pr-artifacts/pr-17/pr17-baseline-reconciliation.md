# PR 17 — Baseline reconciliation (Phase 0)

**PR identifier:** `PR 17` (roadmap `docs/ROADMAP_V01.md`, not a GitHub PR number).
**Artifact directory:** `docs/pr-artifacts/pr-17/`.
**Branch:** `dev/pr17-http-service`.
**Baseline commit:** `4eea688b12005b59aa8dbee9981f08551dcb7702` (`origin/main` at start; `git status --short` clean before edits).
**Executing agent:** coding agent, PR 17 execution plan.

## 1. Reconciled source facts

| Area | Observed state on fresh `origin/main` |
| --- | --- |
| PR 10 root bootstrap | Sanctioned stored functions `mtmf.bootstrap_root`, `mtmf.designate_steward`, `mtmf.activate_tenant`; no Python wrapper exists (installation/operator SQL only). |
| PR 13 eligibility | `mtmf_core.application.application_eligibility.ApplicationTenantEligibilityService` plus `evaluate_application_tenant_eligibility`. |
| PR 13 registry | `Application`, `ApplicationTenantRegistration`, `TenantApplicationSubscription`; operator-only mutation functions in `sql/v010`. |
| PR 14 actor trust | `AuthenticatedActorContextService.resolve(...)`; `mtmf_service.authentication.composition.build_actor_context_service`; fresh zero-cache `BaselineConfigurationAttestor`; bounded `JwksKeyProvider`/`PyJWTTokenVerifier`. Live acceptance was completed in PR 14 Amendment #4 (22 live cases, zero skips). |
| PR 15 wire contract | `mtmf-api` DTOs/codecs/errors/conformance; `DEFAULT_MAX_REQUEST_BYTES = 64 KiB`; no runtime dependencies. |
| PR 16 batch | `mtmf_core.authorization.batch.AuthorizationBatch` (1–100, one exact shared `AuthorizationContext` object) and pure-Python default `BatchAuthorizer`. |
| PR 9 effective roles | `mtmf_core.application.effective_roles.EffectiveRoleResolver` + `build_authorization_context`. |
| Migrations | Alembic head revision `0011_authentication_bindings`. |
| Service package | `packages/mtmf-service` previously depended only on `mtmf-api`, `mtmf-core`, `pyjwt[crypto]`; no HTTP framework. |
| Compose | Root `compose.yaml` declared PostgreSQL 18 only (host `25432`). A separate evidence-only Keycloak fixture lives at `dev/keycloak/compose.yaml` (loopback `28080`/`28443`, project `mtmf-pr14-keycloak`). |

## 2. Determinative execution decisions

### 2.1 User-token transport carrier (REVIEWER DECISION REQUIRED)

PR 14 froze no HTTP transport carrier for the independently verified acting-user token: it owns the provider-neutral verification contract only, and PR 17 owns the HTTP route. The plan authorizes a service-only
`X-MTMF-User-Authorization: Bearer <user-token>` header **only after reviewer approval**, and forbids guessing a new convention.

This PR therefore implements the documented fallback header and **flags it as requiring explicit reviewer approval before merge**. It is rejected if duplicated/absent/ambiguous and is never trusted without PR 14 verification.

### 2.2 Core failure-category refinement (narrow integration composition)

The PR 14 `AuthenticationFailure` taxonomy overloaded `INELIGIBLE_CONTEXT` for
ordinary-Tenant/membership failures and for registration/subscription
ineligibility, while the PR 15 error table requires distinct public codes
(`UNTRUSTED_ACTOR` vs `INELIGIBLE_APPLICATION`). This PR adds three additive,
precise categories (`INELIGIBLE_TENANT`, `INELIGIBLE_REGISTRATION`,
`INELIGIBLE_SUBSCRIPTION`), keeps the old member for compatibility, and adds an
optional non-sensitive `slot` attribute (`"service"`/`"user"`) to
`AuthenticationError` for exact 401/403 mapping. No authentication predicate,
check order, or granted authority is weakened; the PR 14 unit assertions were
updated to the precise categories.

### 2.3 Sensitivity classification (conservative default)

No authoritative Action-sensitivity catalog exists. Per plan B1, the default
`SensitiveActionClassifier` is the conservative one (every Action sensitive →
15 s TTL for every response). A reviewed allowlist classifier can be injected
explicitly.

### 2.4 `mtmf_owned` resource targets

No approved, typed, authoritative MTMF-owned target/qualifier mapping exists, so
every `mtmf_owned` target is denied with `UNSUPPORTED_RESOURCE`; `capability` and
`application_owned` remain action-level decisions. A residual risk is recorded
in the security report: there is no authoritative Action→dominance metadata, so
`dominance_requirement` is `NONE` for all requests.

## 3. Real-acceptance precondition status

- PostgreSQL 18 is available in the environment (MTMF-owned `mtmf_postgres_1`, host `25432`).
- Keycloak `26.8.0-1` image is present but no live issuer was started/attested during this execution.
- **V01–V16 real (live Keycloak + real ASGI/Uvicorn) acceptance is NOT EXECUTED.**

Per plan §13 STOP condition 11, `NOT EXECUTED ≠ PASS`, and PR 17 is therefore
**not marked DONE** and remains unmerged pending reviewer approval.

## 4. Baseline gates (before feature work)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS after the expected PR 17 metadata-test update (baseline had one test asserting `mtmf-service` had no HTTP framework) |
| `./build.sh --sec` | PASS |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS with exported `.env` (556 passed, 22 skipped — the 22 are the opt-in PR 14 live-Keycloak cases and are **not** acceptance PASS) |

## 5. STOP/deviation register

| ID | Item | Disposition |
| --- | --- | --- |
| D1 | User-token HTTP carrier is not frozen by PR 14 | Implemented documented fallback header; **requires reviewer approval** before merge. |
| D2 | No Python API for the PR 10/13/14 operator primitives | The initializer calls only the existing sanctioned stored functions through a privileged one-shot; no new schema/function/grant/root authority. |
| D3 | No authoritative Action-sensitivity/dominance metadata | Conservative 15 s TTL; `mtmf_owned` denied; residual risk recorded. |
| D4 | Real Keycloak/PostgreSQL end-to-end acceptance | NOT EXECUTED; PR 17 not DONE. |
| D5 | Podman Compose one-shot ordering | `podman-compose 1.0.6` does not reliably support `service_completed_successfully`; deployment wiring is provided but **not acceptance-verified**. |
