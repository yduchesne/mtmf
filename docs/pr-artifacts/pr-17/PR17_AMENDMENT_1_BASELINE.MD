# PR 17 — Amendment #1 baseline reconciliation

**PR identifier:** `PR 17` (roadmap `docs/ROADMAP_V01.md`).
**Branch:** `dev/pr17-http-service` (continued; no new PR branch).
**Agent:** coding agent, Amendment #1 execution plan.

## 1. Repository state at Phase 0

| Fact | Value |
| --- | --- |
| `origin/main` | `4eea688b12005b59aa8dbee9981f08551dcb7702` |
| Branch head | `6e92fca` (`docs(pr-17): record final gated SHA and gate evidence`) |
| Merge base | `4eea688` (equals `origin/main`) |
| Feature commit present | `6a33352` |
| Evidence commit present | `6e92fca` |
| Working tree | clean before amendment work |
| Keycloak image | `quay.io/keycloak/keycloak:26.8.0-1` |
| PostgreSQL | MTMF-owned `mtmf_postgres_1`, host `25432`, healthy |
| `podman` / `podman-compose` | `podman 4.x` / `podman-compose 1.0.6` |

## 2. Actual files and entry points inspected

| Concern | Symbol / path |
| --- | --- |
| App factory | `mtmf_service.app.create_app(settings, authorization_service, readiness, rate_limiter, admission=None)` |
| ASGI entry | `mtmf_service.asgi:app` / `create_app_from_env()`; `mtmf_service.__main__` |
| Orchestrator | `mtmf_service.evaluation.AuthorizationService.evaluate` |
| Composition | `mtmf_service.composition.build_dependencies` / `ServiceDependencies` |
| Transport guards | `mtmf_service.transport` (`read_bounded_body`, `extract_service_token`, `extract_user_token`, `enforce_json_content_type`, `peer_key`) |
| Settings | `mtmf_service.settings.ServiceSettings` / `DeploymentMode` |
| Readiness | `mtmf_service.readiness.ReadinessProbe` / `StaticReadiness` |
| Rate limiting | `mtmf_service.rate_limit.TokenBucketRateLimiter` |
| Sensitivity | `mtmf_service.sensitivity.ConservativeSensitiveActionClassifier` |
| PR 14 trust | `mtmf_core.application.authentication.AuthenticatedActorContextService`; `mtmf_service.authentication.composition.build_actor_context_service` |
| PR 13 eligibility | `mtmf_core.application.application_eligibility.ApplicationTenantEligibilityService` |
| PR 9 roles | `mtmf_core.application.effective_roles.EffectiveRoleResolver` |
| PR 16 batch | `mtmf_core.authorization.batch.BatchAuthorizer` (pure Python default) |
| Initializer | `scripts/mtmf-dev-initialize.py`; `mtmf_service.development_bootstrap.DevelopmentBootstrap` |
| Compose | `compose.yaml`, `compose.dev.yaml`, `Dockerfile.service`, `dev/keycloak/compose.yaml` |
| Live tests | `tests/integration/postgres/test_pr14_live_actor_context.py`, `.../test_pr17_live_http.py`, `.../test_pr17_dev_initializer.py` |

## 3. Baseline test evidence (reproduced)

| Suite | Command | Result |
| --- | --- | --- |
| Unit/ASGI | `./build.sh --qa` | 1,750 passed, 0 skipped, coverage 89.99% |
| New G4 concurrency | `pytest tests/unit/service/test_concurrency.py` | 6 passed |
| PR 14 live actor (real Keycloak + PostgreSQL) | `MTMF_PR14_LIVE=1 SSL_CERT_FILE=... pytest tests/integration/postgres/test_pr14_live_actor_context.py` | 22 passed after fixing 6 stale assertions (see §4) |
| PR 17 live HTTP (real Uvicorn + Keycloak + PostgreSQL) | `MTMF_PR17_LIVE=1 SSL_CERT_FILE=... pytest tests/integration/postgres/test_pr17_live_http.py` | 12 passed |
| Dev initializer (real PostgreSQL + live Keycloak client) | `python scripts/mtmf-dev-initialize.py` (fresh, then re-run) | exit 0, idempotent |

## 4. Regression found and fixed at baseline

The PR 17 core refinement introduced precise `INELIGIBLE_TENANT`,
`INELIGIBLE_REGISTRATION`, `INELIGIBLE_SUBSCRIPTION` failure categories but
only the PR 14 unit assertions were updated. The six PR 14 **live**
assertions still expected the old `INELIGIBLE_CONTEXT`, so the live suite
failed (6 failed, 16 passed) once a live issuer was available. This is a
PR-17-introduced regression in test assertions (not in production behavior);
it is fixed in `tests/integration/postgres/test_pr14_live_actor_context.py`
and the live suite now passes 22/22.

## 5. Available tooling and blockers

- Live Keycloak is runnable from the present image (started successfully; TLS
  + realm + clients configured via the approved PR 14 fixture scripts).
- Real PostgreSQL with the `mtmf_owner`/`mtmf_migrator`/`mtmf_runtime` roles
  is available.
- `Dockerfile.service` builds (`mtmf-service:dev`).
- Blocker: `podman-compose 1.0.6` cannot honor
  `depends_on: condition: service_completed_successfully`; handled by the new
  portable `scripts/mtmf-dev-stack.py` launcher.
- Blocker: container-internal Keycloak issuer hostname (`127.0.0.1:28443`) is
  not reachable from the service container; the executed deployment
  demonstration therefore runs the ASGI service on the host over loopback
  against Podman-hosted PostgreSQL/Keycloak (explicitly permitted for
  development).
- **STOP:** the acting-user carrier (G1) has no human approval; PR 17 remains
  not DONE and unmerged.
