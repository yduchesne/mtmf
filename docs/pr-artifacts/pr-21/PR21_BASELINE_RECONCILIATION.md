# PR21_BASELINE_RECONCILIATION

**PR:** roadmap PR 21 — Application-neutral onboarding architecture and API contracts
**Required PR artifact directory:** `docs/pr-artifacts/pr-21/`
**Execution branch:** `dev/onboarding-foundation`
**Baseline:** fresh `main`
**Baseline SHA:** `455ae7a35d090b2546afa0c78fc9e4750ffee5ec`
**Reconciliation status:** **PHASE 0 COMPLETE — documentation-only scope confirmed; STOP-01 opened (see `PR21_STOP_REPORT.md`).**

## 1. Fresh-main reconciliation

| Item | Value |
| --- | --- |
| `git rev-parse HEAD` at reconciliation | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| `git rev-parse origin/main` | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` (identical; no divergence) |
| Working tree | clean (`nothing to commit`) |
| Branch | `dev/onboarding-foundation` (equal to fresh `main`) |
| Alembic migration head | `0013_security_mutation_audit_partitioning` (`down_revision = "0012"`) |
| Python (uv environment) | 3.14.7 |
| PostgreSQL | 18 (image `docker.io/library/postgres:18`, container `mtmf_postgres_1`) |
| psycopg | 3.3.6 |
| Podman | 4.9.3 |
| Roadmap section | `docs/ROADMAP_V01.md` §"PR 21 — Application-neutral onboarding architecture and API contracts [PLANNED]" |

No divergence from the inspected architecture was found. Every code path named
in the execution plan was inspected directly; no file path was invented.

## 2. Authoritative documents read

- `AGENTS.md`
- `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`
- `docs/ROADMAP_V01.md` (PRs 10–26 and the CLI series)
- `docs/SECURITY_MODEL.md` (§§4, 5, 7, 10, 12–16, 18, 24–26)
- `docs/ROOT_AND_STEWARDSHIP.md`
- `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`
- `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md`
- `docs/CLI_ARCHITECTURE.md`
- `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`, `docs/AUTHORIZATION.md`, `docs/DATABASE.md`
- Existing PR-12/13/14/15/16/17/17-B/17-C/18/19/19A/19B/19C/20A/20B artifacts.

## 3. Verified repository anchors (as inspected on baseline SHA)

### 3.1 Domain

| Anchor | File | Observed state |
| --- | --- | --- |
| `Tenant` | `packages/mtmf-core/src/mtmf_core/domain/tenant.py` | Immutable `id`/`owner_identity_id`; `name` is mutable, **non-unique** presentation metadata; `lifecycle` defaults to `TenantLifecycle.PROVISIONING` for ordinary Tenants; root must be `ACTIVE`. There is **no** semantic/unique Tenant key. |
| `TenantStewardshipDesignation` | `packages/mtmf-core/src/mtmf_core/domain/stewardship.py` | Structural validator + lifecycle transition validator. Stewardship alone grants **no** Role/Permission/dominance. |
| `Identity`/`Principal` | `domain/identity_entity.py`, `domain/principal.py` | Global objects with no owning Tenant; Identity belongs to exactly one Principal. |
| `ExternalSubjectBinding` | `domain/authentication_binding.py` | Immutable `(issuer, subject)` → exactly one MTMF Identity; `ServiceCredentialBinding` maps `(issuer, client_id)` → exactly one Application; `BindingLifecycle` is `ACTIVE`/`REVOKED` terminal. |
| `Action` / Action URN | `domain/action.py`, `domain/iam_urn.py` | Exact URN `urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>`; wildcards rejected. Only the SYSTEM definition namespace is supported for Actions/Permissions. `BASELINE_ACTIONS` is explicitly not exhaustive. |

### 3.2 Application layer

| Anchor | File | Observed state |
| --- | --- | --- |
| `AuthenticatedActorContextService.resolve` | `application/authentication.py` | Two-token verification (service + user), fresh zero-cache attestation, OAuth cross-client check, persisted `(issuer, subject)`/`(issuer, client_id)` bindings, existing eligible ordinary Tenant **and membership**. It **cannot** authenticate the first user of a Tenant that does not yet exist, and rejects root. |
| `ManagementMembershipService` | `application/management_memberships.py` | The single trusted authenticated/authorized management mutation: verified actor → one UoW → ordered row locks → `EffectiveRoleResolver` + `Authorizer` → `VerifiedMutationProvenance` → atomic audited membership add. |
| `ManagementAuthorizationResolver` | `application/management_authorization.py` | Delegated cross-Tenant management context (PR 11); loads exactly the approved management Role; not a blanket cross-Tenant grant. |
| `EffectiveRoleResolver` | `application/effective_roles.py` | Reads persisted assignments + prerequisite memberships; fails closed for PROVISIONING/SUSPENDED Tenants; no caching. |
| `ApplicationTenantEligibilityService` | `application/application_eligibility.py` | Fail-closed eligibility (ACTIVE Application, ACTIVE Tenant, ACTIVE registration, ACTIVE in-window subscription); never an `ALLOW`. |
| `VerifiedMutationProvenance` | `application/mutation_provenance.py` | Immutable provenance + closed registration map. Currently registers exactly `identity_group_membership` → `urn:mtmf:iam:actions:system:identity-group-membership:add-object`. |

### 3.3 API / service

| Anchor | File | Observed state |
| --- | --- | --- |
| Management DTOs | `packages/mtmf-api/src/mtmf_api/management.py` | Immutable detached DTOs; nil-UUID rejection; no actor/Action/Role/audit fields. |
| Error catalog | `packages/mtmf-api/src/mtmf_api/errors.py` | `INVALID_REQUEST`(400), `UNAUTHENTICATED`(401), `UNTRUSTED_ACTOR`(403), `INELIGIBLE_APPLICATION`(403), `FORBIDDEN`(403), `REQUEST_TOO_LARGE`(413), `UNSUPPORTED_MEDIA_TYPE`(415), `RATE_LIMITED`(429), `DEPENDENCY_UNAVAILABLE`(503), `INTERNAL_ERROR`(500). **No 404/409/410 codes exist yet.** |
| Management HTTP adapter | `packages/mtmf-service/src/mtmf_service/management.py` | Narrow adapter; opaque `FORBIDDEN`; maps typed denials; performs no policy decision. |
| Composition | `packages/mtmf-service/src/mtmf_service/composition.py` | One shared actor service for evaluation and management; `Authorizer()` default; `EffectiveRoleResolver`. |
| Existing management route | `packages/mtmf-service/src/mtmf_service/app.py` | `POST /v1/management/identity-group-memberships` only; `201`/`200`; `Cache-Control: no-store`. |
| Service auth | `packages/mtmf-service/src/mtmf_service/authentication/{composition,config,jwt_verifier,attestation}.py` | Development Keycloak profile; JWKS and synchronous configuration attestation. Keycloak is a development fixture, not a public onboarding contract. |

### 3.4 Persistence

| Anchor | Observed state |
| --- | --- |
| `MtmfSpi` / `UnitOfWork` | `packages/mtmf-core/src/mtmf_core/persistence/spi.py`, `unit_of_work.py` — one provider, one real transaction per UoW, opt-in commit. |
| Stored-function convention | Owner-owned `SECURITY DEFINER`, fixed `search_path = ''`, `mtmf_runtime` exact-signature allowlist, mandatory post-upgrade privilege verifier. |
| Migration head | `0013`; `mtmf.tenant` currently has (`id`, `name`, `scope`, `owner_identity_id`, `lifecycle`, `deletion_status`, `extension`) — **no immutable semantic key and no idempotency table**. |
| Built-in seed | Revision `0006`: exactly 11 SYSTEM Roles / 11 PermissionSets / 11 exact Permissions / 3 shared Actions; 22 immutable UUID literals. Seeded Actions are `tenant:get-object`, `role:get-object`, `organization:get-object`. |

## 4. Existing-vs-missing onboarding inventory

| Capability | Classification | Evidence |
| --- | --- | --- |
| Global Identity/Principal reuse | DONE (domain/persistence); no onboarding workflow | `identity_entity.py`, `authentication_binding.py`; no application use case creates/reuses for a new Tenant |
| Stewardship designation + structural validation | DONE (structure/DB); no public/authorized workflow | `stewardship.py`, revision `0008`; privileged functions are installation-only, never `mtmf_runtime` |
| Verified actor composition for an existing eligible Tenant | DONE | `AuthenticatedActorContextService.resolve` |
| Application registry + registration + subscription (internal) | DONE | PR 13 (#0010) |
| First authenticated management mutation (membership add) | DONE | PR 19C (#0012/#0013) |
| Tenant creation / `tenant_key` / idempotency store | **NOT STARTED** | no table, no use case, no route |
| Pre-Tenant (bootstrap) verified admission | **NOT STARTED / UNRESOLVED** | `resolve` requires an existing Tenant + membership |
| Invitation create/accept/revoke | **NOT STARTED** | no domain object, table, Action, or route |
| Application subscription management HTTP surface | **NOT STARTED** | registry is read-only at runtime; mutations are operator-only |
| `POST /v1/management/tenants` | **DEFERRED** | no approved v0.1 public admission (STOP-01) |

**Scope of PR 21:** freeze the design and versioned contracts for the NOT
STARTED rows. No runtime behavior is added.

## 5. Overlapping onboarding work classification

- **DONE + VERIFIED:** PR 10 root/stewardship structure; PR 11 delegation;
  PR 13 registry/eligibility; PR 14 actor composition; PR 17 HTTP PDP;
  PR 19C first audited management mutation.
- **DONE NOT YET VERIFIED AS ONBOARDING:** none claimed; no PR claimed
  onboarding.
- **PARTIAL:** root authentication/recovery (separate release gate, not
  solved by PR 21); audit coverage outside PR 19C (inventoried, not claimed).
- **NOT STARTED:** provisioning, subscription management surface, invitations.

## 6. Baseline gate evidence (fresh, before documentation changes)

Environment: WSL2 host, Podman 4.9.3, Python 3.14.7 (uv), PostgreSQL 18
(`mtmf_postgres_1`, host port `25432`), migration head `0013`. Commands were
run from the repository root on baseline SHA `455ae7a`.

| Gate | Exact command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | **PASS** — first run 2173 passed, 177 skipped; coverage 90.23% (>= 85% gate). The 177 skips were the private native module not yet being `maturin develop`-installed in this fresh environment; after the canonical `--rust` gate installed it, `--qa` ran 2462 passed / 90.36%. Both runs PASS; no gate was weakened. |
| Security | `./build.sh --sec` | **PASS** — Bandit 0 findings; Semgrep 297 rules / 0 findings |
| Rust | `./build.sh --rust` | **PASS** — fmt/clippy/test, `maturin develop`, installed-native probe, focused parity tests, isolated wheel build/install/use, benchmark smoke all passed |
| Integration | `set -a && . ./.env && set +a && ./build.sh --integration` | **PASS** — 593 passed, 90 skipped (opt-in live suites skipped) |

`--integration` was executed against the MTMF-owned `mtmf` Compose project
only; no unrelated container was touched. A failure would not have authorized
weakening a gate.

## 7. Reconciliation outcome

The roadmap's PR 21 remains appropriate as a **documentation-only** design
freeze. The dominant missing contract is the **trusted admission authority for
a Tenant that does not yet exist** (and its first user). That authority is not
present on `main` and cannot be manufactured from the existing
`AuthenticatedActorContextService`. This is recorded as **STOP-01** in
`PR21_STOP_REPORT.md`; PR 21 must not be marked DONE until a human decides
between operator-mediated provisioning and an explicitly designed pre-Tenant
self-service admission.
