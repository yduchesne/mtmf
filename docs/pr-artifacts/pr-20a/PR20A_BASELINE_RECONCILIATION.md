# PR20A_BASELINE_RECONCILIATION

**PR:** roadmap PR 20A — MTMF Reference Application Foundation
**Branch:** `dev/pr20a-reference-app`
**Planning baseline SHA:** `56695c08e5b71a032877f319aa05193db31a47ec` (`origin/main`, inspected 2026-10-14)
**Artifact directory:** `docs/pr-artifacts/pr-20a/`

## 1. Phase-0 repository reconciliation

- `git fetch origin` performed; working tree clean before implementation.
- `git rev-parse origin/main` = `56695c08e5b71a032877f319aa05193db31a47ec`; the working
  branch was created from that commit.
- Authoritative documents read: `AGENTS.md`, `docs/ROADMAP_V01.md` (PR 20 section),
  `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT_SETUP.md`,
  `docs/pr-artifacts/pr-15/PR15_HTTP_API_V1_CONTRACT.md`,
  `packages/mtmf-client/README.md`, the PR 17/18/19 acceptance reports, and the
  current authentication/initializer/Compose code.

## 2. Verified current-main contracts reused (not recreated)

| Capability | Exact location |
| --- | --- |
| Official synchronous HTTP consumer | `packages/mtmf-client/src/mtmf_client/client.py` — `HttpMtmfClient.evaluate(request, user_access_token=..., context=...)` and `.require(snapshot, context=..., action=..., resource=..., request_id=...)` |
| Trusted local context | `packages/mtmf-client/src/mtmf_client/snapshot.py` — `TrustedActorContext` |
| Client configuration | `packages/mtmf-client/src/mtmf_client/config.py` — `ClientConfig` (HTTPS-only base URL/token endpoint) |
| Frozen wire DTOs | `packages/mtmf-api/src/mtmf_api/authorization.py` — `AuthorizationBatchRequest`, `ActionRequest`, `ResourceTarget`, `ResourceKind.APPLICATION_OWNED` |
| MTMF endpoint | `POST /v1/authorization/evaluate` (PR 15 frozen v1 contract) |
| Two-token trust boundary | `Authorization: Bearer <service>` plus `X-MTMF-User-Authorization: Bearer <user>` |
| Development issuer/TLS | `dev/keycloak/`, `scripts/mtmf-dev-certs.py`, `scripts/mtmf-dev-forwarder.py` |
| Deployed acceptance patterns | `compose.pr19c-acceptance.yaml`, `scripts/mtmf-pr19c-live.py` |

## 3. Mandatory Phase-0 policy inventory (P0 gate)

### 3.1 Existing Action registry

- Table `mtmf.action`; repository functions
  `mtmf.action_add(text)` / `mtmf.action_get(text)` in
  `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v004/02_action_functions.sql`.
- Built-in Action definitions installed by
  `sql/v006/02_builtin_seed_function.sql` (`mtmf.install_builtin_policy`). Exactly
  three Actions are seeded: `tenant:get-object`, `role:get-object`,
  `organization:get-object`.
- Unregistered (but syntactically valid) Actions are overridden to
  `DENY/UNKNOWN_ACTION` in `packages/mtmf-service/src/mtmf_service/evaluation.py`
  (`AuthorizationService._map_item`), because `action_get` returns false.

### 3.2 Existing Permission / Role aggregate

- Tables `mtmf.permission_set` and `mtmf.permission`; aggregate function
  `mtmf.role_add(jsonb)` / `mtmf.role_save(jsonb)` in
  `sql/v004/04_role_functions.sql`. A Permission carries only a matcher URN owned
  by a PermissionSet owned by a Role; there is no independent Permission registry.
- `sql/v006/03_builtin_role_protection.sql` prevents `role_save` from rewriting a
  built-in Role. Built-in Roles are protected and were **not** modified.

### 3.3 Existing assignment + resolution path

- `mtmf.identity_role_assignment_add(id, tenant_id, identity_id, role_urn, organization_id)`
  in `sql/v005/02_role_assignment_functions.sql`; a TENANT-defined Role may only be
  assigned inside its defining Tenant.
- `EffectiveRoleResolver` in
  `packages/mtmf-core/src/mtmf_core/application/effective_roles.py` loads only
  same-Tenant, prerequisite-valid assignments and returns detached `Role`
  aggregates to the authoritative `Authorizer`.

### 3.4 Existing privileged provisioning mechanism

- `scripts/mtmf-dev-initialize.py` is the reviewed, opt-in, one-shot privileged
  initializer. It connects as the migrator, `SET ROLE mtmf_owner`, and calls only
  sanctioned primitives. It already uses `mtmf.action_add`, `mtmf.role_add`, and
  `mtmf.identity_role_assignment_add` semantics indirectly for the built-in
  tenant-administrator grant.
- The built-in `install_builtin_policy` is owner-only and deliberately **not**
  granted to `mtmf_runtime`.

### 3.5 P0 result — RESOLVED without architecture change

The reference read Action/Permission can be registered and granted through the
existing reviewed privileged fixture mechanism, with no new generic policy API,
no protected built-in manifest edit, and no new runtime grant:

| Item | Value |
| --- | --- |
| Action (new shared exact definition) | `urn:mtmf:iam:actions:system:document:read-object` |
| Permission (owned by the fixture Role's ALLOW PermissionSet) | `urn:mtmf:iam:permissions:system:document:read-object` |
| Grant namespace | new **TENANT-defined** Role `urn:mtmf:iam:roles:tenant:<tenant-id>:reference-document-reader` |
| Registration primitive | `mtmf.action_add` + `mtmf.role_add` (existing `SECURITY DEFINER`, called as owner) |
| Assignment primitive | `mtmf.identity_role_assignment_add` (existing) |
| Denied subject | a second verified Keycloak user with no document Role → `DENY/NO_PERMISSION` |
| Built-in Roles modified | none |
| Runtime grants added | none |

Definitions and the narrow provisioning operations live in
`scripts/pr20a_reference_fixture.py` and `scripts/pr20a-initialize.py`. The
reference Action/Permission are **fixture-only** and are not presented as a claim
that `BASELINE_ACTIONS` is exhaustive.

## 4. Environment topology inspected (no mutation)

- Podman 4.9.3, `podman-compose` 1.0.6.
- The default `mtmf` development project and the `mtmf-pr19c-acceptance` project
  were running. They were left untouched.
- Requested PR20A loopback ports `29532`, `29543`, `29501`, `29511` were free;
  occupied MTMF-adjacent ports (`25432`, `29001`, `29432`, `29443`) were not reused.
- `keycloak.mtmf.test` already resolves to loopback; the orchestrator never edits
  `/etc/hosts`.

## 5. Baseline gate observations

`./build.sh --qa` was executed on the planning baseline and after implementation.
The post-implementation results are recorded in
[PR20A_FINAL_ACCEPTANCE_REPORT.md](PR20A_FINAL_ACCEPTANCE_REPORT.md).

## 6. Recorded planning reconciliation

`docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` and historical PR 15 prose still
contain stale "not implemented" statements and ATI examples. Current code and the
PR 20 roadmap take precedence; PRs 12–19 were not reimplemented. ATI is not a PR
20 dependency.
