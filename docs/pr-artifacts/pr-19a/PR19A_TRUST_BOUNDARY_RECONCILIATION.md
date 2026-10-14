# PR19A_TRUST_BOUNDARY_RECONCILIATION

**PR:** roadmap PR 19A — verified-provenance mutation audit.
**Base commit:** `44c6c0b7230ccbd4820866fb97f36896566753a5`.
**Scope:** Phase 0 of the PR 19A execution plan — inventory, call-graph, privilege and category reconciliation.
**Outcome:** **STOP applies — no category-A authenticated+authorized management mutation entry point exists.** No schema, stored function, grant, or management API was manufactured.

## 1. Method

1. Reconciled the PR 19 inventory (`docs/pr-artifacts/pr-19/PR19_SECURITY_AUDIT_INVENTORY.md`) against the current source at head `0011`.
2. Parsed every `CREATE OR REPLACE FUNCTION mtmf.*` body in `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v*/` and classified each body by `INSERT`/`UPDATE`/`DELETE` presence and audit-table write.
3. Enumerated the exact runtime `EXECUTE` allowlist from `mtmf_core.persistence.postgres.roles.expected_runtime_signatures()` / `_*_FUNCTION_ARGUMENTS`.
4. Traced every production (non-test) caller of the persistence write surface across `packages/*/src`, `scripts/`, and the HTTP service.
5. Classified each callsite as **(A)** verified+authorized application operation, **(B)** privileged operator/bootstrap, **(C)** structural repository-only, or **(D)** unknown. Category A was **never inferred from method names**; it required a proven verified actor + exact Action authorization + target binding in one call path.

## 2. Production application call graph (verified by reading source)

| Seam | File | What it does | Decision / mutation? |
|---|---|---|---|
| Actor verification | `mtmf_core/application/authentication.py::AuthenticatedActorContextService.resolve` | Independently verifies service + user tokens, attestation, lifecycle/membership/eligibility; reads persisted bindings in one UoW | **Read-only**. It writes no row; it does not evaluate an Action. |
| Management scope | `mtmf_core/application/management_authorization.py::ManagementAuthorizationResolver.resolve` | Loads delegated management structural facts and builds `AuthorizationContext` + `ManagementScopeResolution` | **Read-only**. Explicitly "not an authorization decision point". |
| Effective Roles | `mtmf_core/application/effective_roles.py::EffectiveRoleResolver` / `build_authorization_context` | Reads assignments + prerequisites in one UoW; builds trusted `AuthorizationContext` | **Read-only**. |
| Authorization | `mtmf_core/authorization/authorizer.py`, `batch.py` | Authoritative Action evaluation | **Pure decision.** |
| HTTP service | `mtmf_service/evaluation.py::AuthorizationService.evaluate`, `app.py` | Composes verification → eligibility → roles → batch evaluation | **Read-only.** The only mutating-looking route surface is `POST /v1/authorization/evaluate`, which is a **decision endpoint**; the only other routes are `GET /health/live` and `GET /health/ready`. |
| Dev initializer | `scripts/mtmf-dev-initialize.py::PostgresProvisioner` | `SET ROLE mtmf_owner`, advisory lock, raw-SQL invocation of sanctioned installation/operator primitives | **Category B** (privileged operator/bootstrap). Not reachable from an HTTP request or from a verified actor session. |

There is **no** application use case that combines verified actor context, an exact authoritative `ALLOW`, and a subsequent security-state mutation. The repository write protocols exist and are exercised by tests, but no production application or service code calls them (`grep` for write-method invocations across `packages/*/src` finds only the repository definitions, the UoW method allowlist, and telemetry counter `.add(...)` calls — no persistence write caller).

### 2.1 HTTP route inventory

`packages/mtmf-service/src/mtmf_service/app.py` registers exactly:

- `POST /v1/authorization/evaluate` — batch decision;
- `GET /health/live`, `GET /health/ready`.

No management/mutation route exists. Adding one is explicitly out of PR 19A scope and is a documented STOP trigger.

## 3. Mutation-function inventory and classification

Parsed total: 164 function definitions; **59 mutating definitions** (including `CREATE OR REPLACE` supersessions of `tenant_add`, `tenant_save`, `identity_add`, `role_save`, etc.). Logical mutating operations reconcile exactly with the PR 19 inventory.

### 3.1 Already atomic (unchanged, not in PR 19A scope)

| Area | Functions | Audit table | Attribution |
|---|---|---|---|
| Membership removal (v002) | `remove_identity_tenant_membership`, `remove_group_tenant_membership`, `remove_principal_tenant_membership`, `remove_identity_group_membership`, `remove_identity_org_membership`, `remove_group_org_membership` | `mtmf.membership_removal_audit` | caller-supplied `actor_identity_id` — explicitly **unverified** |
| Root/stewardship (v008) | `bootstrap_root`, `designate_steward`, `recover_root_identity` | `mtmf.stewardship_audit` | within the approved stewardship contract; root recovery's separate durable operator audit remains mandatory |

PR 19A does not rewrite these semantics.

### 3.2 Runtime-granted structural writes (no atomic actor audit)

These functions are in the 77-signature runtime allowlist but carry no verified actor provenance (and no atomic audit row, except the removals above). They are **structural repository-only (category C)** in the current codebase: reachable through typed repository protocols that only tests invoke.

| Operation group | Functions | Runtime EXECUTE | Category | Why not A |
|---|---|---|---|---|
| Entity add/save | `tenant_add`, `tenant_save`, `organization_add`, `organization_save`, `principal_add`, `principal_save`, `identity_add`, `identity_save`, `group_add`, `group_save` | yes | C | no production application caller; no verified actor / exact Action binding |
| Action catalog | `action_add` | yes | C | reference data; no application caller |
| Role policy | `role_add`, `role_save` | yes | C | no production application caller |
| Membership add | `principal_tenant_membership_add`, `identity_tenant_membership_add`, `group_tenant_membership_add`, `identity_group_membership_add`, `identity_org_membership_add`, `group_org_membership_add` | yes | C | no production application caller |
| Role assignment | `identity_role_assignment_add`, `identity_role_assignment_remove`, `group_role_assignment_add`, `group_role_assignment_remove` | yes | C | no production application caller |
| Membership removal | the six v002 removals | yes | C (already audited) | audit attribution is explicitly unverified and must not be relabelled |

**Runtime-granted mutating total: 29** (19 repository writes + 4 role-assignment writes + 6 removals).

### 3.3 Operator/installation-only mutations (not granted to runtime)

These are **category B** (privileged operator/bootstrap) and are reachable only through migrations or the privileged development initializer (`SET ROLE mtmf_owner`); they are deliberately absent from the runtime allowlist.

| Area | Functions |
|---|---|
| Tenant lifecycle (v008) | `activate_tenant`, `suspend_tenant` |
| Builtin policy (v006) | `install_builtin_policy` (no authorization state; idempotent seed) |
| TenantManagementGroup (v009) | `install_management_roles` (no state), `create_root_management_group`, `initialize_root_tenant_management_group`, `create_tenant_management_group`, `add_tenant_management_group_membership`, `remove_tenant_management_group_membership`, `add_tenant_management_group_actor_eligibility`, `remove_tenant_management_group_actor_eligibility` |
| Application registry (v010) | `application_add`, `application_save`, `application_tenant_registration_add`, `application_tenant_registration_save`, `tenant_application_subscription_add`, `tenant_application_subscription_save` |
| Authentication bindings (v011) | `service_credential_application_add`, `service_credential_application_revoke`, `external_subject_identity_add`, `external_subject_identity_revoke` |
| Private helper | `role_insert_children` (not runtime-granted) |

### 3.4 Category summary

| Category | Count / finding | Notes |
|---|---|---|
| **A** verified+authorized application operation | **0** | No proven entry point. |
| **B** privileged operator/bootstrap | the operator/installation functions above | Already outside the application trust boundary; not actor-attributed by an authenticated MTMF session. |
| **C** structural repository-only | 29 runtime-granted mutating functions (6 already audited) | Tests and (for migrations/bootstrap) owner connections only. |
| **D** unknown | **0** | Every write function was parsed and classified. |

## 4. Reconciliation with the PR 19 inventory

- Head remains `0011_authentication_bindings`.
- Six audited membership-removal functions and three audited root/stewardship functions are present and unchanged.
- Every "GAP / UNRESOLVED" row in `PR19_SECURITY_AUDIT_INVENTORY.md` is reproduced above and remains **UNRESOLVED**; no row was reclassified as covered.
- The runtime allowlist in `roles.py` still matches the DATABASE.md model (the executable manifest also carries the two v011 authentication-binding reads; DATABASE.md's "75" predates v011's two reads).

## 5. Phase 0 gate decision

The PR 19A execution plan's mandatory early STOP states:

> if no category-A security mutation call path exists, **do not manufacture one**. Implement only the contract and deterministic tests that can be proven without a new management feature, record `BLOCKED: no existing authenticated management mutation entry point`, and request explicit scope approval before adding an end-to-end actor-attributed mutation.

**Result: BLOCKED.** Phase 2 (migration/schema/stored functions/grants) is **not entered**. Only the internal provenance contract and its deterministic tests are implemented (`PR19A_IMPLEMENTATION_REPORT.md`). No table, function, grant, route, DTO, or client method was added.
