# MTMF v0.1 Roadmap

## 1. Purpose

This roadmap provides the initial high-level implementation sequence for MTMF v0.1.

It is intentionally a planning document rather than a frozen specification. PR boundaries and numbering may be refined as implementation reveals better seams. Security and domain semantics are governed by the authoritative model documents, not by this roadmap summary.

## 2. v0.1 Direction

MTMF v0.1 should establish a reusable Python framework that can run in-process or behind an HTTP service while preserving one public, location-transparent contract.

The initial implementation targets:

- the four-distribution Python workspace;
- the foundational domain model and authorization primitives;
- PostgreSQL persistence through `MtmfSpi`, UnitOfWork, repositories, stored functions, and MTMF-owned migration management;
- authoritative core authorization;
- public API DTOs and Connector contract;
- LocalConnector and HttpConnector equivalence;
- a thin HTTP service;
- bootstrap/root invariants;
- Tenant, Principal, Identity, Group, Organization, Role, membership, and assignment management;
- observability and security/audit foundations;
- deterministic unit, integration, authorization-conformance, and connector-contract testing.

External IdP implementations and aggressive authorization caching are not required to establish the initial framework foundation. Rust is intentionally included from the PR 8 series onward as a Rust/Python integration showcase and as a deterministic native policy kernel; no profiling evidence claims a performance bottleneck.

## 3. Planned PR Sequence

### PR 1 — Python workspace and foundational domain primitives [DONE]

Establish the monorepo/workspace with `mtmf-api`, `mtmf-core`, `mtmf-client`, and `mtmf-service`; baseline tooling and CI; package dependency boundaries; UUID/URN value types; lifecycle/status enums; JSON extension conventions; and the smallest dependency-free domain primitives.

This PR should not introduce PostgreSQL, Alembic, FastAPI, or the persistence SPI implementation.

### PR 2 — Core domain entities and typed memberships [DONE]

Implements the initial domain entities and relationships: Tenant, Organization, Principal, Identity, Group, typed Tenant/Organization/Group memberships, ownership/provenance, lifecycle behavior, and cross-object Tenant invariants.

Establishes the global Principal/Identity model and the security-significant `(Tenant, Principal, Identity)` session context.

### PR 3 — Role policy model and Action catalog foundation [DONE]

Implement Role, PermissionSet, Permission, and Action domain concepts and URN validation.

Preserve the ownership model:

```text
Role -> PermissionSet -> Permission
```

with PermissionSet carrying ALLOW/DENY effect, Permission carrying matching semantics, and Action as the shared exact URN-identified operation.

Add deterministic matching tests for exact and constrained wildcard forms.

### PR 4 — Authorizer foundation [DONE]

Implement the core Authorizer and Permission evaluator with default deny, Tenant-context isolation, exact-versus-wildcard specificity, equal-specificity DENY precedence, and separation between policy matching and authorization-context retrieval.

Add authorization conformance tests for the settled security constitution.

The implemented foundation lives in ``mtmf_core.authorization``: a pure, deterministic :class:`PermissionEvaluator` (reusing PR 3 matching), a strict-scope dominance primitive, a narrow internal request/context seam with explicit same-Tenant targets, and an :class:`Authorizer` that validates the structural session context, enforces Tenant isolation, delegates policy resolution, and fails closed on missing/unsupported required constraints. Role assignments, effective-Role loading, persistence, stewardship, TenantManagementGroup delegation, built-in Role policies, public DTOs, and audit schemas remain owned by later PRs.

### PR 5 — Persistence SPI and UnitOfWork contracts [DONE]

Define `MtmfSpi`, repository contracts, UnitOfWork semantics, transaction boundaries, and persistence-provider composition without leaking database-driver types through architectural interfaces.

Use in-memory/test implementations where useful to validate contracts before PostgreSQL details dominate the design.

The implemented persistence boundary lives in ``mtmf_core.persistence``: one provider-level :class:`MtmfSpi`, an explicit :class:`UnitOfWork` transaction contract (opt-in commit, normal-exit rollback, exceptional-exit rollback with exception propagation, no reuse after completion), typed repository contracts for the current persistable aggregates (Tenant, Organization, Principal, Identity, Group, Role, Action) and all typed memberships, and a minimal provider-neutral error hierarchy. A deterministic in-memory contract provider (``mtmf_core.persistence.testing.InMemoryMtmfSpi``, clearly test/internal) proves transaction isolation, multi-repository atomicity, duplicate-identity failure, and detached snapshot semantics. Role persistence preserves the ``Role -> PermissionSet -> Permission`` aggregate; memberships remain typed with no polymorphic ``member_type``/``member_id`` model; repositories persist state and do not authorize. PostgreSQL, SQL, stored functions, Alembic/migrations, Docker, Role assignments/effective-Role loading, stewardship, TenantManagementGroup persistence, public DTOs, connectors, IdP integrations, and observability remain out of scope (PRs 6+).

### PR 6 — PostgreSQL schema and migration foundation [DONE]

Introduce the PostgreSQL provider, MTMF-owned Alembic migration management, initial schema, constraints, and stored-function conventions.

Persist foundational entities and typed memberships while enforcing security-critical structural invariants at trusted write boundaries.

The implemented foundation lives in ``mtmf_core.persistence.postgres``: an MTMF-owned ``mtmf`` physical schema (PR 5 aggregates — Tenant, Organization, Principal, Identity, Group, Role -> PermissionSet -> Permission, Action — and all six typed memberships), Alembic migrations (revision ``0001``, handwritten, packaged with ``mtmf-core`` and resolved via ``importlib.resources``) hidden behind a narrow :class:`PostgresMigrationManager` interface, explicit fail-closed ``MTMF_*`` connection configuration, deterministic trigger-based enforcement of typed-membership preconditions and structural immutability at the database boundary (a documented immediate-validation ordering contract, since core PostgreSQL has no deferred-constraint mechanism), object-constrained ``jsonb`` extension, exact lifecycle/scope/effect values, restrictive (non-cascading) foreign keys, versioned packaged stored-function resources, and a small infrastructure proof function (``mtmf.mtf_schema_version()``). ``compose.yaml`` adds an isolated Podman Compose ``mtmf`` project with a configurable host port, plus ``scripts/mtmf-postgres.py`` lifecycle commands scoped strictly to MTMF-owned resources so MTMF can run concurrently with ATI on the same WSL/Podman host without ever selecting, modifying, or stopping ATI resources. Real-PostgreSQL integration tests under ``tests/integration/postgres`` (run via ``./build.sh --integration``) prove migrations, schema shape, lifecycle/extension/ownership constraints, cross-Tenant membership rejection, policy ownership, stored-function installation, and resource-ownership scoping, while ordinary QA stays service-independent.

No functioning ``PostgresMtmfSpi``, PostgreSQL repositories, UnitOfWork implementation, Role assignments, stewardship, TenantManagementGroup, bootstrap/root state, IdP integration, DTOs/connectors, or observability are included: those remain owned by later PRs (PR 7 owns the PostgreSQL SPI/UnitOfWork/repositories).

### PR 6B — Atomic membership hard-deletion cascades, compact audit, and CI integration [DONE]

Implement the physical-deletion trust boundary for the six typed membership relationships documented in ``docs/DOMAIN_MODEL.md`` and ``docs/SECURITY_MODEL.md``. Alembic revision ``0002`` adds the append-only ``mtmf.membership_removal_audit`` table, the Group Tenant-exclusivity constraint, and the versioned ``sql/v002`` resources that replace the v001 membership precondition functions (adding ``FOR KEY SHARE`` prerequisite locks and the missing GroupTenantMembership check for ``IdentityGroupMembership``), install the membership DELETE/TRUNCATE guard, and install the sanctioned ``remove_principal_tenant_membership`` / ``remove_identity_tenant_membership`` / ``remove_group_tenant_membership`` prerequisite-cascade functions plus the ``remove_identity_group_membership`` / ``remove_identity_org_membership`` / ``remove_group_org_membership`` leaf-removal functions. Each initiating removal physically deletes its applicable rows (a prerequisite cascade, or exactly one leaf relationship) in one transaction and writes exactly one compact operation-level audit row with actual affected-row counts by membership type; no-op and failed removals write no audit row. The existing ``quality`` CI job is preserved and a sibling ``integration`` job runs the canonical ``./build.sh --integration`` gate against disposable PostgreSQL 18. Real-PostgreSQL tests prove migration upgrade without data loss, the closed IdentityGroup prerequisite, Group exclusivity, all three cascades, audit cardinality/count/append-only semantics, rollback, and concurrent double-removal/insert-vs-delete races. Root/bootstrap and Tenant Stewardship protection is documented as deferred to PR 10 because revision 0002 persists no authoritative root/stewardship state; the removal functions enforce structural cascade and audit invariants only, never authorization. Local MTMF PostgreSQL configuration is aligned to the host-port prefix-2 convention (``25432``).

### PR 7 — PostgreSQL Persistence Series

The series separates the **PostgreSQL runtime security boundary** from the **production persistence implementation**. PR 7A is a prerequisite for PR 7B: repositories must never be built or tested solely against a privileged migration/owner connection. Reuse the existing `MtmfSpi`, `UnitOfWork`, and typed repository contracts rather than creating parallel persistence abstractions.

- **PR 7A — PostgreSQL Runtime Privilege Model [DONE]** — Implemented the database privilege architecture specified in [DATABASE.md](DATABASE.md): administrator-provisioned `mtmf_owner` (NOLOGIN), `mtmf_migrator` (LOGIN; `SET ROLE` owner with `INHERIT FALSE`), and restricted `mtmf_runtime` (LOGIN; no elevated membership); owner-executed additive revision `0003` with default-deny schema/table/sequence/function grants, owner-scoped default privileges, explicit runtime `EXECUTE` on exactly the six membership-removal signatures, and the six reviewed owner-owned `SECURITY DEFINER` entry points with fixed `search_path = ''`; separate administrator/migrator/runtime connection configuration (`MTMF_POSTGRES_*`, `MTMF_MIGRATOR_*`, `MTMF_RUNTIME_*`) with the migration manager rejecting the runtime role; and adversarial integration tests (`PRIV-01`..`PRIV-20`) connecting as the actual runtime login. The six membership-removal functions retain their atomic cascades and compact operation-level audit, while direct DML, forged-audit writes, and transaction-marker bypass are denied under runtime credentials. The shared-runtime-login trust limitation and the unverified `actor_identity_id` boundary are documented; database EXECUTE grants do not replace application authorization, and root/bootstrap and Tenant Stewardship protections remain PR 10 scope. PR 7A-1 (amendment on the same branch) hardens this with transitive role-topology verification (fail-closed, no silent rewrites of unrelated roles), a read-only effective runtime-privilege verifier (`scripts/mtmf-provision-roles.py --verify`), an authenticated migrator contract enforced on every psycopg/Alembic connection (rejecting administrator/runtime credentials and configs), and clean-versus-legacy effective-privilege parity, covered by the `A1-01`..`A1-22` real-login adversarial suite. PR 7A-2 makes the effective runtime-privilege verifier a mandatory, non-bypassable postflight of every `upgrade_to_head()` (fresh, populated, and already-head no-op upgrades) on a fresh authenticated migrator connection; a postflight failure raises `MigrationError` after possible commit and never claims rollback. Provisioning and legacy adoption keep topology/ownership postconditions but do not require head-level runtime ACLs. Covered by the `I01`..`I14` lifecycle tests; `--verify` remains an optional read-only operator/CI diagnostic.

- **PR 7B — PostgreSQL Repositories and Domain Persistence [DONE]** — Implemented the production PostgreSQL-backed `MtmfSpi` (`PostgresMtmfSpi`), one-real-transaction `PostgresUnitOfWork`, and all 13 typed repositories against the restricted `mtmf_runtime` role established by PR 7A. Additive revision `0004` installs 44 reviewed repository stored functions (owner-owned `SECURITY DEFINER`, fixed `search_path = ''`, schema-qualified, no dynamic SQL) for entity/Action read/write, the atomic `Role → PermissionSet → Permission` aggregate, and the six typed membership add/get/find operations; the mandatory post-upgrade verifier now checks the full 50-signature runtime `EXECUTE` allowlist (six membership-removal plus 44 repository functions). Repository semantics preserve immutable identifiers/provenance, soft deletion, object-only application `extension` JSON, structural prerequisites and cross-Tenant restrictions, detached snapshots, read-your-writes inside one UoW, and deterministic duplicate/unknown/constraint/concurrency error translation; a failed statement puts the UoW into a rollback-only failed state that cannot commit partial state. The six existing membership-removal functions and their compact audit are unchanged and their regressions still pass. Per the approved scope, no membership `remove` repository API was invented; typed membership removal remains an explicit future design/approval item. Verified by the unit suite (>= 85% coverage gate), the existing PR 7A/PR 6B real-role suites, and the new provider integration slices V1-V6 (`test_postgres_spi.py`, `test_postgres_role_aggregate.py`, `test_postgres_membership_repositories.py`, `test_postgres_runtime_security.py`, `test_postgres_error_concurrency.py`) connecting as the actual `mtmf_runtime` login.

**Dependency:** PR 7B was implemented after PR 7A was merged and verified (the prerequisite is satisfied). PR 9 owns Role assignments/effective authorization state; PR 10 owns root/bootstrap and stewardship protections.

### PR 8 — Rust Permission Engine series

Rust is intentionally included in MTMF as a Rust/Python integration showcase and as a deterministic native policy kernel (AUTHORIZATION.md section 8.1). Python keeps ownership of authorization context, policy applicability, and fail-closed orchestration: the Python `Authorizer` remains authoritative and the Python `PermissionEvaluator` remains the semantic reference through the migration. The series is split into:

- **PR 8A — Rust Permission Engine foundation [DONE]** — private `mtmf-permission-engine` crate with PyO3/maturin packaging, the private `_mtmf_permission_engine` native module, the internal Python adapter (`mtmf_core.authorization.rust_engine`), the deterministic `./build.sh --rust` gate, and this roadmap resequencing. No permission semantics are implemented in Rust and no PostgreSQL/Podman dependency is introduced.
- **PR 8B — Rust permission model and matcher [DONE]** — detached Action/PermissionSet/Permission native inputs with an ALLOW/DENY effect representation, SYSTEM-only Action/Permission URN parsing, exact and complete-qualifier wildcard matching, match specificity (EXACT over wildcard only), native parser/matcher/specificity tests, a small private PyO3 matcher bridge, focused Python/Rust parity tests, and the `build.sh --rust` focused-test update. No full decision algorithm, no PermissionSet evaluation, and no ALLOW/DENY/default-DENY behavior are implemented; Python remains the semantic reference and no active authorization path imports the native module.
- **PR 8C — Rust permission evaluation engine [DONE]** — evaluate an exact Action against already-applicable PermissionSets: select maximum specificity, discard lower specificity, apply equal-specificity DENY, default to DENY, return a deterministic result, and remain order-independent; no context retrieval.
- **PR 8D — Python/Rust evaluator integration and differential testing [DONE]** — introduces the narrow internal `PermissionEvaluatorProtocol` evaluator seam, implements the `RustPermissionEvaluator` with deterministic domain-to-primitive conversion of already-applicable Role policy (Roles flattened into detached PermissionSets, no Role identity sent to Rust, Role/PermissionSet ownership corruption rejected before any native call), maps validated native aggregate results onto the existing `AuthorizationDecision`/`MatchSpecificity`/`DenyReason` values, normalizes native unavailability/capability/parsing failures into the fail-closed `PermissionEvaluationInfrastructureError` (never a semantic DENY, never ALLOW, no Python fallback), and cuts the normal `Authorizer()` default over to the Rust evaluator while keeping the Python evaluator available as the explicit semantic reference (this Rust default was the production path until PR 8H replaced it). Systematic hand-authored and Hypothesis-generated differential/property tests (including permutation and duplicate metamorphic invariants and structural-corruption parity) prove Python/Rust equivalence over the full decision evidence.
- **PR 8E — Rust engine hardening and performance characterization [DONE]** — closes the PR 8 Rust series without adding authorization semantics: malformed/incoherent FFI hardening (malformed Action/Permission URN text, unknown effects, wrong primitive types/container shapes, and unusually long malformed strings all fail explicitly and can never become a decision; native `TypeError` is normalized into the malformed-input `ValueError` contract; the adapter rejects every impossible native aggregate state), bounded stress conformance up to 100 PermissionSets x 20 Permissions (deterministic full-decision parity, order independence, no duplicate voting, no timing assertions), clean wheel build/install/import/use verification in an isolated temporary Python 3.14 environment (`scripts/verify-rust-wheel.py`), a reproducible parity-checking benchmark harness over the domain-facing evaluator seam with human+JSON output and a `--smoke` mode (`benchmarks/`), performance characterization with no speed gate, and final docs (AUTHORIZATION.md, AGENTS.md, package metadata) with durable wording.
- **PR 8G — CompiledPolicy indexed native evaluation experiment [EXPERIMENTAL]** — an independent experimental sibling of PR 8F (which is not a dependency): branches directly from the PR 8E baseline, compiles already-applicable policy once (`native.compile_policy`) into an opaque frozen native object with exact `(namespace, resource, verb, qualifier)` and wildcard `(namespace, resource, verb)` index maps of pre-aggregated effects, then evaluates repeated exact Actions with at most two hash lookups and no resend/reparse/sort/scan. No sorted-list contract, no numeric registries, no third-party map dependency, no project-authored `unsafe`. The experimental Python adapter (`benchmarks/compiled_policy_evaluator.py`) validates PermissionSet ownership before compilation, reuses the opaque policy, and returns the same `AuthorizationDecision`; the compile/evaluate/lifecycle harness (`benchmarks/compiled_policy_benchmark.py`) preserves the PR 8E scenarios, adds 1/25/200/1000/5000-permission scales and a 25/200/1000/5000 unrelated-policy scaling diagnostic (exact/wildcard/no-match), and measures compile, repeated evaluation, and compile+1/10/100/1000 lifecycle cost with complete P == R == PC == RC parity before timing and explicit ratio/break-even reporting. A PR 8G amendment adds a pure-Python CompiledPolicy control (PC: same indexed semantics, no FFI) so the experiment separates the algorithm/data-structure benefit from the language/native-execution benefit; the amended harness measures P/R/PC/RC in one campaign. On the measured machine both compiled paths dominate their linear baselines and PC evaluation beat RC evaluation in every scenario (PC/RC ~0.18-0.50x), indicating that compiling/indexing is the principal optimization and that per-Action PyO3 crossing/Action parsing/result conversion dominate the Rust-compiled path. PC remained experimental benchmark code in 8G, not production; the branch was merged as experimental infrastructure and is now superseded by PR 8H, which productionizes the pure-Python PC semantics.
- **PR 8H — Production AuthorizationPolicy/resolver architecture and Python CompiledPolicy default [DONE]** — productionizes the architectural result of PR 8G without adding authorization semantics. Introduces the narrow `AuthorizationPolicy` protocol (already-resolved policies: `evaluate(Action)` plus `get_diagnostics()`), the `AuthorizationPolicyResolver` resolution seam, and the non-caching `DefaultAuthorizationPolicyResolver`, which compiles `context.applicable_roles` into the production pure-Python indexed `CompiledPolicy` (immutable exact `(namespace, resource, verb, qualifier)` and wildcard `(namespace, resource, verb)` indexes of OR-aggregated effects; already-parsed domain URN components; no sort; duplicates non-voting; exact beats wildcard; equal-specificity DENY) wrapped in an `EffectivePolicy` diagnostics wrapper. The `Authorizer` now depends on resolver injection (`Authorizer(policy_resolver=...)`; default `DefaultAuthorizationPolicyResolver`) and no longer instantiates any evaluator by default; the Rust evaluators are retained for experimentation/differential testing but are explicitly experimental and non-default with no backend/env-var selector, fallback, or runtime probe. The linear Python `PermissionEvaluator` remains the semantic oracle; differential tests prove complete-decision equality with the production `CompiledPolicy`. The 8G Python benchmark control is removed and the benchmark PC path imports the production implementation. Authoritative docs (AUTHORIZATION.md, ARCHITECTURE.md, AGENTS.md) describe the resolver boundary, no-caching-yet status, and that future caching belongs behind resolver decorators (non-implemented).

### PR 9 — Role assignments and effective authorization state [DONE]

Implemented Tenant-bound Role assignments to Identity and Group, optional Organization refinement, effective Role loading, and persisted Role/PermissionSet/Permission policy composition. Ensure assignments never contribute authorization outside their Tenant context.

Resolved the previously UNRESOLVED assignment representation (with explicit approval recorded in DOMAIN_MODEL.md section 13 and SECURITY_MODEL.md section 12) as two typed immutable entities, `IdentityRoleAssignment` and `GroupRoleAssignment` — never a polymorphic subject type. Each assignment carries an immutable UUID identity, exactly one `tenant_id`, an immutable target (`identity_id` or `group_id`), an immutable `role_urn`, and an optional immutable `organization_id`; a `NULL` organization is Tenant-wide and participates in logical uniqueness as a real value. Assignment rows are current-state facts: revocation physically removes the row and a regrant uses a new UUID (no history/tombstone in PR 9).

Prerequisites are explicit and never inferred: a direct assignment requires an `IdentityTenantMembership`; a Group assignment requires a `GroupTenantMembership` with an agreeing structural Group Tenant; an Organization refinement requires the Organization to belong to the assignment Tenant and additionally requires the corresponding `IdentityOrgMembership`/`GroupOrgMembership`. A TENANT-defined Role may only be assigned inside its defining Tenant.

Delivered: the two typed domain entities and pure validators; typed SPI repository contracts (`IdentityRoleAssignmentRepository`, `GroupRoleAssignmentRepository`) with matching deterministic in-memory and restricted-runtime PostgreSQL implementations; additive Alembic revision `0005` with versioned SQL `v005` (restrictive composite foreign keys to prerequisite memberships, a Tenant-consistency foreign key to `organization(id, tenant_id)`, `UNIQUE NULLS NOT DISTINCT` logical uniqueness, stored-function-only runtime access, owner-owned `SECURITY DEFINER` entry points with fixed `search_path = ''`, and three private non-runtime-granted validation helpers); the extended 58-signature runtime `EXECUTE` allowlist and mandatory post-upgrade verifier manifest; and the application-layer `EffectiveRoleResolver` plus trusted `build_authorization_context` factory that produce the detached, Tenant-filtered `applicable_roles` tuple consumed by the unchanged `Authorizer`/`DefaultAuthorizationPolicyResolver`/`CompiledPolicy` path.

Removal safety is explicit: a prerequisite membership may not be removed while a dependent assignment exists — the composite foreign key rejects it deterministically and rolls back the entire removal (including any membership cascade and its compact audit); the caller must revoke the assignment first. Assignment reads and writes are structural persistence only and confer no grant/revoke authority. Assignment privilege grants, public DTOs/Connector work (PR 12), the HTTP service, policy caching/invalidation, and all stewardship/delegation work remain out of scope.

Verified by the unit suite (domain, in-memory persistence contracts, effective-Role resolver matrix R01-R13/R19, and end-to-end R14-R18/R20 through the `Authorizer`), the real-runtime PostgreSQL slice `test_postgres_role_assignments.py` (P07-P18, including concurrent membership-removal versus assignment-creation serialization), the mandatory post-upgrade privilege verifier, and the `0001→0005` / `0004→0005` migration data-preservation checks.

### PR 10 — Bootstrap, root invariants, and Tenant Stewardship [DONE]

Delivered on `dev/pr10-bootstrap` (implementation head `aa1d5eb`); pull request **#39** is the merge reference. Additive Alembic revisions `0006`, `0007`, and `0008` implement the approved Gate M seed and the protected root/stewardship structural foundation without modifying any shipped revision (`0001`–`0005`) or packaged SQL (`v001`–`v005`). No converter for historical development data is introduced: the approved v0.1 baseline is a fresh empty database.

**Revision `0006` — approved Gate M built-in policy.** Installs the reviewed minimum seed (PR #38): exactly 11 SYSTEM-owned Role definitions, 11 ALLOW PermissionSets, 11 exact Permissions, 3 shared Action definitions, and the 22 published UUID literals, idempotently; an identical replay is a no-op and any conflicting definition fails closed (`MT010`). `mtmf.builtin_role` plus a `role_save` guard prevent ordinary runtime mutation of built-in definitions. The installer is `SECURITY INVOKER` and never runtime-granted.

**Revision `0007` — Identity origin and Tenant lifecycle.** Adds the immutable `identity.origin` (`LOCAL`=1 / `FEDERATED`=2) and the ordinary-Tenant `lifecycle` (`PROVISIONING`=0 / `ACTIVE`=1 / `SUSPENDED`=2), independent of soft deletion, with a root-must-be-ACTIVE check and conservative backfill for any pre-existing row. The entity read/write functions carry the fields and the exact runtime signature manifest remains at 58. `EffectiveRoleResolver` fails closed for PROVISIONING/SUSPENDED Tenants before Role evaluation.

**Revision `0008` — root registry and Tenant stewardship.** Adds `root_registry` (canonical root Tenant/Principal and designated LOCAL root Identity), `stewardship_designation` (exactly one per ordinary Tenant), and append-only `stewardship_audit`. Installation/operator-only `SECURITY INVOKER` primitives (never runtime-granted): `bootstrap_root` (serialized, idempotent, fail-closed on partial/corrupt state), `designate_steward` (version compare-and-swap, structural eligibility, atomic audit), `activate_tenant`/`suspend_tenant`, `recover_root_identity`, and the eligibility predicate `stewardship_is_eligible` (ordinary ACTIVE Tenant, active Principal/Identity, explicit memberships, direct or active-group-derived Tenant Administrator). Database guards protect canonical root and current-steward state across the pre-existing mutation paths (lifecycle/deactivation, membership removal, direct/group assignment revocation, group-membership/group deactivation, built-in Role mutation). One documented lock order is used (Tenant → subject Principal/Identity → designation, with a fixed bootstrap advisory lock); `designate_steward`/`activate_tenant` lock the subject rows before the eligibility read and the revocation guards lock the affected Identity rows, so designation and revocation serialize without write skew. Alternative-authority checks require the exact Tenant Administrator Role URN with `NULL` Organization scope and evaluate the post-mutation `UPDATE` state.

**Privilege posture.** `mtmf_runtime` retains no privileged bootstrap/transfer/recovery/activation `EXECUTE`, no direct table DML, and no owner/migrator membership; the mandatory post-upgrade verifier enforces the exact 58-signature runtime allowlist, no `PUBLIC` `EXECUTE`, and no direct privilege. `scripts/mtmf-provision-roles.py --verify` confirms the restricted runtime posture.

**Verification.** Unit suite 1196 tests at 91.47% coverage; security scan 0 findings; real-PostgreSQL integration suite 509 tests; a deterministic concurrency matrix of 15 scenarios x 10 cycles (150 race cycles) covering bootstrap, transfer, activation, designation, revocation, and root recovery; and the mandatory post-upgrade privilege verifier pass. See [PR 10 implementation decisions](PR10_IMPLEMENTATION_DECISIONS.md).

**Deferred to PR 14 — not delivered by PR 10.** Trusted service/end-user identity propagation and runtime-callable stewardship transfer/recovery depend on the PR 14 trusted actor boundary. PR 10 deliberately does not expose privileged bootstrap, transfer, recovery, or activation through the shared runtime database login or a caller-supplied actor UUID. Until the trusted service identity boundary is implemented, those operations remain installation/operator-only and are not claimed as end-user capabilities.

### PR 11 — TenantManagementGroup delegation

Implement ROOT and SYSTEM TenantManagementGroup behavior, implicit universal ROOT management, explicit managed-Tenant relationships for SYSTEM groups, and contextual scope evaluation.

Manager-side actor eligibility must be explicitly settled before enabling delegated authority.

**Status: NOT DONE — Gate D approved; blocked on the management Role catalog.** The Gate D security semantics (explicit Identity-level eligibility, single management Role, ROOT-only root Identity, lifecycle, SYSTEM-only management Roles, delegation boundaries, restricted Actions, revocation, trusted acting Identity) are approved in [PR 11 TenantManagementGroup delegation policy decisions](PR11_TMG_DELEGATION_POLICY_DECISIONS.md). The typed structural `TenantManagementGroup`/`TenantManagementGroupMembership` domain values, their pure structural validators, and a fail-closed contextual resolver (`resolve_management_scope`, which returns a non-elevating candidate and always reports `actor_eligible=False`) are implemented with unit coverage. Schema, stored functions, ROOT bootstrap, SPI/UoW repositories, Authorizer integration, delegated ALLOW, lifecycle, revocation, and trusted-actor work are blocked because the approved built-in Role catalog contains no cross-Tenant management Role and no management Permission allocation; inventing one is not authorized. PR 11 MUST NOT be marked `[DONE]` on structural tests alone.

### PR 12 — Public API contract and detached DTOs

Implement `mtmf-api` service interfaces, detached Pydantic DTOs, stable transport-independent errors, Connector contract, and mappings that preserve remote-service semantics.

Public contracts must not leak core domain, PostgreSQL, FastAPI, or persistence internals.

### PR 13 — LocalConnector

Implement LocalConnector against core application use cases while preserving the same detached, failure-aware semantics expected of a remote Connector.

Begin the shared Connector contract suite.

### PR 14 — HTTP service and HttpConnector

Implement the thin FastAPI/Uvicorn service adapter and HttpConnector, including DTO/error mapping, timeouts/failure semantics, and the same authorization path used by LocalConnector.

Run the shared Connector contract suite against both implementations.

### PR 15 — Observability and security/audit hardening

Add OpenTelemetry instrumentation across application use cases, authorization, UnitOfWork, repositories, PostgreSQL, and HTTP transport. Establish the intended Collector/Prometheus/Jaeger/Loki integration boundaries and security/audit event foundations without leaking sensitive authorization details.

### PR 16 — v0.1 integration and conformance hardening

Exercise complete local and HTTP flows against isolated PostgreSQL; expand security-constitution tests, connector equivalence tests, migration tests, concurrency/transaction tests, and failure-path coverage.

Resolve documentation drift and prepare the framework for its first consuming product integration.

## 4. Deferred Beyond the Initial Sequence

The following should be introduced only when their dependent design questions and use cases justify them:

- concrete external IdP providers and durable cross-boundary IdP workflows;
- authorization-state caching and invalidation;
- additional persistence providers;
- nested Groups;
- Principal Organization membership;
- restoration of soft-deleted objects;
- broader service/agent Principal semantics.

Rust/PyO3 permission-engine work is owned by the PR 8 series above and is not deferred.

## 5. Roadmap Maintenance

This roadmap should evolve with implementation.

When a planned PR is split, merged, reordered, or materially re-scoped, update this document rather than preserving obsolete numbering. When a PR item is fully implemented and validated, mark it `[DONE]` in this roadmap in the implementing PR.

## PR 10 approved policy baseline

The human-readable built-in Role/Permission allocation and the **empty-database v0.1 installation baseline** are recorded in [Built-in Access Policy and Installation](PR10_BUILTIN_ACCESS_AND_INSTALLATION.md). PR 10 retained versioned migrations `0006`–`0008` and did not convert historical development data (the approved v0.1 baseline is a fresh empty database). The exact minimum seed was subsequently reviewed and approved (PR #38) and installed in revision `0006`; privileged functions remain non-runtime-granted. This section records the policy baseline only; implementation and merge status are recorded in the PR 10 `[DONE]` entry above.
