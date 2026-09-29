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

External IdP implementations, aggressive authorization caching, and non-Python evaluator optimization are not required to establish the initial framework foundation.

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

### PR 7 — PostgreSQL repositories and domain persistence

Implement PostgreSQL-backed UnitOfWork/repositories and stored-function operations for the core domain model, including soft deletion, lifecycle state, ownership/provenance, extension JSON objects, and atomic multi-object invariants.

### PR 8 — Role assignments and effective authorization state

Implement Tenant-bound Role assignments to Identity and Group, optional Organization refinement, effective Role loading, and persisted Role/PermissionSet/Permission policy composition.

Ensure assignments never contribute authorization outside their Tenant context.

### PR 9 — Bootstrap, root invariants, and Tenant Stewardship

Implement system bootstrap, root Principal/root Tenant invariants, mandatory local Identity establishment, root membership, built-in Roles/policy, ordinary Tenant stewardship, transfer/recovery rules that are sufficiently specified, and atomic stewardship constraints.

Any still-unresolved acting-Identity stewardship rule must be settled before its dependent behavior is implemented.

### PR 10 — TenantManagementGroup delegation

Implement ROOT and SYSTEM TenantManagementGroup behavior, implicit universal ROOT management, explicit managed-Tenant relationships for SYSTEM groups, and contextual scope evaluation.

Manager-side actor eligibility must be explicitly settled before enabling delegated authority.

### PR 11 — Public API contract and detached DTOs

Implement `mtmf-api` service interfaces, detached Pydantic DTOs, stable transport-independent errors, Connector contract, and mappings that preserve remote-service semantics.

Public contracts must not leak core domain, PostgreSQL, FastAPI, or persistence internals.

### PR 12 — LocalConnector

Implement LocalConnector against core application use cases while preserving the same detached, failure-aware semantics expected of a remote Connector.

Begin the shared Connector contract suite.

### PR 13 — HTTP service and HttpConnector

Implement the thin FastAPI/Uvicorn service adapter and HttpConnector, including DTO/error mapping, timeouts/failure semantics, and the same authorization path used by LocalConnector.

Run the shared Connector contract suite against both implementations.

### PR 14 — Observability and security/audit hardening

Add OpenTelemetry instrumentation across application use cases, authorization, UnitOfWork, repositories, PostgreSQL, and HTTP transport. Establish the intended Collector/Prometheus/Jaeger/Loki integration boundaries and security/audit event foundations without leaking sensitive authorization details.

### PR 15 — v0.1 integration and conformance hardening

Exercise complete local and HTTP flows against isolated PostgreSQL; expand security-constitution tests, connector equivalence tests, migration tests, concurrency/transaction tests, and failure-path coverage.

Resolve documentation drift and prepare the framework for its first consuming product integration.

## 4. Deferred Beyond the Initial Sequence

The following should be introduced only when their dependent design questions and use cases justify them:

- concrete external IdP providers and durable cross-boundary IdP workflows;
- authorization-state caching and invalidation;
- Rust/PyO3 permission-evaluator optimization;
- additional persistence providers;
- nested Groups;
- Principal Organization membership;
- restoration of soft-deleted objects;
- broader service/agent Principal semantics.

## 5. Roadmap Maintenance

This roadmap should evolve with implementation.

When a planned PR is split, merged, reordered, or materially re-scoped, update this document rather than preserving obsolete numbering. When a PR item is fully implemented and validated, mark it `[DONE]` in this roadmap in the implementing PR.
