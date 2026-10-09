# MTMF Architecture

## 1. Purpose

This document describes the technical architecture of the Multi-Tenant Management Framework (MTMF): package boundaries, layers, deployment modes, persistence abstractions, transport behavior, and cross-cutting infrastructure.

Security semantics are defined by [SECURITY_MODEL.md](SECURITY_MODEL.md). Authorization-engine behavior is described in [AUTHORIZATION.md](AUTHORIZATION.md). The structural domain model is defined in [DOMAIN_MODEL.md](DOMAIN_MODEL.md).

PostgreSQL-specific architecture and the implemented restricted runtime privilege model are documented in [DATABASE.md](DATABASE.md). PR 7A (revision `0003`) implements the owner/migrator/runtime role separation, default-deny grants, and the six reviewed `SECURITY DEFINER` membership-removal entry points described there.

## 2. Technology Baseline

MTMF uses the same general technology stack and layered engineering style as Agentic Threat Investigator (ATI):

- Python;
- PostgreSQL;
- Alembic for schema migrations;
- OpenTelemetry;
- Prometheus;
- Jaeger;
- Loki;
- interface-based layering with infrastructure behind explicit abstractions.

The initial implementation is Python. Performance-critical components may later use another implementation language behind stable internal interfaces when profiling justifies it.

## 3. Repository and Distribution Structure

MTMF is a Python monorepo/workspace containing independently installable distributions:

```text
mtmf/
+-- packages/
|   +-- mtmf-api/
|   +-- mtmf-core/
|   +-- mtmf-client/
|   +-- mtmf-service/
+-- docs/
```

### 3.1 mtmf-api

`mtmf-api` owns the location-transparent public service contract.

It contains:

- service interfaces;
- Connector interface;
- public DTOs;
- transport-independent error contract and stable MTMF error codes.

It MUST remain usable without installing the HTTP service implementation.

DTOs are detached value/snapshot representations, not live references to core domain objects.

### 3.2 mtmf-core

`mtmf-core` contains the framework implementation:

- domain model;
- application/use-case layer;
- `Authorizer`;
- persistence SPI;
- PostgreSQL persistence provider;
- UnitOfWork and repository implementations;
- core OpenTelemetry instrumentation;
- migration-management implementation behind an MTMF-owned interface.

Consuming products should not depend directly on core domain objects.

The core should remain independent of external transport concerns.

### 3.3 mtmf-client

`mtmf-client` is the consumer-facing client implementation and depends on `mtmf-api`.

It provides at least:

- `LocalConnector`;
- `HttpConnector`.

Both implement the same Connector/service contract.

`LocalConnector` adapts the public API contract to `mtmf-core` directly. `HttpConnector` adapts the same contract to the remote HTTP service.

The packaging mechanism for making `mtmf-core` optional when only `HttpConnector` is required remains to be finalized. An optional `local` dependency extra is a candidate.

### 3.4 mtmf-service

`mtmf-service` is the optional HTTP deployment.

It depends on `mtmf-api` and `mtmf-core` and provides the transport adapter around core application use cases.

The service layer MUST NOT duplicate business or security logic implemented by core.

FastAPI/Uvicorn are expected service technologies, subject to implementation planning.

## 4. Dependency Direction

The intended dependency direction is:

```text
                 mtmf-api
                ^        ^
               /          \
      mtmf-client        mtmf-service
          |                   |
          | optional          |
          v                   v
      mtmf-core <-------------+
```

The preferred design keeps `mtmf-core` independent of `mtmf-api`: connectors/service adapters map API DTOs and errors to/from core application/domain types.

This boundary remains subject to validation during implementation planning.

## 5. Connector Semantics

Consumers MUST assume that every Connector implementation is remote.

This is true even when the configured implementation is `LocalConnector`.

Consequently consumers must assume Connector operations can exhibit:

- non-trivial latency;
- transient failure;
- unavailability;
- timeout semantics;
- retry/idempotency implications;
- concurrent modification by other callers;
- serialization-style detached state;
- version compatibility concerns.

Consumers MUST NOT depend on Connector implementation type, local Python object identity, in-process mutation semantics, or direct access to core objects.

A public API operation should pass this design test:

> Would this operation still make sense if every invocation crossed a network boundary?

`LocalConnector` is a deployment/transport optimization, not a different programming model.

## 6. DTO Semantics

Public DTOs represent detached snapshots.

Retrieving the same MTMF resource twice does not imply Python object identity. Mutating a DTO locally does not mutate MTMF state.

Stable resource identifiers are used for references. Mutable display names are not identity.

Service operations explicitly perform state changes.

For Tenant, Organization, Principal, Identity, Group, and Role DTOs, application-owned `extension` data is transported as a detached JSON object. The canonical empty value is `{}`; `null` is not a valid domain representation. LocalConnector and HttpConnector MUST preserve equivalent extension semantics and round-trip the data without MTMF interpreting application-defined keys.

The PostgreSQL provider is expected to represent extension data using `jsonb`. This storage choice does not make extension contents part of MTMF domain or authorization semantics.

## 7. Error Contract

`mtmf-api` defines stable, transport-independent MTMF error codes and error semantics.

A service error has, conceptually:

```text
code            stable machine-readable MTMF code
message         human-readable description
details         optional structured data
correlation_id  optional tracing/correlation identifier
```

The HTTP service uses standard HTTP status codes and a structured MTMF error envelope.

It MAY duplicate the MTMF application error code in:

```text
MTMF-Error-Code: <code>
```

The custom header is not a replacement HTTP status code.

`HttpConnector` maps HTTP/network results into the public MTMF error contract. `LocalConnector` maps core/application failures into the same contract. Consumers should not need to handle HTTP-library, FastAPI, PostgreSQL, or core-domain exceptions.

Security-sensitive internal errors may be intentionally collapsed at the service boundary to prevent information disclosure.

## 8. Application and Domain Layers

The application layer coordinates MTMF use cases and transaction boundaries.

The domain/core security model owns business invariants. The `Authorizer` evaluates authorization but does not execute the protected operation.

A typical protected use case is conceptually:

```text
Connector/service operation
        |
        v
application use case
        |
        +--> Authorizer
        |
        +--> UnitOfWork / repositories
        |
        v
result
```

Authorization MUST be enforced at trusted boundaries, never only by a client or UI.

### 8.1 Authorization policy resolution

Inside the Authorizer, the PR 8H architecture separates *policy
resolution* from *policy evaluation*:

```text
Authorizer
  +-- validate SessionContext / enforce target Tenant boundary
  +-- AuthorizationPolicyResolver.resolve(context) -> AuthorizationPolicy
  +-- policy.evaluate(action) -> AuthorizationDecision
  +-- apply later Authorizer constraints
```

- :class:`AuthorizationPolicyResolver` resolves an already-applicable
  policy for a supplied :class:`AuthorizationContext` without
  authorizing an Action. The default implementation
  (:class:`DefaultAuthorizationPolicyResolver`) compiles
  ``context.applicable_roles`` into the production pure-Python
  :class:`CompiledPolicy` wrapped in an :class:`EffectivePolicy` for
  context-aware diagnostics.
- :class:`AuthorizationPolicy` is the static policy surface:
  ``evaluate(action)`` plus ``get_diagnostics()``, no Roles at
  evaluation time, no persistence, no retrieval.
- **Future caching and invalidation belong behind resolver
  implementations**, never inside the Authorizer or the policy
  implementations. The resolver contract intentionally permits later
  decorator composition, for example
  ``InMemoryCachingAuthorizationPolicyResolver(RedisCachingAuthorizationPolicyResolver(DefaultAuthorizationPolicyResolver()))``
  — **no such caching resolver, cache identity, version, fingerprint,
  invalidation, TTL, or cache configuration is implemented** (PR 8H), and
  none exists yet.
- The default path never selects Rust: the pure-Python indexed
  ``CompiledPolicy`` is the production default; the Rust evaluators
  remain experimental infrastructure behind their own explicit seams.

## 9. Persistence SPI

MTMF has one internal persistence Service Provider Interface: `MtmfSpi`.

The SPI owns factories for:

- repository instances;
- UnitOfWork instances.

One persistence provider owns the complete persistence implementation for an MTMF runtime.

Repositories participating in a business operation share a UnitOfWork/transactional context.

Conceptually:

```python
with spi.create_unit_of_work() as uow:
    tenants = spi.create_tenant_repository(uow)
    organizations = spi.create_organization_repository(uow)
    ...
    uow.commit()
```

The UnitOfWork represents transaction semantics without leaking a PostgreSQL/driver connection into public abstractions.

## 10. PostgreSQL Provider

The first persistence provider is PostgreSQL-backed, tentatively `PostgresMtmfSpi`.

Application-level database operations and logic go through PostgreSQL stored functions.

### 10.1 Physical schema

All MTMF physical state lives in a single MTMF-owned schema, `mtmf` (never `public`, never one schema per Tenant). The initial schema persists the PR 5 aggregates — Tenant, Organization, Principal, Identity, Group, Role -> PermissionSet -> Permission, and Action — plus the six typed memberships, using PostgreSQL `uuid` for `DomainId` values, `text` for names/descriptions/URNs, and object-constrained `jsonb` for application `extension` data.

Settled structural invariants are enforced at the database trusted boundary:

- `Role` definition ownership: SYSTEM vs TENANT Role URN namespace agrees with the structural `defining_tenant_id`;
- PermissionSet effects are constrained to the domain ALLOW/DENY string values; Permission URNs are matcher semantics and intentionally not globally unique;
- Action URNs are exact primary keys; no wildcard Action representation exists;
- soft deletion is a `smallint` lifecycle value (DELETED=1 / NOT_DELETED=2), never a Boolean; entity deletion stays soft and referenced entity rows remain protected by restrictive NO ACTION foreign keys. Typed membership relationships are the documented exception: they are current-state facts with no lifecycle column and their removal is a physical hard DELETE (Section 10.3);
- membership preconditions and structural immutability are enforced by schema-qualified trigger functions: a dependent membership requires its prerequisite facts, `IdentityGroupMembership` requires **both** the Identity's Tenant membership and the Group's Tenant membership, a Group has at most one `GroupTenantMembership`, cross-Tenant membership is rejected, and identity/structural columns (and membership rows themselves) are immutable. Each precondition check takes a `FOR KEY SHARE` lock on the prerequisite membership fact; the sanctioned removal functions take the matching `FOR UPDATE` lock, so a dependent INSERT cannot race a prerequisite DELETE and commit an orphan. These are write-time checks: MTMF write paths insert prerequisite rows before dependent rows within one transaction. They enforce structure only and never authorization.

A deliberate PR 6 decision: PostgreSQL does not ship the deferred-constraint mechanism (`CREATE CONSTRAINT` is not in core), so cross-table invariants use deterministic immediate trigger functions with the documented prerequisite-ordering contract. Full Role/Action URN grammar parity stays at the domain boundary; the database constrains the canonical forms and definition-ownership agreement.

### 10.2 Stored-function convention

Substantial SQL functions ship as immutable, versioned, packaged resources under `mtmf_core/persistence/postgres/sql/vNNN/<function>.sql` and are installed by Alembic revisions in sorted filename order. Functions are schema-qualified, do not rely on caller `search_path` (`SET search_path = ''`), and avoid dynamic SQL. PR 6 installs a single infrastructure proof function (`mtmf.mtf_schema_version()`); PR 6B installs the typed-membership precondition replacements, guards, and removal functions described below. PR 7A (revision `0003`) converts only the six reviewed membership-removal entry points to owner-owned `SECURITY DEFINER` and grants the restricted runtime role `EXECUTE` on exactly those signatures; every other function remains non-elevated with PUBLIC EXECUTE revoked. Repository CRUD functions are owned by PR 7B.

Security-critical invariants are enforced at trusted persistence/write boundaries in addition to higher layers where appropriate.

### 10.3 Membership removal, cascade, and compact audit (PR 6B / 6B1)

Removing a typed membership is a physical deletion performed only through six sanctioned `SECURITY INVOKER`, schema-qualified functions. Three remove a prerequisite Tenant membership with its mandatory atomic dependent cascade:

- `mtmf.remove_principal_tenant_membership(principal, tenant, actor?)` removes the Principal's Tenant membership, every owned Identity's Tenant membership in that Tenant, and those Identities' Organization/Group memberships in that Tenant;
- `mtmf.remove_identity_tenant_membership(identity, tenant, actor?)` removes the Identity's Tenant membership and its Organization/Group memberships in that Tenant;
- `mtmf.remove_group_tenant_membership(group, tenant, actor?)` removes the Group's Tenant membership, its Organization memberships in that Tenant, and all of its Identity memberships, while preserving member Identities' Tenant memberships.

The other three remove exactly one leaf relationship and nothing else — no upward or sideways cascade:

- `mtmf.remove_identity_group_membership(identity, group, actor?)`;
- `mtmf.remove_identity_org_membership(identity, organization, actor?)`;
- `mtmf.remove_group_org_membership(group, organization, actor?)`, which fails closed if the Group's authoritative Tenant and the Organization's authoritative Tenant disagree.

A leaf removal deletes only its initiating row; it never removes a prerequisite Tenant membership or a sibling relationship, and it takes no caller Tenant — the Tenant is always derived from the immutable `group.tenant_id` / `organization.tenant_id`.

Each of the six calls deletes the applicable rows in one database transaction and inserts exactly one compact operation-level row into the append-only `mtmf.membership_removal_audit` table. Counts are actual affected-row counts (`ROW_COUNT` per `DELETE`), never pre-count estimates; the initiating row is included in its own count, so a leaf removal records exactly one count equal to 1 and the other five equal to 0. The record stores the initiating kind, typed participant columns (shape-constrained by kind), Tenant, server-generated `occurred_at`, an optional real actor Identity (NULL when unavailable, never fabricated), and per-type counts. It never stores arrays/lists of affected members, never emits one row per cascaded membership, and is not a reconstructable membership ledger or a source of authorization. Audit rows are append-only (UPDATE/DELETE/TRUNCATE are rejected) and are retained independently of current membership rows; entity rows are soft-deleted so actor provenance survives.

Removing a nonexistent initiating row is a documented no-op: it deletes nothing and writes no audit row. A repeated removal therefore produces exactly one audit row in total. Concurrent duplicate removals serialize on the initiating row lock, so only one succeeds. Any failure (including a bad actor or a failing dependent delete) rolls back every deletion and the audit row together.

Lock protocol and concurrency: every precondition check locks its prerequisite membership fact `FOR KEY SHARE`; each removal function locks the initiating row `FOR UPDATE` first (and, for a Principal removal, every owned Identity-Tenant membership in the Tenant) before deleting any dependent. Under `READ COMMITTED` a waiting dependent INSERT re-evaluates its precondition after the removing transaction commits, so it cannot commit an orphan; a dependent that committed first is still cascaded away because the removal holds the prerequisite lock. There are no global locks and no serializable-isolation requirement; concurrent operations may still surface a retryable deadlock/serialization error, which callers may retry.

Trust boundary: a row-level `BEFORE DELETE` (and statement-level `BEFORE TRUNCATE`) guard rejects direct membership deletion unless the transaction-local `mtmf.membership_removal` marker set by the sanctioned functions is present. The enforced privilege model (PR 7A) is owner/migrator/runtime separation: the six removal functions are owner-owned `SECURITY DEFINER` entry points with PUBLIC EXECUTE revoked and `EXECUTE` granted only to `mtmf_runtime`; tables have no runtime grant, so the restricted runtime login cannot issue direct DML, read authoritative/audit tables, use sequences, or alter triggers regardless of the marker. The marker therefore remains defense in depth only, not an authorization boundary; a superuser/owner can disable triggers, and `mtmf_owner`/`mtmf_migrator` are outside the adversarial guarantee. `SECURITY DEFINER` EXECUTE is database capability, not domain authorization: a shared runtime login does not provide per-Tenant SQL isolation, and a fabricated `actor_identity_id` is an unverified caller assertion (see `docs/DATABASE.md` section 7). Root/bootstrap and Tenant Stewardship protection is **not** enforced by these structural functions: revisions through `0003` persist no authoritative root Principal marker, root-membership flag, or stewardship state, so a protected membership cannot yet be identified from data. That protection is deferred to PR 10 and must be applied above the persistence boundary once the authoritative state exists; the removal functions must not invent a root detector or inferred privileged identity.

## 11. Schema Migration

MTMF uses Alembic internally for PostgreSQL schema migration.

Consumers interact with the MTMF-owned migration boundary: `PostgresMigrationManager` (upgrade-to-head + current revision) in `mtmf_core/persistence/postgres`, which hides Alembic `Config` objects, script locations, revision IDs, and migration-graph internals. Migrations and SQL resources are packaged with `mtmf-core` and resolved through `importlib.resources`, so migration tooling never depends on the repository working directory.

MTMF migration state (including the Alembic version table) lives inside the `mtmf` schema so the MTMF migration graph is isolated from application migrations.

An application may independently use Alembic for its own schema. MTMF owns its own migration graph.

Migration management is outside `MtmfSpi` because schema lifecycle is a deployment concern rather than a runtime persistence contract.

Migration and runtime credentials are distinct role-scoped configurations (administrator `MTMF_POSTGRES_*`/`MTMF_DATABASE_URL`; deployment `MTMF_MIGRATOR_*`; restricted application `MTMF_RUNTIME_*`). The administrator-invoked `scripts/mtmf-provision-roles.py` creates `mtmf_owner` (NOLOGIN), `mtmf_migrator`, and `mtmf_runtime` outside Alembic, and validates the effective membership graph (rejecting hostile direct or transitive memberships without rewriting unrelated roles). `PostgresMigrationManager` accepts only the migrator identity and, on every migration connection (the plain-psycopg schema bootstrap/read and the SQLAlchemy Alembic connection), verifies the authenticated `session_user`/`current_user` is a non-elevated `mtmf_migrator` that can `SET ROLE mtmf_owner` without inheriting it, before any `SET ROLE` or DDL. It then executes `SET ROLE mtmf_owner`, so objects are owned by `mtmf_owner` regardless of the authenticating login. The administrator identity is reserved for provisioning/ownership handoff. `scripts/mtmf-provision-roles.py --verify` (or `verify_runtime_privileges`) performs a read-only effective-privilege verification after migration. `upgrade_to_head()` runs that verifier automatically on a fresh authenticated migrator connection after Alembic completes (including already-head no-op upgrades); the migrator assumes `mtmf_owner` only through its authorized `SET ROLE`, and no administrator credentials are present in the migration or runtime process. A postflight failure raises `MigrationError` stating that migrations may already be committed and never claims a rollback.

## 12. Identity Provider Integration

External identity providers are not persistence providers and MUST NOT be obtained through `MtmfSpi`.

IdP integrations use separate provider/SPI abstractions.

MTMF MUST NOT keep an internal PostgreSQL transaction open while performing remote IdP operations. PostgreSQL and a remote IdP do not participate in a distributed transaction.

Cross-boundary IdP workflows may eventually require durable workflow state, retries, compensation, or outbox-style mechanisms. Those details are deferred.

## 13. HTTP Service

The HTTP service is a thin transport adapter.

Its responsibilities include:

- HTTP authentication/transport concerns;
- request/response DTO mapping;
- invoking core application use cases;
- mapping MTMF errors to standard HTTP statuses and the MTMF error envelope;
- HTTP-level telemetry.

It MUST NOT implement an independent authorization model.

Both local and HTTP deployment modes ultimately use the same `mtmf-core` Authorizer.

## 14. Observability

OpenTelemetry is the cross-cutting instrumentation model.

Core may emit:

- application/use-case spans;
- authorization spans/metrics;
- UnitOfWork spans;
- repository/PostgreSQL spans;
- security/audit-related events where appropriate.

The HTTP service adds transport-level telemetry such as request spans, latency, and status metrics.

The intended observability pipeline uses an OpenTelemetry Collector with:

- Prometheus for metrics;
- Jaeger for traces;
- Loki for logs.

Domain logic should not depend directly on these backend products.

## 15. Testing Direction

Connector semantics should be validated with a shared contract suite.

The same behavioral expectations should be exercised against:

- `LocalConnector` backed by core and test persistence;
- `HttpConnector` backed by the service and equivalent test persistence.

A semantic difference between connectors should be treated as a defect unless explicitly documented by the public contract.

Authorization should have independent conformance tests covering the security constitution, Tenant-scoped session isolation, and PermissionSet/Permission resolution.

### 15.1 Unit versus real-PostgreSQL integration testing

Ordinary unit testing (`tests/unit`, driven by `./build.sh --qa`) stays service-independent and runs the >=85% coverage gate without needing PostgreSQL. Real-PostgreSQL migration/schema/constraint testing lives under `tests/integration/postgres` and is driven by `./build.sh --integration`. Integration fixtures connect only to the explicitly configured MTMF database (`MTMF_*` environment variables) and fail closed when that configuration is missing or ambiguous: they never probe for, discover, or fall back to another PostgreSQL instance, including any ATI-owned database.

### 15.2 Local PostgreSQL and ATI coexistence (WSL/Podman)

The canonical local MTMF PostgreSQL service is defined by the repository `compose.yaml` under the Compose project `mtmf`, with a `postgres` service, a project-scoped volume, and a configurable host-published port (`MTMF_POSTGRES_PORT`, default 25432, following the MTMF host-port prefix-2 convention). `scripts/mtmf-postgres.py up|stop|down|reset|status` scopes every Podman/Compose operation to the MTMF project (project name is always passed explicitly; an ambient `COMPOSE_PROJECT_NAME` that differs from `mtmf` causes a refusal). MTMF tooling never discovers PostgreSQL by image name, generic container name, first match, or port, never runs global Podman prunes, and never touches ATI resources. `reset` re-creates only the MTMF project's containers and volumes. Development credentials are placeholders in `.env.example`; no real secret is committed.

## 16. Deferred Architecture Decisions

The following are intentionally not settled here:

- exact Python package/module trees;
- Protocol versus ABC choices for public/internal interfaces;
- exact public service-interface grouping;
- final `mtmf-client` optional-dependency packaging;
- exact DTO-to-core mapping implementation;
- complete repository interfaces;
- exact IdP SPI;
- caching and authorization-state invalidation (deferred; when designed, caching belongs behind `AuthorizationPolicyResolver` decorator implementations, never inside the Authorizer or the policy implementations);
- Rust optimization details (the Rust evaluators are experimental and non-default since PR 8H; the production default is the pure-Python indexed `CompiledPolicy`).
- HTTP API shape and versioning strategy.
