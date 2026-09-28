# MTMF Architecture

## 1. Purpose

This document describes the technical architecture of the Multi-Tenant Management Framework (MTMF): package boundaries, layers, deployment modes, persistence abstractions, transport behavior, and cross-cutting infrastructure.

Security semantics are defined by [SECURITY_MODEL.md](SECURITY_MODEL.md). Authorization-engine behavior is described in [AUTHORIZATION.md](AUTHORIZATION.md). The structural domain model is defined in [DOMAIN_MODEL.md](DOMAIN_MODEL.md).

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

Tables, indexes, constraints, and other physical schema details are implementation details of the PostgreSQL provider.

Security-critical invariants should be enforced at trusted persistence/write boundaries in addition to higher layers where appropriate.

## 11. Schema Migration

MTMF uses Alembic internally for PostgreSQL schema migration.

Consumers interact with an MTMF-owned migration/database-management interface rather than Alembic directly. They should not need to know MTMF Alembic script locations, revision IDs, configuration objects, or migration graph internals.

An application may independently use Alembic for its own schema. MTMF owns its own migration graph.

Migration management is outside `MtmfSpi` because schema lifecycle is a deployment concern rather than a runtime persistence contract.

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

## 16. Deferred Architecture Decisions

The following are intentionally not settled here:

- exact Python package/module trees;
- Protocol versus ABC choices for public/internal interfaces;
- exact public service-interface grouping;
- final `mtmf-client` optional-dependency packaging;
- exact DTO-to-core mapping implementation;
- complete repository interfaces;
- exact IdP SPI;
- caching and authorization-state invalidation;
- Rust optimization details;
- HTTP API shape and versioning strategy.
