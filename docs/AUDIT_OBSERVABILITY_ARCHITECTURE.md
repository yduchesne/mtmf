# MTMF — Audit and Observability Architecture

> **Status: APPROVED SYSTEM ARCHITECTURE; PR 19 IMPLEMENTATION NOT COMPLETE.** This document defines MTMF's system-wide audit and observability architecture; roadmap PR 19 is its initial implementation milestone. It does not claim the collectors, dashboards, new audit coverage, or benchmarks are already deployed. Existing database audit mechanisms remain authoritative.
>
> **Implementation progress (2026-10-14, factual clarification only).** The service-side event/metric/span taxonomy, strict allowlist serializer, bounded instance-scoped OTel runtime, provider-neutral `mtmf-core` persistence telemetry seam, optional `mtmf-client` instrumentation extra, and the opt-in MTMF-owned Collector/Prometheus/Jaeger/Loki/Grafana overlay with four dashboards-as-code and three datasource UIDs are implemented. Canonical `--qa`, `--sec`, `--rust` and `--integration` gates pass. The **live** real-stack acceptance (O-L01–O-L05) passed three consecutive clean cycles, and the controlled disabled/healthy/unavailable-Collector performance comparison measured enabled telemetry within the ≤5% throughput / ≤10% p99 targets in a drift-controlled A/B. PR 19 remains **not DONE** only because the separate database mutation-audit provenance STOP is open; no compliance-grade or tamper-evident guarantee is claimed and the default Loki/OTel pipeline remains best-effort. The mutation-audit inventory is recorded under `docs/pr-artifacts/pr-19/`; no generic audit table or unverified actor attribution was added.
>
> **PR 19A status (2026-10-14).** The scoped follow-up "PR 19A — verified-provenance mutation audit" was opened. Its Phase 0 trust-boundary reconciliation found **no existing authenticated-and-authorized (category-A) management mutation entry point** in the current codebase — the runtime exposes only the batch decision endpoint and health probes, and all writes are privileged operator/bootstrap or structural repository/test paths. Per the PR 19A plan's mandatory early STOP, no management API, schema, stored function, grant, or route was manufactured. Only an internal immutable `VerifiedMutationProvenance` contract with an **empty** closed registration map and fail-closed validation was added (`packages/mtmf-core/src/mtmf_core/application/mutation_provenance.py`). No database audit coverage was added or claimed; PR 19A is **PARTIAL/BLOCKED** and the PR 19 database mutation-audit STOP remains open. See `docs/pr-artifacts/pr-19a/`.

## 1. Architectural decision

MTMF uses **two complementary audit channels**, distinguished by event semantics rather than a blanket requirement to store every event in PostgreSQL:

1. **High-volume observations:** batch authorization ALLOW/DENY decisions, authentication failures, rejected assertions, subscription eligibility rejections, and operational events are emitted as structured OpenTelemetry (OTel) logs. Traces and metrics provide correlation and aggregate visibility. No synchronous PostgreSQL write is added per authorization decision or per evaluated Action.
2. **Authoritative security-state mutations:** security-critical changes to Tenant/subscription state, Role/Permission policy, identity bindings, stewardship, and membership are durably audited at the PostgreSQL trust boundary, atomically with the successful mutation where possible. Existing `mtmf.membership_removal_audit` and `mtmf.stewardship_audit` must be preserved. Audit gaps for additional mutation operations must be inventoried before adding narrowly scoped coverage.

**No generic `authorization_decision_audit` or all-purpose `security_event_audit` PostgreSQL table is required by PR 19.** Do not make audit insert latency or audit-table growth part of the normal batch-PDP critical path.

## 2. Ownership and trust boundaries

- The **MTMF service** owns verified actor/application/Tenant context, decision outcomes, failure classification, and event creation. Never trust caller-supplied identity identifiers as verified audit attribution.
- The **MTMF client** owns only client-side HTTP/token-acquisition/snapshot-enforcement telemetry; it must not assert that a server-side decision was recorded durably.
- The **OTel SDK and Collector** transport structured events, metrics, and traces; exporter success is not proof of permanent retention.
- The **audit destination** owns retention, access controls, durability and optional SIEM forwarding. A default Loki deployment is an operational log store, not automatically a compliance-grade immutable audit archive.
- **PostgreSQL** remains authoritative for state changes. Mutations use existing versioned stored functions and restricted runtime privileges; no direct runtime table writes, generic audit-insertion function, or alternate database access path.
- **Root recovery** retains its separately required independent, durable, operator-controlled audit channel; ordinary OTel emission and a rolled-back PostgreSQL transaction cannot substitute for it.

## 3. Event taxonomy and schema contract

Use one structured OTel log event **per completed batch request**, plus a bounded separate security-rejection event for a rejected request. Avoid an unconditional per-Action log fanout. Required common fields:

| Field | Contract |
|---|---|
| `event.name` | Stable allowlisted name, e.g. `mtmf.authorization.batch`, `mtmf.security.authentication_rejected`, `mtmf.security.context_rejected`, `mtmf.security.subscription_rejected` |
| `event.schema_version` | Integer `1`; future incompatible changes increment version |
| `timestamp` | UTC event time |
| `trace_id`, `span_id` | OTel context when present; do not fabricate |
| `request_correlation_id` | Server-generated opaque correlation ID; validate/replace untrusted inbound values |
| `outcome` | Controlled enum: `ALLOW`, `DENY`, `REJECTED`, `ERROR` (batch outcomes can be `MIXED`) |
| `reason_code` | Stable, bounded, non-sensitive classification; no raw exception message |
| `action_count`, `allow_count`, `deny_count` | Nonnegative bounded integers for batch events |
| `duration_ms` | Finite nonnegative duration |
| `service.name`, `service.version`, `deployment.environment` | Bounded OTel resource attributes |

Sensitive context may be represented only in a separately access-controlled audit-log payload where explicitly necessary and independently reviewed; **never** as metric labels or high-cardinality span attributes. Prefer server-issued opaque correlation IDs for joining with restricted application records. Do not emit raw access/refresh tokens, client secrets, passwords, signed user assertions, authorization policy bodies, resource identifiers, user PII, SQL text containing secrets, or request/response bodies. Redact headers such as `Authorization` and `X-MTMF-User-Authorization` by default. Never log arbitrary exception `str()` or provider responses at the trust boundary.

A rejected request must not be logged as a successful policy DENY. A failed dependency or audit exporter must not be converted into ALLOW.

## 4. Metrics and traces

Instrument service ingress, trusted actor verification, Application/Tenant subscription gate, batch PDP, core authorization, PostgreSQL UnitOfWork/stored-function calls, external IdP/JWKS dependencies, and official client HTTP calls. Use existing instrumentation seams when present; do not duplicate middleware or evaluator implementations.

Recommended stable low-cardinality metrics (exact naming and units to be frozen in the PR 19 detailed execution plan):
- `mtmf.http.requests` (counter), `mtmf.http.duration` (histogram)
- `mtmf.authorization.batches` and `mtmf.authorization.actions` (counters)
- `mtmf.authorization.batch.duration` and `mtmf.authorization.batch.size` (histograms)
- `mtmf.security.rejections` (counter, bounded reason category)
- `mtmf.persistence.operations` and `mtmf.persistence.duration`
- `mtmf.dependencies.failures` (bounded dependency category)
- `mtmf.telemetry.export.failures` and `mtmf.telemetry.dropped.events` (where the chosen SDK/Collector exposes these reliably)

Allowed metric dimensions are bounded enums such as route template, operation, outcome, error category, and dependency class. **Never label metrics by Tenant, Application, Principal, user, resource, request, trace, token, raw Action URN, SQL statement, or arbitrary exception.** Traces must not contain secret-bearing request bodies or authorization policy contents.

## 5. OTel pipeline and dashboards-as-code

PR 19 must deliver an **independently deployable MTMF-owned** OTel Collector, Prometheus, Jaeger, Loki, and Grafana development stack, with pinned/configured images, local-only published ports, non-conflicting MTMF host-port prefix conventions, bounded storage, health checks, and controlled lifecycle. Do not depend on ATI services or mutate another project's Podman resources.

Provision datasources and four version-controlled Grafana dashboards automatically:
1. **MTMF Overview:** traffic, latency percentiles, error rate, service availability.
2. **Authorization Decisions:** batch/action throughput, ALLOW/DENY/MIXED distribution, batch size, PDP latency.
3. **Authentication & Security:** rejected service/user authentication, trust-boundary and subscription rejections, categorized failure rates.
4. **Persistence & Dependencies:** database operation latency/errors, pool health when supported, issuer/JWKS failures, telemetry-export health.

Metrics, logs and traces must be correlated by valid OTel context; dashboards must use real emitted signals, not synthetic production-looking fixtures. Grafana access and Loki log access must be restricted appropriately; default development credentials must not be represented as production security controls.

## 6. Delivery, retention, and failure semantics

- The OTel emission path must be **bounded and asynchronous** with explicit queue capacity, export timeouts, backpressure/drop behavior, and no unbounded memory growth. Authorization must remain fail-closed for authorization/dependency failures, but a normal operational telemetry-export outage **must not** make otherwise valid authorization decisions unavailable.
- **Audit completeness is not guaranteed** by this default pipeline: process crash, queue overflow, exporter failure, collector outage, or backend failure can lose observational events. Document this explicitly; surface losses/failures through available SDK/Collector self-observability and operator alerts.
- If a deployment requires **complete, tamper-evident per-decision audit**, it must provision a separately approved durable audit destination and delivery design with explicit acknowledgement, custody, retention, replay and failure policy. Do not claim Loki + default OTel exporter satisfies that requirement.
- Configure explicit log/trace/metric retention and capacity for the development stack; production retention, access controls and legal hold are deployment policy, not fixed by the development Compose example.
- For database security-state mutations, the mutation and its database audit entry must commit or roll back together. No-op and failed mutations must not be misrepresented as committed changes. If a failed attempt itself requires durable independent audit (notably recovery), use a separate approved channel.

## 7. Performance acceptance

Benchmark the same fixed authorization workload and infrastructure against a **pre-PR-19 baseline** under three conditions: instrumentation disabled, enabled with healthy Collector, and enabled with unavailable Collector. Capture environment, sample sizes, warmup, repetitions, batch-size distribution, throughput and p50/p95/p99 latency, CPU and memory, queue drops and exporter failures. Verify Python/Rust batch parity and no changed authorization semantics.

**Initial engineering targets:** no more than **5% throughput degradation** and **10% p99 latency increase** for normal telemetry enabled compared with the equivalent baseline, under a controlled reproducible workload. These are acceptance targets, not existing measurements or permission to discard required audit events. If exceeded, record evidence and STOP for review; do not silently sample away required events or relax limits.

## 8. Mandatory acceptance and scope boundaries

The PR 19 detailed plan must require deterministic unit tests for event schema/redaction, label cardinality, correlation propagation, bounded queues, disabled/unavailable exporter behavior, and mutation audit atomicity. Require a **live** authenticated Keycloak → MTMF HTTPS → PostgreSQL batch evaluation with real OTel Collector → Prometheus/Jaeger/Loki → Grafana, proving metrics, correlated trace and sanitized audit event arrive and dashboards are provisioned. Test negative auth and subscription cases and failure recovery without service-grant regression.

Preserve `./build.sh --qa`, `./build.sh --sec`, `./build.sh --rust`, and `./build.sh --integration` gates, plus a separately named live telemetry acceptance harness. PR-specific reports and evidence must be committed under `docs/pr-artifacts/pr-19/`, preserving uppercase artifact filenames. Mark roadmap PR 19 DONE only after required tests have actually executed and passed.

**Out of scope:** synchronous per-decision PostgreSQL audit, generic unrestricted audit write APIs, changing PDP policy semantics, new consumer integrations (PR 20), production root recovery, commercial SIEM guarantees, and any shared dependency on ATI infrastructure.

## 9. Relationship to existing database audit

Existing `mtmf.membership_removal_audit` and `mtmf.stewardship_audit` are implemented database audit foundations; they must not be replaced by OTel logs. PR 19 must inventory other security-sensitive mutation paths, distinguish verified from caller-asserted actor attribution, and extend atomic audit only where justified by the current stored-function security model. If that inventory reveals a separate migration or policy redesign larger than PR 19's dominant observability concern, STOP and obtain approval for a scoped follow-on PR rather than improvising a generic audit framework.

### 9.1 PR 19A verified-provenance contract (contract only; no coverage)

PR 19A defines the intended trust boundary for a future durable security-state mutation audit, but it does **not** implement database audit coverage:

```text
trusted application use case
  (independently verified actor + exact authoritative Action ALLOW for the bound target)
    -> immutable VerifiedMutationProvenance (internal; not a transport DTO)
    -> [future] UnitOfWork / repository operation
    -> [future] restricted mtmf_runtime connection
    -> [future] reviewed, narrowly scoped SECURITY DEFINER stored function
    -> [future] authoritative mutation + append-only audit row (same transaction)
```

The guarantee that PR 19A provides is limited to an internal record of a trusted application decision. It is **not** a database guarantee and must not be described as one:

- provenance is **application-verified**, not cryptographically attested by PostgreSQL;
- the PostgreSQL role is an application credential, not an end-user identity;
- a compromised application/runtime credential can forge provenance parameters;
- `SET LOCAL`/`current_setting`/ordinary custom GUCs are not identity proof and must never be used as an authentication boundary;
- no existing `membership_removal_audit`/`stewardship_audit` semantics are changed, relabelled, or duplicated;
- root recovery's separate durable operator audit remains mandatory and outside this scope.

Because no category-A mutation path was proven, the contract's closed registration map is empty and `require_registered_mutation` fails closed for every input: no operation is audited by PR 19A and none may be reported as covered. The blocker and the smallest reviewer decisions are recorded in [docs/pr-artifacts/pr-19a/PR19A_STOP_REPORT.md](pr-artifacts/pr-19a/PR19A_STOP_REPORT.md).


### Future management mutations: mandatory provenance and bypass controls

**Normative architectural limitation (PR 19A):** MTMF currently has no production authenticated-and-authorized management mutation entry point. The batch authorization endpoint only evaluates decisions; structural repository/stored-function writes and privileged operator/bootstrap operations do not become verified management operations by virtue of being callable. The PR 19A immutable provenance type and empty registration map do **not** establish durable mutation-audit coverage.

For any future security-state management mutation, the implementation MUST (1) verify the acting Identity at the approved authentication boundary, (2) evaluate the exact Action against the bound target with applicable scope, dominance, and stewardship rules, (3) carry immutable operation-bound provenance into the transaction, (4) atomically commit the state change and an append-only audit row, and (5) revoke or otherwise eliminate all runtime-accessible legacy unaudited bypasses for that operation, with real `mtmf_runtime` privilege tests. Failed/no-op operations MUST NOT be represented as successful changes. Existing membership/stewardship audit semantics MUST remain explicit and must not be relabelled as verified when they are not.

The shared PostgreSQL runtime credential authenticates the application, **not the end user**. Explicit provenance arguments are application-verified rather than cryptographically database-attested; compromise of the runtime credential or trusted service may permit forged attribution. Neither `SET LOCAL`, custom GUCs, nor a caller-supplied UUID is identity proof. The selected future trust model MUST document this residual risk and must not claim database-attested actor identity. Root recovery's independent durable operator audit remains mandatory. PR 19B owns audit-table partitioning only. See [PR 19A STOP report](pr-artifacts/pr-19a/PR19A_STOP_REPORT.md).
