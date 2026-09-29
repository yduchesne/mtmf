# MTMF — Coding Agent Instructions

## Source of truth

Before implementing a change, read the relevant authoritative project documents:

- `docs/SECURITY_MODEL.md` — normative security constitution and invariants.
- `docs/DOMAIN_MODEL.md` — domain objects, relationships, lifecycle, and aggregate semantics.
- `docs/AUTHORIZATION.md` — authorization evaluation and Permission matching.
- `docs/ARCHITECTURE.md` — package, connector, persistence, transport, and infrastructure boundaries.
- `docs/ROADMAP_V01.md` — current high-level implementation sequence.

Major architecture and security decisions are already documented. Do not replace them with alternate designs without an explicit approved documentation change.

When documents differ in authority for a security question, `docs/SECURITY_MODEL.md` takes precedence.

## Non-negotiable rules

- MTMF is a reusable multi-tenant management framework. Keep core concepts product-independent.
- Tenant isolation is a fundamental security boundary.
- Authorization is deny-by-default and is evaluated for the specific acting Identity in the active `(Tenant, Principal, Identity)` session.
- Never union authorization state across Tenant contexts.
- Principal and Identity are global objects; Tenant participation is explicit through typed memberships.
- Groups contain Identities through explicit typed membership relationships.
- Roles are assigned to Identities or Groups in exactly one Tenant context.
- Roles own PermissionSets; PermissionSets own Permissions. PermissionSets and Permissions are not independently assignable.
- Permission effect belongs to PermissionSet, not Permission.
- Actions are shared exact definitions identified by immutable Action URNs. Permission URNs express exact or constrained-wildcard Action matching.
- List or assignment order does not create authorization precedence.
- Ownership is immutable creator provenance and is not authorization.
- Tenant Stewardship is distinct from ownership, Role, Permission, and Scope.
- Security Scope and Role definition namespace are distinct concepts.
- Destructive/security-sensitive operations must preserve the documented strict-dominance and alternate-dominance rules.
- Persistent deletion is soft deletion unless an authoritative document explicitly states otherwise.
- Application `extension` data is a JSON object, defaults to `{}`, is opaque to MTMF semantics, and must not be used to infer authorization.
- Domain identity and provenance fields are immutable. Other domain state is mutable only where the domain permits it.
- Do not weaken documented invariants for implementation convenience.

## Package and dependency boundaries

The intended workspace contains independently installable distributions for:

- `mtmf-api`;
- `mtmf-core`;
- `mtmf-client`;
- `mtmf-service`.

Preserve the dependency direction defined in `docs/ARCHITECTURE.md`.

In particular:

- public DTOs are detached snapshots;
- consumers must not depend directly on core domain objects;
- `LocalConnector` and `HttpConnector` expose the same location-transparent contract;
- consumers must treat every Connector invocation as potentially remote;
- transport adapters must not duplicate business or authorization logic;
- external IdP integrations are separate from the persistence SPI.

## Python engineering

Use type hints for production code.

Canonical Python tooling:

- `uv` is the package/workspace/dependency tool; `uv sync --locked` is the canonical workspace bootstrap.
- Ruff is authoritative for formatting, linting, and import sorting.
- Mypy strict mode is required for production code; `uv run mypy packages` is the canonical type-check command.
- Pytest is the unit-test runner; the canonical unit suite lives under `tests/unit`.
- Unit-test coverage must remain at least **85%** for all production MTMF packages; the gate fails below that threshold.
- `./build.sh --qa` is the canonical quality command and runs the full gate (Ruff format check, Ruff lint, strict Mypy, unit tests with the coverage gate).

Keep domain objects independent of transport, HTTP frameworks, PostgreSQL drivers, and persistence implementations.

Core domain objects should use plain Python/dataclass-style modeling. Pydantic belongs at the public API/DTO boundary unless an approved architecture change says otherwise.

Do not make a quality gate pass by weakening configuration, suppressing diagnostics broadly, skipping tests, or deleting assertions without independent justification.

When repository-standard formatting, linting, type-checking, test, build, or security commands are introduced, use those canonical commands rather than inventing parallel workflows.

Generated Python bytecode and local development artifacts must not be committed.

## Persistence and transaction rules

- `MtmfSpi` is the internal persistence SPI.
- A persistence provider owns the complete persistence implementation for one MTMF runtime.
- Repositories participating in one business operation share a UnitOfWork/transaction context.
- The PostgreSQL provider performs application-level database operations and logic through stored functions.
- Alembic is an internal migration mechanism; consumers interact through an MTMF-owned migration/database-management interface.
- Do not expose PostgreSQL connections, Alembic internals, or persistence implementation details through public contracts.
- Do not hold a PostgreSQL transaction open while performing remote IdP calls.
- Multi-object operations that establish documented invariants must be atomic where partial completion would create invalid domain state.

## Authorization implementation rules

- The core `Authorizer` is authoritative; clients and transports do not reconstruct authorization.
- Callers request exact Actions, not Permissions.
- Permission matching must remain deterministic and testable independently from authorization-context retrieval.
- Exact matches are more specific than constrained qualifier wildcards.
- At equal specificity, DENY wins.
- A matching ALLOW does not bypass Tenant isolation, assignment context, lifecycle, scope/dominance, stewardship, management delegation, or operation-specific constraints.
- Missing, inconsistent, unknown, or unevaluable authorization context must fail closed.
- Do not infer behavior for security-sensitive unresolved design items. Follow the more restrictive behavior until the design is explicitly settled.

## Rust permission engine

- The Rust permission kernel is pure, deterministic, in-memory computation with no I/O: no PostgreSQL, `MtmfSpi`, UnitOfWork, repositories, network, or filesystem policy discovery.
- Python supplies all required policy input: an exact Action plus already-applicable PermissionSets, flattened to detached primitive values. No live Python domain objects (`Action`, `Role`, `PermissionSet`, `Permission`) cross the FFI boundary, and no JSON serialization carries policy.
- Rust never retrieves session, Tenant, membership, assignment, stewardship, or delegation context.
- The Python `Authorizer` remains authoritative for context, applicability, and fail-closed orchestration.
- The Python `PermissionEvaluator` remains the semantic reference implementation absent a later explicit architecture change; any authorization-semantic change must keep the documented Python/Rust parity tests updated in the same PR.
- Malformed/incoherent native input or output is an infrastructure/evaluation failure that fails closed; it is never a policy DECISION (`ALLOW`/`NO_MATCH`/`MATCHED_DENY`) and there is no automatic Python fallback.
- Native failures must not be compensated by documentation or benchmark claims, and benchmarks never justify weakened semantics; performance findings are recorded, not silent semantic shortcuts.
- The Rust series introduces no PostgreSQL/Podman dependency; the `./build.sh --rust` gate is the canonical native conformance gate (cargo fmt/clippy/test, `maturin develop`, installed-native probe, focused boundary/differential/Authorizer tests, clean wheel build/install/use verification, and benchmark smoke) and never requires `MTMF_*` configuration, Podman, or external services.
- PR 8G (`dev/compiled-policy-perf`) is an **experimental sibling** of PR 8F: it compiles already-applicable policy once into an opaque indexed native object (`_mtmf_permission_engine.compile_policy`) for repeated Action evaluation without resend/reparse/sort/scan. It is not a production cutover: the production path remains `Authorizer() -> RustPermissionEvaluator -> native_evaluate(action, policy)` with no backend/env-var selection, fallback, or cache/invalidation. Experimental code lives under `benchmarks/` (`compiled_policy_evaluator.py`, `python_compiled_policy.py`, `compiled_policy_benchmark.py`) and must preserve complete P == R == PC == RC parity before any timing claim, where PC is the pure-Python CompiledPolicy control that separates the compilation benefit from the Rust benefit. After measurement on the campaign machine, the durable evidence is that compiled/indexed evaluation (PC and RC) dominates the current linear evaluators, and that PC beat RC for single-Action evaluation through the built adapter (per-Action PyO3/Action-transport/result-conversion overhead dominates RC); no production direction is selected and the PR is expected to remain unmerged until experimental review.

## Tests

Tests should directly exercise documented invariants, not only happy-path API behavior.

As implementation grows, maintain coverage for:

- Tenant isolation;
- session-Tenant authorization isolation;
- typed membership prerequisites;
- direct and Group-derived Role assignment;
- PermissionSet/Permission specificity and DENY conflict handling;
- strict scope dominance;
- stewardship invariants;
- root/bootstrap invariants;
- ownership immutability;
- extension authorization;
- LocalConnector/HttpConnector semantic equivalence.

Ordinary CI should be deterministic and should not require live external services or credentials unless a test is explicitly designated for such integration.

## Documentation

When implementation intentionally changes a confirmed contract or invariant, update the relevant authoritative documentation in the same PR.

Do not document speculative functionality as implemented behavior.

Classes, interfaces, modules, and public functions/methods should have useful docstrings where they improve the public or architectural contract. Do not mechanically duplicate inherited interface documentation in implementations; document implementation-specific behavior instead.

When a roadmap PR item is completed, update `docs/ROADMAP_V01.md` in the same PR to reflect its status after implementation and validation are complete.

## Working discipline

Before coding:

1. read the applicable authoritative documents;
2. identify the invariants affected by the change;
3. inspect existing code and tests before choosing an implementation;
4. keep the change within the approved PR scope.

Before considering work complete:

1. run the repository's current canonical quality and test commands, if present;
2. verify security and Tenant-boundary invariants affected by the change;
3. update tests and authoritative documentation where required;
4. update the roadmap item when the planned PR is actually complete.

Do not silently broaden scope, resolve documented open questions by assumption, or introduce product-specific behavior into MTMF.
