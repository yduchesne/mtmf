# Detailed PR Plan Authoring Guide

## Purpose

This document defines the recommended structure, level of specificity, and authoring process for a **Detailed PR Execution Plan**.

It is intended for implementation PRs that will be executed by a coding agent, especially a lower-reasoning agent that performs well when given:

- a narrow architectural objective;
- an accurate description of the current codebase;
- explicit reuse requirements;
- concrete implementation sequencing;
- precise invariants;
- deterministic tests;
- clear acceptance criteria;
- explicit non-goals and STOP conditions.

The model is adapted for MTMF's architecture and implementation workflow: security invariants, multi-tenant domain semantics, explicit authorization boundaries, UnitOfWork/repository persistence, versioned PostgreSQL stored functions, detached connector semantics, deterministic testing, and strict local-infrastructure isolation.

A detailed PR plan is **not** a roadmap entry, design brainstorm, or general feature specification. It is an executable implementation contract.

---

# 1. Core principle

A good detailed PR plan should make the coding problem substantially more deterministic before implementation begins.

The coding agent should not need to make major architectural decisions while implementing the PR.

The plan should answer:

```text
Why does this PR exist?
What exactly is wrong or missing on current main?
What architecture already exists?
What must be reused?
What is the desired final behavior?
What files/components are likely involved?
What order should implementation follow?
What invariants must remain true?
How will each behavior be tested?
What is explicitly outside scope?
When must the coding agent STOP instead of improvising?
How will a reviewer determine that the PR is complete?
```

The desired effect is:

```text
architecture/reasoning
        happens primarily during planning

implementation
        becomes constrained execution

review
        verifies conformance to explicit invariants
```

---

# 2. Prerequisite: inspect current `main`

Never write a detailed PR plan solely from:

- `docs/ROADMAP_V01.md`;
- an earlier architectural discussion;
- a previous PR plan;
- memory of the repository;
- assumptions about what preceding PRs implemented.

Before producing the plan, inspect fresh `main`.

For repository work, verify at minimum:

```text
relevant domain models
application services
ABCs/interfaces
repositories
database migrations
stored functions
configuration
production composition
tests
integration fixtures
documentation
preceding PR implementation
```

Also search for existing implementations of concepts the roadmap says should be added.

Example:

```text
Roadmap says:
    "add authorization policy resolution"

Current main already has:
    AuthorizationPolicyResolver(Protocol)

Detailed plan must say:
    reuse AuthorizationPolicyResolver

It must NOT tell the coding agent to create:
    PolicyProvider
    AuthorizationBackend
    PermissionResolver
    or another duplicate abstraction
```

A detailed plan is based on the **delta from current main**, not merely on the roadmap description.

---

# 3. Reconcile roadmap scope with current implementation

After inspecting `main`, determine whether the roadmap PR is still correctly scoped.

There are three possible outcomes.

## Outcome A — Scope remains appropriate

Proceed with one detailed PR plan.

## Outcome B — Much of the roadmap work already exists

Narrow the detailed plan to the missing work.

Do not reimplement existing architecture merely to match old roadmap wording.

## Outcome C — The roadmap PR contains multiple independent architectural concerns

Split the PR before writing the detailed plan.

A useful heuristic is:

> A coding-agent PR should normally have one dominant architectural problem.

For example:

```text
Bad monolithic scope:

domain model
+ persistence
+ public API
+ HTTP transport
+ observability
```

Prefer:

```text
PR A — domain/security contract
PR B — persistence
PR C — application integration
PR D — API/transport or hardening
```

This pattern reduces implementation ambiguity and makes regressions easier to isolate.

---

# 4. Recommended document structure

A detailed PR plan should normally contain the following sections.

```text
Title
Purpose
Architectural invariants
Current-main facts
Scope
Explicitly out of scope
Detailed implementation parts/steps
Test matrices
Integration/vertical-slice tests
Documentation updates
Expected files changed
Files that should normally not change
Explicit reuse requirements
STOP conditions
Recommended implementation sequence
Reviewer checklist
PR-level acceptance criteria
Suggested PR description
Dependency/next-PR context
Critical coding-agent rules
```

Not every PR requires every section, but omission should be deliberate.

---

# 5. Title

Use an exact PR identifier and a narrow capability description.

Example:

```markdown
# PR 9 — Role Assignment and Effective-Role Resolution
```

Avoid vague titles such as:

```text
RAG improvements
Coordinator updates
Misc fixes
Research work
```

The title should communicate the dominant architectural concern.

---

# 6. Purpose

The Purpose section explains **why this PR exists** and what architectural problem it closes.

It should normally include:

1. what preceding PRs delivered;
2. what remains incomplete or incorrect;
3. what this PR will establish;
4. what major future PR depends on it.

Example pattern:

```markdown
## Purpose

PR X completes the application-level execution seam introduced by PR Y.

Current main already provides A, B, and C. It does not yet provide D.

PR X therefore adds D without redesigning A/B/C.

The dominant architectural concern is:

> [one-sentence invariant/problem statement]
```

The Purpose section should make it impossible to mistake the PR for a broader feature phase.

---

# 7. Architectural invariants

State the rules that must remain true regardless of implementation details.

These are more important than class names.

Examples:

```text
One UnitOfWork represents one real PostgreSQL transaction.

Authorization defaults to DENY.

Tenant/session validation happens before policy evaluation.

One UnitOfWork represents one real PostgreSQL transaction.

Repositories persist; application use cases coordinate transactions.

Application-level PostgreSQL operations use MTMF's versioned
stored-function convention.

LocalConnector and HttpConnector preserve equivalent detached,
remote-service semantics.

MTMF-owned Podman resources are explicitly namespaced and tooling
must never discover, mutate, or prune resources owned by ATI or
another local application.
```

Use diagrams where they clarify ownership:

```text
Connector / service boundary
    receives detached request
          ↓
Application use case
    coordinates authorization and persistence
          ↓
Authorizer
    decides permission
          ↓
UnitOfWork / repositories
    persist atomically
```

Invariants give the coding agent a way to resolve small implementation choices without inventing architecture.

---

# 8. Current-main facts

This section is essential for coding-agent plans.

Document the important implementation facts discovered during repository inspection.

Include:

- exact files;
- relevant classes/functions;
- current behavior;
- existing abstractions;
- important limitations;
- preceding PR semantics.

Example:

```markdown
## Existing authorization-policy abstraction

`packages/mtmf-core/src/mtmf_core/authorization/policy_resolver.py`

Already contains:

```python
class AuthorizationPolicyResolver(Protocol):
    def resolve(self, context: AuthorizationContext) -> AuthorizationPolicy:
        ...
```

**Reuse this seam. Do not create a duplicate policy-resolution abstraction.**
```

This section prevents the agent from reasoning from stale architecture.

Use code snippets only for the contractually important parts.

Do not dump entire source files.

---

# 9. Scope

Define what the PR owns.

Prefer capability-oriented subsections.

Example:

```markdown
## In scope

### A. Role-assignment domain contract
...

### B. PostgreSQL persistence
...

### C. Effective-role resolution
...
```

Each item should correspond to the PR's dominant concern.

If the in-scope section becomes a list of several unrelated systems, reconsider whether the PR should be split.

---

# 10. Explicitly out of scope

This section is mandatory for agent-executed plans.

State adjacent work that the coding agent might otherwise reasonably attempt.

Example:

```markdown
## Explicitly out of scope

PR X must not add:

- unrelated public API changes;
- new persistence providers;
- authorization caching/invalidation;
- external IdP integration;
- unrelated refactors;
- HTTP endpoints owned by a later PR.
```

Include future PR ownership where useful:

```text
A later PR owns public API/Connector exposure.
A later PR owns HTTP transport.
Authorization caching/invalidation remains deferred until explicitly designed.
```

This makes the PR boundary operational rather than aspirational.

---

# 11. Detailed implementation sections

Break implementation into numbered Parts and Steps.

Recommended hierarchy:

```text
Part 1 — Domain contract
    Step 1
    Step 2

Part 2 — Persistence
    Step 3
    Step 4

Part 3 — Application service
    Step 5

Part 4 — Production composition
    Step 6

Part 5 — Tests
```

Each Step should specify:

```text
where
what
why
required behavior
constraints
acceptance criteria
```

Example:

```markdown
## Step 7 — Update `DefaultAuthorizationPolicyResolver`

Modify the existing resolver seam only when the PR owns policy resolution.

Required behavior must be explicit, for example:

- consume the supplied `AuthorizationContext`;
- reuse existing policy/domain types;
- preserve default-DENY behavior;
- perform no persistence unless the plan explicitly assigns retrieval responsibility here.

Do not change unrelated:

- Action/Permission grammar;
- dominance semantics;
- Tenant-boundary checks;
- Rust experimental infrastructure.
```

This is preferable to:

```text
Update retriever to support citations.
```

---

# 12. Separate semantic identity from persistence identity

Whenever a PR involves persistence, explicitly identify different forms of identity.

For example:

```text
row ID
    = persistence identity

semantic key
    = logical object identity

content hash
    = representation/change identity

external source ID
    = upstream identity
```

Do not let the coding agent infer these distinctions.

This is especially important for:

- append-only records;
- replaceable indexes;
- history tables;
- relationships;
- observations;
- cached/derived data;
- versioned artifacts.

---

# 13. Define ownership boundaries

For every important object, say who creates it and who persists it.

Example:

```text
Application use case
    owns operation orchestration

Authorizer
    owns authorization decisions

AuthorizationPolicyResolver
    resolves already-applicable policy

AuthorizationPolicy
    evaluates exact Actions

Repository
    owns aggregate persistence operations

UnitOfWork
    owns transaction commit/rollback semantics
```

Ownership ambiguity is a common source of agentic implementation drift.

---

# 14. Transaction boundaries

For database work, state transaction semantics explicitly.

Example:

```text
load required MTMF state in a short UoW
    ↓
close transaction
    ↓
perform any remote IdP / external service I/O
    ↓
validate result
    ↓
open a short UoW
    ↓
persist atomically
```

If external I/O must remain outside a transaction, say so repeatedly where relevant.

Also state atomicity requirements:

```text
application reports success
iff
all state required by the operation is committed
```

The coding agent should never have to invent transaction semantics.

---

# 15. External boundaries and fakes

Distinguish between:

```text
production architecture
```

and:

```text
deterministic test substitution
```

Preferred rule:

> Fake the external or nondeterministic boundary, not the MTMF architecture being tested.

Example:

```text
Production:
Connector/service adapter
 -> application use case
 -> Authorizer
 -> UnitOfWork/repositories
 -> PostgreSQL provider

Integration test:
same application path
 -> same Authorizer
 -> same repositories/stored functions
 -> isolated real MTMF PostgreSQL
 -> fake only a remote IdP/external boundary when determinism requires it
```

Avoid introducing a parallel fake architecture such as:

```text
FakeAuthorizer
FakeRepository
FakeUnitOfWork
```

for a canonical integration test if doing so bypasses the production path the test is supposed to validate.

Lightweight fakes remain appropriate for isolated unit tests.

---

# 16. Verify external framework contracts

If the PR depends on:

- FastAPI/Uvicorn;
- PostgreSQL/driver behavior;
- Alembic;
- PyO3/maturin/Rust;
- OpenTelemetry;
- an external IdP SDK or API;

verify the exact current contract before finalizing implementation instructions.

Prefer:

```text
installed dependency source/API
official documentation
current upstream schema
```

Do not write implementation instructions from remembered APIs.

Add a STOP condition when the required public contract is unavailable.

---

# 17. Deterministic behavior tables

For policy/state-machine work, define cases in tables.

Example:

| Case | Input | Expected |
|---|---|---|
| exact permission | matching Action | exact decision |
| wildcard permission | matching qualifier | wildcard decision |
| equal-specificity ALLOW + DENY | same Action | DENY |
| cross-Tenant target | otherwise valid request | DENY before policy resolution |

Tables are particularly effective for low-reasoning coding agents because they convert policy into finite cases.

---

# 18. Unit test matrix

Specify important unit cases explicitly.

Use stable IDs when useful:

| ID | Case | Expected |
|---|---|---|
| C1 | valid same-Tenant input | accepted |
| C2 | duplicate persistence identity | rejected |
| C3 | missing membership prerequisite | rejected |
| C4 | exact permission ALLOW | allowed |
| C5 | equal-specificity DENY conflict | denied |

Benefits:

- coding agent can map implementation to tests;
- reviewer can detect missing cases;
- plan discussion can refer to a stable case ID;
- future fixup plans can identify regressions precisely.

Do not attempt to enumerate every trivial test.

Enumerate behavioral boundaries.

---

# 19. Integration and vertical-slice tests

A detailed plan should distinguish unit correctness from production-path correctness.

A vertical slice should exercise as much real application architecture as practical.

Example:

```text
application/connector request
    ↓
production application use case
    ↓
production Authorizer
    ↓
real PostgreSQL stored functions/repositories
    ↓
detached result/error contract
```

Fake only external boundaries required for determinism.

State exact assertions.

Do not merely say:

```text
add integration tests
```

---

# 20. Failure behavior

Define how failures behave.

Examples:

```text
invalid session context
    -> explicit fail-closed authorization result

cross-Tenant target
    -> DENY before policy resolution

repository/database failure
    -> rollback
    -> no partial committed state

remote IdP failure
    -> typed application failure/compensation path
    -> no open PostgreSQL transaction across remote I/O
```

Also specify cancellation behavior for async code:

```text
asyncio.CancelledError propagates
```

unless architecture explicitly requires otherwise.

---

# 21. Idempotency

If the operation can be retried, define idempotency explicitly.

Questions to answer:

```text
What identifies the operation?
What is safe to repeat?
What is append-only?
What is replaceable?
What is deduplicated?
What changes when inputs change?
What remains stable?
```

Example:

```text
same idempotent create request
    -> no duplicate logical resource

retry after transaction rollback
    -> no partial state from failed attempt

stable DomainId / URN identity
    -> remains stable across mutable display-field updates
```

---

# 22. Database migrations and stored functions

When relevant, specify:

- expected migration behavior;
- derived vs authoritative data;
- backfill strategy;
- uniqueness constraints;
- FK behavior;
- function versioning convention;
- whether old functions remain immutable.

Never instruct the coding agent to edit previously shipped versioned SQL in place if the repository uses immutable function versions.

If a migration may safely discard derived data, say so.

Example:

```text
Derived cache/index state may be rebuildable when explicitly documented.
Tenant, Organization, Principal, Identity, Group, Role, membership, and authorization state are authoritative and must not be discarded by a migration.
```

---

# 23. Documentation updates

Name the exact docs that should change and what each should say.

Example:

```text
ARCHITECTURE.md
    package/layer ownership and runtime boundaries

AUTHORIZATION.md
    authorization semantics and policy-resolution behavior

SECURITY_MODEL.md
    security constitution/invariants when affected

DOMAIN_MODEL.md
    structural domain semantics when affected

ROADMAP_V01.md
    delivered PR scope/status only
```

Avoid broad:

```text
update documentation
```

Also specify docs that should **not** be expanded into future architecture.

---

# 24. Expected files changed

Provide a likely file map.

Example:

```text
packages/mtmf-core/src/mtmf_core/domain/...
packages/mtmf-core/src/mtmf_core/authorization/...
packages/mtmf-core/src/mtmf_core/persistence/...
packages/mtmf-core/src/mtmf_core/persistence/postgres/...
tests/unit/...
tests/integration/postgres/...
docs/...
```

Label it as expected rather than mandatory when current implementation may justify a nearby location.

This helps the coding agent recognize scope drift.

---

# 25. Files that should normally not change

This is highly effective for constrained implementation.

Example:

```text
The PR should not normally require behavioral changes in:

packages/mtmf-api/**
packages/mtmf-client/**
packages/mtmf-service/**
packages/mtmf-core/src/mtmf_core/authorization/**
packages/mtmf-core/src/mtmf_core/persistence/postgres/**
```

If the coding agent believes one must change, it should evaluate a STOP condition rather than casually editing it.

---

# 26. Explicit reuse requirements

List existing abstractions/components that must be reused.

Example:

```text
Reuse:

UnitOfWork
MtmfSpi
existing typed repository protocols
AuthorizationPolicy
AuthorizationPolicyResolver
Authorizer
existing domain value objects and membership types
```

Then state:

```text
Do not duplicate them under new feature-specific names.
```

This is especially important in mature codebases where an agent may prefer creating a new local abstraction instead of understanding the existing one.

---

# 27. STOP conditions

STOP conditions are one of the most important parts of a low-reasoning coding-agent plan.

They define when the coding agent must stop implementation and request an architectural decision rather than improvise.

Examples:

```text
STOP if:

1. required behavior changes a settled security invariant;
2. a migration would destroy authoritative MTMF state;
3. the existing abstraction cannot represent the required operation;
4. implementation requires a future-PR feature;
5. an external API/SDK cannot satisfy the planned contract;
6. a PostgreSQL transaction would have to remain open across remote I/O;
7. a new generic framework appears necessary;
8. tests require live Internet;
9. scope requires weakening QA, security, or coverage gates;
10. current main already implements the planned capability differently;
11. local tooling would need to discover/control containers, networks, or volumes not explicitly owned by MTMF.
```

Specify the report format:

```text
When stopping, report:

file/function/schema
current behavior
required invariant
why current architecture cannot satisfy it
smallest reviewer decision needed
```

STOP conditions prevent a coding agent from turning uncertainty into architecture.

---

# 28. Recommended implementation sequence

Give the coding agent an ordered execution path.

Example:

```text
Phase 0 — Baseline
Phase 1 — Pure domain/security changes
Phase 2 — Persistence
Phase 3 — Application/authorization integration
Phase 4 — Connector/adapter work when in scope
Phase 5 — Integration path
Phase 6 — Docs/full QA/security
```

Within Phase 0:

```text
1. re-read current files;
2. identify migration head;
3. run targeted baseline tests;
4. run relevant integration tests;
5. record green baseline;
6. only then edit.
```

This prevents the agent from mistaking pre-existing failures for its own regressions.

---

# 29. Reviewer checklist

Create a checklist grouped by architectural concern.

Example:

```markdown
## Persistence

- [ ] one UoW = one PostgreSQL transaction
- [ ] no external I/O inside transaction
- [ ] existing repository/SPI seams reused
- [ ] rollback tested

## Security

- [ ] default DENY/fail-closed behavior preserved
- [ ] Tenant boundaries remain explicit
- [ ] authorization is enforced at a trusted boundary

## Scope

- [ ] no future-PR caching/API/IdP behavior leaked in
- [ ] no unrelated refactor
- [ ] MTMF Podman/resource isolation preserved when infrastructure is touched
```

The checklist should be usable independently of the implementation narrative.

---

# 30. PR-level acceptance criteria

End with a numbered, exhaustive-but-focused completion list.

Example:

```text
PR is complete only when:

1. required domain/security contract exists;
2. invalid/cross-boundary inputs fail closed;
3. persistence round-trips where in scope;
4. rollback works where persistence is touched;
5. canonical production path is exercised;
6. idempotency/retry behavior is proven where relevant;
7. no future-PR behavior is introduced;
8. docs are reconciled;
9. ./build.sh --qa passes;
10. ./build.sh --sec passes;
11. ./build.sh --integration passes when PostgreSQL behavior is in scope.
```

These criteria become the final contract for both coding agent and reviewer.

Prefer objective statements.

Avoid:

```text
implementation is clean
tests are good
architecture is robust
```

unless accompanied by measurable meaning.

---

# 31. Suggested PR description

Provide a short ready-to-use PR description.

It should summarize:

```text
what was added
what existing architecture was reused
what important invariant was established
what is explicitly not included
```

This is useful both for the coding agent and later review.

---

# 32. Dependency and next-PR context

When the PR is one part of a series, show where it fits.

Example:

```text
PR X
foundation
   ↓
PR Y
persistence/integration
   ↓
PR Z
API/transport or hardening
```

This reinforces why adjacent features must not leak into the current PR.

---

# 33. Critical coding-agent rules

End with a few memorable rules.

Examples:

> **Do not rebuild infrastructure that already exists on `main`.**

> **Do not turn uncertainty into a new abstraction. STOP when the plan requires an architectural decision.**

> **Fake external boundaries, not the production architecture being tested.**

> **Preserve security, Tenant-isolation, transaction, and detached-connector invariants even if a shortcut would reduce code.**

> **Never let MTMF local tooling discover or control infrastructure owned by another application.**

These should summarize the highest-risk failure modes.

---

# 34. Level of specificity

A detailed PR plan should be highly specific about:

```text
behavior
ownership
invariants
state transitions
persistence semantics
transaction boundaries
test cases
scope
failure behavior
reuse
```

It may be less prescriptive about:

```text
private helper names
minor file organization
local refactoring details
exact internal algorithms where multiple implementations satisfy the same contract
```

The goal is not to write the code in prose.

The goal is to remove architectural ambiguity.

---

# 35. What not to put in a detailed PR plan

Avoid:

## Speculative future architecture

Do not design three future releases merely because the current PR creates an extension seam.

## Unnecessary implementation trivia

Do not prescribe every variable name or every assertion.

## Broad cleanup

Avoid:

```text
while here, refactor...
modernize...
clean up...
generalize...
```

unless required for the PR invariant.

## Generic best practices without repository context

Prefer:

```text
Use the existing UnitOfWork and versioned stored-function convention.
```

over:

```text
Follow database best practices.
```

## Unbounded optional work

Avoid:

```text
optionally improve...
consider adding...
if time permits...
```

A coding-agent execution plan should have deterministic scope.

---

# 36. Plan sizing and PR splitting heuristic

Before finalizing a detailed plan, ask whether the coding agent must solve more than one major architectural question.

Warning signs:

```text
new persistence model
+ new authorization model
+ new public API

new API
+ HTTP transport
+ external IdP workflow

new provider SPI
+ several provider implementations
+ caching/invalidation framework
```

Split when failures in one concern would make another concern difficult to review independently.

A useful pattern is:

```text
A — deterministic domain/security foundation
B — persistence
C — application/API integration
D — conformance/docs hardening
```

Not every feature requires A/B/C/D, but it is a strong default for complex agentic systems.

---

# 37. Fixup plans

When review finds defects after implementation, do not rewrite the original detailed plan.

Create a narrow fixup plan.

A fixup plan should contain:

```text
review finding
exact current-main defect
required invariant
minimal code changes
regression tests
explicit non-goals
acceptance criteria
```

Example:

```text
PR 8H-1
    authorization diagnostics disclosure fix only

not:
    redesign AuthorizationPolicyResolver
```

Fixups should be substantially narrower than the originating PR.

---

# 38. Review process after implementation

Review the implementation against:

```text
current main
+
detailed PR plan
+
architectural invariants
+
tests
```

Do not review only the diff mechanically.

Verify:

1. required behavior exists;
2. existing architecture was reused;
3. STOP-boundary features did not leak in;
4. tests actually exercise the intended production path;
5. negative/boundary cases exist;
6. documentation matches delivered behavior;
7. acceptance criteria are satisfied.

If the implementation deviates but is architecturally superior, evaluate the deviation explicitly rather than declaring noncompliance solely because a suggested private implementation detail changed.

Behavioral and architectural contracts outrank incidental naming.

---

# 39. Reusable template

The following template can be copied for a new detailed PR plan.

```markdown
# PR X — <Narrow title>

## Purpose

<What exists, what is missing, why this PR exists.>

The dominant architectural concern is:

> **<one-sentence invariant/problem>**

---

# Architectural invariants

- ...
- ...

```text
<ownership/data-flow diagram>
```

---

# Current-main facts that must be respected

## Existing <component>

`path/to/file.py`

Current behavior:

```python
...
```

**Reuse this. Do not create a duplicate abstraction.**

---

# Scope

## In scope

### A. <capability>
- ...

### B. <capability>
- ...

---

# Explicitly out of scope

PR X must not add:

- ...
- ...

If implementation requires one of these, STOP.

---

# Part 1 — <concern>

## Step 1 — <action>

Location:

```text
path/to/file.py
```

Required behavior:

- ...
- ...

Do not:

- ...
- ...

### Acceptance criteria

- ...
- ...

---

# Part 2 — <concern>

## Step 2 — <action>

...

---

# Unit test matrix

| ID | Case | Expected |
|---|---|---|
| U1 | ... | ... |
| U2 | ... | ... |

---

# PostgreSQL / integration test matrix

## I1 — <scenario>

Exercise:

```text
A
 -> B
 -> C
```

Assert:

- ...
- ...

---

# Failure and cancellation behavior

- ...
- ...

---

# Idempotency and retry semantics

- ...
- ...

---

# Documentation updates

## `docs/ARCHITECTURE.md`
- ...

## `docs/TESTING.md`
- ...

---

# Expected production files changed

```text
...
```

---

# Files that should normally NOT change

```text
...
```

---

# Explicit reuse requirements

Reuse:

```text
...
```

Do not duplicate these abstractions.

---

# STOP conditions

Stop and report if:

1. ...
2. ...
3. ...

When stopping, report:

```text
file/function/schema
current behavior
required invariant
smallest architecture decision needed
```

---

# Recommended implementation sequence

## Phase 0 — Baseline

1. Re-read current main.
2. Run targeted tests.
3. Record baseline green.

## Phase 1 — Domain
...

## Phase 2 — Persistence
...

## Phase 3 — Integration
...

## Phase 4 — Docs/full QA
...

---

# Reviewer checklist

## Architecture

- [ ] ...

## Persistence

- [ ] ...

## Scope

- [ ] ...

---

# PR-level acceptance criteria

PR X is complete only when:

1. ...
2. ...
3. ...
4. full QA passes.

---

# Suggested PR description

> <Concise PR description.>

---

# Sequence after PR X

```text
PR X
   ↓
PR Y
```

Critical coding-agent rules:

> **<rule 1>**

> **<rule 2>**
```

---

# 40. Compact authoring checklist

Before delivering a detailed PR plan, verify:

- [ ] Fresh `main` was inspected.
- [ ] The roadmap scope was reconciled with actual implementation.
- [ ] Existing abstractions are explicitly identified.
- [ ] The PR has one dominant architectural concern.
- [ ] Invariants are explicit.
- [ ] Ownership boundaries are explicit.
- [ ] Transaction boundaries are explicit where relevant.
- [ ] Production vs test/fake boundaries are explicit.
- [ ] External API assumptions were verified where relevant.
- [ ] Scope and non-goals are explicit.
- [ ] Implementation is broken into ordered steps.
- [ ] Boundary cases have deterministic tests.
- [ ] At least one production-path vertical slice exists where appropriate.
- [ ] Failure/idempotency semantics are specified.
- [ ] Expected files and normally-unchanged files are listed.
- [ ] Existing components that must be reused are listed.
- [ ] STOP conditions prevent architectural improvisation.
- [ ] Reviewer checklist exists.
- [ ] Objective PR-level acceptance criteria exist.
- [ ] Full repository QA/security gates are named, including integration when relevant.
- [ ] Future PR responsibilities are not accidentally absorbed.

---

# Final standard

A successful detailed PR plan should let a coding agent spend most of its effort on **implementation**, not architecture discovery.

The plan is sufficiently detailed when a reviewer can ask:

> "Did the implementation satisfy this contract?"

rather than:

> "What architecture did the coding agent decide to build?"

That is the standard.
