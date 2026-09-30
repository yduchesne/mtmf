# MTMF Authorization

## 1. Purpose

This document describes the authorization-evaluation architecture implemented by `mtmf-core`.

It is subordinate to [SECURITY_MODEL.md](SECURITY_MODEL.md). The security model defines normative security semantics; this document explains how the `Authorizer` is expected to apply them. If the documents conflict, `SECURITY_MODEL.md` takes precedence.

This document is intentionally shallow while the security model is still evolving.

## 2. Authorizer

`Authorizer` is the authoritative permission-evaluation engine inside `mtmf-core`.

Its fundamental question is:

> May this specific acting Identity, in this (Tenant, Principal, Identity) session, perform this exact Action against this target in this authorization context?

Callers request an **Action**, not a Permission. The caller MUST NOT reconstruct MTMF authorization by selecting a Permission itself.

The Authorizer evaluates policy; it does not perform the protected business operation.

## 3. Default Deny

Authorization is deny-by-default.

The Authorizer MUST positively establish authorization before a protected operation proceeds. Missing roles, unknown Actions, absent or inconsistent membership/context, unresolved scope, invalid delegation, or other insufficient policy state MUST NOT fall through to ALLOW.

An infrastructure failure while evaluating policy is not itself a policy DENY, but the protected operation MUST fail closed.

## 4. Inputs

An authorization decision may require:

- session Tenant, acting Principal, and acting Identity;
- valid active PrincipalTenantMembership and IdentityTenantMembership in the session Tenant;
- requested exact Action;
- target resource and security scope;
- Tenant and Organization context;
- active/deleted state;
- direct Role assignments;
- Group memberships and Group Role assignments;
- Role-assignment context;
- applicable Role-owned PermissionSets, their effects, and owned Permissions;
- Tenant Stewardship;
- TenantManagementGroup delegation and contextual scope;
- operation-specific invariants.

The final input model remains to be designed.

## 5. Permission Resolution

An Identity may have multiple direct Roles and multiple Group-derived Roles in the session Tenant. Groups may themselves have multiple Roles. Roles have no evaluation precedence.

A Role owns an ordered list of PermissionSets. Each PermissionSet carries one `ALLOW` or `DENY` effect and owns an ordered list of Permissions. Ordering does not establish authorization precedence.

A Permission is an Action matcher. Its UUID identifies the owned Permission instance; its Permission URN expresses matching semantics. The Permission itself has no effect; it inherits the effect of its containing PermissionSet.

Actions are shared exact definitions uniquely identified by Action URNs. Action URNs never contain wildcards.

The canonical Action grammar is:

```text
<resource>:<verb>-<qualifier>
```

A Permission uses an exact resource and verb. Its qualifier is either exact or the complete wildcard `*`.

For example:

```text
principal:set-alias
principal:set-*
```

Resolution rules are:

1. discard Roles and PermissionSets that do not apply to the session Tenant and current assignment/context;
2. collect Permissions matching the requested Action;
3. select the most-specific matching Permission or Permissions;
4. exact qualifier match is more specific than wildcard qualifier match;
5. derive each matching Permission's effect from its containing PermissionSet;
6. if equally specific matching Permissions have conflicting effects, `DENY` wins;
7. if no applicable Permission matches, `DENY`.

Example:

```text
PermissionSet(ALLOW): principal:set-*
PermissionSet(DENY):  principal:set-alias
```

For `principal:set-alias`, the exact DENY wins.

Conversely:

```text
PermissionSet(DENY):  principal:set-*
PermissionSet(ALLOW): principal:set-alias
```

For `principal:set-alias`, the exact ALLOW wins.

---

## 6. Additional Authorization Constraints

A matching ALLOW rule is not necessarily sufficient for final authorization.

The Authorizer must also enforce the security-model constraints applicable to the operation, including:

- Tenant and Organization boundaries;
- membership requirements;
- active/deleted state;
- assignment context;
- strict scope dominance where required;
- Tenant Stewardship as a narrowly defined alternate dominance mechanism;
- TenantManagementGroup delegation and contextual ROOT/SYSTEM scope;
- operation-specific invariants.

Scope and Permission are independent.

### 6.1 Application extension mutation

For `<resource>:update-extension`, Permission matching alone is insufficient.

When the target belongs to an ordinary Tenant, the Authorizer must establish that the applicable authorization originates from a TENANT-defined application Role belonging to that same Tenant. A SYSTEM-defined MTMF Role MUST NOT authorize that Tenant actor's extension mutation merely because one of its Permissions matches the Action.

Normal Tenant-boundary and scope/dominance evaluation then applies independently. This prevents application policy from a lesser-scoped or unrelated Tenant from modifying extension data outside its authorized Tenant context.

## 7. TenantManagementGroup Context

TenantManagementGroup elevation is contextual.

The ROOT TenantManagementGroup implicitly manages all Tenants and may provide contextual ROOT scope according to the security model.

SYSTEM TenantManagementGroups manage only explicitly associated Tenants and may provide contextual SYSTEM scope only for operations against those Tenants.

The management group's Role still constrains which Actions may be authorized. Management-group membership never means unrestricted administration.

Manager-side actor eligibility remains unresolved and MUST fail closed until specified.

## 8. Implementation Boundary

The permission-matching computation is separated from authorization-context retrieval.

The production (PR 8H) internal shape is:

```text
AuthorizationRequest
        |
        v
Authorizer
  |-- validate SessionContext
  |-- enforce target Tenant boundary
  v
AuthorizationPolicyResolver
        |
        v
EffectivePolicy
  |-- AuthorizationContext diagnostics
  |-- delegates evaluation
  v
CompiledPolicy                    # PURE PYTHON, production default
  |-- immutable exact index
  |-- immutable wildcard index
  v
evaluate(Action)
        |
        v
AuthorizationDecision
        |
        v
Authorizer
  |-- policy DENY remains final
  |-- unsupported constraints
  |-- strict dominance
  v
final AuthorizationDecision
```

The default path is:

```text
Authorizer()
 -> DefaultAuthorizationPolicyResolver
 -> EffectivePolicy(CompiledPolicy.compile(context.applicable_roles), context)
 -> CompiledPolicy.evaluate(action)
```

### 8.2 Production policy architecture (PR 8H)

- :class:`AuthorizationPolicy` is the production policy seam: an
already-resolved policy exposing exactly ``evaluate(action: Action) ->
AuthorizationDecision`` and ``get_diagnostics() -> str``. ``evaluate``
receives no Roles; the internal representation is hidden; diagnostics
never affect authorization; no persistence or context retrieval exists
on the policy surface.
- :class:`AuthorizationPolicyResolver` resolves an
:class:`AuthorizationPolicy` for a supplied :class:`AuthorizationContext`.
It does not authorize an Action and must not require an Action. The
initial implementation is the non-caching
:class:`DefaultAuthorizationPolicyResolver`, which compiles
``context.applicable_roles`` into the production pure-Python
:class:`CompiledPolicy` and wraps it in an :class:`EffectivePolicy`.
- :class:`CompiledPolicy` is the production pure-Python policy
implementation: immutable precomputed EXACT
``(namespace, resource, verb, qualifier)`` and WILDCARD
``(namespace, resource, verb)`` indexes of OR-aggregated
:class:`EffectAggregate` evidence. Compilation reuses the already-parsed
domain ``PermissionUrn``/``ActionUrn`` components (no URN
stringification/reparse), refuses ownership corruption with
:class:`PermissionEvaluationError`, and never sorts or uses ordering as
precedence. Evaluation is at most one EXACT lookup, then one WILDCARD
lookup, then ``DENY / NO_MATCH``; exact beats wildcard; equal-specificity
DENY wins; duplicates do not vote; the representation is structurally
immutable and never mutated by evaluation.
- :class:`EffectivePolicy(actual_policy, context)` is a diagnostics
wrapper only: it delegates ``evaluate`` directly and unchanged, adds no
authorization semantics, performs no retrieval, and exposes
context-aware diagnostics that combine safe high-level identity facts
(``(Tenant, Principal, Identity)``, applicable-Role count, nested policy
implementation) with the nested policy's own diagnostics. Diagnostics
are implementation-specific text: not parsed by the Authorizer, not
decision input, not a stable machine API, not cache identity, not
serialization, and not an audit record. PR 8H does not log diagnostics
automatically.
- :class:`Authorizer` remains the authoritative fail-closed orchestration
layer: it validates the structural session, enforces the target Tenant
boundary, then ``policy = resolver.resolve(context)`` and
``decision = policy.evaluate(request.action)``. A policy DENY returns
immediately; ALLOW proceeds only if unsupported constraints and strict
dominance checks pass. The resolver/compilation/policy exceptions
propagate and never become ALLOW. The policy is never resolved before
session/Tenant validation succeeds.
- The default policy implementation is the pure-Python indexed
:class:`CompiledPolicy`. The linear Python
:class:`PermissionEvaluator` remains the semantic reference/oracle and
is differentially tested against it. The Rust evaluator is
experimental and is not selected by the default :class:`Authorizer`.
- No caching exists yet: no repository, ``MtmfSpi``, UnitOfWork,
PostgreSQL, Redis, network, filesystem, global cache, local cache, or
policy fingerprinting. ``AuthorizationContext.applicable_roles``
remains trusted, pre-filtered caller input (Role-assignment/effective-
Role loading is PR 9 work). Future caching/decoration composes behind
the resolver contract (for example
``InMemoryCachingAuthorizationPolicyResolver(RedisCachingAuthorizationPolicyResolver(DefaultAuthorizationPolicyResolver()))``)
and is not implemented here.

Python remains authoritative for authorization-context retrieval and orchestration: session validation, Tenant isolation, context validation, scope/dominance, stewardship/delegation, operation-specific constraints, and fail-closed orchestration all stay in Python, and the `Authorizer` remains the authoritative decision orchestrator.

### 8.1 Rust permission-policy kernel

Since PR 8A, MTMF intentionally includes a Rust permission engine as a Rust/Python integration showcase and as a deterministic native policy kernel (see `ROADMAP_V01.md`, PR 8 series). This is an architecture decision; no profiling evidence claims a performance bottleneck, and performance characterization is useful but not the sole reason for Rust.

The integration mechanism is PyO3/maturin. The native module is the private `_mtmf_permission_engine`, reached only through the internal Python adapter `mtmf_core.authorization.rust_engine`; it is never exposed through `mtmf-api`, Connectors, HTTP, or any public contract.

Boundary rules:

- Rust evaluates policy only; Python determines policy applicability and authorization context.
- Historically (PR 8D-8G) the `Authorizer` depended on a narrow internal evaluator protocol (`PermissionEvaluatorProtocol`) with exactly one capability: decide one exact Action against already-applicable Role objects, and `RustPermissionEvaluator` was the active/default evaluator. Since PR 8H the `Authorizer` depends on the ``AuthorizationPolicyResolver`` / ``AuthorizationPolicy`` seam described in section 8.2, and the default policy is the pure-Python indexed `CompiledPolicy`. The retained linear evaluator protocol is no longer the Authorizer's primary seam.
- Two implementations satisfy that protocol: the Python `PermissionEvaluator`, which remains the semantic reference/oracle, and the `RustPermissionEvaluator`, which is experimental and non-default and never used by a normally constructed `Authorizer()`.
- Since PR 8D the Rust evaluator was the active/default backend for a period; PR 8H replaces that default with `DefaultAuthorizationPolicyResolver -> EffectivePolicy -> CompiledPolicy`. The Python reference implementation remains available for tests and reference/comparison work (historically as `Authorizer(evaluator=PermissionEvaluator())`; in the resolver era behind an explicit test-only policy adapter). There is NO automatic fallback: a native failure is never silently retried on Python.

Domain-to-primitive conversion (owned by the `RustPermissionEvaluator`):

- Role identity is deliberately flattened away: every owned PermissionSet of every supplied Role becomes one entry in the primitive input sequence, preserving nothing about which Role owned it.
- Role/PermissionSet ownership corruption (`permission_set.role_urn != role.urn`) fails closed with the same `PermissionEvaluationError` as the Python reference, before any native call.
- Effect and URN values are passed canonically from the existing domain value objects; no URN is reconstructed from components.

For each already-applicable Role policy, Rust receives exactly:

```text
ActionInput
    action_urn: str

PermissionSetInput
    effect: ALLOW | DENY
    permissions:
        PermissionInput
            permission_urn: str
```

- No live Python domain objects (`Action`, `Role`, `PermissionSet`, `Permission`) cross the FFI boundary, and no JSON serialization is introduced to carry policy across PyO3.
- Rust performs no retrieval and no I/O: no PostgreSQL, `MtmfSpi`, UnitOfWork, repositories, membership/session/assignment state, stewardship, delegation, IdP, network service, or filesystem-based policy discovery.

Failure semantics since PR 8D:

- A native infrastructure failure (module unavailable, missing/incapable native evaluator, malformed/incoherent native response, or an unexpectedly malformed primitive at the native parser) is NOT a policy DENY. It propagates from the evaluator through the `Authorizer` as a narrow `PermissionEvaluationInfrastructureError` and the protected operation fails closed because no ALLOW decision is produced.
- Native failures are never converted into `NO_MATCH`, `MATCHED_DENY`, or ALLOW, and there is no silent Python fallback: a fallback would let deployment errors silently alter the active authorization implementation and could conceal semantic divergence.

The Python `PermissionEvaluator` remains the semantic reference implementation throughout the Rust migration series. Systematic differential testing (a deterministic hand-authored parity matrix plus generated/property-based tests over valid SYSTEM policy, covering Role/PermissionSet/Permission order and duplicate invariance, plus bounded stress conformance up to 100 PermissionSets x 20 Permissions) proves the Rust evaluator and the Python reference produce equal complete decisions (`effect`, `allowed`, deny reason, matched specificity, `matched_allow`, `matched_deny`), never only `allowed`.

Implemented so far in the Rust series:

- PR 8A: only a deterministic smoke/capability API (`engine_version`) exists; no permission semantics are implemented in Rust, and no active authorization path imports the native module.
- PR 8B: a detached native policy model (`ActionInput`, `PermissionInput`, `PermissionSetInput`, `PermissionEffect` with exactly ALLOW/DENY) exists as the structural input contract for future evaluation; the SYSTEM-only Action/Permission URN parsers exist; exact and complete-qualifier wildcard (`*`) single-Permission matching exists; and match specificity exists with exactly two classes (`EXACT` is more specific than the qualifier wildcard, and nothing else is). A small private primitive matcher bridge (`_mtmf_permission_engine.match_permission`) exposes the match facts (`"exact"`, `"qualifier-wildcard"`, or `None` for a valid non-match) through the internal `rust_engine` adapter, and focused Python/Rust parity tests prove agreement with the Python matcher.
- PR 8C: the private native kernel now contains the first complete policy-decision algorithm (`evaluator.rs`). Given an exact Action and already-applicable detached PermissionSets, Rust matches every supplied Permission, retains the maximum matching specificity, discards lower-specificity matches *before* any effect resolution (so a wildcard DENY can never defeat an exact ALLOW), inherits each surviving match's effect from its containing PermissionSet, applies equal-specificity DENY precedence, and defaults to DENY when nothing matches. The result is a deterministic aggregate: an explicit ALLOW/DENY, the highest specificity, whether an ALLOW and/or DENY existed at that specificity, and a coarse deny reason (`no-match` vs `matched-deny`). Evaluation is independent of PermissionSet order, Permission order, and duplicates (no voting semantics). Malformed Action/Permission URNs and unknown effects fail the evaluation with `ValueError` at the native boundary; they are never converted into a policy DENY or NO_MATCH. A small private primitive evaluator bridge (`_mtmf_permission_engine.evaluate`) plus a validating Python adapter (`rust_engine.native_evaluate`) expose this through the internal seam only.
- PR 8D: the private kernel is integrated behind the internal `PermissionEvaluatorProtocol` seam and is the active/default policy engine of the `Authorizer`. `RustPermissionEvaluator` performs domain-to-primitive conversion (flattening Role-owned PermissionSets into detached primitive input with no Role identity), validates Role/PermissionSet ownership before any native call, maps validated native aggregate results onto the existing `AuthorizationDecision`/`MatchSpecificity`/`DenyReason` values, and normalizes native failures into the narrow fail-closed `PermissionEvaluationInfrastructureError` (never a semantic DENY, never ALLOW, no Python fallback). Systematic hand-authored and Hypothesis-generated differential tests, permutation/duplicate metamorphic properties, and structural-corruption parity tests prove equivalence with the Python reference.
- PR 8E: the Rust series is hardened, packaged, and characterized without adding authorization semantics. The boundary-hardening suite proves malformed Action/Permission URN text (empty, truncated, non-URN, unsupported namespace, wildcard Action, partial wildcard, missing/extra structure, unusually long malformed strings), unknown/empty/wrong-case PermissionSet effects, and wrong primitive types/container shapes all fail explicitly and can never become `NO_MATCH`, `MATCHED_DENY`, or ALLOW. The adapter normalizes native `TypeError` into the documented malformed-input `ValueError` contract, and the evaluator seam maps every native failure (unavailable module, missing capability, parser/type failure, malformed or incoherent response) into `PermissionEvaluationInfrastructureError`. The adapter rejects every impossible native aggregate state (ALLOW with a deny reason or `matched_deny`, ALLOW with no specificity, `NO_MATCH` carrying a specificity or match flags, `MATCHED_DENY` without specificity/`matched_deny`, unknown decision/specificity/deny reason, malformed result shapes). Bounded stress conformance (10x10, 50x20, 100x20 PermissionSets x Permissions) proves no crash, deterministic full-decision parity, order independence, and no duplicate-voting semantics with no timing assertions. Packaging is verified end-to-end: a real wheel is built from canonical configuration and installed/imported/used in an isolated clean Python 3.14 environment (`scripts/verify-rust-wheel.py`); the private module is never exported through `mtmf-api`. A reproducible benchmark harness (`benchmarks/`) measures the domain-facing evaluator seam with parity-before-timing, warmup/multiple samples/median/dispersion, and human+JSON output; performance is characterization only - no speed gate exists and results are machine-specific.

On the measured system, the current Rust evaluator did not outperform the Python reference implementation. Release builds approached parity for some larger policy scenarios but remained slower, while full-scan scenarios remained substantially slower. Profiling characteristics indicate that PyO3 conversion and repeated parsing of URNs already represented as parsed Python domain value objects are significant contributors. These results characterize the current boundary design and do not justify changing authorization semantics or PR 8E scope.

PR 8G (experimental; superseded by PR 8H): the ``dev/compiled-policy-perf`` branch tests a different hypothesis than PR 8F - compile already-applicable policy once into an immutable indexed native form, then evaluate repeated Actions without resending, reparsing, sorting, or scanning policy. It branches directly from the PR 8E baseline and has no msgspec/PR 8F dependency. ``_mtmf_permission_engine.compile_policy`` (private seam, reached only by experimental ``benchmarks/compiled_policy_evaluator.py``) parses every Permission URN once, classifies it EXACT or QUALIFIER_WILDCARD, OR-aggregates effects (`EffectAggregate` with `matched_allow`/`matched_deny`; duplicates are non-voting) into exact `(namespace, resource, verb, qualifier)` and wildcard `(namespace, resource, verb)` standard `HashMap` indexes, and returns a frozen opaque object whose ``evaluate`` parses only the single Action and performs at most two lookups. Exact beats wildcard, equal-specificity DENY wins, no match means DENY/NO_MATCH, and malformed compile input fails explicitly and never produces a usable policy. Native scan-vs-compiled parity is proven inside the crate (authored matrix plus 2000 deterministic generated policies), and the Python suite proves P == R == PC == RC complete-decision parity over the full evidence, where PC is a pure-Python CompiledPolicy control (same compiled/indexed algorithm, no FFI) added by the PR 8G amendment to separate the compilation benefit from the Rust benefit. The compile/evaluate/lifecycle benchmark preserves the PR 8E scenarios unchanged, adds 1/25/200/1000/5000-permission scales with multi-Action workloads (exact hits, wildcard-only hits, wildcard DENY, no-match), measures the one-time compile cost, repeated compiled evaluation, and compile + 1/10/100/1000 lifecycle cost separately, and characterizes unrelated-policy scaling at 25/200/1000/5000 for exact/wildcard/no-match outcomes to detect any hidden scan. Ratios and break-even are reported with explicit direction; no timing correctness gate exists. PR 8H productionizes the durable takeaway (compile/index before repeated evaluation) as the pure-Python `CompiledPolicy` default (section 8.2); the Rust compiled path remains experimental, with no backend/env-var selection, fallback, or cache/invalidation architecture.

On the measured system (WSL2 x86_64, Python 3.14.7, optimized release native build, engine 0.1.0), the compiled-policy hypothesis was confirmed for repeated evaluation: compiled evaluation is sub-linear in unrelated policy size (25->5000 unrelated Permissions grew median compiled evaluation only ~4.1-4.4x while policy grew 200x; a hidden full-policy scan would have scaled linearly), and the release campaign showed compiled evaluation beating both baselines for every non-trivial policy while compile cost amortizes after roughly 1-7 evaluations in this environment. Representative release medians: ``large`` (1000 Permissions): Python 475.7us, current Rust 574.3us, compile 571.1us, then compiled evaluation 5.4us per evaluation (88x vs Python, 106x vs current Rust); ``scale_5000`` (5000 Permissions, 5-Action workload pass): compiled evaluation 33.1us vs Python 2.96ms and current Rust 12.3ms (89x/372x), with a one-time compile of 3.98ms. After compilation the remaining per-Action cost is dominated by Action-URN parsing plus the PyO3 call/wrapper overhead (native-only evaluation of an empty policy, parse + two empty-map lookups + PyO3, was ~1.0us; the Python wrapper adds ~2us per workload pass), so further native gains would require addressing Action transport/parsing rather than policy matching. These results characterize the experiment; the durable takeaway (compiling/indexing before repeated evaluation) is what PR 8H productionizes in pure Python (section 8.2). Effective-policy lifecycle, cache identity, RoleAssignment/group-membership dependencies, invalidation, stale-ALLOW prevention, concurrency, and observability remain unsolved and are not addressed by 8G or 8H.

PR 8G amendment (Python CompiledPolicy control): to answer "is the improvement compilation or Rust?", a pure-Python compiled-policy control (PC) was added mirroring the exact/wildcard indexed semantics of RC and measured together with P, R, and RC in one four-way release campaign (P == R == PC == RC complete-decision parity before every timed run; same WSL2 x86_64 / Python 3.14.7 / release native build environment). PC mirrors RC: exact `(namespace, resource, verb, qualifier)` and wildcard `(namespace, resource, verb)` keys, frozen `EffectAggregate(matched_allow, matched_deny)`, duplicate collapse, EXACT-beats-WILDCARD, equal-specificity DENY, default DENY, structural ownership validation, and an immutable representation; PC consumes the already-parsed domain `PermissionUrn`/`ActionUrn` components directly and never crosses FFI. Findings of the four-way campaign: (1) both compiled implementations dominate their linear baselines (P/PC up to ~169x and R/RC up to ~318x at 5000 Permissions), so compiling/indexing policy is the principal optimization, independent of language; (2) PC evaluation beat RC evaluation in every scenario (PC/RC median ratio ~0.18x no_roles to ~0.50x at 5000 unrelated Permissions - PC ~2-5.5x faster per single-Action call) and PC compiled faster than RC at every scale; (3) RC's raw native lookup is fast (native-only empty-policy evaluation ~1.35us), but the per-Action PyO3 crossing, Action-URN transfer/parse, and the Python-side native-result validation/mapping flip the full path, which is evidence that the Python<->Rust boundary dominates single-Action compiled evaluation on this machine; (4) PC and RC evaluation both stay approximately independent of unrelated policy size at 25/200/1000/5000 (sub-linear 1.9-4.2x growth for a 200x policy; no hidden scan). PR 8H adopts the proven pure-Python PC semantics as the production `CompiledPolicy` (section 8.2): PC is no longer experimental benchmark-only code, the benchmark harness imports the production implementation, and no runtime selection, fallback, cache, or invalidation exists. A batched-Action FFI hypothesis remains only a possible future experiment, not implemented.

Rust still does NOT determine applicable policy, consume Roles, retrieve session/Tenant/membership/assignment context, or perform authorization-context orchestration; Python owns applicability and context, and the `Authorizer` remains the authoritative orchestrator. The native module is never imported on the default path: importing `mtmf_core` or constructing an `Authorizer` never loads `_mtmf_permission_engine` (the default policy is pure-Python `CompiledPolicy`), the Python reference evaluator never imports it, and it is loaded lazily only when a Rust-backed experiment is actually invoked.

Not implemented: no Role identity, Tenant, session, assignment, stewardship, or any other authorization context reaches Rust; no persistence/I/O enters the evaluator; only detached primitive policy crosses the FFI boundary. Manifestly invalid URN text raises `ValueError` at the native boundary; a valid non-match is a `None`/`NO_MATCH` fact, so malformed input can never silently become a valid non-match or any authorization decision.

Caching/indexing of effective authorization state may prove more important than the matching algorithm itself and will be designed only after realistic profiling.

## 9. Decision and Auditability

The internal authorization result should contain enough information to support testing, audit, diagnostics, and observability rather than exposing only an unexplained Boolean.

The exact decision type and disclosure policy remain to be specified. External error responses MUST NOT reveal security-sensitive information merely because richer reasoning exists internally.

## 10. Open Design Items

The following remain intentionally unresolved:

- the public/application-facing authorization contract and context representation (the internal `PermissionEvaluatorProtocol` evaluator seam established by PR 8D is settled and is not the open item);
- exact authorization-context representation;
- manager-side actor eligibility for TenantManagementGroups;
- complete Action catalog and built-in Role policy compositions;
- built-in Role-to-PermissionSet/Permission mappings;
- exact audit decision record;
- caching, invalidation, and compiled permission-index design.
