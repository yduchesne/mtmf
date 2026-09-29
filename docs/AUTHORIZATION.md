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

The permission-matching computation SHOULD remain separable from authorization-context retrieval.

A likely internal shape is:

```text
Authorizer
  +-- load/validate authorization context
  +-- PermissionEvaluator (PermissionSet/Permission matching)
  +-- apply scope/delegation/stewardship/operation constraints
  +-- produce decision
```

Python remains authoritative for authorization-context retrieval and orchestration: session validation, Tenant isolation, context validation, scope/dominance, stewardship/delegation, operation-specific constraints, and fail-closed orchestration all stay in Python, and the `Authorizer` remains the authoritative decision orchestrator.

### 8.1 Rust permission-policy kernel

Since PR 8A, MTMF intentionally includes a Rust permission engine as a Rust/Python integration showcase and as a deterministic native policy kernel (see `ROADMAP_V01.md`, PR 8 series). This is an architecture decision; no profiling evidence claims a performance bottleneck, and performance characterization is useful but not the sole reason for Rust.

The integration mechanism is PyO3/maturin. The native module is the private `_mtmf_permission_engine`, reached only through the internal Python adapter `mtmf_core.authorization.rust_engine`; it is never exposed through `mtmf-api`, Connectors, HTTP, or any public contract.

Boundary rules:

- Rust evaluates policy only; Python determines policy applicability and authorization context.
- The `Authorizer` depends on a narrow internal evaluator protocol (`PermissionEvaluatorProtocol`) with exactly one capability: decide one exact Action against already-applicable Role objects.
- Two implementations satisfy that protocol: the Python `PermissionEvaluator`, which remains the semantic reference/oracle, and the `RustPermissionEvaluator`, which is the active/default evaluator used by a normally constructed `Authorizer()`.
- Since PR 8D, the Rust-backed evaluator is the active/default policy engine behind the `Authorizer`, and the Python reference implementation remains explicitly injectable (`Authorizer(evaluator=PermissionEvaluator())`) for tests and reference/comparison work. There is NO automatic fallback: a native failure is never silently retried on Python.

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

### 8.1.1 PR 8F experimental msgspec semantic-buffer boundary (benchmark-only)

PR 8F runs a deliberately isolated performance experiment: an alternative FFI representation for the Rust path, kept entirely out of production authorization. It tests one narrow question - can a compact msgspec/MessagePack semantic buffer materially reduce the Python-to-Rust transfer and redundant URN-parsing costs identified by PR 8E? - WITHOUT changing any authorization behavior.

The experimental boundary (benchmark-only, `benchmarks/`):

- `benchmarks/msgspec_wire.py` defines a private, versioned (v1), positional (`array_like=True`) MessagePack schema carrying only *already-parsed semantic components* (definition namespace, resource, verb, qualifier, and an explicit complete-qualifier wildcard flag) extracted from the existing validated domain value objects. No complete MTMF Action/Permission URN text and no numeric registries cross the payload.
- `_mtmf_permission_engine.evaluate_semantic_msgpack` is a private, clearly experimental single-buffer PyO3 entry point that MessagePack-decodes the payload with `serde`/`rmp-serde`, validates the components against exactly the states the canonical SYSTEM grammar accepts (explicit version check, supported namespace, non-empty resource/verb, exact Action, valid Permission wildcard state, exact ALLOW/DENY effect), and converges onto the SAME canonical decision loop as the production URN path (`evaluator.rs`). There is no second authorization algorithm, no fast-path semantics, and no project-authored `unsafe`.
- `benchmarks/msgspec_evaluator.py` is the experimental adapter (M1: ordinary `encode`; M2: `encode_into` a reused buffer); it reuses the production result-validation and evidence-mapping helpers and preserves Role/PermissionSet ownership validation.

Everything below is unchanged by PR 8F:

- The production `Authorizer` and `RustPermissionEvaluator` are untouched; `Authorizer()` still evaluates through `RustPermissionEvaluator` and the existing primitive `native_evaluate` boundary.
- No runtime backend selection, no fallback, no caching, and no compiled-policy handle exist. Every experimental end-to-end evaluation transfers the full policy payload; pre-encoded benchmark payloads are component fixtures, not runtime state.
- `msgspec` is a development/experimental dependency only and is never a runtime dependency of `mtmf-core`/`mtmf-api`/`mtmf-client`/`mtmf-service`.
- Malformed wire data (empty/truncated payloads, random bytes, wrong top-level type, missing fields, unsupported versions, unknown effects, invalid wildcard states, invalid component types, bounded excessive nesting) fails explicitly and is never ALLOW, NO_MATCH, or MATCHED_DENY.

PR 8F findings (measured machine, Python 3.14.7 x86-64, msgspec 0.22.0; medians rounded; ratios are `baseline_median / candidate_median`, so `> 1.0` means the candidate was faster; full JSON in `benchmarks/results/`):

- **Release native build; end-to-end msgspec did NOT improve over the current Rust boundary.** P/R/M1/M2 medians for a 1000-Permission policy: P 535 vs R 727 vs M1 995 vs M2 994 microseconds. M1 is never faster than Python (M1/P 0.15-0.54 across scenarios) and is faster than the current Rust boundary only for fixed-overhead/tiny scenarios (M1/R 1.03-1.16 for `no_roles`/`tiny_*`; 0.59-0.80 elsewhere, worsening as policy grows).
- **No crossover as policy grows**: the M1/R and M1/P gaps widen with Permission count (M1/R 0.73 at 1000 perms, 0.63 at 5000 perms on the extended run).
- **Component costs (release, 1000 perms):** domain-to-wire DTO construction 328 us (the single largest Python-side cost, more expensive than the current Rust evaluator's primitive conversion), ordinary encode 57 us, `encode_into` 56 us, pre-encoded native decode/evaluate 494 us. End-to-end M1 approximates C1+C2+C4 + adapter overhead, confirming per-call conversion/encoding/transfer dominates.
- **`encode_into` (M2) does not materially help** (M2 is within ~1-3% of M1 across scenarios; at 5000 perms M2/P 0.43 vs M1/P 0.44).
- **Full scans remain the worst relative case**: 1000-Permission no-match M1/P 0.17 and M1/R 0.72 (release), and 5000-Permission no-match M1/P 0.16 / M1/R 0.64; full policy is still transferred and scanned every call.
- **Eliminating URN reparsing did not change scaling materially**: the pre-encoded native component alone costs 494 us (1000 perms) - on par with the whole Python reference (535 us) - so decode/validation plus evaluation, not URN parsing, absorbs most native time.
- **Repeated policy transfer remains the dominant cost.** The evidence does not support msgspec as a material improvement; it supports retaining the current architecture. A separate CompiledPolicy experiment (compile-once, evaluate-many) is a plausible separate experiment but PR 8F does not implement or endorse it.
- **Debug vs release**: debug-build R/M1 medians at 1000 perms were 2.59/3.25 ms vs release 0.73/0.99 ms; debug conclusions (native slower by ~-3.5x) are not the headline. Release measurements are the basis for the conclusions above, as required by the methodology.

PR 8F is complete: the experiment is correct (four-way parity P == R == M1 == M2 on every scenario before timing), reproducible (`benchmarks/results/` + README procedure), fail-closed (malformed wire is never a decision), and honestly documented. A negative result (msgspec is slower) is still a valid outcome; no speed gate or adoption decision is implied.

Rust still does NOT determine applicable policy, consume Roles, retrieve session/Tenant/membership/assignment context, or perform authorization-context orchestration; Python owns applicability and context, and the `Authorizer` remains the authoritative orchestrator. The native module is never imported eagerly: importing `mtmf_core` or constructing an `Authorizer` loads `_mtmf_permission_engine` only when Rust evaluation is actually invoked, and the Python reference evaluator never imports it.

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
