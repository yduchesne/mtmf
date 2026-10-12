# PR 16 — Baseline reconciliation (Part A)

Recorded: 2026-10-12. Author: coding agent (PR 16). Status: **reconciled; prerequisite gate PASSED**.

This document is the mandatory Part A inventory for
`PR16_DETAILED_EXECUTION_PLAN.md`
(the plan lives outside the repository; this is the repository-resident
record). It captures the exact base, prerequisite confirmation, existing
surface, and baseline gate results **before** any PR 16 change. Baseline
results are prerequisite evidence only and are not PR 16 acceptance
evidence.

## A1 — Prerequisite confirmation (STOP gate)

- Plan requirement: PR 15 must be merged to `main` (or an approved
  alternative base) before branching; do not cherry-pick.
- `git fetch origin` performed.
- PR 15 was reported finalized at
  `0bca7b05b90b45607cb5557100885a79449bd67b`. That exact commit is
  **present on `origin/main`** as an ancestor of the PR 15 merge commit
  `540c20b0c4253744cf68c5af0e4cad0b18847c3e`
  (`Merge pull request #46 from yduchesne/dev/api-contract`).
- Base/start-of-work commit: **`540c20b0c4253744cf68c5af0e4cad0b18847c3e`**.
- Working branch: `dev/native-batch-auth` (already checked out; worktree
  clean at reconciliation).
- **Result: prerequisite gate PASSED.** No cherry-pick, no alternate
  base, no STOP required.

## A2 — Existing surface inventory (current main)

### Python authorization package (`packages/mtmf-core/src/mtmf_core/authorization/`)

| Module | Role / notable signatures |
|---|---|
| `authorizer.py` | `Authorizer.__init__(policy_resolver: AuthorizationPolicyResolver | None = None)`; `authorize(request: AuthorizationRequest) -> AuthorizationDecision`. Order: session validation → target/management check → `resolver.resolve(context)` → `policy.evaluate(action)` → unsupported constraint → strict dominance. Module-private `_management_scope_is_valid(request)` was the only guard helper. |
| `context.py` | `AuthorizationContext(session, tenant, principal, identity, principal_tenant_memberships, identity_tenant_memberships, applicable_roles)`; `AuthorizationRequest(context, action, target_tenant_id, dominance_requirement=NONE, subject_scope=None, target_scope=None, unsupported_constraints=(), management_scope=None)`; `DominanceRequirement{NONE,STRICT}`; `UnsupportedConstraint{ALTERNATE_DOMINANCE,EXTENSION_MUTATION_PROVENANCE}`. All frozen+slots. |
| `decision.py` | `AuthorizationEffect{ALLOW,DENY}`; `DenyReason{NO_MATCH,MATCHED_DENY,INVALID_CONTEXT,TENANT_MISMATCH,NO_MANAGEMENT_SCOPE,INSUFFICIENT_DOMINANCE,UNSUPPORTED_CONSTRAINT}`; frozen `AuthorizationDecision(effect, matched_specificity=None, matched_allow=False, matched_deny=False, reason=None)` with `allow()`/`deny()` constructors. |
| `compiled_policy.py` | Production pure-Python `CompiledPolicy.compile(roles: Iterable[Role])`; `evaluate(action) -> AuthorizationDecision`; EXACT `(namespace,resource,verb,qualifier)` and WILDCARD `(namespace,resource,verb)` `MappingProxyType` indexes of `EffectAggregate`; `get_diagnostics()`. Ownership corruption → `PermissionEvaluationError`. |
| `policy_resolver.py` | `AuthorizationPolicyResolver` protocol; `DefaultAuthorizationPolicyResolver.resolve(context) -> AuthorizationPolicy` = `EffectivePolicy(CompiledPolicy.compile(context.applicable_roles), context)`. No I/O/cache. |
| `policy.py` | `AuthorizationPolicy` protocol (`evaluate(action)`, `get_diagnostics()`); `EffectivePolicy(policy, context)` diagnostics delegation wrapper. |
| `permission_evaluator.py` | Linear Python oracle `PermissionEvaluator.evaluate(action, roles)`; `PermissionEvaluationError` for ownership corruption. |
| `evaluator.py` | `PermissionEvaluatorProtocol` (legacy linear seam; no longer the Authorizer primary seam). |
| `rust_engine.py` | Private native adapter. Existing capabilities: `engine_version()`, `native_match_permission_urn(action_urn, permission_urn)`, `native_evaluate(action_urn, permission_sets)`, `native_compile_policy(permission_sets) -> opaque object with evaluate`. Exceptions `RustEngineUnavailableError`, `RustEngineCapabilityError`; `RustEvaluation`; `_validate_native_evaluation`. Module name `_mtmf_permission_engine`, lazily imported. |
| `rust_permission_evaluator.py` | Experimental linear Rust evaluator; `PermissionEvaluationInfrastructureError`; `_map_native_evaluation`. |
| `management.py` | `ManagementScopeCandidate`, `ManagementScopeResolution`, `is_extension_action`. |
| `dominance.py` | `strictly_dominates(subject, target)`. |
| `__init__.py` | Exports the above; `mtmf_core/__init__.py` re-exports the public authorization names. |

### Rust crate (`packages/mtmf-permission-engine/`, crate `mtmf-permission-engine`)

- `src/lib.rs`: PyO3 `_mtmf_permission_engine` module; `engine_version`, `match_permission`, `evaluate`, `compile_policy`; `NativeCompiledPolicy` (`frozen`, one `evaluate(action_urn)`).
- `src/model.rs`: detached `ActionInput`, `PermissionInput`, `PermissionEffect{Allow,Deny}`, `PermissionSetInput`.
- `src/urn.rs`: SYSTEM-only Action/Permission URN parsers; `ParsedActionUrn`, `ParsedPermissionUrn`; `UrnParseError`.
- `src/matcher.rs`: exact/wildcard match + `MatchSpecificity`.
- `src/evaluator.rs`: linear scan evaluator `evaluate(&ActionInput, &[PermissionSetInput])`, `EvaluationResult`, `EvaluationDecision`, `DenyReason`.
- `src/compiled_policy.rs`: PR 8G experimental indexed `CompiledPolicy::compile`, `evaluate(&str)`; `ExactKey`, `WildcardKey`, `EffectAggregate`, `CompiledPolicyError`.
- Packaging: `pyproject.toml` (maturin, module `_mtmf_permission_engine`), root `Cargo.toml` workspace.

### Benchmarks and verification scripts

- `benchmarks/permission_evaluator_benchmark.py` (PR 8E P/R paths; `_build_scenarios`).
- `benchmarks/compiled_policy_benchmark.py` (PR 8G/8H P/R/PC/RC; `Scenario`, `_build_scale_roles`, `_build_diagnostic_roles`, `_policy_counts`, `_MULTI_ACTION_WORKLOAD`, `_full_decision_equality`).
- `benchmarks/compiled_policy_evaluator.py` (experimental native compiled adapter `CompiledPolicyEvaluator`).
- `scripts/verify-rust-wheel.py` (clean wheel build/install/use probe; required callables `engine_version`, `match_permission`, `evaluate`, `compile_policy`).
- `build.sh` gates: `--qa`, `--sec`, `--rust`, `--integration`.

### Test factories reused by PR 16

- `tests/unit/core/helpers.py`: `make_tenant`, `make_principal`, `make_identity`, `make_action_urn`, `make_permission`, `make_permission_set`, `make_role`, `make_role_urn`, `make_id`.
- `tests/unit/authorization/authz_helpers.py`: `make_action`, `make_permission_set_with_rules`, `make_role_from_sets`, `corrupt_role`, `build_authorization_request`.
- `tests/unit/conftest.py` registers `tests/unit/core` and `benchmarks/` on `sys.path`.
- Existing native suites: `test_rust_engine.py`, `test_rust_matcher.py`, `test_rust_evaluator.py`, `test_rust_permission_evaluator.py`, `test_permission_evaluator_differential.py`, `test_rust_boundary_hardening.py`, `test_authorizer_rust.py`, `test_compiled_policy_evaluator.py`, `test_compiled_policy_differential.py`, `test_python_compiled_policy.py`.

### Environment

- Python 3.14.7; native `_mtmf_permission_engine` installed (engine `0.1.0`).
- PostgreSQL 18 in MTMF Podman project `mtmf` (container `mtmf_postgres_1`); host port `25432` (MTMF `2` prefix).
- Integration role-scoped configuration loaded from `.env`
  (`MTMF_POSTGRES_*`, `MTMF_MIGRATOR_*`, `MTMF_RUNTIME_*`).

## A3 — Baseline gate results (pre-PR16 tree at `540c20b`)

| Gate | Command | Result | Notes |
|---|---|---|---|
| Quality | `./build.sh --qa` | **PASS** | unit suite **1600 passed**; coverage **89.17%** (gate 85%). |
| Security | `./build.sh --sec` | **PASS** | Bandit + Semgrep; 0 findings. |
| Native | `./build.sh --rust` | **PASS** | cargo fmt/clippy/test (baseline 118 Rust tests), `maturin develop`, capability probe, focused native tests, isolated wheel verification, P/R/PC/RC benchmark smoke. |
| Integration | `./build.sh --integration` (with role-scoped env) | **PASS** | **556 passed, 22 skipped** in ~297s. The 22 skips are the PR 14 Keycloak live-environment tests, recorded as skips (not PASS); no Keycloak service was exercised. |

## A4 — Classification

| Item | Classification |
|---|---|
| PR 15 merged prerequisite | **DONE + VERIFIED** (`0bca7b0…` on `origin/main`). |
| Baseline QA / security / native / integration | **DONE + VERIFIED** (results above, pre-change). |
| PR 16 batch seam (Python + Rust + parity + bench + docs) | **NOT STARTED** at baseline; implemented after this reconciliation. |
| PR 17 authenticated HTTP endpoint | **NOT STARTED** (out of PR 16 scope). |
| PR 18 scoped client snapshots | **NOT STARTED** (out of PR 16 scope). |

No blocker prevented the start of PR 16. The single-Action `Authorizer`
and the Python `CompiledPolicy` default were unchanged at baseline and
remain the production default.

## A5 — Guard-extraction risk note

The plan permits extracting the Authorizer pre/post guards only if
single-Action behavior is unchanged. Baseline confirms the exact guard
order (session → target/management → resolve/evaluate → unsupported
constraint → strict dominance). The extraction is recorded and validated
in the acceptance report; the existing Authorizer suites were re-run
immediately after extraction.
