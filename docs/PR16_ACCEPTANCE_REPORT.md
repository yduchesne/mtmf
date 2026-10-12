# PR 16 — Acceptance report: native batch authorization and Python/Rust parity

Status: **implemented; mandatory gates PASS on the final tree.**
Base commit: `540c20b0c4253744cf68c5af0e4cad0b18847c3e` (PR 15 merged).
Branch: `dev/native-batch-auth`. PR 17 (authenticated HTTP) and PR 18
(scoped client snapshots) remain out of scope and unimplemented.

This report records the exact commands, results, environment, and
complete-decision evidence for PR 16. It is grounded in
[PR16_BASELINE_RECONCILIATION.md](PR16_BASELINE_RECONCILIATION.md),
[SECURITY_MODEL.md](SECURITY_MODEL.md), and
[AUTHORIZATION.md §8.4](AUTHORIZATION.md).

## 1. Delivered surface

### Python (`packages/mtmf-core/src/mtmf_core/authorization/`)

- `guards.py` — extracted, behaviour-preserving Authorizer pre/post
  guards (`validate_request_session`, `target_is_permitted`,
  `apply_post_policy_guards`, `management_scope_is_valid`). The single
  `Authorizer` now uses them; its ordering and security semantics are
  unchanged (existing Authorizer/management/effective-Role/Rust-cutover
  suites pass unchanged).
- `batch.py` — frozen internal contract:
  - `InvalidAuthorizationBatchError(ValueError)`;
  - `AuthorizationBatch(requests: tuple[AuthorizationRequest, ...])`
    validated at construction: 1–100, immutable tuple, genuine requests,
    **one shared `AuthorizationContext` object identity**;
  - `AuthorizationBatchResult(decisions: tuple[AuthorizationDecision, ...])`;
  - `BatchAuthorizer` (pure-Python default): shared session validated
    once, per-item target/management precheck in original position,
    policy resolved **at most once** (zero times when all items are
    pre-denied), surviving ordered Actions evaluated against that one
    policy, then the same post-policy guards; failures propagate and
    fail the whole batch with no partial result;
  - `RustBatchAuthorizer` (explicit, non-default): ownership-validates
    and flattens `context.applicable_roles`, then evaluates the whole
    surviving batch in **one** PyO3 crossing; no resolver injection (the
    native path determines no applicable policy).
- `rust_engine.py` — new private adapter `native_batch_evaluate(
  permission_sets, action_urns)`: lazy native import, 1–100 bound,
  complete-response validation (container type, exact length, per-element
  decision/specificity/flags/deny-reason/coherence) before returning
  anything; malformed input/capability failures map to the existing
  narrow `ValueError`/`RustEngineUnavailableError`/
  `RustEngineCapabilityError`, never a policy decision and never a
  fallback.
- `rust_permission_evaluator.py` — canonical
  `flatten_roles_to_primitive_sets(roles)` helper shared by the linear
  Rust evaluator, `RustBatchAuthorizer`, and the benchmark adapter.
- `mtmf_core` / `mtmf_core.authorization` re-export the batch contract.

### Rust (`packages/mtmf-permission-engine/`)

- `compiled_policy.rs` — `CompiledPolicy::evaluate_batch(&[String])`
  (all-or-nothing parsing, one `Vec<EvaluationResult>` in input order)
  and a private `evaluate_parsed` core shared with `evaluate`. Reuses the
  exact existing EXACT/WILDCARD indexed lookups; no second engine and no
  scan.
- `lib.rs` — `NativeCompiledPolicy.evaluate_batch(action_urns)` and the
  single-crossing PyO3 `batch_evaluate(permission_sets, action_urns)`
  (1–100 bound, compiles once, transfers all Actions once, returns all
  results once). Unknown effect / malformed URN / out-of-range size →
  `ValueError` and no partial result.

### Tests, benchmark, verification

- `tests/unit/authorization/test_batch_authorizer.py` (35 tests; Python
  default path, matrix B01–B27/B29–B33/B37 for the Python path).
- `tests/unit/authorization/test_rust_batch_authorizer.py` (11 tests;
  native-wheel parity, crossing counts, malformed native input).
- `tests/unit/authorization/test_rust_batch_adapter.py` (11 tests;
  negative boundary validation, no native required).
- `tests/unit/authorization/authz_helpers.py` gained
  `make_authorization_context` and `build_request_from_context` (shared
  context identity).
- `benchmarks/batch_authorization_benchmark.py` — three-path (PI/PB/RB)
  lifecycle benchmark; parity before timing; batch sizes 1/10/25/100;
  policy sizes 25/200/1000/5000; warmup + samples; median + IQR;
  human + JSON; no speed threshold.
- `scripts/verify-rust-wheel.py` now proves the `batch_evaluate` and
  `NativeCompiledPolicy.evaluate_batch` capabilities in the isolated
  clean wheel.
- `build.sh --rust` runs the new native batch tests and the batch
  benchmark smoke.

## 2. Deterministic acceptance matrix

All items PASS on the final tree. Native-positive items B28/B31/B32/B36
use the real installed `_mtmf_permission_engine` wheel; mocks appear
only in negative boundary tests (B25/B26/B34 adapter-level).

| ID | Scenario | Evidence | Result |
|---|---|---|---|
| B01 | Batch one parity | `test_b01_batch_of_one_matches_single_authorizer` | PASS |
| B02 | Batch 100 ordered | `test_b02_batch_of_one_hundred_returns_exactly_one_hundred_ordered` | PASS |
| B03 | Batch 0/101/invalid rejected before calls | `test_b03_*` (4 tests) | PASS |
| B04 | Duplicate Action occurrences | `test_b04_duplicate_action_occurrences_are_independent_and_ordered` | PASS |
| B05 | Distinct context instances rejected | `test_b05_distinct_but_equal_context_instances_are_rejected` | PASS |
| B06 | Shared session once / policy once | `test_b06_shared_session_checked_once_and_policy_resolved_once` | PASS |
| B07 | Invalid session all DENY/INVALID_CONTEXT, zero resolver | `test_b07_invalid_session_denies_all_without_resolver` | PASS |
| B08 | All cross-Tenant DENY/NO_MANAGEMENT_SCOPE, zero resolver | `test_b08_all_cross_tenant_denied_without_resolver` | PASS |
| B09 | Mixed valid/invalid targets | `test_b09_mixed_valid_and_invalid_targets_keep_positions` | PASS |
| B10 | Eligible management parity (Python + native) | `test_b10_eligible_management_parity_with_single_authorizer`, `test_b10_native_eligible_management_parity` | PASS |
| B11 | Ineligible management DENY | `test_b11_ineligible_management_is_denied` | PASS |
| B12 | Cross-Tenant extension mutation DENY | `test_b12_cross_tenant_extension_mutation_is_denied` | PASS |
| B13 | Exact ALLOW vs wildcard DENY | `test_b13_b17_policy_case_parity[...]` | PASS |
| B14 | Exact DENY vs wildcard ALLOW | same parametrization | PASS |
| B15 | Equal-specificity ALLOW+DENY | `test_b15_equal_specificity_conflict_flags_both_true` | PASS |
| B16 | Wildcard-only ALLOW | parametrization | PASS |
| B17 | No matching Permission | parametrization | PASS |
| B18 | Duplicates and permutations | `test_b18_duplicates_and_permutations_do_not_change_decisions` | PASS |
| B19 | Unsupported constraint after ALLOW | `test_b19_unsupported_constraint_after_policy_allow_denies` | PASS |
| B20 | Missing/equal/insufficient dominance | `test_b20_missing_equal_or_insufficient_dominance_denies` | PASS |
| B21 | Sufficient strict dominance | `test_b21_sufficient_strict_dominance_retains_allow` | PASS |
| B22 | Policy DENY plus post-constraints | `test_b22_policy_deny_survives_post_constraints` | PASS |
| B23 | Corrupt PermissionSet ownership | `test_b23_*`, `test_corrupt_ownership_fails_before_native_call` | PASS |
| B24 | Resolver exception after pre-deny | `test_b24_resolver_exception_fails_whole_batch_without_partial_result` | PASS |
| B25 | Native unavailable, no fallback | `test_b25_native_unavailable_fails_closed_without_fallback` | PASS |
| B26 | Wrong native count/type/effect/reason/flags | `test_rust_batch_adapter.py` (length/container/decision/incoherent/flags) | PASS |
| B27 | Malformed native middle Action | `test_b27_malformed_middle_action_fails_whole_native_call` | PASS |
| B28 | 100 eligible Actions → one real PyO3 batch call | `test_b28_one_hundred_eligible_actions_cross_native_boundary_once` (real installed module instrumented) | PASS |
| B29 | All pre-denied → zero native calls | `test_b29_all_pre_denied_crosses_native_boundary_zero_times` | PASS |
| B30 | Default import/construct never loads native | `test_b30_default_authorizer_import_never_loads_native_module` (subprocess) | PASS |
| B31 | Linear Python vs indexed Python/Rust policy parity | `test_b31_policy_only_parity_across_python_and_native` | PASS |
| B32 | Single Authorizer vs both batches full parity | `test_b32_single_authorizer_and_both_batches_full_parity` | PASS |
| B33 | Sequential actors/Tenants, no leakage | `test_b33_sequential_batches_do_not_leak_authority` | PASS |
| B34 | Malformed native effects/URNs are errors | `test_b34_malformed_native_effects_and_urns_are_errors` | PASS |
| B35 | Full benchmark matrix + parity before timing | `benchmarks/batch_authorization_benchmark.py` (parity aborts on mismatch) | PASS |
| B36 | Isolated wheel exposes new capability | `scripts/verify-rust-wheel.py` (`installed wheel OK`) | PASS |
| B37 | Existing single-action tests unchanged | full QA suite (previous suites unchanged) | PASS |
| B38 | Public DTO/HTTP/SQL unchanged | `git diff` protected-file check | PASS |

## 3. Mandatory final-tree gates

| Gate | Command | Result | Evidence |
|---|---|---|---|
| Diff hygiene | `git diff --check` | **PASS** | clean (no whitespace errors). |
| Native | `./build.sh --rust` | **PASS** | cargo fmt/clippy clean; **118 Rust tests passed**; `maturin develop`; capability probe; **392 focused Python native tests passed**; isolated clean-wheel build/install/use (`installed wheel OK`); 3 benchmark smokes validated (P/R, compiled, batch). |
| Quality | `./build.sh --qa` | **PASS** | Ruff format+lint clean; strict Mypy clean (`packages`); **1657 unit tests passed**; coverage **89.39%** (gate ≥85%). |
| Security | `./build.sh --sec` | **PASS** | Bandit + Semgrep; 0 findings. |
| Integration | `./build.sh --integration` (role-scoped `MTMF_*`) | **PASS** | PostgreSQL 18 / restricted runtime: **556 passed, 22 skipped**. Skips = the PR 14 Keycloak live-environment tests (recorded as skips, not PASS; no Keycloak service exercised). |
| Pre-commit | `uv run --no-sync pre-commit run --all-files` | **PASS** | All hooks passed; its Rust/QA/Sec hooks re-ran the canonical gates on the same tree. |
| Release benchmark | release wheel + `benchmarks/batch_authorization_benchmark.py --warmup 20 --samples 15` | **PASS** | parity before timing; results below. |

No failure was concealed by a silent rerun. No gate was skipped,
downgraded, or suppressed. Classifications: **introduced regression:
none; feature defect: none; pre-existing/unrelated: none observed;
nondeterministic/flaky: none; environment/harness failure: none** on the
final tree. The only skips are the deterministic PR 14 Keycloak
environment tests (environment/harness-limited, pre-existing).

## 4. Release benchmark (informational; no speed threshold)

Environment: WSL2 x86_64, Linux 6.18.33.2, Python 3.14.7, release native
wheel, engine `0.1.0`, seed `0x50523136`, warmup 20, samples 15 (median
primary; IQR reported in the artifact), parity checked before every
timed run. Paths: **PI** = N full `Authorizer.authorize` calls (per-item
policy compile); **PB** = one `BatchAuthorizer.authorize` (one shared
session/policy resolution); **RB** = one `RustBatchAuthorizer.authorize`
(Role→primitive conversion + native compile + one PyO3 crossing +
mapping).

Representative medians (ns), batch=100:

| Policy (Permissions) | PI | PB | RB | pb/pi | rb/pb | rb/pi |
|---|---|---|---|---|---|---|
| 25 | 2,381,698 | 217,801 | 419,902 | 10.94x | 0.52x | 5.67x |
| 200 | 14,702,368 | 353,252 | 648,390 | 41.62x | 0.54x | 22.68x |
| 1000 | 75,199,106 | 964,168 | 1,495,191 | 77.99x | 0.64x | 50.29x |
| 5000 | 477,555,117 | 4,477,493 | 5,132,185 | 106.66x | 0.87x | 93.05x |

Observations (characterization only, machine-specific, no generalization
claimed):

- Both batch paths dominate per-request evaluation (`pb/pi` and `rb/pi`
  grow with batch size), because one shared session check and one policy
  compile replace N of each.
- For these batches the pure-Python batch path is consistently faster
  than the Rust batch path (`rb/pb` ~0.52–0.97x): the Rust path pays
  Role→primitive conversion + native recompile + one PyO3 crossing +
  result mapping per batch, while the Python `CompiledPolicy` compile and
  indexed lookup are already fast. This is consistent with the PR 8G/8H
  finding that the Python↔Rust boundary dominates single/few-crossing
  compiled work on this machine.
- **No speed threshold exists; Rust slower is acceptable.** These
  measurements justify preserving the Python default, not changing it.

The full per-scenario median/IQR/min/max and ratios are in
`/tmp/pr16-batch-bench-final.json` (also re-derivable with the documented
command).

## 5. Protected scope

`git diff --name-only` confirms **no** change under `packages/mtmf-api/**`,
`mtmf-service/**`, `mtmf-client/**`, migrations, `sql/`, grants,
Keycloak/root, secrets, or other Podman projects. No HTTP endpoint,
public DTO/schema, database migration, or authentication change is made.
The default `Authorizer()` and `BatchAuthorizer` remain Python, load no
native module, and have no backend selector, fallback, or cache.

## 6. Reproduction

```bash
# Bootstrap and gates (final tree)
uv sync --locked
./build.sh --qa
./build.sh --sec
./build.sh --rust
set -a && . ./.env && set +a
./build.sh --integration
uv run --no-sync pre-commit run --all-files

# Release benchmark campaign
PYO3_PYTHON="$(uv run --no-sync python -c 'import sys; print(sys.executable)')" \
  uv run --no-sync maturin develop --release \
  --manifest-path packages/mtmf-permission-engine/Cargo.toml
uv run --no-sync python benchmarks/batch_authorization_benchmark.py \
  --warmup 20 --samples 15 --json /tmp/pr16-batch-bench-final.json
```
