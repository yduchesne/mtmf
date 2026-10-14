# PR20B_FINAL_ACCEPTANCE_REPORT

**PR:** roadmap PR 20B — Deployed End-to-End Conformance and Resilience
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Baseline SHA:** `c7c992a372bb83bae3837efb04b1f19742bb83e2`
**Implementation SHA (validated):** `61649b4969eb882501920a506584f2bba581d125`
**Status:** **NOT DONE — explicit P0 STOP** (mixed-batch deployed proof not
representable under the approved policy model). All other required gates and
deployed conformance cases executed green.

## 1. Outcome

PR 20B delivers a bounded multi-document batch PEP route with atomic
all-or-nothing disclosure and an isolated, deployed conformance harness that
reuses the official `mtmf-client`, real Keycloak/MTMF/PostgreSQL, and the
canonical PR 20A topology. No production MTMF package, migration, protected
policy, or default-stack resource changed.

The single mandatory gate that could not be satisfied is the P0 mixed-batch
deployed proof, because the approved policy model matches exact Actions and
never resource instances. Per the execution plan this is a STOP and PR 20B is
**not** DONE. See [`PR20B_STOP_REPORT.md`](PR20B_STOP_REPORT.md).

## 2. Canonical gate results (executed on the implementation tree)

| Gate | Command | Observed |
| --- | --- | --- |
| Quality | `./build.sh --qa` | Ruff format/lint clean, strict Mypy clean, **2457 passed**, coverage **90.36%** (≥ 85) |
| Security | `./build.sh --sec` | Bandit 0 medium/high, Semgrep **0 findings** |
| Examples scan | `uv run semgrep scan --config=auto examples` | **0 findings** (11 files) |
| Rust/native | `./build.sh --rust` | cargo fmt/clippy/test, `maturin develop`, native probe, focused parity/differential tests, clean wheel, benchmark smoke — **PASS** |
| Integration | `set -a; source .env; set +a; ./build.sh --integration` | **593 passed, 90 skipped** (documented opt-in live suites) |
| Example package | `uv run pytest examples/mtmf-reference-app/tests --cov=mtmf_reference_app --cov-fail-under=85` | **89.45%** coverage (≥ 85) |
| Deployed | `uv run python scripts/pr20b-reference-acceptance.py acceptance` | **3 cycles**; each 5 PR20A + 18 PR20B, **0 skips**; default stack unchanged |

Skipped integration tests are the pre-existing opt-in live suites (PR 17/18/19C),
not PR20B skips.

## 3. Part H — parity, migrations, and wire-contract evidence

- **Python/Rust complete-decision parity** ran inside `./build.sh --rust`:
  `tests/unit/authorization/test_permission_evaluator_differential.py`,
  `test_compiled_policy_differential.py`, `test_compiled_policy_evaluator.py`,
  `test_python_compiled_policy.py`, and the focused `test_rust_engine.py`,
  `test_rust_matcher.py`, `test_rust_evaluator.py`,
  `test_rust_permission_evaluator.py`, `test_rust_boundary_hardening.py`,
  `test_authorizer_rust.py`, `test_rust_batch_adapter.py`,
  `test_rust_batch_authorizer.py`. No new evaluator or ad-hoc policy engine was
  introduced.
- **Frozen v1 wire contract / ordered response binding** ran in `--qa`:
  `tests/unit/api/test_api_authorization_dtos.py`,
  `test_api_conformance.py`, `test_api_schema_parity.py`,
  `test_api_vertical_slice.py`, and the client suites
  `tests/unit/client/test_client_snapshot.py`,
  `test_client_resource_binding.py`, `test_client_transport.py`.
- **Migrations** ran in `./build.sh --integration` against real PostgreSQL 18;
  the migration head is unchanged at
  `0013_security_mutation_audit_partitioning`. No shipped versioned migration
  was edited.

## 4. Diff inventory

**New:**

```text
examples/mtmf-reference-app/tests/test_batch_pep.py
scripts/pr20b-fault-proxy.py
scripts/pr20b-reference-acceptance.py
scripts/pr20b_fixture_transitions.py
tests/e2e/reference_app/test_pr20b_live_conformance.py
tests/unit/service/test_pr20b_harness.py
docs/pr-artifacts/pr-20b/PR20B_BASELINE_RECONCILIATION.md
docs/pr-artifacts/pr-20b/PR20B_MATRIX_AND_FIXTURE_CONTRACT.md
docs/pr-artifacts/pr-20b/PR20B_SECURITY_BOUNDARY_REVIEW.md
docs/pr-artifacts/pr-20b/PR20B_DEPLOYED_ACCEPTANCE_REPORT.md
docs/pr-artifacts/pr-20b/PR20B_FINAL_ACCEPTANCE_REPORT.md
docs/pr-artifacts/pr-20b/PR20B_STOP_REPORT.md
```

**Narrowly modified:**

```text
examples/mtmf-reference-app/src/mtmf_reference_app/app.py   (batch route + shared context helper)
examples/mtmf-reference-app/README.md                       (batch semantics)
docs/DEVELOPMENT_SETUP.md                                   (PR20B commands)
docs/ROADMAP_V01.md                                         (PR20B status; not DONE)
```

**Deliberately unchanged:** `packages/mtmf-api`, `packages/mtmf-client`,
`packages/mtmf-core`, `packages/mtmf-service`, all `sql/**` and migrations,
`compose.yaml`, `compose.dev.yaml`, `compose.pr19c-acceptance.yaml`,
`compose.pr20a-acceptance.yaml`, `dev/keycloak/expected-*.json`,
`scripts/pr20a-reference-acceptance.py`, and historical PR20A reports.

## 5. Reviewer checklist

- [x] Fresh-main SHA, architecture inventory and preflight recorded.
- [x] Real independent PEP/Keycloak/MTMF/PG deployed; default stack untouched.
- [x] Every new batch action corresponds to a real resource operation; no fake
      ALLOW/DENY (unit tests use a per-occurrence decision fake only to exercise
      the app's own atomic-disclosure ordering; deployed cases use real MTMF).
- [ ] Mixed-batch P0 satisfied **or** explicit STOP — **explicit STOP recorded**.
- [x] Lifecycle/subscription and spoofing scenarios prove authoritative denial
      and restoration (executed subset; S02/S05/S07/S08 documented deviations).
- [x] Snapshot exactness/expiry and revocation tested without invented cache
      (existing client suite N01–N08 + deployed N09/N10).
- [ ] Fault scenarios substitute only remote response, fail closed, and recover
      — component implemented/unit-tested; **deployed F01–F07 not executed**
      (topology constraint, documented).
- [x] Concurrency waves show no actor/context/body mixing.
- [x] Existing Rust/Python parity, v1 contract and migration gates executed.
- [x] All canonical gates passed; no required skips in the PR20B deployed suite.
- [x] PR20B reports committed under `docs/pr-artifacts/pr-20b/`, links valid.
- [x] Roadmap not marked DONE (P0 STOP); no scope leakage.

## 6. Completion contract

> PR 20B is DONE iff every mandatory gate above was actually executed
> successfully, including P0 mixed-batch deployed proof.

Because P0 cannot be executed under the approved policy model, PR 20B is
**NOT DONE**. The implementation is complete and green for every other required
feature-specific gate, and the one gap is recorded as an explicit STOP rather
than a fabricated PASS.
