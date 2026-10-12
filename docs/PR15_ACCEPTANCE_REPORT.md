# PR 15 — Acceptance report

**Document type:** Execution evidence for the PR 15 contract-only package
**Branch:** `dev/api-contract`
**Base commit:** `5ae16506966c168710f0f369789043e39be7ac69` (`origin/main`, PR 14 squash merge)
**Implementation commit:** `2a1a1f5492cdeca0a23df55e986139be4ba6a633`
**Date:** 2026-10-12
**Environment:** WSL2 x86_64; Python 3.14.7 (uv-managed); uv 0.12.17; PostgreSQL 18 in `mtmf_postgres_1` (host `25432`, MTMF-owned prefix `2`); Rust 1.98.1.

**Result:** PASS. PR 15 is a **contract-only** deliverable. No HTTP route,
batch evaluator, migration, database grant, OAuth issuance, dependency, or
native change was added.

## 1. Phase 0 reconciliation

| Item | Baseline finding |
| --- | --- |
| `origin/main` | `5ae16506966c168710f0f369789043e39be7ac69` (matches the plan's authoring baseline) |
| `mtmf-api` before | package shell only: `__init__.py` exporting `__version__`, `pyproject.toml` with `dependencies = []` |
| Detached DTOs / codecs / errors / conformance | **missing** (added here) |
| Public Action grammar | core Action identity is the exact URN `urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>`; the plan's illustrative short-name regex cannot represent it (see W3) |
| HTTP runtime | **deferred** to PR 16/17/18 (unchanged) |
| Baseline `./build.sh --qa` | 1418 passed; total coverage 88.28% |
| Baseline `./build.sh --sec` | 0 findings |
| Baseline `./build.sh --integration` | 556 passed, 22 skipped (env-loaded) |

## 2. W1–W7 approvals

Recorded in [`PR15_API_CONTRACT_DECISIONS.md`](PR15_API_CONTRACT_DECISIONS.md).
Approval source: the human reviewer instructed the coding agent to
implement the detailed execution plan (2026-10-12) and explicitly
confirmed W3 (exact canonical Action URNs) during PR 15 review
(2026-10-11). All W1–W7 decisions are now approved; no contract decision
remains open.

| ID | Status | Note |
| --- | --- | --- |
| W1 | APPROVED | route/versioning/strict JSON |
| W2 | APPROVED | 1–100 batch, unique ordered correlation |
| W3 | APPROVED | exact canonical Action URN instead of the illustrative short name — explicitly confirmed by the human reviewer during PR 15 review (2026-10-11) |
| W4 | APPROVED | tagged resource union; MTMF-owned fails closed |
| W5 | APPROVED | public reasons/errors/status mapping |
| W6 | APPROVED | UTC TTL handoff |
| W7 | APPROVED | stdlib only, no new dependency |

## 3. Build, import, and packaging evidence

- `packages/mtmf-api/pyproject.toml` still declares `dependencies = []`.
- `mtmf-api` wheel builds via `uv build --wheel --package mtmf-api`; the
  wheel contains `mtmf_api/py.typed`, `authorization.py`, `json_codec.py`,
  `errors.py`, and `conformance.py`.
- Installed into a freshly created, isolated venv and imported/exercised
  successfully (`tests/unit/api/test_api_package_isolation.py::test_a25_wheel_builds_installs_and_imports_in_isolation`).
- Importing every `mtmf_api` submodule loads none of: `mtmf_core`,
  `mtmf_service`, `mtmf_client`, `fastapi`, `uvicorn`, `starlette`,
  `pydantic`, `psycopg`, `alembic`, `sqlalchemy`, `jwt`, `httpx`,
  `requests`, `_mtmf_permission_engine`.

## 4. A01–A28 test-node mapping

| ID | Test node(s) |
| --- | --- |
| A01 | `test_api_authorization_dtos.py::test_a01_minimal_valid_request_round_trips` |
| A02 | `test_api_authorization_dtos.py::test_a02_organization_selector_is_preserved` |
| A03 | `test_api_authorization_dtos.py::test_a03_one_and_one_hundred_entries_accepted`, `::test_a03_zero_and_101_entries_rejected` |
| A04 | `test_api_authorization_dtos.py::test_a04_duplicate_actions_with_distinct_ids_are_retained` |
| A05 | `test_api_authorization_dtos.py::test_a05_duplicate_request_id_is_rejected` |
| A06 | `test_api_json_codec.py::test_a06_unknown_syntactically_valid_action_parses`, `::test_a06_unknown_action_deny_response_parses` |
| A07 | `test_api_authorization_dtos.py::test_a07_wildcard_action_is_rejected`, `::test_action_urn_grammar_mirrors_core` |
| A08 | `test_api_authorization_dtos.py::test_a08_unknown_identity_fields_are_rejected`, `test_api_security_negative.py::test_no_caller_supplied_identity_is_accepted` (parametrized over 10 identity fields) |
| A09 | `test_api_json_codec.py::test_a09_duplicate_keys_rejected_including_nested` |
| A10 | `test_api_json_codec.py::test_a10_non_object_top_level_rejected`, `::test_a10_malformed_or_wrong_shaped_payloads_rejected`, `::test_a10_non_finite_numbers_rejected` |
| A11 | `test_api_authorization_dtos.py::test_a11_nil_and_uppercase_uuid_rejected`, `::test_a11_wrong_types_rejected` |
| A12 | `test_api_authorization_dtos.py::test_a12_capability_with_id_rejected`, `::test_a12_unknown_resource_kind_rejected` |
| A13 | `test_api_authorization_dtos.py::test_a13_application_owned_requires_type_and_id` |
| A14 | `test_api_authorization_dtos.py::test_a14_mtmf_owned_requires_qualifiers` |
| A15 | `test_api_authorization_dtos.py::test_a15_allow_permitted_and_deny_no_permission_accepted` |
| A16 | `test_api_authorization_dtos.py::test_a16_effect_reason_mismatches_rejected`, `::test_a16_unknown_effect_and_reason_rejected` |
| A17 | `test_api_conformance.py::test_a17_duplicate_actions_correlate_distinctly`, `test_api_vertical_slice.py::test_vertical_slice_end_to_end` |
| A18 | `test_api_conformance.py::test_a18_decision_correlation_violations_rejected` (5 parametrized violations) |
| A19 | `test_api_conformance.py::test_a19_tenant_mismatch_rejected`, `::test_a19_organization_mismatch_rejected` |
| A20 | `test_api_authorization_dtos.py::test_a20_valid_ttl_accepted`, `::test_a20_invalid_ttl_rejected`, `::test_a20_non_utc_timestamp_rejected`, `::test_a20_overlong_ttl_fixture_rejected`, `::test_max_ttl_constant_matches_approved_decision` |
| A21 | `test_api_error_contract.py::test_a21_every_reserved_error_round_trips`, `::test_a21_error_fixtures_match_the_catalog`, `::test_a21_optional_request_id_round_trips`, `::test_a21_http_status_table_is_complete` |
| A22 | `test_api_error_contract.py::test_a22_unknown_error_code_rejected`, `::test_a22_secret_or_stack_field_rejected`, `::test_a22_message_must_match_static_catalog` |
| A23 | `test_api_json_codec.py::test_a23_parser_never_crashes_uncontrolled`, `::test_a23_text_parser_never_crashes_uncontrolled` (Hypothesis) |
| A24 | `test_api_package_isolation.py::test_a24_import_graph_has_no_forbidden_dependencies`, `::test_a24_api_cannot_import_core_or_service` |
| A25 | `test_api_package_isolation.py::test_a25_wheel_builds_installs_and_imports_in_isolation` |
| A26 | `test_api_schema_parity.py::test_a26_valid_fixtures_validate_against_schema_and_parser`, `::test_a26_invalid_fixtures_are_rejected_by_every_parser`, `::test_a26_schema_expressible_invalid_fixtures_fail_the_schema`, `::test_a26_cross_field_fixtures_remain_parser_only` |
| A27 | `test_api_conformance.py::test_a27_conformance_is_pure_and_cannot_mint_policy` |
| A28 | `test_api_json_codec.py::test_a28_request_round_trip_is_stable`, `::test_a28_response_round_trip_is_stable`, `::test_a28_error_round_trip_is_stable`, `test_api_authorization_dtos.py::test_a28_serialization_is_byte_identical` |

Additional strictness guards live in
`test_api_dto_type_guards.py`; the Part 4 vertical slice and failure
behavior live in `test_api_vertical_slice.py`.

## 5. Test counts, coverage, and parity

| Metric | Baseline | Final |
| --- | --- | --- |
| Unit tests | 1418 passed | **1600 passed** |
| `mtmf-api` new tests | 0 | **182 passed** |
| Total coverage | 88.28% | **89.17%** |
| `mtmf_api` coverage | n/a | **97.40%** (`authorization` 99%, `conformance` 100%, `errors` 100%, `json_codec` 95%, `__init__` 100%) |
| Integration | 556 passed, 22 skipped | 556 passed, 22 skipped |
| Security findings | 0 | 0 |

**Schema/parser parity.** `packages/mtmf-api/schema/authorization-v1.schema.json`
is cross-checked against the runtime codecs by a test-only JSON Schema
subset validator: valid fixtures satisfy the schema and parse; every
invalid fixture is rejected by all three parsers; schema-expressible
invalid fixtures also fail the schema; cross-field fixtures
(`request_id` uniqueness, effect/reason coupling, TTL ordering) are
schema-valid but parser-rejected, as documented.

**Negative security results.**
`test_api_security_negative.py` proves: no caller-supplied identity field
is accepted; the request DTO exposes no identity authority; no
missing/unknown effect or reason defaults to ALLOW; error messages
contain no internal detail; the error envelope rejects SQL/policy detail;
error serialization carries only `schema_version` and `{code, message}`.

## 6. Gate execution

All commands were executed on the final tree.

| Command | Result |
| --- | --- |
| `./build.sh --qa` | PASS — ruff format, ruff lint, strict mypy (107 files), 1600 passed; coverage 89.17% (≥ 85%) |
| `./build.sh --sec` | PASS — Bandit 0 Medium/High; Semgrep 0 findings / 171 files |
| `./build.sh --integration` (env-loaded) | PASS — 556 passed, 22 skipped in ~5m |
| `pre-commit run --all-files` | PASS — gitleaks Passed; MTMF Rust/native gate Passed; MTMF quality gate Passed; MTMF security scan Passed |

Targeted command:
`uv run --no-sync pytest tests/unit/api -q --cov=mtmf_api --cov-report=term-missing`
→ 182 passed, `mtmf_api` coverage 97.40%.

### Integration topology

Real PostgreSQL 18 (`mtmf_postgres_1`) published on MTMF host port
`25432`; the suite runs as the restricted `mtmf_runtime` login with the
`MTMF_MIGRATOR_*`/`MTMF_RUNTIME_*` configuration from `.env`. No SQLite
or in-memory substitute was used. PR 15 adds no SQL; the integration run
is a regression guard only. The 22 skips are the PR 14
live-issuer/Keycloak actor-context cases (`test_pr14_live_actor_context.py`),
identical on the baseline and unrelated to PR 15.

### Skips and classification

| Item | Classification |
| --- | --- |
| 22 integration skips | preexisting environment-dependent PR 14 live-issuer cases; reproduced identically on the baseline |
| Rust gate under `pre-commit` | not required by PR 15 scope (no native change); run anyway by the canonical `pre-commit` configuration and passed |
| All other gates | no skips |

## 7. Baseline vs regression vs feature acceptance

| Classification | Evidence |
| --- | --- |
| Baseline reproduced | `git rev-parse HEAD` = base SHA; baseline QA/sec/integration recorded in §1 |
| No regression | Unit count 1418 → 1600 with no preexisting test removed or weakened; integration unchanged (556/22); sec 0 findings; total coverage rose 88.28% → 89.17% |
| Feature acceptance | A01–A28 mapped and passing; package builds/installs/imports in isolation; schema/parser parity asserted; vertical slice passes |

No gate failed, so no failure classification (introduced regression /
feature defect / preexisting failure / flake / environment) was required.

## 8. Scope confirmation

`git show --stat 2a1a1f54` is limited to `packages/mtmf-api/**`,
`tests/unit/api/**`, the three PR 15 documents, the PR 15 package README,
and the PR 12 cross-link/roadmap status. It does **not** touch
`mtmf-core` authorization/application code, `mtmf-service` authentication
or routes, `mtmf-client`, Alembic migrations, `sql/v*`, PostgreSQL
grants, the Rust workspace, or the Keycloak fixtures. No HTTP endpoint
was implemented. PR 16/17/18 remain not DONE.
