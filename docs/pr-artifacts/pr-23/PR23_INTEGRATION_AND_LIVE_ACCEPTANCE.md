# PR 23 — Integration and Live Acceptance

## Environment

- Branch: `dev/pr23-verified-subject-stewardship`
- Base: `1bb46af8a8fe780be23521954e130ef895906ab9`
- PostgreSQL: 18.6 (Debian 18.6-1.pgdg13+2), host `127.0.0.1:25432`, database `mtmf`
- Authenticated identities used:
  - administrator `mtmf` (schema reset/provisioning only)
  - migrator `mtmf_migrator` (migrations; `SET ROLE mtmf_owner` in test harness)
  - runtime `mtmf_runtime` (denial subject; no `SET ROLE`)
- Migration head: `0015`
- Runtime EXECUTE manifest: `78`

## Canonical gates

| Gate | Command | Result |
| --- | --- | --- |
| Workspace | `uv sync --locked` | PASS |
| QA | `./build.sh --qa` | **PASS — 2201 passed, 177 skipped, coverage 90.18%** |
| Security | `./build.sh --sec` | **PASS — 0 findings** |
| Rust | `./build.sh --rust` | **BLOCKED-ENV — `cargo` not installed in this environment** |
| Integration | `./build.sh --integration` | **PASS — 628 passed, 94 skipped** |
| Role verifier | `uv run python scripts/mtmf-provision-roles.py --verify` | **PASS** |
| Diff hygiene | `git diff --check` | PASS |
| Object integrity | `git fsck --full` | PASS |

## Feature acceptance — unit (executed)

`tests/unit/application/test_pre_tenant_subject.py` — **18 passed**
(A-U01…A-U18): valid pair/derived Application, attestation order, class/issuer/
cross-client rejection, existing vs absent binding, deleted/non-FEDERATED
identity, missing root registry, no Tenant/commit/write requirement, naive
instant, infrastructure failure distinct from unknown subject, immutability/
detachment, root exclusion, and unchanged ordinary actor-resolution semantics.

## Feature acceptance — real PostgreSQL (executed)

`tests/integration/postgres/test_pr23_initial_stewardship.py` — **22 passed**:

| Case | Evidence |
| --- | --- |
| P23-I01 | Populated `0014 → 0015` upgrade preserves principal/identity/binding/entitlement/root/audit rows; head `0015` |
| P23-I02 | Fresh head and no-op upgrade; runtime manifest 78 |
| P23-I03 | Owner `mtmf_owner`, INVOKER, empty `search_path`, PUBLIC revoked, runtime denied |
| P23-I04 | New subject creates exactly one Principal/FEDERATED Identity/ACTIVE binding; no Tenant/membership/Role/audit side effects |
| P23-I05 | Repeat subject returns `EXISTING` exact IDs with no writes |
| P23-I06 | Revoked-only history, inactive identity/principal, blank/oversized input fail closed (`MT048`/`MT047`) |
| P23-I07 | Different issuers + same `sub` produce distinct Identities; equal display names never merge |
| P23-I08 | Two concurrent same-key transactions produce exactly one `CREATED` + one `EXISTING`, one ACTIVE binding, no orphan |
| P23-I09 | One owner transaction installs exact memberships, Tenant-wide Tenant Administrator Role, designation v1, one `INITIAL_ONBOARDING` audit; Tenant still `PROVISIONING`; rollback removes all |
| P23-I10 | Rollback after B1, after Tenant insert, and after B2 leaves zero partial rows |
| P23-I11 | Root Principal/Identity/Tenant attempts denied; root registry unchanged |
| P23-I12 | ACTIVE/deleted/wrong-owner Tenant denied |
| P23-I13 | Missing binding, wrong binding Identity, LOCAL Identity, deleted Principal denied |
| P23-I14 | Dirty Tenant (membership/registration), re-attach, duplicate assignment UUID denied |
| P23-I15 | Missing Tenant Administrator seed fails closed without seeding |
| P23-I16 | Concurrent attachment: exactly one success, one `MT048`, one designation/audit |
| P23-I17 | Five audit operations accepted; arbitrary value rejected; UPDATE/DELETE raise `MT033` |
| P23-I18 | Actual `mtmf_runtime` denied both functions and protected table DML/SELECT |
| P23-I19 | Existing Tenant-A membership not inherited by another Application/subject verification |
| P23-I20 | Legacy PR 10 final-steward membership/assignment deletion guards still deny (`MT032`) |
| P23-I21 | Revoked runtime grant makes the no-op postflight fail (no auto-repair) |
| P23-I22 | `MT047`/`MT048` remain fail-closed `PersistenceError` |

No test commits an ACTIVE Tenant through PR 23. The only ACTIVE Tenant in
P23-I20 is created by the existing approved PR 10 test helper
(`designate_steward` + `activate_tenant`), not by the v015 participants.

## Live token acceptance — BLOCKED-LIVE

`tests/integration/postgres/test_pr23_live_pre_tenant_subject.py` is opt-in
(`MTMF_PR14_LIVE=1`) and was exercised against the isolated PR 14 Keycloak
fixture (`dev/keycloak/compose.yaml`, realm `mtmf-pr14-dev`, TLS on
`https://127.0.0.1:28443`, `setup-realm.py` executed).

Result: **4 failed, 0 skipped** with `AuthenticationFailure.ATTESTATION_DRIFT`
before token-class evaluation. Root cause is a pre-existing fixture/baseline
mismatch: the live realm contains `mtmf-attestation-reader` and
`mtmf-evidence-same-client-b`, which are absent from the committed
`dev/keycloak/expected-realm-security.json`. The unmodified PR 14 live test
(`test_pr14_live_actor_context.py::test_dc07_v01_positive_real_tokens_and_postgres`)
fails with the identical `ATTESTATION_DRIFT` on the baseline commit, proving this
is not a PR 23 regression.

No alternative IdP, attestation bypass, or regenerated trust baseline was
substituted. Per plan STOP-08, genuine-token feature acceptance is therefore
**not claimed**.

Normal `./build.sh --integration` reports the four live cases as skipped
(documented opt-in), and skipped tests are not feature acceptance evidence.
