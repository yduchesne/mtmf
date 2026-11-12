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
- Rust: rustup stable `1.99.1` (cargo/rustfmt/clippy) installed into the
  repository-supported `~/.cargo/bin` location.

## Canonical gates

| Gate | Command | Result |
| --- | --- | --- |
| Workspace | `uv sync --locked` | PASS |
| QA | `./build.sh --qa` | **PASS — 2490 passed, 0 skipped, coverage 90.30%** |
| Security | `./build.sh --sec` | **PASS — 0 findings** |
| Rust | `./build.sh --rust` | **PASS** (fmt, clippy `-D warnings`, cargo test, maturin develop, native probe, focused boundary/differential tests, clean wheel, benchmark smoke) |
| Integration | `./build.sh --integration` | **PASS — 628 passed, 94 skipped** |
| Role verifier | `uv run python scripts/mtmf-provision-roles.py --verify` | **PASS** |
| Diff hygiene | `git diff --check` | PASS |
| Object integrity | `git fsck --full` | PASS |

## QA count reconciliation

The earlier 2201 passed / 177 skipped result was caused by the native
`_mtmf_permission_engine` module not being installed: the QA gate skipped the
native/Rust-conditioned unit tests and suppressed their parametrized
differential cases. The same QA gate was then run on unmodified `main` in the
same environment with the same toolchain:

| Tree | Command | Result |
| --- | --- | --- |
| `main` @ `1bb46af` (clean worktree) | `./build.sh --qa` | **2472 passed, 0 skipped, coverage 90.32%** |
| PR 23 branch | `./build.sh --qa` | **2490 passed, 0 skipped, coverage 90.30%** |

`2472 + 18 = 2490`; the 18 additional tests are exactly the new PR 23 unit
cases A-U01…A-U18. The `main` result matches the PR 22A reported 2472 passing
unit tests. No test was unintentionally excluded.

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

## Live token acceptance — executed

Fixture selection was corrected to the approved `mtmf-dev` realm topology; no
trust baseline or authentication policy was changed. Diagnosis:
[PR23_ATTESTATION_FIXTURE_DIAGNOSIS.md](PR23_ATTESTATION_FIXTURE_DIAGNOSIS.md).

Configuration:

```text
Issuer URL:                 https://127.0.0.1:28443/realms/mtmf-dev
Realm:                      mtmf-dev
Realm-security baseline:    dev/keycloak/expected-realm-security.json
Expected-client policy:     dev/keycloak/expected-client-policy.json
Realm match:                YES
realmSecurity match:        YES
clientScopes match:         YES
same-client policy match:   YES
same-client-b policy match: YES
```

Commands (secrets supplied from the uncommitted `/tmp/mtmf-pr14-kc.env`):

```bash
podman-compose -p mtmf-pr14-keycloak -f dev/keycloak/compose.yaml \
  --env-file /tmp/mtmf-pr14-kc.env up -d
uv run --no-sync python scripts/pr14-keycloak-evidence.py wait
set -a; . /tmp/mtmf-pr14-kc.env; set +a
uv run --no-sync python dev/keycloak/setup-realm.py --realm mtmf-dev

SSL_CERT_FILE=/tmp/mtmf-pr14-kc-tls/server.crt MTMF_PR14_LIVE=1 \
  uv run --no-sync pytest \
  tests/integration/postgres/test_pr23_live_pre_tenant_subject.py -q -rs --no-cov

SSL_CERT_FILE=/tmp/mtmf-pr14-kc-tls/server.crt MTMF_PR14_LIVE=1 \
MTMF_AUTH_ADMIN_REALM=mtmf-dev \
  uv run --no-sync pytest \
  tests/integration/postgres/test_pr14_live_actor_context.py -q -rs --no-cov
```

Results:

| Suite | Result |
| --- | --- |
| PR 23 L01–L04 | **4 passed, 0 skipped** |
| PR 14 live regression | **22 passed, 0 skipped** |

L01–L04 prove valid service+user tokens with no Identity binding/Tenant,
existing global binding with exact UUIDs, wrong-class/cross-client rejection
without mutation, and ordinary actor resolution still requiring an eligible
Tenant.

The four PR 23 live cases remain opt-in in ordinary `--integration` runs by
design; when `MTMF_PR14_LIVE=1` they execute with zero skips.
