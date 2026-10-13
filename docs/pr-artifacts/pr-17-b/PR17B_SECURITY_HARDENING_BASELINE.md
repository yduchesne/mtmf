# PR 17-B Security-Hardening Baseline

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Amendment:** security-hardening amendment
**`origin/main`:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**`origin/dev/pr17b-keycloak-user-provisioning`:** `0c9ee1e6ae75d41b56d4353c85c65060a0432f64` (matches local `HEAD`)
**Merge base:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Working tree at start:** clean; no rebase and no unrelated changes.

## 1. Main vs branch reconciliation

`origin/main` does **not** contain
`packages/mtmf-service/src/mtmf_service/development_user.py`; the implementation
branch does. This is therefore an in-progress amendment of the existing PR 17-B
branch, not a new implementation from `main`.

Branch commits relative to `main`:

| Commit | Role |
| --- | --- |
| `362aae6` | PR 17-B core implementation |
| `daeed82` | PR 17-B artifacts |
| `9e074fb` | brokered-`origin` account hardening |
| `f0de6b1` | artifact provenance corrections |
| `ca23d11` | acceptance-completion amendment (failpoint, live harness, Tenant-name fix) |
| `e860e21` | acceptance-completion reports |
| `0c9ee1e` | exact-tip provenance correction (starting tip) |

## 2. Actual test paths (inspected, not invented)

- Unit: `tests/unit/service/test_pr17b_development_user.py`,
  `tests/unit/service/test_pr17b_initialize_script.py`.
- Live PR 17-B: `tests/integration/postgres/test_pr17b_live_acceptance.py`
  (`MTMF_PR17B_LIVE=1`), `tests/integration/postgres/test_pr17b_compose_isolation.py`
  (`MTMF_PR17B_COMPOSE=1`), `tests/integration/postgres/pr17b_fault_proxy.py`.
- Regression: `tests/integration/postgres/test_pr14_live_actor_context.py`,
  `test_pr17_live_http.py`, `test_pr17_attestation_reader_permissions.py`
  (`MTMF_PR14_LIVE=1` / `MTMF_PR17_LIVE=1`).

## 3. Prior evidence classification

The committed PR 17-B acceptance reports (`PR17B_ACCEPTANCE_REPORT.md`,
`PR17B_AMENDMENT_ACCEPTANCE_REPORT.md`) describe successful prior test runs on
`ca23d11`. Those are **baseline/regression context only**; they do not prove the
amended commit. The amended tip must re-run the canonical gates and the full
live matrix.

## 4. Review findings confirmed in source

| Finding | Location | Current unsafe behavior |
| --- | --- | --- |
| Unearned email verification | `development_user.py` `_create_once` | Sets `emailVerified: true` when an email is configured, despite no email-control proof. |
| Weak create reconciliation | `development_user.py` `ensure_user`/`_create_once` | Any failed POST (including definite 400/401/403/422) is swallowed; a subsequent matching-username lookup is accepted as if this invocation created the account. |
| Password-file TOCTOU | `development_user.py` `load_dev_user_password` | `lstat()` validates the path, then `Path.read_bytes()` reopens it by pathname. |

The test-only failpoint `MTMF_DEV_TEST_FAILPOINT=after-user-verify` is inert by
default, exact-match, initializer-only, and placed before any MTMF write; the
amendment treats it as not a vulnerability (audited in Part D).

## 5. Live Keycloak create-response contract (probed)

Against the pinned `quay.io/keycloak/keycloak:26.8.0-1` realm `mtmf-pr14-dev`:

- `POST /admin/realms/{realm}/users` → **HTTP 201** with a `Location` header whose
  final path segment equals the created user's immutable `id`.
- Duplicate username → **HTTP 409**.
- Missing/invalid user body → **HTTP 400**.

This gives an authoritative creation identifier for the successful-POST path and
lets the reconciliation policy distinguish success from conflict without trusting
a mutable username.

## 6. Scope boundaries

- The standard Compose `up` issuer-hostname limitation remains a **separate
  infrastructure PR**; it is not fixed or claimed here.
- No change to `mtmf-core`, `mtmf-api`, Rust, migrations, stored functions,
  grants, realm/client policy, or `scripts/mtmf-dev-stack.py`.
