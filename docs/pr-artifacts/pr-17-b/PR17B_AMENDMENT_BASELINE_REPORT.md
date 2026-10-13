# PR 17-B Amendment Baseline Report (Phase 0 reconciliation)

**PR:** PR 17-B — Development Keycloak user provisioning and verified MTMF identity binding
**Amendment:** acceptance-completion amendment
**Base commit:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3` (`origin/main`)
**Reported starting tip:** `f0de6b1` — verified correct
**Final amendment tip:** `e860e214d7cbddbe0b58d82267041a687ad39907` (reports) · code/test tip `ca23d11ebbb2f7c316be444aeb594c38d7114d6f`
**Branch:** `dev/pr17b-keycloak-user-provisioning`
**Working tree:** clean at the start and end of the amendment.

## 1. Commit and provenance reconciliation

`git status --short` was empty; `git branch --show-current` was
`dev/pr17b-keycloak-user-provisioning`; `git rev-parse HEAD` was
`f0de6b1`, matching the reported tip; `git rev-parse origin/main` was `b60c50b`
and was the merge base (no rebase/force-push performed).

The previously committed reports referred to `9e074fb` as the "final tip". That was
imprecise: `9e074fb` was the **code** tip, and `f0de6b1` was the later docs-only
artifact commit. Full commit provenance:

| Commit | Role |
| --- | --- |
| `362aae664c4f76a88c69ae25421249346b5591c7` | PR 17-B core implementation |
| `daeed82dd7ff49cbc7715be3769ab67f93f00db1` | PR 17-B artifacts |
| `9e074fb09e92b1db37f96496f3f256ef49196e1a` | brokered-`origin` account hardening |
| `f0de6b13f440d42db55a0d19057268822e96df9f` | artifact provenance/count corrections (starting tip) |
| `ca23d11ebbb2f7c316be444aeb594c38d7114d6f` | this amendment code/test (failpoint, live harness, Tenant-name fix) |
| `e860e214d7cbddbe0b58d82267041a687ad39907` | this amendment reports (branch tip) |

## 2. Live infrastructure inventory

| Capability | Harness | Real components | Default gating |
| --- | --- | --- | --- |
| PR 14 actor trust | `tests/integration/postgres/test_pr14_live_actor_context.py` | Keycloak + PostgreSQL | `MTMF_PR14_LIVE=1` |
| PR 17 HTTP | `tests/integration/postgres/test_pr17_live_http.py` | Keycloak + PostgreSQL + Uvicorn | `MTMF_PR17_LIVE=1` |
| PR 17 reader least privilege | `tests/integration/postgres/test_pr17_attestation_reader_permissions.py` | Keycloak | `MTMF_PR17_LIVE=1` |
| PR 17 base initializer | `tests/integration/postgres/test_pr17_dev_initializer.py` | PostgreSQL + doubled credential port | always (skips live) |
| PR 17-B live acceptance (new) | `tests/integration/postgres/test_pr17b_live_acceptance.py` | production initializer process + Keycloak + PostgreSQL | `MTMF_PR17B_LIVE=1` |
| PR 17-B Compose isolation (new) | `tests/integration/postgres/test_pr17b_compose_isolation.py` | Compose containers + initializer image + Keycloak | `MTMF_PR17B_COMPOSE=1` |
| PR 17-B fault proxy (new) | `tests/integration/postgres/pr17b_fault_proxy.py` | real Keycloak (pass-through) | imported by I15 |

Topology: MTMF-owned PostgreSQL `mtmf_postgres_1` published on prefix-2 loopback
`25432`; MTMF-owned Keycloak project `mtmf-pr14-keycloak`, realm `mtmf-pr14-dev`,
loopback `28080`/`28443`, self-signed TLS from `/tmp/mtmf-pr14-kc-tls/server.crt`;
initializer image `localhost/mtmf_initializer:latest`. No ATI/Digr/Darkula/Hammeridian
resource was inspected, mutated, or pruned.

## 3. Baseline results

Historical results from the core PR 17-B reports were treated as claims, not proof.
The amendment re-ran every canonical gate and live suite on the final amendment tip
(`ca23d11`): see `PR17B_AMENDMENT_ACCEPTANCE_REPORT.md`. The previously reported
baseline (on `b60c50b`/`f0de6b1`) was: QA 1863 passed / coverage 90.70%, sec clean,
Rust clean, integration 564 passed / 60 skipped, live PR 14/17 51 passed.

## 4. Acceptance gaps identified at baseline

The prior `PR17B_ACCEPTANCE_REPORT.md` §4 and `PR17B_STOP_DEVIATION_REGISTER.md` SD-2
listed I10/I12/I13/I15/I16/I18/I20 as design/unit-covered but not exercised live.
Reconciliation found one real coverage gap and one real defect:

- **Gap:** no deterministic harness for concurrency, terminate-after-create, lost-POST
  reconciliation, incompatible-binding, multi-Application, or Compose isolation.
- **Defect (found while designing I20):** `PostgresProvisioner.ensure_ordinary_tenant`
  reused an existing Tenant by deterministic ID without comparing its name, so a
  conflicting `MTMF_DEV_TENANT_NAME` override did **not** fail closed. Reproduced and
  fixed in `ca23d11` with the I20 regression test.

## 5. Conclusion

No branch/base drift, no destructive operation against shared state, no realm/client
policy change. Proceeded with the narrow amendment.
