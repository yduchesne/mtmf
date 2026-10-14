# PR19C_AMENDMENT03_REPRODUCIBILITY_REPORT

**PR:** roadmap PR 19C. **Date:** 2026-10-14.

| Case | Status | Evidence |
| --- | --- | --- |
| COLD-01 (`acceptance-pr19c --fresh`) | **BLOCKED** | orchestrator reached a healthy disposable PostgreSQL/keycloak/forwarder project but could not obtain an isolated fresh `mtmf-dev` realm; see `PR19C_AMENDMENT03_STOP_REPORT.md` |
| REPEAT-01 (`acceptance-pr19c`) | **NOT EXECUTED** | depends on COLD-01 |
| RECREATE-01 (second `--fresh`) | **NOT EXECUTED** | depends on COLD-01 |
| ISOLATION-01 (resource inventory) | **PARTIAL** | the acceptance project created only project-scoped containers/volumes; the Keycloak volume is globally named (root cause of the stop). No unrelated ATI/Darkula/other resource was touched. |
| NEG-01 (wrong CA / DNS / issuer) | **PARTIAL** | canonical issuer exactness is enforced by `mtmf-dev-stack.py`; `_canonical_dns_ok` fails closed on missing DNS. Not executed as a standalone acceptance case. |
| NEG-02 (non-owned project collision) | **PASS (unit)** | `test_oru01_default_project_is_refused` — the orchestrator refuses the default/any non-acceptance project. |
| NEG-03 (Keycloak unavailable) | **NOT EXECUTED** | no fake-token fallback exists by construction; bounded probe retry fails closed. |
| SECRET-01 | **PASS** | generated admin/user passwords appear zero times in the acceptance logs after the redaction fix; `test_oru04_secrets_are_redacted`. |

## Reproducible live acceptance that did run

The canonical `mtmf` stack was brought up noninteractively with a staged admin secret and reconciled with `setup-realm.py`, and H01–H05 passed (see `PR19C_AMENDMENT03_LIVE_ACCEPTANCE.md`). This proves the live trust chain but is not a disposable cold start.

## Failure classification

COLD-01 root cause is an **environment/harness/topology limitation**, not a feature defect: `compose.dev.yaml` declares the Keycloak data volume with a global `name`, so a second Compose project cannot obtain an independent fresh realm without modifying production Compose definitions or destroying the operator's persistent realm volume. `podman-compose` 1.0.6 did not reliably apply the acceptance-only volume-name override.
