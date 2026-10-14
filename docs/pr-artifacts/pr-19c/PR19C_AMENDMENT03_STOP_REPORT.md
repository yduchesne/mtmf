# PR19C_AMENDMENT03_STOP_REPORT

**PR:** roadmap PR 19C. **Date:** 2026-10-14.
**Scope of STOP:** disposable cold-start / repeat / recreate acceptance only. The live H01–H05 trust chain was executed and passed against the canonical development Keycloak and is not blocked.

## Trigger

Amendment 03 §13 STOP condition (1)/(2): the canonical Compose model cannot provide an isolated, disposable Keycloak realm without destroying or mutating the operator's persistent realm volume, or without changing the production Compose volume definition.

## Root cause

`compose.dev.yaml` declares the Keycloak data volume with an explicit global name:

```yaml
# compose.dev.yaml
volumes:
  mtmf-dev-keycloak-data:   # no project prefix -> shared by every Compose project
```

Verified by `podman volume ls` and `podman inspect`: the default and disposable projects both resolve the Keycloak data volume to a shared global name. An acceptance-only override (`compose.pr19c-acceptance.yaml`, `name: ${COMPOSE_PROJECT_NAME}_mtmf-dev-keycloak-data`) was added and does not change production definitions, but `podman-compose` 1.0.6 did not apply the rename reliably: the disposable Keycloak still mounted a shared/admin-mismatched volume, and admin authentication with the generated password failed (`HTTP 400 invalid_grant`).

## Exact evidence

- Default realm volume: `mtmf-dev-keycloak-data` (global, no project prefix).
- Disposable project keycloak volume observed: `mtmf_mtmf-dev-keycloak-data` (project name resolved to `mtmf`, not the acceptance project).
- `dev/keycloak/setup-realm.py` against the disposable Keycloak failed with `administrator authentication failed: HTTP 400 ... Invalid user credentials`.
- `mtmf-dev-stack.py` canonical issuer probe failed closed (`discovery returned HTTP 404`) rather than bypassing TLS.

## Minimum decision required

Choose one:

1. Approve making the Keycloak data volume project-scoped in the canonical Compose definition (a reviewed production Compose change), so `acceptance-pr19c --fresh` can create an isolated realm; or
2. Approve a dedicated acceptance Compose definition/volume and port set for PR 19C; or
3. Accept the canonical-stack live H01–H05 evidence as PR 19C live acceptance and scope the disposable cold-start orchestration to a follow-up.

No security invariant was weakened; the live feature acceptance passed. PR 19C remains **not DONE** until COLD/REPEAT/RECREATE reproducibility is executed or the human selects option 3.
