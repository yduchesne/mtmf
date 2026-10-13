# PR 17-C Amendment 3 Fixup 2 — Baseline Report

**Branch:** `dev/pr17c-keycloak-issuer`
**Base revision:** `2515ca5b8659dd0b513ad67712168ef9b4079723` (Amendment 3 Fixup 1)
**Comparator:** `main` = `669337c1b496a5660d36e5d72cff5544f6c04722`
**Date:** 2026-10-13
**Environment:** Ubuntu 24.04.5 WSL2; rootless Podman 4.9.3; `podman-compose`
1.0.6; Keycloak `26.8.0-1`; Python 3.14.7.
**Canonical issuer:** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`.

## Status at baseline

- Working tree clean; `2515ca5` is the branch tip; `main` does not contain the
  PR 17-C forwarder, so this is a branch follow-up.
- Fixup 1 left the recovery-admin reconciliation as a **STOP**: both
  `mtmf-pr14-admin` and `mtmf-pr14-admin2` were enabled master admins, but only
  `mtmf-pr14-admin2` authenticated (the original `mtmf-pr14-admin` credential
  was lost in the earlier host crash).
- The standard-stack Keycloak bootstrap used
  `MTMF_PR14_KC_ADMIN_USERNAME` (default `mtmf-pr14-admin`) and the initializer
  used `MTMF_AUTH_ADMIN_USERNAME/PASSWORD`; the initializer environment also
  carried an unused `MTMF_PR14_KC_ADMIN_*` pair.

## Read-only account inspection (CA-I01)

Executed with the working recovery administrator `mtmf-pr14-admin2`:

```text
mtmf-admin       : ABSENT
mtmf-pr14-admin  : enabled=true  federated=false requiredActions=[] roles=[admin, default-roles-master]
mtmf-pr14-admin2 : enabled=true  federated=false requiredActions=[] roles=[admin, default-roles-master]
```

## Confirmed gaps this fixup addresses

| Gap | Evidence |
| --- | --- |
| Standard stack used a PR-numbered bootstrap administrator | `compose.dev.yaml` Keycloak bootstrap defaulted to `mtmf-pr14-admin` |
| No canonical-name guard | The launcher did not validate the bootstrap admin identity |
| Legacy administrators unresolved | Fixup 1 STOP: two enabled legacy admins, only one credential known |
| No explicit migration path | No tooling to create/verify a canonical admin on an existing volume |

## Existing tests run at baseline

`tests/unit/service/test_pr17c_dev_stack.py` and the full unit suite passed on
the base tip (Fixup 1: 2065 tests, coverage 90.75%). This fixup adds the
canonical-admin configuration tests (CA-U01–CA-U08) and the migration state
machine tests (CA-U09–CA-U32).

## Preserved behavior (not re-litigated)

Amendment 1 exact issuer/JWKS/PKI, Amendment 2 stable Compose lifecycle,
Amendment 3/Fixup 1 forwarder reliability, the PR 14 evidence-only fixture
(`dev/keycloak/compose.yaml`, `setup-realm.py`, collectors), and the canonical
issuer/TLS/authorization semantics were preserved and re-verified on the fixup
tip.
