# PR 17-C Amendment 3 Fixup 3 — Implementation Report

## Canonical realm contract

```text
realm   : mtmf-dev
issuer  : https://keycloak.mtmf.test:28443/realms/mtmf-dev
jwks    : https://keycloak.mtmf.test:28443/realms/mtmf-dev/protocol/openid-connect/certs
admin   : mtmf-admin (master realm, unchanged)
```

## Files changed

| File | Change |
| --- | --- |
| `scripts/mtmf-dev-stack.py` | `CANONICAL_KC_ISSUER` → `mtmf-dev`; added `CANONICAL_KC_REALM` + `CANONICAL_KC_JWKS_URI`; `_require_canonical_issuer()` now enforces all three exactly (no whitespace stripping) and is called by `up` and `up-host-network` before any side effect |
| `scripts/mtmf-dev-probe.py` | Canonical issuer/JWKS → `mtmf-dev` (exact issuer + exact JWKS already enforced) |
| `scripts/mtmf-dev-initialize.py` | Both `MTMF_AUTH_ADMIN_REALM` fallbacks → `mtmf-dev`; new `_require_realm_matches_issuer()` fail-closed check before Keycloak Admin REST/DB work |
| `scripts/mtmf-dev-admin-migrate.py` | `TARGET_REALM` → `mtmf-dev` |
| `.env.example` | Issuer/JWKS/realm → `mtmf-dev` |
| `compose.dev.yaml` | Initializer and service `MTMF_AUTH_ADMIN_REALM` defaults → `mtmf-dev`; comment updated |
| `dev/keycloak/expected-realm-security.json` | Standard-stack manifest `"realm"` → `mtmf-dev` (the independent PR 14 manifest is separate) |
| `docs/DEVELOPMENT_SETUP.md` | Canonical realm section: provisioning command (`--realm mtmf-dev`), existing-volume STOP, explicit clean-reset procedure, identity/subject consequences, credential custody |
| `dev/keycloak/README.md` | Standard-stack cross-reference updated to `mtmf-dev`; fixture instructions and cert CN preserved |
| Standard-stack tests | `test_pr17c_dev_stack/probe/forwarder/reliability` constants → `mtmf-dev`; new `test_pr17c_dev_realm.py` (CR-U01–CR-U30) |
| Standard-stack live harnesses | `test_pr17_live_http`, `test_pr17b_live_acceptance`, `test_pr17_attestation_reader_permissions`, `pr17b_fault_proxy` realm driven by `MTMF_AUTH_ADMIN_REALM` with `mtmf-dev` default; `test_pr14_live_actor_context` default preserved as `mtmf-pr14-dev` |

## Preserved architecture

- Forwarder (`mtmf-dev-forwarder.py`), certs, `dev/nsswitch.conf`,
  `compose.yaml`, and the PR 14 evidence-only fixture are unchanged.
- No new provisioning architecture: the launcher keeps realm provisioning as a
  documented one-time operator prerequisite; the initializer fails closed if the
  issuer's realm segment is not exactly `mtmf-dev`.
- No dual-issuer compatibility, no automatic realm creation in `up`, no
  automatic migration or reset of an existing volume.

## Reset

No destructive reset was performed (no operator authorization). The existing
`mtmf-dev-keycloak-data` and `mtmf_mtmf-postgres-data` volumes remain as-is;
after this change standard `up` against them fails closed with an actionable
error until the operator performs the documented clean reset.
