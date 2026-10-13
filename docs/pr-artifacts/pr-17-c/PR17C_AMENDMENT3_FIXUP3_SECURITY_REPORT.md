# PR 17-C Amendment 3 Fixup 3 — Security Report

## Issuer / JWKS / TLS

- Exactly one standard development issuer:
  `https://keycloak.mtmf.test:28443/realms/mtmf-dev`, with the exact JWKS
  endpoint `.../protocol/openid-connect/certs`. The launcher, initializer,
  probe, compose defaults, and `.env.example` agree on the realm `mtmf-dev`.
- The launcher enforces literal equality of `MTMF_AUTH_ISSUER`,
  `MTMF_AUTH_JWKS_URI`, and `MTMF_AUTH_ADMIN_REALM` before certificate
  generation, Compose, Keycloak Admin REST, or database writes. There is no
  alternate issuer, dual-realm compatibility, or `startswith` matching.
  Whitespace/case/scheme/host/port/lookalike/userinfo/trailing-slash variants
  fail closed without echoing the untrusted value.
- The initializer independently verifies the issuer path is exactly
  `/realms/mtmf-dev` before any mutation; the probe re-verifies live discovery
  issuer, JWKS endpoint, CA and SAN.
- Live confirmation: discovery `issuer`, `jwks_uri`, and token `iss` are exactly
  canonical; the old realm returns HTTP 404 in the fresh volume and no
  old-issuer token is accepted.

## Secret isolation

- The long-running HTTP service receives no master-admin, migrator, owner, or
  bootstrap credential (verified live). The `mtmf-admin` credential is confined
  to the Keycloak bootstrap and the privileged one-shot initializer.
- No secret appears in git, reports, argv, or subprocess output. Passwords are
  supplied via environment/owner-only `_FILE` only.
- The development admin credential remains held outside ephemeral `/tmp`
  (development-only limitation; operator must use a password manager).

## Volume / project scope

- The fixup never reset, renamed, imported, or mutated the persistent
  `mtmf-dev-keycloak-data` / `mtmf_mtmf-postgres-data` volumes or the
  independent `mtmf-pr14-keycloak-data` volume.
- The fresh-environment acceptance used disposable MTMF-owned resources
  (`mtmf-fixup3-*` volumes) that were removed afterwards; the operator and PR 14
  volumes remain. No cross-project prune or foreign-resource action occurred.
- Standard `up` against the old-realm volume fails closed with an actionable
  error and does not auto-create `mtmf-dev`, repoint bindings, or reset accounts.

## Preserved security baseline

- Forwarder opaque TLS, loopback-only publications, rootless Podman, and
  MTMF-owned Compose isolation are unchanged.
- The realm attestation projection and expected-client policy are unchanged
  except the standard-stack manifest's realm name; no policy was weakened and
  no attestation bypass was introduced.
- Client IDs, audiences, mappers, role grants, root/Tenant initialization, and
  runtime privilege boundaries are unchanged.

## N17/N18 (human decision required)

Windows-browser N17/N18 acceptance remains **not executed**. A prior amendment
reclassified them as optional manual workstation smoke tests; that
reclassification was not based on a clear explicit user approval. This fixup
does **not** re-modify the gate and records it as a **human-review decision** in
the STOP/deviation register. No Windows browser testing is claimed.
