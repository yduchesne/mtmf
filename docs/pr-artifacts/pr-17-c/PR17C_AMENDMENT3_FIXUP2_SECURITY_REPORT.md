# PR 17-C Amendment 3 Fixup 2 — Security Report

## Preserved security invariants

- **Canonical issuer/TLS.** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`
  unchanged; discovery `issuer`, `jwks_uri`, and token `iss` remain exact
  (verified live); CA/SAN/SJWKS verification and exact JWKS endpoint unchanged.
- **Isolation.** Forwarder `publish=none`/`privileged=false`; PostgreSQL,
  Keycloak and service host ports loopback-only; no host networking.
- **Least privilege.** The long-running HTTP service environment contains **no**
  `mtmf-admin` credential: only non-secret routing config
  (`MTMF_AUTH_ADMIN_BASE`, `MTMF_AUTH_ADMIN_REALM`) and the restricted runtime /
  read-only attestation-reader credentials. The migration and bootstrap
  credentials are confined to the Keycloak bootstrap and the privileged
  one-shot initializer.
- **Stable Compose.** After the one expected configuration transition (renamed
  bootstrap variables), three unchanged `up` cycles preserved all four container
  IDs/`StartedAt` with zero `podman stop`/`rm`.
- **Authorization semantics, PostgreSQL, realm, clients, signing keys, and the
  development end user (`sub`) unchanged.**

## Administrator migration security properties

- **One canonical administrator.** Exactly one enabled development master-realm
  administrator (`mtmf-admin`) with the required `admin` role and no unexpected
  extra roles.
- **Legacy accounts disabled, not deleted.** `mtmf-pr14-admin` and
  `mtmf-pr14-admin2` remain present and disabled; the migration never removes a
  user.
- **Never disable the last working admin.** Before each disable the tool
  verifies another independently enabled administrator exists; a failed disable
  stops before the next mutation.
- **No credential reset.** An existing canonical account is reused without
  touching its password; the tool never resets an existing account.
- **Ambiguity fails closed.** Duplicate usernames, create 409/timeout/lost
  Location, missing privileged reads, federation, required actions, unexpected
  roles, and authentication failures all STOP without further mutation.
- **Transport.** The migration uses HTTPS with the development CA, rejects
  non-HTTPS and a missing/untrusted CA, disables redirect following, and bounds
  every response.
- **No secret disclosure.** Passwords are read only from the environment or an
  owner-only `_FILE`; they are never accepted as CLI arguments, printed, or
  written to reports. Error messages were verified not to contain credentials.

## Credential custody

The `mtmf-admin` credential is stored in an owner-only file outside ephemeral
`/tmp` (`~/.config/mtmf/dev-admin.env`, `0600`, not committed). Runtime
environment-variable exposure is a **development-only limitation**; the
operator's source of truth must be a password manager/approved secret store.
No password, bearer token, client secret, or private key appears in any
committed report, log, git object, or the runtime service environment.

## Residual notes

- The pre-existing temporary bootstrap recovery admin is retired by Keycloak
  once a permanent admin exists; this is an environment behavior, recorded in
  the deviation register, not a source vulnerability. It is the reason the
  first `--apply` returned non-zero after successful mutations.
- This is local development environment work, not a production root-account
  recovery design.
