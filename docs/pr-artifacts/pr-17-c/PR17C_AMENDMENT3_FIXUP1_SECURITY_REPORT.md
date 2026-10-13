# PR 17-C Amendment 3 Fixup 1 — Security Report

## Preserved security invariants

- **Opaque TLS.** The forwarder imports no TLS library and performs no
  termination, decryption, rewriting, or protocol parsing; it moves raw bytes.
  TLS CA/SAN verification, exact discovery `issuer`, exact `jwks_uri`, and token
  `iss` remain canonical (verified live).
- **Single canonical issuer.** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`
  unchanged.
- **Isolation.** Forwarder `publish=none`, `privileged=false`; PostgreSQL,
  Keycloak and service host ports are loopback-only; no host networking.
- **Least privilege.** The runtime service environment contains no
  migrator/admin/bootstrap/owner/development-user variables.
- **Stable Compose.** No dynamic forwarder IP, no `extra_hosts`; three unchanged
  `up` cycles preserved all four container IDs/`StartedAt` with zero
  `podman stop`/`rm`.
- **No secrets in logs.** The only emitted lines are the bounded startup line,
  one bounded `unexpected pump error (<Type>)` diagnostic, and one configuration
  error line; no payloads, tokens, or credentials. Payload suppression is
  asserted by FX18/FX-U24.

## DNS hardening properties

- The resolver deadline is a real caller-facing bound; a stalled worker cannot
  block the listener indefinitely (FX-U06).
- The worker thread has **no path to mutate resolver state**; the cache commit
  occurs only in the awaiting coroutine and only when the invalidation
  generation is unchanged (FX-U07, FX-U08).
- `CancelledError` propagates; a cancelled caller cannot leave a stale commit
  (FX-U11).

## Cancellation/cleanup properties

- Every pump task is registered and joined before `_handle` returns, including
  cancellation during the wait, the drain window, a blocked `drain()`, or writer
  `wait_closed()` (FX-U19–FX-U22, FX-U26).
- Writers are closed and `wait_closed()` awaited under a bounded 2 s budget;
  cleanup cannot hang the handler (FX-U25).
- Expected disconnect errors are contained; an unexpected pump exception is
  surfaced, not silently swallowed, and cleanup still completes (FX-U24).

## Recovery administrator reconciliation (Part C) — read-only finding

Live master-realm inspection via the supported Admin REST API (no secrets
recorded):

```text
mtmf-pr14-admin2: enabled=True requiredActions=[] realmRoles=['admin','default-roles-master']
mtmf-pr14-admin : enabled=True requiredActions=[] realmRoles=['admin','default-roles-master']
admin2 authenticates with the current known credential: True
mtmf-pr14-admin authenticates with the current known credential: False
```

The original `mtmf-pr14-admin` is enabled and privileged, but its credential was
lost when the workstation crashed/rebooted and `/tmp` (holding the ephemeral
dev admin password) was cleared. It cannot be verified usable.

Per the fixup contract, **the original admin cannot be authenticated, so
`mtmf-pr14-admin2` was NOT disabled** — disabling it would remove the only
known working recovery route. The plan explicitly forbids changing admin
credentials or resetting the realm as a workaround, so no credential reset was
performed. This is a **STOP**; human action is required (recover/confirm the
original admin credential, or explicitly authorize disabling it and keeping the
recovery admin). See `PR17C_AMENDMENT3_FIXUP1_STOP_DEVIATIONS.md`.

No secret, password, token, or private key value was displayed or committed;
only enabled/required-action/role metadata was inspected.
