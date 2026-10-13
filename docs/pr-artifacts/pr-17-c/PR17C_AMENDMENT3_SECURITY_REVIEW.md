# PR 17-C Amendment 3 — Security Review

## Invariants preserved

- **Opaque end-to-end TLS.** The forwarder imports no TLS library
  (`import ssl`/`ssl.` absent) and performs no termination, decryption,
  rewriting, or protocol parsing. It moves raw bytes on a TCP socket, so
  Keycloak's certificate, SAN, and issuer validation remain end to end.
- **Single canonical issuer.** `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`
  is unchanged; the probe's exact issuer/JWKS checks (Amendment 1) are untouched
  and still enforced (live discovery `issuer`, `jwks_uri`, token `iss` exact).
- **Isolation.** The forwarder is internal-only, unprivileged, MTMF-owned, not
  host-published (`publish=none`), and never reached via host networking. Other
  applications' Podman resources were not touched.
- **Stable Compose.** No dynamic forwarder IP, no `extra_hosts`, no config-hash
  drift; the Amendment 2 static resolver model is unchanged and the launcher
  does not cache or inject an address.
- **Least privilege.** The runtime service still receives only the restricted
  runtime credential and read-only attestation-reader secret; no
  migrator/admin/bootstrap/owner credential is present.

## Bounded resources and lifecycle

- Each client has a bounded first-byte wait, a bounded per-attempt target
  connect (5 s) with at most 3 attempts, and an explicit teardown:
  cancel-the-peer, `gather(return_exceptions=True)`, `close()`, and
  `await wait_closed()` on both writers.
- `_pipe` suppresses only expected disconnect errors (`OSError`,
  `IncompleteReadError`) and calls `write_eof()` only when
  `can_write_eof()`; unexpected exceptions are not silently swallowed.
- Per-client `OSError` is contained so a client cannot terminate the listener;
  `CancelledError` propagates for correct task cancellation.
- Streaming/backpressure is preserved (`read(65536)` + `write` + `await drain`);
  no whole-response buffering.

## Address cache

`_TargetResolver` caches the resolved Keycloak address and invalidates it on any
connect failure, so a rebuilt Keycloak is re-resolved rather than assumed to keep
its IP. This is an address cache, not shared connection state: no socket, reader,
or writer is reused between clients. The cache is warmed at startup so the first
request does not pay the resolver search-query cost. The plan's "no global
mutable connection state" is respected.

## No secrets / bounded logging

- The module emits exactly one non-secret startup line; there is no per-request
  or payload logging (FW18 asserts a distinctive payload never appears in
  output).
- No TLS payloads, HTTP headers, credentials, tokens, certificate keys, or
  sensitive URLs are logged.
- Live forwarder logs since restart: no tracebacks and no payloads.

## Residual notes

- The forwarder remains a development-only component; it is not a production
  reverse proxy and adds no authentication/authorization surface.
- The host-crash recovery added a second master-realm admin
  (`mtmf-pr14-admin2`) via Keycloak's supported `bootstrap-admin user` command;
  no volume was deleted and the realm/clients were untouched. See the deviation
  register.
