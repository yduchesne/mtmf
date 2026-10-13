# PR 17-C Amendment 1 — Security Review

## Canonical issuer and JWKS invariants (now enforced)

- `MTMF_AUTH_ISSUER` must equal the literal
  `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`. The launcher helper
  `_require_canonical_issuer()` uses string equality (no substring, prefix,
  suffix, case, whitespace, trailing-slash, query, fragment, userinfo, default
  port, or URL normalization) and runs **before** certificate generation,
  Compose startup, Podman inspection, database-URL rewriting, or any mutation.
- The failure diagnostic contains the expected canonical value only; the
  untrusted supplied value is never echoed (it could embed credentials).
- The probe independently enforces the same literal issuer in
  `_parse_issuer()` (`CANONICAL_ISSUER`), so a matching mocked/live discovery
  document cannot admit a caller-supplied non-canonical issuer. A unit test
  asserts `stack.CANONICAL_KC_ISSUER == probe.CANONICAL_ISSUER`.
- The discovered `jwks_uri` must equal exactly
  `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/protocol/openid-connect/certs`
  (`_require_expected_jwks_uri()`), checked **before** any JWKS request. No
  `startswith`, `urljoin`, hostname-only comparison, percent decoding, or
  relative URL is accepted.
- Discovery `issuer` remains an exact equality check. `_fetch` still uses a
  CA-verified context, an explicit `HTTPSHandler`, redirects disabled, a 200-only
  status, and a bounded 256 KiB read. TLS verification is never disabled and
  there is no alternate issuer or JWKS fallback.

## Local PKI invariants (now fail-closed)

- **State classification** uses non-following `lstat` on the four authoritative
  components. `EMPTY` generates a complete set; `COMPLETE` is validated and
  reused unchanged; `PARTIAL` (1–3 components) and `NONREGULAR` (symlink,
  directory, device, FIFO) fail closed without generating or deleting anything.
- **COMPLETE BUT INVALID** (bad SAN, broken chain, key-pair mismatch,
  group/other-accessible private key) fails closed and is never regenerated.
- **Key-pair consistency** is verified independently for the CA
  (`dev-ca.crt`/`dev-ca.key`) and the leaf (`server.crt`/`server.key`) by
  comparing normalized public keys extracted with OpenSSL.
- **Hardened-leaf handling:** the hardened leaf key is owner-mapped to the
  Keycloak container UID and is intentionally unreadable by the host user. The
  pairing check retries the public-key extraction inside the rootless Podman
  user namespace (`podman unshare`) rather than widening key permissions. If the
  material cannot be verified, the check fails closed.
- **Private-key custody is unchanged:** CA key is host-owner-only `0600`,
  leaf key is host-mapped `0600`, the CA private key is never mounted into any
  container, and only the public CA certificate is mounted read-only. No private
  key content is printed or logged; OpenSSL output is suppressed.
- **Rotation** is explicit (`generate --rotate`), destructive, and documented as
  requiring the stack to be stopped. Normal `up` never rotates. An interrupted
  rotation leaves `PARTIAL` material that the next normal `generate` refuses to
  regenerate.
- **Stale serial:** `dev-ca.srl` is serial bookkeeping, excluded from
  classification and removed before a fresh CA is created, so it cannot
  associate a new CA with an old certificate.

## Preserved security guarantees

- Canonical TLS-transparent forwarder (no TLS termination), isolated `mtmf`
  Compose network, no host networking, forwarder never host-published,
  loopback-only host publications.
- Initializer remains the only holder of privileged credentials; the runtime
  service environment contains no migrator/admin/bootstrap/owner/development-user
  variables (verified live).
- PR 17-B provisioning, strict created-resource provenance, realm/client
  attestation, and OIDC validation are untouched.
- No schema, migration, stored function, grant, DTO, or authorization semantics
  were changed.

## Residual risk / notes

- The pre-existing launcher sequencing transient (final `compose up -d service`
  recreates Keycloak because the forwarder IP changes the config hash) can make
  an *immediate* post-`up` `preflight` fail with a transient connection reset
  until Keycloak is healthy. It is unrelated to issuer/JWKS/PKI hardening and is
  recorded in `PR17C_AMENDMENT1_STOP_DEVIATIONS.md`.
- Windows trust-store import and `/etc/hosts` remain operator-controlled; the
  amendment reads (never edits) the hosts mapping.
- Windows-browser N17/N18 remain **NOT EXECUTED**.
