# PR 17-C Security Review

## Invariants preserved

- **Strict OIDC trust:** issuer equality, expected audience, RS256 signature/JWKS
  verification, Keycloak realm/client attestation, and TLS hostname/CA verification
  remain mandatory. No `verify=False`, `curl -k`, issuer rewriting, permissive aliases,
  or HTTP canonical issuer exists.
- **Canonical hostname ↔ SAN agreement:** the leaf carries
  `DNS:keycloak.mtmf.test` (+ `localhost`, `IP:127.0.0.1` for the documented loopback
  fallback). `mtmf-dev-certs.py check` fails closed on a missing canonical SAN.
- **Private-key custody:** the CA key stays owner-only (`0600`, host user). The leaf key
  is `0600` and owner-mapped to the Keycloak container UID with `podman unshare chown`;
  if the mapping fails, the helper fails closed rather than widening permissions. The
  CA private key is never mounted into any container; the initializer/service receive
  only the public CA certificate read-only.
- **Least privilege:** the one-shot initializer keeps the only migrator/bootstrap
  credentials. `podman inspect mtmf_service_1` confirms the runtime environment has no
  migrator/admin/bootstrap/owner/development-user variables and mounts only the public
  CA.
- **Resource isolation:** only the explicit `mtmf` Compose project is managed. No
  wildcard prune, discovery, or mutation of ATI/Digr/Darkula/Hammeridian resources.
- **No host networking** for the standard `up`; every introduced publication is
  loopback-only and the forwarder is unpublished.
- **Domain/contracts unchanged:** no schema, migration, stored function, grant,
  authentication/authorization domain object, Rust evaluator, API DTO, or PR 17-B
  provisioning/recovery behavior was changed.

## Controlled decisions requiring reviewer attention

### 1. Approved development authority set (was loopback-only)

`IssuerConfig` and `HttpAdminRestReader` previously required a loopback issuer/admin
base. PR 17-C centralises the allowed set in
`mtmf_service/authentication/development_authority.py`:

```text
APPROVED_DEVELOPMENT_HOSTS = {127.0.0.1, localhost, ::1, keycloak.mtmf.test}
```

`keycloak.mtmf.test` is the explicit canonical development authority. Any other host
(including `evil.keycloak.mtmf.test` and arbitrary remote IdPs) remains rejected;
HTTPS is still required where it was. This is a narrow, development-only expansion
required by the PR's canonical-issuer design, not a relaxation of OIDC/TLS checks or a
production trust change. The same approved host was added to the standalone PR 14
evidence collector `Issuer.guard()` so the authoritative live regression suite can run
against the canonical authority without `--allow-nonlocal`; arbitrary non-loopback
hosts remain rejected there too.

### 2. Host `/etc/hosts` shadowing of the container network alias

Rootless Podman copies the host `hosts` file into containers. The operator
`127.0.0.1 keycloak.mtmf.test` entry therefore appears inside containers and can
shadow the MTMF network alias. The initializer and service are given an explicit
`extra_hosts` mapping to the forwarder IP (resolved by the launcher after the forwarder
is healthy). Podman writes `--add-host` entries before copied entries, so the canonical
mapping wins. This is a correctness control, not a trust bypass: TLS and issuer
verification still run against the real Keycloak certificate. The container path no
longer depends on host DNS.

### 3. Forwarder trust boundary

The forwarder is a raw TCP byte pipe. It terminates no TLS, inspects no payload,
performs no policy/DNS rewriting, logs no payload, and exposes no admin or health HTTP
surface. It is unprivileged, never host-published, and lives only on the isolated
`mtmf_default` network. It does not create a second issuer. A bounded target-connect
retry avoids dropping requests during a Keycloak restart; it never falls back to
another host or disables verification.

### 4. Loopback-only PostgreSQL publication

`compose.yaml` changed `"${MTMF_POSTGRES_PORT:-25432}:5432"` to
`"127.0.0.1:${MTMF_POSTGRES_PORT:-25432}:5432"`. This closes a pre-existing
all-interfaces exposure and matches the loopback-only invariant. Port, volume, data,
and role topology are unchanged.

### 5. Subprocess output redaction

`podman-compose` echoes the fully substituted `podman run` command, including
environment secrets. The launcher now captures subprocess output and redacts every
value whose environment name contains `PASSWORD`/`SECRET`/`TOKEN` or ends in
`DATABASE_URL` before printing it. This prevents bootstrap-admin, migrator, runtime,
and client secrets from reaching logs.

## Residual risks / notes

- The container probe (`resolve_host`) may list both the shadowed loopback entry and
  the forwarder address; `socket.create_connection`/`urllib` fail over to the
  reachable forwarder. The `extra_hosts` mapping remains authoritative for the
  initializer/service because Podman writes it first.
- The Windows trust-store import and `/etc/hosts` mapping are operator-controlled and
  are not automated by this PR.
- The realm and approved clients remain a one-time operator prerequisite
  (`dev/keycloak/setup-realm.py`); the launcher does not create them.
- Windows-browser TLS/auth-code acceptance (N17/N18) was not executed and is not
  claimed.
