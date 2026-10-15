# Development environment setup: Keycloak, MTMF, and consuming applications

This guide explains how to initialize a **local development environment** for MTMF and an application such as Agentic Threat Investigator (ATI). You do not need to know MTMF's internal database schema to understand the sequence. The **PR 17-B development user provisioning step is implemented**; the running MTMF HTTP service and ATI never hold privileged setup credentials.

## What each system does

| Component | Responsibility |
| --- | --- |
| **Keycloak** | Signs users in and assigns each account a stable, unique subject ID (`sub`). |
| **MTMF initializer** | A temporary, privileged setup job that creates/verifies the development user, the root foundation, customer Tenant, administrator, Application registration, subscription, and identity binding. |
| **MTMF HTTP service** | Answers authenticated authorization requests from applications; it is not a user-login service. |
| **ATI** | Owns its own investigation data, signs users in through Keycloak, asks MTMF for authorization decisions, and enforces them. |

A **Tenant** represents a customer. An **Application** represents a product such as ATI. A **subscription** associates the customer with that product. A **Principal/Identity** is MTMF's representation of an actor; the Keycloak subject links that representation to a real authenticated user.

## Recommended startup order

1. **Start Keycloak** and initialize/verify the development realm and approved OAuth clients (see the [Keycloak development fixture](../dev/keycloak/README.md)).
2. **Run the privileged MTMF initializer once.** It performs the realm/issuer preflight, creates or verifies exactly one Keycloak development user, reads Keycloak's authoritative immutable `sub`, and then creates or verifies the protected root foundation, an ordinary customer Tenant, its administrator identity and membership, the registered Application, the customer's active subscription, and the external user binding to the real Keycloak `sub`. It must finish successfully before the service or the application starts.
3. **Start the MTMF HTTP service** with only its restricted runtime credentials; confirm readiness.
4. **Start ATI.** ATI uses its OAuth client and a signed end-user identity assertion when calling MTMF's versioned HTTP API. It must not use MTMF's database or privileged provisioning credentials.

With `scripts/mtmf-dev-stack.py`, these steps are ordered automatically: `keycloak -> initializer -> HTTP service`. The initializer is a one-shot container that exits before the unprivileged service starts; the service is not declared ready unless the initializer exited successfully.

## Canonical issuer and development networking (PR 17-C)

The standard development stack uses **one canonical Keycloak authority**:

| Item | Canonical value |
| --- | --- |
| Keycloak hostname | `keycloak.mtmf.test` |
| Public issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-dev` |
| JWKS URI | `https://keycloak.mtmf.test:28443/realms/mtmf-dev/protocol/openid-connect/certs` |
| Keycloak admin base | `https://keycloak.mtmf.test:28443` |
| Keycloak internal HTTPS | `8443` (unchanged) |

A **single authority is not the same as a single IP address**. DNS may resolve the
hostname differently in each namespace, provided the TLS endpoint, hostname and
issuer are identical everywhere:

- **Windows browser / WSL2 host** resolve `keycloak.mtmf.test` to `127.0.0.1`
  through an operator-managed `hosts` entry and reach the loopback-published
  Keycloak `28443` port.
- **MTMF containers** resolve `keycloak.mtmf.test` through the MTMF-owned
  `forwarder` network alias. The forwarder is non-privileged, never
  host-published, and forwards bytes on the canonical port `28443` to
  Keycloak's internal `8443` **without terminating TLS**, so certificate,
  hostname/SAN and issuer validation remain intact and no second issuer exists.

### Operator host mapping

Add the mapping once on **both** the Windows host and the WSL2 Ubuntu host
(administrator/root only for the `hosts` edit):

```text
127.0.0.1 keycloak.mtmf.test
```

- Windows: `C:\Windows\System32\drivers\etc\hosts`.
- WSL2 Ubuntu: `/etc/hosts`. WSL regenerates `/etc/hosts` on some restarts; if
  the entry disappears, re-add it (or configure a WSL `hosts` generator) rather
  than exposing ports on all interfaces.

Do **not** copy the WSL `/etc/hosts` into containers. Containers use the MTMF
network alias, not host loopback.

### Local development CA and TLS trust

Generate the disposable development CA and the `keycloak.mtmf.test` leaf
(private keys stay uncommitted and are never mounted into the runtime):

```bash
uv run --no-sync python scripts/mtmf-dev-certs.py generate
uv run --no-sync python scripts/mtmf-dev-certs.py harden   # owner-map the leaf key to the Keycloak container UID
uv run --no-sync python scripts/mtmf-dev-certs.py check
```

`harden` fails closed rather than making the leaf key world-readable; if Podman
cannot map the key to the Keycloak container UID, stop and fix the user
namespace mapping. Import the **public** `$(MTMF_DEV_CA_DIR)/dev-ca.crt`
(default `/tmp/mtmf-dev-ca/dev-ca.crt`) into the Windows trusted root store
(operator-controlled) and into the WSL trust store so the browser and host-side
checks verify TLS. Only the public CA certificate is mounted into the
initializer and service at `/certs/mtmf-ca.crt`.

Certificate generation is **idempotent only for a complete, validated set**.
The four authoritative components are `dev-ca.key`, `dev-ca.crt`, `server.key`,
and `server.crt`. `generate` classifies the directory and fails closed without
generating or deleting anything when the state is:

- **partial** (1–3 components present, e.g. after an interrupted operation), or
- **non-regular** (a managed path is a symlink, directory, or device), or
- **complete but invalid** (bad SAN, broken chain, mismatched CA/leaf key pair,
  or group/other-accessible private key).

`dev-ca.srl` is serial bookkeeping and is ignored for classification; a stale
serial on an otherwise empty directory is removed before a fresh CA is created
and can never associate a new CA with an old certificate.

Recover a partial or invalid directory deliberately, with the stack stopped:

```bash
uv run --no-sync python scripts/mtmf-dev-stack.py down           # stop first; volumes preserved
uv run --no-sync python scripts/mtmf-dev-certs.py generate --rotate
uv run --no-sync python scripts/mtmf-dev-stack.py up
```

`--rotate` is destructive (it removes the previous CA and leaf before creating
a replacement) and must only be run while the stack is stopped. If a rotation
is interrupted, the directory is partial and the next normal `generate`/`up`
fails closed until the operator completes an explicit rotation. Regenerating
the material or changing the hostname requires refreshing the Windows/WSL trust
stores; the canonical SAN must always agree with the canonical hostname.

`MTMF_AUTH_ISSUER` must equal the exact canonical issuer
`https://keycloak.mtmf.test:28443/realms/mtmf-dev`. Any other host, port,
scheme, realm, trailing slash, query, fragment, or userinfo is rejected before
certificate generation, Compose startup, or database rewriting.

### Start, verify and stop

```bash
set -a && . ./.env && set +a
uv run python scripts/mtmf-dev-stack.py up          # canonical, isolated Compose path (no host networking)
uv run python scripts/mtmf-dev-stack.py preflight   # re-run host + container issuer preflight only
uv run python scripts/mtmf-dev-stack.py status
uv run python scripts/mtmf-dev-stack.py down         # stop; volumes/data preserved
```

The launcher prepares the certificate material, starts PostgreSQL, Keycloak and
the forwarder, waits for real health, proves the canonical issuer from **both**
the host and container namespaces, runs the privileged initializer exactly
once, then starts the restricted service and waits for
`http://127.0.0.1:28001/health/ready`. `up` refuses a non-canonical
`MTMF_AUTH_ISSUER` with literal string equality (no substring/prefix acceptance).

**Stable lifecycle (PR 17-C Amendment 2).** The Compose model contains no
dynamic container address, so the configuration hash is invariant across the
phases of one `up` and across repeated `up` runs. Once PostgreSQL, Keycloak and
the forwarder have started, a normal `up` does not recreate or restart them:
repeated `up` preserves the same container IDs and `State.StartedAt`
timestamps. The initializer remains intentionally rerunnable.

Containers resolve `keycloak.mtmf.test` through `dev/nsswitch.conf`, a static
resolver override mounted at `/etc/nsswitch.conf` that makes MTMF DNS
authoritative over the host `/etc/hosts` entry Podman copies into the
container. This keeps the canonical name pointing at the current forwarder
without baking any IP into the Compose configuration. Do not add
`MTMF_DEV_FORWARDER_IP`-style dynamic values to `compose.dev.yaml`.

The realm and approved clients are still a one-time operator prerequisite (see
the [Keycloak development fixture](../dev/keycloak/README.md)); they persist in
the `mtmf-dev-keycloak-data` volume across restarts.

### Diagnostics and recovery

- **`does not resolve`** — add the operator `hosts` mapping on the reported
  namespace and re-run `preflight`.
- **TLS/CA failure** — the `dev-ca.crt` is not trusted (import it) or the leaf
  was regenerated (refresh trust). The tooling never falls back to an insecure
  or unverified connection.
- **`discovery issuer mismatch`** — the live Keycloak hostname does not equal
  the configured trust anchor; fix the Keycloak hostname or the MTMF issuer,
  never rewrite the issuer.
- **`JWKS ... contains no signing keys`** — the realm is missing or not
  configured; restore the realm before restarting.
- **`refusing to remove ...`** — MTMF ownership labels do not match; the
  resource is foreign and is never removed.
- **Container probe times out** — the forwarder resolves `keycloak` once with a
  bounded (default 2 s, `MTMF_DEV_FORWARDER_RESOLVE_TIMEOUT`) deadline, caches the
  address, and re-resolves on a failed connect, so it no longer issues an
  unbounded DNS search query per request; `preflight`/`up` also retain a bounded
  probe retry as defense in depth. A persistent failure indicates a real problem
  with the `forwarder` container or the network, not a normal transient. This
  does **not** indicate Compose recreation and does not require restarting
  Keycloak.

`up-host-network` remains a documented development fallback; it is no longer
the normal path.

## Canonical development Keycloak administrator (`mtmf-admin`)

The standard development stack uses **one** canonical Keycloak master-realm
administrator, `mtmf-admin`. It is strictly a development bootstrap/operator
identity and is distinct from every other actor:

| Concept | Value |
| --- | --- |
| Canonical development master-realm administrator | `mtmf-admin` (Keycloak `master` realm) |
| Development end user | `MTMF_DEV_USER_USERNAME` (e.g. `ati-admin`) in realm `mtmf-dev` |
| Keycloak development realm | `mtmf-dev` |
| MTMF root identity | the protected canonical root Principal/Identity (not a Keycloak admin) |
| Read-only service attestation credential | least-privilege client `mtmf-attestation-reader` (no admin password) |

Configuration:

- `MTMF_DEV_KC_ADMIN_USERNAME` — defaults to `mtmf-admin`. The launcher rejects
  an explicit empty/whitespace/uppercase value or a PR-numbered legacy name
  (`mtmf-pr14-admin`, `mtmf-pr14-admin2`) **before** certificates, Compose or
  database writes.
- `MTMF_DEV_KC_ADMIN_PASSWORD` — required at runtime; supplied from a password
  manager/approved store, never committed. Environment-variable exposure is a
  development-only limitation.
- `MTMF_AUTH_ADMIN_USERNAME` / `MTMF_AUTH_ADMIN_PASSWORD` — the privileged
  one-shot initializer's Admin REST credential. It must refer to the **same**
  `mtmf-admin` account and credential; the launcher enforces this.

### Fresh volume vs existing volume

- **Fresh volume:** the Keycloak bootstrap creates `mtmf-admin` from
  `MTMF_DEV_KC_ADMIN_PASSWORD`. Nothing else is required.
- **Existing volume:** bootstrap variables **do not** rename or reset existing
  users. Run the explicit, operator-supervised, development-only migration:

```bash
# Read-only inspection (default)
uv run python scripts/mtmf-dev-admin-migrate.py --inspect
# Explicit migration: create/verify mtmf-admin, then disable (not delete) the
# legacy PR-numbered administrators after independent verification.
MTMF_DEV_KC_ADMIN_PASSWORD="$MTMF_DEV_KC_ADMIN_PASSWORD" \
MTMF_DEV_KC_RECOVERY_PASSWORD="$MTMF_DEV_KC_RECOVERY_PASSWORD" \
  uv run python scripts/mtmf-dev-admin-migrate.py --apply
```

Passwords are read only from the environment or an owner-only
`MTMF_DEV_KC_*_PASSWORD_FILE`; they are never passed on the command line,
printed, or committed. The migration never resets an existing account's
password and never disables the last verified enabled administrator. If the
recovery credential is unavailable, `mtmf-admin` cannot be independently
verified, an account is federated/has required actions/has unexpected roles, or
an outcome is ambiguous, the tool **stops** without further mutation.

**Credential custody and rollback:** keep the `mtmf-admin` credential in a
password manager/approved secret store (not `/tmp`). The operational rollback
for a failed migration is to re-enable a legacy administrator **only while an
independently verified administrator is still working**; there is no password
recovery for a disabled account, so re-enable it before losing access.

## Canonical development realm (`mtmf-dev`) and clean reset

The standard development stack uses one realm, `mtmf-dev`; the canonical issuer
is `https://keycloak.mtmf.test:28443/realms/mtmf-dev`. The separate PR 14
evidence-only fixture (`dev/keycloak/`) intentionally remains on
`mtmf-pr14-dev` and is not part of the standard stack. The launcher enforces the
exact issuer, JWKS endpoint, and realm before any side effect.

### Provisioning the realm (one-time operator prerequisite)

The launcher does not create the realm. On a fresh or reset environment,
provision `mtmf-dev` and its approved clients **before** `up`, explicitly
passing the realm:

```bash
uv run --no-sync python dev/keycloak/setup-realm.py \
  --base https://keycloak.mtmf.test:28443 \
  --realm mtmf-dev \
  --ca-file "$MTMF_PR14_KC_CA_FILE" \
  --allow-nonlocal
```

Then `up` runs the privileged initializer, which fails closed unless the
issuer's realm segment is exactly `mtmf-dev`.

### Existing-volume STOP and explicit clean reset

A persistent volume created for the old `mtmf-pr14-dev` realm is **not** migrated
automatically. After this change, a standard `up` against such a volume fails
closed with an actionable error; it never auto-creates `mtmf-dev`, repoints
existing identity bindings, or resets accounts.

Converting an existing development environment is a destructive,
explicitly operator-approved clean reset. It is **not** performed by the tooling
and must never be automated. Consequences: Keycloak user `sub` values, client
secrets, and MTMF identity bindings all change, and existing development data is
discarded.

Operator procedure (MTMF-only):

1. Confirm you may permanently discard the current MTMF development Keycloak and
   PostgreSQL state.
2. Record the standard `mtmf` Compose project's exact containers and volumes;
   keep the separate `mtmf-pr14-keycloak` evidence volume.
3. `uv run python scripts/mtmf-dev-stack.py down` (preserves volumes).
4. Remove only the explicitly confirmed standard-stack volumes
   (`mtmf-dev-keycloak-data`, `mtmf_mtmf-postgres-data`). Do not remove
   `mtmf-pr14-keycloak-data` or host CA material.
5. Prepare a new securely held `mtmf-admin` credential outside `/tmp`.
6. Start the clean stack, provision `mtmf-dev` (above), and run `up`.
7. Verify discovery `issuer`, `jwks_uri`, and token `iss` are exactly the
   canonical `mtmf-dev` values; no old-issuer token is accepted.

## Development user configuration

The development one-shot reads the following variables. They are **not** part of the runtime `ServiceSettings`, so the long-running HTTP service never receives them.

| Variable | Required | Behavior |
| --- | --- | --- |
| `MTMF_DEV_USER_USERNAME` | Yes | Exact Keycloak username to create or verify. Must be lowercase, trimmed, and free of control characters and `/ \ ? #`. No fabricated default. |
| `MTMF_DEV_USER_EMAIL` | No | Expected email. Compared case-insensitively against the existing account; a mismatch fails closed. It is an attribute consistency check, **not** proof of email control, and is never a lookup fallback or identity key. |
| `MTMF_DEV_USER_CREATE` | No | Explicit `true` or `false`; **default `false`**. Creation is opt-in. Unknown values fail configuration validation. |
| `MTMF_DEV_USER_PASSWORD_FILE` | Only when creating a missing user | Container path to the initial password file (see the secret-file rules below). Read only when a user must be created. |
| `MTMF_DEV_USER_SUBJECT` | No | Optional assertion. When non-empty it must equal Keycloak's actual user ID; a mismatch stops before any MTMF binding. Empty is treated as unset. |

### Example: verify an existing user (creation disabled)

```dotenv
MTMF_DEV_TENANT_KEY=ati-dev
MTMF_DEV_TENANT_NAME=ATI Development Customer
MTMF_DEV_APPLICATION_KEYS=ati
MTMF_DEV_USER_USERNAME=ati-admin
MTMF_DEV_USER_EMAIL=ati-admin@example.test
MTMF_DEV_USER_CREATE=false
```

### Example: create a user when missing

```dotenv
MTMF_DEV_USER_USERNAME=ati-admin
MTMF_DEV_USER_EMAIL=ati-admin@example.test
MTMF_DEV_USER_CREATE=true
MTMF_DEV_USER_PASSWORD_FILE=/run/mtmf-secrets/dev-user-password
```

The initializer never resets or changes the password of an existing user. For a newly created user, the initial password is non-temporary (so local sign-in works immediately) and Keycloak marks the account enabled. Do **not** enable direct-access (password) grants on approved clients merely to make login easier; use the realm's approved browser/OIDC flow.

### Email verification and creation provenance

- **Email is not automatically verified.** A newly created user is submitted with `emailVerified=false`; the initializer has not proven control of the configured address. An existing account's `emailVerified` state is never modified, and a valid existing account is not rejected merely because its email is unverified. An email match remains an attribute consistency check only.
- **Existing account reuse is an operator-approved trust decision** within the isolated development realm. When exactly one exact-username account already exists, it is validated read-only (immutable `id`, `enabled`, non-federated, optional email/subject checks) and reused. It is never repaired, renamed, or password-reset.
- **A create is bound only with authoritative provenance.** After a successful create, the account read back must match the immutable user id in Keycloak's own `Location` response header, and only an absolute location naming exactly `/admin/realms/<realm>/users/<id>` on the trusted Keycloak admin origin is accepted. A successful create with a **missing, malformed, foreign-origin, wrong-realm, or wrong-resource** `Location` stops initialization; Keycloak may nevertheless contain the account, and a subsequent run verifies and reuses it without resetting credentials. A conflict (`409`) or an uncertain create (timeout / lost response / transport failure / server error) is accepted only when `MTMF_DEV_USER_SUBJECT` is supplied and equals the authoritative subject; otherwise the initializer fails closed and performs no MTMF write. A later rerun reuses the now-existing account under the read-only rule above.
- **A definite rejection (`400`/`401`/`403`/`422`, etc.) always fails closed.** A matching username that appears afterwards is never treated as proof that this invocation created it, and is not bound.

## Secret file setup

Plaintext passwords must never appear in `compose.dev.yaml`, a committed `.env`, or command-line arguments. The initializer opens the configured file **once** with `O_NOFOLLOW` (no final-component symlink) and validates it with `fstat` on that same descriptor before reading a bounded number of bytes from it, so a path substitution between validation and reading cannot be observed. The file must be:

- a **regular file** (not a symlink, FIFO, device, or directory);
- owned by the initializer user and **not group- or other-accessible** (`0600`, or owner-only under a `0700` directory);
- non-empty, at most 8192 bytes, and valid UTF-8 (no NUL bytes).

Create it once, for example:

```sh
install -d -m 0700 /tmp/mtmf-dev-secrets
printf '%s' 'a-development-only-password' > /tmp/mtmf-dev-secrets/dev-user-password
chmod 600 /tmp/mtmf-dev-secrets/dev-user-password
```

Compose mounts `$MTMF_DEV_SECRET_DIR` (default `/tmp/mtmf-dev-secrets`) read-only at `/run/mtmf-secrets`; the default container password path is therefore `/run/mtmf-secrets/dev-user-password`. This directory is MTMF-owned and is never shared with another application's resources.

## Behavior on restart or failure

- **Normal restart:** the initializer verifies the existing Keycloak user and the existing MTMF records. It keeps the same Keycloak `sub`, Tenant identity, Application subscription, and client credentials. No duplicate user, Tenant, Identity, or subscription is created.
- **User exists:** identity and expected attributes are verified; the password file is not even opened, and no password/attribute/role/MFA change is made.
- **User is missing and creation is disabled:** initialization stops with an actionable error; no MTMF subject is invented.
- **User is disabled, drifted, federated, or ambiguous:** initialization stops and performs no repair.
- **Subject assertion mismatch or conflicting MTMF binding:** initialization stops before writing MTMF state and requires explicit operator remediation.
- **Partial failure:** Keycloak and PostgreSQL cannot commit atomically. If a create committed but its response was lost (or the outcome is otherwise uncertain), the initializer fails closed without a second POST and without binding a merely-visible username; a later rerun reuses the now-existing account without resetting its password, or the operator supplies `MTMF_DEV_USER_SUBJECT`. No cross-system rollback is claimed.

## Troubleshooting

- **"no Keycloak user matches ... and creation is not enabled":** the username is wrong, or the user has not been created. Set `MTMF_DEV_USER_CREATE=true` with a valid password file, or create the user in the realm first.
- **"the configured development Keycloak user email does not match":** the existing account's email differs from `MTMF_DEV_USER_EMAIL`. Correct the configuration or the account; the initializer will not silently rewrite the account.
- **"the configured MTMF_DEV_USER_SUBJECT assertion does not match":** the asserted subject is not the actual Keycloak user ID. Clear the assertion or correct it.
- **"the live issuer does not match the configured trust anchor":** `MTMF_AUTH_ISSUER` and the reachable Keycloak realm disagree.
- **"the development issuer preflight failed with HTTP ...":** the Keycloak admin credential, base URL, or TLS trust is wrong. The HTTP service must never be given this credential.

To obtain the actual subject for manual troubleshooting, query the Admin REST API with the privileged admin credential and inspect the user's `id` field (never paste an access token or password into a report):

```sh
curl -sk -X POST "$MTMF_AUTH_ADMIN_BASE/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$MTMF_AUTH_ADMIN_USERNAME&password=$MTMF_AUTH_ADMIN_PASSWORD" > /dev/null
# then GET /admin/realms/<realm>/users?username=<user>&exact=true with the bearer token
```

## Official Python client (`mtmf-client`) local configuration

The official consumer client is an HTTPS-only library. It never disables
TLS verification, so for the local development stack it must be given the
disposable development CA (`MTMF_DEV_CA_DIR/dev-ca.crt`) through
`ca_bundle` (or the process trust store via `SSL_CERT_FILE`). The
client's token endpoint and issuer are the canonical development values:

| Setting | Development value |
| --- | --- |
| MTMF base URL | `https://<mtmf-service>` (v1 route is `/v1/authorization/evaluate`) |
| Token endpoint | `https://keycloak.mtmf.test:28443/realms/mtmf-dev/protocol/openid-connect/token` |
| Expected issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-dev` |
| CA bundle | `$(MTMF_DEV_CA_DIR)/dev-ca.crt` |
| Service credential | a development OAuth client id + an owner-only secret file |
| Acting user | a separately obtained end-user access token, propagated in `X-MTMF-User-Authorization` |

The client stores no OAuth refresh token and will not fall back to an
unverified TLS connection. The client currently caps every authorization
snapshot at the 15-second security-sensitive ceiling because the
authoritative Action sensitivity classifier is not a public contract. See
[packages/mtmf-client/README.md](../packages/mtmf-client/README.md).

Run the opt-in real-topology slice with:

```sh
MTMF_PR18_LIVE=1 uv run --no-sync pytest \
  tests/integration/postgres/test_pr18_live_client.py --no-cov
```

## Opt-in observability stack (PR 19)

The MTMF-owned telemetry stack is an **opt-in overlay** on the canonical
`mtmf` Compose project. Normal development startup is unchanged and does not
start it. Supply a development-only Grafana password and start it explicitly:

```sh
MTMF_GRAFANA_ADMIN_PASSWORD=<dev-only> python scripts/mtmf-observability.py up
python scripts/mtmf-observability.py status
python scripts/mtmf-observability.py down   # removes only the observability services
```

`down` removes only the observability services; it never removes the project
network, named volumes, or any other project service, and it never touches
resources owned by another application. There is no broad `down --volumes`.

| Component | Host publication (loopback only) | Notes |
|---|---|---|
| Collector OTLP gRPC | `127.0.0.1:24317` | Optional; the service uses `collector:4317` in-network |
| Collector health | `127.0.0.1:24318` | Built-in `health_check` extension (`/health/status`); the distroless image cannot run a shell healthcheck |
| Prometheus | `127.0.0.1:29090` | Scrapes the Collector's Prometheus exporter |
| Jaeger UI | `127.0.0.1:21686` | OTLP trace receiver is internal |
| Grafana | `127.0.0.1:23000` | Fixed datasource UIDs `mtmf-prometheus`, `mtmf-jaeger`, `mtmf-loki`; dashboards `mtmf-overview`, `mtmf-authorization`, `mtmf-security`, `mtmf-dependencies` |
| Loki | none | Internal-only; reachable through the authenticated Grafana datasource proxy |

Enable service export by setting `MTMF_OTEL_ENABLED=true` and
`MTMF_OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317` (see `.env.example`).
Export is bounded and asynchronous; a Collector outage must not change an
authorization response. The development Grafana/Loki credentials and the
default Loki retention are development controls, **not** production security
or compliance controls. Run the opt-in live slice with:

```sh
MTMF_PR19_LIVE=1 uv run --no-sync pytest \
  tests/integration/postgres/test_pr19_live_observability.py --no-cov
```

## Security and production boundary

The initializer is **development-only**, short-lived, and privileged. The long-running MTMF service and ATI must never receive Keycloak administrator, MTMF root, migrator, or database owner credentials. MTMF's protected root foundation is not the same as an automatically configured production root login; production root authentication and recovery are separate requirements. Production customer provisioning must use an explicitly authorized administrative workflow, **not** ordinary ATI startup or automatic environment-variable creation.

## Related documentation

- [Architecture](ARCHITECTURE.md) — why the components are separate and how authorization flows.
- [Roadmap](ROADMAP_V01.md) — PR 17-B status and acceptance expectations.
- [Keycloak development fixture](../dev/keycloak/README.md) — isolated local issuer used by existing tests and development setup.
- [Repository README](../README.md) — current build and test commands.

## PR 19C acceptance-only isolated stack

A separate, isolated acceptance topology exists for the PR 19C live management
acceptance. It never uses, stops, or mutates the default `mtmf` development stack.

- Project: `mtmf-pr19c-acceptance`; Compose model: `compose.pr19c-acceptance.yaml` alone.
- Issuer: `https://keycloak.mtmf.test:29443/realms/mtmf-dev`; Keycloak published only on
  `127.0.0.1:29443`; PostgreSQL on `127.0.0.1:29432`; service on `127.0.0.1:29001`.
- Both data volumes are project-scoped (no global `name:`), so the canonical
  `mtmf-dev-keycloak-data` realm volume is never reused.
- Own CA (`/tmp/mtmf-pr19c-acceptance-ca`) and secrets
  (`/tmp/mtmf-pr19c-acceptance-secrets`); generated secrets are owner-only and redacted
  from all output.

Commands:

```
uv run python scripts/mtmf-pr19c-live.py preflight   # read-only validation
uv run python scripts/mtmf-pr19c-live.py up          # create CA/secrets + isolated stack
uv run python scripts/mtmf-pr19c-live.py test        # run H01-H05 against it
uv run python scripts/mtmf-pr19c-live.py down        # stop containers, keep volumes
uv run python scripts/mtmf-pr19c-live.py reset       # DESTRUCTIVE: remove acceptance volumes + secrets
uv run python scripts/mtmf-dev-stack.py acceptance-pr19c   # cold -> repeat -> recreate
```

`reset` is destructive but scoped strictly to the verified acceptance project and its two
volumes; it refuses any mismatched ownership and never touches the default stack. The
default host ports (25432/28443/28001) are untouched by acceptance.

## PR 20A reference application (`mtmf-reference-app`)

The independently deployable reference consumer lives at
[`examples/mtmf-reference-app`](../examples/mtmf-reference-app/README.md). It is a real
Policy Enforcement Point (PEP): it owns a minimal Tenant-scoped Document store, verifies
the inbound end-user access token at its own boundary, calls MTMF only through the
official `mtmf-client` HTTP library, and enforces the returned decision before disclosing
any body. It imports no `mtmf-core`/`mtmf-service` and never opens an MTMF database
connection.

Its isolated acceptance topology is separate from both the default stack and the PR 19C
stack, and never mutates them.

- Project: `mtmf-pr20a-acceptance`; Compose model: `compose.pr20a-acceptance.yaml` alone.
- Issuer: `https://keycloak.mtmf.test:29543/realms/mtmf-dev`; PostgreSQL on
  `127.0.0.1:29532`; restricted MTMF service on `127.0.0.1:29501`; reference app on
  `127.0.0.1:29511`.
- The `mtmf-client` HTTPS requirement is met by an internal development-only TLS
  terminator; TLS verification is never disabled.
- Own CA (`/tmp/mtmf-pr20a-acceptance-ca`), secrets
  (`/tmp/mtmf-pr20a-acceptance-secrets`), and non-secret fixtures
  (`/tmp/mtmf-pr20a-acceptance-fixtures`).

Commands:

```
uv run python scripts/pr20a-reference-acceptance.py preflight    # read-only validation
uv run python scripts/pr20a-reference-acceptance.py up           # CA/secrets + full isolated stack + seed
uv run python scripts/pr20a-reference-acceptance.py test         # run L01-L05 against it
uv run python scripts/pr20a-reference-acceptance.py down         # stop containers, keep volumes
uv run python scripts/pr20a-reference-acceptance.py recreate     # DESTRUCTIVE: remove acceptance volumes + fixtures
uv run python scripts/pr20a-reference-acceptance.py acceptance   # cold -> repeat -> recreate
```

See [docs/pr-artifacts/pr-20a/](pr-artifacts/pr-20a/) for the executed acceptance evidence.

### PR 20B deployed conformance and resilience

PR 20B reuses the same isolated `mtmf-pr20a-acceptance` topology and adds a
bounded multi-document batch route plus black-box lifecycle, subscription,
spoofing, cross-Tenant, revocation, and concurrency conformance. It does not
change any production MTMF package, migration, or protected policy.

```
uv run python scripts/pr20b-reference-acceptance.py preflight    # delegate to PR 20A preflight
uv run python scripts/pr20b-reference-acceptance.py up           # PR 20A stack + PR 20B fixture seed
uv run python scripts/pr20b-reference-acceptance.py test         # PR 20A L01-L05 + PR 20B conformance
uv run python scripts/pr20b-reference-acceptance.py down         # stop the acceptance project
uv run python scripts/pr20b-reference-acceptance.py recreate     # DESTRUCTIVE: acceptance-only reset
uv run python scripts/pr20b-reference-acceptance.py acceptance   # cold -> repeat -> recreate
```

Follow-up 01 adds a genuine metadata-only Document operation
(`urn:mtmf:iam:actions:system:document:read-metadata`), a mixed-operation
`POST /v1/documents/batch-access` route, a real mixed ALLOW/DENY deployed proof,
deployed remote-fault scenarios, and the deferred spoofing cases.

- `scripts/pr20b_metadata_fixture.py` registers the approved metadata Action,
  TENANT-defined metadata-reader Role, and deterministic Alice/Bob assignments
  through sanctioned stored functions as the authenticated `mtmf_migrator`.
- `compose.pr20b-fault-acceptance.yaml` + `scripts/pr20b-fault-proxy.py` add an
  acceptance-only deterministic fault fronting component on a **distinct**
  CA-signed hostname (`mtmf-fault.mtmf.test`); the launcher applies it on every
  `up()` and removes it on `down()`/`recreate()`. The canonical
  `mtmf.mtmf.test` terminator is untouched and TLS verification is never
  disabled.
- Lifecycle/subscription/Role transitions use the privileged, acceptance-only
  one-shot helper `scripts/pr20b_fixture_transitions.py`, which calls only
  sanctioned stored functions as the authenticated `mtmf_migrator` identity and
  verifies the connected database before mutating.

See [docs/pr-artifacts/pr-20b/](pr-artifacts/pr-20b/) for the executed evidence and
the explicit P0 STOP on mixed-batch disclosure.
