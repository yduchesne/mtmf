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
| Public issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev` |
| JWKS URI | `https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/protocol/openid-connect/certs` |
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
`https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev`. Any other host, port,
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
- **Container probe times out** — the forwarder resolves `keycloak` once, caches the
  address, and re-resolves on a failed connect, so it no longer issues a DNS
  search query per request; `preflight`/`up` also retain a bounded probe retry as
  defense in depth. A persistent failure indicates a real problem with the
  `forwarder` container or the network, not a normal transient. This does **not**
  indicate Compose recreation and does not require restarting Keycloak.

`up-host-network` remains a documented development fallback; it is no longer
the normal path.

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

## Security and production boundary

The initializer is **development-only**, short-lived, and privileged. The long-running MTMF service and ATI must never receive Keycloak administrator, MTMF root, migrator, or database owner credentials. MTMF's protected root foundation is not the same as an automatically configured production root login; production root authentication and recovery are separate requirements. Production customer provisioning must use an explicitly authorized administrative workflow, **not** ordinary ATI startup or automatic environment-variable creation.

## Related documentation

- [Architecture](ARCHITECTURE.md) — why the components are separate and how authorization flows.
- [Roadmap](ROADMAP_V01.md) — PR 17-B status and acceptance expectations.
- [Keycloak development fixture](../dev/keycloak/README.md) — isolated local issuer used by existing tests and development setup.
- [Repository README](../README.md) — current build and test commands.
