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

## Development user configuration

The development one-shot reads the following variables. They are **not** part of the runtime `ServiceSettings`, so the long-running HTTP service never receives them.

| Variable | Required | Behavior |
| --- | --- | --- |
| `MTMF_DEV_USER_USERNAME` | Yes | Exact Keycloak username to create or verify. Must be lowercase, trimmed, and free of control characters and `/ \ ? #`. No fabricated default. |
| `MTMF_DEV_USER_EMAIL` | No | Expected email. Compared case-insensitively against the existing account; a mismatch fails closed. Never a lookup fallback or identity key. |
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

## Secret file setup

Plaintext passwords must never appear in `compose.dev.yaml`, a committed `.env`, or command-line arguments. The initializer accepts a read-only mount and validates the file before reading it:

- it must be a **regular file** (not a symlink or directory);
- it must be owned by the initializer user and **not group- or other-accessible** (`0600`, or owner-only under a `0700` directory);
- it must be non-empty, bounded in size, and valid UTF-8.

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
- **Partial failure:** Keycloak and PostgreSQL cannot commit atomically. If Keycloak user creation succeeded but MTMF initialization failed, the Keycloak account remains; a later rerun verifies that same account and completes reconciliation without resetting its password. No cross-system rollback is claimed.

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
