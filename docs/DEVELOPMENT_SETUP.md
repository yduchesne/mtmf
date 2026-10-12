# Development environment setup: Keycloak, MTMF, and consuming applications

This guide explains how to initialize a **local development environment** for MTMF and an application such as Agentic Threat Investigator (ATI). You do not need to know MTMF's internal database schema to understand the sequence. The automation described for **PR 17-B is planned, not yet implemented**.

## What each system does

| Component | Responsibility |
| --- | --- |
| **Keycloak** | Signs users in and assigns each account a stable, unique subject ID (`sub`). |
| **MTMF initializer** | A temporary, privileged setup job that creates/verifies the root foundation, customer Tenant, administrator, Application registration, subscription, and identity binding. |
| **MTMF HTTP service** | Answers authenticated authorization requests from applications; it is not a user-login service. |
| **ATI** | Owns its own investigation data, signs users in through Keycloak, asks MTMF for authorization decisions, and enforces them. |

A **Tenant** represents a customer. An **Application** represents a product such as ATI. A **subscription** associates the customer with that product. A **Principal/Identity** is MTMF's representation of an actor; the Keycloak subject links that representation to a real authenticated user.

## Recommended startup order

1. **Start Keycloak** and initialize/verify the development realm and approved OAuth clients.
2. **Create or verify the Keycloak development user** and obtain its real immutable `sub`. **Current state:** this user-provisioning step is manual or separately scripted; PR 17 does not create the user. **Planned PR 17-B:** the privileged one-shot initializer will perform it and verify any existing account.
3. **Run the privileged MTMF initializer once.** It creates or verifies the protected root foundation, an ordinary customer Tenant, its administrator identity and membership, the ATI Application, the customer's active subscription, and the external user binding to the real Keycloak `sub`. It must finish successfully before ATI starts.
4. **Start the MTMF HTTP service** with only its restricted runtime credentials; confirm readiness.
5. **Start ATI.** ATI uses its OAuth client and a signed end-user identity assertion when calling MTMF's versioned HTTP API. It must not use MTMF's database or privileged provisioning credentials.

### Configuration example (local development)

The following values illustrate the **existing PR 17 development fixture**, not a complete ready-to-run `.env`. You must also configure PostgreSQL, the Keycloak realm, issuer/audiences, approved OAuth clients, and secrets according to your local stack.

```dotenv
MTMF_DEV_TENANT_KEY=ati-dev
MTMF_DEV_TENANT_NAME=ATI Development Customer
MTMF_DEV_APPLICATION_KEYS=ati
# CURRENT PR 17: set this to the actual Keycloak user's immutable subject (sub), not its username.
MTMF_DEV_USER_SUBJECT=<actual-keycloak-user-sub>
```

**Planned for PR 17-B (not yet recognized by the existing initializer):**

```dotenv
MTMF_DEV_USER_USERNAME=ati-admin
MTMF_DEV_USER_EMAIL=ati-admin@example.test
MTMF_DEV_USER_PASSWORD_FILE=/run/secrets/mtmf-dev-user-password
MTMF_DEV_USER_CREATE=true
# Optional assertion only: must match the real Keycloak subject if supplied.
# MTMF_DEV_USER_SUBJECT=<expected-keycloak-sub>
```

The exact defaults and validation for these new variables will be specified and implemented in PR 17-B. Use an owner-protected secret file or Podman secret mount; do not put a real password in a committed `.env` or log output. The ATI client (`mtmf-ati` in the existing fixture convention) must also be present in the approved Keycloak client policy; setting `MTMF_DEV_APPLICATION_KEYS=ati` alone is not sufficient.

## What happens on restart or failure?

- **Normal restart:** verify existing Keycloak user and MTMF records; keep the same Keycloak `sub`, Tenant identity, and client credentials. No duplicate customer, user, or subscription should be created.
- **User exists:** verify the account; do not silently replace it or reset its password.
- **User is missing and creation is disabled:** stop with an actionable error; do not invent an MTMF subject.
- **Subject mismatch or conflicting MTMF binding:** stop and require explicit operator remediation.
- **Partial failure:** Keycloak and PostgreSQL cannot participate in one atomic transaction. The initializer must detect partial state and reconcile only when safe; it must not claim everything was rolled back.

## Security and production boundary

The initializer is **development-only**, short-lived, and privileged. The long-running MTMF service and ATI must never receive Keycloak administrator, root, migrator, or database owner credentials. MTMF's protected root foundation is not the same as an automatically configured production root login; production root authentication and recovery are separate requirements. Production customer provisioning must use an explicitly authorized administrative workflow, **not** ordinary ATI startup or automatic environment-variable creation.

## Related documentation

- [Architecture](ARCHITECTURE.md) — why the components are separate and how authorization flows.
- [Roadmap](ROADMAP_V01.md) — PR 17-B planned work and acceptance expectations.
- [Keycloak development fixture](../dev/keycloak/README.md) — isolated local issuer used by existing tests and development setup.
- [Repository README](../README.md) — current build and test commands.
