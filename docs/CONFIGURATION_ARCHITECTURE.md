# MTMF Startup Configuration Architecture — TOML-first, Environment Fallback

> **STATUS: APPROVED DESIGN BASELINE — DOCUMENTATION ONLY; NOT IMPLEMENTED (2026-11-02).**
> This document specifies future configuration behavior, not the behavior of the
> currently deployed MTMF initializer, HTTP service, or Keycloak development launcher.
> The current PR 17/17-C environment-based local setup remains authoritative until
> an implementation PR passes its acceptance gates. See
> [Multi-IdP Architecture](MULTI_IDP_ARCHITECTURE.md),
> [Architecture](ARCHITECTURE.md), and [Development Setup](DEVELOPMENT_SETUP.md).

## 1. Decisions and scope

- **CFG-D01 — Primary source:** MTMF loads `/etc/mtmf/config.toml` at startup.
  `MTMF_CONFIG_PATH` MAY select a different absolute configuration file path.
- **CFG-D02 — Fallback:** if *and only if* the default file is absent and no
  explicit override path was supplied, MTMF uses the existing environment
  variables to construct a normalized, backward-compatible **single-issuer**
  configuration with a fixed internal bootstrap-provider ID (no untrusted
  issuer aliases). Existing environment-only startup continues to work.
- **CFG-D03 — Fail closed:** an existing but unreadable, nonregular, malformed,
  or invalid TOML file is a startup error, **not** a reason to use environment
  variables. An explicit `MTMF_CONFIG_PATH` pointing to a missing file is also
  an error. An empty/non-absolute override path is invalid.
- **CFG-D04 — No mixed authority:** for configuration sections that have moved
  to TOML, the file is the sole non-secret source when present. Do not merge
  `MTMF_AUTH_*` issuer/audience/trust values into a file-defined authentication
  section or treat environment values as overrides. Until other sections are
  migrated, existing dedicated environment-only deployment configuration
  remains in use *as such*, with explicit documented ownership; do not claim
  the first PR migrates database or deployment secrets.
- **CFG-D05 — General application configuration:** `config.toml` is MTMF's
  general configuration surface. Authentication is its first migrated section;
  future sections may include `[database]`, `[service]`, and
  `[observability]`, each with versioned schema and explicit migration gates.
  This is **not** the separate `mtmf-client` or CLI configuration contract.
- **CFG-D06 — Multi-provider shape:** the file can represent one or more
  named OIDC providers, with exactly one explicitly designated **bootstrap
  provider**. The initial configuration-foundation implementation MUST
  preserve **single-issuer authentication** and reject unsupported
  multi-provider operation until the Multi-IdP implementation is ready.
- **CFG-D07 — Trust changes:** issuer trust is immutable for a running process
  for the initial implementation. Configuration changes require restart and
  full revalidation; silent reloads, environment merges, and fail-open
  fallback are prohibited.
- **CFG-D08 — Secrets:** TOML contains no plaintext passwords, client
  secrets, signing keys, bootstrap credentials, or root recovery credentials.
  It MAY contain protected secret-file references or approved secret-manager
  references, resolved at the appropriate privilege boundary. Secret content
  MUST NOT appear in errors, logs, metrics, or configuration diagnostics.
- **CFG-D09 — Hybrid IdP configuration (future IDP-2):** after the
  installation/bootstrap trust anchors are loaded from TOML (or legacy
  environment fallback), PostgreSQL supplies additional DB-managed
  providers and explicit `TenantIdp` associations. Both sources may coexist.
  A file-defined provider or association is pinned and cannot be
  overridden through database administration; conflicts fail closed.
- **CFG-D10 — Management without file access:** authorized SYSTEM/root or
  eligible managing-Tenant actors may administer DB-owned provider/tenant
  policy through versioned HTTP management APIs and `mtmf-cli`, subject to
  exact management Permissions, separate operator execution boundaries and
  audit. The ordinary target Tenant's own administrators have no such
  mutation authority. This is a post-v0.1 design, not available today.

## 2. Deterministic source-selection procedure

| Condition | Required behavior |
| --- | --- |
| No `MTMF_CONFIG_PATH`; readable regular default file exists | Parse and validate file; use normalized file configuration |
| No `MTMF_CONFIG_PATH`; default file absent | Parse legacy environment variables and construct equivalent single-issuer configuration |
| No `MTMF_CONFIG_PATH`; default file exists but is invalid/unreadable | Fail startup; no environment fallback |
| Explicit nonempty absolute `MTMF_CONFIG_PATH`; file exists | Parse and validate exactly that file |
| Explicit override path missing, unreadable, invalid, or not absolute | Fail startup; no environment fallback |
| Empty `MTMF_CONFIG_PATH` value | Fail configuration validation; do not guess |
| File valid and legacy authentication environment variables also set | File wins for migrated authentication settings; do not merge or silently override |
| Either source lacks mandatory trust/credential settings | Fail startup; no default wildcard issuer/audience |

Source selection, parsing, schema validation, normalization, secret-reference
validation and issuer policy validation occur **before** service readiness,
authentication, or any configuration-dependent privileged mutation. After
IDP-2, the trusted file/environment bootstrap source and database-managed
IdP registry are **additive, not fallback substitutes**: database failure
or an unsafe file-versus-DB conflict must not cause MTMF to ignore DB policy
and authorize from an incomplete file-only view. The
initializer and service MUST consume the same normalized meaning, although
their process privileges and secret visibility remain separate. The
development launcher must be explicitly adapted before it can use TOML; its
currently enforced canonical Keycloak issuer remains a live development
invariant until then.

An operator-supplied path must not cause MTMF to fall back to another file or
a second source. Diagnose the path or configuration problem without logging
secret values or token material.

## 3. Proposed TOML contract

The following is an **illustrative schema to implement and validate**, not a
currently accepted runtime file. Identifiers are stable configuration keys;
issuer strings are exact, case-sensitive security identifiers, not display
labels. Values for the second provider are illustrative placeholders.

~~~toml
[authentication]
bootstrap_provider = "keycloak-dev"

[[authentication.providers]]
id = "keycloak-dev"
type = "oidc"
enabled = true
issuer = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
jwks_uri = "https://keycloak.mtmf.test:28443/realms/mtmf-dev/protocol/openid-connect/certs"
service_audiences = ["mtmf-service-api"]
user_audiences = ["mtmf-user-api"]

[[authentication.providers]]
id = "entra-example"
type = "oidc"
enabled = true
issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0"
service_audiences = ["<registered-service-audience>"]
user_audiences = ["<registered-user-audience>"]
~~~

Acceptance of the second provider and its audience/client-binding behavior
requires the later Multi-IdP implementation. The current development
Keycloak realm security manifest, expected-client policy, attestation reader,
TLS trust and canonical hostname controls remain in force; merely declaring
`type = "oidc"` must **not** disable or bypass those checks. A provider-specific
attestation configuration/adapter schema must be reviewed prior to accepting
non-Keycloak issuers.

A later schema MAY declare pinned Tenant-to-provider associations (e.g.
`[[authentication.tenant_providers]]` with an authoritative Tenant UUID and
provider ID), but it must require explicit privileged reconciliation and
must never silently overwrite DB-managed policy or ordinary tenant
membership. Such TOML associations are not accepted by the current runtime
and are not part of CFG-1 implementation.

A production schema SHOULD define validation rules for exact provider IDs,
issuer URLs, TLS, trusted discovery/JWKS, service/user audiences, approved
algorithms, lifetime/skew limits, attestation policy, and trust-pairing
restrictions. Unknown security-sensitive fields, duplicate provider IDs,
duplicate issuers, an absent/disabled bootstrap provider, missing required
fields, or unsupported provider types must be rejected. No implicit default
provider, wildcard issuer, issuer alias, or auto-correction of mismatched
security policy is allowed. The file-mode `bootstrap_provider` field is mandatory; only the
legacy environment fallback synthesizes its fixed single-provider designation.

## 4. Bootstrap and identity semantics

The **bootstrap provider** is the named initial configured external
authentication authority. It is **not** the canonical root Principal,
protected LOCAL root Identity, root credential store, operator recovery
mechanism, or automatically an acceptable issuer for every ordinary Tenant.

MTMF continues to authenticate each Application through its separately
verified service credential and each acting user through a separately
verified assertion. Verified `(issuer, subject)` resolves to an existing
`ExternalSubjectBinding` and the acting global Identity. Neither
configuration source grants Tenant membership, Application subscription,
Role, Group membership, or stewardship. Refer to
[Multi-IdP Architecture](MULTI_IDP_ARCHITECTURE.md) and the
[Security Model](SECURITY_MODEL.md).

## 5. Ownership and migration

| Component | Future responsibility |
| --- | --- |
| MTMF startup configuration loader | Source selection, TOML parsing, schema validation and normalized provider settings |
| `mtmf-service` | Safe issuer/JWKS transport, verified service/user token handling, approved per-provider attestation, readiness |
| `mtmf-core` | Provider-neutral verification policy, authoritative bindings, actor composition and authorization invariants |
| Privileged initializer | Configured/bootstrap issuer verification and narrowly privileged bootstrap; no implicit runtime elevation |
| Keycloak development launcher | Preserve canonical TLS issuer and its existing controls until explicitly upgraded |
| `mtmf-client` / administrative CLI | Their own separately defined client/CLI configuration; no implicit reading of the server file |
| PostgreSQL IdP catalog / `TenantIdp` (IDP-2 only) | DB-managed issuer and Tenant policy; protected file-pinned anchors, explicit source provenance, fail-closed association resolution and audited mutation |

The configuration loader MUST NOT move IdP integrations behind
`MtmfSpi`, nor introduce remote IdP calls inside a PostgreSQL UnitOfWork.
An independent consuming application never reads MTMF server configuration
or accesses MTMF's database.

### Planned implementation PR: CFG-1 — TOML Configuration Foundation

1. Add a shared typed normalized configuration model and strict TOML reader;
   enforce the complete decision table in Section 2.
2. Preserve the legacy environment-only path (including exact PR 17-C
   Keycloak trust, distinct service/user audience and attestation checks).
3. Support **one** configured OIDC issuer for authentication; explicitly reject
   unsupported multiple configured issuers rather than silently ignoring them.
4. Integrate the service and privileged startup paths without exposing
   migrator/owner/bootstrap secrets to the HTTP runtime.
5. Provide a sample non-secret config, operational guidance, and deterministic
   validation/readiness tests. Preserve development launcher semantics until
   it is separately adapted.

**Acceptance:** file present/absent, override present/missing/malformed, unreadable
file, duplicate keys and IDs, duplicate issuers, missing bootstrap provider,
unknown types, conflicting environment values, secret redaction, single-issuer
parity, exact expected Keycloak issuer, COLD/REPEAT/RECREATE and negative
authentication tests. Do not claim multi-issuer runtime readiness.

### Planned implementation PR: IDP-1 — Multi-IdP Authentication

After CFG-1, support multiple OIDC issuers, bounded per-provider trust,
service/user issuer-pairing rules and tenant-provider eligibility for
file-configured providers as specified in
[Multi-IdP Architecture](MULTI_IDP_ARCHITECTURE.md).

### Planned implementation PR: IDP-2 — DB Registry and TenantIdp Management

After IDP-1 and explicit security approval of its write actions and execution
boundary, persist dynamically managed IdPs and `TenantIdp` associations in
PostgreSQL. Preserve file-pinned provider trust. Add management-only HTTP APIs
and CLI commands with exact management-role authorization, reviewed
stored-function privilege boundaries, atomic audit, conflict/recovery and
fail-closed DB unavailability behavior.

Do not scope these into PRs 22B, 23, 24P or 24–26 without an explicit separate
security approval.

## 6. Deferred decisions / mandatory STOP gates

The current documents do **not** approve or implement:

- exact persistent catalog/`TenantIdp` DDL, change-version and reconciliation
  implementation, beyond the approved source precedence and no-shadowing rule;
- exact management Action URNs, management Role grants, operator-adapter
  privilege boundaries, HTTP DTOs and CLI commands for IdP mutations;
- provider-specific attestation equivalence for Entra ID, Okta, or any
  non-Keycloak issuer, including discovery/client binding and revocation;
- exact client-credential issuer/acting-user issuer pairing beyond the
  already approved single-issuer development profile;
- operational production root login, cross-IdP root failover or recovery;
- automatic reload/rotation of trust configuration, secret material, or
  persisted issuer bindings.

An implementation agent encountering any of these unresolved cases MUST stop
and request a reviewed security/design decision rather than inventing an
implicit default, weakening attestations, or silently migrating subjects.

## 7. Documentation status

This document defines future architecture only. No TOML loader, new
`MTMF_CONFIG_PATH` parser, multiple-issuer verifier, runtime registry,
`TenantIdp` table or management CLI is claimed to exist. Existing `.env.example` and
[Development Setup](DEVELOPMENT_SETUP.md) remain the operational truth for
the current local Keycloak stack.
