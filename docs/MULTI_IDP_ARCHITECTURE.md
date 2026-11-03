# Multi-IdP Authentication Architecture — External OIDC Issuers

> **STATUS: APPROVED DIRECTION; DESIGN-ONLY, NOT IMPLEMENTED (2026-11-02).**
> This is the planned extension of MTMF's existing provider-neutral
> `(issuer, subject)` bindings and global Principal/Identity model.
> One canonical Keycloak issuer is currently supported in the isolated
> development topology; multiple-issuer runtime acceptance, tenant IdP
> registration and account linking are future work. See
> [Startup Configuration Architecture](CONFIGURATION_ARCHITECTURE.md).

## 1. Goals and exclusions

The architecture will support:

1. Different approved external IdPs for different ordinary Tenants.
2. Multiple approved IdPs within the same ordinary Tenant.
3. One configured issuer accepted by multiple Tenants, with independent
   Tenant membership and authorization gates.
4. One global Principal holding multiple federated Identities, which are
   never collapsed into one authorization context.
5. A bootstrap IdP designated in the startup configuration; Keycloak
   remains the current local development issuer.
6. Standards-based OIDC issuers first; SAML may later be brokered or
   supported by separately reviewed adapters.

MTMF remains an OAuth-protected **resource server and authorization PDP**,
not an authorization server, password repository, refresh-token issuer, SAML
IdP, or substitute for a consumer's login/user-session implementation.
Consuming Applications use the versioned HTTP API only.

## 2. Trust and authorization boundaries

~~~text
  Configured issuer trust anchors (TOML; legacy env when no file)
                       |
            Verify signed service credential
                       |
                 Registered Application
                       |
       Independently verify signed acting-user proof
                       |
            Verified (issuer, opaque subject)
                       |
       ExternalSubjectBinding -> acting Identity
                       |
          Identity -> global Principal association
                       |
   Selected Tenant + both memberships + provider eligibility
                       |
      Application/Tenant subscription + exact authorization
                       |
         Authorization decision; consumer enforces
~~~

**Provider lookup MUST use the exact verified issuer**; an unverified `iss`
may identify candidate verification policy but is not proof. Validate signature,
algorithm, JWKS/discovery trust, expiration, not-before, audience, token type,
approved client/`azp` semantics, issuer and client lifecycle. Never try a
different provider as fallback when a token fails verification, and never
consider a configured/cryptographically valid issuer sufficient to authorize
an Application or a Tenant session.

Service and user proof are independent: service credentials identify the
registered Application, not an end user, Tenant, operator or root. Any
cross-issuer service/user pairing requires an **explicit approved pairing**
policy tied to the registered Application and the tenant's policy; an issuer
match, email match, supplied UUID or `client_id` cannot implicitly approve
the pair. Preserve PR 14's currently approved same-client development
semantics until their replacement is reviewed.

The existing Keycloak development policy includes exact issuer
attestation, realm-security projection, expected-client policy and a
least-privilege read-only attestation reader. New providers MUST implement an
approved, equivalent provider-specific security policy; a generic OIDC
signature check is not authorization to bypass these existing controls.
Unsupported issuer profiles fail closed.

## 3. Persistent identity semantics: no authorization union

The existing global identity model is authoritative:

- `ExternalSubjectBinding` maps the verified, immutable
  `(issuer, subject)` key to **one** MTMF Identity (active/revoked
  lifecycle and conflict detection).
- Each concrete Identity belongs to exactly one global Principal.
- Every Principal retains its mandatory MTMF-local, non-federated
  Identity; additional federated Identities are permitted.
- An explicit `(Tenant, Principal, acting Identity)` session requires valid
  active Principal- and Identity-Tenant membership.
- Roles, Groups, Permissions, stewardship-derived dominance and Tenant
  subscriptions remain separately governed; linking two Identities never
  unions their privilege or Tenant memberships.

A second Application using the *same verified issuer and subject* may
resolve the existing global Identity subject to Application eligibility
and tenant membership, as in the approved onboarding design. A login from
a *different* issuer is a distinct Identity unless an approved account-link
operation explicitly associates it with an existing Principal.

Emails, usernames, names, verified-email flags, domain names, display
attributes, or consumer-supplied Principal/Identity UUIDs MUST NOT
automatically merge subjects or link Principals. A future linking workflow
requires proof of both accounts (or narrowly authorized recovery), exact
Action authorization, audit, conflict/replay defenses, and explicit identity
and tenant membership handling. Linking, unlinking and issuer migrations
must not silently transfer old Role or stewardship assignments. Root
Identity binding changes are a separate privileged recovery problem.

## 4. Tenant policy and bootstrap

- A provider being **configured and trusted** means only that MTMF can
  validate its tokens under an approved policy. It does **not** make that
  provider automatically eligible for all Tenants.
- Each ordinary Tenant may accept zero or more named trusted IdPs, as
  explicitly configured/authorized. Authentication to a non-eligible
  issuer for the selected Tenant is rejected even when cryptographically valid.
- Multiple IdPs for one Tenant do not confer privileges across each other's
  Identities. Existing explicit Principal/Identity-Tenant membership is still
  required.
- Provider enable/disable, revocation and tenant assignment must be
  fail-closed and independently auditable. Never silently rewrite immutable
  subject bindings during issuer or key rotation.
- Pre-Tenant onboarding (PR 21/22B/23/24P/24) still uses its separately
  approved Application/user/entitlement admission and first-Tenant atomic
  transaction. The bootstrap IdP is **not** an automatic admission bypass.
- Protected SYSTEM/root Tenant remains unavailable for ordinary Application
  subscriptions and onboarding. Bootstrap IdP selection does not establish
  normal root authentication or operational recovery.

### 4.1 Database-backed provider catalog and TenantIdp association — approved direction

**Architectural decision (2026-11-02; NOT IMPLEMENTED):** support BOTH
file-declared and PostgreSQL-managed IdP configuration. TOML (or legacy
bootstrap environment fallback) establishes installation/bootstrap trust;
PostgreSQL is the authoritative administrative store for **dynamically**
registered IdPs and their ordinary-Tenant associations. A CLI must be able
to administer DB-managed settings through authenticated, authorized and
audited versioned HTTP management APIs; no CLI access to server files or
direct database operations.

The planned persistent model has two distinct concepts:

| Concept / proposed table | Required semantics |
| --- | --- |
| `IdentityProvider` / `identity_provider` | Global provider catalog: immutable provider UUID and exact canonical issuer, type (initially OIDC), source/provenance (`FILE_PINNED` or `DB_MANAGED`), approved verification/attestation policy, lifecycle/version and audit metadata. An issuer cannot silently be reused with incompatible trust policy. |
| `TenantIdp` / `tenant_idp` | Explicit association of target ordinary `tenant_id` with provider UUID; tenant-specific activation and permitted login/admission/assurance policy; source/provenance, lifecycle/version and audit metadata. No implicit association for all tenants and no implicit authorization or membership. |

Each provider may serve multiple Tenants; each Tenant may accept multiple
providers. Tenant-specific configuration cannot weaken the provider's global
issuer verification, client binding, signing, TLS or attestation requirements.
Use stable UUID references, uniqueness and current-row constraints, and
revocation-aware resolution; mutable names/emails are never keys.

**Source-of-truth and reconciliation rules:**

- File-defined bootstrap/provider trust anchors are protected and **cannot**
  be overwritten or disabled through ordinary CLI/API/database management.
  An explicitly privileged install/reconcile operation may materialize their
  immutable identities/provenance in the provider catalog to support foreign
  keys, but a mismatch requires operator intervention, not automatic repair.
- File-declared tenant associations, if supplied, are **file-pinned** and
  cannot be removed or changed by a delegated DB mutation. DB-managed tenant
  associations are changed through the authorized API. No file-versus-DB
  last-writer-wins precedence, silent source merge or deletion on omission.
- DB-managed additional providers may be registered and attached to covered
  tenants through separately authorized operations, after exact issuer and
  trust-policy verification. A manager cannot globally modify a shared
  provider used by an unrelated tenant; shared provider changes require a
  separately approved system-level authority or versioned migration.
- In the absence of the default TOML file, the **environment-sourced
  bootstrap** still works and the database MAY supply additional IdPs.
  Unavailability/corruption of the database or its authoritative policy is
  a fail-closed service/readiness condition, **never** a reason to ignore
  DB restrictions or fall back to file-only authorization.
- Database registration does not make a provider eligible for a Tenant:
  the `TenantIdp` association must be separately active, and existing
  Application/Tenant/Identity membership and authorization gates still apply.
  DB credentials and any secret references must remain restricted; no raw
  private secrets in catalog rows or API responses.

### 4.2 Mandatory separation of duties — managed tenants only

The target Tenant's own Tenant Administrator, Tenant Security Administrator,
and steward MUST NOT register/replace/disable the IdP trust or `TenantIdp`
associations for **that** Tenant merely through their local roles. This is a
management-plane operation, never authorized by ordinary target-Tenant
`tenant:update-object`, local Role policy or Tenant stewardship.

The allowed actor is either (a) an independently authenticated, authorized
SYSTEM/root operator exercising its approved management authority or (b)
an explicitly eligible acting Identity of a **different manager Tenant**
with an approved `TenantManagementGroup` covering the target ordinary Tenant.
Existing PR 11 safeguards all apply: no SYSTEM group self-management,
root-target management, cycles or transitive delegation; verified actor,
manager-side eligibility, active manager/target Tenants, explicit managed-
Tenant membership, contextual scope, **and** an exact matching Permission in
the SYSTEM-defined management Role are separately required.

**Critical implementation prerequisite:** PR 11's currently seeded management
Roles allow **only** `tenant:get-object`. They do NOT authorize IdP mutation.
A subsequent policy-design approval must define the exact distinct IdP
registration, provider trust mutation and `TenantIdp` assignment/revocation
Actions, management-role grants, target semantics, privileged execution
adapter and atomic mutation audit before any route is exposed. The
management relationship or CLI command alone grants nothing. A delegated
MSP may register a new issuer only through a target-bounded, approved
workflow and cannot thereby alter trust for other Tenants.

Changes must be serialized/optimistically versioned, audit both successes
and rejected sensitive attempts, deny self-authorization and unsafe
last-usable-provider removal, and explicitly provide controlled recovery
when tenant authentication would otherwise be locked out. External IdP
network verification happens **outside** a database UnitOfWork; authorized
MTMF state and its mutation audit are atomic. Database mutation uses the
existing reviewed least-privilege stored-function boundary, never direct
`mtmf_runtime` table DML.


## 5. Provider integration and lifecycle

OIDC is the first planned provider family. Each issuer needs explicit trust
and client/audience policy; provider-adapter interfaces belong **outside**
`MtmfSpi`. Keycloak-specific administration/attestation stays isolated in
the current development adapter. Enterprise IdP adapters may use a broker
(e.g. Keycloak) or direct issuer verification, but must retain upstream
identity provenance and exact trusted token issuer semantics.

No external IdP call is permitted inside an MTMF PostgreSQL UnitOfWork.
Remote IdP provisioning, linking, configuration changes, and retries may
eventually require durable reconciliation/outbox-style workflows with
security audit. They are not introduced here.

Startup configuration is initially static. Disabling an issuer or updating
trust configuration requires a controlled restart and reconciliation; MTMF
must not misrepresent offline issuer revocation as instantly known.
Any provider retirement or unlinking design must address existing
authoritative active bindings, tenant policies, active sessions, and
short-lived authorization snapshots.

## 6. Planned implementation and acceptance

**CFG-1 — TOML Configuration Foundation** (separate implementation PR):
implement [Startup Configuration Architecture](CONFIGURATION_ARCHITECTURE.md),
preserve one configured issuer and legacy environment fallback, normalize
configuration for service and initializer, and preserve all current Keycloak
validation/attestation. A file listing two providers is **not** silently
accepted as operational multi-IdP support.

**IDP-1 — Multi-IdP Authentication** (separate implementation PR; not a
v0.1 release requirement): add multi-issuer verification, strict issuer
and audience/client pairing, controlled tenant eligibility policy, and
trust-provider lifecycle policy using static/file-configured providers first.

**IDP-2 — Database IdP Registry, TenantIdp and Management** (separate
implementation PR, following IDP-1 and approved management-write gates):
implement verified DB-managed provider catalog, explicit `TenantIdp`
association/policy, file-pinned source protection, authorized SYSTEM/root and
cross-Tenant management APIs, atomic audit and CLI integration. Do not
implement database writes or HTTP mutations before exact Actions,
management Role grants, actor eligibility, privileged execution topology,
concurrency/reconciliation and audit are approved.

Mandatory deterministic and live-provider acceptance includes:

| Scenario | Expected |
| --- | --- |
| Same issuer/subject, different consuming Applications | Same mapped Identity, only with independent Application eligibility and Tenant membership |
| Same human, distinct issuer/subject pairs | Distinct Identities; no account merge by email |
| One Tenant accepting two approved issuers | Both can authenticate only with explicit tenant eligibility and memberships |
| Own Tenant Administrator/steward attempts IdP mutation | Deny regardless of ordinary Tenant permissions or stewardship |
| Eligible MSP manager mutates a covered TenantIdp | Permit only with exact management Role grant, identity eligibility, coverage, authoritative trust validation and audit |
| MSP manager targets an unmanaged tenant, its own manager Tenant, or root Tenant | Deny |
| DB provider conflicts with file-pinned issuer/association | Fail closed; no shadowing, implicit override or automatic repair |
| DB unavailable or corrupt during provider policy resolution | Fail closed; do not use an incomplete file-only view to grant authorization |
| Updating a globally shared provider via one tenant manager | Deny unapproved cross-Tenant effect; require separate system authority or safe versioning |
| Valid token from globally trusted but tenant-disallowed issuer | Reject before PDP / tenant session |
| Unknown issuer, duplicate issuer ID, wrong audience or `azp` | Reject; never fallback to bootstrap provider |
| Service token from issuer A with user token from issuer B | Reject unless an exact reviewed pairing policy explicitly permits it |
| Suspended/revoked provider or binding | Reject as policy requires; no cached indefinite ALLOW |
| Keycloak realm/client policy drift | Fail closed with current PR 14/17 attestation strength |
| Different Identities linked to one Principal | No Role, Group, Tenant membership or stewardship union |
| Issuer/JWKS outage, TLS failure, algorithm confusion, key rotation | Reject unverifiable proof; perform no unsafe repair |
| COLD/REPEAT/RECREATE and cross-Tenant/Root attempts | Stable approved bindings; no duplications or privilege escalation |

Required implementation STOPs: security-equivalent non-Keycloak
attestation; exact trust policies for issuer/client combinations; distinct
SYSTEM management Actions/grants and trusted operator adapter; protected
file-to-catalog reconciliation and source identity; DB-trust/secret handling;
last-provider lockout/recovery; safe linking/rebinding semantics; production
root continuity/recovery.
Escalate these for explicit review rather than guessing.

## 7. Current implementation boundary

PR 14 implements provider-neutral verification and authenticated actor
contracts for the approved development issuer; PR 17/17-C provide the
Keycloak-specific local topology and trust checks; PR 21 approved global
Identity reuse by a verified `(issuer, subject)`, and PR 22A supplies only
the operator-only onboarding entitlement persistence foundation.
**This documentation does not deliver a second runtime issuer, multi-IdP
tenant policy, linking API, database catalog, `TenantIdp` association,
CLI management command or root recovery mechanism.**

See also the [Security Model](SECURITY_MODEL.md),
[Onboarding Architecture](ONBOARDING_ARCHITECTURE.md),
[HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
and [Roadmap](ROADMAP_V01.md).
