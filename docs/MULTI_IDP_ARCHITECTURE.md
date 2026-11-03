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

A future database-backed issuer/tenant association registry is optional and
**not implemented or specified as a source of truth by this PR**.
If added later, its relationship to startup-configured immutable trust
anchors and protected operator actions needs explicit design approval.
Do not invent a management API, permissions, backing tables, or migration
from file to database yet.

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
trust-provider lifecycle policy. Do not treat this document as authorization
to implement database writes or new management APIs without approved exact
Actions, privilege boundaries, concurrency/rollback, and atomic audit.

Mandatory deterministic and live-provider acceptance includes:

| Scenario | Expected |
| --- | --- |
| Same issuer/subject, different consuming Applications | Same mapped Identity, only with independent Application eligibility and Tenant membership |
| Same human, distinct issuer/subject pairs | Distinct Identities; no account merge by email |
| One Tenant accepting two approved issuers | Both can authenticate only with explicit tenant eligibility and memberships |
| Valid token from globally trusted but tenant-disallowed issuer | Reject before PDP / tenant session |
| Unknown issuer, duplicate issuer ID, wrong audience or `azp` | Reject; never fallback to bootstrap provider |
| Service token from issuer A with user token from issuer B | Reject unless an exact reviewed pairing policy explicitly permits it |
| Suspended/revoked provider or binding | Reject as policy requires; no cached indefinite ALLOW |
| Keycloak realm/client policy drift | Fail closed with current PR 14/17 attestation strength |
| Different Identities linked to one Principal | No Role, Group, Tenant membership or stewardship union |
| Issuer/JWKS outage, TLS failure, algorithm confusion, key rotation | Reject unverifiable proof; perform no unsafe repair |
| COLD/REPEAT/RECREATE and cross-Tenant/Root attempts | Stable approved bindings; no duplications or privilege escalation |

Required implementation STOPs: security-equivalent non-Keycloak
attestation; exact trust policies for issuer/client combinations; tenant
provider assignment mutation authority; safe linking/rebinding semantics;
production root continuity/recovery; file-versus-registry precedence.
Escalate these for explicit review rather than guessing.

## 7. Current implementation boundary

PR 14 implements provider-neutral verification and authenticated actor
contracts for the approved development issuer; PR 17/17-C provide the
Keycloak-specific local topology and trust checks; PR 21 approved global
Identity reuse by a verified `(issuer, subject)`, and PR 22A supplies only
the operator-only onboarding entitlement persistence foundation.
**This documentation does not deliver a second runtime issuer, multi-IdP
tenant policy, linking API, dynamic registry or root recovery mechanism.**

See also the [Security Model](SECURITY_MODEL.md),
[Onboarding Architecture](ONBOARDING_ARCHITECTURE.md),
[HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
and [Roadmap](ROADMAP_V01.md).
