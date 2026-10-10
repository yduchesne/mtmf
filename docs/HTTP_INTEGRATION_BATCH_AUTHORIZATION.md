# HTTP Integration and Batch Authorization — v0.1 Normative Design Contract (PR 12)

> **STATUS: NORMATIVE DESIGN CONTRACT — RUNTIME NOT IMPLEMENTED; SECURITY DECISIONS APPROVED.**
> This document is the PR 12 normative contract for the planned HTTP-only
> consumer integration. No Application registry, Tenant subscription,
> trusted HTTP actor propagation, batch endpoint, native Rust batch
> evaluator, or client authorization snapshot is implemented. The
> implemented baseline remains the single-action `Authorizer` with the PR 8H
> pure-Python indexed `CompiledPolicy`.
>
> Security-critical decisions `T1`, `T3`, `T4`, and `T6` are **APPROVED**;
> `T2`/`T5` wire/lifecycle specifics are owned by PR 15/13. See
> [PR12_INTEGRATION_SECURITY_DECISIONS.md](PR12_INTEGRATION_SECURITY_DECISIONS.md).
> The illustrative JSON below remains **non-normative** until PR 15 freezes
> the DTO contract.
>
> Contract identifiers `C01`–`C11` are stable review anchors.

## 1. Purpose and dominant invariant (C01)

MTMF is the authoritative **Policy Decision Point (PDP)**. It exposes a
separately deployed, versioned HTTPS API. Consuming applications (ATI, Digr,
Darkula, Hammeridian) are **Policy Enforcement Points (PEPs)**: they
authenticate their own end users, request authorization decisions, and
enforce the returned effects at handlers, workflows, and data-access
boundaries.

**Dominant invariant.** An MTMF batch `ALLOW` may be produced only for:

1. an authenticated, registered Application;
2. a separately verified acting Identity in a valid Tenant context;
3. an eligible Tenant/Application subscription;
4. an explicit Action/resource scope; and
5. a positive authoritative policy decision.

The PEP must independently enforce the decision and its own resource/data
isolation. Failure of any prerequisite yields no `ALLOW`.

`mtmf-core` is private PDP implementation. External consumers **MUST NOT**
connect to MTMF PostgreSQL, embed `mtmf-core` as an authorization library, or
use local-connector semantics as an alternative authority. Internal MTMF
packages may depend on core.

```text
Consumer application (PEP)
  authenticates its end user and owns domain data
       | verified user assertion + OAuth2 service token
       v
MTMF HTTPS service (trust/transport boundary)
  verifies service/Application + end user + Tenant/Org
  checks Tenant/Application subscription
       v
MTMF core (authoritative PDP)
  resolves context/policy; evaluates ordered Action batch
       | detached scoped decisions / expiry
       v
mtmf-client helper within consumer (non-authoritative)
       v
Consumer PEP enforces handler/workflow/data access
```

## 2. Ownership matrix (C02)

| Component | Owns | Must not own |
| --- | --- | --- |
| `mtmf-core` | authoritative authorization orchestration, Role/policy resolution, domain validation, future subscription eligibility and batch evaluation | HTTP authentication, application resource enforcement |
| `mtmf-api` | detached public DTO/error and versioned contract (PR 15) | database types, core domain imports, Rust/PyO3, FastAPI runtime dependencies |
| `mtmf-service` | authenticated HTTP trust boundary, token/user verification, DTO mapping, subscription gate, limits, invoking the PDP (PRs 14/17) | duplicate permission engine or app-owned resource authorization |
| `mtmf-client` | authenticated HTTP calls, strict response validation, scoped expiring snapshots, `is_allowed`/`require` (PR 18) | independent ALLOW decisions, embedded policy evaluation, automatic stale-grant extension |
| consuming Application / PEP | end-user auth flow, verified user assertion, handler/workflow/data access enforcement, Tenant/resource isolation | MTMF policy administration or direct MTMF database access |

## 3. Prerequisite gates (C03, C04)

Service authentication, acting-user verification, and subscription
eligibility are **separate gates**. Failure at any gate cannot yield `ALLOW`.

1. **Service authentication (PR 14).** OAuth 2.0 client credentials
   authenticate the calling service. MTMF verifies issuer, audience,
   signature/keys, temporal claims, token type, and the registered
   Application mapping, then derives the Application identity **only** from
   validated credentials.
2. **Acting-user verification (PR 14).** End-user identity is verified through
   a separate, explicit trust mechanism. MTMF authenticates the concrete
   Identity and binds Principal, Identity, active Tenant, and optional
   Organization. A UUID, unsigned header, or body field is not proof. The
   **approved** mechanism is a signed end-user access token issued by a
   trusted external issuer, or standards-based token exchange; MTMF validates
   issuer, audience, signature, expiry, subject mapping, and the authenticated
   Application's authority to act for the user and Tenant. Arbitrary
   service-signed assertions and caller-supplied Identity UUIDs are rejected.
   Exact token-exchange implementation belongs to PR 14.
3. **Subscription eligibility (PR 13).** A Tenant subscribes to a registered
   Application. Missing, expired, suspended, or cancelled subscriptions deny
   new grants. A Tenant subscription does not automatically grant
   Organization-level permission and never grants a Permission.

Mandatory trust properties for the acting-user mechanism: issuer and
audience binding;
signature/key validation and rotation; bounded lifetime; token/service-to-
Application binding; replay constraints; an authorized service-to-user/Tenant
relationship; immutable authenticated subject mapping; rejection of arbitrary
`principal_id`/`identity_id` claims without verification; active
Tenant/Principal/Identity memberships; explicit Organization validation.
An authenticated service acting on its own behalf is distinct from a
user-delegated call; there is no implicit service-as-user or root fallback.

**Application/credential binding (approved T6).** Each authenticated
credential identity maps to exactly one registered Application. An
Application may possess multiple credentials and serve multiple Tenants;
Application–Tenant authorization is explicitly registered and verified. Each
request/batch is bound to exactly one verified Application and one acting
Tenant context, and cannot be mixed or overridden by a request-body field.

## 3A. OAuth access-token lifecycle and refresh-token boundary (PRs 14 and 18; NOT IMPLEMENTED)

**Status: approved scope clarification, future implementation only.** MTMF is an OAuth 2.0 protected resource server and authorization PDP, **not** an OAuth authorization server or refresh-token issuer. The trusted external issuer/authorization server issues access tokens. PR 14 owns validation and trusted identity mapping; PR 18 owns the official Python client's service-token acquisition/renewal. No OAuth token handling is implemented by this documentation change.

| Flow | Access token | Refresh token | Owner |
| --- | --- | --- | --- |
| Backend service → MTMF (OAuth 2.0 Client Credentials) | REQUIRED, validated by MTMF service (PR 14) | NOT used or issued for this flow | External authorization server issues access token; `mtmf-client` acquires/renews it (PR 18) |
| End user → consuming application (e.g. Authorization Code + PKCE) | External IdP token or approved exchanged token may establish verified acting user (PR 14) | MAY be issued, rotated, and revoked by external IdP; consuming app manages its own session | External IdP and consumer, **not** MTMF |
| MTMF authorization decision snapshot | NOT an OAuth access token | NOT a refresh token | MTMF PDP issues bounded decisions; PEP/client enforces (PRs 17–18) |

**PR 14 acceptance criteria (server/trust boundary):**
- Verify issuer, audience, signature/JWKS and key rotation, token type, `nbf`/`iat`/`exp` with bounded clock skew, credential-to-Application mapping, and authorized acting-user/Tenant binding; reject missing, expired, malformed, revoked when issuer revocation evidence is available, or otherwise untrusted tokens.
- Service credentials MUST be bound to exactly one registered Application; a valid service token alone MUST NOT establish an acting end-user Identity.
- Separately validate a trusted external end-user access token or approved standards-based token exchange. The exact wire format and exchange endpoint integration remain PR 14 implementation decisions under approved T1/T6; do not accept a caller-provided UUID or service-signed user assertion.
- MTMF MUST NOT issue, persist, rotate, revoke, or accept refresh tokens as credentials at its authorization endpoint. User refresh tokens, if any, are handled by the external IdP and consumer.
- Fail closed on token verification/issuer errors; do not treat authentication errors as policy DENY with a usable snapshot.

**PR 18 acceptance criteria (client/PEP helper):**
- Obtain service access tokens from the configured trusted authorization server using Client Credentials; cache only until their validated expiry and reacquire with the same authorized flow. Do **not** request or use OAuth refresh tokens for service credentials.
- Bound proactive renewal, concurrency/single-flight handling, timeouts and retries to prevent refresh stampedes; never log credentials or tokens. A bounded, at-most-once retry after a token-expiry `401` MAY reacquire a new service token; do not retry authorization `403` or user/tenant trust failures as token-expiry. No infinite retry loops or downgrade to unauthenticated calls.
- Keep **service access-token renewal**, **external end-user session refresh**, and **MTMF authorization snapshot reevaluation** independent. A renewed OAuth token does not renew a decision, extend snapshot TTL, or make a previously denied Action ALLOW.
- Fail closed if the token endpoint is unavailable or a fresh token cannot be obtained; no new authorization grants. Existing snapshots remain subject to their exact binding and previously approved 60s default / 300s maximum / 15s security-sensitive TTL constraints, not to OAuth token lifetime.
- Add conformance tests for expiry, issuer/audience mismatch, revoked/invalid tokens, one bounded 401 retry, no 403 retry, concurrent acquisition, token-endpoint failure, and snapshot expiry independent of OAuth renewal.

**No new PR is needed:** PR 14 and PR 18 already own these responsibilities. The refresh-token exclusion does not prohibit external IdP-managed interactive user refresh tokens. Neither an external user's refresh token nor a service access token can be substituted for a verified MTMF authorization decision.

## 3B. Application-neutral Podman development bootstrap and OAuth service credentials (PRs 13, 14, 17, 18 and 20; NOT IMPLEMENTED)

**Status: future development deployment contract, not an implemented startup behavior.** This section is application-neutral: a *consuming Application* is any independently deployed PEP that integrates with MTMF. The SYSTEM/root Tenant is reserved for MTMF control-plane administration. **No consuming Application may operate, subscribe, or obtain authorization decisions in the SYSTEM/root Tenant**, even if its registration was performed by a root administrator. An Application may serve multiple explicitly subscribed **ordinary** Tenants; a request is bound to one verified Application and one ordinary Tenant. PR 13 must enforce this at the authoritative domain/database boundary, PR 14 at the authenticated request boundary, and PR 20 in negative end-to-end tests.

### Initialization sequence (PR 17 orchestration)

The development profile MUST run a privileged, one-shot, idempotent initializer during Podman startup, **before** the MTMF HTTP service is marked ready:

1. **Database readiness:** wait for PostgreSQL health; abort on unavailable database.
2. **Migrations:** apply pending Alembic revisions and verify the approved SYSTEM Role/Permission seed.
3. **Canonical root bootstrap:** invoke the existing PR 10 serialized, installation-only `bootstrap_root` operation; validate the root Tenant, root Principal, protected local root Identity, memberships and registry. Never create a second root or infer a replacement on conflict.
4. **Ordinary development Tenant:** create or validate a configured non-SYSTEM Tenant with an eligible development administrator, acting Identity, memberships and designated steward; activate only once stewardship invariants are satisfied. A development Tenant is not a SYSTEM Tenant.
5. **Application registry:** create or validate each configured consuming Application independently of its Tenant; no product-specific Application is hardcoded into MTMF.
6. **Subscription:** create or validate an ACTIVE Application–ordinary-Tenant subscription, including explicit eligibility checks. Reject any attempted SYSTEM Tenant subscription.
7. **Local OAuth development issuer:** start/verify a local Keycloak container and configure a dedicated confidential OAuth 2.0 Client Credentials client for each consuming Application. Create or reconcile the external OAuth client and MTMF's one-credential-to-one-Application mapping. Ensure issuer, audience, signature/JWKS and token lifetime are configured for PR 14 validation. **MTMF does not issue OAuth access tokens or refresh tokens.**
8. **Credential delivery:** securely generate a per-Application client secret where needed and supply the client ID/secret to the consuming application's deployment via Podman secrets or another protected local mechanism; never bake secrets into images, commit them to Git, print them in logs, or expose root/bootstrap credentials. Reuse existing valid credentials on restart; rotation is an explicit operation.
9. **Readiness:** expose MTMF HTTP readiness only after all mandatory provisioning and issuer trust checks succeed. The consuming Application uses `mtmf-client` (PR 18) to obtain a short-lived access token from the external issuer, then calls MTMF using that token plus the separately verified acting-user context.

**Idempotency and failure policy:** fresh state creates the expected objects; a fully matching state is validated/reused without duplicate resources, secret resets or unnecessary mutations; new configured Applications can be added without changing existing ones. Concurrent startup must serialize provisioning. Missing prerequisites, partial/corrupt state, incompatible registry or subscription mappings, or issuer provisioning errors fail closed and prevent readiness. Do not silently recreate privileged identities, elevate an Application, or recover root credentials. Use deterministic development fixture identities/configuration, but generate secrets securely. The development fixture is opt-in and cannot run in production; production bootstrap requires a separate explicit privileged deployment operation.

**Implementation ownership:** PR 10 already provides the root bootstrap primitive; PR 13 provides Application/subscription persistence and SYSTEM Tenant exclusion; PR 14 provides external OAuth trust and Application mapping; PR 17 owns Podman initialization orchestration, local Keycloak development integration and readiness; PR 18 owns provider-neutral Client Credentials token acquisition/renewal; PR 20 owns generic integration conformance, including negative SYSTEM Tenant tests. This documentation does not assert any of these future integrations exist today.

### Development service credential contract

| Field | Meaning | Example (illustrative only) |
| --- | --- | --- |
| `client_id` | OAuth credential identifier for one registered Application; not a Principal or Tenant ID | `sample-app-dev` |
| `client_secret` | High-entropy confidential credential held by the consumer/IdP, delivered as a secret | generated, never documented |
| `grant_type` | OAuth 2.0 machine-to-machine flow | `client_credentials` |
| `token_endpoint` | External issuer endpoint, configurable independently of MTMF | local Keycloak realm token endpoint |
| `issuer` / `jwks_uri` | MTMF trust and signature verification configuration | local Keycloak development issuer |
| `audience` | Access token recipient binding | `mtmf-api` (illustrative) |
| `access_token_ttl` | Short-lived issuer-controlled validity | 15 minutes (illustrative, not mandated) |
| `application_id` | MTMF Application derived from validated credential mapping | registered consuming Application |
| `tenant_id` | Verified ordinary Tenant context, independently subscription-checked | configured development Tenant |

A service access token authenticates the Application, **not** its end user and **not** its Tenant. PR 14 separately verifies acting-user identity and Tenant membership via the approved T1 trusted external access token or token-exchange mechanism; a service token cannot be treated as proof of a user session. No OAuth refresh token is issued or used in the Client Credentials flow. Interactive end-user refresh tokens, if present, remain entirely under the external IdP/consuming application's control. Keycloak is the **recommended local development issuer**, not a production dependency or a hardcoded requirement of MTMF's OAuth interfaces; production may use another conforming issuer and stronger client authentication such as `private_key_jwt` or workload identity federation.

## 4. Batch request semantics (C05)

Semantics are defined here; exact JSON fields, status codes, reason spellings,
and limits are frozen by PR 15.

- one authenticated Application and one verified acting Identity/Tenant
  context per batch; optional Organization context is validated and scoped;
- an explicit, finite array of Action requests, each carrying sufficient
  resource/scope qualifiers to prevent accidental broadening;
- no implicit "all Actions" operation and no wildcard expansion from the
  request into Permissions;
- each input occurrence receives one correlated decision, including
  duplicates; request order or a stable per-item identifier is preserved
  (representation frozen by PR 15);
- unknown, unrecognized, or unsupported Actions cannot `ALLOW`;
- malformed request envelopes fail validation with no grants;
- all decisions use the *same* verified batch context; a batch never mixes
  users, Tenants, or Applications;
- batch decisions may mix `ALLOW`/`DENY`; an infrastructure failure cannot be
  presented as an `ALLOW` or as a silently successful partial response;
- no batch item may authorize an application-owned object solely because the
  action-level capability is `ALLOW`.

Ordered batch semantics and the Python semantic oracle are unchanged from the
existing single-action path; batch evaluation is a repeated application of the
same per-Action decision.

## 5. Scope and resource binding (C06)

Every decision binds the tuple: authenticated Application; verified acting
Principal and concrete Identity; active Tenant; optional Organization;
Action; target resource class and resource identifier/qualifiers where MTMF
evaluates them; required dominance/scope; policy/version metadata where safely
available.

- Cross-Tenant target requires existing explicit management authorization
  (PR 11); ordinary same-Tenant membership never grants cross-Tenant access.
- Organization scoping never transfers across Organizations.
- An ALLOW for a capability is not blanket access to every resource instance.
  When resource-level policy is MTMF-owned, the required qualifier must be
  present and validated before `ALLOW`; when the resource is application-owned,
  the PEP independently checks row/resource isolation.
- MTMF does not know arbitrary ATI/Digr/Darkula/Hammeridian domain objects and
  cannot enforce their SQL row predicates.

**Resource-qualifier ownership (approved T4).** Capability-level authorization
is permitted for application-owned resources, and the consuming application
remains responsible for independent Tenant and resource isolation. Explicit,
validated qualifiers are mandatory when MTMF owns resource-specific policy. A
capability ALLOW never grants unrestricted access to individual application
resources. Detailed API representation belongs to PR 15.

## 6. Policy semantics are preserved (C07)

Existing default DENY, exact/wildcard specificity, equal-specificity DENY
precedence, Tenant/session isolation, Role ownership, stewardship and
management-group restrictions, strict dominance where applicable, and
extension-mutation restrictions remain unchanged and apply to **each**
requested Action.

Python remains authoritative for context orchestration. Rust never
independently resolves identities, memberships, subscriptions, or Roles.
Native Rust batch (PR 16) must use one shared-policy/context FFI call per
batch, not N per-action crossings, with full parity and measured performance
before any default switch.

## 7. Authorization snapshots and expiry (C08)

A client snapshot is a scoped, expiring **application object**, not a bearer
token, identity credential, or general entitlement.

- Exact reuse binding: Application, acting Principal/Identity, Tenant,
  optional Organization, resource/scope, enumerated Actions and results.
- Unknown, missing, duplicate-ambiguous, invalid, mismatched, or expired
  decisions deny.
- No cross-user, cross-Tenant, cross-Organization, or cross-Application
  replay.
- `require`/`is_allowed` must deny on any invalid snapshot.
- No automatic TTL renewal; new grants require fresh trusted PDP evaluation.
- The official client must obtain fresh service access tokens through Client Credentials, without refresh tokens; access-token renewal never extends authorization snapshot validity (see §3A).
- A revoked policy or subscription can leave already-issued unexpired
  snapshots stale; there is no distributed instant-revocation promise.
- A snapshot from a partially failed batch is prohibited (see T7).

**Snapshot lifetime (approved T3).** The configurable maximum TTL is
**300 seconds**, the default TTL is **60 seconds**, and security-sensitive
Actions use a maximum TTL of **15 seconds**. Timestamps are server-issued in
UTC; clients validate with monotonic elapsed time; clock uncertainty must
reduce, never extend, validity; there is no silent renewal, indefinite
snapshot, or extension beyond the server-issued expiry. Implementation
belongs to PR 18.

## 8. Failure taxonomy (C09)

Semantic classification for downstream PR 15; status codes and enum spellings
are not frozen here.

| Condition | Semantic outcome | May create ALLOW? |
| --- | --- | --- |
| Invalid/missing service credential | authentication failure | No |
| Unverified/unauthorized acting user or Tenant | trust/context failure | No |
| Inactive/missing Application or subscription | eligibility failure | No |
| Valid context, unmatched/denied Action | per-item policy DENY | No |
| Invalid batch envelope/qualifier | validation failure | No |
| Timeout, database failure, native evaluator failure | infrastructure failure; no usable new grant | No |
| Mixed valid authorized/unauthorized Actions | ordered per-item ALLOW/DENY | Only matching items |
| Client snapshot absent/expired/mismatched | PEP denies locally | No |

A legitimate policy DENY is distinct from an unavailable service. An
infrastructure exception must not be disguised as an ordinary DENY if doing so
hides operational faults; both are fail-closed from the PEP's perspective.

## 9. Trust and revocation boundaries (C10)

The MTMF service authenticates requests and authorizes; the PEP enforces at
every sensitive handler/workflow/data boundary. The PEP must not accept a
snapshot supplied by an arbitrary end user as authorization. Audit records
must be non-sensitive: no tokens, policy contents, or credentials. New PDP
decisions after a committed revocation use authoritative current state;
already-issued unexpired snapshots are not retroactively invalidated.

**The service verifies:** service credential/Application mapping, acting-user
assertion integrity and binding, Tenant/Organization membership, subscription
eligibility, Action/policy decisions and their context binding, and snapshot
issuance/expiry.

The PEP must verify: its own end-user authentication flow, propagation of the
verified assertion, that it uses the authenticated Application context, that
it does not accept a caller-supplied snapshot as authorization, and that it
independently enforces its own resource/data/Tenant isolation at each
sensitive access.

## 10. Future PR ownership (C11)

| PR | Deliverable | Implemented now? |
| --- | --- | --- |
| 12 | Architecture, trust, and batch contracts | No — documentation only |
| 13 | Application registry and Tenant subscriptions | No |
| 14 | Trusted service/end-user authentication boundary | No |
| 15 | Versioned HTTP batch API DTO contract | No |
| 16 | Python/Rust native batch and parity benchmarks | No |
| 17 | Authenticated HTTP service endpoint | No |
| 18 | HTTP client and scoped snapshot helper | No |
| 19 | Decision observability/audit | No |
| 20 | ATI PEP reference integration and E2E validation | No |

## 11. Normative terminology

- **Application** — a registered service client identity, distinct from an
  OAuth client credential identifier, from an end-user Principal/Identity, and
  from a Tenant ID.
- **TenantApplicationSubscription** — a Tenant's explicit eligibility
  relationship to a registered Application; eligibility, never a Permission.
- **Acting Principal / Identity** — the verified end-user Principal and the
  concrete Identity used for the session.
- **Action** — the exact shared operation definition requested.
- **Target resource qualifier** — the resource class/identifier/scope that
  binds a capability decision to a specific resource where MTMF evaluates it.
- **Policy decision** — the authoritative per-Action `ALLOW`/`DENY` from the
  PDP.
- **Batch** — a finite ordered array of Action requests evaluated under one
  verified context.
- **Authorization snapshot** — a scoped, expiring client-side application
  object holding decisions for an exact binding.
- **PDP** — Policy Decision Point (MTMF core/service).
- **PEP** — Policy Enforcement Point (consuming application).
- **Subscription eligibility** — the prerequisite check that the Tenant may
  use the Application.
- **Revocation window** — the bounded period during which an already-issued
  snapshot may remain valid after revocation.

## 12. Threat-boundary abuse cases

All rows are design-time analysis, not executed tests. The owning PR
implements the rejection; the test ID is a future conformance case.

| # | Abuse case | Boundary | Expected rejection | Owner | Future test |
| --- | --- | --- | --- | --- | --- |
| A1 | Stolen service token | service auth | reject/expiry/rotation; no Application authority | 14/17 | F02 |
| A2 | Service token for Application A used as B | Application binding | derive Application from credential; reject body override | 14/17 | F03 |
| A3 | Forged acting Identity UUID | user trust | reject before PDP | 14/17 | F04 |
| A4 | Valid service credential with untrusted user assertion | user trust | reject assertion (T1) | 14/17 | F04/F19 |
| A5 | User switches Tenant | context binding | verify requested Tenant membership; reject otherwise | 14/17 | F05 |
| A6 | Organization replay across Organizations | context binding | reject Organization mismatch | 14/17 | F12 |
| A7 | Stale subscription | eligibility | no ALLOW | 13/17 | F06 |
| A8 | Duplicate Actions | batch correlation | stable per-occurrence result | 15/17 | F08 |
| A9 | Unknown but syntactically valid Action | batch semantics | per-item DENY | 15/17 | F09 |
| A10 | Malformed Action/invalid envelope | validation | no usable grant | 15/17 | F10 |
| A11 | Partial backend failure | batch atomicity | whole-request failure; no partial snapshot | 16/17/18 | F11 |
| A12 | Stale snapshot after revocation | revocation window | new evaluation denies; bounded old TTL | 13/17/18 | F14 |
| A13 | Cross-resource replay of an ALLOW | resource binding | PEP denies at resource boundary | 18/20 | F12/F13 |
| A14 | Policy ALLOW but PEP row isolation fails | PEP enforcement | PEP blocks data access | 20 | F15 |
| A15 | Root/TMG management context used as blanket app access | delegation | deny absent independent gates | 14/17/20 | F18 |
| A16 | Malicious batch sizes | limits | bounded reject | 17 | F17 |
| A17 | Shared runtime DB credential treated as verified user | trust boundary | reject (not an end-user auth path) | 14/17 | F19 |
| A18 | Snapshot supplied by end user or another service | snapshot integrity | reject at PEP helper | 18/20 | F20 |

## 13. Illustrative examples (NON-NORMATIVE)

These examples are conceptual and are **not** final JSON, endpoints, or
current behavior. Exact Action URNs, DTO fields, error codes, and TTLs are
PR 15 decisions.

Positive (conceptual): authenticated Application + verified user in Tenant A +
active subscription + explicit `read` Action → one `ALLOW` for that Action,
bound to the exact context.

Negative (conceptual): (1) no service credential; (2) token for another
Application; (3) forged user UUID; (4) user not a member of the requested
Tenant; (5) inactive/missing subscription; (6) unknown Action; (7) malformed
envelope; (8) infrastructure failure → none yields `ALLOW`.

## 14. Future conformance matrix (PR 13–20; not implemented)

| ID | Scenario | Expected future behavior | Owner |
| --- | --- | --- | --- |
| F01 | Authenticated service + verified user + eligible subscription + explicit ALLOW | per-item ALLOW | 13–17 |
| F02 | Missing/invalid OAuth service token | HTTP authentication failure; no grant | 14/17 |
| F03 | Token for App A attempts App B | reject; no Application body override | 14/17 |
| F04 | Forged user/Principal UUID | reject before PDP | 14/17 |
| F05 | User valid for Tenant A, requests Tenant B without membership | reject/no grant | 14/17 |
| F06 | Inactive/missing Tenant subscription | no ALLOW | 13/17 |
| F07 | Mixed permitted and denied Actions | one ordered result per occurrence | 15–17 |
| F08 | Duplicate Actions | stable correlation, no lost entries | 15–17 |
| F09 | Unknown syntactically valid Action | per-item DENY | 15–17 |
| F10 | Malformed Action or invalid envelope | validation failure; no usable grant | 15/17 |
| F11 | Infrastructure error during batch | fail closed; no partial reusable snapshot | 16/17/18 |
| F12 | Cross-Tenant or Organization snapshot replay | local deny | 18/20 |
| F13 | Expired/missing snapshot Action | local deny | 18/20 |
| F14 | Subscription/Role revoked after snapshot issue | new evaluation denies; bounded existing TTL | 13/17/18/20 |
| F15 | App resource owned by other Tenant despite capability ALLOW | PEP blocks data access | 20 |
| F16 | Python vs Rust batch mixed policy incl equal-specificity DENY | identical ordered decisions | 16 |
| F17 | Batch sizes 1/5/10/25/50/100/500 | correctness + measured benchmark, no assumed speedup | 16 |
| F18 | Root/TMG management context used as blanket App access | deny absent independent gates | 14/17/20 |
| F19 | Shared runtime credential treated as verified user | rejected by trust boundary | 14/17 |
| F20 | Snapshot supplied by end user or different service | rejected by PEP helper | 18/20 |

## 15. Review anchors

- [PR 12 decisions register](PR12_INTEGRATION_SECURITY_DECISIONS.md) — `T1`–`T8`.
- [Security Model](SECURITY_MODEL.md) — service/acting-identity distinction and invariants.
- [Authorization](AUTHORIZATION.md) — batch semantics and policy oracle.
- [Architecture](ARCHITECTURE.md) — package ownership and HTTP-only boundary.
- [Domain Model](DOMAIN_MODEL.md) — planned Application/subscription model.
- [Roadmap](ROADMAP_V01.md) — PR 13–20 ownership.

## 16. PR 12 documentation acceptance matrix

| ID | Requirement | Where satisfied |
| --- | --- | --- |
| D01 | HTTP-only architecture and package responsibilities consistent | §1, §2, `ARCHITECTURE.md` banner |
| D02 | PDP/PEP and app-owned data isolation explicit | §1, §5, §9 |
| D03 | Service token and end-user identity separate; UUID spoof rejected | §3 |
| D04 | Subscription gate separate from Permission | §3, `DOMAIN_MODEL.md` |
| D05 | Batch ordered/correlated per-input incl. duplicates | §4 |
| D06 | Unknown Action, malformed envelope, infrastructure failure separated | §8 |
| D07 | Context bound to Application/Identity/Tenant/Org/resource/Action | §5 |
| D08 | Existing default-DENY/dominance/ROOT-TMG/extension invariants preserved | §6, `SECURITY_MODEL.md` |
| D09 | Snapshot exact scope/expiry, no bearer/replay, stale window | §7 |
| D10 | Rust one-call-per-batch and Python parity preserved | §6 |
| D11 | Explicit PR 13–20 ownership; no production implementation | §10, `ROADMAP_V01.md` |
| D12 | Decision register statuses honest; human gates identified | decisions register |
| D13 | No migration, runtime code, dependency, API/HTTP/client implementation | `git diff` review |
| D14 | Historical connector contradictions resolved/labelled | `ARCHITECTURE.md` labels |
| D15 | Examples labelled non-normative | status banner, §13 |
