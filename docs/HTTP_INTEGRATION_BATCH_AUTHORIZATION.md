# HTTP Integration and Batch Authorization — v0.1 Normative Design Contract (PR 12)

> **STATUS: NORMATIVE DESIGN CONTRACT — RUNTIME NOT IMPLEMENTED.**
> This document is the PR 12 normative contract for the planned HTTP-only
> consumer integration. No Application registry, Tenant subscription,
> trusted HTTP actor propagation, batch endpoint, native Rust batch
> evaluator, or client authorization snapshot is implemented. The
> implemented baseline remains the single-action `Authorizer` with the PR 8H
> pure-Python indexed `CompiledPolicy`.
>
> Security-critical decisions that must be approved before this contract is
> final are tracked in [PR12_INTEGRATION_SECURITY_DECISIONS.md](PR12_INTEGRATION_SECURITY_DECISIONS.md)
> (`T1`–`T8`). Items marked `PROPOSED — REQUIRES HUMAN APPROVAL` there are
> **not** frozen; the illustrative JSON below is **non-normative** until PR 15
> freezes the DTO contract.
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
   Organization. A UUID, unsigned header, or body field is not proof.
3. **Subscription eligibility (PR 13).** A Tenant subscribes to a registered
   Application. Missing, expired, suspended, or cancelled subscriptions deny
   new grants. A Tenant subscription does not automatically grant
   Organization-level permission and never grants a Permission.

Mandatory trust properties for the acting-user mechanism (the exact protocol
is decision `T1`, still pending): issuer and audience binding;
signature/key validation and rotation; bounded lifetime; token/service-to-
Application binding; replay constraints; an authorized service-to-user/Tenant
relationship; immutable authenticated subject mapping; rejection of arbitrary
`principal_id`/`identity_id` claims without verification; active
Tenant/Principal/Identity memberships; explicit Organization validation.
An authenticated service acting on its own behalf is distinct from a
user-delegated call; there is no implicit service-as-user or root fallback.

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

Resource-qualifier ownership is decision `T4` (principle approved; specifics
pending).

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
- A revoked policy or subscription can leave already-issued unexpired
  snapshots stale; there is no distributed instant-revocation promise.
- A snapshot from a partially failed batch is prohibited (see T7).

TTL/clock policy is decision `T3` (pending). Five minutes is an illustration,
**not** an approved default.

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
