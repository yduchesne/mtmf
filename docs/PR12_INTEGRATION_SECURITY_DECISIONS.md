# PR 12 — Integration security decisions register

> **STATUS: PARTIALLY APPROVED — SECURITY-CRITICAL ITEMS PENDING HUMAN APPROVAL.**
> This register records the decisions required to freeze the PR 12
> integration/authorization security contract. Items marked `APPROVED
> PRINCIPLE` restate constraints already agreed in the authoritative
> documents; items marked `PROPOSED — REQUIRES HUMAN APPROVAL` are not
> approved and MUST NOT be treated as frozen contracts, implemented, or
> referenced as final wire/TTL/token semantics until a human reviewer
> records approval here.
>
> Companion contract: [HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md).
> Owner documentation: [SECURITY_MODEL.md](SECURITY_MODEL.md), [AUTHORIZATION.md](AUTHORIZATION.md).
>
> No runtime behavior is implemented by PR 12. This register is a
> documentation artifact only.

## 1. Approved principles (already settled)

These constraints are already stated by the authoritative documents and are
recorded here as approved *principles*. They do not approve any unspecified
token format, numeric TTL, HTTP status code, DTO field, route, or batch
limit.

| ID | Approved principle | Source |
| --- | --- | --- |
| P01 | External integration is HTTP-only; consumers never embed `mtmf-core`, connect to MTMF PostgreSQL, or use a local connector as an alternative authorization authority. | `ARCHITECTURE.md`, `ROADMAP_V01.md` |
| P02 | MTMF is the authoritative PDP; consuming applications are PEPs and own resource/data isolation. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §1 |
| P03 | Service authentication and acting end-user verification are separate gates; a supplied `principal_id`/`identity_id`/UUID is never authentication. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §2, `SECURITY_MODEL.md` |
| P04 | Tenant/Application subscription eligibility is a prerequisite for new ALLOW decisions, never a substitute for Permission evaluation. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §2 |
| P05 | Existing default DENY, exact/wildcard specificity, equal-specificity DENY precedence, Tenant isolation, Role ownership, stewardship/management-group restrictions, strict dominance, and extension-mutation restrictions are preserved per Action. | `AUTHORIZATION.md`, `SECURITY_MODEL.md` |
| P06 | Batch decisions are per input occurrence (including duplicates), correlated, and stable-ordered; unknown/malformed Actions never ALLOW; infrastructure failure never becomes ALLOW. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §3 |
| P07 | An ALLOW for a capability never grants universal access to application-owned resources; the PEP enforces Tenant/resource isolation independently. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §3 |
| P08 | Client snapshots are scoped, expiring server-side application objects bound to the exact Application/actor/Tenant/Organization/Action/resource scope; they are not bearer credentials and are not transferable. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §4 |
| P09 | Revocation applies to new evaluations; already-issued unexpired snapshots are not retroactively invalidated, and no instant distributed revocation is promised. | `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §4 |
| P10 | Python remains authoritative for context orchestration; native Rust batch (PR 16) requires one shared-context call per batch, full parity, and measured performance before any default change. | `AUTHORIZATION.md`, `HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §5 |

## 2. Required decisions

Each decision lists alternatives, a least-privilege recommendation,
consequences, the owning roadmap PR, and current status. Status values:
`APPROVED PRINCIPLE`, `PROPOSED — REQUIRES HUMAN APPROVAL`, `OPEN`.

### T1 — Verified acting-user assertion and propagation protocol

**Decision.** How is an end-user acting Identity cryptographically verified
and propagated to MTMF, distinct from service authentication?

**Status: `PROPOSED — REQUIRES HUMAN APPROVAL` (BLOCKING PR 14).**

**Alternatives.**

1. Standards-based token exchange (for example RFC 8693) or acceptance of a
   user access token minted by a trusted authorization server: the service
   presents its client-credentials token and/or a user token; MTMF validates
   issuer, audience, signature/keys, temporal claims, token type, and the
   registered Application→subject binding.
2. A signed user assertion (for example a JWT) minted by the calling service
   under a per-Application registered key, forwarded to MTMF.
3. MTMF-hosted interactive user authentication (out of v0.1 scope).

**Recommended (least privilege).** Option 1 with a trusted external issuer:
MTMF validates a signed, short-lived user token/assertion; the authenticated
service must be registered and authorized to act for the asserted
user/Tenant; arbitrary `principal_id`/`identity_id` claims are rejected unless
independently verified. Option 3 is excluded from v0.1.

**Consequences.** Fixes the token format/issuer/key-rotation/replay contract
and therefore PR 14 implementation. Until approved, PR 14 cannot finalize a
trust contract and no token format may be documented as approved.

**Owner PR:** 14.

### T2 — Malformed vs unknown vs infrastructure batch outcomes and correlation

**Decision.** How the service distinguishes (a) a syntactically invalid whole
request, (b) a syntactically valid but unrecognized/unsupported Action, and
(c) an infrastructure failure during evaluation, and how batch entries are
correlated.

**Status:** outcome distinction `APPROVED PRINCIPLE` (P06); correlation/wire
representation `PROPOSED — REQUIRES HUMAN APPROVAL` (PR 15 freezes the DTO).

**Approved semantics.**

- invalid envelope/qualifier → whole-request **validation failure**; no grants;
- syntactically valid unknown/unsupported Action → **per-item DENY**;
- infrastructure failure during evaluation → **whole-request failure**; no
  usable new snapshot.

**Proposed specifics (require approval).** Every input occurrence receives
exactly one correlated result; duplicates are preserved; ordering is stable
(request order or stable per-item identifier, frozen by PR 15); the
representation of the correlation key is a PR 15 decision.

**Recommended.** As above; a bounded maximum batch size (numeric value a
PR 15 decision). Do **not** invent a numeric limit in PR 12.

**Owner PR:** 15 (contract), 16/17 (behavior).

### T3 — Client snapshot TTL and clock semantics

**Decision.** The initial snapshot TTL policy, sensitive-action overrides, and
authoritative time handling.

**Status: `PROPOSED — REQUIRES HUMAN APPROVAL` (BLOCKING PR 18).**

**Alternatives.**

1. Fixed short TTL (for example five minutes) for every snapshot.
2. Configurable per-deployment upper bound with a conservative default and an
   optional shorter TTL for sensitive Actions.
3. No client snapshots; every PEP check calls the service fresh.

**Recommended (least privilege).** Option 2, with the numeric upper bound,
default, sensitive-action TTL, and permitted clock skew requiring explicit
approval. Server issues `issued_at`/`expires_at` in UTC; clients reject
snapshots beyond a small approved skew; no automatic renewal.

**Consequences.** Determines the worst-case stale-grant window. Five minutes
remains an illustration, **not** an approved default. A snapshot from a
partially failed batch is prohibited (see T7).

**Owner PR:** 18.

### T4 — Resource qualifier ownership and mandatory binding

**Decision.** Which resource qualifiers MTMF must evaluate and which remain
PEP-owned, and when a qualifier is mandatory before ALLOW.

**Status:** principle `APPROVED PRINCIPLE` (P07); qualifier semantics
`PROPOSED — REQUIRES HUMAN APPROVAL` (PR 15).

**Approved principle.** MTMF does not know arbitrary application domain
objects (ATI/Digr/Darkula/Hammeridian) and cannot enforce their SQL row
predicates. A capability ALLOW never implies resource-instance access.

**Proposed specifics (require approval).** When MTMF owns resource-scoped
policy, the request MUST include the validated qualifier before ALLOW; when
the resource is application-owned, the PEP MUST independently enforce row/
resource/Tenant isolation and no qualifier is fabricated by MTMF.

**Recommended.** Capability-level ALLOW by default; explicit mandatory
qualifiers only for resources whose policy MTMF actually owns; PEP does a
fresh resource-scoped evaluation rather than widening an ALLOW.

**Owner PR:** 15 (contract), 20 (reference PEP).

### T5 — Subscription eligibility and failure precedence

**Decision.** The ordering and precedence of service authentication, acting-user
verification, subscription eligibility, and policy evaluation.

**Status:** precedence `APPROVED PRINCIPLE` (P03, P04); exact lifecycle states
are a PR 13 decision.

**Approved precedence (fail-closed).**

1. authenticate the service → authentication failure stops evaluation;
2. verify the acting user/Tenant/Organization context → trust/context failure;
3. verify the Tenant/Application subscription is active and valid → eligibility
   failure (no ALLOW, no Permission evaluation);
4. evaluate explicit Actions against applicable policy.

**Proposed specifics (PR 13).** Subscription lifecycle names/transition rules
and whether an Organization refinement can further restrict (without
independently subscribing in v0.1).

**Recommended.** The above; subscription never grants a Permission and cannot
be overridden by a Role, root, or management relationship.

**Owner PR:** 13 (state), 17 (enforcement).

### T6 — Application identity ↔ service credential binding and multi-Tenant callers

**Decision.** How authenticated service credentials map to a registered
Application and how a multi-Tenant caller is authorized for a selected
user/Tenant.

**Status:** principle `APPROVED PRINCIPLE` (P03); binding/mapping
`PROPOSED — REQUIRES HUMAN APPROVAL` (PR 14).

**Approved principle.** The Application identity is derived only from
validated service credentials; a body/query-supplied Application identifier is
never trusted.

**Proposed specifics (require approval).** A registered Application may map to
one or more credential subjects/issuers; a credential may act only for the
Applications and Tenants it is registered for; a single credential acting for
multiple Tenants requires an explicit registered relationship and per-request
Tenant binding verified against it.

**Recommended.** One credential → explicitly registered Application(s); an
Application→Tenant authorization relationship gates which Tenants a service
may request; no cross-Application credential reuse.

**Owner PR:** 13 (registry), 14 (authentication/binding).

### T7 — Batch all-or-nothing on infrastructure failure

**Decision.** Whether a batch may return partial per-item ALLOW results when
some evaluation failed for infrastructure reasons.

**Status: `APPROVED PRINCIPLE` (P06).**

**Semantics.** Deterministic policy results (ALLOW/DENY) may be mixed per item.
An infrastructure failure (timeout, database error, native evaluator failure,
unavailable dependency) fails the whole request: no partial response, no usable
new snapshot, and never a per-item ALLOW derived from a failed evaluation.

**Recommended.** Whole-request failure on infrastructure error; the PEP treats
both a genuine DENY and an infrastructure failure as fail-closed, while the
service still distinguishes them operationally.

**Owner PR:** 16/17/18.

### T8 — Snapshot response integrity and PEP trust boundary

**Decision.** What makes a snapshot trustworthy to the PEP helper and how the
PEP must not treat an untrusted snapshot as authorization.

**Status: `APPROVED PRINCIPLE` (P08, P09) with implementation details owned by
PR 18.**

**Semantics.** A snapshot is bound to the authenticated Application + verified
actor + Tenant + optional Organization + resource/scope + enumerated Actions
and results. It is not a bearer token, is not transferable across users,
Tenants, Organizations, Applications, resources, or services, and must not be
accepted from an arbitrary end user. The PEP uses the official helper, which
denies on absent/expired/mismatched/invalid/unknown decisions. New grants
require fresh PDP evaluation; no automatic renewal.

**Recommended.** Server-side scoped snapshot objects delivered over
authenticated TLS; the helper validates binding in-process; the PEP enforces
at every sensitive handler/workflow/data boundary.

**Owner PR:** 18 (helper), 20 (reference PEP).

## 3. Smallest human decision request

To freeze the remaining security-critical contract, a reviewer must approve
(or amend):

1. **T1** — the acting-user verification mechanism class (token exchange vs
   service-signed assertion) and its trust issuer.
2. **T3** — the snapshot TTL policy (upper bound/default, sensitive-action
   override, clock skew).
3. **T4** — which resources require MTMF-evaluated qualifiers.
4. **T6** — the Application↔credential↔Tenant binding model.
5. **T2** — the correlation representation (can be deferred to PR 15 if the
   semantic distinction is accepted).
6. **T5** — subscription lifecycle specifics (can be deferred to PR 13 if the
   precedence is accepted).

Until T1/T3/T4/T6 are approved, the PR 12 contract is a **reviewable design
draft**: roadmap PR 12 is not marked `[DONE]`, and PR 14/18 must not freeze
token/TTL behavior.

## 4. Approval log

| ID | Status | Approved by | Date | Reference |
| --- | --- | --- | --- | --- |
| P01–P10 | APPROVED PRINCIPLE | existing authoritative docs | — | see §1 |
| T1 | PROPOSED — REQUIRES HUMAN APPROVAL | — | — | §2 T1 |
| T2 | APPROVED PRINCIPLE + PROPOSED specifics | — | — | §2 T2 |
| T3 | PROPOSED — REQUIRES HUMAN APPROVAL | — | — | §2 T3 |
| T4 | APPROVED PRINCIPLE + PROPOSED specifics | — | — | §2 T4 |
| T5 | APPROVED PRINCIPLE + PROPOSED specifics | — | — | §2 T5 |
| T6 | APPROVED PRINCIPLE + PROPOSED specifics | — | — | §2 T6 |
| T7 | APPROVED PRINCIPLE | existing authoritative docs | — | §2 T7 |
| T8 | APPROVED PRINCIPLE | existing authoritative docs | — | §2 T8 |
