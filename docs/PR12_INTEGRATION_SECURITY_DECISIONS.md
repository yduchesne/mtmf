# PR 12 — Integration security decisions register

> **STATUS: T1/T3/T4/T6 APPROVED BY HUMAN REVIEWER.** The security-critical
> decisions required to freeze the PR 12 integration/authorization contract
> are approved. Remaining items are either approved principles or downstream
> specifics explicitly owned by PR 13/15. No runtime behavior is implemented
> by PR 12; this register and the companion contract are documentation only.
>
> Companion contract: [HTTP Integration and Batch Authorization](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md).
> Owner documentation: [SECURITY_MODEL.md](SECURITY_MODEL.md), [AUTHORIZATION.md](AUTHORIZATION.md).

## 1. Approved principles

These constraints are already stated by the authoritative documents and are
recorded here as approved principles. They do not by themselves approve a
wire DTO, HTTP status code, or route (owned by PR 15).

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

## 2. Approved decisions

### T1 — Verified acting-user assertion and propagation protocol

**Status: APPROVED (human reviewer).**

- Use **signed end-user access tokens issued by a trusted external issuer**,
  or **standards-based token exchange** (for example RFC 8693).
- Validate issuer, audience, signature, expiry, subject mapping, and the
  authenticated Application's authority to act for the user and Tenant.
- **Do not** accept arbitrary service-signed assertions or caller-supplied
  Identity UUIDs as authentication.
- Exact token-exchange implementation details belong to **PR 14**.

**Consequences.** The Option-2 service-signed assertion alternative is
rejected. PR 14 must implement external-issuer validation and a standards-
based delegation/token-exchange mechanism; no service-minted user assertion is
an accepted authority.

**Owner PR:** 14.

### T3 — Authorization snapshot lifetime

**Status: APPROVED (human reviewer).**

- Configurable maximum TTL: **300 seconds**.
- Default TTL: **60 seconds**.
- Security-sensitive Action maximum TTL: **15 seconds**.
- Server-issued **UTC** timestamps.
- Client-side **monotonic elapsed-time** validation.
- Clock uncertainty must **reduce, never extend**, snapshot validity.
- **No** silent renewal, indefinite snapshots, or extension beyond the
  server-issued expiry.
- Implementation belongs to **PR 18**.

**Owner PR:** 18.

### T4 — Resource qualifier ownership

**Status: APPROVED (human reviewer).**

- Capability-level authorization is permitted for **application-owned**
  resources.
- Consuming applications remain responsible for independent Tenant and
  resource isolation.
- Explicit, validated qualifiers are **mandatory when MTMF owns
  resource-specific policy**.
- A capability ALLOW **never** grants unrestricted access to individual
  application resources.
- Detailed API representation belongs to **PR 15**.

**Owner PR:** 15 (representation), 20 (reference PEP).

### T6 — Application and credential binding

**Status: APPROVED (human reviewer).**

- Each authenticated credential identity maps to **exactly one** registered
  Application.
- An Application may possess multiple credentials and serve multiple Tenants.
- Application–Tenant authorization must be **explicitly registered and
  verified**.
- Each request/batch must be bound to exactly one verified Application and one
  acting Tenant context; Application and Tenant context must not be mixed
  within a request or overridden by a request-body field.

> **Reviewer-text note.** The approval message was truncated after
> “Each …”. The final bullet above records the conservative completion
> consistent with C05 (one Application and one verified acting
> Identity/Tenant context per batch) and the rest of T6. If the intended
> final requirement differs, amend this bullet before PR 14 implementation.

**Owner PR:** 13 (registry), 14 (authentication/binding).

## 3. Downstream-owned specifics (not PR 12 blockers)

These items were not settled by PR 12 and are intentionally owned by later
PRs. They are not blocking decisions and do not prevent PR 12 completion.

### T2 — Batch malformed vs unknown vs infrastructure outcomes and correlation

**Status:** semantics `APPROVED PRINCIPLE` (P06); correlation/wire
representation owned by **PR 15**.

Approved semantics: invalid envelope/qualifier → whole-request validation
failure; syntactically valid unknown/unsupported Action → per-item DENY;
infrastructure failure during evaluation → whole-request failure with no
usable new snapshot. Every input occurrence receives one correlated result;
duplicates are preserved; the correlation representation and any bounded
maximum batch size are PR 15 decisions.

**Owner PR:** 15 (contract), 16/17 (behavior).

### T5 — Subscription eligibility and failure precedence

**Status:** precedence `APPROVED PRINCIPLE` (P03, P04); lifecycle specifics
owned by **PR 13**.

Approved precedence (fail-closed): (1) authenticate the service;
(2) verify the acting user/Tenant/Organization context; (3) verify the
Tenant/Application subscription is active and valid; (4) evaluate explicit
Actions. Failure at any earlier gate prevents later gates from producing an
ALLOW, and a subscription never grants a Permission and cannot be overridden
by a Role, root, or management relationship. Subscription lifecycle names and
transition rules are PR 13 decisions.

**Owner PR:** 13 (state), 17 (enforcement).

### T7 — Batch all-or-nothing on infrastructure failure

**Status: APPROVED PRINCIPLE (P06).**

Deterministic policy results may mix per item. An infrastructure failure
(timeout, database error, native evaluator failure) fails the whole request:
no partial response, no usable new snapshot, and never a per-item ALLOW
derived from a failed evaluation.

**Owner PR:** 16/17/18.

### T8 — Snapshot response integrity and PEP trust boundary

**Status: APPROVED PRINCIPLE (P08, P09); implementation owned by PR 18.**

A snapshot is bound to the authenticated Application + verified actor +
Tenant + optional Organization + resource/scope + enumerated Actions/results.
It is not a bearer token and is not transferable across users, Tenants,
Organizations, Applications, resources, or services, and must not be accepted
from an arbitrary end user. The official helper denies on
absent/expired/mismatched/invalid/unknown decisions; new grants require fresh
PDP evaluation; no automatic renewal.

**Owner PR:** 18 (helper), 20 (reference PEP).

## 4. Approval log

| ID | Status | Approved by | Date | Reference |
| --- | --- | --- | --- | --- |
| P01–P10 | APPROVED PRINCIPLE | authoritative docs | — | §1 |
| T1 | APPROVED | human reviewer | PR 12 approval | §2 T1 |
| T2 | semantics APPROVED; specifics deferred to PR 15 | human reviewer | PR 12 approval | §3 |
| T3 | APPROVED | human reviewer | PR 12 approval | §2 T3 |
| T4 | APPROVED | human reviewer | PR 12 approval | §2 T4 |
| T5 | precedence APPROVED; lifecycle deferred to PR 13 | human reviewer | PR 12 approval | §3 |
| T6 | APPROVED | human reviewer | PR 12 approval | §2 T6 |
| T7 | APPROVED PRINCIPLE | authoritative docs | — | §3 |
| T8 | APPROVED PRINCIPLE | authoritative docs | — | §3 |

**No blocking decisions remain.** PR 12 may be marked `[DONE]` once the
documentation acceptance matrix D01–D15 in the companion contract is
satisfied and docs-only QA passes.
