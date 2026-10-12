# PR 15 — Public HTTP API contract decisions (W1–W7)

> **STATUS: APPROVED / IMPLEMENTED — contract-only package.**
> Source of approval: the human reviewer instructed the coding agent to
> implement `PR15_DETAILED_EXECUTION_PLAN.md` on 2026-10-12, and during
> PR 15 review on 2026-10-11 explicitly confirmed `W3` (exact canonical
> MTMF Action URNs as the public Action identifier). All W1–W7 decisions
> are approved; no contract decision remains open. The historical
> reasoning for preferring the canonical Action URN over the plan's
> illustrative short-name proposal is retained under `W3`. No HTTP
> runtime, route, evaluator, migration, grant, or dependency was added.

This register freezes the PR 15 wire decisions that PR 12 explicitly
delegated (`T2`) and that `ROADMAP_V01.md` assigns to PR 15. It does not
re-open any approved PR 12 semantic rule (`T1`, `T3`, `T4`, `T6`,
`P01`–`P10`).

Companion normative document:
[PR 15 HTTP API v1 Contract](../pr-15/pr15-http-api-v1-contract.md).
Companion sources: [HTTP Integration and Batch Authorization](../../HTTP_INTEGRATION_BATCH_AUTHORIZATION.md)
C01–C11, [PR 12 Integration Security Decisions](../pr-12/pr12-integration-security-decisions.md),
[PR 14 Authentication Security Decisions](../pr-14/pr14-authentication-security-decisions.md) §14J.

## Decision register

| ID | Decision | Status |
| --- | --- | --- |
| W1 | Route `/v1/authorization/evaluate`; URL-selected version; strict JSON with unknown/duplicate-member rejection | APPROVED |
| W2 | 1–100 actions; unique per-occurrence `request_id`; stable order; exact one-to-one response correlation including duplicates | APPROVED |
| W3 | Exact canonical public Action **URN** grammar (final; historical deviation recorded below) | APPROVED |
| W4 | Tagged resource union `capability` / `application_owned` / `mtmf_owned`; no free-form qualifiers; MTMF-owned fails closed until PR 17 validates | APPROVED |
| W5 | Public reason/error taxonomy, reserved HTTP mapping, static safe messages; `INELIGIBLE_CONTEXT` omitted per-item | APPROVED |
| W6 | UTC `issued_at`/`expires_at`, positive TTL ≤ 300s; 60s default / 15s sensitive are PR 17/18 limits | APPROVED |
| W7 | Stdlib `dataclasses`/`Enum`/`uuid`/`datetime`; no new runtime or dev dependency; no Pydantic, no FastAPI, no schema-generation library | APPROVED |

## W1 — versioning and strict JSON

- Reserved route: `POST /v1/authorization/evaluate` (implemented by PR 17).
- Version is selected by the URL `/v1`; the request body carries **no**
  caller-controlled version field. The response and error envelopes carry
  literal `"schema_version": "1"`.
- `snake_case` keys, UTF-8, canonical lowercase UUID strings, RFC 3339
  UTC timestamps ending in `Z`.
- Duplicate JSON member names (recursively), non-finite numbers,
  non-object top-level values, unknown fields, and over-deep nesting are
  rejected before model creation. Unknown keys are never normalized away.
- `application/json` and HTTPS are PR 17 transport requirements.

## W2 — batch and correlation

- 1–100 action occurrences; each request occurrence receives exactly one
  ordered, correlated `ALLOW`/`DENY`.
- `request_id` is 1–64 ASCII `[A-Za-z0-9._:-]`, unique within the batch,
  and is **correlation only — never a security identity**.
- Duplicate Actions are preserved and never deduplicated. A pure
  `validate_response_for_request(request, response)` check enforces exact
  length/order/uniqueness and Tenant/organization equality with no policy
  evaluation.

## W3 — exact public Action URN (approved)

**Plan proposal.** The plan's §4.2 table proposed a short public name
grammar `[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+` (example `document.read`),
with an instruction to inspect the core Action grammar and to **STOP
rather than silently narrow the public contract** if valid core Actions
cannot be represented losslessly (STOP condition 2).

**Phase 0 finding.** The authoritative core Action grammar is the exact
URN `urn:mtmf:iam:actions:<definition-namespace>:<resource>:<verb>-<qualifier>`
(`SECURITY_MODEL.md` §14.3/§15, `mtmf_core.domain.iam_urn.ActionUrn`).
The only supported definition namespace is `system`; Actions never
contain a wildcard. The proposed lowercase dot-separated grammar cannot
represent a core Action URN, and no public-name-to-Action-URN catalog
exists. Implementing the short-name grammar would therefore silently
narrow the contract and fail the plan's own reviewer check
("Exact Action grammar agrees with core").

**Approved resolution (implemented).** The final public Action grammar is
the **exact canonical MTMF Action URN**:

```text
urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>
```

It is validated by a detached grammar in `mtmf-api` that mirrors the core
grammar without importing core: ASCII, ≤ 256 characters, no whitespace,
no `*`, non-empty components, and a `<verb>-<qualifier>` operation. This
is a *widening* to the canonical identity, not a narrowing. A
syntactically valid but unregistered Action is **not** a DTO error; it
becomes a per-item `DENY/UNKNOWN_ACTION` downstream.

**Why it is safe.** AGENTS.md requires callers to request exact Actions
identified by immutable Action URNs; the reviewer checklist requires the
public Action grammar to agree with core. The DTO package still imports
no core type and resolves no catalog. **The human reviewer explicitly
approved this resolution during PR 15 review (2026-10-11); the canonical
Action URN preserves compatibility with `mtmf-core` and avoids an
unnecessary public-name translation layer. W3 is final.**

## W4 — resource union

- `{"kind":"capability"}` — no type/id; capability-level only. It never
  implies object-level access.
- `{"kind":"application_owned","type":...,"id":...}` — scope binding
  metadata only; the PEP enforces its own Tenant/resource isolation.
- `{"kind":"mtmf_owned","type":...,"id":...}` — PR 17 **must** validate
  target class and required qualifiers against authoritative MTMF policy
  before any `ALLOW`; until then this kind fails closed.
- No nested free-form `qualifiers` dictionary. If an approved
  MTMF-owned resource policy cannot be expressed by `{kind,type,id}`,
  stop and request a narrow explicit schema extension rather than
  improvising policy input.
- Bounds: resource type ≤ 128 ASCII, resource id ≤ 256 characters.

## W5 — decisions, reasons, and public errors

- `effect` ∈ {`ALLOW`, `DENY`}. `reason` = `PERMITTED` only with `ALLOW`;
  `DENY` uses `NO_PERMISSION`, `EXPLICIT_DENY`, `UNKNOWN_ACTION`,
  `INVALID_SCOPE`, or `UNSUPPORTED_RESOURCE`.
- `INELIGIBLE_CONTEXT` is **omitted per-item** and retained only in the
  error catalog, per the plan's recommended final choice. Application/
  subscription ineligibility is an envelope-level `INELIGIBLE_APPLICATION`
  error.
- Public error codes and reserved HTTP statuses: `INVALID_REQUEST` (400),
  `UNAUTHENTICATED` (401), `UNTRUSTED_ACTOR` (403),
  `INELIGIBLE_APPLICATION` (403), `REQUEST_TOO_LARGE` (413),
  `UNSUPPORTED_MEDIA_TYPE` (415), `RATE_LIMITED` (429),
  `DEPENDENCY_UNAVAILABLE` (503), `INTERNAL_ERROR` (500).
- `message` is a fixed static string per code; arbitrary `details` are
  not part of v1. No stack traces, tokens, SQL, JWKS, matched policy,
  Tenant-existence oracle, or internal exception strings.
- A syntactically valid unknown Action is a per-item `DENY`, never
  `INVALID_REQUEST`.

## W6 — snapshot metadata

- `issued_at`/`expires_at` are UTC, `issued_at < expires_at`, and
  `expires_at - issued_at ≤ 300s`.
- The DTO only represents the window; PR 17 classifies sensitive Actions
  and applies the effective TTL (60s default / 15s sensitive).
- No Application/Principal/Identity UUID is exposed in the response.
  PR 18 must bind a snapshot to the original immutable request plus the
  verified authenticated context; `request_id` is correlation, not
  authority.

## W7 — implementation technology

- Python 3.14 stdlib only: `dataclasses(frozen=True, slots=True)`,
  `Enum`, `uuid.UUID`, `datetime`, `json`, `re`. `dependencies = []`
  remains true.
- `packages/mtmf-api/src/mtmf_api/py.typed` is shipped.
- The JSON Schema file is hand-authored and contract-only; no schema
  generation library or FastAPI dependency is introduced.

## Approval log

| ID | Status | Approved by | Date | Reference |
| --- | --- | --- | --- | --- |
| W1–W7 | APPROVED | human reviewer | 2026-10-12 | instruction to implement `PR15_DETAILED_EXECUTION_PLAN.md` |
| W3 | APPROVED | human reviewer | 2026-10-11 | explicit human confirmation during PR 15 review: exact canonical MTMF Action URNs as the public Action identifier |
