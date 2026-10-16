# PR22A_SCOPE_AND_DEPENDENCY_DECISION

**Roadmap identifier:** PR 22A — Entitlement persistence foundation
**Status:** DONE — ENTITLEMENT FOUNDATION ONLY (acceptance pending final gate rerun).

## 1. Decision

The original roadmap PR 22 is split into an independently shippable foundation
and a blocked composite, with a named privileged-execution prerequisite:

```text
PR 21 approved design (merged main abba785)
        |
        v
PR 22A — entitlement persistence foundation   (this delivery)
        |
        +---------------------------+
        |                           |
        v                           v
PR 23 — verified subject,        PR 24P — privileged operator execution
Identity/Principal and           and narrow pre-Tenant admission boundary
initial stewardship seam
        |                           |
        +-------------+-------------+
                      v
PR 22B — atomic first-Tenant composite, quota, replay, registration,
         subscription, audit
                      |
                      v
PR 24 — HTTP onboarding/management routes
                      |
                      v
PR 25 invitations/client -> PR 26 deployed conformance
```

The original PR 22 record remains historically **PARTIAL — BLOCKED** and is not
renamed or marked DONE.

## 2. PR 22A in scope

- Additive revision `0014`: `mtmf.application_onboarding_entitlement` and
  append-only `mtmf.application_onboarding_entitlement_event`.
- Immutable grant provenance; `ACTIVE`/`REVOKED` terminal lifecycle; single
  `ACTIVE` per Application; explicit positive quota (not consumption).
- Owner-owned `SECURITY INVOKER` grant/revoke/read functions with fixed empty
  `search_path`; `PUBLIC` revoked; **no `mtmf_runtime` grant**.
- Detached domain contract and pure validators.
- Real-PostgreSQL tests including a concurrent duplicate-grant race.

## 3. PR 22A explicitly out of scope (unchanged by this branch)

- Quota **consumption** and the replay/idempotency ledger.
- Any Tenant, registration, subscription, Identity, Principal, membership, or
  steward creation.
- Operator sign-in / SYSTEM-scope assignment / global-target authorization /
  privileged execution adapter (PR 24P).
- Any HTTP route, entitlement grant/revoke route, or runtime-callable proxy.

## 4. Dependency decisions

- **PR 23** supplies the verified-subject and Identity/Principal/initial
  stewardship **transaction participant**; it must not itself commit an ACTIVE
  Tenant.
- **PR 24P** is a named, bounded prerequisite owning only the operator execution
  boundary and the pre-Tenant admission boundary; it is gated by
  STOP-P24P-TOPOLOGY (human-approved execution topology required).
- **PR 22B** composes PR 23 inside one privileged UnitOfWork owned by the
  approved PR 24P adapter; it is blocked until both are merged.
- **PR 24** (HTTP) depends on PR 22B and PR 24P.
- PR 21's 25-row manifest, 11/2/7 grant allocation, zero-grant admission
  identifiers, lifecycle, and operator prerequisites are unchanged.

## 5. Artifact policy

Historical `docs/pr-artifacts/pr-22/*` files are preserved unchanged. All
PR 22A-specific reports are under `docs/pr-artifacts/pr-22a/`. Future PR 23 /
PR 24P / PR 22B artifacts use `docs/pr-artifacts/pr-23/`, `pr-24p/`, `pr-22b/`
respectively after their roadmap identifiers exist.
