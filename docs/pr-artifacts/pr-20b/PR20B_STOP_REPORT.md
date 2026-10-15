# PR20B_STOP_REPORT

**PR:** roadmap PR 20B — Deployed End-to-End Conformance and Resilience
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Baseline SHA:** `c7c992a372bb83bae3837efb04b1f19742bb83e2`
**STOP gate:** §6.1 of the execution plan — **P0 mixed batch fixture**.

## 1. Exact gate

> **P0 — mixed batch fixture:** If existing MTMF policy cannot return mixed
> decisions for the same verified actor and an application-owned operation
> without new policy semantics, STOP before adding a misleading test or an
> invented Action.

## 2. Exact file / function / schema inspected

| File | Symbol | Finding |
| --- | --- | --- |
| `packages/mtmf-core/src/mtmf_core/authorization/compiled_policy.py` | `CompiledPolicy.evaluate(action)` / `_exact` / `_wildcard` | Policy indexes are keyed by Action-URN components only: exact `(namespace, resource, verb, qualifier)`, wildcard `(namespace, resource, verb)`. The `ResourceTarget` instance is not an input. |
| `packages/mtmf-core/src/mtmf_core/authorization/authorizer.py` | `Authorizer.authorize` | Order: session validation → `target_is_permitted` (Tenant/management boundary) → `policy.evaluate(request.action)` → post-policy guards. Resource governs only the boundary, never Permission selection. |
| `packages/mtmf-core/src/mtmf_core/authorization/guards.py` | `target_is_permitted` | Compares `request.target_tenant_id` to the session Tenant (or a resolved management scope). No per-resource policy. |
| `packages/mtmf-core/src/mtmf_core/authorization/batch.py` | batch evaluation | Delegates each occurrence's Action to the same guard/policy ordering; no resource-instance predicate. |
| `docs/AUTHORIZATION.md` §5 | Permission resolution | A Permission is an **Action matcher** (`<resource>:<verb>-<qualifier>`); exact vs. qualifier-wildcard only. No resource-instance matching. |
| `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` §11 | Resource qualifier | `ResourceTarget` binds a capability decision to a specific resource **where MTMF evaluates it**; the PEP enforces domain resource/data isolation. The PDP per-Action decision is policy-derived. |
| `sql` / `mtmf.permission` schema | Permission URN | `urn:mtmf:iam:permissions:system:document:read-object` expresses action matching, not a document-instance predicate. |

## 3. Observed behavior (reasoning, not fabricated execution)

For one verified actor in one Tenant, the policy decision is a pure function of
the requested **Action**. Two T1 documents, `D1` and `D3`, both read with
`urn:mtmf:iam:actions:system:document:read-object`:

- Alice (holds the fixture `reference-document-reader` Role) → both occurrences
  ALLOW.
- Bob (holds no Role) → both occurrences DENY.

There is no existing Policy / PermissionSet / Permission shape that expresses
"ALLOW document D1, DENY document D3" for the same actor and Action. A single
batch therefore cannot contain a mixed ALLOW/DENY pair for one verified user
under existing contracts.

## 4. Attempted proof / evidence

- Source inspection of `CompiledPolicy`, `Authorizer`, `guards`, and
  `batch.py` (table above).
- Confirmed the existing fixture registers exactly one document Action and one
  matching Permission (`scripts/pr20a_reference_fixture.py`
  `DOCUMENT_READ_ACTION`, `DOCUMENT_READ_PERMISSION`).
- Confirmed `BASELINE_ACTIONS` (`packages/mtmf-core/src/mtmf_core/domain/action.py`)
  contains no second `document:*` Action.
- No mixed-batch deployed test was added, because no valid contract produces
  the condition; adding one would fabricate a decision or invent an Action.

## 5. Missing invariant / primitive

A resource-instance-scoped policy predicate (for example a Permission or
policy binding that constrains matching to a specific `ResourceTarget`), or an
approved fixture Action with a corresponding real app-owned operation, is
required to demonstrate mixed decisions in one verified-user batch. Neither
exists under the approved design.

## 6. Smallest decision needed

Choose exactly one, via explicit architecture review:

1. **Approve a resource-scoped policy mechanism** (new documented semantics),
   after which a mixed batch can be evaluated honestly; or
2. **Approve a second fixture Action plus a real app-owned operation**
   (for example metadata vs. body disclosure), each with reviewed fixture
   registration, so a same-row mixed batch is meaningful; or
3. **Formally descope the P0 mixed-batch deployed proof** as not representable
   under the approved personal/Action policy model, and rely on the local
   atomic-disclosure unit tests plus the all-allow/all-deny deployed cases.

Until one is approved, PR 20B cannot produce the P0 deployed proof.

## 7. Gate status at STOP time

| Gate | Status |
| --- | --- |
| P0 mixed-batch deployed proof | **BLOCKED / STOP** |
| Other Part B batch-route unit contracts | implemented and unit-tested (not a substitute for P0) |
| Deployed lifecycle/spoofing/snapshot/fault/concurrency matrices | attempted as far as the plan allows; see `PR20B_DEPLOYED_ACCEPTANCE_REPORT.md` |
| Canonical gates | see `PR20B_FINAL_ACCEPTANCE_REPORT.md` |

## 8. Untouched resources

- `packages/mtmf-api/**`, `packages/mtmf-client/**`, `packages/mtmf-core/**`,
  `packages/mtmf-service/**` — unchanged.
- `packages/mtmf-core/.../sql/**` and migrations — unchanged (head remains
  `0013`).
- Protected built-in policy manifests and `dev/keycloak/expected-*.json` —
  unchanged.
- Default `mtmf` Compose project, PR 19C acceptance project, and all
  ATI/Darkula resources — untouched.
- No new Action, Role, Permission, migration, or runtime grant was invented.

## 9. Non-DONE declaration

Because the P0 mandatory deployed proof cannot be executed, **PR 20B is NOT
DONE.** `docs/ROADMAP_V01.md` is not marked DONE for PR 20B. This STOP is an
explicit, recorded deviation, not a skipped acceptance case and not a
fabricated PASS.

---

## Addendum — 2026-10-15: P0 STOP RESOLVED by approved follow-up 01

The historical STOP above is preserved unchanged. The owner subsequently
approved the genuine second application operation described in §6 option 2:
a metadata-only Document read with its own exact Action
`urn:mtmf:iam:actions:system:document:read-metadata` and matching Permission,
provisioned through existing sanctioned stored functions.

Follow-up 01 (validated SHA `7f9092ddebb7913059a03c6996e5394180247bc2`) produced
the real, single-batch, same-actor, same-document mixed decisions through the
deployed PDP (`ALLOW read-metadata` + `DENY read-object` for Bob, in both
orders), with the PEP returning `403` and zero disclosure. See
[`PR20B_FOLLOWUP01_ACCEPTANCE_REPORT.md`](PR20B_FOLLOWUP01_ACCEPTANCE_REPORT.md)
and [`PR20B_FOLLOWUP01_SECURITY_REVIEW.md`](PR20B_FOLLOWUP01_SECURITY_REVIEW.md).
No MTMF authorization semantics, migration, protected policy, or production
grant changed. The earlier non-DONE declaration applied only to the pre-follow-up
implementation; PR 20B is now DONE on the follow-up SHA.
