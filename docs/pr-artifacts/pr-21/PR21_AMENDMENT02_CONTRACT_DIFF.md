# PR21_AMENDMENT02_CONTRACT_DIFF

**PR:** roadmap PR 21 — Amendment 02
**Status:** documentation-only. All capabilities remain **PROPOSED / NOT
IMPLEMENTED**. Exact Action/Permission/Role literals remain STOP-03 open.

## 1. Amendment 01 → Amendment 02 mapping

| Area | Amendment 01 | Amendment 02 |
| --- | --- | --- |
| Pre-Tenant entitlement | STOP-02 open; general proposal | **P02 approved:** MTMF-persisted per-Application entitlement, `ACTIVE`/`REVOKED` (terminal), system grant/revoke, immutable provenance, append-only revocation, quotas, new-Identity branch only; not a Role |
| Exact Actions/Roles | STOP-03 open; candidate names only | **STOP-03 remains OPEN (conditional):** complete grammar-validated candidate manifest with per-row status; no literal/grant approved |
| Registration authority | STOP-04 open | **P04 approved:** system-authorized registration; Tenant-admin subscription only with `ACTIVE` registration; narrow first-Tenant composite exception |
| Terminal replacement | STOP-05 open; "policy pending" | **P05 approved:** fresh-UUID replacement only; system authority for registration replacement, Tenant-scoped for subscription replacement with `ACTIVE` registration; `SUSPENDED→ACTIVE` is in-place resume |
| Credential binding | STOP-06 open | **P06 approved:** separate credential administration; Application CRUD never mints credentials; PR 14 boundary preserved; PR 24 contract gated |
| `resolve-or-provision` | outcomes + entitlement proposal | entitlement gating, ordering, quota/idempotency, no-mutation reads, credential separation |
| Application management | generic | system authority; suspend/resume in place; retire terminal; no secrets; credential separate |
| Registration/subscription HTTP | create/inspect/lifecycle sketch | explicit replacement-vs-resume, `ACTIVE`-registration prerequisite, CAS, non-enumeration |

## 2. Backward compatibility

- D1–D8 (Amendment 01) are unchanged and remain binding.
- All API paths and outcome names from Amendment 01 are retained; Amendment 02
  refines semantics and adds the entitlement/registration/replacement/
  credential-separation rules. No previously proposed path is removed.
- PR 13 domain transitions, guards, historical rows, unique current-row
  constraints, and operator-only mutation posture are unchanged.
- `POST /v1/management/tenants` remains DEFERRED; no endpoint is implemented.

## 3. Preserved invariants

- Two-token trust boundary; default DENY; SYSTEM/root isolation; exact
  Action/Permission model; stewardship invariants; stored-function-only writes;
  atomic mutation audit; PR 13 terminal lifecycle; PR 14 verified credential
  binding; no network I/O inside the UoW; no cross-IdP/DB atomicity claim.

## 4. New/changed semantics summary

| Item | New/changed |
| --- | --- |
| Entitlement | new MTMF-owned per-Application state; grant/revoke system authority; quotas |
| Initial registration+subscription | permitted in the entitled first-Tenant transaction (composite exception) |
| Registration | system authority; required before an `ACTIVE` subscription counts |
| Subscription | Tenant-admin-managed with `ACTIVE` registration; replacement new UUID |
| Replacement | fresh UUID + predecessor audit; terminal never reopened; retired Application cannot reopen |
| Credential binding | separate gated contract; no secret exposure; eligibility fails on suspend/retire |
| Actions | candidate manifest only; STOP-03 open |

## 5. PR 22–26 ownership

| PR | Owns |
| --- | --- |
| 22 | entitlement persistence; atomic Tenant + initial registration/subscription; uniqueness/idempotency; stored-function boundary; replacement predecessor-audit schema if required |
| 23 | verified global Identity/Principal resolution+reuse; first steward; pre-Tenant verified-subject seam; entitlement enforcement |
| 24 | `ResolveOrProvisionTenant`; Tenant resolve/selection; Application create/inspect/suspend/resume/retire; system registration; Tenant-admin subscription; gated credential contract |
| 25 | invitations + pre-membership acceptance |
| 26 | deployed two-Application/one-Tenant conformance incl. entitlement/quota/replacement/credential negatives; COLD/REPEAT/RECREATE |

## 6. Remaining unknowns (require human approval)

1. **STOP-03:** every new literal Action/Permission, the system-management Role
   composition, and the additive seed migrations (see the manifest).
2. Entitlement table/function shape and operator quota defaults (PR 22/23
   implementation; semantics fixed by P02).
3. Credential-binding management contract — only if the PR 14 trust model
   supports it; otherwise a separately named prerequisite (P06).
4. Any additive predecessor-reference schema support for replacement audit
   (PR 22/24).


---

## Amendment 03 closure (2026-10-15)

The STOP-03 comparisons above (`STOP-03 open; candidate names only` /
`STOP-03 remains OPEN (conditional)`) are historical. STOP-03 was **CLOSED** by
`PR21-STOP03-APPROVAL-2026-10-15` — the exact manifest, 11/2/7 composition, and
two admission-only zero-grant identifiers. See
[`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md).
Nothing is implemented.
