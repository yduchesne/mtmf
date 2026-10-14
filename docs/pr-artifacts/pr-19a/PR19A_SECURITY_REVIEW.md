# PR19A_SECURITY_REVIEW

**PR:** roadmap PR 19A — verified-provenance mutation audit.
**Status:** PARTIAL / BLOCKED (contract scaffold only; no database change).
**Base commit:** `44c6c0b7230ccbd4820866fb97f36896566753a5`.
**Normative references:** `docs/SECURITY_MODEL.md`, `docs/AUTHORIZATION.md`, `docs/DATABASE.md`, `docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md`.

## 1. Actor-provenance guarantee (what PR 19A actually claims)

PR 19A claims **nothing about database-verified human identity**. The implemented contract records an *application-verified* decision that does not yet reach any database write:

```
VerifiedActorContext + exact authorized operation (trusted application)
    -> VerifiedMutationProvenance (internal, immutable)
    -> [would-be] UnitOfWork / repository operation
    -> [would-be] restricted runtime connection
    -> [would-be] reviewed stored function
    -> [would-be] authoritative mutation + append-only audit row
```

Because Phase 0 found no category-A path, the last four links do not exist and **no attribution guarantee is claimed for any operation**. The PostgreSQL role is an application credential, not an end-user identity.

Explicit non-claims:

- No operation is marked audited/covered by PR 19A.
- No `attribution_source='DATABASE_VERIFIED'` is written anywhere; the plan forbids it and no value is written at all.
- No cryptographic database attestation of the actor exists or is claimed.
- The existing membership-removal `actor_identity_id` remains **caller-asserted and unverified**; it was not relabelled.
- A compromised application/runtime credential can forge provenance parameters; PR 19A does not defend against a compromised runtime process. That is a separate design decision (STOP trigger #5).

## 2. Runtime-credential threat model

| Fact | Consequence |
|---|---|
| A single `mtmf_runtime` login is shared across Tenants. | Database-level per-Tenant isolation is not provided. A runtime process can invoke any granted function. |
| Runtime holds `EXECUTE` on 29 mutating functions (6 already audited removals, 19 repository writes, 4 role-assignment writes). | Any of these can be invoked without a verified actor or atomic actor audit. |
| Runtime holds no direct table DML and no audit-table write. | It cannot directly insert/update/delete audit rows or bypass a stored function's structural constraints. |
| `SECURITY DEFINER` stored functions elevate database privileges. | `EXECUTE` is database capability, not domain authorization; the application `Authorizer` remains authoritative. |
| PostgreSQL ordinary custom GUCs can be set by the same role. | `SET LOCAL`/`current_setting` is **not** identity proof and must not be used as an authentication boundary (locked decision 6). |
| `mtmf_owner`/migrator/admin are trusted. | They are outside this guarantee and require separate operational controls and audit. |

The plan's locked decision 7 notes that **a runtime caller who retains direct `EXECUTE` on legacy mutators can bypass new auditing**. Since no operation was migrated and no legacy `EXECUTE` was revoked, this bypass is necessarily still open for every uncovered mutator. That is recorded as BLOCKED, not as closed.

## 3. SQL grant matrix (current, unchanged by PR 19A)

Runtime `EXECUTE` allowlist = **77 signatures** (the executable manifest in `mtmf_core.persistence.postgres.roles`): 6 membership-removal + 44 repository read/write + 8 role-assignment + 9 TenantManagementGroup/root reads + 8 Application-registry reads + 2 authentication-binding reads. `DATABASE.md`'s earlier "75" wording predates v011's two reads.

| Function group | Runtime `EXECUTE` | Direct table DML | Audit table write | Actor attribution |
|---|---|---|---|---|
| 6 membership removals | yes | no | yes (`membership_removal_audit`, atomic) | caller-asserted, explicitly unverified |
| 19 repository read/write (entity/membership/Role/authz) | yes | no | no | none |
| 4 role-assignment add/remove | yes | no | no | none |
| 3 root/stewardship mutators | **no** | no | yes (`stewardship_audit`) | stewardship contract (operator/installation) |
| Tenant lifecycle / TenantManagementGroup / Application-registry / authentication-binding mutators | **no** | no | no | operator/installation only |
| Private helpers (`role_insert_children`, validators, guards) | **no** | n/a | n/a | n/a |

`PUBLIC` `EXECUTE` is revoked; owner default privileges grant none; the mandatory post-upgrade verifier enforces the exact allowlist. PR 19A changed none of this.

## 4. Bypass analysis

| Bypass vector | Current state | Required before any operation could be called "covered" |
|---|---|---|
| Runtime invokes a legacy uncovered mutator directly | Open (these functions remain runtime-granted) | Migrate legitimate callers, then `REVOKE EXECUTE` on the legacy signature and prove denial on the real runtime login. |
| Runtime writes the audit table directly | Denied (no runtime table DML) | Unchanged. |
| Caller forges a GUC/session setting | Not used as identity anywhere; no GUC-based provenance | No GUC is trusted. |
| Caller supplies a raw actor UUID to a stored function | Would be unverified input | Only pass provenance from a reviewed `ALLOW` path; the database still cannot independently verify it. |
| Runtime fabricates provenance parameters to a new audited function | N/A (no such function) | Documented residual limitation under the trusted-service model. |

No bypass was "fixed" by documentation: the only honest state is that every uncovered mutator remains uncovered.

## 5. Cross-Tenant, stewardship, and no-double-record review

- No Tenant boundary, scope/dominance, stewardship, or eligibility semantics were changed.
- No membership-removal or stewardship audit row is duplicated, rewritten, or removed.
- No root-recovery logic or its separate durable operator audit was touched.
- Soft-delete/lifecycle behavior is unchanged (no schema change).

## 6. Conclusion

The implemented contract is a strictly internal, fail-closed scaffold. It creates no new attack surface (no route, DTO, SQL, or grant), and it cannot be mistaken for audit coverage because its registration map is empty and it is not wired to any write path. The PR 19 database mutation-audit STOP remains open. See `PR19A_STOP_REPORT.md`.
