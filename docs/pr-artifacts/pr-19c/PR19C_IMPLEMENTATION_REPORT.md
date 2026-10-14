# PR19C_IMPLEMENTATION_REPORT

**PR:** roadmap PR 19C — first authenticated, authorized, atomically audited management mutation.
**Date:** 2026-10-14.
**Base:** `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db`; prior docs STOP commit `ed206ab`.
**Authority:** human-approved `PR19C_AMENDMENT_01_APPROVED_POLICY_AND_CONCURRENCY.md`.
**Status:** **PARTIAL — not DONE.** Core policy/audit/persistence + application orchestration implemented and validated; HTTP/DTO/service composition and live Keycloak acceptance are not implemented.

## 1. What was implemented

### 1.1 Exact authorization policy (Amendment §A–B)

- `sql/v012/02_membership_add_policy.sql` — installation-only, idempotent, fail-closed seed adding the exact Action `urn:mtmf:iam:actions:system:identity-group-membership:add-object` and one exact ALLOW Permission `urn:mtmf:iam:permissions:system:identity-group-membership:add-object` (fixed UUID `5ad78530-2945-4f66-8ce1-ddbd8794d7b2`, position `1`) to the existing Tenant Administrator PermissionSet.
- `sql/v012/06_builtin_seed_replay_compat.sql` — supersedes `install_builtin_policy` (the v006 file itself is unchanged) so the historical Gate M installer remains replay-safe against the cumulative state; the original eleven Permissions and all immutable UUIDs are still verified.
- `sql/v012/05_security_mutation_assertions.sql` — cumulative assertions (3 historical Actions + 1; 13 historical Permissions + 1; other twelve built-in Roles unchanged; no wildcards; exact runtime allowlist; legacy bypass closed).
- `docs/SECURITY_MODEL.md`/`databases` updates are **not** made in this partial state (left for acceptance).

### 1.2 Audit and atomic mutation (Amendment §E)

- `sql/v012/01_security_mutation_audit_schema.sql` — unpartitioned append-only `mtmf.security_mutation_audit` with the prescribed columns, indexes, and UPDATE/DELETE/TRUNCATE guards; no runtime table DML.
- `sql/v012/03_membership_add_control.sql`:
  - `mtmf.identity_group_membership_add_lock(uuid, uuid, uuid, uuid)` — bounded, ordered row-lock/recheck protocol (Tenant → designation → actor/subject entities and memberships → Group → policy dependencies).
  - `mtmf.identity_group_membership_add_verified(…11 args…)` — re-validates the target binding and steward guard, then `INSERT … ON CONFLICT DO NOTHING RETURNING` and one audit row iff a membership row was inserted; any audit failure aborts the statement.
- `sql/v012/04_security_mutation_grants.sql` — both new functions owner-owned `SECURITY DEFINER`, `PUBLIC` revoked, runtime-granted; legacy `identity_group_membership_add(uuid,uuid)` revoked from runtime/PUBLIC and demoted to `SECURITY INVOKER` so the "every SECURITY DEFINER function is runtime-granted" posture stays exact.

### 1.3 Privilege manifest and provenance

- `mtmf_core/persistence/postgres/roles.py` — legacy entry removed from the repository manifest; `_SECURITY_MUTATION_FUNCTION_ARGUMENTS` added with the two v012 signatures; `expected_runtime_signatures()` is now 78.
- `mtmf_core/persistence/postgres/migration.py` — `HEAD_REVISION = "0012"`.
- `mtmf_core/application/mutation_provenance.py` — registers exactly `identity_group_membership` + the approved Action; the registry remains a whitelist, not an authorization mechanism.

### 1.4 Persistence and application orchestration

- `MtmfSpi`/`IdentityGroupMembershipRepository` gained `lock_verified_add(...)` and `add_verified(...)` (provider-neutral primitive arguments; no application-layer import into persistence).
- `PostgresIdentityGroupMembershipRepository` implements both by calling the reviewed stored functions.
- In-memory provider implements `lock_verified_add` as a no-op and `add_verified` as an idempotent insert.
- `mtmf_core/application/management_memberships.py` — `ManagementMembershipService.add_identity_to_group(...)`: verification outside the transaction, one UoW (lock → effective roles → authoritative exact-Action `Authorizer` → `VerifiedMutationProvenance` + `require_registered_mutation` → audited write → single commit), detached `ManagementMembershipResult`.

## 2. Deviations

| Amendment item | Deviation | Reason |
| --- | --- | --- |
| §E legacy revoke | Function additionally demoted to `SECURITY INVOKER` (body/metadata otherwise preserved) | Preserves the existing exact "every SECURITY DEFINER function is runtime-granted" invariant asserted by `test_fun05`/`test_priv15`; owner/operator access is retained. |
| §B.5 v006 preserved | Added `06_builtin_seed_replay_compat.sql` replacing `install_builtin_policy` | The historical installer asserted one Permission per built-in set; replay after the approved append otherwise fails. The v006 file is unchanged; the 04 historical assertion block is untouched. |
| Existing integration fixtures | Runtime-tests that seeded Identity-Group memberships through the legacy function now seed through the administrator connection (`helpers.add_identity_group_membership`) | The legacy runtime grant is intentionally revoked. |

## 3. Not implemented (honest gaps)

- HTTP `POST /v1/management/identity-group-memberships` route, public DTO/codec, and service composition (`mtmf-api`, `mtmf_service`).
- Live dual-token Keycloak acceptance H01–H05; `mtmf-client` parity is not required by the amendment for this partial step.
- The full deterministic U01–U08/CC-01–CC-07/DB-01–DB-03 case matrix; the concurrency *proof* matrix was executed instead (Amendment §D).
- Documentation updates to `SECURITY_MODEL.md`, `AUTHORIZATION.md`, `ARCHITECTURE.md`, `DATABASE.md`, `AUDIT_OBSERVABILITY_ARCHITECTURE.md` and the PR 19 inventory are deferred until the operation is genuinely covered end to end.

## 4. Uncovered mutators

No new mutators are covered. Only the identity-group membership add is migrated; every other PR 19 inventory gap remains **UNRESOLVED**. No false audit-coverage claim is made.

---

# Amendment 02 addendum (2026-10-14)

Implemented the HTTP/DTO/service layer on top of the Amendment 01 core:

- `mtmf_api/management.py` detached request/response DTOs; `json_codec` strict parser/serializer; additive `ApiErrorCode.FORBIDDEN` (403, `Operation is not permitted`) and JSON-schema enum update.
- `mtmf_service/management.py` narrow adapter that invokes the existing `ManagementMembershipService` once (no double authentication, no second UoW) and maps guard/target denials to opaque `FORBIDDEN`.
- `composition.build_dependencies` now builds **one** shared `AuthenticatedActorContextService` for both the evaluate and management paths and wraps a `ManagementMembershipService`; `ServiceDependencies` carries the new adapter; `asgi.create_app_from_env` forwards it.
- `app.create_app` registers `POST /v1/management/identity-group-memberships` with the shared rate limit, strict media/body guards, dual-token extraction, bounded admission, shared timeout, `201/200` selection, `no-store`, and one terminal management telemetry event (never a batch event).
- Telemetry closed additions: `AuditEventName.MANAGEMENT_MUTATION`, `AuditOutcome.CREATED/NO_OP`, `AuditReason.OPERATION_FORBIDDEN`, `HttpRoute.MANAGEMENT_MEMBERSHIP_ADD`, `SpanName.HTTP_MANAGEMENT_MEMBERSHIP_ADD`.

Defect fix: v012 lock/verify functions reused PR 13 SQLSTATEs `MT040`–`MT043` and left `MT044`/`MT045` unmapped. They now use the established `MT002` (prerequisite/guard) and `MT003` (malformed provenance) codes so the adapter can map target/steward failures to opaque `FORBIDDEN` without confusing them with Application-registry integrity faults.

Deviation: the existing `ManagementMembershipService` resolves the actor from tokens itself, so the HTTP adapter injects only that service (not a second actor service); this is the Amendment 02 Step B "do not authenticate twice" case.

Not implemented: live H01–H05 (BLOCKED — see `PR19C_AMENDMENT02_LIVE_ACCEPTANCE.md`); `mtmf-client` connector parity (Amendment 02 Step E forbids inventing it).
