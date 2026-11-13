# PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED

**Status:** **PROPOSED — NOT IMPLEMENTED — STOP-P24P-TOPOLOGY**
**PR:** roadmap **PR 24P** — Operator and Pre-Tenant Privileged Execution Prerequisite
**Artifact:** `docs/pr-artifacts/pr-24p/PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md`
**Decision authority:** none. This is a **proposal-only** development-profile summary. Human approval is later and separate.

> **Authoritative source:** this artifact summarizes the frozen decision request.
> If there is any discrepancy, **`PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md`
> §5B is authoritative**. This file is not a second source of truth and does not
> authorize any implementation, startup change, role, grant, socket, secret, or
> deployment resource.

## Purpose and decision authority

Describe the proposed, strictly opt-in local development bootstrap for exactly
one dedicated non-root SYSTEM operator and its approved
`urn:mtmf:iam:roles:system:application-administrator` assignment. The proposal
exists because Field 5 otherwise prohibits initializer-created SYSTEM
assignments. It is **not approved** and cannot be generalized to production.
`STOP-P24P-TOPOLOGY` remains active.

No production build, environment, image, config path, or startup script may
activate this fixture. Approval of the production topology does not approve this
fixture, and vice versa.

## Frozen non-secret fixture literals

| Item | Proposed literal |
| --- | --- |
| Profile ID | `mtmf-pr24p-local-development-v1` (**PROPOSED, NOT APPROVED**) |
| Deployment mode | `development` (**PROPOSED**) |
| Compose project | `mtmf` (**PROPOSED**) |
| Canonical issuer | `https://keycloak.mtmf.test:28443/realms/mtmf-dev` (**PROPOSED**) |
| Keycloak operator username | `mtmf-dev-operator` (**PROPOSED**) |
| SYSTEM Role | `urn:mtmf:iam:roles:system:application-administrator` (**PROPOSED**) |
| Opt-in selector | `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true` (**PROPOSED; unset/false disables**) |
| Fixture provenance label | `dev-fixture:mtmf:pr24p:system-operator:v1` (**PROPOSED**) |

The operator is a Keycloak **interactive user**, not the `mtmf-admin`
master-realm administrator, not the ordinary development user
(`MTMF_DEV_USER_USERNAME`), and not the MTMF root Identity/Principal. Its actual
immutable Keycloak `sub` must come from the approved `KeycloakDevUserProvisioner`
verification path; no guessed, literal, username-derived, or environment-supplied
subject is acceptable.

No Tenant membership, Tenant Role assignment, stewardship, or ownership is
created for this SYSTEM operator. No new Action, Permission, Role, IdP, client,
grant type, or token flow is introduced.

## Future one-command startup sequence

This is a future design, **not current behavior** and not a command to run:

```text
0  PRE-FLIGHT: accept only exact MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true for
   privileged setup; mode=development, project=mtmf, canonical issuer/client,
   reviewed manifest, credential custody, and approved UID/socket/network/
   secret paths. Abort before side effects on noncanonical/unknown config.
1  START BASE: start only MTMF-owned PostgreSQL, Keycloak and canonical TLS
   forwarder; perform existing health/issuer probes.
2  MIGRATE + BASE FIXTURES: run the existing short-lived initializer, including
   migration to head 0016, mandatory runtime privilege postflight, and ordinary
   fixture verification. Revision 0016 installs owner-owned PUBLIC-denied
   functions without requiring or creating mtmf_control_exec and without
   granting it EXECUTE. No SYSTEM operator in --migrations-only mode.
3  CONTROL LOGIN: only because exact opt-in was approved, run a separate
   short-lived cluster-administrator action: CREATE mtmf_control_exec if absent
   and pristine, or verify a fully provisioned approved existing role. Never
   invoke default three-role password provisioning or rotate migrator/runtime.
4  CONTROL GRANTS: with approved installation-only migrator/SET ROLE mtmf_owner
   authority, install exactly five §7 EXECUTEs; scope CONNECT/USAGE as needed;
   verify no other EXECUTE, DML, membership or PUBLIC/runtime reachability.
   Previously installed role: verify-only; unexpected partial state STOP.
5  OPERATOR FIXTURE: only after steps 2–4 verify, run the short-lived installer
   with the existing verified Keycloak-sub flow and owner-approved fixture path.
   Create mtmf-dev-operator only in a clean fresh state; otherwise verify exact
   immutable provenance. No self-grant, adoption, regrant or repair.
6  EXIT INSTALLERS: terminate admin/migrator/Keycloak-master contexts; prove
   their secrets and mounts are absent from worker and ordinary service.
7  START ISOLATED WORKER + PUBLIC SERVICE: non-root worker with only restricted
   control/read credentials and private sockets; admission socket
   test-harness-only. Unprivileged service with mtmf_runtime only.
8  PROVE AND REPORT: run real peer-UID, socket, role/grant, effective-privilege,
   genuine-token and compromised-runtime probes; report privileged readiness
   only if all pass, otherwise fail closed.
```

## Migration, role-provisioning, and opt-out semantics

- Future `0016` is **role-independent and unconditional**: it installs the
  owner-owned, PUBLIC-denied schema/functions for all instances and does not
  create `mtmf_control_exec`, grant it EXECUTE, branch on the flag/profile, or
  add any `mtmf_runtime` grant. It must pass the runtime postflight with the
  control role absent or present. A migration rerun must not strip or rotate a
  previously approved control role.
- Only the opt-in installation phase, after migration, may use administrator
  authority to create/verify the restricted control LOGIN, then owner authority
  to install/verify exactly five grants, then install the operator fixture.
  `--provision-control` and `--verify-control` are future modes; neither exists
  or may be invoked now, and neither changes current default/`--verify`
  behavior.
- Opt-out (unset/exact false) runs the ordinary stack and does **not** create,
  repair, revoke, drop or rotate control role/grants/fixture, and never starts
  the worker. Fresh opt-out leaves no new control objects. A previously opted-in
  database may retain role/grants/fixture; the flag is **not** revocation.
  Actual revocation requires a distinct human-approved process or explicit
  MTMF-only destructive reset.


## Keycloak user/subject and operator binding provenance

- One user only: `mtmf-dev-operator` in realm `mtmf-dev`.
- Creation is allowed only when the exact user is genuinely absent, opt-in is
  exact `true`, the profile is canonical, an owner-only development password
  file is valid, and Keycloak Admin REST create/read-back is verifiable.
- Never print, commit, default, or synthesize a password; never reset an existing
  password, enable a disabled account, impersonate a user, or retry an uncertain
  create.
- An existing username without a matching MTMF fixture is an adoption/partial
  install: STOP. A different subject, disabled/federated/drifted account,
  missing/deleted/LOCAL/root Identity, inactive Principal, or unexpected Tenant
  membership: STOP.
- Standard Authorization Code user sign-in with the approved client remains
  mandatory for real operator requests. No password grant, impersonation,
  fabricated JWT, or authentication bypass is permitted.
- The fixed SYSTEM Role must already be the approved built-in seed with the PR 21
  manifest. Missing/mismatched seed: STOP-SEED; never synthesize or repair it.

## Installation transaction and replay/idempotency behavior

The fixture runs only as a short-lived installation job using the privileged
migrator with explicit `SET ROLE mtmf_owner` after approved migrations and role
topology verification. The public service and persistent worker never receive
migrator, Keycloak Admin REST, root, or owner credentials.

Provenance uses the fixed label `dev-fixture:mtmf:pr24p:system-operator:v1` plus
the eventual human decision ID as a separate installation-decision reference
(never fabricated by the installer). The append-only event records the source
label, canonical Identity/Principal, Role URN, assignment UUID, `CREATED` outcome,
correlation UUID, and timestamp. Repeated verified bootstrap writes nothing.

Deterministic UUIDv5 names (using the existing `_deterministic(...)` helper and
its shipped namespace) are proposed after the real Keycloak `sub` is verified:

```text
pr24p:dev-operator:principal:<actual-Keycloak-sub>
pr24p:dev-operator:identity:<actual-Keycloak-sub>
pr24p:dev-operator:binding:<actual-Keycloak-sub>
pr24p:dev-operator:system-assignment:<actual-Keycloak-sub>
pr24p:dev-operator:installation-correlation:<actual-Keycloak-sub>
```

No general Role-grant API, self-grant, automatic repair, regrant of a revoked
assignment, or root bootstrap is permitted. D01–D20 in §5B.5 are normative.

## Secrets, UIDs, sockets and runtime isolation

- Distinct non-root UIDs for control worker, operator client, admission test
  ingress, and runtime; no UID collapsing; real `SO_PEERCRED` validation.
- Separate private operator and admission sockets under the §5/§5A contracts;
  no TCP, localhost, group-only, or Podman-socket fallback.
- Admission socket is test-harness-only in PR 24P.
- Worker secret mounts exclude Keycloak master-admin, owner/migrator DB
  credentials, host Podman socket, and public-service secret volumes; no secrets
  in argv, logs, repository, or shell history.
- `mtmf_control_exec` has exactly five approved function EXECUTEs and no table/
  sequence DML, owner/migrator membership, SUPERUSER, CREATEROLE, CREATEDB,
  BYPASSRLS or CREATE-on-schema; CONNECT/USAGE is separately scoped and verified.
  `mtmf_runtime` keeps exactly 78 signatures.
- Only the `mtmf` Compose project may be managed; no discovery or destructive
  action against ATI, Digr, Darkula, or unrelated projects.
- Real deployed UID/role/socket/mount negative controls are required; chmod on a
  shared UID, mocks, or fake credentials are not evidence.

Exact numerical UIDs/GIDs, paths, namespace mapping, secret mount/rotation owner,
and socket modes remain **UNRESOLVED — HUMAN APPROVAL REQUIRED**.

## Portable Linux development deployment profile (PROPOSED — NOT APPROVED)

The developer host may be native Linux, Windows, or macOS, but privileged
Unix sockets and identity checks execute *only inside* native Linux/WSL2 or
a Podman-managed Linux VM. The operator CLI is an ephemeral non-root
MTMF-owned container, never a Windows/macOS host-side direct socket client.
The approved OIDC Authorization Code verification remains mandatory.

| Role | Candidate Linux-container UID | Socket/secret access |
|---|---:|---|
| Control worker | `24501` | Both private socket volumes; worker-only DB secret |
| Operator CLI | `24502` | Operator socket only; no worker secret |
| Admission test | `24503` | Admission socket only; PR 24P test harness |
| Ordinary runtime | `24504` | Neither socket nor control secret |

Proposed socket locations: `/run/mtmf-control/operator/operator.sock` and
`/run/mtmf-control/admission/admission.sock` on different MTMF-scoped
Linux-native volumes. Proposed directory/socket modes: `0710`/`0660`,
with distinct narrow groups and exact worker-observed `SO_PEERCRED` UID
checks. Proposed worker secret path: `/run/secrets/mtmf-control-db`,
owner-only file. Proposed network: private project-scoped control network
with no worker published ports; public service is excluded.

These are **candidates**, not observed user-namespace IDs, approved §8
values, or compatibility evidence. Windows/macOS shared filesystem paths
do not automatically provide POSIX socket/permission semantics. Each
installation must record Linux/kernel/Podman version, effective UID/GID
mapping, peer creds, socket modes, mounts, control network and DB grants.
Run genuine permitted/denied peer and secret probes as real containers.
Failure or unmeasurable mapping triggers `STOP-DEPLOYMENT`; no TCP,
shared UID, `0777`, Podman-socket proxy, or automatic mapping substitution.
Passing on one Linux environment does not certify another.

§5B.6 in the topology decision record is authoritative. All original
§8/§8A host choices and §9 approval questions remain unresolved.
No code, deployment, role, socket or test is authorized by this profile.

## Forbidden deployment modes and emergency stop

- Any non-`development` mode with the flag `true`: error before Keycloak/
  PostgreSQL access.
- Any issuer/project/client other than the canonical development profile: error,
  never a fallback.
- Production automatic bootstrap, dev-fixture provenance in production, ordinary
  dev user/root SYSTEM authority, dynamic Role selection, or a self-grant:
  forbidden.
- If UIDs collapse, runtime reaches a socket/secret, probes fail, or an
  unreviewed/ambiguous fact appears: fail closed and STOP; never claim partial
  readiness.
- The flag alone is **not** authorization evidence.

## Future acceptance matrix E01–E20 (NOT EXECUTED)

All rows are **planned only**. No test, fixture, container, token, database, role,
or benchmark was executed in Amendment E.

| ID | Required scenario | Future required evidence |
|---|---|---|
| E01 | Missing/false bootstrap flag | Test both fresh opt-out and opt-out after prior opt-in: existing dev stack unchanged; no new control mutation/worker; prior persisted role/grants/fixture may remain. |
| E02 | Exact true + canonical dev mode/issuer/profile | Pre-provision role absence accepted (not STOP), then migration/postflight, administrator role creation, owner grants, fixture, and all gates. |
| E03 | True on non-dev mode/noncanonical issuer | STOP before DB, Keycloak or container privilege changes. |
| E04 | Fresh isolated Keycloak + PostgreSQL, valid password file | Dedicated `mtmf-dev-operator` created once; actual `sub` verified from Keycloak REST response. |
| E05 | Repeated `up` against unchanged fixture | Verify-only existing role/grants/fixture; same IDs, one ACTIVE assignment, one immutable creation event; no write, password reset, regrant or audit inflation. |
| E06 | Existing same username without matching MTMF fixture | STOP; no automatic takeover. |
| E07 | Disabled/ambiguous/drifted/federated Keycloak operator | STOP; no account repair. |
| E08 | Different user subject from previous fixture | STOP; no cross-subject binding. |
| E09 | Deleted/LOCAL/root operator Identity or inactive Principal | STOP; no assignment. |
| E10 | Approved SYSTEM Role seed missing/drifted | STOP-SEED; no policy synthesis. |
| E11 | Assignment previously REVOKED | STOP; no regrant or alternate UUID. |
| E12 | Partial Keycloak create vs PostgreSQL failure | No blind retry or auto rollback of Keycloak; stable diagnostic/provenance. |
| E13 | Real standard-flow signed operator token | Exact issuer/audience/client/subject ACTIVE binding and SYSTEM authorization succeed for allowed Action; denied Action remains DENY. |
| E14 | Service-only token or forged user claims | Operator request denied; no DB mutation. |
| E15 | Runtime UID tries operator Unix socket | Peer rejected under real container user-namespace mapping. |
| E16 | Runtime UID tries admission socket and worker DB secret | Both unavailable; no public proxy or shared secret mount. |
| E17 | Runtime DB role invokes any of five control functions or protected DML | Permission denied; exact 78-signature runtime allowlist intact and exact post-grant least-privilege surface. |
| E18 | Control DB role tries direct table DML or `SET ROLE mtmf_owner` | Permission denied; exactly five reviewed EXECUTEs and no additional reachability. |
| E19 | One-shot initializer exited, long-lived containers inspect | Neither public service nor control worker holds installer, Keycloak master-admin, owner or migrator credentials. |
| E20 | Restart/reset/transport failures | No premature readiness; partial-install state STOPs; MTMF-only resource scope; opt-out is not revocation; explicit destructive reset gate; no other project touched. |

Future acceptance requires real PostgreSQL, actual rootless Podman containers with
distinct UIDs/mounts, genuine signed local Keycloak user tokens, production worker
code, the canonical quality/security/Rust/integration gates, and the deployed
negative-control harness. Benchmarking is out of scope until separately approved.

## Human-owned unresolved deployment parameters

- Dev operator password-file path, file ownership, mount, and permissions.
- Admin/provisioner/initializer/control/runtime UID/GID and user-namespace mapping.
- Operator and admission socket absolute paths, owners, groups, and modes.
- Control DB secret path, ownership, rotation owner, and Podman network attachment.
- Human-approved fixture decision ID/provenance reference.
- Runtime/image versions and hardware when benchmarking is eventually approved.

Until these are approved with all §5B fields, the status remains
**`PR24P_BLOCKED_TOPOLOGY_APPROVAL`** and no implementation may begin.
