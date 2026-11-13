# PR 24P — Recorded Gate A approval and proposed Gate B development manifest

**Document type:** human-decision transcription plus **unapproved** implementation manifest candidate  
**Baseline architecture:** [merged PR #77](https://github.com/yduchesne/mtmf/pull/77), immutable merge commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4`  
**PR 24P status:** IN PROGRESS — `STOP-P24P-TOPOLOGY` remains ACTIVE pending Gate B  
**Date (UTC):** 2026-11-13

## A. Human Gate A approval — RECORDED

| Attribute | Recorded value |
|---|---|
| Decision ID | `MTMF-PR24P-GATE-A-2026-11-13-01` |
| Approving party | MTMF project owner (connected GitHub account `@yduchesne`) |
| Evidence | In this ChatGPT conversation, the user replied **"yes"** immediately after being asked whether they approved the **Gate A architecture specified in the merged PR #77 decision record, without amendments** |
| Exact architecture approved | `docs/pr-artifacts/pr-24p/PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md` at merge commit `4b48f5a14bbadf99b5b30be99a256cf3d47304b4` |
| Scope | All twelve topology fields, §§5/5A/5A.6/5A.7/5B/5B.6/5B.6A/6/6A/6B/7, five SQL signatures, immutable operator/security contracts, portable manifest schema and required Gate C acceptance obligations |
| Amendments / conditions | **None** to the approved architecture; approval is for Gate A only |
| Recorder | Assistant transcribing the user's explicit affirmative response; **not** an independently signed or cryptographically authenticated approval record |
| Gate B | **NOT APPROVED** |
| Gate C | **NOT EXECUTED** |
| Implementation authorization | **NOT GRANTED** |
| Mandatory STOP | `STOP-P24P-TOPOLOGY` **ACTIVE**, waiting for Gate B |

The explicit user response authorizes recording the Gate A architecture decision
**only**. It is not assent to any specific UID, GID, pathname, credential,
secret, socket ACL, deployment topology, or implementation. Those remain a
separate Gate B human choice.

## B. Gate B — concrete portable development manifest CANDIDATE (NOT APPROVED)

**Candidate manifest ID:** `mtmf-pr24p-development-gateb-v1`  
**Scope:** development only; rootless Podman inside a Linux execution environment
(native Linux, WSL2 Linux, or Podman-managed Linux VM).  
**Reference:** the merged PR #77 contract. No host-OS identity is trusted in
lieu of container/worker-observed credentials.

### B1. Project, identities and group topology

| Process / actor | Candidate Linux-container UID:GID | Supplementary group(s) | Notes |
|---|---|---|---|
| Dedicated control-plane worker | `24501:24501` | `24602` (operator socket), `24603` (admission socket) | Non-root; sole worker DB control credential |
| Ephemeral operator CLI | `24502:24502` | `24602` | Genuine user OIDC token; operator socket volume only |
| Ephemeral admission test ingress | `24503:24503` | `24603` | PR 24P isolated harness only; never a public ingress |
| Public `mtmf-service` runtime | `24504:24504` | None of the above | Neither private socket nor worker secret mounted |
| One-shot dev fixture initializer | `24505:24505` | None of the above | Short-lived Keycloak/owner fixture credentials only |
| One-shot role provisioner | `24506:24506` | None of the above | Short-lived cluster-admin credential for `mtmf_control_exec` provisioning |

These are **candidate numeric IDs**, not measured host/VM mappings. Each
container must have a distinct worker-observed effective identity. The
provisioning code must not use a root or privileged long-lived worker to
circumvent failed group ownership. Invalid/unmapped/collapsed identities:
`STOP-DEPLOYMENT` and a human-approved manifest amendment.

### B2. Unix sockets and volumes

| Attribute | Operator interface | Admission interface |
|---|---|---|
| Linux absolute path | `/run/mtmf-control/operator/operator.sock` | `/run/mtmf-control/admission/admission.sock` |
| Project-scoped named volume (logical name) | `control-operator-socket` | `control-admission-socket` |
| Socket directory owner:group:mode | `24501:24602:0710` | `24501:24603:0710` |
| Socket owner:group:mode | `24501:24602:0660` | `24501:24603:0660` |
| Only permitted non-worker mount | Operator CLI | Admission test harness |
| Exact worker-observed peer UID | `24502` | `24503` |

The CLI cannot mount admission, and the admission harness cannot mount the
operator volume. Both sockets reject the service/runtime UID and each other's
peer UID even if filesystem permissions are bypassed. Group access controls
traversal/connection only; the exact peer UID is the authorization boundary.
No worker TCP listener and no host Podman socket.

### B3. Database role and credential custody

- Database control login: **`mtmf_control_exec`**; only the approved five
  owner-owned private §7 function EXECUTE grants, necessary DB CONNECT/schema
  USAGE, no table/sequence DML, owner membership, CREATEROLE, SUPERUSER, etc.
- Runtime login: **`mtmf_runtime`**, unchanged **78** approved function
  EXECUTE signatures.
- Control DB credential: restricted project-owned Podman secret logical ID
  `mtmf-pr24p-control-db`, worker mount
  `/run/secrets/mtmf-control-db` (file owner worker UID, effective mode
  `0400`); never mounted into CLI, runtime, admission or shared initializer.
- Confidential Keycloak client secret: restricted project-owned Podman secret
  logical ID `mtmf-pr24p-operator-oidc-client`, **ephemeral CLI mount only**
  `/run/secrets/mtmf-operator-oidc-client` (file owner CLI UID,
  effective mode `0400`). Existing client is deliberately dual-use; a
  service-credentials token from this client must be denied as operator.
- Operator Keycloak bootstrap password: secret logical ID
  `mtmf-pr24p-operator-password`, one-shot initializer mount only at
  `/run/mtmf-operator-install/dev-operator-password` (file owner
  initializer UID, mode `0400`). No defaults, plaintext argv/env,
  logging, password reset or migration/worker mount.
- One-shot cluster/admin/migrator credentials remain isolated to
  their approved short-lived provisioner/initializer processes and are
  absent from worker and runtime. Existing ordinary Keycloak admin
  identities are not converted to SYSTEM operators.
- Secret values are **not supplied** by this document. An approved
  project-local secret-provider setup must enforce the above mounts and
  modes; if it cannot, fail closed, do not relax permissions.
- Rotation/runbook owner: **MTMF development deployment operator**
  (the developer who administers the approved `mtmf` Podman project);
  only human-controlled reset/rotation with previous credentials invalidated.

### B4. Network and on-demand OAuth login

- Compose project: `mtmf`, with project-scoped named resources; never touch
  ATI, Digr, Darkula or unrelated projects.
- Normal `mtmf` network retains currently approved loopback service ports,
  including PostgreSQL 25432, Keycloak forwarder 28443 and public
  development service 28001, subject to existing deployment checks.
- Dedicated private network: logical `control-private`, worker plus only
  needed PostgreSQL and Keycloak-TLS-forwarder dependencies; **not**
  `mtmf-service`; no published control-worker ports.
- Operator authentication network: logical `operator-auth`, ephemeral CLI
  plus canonical Keycloak TLS forwarder; no ordinary application, PostgreSQL
  or admission harness attachment.
- Interactive callback: exact existing confidential client
  `mtmf-evidence-same-client`, issuer
  `https://keycloak.mtmf.test:28443/realms/mtmf-dev`, access-token audience
  `mtmf-same-client-api`, exact registered redirect
  `http://127.0.0.1:28400/callback`. Temporary host-loopback-only
  publish `127.0.0.1:28400:28400` to the ephemeral CLI. PKCE S256,
  fresh state and nonce, bounded callback parsing, one-time exchange,
  120-second deadline, `303` clean completion and full teardown.
  No public worker control port and no OAuth flow during ordinary `up`.
- Rootless Podman on each OS/VM must prove host-to-CLI loopback forwarding
  and no LAN or unrelated-container reachability at Gate C; unsupported
  forwarding is `STOP-AUTH-PROFILE`, **not** a change of redirect/port.
- Canonical development operator: `mtmf-dev-operator`; exact approved built-in
  SYSTEM Role `urn:mtmf:iam:roles:system:application-administrator`;
  bootstrap selector `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED=true` only;
  production auto-bootstrap permanently forbidden.

### B5. Required implementation / acceptance sequence

1. After explicit human Gate B approval, the existing PR 24P coding agent
   reconciles its branch with the approved current `main` baseline; it
   resumes the **existing** held work, not a new PR.
2. Follow the approved 0–8 sequence: unconditional role-independent
   migration `0016` and runtime postflight; separately provision restricted
   control login; install the exact five owner grants; verify effective
   permissions; install/verify one-shot operator fixture; then start the
   isolated worker. No production automatic bootstrap.
3. **Gate C**, after implementation: verify actual UID/GID namespace maps,
   worker-observed `SO_PEERCRED`, both socket/secret mount restrictions,
   exact DB privileges, genuine Keycloak user token/Service-token denial,
   on-demand browser loopback flow, audit/replay/negative controls,
   installation idempotency and no leaked privilege.
4. Each supported machine may reuse this unchanged human-approved static
   manifest after independent Gate C proof. Failure/unknown behavior is STOP,
   not implicit human approval or authorization to improvise.

### B6. Decision still required (do not fill automatically)

```text
Gate B decision ID:            PENDING
Approving party and UTC date:  PENDING
Gate A decision reference:    MTMF-PR24P-GATE-A-2026-11-13-01
Manifest candidate:           mtmf-pr24p-development-gateb-v1
Exact approved manifest ref:  PENDING (commit/file version once approved)
Static UID/GID/socket/secret/network values accepted?  YES / NO (UNANSWERED)
OAuth login/secret policy accepted?               YES / NO (UNANSWERED)
Automated per-machine Gate C checks accepted?     YES / NO (UNANSWERED)
Resume existing PR 24P implementation authorized? YES / NO (UNANSWERED)
```

**Current terminal state:** `GATE_A_APPROVED — GATE_B_PENDING —
PR24P_BLOCKED_TOPOLOGY_APPROVAL`. **Gate C NOT EXECUTED.**
