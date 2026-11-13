# PR24P_PORTABLE_TOPOLOGY_INDEPENDENT_REVIEW_REPORT

**PR:** roadmap PR 24P  
**Artifact directory:** `docs/pr-artifacts/pr-24p/`  
**Reviewed branch:** `dev/pr24p-part-deux`  
**Reviewed commit:** `b291315ddd44975709c68e2e2d0b1ee0dbb95903`  
**Review disposition:** `PORTABLE_TOPOLOGY_REVIEWED — TARGETED_FIXUP_REQUIRED`  
**Approval/implementation:** NOT AUTHORIZED; `STOP-P24P-TOPOLOGY` remains ACTIVE

## Scope and independent verification

Review of the documentation-only portability clarification at `b291315`
relative to `9fe0b13`, against the existing Keycloak development client
policy, `compose.dev.yaml`, `scripts/mtmf-dev-stack.py`, and
`PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md`. This is a document/contract
review only, not an operational isolation test.

Verified via GitHub commit comparison: exactly four PR 24P Markdown files
changed, with no SQL/Python/Rust/Compose/secret/test/code delta. The proposed
private SQL signatures, operator/admission separation, role-independent
migration `0016`, 78-function runtime limit, proposed test matrices and
human-approval STOP remain unchanged. No control worker exists, so no
platform-specific conformance or performance result can be claimed.

## P1 — Architecture approval and runtime conformance form a circular gate

**Source:** decision record §8, §8A, §9 and §11.

Section 9 adds `Target installation conformance evidence recorded? YES / NO
(NOT EXECUTED)` to a record whose answers govern permission to implement.
Yet §5B.6 demands real worker-observed `SO_PEERCRED`, socket mounts and
control-role privileges, none of which can exist while the mandatory
`STOP-P24P-TOPOLOGY` implementation gate remains active.

**Required minimal fix:** separate the approvals and deployment checks into
three ordered gates, without lowering requirements:

1. **A: architecture authorization** — human approves all twelve topology
   fields, frozen protocols, the portable manifest *schema*, invariant
   candidates (including the approved selection policy) and required real
   security acceptance tests. Record the named human decision/conditions.
2. **B: implementation authorization and installation manifest** — only after
   A, the target deployment's required static manifest values are approved.
   This gate may permit implementation work, but does not claim a deployed
   isolation result. No worker startup or privileged readiness is implied.
3. **C: post-implementation per-installation attestation** — actual
   worker-observed peer IDs, namespace mappings, secrets, sockets, role grants
   and genuine-token flows must pass before the privileged control plane is
   declared ready. Failed C invokes STOP-DEPLOYMENT/STOP-PRIVILEGE, never
   retroactively grants an architecture approval.

Move `Target installation conformance evidence recorded?` out of the
pre-implementation YES/NO approval prerequisites; retain it as a mandatory
post-implementation acceptance check. Do not fill in any §8 values or grant
approval by editing the form. Clarify whether an already approved portable
manifest can apply to additional machines via automatic attestation of
invariants, so routine development is not contingent on arbitrary manual
per-machine decisions.

## P1 — Containerized operator CLI has no specified browser callback bridge

**Source:** `dev/keycloak/expected-client-policy.json`, decision record
Field 4 and §5B.6.

The approved confidential client `mtmf-evidence-same-client` has
`standardFlowEnabled=true`, `directAccessGrantsEnabled=false`,
`publicClient=false`, and exactly one redirect URI:
`http://127.0.0.1:28400/callback`.

The portability clarification makes the ephemeral operator CLI a Linux
container, but developer browsers may be on Windows/macOS while that
localhost address points to the developer host, **not** the container.
The current proposal has no frozen callback bridge or confidential client
secret custody arrangement for that separation. A genuine user-class token
cannot simply be assumed.

**Required minimal fix:** freeze a single portable flow with these properties:

- Browser redirect remains the approved exact URI and uses Authorization
  Code, never resource-owner password grant, impersonation, fabricated token
  or an unapproved device/token-exchange flow.
- Explicitly define how host-loopback `127.0.0.1:28400` reaches an
  ephemeral, non-root operator-CLI callback listener in the relevant
  Linux VM/container, with short lifetime and strictly local exposure.
- The callback listener is a **separate OAuth login endpoint**, not a
  control-plane TCP interface. The control worker exposes no TCP port and
  remains reachable only via the private Unix socket.
- Specify PKCE/state/nonce/client-auth handling compatible with the
  existing confidential client, restricted temporary client-secret
  custody, callback teardown, and the exact denial/STOP when a verified
  browser-to-CLI loopback path is unavailable.
- Require a real-browser/auth-code/genuine-signed-token acceptance test on
  each claimed execution platform before privileged readiness. No shortcut
  that weakens the existing Keycloak client policy is permitted.
- If the exact callback/credential boundary cannot be implemented under the
  current approved policy, STOP-AUTH-PROFILE for a human-controlled revised
  design rather than inventing an alternate redirect, port, grant or IdP.

## Nonblocking implementation observation — public runtime UID

The portable numeric proposal assigns public `mtmf-service` container UID
`24504`, but the current `Dockerfile.service` does not declare a `USER`.
The proposed non-root runtime UID is a **future implementation change**, not
an existing isolation property. It must be verified on the actual runtime
before E15/E16/PORT acceptance; do not claim current implementation supports
the proposed UID or adjust the service spec during this docs-only review.

## Preserved security invariants and acceptance

- Independent operator and admission actor/socket/UID boundaries.
- No production operator auto-bootstrap, root impersonation, dynamic grant or
  public control-plane route.
- Opt-in local bootstrap through a short-lived privileged installer only;
  `MTMF_DEV_CONTROL_BOOTSTRAP_ENABLED` is a selector, not authorization.
- Unconditional role-independent migration followed by separately authorized
  role creation and exactly five control EXECUTE grants.
- `mtmf_runtime` retains exactly 78 approved function signatures.
- Distinct Linux container identities and real `SO_PEERCRED`, filesystem,
  mount, token and secret isolation evidence mandatory before readiness.
- The candidate UIDs `24501`–`24504`, socket locations and access modes
  remain unapproved proposals. No portability promise without verification.
- No existing deployment, credential, token, SQL, migration or benchmark was
  changed or executed during this review.

## Reviewer disposition and precise next action

**`PORTABLE_TOPOLOGY_REVIEWED — TARGETED_FIXUP_REQUIRED`.**

Make a **documentation-only** narrow follow-up on `dev/pr24p-part-deux`
that addresses both P1 findings in the decision record and proposed dev
profile, updates the STOP report, and preserves all other frozen contracts.
After independently reviewing that fixup, the approving human can decide the
architecture and target manifest. Until then, every §9 approval question
remains unanswered, `PR24P_BLOCKED_TOPOLOGY_APPROVAL` and
`STOP-P24P-TOPOLOGY` remain in force.
