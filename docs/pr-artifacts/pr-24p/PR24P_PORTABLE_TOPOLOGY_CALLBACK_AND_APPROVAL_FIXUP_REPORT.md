# PR24P_PORTABLE_TOPOLOGY_CALLBACK_AND_APPROVAL_FIXUP_REPORT

**Status:** `PORTABLE_TOPOLOGY_FIXUP_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`
**Review source:** [PR24P_PORTABLE_TOPOLOGY_INDEPENDENT_REVIEW_REPORT.md](PR24P_PORTABLE_TOPOLOGY_INDEPENDENT_REVIEW_REPORT.md)
**Branch:** `dev/pr24p-part-deux`
**Starting SHA:** `780cc05324f6d050ba8a6869b048dd352e836cd3`
**Baseline main:** `28d5de85ccf63c9ffb5bdc8298156e6038cbdadd`
**Artifact directory:** `docs/pr-artifacts/pr-24p/`
**Mandatory STOP:** `STOP-P24P-TOPOLOGY` ACTIVE; **approval:** NONE
**Implementation/feature tests/benchmarks:** NOT EXECUTED

## Review findings and frozen fixes

| ID | Review defect | Documentation correction |
|---|---|---|
| P1-1 | §9 demanded non-existent real-worker conformance before authorizing implementation | Gate A human architecture, Gate B approved static manifest/implementation, Gate C real post-implementation attestation; reuse of a matching approved manifest on another machine after automatic evidence |
| P1-2 | Ephemeral Linux operator CLI lacked portable browser redirect | Exact registered loopback `http://127.0.0.1:28400/callback`; temporary `127.0.0.1:28400:28400` Podman port publish, dedicated operator-auth network, confidential-client Basic with CLI-only file-mounted secret, PKCE S256, state/nonce, strict one-shot/timeout and cleanup |

## Current-source reconciliation

- Canonical approved confidential client in
  `dev/keycloak/expected-client-policy.json` is
  `mtmf-evidence-same-client`, `standardFlowEnabled=true`,
  `publicClient=false`, `directAccessGrantsEnabled=false`, exact
  redirect `http://127.0.0.1:28400/callback`, audience
  `mtmf-same-client-api`. Do NOT change this policy.
- Existing ordinary local development launcher
  `scripts/mtmf-dev-stack.py` starts database/Keycloak/initializer/service
  but implements no control worker, operator CLI, callback port or
  machine-specific UID isolation.
- Revision `0016`, `mtmf_control_exec`, dedicated SYSTEM operator
  fixture and both private sockets are not implemented.
- `Dockerfile.service` does not set the proposed runtime UID 24504;
  this remains a post-authorization implementation/acceptance obligation.

## Files in this fixup

- `PR24P_EXECUTION_TOPOLOGY_DECISION_REQUIRED.md`: §3, Field 4,
  §5B.2/§5B.6/§5B.6A, §8/§8A, §9, §11.
- `PR24P_AMENDMENT_E_DEVELOPMENT_PROFILE_PROPOSED.md`: portable OAuth
  login and three-gate deployment model.
- `PR24P_STOP_AND_DEVIATION_REPORT.md`: §2E and revised minimum
  human-decision prerequisites.
- This PR-specific fixup report. Earlier independent-review report
  is retained unchanged as historical review evidence.

## Future tests (all NOT EXECUTED)

| ID | Future requirement | Required result |
|---|---|---|
| FX01 | Gate A/B approvals absent | No privileged implementation or install |
| FX02 | Gate A+B approved, Gate C pending | Implementation allowed; no privileged-ready claim |
| FX03 | Fresh machine with unchanged approved manifest | Real local automatic Gate C acceptance, no manual machine authorization |
| FX04 | Drifted manifest or failed mapping/proof | STOP; no automatic remediation or privilege claim |
| FX05 | Host-browser exact callback for every claimed platform | Real authorization code and PKCE, signed user token |
| FX06 | Loopback port unavailable/exposed externally/VM mapping absent | `STOP-AUTH-PROFILE`, no alternate redirect or port |
| FX07 | Forged/replayed callback, bad state/nonce, bad client Basic | Denied, no token or control mutation |
| FX08 | Callback terminal outcome | Port, ephemeral CLI listener/container and secret mount removed |
| FX09 | Ordinary dev `up` without operator command | No interactive login or published 28400 callback |
| FX10 | Existing privilege invariants | Five control EXECUTEs, 78 runtime, admission test only, no public control TCP |

These are future feature-security tests; no substitute mocks, historical
regression or host-idle benchmark can count as execution evidence.

## Preservation and gate

- Four files only, all under `docs/pr-artifacts/pr-24p/`.
- Existing §5 operator and §5A admission protocols, §5A.7 precedence,
  §6/§6A/§6B, §7 exact five SQL signatures, runtime 78 grants,
  D01–D20/E01–E20 and no-production-auto-grant unchanged.
- No human §4/§9 checkbox, approval date, deployment value, Gate C
  attestation or PASS was supplied or fabricated.
- No migrations, database grants, Keycloak modification, containers,
  sockets, tokens, tests or benchmarking were run.

**Terminal state:** `PORTABLE_TOPOLOGY_FIXUP_DOCUMENTED — PR24P_BLOCKED_TOPOLOGY_APPROVAL`.
