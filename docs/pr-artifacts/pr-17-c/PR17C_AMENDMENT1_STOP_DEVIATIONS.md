# PR 17-C Amendment 1 — STOP / Deviations

No mandatory STOP condition was triggered. The canonical issuer was reachable
and exactly correct in all namespaces; the live JWKS endpoint equaled the
expected canonical endpoint; empty/complete/partial/invalid PKI states are
distinguishable and key pairs are provably consistent; no second issuer, TLS
bypass, or realm/client policy relaxation was required.

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| AM1-D1 | Pre-existing deterministic launcher transient (feature-adjacent) | `up()` sets `MTMF_DEV_FORWARDER_IP` only after the first `compose up`, so the final `compose up -d service` recreates Keycloak/forwarder/initializer/service (config-hash change). `up` can return while Keycloak is briefly restarting, so a `preflight` invoked *immediately* after `up` may see a transient `Connection reset by peer`. It is present on base `f4d1905` (the value participates in the config hash via initializer/service `extra_hosts`) and is not introduced by this amendment. | Reported both ways (transient failure and later green pass). Not fixed here: the amendment is bounded to issuer/JWKS/PKI hardening and `scripts/mtmf-dev-stack.py` sequencing is outside its stated gap. Recommend a separate follow-up to make `up` wait for Keycloak health after the final service reconcile. |
| AM1-D2 | Manual acceptance not executed | N17 (Windows browser TLS trust/discovery) and N18 (real auth-code+PKCE login) require an interactive Windows browser. | Operator action; do not claim PASS. |
| AM1-D3 | Environment dependency (documented, not a STOP) | Pairing verification of a hardened leaf key uses `podman unshare` because the host user cannot read the owner-mapped `0600` key. If Podman is unavailable, the check fails closed rather than widening permissions. | Accepted; documented in `DEVELOPMENT_SETUP.md` and the security review. |
| AM1-D4 | Test-only fixup during development | The first AM16/AM17 run used a snapshot helper that read all four files; partial directories legitimately lack files. The test helper was corrected to record missing/non-regular state. No product logic changed. | Reported for transparency; final tests pass. |

## Failure classification

- Launcher/KC transient (AM1-D1): **deterministic pre-existing**, reproduced on
  the amended tip and explained by the base-tip sequencing; not an amendment
  regression.
- All canonical gates and live suites on the amended tip: **PASS**.
- No test was skipped, xfailed, deleted, or weakened to obtain a pass.

## Outstanding blocker

Windows N17/N18 remain unexecuted. PR 17-C stays
**AWAITING HUMAN REVIEW — NOT DONE** until real browser evidence is provided
and the pre-existing sequencing transient is either accepted or fixed.
