# PR 17-C STOP / Deviation Register

PR 17-C did **not** trigger a mandatory STOP condition: the canonical authority is
reachable from host and containers without host networking, extra privilege, or global
exposure; the pinned Keycloak advertises the canonical issuer while keeping its
internal listener and loopback publication; CA/leaf key permissions are enforced
without a world-readable private key; and no approved realm/client policy, PR 17-B
provenance rule, or authentication flow was relaxed.

The following deviations/open items are recorded for the human reviewer.

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| 17C-D1 | Manual acceptance not executed | N17 (Windows browser canonical HTTPS discovery) and N18 (real browser auth-code+PKCE) require an interactive Windows browser. HTTP-client auth-code+PKCE is covered by the live PR 14/17/17-B suites, not by a browser. | Operator to execute on the amended tip; do not claim PASS. |
| 17C-D2 | Narrow authority expansion | `IssuerConfig`/`HttpAdminRestReader` now accept `keycloak.mtmf.test` in addition to loopback; arbitrary hosts remain rejected. | Documented in `PR17C_SECURITY_REVIEW.md` §1; requires reviewer acknowledgement. |
| 17C-D3 | N12 live break/restore not run | The service-not-ready-on-issuer-loss path is unit-tested; the deliberate live forwarder outage was not executed. | Classified as unit PASS / live NOT EXECUTED. |
| 17C-D4 | Pre-existing defect fixed in scope | `_postgres_inspect` had always read `None` stdout; `_run` never captured output. Fixed as part of making standard `up` viable. | Baseline + acceptance documented. |
| 17C-D5 | `compose.yaml` publication hardening | PostgreSQL publication made loopback-only (port/data/topology unchanged). The execution plan lists `compose.yaml` as "normally unchanged". | Reviewer acknowledgement requested; aligns with the loopback-only invariant. |
| 17C-D6 | Realm prerequisite | The realm and approved clients remain a one-time operator step (`dev/keycloak/setup-realm.py`); the launcher does not create them. Fresh environments still require this bootstrap. | Documented; preserves the evidence-fixture distinction. |
| 17C-D7 | `podman-compose` tooling quirk | `podman-compose 1.0.6` emits a benign "container name already in use" create attempt followed by `podman start`; the launcher treats the overall exit code as authoritative. | Observed, not a correctness defect. |
| 17C-D8 | Evidence-fixture guard alignment | `scripts/pr14-keycloak-evidence.py` `Issuer.guard()` now accepts the canonical development host so the authoritative live suites can run against the canonical issuer. | Assertions unchanged; lookalike/arbitrary hosts rejected. |

## Environment/harness notes

- The standard `up` requires the operator `/etc/hosts` mapping on Windows and WSL2 for
  the host/browser path. Containers pin the canonical authority to the forwarder and do
  not depend on host DNS.
- The shared `mtmf` PostgreSQL schema is reset by the integration `db` fixture;
  the live regression suites were run after the stack acceptance evidence was captured.
