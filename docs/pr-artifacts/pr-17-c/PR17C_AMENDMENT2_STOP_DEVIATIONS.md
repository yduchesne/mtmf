# PR 17-C Amendment 2 — STOP / Deviations

No mandatory STOP condition was triggered. The Compose configuration-hash
recreation was reproduced and its demonstrable cause fixed; canonical routing
and TLS/issuer/JWKS verification are preserved; no host networking, broader
publication, destructive reset, or foreign-resource action was required.

| ID | Type | Description | Disposition |
| --- | --- | --- | --- |
| AM2-D1 | Pre-existing forwarder transient (out of scope) | The standalone `preflight` container probe failed intermittently (~40%) with a container-namespace TLS handshake timeout. Diagnosis: direct host `127.0.0.1:28443` and direct container `keycloak:8443` were reliable (0/15), but the long-running forwarder's `asyncio.open_connection("keycloak", 8443)` occasionally stalled 5–23 s while a fresh process connected in <25 ms. Root cause is the event-loop handling in `scripts/mtmf-dev-forwarder.py` (a defect in this PR's forwarder), **not** the Compose hash. | The forwarder file was left at its committed state out of scope. `preflight()` now uses the same bounded `_probe_until_stable` retry as `up()` so an otherwise-healthy stack is not reported broken by a transport timeout. The retry never re-runs a Compose/lifecycle operation and cannot hide a configuration change, which is proven stable separately. Recommend a separate approved forwarder fix (e.g., lazy target connect / explicit `OSError` suppression in `write_eof`). |
| AM2-D2 | Deliberate retry change | `preflight()` previously ran each probe once; it now retries for up to 60 s (2 s interval), matching `up()`. | Documented in `PR17C_AMENDMENT2_LIFECYCLE_DECISION.md`; classified as transport robustness, not acceptance-gate suppression. |
| AM2-D3 | Live case not executed | LC13 live ("rebuild only the forwarder and verify safe mapping refresh") was not run, to avoid disturbing the preserved acceptance stack. | Deterministic counterpart `test_lc13_launcher_state_holds_no_container_ip` passes; no IP is cached, so the next probe re-resolves the alias. The plan marks live LC13 optional. |
| AM2-D4 | Manual acceptance unchanged | Windows-browser N17/N18 remain unexecuted. | Out of scope for this amendment; PR 17-C remains NOT DONE pending those and human review. |

## Forwarder change disclosure

`scripts/mtmf-dev-forwarder.py` was **not** modified in this amendment. During
diagnosis a temporary local experiment (lazy target connect and `OSError`
suppression) was tried and then reverted; the committed forwarder is the
Amendment 1 version. The finding is recorded above for the reviewer.

## Failure classification summary

- Compose recreation: **introduced regression** (PR 17-C `extra_hosts` dynamic
  IP) — fixed and verified absent.
- Forwarder TLS stall: **deterministic pre-existing failure** — recorded;
  mitigated in the launcher only, not fixed.
- All canonical gates and live regression suites on the amended tip: PASS.
- No test was skipped, xfailed, deleted, or weakened to obtain a pass.

## Outstanding blocker

Windows N17/N18 (and a separately approved forwarder fix if the reviewer wants
the retry removed). PR 17-C stays **AWAITING HUMAN REVIEW — NOT DONE**.
