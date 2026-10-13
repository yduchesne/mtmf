# PR 17-C Amendment 3 Fixup 1 — Final Report

## Summary

Closed the Amendment 3 review findings on bounded DNS, cancellation-safe pump
ownership, and (partially, blocked) recovery-admin reconciliation. Parts A and B
are implemented, tested, and accepted on the fixup tip; Part C is a documented
STOP requiring human action.

## Changed files

```text
scripts/mtmf-dev-forwarder.py                    (Parts A + B)
tests/unit/service/test_pr17c_dev_forwarder.py   (FX-U01-FX-U26; FW01-FW20 preserved)
docs/pr-artifacts/pr-17-c/PR17C_AMENDMENT3_FIXUP1_*.md   (seven reports)
docs/ROADMAP_V01.md                              (status; Windows smoke classification)
```

`compose.dev.yaml`, `dev/nsswitch.conf`, `scripts/mtmf-dev-stack.py`,
`scripts/mtmf-dev-probe.py`, and certificate code are unchanged.

## Part A — bounded, race-safe DNS

`RESOLVE_TIMEOUT_SECONDS` (default 2.0) with startup validation that rejects
nonfinite/zero/negative/nonnumeric before the listener; `resolve()` uses
`asyncio.wait_for(asyncio.to_thread(...))` and returns `None` on timeout/`OSError`/
empty without mutating the cache; a single `asyncio.Lock` coalesces lookups; a
monotonic generation plus synchronous `invalidate()` prevents a stale in-flight
result from repopulating the cache; the worker thread never mutates state;
`CancelledError` propagates.

## Part B — cancellation-safe pumps and writers

`_handle` owns both pumps and writers; every pump is registered and joined; a
single bounded (`2 s`) shielded `_finish_cleanup` cancels/joins pumps and closes
both writers with bounded `wait_closed()`, running on success, error, abort, and
cancellation; ordering is cancel → join → close target → await target → close
client → await client; unexpected pump exceptions are surfaced as a bounded
non-secret diagnostic, expected disconnect errors are contained, and
cancellation propagates.

## Verification (fixup tip)

- `tests/unit/service/test_pr17c_dev_forwarder.py`: **51 passed** (FW01–FW20 +
  FX-U01–FX-U26); all five startup-validation values rejected.
- Gates: `--qa` **2065 passed / 90.75%**, `--sec` 0 findings, `--rust` PASS,
  `--integration` **564 passed / 65 skipped**.
- Live: FX-I01–FX-I08 pass — `up`/`preflight`/ready; **100/100** sequential
  (max 0.019 s); **50/50** concurrency-10; **30/30** direct control;
  Keycloak-down bounded failure and restore **20/20** without forwarder restart;
  30 aborted connects then **20/20** with FDs 7 → 7 and 0 tracebacks; three
  unchanged `up` cycles preserve all four container IDs/`StartedAt`; forwarder
  `publish=none`/`privileged=false`, loopback-only ports, no privileged runtime
  secrets, exact canonical `issuer`/`jwks_uri`/token `iss`.
- Regressions: PR 17-B **13/13**, PR 14 **22/22**, PR 17 **26/26**.
- FX-I09 covered by unit fake-DNS cases (no live DNS tampering).

## STOP / remaining human action

FX-I10 (recovery admin) is **STOP**: `mtmf-pr14-admin` cannot be authenticated
(pre-crash credential lost), so `mtmf-pr14-admin2` was **not** disabled. Human
action: recover/confirm the original credential and disable the recovery admin,
or explicitly authorize the reverse. No realm/volume reset and no credential
change was performed.

## Disposition

Parts A and B are complete and evidenced. Part C is blocked per plan STOP
condition §11.5. PR 17-C remains **AWAITING HUMAN REVIEW — NOT DONE**; Windows
N17/N18 are optional manual workstation smoke tests, not mandatory automated
gates.
