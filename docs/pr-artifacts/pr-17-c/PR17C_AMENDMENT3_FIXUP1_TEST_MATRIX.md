# PR 17-C Amendment 3 Fixup 1 — Test Matrix (FX-U01–U26, FX-I01–I10)

Deterministic tests live in `tests/unit/service/test_pr17c_dev_forwarder.py` and
exercise the real `_TargetResolver` / `_open_target` / `_handle` / `_pipe` /
`_finish_cleanup` path with in-process asyncio targets and controlled fakes.
Live tests use the real rootless Podman MTMF topology and
`tests/integration/pr17c_forwarder_reliability.py`.

## Deterministic unit matrix

| ID | Scenario | Test | Result |
| --- | --- | --- | --- |
| FX-U01 | DNS resolves one IPv4 address, cached/reused, one `getaddrinfo` | `test_fxu01_dns_resolves_and_caches` | PASS |
| FX-U02 | Cached address with 20 concurrent clients, no new DNS | `test_fxu02_cached_address_no_new_dns_with_concurrent_clients` | PASS |
| FX-U03 | 20 concurrent uncached resolves → single serialized call | `test_fxu03_concurrent_uncached_resolve_single_call` | PASS |
| FX-U04 | DNS `OSError` → `None`, no cache mutation, later retry succeeds | `test_fxu04_dns_oserror_none_then_retry` | PASS |
| FX-U05 | DNS empty → `None`, no cache mutation | `test_fxu05_dns_empty_list_none` | PASS |
| FX-U06 | DNS worker stalls → caller returns within deadline | `test_fxu06_dns_worker_stalls_bounded` | PASS |
| FX-U07 | Timed-out worker later returns → cannot populate cache | `test_fxu07_late_dns_result_cannot_populate_cache` | PASS |
| FX-U08 | Invalidate while lookup in flight → generation blocks stale commit | `test_fxu08_invalidate_during_inflight_lookup` | PASS |
| FX-U09 | Refused TCP connect → invalidate → next attempt resolves/succeeds | `test_fxu09_invalidation_after_refused_connect` | PASS |
| FX-U10 | All three attempts fail DNS → bounded, no infinite retry | `test_fxu10_all_attempts_fail_dns_bounded` | PASS |
| FX-U11 | Cancel caller during DNS → `CancelledError`, no cache mutation | `test_fxu11_cancel_during_dns` | PASS |
| FX-U12 | Invalid timeout `0`, `-1`, `nan`, `inf`, nonnumeric → startup rejects | `test_fxu12_invalid_resolve_timeout_rejected` | PASS |
| FX-U13 | Client sends no data → no target connection, bounded close | `test_fxu13_no_data_no_target_connection` | PASS |
| FX-U14 | Normal bidirectional transfer → exact bytes, pumps joined/writers closed | `test_fxu14_bidirectional_and_all_tasks_done` | PASS |
| FX-U15 | Client half-closes → remaining response delivered within grace | `test_fxu15_half_close_response_within_grace` | PASS |
| FX-U16 | Target closes first → peer pump cancelled/joined, no task remains | `test_fxu16_target_closes_first_tasks_joined` | PASS |
| FX-U17 | Client reset midstream → listener survives, writers closed | `test_fxu17_client_reset_listener_survives` | PASS |
| FX-U18 | Target connect failure after first bytes → no pump, client closed | `test_fxu18_target_connect_failure_after_first_bytes` | PASS |
| FX-U19 | Cancel handler waiting for `FIRST_COMPLETED` → pumps joined, cancellation propagates | `test_fxu19_cancel_while_waiting_first_completed` | PASS |
| FX-U20 | Cancel handler during drain window → same guarantees | `test_fxu20_cancel_during_drain_window` | PASS |
| FX-U21 | Cancel handler while pump blocked in `drain()` → no orphan pump | `test_fxu21_cancel_while_pump_blocked_in_drain` | PASS |
| FX-U22 | Cancel during writer `wait_closed()` → shielded cleanup completes | `test_fxu22_cancel_during_writer_wait_closed` | PASS |
| FX-U23 | Pump raises expected `OSError` → listener usable, no orphan tasks | `test_fxu23_pump_oserror_listener_usable` | PASS |
| FX-U24 | Pump raises unexpected exception → surfaced, cleanup completes | `test_fxu24_unexpected_pump_exception_surfaced` | PASS |
| FX-U25 | Cleanup join/close exceeds injected budget → bounded completion | `test_fxu25_cleanup_budget_bounded` | PASS |
| FX-U26 | 50 sequential handler cancellations → no task/stream growth | `test_fxu26_fifty_handler_cancellations_no_growth` | PASS |

Module total: **51 passed** (`pytest tests/unit/service/test_pr17c_dev_forwarder.py`).
FW01–FW20 from Amendment 3 are preserved and still pass.

## Real WSL2/Podman acceptance matrix

| ID | Procedure | Result |
| --- | --- | --- |
| FX-I01 | `up`, `preflight`, `/health/ready` | PASS — `up` 0, `preflight` 0, ready 200 |
| FX-I02 | 100 sequential container-path discovery+JWKS (5 s deadline, no retry) | PASS — **100/100**, max 0.019 s, p95 0.013 s |
| FX-I03 | 50 at concurrency 10 | PASS — **50/50**, max 0.083 s, p95 0.081 s |
| FX-I04 | 30 direct-to-Keycloak control | PASS — **30/30**, max 0.015 s |
| FX-I05 | Stop MTMF Keycloak → bounded failure → restore → 20 without forwarder restart | PASS — bounded failures; **20/20** after recovery; forwarder not restarted |
| FX-I06 | 30 aborted connections then 20 valid TLS | PASS — **20/20**; FDs 7 → 7; 0 tracebacks |
| FX-I07 | Three unchanged `up` cycles | PASS — all four IDs/`StartedAt` identical; 0 `podman stop`/`rm`; `preflight` 0; ready 200 |
| FX-I08 | Ports/privilege/secrets/issuer/discovery/JWKS/token `iss` | PASS — forwarder `publish=none` `privileged=false`; loopback-only; no privileged runtime secrets; exact canonical values |
| FX-I09 | DNS stall/failure under deterministic fake (no live DNS tampering) | PASS — covered by FX-U06–FX-U11 |
| FX-I10 | Recovery administrator reconciliation (Part C) | **STOP** — original admin cannot be authenticated (credential lost); `mtmf-pr14-admin2` left enabled. See STOP/deviation register. |

## Authoritative gates (fixup tip)

```text
uv sync --locked        PASS
./build.sh --qa         2065 passed, coverage 90.75%
./build.sh --sec        0 findings (Bandit Medium/High 0, Semgrep 0)
./build.sh --rust       PASS
./build.sh --integration 564 passed, 65 skipped
PR 17-B live            13 passed
PR 14 live              22 passed
PR 17 live              26 passed
```
