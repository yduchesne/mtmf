# PR 17-C Amendment 3 — Test Matrix (FW01–FW20)

Deterministic tests live in `tests/unit/service/test_pr17c_dev_forwarder.py`
and exercise the **production** `_handle` / `_pipe` / `_open_target` path against
in-process asyncio targets and a controlled resolver (no Podman/Keycloak/network).
"PASS" = code exists, executed, and passed on the amended tip.

| ID | Test | Result |
| --- | --- | --- |
| FW01 | `test_fw01_client_to_target_bytes` | PASS |
| FW02 | `test_fw02_target_to_client_bytes` | PASS |
| FW03 | `test_fw03_simultaneous_bidirectional` | PASS |
| FW04 | `test_fw04_multi_chunk_over_64k` (200 000 bytes) | PASS |
| FW05 | `test_fw05_client_half_close_then_response` | PASS |
| FW06 | `test_fw06_target_eof_reaches_client` (+ no pending handler tasks) | PASS |
| FW07 | `test_fw07_client_reset_during_target_response` | PASS |
| FW08 | `test_fw08_target_reset_during_client_upload` | PASS |
| FW09 | `test_fw09_target_connection_refused` (bounded, listener alive) | PASS |
| FW10 | `test_fw10_target_connect_timeout` (bounded, `_open_target` → None) | PASS |
| FW11 | `test_fw11_cancellation_during_pump` | PASS |
| FW12 | `test_fw12_write_eof_unsupported_or_raises` (`can_write_eof` false / raises `OSError`) | PASS |
| FW13 | `test_fw13_twenty_concurrent_clients` (independent payloads, no crosstalk) | PASS |
| FW14 | `test_fw14_stalled_client_does_not_block_healthy` | PASS |
| FW15 | `test_fw15_fifty_sequential_connections_no_leak` | PASS |
| FW16 | `test_fw16_target_recovers_without_forwarder_restart` | PASS |
| FW17 | `test_fw17_listener_survives_aborted_client` | PASS |
| FW18 | `test_fw18_no_payload_in_forwarder_output` | PASS |
| FW19 | `test_fw19_canonical_issuer_jwks_constants_unchanged` (no `ssl` import; exact canonical issuer/JWKS) | PASS |
| FW20 | `test_fw20_compose_model_and_launcher_unchanged` (no dynamic IP/`extra_hosts`; `dns files`) | PASS |

## Live/cross-cutting execution

```text
tests/unit/service/test_pr17c_dev_forwarder.py   21 passed (FW01–FW20, parameterized)
./build.sh --qa                                  2035 passed, coverage 90.75%
```

## Live real-topology reliability (harness, not a substitute for the unit gate)

`tests/integration/pr17c_forwarder_reliability.py` (real isolated Podman
network, real Keycloak TLS, dev CA, `dev/nsswitch.conf`):

| Case | Result |
| --- | --- |
| C 100 sequential first-attempt (5 s, no retry) | 100/100, max 0.051 s, p95 0.041 s |
| C 50 @ concurrency 10 | 50/50, max 0.125 s, p95 0.106 s |
| B 30 direct-to-Keycloak control | 30/30, max 0.033 s |
| `check_tcp`→TLS (connection-close trigger) 30 | 0 failures |
| 10 connect/close leak check | FDs 7 → 7, no tracebacks |
| Keycloak down → bounded failure; restore → 20/20 without forwarder restart | PASS |

All mandatory cases were executed on the amended tip. No test was skipped,
xfailed, deleted, or weakened.
