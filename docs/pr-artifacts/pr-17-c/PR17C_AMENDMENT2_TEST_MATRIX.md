# PR 17-C Amendment 2 — Test Matrix (LC01–LC16)

Classification: **U** = deterministic unit test, **L** = live WSL2/Podman.
"PASS" = executed and green; "N/E" = not executed (with reason).

| ID | Scenario | Class | Result | Evidence |
| --- | --- | --- | --- | --- |
| LC01 | Fresh `up` sequence: infrastructure once → probes → initializer → service | U + L | PASS | `test_up_orders_certs_forwarder_probes_initializer_service`; live `up` exit 0 |
| LC02 | Discovered forwarder address no longer changes launcher state / Compose inputs | U | PASS | `test_lc02_compose_model_has_no_dynamic_forwarder_input` (no `MTMF_DEV_FORWARDER_IP`/`extra_hosts` in `compose.dev.yaml`), `test_lc02_up_does_not_mutate_forwarder_ip` |
| LC03 | Service-only startup does not recreate infrastructure dependencies | L | PASS | identity snapshots: `up` log `stop/rm=0`; all four IDs/`StartedAt` preserved across the `compose up -d service` phase |
| LC04 | Repeated unchanged `up` does not force restart/recreate; probes/initializer still correct | L | PASS | 3 cycles × (`up` exit 0, `stop/rm=0`, IDENTICAL IDs/`StartedAt`, immediate `preflight` exit 0) |
| LC05 | `extra_hosts`/resolver for initializer maps canonical name to current forwarder | U + L | PASS | `test_lc05_lc06_initializer_and_service_mount_static_resolver_override`; live `service getent hosts keycloak.mtmf.test` → forwarder IP |
| LC06 | Same for service | U + L | PASS | same tests; live service resolution verified |
| LC07 | Host `/etc/hosts` maps name to loopback; container routing still works | U + L | PASS | `test_lc07_resolver_override_prefers_dns_over_files` (`hosts: dns files`), `test_probe_container_uses_static_resolver_override`; live service shows copied `127.0.0.1` entry ignored, resolves to forwarder |
| LC08 | Missing/uninspectable forwarder fails closed, no guessed IP | U + L | PASS | `test_lc08_no_forwarder_ip_discovery_or_guess_helper`; no IP discovery exists; live probe fails closed when the endpoint is unreachable |
| LC09 | Wrong issuer rejected before Compose/Podman mutation (Amendment 1 regression) | U + L | PASS | `test_am03_am07_rejected_before_side_effects`; Amendment 1 live negative retained |
| LC10 | Failed canonical TLS preflight → initializer and service not started | U | PASS | `test_lc10_failed_preflight_blocks_initializer_and_service` |
| LC11 | Failed initializer → service not started | U | PASS | `test_lc11_failed_initializer_blocks_service` |
| LC12 | Unsupported/nonzero Compose command fails explicitly, no silent fallback | U | PASS | `test_lc12_nonzero_command_fails_closed` |
| LC13 | Forwarder rebuilt with new address → safe refresh, no unrelated recreation | U + L(partial) | PASS (U) / N/E (L) | `test_lc13_launcher_state_holds_no_container_ip`; live rebuild of only the forwarder was **not** attempted to avoid disturbing the preserved stack (plan marks this optional). No address is cached, so the next probe re-resolves the alias. |
| LC14 | Compose/secret output redaction | U + L | PASS | `test_lc14_secrets_are_redacted`; live `up` logs contain only `<redacted>` for secrets |
| LC15 | `down` / `status` / `preflight` preserve ownership and semantics | U + L | PASS | existing `test_dev_stack_lifecycle.py` ownership tests; live `down` (volumes preserved) + `preflight` |
| LC16 | No change to PKI/issuer/JWKS; Amendment 1 tests still pass | U + L | PASS | full `pytest`/`--qa`; live discovery issuer/JWKS/`MTMF_AUTH_ISSUER` exact |

## Unit execution

```text
tests/unit/service/test_pr17c_dev_stack.py   (LC01–LC15) + Amendment 1 AM tests
./build.sh --qa                              2014 passed, coverage 90.75%
```

## Live lifecycle acceptance executed

```text
transition up (new model)                 one expected recreate; hash 1840ce6a…
cycle 1/2/3  up                           exit 0, stop/rm=0, IDENTICAL IDs+StartedAt
cycle 1/2/3  immediate preflight          exit 0 (host + container OK)
down                                      MTMF-only, volumes preserved
up after down                             exit 0, stop/rm=0, same hash, dev-user sub preserved
```

Live preflight uses the same bounded retry as `up` (documented under LC13/STOP
deviations) because of the pre-existing forwarder transport transient; the core
lifecycle claim (no recreation) is independent of the retry and is proven by
container ID/`StartedAt` snapshots.
