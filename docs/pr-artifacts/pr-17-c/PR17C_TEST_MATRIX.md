# PR 17-C Test Matrix (N01–N24)

Classification legend: **U** = deterministic unit test, **L** = live WSL/Podman,
**W** = Windows browser manual (operator). "PASS" means actually executed in the
listed class; "NOT EXECUTED" means it was not executed and is not claimed.

| ID | Required case | Class | Result | Evidence |
| --- | --- | --- | --- | --- |
| N01 | canonical issuer configured in all MTMF components | U + L | PASS | `test_pr17c_dev_stack` (`up` rejects non-canonical), `test_config`/`test_attestation_reader` (canonical accepted); live `up` discovery `issuer == https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev` from host and container |
| N02 | missing/incorrect hostname resolution fails closed, actionable | U | PASS | `test_pr17c_dev_probe.test_unresolvable_host_fails_closed`; live probe prints "does not resolve … add the operator-managed hosts/DNS mapping" |
| N03 | container DNS points to unreachable endpoint fails closed | L | PASS | live negative: `podman run --add-host keycloak.mtmf.test:127.0.0.1 … probe` → `cannot reach the canonical authority … Connection refused` |
| N04 | issuer port `28443` vs container `8443` documented working forward route | L | PASS | live container probe + real initializer succeeded through the forwarder (`forwarder:28443 -> keycloak:8443`) |
| N05 | missing CA / untrusted CA fails; no insecure retry | U + L | PASS | unit `tls_context` failure path; live `--ca-file /nonexistent…` and `--ca-file server.crt` both failed closed |
| N06 | SAN mismatch fails | U + L | PASS | live `mtmf-dev-certs.py --hostname other.mtmf.test check` → "missing SAN DNS:other.mtmf.test" (exit 1) |
| N07 | discovery issuer mismatch fails closed | U | PASS | `test_pr17c_dev_probe.test_issuer_mismatch_fails_closed` |
| N08 | JWKS endpoint unavailable / empty fails | U | PASS | `test_pr17c_dev_probe.test_empty_jwks_fails_closed` |
| N09 | wrong realm fails closed | L | PASS | live probe against `/realms/no-such-realm` failed closed (no silent fallback) |
| N10 | canonical admin `Location` + PR 17-B strict provenance | L | PASS | PR 17-B live suite 13/13 (PV01–PV03, SH16) against the canonical issuer |
| N11 | `up` startup ordering (initializer before service) | U + L | PASS | `test_up_orders_certs_forwarder_probes_initializer_service`; live `up` log ordering |
| N12 | service cannot reach canonical issuer → not ready | U | PASS (unit) | `_probe_until_stable` / `_probe_container` failure aborts before the service; live break-and-restore not executed |
| N13 | `up` repeat → stable identities/counts, no duplicates | L | PASS | second `up` exit 0; tenant/principal/identity/application/subscription/membership counts identical; Keycloak `mtmf-dev-user` count 1 |
| N14 | `down`/`destroy` ownership (MTMF-only) | U + L | PASS | existing U19–U22 ownership tests; live `down` removed only `mtmf_*` containers, volumes preserved |
| N15 | secrets absent from HTTP service | L | PASS | `podman inspect mtmf_service_1`: no `MIGRATOR`/`ADMIN_PASSWORD`/`KC_ADMIN`/`POSTGRES_PASSWORD`/`DEV_USER`; mount is only the public CA (ro) |
| N16 | no host networking, loopback-only publications | L | PASS | inspect: postgres `127.0.0.1:25432`, keycloak `127.0.0.1:28080/28443`, service `127.0.0.1:28001`, forwarder no publications; all `net=bridge` |
| N17 | Windows browser canonical HTTPS discovery | W | NOT EXECUTED | requires a real Windows browser; CA import and hosts mapping are operator steps |
| N18 | real browser auth-code+PKCE login | W | NOT EXECUTED | browser required; HTTP-client auth-code+PKCE login is covered by the live PR 14/17/17-B suites |
| N19 | WSL and both MTMF containers observation | L | PASS | host preflight and container preflight both report the identical canonical issuer; PR 14/17 live suites 22/22 and 26/26 |
| N20 | altered DNS/CA/issuer negatives classified, no bypass | L | PASS | N03/N05/N09 negatives above; wrong CA is not retried and issuer is never rewritten |
| N21 | restart with persistent Keycloak data → canonical issuer stable | L | PASS | `down` (volumes preserved) then `up`; same issuer, same `mtmf-dev-user` `sub`, identical counts |
| N22 | separate PR14 evidence fixture unchanged/isolated | S | PASS | `dev/keycloak/compose.yaml`, `setup-realm.py`, expected realm/client files unchanged; PR14 live suite runs via the evidence tooling against the canonical realm |
| N23 | no wildcard cleanup or other-project mutations | U + L | PASS | ownership tests; live operations touched only `mtmf_*`; no `podman prune`/discovery |
| N24 | absent/invalid operator Windows hosts/CA setup → actionable preflight | U + W | PASS (WSL/Host) / NOT EXECUTED (Windows) | probe failures are actionable and non-secret; Windows operator step documented in `DEVELOPMENT_SETUP.md` |

## Live commands executed (final code)

```text
uv sync --locked
./build.sh --qa                                  # 1947 passed, coverage 90.75%
./build.sh --sec                                 # bandit + semgrep, 0 findings
./build.sh --rust                                # cargo gate + native + benchmarks
./build.sh --integration                         # 564 passed, 65 skipped
python scripts/mtmf-dev-stack.py up              # exit 0 (no host networking)
python scripts/mtmf-dev-stack.py up              # exit 0, identical counts
python scripts/mtmf-dev-stack.py down            # MTMF-only, volumes preserved
MTMF_PR17B_LIVE=1 pytest test_pr17b_live_acceptance.py   # 13 passed
MTMF_PR14_LIVE=1  pytest test_pr14_live_actor_context.py # 22 passed
MTMF_PR17_LIVE=1  pytest test_pr17_live_http.py          # 26 passed
```
