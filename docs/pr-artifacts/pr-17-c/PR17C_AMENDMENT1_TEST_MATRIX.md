# PR 17-C Amendment 1 — Test Matrix (AM01–AM24)

All amendment tests live in the existing PR 17-C modules and were executed on
the amended tip. "PASS" = executed and green. No existing test was weakened,
skipped, or removed; N01–N24 remain intact.

| ID | Scenario | Test (module) | Result |
| --- | --- | --- | --- |
| AM01 | exact issuer accepted by `up` | `test_up_orders_certs_forwarder_probes_initializer_service` / `test_constants_agree_with_probe` (`test_pr17c_dev_stack`) | PASS |
| AM02 | exact issuer accepted by `preflight` | `test_preflight_runs_both_namespaces` (`test_pr17c_dev_stack`) | PASS |
| AM03 | hostname prefix/suffix deception rejected before side effects | `test_am03_am07_rejected_before_side_effects[up\|preflight-https://evil-keycloak…/https://keycloak.mtmf.test.evil…]`, `test_parse_issuer_rejects_noncanonical_variants` | PASS |
| AM04 | wrong port / scheme rejected | same, `:28444` and `http://` variants | PASS |
| AM05 | wrong realm / trailing slash rejected | same, `/realms/other` and trailing `/` variants | PASS |
| AM06 | `preflight` wrong issuer variants rejected before network | `test_am03_am07_rejected_before_side_effects[preflight-*]`, `test_preflight_rejects_non_canonical_issuer` | PASS |
| AM07 | userinfo/query/fragment rejected; untrusted value not in error | `test_am03_am07_rejected_before_side_effects[…-https://user:secret@… / ?x=1 / #frag]` asserts `bad not in message` and `"secret" not in message` | PASS |
| AM08 | exact discovery issuer + exact JWKS accepted, JWKS fetched once | `test_am08_exact_jwks_uri_is_fetched_once`, `test_parse_issuer_exact_canonical` (`test_pr17c_dev_probe`) | PASS |
| AM09 | JWKS issuer-path prefix deception rejected, no fetch | `test_am09_am12_bad_jwks_uri_rejected_without_fetch[...mtmf-pr14-dev.evil...]` | PASS |
| AM10 | JWKS foreign origin / subdomain / wrong port rejected, no fetch | same, `https://evil.example/...`, `keycloak.mtmf.test.evil.example`, `:28444` | PASS |
| AM11 | JWKS same-origin wrong path or realm rejected, no fetch | same, `.../certs-other`, `.../realms/other/...` | PASS |
| AM12 | JWKS relative / query / fragment / encoded path rejected, no fetch | same, `/protocol/...`, `?x=1`, `#frag`, `%63erts` | PASS |
| AM13 | probe wrong issuer input rejected before network | `test_am13_wrong_issuer_input_rejected_before_network` | PASS |
| AM14 | empty PKI directory generates full valid CA+leaf | `test_am14_empty_directory_generates_valid_material` | PASS |
| AM15 | complete valid PKI is idempotent, bytes/mtimes unchanged | `test_am15_complete_valid_is_idempotent` | PASS |
| AM16 | CA key only / CA cert only fails closed, bytes unchanged | `test_am16_am17_partial_material_fails_closed[1-*]` | PASS |
| AM17 | leaf key/cert only and any 3-of-4 fails closed, bytes unchanged | `test_am16_am17_partial_material_fails_closed[3-*]` | PASS |
| AM18 | symlink / non-regular managed material fails closed, no overwrite | `test_am18_symlink_material_fails_closed`, `test_am18_directory_component_fails_closed` | PASS |
| AM19 | complete set with invalid SAN fails closed, no rewrite | `test_am19_wrong_san_fails_closed` | PASS |
| AM20 | complete set with mismatched CA key/cert fails closed | `test_am20_mismatched_ca_key_fails_closed` | PASS |
| AM21 | complete set with mismatched leaf key/cert fails closed | `test_am21_mismatched_leaf_key_fails_closed`, `test_pairing_helper_detects_mismatch` | PASS |
| AM22 | explicit rotate produces a new valid set; normal generate then idempotent | `test_am22_explicit_rotate_replaces_and_then_idempotent` | PASS |
| AM23 | interrupted rotation leaves partial material; next normal generate fails closed | `test_am23_partial_after_interrupted_rotation_fails_closed` | PASS |
| AM24 | secrets/failure diagnostics never expose keys, tokens, passwords, or URL credentials | `test_am03_am07_rejected_before_side_effects` (no supplied URL / `secret` in error); cert errors carry no key material; live wrong-issuer error checked | PASS |

## Extra regression coverage added

- `test_stale_serial_on_empty_directory_is_ignored` — stale `dev-ca.srl` cannot
  cause wrong-CA reuse on empty material.
- Existing N02/N03/N05/N06/N07/N08 probe failures retained (`_parse_issuer`,
  `tls_context`, `test_issuer_mismatch_fails_closed`, `test_empty_jwks_fails_closed`,
  `test_tcp_check_reports_unreachable`).

## Execution summary (amended tip)

```text
tests/unit/service/test_pr17c_dev_certs.py   24 passed
tests/unit/service/test_pr17c_dev_probe.py   parameterized AM08-AM13 + N-series
tests/unit/service/test_pr17c_dev_stack.py   parameterized AM01-AM07 + existing
./build.sh --qa                              2004 passed, coverage 90.75%
```

A unit test that mocks `_fetch` proves the validation contract, not real TLS
acceptance; the live acceptance report records the real TLS/JWKS/token checks.
