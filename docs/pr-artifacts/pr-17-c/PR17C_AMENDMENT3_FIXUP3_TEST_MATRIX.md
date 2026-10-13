# PR 17-C Amendment 3 Fixup 3 — Test Matrix (CR-U01–U30, CR-I01–I18)

Deterministic tests live in `tests/unit/service/test_pr17c_dev_realm.py` plus the
updated standard-stack modules. Live tests used a disposable MTMF-owned
environment (project `mtmf-fixup3` / separate volumes, then the standard project
name with the same disposable volumes for the harness container-name
compatibility).

## Deterministic unit/contract matrix

| ID | Scenario | Test | Result |
| --- | --- | --- | --- |
| CR-U01 | Canonical realm constant `mtmf-dev` | `test_cru01` | PASS |
| CR-U02 | Canonical issuer literal | `test_cru02` | PASS |
| CR-U03 | Canonical JWKS literal | `test_cru03` | PASS |
| CR-U04 | Valid three-field config accepted, no mutation | `test_cru04` | PASS |
| CR-U05 | Old issuer rejected before side effects | `test_cru05_cru07_old_values_rejected[old-issuer]` | PASS |
| CR-U06 | Old realm rejected | `test_cru05_cru07_old_values_rejected[old-realm]` | PASS |
| CR-U07 | Old JWKS rejected | `test_cru05_cru07_old_values_rejected[old-jwks]` | PASS |
| CR-U08 | Missing issuer rejected | `test_cru08_cru10_missing_values_rejected[issuer]` | PASS |
| CR-U09 | Missing JWKS rejected | `test_cru08_cru10_missing_values_rejected[jwks]` | PASS |
| CR-U10 | Missing realm rejected | `test_cru08_cru10_missing_values_rejected[realm]` | PASS |
| CR-U11 | `MTMF-DEV` rejected (case sensitive) | `test_cru11_cru12_realm_case_and_whitespace_rejected[MTMF-DEV]` | PASS |
| CR-U12 | Leading/trailing/newline whitespace realm rejected | `test_cru11_cru12_...` | PASS |
| CR-U13 | Issuer trailing slash rejected | `test_cru13_cru18_...` | PASS |
| CR-U14 | Issuer query/fragment rejected | `test_cru13_cru18_...` | PASS |
| CR-U15 | Issuer userinfo rejected | `test_cru13_cru18_...` | PASS |
| CR-U16 | `http` scheme rejected | `test_cru13_cru18_...` | PASS |
| CR-U17 | Wrong host/port rejected | `test_cru13_cru18_...` | PASS |
| CR-U18 | Prefix/suffix lookalike rejected (no `startswith`) | `test_cru13_cru18_...` | PASS |
| CR-U19 | JWKS relative/foreign/wrong-path rejected | `test_cru19_jwks_malformations_rejected` | PASS |
| CR-U20 | Malformed fail before cert/Compose/DB | `test_cru20_malformed_rejected_before_side_effects` | PASS |
| CR-U21 | `up-host-network` uses same validation | `test_cru21_up_host_network_same_validation` | PASS |
| CR-U22 | Initializer defaults to `mtmf-dev` in both paths | `test_cru22_initializer_fixture_defaults_to_mtmf_dev` | PASS |
| CR-U23 | Initializer realm/issuer mismatch stops | `test_cru23_initializer_realm_issuer_mismatch_stops` | PASS |
| CR-U24 | Compose initializer realm default `mtmf-dev` | `test_cru24_compose_initializer_realm_default` | PASS |
| CR-U25 | Compose service realm default `mtmf-dev` | `test_cru25_compose_service_realm_default` | PASS |
| CR-U26 | `mtmf-admin` stays master admin, not end-user realm | `test_cru26_canonical_admin_is_master_realm` | PASS |
| CR-U27 | Standard setup uses `--realm mtmf-dev`; PR14 default unchanged | `test_cru27_realm_setup_invocation_and_fixture_default` | PASS |
| CR-U28 | No routine password reset | `test_cru28_initializer_has_no_routine_password_reset` + `test_pr17b_development_user.py` | PASS |
| CR-U29 | Legacy issuer rejected in probe; no fallback | `test_cru29_probe_rejects_legacy_issuer` | PASS |
| CR-U30 | Diagnostics redact untrusted input/credentials | `test_cru30_diagnostics_redact_untrusted_input` | PASS |

Module totals: `test_pr17c_dev_realm.py` 41 passed; full `./build.sh --qa` =
**2153 passed**, coverage **90.75%**.

## Live integration/security matrix

| ID | Case | Result |
| --- | --- | --- |
| CR-I01 | Test project/volumes proven non-persistent | PASS — disposable `mtmf-fixup3-*` volumes; operator `mtmf-dev-keycloak-data`/`mtmf_mtmf-postgres-data` and `mtmf-pr14-keycloak-data` preserved |
| CR-I02 | Foreign project/volume not targeted | PASS — only the named disposable project/volumes were used and removed; volumes list after cleanup still shows the operator + PR14 volumes |
| CR-I03 | Fresh Keycloak bootstraps `mtmf-admin`; `mtmf-dev` provisioned | PASS |
| CR-I04 | Fresh Postgres + initializer consistent binding | PASS — initializer completed; `mtmf-dev-user` sub `a9983174-ded6-4ec3-9129-e0b9c259db00` |
| CR-I05 | Discovery `issuer` exact `mtmf-dev`, TLS CA/SAN verified | PASS |
| CR-I06 | Discovery `jwks_uri` exact, keys retrievable | PASS |
| CR-I07 | Token `iss` equals new issuer | PASS |
| CR-I08 | Old realm absent; old issuer rejected | PASS — `/realms/mtmf-pr14-dev` HTTP 404 in the fresh volume |
| CR-I09 | Attestation under new realm, no weakened policy | PASS — initializer `verify_issuer` passed against the unchanged `expected-realm-security.json`/policy |
| CR-I10 | No privileged runtime credentials in service | PASS — service env has no admin/migrator/owner secret |
| CR-I11 | Standard isolated `up` with forwarder, loopback-only | PASS — forwarder `publish=none`; PostgreSQL/Keycloak/service loopback-only; no host networking |
| CR-I12 | Three unchanged `up` cycles stable | PASS — identical container IDs/`StartedAt`, 0 unexpected stop/rm |
| CR-I13 | `down`/`up` preserves realm/clients/`sub`/binding | PASS — 18 clients, sub `a9983174-…`, 1 active binding, 2 tenants preserved |
| CR-I14 | Existing old-realm volume fails closed, no mutation | PASS — standard `up` rejected with an actionable non-secret error; Keycloak container untouched |
| CR-I15 | Wrong realm/issuer/JWKS fails before startup | PASS — CR-U20/CR-U21/CR-I14 |
| CR-I16 | Forwarder reliability | PASS — **100/100** sequential (max 0.023 s), **50/50** @10 (max 0.048 s), **30/30** direct control |
| CR-I17 | PR17-B / PR14 / PR17 live regressions | PASS — **13 / 22 / 26** |
| CR-I18 | Disposable reset yields fresh subject + binding | PASS — new sub `a9983174-…` (pre-reset standard sub was `5d198663-…`); matching binding; no foreign resources affected |

## Mandatory repository gates (fixup tip)

```text
./build.sh --qa           2153 passed, coverage 90.75%
./build.sh --sec          0 findings (Bandit Medium/High 0, Semgrep 0)
./build.sh --rust         PASS
./build.sh --integration  564 passed, 65 skipped
```
