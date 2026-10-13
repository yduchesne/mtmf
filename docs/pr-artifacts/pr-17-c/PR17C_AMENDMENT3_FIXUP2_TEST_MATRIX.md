# PR 17-C Amendment 3 Fixup 2 — Test Matrix (CA-U01–U32, CA-I01–I14)

Deterministic tests: `tests/unit/service/test_pr17c_dev_stack.py` (CA-U01–CA-U08)
and `tests/unit/service/test_pr17c_dev_admin_migrate.py` (CA-U09–CA-U32), using a
scripted fake of the Keycloak Admin REST/credential boundary. Live tests use the
real rootless Podman/Keycloak topology.

## Unit / contract matrix

| ID | Scenario | Test | Result |
| --- | --- | --- | --- |
| CA-U01 | Username unset → defaults to `mtmf-admin` | `test_cau01_username_unset_defaults_to_canonical` | PASS |
| CA-U02 | Explicit `mtmf-admin` accepted | `test_cau02_explicit_canonical_accepted` | PASS |
| CA-U03 | `mtmf-pr14-admin`/`mtmf-pr14-admin2` rejected before side effects | `test_cau03_legacy_pr_numbered_rejected_before_side_effects` | PASS |
| CA-U04 | Empty/whitespace/uppercase/other rejected | `test_cau04_empty_whitespace_uppercase_or_other_rejected` | PASS |
| CA-U05 | Bootstrap password missing → fail before Compose | `test_cau05_bootstrap_password_missing_fails_before_compose` | PASS |
| CA-U06 | Initializer credential missing → fail closed | `test_cau06_initializer_credential_missing_fails_closed` | PASS |
| CA-U07 | Normal config → one canonical account; mismatched passwords rejected | `test_cau07_normal_config_targets_one_account`, `test_cau07b_mismatched_passwords_fail_closed` | PASS |
| CA-U08 | Wrong initializer admin username → fail closed | `test_cau08_wrong_initializer_username_fails_closed` | PASS |
| CA-U09 | Canonical absent → created enabled local with minimum role | `test_cau09_absent_canonical_created_with_role` | PASS |
| CA-U10 | Canonical exists verified → reuse, no reset | `test_cau10_existing_verified_reused_without_reset` | PASS |
| CA-U11 | Canonical exists unverified → STOP | `test_cau11_cau30_unverified_canonical_stops` | PASS |
| CA-U12 | Duplicate exact username → STOP | `test_cau12_duplicate_canonical_stops` | PASS |
| CA-U13 | Create 409 → STOP, no second POST | `test_cau13_create_conflict_stops_without_second_post` | PASS |
| CA-U14 | Create timeout / no Location → STOP, no retry | `test_cau14_create_timeout_stops_without_retry`, `test_cau14b_create_without_location_stops` | PASS |
| CA-U15 | Recovery credential fails → STOP | `test_cau15_recovery_credential_failure_stops` | PASS |
| CA-U16 | New admin login fails → legacy remain enabled | `test_cau16_new_admin_login_failure_leaves_legacy_enabled` | PASS |
| CA-U17 | New admin lacks `admin` role → STOP | `test_cau17_new_admin_missing_role_stops` | PASS |
| CA-U18 | New admin privileged read fails → STOP | `test_cau18_privileged_read_failure_stops` | PASS |
| CA-U19 | Verification passes → disable eligible | `test_cau19_cau20_verification_then_disable_read_after_write` | PASS |
| CA-U20 | First legacy disable → read-after-write confirms disabled | same | PASS |
| CA-U21 | First disable fails → STOP, second not attempted | `test_cau21_first_disable_failure_stops` | PASS |
| CA-U22 | Second disable fails → STOP, partial recorded | `test_cau22_second_disable_failure_reports_partial` | PASS |
| CA-U23 | Rerun after migration stable | `test_cau23_rerun_after_completed_is_stable` | PASS |
| CA-U24 | Insecure/untrusted transport rejected | `test_cau24_insecure_or_untrusted_transport_rejected` | PASS |
| CA-U25 | Errors do not disclose secrets | `test_cau25_errors_do_not_disclose_secrets` | PASS |
| CA-U26 | Fresh volume bootstrap uses canonical name | `test_cau26_fresh_volume_bootstrap_uses_canonical_name` | PASS |
| CA-U27 | PR 14 fixture contract unchanged | `test_cau27_pr14_evidence_fixture_unchanged` | PASS |
| CA-U28 | Preserved volume bootstrap does not reset existing user | `test_cau28_preserved_volume_bootstrap_does_not_reset_existing_user` | PASS |
| CA-U29 | Missing credential custody → STOP | `test_cau29_missing_credential_custody_stops` | PASS |
| CA-U30 | Unexpected federated/disabled/required-action account → STOP | `test_cau11_cau30_unverified_canonical_stops` | PASS |
| CA-U31 | Admin lookup 401/5xx → STOP | `test_cau31_admin_lookup_unauthorized_stops` | PASS |
| CA-U32 | Canonical has unexpected extra roles → STOP | `test_cau32_unexpected_extra_role_stops` | PASS |
| — | `--inspect` is read-only | `test_inspect_is_read_only` | PASS |

Module totals: `test_pr17c_dev_stack.py` 55 passed; `test_pr17c_dev_admin_migrate.py` 27 passed. Full `./build.sh --qa` = **2107 passed**, coverage **90.75%**.

## Live integration/security matrix

| ID | Case | Result |
| --- | --- | --- |
| CA-I01 | Existing-volume read-only inspection | PASS — `mtmf-admin` ABSENT; both legacy admins enabled, roles `[admin, default-roles-master]` |
| CA-I02 | Recovery admin authentication | PASS — `mtmf-pr14-admin2` authenticated and performed privileged reads |
| CA-I03 | Create/reconcile canonical admin | PASS — exactly one `mtmf-admin` in `master`, role `admin`, no duplicate |
| CA-I04 | Independent canonical admin authentication | PASS — fresh `mtmf-admin` token, privileged `master` + realm reads |
| CA-I05 | Disable legacy accounts | PASS — both legacy admins `enabled=false`, `mtmf-admin` `enabled=true` |
| CA-I06 | Repeat admin authentication after cleanup | PASS — fresh `mtmf-admin` login and privileged reads |
| CA-I07 | Existing-volume `up`/`preflight` | PASS — `up` 0, `preflight` 0, `/health/ready` 200; realm/user `sub` unchanged |
| CA-I08 | Fresh-volume behavior | PASS — isolated `mtmf-fixup2-freshcheck` volume/project bootstrap created `mtmf-admin` which authenticated; test resources removed; the persistent volume was not touched |
| CA-I09 | No credential leakage | PASS — service env has no admin credential (`MTMF_AUTH_ADMIN_BASE`/`REALM` only, non-secret); no secret in reports/git |
| CA-I10 | PR 14 evidence fixture isolation | PASS — fixture files unchanged; PR 14/17 live suites pass |
| CA-I11 | Repeated standard `up` ×3 | PASS — after the one expected Compose config transition, all four container IDs/`StartedAt` stable, 0 unexpected `stop`/`rm` |
| CA-I12 | Negative TLS/issuer/wrong credentials | PASS — unit CA-U15/U24/U31 and launcher issuer/admin validation fail closed |
| CA-I13 | Recovery admin unavailable | PASS (controlled fake) — CA-U15/CA-U21/CA-U22 prove STOP without disabling the live working admin |
| CA-I14 | Post-migration account inventory | PASS — one enabled `mtmf-admin`; two legacy disabled; realm `mtmf-pr14-dev`; dev user `sub` `5d198663-…`; 18 clients incl. `mtmf-sample-app` and `mtmf-attestation-reader` |

## Authoritative gates and regressions (fixup tip)

```text
uv sync --locked          PASS
./build.sh --qa           2107 passed, coverage 90.75%
./build.sh --sec          0 findings (Bandit Medium/High 0, Semgrep 0)
./build.sh --rust         PASS
./build.sh --integration  564 passed, 65 skipped
PR 17-B live              13 passed
PR 14 live                22 passed
PR 17 live                26 passed
Forwarder reliability     100/100 sequential; 50/50 @10; 30/30 direct control
```
