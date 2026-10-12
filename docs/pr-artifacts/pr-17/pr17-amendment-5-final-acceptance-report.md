# PR 17 — Amendment #5 final acceptance report

**Branch:** `dev/pr17-http-service`. **Base:** `4eea688`; prior head `e6bdcbc`.
**Amendment #5 feature commit:** `__FILL_AFTER_COMMIT__` (all gates and the
pre-commit hook ran on this tree).
**Disposition: IMPLEMENTATION COMPLETE — ACCEPTANCE COMPLETE — READY FOR HUMAN REVIEW.**
No self-merge; PR 17 is not marked DONE.

## 1. Findings closed

| ID | Finding | Status |
| --- | --- | --- |
| SEC-01 | admin `admin-cli` password grant in runtime | **FIXED** — dedicated client-credentials reader; least-privilege proof |
| SEC-02 | `down_volumes()` omitted host-network cleanup | **FIXED** — unified ownership-verified cleanup |
| SEC-03 | expected-client policy schema not strict | **FIXED** — strict versioned type/field/duplicate validation |
| SEC-04 | projection coverage not inventoried | **DOCUMENTED + TESTED**; AT16 kept PARTIAL |
| SEC-05 | non-atomic Admin REST reads | **CHARACTERIZED**; ABA residual documented |

## 2. Final gates

| Gate | Command | Result |
| --- | --- | --- |
| Quality | `./build.sh --qa` | PASS — 1806 passed, 0 skipped, coverage 90.39% |
| Security | `./build.sh --sec` | PASS (0 findings) |
| Rust | `./build.sh --rust` | PASS (pre-commit hook) |
| Integration | `./build.sh --integration` | PASS — 564 passed, 51 skipped (the 51 = PR 14 live 22 + PR 17 live 26 + reader permissions 3, run separately and passing) |
| PR 14 live actor | opt-in | PASS — 22 passed |
| PR 17 live HTTP | opt-in | PASS — 26 passed |
| Reader permissions | opt-in | PASS — 3 passed |
| Pre-commit | commit hook | PASS |

## 3. Acceptance criteria A5-01–A5-22

All satisfied. Highlights: dedicated least-privilege reader with real denial
proof (A5-02/A5-03); runtime uses client credentials with no admin fallback
(A5-04) and no privileged credentials (A5-05); bounded/typed transport
(A5-06); fresh per-request signed-`azp` attestation retained (A5-07); strict
loaders (A5-08); field inventory (A5-09); AT16 accurately PARTIAL (A5-10);
read-skew characterized (A5-11); both teardown paths ownership-verified
(A5-12/A5-13/A5-14); U01–U28 and I01–I16 executed (A5-15/A5-16); genuine
ALLOW/DENY/revocation/recovery (A5-17); PR14/PR17 live + V01–V16 (A5-18); all
gates (A5-19); nine reports (A5-20); no protected-contract change (A5-21);
clean tree, no self-merge (A5-22).

## 4. Files changed

```
packages/mtmf-service/src/mtmf_service/authentication/attestation.py   (client-credentials reader, strict policy/JSON schema, bounded transport)
packages/mtmf-service/src/mtmf_service/authentication/config.py        (reader client id/secret + _FILE; reject admin-only)
packages/mtmf-service/src/mtmf_service/authentication/composition.py   (reader wiring)
dev/keycloak/setup-realm.py                                            (provision least-privilege reader + roles)
scripts/mtmf-dev-stack.py                                              (ownership labels; unified cleanup; reader secret via _FILE)
compose.dev.yaml, .env.example                                        (reader client env; admin = initializer-only)
tests/unit/authentication/{test_attestation,test_attestation_reader,test_config,test_actor_context}.py
tests/unit/service/{conftest,test_dev_stack_lifecycle}.py
tests/integration/postgres/test_pr14_live_actor_context.py, test_pr17_live_http.py, test_pr17_attestation_reader_permissions.py
docs/pr-artifacts/pr-17/pr17-amendment-5-*.md
docs/ARCHITECTURE.md, docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md, docs/ROADMAP_V01.md
```

## 5. Residuals and disposition

Residuals R-2..R-7 in `pr17-amendment-5-stop-deviation-register.md`. R-1
(runtime admin credential) is resolved.

**Disposition:** IMPLEMENTATION COMPLETE — ACCEPTANCE COMPLETE — READY FOR HUMAN
REVIEW. Not merged; not DONE.
