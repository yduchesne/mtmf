# PR 14 Amendment #3 — Shared-Audience D1 Live Acceptance Closure

**Status:** APPROVED EXECUTION PLAN; NOT MERGE AUTHORIZATION  
**Branch:** `dev/service-auth` (do not merge)  
**Architecture authority:** `docs/PR14_AUTHENTICATION_SECURITY_DECISIONS.md` §14J, commit `ceeb1f9a1be3a01c1a09506b08f065613949aa07`  
**Authoring standard:** `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`, especially §§2–3D and 37A.  
**Baseline:** Amendment #2 commit `db9bfedb980c11811506db82fec935624f3caa42`; refresh both refs before acting.

## 1. Purpose and success condition

Resolve Amendment #2's proven Keycloak 26.8.0 same-client audience limitation without changing D1's same-client trust model. Execute the **actual** Keycloak-issued service + interactive-user token → shipped per-operation Admin REST attestation → shipped RS256/JWKS verification → `AuthenticatedActorContextService.resolve` → real `PostgresMtmfSpi`/UnitOfWork/stored functions → ordinary Tenant actor-context slice. Close DC07, V01–V16 and remaining mandatory live AUTH/D1 evidence, with exact executable test-node mapping. No public HTTP route.

**Important:** Shared `aud` is an intended-recipient check, **never** evidence of grant type. Authentication classes rely on the reviewed and freshly attested signed `client_id`/ `azp` predicate. Neither a signed `client_id` alone nor an attestation result alone establishes grant type; both controls and all other actor eligibility gates are required.

## 2. Current-main/branch facts; required Phase 0 reconciliation

Already inspected on `dev/service-auth`:
- `dev/keycloak/setup-realm.py`: `ClientSpec` and `mtmf-evidence-same-client` already permit service account + standard authorization-code flow with audience `mtmf-same-client-api`. Amendment #2 experimentally demonstrated both grant types receive the same audience set when extra mappers are added. **Do not add separate class-specific audience mappers.**
- `packages/mtmf-service/src/mtmf_service/authentication/composition.py`: `build_actor_context_service(spi, IssuerConfig)` already creates independent service/user `IssuerProfile` objects, one `JwksKeyProvider`, shipped `PyJWTTokenVerifier`, `HttpAdminRestReader`, and `BaselineConfigurationAttestor`. No route.
- `packages/mtmf-service/src/mtmf_service/authentication/attestation.py`: canonical live Admin REST manifest and exact baseline comparison; per-operation fresh read. Preserve this; avoid baseline learned from live state.
- `packages/mtmf-service/src/mtmf_service/authentication/jwt_verifier.py`: strict duplicate-JSON/JOSE/base64 validation, fixed algorithm, issuer/audience/time checks and bounded JWKS.
- `docs/PR14_AMENDMENT2_ACCEPTANCE_REPORT.md`: DC05-LOCAL-KEY PASS; DC05-ISSUER NOT EXECUTED; DC07/V01–V16 NOT EXECUTED. Existing real-PG uniqueness/concurrency/lifecycle and deterministic tests PASS per agent report; independently rerun relevant regressions.
- `docs/PR14_AMENDMENT2_ACCEPTANCE_MATRIX.md`: named remaining case crosswalk. `AUTH-26/27` are DEFERRED ROOT, with root fail-closed required.
- `docs/PR14_DEVELOPMENT_FIRST_IMPLEMENTATION_GATE.md` contains historical distinct-audience assumptions. §14J supersedes them **only for the development-only D1 profile**.

**Agent MUST FIRST:** fetch `origin/main` and `origin/dev/service-auth`, record both SHAs and actual branch HEAD; inspect changed files, `IssuerConfig` validators, `AuthenticatedActorContextService.resolve`, `PostgresMtmfSpi` factory and provisioning test helpers, migration `0011`, runtime allowlist, current Keycloak baseline location, token acquisition scripts and exact V01–V16 definitions in preceding plans. Record a table of DONE+VERIFIED, DONE+UNVERIFIED, PARTIAL, NOT STARTED, BLOCKED. If another commit changed §14J or core predicates, STOP and reconcile. Do not reset, overwrite, or recreate verified work.

## 3. Non-negotiable security invariants

1. Pin development Keycloak image `quay.io/keycloak/keycloak:26.8.0-1` at digest `sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741`; loopback `https://127.0.0.1:28443`, realm `mtmf-pr14-dev`, isolated Podman resources `mtmf-pr14-keycloak` only.
2. **Exact configured audience remains required for each token**, even when service/user audience strings are identical. Do not turn off `verify_aud`, accept arbitrary audiences, infer class from `aud`, or trust unsigned token fields.
3. Verify each access token independently: RS256, configured issuer, configured audience, expiry, iat, optional nbf, trusted bounded JWKS. Service class: signed `typ=Bearer`, nonempty `client_id == azp`; user class: signed `typ=Bearer`, nonempty `azp` and `sub`, **no `client_id`**. Confirm exact behavior from current core code before writing tests.
4. Service/user `azp` values must match exactly; independently resolve service `(issuer,client_id)` to eligible Application and user `(issuer,sub)` to active FEDERATED Identity. Active Principal/Tenant membership, Application registration and subscription required; root rejected; default deny.
5. Every `resolve` performs fresh live privileged Admin REST attestation against a **separately reviewed committed manifest**, with no positive cache. Any drift, network error, credential failure, invalid baseline or ambiguous mapping fails closed. Retain malicious `client_id` mapper injection test.
6. No open PostgreSQL transaction across Keycloak network operations. Only existing SPI/UoW/stored functions; runtime direct table SELECT and operator mutations denied. Never broaden grants or rewrite versioned SQL.
7. No secrets, private keys, bearer tokens, passwords or user PII in source, evidence, exception strings or logs. Test-only RSA keys used for DC05 remain test-only.
8. Do not claim cryptographic proof of grant type; residual risks: privileged issuer admin, attestation TOCTOU, bearer replay/separate-session token acquisition, bounded JWKS rotation cache.

## 4. Exact work sequence

### Phase 0 — Baseline and feasibility inventory (no production edits)

1. Reconcile commits and inspect all above files. Find the **actual** expected manifest and generator/review workflow. Inspect Keycloak setup for existing same-client audience mapper and built-in `service_account` scope. Inspect `IssuerConfig` validation: if it rejects equal audiences, add a **development-only, explicitly gated** allowance with unit tests; otherwise prefer a configuration-only change. Do not modify generic verifier semantics.
2. Locate exact original V01–V16 definitions and test-harness entry points. Create a written case-to-fixture matrix **before coding**; do not invent/rename their meaning.
3. Record test baseline: existing auth unit tests, real PostgreSQL integration, `./build.sh --integration`, and relevant fixture bootstrap commands. Baseline failures require §3C classification.
4. STOP if a supported attested same-client class distinction cannot be demonstrated in the pinned fixture, or if the live fixture is not safely isolated.

### Phase 1 — Minimal shared-audience fixture + independently reviewed baseline

1. Use existing `mtmf-evidence-same-client` with **one configured shared recipient audience**, preferably existing `mtmf-same-client-api`. Do not add grant-specific mappers, a custom Keycloak extension, or broaden the audience set just to satisfy the tests.
2. Start only the namespaced pinned Keycloak fixture. Obtain one real `client_credentials` access token and one real authorization-code+PKCE interactive-user access token for the **same** client. Never print/store token strings. Record sanitized signed-claim summaries: issuer, audience list, `azp`, `client_id` present/absent, `sub` class, payload `typ`, algorithm, `kid`; verify signatures using the shipped verifier.
3. Required result: both tokens include the configured shared audience, service `client_id==azp`, user `client_id` absent, both `azp` equal. Also verify that swapping slots fails **even though audiences match**.
4. Derive expected manifest by reviewing the **declared fixture configuration and actual canonical schema**, not by trusting a snapshot of arbitrary live state. A one-time live canonicalization may be used as comparison evidence, **not** as an automatically approved trust baseline. Produce a human-reviewable diff and canonical hash. Commit baseline only after verifying each security-sensitive client, scope, mapper, grant setting and realm association. Existing G0-A malicious-mapper drift must still fail and restoration must pass.
5. Clean `down -v` recreate the fixture, reapply idempotent setup, rerun both token-class and attestation checks; require identical expected manifest hash. Preserve historical G0-T09/R06/R12 artifacts; report new run separately.
6. STOP if class predicate is spoofable while live manifest is accepted, expected manifest cannot be independently justified, or clean recreate differs.

### Phase 2 — Real Keycloak + real PostgreSQL DC07 canonical actor slice

1. Add a dedicated **live acceptance harness** under the existing test conventions (inspect paths first). Gate it explicitly on the namespaced Keycloak fixture and PostgreSQL 18; it must never silently skip in the authoritative acceptance run. Isolated unit tests may use fake transports; **DC07 may not**.
2. Build `IssuerConfig` with shared configured service/user audience, pinned issuer/JWKS, reviewed manifest path, trusted dev CA and dedicated privileged attestation credentials. Construct actor service **only** through `build_actor_context_service(real_postgres_spi, config)`.
3. Provision real ordinary Tenant, Organization/default where needed, active Principal/FEDERATED Identity, active Application, service-client binding, subject binding, Tenant membership, Application registration and active subscription **using existing operator/test provisioning seams and real versioned stored functions**. No direct runtime table writes. Record generated identifiers only in sanitized evidence. Do not hard-code production identities.
4. Acquire fresh real Keycloak-issued service and user tokens for the same client and invoke `resolve(service_token, user_token, tenant_id)`. Assert returned actor context references the expected persisted Application, Principal, Identity and Tenant; **no authorization ALLOW is implied**.
5. Instrument/wrap the shipped attestor only for counting if needed without replacing its behavior. Assert one fresh Admin REST read/attestation on each resolve; after a successful resolve, inject the forbidden `client_id` mapper and assert next resolve fails; restore and assert next succeeds. Include Admin REST outage, invalid admin credential, invalid/missing baseline.
6. Exercise negative cases by mutating **real persisted state through reviewed operator APIs** and obtaining real Keycloak tokens as required. Roll back/restore fixture state between tests. Ensure no transaction spans remote Keycloak I/O.
7. For every live case, capture test node, environment, exact command, expected/actual typed failure, and cleanup outcome. If a test requires a token the issuer cannot issue, report the exact unsupported condition; never replace it with a locally signed token and call it DC07.

### Phase 3 — V01–V16 and AUTH/D1 live traceability

**Use original V01–V16 definitions as authority.** The table below is a coverage checklist, not permission to relabel those original IDs:

| Coverage group | Required live assertions |
| --- | --- |
| Positive same-client | Keycloak service+user tokens with shared `aud`, valid signed class predicate, real PG eligible actor; repeated resolve stable |
| Wrong slot/class | Service token in user slot, user token in service slot, wrong-grant token with correct shared audience all rejected |
| Cross-client | Valid independently signed tokens from different clients rejected on verified `azp` mismatch |
| Invalid binding | Missing/revoked service or subject binding; inactive Application, Identity or Principal |
| Tenant gates | Inactive Tenant, missing membership, cross-Tenant selection |
| Application gates | Missing/inactive registration or subscription |
| Root | Root Identity/Tenant/Principal always rejected |
| Trust boundary | Mapper drift after success, Admin REST outage, malformed baseline, verifier/JWKS outage, wrong issuer/signature/audience |
| Freshness | Binding revocation between resolves denies second; no positive actor cache |
| Infrastructure | Real PG outage/failed SPI resolution gives typed fail-closed error; restore without data corruption |

1. Map **every original V01–V16** to a distinct executed test node and result. If two cases share a parameterized node, include case parameter IDs.
2. Reconcile **AUTH-01–AUTH-36** and **D1-01–D1-10** using Amendment #1 and #2 matrices. A previous unit PASS stays unit PASS; mark full-layer PASS only after the actual live slice. Prior real-PG binding tests need not be reimplemented but must be rerun. `AUTH-26/27` remain DEFERRED ROOT, with fail-closed proof.
3. Explicitly address AUTH-05/D1-09 (no caller-provided UUID or assertion can authenticate; no HTTP route exists), AUTH-32 real DB outage, AUTH-33 real revocation freshness, AUTH-36 no secrets in errors/logs, and D1-10 clean recreate. If not executable in approved scope, write a specific disposition and request review; do not mark PASS by construction alone.
4. Preserve DC05 split: **DC05-LOCAL-KEY PASS (rerun)**; **DC05-ISSUER NOT EXECUTED (issuer limitation)**. Never conflate.
5. Distinguish historical evidence from new evidence. Do not overwrite or retroactively mark historical artifacts PASS.

### Phase 4 — Regression, security and final acceptance

Run in this order, capture commands, exit status, counts and coverage:
1. Targeted auth unit tests: `uv run --no-sync pytest tests/unit/authentication -q --no-cov`.
2. Targeted PostgreSQL tests with real PostgreSQL 18, `mtmf_runtime` and operator roles, actual test environment: `uv run --no-sync pytest tests/integration/postgres/test_postgres_authentication_bindings.py -q --no-cov`.
3. **New live Keycloak+real-PG acceptance harness**: exact repository-prescribed command with explicitly verified live prerequisites; zero skips for DC07/V01–V16. Record which tests were truly executed.
4. `./build.sh --integration` — authoritative DB integration gate, not replaceable by targeted pytest.
5. `./build.sh --qa`, `./build.sh --sec`, `pre-commit run --all-files`.
6. Migration `0011`, **77-signature** runtime function verifier and runtime direct-table/operator-mutation denial.
7. Clean recreate and mapper-drift/restore tests after the final fixture and manifest changes.

On failure classify as introduced regression, feature defect, reproduced baseline failure, demonstrated flake or environment/harness failure. No green subset, rerun or undocumented skip is acceptance. Verify no foreign Podman resources touched and all fixture secrets excluded from Git.

## 5. Expected changes and forbidden changes

**Likely files** (confirm paths during Phase 0): `dev/keycloak/setup-realm.py` only if required; development `IssuerConfig` profile or validation if equal audiences are currently rejected; reviewed expected manifest; new live test harness and provisioning helpers; `docs/PR14_AMENDMENT3_ACCEPTANCE_MATRIX.md`, `docs/PR14_AMENDMENT3_ACCEPTANCE_REPORT.md`; status-only gate/roadmap edits **after** evidence.

**Preserve:** `AuthenticatedActorContextService`, `build_actor_context_service`, `PyJWTTokenVerifier`, `BaselineConfigurationAttestor`, existing stored functions/SPI/UoW, G0-A historical artifacts, all Amendment #1/#2 passing tests. Make the smallest proven production defect fix only with failing regression first.

**Forbidden:** production issuer, root authentication/recovery, RFC 8693, cross-client delegation, HTTP routes, new token minting, extra auth authority, grant-type inference from `aud`, relaxing signature/issuer/audience/class checks, auto-learning trusted manifest, caching positive attestation, schema/migration/grant changes without new human approval, editing shipped versioned SQL, modifying unrelated Podman projects.

## 6. Explicit STOP conditions

STOP and report evidence (do not improvise) if: (S1) branch/main/approval drift changes security contract; (S2) same-client service/user signed class predicate fails under approved configuration; (S3) forbidden mapper can spoof a class without drift detection; (S4) independently reviewed manifest unavailable; (S5) any authentication accepts token with missing/wrong configured audience, invalid issuer/signature or wrong class; (S6) live Keycloak or PG topology cannot be established; (S7) DC07 requires fake SPI/verifier/attestor or direct DB writes; (S8) real Tenant/root isolation cannot be maintained; (S9) new migration/grant/public API seems necessary; (S10) live test is skipped or evidence cannot distinguish executed vs merely implemented; (S11) secret/token leakage; (S12) fixture clean recreation or cleanup fails; (S13) required gate fails without defensible classification; (S14) approved scope requires broader trust-model changes.

On STOP: commit only independently completed, tested, safe changes; preserve unexecuted statuses; provide smallest reviewer decision needed; **never recommend merge**.

## 7. Reviewer checklist and PR-level acceptance

- [ ] Fresh main/branch SHAs and reconciliation table recorded; no verified work reimplemented.
- [ ] Signed same-client service and interactive tokens show correct class predicate with **shared audience**; swapped slots rejected.
- [ ] Exact audience, issuer, RS256, expiry and all current JWKS defenses unchanged.
- [ ] Independently reviewed baseline; malicious mapper drift fails; restored state passes; clean recreate reproducible.
- [ ] DC07 passes via shipped composition, live attestation and **real** PG SPI/UoW/stored functions.
- [ ] Every original V01–V16 mapped to **executed** live node; no skips.
- [ ] AUTH-01–36 and D1-01–10 have accurate layer-specific statuses; AUTH-26/27 root deferred and root fails closed.
- [ ] Real-PG privilege and runtime function signature gates pass; no schema/grant expansion.
- [ ] DC05-ISSUER remains NOT EXECUTED, DC05-LOCAL-KEY independently PASS.
- [ ] All integration/QA/security/pre-commit gates executed and PASS; no leaks or foreign resource changes.
- [ ] Docs updated from evidence, not aspiration; explicit residual risks and merge recommendation recorded.

**Completion rule:** all mandatory non-root live acceptance cases must pass in their prescribed topology, or the reviewer must explicitly approve a documented exception. The coding agent **cannot grant itself an exception or merge authorization**.

## 8. Final agent report format

Return: branch + fresh main/base/final SHAs; exact changed paths; fixture image digest, CA, sanitized claims, reviewed baseline hash, clean-recreate result; live DC07 + V01–V16 table with test nodes; AUTH/D1 crosswalk; DC05 split; PostgreSQL/privilege proof; all exact gate commands/results; STOPs and residual risks; explicit **MERGE RECOMMENDED / NOT RECOMMENDED** (never claim merged); commits pushed and clean tree.

## 9. Suggested PR amendment description and next dependency

**Title:** `PR 14 Amendment #3 — Shared-Audience D1 Live Acceptance Closure`.

**Description:** Align the development-only Keycloak D1 fixture with observed shared-audience semantics while retaining independent JWT verification, signed attested class predicates, fresh configuration attestation and real PostgreSQL actor eligibility. Complete canonical live acceptance and named traceability without extending production/root/API scope.

**Next dependency:** PR 14 security reviewer accepts evidence and separately authorizes merge. Later PRs own production issuer trust, root authentication/recovery and HTTP transport.
