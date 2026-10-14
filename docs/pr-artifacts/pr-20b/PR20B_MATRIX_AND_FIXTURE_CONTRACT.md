# PR20B_MATRIX_AND_FIXTURE_CONTRACT

**PR:** roadmap PR 20B — Deployed End-to-End Conformance and Resilience
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Baseline SHA:** `c7c992a372bb83bae3837efb04b1f19742bb83e2`
**Purpose:** freeze the exact existing contracts, fixture identities, and
test-inventory mapping that PR20B accepts against. **No guessed SQL names and
no raw table writes.** Every stored function and enum below was read from the
repository source on the baseline SHA.

## 1. Immutable fixture identities

| Symbol | Value | Source |
| --- | --- | --- |
| Fixture Tenant T1 | deterministic from `tenant:dev` (`MTMF_DEV_TENANT_KEY=dev`) | `scripts/mtmf-dev-initialize.py` `_deterministic("tenant:dev")` |
| Fixture Application A1 | `application_id("evidence-same-client")` (`uuid5(FIXTURE_NAMESPACE, "application:evidence-same-client")`) | `scripts/pr20a_reference_fixture.py` |
| Allowed user | `mtmf-user-alice` (verified subject at runtime) | `pr20a-reference-acceptance.py` `ACCEPTANCE_ALLOWED_USERNAME` |
| Denied user | `mtmf-user-bob` (verified subject at runtime) | `pr20a-reference-acceptance.py` `ACCEPTANCE_DENIED_USERNAME` |
| Action | `urn:mtmf:iam:actions:system:document:read-object` | `app.py` `DOCUMENT_READ_ACTION` |
| Matching Permission | `urn:mtmf:iam:permissions:system:document:read-object` | `pr20a_reference_fixture.py` |
| Role | `urn:mtmf:iam:roles:tenant:{T1}:reference-document-reader` (TENANT-defined) | `pr20a_reference_fixture.py` `reference_role_urn` |
| Document D1 | `d0c0a1e0-0001-4000-8000-000000000001` (T1) | `pr20a-reference-acceptance.py` `ALLOWED_DOCUMENT_ID` |
| Other-Tenant document D2 | `d0c0a1e0-0002-4000-8000-000000000002` (other Tenant) | `pr20a-reference-acceptance.py` `OTHER_TENANT_DOCUMENT_ID` |
| Other Tenant | `d0c0a1e0-0003-4000-8000-000000000003` | `OTHER_TENANT_ID` |

PR20B adds one further T1 document, **D3**, with a distinct deterministic UUID
and fixture-owned title/body, seeded through the existing
`mtmf_reference_app.fixture_loader` manifest mechanism. **No T2/A2 resources are
assigned to T1 implicitly.** D2 deliberately remains owned by a different
Tenant so that cross-Tenant isolation can be asserted without creating a second
MTMF Tenant.

## 2. Sanctioned lifecycle / subscription primitives (read from source)

PR20B may mutate acceptance-only fixture state **only** through these existing,
reviewed stored functions, executed with the authenticated `mtmf_migrator`
identity held by the one-shot fixture initializer. No direct `UPDATE`/`DELETE`
and no raw table writes are permitted.

| Operation | Function (exact) | Arguments (exact) | Lifecycle values |
| --- | --- | --- | --- |
| Suspend Tenant | `mtmf.suspend_tenant(uuid)` | `tenant_id` | sets `tenant.lifecycle = 2`; requires existing ordinary Tenant (`scope = 2`) |
| Activate Tenant | `mtmf.activate_tenant(uuid)` | `tenant_id` | sets `tenant.lifecycle = 1`; requires a valid stewardship designation and eligible steward |
| Subscription add | `mtmf.tenant_application_subscription_add(uuid, uuid, uuid, uuid, smallint, timestamptz, timestamptz, timestamptz)` | `id, application_id, tenant_id, created_by_identity_id, lifecycle, starts_at, ends_at, created_at` | `lifecycle` smallint; `ends_at > starts_at` when set |
| Subscription save (unsubscribe/subscribe) | `mtmf.tenant_application_subscription_save(uuid, smallint, timestamptz)` | `id, lifecycle, ends_at` | updates `lifecycle` + `ends_at` only |
| Revoke Role assignment | `mtmf.identity_role_assignment_remove(uuid, uuid, uuid, text)` / `mtmf.identity_role_assignment_add(uuid, uuid, uuid, text, uuid)` | see source | assignment identity/provenance immutable; remove + re-add restores exactly |
| Add Action (fixture) | `mtmf.action_add(text)` | exact Action URN | idempotent |
| Add Role (fixture) | `mtmf.role_add(jsonb)` | canonical Role aggregate | idempotent/drift-checked |
| Add IdentityRoleAssignment (fixture) | `mtmf.identity_role_assignment_add(uuid, uuid, uuid, text, uuid)` | `id, tenant_id, identity_id, role_urn, organization_id` | idempotent |

The subscription/tenant lifecycle numeric enum values are **not** hard-coded in
tests. The acceptance helper reads the persisted `lifecycle` value it wrote
through the same sanctioned primitive and asserts on the observed MTMF
eligibility outcome (HTTP mapping), not on an unverified enum literal. The
existing subscription lifecycle contract is used exactly as persisted by
`pr20a-initialize.py` (created active through `ensure_registration_and_subscription`).

Notes on restore semantics:

- `suspend_tenant`/`activate_tenant` are exactly reversible when the fixture
  steward remains eligible (it does — the fixture does not modify steward
  memberships).
- Subscription unsubscribe/subscribe is exactly reversible through
  `tenant_application_subscription_save` on the deterministic subscription id.
- Role revoke/re-grant is exactly reversible through
  `identity_role_assignment_remove` / `identity_role_assignment_add` using the
  deterministic assignment id from `reference_assignment_id`.
- `mtmf.tenant_application_subscription_save` is **SECURITY INVOKER** and
  owner-only (not granted to `mtmf_runtime`); the acceptance one-shot helper
  connects as `mtmf_migrator`.
- If a state cannot be safely restored through these primitives, the harness
  uses the isolated project `recreate` path instead of any manual row update.

## 3. Authorization snapshot constants (read from source)

| Constant | Value | Source |
| --- | --- | --- |
| `SNAPSHOT_MAX_TTL` | 300 s | `packages/mtmf-api/src/mtmf_api/authorization.py` |
| `SNAPSHOT_DEFAULT_TTL` | 60 s | same |
| `SNAPSHOT_SENSITIVE_MAX_TTL` | 15 s | same |
| `ClientConfig.max_snapshot_ttl_seconds` default | 60 (`_DEFAULT_MAX_SNAPSHOT_TTL`), bounded `0 < ttl <= 300` | `packages/mtmf-client/src/mtmf_client/config.py` |
| `ClientConfig.clock_uncertainty_seconds` default | 5.0 | same |
| Client tenant cap | `min(max_snapshot_ttl, SNAPSHOT_MAX_TTL, SNAPSHOT_SENSITIVE_MAX_TTL)` | `client.py` `_build_snapshot` |

The reference PEP performs **no cross-request snapshot caching** (each GET
triggers a new `evaluate`). PR20B therefore verifies the *client* snapshot
semantics deterministically with injected clocks, and measures the
post-revocation **new-request** behavior; it does **not** claim a cross-request
stale window.

## 4. Conformance inventory and matrix mapping

Legend: **L** = lower-level existing coverage (reused, not rewritten);
**D** = new deployed black-box acceptance; **C** = new deterministic client
test.

### 4.1 Part B — batch PEP route

| Requirement | Type | Where |
| --- | --- | --- |
| `POST /v1/documents/batch-read` fixed route, 1–16 unique canonical UUIDs | D + unit | `examples/mtmf-reference-app/tests/test_batch_pep.py` (unit) |
| any absent/cross-Tenant → generic 404, no MTMF call | D + unit | same |
| one batch, one occurrence per loaded row, `request_id="document-read-<index>"` | unit | same |
| single `evaluate`, `require` per occurrence in input order | unit | same |
| atomic disclosure: any DENY → 403, zero bodies | unit | same |
| mixed ALLOW/DENY in one verified user batch | D | **BLOCKED — P0 STOP, §5** |

### 4.2 Part C — deployed lifecycle/subscription

| ID | State | Expected | Type |
| --- | --- | --- | --- |
| L20B-01 | T1 active, A1 subscribed, Alice permitted, D1 present | 200 exact D1, real evaluation | D |
| L20B-02 | A1 unsubscribed from T1 | no 200/body; MTMF eligibility rejection mapped 403/401 | D |
| L20B-03 | subscription restored | 200, no residual deny | D |
| L20B-04 | T1 suspended/ineligible | no 200/body; authoritative rejection | D |
| L20B-05 | T1 restored active | 200; recovery works | D |
| L20B-06 | verified Bob in T1, no Role | 403; real MTMF DENY | D (extends L02) |
| L20B-07 | Alice requests D2 in another Tenant | 404; no MTMF call | D (extends L05) |
| L20B-08 | malformed/absent JWT | 401; no MTMF call | D (extends L03) |

### 4.3 Part D — spoofing / identity binding

| ID | Attempt | Expected | Type |
| --- | --- | --- | --- |
| S01 | spoofed user-forwarding header, no `Authorization` | 401, no evaluation | D |
| S02 | Bob Bearer + Alice token in spoofed header | Bob remains Bob; 403 | D |
| S03 | arbitrary Tenant/Application/Actor/Session headers | ignored; unchanged decision | D |
| S04 | body/query `tenant_id`/`application_id` spoof | ignored/rejected | D |
| S05 | wrong audience/issuer/typ or bad signature | 401, no evaluation | D (reuses isolated fixture issuer) |
| S06 | T1 actor reads another-Tenant document | 404, no evaluation | D (= L20B-07) |
| S07 | service credentials presented as end-user Bearer | 401 / verified-user-denied; never content | D |
| S08 | unknown but cryptographically verified subject | 403, no MTMF call | D |

Coverage cross-reference: user-trust actor forgery is already lower-level
covered by PR17 `F04`-style tests in `tests/integration/postgres/test_pr17_live_http.py`
(L). PR20B provides the deployed consumer-side black-box form.

### 4.4 Part E — snapshot exactness, expiry, revocation

| ID | Scenario | Type / existing test |
| --- | --- | --- |
| N01 | same context/action/resource/request id, live ALLOW → allow | L: `test_cl_u27_*` |
| N02 | actor/session/Tenant/application/Organization mismatch → deny | L: `test_cl_u31_*`, `test_cl_u32_*` |
| N03 | resource / Action / request id mismatch → deny | L: `test_cl_u33_*` + C if a gap |
| N04 | duplicate same action/resource without discriminator → deny | L: `test_cl_u29_*` |
| N05 | missing or DENY occurrence → deny | L: `test_cl_u28_*` |
| N06 | monotonic deadline exact boundary, backward clock → deny | L: `test_cl_u35_*`, `test_cl_u44_*` |
| N07 | snapshot from another client instance → deny | L: `test_cl_u30_*` |
| N08 | malformed/mismatched HTTP response → no snapshot | L: `test_client_transport.py`, plus C if a gap |
| N09 | live revoke Alice Role; next deployed GET → deny | D |
| N10 | restore Role; next deployed GET → allow | D |

### 4.5 Part F — deterministic remote faults

| ID | Injected condition | Expected | Type |
| --- | --- | --- | --- |
| F01 | TCP refused/closed | 503, no body | D |
| F02 | delayed beyond client timeout | 503, no body; no worker leak | D |
| F03 | HTTP 502/503 | 503, no body | D |
| F04 | 200 non-JSON / wrong content-type | 503, no body | D |
| F05 | 200 malformed JSON | 503, no body | D |
| F06 | 200 valid but mismatched Action/resource/request id / missing decision | 503, no body | D |
| F07 | healthy after reset | 200 Alice / 403 Bob | D |

Injection is via an acceptance-only fault fronting component that uses the
**same pinned TLS certificate** and is reachable only by the reference-app
container. Only the **remote network response** is substituted; the real
`HttpMtmfClient` and `DocumentReader` are used. No production MTMF, client, or
default-stack change.

### 4.6 Part G — concurrency

| Requirement | Type |
| --- | --- |
| 32 concurrent GETs (16 Alice / 16 Bob), exact 16×200 / 16×403 | D |
| no cross-user body disclosure, no 5xx, no mixed context | D |
| three independent waves, deterministic barrier | D |
| 16 simultaneous requests during a bounded slow MTMF fault; no content | D |
| `BoundedWorker` regression preserved | L: `tests/test_worker.py` |

### 4.7 Part H — parity, migrations, wire contract

| Gate / invariant | Type |
| --- | --- |
| Python/Rust complete-decision parity | L: `tests/unit/authorization/test_permission_evaluator_differential.py`, `test_compiled_policy_differential.py`, `test_rust_*`; run by `./build.sh --rust` |
| Frozen v1 request/response conformance | L: `tests/unit/api/*`, `packages/mtmf-api` suites |
| Ordered response binding | L: `tests/unit/client/*`, `tests/unit/api/*` |
| Real-PostgreSQL migration to head + privilege postflight | L: `./build.sh --integration` |
| Migration head unchanged (`0013`) | L |

## 5. P0 gate — mixed ALLOW/DENY in one verified user batch

**Question:** can the existing, approved policy model produce an ALLOW for one
occurrence and a DENY for another occurrence in a single batch evaluated for the
same verified actor, Tenant, and Application?

**Source inspection result — resource-instance policy is not a supported
mechanism.**

- `mtmf_core.authorization.compiled_policy.CompiledPolicy` indexes Permissions
  by `(namespace, resource, verb, qualifier)` (exact) and
  `(namespace, resource, verb)` (wildcard) of the **Action URN**. `evaluate`
  receives only the Action; the `ResourceTarget` is never an input to policy
  matching (`compiled_policy.py`).
- `mtmf_core.authorization.guards.target_is_permitted` uses the target only for
  the same-Tenant / resolved management-scope boundary, not to select a
  Permission (`guards.py`).
- `docs/AUTHORIZATION.md` §5 defines a Permission as an **Action matcher**
  (`<resource>:<verb>-<qualifier>`) with no resource-instance predicate.
  `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md` defines `ResourceTarget` as a
  binding the **PEP** enforces; the PDP's per-Action decision is policy-derived.

Consequently, for one `(actor, Action, Tenant)` tuple the decision is identical
for every loaded row. Two T1 documents D1/D3 read with
`document:read-object` by Alice are both ALLOW; both are DENY for Bob. The
plan's fallback ("two different existing Actions against the same loaded row")
would require registering a second fixture Action and a corresponding real
app-owned operation, which does not exist; inventing one is explicitly
forbidden by the plan and by `AGENTS.md`.

**Result: P0 STOP.** The mixed-batch deployed proof cannot be produced through
the existing approved contracts. It is recorded in
[`PR20B_STOP_REPORT.md`](PR20B_STOP_REPORT.md). It is **not** replaced by a
fabricated or weakened test, and PR 20B is **not** marked DONE.

## 6. Fixture transition helper contract

`scripts/pr20b_fixture_transitions.py` is a privileged, one-shot, test-only
helper. Contract:

- refuses any deployment profile other than `development`;
- connects only with `PostgresConfig.from_env(PostgresRole.MIGRATOR)`;
- verifies the connected database name is the isolated acceptance database
  before any mutation (`SELECT current_database()`);
- exposes exactly: `suspend-tenant`, `activate-tenant`, `unsubscribe`,
  `subscribe`, `revoke-role`, `grant-role`, `state`, each of which calls only
  the sanctioned functions in §2;
- prints only non-secret identifiers;
- is never imported by the reference app and holds no IdP I/O inside a DB
  transaction.

`scripts/pr20b-reference-acceptance.py` is the prescribed launcher and refuses
foreign projects, calls the PR20A preflight, owns only the
`mtmf-pr20a-acceptance` project, verifies the default `mtmf` inventory is
unchanged, and performs the cold/repeat/recreate cycles.
