# PR 18 — Final Acceptance

> **Superseded in part by Acceptance Fixup 1.** That fixup makes an exact
> `Action` and `ResourceTarget` mandatory in `is_allowed`/`require` and adds
> the owned-Uvicorn restart acceptance (CL-I16). See
> [PR18_FIXUP1_FINAL_ACCEPTANCE.md](PR18_FIXUP1_FINAL_ACCEPTANCE.md); this
> report is retained as PR 18 implementation history.

**Status:** **READY FOR HUMAN REVIEW — NOT DONE.** No unresolved mandatory
STOP condition. All canonical gates pass on the implementation tip; CL-I16
was not executed and is recorded as NOT TESTED.

## 1. Canonical gate table

| Gate | Command | Result |
| --- | --- | --- |
| Workspace bootstrap | `uv sync --locked` | PASS (107 packages resolved; `mtmf-client` built/installed) |
| Quality | `./build.sh --qa` | PASS — Ruff format, Ruff lint, strict Mypy, **2275 passed**, coverage **91.34%** (gate ≥85%) |
| Security | `./build.sh --sec` | PASS — Bandit 0 Medium/0 High; Semgrep 297 rules / 197 targets / 0 findings; exit 0 |
| Rust/native | `./build.sh --rust` | PASS — cargo fmt/clippy/test, `maturin develop`, installed-native probe (`engine_version=0.1.0`), focused boundary/differential tests, clean wheel verification, benchmark smoke |
| PostgreSQL integration | `./build.sh --integration` | PASS — **564 passed, 80 skipped** (includes the opt-in PR18/PR17 live modules, skipped) |
| PR 18 real live slice | `MTMF_PR18_LIVE=1 pytest tests/integration/postgres/test_pr18_live_client.py` | PASS — **15 passed** on three consecutive clean runs (retries = 0) |

Baseline for comparison (pre-implementation): 2153 passed, coverage 90.75%.
The suite grew by the 122 parametrized `tests/unit/client` cases (74 test
functions). All gates above were re-run on the committed implementation tip
(`afa568b3edb2fa6c09312a28a621e33be9b4b59b`).

## 2. Objective acceptance criteria (plan §16)

1. **Wheel imports without core/service/DB/Rust; HTTP-only tree.** PASS
   (`test_cl_u01_*`).
2. **Real Keycloak Client Credentials + separately acquired user token via
   the real PR 17 HTTPS endpoint.** PASS (CL-I01/I02/I03).
3. **Frozen v1 DTO/error contracts strictly enforced; no partial snapshot.**
   PASS (CL-U17–CL-U23, CL-U41; CL-I18).
4. **All applicable CL-U cases and CL-I01–CL-I18 evidence.** CL-U01–CL-U23,
   CL-U25, CL-U27–CL-U45 PASS; CL-U24 and CL-U26 documented **NOT
   APPLICABLE — deferred by contract** (no unsafe retry exists); CL-I01–CL-I15,
   CL-I17, CL-I18 PASS; **CL-I16 NOT TESTED** (environment limitation,
   documented).
5. **Monotonic expiry, 15 s sensitive TTL, replay negatives.** PASS
   (CL-U30–CL-U37, CL-U44).
6. **Bounded, safe, independent token renewal; no refresh token.** PASS
   (CL-U05–CL-U13, CL-U38, CL-U43; CL-I11).
7. **Three first-attempt live vertical-slice runs and the renewal loop.**
   PASS (three runs of 15/15; 20-iteration forced-renewal loop).
8. **Canonical `--qa`/`--sec`/`--rust`/`--integration`, coverage ≥85%.**
   PASS (coverage 91.34%).
9. **All mandatory reports committed under `docs/pr-artifacts/pr-18/`; no
   hidden failures.** PASS (this report set).
10. **No PR19/PR20 scope, API/schema change, destructive reset, or security
    weakening.** PASS (no `mtmf-api`/`mtmf-service`/SQL/Alembic/Rust changes;
    no destructive Podman reset).

## 3. Reviewer checklist (plan §15)

- [x] `mtmf-client` is HTTP-only and independently installable.
- [x] Real v1 headers, DTOs, strict codec and conformance reused; no second
      wire contract.
- [x] Service Client Credentials and independently supplied user token are
      separate.
- [x] Token manager never uses a refresh token; renewal bounded,
      concurrency-safe, secret-redacted.
- [x] HTTPS trust verified; no redirects carrying credentials; no insecure
      fallback.
- [x] Service-token renewal never extends a snapshot.
- [x] Snapshot binds exact authenticated context / Application / Tenant /
      Org / resource / action occurrence.
- [x] Conservative monotonic deadline, 15 s sensitive safety, 300 s absolute
      cap.
- [x] Missing/ambiguous/expired/mismatched/invalid decisions deny;
      `require` raises.
- [x] PEP independently checks its own resource/Tenant isolation; no
      capability-to-object broadening.
- [x] Failures preserve typed operational errors; no partial snapshot.
- [x] No unauthorized changes to API, service, core, persistence, Podman
      resources, or the PR 14 fixture.
- [x] CL-U and CL-I matrices executed and documented.
- [x] Canonical gates pass on the final tip; coverage ≥85%.
- [x] Reports committed under `docs/pr-artifacts/pr-18/`, no secrets.

## 4. Outstanding decisions for human review

1. **Optional 401 retry** remains deferred until PR 17 exposes a
   machine-readable service-token-expiry signal (deviation 1).
2. **15-second universal snapshot cap** remains until an authoritative,
   approved Action sensitivity contract is exposed to clients (deviation 2).
3. **CL-I16** (service/Keycloak restart) was not executed (deviation 4).

## 5. PR 18 is not DONE

Per the plan, PR 18 may not be marked `[DONE]` until human review and merge
approval. The roadmap records it as **IMPLEMENTED; READY FOR HUMAN REVIEW**.
