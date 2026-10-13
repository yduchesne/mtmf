# PR 17-C Amendment 3 Fixup 2 — Final Acceptance

## Delivered

`mtmf-admin` is the canonical development Keycloak master-realm administrator.
On the preserved development volume, `mtmf-admin` was created and independently
verified, and the PR-numbered legacy administrators `mtmf-pr14-admin` /
`mtmf-pr14-admin2` were **disabled (not deleted)**. Standard-stack configuration
and documentation now use `mtmf-admin`; the PR 14 evidence-only fixture is
unchanged; a development-only migration utility supports repeatable safe
execution.

## Final account state (CA-I05/CA-I14)

| Account | Enabled | Federation | Required actions | Realm roles |
| --- | --- | --- | --- | --- |
| `mtmf-admin` | true | none | none | `admin`, `default-roles-master` |
| `mtmf-pr14-admin` | false | — | — | (disabled) |
| `mtmf-pr14-admin2` | false | — | — | (disabled) |

Realm `mtmf-pr14-dev` present; development user `mtmf-dev-user` `sub`
`5d198663-d3a7-413b-a6fc-269910096799` unchanged; 18 clients including
`mtmf-sample-app` and `mtmf-attestation-reader`. No volume deleted, no realm
reset, no existing-account password reset.

## Authoritative gates (fixup tip)

| Gate | Result |
| --- | --- |
| `uv sync --locked` | PASS |
| `./build.sh --qa` | PASS — **2107 passed**, coverage **90.75%** |
| `./build.sh --sec` | PASS — Bandit Medium/High 0, Semgrep 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — **564 passed, 65 skipped** |
| PR 17-B live (`MTMF_PR17B_LIVE=1`) | **13 passed** (canonical `mtmf-admin`) |
| PR 14 live (`MTMF_PR14_LIVE=1`) | **22 passed** |
| PR 17 live (`MTMF_PR17_LIVE=1`) | **26 passed** |
| Forwarder reliability | **100/100** sequential (max 0.054 s) and **50/50** @10 (max 0.094 s); **30/30** direct control |

## Live verification (CA-I01–CA-I14)

- **CA-I01** read-only inspection captured the pre-migration state.
- **CA-I02** recovery admin authenticated and performed privileged reads.
- **CA-I03/I04** exactly one `mtmf-admin` created with the `admin` role and
  independently authenticated (fresh token, privileged reads).
- **CA-I05** both legacy admins disabled with read-after-write; `mtmf-admin`
  still enabled.
- **CA-I06** repeat `mtmf-admin` authentication after cleanup succeeded.
- **CA-I07** existing-volume `up` (exit 0), `preflight` (exit 0), and
  `/health/ready` **200**; realm/user `sub` unchanged.
- **CA-I08** isolated fresh-volume bootstrap (separate MTMF-owned
  `mtmf-fixup2-freshcheck` volume/project) created `mtmf-admin`, which
  authenticated; test resources removed; persistent volume untouched.
- **CA-I09** the service environment has no admin credential; no secret in any
  report, log, or git object.
- **CA-I10** PR 14 fixture unchanged; PR 14/17 live suites pass.
- **CA-I11** after the one expected Compose configuration transition (renamed
  bootstrap variables), three unchanged `up` cycles preserved all four
  container IDs/`StartedAt` with zero unexpected `stop`/`rm`.
- **CA-I12** negative TLS/issuer/wrong-credential cases fail closed (unit +
  launcher validation).
- **CA-I13** recovery-unavailable STOP proven with a controlled fake; the live
  working administrator was never disabled to test the failure path.
- **CA-I14** post-migration inventory correct, no identity drift.

## Configuration and docs

- `compose.dev.yaml`: Keycloak bootstrap uses
  `MTMF_DEV_KC_ADMIN_USERNAME` (default `mtmf-admin`) / `MTMF_DEV_KC_ADMIN_PASSWORD`;
  the initializer keeps `MTMF_AUTH_ADMIN_USERNAME/PASSWORD` mapped to the same
  canonical account; the unused `MTMF_PR14_KC_ADMIN_*` pair was removed from the
  standard-stack initializer.
- `scripts/mtmf-dev-stack.py`: pre-side-effect `_require_canonical_dev_admin()`
  validation for `up` and `up-host-network`.
- `.env.example` and `docs/DEVELOPMENT_SETUP.md`: canonical-admin section with
  fresh-vs-existing volume, verification, custody, rollback, and STOP guidance.
- `scripts/mtmf-dev-admin-migrate.py`: development-only `--inspect`/`--apply`
  migration with the Step 0–5 state machine.
- New deterministic tests: CA-U01–CA-U32 (`test_pr17c_dev_stack.py`,
  `test_pr17c_dev_admin_migrate.py`).

## Disposition

PARTIAL only in the sense that PR 17-C as a whole still awaits human review and
Windows N17/N18 smoke tests remain optional/manual. The Fixup 2 objective is
complete and evidenced: `mtmf-admin` is canonical and operational, legacy
administrators are disabled (not deleted), no identity drifted, and all
mandatory gates pass. **PR 17-C remains AWAITING HUMAN REVIEW — NOT DONE.**
