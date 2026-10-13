# PR 17-B Creation-Provenance Baseline

**PR:** PR 17-B — Strict Keycloak created-resource provenance follow-up
**`origin/main`:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Target branch tip:** `f84cadd371a3f889fe79fd98464908b3a88b4225`
(`origin/dev/pr17b-keycloak-user-provisioning` also points here)
**Reviewed code tip:** `6471e392d4b2f0ecc617ced9c70e33ef10c489ba`
**Merge base:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`
**Working tree:** clean; no rebase or unrelated change.

## 1. Reconciliation

The in-progress PR 17-B implementation (including
`packages/mtmf-service/src/mtmf_service/development_user.py`) exists on the
branch, not on `main`. No file on the branch differs materially from the
reviewed commit.

## 2. Capability classification

| Capability | Status |
| --- | --- |
| `emailVerified=false` for new users | DONE + VERIFIED (`test_create_includes_email_verification`, live SH16) |
| Descriptor-based password read (`O_NOFOLLOW`/same `fstat`) | DONE + VERIFIED (SH13) |
| Test-only failpoint isolation | DONE + VERIFIED (SH15; absent from `compose.dev.yaml`) |
| Typed create outcomes (`_CreateOutcome`) | DONE + VERIFIED (SH04–SH11) |
| Existing-account read-only reuse | DONE + VERIFIED (SH02/SH14) |
| Conflict/indeterminate explicit-subject correlation | DONE + VERIFIED (SH07–SH09, I15) |
| I01–I20 live acceptance | DONE + VERIFIED (61-test live run) |
| **Successful-create `Location` provenance** | **PARTIAL / NOT VERIFIED — this amendment** |

## 3. Defect (confirmed in source at `f84cadd`)

`KeycloakDevUserProvisioner.ensure_user`, `CREATED` branch:

```python
created_subject = _created_subject(location)
if created_subject is not None and created_subject != verified.subject:
    raise BootstrapError(...)
```

and `_created_subject`:

```python
if not location:
    return None
candidate = urllib.parse.urlparse(location).path.rstrip("/").rsplit("/", 1)[-1]
return candidate or None
```

Consequences:

1. A successful `POST` with a **missing/blank/malformed** `Location` yields
   `created_subject is None`, so the guard is skipped and the username-matching
   account is bound — a fail-open bypass of the `CREATED` provenance invariant.
2. `_created_subject` accepts the last path segment of arbitrary URLs and does
   not require the `/admin/realms/<realm>/users/<id>` resource path or the
   trusted Keycloak origin.

## 4. Real Keycloak Location shape (prior verified evidence)

Probed against `quay.io/keycloak/keycloak:26.8.0-1`, realm `mtmf-pr14-dev`:

- `POST /admin/realms/{realm}/users` → `201` with
  `Location: https://<admin-origin>/admin/realms/<realm>/users/<id>`, whose final
  segment equals the created immutable `id`.
- Duplicate username → `409`; invalid body → `400`.

The transport is HTTPS (`MTMF_AUTH_ADMIN_BASE`, e.g. `https://127.0.0.1:28443`),
and `KeycloakDevUserProvisioner` currently receives only `transport` and `realm`,
not the admin origin.

## 5. Scope of this amendment

In: strict `Location` grammar + trusted-origin validation, mandatory fail-closed
enforcement on the `CREATED` branch, deterministic PV01–PV20 tests, a real-Keycloak
header fault wedge, docs and reports.

Out (unchanged): existing-user reuse, 409/indeterminate policy, `MTMF_DEV_USER_SUBJECT`
assertion, email verification, password-file handling, failpoint, OAuth flows,
realm/client policy, issuer hostname/networking, schema/API, ATI.
