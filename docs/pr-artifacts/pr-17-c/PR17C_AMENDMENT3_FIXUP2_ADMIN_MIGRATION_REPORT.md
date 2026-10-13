# PR 17-C Amendment 3 Fixup 2 — Admin Migration Report

## Canonical final state (verified)

| Account | Realm | Enabled | Federation | Required actions | Realm roles |
| --- | --- | --- | --- | --- | --- |
| `mtmf-admin` | `master` | **true** | none | none | `admin`, `default-roles-master` |
| `mtmf-pr14-admin` | `master` | **false** | none | none | (disabled) |
| `mtmf-pr14-admin2` | `master` | **false** | none | none | (disabled) |

Identity invariants verified after migration: realm `mtmf-pr14-dev` present,
development user `mtmf-dev-user` `sub`
`5d198663-d3a7-413b-a6fc-269910096799` unchanged, 18 realm clients including
`mtmf-sample-app` and `mtmf-attestation-reader`. No volume was deleted and no
existing account password was reset.

## Procedure (Steps 0–5)

1. **Read-only inspection** (`--inspect`, recovery `mtmf-pr14-admin2`):
   `mtmf-admin` absent; both legacy admins enabled with the `admin` master role.
2. **Recovery path verified** by a successful privileged read.
3. **Canonical account reconciled:** `mtmf-admin` did not exist, so it was
   created as an enabled, local (non-federated) master-realm user with a
   non-temporary password supplied from the operator credential store, and the
   `admin` master role was assigned.
4. **Independent verification:** a fresh `mtmf-admin` session authenticated and
   performed a privileged read of both `master` and `mtmf-pr14-dev`.
5. **Legacy admins disabled** (not deleted): `mtmf-pr14-admin` and
   `mtmf-pr14-admin2` were disabled with a read-after-write after each.
6. **Post-migration verification:** a fresh `mtmf-admin` login and privileged
   reads succeeded; `up`/`preflight`/`/health/ready` passed; the long-running
   service has no admin credential.

## Observed Keycloak behavior during the first `--apply`

The first `--apply` created `mtmf-admin` and disabled both legacy admins, but
the tool then exited non-zero with `GET admin request failed with HTTP 401`.
The cause is a Keycloak bootstrap behavior, not a tool defect in the mutation
path: the pre-existing recovery admin `mtmf-pr14-admin2` had been created with
Keycloak's **temporary bootstrap-admin** mechanism, and Keycloak retired it once
a permanent administrator existed. The recovery session therefore expired
mid-run after the mutations had completed.

Reconciliation was completed idempotently by re-running `--apply` with the
newly verified canonical administrator as the recovery identity:

```text
$ MTMF_DEV_KC_RECOVERY_USERNAME=mtmf-admin \
  MTMF_DEV_KC_RECOVERY_PASSWORD=<canonical credential> \
  python scripts/mtmf-dev-admin-migrate.py --apply
{ "created": false, "disabled": [], "canonical": { "enabled": true, ... } }
```

This run exited 0 and confirmed the required final state. The behavior is
recorded as a deviation/limitation in
`PR17C_AMENDMENT3_FIXUP2_STOP_DEVIATIONS.md`: an operator migrating an existing
volume whose only recovery admin is a temporary bootstrap account should expect
that account to be retired when the permanent admin is created; the canonical
admin must be verified before the recovery account disappears.

## Credential custody

The canonical `mtmf-admin` password is held in an owner-only file outside
ephemeral `/tmp` (`~/.config/mtmf/dev-admin.env`, mode `0600`, not committed).
This is a **development-only limitation**; the operator's source of truth must
be a password manager/approved secret store. No password, token, or client
secret appears in any committed report, log, or git object.

## Rollback

There is no password recovery for a disabled account. The operational rollback
for a failed migration is to re-enable a legacy administrator **only while an
independently verified administrator still works**; otherwise the operator must
recover via the documented Keycloak bootstrap path. No automated rollback is
provided.
