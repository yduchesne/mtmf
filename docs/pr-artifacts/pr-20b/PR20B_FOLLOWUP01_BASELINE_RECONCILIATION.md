# PR20B_FOLLOWUP01_BASELINE_RECONCILIATION

**PR:** roadmap PR 20B — Follow-up 01: genuine mixed-action conformance,
deployed faults, and spoofing closure.
**Artifact directory:** `docs/pr-artifacts/pr-20b/`
**Branch:** `dev/pr20b-conformance` (continued; not rebased or replaced).

## 1. Fresh reconciliation (executed)

| Item | Value |
| --- | --- |
| `git rev-parse HEAD` at start | `a13ededd8aa04ea210d1aca0e5e8454a99492ff1` |
| `git rev-parse origin/main` | `c7c992a372bb83bae3837efb04b1f19742bb83e2` |
| `git merge-base HEAD origin/main` | `c7c992a372bb83bae3837efb04b1f19742bb83e2` |
| Working tree | clean |
| Original PR 20B base | `c7c992a372bb83bae3837efb04b1f19742bb83e2` |
| Initial PR 20B implementation commit (tested) | `61649b4969eb882501920a506584f2bba581d125` |
| PR 20B evidence commit | `a13ededd8aa04ea210d1aca0e5e8454a99492ff1` |
| Alembic head | `0013_security_mutation_audit_partitioning` |
| Python (uv env) | 3.14.7 |
| PostgreSQL (acceptance) | 18.6 (`docker.io/library/postgres:18`) |
| Keycloak | `quay.io/keycloak/keycloak:26.8.0-1` |

No material divergence from the inspected contracts was found. `main` has not
moved since the original PR 20B base; the branch contains exactly the two
prior PR 20B commits on top of the merge base.

## 2. Owner-approved design decision

The previous P0 STOP is resolved by an **approved genuine second application
operation**: a metadata-only Document read with its own Action and Permission.
MTMF's Action-based policy model is retained unchanged:

```text
METADATA_ACTION     = urn:mtmf:iam:actions:system:document:read-metadata
METADATA_PERMISSION = urn:mtmf:iam:permissions:system:document:read-metadata
```

A TENANT-defined metadata-reader Role is granted to both Alice and Bob. Alice
also retains the existing content-reader Role; Bob never receives it. This
yields a genuine same-actor, same-document mixed ALLOW/DENY in **one** batch
(`read-metadata` ALLOW, `read-object` DENY for Bob).

## 3. Verified anchors re-checked on the branch

| Anchor | State |
| --- | --- |
| `POST /v1/documents/batch-read` | present, unchanged |
| `GET /v1/documents/{id}` | present, unchanged |
| `BoundedWorker` capacity lifetime | preserved (PR 20A fixup 01) |
| `mtmf.action_add(text)`, `mtmf.role_add(jsonb)`, `mtmf.identity_role_assignment_add(uuid,uuid,uuid,text,uuid)` | verified in source |
| `scripts/pr20b_fixture_transitions.py` | sanctioned stored functions, migrator identity, DB identity check |
| `scripts/pr20b-fault-proxy.py` | component present (not deployed-verified) |
| `compose.pr20a-acceptance.yaml` | canonical; `service-tls-proxy` owns alias `mtmf.mtmf.test` |
| Realm fixture users | `mtmf-user-alice`, `mtmf-user-bob`, `mtmf-user-carol`, `mtmf-root-admin` (`dev/keycloak/setup-realm.py`) |
| Fixture mapping subjects | Alice + Bob only (carol unmapped → suitable for S08) |

## 4. Reconciliation conclusion

The branch matches the plan's inspected contracts. No STOP at Phase 0.
Implementation continues on `dev/pr20b-conformance`.
