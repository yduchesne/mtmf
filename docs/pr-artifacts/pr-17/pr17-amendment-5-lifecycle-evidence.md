# PR 17 — Amendment #5 host-network lifecycle evidence (SEC-02)

## 1. Ownership labels

The host-network service container is created with deterministic labels:

```
io.mtmf.owner=mtmf
io.mtmf.component=http-service
io.mtmf.deployment-mode=development
```

## 2. Unified, ownership-verified cleanup

`scripts/mtmf-dev-stack.py` now routes **both** `down()` and `down_volumes()`
through `_cleanup_host_network_service()` before any Compose teardown:

1. `podman inspect` the exact container name;
2. an inspect error indicating verified absence is an idempotent success;
3. any other inspect error aborts;
4. a present container whose ownership labels do not match exactly is a
   foreign/legacy resource and **aborts without removal**;
5. only a fully matching container is removed; a non-zero `podman rm` aborts;
6. `down` then runs Compose `down` (volumes retained); `down_volumes` runs
   `down -v` — and only reaches it if service cleanup succeeded.

No broad discovery, prefix wildcard, `podman system prune`, or cross-project
command is used. Compose teardown stays scoped to the explicit `mtmf` project.

## 3. Deterministic proof (U19–U23)

`tests/unit/service/test_dev_stack_lifecycle.py` (6 tests) drives a
`subprocess.run` spy and proves: owned service removed before Compose; `down`
preserves volumes while `down_volumes` passes `-v`; absent container is
idempotent; foreign/unlabeled container is never removed; inspect/rm failure
aborts and never reaches Compose destroy.

## 4. Executed

- A#4 V13 already executed an isolated disposable MTMF-only PostgreSQL
  create → destroy → recreate with before/after inventory and shared resources
  untouched.
- The host-network service container created during this amendment carried the
  ownership labels and was removed explicitly after inspection.

## 5. Residual

Legacy host-network containers created before labels existed are not guessed:
cleanup would abort and require a documented one-time operator migration. No
such container exists in the current environment.
