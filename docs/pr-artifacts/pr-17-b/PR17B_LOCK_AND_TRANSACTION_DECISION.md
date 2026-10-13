# PR 17-B Lock and Transaction Decision Record

**Scope:** plan architectural invariant 6 and Step C1 ("do not hold a PostgreSQL transaction or MTMF
advisory lock across remote Keycloak I/O unless inspection proves an existing bounded lock contract
requires it").

**Decision:** Proceed without a blocking STOP. Place the **new** development-user Keycloak I/O outside the
advisory lock; retain the pre-existing bounded advisory lock for the existing bootstrap sequence. No
PostgreSQL transaction is held across remote Keycloak I/O.

## Findings from the actual code (base commit `b60c50b`)

- `PostgresProvisioner.acquire()` connects with `psycopg.connect(self._config.psycopg_dsn, autocommit=True)`,
  executes `SET ROLE mtmf_owner`, then `SELECT pg_advisory_lock(hashtextextended('mtmf.pr17.dev', 0))`.
  The connection is **autocommit**, so there is **no open PostgreSQL transaction** while the lock is held.
- `DevelopmentBootstrap.run()` acquires that session-level advisory lock and, inside it, performs the
  pre-existing `ensure_client` and `verify_issuer` Keycloak Admin REST calls. This is the accepted PR 17
  design and is what serializes concurrent initializers.
- The lock is bounded: it is released in a `finally` block when the run ends.

## Why this is not a blocking STOP

- The STOP condition is about **DB transactions** held across external I/O. The initializer holds no DB
  transaction across Keycloak calls (autocommit), so there is no long-running transaction, no held row
  locks, and no vacuum blockage.
- The advisory lock is an **existing, bounded lock contract** required for convergence: concurrent
  initializers must converge on one Keycloak account and one MTMF binding (plan Step C3). Removing or
  reordering it would change accepted PR 17 behavior.
- To avoid extending that contract, the **new PR 17-B remote user I/O is performed in `main()` before**
  `DevelopmentBootstrap.run()` acquires the lock. The new work therefore adds no advisory-lock duration
  across external calls.

## Resulting ordering

```
deployment-mode check
-> DevUserConfig.from_env()               # no I/O
-> issuer preflight (read)                # remote, no lock
-> Keycloak user create/verify            # remote, no lock, before MTMF writes
-> DevelopmentBootstrap.run()
   -> advisory lock acquire               # session-level, autocommit, no DB transaction
   -> migrations + postflight
   -> root/tenant/user binding            # verified subject
   -> ensure_client (remote) ...          # pre-existing PR 17 behavior
   -> verify_issuer (remote) ...          # pre-existing PR 17 behavior
   -> advisory lock release
```

Concurrency: two initializers may both reconcile the Keycloak user before the lock; Keycloak's unique
username constraint plus the bounded exact re-read make that idempotent, and the advisory lock still
serializes all MTMF writes.

## Evidence

- `scripts/mtmf-dev-initialize.py` (`PostgresProvisioner.acquire/release`, `main`).
- `packages/mtmf-service/src/mtmf_service/development_bootstrap.py` (`DevelopmentBootstrap.__init__/run`).
- Live I02 restart produced identical Keycloak `sub` and MTMF binding identity with no duplicates.

**Status:** resolved by scoping the new remote I/O outside the lock; no code change to the existing
lock/transaction contract and no database transaction is held across external I/O.
