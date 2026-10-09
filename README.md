# mtmf: Multitenant Management Framework

A Python package implementing an Identity and Access Management framework.

Current status: WIP.


Project documentation is under [docs/](docs/), including [database architecture and privileges](docs/DATABASE.md), [coding-agent instructions](AGENTS.md), and [benchmark methodology](docs/BENCHMARKS.md).

## Development

- Python **3.14** (managed by `uv`)
- `uv` is the package/workspace/dependency tool
- Rust toolchain for the native permission engine (installed by
  `./install.sh` via rustup, with the `clippy` and `rustfmt` components)

Bootstrap a clean checkout:

```bash
./install.sh   # idempotent: installs uv, uv-managed Python 3.14, and the Rust toolchain when missing
uv sync --locked
```

Run the canonical Python quality gate (Ruff format + lint, strict Mypy,
unit tests with a hard **>= 85%** coverage threshold):

```bash
./build.sh --qa
```

Run the security scans (Bandit + Semgrep):

```bash
./build.sh --sec
```

Run the deterministic Rust/native gate for the private permission-engine
crate (requires the Rust toolchain on `PATH`, installed by
`./install.sh`):

```bash
./build.sh --rust
```

The gate covers cargo fmt/clippy/test, `maturin develop`, the installed
native capability probe, focused FFI-boundary/differential/Authorizer
tests, a clean wheel build/install/use verification in an isolated
temporary environment, and a benchmark smoke check, with no
PostgreSQL/Podman/network dependency.

### PostgreSQL integration (PR 6+)

The MTMF-owned physical schema, migrations, and stored-function
infrastructure live under `mtmf_core/persistence/postgres`. Real-PostgreSQL
integration tests run against the explicitly configured MTMF database and
connect as three distinct identities (administrator, migrator, restricted
runtime):

```bash
cp .env.example .env        # MTMF_* development placeholders
set -a && . ./.env && set +a
uv run python scripts/mtmf-postgres.py up      # starts the MTMF `mtmf` Compose project (Podman, port 25432)
uv run python scripts/mtmf-provision-roles.py  # idempotent owner/migrator/runtime roles (admin credentials)
./build.sh --integration    # real-PostgreSQL migration/schema/constraint/privilege tests
uv run python scripts/mtmf-postgres.py down    # stops only MTMF resources
```

The administrator identity (`MTMF_POSTGRES_*` / `MTMF_DATABASE_URL`) only
provisions roles and inspects/seed data. Migrations run as `mtmf_migrator`
(`MTMF_MIGRATOR_*`) under a controlled `SET ROLE mtmf_owner`, and the
privilege tests connect as the restricted `mtmf_runtime`
(`MTMF_RUNTIME_*`). `scripts/mtmf-provision-roles.py --adopt-existing-schema`
is the one-time administrator handoff for a database whose `mtmf` objects
predate PR 7A. See [DATABASE.md](docs/DATABASE.md) for the privilege model.

All MTMF Podman/Compose operations are scoped to the canonical `mtmf`
project and never touch ATI or any other PostgreSQL running on the same
host; missing or ambiguous `MTMF_*` configuration fails closed.

The workspace contains four independently installable distributions
under `packages/`: `mtmf-api`, `mtmf-core`, `mtmf-client`, and
`mtmf-service`.
