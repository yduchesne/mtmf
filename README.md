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
integration tests run against the explicitly configured MTMF database:

```bash
cp .env.example .env        # MTMF_* development placeholders
uv run python scripts/mtmf-postgres.py up      # starts the MTMF `mtmf` Compose project (Podman, port 55432)
./build.sh --integration    # real-PostgreSQL migration/schema/constraint tests
uv run python scripts/mtmf-postgres.py down    # stops only MTMF resources
```

All MTMF Podman/Compose operations are scoped to the canonical `mtmf`
project and never touch ATI or any other PostgreSQL running on the same
host; missing or ambiguous `MTMF_*` configuration fails closed.

The workspace contains four independently installable distributions
under `packages/`: `mtmf-api`, `mtmf-core`, `mtmf-client`, and
`mtmf-service`.
