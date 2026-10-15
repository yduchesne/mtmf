# mtmf: Multitenant Management Framework

Release tags, Python package versions, and HTTP API compatibility are governed by [VERSIONING.md](VERSIONING.md).

A Python package implementing an Identity and Access Management framework.

<p align="center">
  <img src="docs/img/MtmfLogo-384x384.png"
       alt="MTMF"
       width="384">
</p>

Current status: WIP.


For a plain-language explanation of local Keycloak → MTMF → application startup, see the [development setup guide](docs/DEVELOPMENT_SETUP.md) (including the PR 17-B development-user provisioning step).

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

### Opt-in observability stack (PR 19)

The MTMF-owned OpenTelemetry Collector → Prometheus/Jaeger/Loki → Grafana
stack is an opt-in overlay and is not started by normal development
startup:

```bash
MTMF_GRAFANA_ADMIN_PASSWORD=<dev-only> python scripts/mtmf-observability.py up
MTMF_GRAFANA_ADMIN_PASSWORD=<dev-only> python scripts/mtmf-observability.py status
python scripts/mtmf-observability.py down   # removes only the observability services
```

Grafana is published at `127.0.0.1:23000`, Prometheus at `127.0.0.1:29090`,
Jaeger UI at `127.0.0.1:21686`, and the optional Collector OTLP gRPC
endpoint at `127.0.0.1:24317`; Loki is internal-only. Enable service export
with `MTMF_OTEL_ENABLED=true` and
`MTMF_OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317`. See
[docs/DEVELOPMENT_SETUP.md](docs/DEVELOPMENT_SETUP.md) and the
[audit and observability architecture](docs/AUDIT_OBSERVABILITY_ARCHITECTURE.md).

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
uv run python scripts/mtmf-provision-roles.py --verify  # post-migration effective-privilege verification
uv run python scripts/mtmf-postgres.py down    # stops only MTMF resources
```

The administrator identity (`MTMF_POSTGRES_*` / `MTMF_DATABASE_URL`) only
provisions roles, performs the ownership handoff, and runs verification.
Migrations run as `mtmf_migrator` (`MTMF_MIGRATOR_*`); the manager verifies
the authenticated login is a non-elevated `mtmf_migrator` on every
migration connection before assuming `SET ROLE mtmf_owner`, and rejects an
administrator- or runtime-labelled configuration. A successful
`upgrade_to_head()` means Alembic reached head **and** the mandatory
effective runtime privilege verifier passed on a fresh migrator session;
a postflight failure raises `MigrationError` (migrations may already be
committed) and must stop the deployment. The privilege tests connect as the
restricted `mtmf_runtime` (`MTMF_RUNTIME_*`).
`scripts/mtmf-provision-roles.py --adopt-existing-schema` is the one-time
administrator handoff for a database whose `mtmf` objects predate PR 7A;
`--verify` is an additional read-only diagnostic for later audits/CI after
migration. In production, a runtime process receives **only**
`MTMF_RUNTIME_*`. See [DATABASE.md](docs/DATABASE.md) for the privilege model.

All MTMF Podman/Compose operations are scoped to the canonical `mtmf`
project and never touch ATI or any other PostgreSQL running on the same
host; missing or ambiguous `MTMF_*` configuration fails closed.

The workspace contains four independently installable distributions
under `packages/`: `mtmf-api`, `mtmf-core`, `mtmf-client`, and
`mtmf-service`.
