# mtmf: Multitenant Management Framework

A Python package implementing an Identity and Access Management framework.

Current status: WIP.


## Development

- Python **3.14** (managed by `uv`)
- `uv` is the package/workspace/dependency tool

Bootstrap a clean checkout:

```bash
./install.sh   # idempotent: installs uv + uv-managed Python 3.14 when missing
uv sync --locked
```

Run the canonical Python quality gate (Ruff format + lint, strict Mypy,
unit tests with a hard **>= 85%** coverage threshold):

```bash
./build.sh --qa
```

The workspace contains four independently installable distributions
under `packages/`: `mtmf-api`, `mtmf-core`, `mtmf-client`, and
`mtmf-service`.
