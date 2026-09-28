# mtmf
Multitenant Management Framework

## Development

- Python **3.14** (managed by `uv`)
- `uv` is the package/workspace/dependency tool

Bootstrap a clean checkout:

```bash
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