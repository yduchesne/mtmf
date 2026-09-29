#!/usr/bin/env bash
#
# Canonical MTMF quality gates.
#
# Usage:
#   ./build.sh --qa
#   ./build.sh --sec
#   ./build.sh --rust
#   ./build.sh --integration
#
# Every gate runs project tools through `uv run --no-sync`: the gates execute
# against the already-bootstrapped uv environment (`uv sync --locked`) and
# must never let uv mutate that environment mid-gate. In particular the
# private native module (`mtmf-permission-engine`) and the workspace
# distributions are not part of the uv dependency graph, so an implicit
# `uv run` auto-sync can silently uninstall them or swap in a stale
# version-keyed cache wheel; `--no-sync` keeps gate execution deterministic.
#
# --qa runs the default quality gate, in order and failing fast:
#   1. Ruff formatting check
#   2. Ruff lint
#   3. strict Mypy
#   4. unit tests with a hard >= 85% coverage gate
#
# --sec runs the security scan, in order and failing fast:
#   1. Bandit (Python security linter) over packages/ and tests/
#   2. Semgrep (static analysis) over packages/ and tests/
#
# --rust runs the deterministic Rust/native gate for the private
#   mtmf-permission-engine crate, in order and failing fast:
#   1. cargo fmt --check
#   2. cargo clippy --all-targets --all-features -- -D warnings
#   3. cargo test
#   4. maturin develop (native build + development install)
#   5. installed-native capability probe (fails fast on a stale/clobbered
#      install, e.g. one silently swapped by a uv environment sync)
#   6. focused Python native-boundary, domain-conversion, differential,
#      boundary-hardening, stress, and Authorizer-cutover tests
#   7. clean wheel build/install/import/use verification in an isolated
#      temporary environment
#   8. benchmark smoke verification (native availability, fixture
#      construction, Python/Rust parity, timing-loop and output-
#      formatting checks with tiny counts; no timing threshold)
#   The Rust gate never uses Podman, PostgreSQL, MTMF_POSTGRES_*,
#   --integration resources, network services, or external credentials.
#
# --integration runs the real-PostgreSQL migration/schema/constraint
#   integration suite against the explicitly configured MTMF database
#   (MTMF_* variables). Start it first with:
#       uv run python scripts/mtmf-postgres.py up
#   The integration suite never runs as part of --qa; it fails closed
#   when MTMF database configuration is missing or ambiguous.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

MODE="${1:-}"

case "${MODE}" in
    --qa)
        echo "==> Running formatting check with ruff (format --check)"
        uv run --no-sync ruff format --check .

        echo "==> Running lint with ruff (ruff check)"
        uv run --no-sync ruff check .

        echo "==> Running static analysis with mypy (strict mode)"
        uv run --no-sync mypy packages

        echo "==> Running unit tests with pytest (coverage gate >= 85%)"
        uv run --no-sync pytest tests/unit
        ;;
    --sec)
        echo "==> Running security lint with bandit (Medium/High severity gate)"
        # The default Low threshold reports test-only noise (e.g. B101
        # asserts in tests); fail on Medium/High findings instead.
        uv run --no-sync bandit -r packages tests -ll

        echo "==> Running static analysis with semgrep (registry rules)"
        uv run --no-sync semgrep scan --config=auto packages tests
        ;;
    --rust)
        RUST_CRATE_DIR="${SCRIPT_DIR}/packages/mtmf-permission-engine"

        if ! command -v cargo >/dev/null 2>&1; then
            echo "ERROR: --rust requires the Rust toolchain (cargo) on PATH." >&2
            echo "       Install it with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
            exit 1
        fi

        # Pin the interpreter used by PyO3/maturin to the canonical
        # uv-managed venv so builds are deterministic regardless of the
        # ambient PATH.
        PYO3_PYTHON="$(uv run --no-sync python -c 'import sys; print(sys.executable)')"
        export PYO3_PYTHON

        echo "==> Running Rust formatting check (cargo fmt --check)"
        (cd "${RUST_CRATE_DIR}" && cargo fmt --check)

        echo "==> Running Clippy with warnings denied (cargo clippy -- -D warnings)"
        (cd "${RUST_CRATE_DIR}" && cargo clippy --all-targets --all-features -- -D warnings)

        echo "==> Running native tests (cargo test)"
        (cd "${RUST_CRATE_DIR}" && cargo test)

        echo "==> Building and installing the private native module (maturin develop)"
        uv run --no-sync maturin develop --manifest-path "${RUST_CRATE_DIR}/Cargo.toml"

        echo "==> Verifying the installed native module exposes the primitive capability surface"
        "${PYO3_PYTHON}" - <<'PY'
import _mtmf_permission_engine as native

required = ("engine_version", "match_permission", "evaluate")
missing = [name for name in required if not callable(getattr(native, name, None))]
if missing:
    raise SystemExit(
        f"installed native module {native.__file__} is stale or clobbered: "
        f"missing {missing}; re-run the canonical --rust gate so maturin develop "
        "reinstalls the freshly built module"
    )

version = native.engine_version()
if not isinstance(version, str) or not version:
    raise SystemExit(f"invalid engine_version response: {version!r}")
print(f"native module OK (engine_version={version!r})")
PY

        echo "==> Running focused Python native-boundary tests"
        # Focused on the primitive boundary, the matcher parity matrix, the
        # evaluator contract, the RustPermissionEvaluator
        # domain-conversion/mapping tests, the hand-authored and generated
        # Python/Rust differential suite (including bounded stress
        # conformance), the boundary-hardening suite (malformed/incoherent
        # FFI states), and the Authorizer cutover/fail-closed tests; the
        # full coverage gate stays with --qa.
        uv run --no-sync pytest \
            tests/unit/authorization/test_rust_engine.py \
            tests/unit/authorization/test_rust_matcher.py \
            tests/unit/authorization/test_rust_evaluator.py \
            tests/unit/authorization/test_rust_permission_evaluator.py \
            tests/unit/authorization/test_permission_evaluator_differential.py \
            tests/unit/authorization/test_rust_boundary_hardening.py \
            tests/unit/authorization/test_authorizer_rust.py \
            --no-cov

        echo "==> Verifying a clean wheel build/install/import/use (isolated environment)"
        uv run --no-sync python scripts/verify-rust-wheel.py --interpreter "${PYO3_PYTHON}"

        echo "==> Running benchmark smoke verification (no timing threshold)"
        uv run --no-sync python benchmarks/permission_evaluator_benchmark.py --smoke
        ;;
    --integration)
        echo "==> Running PostgreSQL integration tests (MTMF-owned database only)"
        echo "    Requires the MTMF PostgreSQL service; start it with:"
        echo "        uv run python scripts/mtmf-postgres.py up"
        echo "    Tests FAIL CLOSED when MTMF_* database configuration is missing."
        uv run --no-sync pytest tests/integration/postgres --no-cov
        ;;
    *)
        echo "usage: $0 --qa | --sec | --rust | --integration" >&2
        exit 2
        ;;
esac