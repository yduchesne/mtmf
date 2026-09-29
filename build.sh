#!/usr/bin/env bash
#
# Canonical MTMF Python quality gate.
#
# Usage:
#   ./build.sh --qa
#   ./build.sh --sec
#   ./build.sh --integration
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
        uv run ruff format --check .

        echo "==> Running lint with ruff (ruff check)"
        uv run ruff check .

        echo "==> Running static analysis with mypy (strict mode)"
        uv run mypy packages

        echo "==> Running unit tests with pytest (coverage gate >= 85%)"
        uv run pytest tests/unit
        ;;
    --sec)
        echo "==> Running security lint with bandit (Medium/High severity gate)"
        # The default Low threshold reports test-only noise (e.g. B101
        # asserts in tests); fail on Medium/High findings instead.
        uv run bandit -r packages tests -ll

        echo "==> Running static analysis with semgrep (registry rules)"
        uv run semgrep scan --config=auto packages tests
        ;;
    --integration)
        echo "==> Running PostgreSQL integration tests (MTMF-owned database only)"
        echo "    Requires the MTMF PostgreSQL service; start it with:"
        echo "        uv run python scripts/mtmf-postgres.py up"
        echo "    Tests FAIL CLOSED when MTMF_* database configuration is missing."
        uv run pytest tests/integration/postgres --no-cov
        ;;
    *)
        echo "usage: $0 --qa | --sec | --integration" >&2
        exit 2
        ;;
esac