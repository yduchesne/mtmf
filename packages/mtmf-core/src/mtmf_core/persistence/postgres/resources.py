"""Packaged MTMF migration and versioned-SQL resource discovery.

MTMF migrations and versioned SQL files ship inside ``mtmf-core`` so
that migration tooling never assumes a repository working directory.
Resource paths resolve through :mod:`importlib.resources` against the
``mtmf_core.persistence.postgres`` package, which works both in the
source workspace and from an installed wheel.
"""

from __future__ import annotations

# MTMF requires Python >= 3.14 (pyproject.toml), so the stdlib
# ``importlib.resources`` API is fully available; the Python-3.7
# compatibility backport rule does not apply to this codebase.
# nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from importlib import (
    resources,
)
from pathlib import Path

_MIGRATIONS_PACKAGE = "mtmf_core.persistence.postgres.migrations"
_SQL_PACKAGE = "mtmf_core.persistence.postgres.sql"


class MigrationResourceError(RuntimeError):
    """A packaged migration/SQL resource could not be resolved."""


def _resource_directory(package: str) -> Path:
    try:
        traversable = resources.files(package)
    except (ModuleNotFoundError, ValueError) as exc:
        raise MigrationResourceError(
            f"packaged resource package {package!r} is not available"
        ) from exc
    path = Path(str(traversable))
    if not path.is_dir():
        raise MigrationResourceError(
            f"packaged resource directory {package!r} resolved to {str(path)!r}, "
            "which is not a directory"
        )
    return path


def migrations_script_directory() -> Path:
    """Return the packaged Alembic script directory (env.py + versions/)."""
    return _resource_directory(_MIGRATIONS_PACKAGE)


def sql_version_files(version: str) -> tuple[Path, ...]:
    """Return the packaged ``.sql`` files of one SQL version, sorted.

    Versions are lexicographically ordered directory names such as
    ``v001``. Files within a version run in sorted filename order; the
    numbering prefix (``01_``, ``02_``, ...) expresses dependency order.
    """
    package = f"{_SQL_PACKAGE}.{version}"
    directory = _resource_directory(package)
    files = tuple(sorted(path for path in directory.iterdir() if path.suffix == ".sql"))
    if not files:
        raise MigrationResourceError(f"SQL version {version!r} contains no .sql files")
    return files
