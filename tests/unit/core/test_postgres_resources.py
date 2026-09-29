"""Unit tests for packaged migration/SQL resource discovery.

Migration tooling must work from packaged resources without a repository
working directory; these tests prove the packaged layout resolves for
the current source tree (the same resolution is used from an installed
wheel).
"""

from __future__ import annotations

from mtmf_core.persistence.postgres import (
    MigrationResourceError,
    migrations_script_directory,
    sql_version_files,
)


def test_migrations_script_directory_resolves() -> None:
    directory = migrations_script_directory()
    assert directory.is_dir()
    assert (directory / "env.py").is_file()
    assert (directory / "script.py.mako").is_file()
    assert (directory / "versions").is_dir()


def test_sql_version_files_are_sorted_and_complete() -> None:
    files = sql_version_files("v001")
    assert [path.name for path in files] == [
        "01_schema_version_proof.sql",
        "02_membership_precondition_functions.sql",
        "03_membership_precondition_triggers.sql",
        "04_immutability_triggers.sql",
    ]
    for path in files:
        assert path.is_file()


def test_unknown_sql_version_raises() -> None:
    import pytest

    with pytest.raises(MigrationResourceError):
        sql_version_files("v999")
