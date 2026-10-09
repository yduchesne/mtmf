"""CI workflow structure tests (CI-01..CI-03).

Static verification that the existing ``quality`` job is preserved and a
sibling disposable-PostgreSQL-18 ``integration`` job runs exactly
``./build.sh --integration`` without duplicating pytest arguments, without
Podman, and without ``MTMF_DATABASE_URL``. The live pass/fail status of both
jobs is observed on the PR (branch-protection requirements are a separate
GitHub ruleset setting, not something this workflow can assert).
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "quality.yml"


def _workflow() -> dict:
    with WORKFLOW.open() as handle:
        return yaml.safe_load(handle)


def test_ci01_quality_job_is_preserved() -> None:
    workflow = _workflow()
    assert workflow["name"] == "CI"
    triggers = workflow.get(True) or workflow.get("on") or {}
    assert "pull_request" in triggers
    quality = workflow["jobs"]["quality"]
    runs = [step.get("run", "") for step in quality["steps"] if isinstance(step, dict)]
    assert any("./build.sh --rust" in run for run in runs)
    assert any("./build.sh --qa" in run for run in runs)
    uses = " ".join(step.get("uses", "") for step in quality["steps"] if isinstance(step, dict))
    assert "dtolnay/rust-toolchain" in uses


def test_ci02_integration_job_runs_canonical_gate_on_postgres_18() -> None:
    jobs = _workflow()["jobs"]
    assert "integration" in jobs
    integration = jobs["integration"]
    service = integration["services"]["postgres"]
    assert str(service["image"]).endswith("postgres:18")
    runs = [step.get("run", "") for step in integration["steps"] if isinstance(step, dict)]
    assert any("./build.sh --integration" in run for run in runs)
    # build.sh owns the pytest invocation; CI must not duplicate it.
    assert not any("pytest" in run for run in runs)
    env = integration["env"]
    assert env["MTMF_POSTGRES_PORT"] == "5432"
    assert env["MTMF_POSTGRES_HOST"] == "127.0.0.1"
    assert "MTMF_DATABASE_URL" not in env
    # CI uses a disposable runner-local service, never Podman.
    assert not any("podman" in run.lower() for run in runs)


def test_ci03_integration_failures_fail_the_job() -> None:
    integration = _workflow()["jobs"]["integration"]
    for step in integration["steps"]:
        assert step.get("continue-on-error", False) is False
