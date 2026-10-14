#!/usr/bin/env python3
"""PR 20B isolated deployed conformance orchestrator.

This is the prescribed launcher for PR 20B. It **reuses** the canonical PR 20A
topology creator (`scripts/pr20a-reference-acceptance.py`) rather than
duplicating it: the same isolated ``mtmf-pr20a-acceptance`` Compose project,
real PostgreSQL 18, Keycloak 26.8, restricted MTMF service, internal TLS
terminator, and independent reference app.

It adds only:

- a PR 20B fixture document seed (one extra T1 document) through the existing
  reference-app fixture loader;
- execution of the PR 20B black-box conformance suite
  (``tests/e2e/reference_app/test_pr20b_live_conformance.py``) in addition to
  the PR 20A L01-L05 regression;
- the required cold / repeat / recreate cycles and a default-stack inventory
  check.

Subcommands::

    preflight    delegate to the PR 20A read-only preflight
    up           PR 20A up + PR 20B fixture seed
    test         PR 20A L01-L05 + PR 20B conformance
    down         stop the acceptance project
    recreate     destructive acceptance-only recreate
    acceptance   cold -> PR20A+PR20B -> repeat -> recreate -> PR20A+PR20B

No secret is printed or placed on a command line.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

#: The PR 20B extra fixture document. Deterministic and non-secret.
PR20B_BATCH_DOCUMENT_ID = "d0c0a1e0-0004-4000-8000-000000000004"
PR20B_BATCH_TITLE = "Batch Reference Document"
PR20B_BATCH_BODY = "reference-app-batch-body-v1"

PR20B_LIVE_TEST = "tests/e2e/reference_app/test_pr20b_live_conformance.py"


def _load_base() -> Any:
    """Load the canonical PR 20A orchestrator as the topology creator."""
    spec = importlib.util.spec_from_file_location(
        "pr20b_pr20a_acceptance", _SCRIPTS / "pr20a-reference-acceptance.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("the PR 20A acceptance orchestrator could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr20b_pr20a_acceptance"] = module
    spec.loader.exec_module(module)
    return module


base = _load_base()


class Pr20bAcceptanceError(RuntimeError):
    """A bounded PR 20B acceptance failure; never contains a secret."""


def preflight() -> int:
    """Delegate to the PR 20A read-only preflight."""
    return int(base.preflight())


def _seed_batch_document(env: dict[str, str]) -> None:
    """Seed the PR 20B extra T1 document through the existing fixture loader."""
    mapping_path = base.ACCEPTANCE_FIXTURE_DIR / "reference-app-fixture.json"
    if not mapping_path.is_file():
        raise Pr20bAcceptanceError("the reference-app fixture mapping was not generated")
    tenant_id = str(json.loads(mapping_path.read_text(encoding="utf-8"))["tenant_id"])
    manifest = {
        "documents": [
            {
                "document_id": PR20B_BATCH_DOCUMENT_ID,
                "tenant_id": tenant_id,
                "title": PR20B_BATCH_TITLE,
                "body": PR20B_BATCH_BODY,
            }
        ]
    }
    manifest_path = base.ACCEPTANCE_FIXTURE_DIR / "pr20b-documents.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    container = base._reference_app_container()
    result = subprocess.run(
        [
            "podman",
            "exec",
            container,
            "python",
            "-m",
            "mtmf_reference_app.fixture_loader",
            "--manifest",
            "/run/fixtures/pr20b-documents.json",
            "--sqlite",
            "/data/reference-app.db",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = base._redact((result.stderr or result.stdout).strip())
        raise Pr20bAcceptanceError(f"the PR 20B fixture seed failed: {detail[-200:]}")


def up() -> int:
    """Bring up the canonical PR 20A stack and seed the PR 20B document."""
    base.up()
    env = base._build_env(base._stage_secrets(), base._read_dotenv())
    _seed_batch_document(env)
    print("PR 20B fixture document seeded", flush=True)
    return 0


def _pr20b_test_env() -> dict[str, str]:
    env = base._test_env()
    env["MTMF_PR20B_LIVE"] = "1"
    env["MTMF_PR20B_ACCEPTANCE_DB"] = "mtmf"
    env["MTMF_PR20B_BATCH_DOCUMENT_ID"] = PR20B_BATCH_DOCUMENT_ID
    env["MTMF_PR20B_BATCH_TITLE"] = PR20B_BATCH_TITLE
    env["MTMF_PR20B_BATCH_BODY"] = PR20B_BATCH_BODY
    return env


def _run_pr20b_suite() -> None:
    base._assert_owned()
    base._verify_deployed_reference_app()
    env = _pr20b_test_env()
    result = subprocess.run(
        [
            "uv",
            "run",
            "--no-sync",
            "pytest",
            PR20B_LIVE_TEST,
            "-q",
            "--no-cov",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    output = base._redact((result.stdout or "") + (result.stderr or ""))
    print(output.rstrip()[-6000:], flush=True)
    if result.returncode != 0:
        raise Pr20bAcceptanceError("the PR 20B live conformance suite failed")
    if re.search(r"\bskipped|\bxfailed|\bxpassed|\bfailed|\berror", output):
        raise Pr20bAcceptanceError("the PR 20B suite reported skips, xfails or failures")


def test() -> int:
    """Run the PR 20A regression and the PR 20B conformance suite."""
    base.test()
    _run_pr20b_suite()
    print("PR 20A L01-L05 and PR 20B conformance passed", flush=True)
    return 0


def down() -> int:
    return int(base.down())


def recreate() -> int:
    return int(base.recreate())


def acceptance() -> int:
    """Run cold / repeat / recreate cycles and verify the default stack."""
    before = base._default_inventory()
    recreate()
    up()
    test()
    print("COLD-01 PASS", flush=True)
    up()
    test()
    print("REPEAT-01 PASS", flush=True)
    recreate()
    up()
    test()
    print("RECREATE-01 PASS", flush=True)
    after = base._default_inventory()
    if before != after:
        raise Pr20bAcceptanceError("default stack inventory changed during acceptance")
    print("default stack inventory unchanged", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 20B isolated conformance orchestrator")
    parser.add_argument(
        "command",
        choices=("preflight", "up", "test", "down", "recreate", "acceptance"),
    )
    args = parser.parse_args(argv)
    try:
        return {
            "preflight": preflight,
            "up": up,
            "test": test,
            "down": down,
            "recreate": recreate,
            "acceptance": acceptance,
        }[args.command]()
    except base.AcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1
    except Pr20bAcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
