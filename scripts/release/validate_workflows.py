#!/usr/bin/env python3
"""Validate the GitHub Actions workflows that ship or verify the release.

Two layers run, and both must pass:

1. A real YAML parse of every ``.github/workflows/*.yml`` file, when PyYAML is
   importable. The repository's own suites are standard-library only, so this
   layer is optional and reports itself as skipped when PyYAML is absent.
2. The text-level contract tests in ``test_release_workflow.py``: pinned
   action SHAs, least-privilege permissions, the three-OS matrix, the
   lockfile/feature/target binding on every release build, artifact upload +
   SHA256SUMS, and the guarantee that the verification workflow cannot publish.

Usage:
    python scripts/release/validate_workflows.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"


def workflow_files() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yml"))


def parse_workflows() -> tuple[bool, list[str]]:
    """Parse every workflow; returns (ok, report lines)."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - depends on the local interpreter
        return True, [
            "yaml parse: SKIPPED (PyYAML is not installed; `pip install pyyaml`"
            " to enable it) - contract checks below still enforce structure"
        ]
    lines: list[str] = [f"yaml parse: PyYAML {yaml.__version__}"]
    ok = True
    for path in workflow_files():
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            ok = False
            lines.append(f"  {path.name}: PARSE ERROR: {error}")
            continue
        problems = structure_problems(document)
        if problems:
            ok = False
            lines.append(f"  {path.name}: " + "; ".join(problems))
        else:
            lines.append(f"  {path.name}: parsed")
    return ok, lines


def structure_problems(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["document is not a mapping"]
    problems: list[str] = []
    if not document.get("name"):
        problems.append("missing top-level name")
    triggers = document.get("on", document.get(True))
    if triggers is None:
        problems.append("missing trigger block")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append("missing jobs")
        return problems
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            problems.append(f"job {job_name} is not a mapping")
            continue
        if "uses" not in job and "runs-on" not in job:
            problems.append(f"job {job_name} has neither uses nor runs-on")
    return problems


def contract_suite() -> unittest.TestSuite:
    module_path = Path(__file__).with_name("test_release_workflow.py")
    spec = importlib.util.spec_from_file_location("test_release_workflow", module_path)
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise RuntimeError(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return unittest.defaultTestLoader.loadTestsFromModule(module)


def main() -> int:
    if not workflow_files():
        print(f"no workflow files under {WORKFLOW_DIR}")
        return 1
    print(f"validating {len(workflow_files())} workflow files in {WORKFLOW_DIR}")
    parse_ok, lines = parse_workflows()
    for line in lines:
        print(line)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(contract_suite())
    if not parse_ok:
        print("FAILED: YAML parse")
        return 1
    if not result.wasSuccessful():
        print("FAILED: workflow contract checks")
        return 1
    print("OK: YAML parse and workflow contract checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
