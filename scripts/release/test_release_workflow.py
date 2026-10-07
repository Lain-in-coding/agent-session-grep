#!/usr/bin/env python3
"""Contract tests for the GitHub Actions workflows that ship the release.

Properties that break silently and are only observable when a workflow
actually runs: an action reference that is not pinned to a commit SHA, a
``gh`` invocation inside a job that has no checkout for ``gh`` to resolve the
repository from, a release build that stopped binding the lockfile / feature
set / target, a matrix that lost an operating system, and a verification
workflow that quietly gained the ability to publish. The assertions are
text-based on purpose — the helper suites are standard-library only, so no
YAML parser is available; ``scripts/release/validate_workflows.py`` adds a
real YAML parse for local runs.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)")
SHA_PINNED = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
# Steps are the only 6-space list items that carry a `run:` block; splitting on
# them is enough to attribute a command to the step whose env must declare the
# repository.
STEP_BOUNDARY = re.compile(r"(?m)^      - ")
GH_COMMAND = re.compile(r"(?m)^\s*gh\s+[a-z]")
# The workflows wrap the `-p <package>` part of a build command onto the next
# line with a PowerShell backtick, so the command text is re-joined first.
MATRIX_RUNNER = re.compile(r"(?m)^\s+- runner:\s*(\S+)\s*$")
MATRIX_TARGET = re.compile(r"(?m)^\s+target:\s*(\S+)\s*$")
TAG_TRIGGER = re.compile(r"(?m)^\s+tags:\s*$")
# Workflows that build a downloadable release-shaped artifact: both must keep
# the same lockfile/feature/target contract.
RELEASE_BUILD_WORKFLOWS = ("release.yml", "release-verify.yml")
OS_FAMILIES = ("windows", "ubuntu", "macos")


def workflow_files() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yml"))


def read_workflow(name: str) -> str:
    return (WORKFLOW_DIR / name).read_text(encoding="utf-8")


def cargo_build_commands(text: str) -> list[str]:
    """Join each `cargo build` with its backtick-continued argument lines."""
    lines = text.splitlines()
    commands: list[str] = []
    for index, line in enumerate(lines):
        if "cargo build" not in line:
            continue
        parts = [line.strip()]
        cursor = index
        while parts[-1].endswith("`") and cursor + 1 < len(lines):
            cursor += 1
            parts.append(lines[cursor].strip())
        commands.append(" ".join(parts))
    return commands


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_directory_is_not_empty(self) -> None:
        # Guards the tests below against silently passing over zero files.
        self.assertTrue(workflow_files(), f"no workflow files under {WORKFLOW_DIR}")

    def test_every_action_reference_is_pinned_to_a_commit_sha(self) -> None:
        unpinned: list[str] = []
        for path in workflow_files():
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = USES.match(line)
                if not match:
                    continue
                reference = match.group(1)
                # A local reusable workflow is versioned by this repository's
                # own commit; only third-party actions need a SHA.
                if reference.startswith("./"):
                    continue
                if not SHA_PINNED.match(reference):
                    unpinned.append(f"{path.name}:{number}: {reference}")
        self.assertEqual(unpinned, [], f"unpinned action references: {unpinned}")

    def test_gh_steps_declare_the_repository_they_act_on(self) -> None:
        """`gh` resolves its repository from a git remote, `GH_REPO`, or
        `--repo`; it never falls back to `GITHUB_REPOSITORY`."""
        release = WORKFLOW_DIR / "release.yml"
        text = release.read_text(encoding="utf-8")
        offenders: list[str] = []
        gh_steps = 0
        for block in STEP_BOUNDARY.split(text):
            if not GH_COMMAND.search(block):
                continue
            gh_steps += 1
            if "GH_REPO:" not in block and "--repo" not in block:
                offenders.append(block.splitlines()[0].strip())
        self.assertGreater(gh_steps, 0, "no gh step found in release.yml")
        self.assertEqual(
            offenders, [], f"gh steps without a repository: {offenders}"
        )

    def test_every_workflow_declares_least_privilege_permissions(self) -> None:
        for path in workflow_files():
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                "permissions:\n  contents: read\n",
                text,
                f"{path.name} must declare top-level `contents: read`",
            )
            self.assertNotIn(
                "pull_request_target",
                text,
                f"{path.name} must not use pull_request_target",
            )
        # The token may be widened only for the tag-gated publish job.
        for path in workflow_files():
            widened = path.read_text(encoding="utf-8").count("contents: write")
            expected = 1 if path.name == "release.yml" else 0
            self.assertEqual(
                widened,
                expected,
                f"{path.name} widens the token in unexpected places",
            )

    def test_release_builds_bind_lockfile_features_and_target(self) -> None:
        for name in RELEASE_BUILD_WORKFLOWS:
            text = read_workflow(name)
            commands = cargo_build_commands(text)
            self.assertTrue(commands, f"{name} has no cargo build step")
            for flags in commands:
                for required in (
                    "--locked",
                    "--release",
                    "--no-default-features",
                    "--target",
                    "-p agent-session-grep-cli",
                ):
                    self.assertIn(
                        required,
                        flags,
                        f"{name}: release build is missing {required}",
                    )

    def test_release_workflows_cover_three_operating_systems(self) -> None:
        expected_targets = {
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
        }
        for name in RELEASE_BUILD_WORKFLOWS:
            text = read_workflow(name)
            runners = MATRIX_RUNNER.findall(text)
            for family in OS_FAMILIES:
                self.assertTrue(
                    any(family in runner for runner in runners),
                    f"{name}: matrix lost the {family} runner ({runners})",
                )
            targets = set(MATRIX_TARGET.findall(text))
            self.assertTrue(
                expected_targets.issubset(targets),
                f"{name}: matrix targets {sorted(targets)} do not cover "
                f"{sorted(expected_targets)}",
            )
            self.assertIn("fail-fast: false", text, f"{name}: fail-fast is on")
            self.assertIn("timeout-minutes:", text, f"{name}: matrix has no timeout")

    def test_release_matrix_promises_both_macos_arches(self) -> None:
        # assemble job fails unless four archives and four manifests exist, so
        # the tagged matrix must keep building both macOS targets.
        targets = set(MATRIX_TARGET.findall(read_workflow("release.yml")))
        self.assertIn("x86_64-apple-darwin", targets)
        self.assertIn("aarch64-apple-darwin", targets)

    def test_verify_matrix_keeps_one_runner_per_os_family(self) -> None:
        # Deliberate difference from release.yml: one runner per OS family
        # keeps verification runner minutes down; the release matrix still
        # covers the second macOS arch.
        runners = MATRIX_RUNNER.findall(read_workflow("release-verify.yml"))
        self.assertEqual(len(runners), 3, f"verify runners: {runners}")

    def test_release_workflows_upload_artifacts_with_checksums(self) -> None:
        for name in RELEASE_BUILD_WORKFLOWS:
            text = read_workflow(name)
            self.assertIn("uses: actions/upload-artifact@", text)
            self.assertIn("build-manifest.py checksums", text)
            self.assertIn("--output dist/SHA256SUMS", text)
            self.assertIn("if-no-files-found: error", text)

    def test_release_workflows_gate_builds_on_the_required_ci_workflow(self) -> None:
        for name in RELEASE_BUILD_WORKFLOWS:
            self.assertIn("uses: ./.github/workflows/ci.yml", read_workflow(name))

    def test_verify_workflow_cannot_publish_or_run_on_tags(self) -> None:
        text = read_workflow("release-verify.yml")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("\n    tags:", text)
        self.assertEqual(TAG_TRIGGER.findall(text), [], "verify workflow must not "
                         "trigger on tag pushes")
        self.assertNotIn("gh release", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("secrets.", text)

    def test_release_publish_job_is_tag_gated_and_uses_its_repository(self) -> None:
        text = read_workflow("release.yml")
        self.assertIn(
            "if: github.event_name == 'push' && github.ref_type == 'tag'", text
        )
        self.assertIn("GH_REPO: ${{ github.repository }}", text)


if __name__ == "__main__":
    unittest.main()
