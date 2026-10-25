#!/usr/bin/env python3
"""Contract checks for the immutable update-check transport helpers.

These tests never contact the network. They assert the no-Rust/no-Python/
no-Node/no-jq delivery constraints and exercise argument-validation failures
through the real helper entrypoints when the native shell is available.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PS1 = ROOT / "scripts" / "install" / "update-check.ps1"
SH = ROOT / "scripts" / "install" / "update-check.sh"
SCHEMA = "asg.update-fetch/v1"
FORBIDDEN_COMMANDS = (
    "Set-ExecutionPolicy",
    "Unblock-File",
    "-ExecutionPolicy Bypass",
    "cargo ",
    "python ",
    "python3 ",
    "node ",
    "jq ",
)


def error_document(stdout: bytes) -> dict:
    value = json.loads(stdout.decode("utf-8"))
    assert value["schema"] == SCHEMA
    assert value["status"] == "error"
    return value


def executable_text(source: str) -> str:
    """Drop comments so documentation may name tools the helpers never run."""
    if "<#" in source:
        source = re.sub(r"<#.*?#>", "", source, flags=re.DOTALL)
    return "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )


class UpdateCheckHelperSourceTests(unittest.TestCase):
    def test_helpers_exist_and_share_the_transport_schema(self) -> None:
        for path in (PS1, SH):
            self.assertTrue(path.is_file(), path)
            source = path.read_text(encoding="utf-8")
            self.assertIn(SCHEMA, source)
            self.assertIn("capability", source)
            self.assertIn("redirect", source.lower())

    def test_helpers_require_no_extra_runtime_or_execution_policy_changes(self) -> None:
        ps1 = PS1.read_text(encoding="utf-8")
        sh = SH.read_text(encoding="utf-8")
        for source in (ps1, sh):
            code = executable_text(source)
            for token in FORBIDDEN_COMMANDS:
                self.assertNotIn(token, code, token)
        self.assertIn("command -v curl", sh)
        self.assertIn("command -v wget", sh)
        self.assertIn("mktemp", sh)


class UpdateCheckHelperExecutionTests(unittest.TestCase):
    def test_shell_helper_rejects_invalid_repository(self) -> None:
        shell = shutil.which("sh")
        if shell is None or not Path(shell).is_absolute():
            self.skipTest("no absolute POSIX sh available")
        completed = subprocess.run(
            [
                shell,
                str(SH),
                "-Mode",
                "page",
                "-Repository",
                "not-a-repo",
                "-Channel",
                "beta",
                "-Target",
                "x86_64-unknown-linux-gnu",
                "-CurrentVersion",
                "0.2.0-beta.1",
                "-Page",
                "1",
            ],
            check=False,
            capture_output=True,
            timeout=15,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(error_document(completed.stdout)["error"], "usage")
        self.assertEqual(completed.stderr, b"")

    def test_shell_helper_reports_capability_without_downloader(self) -> None:
        shell = shutil.which("sh")
        if shell is None or not Path(shell).is_absolute():
            self.skipTest("no absolute POSIX sh available")
        completed = subprocess.run(
            [
                shell,
                str(SH),
                "-Mode",
                "page",
                "-Repository",
                "Lain-in-coding/agent-session-grep",
                "-Channel",
                "beta",
                "-Target",
                "x86_64-unknown-linux-gnu",
                "-CurrentVersion",
                "0.2.0-beta.1",
                "-Page",
                "1",
            ],
            check=False,
            capture_output=True,
            timeout=15,
            env={"PATH": ""},
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(error_document(completed.stdout)["error"], "capability")

    def test_powershell_helper_rejects_invalid_repository(self) -> None:
        shell = None
        for name in ("pwsh", "powershell"):
            candidate = shutil.which(name)
            if candidate is not None:
                shell = candidate
                break
        if shell is None:
            self.skipTest("no native PowerShell available")
        completed = subprocess.run(
            [
                shell,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(PS1),
                "-Mode",
                "page",
                "-Repository",
                "not-a-repo",
                "-Channel",
                "beta",
                "-Target",
                "x86_64-pc-windows-msvc",
                "-CurrentVersion",
                "0.2.0-beta.1",
                "-Page",
                "1",
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(error_document(completed.stdout)["error"], "usage")
        self.assertEqual(completed.stderr, b"")


if __name__ == "__main__":
    unittest.main()
