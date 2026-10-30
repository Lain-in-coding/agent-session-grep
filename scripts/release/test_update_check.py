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

    def test_powershell_timeout_is_set_before_any_request(self) -> None:
        # HttpClient forbids modifying Timeout after the first SendAsync; the
        # redirect loop must not try to set it per iteration.
        source = PS1.read_text(encoding="utf-8")
        loop = source[source.index("while ($true)"):]
        self.assertNotIn(".Timeout", loop.split("\n}\n")[0])
        self.assertLess(source.index("$client.Timeout"),
                        source.index("SendAsync"))

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

    def test_shell_header_matching_is_portable_case_insensitive_awk(self) -> None:
        # IGNORECASE is a gawk extension; mawk and BSD awk silently treat an
        # assignment as an unset variable, so header matching must use an
        # explicit tolower comparison instead.
        source = SH.read_text(encoding="utf-8")
        code = executable_text(source)
        self.assertNotIn("IGNORECASE", code)
        self.assertIn("tolower($0)", code)
        self.assertEqual(
            code.count('tolower($0) !~ /^[[:space:]]*location:/'), 2,
            "both header_location and last_locations must match case-insensitively",
        )

    def test_wget_enforces_allowlist_before_each_download(self) -> None:
        # wget follows redirects internally and downloads along the way; the
        # allowlist check must run on the URL before every request, not only
        # on recorded Location headers after success.
        code = executable_text(SH.read_text(encoding="utf-8"))
        self.assertIn('allowed_redirect "$current_url" || fail redirect_rejected 6', code)
        pre_request = code.index('allowed_redirect "$current_url"')
        wget_call = code.index("wget --https-only")
        self.assertLess(pre_request, wget_call)


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
        # Git for Windows' sh.exe rebuilds PATH and still finds its curl, so
        # an empty PATH alone would let the helper reach the network.
        reachable = subprocess.run(
            [shell, "-c", "command -v curl || command -v wget"],
            check=False,
            capture_output=True,
            timeout=15,
            env={"PATH": ""},
        )
        if reachable.returncode == 0:
            self.skipTest("sh still finds a downloader with an empty PATH")
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
