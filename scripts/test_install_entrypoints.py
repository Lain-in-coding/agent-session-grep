#!/usr/bin/env python3
"""Regression tests for the root installer compatibility entrypoints."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ROOT_SH = ROOT / "scripts" / "install.sh"
ROOT_PS1 = ROOT / "scripts" / "install.ps1"
CANONICAL_SH = ROOT / "scripts" / "install" / "install.sh"
CANONICAL_PS1 = ROOT / "scripts" / "install" / "install.ps1"


def resolve_bash_executable() -> str | None:
    """Retain one absolute executable; never fall back from an explicit input."""
    explicit = os.environ.get("AGENT_SESSION_GREP_TEST_BASH")
    candidate = explicit if explicit is not None else shutil.which("bash")
    if candidate is None:
        return None
    path = Path(candidate)
    invalid = "AGENT_SESSION_GREP_TEST_BASH must name an absolute executable file"
    if explicit is not None and not path.is_absolute():
        raise ValueError(invalid)
    path = path.resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        if explicit is not None:
            raise ValueError(invalid)
        return None
    return str(path)


def bash_runs_native_paths(executable: str | None) -> bool:
    """Probe the selected executable, not another Bash discovered through PATH."""
    if executable is None:
        return False
    with tempfile.TemporaryDirectory() as temp_name:
        probe = Path(temp_name) / "probe.sh"
        probe.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        os.chmod(probe, 0o755)
        try:
            completed = subprocess.run(
                [executable, str(probe)], check=False, capture_output=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
    return completed.returncode == 0


BASH_EXECUTABLE = resolve_bash_executable()
BASH_RUNS_NATIVE_PATHS = bash_runs_native_paths(BASH_EXECUTABLE)


class InstallEntrypointTests(unittest.TestCase):
    def test_root_entrypoints_are_thin_delegators(self) -> None:
        root_sh = ROOT_SH.read_text(encoding="utf-8")
        root_ps1 = ROOT_PS1.read_text(encoding="utf-8")

        self.assertIn('exec bash "$canonical" "$@"', root_sh)
        self.assertIn("Join-Path $PSScriptRoot 'install/install.ps1'", root_ps1)
        self.assertIn("& $canonical @args", root_ps1)
        self.assertNotIn("git clone", root_sh.lower())
        self.assertNotIn("git clone", root_ps1.lower())
        self.assertNotIn("cargo build", root_sh.lower())
        self.assertNotIn("cargo build", root_ps1.lower())
        self.assertTrue(CANONICAL_SH.exists())
        self.assertTrue(CANONICAL_PS1.exists())

    def test_root_shell_forwards_all_arguments_to_canonical_script(self) -> None:
        required = os.environ.get("AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH")
        if required not in (None, "1"):
            self.fail("AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH must be 1 when set")
        if not BASH_RUNS_NATIVE_PATHS:
            reason = "a Bash that can execute native-path scripts is required"
            if required == "1":
                self.fail(f"{reason} by CI; selected executable: {BASH_EXECUTABLE!r}")
            self.skipTest(f"{reason} for this optional local forwarding test")
        with tempfile.TemporaryDirectory() as temp_name:
            temp = Path(temp_name)
            scripts = temp / "scripts"
            canonical_dir = scripts / "install"
            canonical_dir.mkdir(parents=True)
            root = scripts / "install.sh"
            root.write_text(ROOT_SH.read_text(encoding="utf-8"), encoding="utf-8")
            canonical = canonical_dir / "install.sh"
            canonical.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            os.chmod(root, 0o755)
            os.chmod(canonical, 0o755)

            arguments = ["--prefix", "path with spaces", "--skip-build", "--dry-run"]
            result = subprocess.run(
                [BASH_EXECUTABLE, str(root), *arguments],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), arguments)

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is required for the PowerShell forwarding smoke test")
    def test_root_powershell_forwards_all_arguments_to_canonical_script(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            temp = Path(temp_name)
            scripts = temp / "scripts"
            canonical_dir = scripts / "install"
            canonical_dir.mkdir(parents=True)
            root = scripts / "install.ps1"
            root.write_text(ROOT_PS1.read_text(encoding="utf-8"), encoding="utf-8")
            canonical = canonical_dir / "install.ps1"
            canonical.write_text(
                "param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)\n"
                "$Arguments | ForEach-Object { Write-Output ([string]$_) }\n"
                "exit 0\n",
                encoding="utf-8",
            )

            arguments = ["-Prefix", "path with spaces", "-SkipBuild", "-DryRun"]
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(root), *arguments],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), arguments)


class BashSelectionTests(unittest.TestCase):
    def run_case(self, **overrides):
        # Each selection happens during a fresh import. Keep the driver's normal
        # bootstrap environment; only these two test-only keys are isolated.
        config = {
            "discovered": str(Path(sys.executable).resolve()),
            "executable": True,
            "probe_returncode": 0,
            "probe_error": None,
            "forward_returncode": 0,
            "forward_stdout": None,
        }
        config.update(overrides)
        environment = os.environ.copy()
        for key in ("AGENT_SESSION_GREP_TEST_BASH", "AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH"):
            environment.pop(key, None)
        environment.update(config.pop("environment", {}))
        driver = """
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

config = json.loads(sys.argv[2])
report = {"calls": [], "bash_lookups": 0, "import_error": None}
real_which = shutil.which
real_access = os.access

def discover(name, *args, **kwargs):
    if name == "bash":
        report["bash_lookups"] += 1
        return config["discovered"]
    return real_which(name, *args, **kwargs)

def access(path, mode, *args, **kwargs):
    if not config["executable"]:
        return False
    return real_access(path, mode, *args, **kwargs)

def native(argv, **kwargs):
    report["calls"].append([argv, kwargs])
    if Path(argv[1]).name == "probe.sh":
        if config["probe_error"] == "launch":
            raise OSError("synthetic Bash launch failure")
        if config["probe_error"] == "timeout":
            raise subprocess.TimeoutExpired(argv, 10)
        return subprocess.CompletedProcess(argv, config["probe_returncode"], b"", b"")
    stdout = config["forward_stdout"]
    if stdout is None:
        stdout = "\\n".join(argv[2:]) + "\\n"
    return subprocess.CompletedProcess(argv, config["forward_returncode"], stdout,
                                       "synthetic forwarding failure")

with patch("shutil.which", side_effect=discover), \\
        patch("os.access", side_effect=access), \\
        patch("subprocess.run", side_effect=native):
    try:
        scope = runpy.run_path(sys.argv[1], run_name="entrypoint_contract")
    except Exception as error:
        report["import_error"] = f"{type(error).__name__}: {error}"
    else:
        method = "test_root_shell_forwards_all_arguments_to_canonical_script"
        suite = unittest.TestSuite([scope["InstallEntrypointTests"](method)])
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        report.update(tests_run=result.testsRun, skips=len(result.skipped),
                      failures=len(result.failures), errors=len(result.errors),
                      output=stream.getvalue())
print(json.dumps(report))
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", driver, str(Path(__file__).resolve()), json.dumps(config)],
            env=environment, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def assert_result(self, report, *, failures=0, skips=0):
        self.assertIsNone(report["import_error"], report)
        self.assertEqual(report["tests_run"], 1, report)
        self.assertEqual(report["errors"], 0, report)
        self.assertEqual(report["failures"], failures, report)
        self.assertEqual(report["skips"], skips, report)

    def test_explicit_absolute_executable_is_reused_for_probe_and_forwarding(self):
        executable = str(Path(sys.executable).resolve())
        report = self.run_case(environment={"AGENT_SESSION_GREP_TEST_BASH": executable})
        self.assert_result(report)
        self.assertEqual([call[0][0] for call in report["calls"]], [executable, executable])
        self.assertEqual(report["bash_lookups"], 0, "explicit selection must not rediscover bash")
        self.assertEqual(report["calls"][1][0][2:],
                         ["--prefix", "path with spaces", "--skip-build", "--dry-run"])

    def test_discovery_resolves_once_and_never_launches_bare_bash(self):
        executable = str(Path(sys.executable).resolve())
        path = Path(executable)
        # Keep the fixture on the tool's volume, even when the workspace is on
        # another Windows drive. The noncanonical spelling must still resolve.
        discovered = path.parent / ".." / path.parent.name / path.name
        report = self.run_case(discovered=str(discovered))
        self.assert_result(report)
        self.assertEqual([call[0][0] for call in report["calls"]], [executable, executable])
        self.assertEqual(report["bash_lookups"], 1)

    def test_explicit_invalid_candidates_never_fall_back(self):
        with tempfile.TemporaryDirectory(prefix="invalid-bash-") as directory:
            cases = (("", True), ("bash", True), ("relative/bash.exe", True),
                     (str(Path(directory) / "missing-bash.exe"), True),
                     (directory, True), (str(Path(sys.executable).resolve()), False))
            for candidate, executable in cases:
                with self.subTest(candidate=candidate, executable=executable):
                    report = self.run_case(
                        environment={"AGENT_SESSION_GREP_TEST_BASH": candidate},
                        executable=executable,
                    )
                    self.assertIsNotNone(report["import_error"], "invalid explicit Bash was accepted")
                    self.assertIn("AGENT_SESSION_GREP_TEST_BASH", report["import_error"])
                    self.assertEqual(report["bash_lookups"], 0, report)
                    self.assertEqual(report["calls"], [], report)

    def test_absent_optional_bash_skips_without_probing(self):
        report = self.run_case(discovered=None)
        self.assert_result(report, skips=1)
        self.assertEqual(report["calls"], [])

    def test_optional_failed_capability_remains_a_local_skip(self):
        for failure in ({"probe_returncode": 127}, {"probe_error": "launch"},
                        {"probe_error": "timeout"}):
            with self.subTest(failure=failure):
                report = self.run_case(**failure)
                self.assert_result(report, skips=1)
                self.assertEqual(len(report["calls"]), 1)

    def test_required_absent_bash_fails_instead_of_skipping(self):
        report = self.run_case(discovered=None, environment={
            "AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH": "1",
        })
        self.assert_result(report, failures=1)
        self.assertIn("required", report["output"])
        self.assertEqual(report["calls"], [])

    def test_required_failed_probe_fails_instead_of_skipping(self):
        for failure in ({"probe_returncode": 127}, {"probe_error": "launch"},
                        {"probe_error": "timeout"}):
            with self.subTest(failure=failure):
                report = self.run_case(environment={
                    "AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH": "1",
                }, **failure)
                self.assert_result(report, failures=1)
                self.assertEqual(len(report["calls"]), 1)

    def test_other_provided_requirement_values_are_rejected(self):
        for value in ("", "0", "true", "01"):
            with self.subTest(value=value):
                report = self.run_case(environment={
                    "AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH": value,
                })
                self.assert_result(report, failures=1)
                self.assertIn("AGENT_SESSION_GREP_REQUIRE_NATIVE_BASH", report["output"])

    def test_capability_probe_has_a_ten_second_timeout(self):
        report = self.run_case()
        self.assert_result(report)
        self.assertEqual(report["calls"][0][1].get("timeout"), 10)

    def test_forwarding_exit_and_argument_failures_are_not_hidden(self):
        for failure in ({"forward_returncode": 17}, {"forward_stdout": "lost arguments\n"}):
            with self.subTest(failure=failure):
                report = self.run_case(**failure)
                self.assert_result(report, failures=1)
                self.assertEqual(len(report["calls"]), 2)


if __name__ == "__main__":
    unittest.main()
