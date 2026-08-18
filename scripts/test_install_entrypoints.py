#!/usr/bin/env python3
"""Regression tests for the root installer compatibility entrypoints."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ROOT_SH = ROOT / "scripts" / "install.sh"
ROOT_PS1 = ROOT / "scripts" / "install.ps1"
CANONICAL_SH = ROOT / "scripts" / "install" / "install.sh"
CANONICAL_PS1 = ROOT / "scripts" / "install" / "install.ps1"


def bash_runs_native_paths() -> bool:
    """Report whether the discovered ``bash`` can execute a native-path script.

    ``shutil.which("bash")`` is not enough on Windows: a WSL bash resolves
    ``/mnt/c/...`` and cannot open the ``C:\\...`` temp path this test builds,
    while Git Bash translates it fine. Probe the real capability so the
    forwarding smoke test skips on the former instead of failing for a reason
    that has nothing to do with the installer.
    """
    if shutil.which("bash") is None:
        return False
    with tempfile.TemporaryDirectory() as temp_name:
        probe = Path(temp_name) / "probe.sh"
        probe.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        os.chmod(probe, 0o755)
        try:
            completed = subprocess.run(
                ["bash", str(probe)], check=False, capture_output=True
            )
        except OSError:
            return False
    return completed.returncode == 0


BASH_RUNS_NATIVE_PATHS = bash_runs_native_paths()


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

    @unittest.skipUnless(
        BASH_RUNS_NATIVE_PATHS,
        "a bash that can execute a native-path script is required for the shell forwarding smoke test",
    )
    def test_root_shell_forwards_all_arguments_to_canonical_script(self) -> None:
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
                ["bash", str(root), *arguments],
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


if __name__ == "__main__":
    unittest.main()
