"""Install an explicitly opted-in commit-msg adapter, never replacing hooks."""
from pathlib import Path
import shlex
import sys
from common import Parser, GitRepo, decode, fail, main_guard


def install(repo_path):
    repo = GitRepo(repo_path)
    # Respect local/global/system custom hook configuration rather than bypass it.
    # Read-only query uses ordinary Git config; no config write occurs.
    import subprocess
    try:
        result = subprocess.run([repo.executable, "-C", str(repo.path), "config", "--get", "core.hooksPath"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        fail("hook-config-unavailable")
    if result.returncode not in (0, 1) or result.returncode == 0:
        fail("existing-hooks-path-refused")
    git_dir = Path(decode(repo.git("rev-parse", "--absolute-git-dir")).strip()).resolve(strict=True)
    hooks = git_dir / "hooks"
    if hooks.is_symlink():
        fail("linked-hooks-directory-refused")
    if hooks.exists() and (not hooks.is_dir() or hooks.resolve() != hooks):
        fail("unsafe-hooks-directory")
    hooks.mkdir(exist_ok=True)
    destination = hooks / "commit-msg"
    if destination.exists() or destination.is_symlink():
        fail("existing-commit-hook-refused")
    checker = Path(__file__).resolve().with_name("check_commit.py")
    python = Path(sys.executable).resolve()
    adapter = ("#!/bin/sh\n# Explicit local opt-in; remove this file to uninstall.\nexec "
               + shlex.quote(python.as_posix()) + " " + shlex.quote(checker.as_posix())
               + ' --message-file "$1"\n')
    with destination.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(adapter)
    destination.chmod(0o700)
    return {"status": "installed", "scope": "local-commit-message-syntax-only",
            "server_gate_replacement": False}


def main():
    parser = Parser(description=__doc__, epilog=(
        "Explicit --install is required. Refuses custom core.hooksPath and any "
        "existing commit-msg hook. Never writes global or local Git configuration. "
        "Local hook is convenience only; it does not replace range/PR/credential "
        "checks, human review or required server checks. Remove only the generated "
        "commit-msg adapter to uninstall after verifying it remains unchanged."))
    parser.add_argument("--repo", required=True, help="Repository receiving the opt-in adapter")
    parser.add_argument("--install", action="store_true", help="Explicitly authorize adding a missing local commit-msg hook")
    args = parser.parse_args()
    if not args.install:
        fail("explicit-install-required")
    return install(args.repo)


if __name__ == "__main__":
    raise SystemExit(main_guard(main))
