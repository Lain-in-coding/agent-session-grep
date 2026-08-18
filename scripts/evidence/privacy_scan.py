#!/usr/bin/env python3
"""Privacy scan for tracked text in the public tree.

Scans every path reported by ``git ls-files -z`` for personal or machine
absolute paths that must not ship in a public repository (user homes, local
checkout roots, worktree coordinates). Binary files and UTF-16 blobs (Windows
PowerShell transcripts) are skipped. A small allowlist covers paths that are
deliberately synthetic (test fixtures and documentation examples); every
allowlist entry is exact and commented with its rationale.

Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

SCANNER_NAME = "scripts/evidence/privacy_scan.py"

# Patterns: (rule id, explanation, compiled regex).
# The user-home pattern only treats the first path segment as the account
# name, so multi-byte usernames are caught without allowing `/..` tricks.
RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "user-home",
        "absolute user-home path (Windows drive/Users/<name>, /Users/<name>, /home/<name>)",
        re.compile(
            r"(?:[A-Za-z]:[\\/]+Users[\\/]+[^\s`'\"<>|/\\]+"
            r"|(?<![A-Za-z0-9])/Users/[A-Za-z0-9._-]+"
            r"|(?<![A-Za-z0-9])/home/[A-Za-z0-9._-]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "machine-root",
        "local checkout/reference root (AgentSessions or AgentHub absolute path)",
        re.compile(r"[A-Za-z]:[\\/]+(?:AgentSessions|AgentHub)(?:[\\/]|\b)", re.IGNORECASE),
    ),
    (
        "agent-coordinate",
        "agent worktree checkout coordinate (.claude/worktrees/<name> or worktree-<name>)",
        re.compile(
            r"(?:\.claude[\\/]worktrees[\\/][A-Za-z0-9._-]+|\bworktree-[A-Za-z0-9._-]+\b)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    """One privacy rule hit inside a tracked text file."""

    path: str
    line: int
    rule: str
    match: str
    excerpt: str


BACKSLASH = chr(92)
WIN_HOME = "C:" + BACKSLASH + "Users" + BACKSLASH
RUST_WIN_HOME = "C:" + BACKSLASH * 2 + "Users" + BACKSLASH * 2
SLASH_WIN_HOME = "C:/" + "Users/"
LINUX_HOME = "/" + "home/"

# Allowlist: exact (path, rule, match) triples. Every entry must be a
# deliberately synthetic value used by tests or documentation — never a real
# personal path. Keep this list narrow; widening it silently re-opens the
# privacy boundary this scanner guards.
ALLOWLIST: frozenset[tuple[str, str, str]] = frozenset(
    {
        # Synthetic Linux user-home working directories in resume/hook fixtures.
        ("crates/agent-session-grep-application/src/resume.rs", "user-home", LINUX_HOME + "user"),
        ("crates/agent-session-grep-cli/src/hooks.rs", "user-home", LINUX_HOME + "u"),
        ("crates/agent-session-grep-cli/src/human.rs", "user-home", LINUX_HOME + "u"),
        ("crates/agent-session-grep-provider-openclaw/src/lib.rs", "user-home", LINUX_HOME + "user"),
        ("crates/agent-session-grep-provider-pi/src/lib.rs", "user-home", LINUX_HOME + "user"),
        ("crates/agent-session-grep-provider-qoder/src/lib.rs", "user-home", LINUX_HOME + "user"),
        # Golden fixtures for the same two providers: the byte-pinned synthetic
        # transcript declares a placeholder Linux home working directory, and
        # each PROVENANCE.md documents it. The fixtures are BLAKE3-pinned, so
        # the placeholder is allowlisted rather than rewritten.
        (
            "crates/agent-session-grep-provider-openclaw/tests/golden/basic.jsonl",
            "user-home",
            LINUX_HOME + "user",
        ),
        (
            "crates/agent-session-grep-provider-openclaw/tests/golden/PROVENANCE.md",
            "user-home",
            LINUX_HOME + "user",
        ),
        (
            "crates/agent-session-grep-provider-pi/tests/golden/basic.jsonl",
            "user-home",
            LINUX_HOME + "user",
        ),
        (
            "crates/agent-session-grep-provider-pi/tests/golden/PROVENANCE.md",
            "user-home",
            LINUX_HOME + "user",
        ),
        ("spikes/search-backend/src/corpus.rs", "user-home", LINUX_HOME + "user"),
        # Synthetic Windows user homes in redaction/path-handling fixtures:
        # accounts named `secret`, `someone`, `me`, `dev` are placeholders, and
        # each is asserted to be collapsed or redacted — never a real identity.
        ("crates/agent-session-grep-application/src/cjk.rs", "user-home", WIN_HOME + "me"),
        ("crates/agent-session-grep-application/src/lib.rs", "user-home", RUST_WIN_HOME + "secret"),
        ("crates/agent-session-grep-adapters-sqlite/src/lib.rs", "user-home", RUST_WIN_HOME + "dev"),
        ("crates/agent-session-grep-cli/src/human.rs", "user-home", SLASH_WIN_HOME + "someone"),
        ("crates/agent-session-grep-cli/src/human.rs", "user-home", SLASH_WIN_HOME + "…"),
        ("crates/agent-session-grep-cli/src/human.rs", "user-home", WIN_HOME + "someone"),
        ("crates/agent-session-grep-cli/src/human.rs", "user-home", WIN_HOME + "…"),
        ("crates/agent-session-grep-cli/src/protocol.rs", "user-home", SLASH_WIN_HOME + "secret"),
        # serve's POST-echo regression asserts a synthetic Windows user-home
        # transcript path is never reflected back in the 501 body.
        ("crates/agent-session-grep-cli/src/serve.rs", "user-home", SLASH_WIN_HOME + "alice"),
        ("crates/agent-session-grep-ports/src/lib.rs", "user-home", RUST_WIN_HOME + "secret"),
        ("spikes/search-backend/src/corpus.rs", "user-home", RUST_WIN_HOME + "dev"),
        (
            ".trellis/tasks/08-15-open-source-product-roadmap/research/2026-08-15-review-tests.md",
            "user-home",
            SLASH_WIN_HOME + "secret",
        ),
    }
)


def tracked_files(repo: Path) -> list[str]:
    """Return every tracked path, preserving names with spaces via -z.

    Every path git reports is scanned. No prefix is filtered out here: git
    already omits `.git/` itself, and anything else that is explicitly tracked
    is part of the public tree even when it lives under an internal or
    generated directory, so it must be checked rather than silently skipped.
    """
    completed = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [entry.decode("utf-8") for entry in completed.stdout.split(b"\0") if entry]


def decode_text(data: bytes) -> str | None:
    """Decode a blob as text, or return None when it is binary/UTF-16."""
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_lines(
    path: str,
    lines: list[str],
    allowlist: frozenset[tuple[str, str, str]] = ALLOWLIST,
) -> list[Finding]:
    """Scan decoded lines for rule hits not covered by the allowlist."""
    findings: list[Finding] = []
    for number, line in enumerate(lines, start=1):
        normalized = unicodedata.normalize("NFC", line)
        for rule, _why, pattern in RULES:
            for match in pattern.finditer(normalized):
                value = match.group(0)
                if (path, rule, value) in allowlist:
                    continue
                findings.append(
                    Finding(
                        path=path,
                        line=number,
                        rule=rule,
                        match=value,
                        excerpt=normalized.strip()[:120],
                    )
                )
    return findings


def scan_repo(repo: Path) -> list[Finding]:
    """Scan every tracked text file under ``repo``."""
    findings: list[Finding] = []
    for name in tracked_files(repo):
        path = repo / name
        data = path.read_bytes()
        text = decode_text(data)
        if text is None:
            continue
        findings.extend(scan_lines(name, text.splitlines()))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan tracked text files for personal/machine absolute paths.",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="repository root to scan (default: current directory)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    try:
        findings = scan_repo(repo)
    except subprocess.CalledProcessError as error:
        print(f"{SCANNER_NAME}: git ls-files failed: {error}", file=sys.stderr)
        return 2

    if not findings:
        print(f"{SCANNER_NAME}: no personal path findings in tracked text")
        return 0

    print(
        f"{SCANNER_NAME}: {len(findings)} personal path finding(s) in tracked text:",
        file=sys.stderr,
    )
    for finding in findings:
        print(
            f"  {finding.path}:{finding.line}: [{finding.rule}] {finding.match}",
            file=sys.stderr,
        )
    print(
        "Replace with <repo>/<user-home> or a repository-relative path; "
        "extend ALLOWLIST only for provably synthetic fixtures.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
