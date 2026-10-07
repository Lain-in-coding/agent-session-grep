#!/usr/bin/env python3
"""Privacy scan for tracked text in the public tree.

Scans every path reported by ``git ls-files -z`` for personal or machine
absolute paths that must not ship in a public repository (user homes, local
checkout roots, worktree coordinates). Relative filenames are always scanned;
binary and UTF-16 payloads (Windows PowerShell transcripts) are not decoded. A small allowlist covers paths that are
deliberately synthetic (test fixtures and documentation examples); every
allowlist entry is exact and commented with its rationale.

Two profiles exist. ``repo`` (default) applies the personal/machine path rules
and is what the development checkout runs in CI. ``public`` adds the
internal-leak rules — references to the private task tracker, its task ids, the
reference-clone directory, and the private repository — which are findings only
for a tree that is about to be published. The exported public tree is scanned
with ``public``.

Rule literals are assembled from fragments so this scanner never contains a
matchable copy of the tokens it forbids.

Historical import policy metadata is omitted only after exact tool-owned
path/raw-hash/schema verification. Changed or unknown snapshots fail closed.

Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

SCANNER_NAME = "scripts/evidence/privacy_scan.py"

# Every token this scanner forbids is assembled from fragments, so the file
# never contains a matchable copy of one and can therefore scan itself without
# an exemption. Adding a literal here would silently create a blind spot.
_TRACKER = "tre" + "llis"
_CLONE_DIR = "Git" + "hub_src"
_CHECKOUT_ROOT = "Agent" + "Sessions"
_REFERENCE_ROOT = "Agent" + "Hub"
_PRIVATE_OWNER = "qin-" + "devs"
_INTERNAL_INTERVIEW = "grill" + "-with-docs"

# Patterns: (rule id, explanation, compiled regex).
# The user-home pattern only treats the first path segment as the account
# name, so multi-byte usernames are caught without allowing `/..` tricks.
BASE_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
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
        "local checkout or reference root as an absolute path",
        re.compile(
            r"(?:[A-Za-z]:[\\/]+|/mnt/[a-z]/)"
            rf"(?:{_CHECKOUT_ROOT}|{_REFERENCE_ROOT})(?:[\\/]|\b)",
            re.IGNORECASE,
        ),
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

# Public-tree rules. These are findings only for a tree about to be published:
# the internal task tracker, its task ids, the local reference-clone directory,
# the private repository slug, and internal interview tooling all point at
# things a public reader cannot resolve. Provider directories (`.claude`,
# `.codex`, `.codebuddy`) are deliberately NOT matched — they are real
# transcript locations this tool must name.
PUBLIC_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = BASE_RULES + (
    (
        "internal-tracker",
        "internal task-tracker directory or tooling reference",
        re.compile(rf"(?:\.{_TRACKER}\b|\b{_TRACKER}\b|{_INTERNAL_INTERVIEW})", re.IGNORECASE),
    ),
    (
        "internal-task-id",
        "internal task id (MM-DD-slug with two or more slug words)",
        re.compile(r"(?<![0-9])(?:0[1-9]|1[0-2])-[0-3][0-9]-[a-z][a-z0-9]*(?:-[a-z0-9]+)+"),
    ),
    (
        "reference-clone-dir",
        "local reference-clone directory for surveyed peer projects",
        re.compile(rf"\b{_CLONE_DIR}\b", re.IGNORECASE),
    ),
    (
        "private-repo-slug",
        "private development repository slug",
        re.compile(rf"{_PRIVATE_OWNER}/{_CHECKOUT_ROOT}\b", re.IGNORECASE),
    ),
)

PROFILES: dict[str, tuple[tuple[str, str, re.Pattern[str]], ...]] = {
    "repo": BASE_RULES,
    "public": PUBLIC_RULES,
}


# Reviewed immutable archives only. Neither a candidate file nor a caller can
# supply this registry. Each pin binds COMPLETE raw bytes before policy fields
# are omitted; the original root manifest deliberately has no alias here.
HISTORICAL_SNAPSHOTS = MappingProxyType({
    "docs/operations/imports/public-tree-v1-"
    "e0f26822ff2383e0017a7054ecc1acf8d18830bd57cb32e99c5d64155f8568af.json": (
        "e0f26822ff2383e0017a7054ecc1acf8d18830bd57cb32e99c5d64155f8568af",
        "agent-session-grep.public-tree/v1", frozenset({"excluded_prefixes"}),
    ),
    "docs/operations/imports/public-tree-v2-f587c73332158342330a63874fabdc8f565624ec.json": (
        "121e09c2ab6f7e5922a0862ea095fae3ae343913847cc3efa62546cf71585ead",
        "agent-session-grep.public-tree/v2", frozenset({"excluded_prefixes", "profile"}),
    ),
})


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
        # Hand-authored, byte-pinned Pi v3 branch fixture; see its PROVENANCE.md.
        (
            "crates/agent-session-grep-provider-pi/tests/golden/v3-branched.jsonl",
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
        # Registered-root tests use the placeholder account x in both Windows
        # spellings; MCP error-frame tests must redact the synthetic secret path.
        ("crates/agent-session-grep-cli/src/lib.rs", "user-home", SLASH_WIN_HOME + "x"),
        ("crates/agent-session-grep-cli/src/lib.rs", "user-home", WIN_HOME + "x"),
        ("crates/agent-session-grep-cli/src/mcp.rs", "user-home", SLASH_WIN_HOME + "secret"),
        # serve's POST-echo regression asserts a synthetic Windows user-home
        # transcript path is never reflected back in the 501 body.
        ("crates/agent-session-grep-cli/src/serve.rs", "user-home", SLASH_WIN_HOME + "alice"),
        ("crates/agent-session-grep-ports/src/lib.rs", "user-home", RUST_WIN_HOME + "secret"),
        ("spikes/search-backend/src/corpus.rs", "user-home", RUST_WIN_HOME + "dev"),
        # A tracker research note quotes the same synthetic `secret` account
        # while reviewing the redaction tests. Both the tracker directory and
        # the task id are assembled from fragments so this scanner stays free of
        # a literal internal reference and can scan itself. The entry only
        # matters for the private checkout, where the tracker is tracked; it is
        # inert in the public tree.
        (
            f".{_TRACKER}/tasks/08-15-" + "open-source-product-roadmap"
            "/research/2026-08-" + "15-review-tests.md",
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
    rules: tuple[tuple[str, str, re.Pattern[str]], ...] = BASE_RULES,
) -> list[Finding]:
    """Scan decoded lines for rule hits not covered by the allowlist."""
    findings: list[Finding] = []
    for number, line in enumerate(lines, start=1):
        normalized = unicodedata.normalize("NFC", line)
        for rule, _why, pattern in rules:
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


def scan_content(
    path: str,
    data: bytes,
    profile: str = "repo",
    *,
    _generated_snapshot: tuple[str, str] | None = None,
) -> list[Finding]:
    """Scan a relative filename and bytes once under the shared policy.

    The private generated-snapshot grant is one (path, raw SHA256) pair from
    the trusted exporter's exact tool/profile check, never candidate config.
    It applies only to that invocation's v2 output, cannot override an archive
    pin, and cannot choose omitted fields. Standalone scans never supply it.
    """
    rules = PROFILES[profile]
    # Filenames are scan input too, including when the payload is binary.
    findings = scan_lines(path, [path], rules=rules)
    text = decode_text(data)
    document = None
    if text is not None:
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            pass  # Ordinary non-JSON text still gets the unchanged line scan.
    schema = document.get("schema") if isinstance(document, dict) else None
    snapshot_name = Path(path).name.casefold()
    snapshot = (
        snapshot_name == "public-tree-manifest.json"
        or (snapshot_name.startswith("public-tree-") and snapshot_name.endswith(".json"))
        or (isinstance(schema, str) and schema.startswith("agent-session-grep.public-tree/"))
    )
    omitted: frozenset[str] = frozenset()
    pinned = HISTORICAL_SNAPSHOTS.get(path)
    if pinned is not None:
        digest, expected_schema, fields = pinned
        if hashlib.sha256(data).hexdigest() != digest or schema != expected_schema:
            findings.append(Finding(path, 1, "snapshot-integrity", "", ""))
        else:
            omitted = fields
    elif (_generated_snapshot is not None
          and _generated_snapshot == (path, hashlib.sha256(data).hexdigest())
          and schema == "agent-session-grep.public-tree/v2"
          and isinstance(document.get("source_commit"), str)
          and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", document["source_commit"])
          and path == "docs/operations/imports/public-tree-v2-" + document["source_commit"] + ".json"):
        omitted = frozenset({"excluded_prefixes", "profile"})
    elif snapshot:
        findings.append(Finding(path, 1, "unregistered-snapshot", "", ""))
    if omitted:
        # Retain EVERY other top-level field and all nested content, including
        # unknown free text and inventory entries. Never rewrite source bytes.
        text = json.dumps({key: value for key, value in document.items() if key not in omitted},
                          indent=2, ensure_ascii=False)
    if text is not None:
        findings.extend(scan_lines(path, text.splitlines(), rules=rules))
    return findings


def scan_repo(repo: Path, profile: str = "repo") -> list[Finding]:
    """Scan every tracked filename and supported payload with the named profile."""
    findings: list[Finding] = []
    for name in tracked_files(repo):
        findings.extend(scan_content(name, (repo / name).read_bytes(), profile))
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
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="repo",
        help=(
            "rule profile: `repo` checks personal/machine paths only (default); "
            "`public` also rejects internal task-tracker, task-id, "
            "reference-clone, and private-repository references"
        ),
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    try:
        findings = scan_repo(repo, args.profile)
    except (subprocess.CalledProcessError, OSError):
        print(f"{SCANNER_NAME}: tracked-file scan failed", file=sys.stderr)
        return 2

    if not findings:
        print(f"{SCANNER_NAME}: no findings in tracked text (profile: {args.profile})")
        return 0

    print(
        f"{SCANNER_NAME}: {len(findings)} finding(s) in tracked text "
        f"(profile: {args.profile}):",
        file=sys.stderr,
    )
    for finding in findings:
        print(
            f"  privacy finding: [{finding.rule}]",
            file=sys.stderr,
        )
    print(
        "Replace personal paths with <repo>/<user-home> or a repository-relative "
        "path; drop internal tracker/task-id/reference-clone/private-repository "
        "references; preserve snapshot bytes and review unknown or changed snapshots; "
        "extend ALLOWLIST only for provably synthetic fixtures.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
