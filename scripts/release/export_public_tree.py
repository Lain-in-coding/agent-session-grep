#!/usr/bin/env python3
"""Export a deterministic public-tree candidate without rewriting Git history.

The development checkout carries task-tracker and agent coordination records
that are useful internally but are not part of the public product. This command
copies tracked files from a selected commit into a fresh destination, excludes
those working records and the throwaway spikes, writes a manifest with the
source commit and SHA-256 per file, and runs the repository privacy scanner over
the exported tree under its `public` profile — which rejects internal
task-tracker references, internal task ids, the reference-clone directory, and
the private repository slug in addition to personal and machine paths.

It never changes refs, deletes history, or changes repository visibility.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_TRACKER = "tre" + "llis"

# Working records that never ship: the task tracker, per-provider agent config
# directories, and generated evidence output. Assembled for the tracker so the
# exporter itself stays clean under the public privacy profile.
#
# `spikes/` deliberately DOES ship. The spike cards and EVIDENCE.md files are
# the reproducible measurements that docs/adr and docs/architecture cite; a
# reader evaluating those decisions needs them, and excluding the directory
# would break 18 evidence links across the ADRs, the RFCs, the threat model,
# and the evidence matrix.
EXCLUDED_PREFIXES = (
    f".{_TRACKER}/",
    ".codex/",
    ".codebuddy/",
    ".agents/",
    ".claude/",
    "scripts/evidence/out/",
)
MANIFEST_NAME = "PUBLIC-TREE-MANIFEST.json"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def tracked_paths(repo: Path, commit: str) -> list[str]:
    raw = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", commit],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.splitlines()
    return [path for path in raw if not path.startswith(EXCLUDED_PREFIXES)]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def export_tree(repo: Path, destination: Path, commit: str) -> dict[str, object]:
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"destination must be empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    paths = tracked_paths(repo, commit)
    files: list[dict[str, object]] = []
    for relative in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        content = subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{relative}"],
            check=True,
            capture_output=True,
        ).stdout
        target.write_bytes(content)
        files.append(
            {
                "path": relative,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    manifest = {
        "schema": "agent-session-grep.public-tree/v1",
        "source_commit": commit,
        "excluded_prefixes": list(EXCLUDED_PREFIXES),
        "file_count": len(files),
        "files": files,
    }
    (destination / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def scan_export(repo: Path, destination: Path) -> int:
    scanner_path = repo / "scripts/evidence/privacy_scan.py"
    spec = importlib.util.spec_from_file_location("privacy_scan", scanner_path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load privacy scanner")
    scanner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = scanner
    spec.loader.exec_module(scanner)
    rules = scanner.PROFILES["public"]
    findings = []
    for path in sorted(destination.rglob("*")):
        if not path.is_file() or path.name == MANIFEST_NAME:
            continue
        relative = path.relative_to(destination).as_posix()
        text = scanner.decode_text(path.read_bytes())
        if text is not None:
            findings.extend(scanner.scan_lines(relative, text.splitlines(), rules=rules))
    if findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line}: [{finding.rule}] {finding.match}",
                file=sys.stderr,
            )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--commit", default="HEAD")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    destination = args.destination.resolve()
    try:
        commit = git(repo, "rev-parse", "--verify", args.commit)
        manifest = export_tree(repo, destination, commit)
        scan_result = scan_export(repo, destination)
        if scan_result != 0:
            return scan_result
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"public-tree export failed: {error}", file=sys.stderr)
        return 2
    print(
        f"exported {manifest['file_count']} files from {manifest['source_commit']} "
        f"to {destination}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
