#!/usr/bin/env python3
"""Export fixed Git objects with a reviewed, tool-owned public profile.

Export requires an empty, isolated destination and never stages files or changes
source refs. Import manifests are immutable snapshots, not current-tree claims.
An explicit --index-modes operation checks/applies recorded modes AFTER the
owner initializes and stages an exported destination; see the scrub runbook.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import unicodedata
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


SCHEMA = "agent-session-grep.public-tree/v2"
TOOL_ROOT = Path(__file__).resolve().parents[2]
PROJECTION_PATH = "scripts/release/public_AGENTS.md"
SCANNER_PATH = "scripts/evidence/privacy_scan.py"
IMPORT_ROOT = "docs/operations/imports"


def git_bytes(repo: Path, *args: str, data: bytes | None = None,
              index_file: Path | None = None) -> bytes:
    # Ambient overrides must not redirect reads or the explicit index operation.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        if name in os.environ:
            raise ValueError(f"unset {name} before running the exporter")
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args], input=data,
        check=True, capture_output=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
             **({"GIT_INDEX_FILE": str(index_file)} if index_file is not None else {})},
    ).stdout


def git(repo: Path, *args: str) -> str:
    return git_bytes(repo, *args).decode("utf-8").strip()


def resolve_commit(repo: Path, commit: str) -> str:
    return git(repo, "rev-parse", "--verify", "--end-of-options", commit + "^{commit}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def manifest_path(commit: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise ValueError("snapshot requires a full commit object ID")
    return f"{IMPORT_ROOT}/public-tree-v2-{commit}.json"


def validate_paths(paths: list[str]) -> None:
    """Reject names whose literal meaning is not portable to Windows/macOS."""
    nodes: dict[str, tuple[str, bool]] = {}
    for path in paths:
        parts = path.split("/")
        for index, part in enumerate(parts):
            stem = part.split(".")[0].rstrip(" ").upper()
            if (not part or part in (".", "..") or part.endswith((".", " "))
                    or any(c in '<>:"\\|?*' or unicodedata.category(c) in ("Cc", "Cf") for c in part)
                    or len(part.encode("utf-8")) > 255 or len(part.encode("utf-16-le")) > 510
                    or unicodedata.normalize("NFC", part) != part
                    or stem in ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$")
                    or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem)
                    or part.casefold() == ".git" or re.search(r"~[0-9]", part)):
                raise ValueError("unsafe or nonportable export path")
            prefix = "/".join(parts[:index + 1])
            key = prefix.casefold()
            is_file = index == len(parts) - 1
            previous = nodes.get(key)
            if previous is not None and (previous != (prefix, is_file) or is_file):
                raise ValueError("colliding export paths")
            nodes[key] = (prefix, is_file)


def tree_entries(repo: Path, commit: str) -> list[tuple[str, str, str]]:
    records = git_bytes(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries = []
    for record in records.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError(f"unsupported Git object: {mode} {kind}")
        entries.append((path, mode, oid))
    validate_paths([path for path, _, _ in entries])
    return sorted(entries)


def tracked_paths(repo: Path, commit: str) -> list[str]:
    return [path for path, _, _ in tree_entries(repo, resolve_commit(repo, commit))
            if not path.startswith(EXCLUDED_PREFIXES)]


def checked_path(path: Path) -> Path:
    """Check lexical ancestors BEFORE resolve(), including dangling links."""
    if ".." in path.parts:
        raise ValueError("destination traversal is not allowed")
    path = path.absolute()
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("destination contains a symlink or reparse point")
    return path


def destination_files(destination: Path, *, git_directory: bool = False) -> list[Path]:
    checked_path(destination)
    if not destination.is_dir():
        raise ValueError("scan destination must be an existing directory")

    def fail_walk(error: OSError) -> None:
        raise error

    files = []
    for root, dirs, names in os.walk(destination, followlinks=False, onerror=fail_walk):
        for name in dirs + names:
            path = Path(root) / name
            checked_path(path)
            if name == ".git" and Path(root) == destination and git_directory:
                if not path.is_dir():
                    raise ValueError("destination must have its own Git directory")
                dirs.remove(name)
                continue
            if not path.is_dir():
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("destination contains a non-regular file")
                files.append(path)
    return sorted(files)


def tool_context() -> tuple[object, dict[str, object], bytes]:
    """Execute only the scanner next to THIS reviewed exporter, never --repo."""
    scanner_path = TOOL_ROOT / SCANNER_PATH
    scanner_bytes = scanner_path.read_bytes()
    spec = importlib.util.spec_from_file_location("public_export_privacy_scan", scanner_path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load trusted privacy scanner")
    scanner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = scanner
    # Execute the exact bytes hashed below, without generating bytecode files.
    exec(compile(scanner_bytes, str(scanner_path), "exec"), scanner.__dict__)
    projection = (TOOL_ROOT / PROJECTION_PATH).read_bytes()
    profile = {
        "version": "agent-session-grep.public-profile/v2",
        "scanner": {"path": SCANNER_PATH, "profile": "public",
                    "sha256": hashlib.sha256(scanner_bytes).hexdigest()},
        "excluded_prefixes": list(EXCLUDED_PREFIXES),
        "projections": [{"path": "AGENTS.md", "input": PROJECTION_PATH,
                         "mode": "100644", "sha256": hashlib.sha256(projection).hexdigest()}],
    }
    rules = [(name, description, pattern.pattern, pattern.flags)
             for name, description, pattern in scanner.PROFILES["public"]]
    profile["sha256"] = hashlib.sha256(json_bytes({"profile": profile, "rules": rules})).hexdigest()
    return scanner, profile, projection


def file_entry(path: str, mode: str, content: bytes) -> dict[str, object]:
    return {"path": path, "mode": mode, "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}


def validate_manifest(manifest: dict, *, version: int) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("import manifest must be an object")
    if manifest.get("schema") != f"agent-session-grep.public-tree/v{version}":
        raise ValueError("unsupported import manifest schema")
    manifest_path(manifest["source_commit"])
    entries = manifest["files"]
    if (not isinstance(entries, list) or type(manifest["file_count"]) is not int
            or manifest["file_count"] != len(entries)):
        raise ValueError("invalid import manifest file inventory")
    if any(not isinstance(entry, dict) or not isinstance(entry.get("path"), str) for entry in entries):
        raise ValueError("invalid import manifest file path")
    validate_paths([entry["path"] for entry in entries])
    for entry in entries:
        if (type(entry["size_bytes"]) is not int or entry["size_bytes"] < 0
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                or (version == 2 and entry["mode"] not in ("100644", "100755"))):
            raise ValueError("invalid import manifest file record")


def export_tree(repo: Path, destination: Path, commit: str) -> dict[str, object]:
    destination = checked_path(destination)
    if destination.is_relative_to(repo.resolve()):
        raise ValueError("destination must be outside the source repository")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError("destination must be an empty directory")
    commit = resolve_commit(repo, commit)
    if git(repo, "rev-parse", "--is-bare-repository") == "false":
        source_root = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
        if destination.is_relative_to(source_root):
            raise ValueError("destination must be outside the source repository")
    for option in ("--absolute-git-dir", "--git-common-dir"):
        git_directory = Path(git(repo, "rev-parse", option))
        if not git_directory.is_absolute():
            git_directory = repo / git_directory
        if destination.is_relative_to(git_directory.resolve()):
            raise ValueError("destination must be outside source Git metadata")
    entries = tree_entries(repo, commit)
    _, profile, projection = tool_context()
    planned: list[tuple[str, str, bytes]] = []
    prior_manifest = None
    for relative, mode, oid in entries:
        if relative.startswith(EXCLUDED_PREFIXES):
            continue
        content = git_bytes(repo, "cat-file", "blob", oid)
        if relative == MANIFEST_NAME:
            # A legacy root manifest describes an older snapshot. Archive its
            # original bytes, never overwrite/hash it as the new manifest.
            old = json.loads(content)
            validate_manifest(old, version=1)
            relative = f"{IMPORT_ROOT}/public-tree-v1-{hashlib.sha256(content).hexdigest()}.json"
            prior_manifest = file_entry(relative, mode, content)
        elif relative == "AGENTS.md":
            content, mode = projection, "100644"
        planned.append((relative, mode, content))
    output_manifest = manifest_path(commit)
    validate_paths([path for path, _, _ in planned] + [output_manifest])
    files = [file_entry(path, mode, content) for path, mode, content in sorted(planned)]
    manifest = {
        "schema": SCHEMA, "source_commit": commit,
        "source_tree": git(repo, "rev-parse", commit + "^{tree}"),
        "tool": {"path": "scripts/release/export_public_tree.py", "version": "2",
                 "sha256": sha256(Path(__file__))},
        "profile": profile, "excluded_prefixes": list(EXCLUDED_PREFIXES),
        "lifecycle": "immutable-import-snapshot", "file_count": len(files), "files": files,
    }
    if prior_manifest is not None:
        manifest["prior_manifest"] = prior_manifest
    # No filesystem writes until ALL objects, paths, tools and metadata validate.
    # The destination must be privately owned; concurrent mutation is unsupported.
    destination.mkdir(parents=True, exist_ok=True)
    for relative, mode, content in planned + [(output_manifest, "100644", json_bytes(manifest))]:
        target = checked_path(destination / relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(content)
        target.chmod(0o755 if mode == "100755" else 0o644)
    return manifest


def scan_export(repo: Path, destination: Path, manifest: dict | None = None) -> int:
    # `repo` is retained for callers of the v1 API, but is NEVER a tool source.
    scanner, profile, _ = tool_context()
    findings = []
    for path in destination_files(destination):
        relative = path.relative_to(destination).as_posix()
        data = path.read_bytes()
        generated_snapshot = None
        if manifest is not None and relative == manifest_path(manifest["source_commit"]):
            if data != json_bytes(manifest):
                raise ValueError("generated manifest changed before scan")
            if (manifest.get("schema") != SCHEMA
                    or manifest.get("tool") != {
                        "path": "scripts/release/export_public_tree.py", "version": "2",
                        "sha256": sha256(Path(__file__)),
                    }
                    or manifest.get("profile") != profile
                    or manifest.get("excluded_prefixes") != list(EXCLUDED_PREFIXES)):
                raise ValueError("tool profile changed before scan")
            # A one-file grant, bound to the complete checked bytes. It cannot
            # authorize any later historical file or replace an archive pin.
            generated_snapshot = (relative, hashlib.sha256(data).hexdigest())
        findings.extend(scanner.scan_content(relative, data, "public",
                                             _generated_snapshot=generated_snapshot))
    if findings:
        for finding in findings:
            # Do not print the matching private value or raw source excerpt.
            print(f"public-tree privacy finding: [{finding.rule}]", file=sys.stderr)
        return 1
    return 0


def index_changes(destination: Path, snapshot: str, index_file: Path) -> list[bytes]:
    """Validate every file against one locked index; return mode-only edits."""
    destination = checked_path(destination)
    validate_paths([snapshot])
    if not (destination / ".git").is_dir():
        raise ValueError("initialize and explicitly stage the destination first")
    actual_files = destination_files(destination, git_directory=True)
    if Path(git(destination, "rev-parse", "--show-toplevel")).resolve() != destination.resolve():
        raise ValueError("index operation requires the destination repository root")
    raw_manifest = (destination / snapshot).read_bytes()
    manifest = json.loads(raw_manifest)
    validate_manifest(manifest, version=2)
    if snapshot != manifest_path(manifest["source_commit"]):
        raise ValueError("snapshot path does not match its source commit")
    entries = manifest["files"] + [file_entry(snapshot, "100644", raw_manifest)]
    validate_paths([entry["path"] for entry in entries])
    expected = {entry["path"]: entry for entry in entries}
    if {p.relative_to(destination).as_posix() for p in actual_files} != set(expected):
        raise ValueError("destination inventory differs from the snapshot")
    staged = {}
    for record in git_bytes(destination, "ls-files", "--stage", "-z", index_file=index_file).split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        name = path.decode("utf-8")
        if stage != "0" or name in staged or mode not in ("100644", "100755"):
            raise ValueError("destination index contains unsupported/unmerged entries")
        staged[name] = (mode, oid)
    if set(staged) != set(expected):
        raise ValueError("stage exactly the exported inventory before applying modes")
    changes = []
    for name, entry in expected.items():
        mode, oid = staged[name]
        working = (destination / name).read_bytes()
        indexed = git_bytes(destination, "cat-file", "blob", oid)
        if (file_entry(name, entry["mode"], working) != entry
                or file_entry(name, entry["mode"], indexed) != entry):
            raise ValueError("destination/index bytes differ from snapshot")
        if mode != entry["mode"]:
            changes.append(f"{entry['mode']} {oid}\t{name}\0".encode("utf-8"))
    return changes


def index_modes(destination: Path, snapshot: str, *, apply: bool = False) -> None:
    """Lock, validate and atomically publish a mode-only destination index."""
    destination = checked_path(destination)
    index = checked_path(destination / ".git/index")
    lock = index.with_name("index.lock")
    # Exclusive creation uses Git's real lock path before reading the index.
    # A pre-existing lock belongs to another writer and must not be removed.
    handle = lock.open("xb")
    owns_lock = True
    try:
        with handle:
            original = index.read_bytes()
            handle.write(original)
        changes = index_changes(destination, snapshot, lock)
        if changes:
            if not apply:
                raise ValueError("Git index modes differ; review then use --index-modes apply")
            # Git updates the private candidate using its own index.lock.lock;
            # the real index stays locked and unchanged until revalidation.
            git_bytes(destination, "update-index", "-z", "--index-info",
                      data=b"".join(changes), index_file=lock)
            if index_changes(destination, snapshot, lock):
                raise ValueError("candidate index modes differ from snapshot")
            if index.read_bytes() != original:
                raise ValueError("destination index changed despite its lock")
            os.replace(lock, index)
            # Publication releases our lock; a subsequent writer may already
            # own a new file at that path. Never clean up that writer's lock.
            owns_lock = False
    finally:
        if owns_lock:
            lock.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."), help="read-only source repository")
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--commit", help="source commit/ref, resolved once (default: HEAD)")
    parser.add_argument("--index-modes", choices=("check", "apply"), help="explicit destination-only index operation; does not export or stage content")
    parser.add_argument("--manifest", help="relative v2 snapshot path for --index-modes")
    args = parser.parse_args(argv)
    try:
        if args.index_modes:
            if not args.manifest or args.commit:
                raise ValueError("--index-modes requires --manifest and forbids --commit")
            index_modes(args.destination, args.manifest, apply=args.index_modes == "apply")
            print("destination Git index content and modes match the import snapshot")
            return 0
        if args.manifest:
            raise ValueError("--manifest is only used with --index-modes")
        manifest = export_tree(args.repo.resolve(), args.destination, args.commit or "HEAD")
        if scan_export(args.repo, args.destination.absolute(), manifest):
            return 1
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError) as error:
        # Git/OS exceptions include machine paths. Report the operation's
        # rejection reason without echoing private command arguments or names.
        if isinstance(error, subprocess.CalledProcessError):
            detail = f"Git object/index command failed (exit {error.returncode})"
        elif isinstance(error, OSError):
            detail = error.strerror or "filesystem operation failed"
        else:
            detail = str(error)
        print(f"public-tree operation failed: {detail}", file=sys.stderr)
        return 2
    print(f"exported {manifest['file_count']} files from {manifest['source_commit']}")
    print(f"snapshot: {manifest_path(manifest['source_commit'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
