#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SCRIPT = Path(__file__).with_name("export_public_tree.py")
SPEC = importlib.util.spec_from_file_location("export_public_tree", SCRIPT)
assert SPEC and SPEC.loader
export_public_tree = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export_public_tree)

# Reuse the exporter's fragment-assembled tracker token so this test never
# contains a literal internal reference of its own.
TRACKER = export_public_tree._TRACKER


class PublicTreeExportTests(unittest.TestCase):
    def test_tracked_paths_exclude_internal_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            repo = Path(temp_name)
            import subprocess

            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            for relative in [
                "README.md",
                f".{TRACKER}/tasks/x.md",
                ".codex/hook.py",
                "scripts/evidence/out/report.json",
                "spikes/probe/EVIDENCE.md",
                "src/lib.rs",
            ]:
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            paths = export_public_tree.tracked_paths(repo, "HEAD")
            # spikes/ ships: the ADRs and RFCs cite its EVIDENCE.md files.
            self.assertEqual(paths, ["README.md", "spikes/probe/EVIDENCE.md", "src/lib.rs"])

    def test_scan_export_uses_the_public_profile(self) -> None:
        # An internal tracker reference is invisible to the default profile but
        # must fail the export, so the exporter has to select `public`.
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp_name:
            destination = Path(temp_name)
            (destination / "notes.md").write_text(
                f"see .{TRACKER}/tasks/x/prd.md\n", encoding="utf-8"
            )
            self.assertEqual(export_public_tree.scan_export(repo_root, destination), 1)
            (destination / "notes.md").write_text("no internal refs\n", encoding="utf-8")
            self.assertEqual(export_public_tree.scan_export(repo_root, destination), 0)

    def test_export_manifest_is_sorted_and_path_free(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            repo = root / "repo"
            destination = root / "public"
            import subprocess

            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "b.txt").write_text("b", encoding="utf-8")
            (repo / "a.txt").write_text("a", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            commit = export_public_tree.git(repo, "rev-parse", "HEAD")
            manifest = export_public_tree.export_tree(repo, destination, commit)
            self.assertEqual([entry["path"] for entry in manifest["files"]], ["a.txt", "b.txt"])
            parsed = json.loads((destination / export_public_tree.manifest_path(commit)).read_text(encoding="utf-8"))
            self.assertEqual(parsed["source_commit"], commit)
            self.assertNotIn(str(root), json.dumps(parsed))


class PublicTreeIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "source"
        self.destination = self.root / "export"
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")

    def git(self, *args: str, data: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], input=data,
            check=True, capture_output=True,
        ).stdout

    def commit(self, entries: dict[str, tuple[str, bytes]]) -> str:
        # Construct objects directly: Windows cannot create many hostile names.
        tree: dict = {}
        for path, entry in entries.items():
            parts = path.split("/")
            node = tree
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = entry

        def store(node: dict) -> str:
            records = []
            for name, entry in sorted(node.items()):
                if isinstance(entry, dict):
                    mode, oid = "40000", store(entry)
                else:
                    mode, content = entry
                    if mode == "160000":
                        oid = content.decode("ascii")
                    else:
                        oid = self.git("hash-object", "-w", "--stdin", data=content).decode().strip()
                records.append(mode.encode() + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(oid))
            return self.git("hash-object", "--literally", "-w", "-t", "tree", "--stdin", data=b"".join(records)).decode().strip()

        return self.git("commit-tree", store(tree), data=b"synthetic fixture\n").decode().strip()

    def export(self, entries: dict[str, tuple[str, bytes]]) -> tuple[str, dict]:
        commit = self.commit(entries)
        return commit, export_public_tree.export_tree(self.repo, self.destination, commit)

    def test_v2_repeats_exact_bytes_modes_and_provenance(self) -> None:
        commit, manifest = self.export({
            "space name.txt": ("100644", b"data\r\n"),
            "unicode-\u6d4b\u8bd5.txt": ("100644", b"utf8 path"),
            "scripts/run.sh": ("100755", b"#!/bin/sh\nexit 0\n"),
            "-leading.txt": ("100644", b"literal"),
        })
        second = self.root / "second"
        again = export_public_tree.export_tree(self.repo, second, commit)
        self.assertEqual(manifest, again)
        self.assertEqual(manifest["schema"], "agent-session-grep.public-tree/v2")
        self.assertEqual(manifest["source_commit"], commit)
        self.assertEqual(manifest["source_tree"], self.git("rev-parse", commit + "^{tree}").decode().strip())
        self.assertEqual(manifest["tool"]["sha256"], export_public_tree.sha256(SCRIPT))
        self.assertEqual(manifest["profile"]["scanner"]["sha256"], export_public_tree.sha256(SCRIPT.parent.parent / "evidence/privacy_scan.py"))
        self.assertEqual(len(manifest["profile"]["sha256"]), 64)
        paths = [entry["path"] for entry in manifest["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertNotIn(export_public_tree.manifest_path(commit), paths)
        for entry in manifest["files"]:
            data = (self.destination / entry["path"]).read_bytes()
            self.assertEqual(len(data), entry["size_bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
        self.assertEqual(next(e["mode"] for e in manifest["files"] if e["path"].endswith(".sh")), "100755")
        self.assertEqual((self.destination / export_public_tree.manifest_path(commit)).read_bytes(), (second / export_public_tree.manifest_path(commit)).read_bytes())
        self.assertNotIn(str(self.root), json.dumps(manifest))

    def test_autocrlf_checkout_does_not_change_profile_or_output(self) -> None:
        tool_root = SCRIPT.parents[2]
        paths = [".gitattributes", "AGENTS.md", "scripts/release/export_public_tree.py",
                 export_public_tree.PROJECTION_PATH, export_public_tree.SCANNER_PATH]
        # Commit canonical LF bytes, then let real Git checkout apply each
        # clone's attributes/config; the two tools run from their own clones.
        commit = self.commit({path: ("100644", (tool_root / path).read_text(encoding="utf-8").encode())
                              for path in paths})
        self.git("update-ref", "refs/heads/main", commit)
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        outputs = []
        for setting in ("false", "true"):
            clone = self.root / ("tool-" + setting)
            subprocess.run(["git", "clone", "-q", "--no-local", "--config", "core.autocrlf=" + setting,
                            str(self.repo), str(clone)], check=True, capture_output=True)
            self.assertEqual(b"\r\n" in (clone / "AGENTS.md").read_bytes(), setting == "true")
            output = self.root / ("output-" + setting)
            subprocess.run([sys.executable, str(clone / "scripts/release/export_public_tree.py"),
                            "--repo", str(self.repo), "--commit", commit, "--destination", str(output)],
                           check=True, capture_output=True)
            outputs.append(output)
        snapshot = export_public_tree.manifest_path(commit)
        self.assertEqual((outputs[0] / snapshot).read_bytes(), (outputs[1] / snapshot).read_bytes())
        self.assertEqual((outputs[0] / "AGENTS.md").read_bytes(), (outputs[1] / "AGENTS.md").read_bytes())

    def test_ref_is_resolved_once_and_dirty_source_is_untouched(self) -> None:
        commit = self.commit({"a.txt": ("100644", b"committed")})
        self.git("update-ref", "refs/heads/main", commit)
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        (self.repo / "a.txt").write_bytes(b"dirty")
        before = self.git("status", "--porcelain=v1", "-z")
        manifest = export_public_tree.export_tree(self.repo, self.destination, "HEAD")
        self.assertEqual(manifest["source_commit"], commit)
        self.assertEqual((self.destination / "a.txt").read_bytes(), b"committed")
        self.assertEqual(before, self.git("status", "--porcelain=v1", "-z"))
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"dirty")

    def test_replace_refs_cannot_change_fixed_source_objects(self) -> None:
        original = self.commit({"a": ("100644", b"original")})
        replacement = self.commit({"a": ("100644", b"replacement")})
        self.git("replace", original, replacement)
        manifest = export_public_tree.export_tree(self.repo, self.destination, original)
        self.assertEqual(manifest["source_commit"], original)
        self.assertEqual((self.destination / "a").read_bytes(), b"original")

    def test_non_commit_input_rejected_before_writes(self) -> None:
        oid = self.git("hash-object", "-w", "--stdin", data=b"blob").decode().strip()
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            export_public_tree.export_tree(self.repo, self.destination, oid)
        self.assertFalse(self.destination.exists())

    def test_unsafe_names_rejected_before_writes(self) -> None:
        for name in ["../escape", "/absolute", "C:drive", "back\\slash", "line\nfeed", "tab\tname", "NUL.txt", "con .txt", "LPT1", "COM\u00b9.log", "name.", "name ", "dir//file", ".git/config", "GIT~1/config", "a:b", "a?b", "e\u0301.txt"]:
            with self.subTest(name=name):
                self.destination = self.root / ("export-" + hashlib.sha256(name.encode()).hexdigest())
                commit = self.commit({"a-safe": ("100644", b"safe"), name: ("100644", b"unsafe")})
                with self.assertRaises(ValueError):
                    export_public_tree.validate_paths([name])
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    export_public_tree.export_tree(self.repo, self.destination, commit)
                self.assertFalse(self.destination.exists())

    def test_case_and_file_directory_collisions_rejected(self) -> None:
        for paths in [("A.txt", "a.txt"), ("Folder/a", "folder/b"), ("A", "a/b")]:
            with self.subTest(paths=paths):
                commit = self.commit({p: ("100644", b"data") for p in paths})
                with self.assertRaises(ValueError):
                    export_public_tree.export_tree(self.repo, self.destination, commit)
                self.assertFalse(self.destination.exists())

    def test_symlink_gitlink_and_excluded_unsupported_objects_rejected(self) -> None:
        base = self.commit({"a": ("100644", b"a")})
        for path, mode, data in [("link", "120000", b"../escape"), ("sub", "160000", base.encode()), (".codex/link", "120000", b"../escape")]:
            with self.subTest(mode=mode, path=path):
                commit = self.commit({"a": ("100644", b"a"), path: (mode, data)})
                with self.assertRaises(ValueError):
                    export_public_tree.export_tree(self.repo, self.destination, commit)
                self.assertFalse(self.destination.exists())

    def test_nonempty_destination_and_source_destination_rejected(self) -> None:
        commit = self.commit({"a": ("100644", b"a")})
        self.destination.mkdir()
        (self.destination / "keep").write_bytes(b"keep")
        with self.assertRaises(ValueError):
            export_public_tree.export_tree(self.repo, self.destination, commit)
        self.assertEqual((self.destination / "keep").read_bytes(), b"keep")
        with self.assertRaises(ValueError):
            export_public_tree.export_tree(self.repo, self.repo / "out", commit)
        self.assertFalse((self.repo / "out").exists())

    def test_source_subdirectory_cannot_hide_destination_overlap(self) -> None:
        commit = self.commit({"a": ("100644", b"a")})
        nested = self.repo / "nested"
        nested.mkdir()
        with self.assertRaises(ValueError):
            export_public_tree.export_tree(nested, self.repo / "out", commit)
        self.assertFalse((self.repo / "out").exists())

    def test_destination_link_escape_rejected(self) -> None:
        commit = self.commit({"a": ("100644", b"a")})
        outside = self.root / "outside"
        outside.mkdir()
        link = self.root / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        for dest in [link, link / "nested"]:
            with self.subTest(dest=dest):
                with self.assertRaises(ValueError):
                    export_public_tree.export_tree(self.repo, dest, commit)
        self.assertEqual(list(outside.iterdir()), [])

    def test_windows_reparse_attribute_rejected(self) -> None:
        self.destination.mkdir()
        original = Path.lstat

        def reparse(path: Path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == self.destination:
                return mock.Mock(st_mode=info.st_mode, st_file_attributes=0x400)
            return info

        commit = self.commit({"a": ("100644", b"a")})
        with mock.patch.object(Path, "lstat", reparse):
            with self.assertRaises(ValueError):
                export_public_tree.export_tree(self.repo, self.destination, commit)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_untrusted_source_scanner_never_executes(self) -> None:
        poison = self.repo / "scripts/evidence/privacy_scan.py"
        poison.parent.mkdir(parents=True)
        poison.write_text("raise RuntimeError('untrusted source executed')\n", encoding="utf-8")
        self.destination.mkdir()
        (self.destination / "notes.md").write_text(f"see .{TRACKER}/tasks/x\n", encoding="utf-8")
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination), 1)

    def test_missing_trusted_scanner_stops_before_writes(self) -> None:
        commit = self.commit({"a": ("100644", b"a")})
        with mock.patch.object(export_public_tree, "SCANNER_PATH", "missing-scanner.py"):
            with self.assertRaises(OSError):
                export_public_tree.export_tree(self.repo, self.destination, commit)
        self.assertFalse(self.destination.exists())

    def test_scan_requires_an_existing_readable_directory(self) -> None:
        with self.assertRaises(ValueError):
            export_public_tree.scan_export(self.repo, self.destination)
        self.destination.mkdir()
        with mock.patch.object(export_public_tree.os, "scandir", side_effect=PermissionError("unreadable")):
            with self.assertRaises(OSError):
                export_public_tree.scan_export(self.repo, self.destination)

    def test_scan_rejects_changed_generated_snapshot(self) -> None:
        commit, manifest = self.export({"a": ("100644", b"a")})
        (self.destination / export_public_tree.manifest_path(commit)).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            export_public_tree.scan_export(self.repo, self.destination, manifest)

    def test_generated_snapshot_does_not_exempt_extra_data(self) -> None:
        commit, manifest = self.export({"a": ("100644", b"a")})
        manifest["notes"] = f"see .{TRACKER}/tasks/private"
        (self.destination / export_public_tree.manifest_path(commit)).write_bytes(
            export_public_tree.json_bytes(manifest))
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination, manifest), 1)

    def test_scan_rejects_profile_drift_since_export(self) -> None:
        _, manifest = self.export({"a": ("100644", b"a")})
        scanner, profile, projection = export_public_tree.tool_context()
        profile["scanner"]["sha256"] = "0" * 64
        with mock.patch.object(export_public_tree, "tool_context", return_value=(scanner, profile, projection)):
            with self.assertRaises(ValueError):
                export_public_tree.scan_export(self.repo, self.destination, manifest)

    def test_existing_v2_snapshot_is_preserved_and_still_scanned(self) -> None:
        first_commit, first = self.export({"a": ("100644", b"a")})
        archive = export_public_tree.manifest_path(first_commit)
        original = (self.destination / archive).read_bytes()
        self.destination = self.root / "next-export"
        _, second = self.export({"a": ("100644", b"new a"), archive: ("100644", original)})
        self.assertEqual((self.destination / archive).read_bytes(), original)
        self.assertNotIn("prior_manifest", second)
        self.assertFalse((self.destination / export_public_tree.MANIFEST_NAME).exists())
        self.assertIn(export_public_tree.file_entry(archive, "100644", original), second["files"])
        # Even authentic historical policy metadata is not a blanket exemption.
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination, second), 1)

    def test_agents_projection_is_declared_hashed_and_standalone(self) -> None:
        original = f"read .{TRACKER}/workflow.md\n".encode()
        _, manifest = self.export({"AGENTS.md": ("100755", original)})
        profile = SCRIPT.with_name("public_AGENTS.md")
        self.assertEqual((self.destination / "AGENTS.md").read_bytes(), profile.read_bytes())
        self.assertEqual(profile.read_bytes(), (SCRIPT.parents[2] / "AGENTS.md").read_text(encoding="utf-8").encode("utf-8"))
        entry = manifest["files"][0]
        self.assertEqual(entry["mode"], "100644")
        projection = manifest["profile"]["projections"][0]
        self.assertEqual(projection["path"], "AGENTS.md")
        self.assertEqual(projection["sha256"], hashlib.sha256(profile.read_bytes()).hexdigest())
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination, manifest), 0)

    def test_v1_snapshot_preserves_bytes_without_self_hashing(self) -> None:
        old = b'{"schema":"agent-session-grep.public-tree/v1","source_commit":"' + b"1" * 40 + b'","excluded_prefixes":[],"file_count":0,"files":[]}\r\n'
        commit, manifest = self.export({export_public_tree.MANIFEST_NAME: ("100644", old), "a": ("100644", b"a")})
        archive = "docs/operations/imports/public-tree-v1-" + hashlib.sha256(old).hexdigest() + ".json"
        self.assertEqual((self.destination / archive).read_bytes(), old)
        self.assertFalse((self.destination / export_public_tree.MANIFEST_NAME).exists())
        self.assertNotIn(export_public_tree.manifest_path(commit), [e["path"] for e in manifest["files"]])
        self.assertEqual(manifest["prior_manifest"]["path"], archive)

    def test_unknown_manifest_rejected(self) -> None:
        commit = self.commit({export_public_tree.MANIFEST_NAME: ("100644", b"not a manifest")})
        with self.assertRaises(ValueError):
            export_public_tree.export_tree(self.repo, self.destination, commit)
        self.assertFalse(self.destination.exists())

    def test_malformed_manifest_types_raise_controlled_value_error(self) -> None:
        for version in (1, 2):
            for field in ("path", "file_count"):
                with self.subTest(version=version, field=field):
                    manifest = {"schema": f"agent-session-grep.public-tree/v{version}",
                                "source_commit": "1" * 40, "file_count": 1,
                                "files": [export_public_tree.file_entry("a", "100644", b"a")]}
                    if field == "path":
                        manifest["files"][0]["path"] = 123
                    else:
                        manifest["file_count"] = True
                    with self.assertRaises(ValueError):
                        export_public_tree.validate_manifest(manifest, version=version)

    def test_malformed_manifest_cli_rejects_before_writes_without_traceback(self) -> None:
        for field, reason in (("path", "invalid import manifest file path"),
                              ("file_count", "invalid import manifest file inventory")):
            with self.subTest(field=field):
                manifest = {"schema": "agent-session-grep.public-tree/v1",
                            "source_commit": "1" * 40, "file_count": 1,
                            "files": [export_public_tree.file_entry("a", "100644", b"a")]}
                if field == "path":
                    manifest["files"][0]["path"] = 123
                else:
                    manifest["file_count"] = True
                commit = self.commit({export_public_tree.MANIFEST_NAME:
                                      ("100644", export_public_tree.json_bytes(manifest)),
                                      "a": ("100644", b"a")})
                destination = self.root / ("invalid-" + field)
                result = subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo),
                                         "--commit", commit, "--destination", str(destination)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(destination.exists())
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, f"public-tree operation failed: {reason}\n")
                self.assertNotIn("Traceback", result.stderr)
                self.assertNotIn(str(self.root), result.stderr)
                self.assertNotIn(str(SCRIPT), result.stderr)

    def test_legacy_archive_collision_rejected_before_writes(self) -> None:
        old = json.dumps({"schema": "agent-session-grep.public-tree/v1", "source_commit": "1" * 40,
                          "file_count": 0, "files": [], "excluded_prefixes": []}).encode()
        archive = "docs/operations/imports/public-tree-v1-" + hashlib.sha256(old).hexdigest() + ".json"
        commit = self.commit({export_public_tree.MANIFEST_NAME: ("100644", old), archive: ("100644", b"collision")})
        with self.assertRaises(ValueError):
            export_public_tree.export_tree(self.repo, self.destination, commit)
        self.assertFalse(self.destination.exists())

    def test_old_manifest_is_not_a_privacy_exemption(self) -> None:
        old = json.dumps({"schema": "agent-session-grep.public-tree/v1", "source_commit": "1" * 40,
                          "file_count": 0, "files": [], "excluded_prefixes": [f".{TRACKER}/"]}).encode()
        _, manifest = self.export({export_public_tree.MANIFEST_NAME: ("100644", old)})
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination, manifest), 1)

    def test_export_cli_never_imports_source_scanner(self) -> None:
        commit = self.commit({"scripts/evidence/privacy_scan.py": ("100644", b"raise RuntimeError('poison')"),
                              "AGENTS.md": ("100644", f"use .{TRACKER}/workflow.md".encode())})
        self.assertEqual(export_public_tree.main(["--repo", str(self.repo), "--commit", commit,
                                                "--destination", str(self.destination)]), 0)

    def stage_destination(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.destination)], check=True)
        subprocess.run(["git", "-C", str(self.destination), "config", "core.filemode", "false"], check=True)
        paths = [path.relative_to(self.destination).as_posix() for path in
                 export_public_tree.destination_files(self.destination, git_directory=True)]
        subprocess.run(["git", "-C", str(self.destination), "--literal-pathspecs", "-c", "core.autocrlf=false",
                        "add", "--pathspec-from-file=-", "--pathspec-file-nul"],
                       input=b"".join(path.encode("utf-8") + b"\0" for path in paths), check=True)
        subprocess.run(["git", "-C", str(self.destination), "update-index", "--chmod=-x", "--", "run.sh"], check=True)

    def test_explicit_index_modes_check_apply_and_final_tree(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n"), "a.txt": ("100644", b"a"),
                                 "space [name].txt": ("100644", b"literal pathspec"),
                                 "-leading.txt": ("100644", b"literal option"),
                                 "unicode-\u6d4b\u8bd5.txt": ("100644", b"unicode name")})
        self.stage_destination()
        snapshot = export_public_tree.manifest_path(commit)
        with self.assertRaises(ValueError):
            export_public_tree.index_modes(self.destination, snapshot, apply=False)
        export_public_tree.index_modes(self.destination, snapshot, apply=True)
        export_public_tree.index_modes(self.destination, snapshot, apply=False)
        tree = subprocess.check_output(["git", "-C", str(self.destination), "write-tree"]).decode().strip()
        record = subprocess.check_output(["git", "-C", str(self.destination), "ls-tree", tree, "--", "run.sh"])
        self.assertTrue(record.startswith(b"100755 blob "), record)
        self.assertFalse((self.repo / ".git/index").exists())

    def test_index_cli_and_environment_guard(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        arguments = ["--destination", str(self.destination), "--manifest", export_public_tree.manifest_path(commit)]
        self.assertEqual(export_public_tree.main(arguments + ["--index-modes", "check"]), 2)
        before = (self.destination / ".git/index").read_bytes()
        with mock.patch.dict(os.environ, {"GIT_INDEX_FILE": str(self.root / "wrong-index")}):
            self.assertEqual(export_public_tree.main(arguments + ["--index-modes", "apply"]), 2)
        self.assertEqual((self.destination / ".git/index").read_bytes(), before)
        self.assertFalse((self.root / "wrong-index").exists())
        self.assertEqual(export_public_tree.main(arguments + ["--index-modes", "apply"]), 0)
        self.assertEqual(export_public_tree.main(arguments + ["--index-modes", "check"]), 0)

    def test_index_missing_extra_and_unstaged_files_rejected(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n"), "a": ("100644", b"a")})
        self.stage_destination()
        before = (self.destination / ".git/index").read_bytes()
        for kind in ("extra", "unstaged", "missing"):
            with self.subTest(kind=kind):
                if kind == "extra":
                    (self.destination / "extra").write_bytes(b"extra")
                elif kind == "unstaged":
                    (self.destination / "a").write_bytes(b"different")
                else:
                    (self.destination / "a").unlink()
                with self.assertRaises(ValueError):
                    export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
                self.assertEqual((self.destination / ".git/index").read_bytes(), before)
                if kind == "extra":
                    (self.destination / "extra").unlink()
                (self.destination / "a").write_bytes(b"a")

    def test_index_destination_link_rejected(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        link = self.root / "index-link"
        try:
            link.symlink_to(self.destination, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises(ValueError):
            export_public_tree.index_modes(link, export_public_tree.manifest_path(commit), apply=True)

    def test_index_lock_blocks_concurrent_blob_replacement(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        new_oid = subprocess.check_output(
            ["git", "-C", str(self.destination), "hash-object", "-w", "--stdin"],
            input=b"concurrently staged content",
        ).decode().strip()
        original = export_public_tree.git_bytes
        attempts = []

        def race(repo, *args, **kwargs):
            if args[0] == "update-index" and not attempts:
                attempts.append(subprocess.run(
                    ["git", "-C", str(self.destination), "update-index", "--cacheinfo",
                     "100644", new_oid, "run.sh"], capture_output=True,
                ))
            return original(repo, *args, **kwargs)

        with mock.patch.object(export_public_tree, "git_bytes", race):
            export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
        self.assertEqual(len(attempts), 1)
        self.assertNotEqual(attempts[0].returncode, 0, "concurrent content staging was overwritten")
        self.assertFalse((self.destination / ".git/index.lock").exists())

    def test_failed_post_update_validation_preserves_real_index(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        before = (self.destination / ".git/index").read_bytes()
        original = export_public_tree.git_bytes

        def drift(repo, *args, **kwargs):
            result = original(repo, *args, **kwargs)
            if args[0] == "update-index":
                (self.destination / "run.sh").write_bytes(b"concurrent working edit")
            return result

        with mock.patch.object(export_public_tree, "git_bytes", drift):
            with self.assertRaises(ValueError):
                export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
        self.assertEqual((self.destination / ".git/index").read_bytes(), before)
        self.assertFalse((self.destination / ".git/index.lock").exists())

    def test_index_update_or_publish_error_preserves_real_index(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        before = (self.destination / ".git/index").read_bytes()
        original = export_public_tree.git_bytes

        def fail_update(repo, *args, **kwargs):
            if args[0] == "update-index":
                raise subprocess.CalledProcessError(1, ["git", "update-index"])
            return original(repo, *args, **kwargs)

        for failure in ("update", "publish"):
            with self.subTest(failure=failure):
                patch = (mock.patch.object(export_public_tree, "git_bytes", fail_update) if failure == "update"
                         else mock.patch.object(export_public_tree.os, "replace", side_effect=PermissionError("denied")))
                with patch:
                    with self.assertRaises((OSError, subprocess.CalledProcessError)):
                        export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
                self.assertEqual((self.destination / ".git/index").read_bytes(), before)
                self.assertFalse((self.destination / ".git/index.lock").exists())

    def test_next_writers_lock_survives_successful_index_publication(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        index = self.destination / ".git/index"
        lock = self.destination / ".git/index.lock"
        next_writer_bytes = b"next writer owns this lock"
        published = []
        original = export_public_tree.os.replace

        def publish_then_acquire(source, target):
            result = original(source, target)
            published.append(index.read_bytes())
            with lock.open("xb") as handle:
                handle.write(next_writer_bytes)
            return result

        with mock.patch.object(export_public_tree.os, "replace", publish_then_acquire):
            export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
        self.assertEqual(len(published), 1)
        self.assertTrue(lock.exists(), "cleanup removed the next writer's lock")
        self.assertEqual(lock.read_bytes(), next_writer_bytes)
        self.assertEqual(index.read_bytes(), published[0])
        record = export_public_tree.git_bytes(self.destination, "ls-files", "--stage", "--", "run.sh")
        self.assertTrue(record.startswith(b"100755 "), record)

    def test_pinned_snapshot_bytes_survive_both_clone_newline_settings(self) -> None:
        scanner, _, _ = export_public_tree.tool_context()
        entries = {path: ("100644", (SCRIPT.parents[2] / path).read_bytes())
                   for path in scanner.HISTORICAL_SNAPSHOTS}
        entries[".gitattributes"] = ("100644", (SCRIPT.parents[2] / ".gitattributes").read_bytes())
        entries["ordinary.txt"] = ("100644", b"ordinary text\n")
        commit = self.commit(entries)
        self.git("update-ref", "refs/heads/snapshots", commit)
        for autocrlf in ("true", "false"):
            with self.subTest(autocrlf=autocrlf):
                clone = self.root / ("clone-" + autocrlf)
                subprocess.run(["git", "clone", "--no-local", "-q", "--branch", "snapshots",
                                "--config", "core.autocrlf=" + autocrlf,
                                str(self.repo), str(clone)], check=True, capture_output=True)
                for path, (digest, _, _) in scanner.HISTORICAL_SNAPSHOTS.items():
                    self.assertEqual((clone / path).read_bytes(), entries[path][1])
                    self.assertEqual(hashlib.sha256((clone / path).read_bytes()).hexdigest(), digest)
                    self.assertEqual(export_public_tree.git_bytes(clone, "show", "HEAD:" + path),
                                     entries[path][1])
                self.assertEqual((clone / "ordinary.txt").read_bytes(),
                                 b"ordinary text\r\n" if autocrlf == "true" else b"ordinary text\n")
                self.assertEqual(scanner.scan_repo(clone, "public"), [])
                destination = self.root / ("export-" + autocrlf)
                manifest = export_public_tree.export_tree(clone, destination, commit)
                self.assertEqual(export_public_tree.scan_export(clone, destination, manifest), 0)
                for path in scanner.HISTORICAL_SNAPSHOTS:
                    self.assertEqual((destination / path).read_bytes(), entries[path][1])

    def test_historical_scans_agree_without_rule_hits_and_do_not_trust_candidate_registry(self) -> None:
        scanner, _, _ = export_public_tree.tool_context()
        cases = []
        for path in scanner.HISTORICAL_SNAPSHOTS:
            raw = (SCRIPT.parents[2] / path).read_bytes()
            cases.extend([(path, raw, 0), (path, b"{}", 1), (path, raw + b" ", 1),
                          ("renamed.json", raw, 1)])
        cases.extend([
            ("docs/operations/imports/public-tree-v2-unknown.json", b"{}", 1),
            ("ordinary.json", b'{"profile":"public","excluded_prefixes":[]}', 0),
            ("ordinary.md", ("." + TRACKER + "/private").encode(), 1),
        ])
        for index, (relative, raw, status) in enumerate(cases):
            with self.subTest(case=index):
                destination = self.root / ("candidate-" + str(index))
                target = destination / relative
                target.parent.mkdir(parents=True)
                target.write_bytes(raw)
                # Candidate data is never imported as policy or executable code.
                (destination / "registry.json").write_text(
                    json.dumps({relative: {"sha256": hashlib.sha256(raw).hexdigest(),
                                          "fields": ["profile", "excluded_prefixes", "files"]}}),
                    encoding="utf-8")
                indexed = self.root / ("indexed-" + str(index))
                (indexed / relative).parent.mkdir(parents=True)
                (indexed / relative).write_bytes(raw)
                (indexed / "registry.json").write_bytes((destination / "registry.json").read_bytes())
                subprocess.run(["git", "init", "-q", str(indexed)], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(indexed), "-c", "core.autocrlf=false", "add",
                                "--", relative, "registry.json"], check=True, capture_output=True)
                self.assertEqual(bool(scanner.scan_repo(indexed, "public")), bool(status))
                with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(export_public_tree.scan_export(self.repo, destination), status)
                if status:
                    self.assertIn("public-tree privacy finding:", stderr.getvalue())
                    self.assertNotIn(relative, stderr.getvalue())
                    self.assertNotIn(TRACKER, stderr.getvalue())

    def test_filename_only_findings_agree_and_are_not_duplicated(self) -> None:
        scanner, _, _ = export_public_tree.tool_context()
        for index, raw in enumerate((b"ordinary text", b"{}", b"\x00")):
            with self.subTest(binary=b"\x00" in raw):
                relative = "docs/" + "08-15-" + "synthetic-check.txt"
                destination = self.root / ("path-export-" + str(index))
                target = destination / relative
                target.parent.mkdir(parents=True)
                target.write_bytes(raw)
                with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(export_public_tree.scan_export(self.repo, destination), 1)
                self.assertEqual(stderr.getvalue().count("[internal-task-id]"), 1)
                self.assertNotIn(relative, stderr.getvalue())
                indexed = self.root / ("path-indexed-" + str(index))
                target = indexed / relative
                target.parent.mkdir(parents=True)
                target.write_bytes(raw)
                subprocess.run(["git", "init", "-q", str(indexed)], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(indexed), "add", "--", relative],
                               check=True, capture_output=True)
                self.assertEqual([f.rule for f in scanner.scan_repo(indexed, "public")],
                                 ["internal-task-id"])
                with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(scanner.main(["--repo", str(indexed), "--profile", "public"]), 1)
                self.assertEqual(stderr.getvalue().count("[internal-task-id]"), 1)
                self.assertNotIn(relative, stderr.getvalue())

    def test_fresh_authorization_cannot_flow_to_unknown_historical_snapshot(self) -> None:
        _, manifest = self.export({"a": ("100644", b"a")})
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination, manifest), 0)
        unknown = self.destination / "docs/operations/imports/public-tree-v2-unknown.json"
        unknown.write_bytes(b"{}")
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination, manifest), 1)
        # Without this invocation's verified generated manifest, its snapshot
        # is historical too. Profile/schema resemblance alone grants nothing.
        self.assertEqual(export_public_tree.scan_export(self.repo, self.destination), 1)

    def test_generated_grant_cannot_override_a_historical_pin(self) -> None:
        _, manifest = self.export({"a": ("100644", b"a")})
        # Same current tool/profile as a fresh output, but an approved historical
        # path can NEVER be repurposed to accept different bytes.
        manifest["source_commit"] = "f587c73332158342330a63874fabdc8f565624ec"
        destination = self.root / "override-candidate"
        snapshot = destination / export_public_tree.manifest_path(manifest["source_commit"])
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes(export_public_tree.json_bytes(manifest))
        with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(export_public_tree.scan_export(self.repo, destination, manifest), 1)
        self.assertIn("snapshot-integrity", stderr.getvalue())

    def test_generated_schema_tool_and_policy_fields_remain_exact(self) -> None:
        commit, manifest = self.export({"a": ("100644", b"a")})
        snapshot = self.destination / export_public_tree.manifest_path(commit)
        for key, value in (("schema", "agent-session-grep.public-tree/v1"),
                           ("tool", {"path": "untrusted.py", "sha256": "0" * 64}),
                           ("profile", {}), ("excluded_prefixes", [])):
            with self.subTest(field=key):
                modified = {**manifest, key: value}
                snapshot.write_bytes(export_public_tree.json_bytes(modified))
                with self.assertRaises(ValueError):
                    export_public_tree.scan_export(self.repo, self.destination, modified)

    def test_byte_exact_golden_json_whitespace(self) -> None:
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.whitespace", "trailing-space,space-before-tab")
        attributes = SCRIPT.parents[2] / ".gitattributes"
        (self.repo / ".gitattributes").write_bytes(attributes.read_bytes())
        relative = "crates/example/tests/golden/basic.expected.json"
        fixture = self.repo / relative
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(b'{"value":0}\r\n')
        other = self.repo / "other.json"
        other.write_bytes(b'{"value":0}\n')
        self.git("add", "--", ".gitattributes", relative, "other.json")
        self.git("commit", "-qm", "synthetic whitespace baseline")

        def stage_and_check(content: bytes) -> int:
            fixture.write_bytes(content)
            self.git("add", "--", relative)
            self.assertEqual(self.git("show", ":" + relative), content)
            return subprocess.run(
                ["git", "-C", str(self.repo), "diff", "--cached", "--check"],
                capture_output=True,
            ).returncode

        self.assertEqual(stage_and_check(b'{"value":1}\r\n'), 0)
        for malformed in (b'{"value":1} \r\n', b'{"value":1}\r\n\r\n',
                          b' \t{"value":1}\r\n'):
            with self.subTest(content=malformed):
                self.assertNotEqual(stage_and_check(malformed), 0)
        self.assertEqual(stage_and_check(b'{"value":1}\r\n'), 0)
        other.write_bytes(b'{"value":1}\r\n')
        self.git("add", "--", "other.json")
        self.assertNotEqual(subprocess.run(
            ["git", "-C", str(self.repo), "diff", "--cached", "--check"],
            capture_output=True,
        ).returncode, 0)

    def test_existing_index_lock_is_never_removed(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n")})
        self.stage_destination()
        lock = self.destination / ".git/index.lock"
        lock.write_bytes(b"another writer owns this lock")
        before = (self.destination / ".git/index").read_bytes()
        with self.assertRaises((OSError, subprocess.CalledProcessError)):
            export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
        self.assertEqual(lock.read_bytes(), b"another writer owns this lock")
        self.assertEqual((self.destination / ".git/index").read_bytes(), before)

    def test_index_drift_rejected_without_partial_mode_updates(self) -> None:
        commit, _ = self.export({"run.sh": ("100755", b"#!/bin/sh\n"), "z.txt": ("100644", b"z")})
        self.stage_destination()
        (self.destination / "z.txt").write_bytes(b"changed")
        subprocess.run(["git", "-C", str(self.destination), "add", "--", "z.txt"], check=True)
        before = (self.destination / ".git/index").read_bytes()
        with self.assertRaises(ValueError):
            export_public_tree.index_modes(self.destination, export_public_tree.manifest_path(commit), apply=True)
        self.assertEqual((self.destination / ".git/index").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
