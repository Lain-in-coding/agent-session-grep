#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("export_public_tree.py")
SPEC = importlib.util.spec_from_file_location("export_public_tree", SCRIPT)
assert SPEC and SPEC.loader
export_public_tree = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export_public_tree)


class PublicTreeExportTests(unittest.TestCase):
    def test_tracked_paths_exclude_internal_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            repo = Path(temp_name)
            import subprocess

            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            for relative in ["README.md", ".trellis/tasks/x.md", ".codex/hook.py", "src/lib.rs"]:
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            paths = export_public_tree.tracked_paths(repo, "HEAD")
            self.assertEqual(paths, ["README.md", "src/lib.rs"])

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
            parsed = json.loads((destination / export_public_tree.MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual(parsed["source_commit"], commit)
            self.assertNotIn(str(root), json.dumps(parsed))


if __name__ == "__main__":
    unittest.main()
