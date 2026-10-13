"""Synthetic path-history regressions; never print finding contents."""
import json
from pathlib import Path
import subprocess
import sys

from common import GateError, GitRepo
from scan_paths import scan_paths, path_content_surfaces
from credential_scan import Surface, collect_surfaces
from test_policy import GitFixture, GOOD

ROOT = Path(__file__).resolve().parent


def private_value():
    return "/" + "home/" + "synthetic-review-person"


class PathHistoryTests(GitFixture):
    def scan(self, head):
        return scan_paths(*collect_surfaces(GitRepo(self.repo), self.base, head,
                                           content_factory=path_content_surfaces))

    def test_added_then_deleted_private_content_rejects(self):
        self.commit("transient", private_value())
        self.git("rm", "--", "transient")
        self.git("commit", "-q", "-m", GOOD)
        with self.assertRaisesRegex(GateError, "path-privacy-findings"):
            self.scan(self.git("rev-parse", "HEAD"))

    def test_unchanged_head_and_private_commit_identity_reject(self):
        self.base = self.commit("existing", private_value())
        with self.assertRaisesRegex(GateError, "path-privacy-findings"):
            self.scan(self.base)
        self.git("rm", "--", "existing")
        self.git("commit", "-q", "-m", GOOD)
        self.base = self.git("rev-parse", "HEAD")
        self.git("config", "user.name", private_value())
        head = self.commit("clean", "Public text")
        with self.assertRaisesRegex(GateError, "path-privacy-findings"):
            self.scan(head)

    def test_new_context_for_old_allowlisted_blob_rejects(self):
        name = "crates/agent-session-grep-application/src/resume.rs"
        (self.repo / name).parent.mkdir(parents=True)
        self.base = self.commit(name, "/" + "home/user")
        self.commit("new-context", "/" + "home/user")
        self.git("rm", "--", "new-context")
        self.git("commit", "-q", "-m", GOOD)
        with self.assertRaisesRegex(GateError, "path-privacy-findings"):
            self.scan(self.git("rev-parse", "HEAD"))

    def test_metadata_cli_escapes_and_candidate_scanner_are_not_trusted(self):
        name = "scripts/evidence/privacy_scan.py"
        (self.repo / name).parent.mkdir(parents=True)
        head = self.commit(name, "raise RuntimeError('candidate executed')")
        metadata = self.repo / "input.json"
        for surface in ("event", "merge"):
            event = self.event(head)
            if surface == "event":
                event["pull_request"]["user"] = {"name": private_value()}
                args = ["--event-file", str(metadata)]
                value = event
            else:
                identity = {"name": private_value(), "email": "real@example.org"}
                value = {"author": identity, "committer": identity}
                message = self.repo / "message.txt"
                message.write_text(GOOD, encoding="utf-8")
                args = ["--merge-message-file", str(message), "--merge-metadata-file", str(metadata)]
            encoded = json.dumps(value).replace("/", "\\u002f")
            metadata.write_text(encoded, encoding="utf-8")
            proc = subprocess.run([sys.executable, str(ROOT / "scan_paths.py"),
                                   "--repo", str(self.repo), "--base", self.base,
                                   "--head", head, *args], capture_output=True)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stderr)["code"], "path-privacy-findings")
            self.assertNotIn(private_value().encode(), proc.stdout + proc.stderr)

    def test_private_filename_is_redacted(self):
        # A portable relative path that contains a matched private coordinate.
        name = "notes/" + "work" + "tree-" + "synthetic/file"
        (self.repo / name).parent.mkdir(parents=True)
        head = self.commit(name, "Safe public text")
        proc = subprocess.run([sys.executable, str(ROOT / "scan_paths.py"),
                               "--repo", str(self.repo), "--base", self.base,
                               "--head", head], capture_output=True)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(name.encode(), proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stderr)["code"], "path-privacy-findings")

    def test_binary_metadata_cannot_silently_skip_path_rules(self):
        with self.assertRaisesRegex(GateError, "binary-coverage-required"):
            scan_paths([Surface("metadata", "", b"\x00" + private_value().encode())], {})

    def test_transient_filename_and_divergent_base_are_covered(self):
        name = "notes/" + "work" + "tree-" + "synthetic/file"
        (self.repo / name).parent.mkdir(parents=True)
        self.commit(name, "Public text")
        self.git("rm", "--", name)
        self.git("commit", "-q", "-m", GOOD)
        head = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "-b", "advanced-base", self.base)
        self.base = self.commit("base-only", "Public base advancement")
        with self.assertRaisesRegex(GateError, "path-privacy-findings"):
            self.scan(head)

    def test_clean_and_old_removed_debt(self):
        self.base = self.commit("old", private_value())
        self.git("rm", "--", "old")
        self.git("commit", "-q", "-m", GOOD)
        self.assertEqual(self.scan(self.git("rev-parse", "HEAD"))["findings"], 0)
