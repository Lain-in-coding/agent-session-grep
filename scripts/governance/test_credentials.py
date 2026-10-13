"""Offline scanner adversaries use generated values and synthetic Git history."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from common import GateError
from credential_scan import Scanner, collect_surfaces, read_report
from provision_gitleaks import extract_verified, verify_archive
from test_policy import GitFixture


def fake_value():
    # Not a real credential; construct the provider shape only at runtime.
    return "gh" + "p_" + hashlib.sha256(os.urandom(32)).hexdigest()[:36]


class ReportTests(unittest.TestCase):
    def test_report_required_and_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with self.assertRaises(GateError):
                read_report(path, 0)
            for value in ["", "null", "{}", "not json", '[{"Secret":"hidden"}]']:
                path.write_text(value)
                with self.assertRaises(GateError):
                    read_report(path, 0)
            path.write_text("[]")
            self.assertEqual(read_report(path, 0), 0)
            with self.assertRaises(GateError):
                read_report(path, 2)

    def test_archive_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bad.zip"
            for member in ["../gitleaks.exe", "/gitleaks.exe", "C:/gitleaks.exe"]:
                with zipfile.ZipFile(archive, "w") as handle:
                    handle.writestr(member, b"not executable")
                with self.assertRaises(GateError):
                    extract_verified(archive, "windows_x64")
            with self.assertRaises(GateError):
                verify_archive(archive, "windows_x64")


class CoverageTests(GitFixture):
    def test_added_then_removed_and_old_removed(self):
        from common import GitRepo
        old = fake_value()
        self.base = self.commit("old", old)
        introduced = fake_value()
        self.commit("transient", introduced)
        self.git("rm", "--", "old", "transient")
        self.git("commit", "-q", "-m", "fix(core): Remove obsolete files\n\nKeep only the supported evidence for future reviews.")
        head = self.git("rev-parse", "HEAD")
        surfaces, coverage = collect_surfaces(GitRepo(self.repo), self.base, head)
        payload = b"\n".join(surface.data for surface in surfaces)
        self.assertIn(introduced.encode(), payload)
        self.assertNotIn(old.encode(), payload)
        self.assertGreater(coverage["introduced_files"], 0)

    def test_unknown_binary_and_archive_fail_closed(self):
        from common import GitRepo
        for data in [b"\x00\xffunknown", b"PK\x03\x04not-a-valid-archive"]:
            (self.repo / "binary").write_bytes(data)
            self.git("add", "binary")
            self.git("commit", "-q", "-m", "test(core): Exercise binary coverage\n\nBlock unsupported payloads rather than silently skipping.")
            with self.assertRaises(GateError):
                collect_surfaces(GitRepo(self.repo), self.base, self.git("rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
