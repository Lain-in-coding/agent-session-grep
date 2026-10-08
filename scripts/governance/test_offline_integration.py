"""Required live pinned-scanner fixtures. Set GOVERNANCE_TEST_ARCHIVE offline."""
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from common import GateError, GitRepo, MAX_BLOB
from credential_scan import Scanner, Surface, collect_surfaces, content_surfaces
from provision_gitleaks import extract_verified, native_platform
from test_credentials import fake_value
from test_policy import GitFixture, GOOD

ROOT = Path(__file__).resolve().parent


class ArchiveTests(unittest.TestCase):
    def test_verified_bytes_still_require_safe_structure(self):
        for name in ["../gitleaks.exe", "/gitleaks.exe", "C:/gitleaks.exe"]:
            memory = io.BytesIO()
            with zipfile.ZipFile(memory, "w") as archive:
                archive.writestr(name, b"malicious")
            with patch("provision_gitleaks.verify_archive", return_value=memory.getvalue()):
                with self.assertRaises(GateError):
                    extract_verified("unused", "windows_x64")

    def test_links_and_duplicate_members_reject(self):
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w") as archive:
            info = zipfile.ZipInfo("gitleaks.exe")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "elsewhere")
        with patch("provision_gitleaks.verify_archive", return_value=memory.getvalue()):
            with self.assertRaises(GateError):
                extract_verified("unused", "windows_x64")
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode="w:gz") as archive:
            info = tarfile.TarInfo("gitleaks")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
        with patch("provision_gitleaks.verify_archive", return_value=memory.getvalue()):
            with self.assertRaises(GateError):
                extract_verified("unused", "linux_x64")

    def test_oversize_and_deep_decoding_reject(self):
        for data in [b"x" * (MAX_BLOB + 1), b"\xff\xfeUTF16", b"\x00binary"]:
            with self.assertRaises(GateError):
                content_surfaces("tree", "data", data)
        data = b"This is recognisable synthetic text content for decoding checks."
        for _ in range(6):
            data = base64.b64encode(data)
        with self.assertRaises(GateError):
            content_surfaces("tree", "data", data)

    def test_changed_or_moved_reviewed_sqlite_is_not_exempt(self):
        for path in ["unknown.db", "crates/agent-session-grep-provider-cursor/tests/golden/basic.db"]:
            with self.assertRaises(GateError):
                content_surfaces("tree", path, b"SQLite format 3\x00changed")


class OfflineIntegrationTests(GitFixture):
    @classmethod
    def setUpClass(cls):
        archive = os.environ.get("GOVERNANCE_TEST_ARCHIVE")
        if not archive:
            raise RuntimeError("Set GOVERNANCE_TEST_ARCHIVE to the pinned offline archive; integration is required, not skipped")
        cls.archive = Path(archive).resolve(strict=True)
        cls.scanner = Scanner(cls.archive)

    def test_clean_and_inline_allow_local_config_environment(self):
        self.scanner.scan([Surface("tree", "README.md", b"Only public synthetic text.\n")])
        value = fake_value()
        malicious = b'title="candidate"\n[allowlist]\nregexes=[".*"]\n'
        with patch.dict(os.environ, {"GITLEAKS_CONFIG_TOML": malicious.decode(),
                                    "GITLEAKS_CONFIG": str(self.repo / "malicious.toml")}):
            with self.assertRaisesRegex(GateError, "credential-findings"):
                self.scanner.scan([Surface("tree", "leak.txt", (value + " # gitleaks:allow\n").encode()),
                                   Surface("tree", ".gitleaks.toml", malicious),
                                   Surface("tree", ".gitleaksignore", b"*\n")])

    def test_metadata_and_path_leaks(self):
        for surface in [Surface("metadata", "", fake_value().encode()),
                        Surface("metadata", "", ("Human <" + fake_value() + "@example.org>").encode())]:
            with self.assertRaisesRegex(GateError, "credential-findings"):
                self.scanner.scan([surface])
        name = fake_value()
        head = self.commit(name, "innocent")
        surfaces, _ = collect_surfaces(GitRepo(self.repo), self.base, head)
        with self.assertRaisesRegex(GateError, "credential-findings"):
            self.scanner.scan(surfaces)

    def test_intermediate_only_leak_not_removed_prebase(self):
        old = fake_value()
        self.base = self.commit("old.txt", old)
        self.git("rm", "old.txt")
        self.git("commit", "-q", "-m", GOOD)
        head = self.git("rev-parse", "HEAD")
        surfaces, _ = collect_surfaces(GitRepo(self.repo), self.base, head)
        self.scanner.scan(surfaces)
        whole_history, _ = collect_surfaces(GitRepo(self.repo), None, head)
        with self.assertRaisesRegex(GateError, "credential-findings"):
            self.scanner.scan(whole_history)
        self.commit("transient.txt", fake_value())
        self.git("rm", "transient.txt")
        self.git("commit", "-q", "-m", GOOD)
        surfaces, _ = collect_surfaces(GitRepo(self.repo), self.base, self.git("rev-parse", "HEAD"))
        with self.assertRaisesRegex(GateError, "credential-findings"):
            self.scanner.scan(surfaces)

    def test_message_leak_and_reused_blob_new_path(self):
        value = fake_value()
        head = self.commit("one", "one", GOOD + "\n" + value)
        surfaces, _ = collect_surfaces(GitRepo(self.repo), self.base, head)
        with self.assertRaisesRegex(GateError, "credential-findings"):
            self.scanner.scan(surfaces)
        # Same benign blob is still checked in its new filename context.
        renamed = fake_value()
        self.git("mv", "one", renamed)
        self.git("commit", "-q", "-m", GOOD)
        surfaces, coverage = collect_surfaces(GitRepo(self.repo), head, self.git("rev-parse", "HEAD"))
        self.assertEqual(coverage["introduced_files"], 1)
        with self.assertRaisesRegex(GateError, "credential-findings"):
            self.scanner.scan(surfaces)

    def test_offline_provision_keeps_archive_license_and_refuses_overwrite(self):
        destination = Path(self.temp.name) / "provisioned"
        command = [sys.executable, str(ROOT / "provision_gitleaks.py"),
                   "--archive-file", str(self.archive), "--output-dir", str(destination)]
        proc = subprocess.run(command, capture_output=True)
        self.assertEqual(proc.returncode, 0)
        from provision_gitleaks import asset_name
        self.assertEqual((destination / asset_name(native_platform())).read_bytes(), self.archive.read_bytes())
        self.assertTrue((destination / "LICENSE").is_file())
        proc = subprocess.run(command, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(str(destination).encode(), proc.stderr)

    def test_bad_binary_never_executed_and_missing_archive(self):
        bad = self.repo / "fake.exe"
        bad.write_bytes(b"not a pinned archive")
        with patch("credential_scan.run") as execute:
            for archive in [bad, self.repo / "missing.zip"]:
                with self.assertRaises((GateError, OSError)):
                    Scanner(archive)
            execute.assert_not_called()

    def test_exit_zero_without_report_and_scanner_error(self):
        for response in [(0, b""), (2, b"private diagnostic")]:
            with patch("credential_scan.run", side_effect=[(0, b"8.30.1\n"), response]):
                with self.assertRaises(GateError):
                    self.scanner.scan([Surface("metadata", "", b"benign")])
        with patch("credential_scan.run", side_effect=GateError("tool-timeout")):
            with self.assertRaisesRegex(GateError, "tool-timeout"):
                self.scanner.scan([Surface("metadata", "", b"benign")])

    def test_cli_metadata_leaks_injection_and_no_raw_output(self):
        head = self.commit("one", "one")
        marker = self.repo / "must-not-exist"
        value = fake_value()
        event = self.event(head)
        event["pull_request"]["body"] += '\n$(echo injected) " ; ' + value
        event_file = self.repo / "event.json"
        event_file.write_text(json.dumps(event))
        command = [sys.executable, str(ROOT / "scan_credentials.py"), "--repo", str(self.repo),
                   "--base", self.base, "--head", head, "--gitleaks-archive", str(self.archive),
                   "--event-file", str(event_file)]
        proc = subprocess.run(command, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(value.encode(), proc.stdout + proc.stderr)
        self.assertNotIn(str(self.repo).encode(), proc.stdout + proc.stderr)
        self.assertNotIn(b"Traceback", proc.stdout + proc.stderr)
        self.assertFalse(marker.exists())
        event["pull_request"]["body"] = GOOD.split("\n\n")[1]
        event_file.write_text(json.dumps(event))
        merge = self.repo / "merge.txt"
        merge.write_text(GOOD + "\n" + value)
        proc = subprocess.run(command + ["--merge-message-file", str(merge)], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(value.encode(), proc.stdout + proc.stderr)

    def test_escaped_merge_identity_and_non_title_event_data_are_scanned(self):
        head = self.commit("one", "one")
        value = fake_value()
        identity = {"name": value, "email": "real@example.org"}
        merge = self.repo / "merge.txt"
        merge.write_text(GOOD, encoding="utf-8")
        payload = self.repo / "metadata.json"
        command = [sys.executable, str(ROOT / "scan_credentials.py"), "--repo", str(self.repo),
                   "--base", self.base, "--head", head, "--gitleaks-archive", str(self.archive)]
        for surface in ("merge", "event"):
            if surface == "merge":
                data = {"author": identity, "committer": identity}
                args = ["--merge-message-file", str(merge), "--merge-metadata-file", str(payload)]
            else:
                data = self.event(head)
                data["pull_request"]["user"] = {"name": value}
                args = ["--event-file", str(payload)]
            escaped = "".join("\\u" + format(ord(c), "04x") for c in value)
            payload.write_text(json.dumps(data).replace(value, escaped), encoding="utf-8")
            proc = subprocess.run(command + args, capture_output=True)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stderr)["code"], "credential-findings")
            self.assertNotIn(value.encode(), proc.stdout + proc.stderr)

    def test_all_reviewed_sqlite_fixtures_are_decoded_and_scanned(self):
        from credential_scan import REVIEWED
        from scan_paths import path_content_surfaces, scan_paths
        credential_surfaces, path_surfaces = [], []
        for name in REVIEWED:
            data = (ROOT.parents[1] / name).read_bytes()
            credential_surfaces.extend(content_surfaces("tree", name, data))
            path_surfaces.extend(path_content_surfaces("tree", name, data))
        self.assertEqual(len(REVIEWED), 5)
        self.assertEqual(sum(x["rows"] for x in REVIEWED.values()), 56)
        self.assertEqual(sum(x["text_cells"] for x in REVIEWED.values()), 136)
        self.assertEqual(sum(x["ff_cells"] for x in REVIEWED.values()), 2)
        self.scanner.scan(credential_surfaces)
        self.assertEqual(scan_paths(path_surfaces, {})["findings"], 0)

    def test_decoded_credential_leak(self):
        value = ("credential=" + fake_value()).encode()
        encodings = [base64.b64encode(value), value.hex().encode(),
                     "".join("%" + format(b, "02x") for b in value).encode()]
        for encoded in encodings:
            with self.assertRaisesRegex(GateError, "credential-findings"):
                self.scanner.scan([Surface("metadata", "", encoded)])

    def test_deep_percent_and_hex_encoding_reject(self):
        for mode in ("percent", "hex"):
            data = b"Synthetic printable text for recursive coverage."
            for _ in range(6):
                data = data.hex().encode() if mode == "hex" else "".join("%" + format(b, "02x") for b in data).encode()
            with self.assertRaisesRegex(GateError, "decode-depth-limit"):
                content_surfaces("tree", "data", data)
