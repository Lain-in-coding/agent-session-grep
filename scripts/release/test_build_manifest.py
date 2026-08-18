#!/usr/bin/env python3
"""Tests for the stdlib-only release manifest and packaging helper."""

from __future__ import annotations

import importlib.util
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("build-manifest.py")
SPEC = importlib.util.spec_from_file_location("build_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILD_MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_MANIFEST)


class BuildManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tempdir.name) / "private-user-workspace"
        (self.workspace / "crates" / "agent-session-grep-cli").mkdir(parents=True)
        (self.workspace / "Cargo.toml").write_text(
            """[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"0.1.0\"\n""",
            encoding="utf-8",
        )
        (self.workspace / "Cargo.lock").write_text(
            """version = 4\n\n[[package]]\nname = \"agent-session-grep-cli\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"dependency-a\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc123\"\n\n[[package]]\nname = \"dependency-b\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"def456\"\n""",
            encoding="utf-8",
        )
        for name in (
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "CHANGELOG.md",
            "SECURITY.md",
            "NOTICE",
        ):
            (self.workspace / name).write_text(f"synthetic {name}\n", encoding="utf-8")
        self.binary = self.workspace / "agent-session-grep"
        self.binary.write_bytes(b"synthetic release binary\n")
        workspace_id = "path+file:///private/user/repo/crates/agent-session-grep-cli#0.1.0"
        dependency_a_id = "registry+https://github.com/rust-lang/crates.io-index#dependency-a@1.2.3"
        dependency_b_id = "registry+https://github.com/rust-lang/crates.io-index#dependency-b@2.0.0"
        self.metadata = self.workspace / "cargo-metadata.json"
        self.metadata.write_text(
            json.dumps(
                {
                    "version": 1,
                    "workspace_members": [workspace_id],
                    "workspace_root": "/private/user/repo",
                    "target_directory": "/private/user/repo/target",
                    "packages": [
                        {
                            "id": workspace_id,
                            "name": "agent-session-grep-cli",
                            "version": "0.1.0",
                            "source": None,
                            "license": "MIT OR Apache-2.0",
                            "license_file": None,
                            "manifest_path": "/private/user/repo/crates/agent-session-grep-cli/Cargo.toml",
                        },
                        {
                            "id": dependency_a_id,
                            "name": "dependency-a",
                            "version": "1.2.3",
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "license": "MIT",
                            "license_file": None,
                            "manifest_path": "/private/cargo/dependency-a/Cargo.toml",
                        },
                        {
                            "id": dependency_b_id,
                            "name": "dependency-b",
                            "version": "2.0.0",
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "license": None,
                            "license_file": "/private/cargo/dependency-b/LICENSE",
                            "manifest_path": "/private/cargo/dependency-b/Cargo.toml",
                        },
                    ],
                    "resolve": {
                        "nodes": [
                            {"id": workspace_id, "dependencies": [dependency_a_id, dependency_b_id]},
                            {"id": dependency_a_id, "dependencies": []},
                            {"id": dependency_b_id, "dependencies": []},
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_release_contract_rejects_tag_or_lock_version_drift(self) -> None:
        BUILD_MANIFEST.validate_release_contract(
            self.workspace, "v0.1.0", "0.1.0", self.metadata
        )
        with self.assertRaisesRegex(ValueError, "tag"):
            BUILD_MANIFEST.validate_release_contract(
                self.workspace, "v0.2.0", "0.1.0", self.metadata
            )
        lock_path = self.workspace / "Cargo.lock"
        lock_path.write_text(
            lock_path.read_text(encoding="utf-8").replace(
                'name = "agent-session-grep-cli"\nversion = "0.1.0"',
                'name = "agent-session-grep-cli"\nversion = "9.9.9"',
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            BUILD_MANIFEST.validate_release_contract(
                self.workspace, "v0.1.0", "0.1.0", self.metadata
            )

    def test_dependency_inventory_is_path_free_and_honest_about_license_data(self) -> None:
        output_dir = self.workspace / "inventory"
        json_path, csv_path = BUILD_MANIFEST.write_dependency_inventory(
            self.workspace, self.metadata, "0.1.0", output_dir
        )
        report = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertFalse(report["spdx_document"])
        self.assertEqual(report["dependency_count"], 2)
        missing = next(
            dependency
            for dependency in report["dependencies"]
            if dependency["name"] == "dependency-b"
        )
        self.assertIsNone(missing["license_declared"])
        self.assertTrue(missing["license_file_present"])
        self.assertEqual(
            missing["license_status"], "license_file_declared_metadata_not_inspected"
        )
        combined = json_path.read_text(encoding="utf-8") + csv_path.read_text(
            encoding="utf-8"
        )
        self.assertNotIn("private-user-workspace", combined)
        self.assertNotIn("/private/", combined)

    def test_package_is_deterministic_and_contains_only_the_release_allowlist(self) -> None:
        inventory_dir = self.workspace / "inventory"
        inventory_json, inventory_csv = BUILD_MANIFEST.write_dependency_inventory(
            self.workspace, self.metadata, "0.1.0", inventory_dir
        )
        required_tail = {
            "agent-session-grep",
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "CHANGELOG.md",
            "SECURITY.md",
            "NOTICE",
            "THIRD-PARTY-DEPENDENCIES.json",
            "THIRD-PARTY-DEPENDENCIES.csv",
        }
        for archive_format in ("tar.gz", "zip"):
            with self.subTest(archive_format=archive_format):
                first_dir = self.workspace / f"first-{archive_format.replace('.', '-')}"
                second_dir = self.workspace / f"second-{archive_format.replace('.', '-')}"
                first_archive, first_manifest = BUILD_MANIFEST.package_release(
                    workspace=self.workspace,
                    binary=self.binary,
                    dependency_json=inventory_json,
                    dependency_csv=inventory_csv,
                    target="x86_64-unknown-linux-gnu",
                    tag="v0.1.0",
                    version="0.1.0",
                    source_commit="a" * 40,
                    source_date_epoch=1_700_000_000,
                    archive_format=archive_format,
                    output_dir=first_dir,
                )
                second_archive, _ = BUILD_MANIFEST.package_release(
                    workspace=self.workspace,
                    binary=self.binary,
                    dependency_json=inventory_json,
                    dependency_csv=inventory_csv,
                    target="x86_64-unknown-linux-gnu",
                    tag="v0.1.0",
                    version="0.1.0",
                    source_commit="a" * 40,
                    source_date_epoch=1_700_000_000,
                    archive_format=archive_format,
                    output_dir=second_dir,
                )
                self.assertEqual(
                    BUILD_MANIFEST.sha256_file(first_archive),
                    BUILD_MANIFEST.sha256_file(second_archive),
                )
                manifest = json.loads(first_manifest.read_text(encoding="utf-8"))
                self.assertTrue(manifest["release"]["unsigned"])
                self.assertEqual(manifest["release"]["source_commit"], "a" * 40)
                self.assertEqual(
                    manifest["archive"]["sha256"],
                    BUILD_MANIFEST.sha256_file(first_archive),
                )
                self.assertNotIn(
                    "private-user-workspace", first_manifest.read_text(encoding="utf-8")
                )
                if archive_format == "zip":
                    with zipfile.ZipFile(first_archive) as archive:
                        names = archive.namelist()
                else:
                    with tarfile.open(first_archive, "r:gz") as archive:
                        names = archive.getnames()
                self.assertEqual({Path(name).name for name in names}, required_tail)
                self.assertTrue(all(name.startswith("agent-session-grep-v0.1.0-") for name in names))

    def test_checksum_file_is_sorted_and_does_not_hash_itself(self) -> None:
        output_dir = self.workspace / "checksums"
        output_dir.mkdir()
        (output_dir / "b.zip").write_bytes(b"b")
        (output_dir / "a.tar.gz").write_bytes(b"a")
        (output_dir / "ignored.txt").write_text("ignored", encoding="utf-8")
        checksum_path = output_dir / "SHA256SUMS"
        BUILD_MANIFEST.write_checksums(output_dir, checksum_path)
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual([line.split("  ", 1)[1] for line in lines], ["a.tar.gz", "b.zip"])
        BUILD_MANIFEST.write_checksums(output_dir, checksum_path)
        self.assertNotIn("SHA256SUMS", checksum_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
