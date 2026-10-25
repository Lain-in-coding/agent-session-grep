#!/usr/bin/env python3
"""Tests for the stdlib-only release manifest and packaging helper."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
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
        # Resolve only the trusted, newly allocated test root (e.g. macOS /var
        # alias). Production input validation must still reject linked paths.
        self.workspace = Path(self.tempdir.name).resolve() / "private-user-workspace"
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
        source_root = MODULE_PATH.parents[2]
        for name in (*BUILD_MANIFEST.PACKAGE_INSTALLERS,
                     *BUILD_MANIFEST.UPDATE_CHECK_HELPERS,
                     *BUILD_MANIFEST.UNINSTALL_HELPERS):
            destination = self.workspace / "scripts/install" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_root / "scripts/install" / name, destination)
        guide = self.workspace / "docs/operations/INSTALL-AND-UPGRADE.md"
        guide.parent.mkdir(parents=True)
        guide.write_text("Synthetic install instructions.\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def native_image(target: str, label: bytes, *, gui: bool = False) -> bytes:
        """Header-only synthetic bytes, never claimed to be runnable binaries."""
        content = bytearray(256)
        if target.endswith("windows-msvc"):
            content[:2] = b"MZ"
            struct.pack_into("<I", content, 60, 64)
            content[64:68] = b"PE\0\0"
            struct.pack_into("<H", content, 68, 0x8664)
            struct.pack_into("<H", content, 84, 240)
            struct.pack_into("<H", content, 88, 0x20B)
            struct.pack_into("<H", content, 156, 2 if gui else 3)
        elif target.endswith("linux-gnu"):
            content[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HH", content, 16, 2, 62)
        else:
            content[:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<III", content, 4,
                             0x01000007 if target.startswith("x86_64") else 0x0100000C, 0, 2)
        return bytes(content) + label

    def managed_arguments(self, target: str = "x86_64-unknown-linux-gnu", *,
                          schemas: tuple[int, int] = (19, 1)) -> dict:
        # Default is an explicit historical package fixture. Current-package
        # cases derive their versions from the shipped normative source.
        suffix = ".exe" if target.endswith("windows-msvc") else ""
        binary = self.workspace / f"agent-session-grep{suffix}"
        launcher = self.workspace / f"agent-session-grep-launcher{suffix}"
        supervisor = self.workspace / f"asg-supervisor{suffix}"
        binary.write_bytes(self.native_image(target, b"synthetic application"))
        launcher.write_bytes(self.native_image(target, b"synthetic launcher"))
        supervisor.write_bytes(self.native_image(target, b"synthetic supervisor", gui=True))
        inventory_json, inventory_csv = BUILD_MANIFEST.write_dependency_inventory(
            self.workspace, self.metadata, "0.1.0", self.workspace / "inventory"
        )
        return dict(
            workspace=self.workspace, binary=binary, launcher=launcher, supervisor=supervisor,
            dependency_json=inventory_json, dependency_csv=inventory_csv,
            target=target, tag="v0.1.0", version="0.1.0", source_commit="a" * 40,
            source_date_epoch=1_700_000_000, archive_format="tar.gz",
            output_dir=self.workspace / "managed", managed_layout=True,
            catalog_schema=schemas[0], control_schema=schemas[1],
        )

    def test_managed_archives_all_targets_have_exact_metadata_digests_and_modes(self) -> None:
        for target in sorted(BUILD_MANIFEST.MANAGED_TARGETS):
            for archive_format in ("zip", "tar.gz"):
                with self.subTest(target=target, archive_format=archive_format):
                    args = self.managed_arguments(target)
                    args["archive_format"] = archive_format
                    archive_path, manifest_path = BUILD_MANIFEST.package_release(**args)
                    first_bytes = archive_path.read_bytes()
                    BUILD_MANIFEST.package_release(**args)
                    self.assertEqual(first_bytes, archive_path.read_bytes())
                    manifest = json.loads(manifest_path.read_bytes())
                    if archive_format == "zip":
                        with zipfile.ZipFile(archive_path) as archive:
                            contents = {item.filename: (archive.read(item), item.external_attr >> 16)
                                        for item in archive.infolist()}
                    else:
                        with tarfile.open(archive_path) as archive:
                            self.assertTrue(all(item.isfile() for item in archive))
                            contents = {item.name: (archive.extractfile(item).read(), item.mode)
                                        for item in archive}
                    self.assertEqual(len(contents), 21)
                    root = manifest["archive"]["root"] + "/"
                    contents = {name.removeprefix(root): entry for name, entry in contents.items()}
                    app_name = args["binary"].name
                    alias = "asg.exe" if app_name.endswith(".exe") else "asg"
                    self.assertEqual(contents[app_name], (args["launcher"].read_bytes(), 0o755))
                    self.assertEqual(contents[app_name], contents[alias])
                    pointer = json.loads(contents["current.json"][0])
                    app_sha = BUILD_MANIFEST.sha256_file(args["binary"])
                    self.assertEqual(pointer, {
                        "schema": "asg.current/v1", "generation": 1, "version": "0.1.0",
                        "dir": f"versions/0.1.0-{app_sha[:12]}", "app": app_name,
                        "app_sha256": app_sha, "launcher_protocol": 1,
                        "activated_at": "2023-11-14T22:13:20Z",
                    })
                    self.assertEqual(contents[f"{pointer['dir']}/{app_name}"],
                                     (args["binary"].read_bytes(), 0o755))
                    self.assertEqual(contents[f"{pointer['dir']}/{args['supervisor'].name}"],
                                     (args["supervisor"].read_bytes(), 0o755))
                    self.assertEqual(json.loads(contents[f"{pointer['dir']}/release.json"][0]), {
                        "schema": "asg.version/v1", "version": "0.1.0", "target": target,
                        "source_commit": "a" * 40, "app_sha256": app_sha,
                        "catalog_schema": 19, "control_schema": 1,
                        "launcher_protocol_min": 1, "launcher_protocol_max": 1,
                        "built_at": "2023-11-14T22:13:20Z",
                    })
                    for entry in manifest["archive"]["files"]:
                        content, mode = contents[entry["name"].removeprefix(root)]
                        self.assertEqual(entry["sha256"], BUILD_MANIFEST.sha256_bytes(content))
                        self.assertEqual(entry["size_bytes"], len(content))
                        self.assertEqual(entry["mode"], f"{mode:04o}")
                    self.assertEqual(contents["package-install.sh"][1], 0o755)
                    self.assertEqual(contents["package-install.ps1"][1], 0o644)
                    source_root = MODULE_PATH.parents[2]
                    for helper in (*BUILD_MANIFEST.UPDATE_CHECK_HELPERS, *BUILD_MANIFEST.UNINSTALL_HELPERS):
                        name = f"{pointer['dir']}/helpers/{helper}"
                        self.assertEqual(
                            contents[name],
                            ((source_root / "scripts/install" / helper).read_bytes(),
                             0o755 if helper.endswith(".sh") else 0o644),
                        )
                    tsv = contents["PACKAGE-MANIFEST.tsv"][0]
                    self.assertIn(f"{pointer['dir']}/helpers/update-check.sh".encode(), tsv)
                    self.assertIn(f"supervisor\t{args['supervisor'].name}\n".encode(), tsv)
                    self.assertIn(f"supervisor_sha256\t{BUILD_MANIFEST.sha256_file(args['supervisor'])}\n".encode(), tsv)
                    self.assertEqual(manifest["install_manifest_sha256"], BUILD_MANIFEST.sha256_bytes(tsv))
                    for row in tsv.decode().splitlines():
                        if row.startswith("file\t"):
                            _, digest, mode, size, name = row.split("\t")
                            self.assertEqual(digest, BUILD_MANIFEST.sha256_bytes(contents[name][0]))
                            self.assertEqual(int(size), len(contents[name][0]))
                            self.assertEqual(int(mode, 8), contents[name][1])

    def test_managed_rejects_missing_wrong_or_shared_launcher_and_schema(self) -> None:
        args = self.managed_arguments()
        for change in ({"launcher": None}, {"supervisor": None}, {"catalog_schema": None}, {"control_schema": 0},
                       {"managed_layout": False}, {"target": "i686-unknown-linux-gnu"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                BUILD_MANIFEST.package_release(**{**args, **change})
        args["launcher"].unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            BUILD_MANIFEST.package_release(**args)
        args["launcher"].write_bytes(self.native_image("x86_64-pc-windows-msvc", b"wrong"))
        with self.assertRaisesRegex(ValueError, "target"):
            BUILD_MANIFEST.package_release(**args)
        args["launcher"].write_bytes(args["binary"].read_bytes())
        with self.assertRaisesRegex(ValueError, "distinct"):
            BUILD_MANIFEST.package_release(**args)

    def test_supervisor_header_name_and_gui_are_checked_before_archive_creation(self) -> None:
        for target in sorted(BUILD_MANIFEST.MANAGED_TARGETS):
            args = self.managed_arguments(target)
            correct = args["supervisor"].read_bytes()
            for bad in (b"not executable", self.native_image("x86_64-unknown-linux-gnu", b"wrong")
                        if "windows" in target else self.native_image("x86_64-pc-windows-msvc", b"wrong", gui=True)):
                args["supervisor"].write_bytes(bad)
                with self.subTest(target=target), self.assertRaises(ValueError):
                    BUILD_MANIFEST.package_release(**args)
                self.assertFalse(args["output_dir"].exists())
            args["supervisor"].write_bytes(correct)
        args = self.managed_arguments("x86_64-pc-windows-msvc")
        args["supervisor"].write_bytes(self.native_image(args["target"], b"console supervisor"))
        with self.assertRaisesRegex(ValueError, "GUI"):
            BUILD_MANIFEST.package_release(**args)
        args["supervisor"] = self.workspace / "different.exe"
        args["supervisor"].write_bytes(correct)
        with self.assertRaisesRegex(ValueError, "names"):
            BUILD_MANIFEST.package_release(**args)

    def test_schema_versions_follow_source_constants_and_fail_on_ambiguity(self) -> None:
        source = self.workspace / "crates/agent-session-grep-adapters-sqlite/src"
        source.mkdir(parents=True)
        (source / "lib.rs").write_text("pub const SCHEMA_VERSION: i64 = 19;\n")
        (source / "control.rs").write_text("const VERSION: i64 = 1;\n")
        self.assertEqual(BUILD_MANIFEST._source_schemas(self.workspace), (19, 1))
        (source / "lib.rs").write_text("pub const SCHEMA_VERSION: i64 = 20;\n")
        self.assertEqual(BUILD_MANIFEST._source_schemas(self.workspace), (20, 1))
        (source / "lib.rs").write_text("pub const SCHEMA_VERSION: i64 = 21;\n")
        self.assertEqual(BUILD_MANIFEST._source_schemas(self.workspace), (21, 1))
        (source / "control.rs").write_text(
            "const VERSION: i64 = 2;\npub const CONTROL_SCHEMA_VERSION: i64 = VERSION;\n")
        self.assertEqual(BUILD_MANIFEST._source_schemas(self.workspace), (21, 2))
        (source / "lib.rs").write_text("pub const SCHEMA_VERSION: i64 = 22;\n")
        self.assertEqual(BUILD_MANIFEST._source_schemas(self.workspace), (22, 2))
        (source / "control.rs").write_text("const VERSION: i64 = 0;\n")
        with self.assertRaises(ValueError):
            BUILD_MANIFEST._source_schemas(self.workspace)

    def test_current_package_cli_uses_source_schemas_without_relabeling_legacy_fixtures(self) -> None:
        schemas = BUILD_MANIFEST._source_schemas(MODULE_PATH.parents[2])
        self.assertEqual(schemas, (22, 2))
        source = self.workspace / "crates/agent-session-grep-adapters-sqlite/src"
        source.mkdir(parents=True)
        (source / "lib.rs").write_text(f"pub const SCHEMA_VERSION: i64 = {schemas[0]};\n", encoding="utf-8")
        (source / "control.rs").write_text(f"const VERSION: i64 = {schemas[1]};\n", encoding="utf-8")
        for target in sorted(BUILD_MANIFEST.MANAGED_TARGETS):
            args = self.managed_arguments(target)
            self.assertEqual((args["catalog_schema"], args["control_schema"]), (19, 1))
            for archive_format in ("zip", "tar.gz"):
                with self.subTest(target=target, archive_format=archive_format):
                    command = [sys.executable, "-B", str(MODULE_PATH), "package", "--managed-layout",
                               "--schemas-from-source", "--archive-format", archive_format]
                    for option in ("workspace", "binary", "launcher", "supervisor", "dependency_json",
                                   "dependency_csv", "target", "tag", "version", "source_commit",
                                   "source_date_epoch", "output_dir"):
                        command += ["--" + option.replace("_", "-"), str(args[option])]
                    result = subprocess.run(command, capture_output=True, text=True,
                                            errors="backslashreplace", timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    name = f"agent-session-grep-v{args['version']}-{target}"
                    manifest = json.loads((args["output_dir"] / (name + ".manifest.json")).read_bytes())
                    archive_path = args["output_dir"] / (name + "." + archive_format)
                    if archive_format == "zip":
                        with zipfile.ZipFile(archive_path) as archive:
                            contents = {item.filename: (archive.read(item), item.external_attr >> 16)
                                        for item in archive.infolist()}
                    else:
                        with tarfile.open(archive_path) as archive:
                            self.assertTrue(all(item.isfile() for item in archive))
                            contents = {item.name: (archive.extractfile(item).read(), item.mode)
                                        for item in archive}
                    self.assertEqual(len(contents), 21)
                    self.assertEqual(set(contents), {entry["name"] for entry in manifest["archive"]["files"]})
                    for entry in manifest["archive"]["files"]:
                        payload, mode = contents[entry["name"]]
                        self.assertEqual(entry["sha256"], BUILD_MANIFEST.sha256_bytes(payload))
                        self.assertEqual(entry["size_bytes"], len(payload))
                        self.assertEqual(entry["mode"], f"{mode:04o}")
                    pointer = json.loads(contents[name + "/current.json"][0])
                    release = json.loads(contents[name + "/" + pointer["dir"] + "/release.json"][0])
                    self.assertEqual((release["catalog_schema"], release["control_schema"]), schemas)
                    inventory = contents[name + "/PACKAGE-MANIFEST.tsv"][0]
                    self.assertEqual(manifest["install_manifest_sha256"], BUILD_MANIFEST.sha256_bytes(inventory))
                    self.assertIn(b"\ncatalog_schema\t22\ncontrol_schema\t2\n", inventory)
                    before = self.file_snapshot(args["output_dir"])
                    for explicit in ("--catalog-schema", "--control-schema"):
                        refused = subprocess.run(command + [explicit, "1"], capture_output=True, text=True,
                                                 errors="backslashreplace", timeout=30)
                        self.assertNotEqual(refused.returncode, 0)
                        self.assertIn("no explicit schemas", refused.stderr)
                        self.assertEqual(self.file_snapshot(args["output_dir"]), before)

    def test_git_package_inputs_ignore_checkout_drift_and_reject_missing_or_link_blobs(self) -> None:
        args = self.managed_arguments()
        names = BUILD_MANIFEST.MANAGED_SOURCE_INPUTS
        objects = {name: str(index + 1) * 40 for index, name in enumerate(names)}
        contents = {objects[name]: f"immutable source bytes {name}\n".encode() for name in names}
        tree = b"".join(b"100644 blob " + objects[name].encode() + b"\t" + name.encode() + b"\0"
                        for name in names)
        def git_output(argv):
            if argv[3] == "ls-tree":
                self.assertEqual(argv[6], args["source_commit"])
                return tree
            self.assertEqual(argv[3:5], ["cat-file", "blob"])
            return contents[argv[5]]
        with mock.patch.object(BUILD_MANIFEST.subprocess, "check_output", side_effect=git_output):
            archive_path, _ = BUILD_MANIFEST.package_release(**args, git_package_inputs=True)
        with tarfile.open(archive_path) as archive:
            for name in names:
                member = next(member for member in archive if member.name.endswith("/" + Path(name).name))
                self.assertEqual(archive.extractfile(member).read(), contents[objects[name]])
        for bad in (tree.replace(b"100644", b"120000", 1), tree.split(b"\0", 1)[0] + b"\0"):
            with mock.patch.object(BUILD_MANIFEST.subprocess, "check_output", return_value=bad), self.assertRaises(ValueError):
                BUILD_MANIFEST._git_package_inputs(self.workspace, args["source_commit"])

    def test_archive_rejects_traversal_reserved_names_and_case_collisions(self) -> None:
        for name in ("../escape", "/absolute", "root/../escape", "root/C:drive",
                     "root/back\\slash", "root/NUL.txt", "root/trailing."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                BUILD_MANIFEST._validate_members([(name, b"", 0o644)])
        for names in (("root/asg", "root/asg"), ("root/ASG", "root/asg"),
                      ("root/dir", "root/dir/file"), ("root/dir/file", "root/dir")):
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "collision"):
                BUILD_MANIFEST._validate_members([(name, b"", 0o644) for name in names])
        args = self.managed_arguments()
        for name in (*BUILD_MANIFEST.PACKAGE_INSTALLERS,
                     *BUILD_MANIFEST.UPDATE_CHECK_HELPERS,
                     *BUILD_MANIFEST.UNINSTALL_HELPERS):
            path = self.workspace / "scripts/install" / name
            content = path.read_bytes(); path.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                BUILD_MANIFEST.package_release(**args)
            path.write_bytes(content)

    def powershell_fixture(self, *, broken_launcher: bool = False,
                           broken_supervisor: bool = False,
                           schemas: tuple[int, int] = (19, 1)) -> tuple[Path, Path, Path]:
        compiler = Path(os.environ.get("WINDIR", "")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        if os.name != "nt" or not compiler.is_file() or not shutil.which("pwsh"):
            self.skipTest("Windows .NET Framework compiler and PowerShell required for synthetic process test")
        args = self.managed_arguments("x86_64-pc-windows-msvc", schemas=schemas)

        def compile_fixture(destination: Path, info: str | None, *, supervisor: bool = False) -> None:
            source = destination.with_suffix(".cs")
            literal = json.dumps(info or "not a launcher")
            product = "asg-supervisor" if supervisor else "agent-session-grep"
            reported_version = "9.9.9" if supervisor and broken_supervisor else "0.1.0"
            source.write_text(
                'using System; using System.IO; using System.Text; class Fixture { static int Main(string[] args) {'
                'if(args.Length == 1) { '
                f'if(args[0] == "--version") {{ Console.WriteLine("{product} {reported_version}"); return 0; }}'
                f'if(args[0] == "--asg-launcher-info") {{ Console.WriteLine({literal}); return 0; }}'
                'return 24; } '
                'bool setup = Array.IndexOf(args, "setup") >= 0; '
                'bool path = Array.IndexOf(args, "path") >= 0; '
                'string receipt = Environment.GetEnvironmentVariable("ASG_TEST_COMMAND_RECEIPT"); '
                'if(receipt == null || (!setup && !path)) return 23; '
                'using(var stream = new FileStream(receipt, FileMode.Append, FileAccess.Write, FileShare.Read)) '
                'using(var writer = new BinaryWriter(stream)) { '
                'writer.Write((uint)args.Length); foreach(string arg in args) { '
                'byte[] value = new UTF8Encoding(false).GetBytes(arg); writer.Write((uint)value.Length); writer.Write(value); } } '
                'int code; if(!Int32.TryParse(Environment.GetEnvironmentVariable(setup ? "ASG_TEST_SETUP_EXIT" : "ASG_TEST_PATH_EXIT"), out code)) code = 0; '
                'Console.WriteLine(setup ? "synthetic setup receipt" : "synthetic path receipt"); return code; }}', encoding="utf-8",
            )
            subsystem = "/target:winexe" if supervisor else "/target:exe"
            subprocess.run([str(compiler), "/nologo", subsystem, "/platform:x64",
                            f"/out:{destination}", str(source)], check=True, capture_output=True, timeout=30)

        compile_fixture(args["binary"], None)
        compile_fixture(args["supervisor"], None, supervisor=True)
        info = json.dumps({
            "schema": "asg.launcher-info/v1", "launcher_protocol": 1,
            "target": args["target"], "generation": 1, "version": "0.1.0",
            "source_commit": "a" * 40, "app_sha256": BUILD_MANIFEST.sha256_file(args["binary"]),
            "catalog_schema": args["catalog_schema"], "control_schema": args["control_schema"],
        })
        compile_fixture(args["launcher"], None if broken_launcher else info)
        if broken_launcher or broken_supervisor:
            with self.assertRaises(ValueError):
                BUILD_MANIFEST.package_release(**args, verify_native=True)
            self.assertFalse(args["output_dir"].exists(), "failed native probe must not publish an archive")
        archive, manifest = BUILD_MANIFEST.package_release(**args, verify_native=not (broken_launcher or broken_supervisor))
        checksums = args["output_dir"] / "SHA256SUMS"
        BUILD_MANIFEST.write_checksums(args["output_dir"], checksums)
        extracted = self.workspace / "extracted"
        with tarfile.open(archive) as bundle:
            # All members come from this test's already validated builder.
            bundle.extractall(extracted)
        root = extracted / json.loads(manifest.read_bytes())["archive"]["root"]
        return root, manifest, checksums

    def run_ps_install(self, root: Path, manifest: Path, checksums: Path,
                       prefix: Path | None = None, env: dict | None = None,
                       engine: str = "pwsh", extra_args: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
        command = [shutil.which(engine), "-NoProfile", "-NonInteractive", "-File",
                   str(root / "package-install.ps1"), "-Manifest", str(manifest),
                   "-Checksums", str(checksums)]
        if prefix is not None:
            command += ["-Prefix", str(prefix)]
        command += list(extra_args)
        return subprocess.run(command, capture_output=True, text=True, errors="backslashreplace", env=env, timeout=55)

    def run_ps_install_options(self, root: Path, manifest: Path, checksums: Path,
                               prefix: Path, options: dict, env: dict,
                               engine: str = "pwsh") -> subprocess.CompletedProcess:
        # Fixed script binds structured data; paths/values never become code.
        bindings = {"Manifest": str(manifest), "Checksums": str(checksums),
                    "Prefix": str(prefix), **options}
        runner = (
            '$inputOptions = $env:ASG_TEST_INSTALL_OPTIONS | ConvertFrom-Json; '
            '$bindings = @{}; foreach ($property in $inputOptions.PSObject.Properties) '
            '{ $bindings[$property.Name] = $property.Value }; '
            '& $env:ASG_TEST_INSTALL_SCRIPT @bindings; if (-not $?) { exit 1 }'
        )
        return subprocess.run(
            [shutil.which(engine), "-NoProfile", "-NonInteractive", "-Command", runner],
            env={**env, "ASG_TEST_INSTALL_OPTIONS": json.dumps(bindings),
                 "ASG_TEST_INSTALL_SCRIPT": str(root / "package-install.ps1")},
            capture_output=True, text=True, errors="backslashreplace", timeout=55,
        )

    @staticmethod
    def command_receipts(path: Path) -> list[list[str]]:
        if not path.exists():
            return []
        data = path.read_bytes()
        if len(data) > 131_072:
            raise AssertionError("synthetic command receipts exceed finite test budget")
        position = 0
        calls = []
        while position < len(data):
            count, = struct.unpack_from("<I", data, position)
            position += 4
            if count > 64:
                raise AssertionError("unexpected synthetic argument count")
            args = []
            for _ in range(count):
                length, = struct.unpack_from("<I", data, position)
                position += 4
                end = position + length
                if end > len(data):
                    raise AssertionError("torn synthetic command receipt")
                args.append(data[position:end].decode("utf-8"))
                position = end
            calls.append(args)
        return calls

    @staticmethod
    def file_snapshot(root: Path) -> dict[str, bytes]:
        return {str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*") if path.is_file()}

    def test_powershell_six_host_history_forwarding_records_literal_argv_and_legacy_repeat(self) -> None:
        schemas = BUILD_MANIFEST._source_schemas(MODULE_PATH.parents[2])
        self.assertEqual(schemas, (22, 2))
        root, manifest, checksums = self.powershell_fixture(schemas=schemas)
        prefix = self.workspace / "six host installation"
        receipt = self.workspace / "windows-command-receipt.bin"
        profile = self.workspace / "isolated-profile"
        profile.mkdir()
        sentinel = profile / "unrelated-config.txt"
        sentinel.write_bytes(b"unrelated config must remain unchanged\n")
        histories = {}
        for provider, parameter in [
            ("claude-code", "ClaudeHistory"), ("codex", "CodexHistory"),
            ("workbuddy", "WorkBuddyHistory"), ("zcode", "ZCodeHistory"),
            ("deepseek-harness", "DeepSeekHarnessHistory"), ("antigravity", "AntigravityHistory"),
        ]:
            path = profile / (provider + " history & literal;$(not-evaluated) 'quoted' [x]")
            path.mkdir()
            (path / "source.txt").write_bytes(b"synthetic original history\n")
            histories[provider] = (parameter, str(path) + "\\")
        unselected = profile / "unselected-source"
        unselected.mkdir()
        (unselected / "source.txt").write_bytes(b"not selected\n")
        before = self.file_snapshot(profile)
        package_before = self.file_snapshot(root)
        catalog = str(profile / "catalog & literal;$(not-evaluated).db")
        hosts = ["claude", "codex", "workbuddy", "zcode", "deepseek-harness", "antigravity"]
        options = {"HostChoice": hosts, "Catalog": catalog, "NoAutostart": True,
                   **{parameter: path for parameter, path in histories.values()}}
        env = {**os.environ, "ASG_TEST_COMMAND_RECEIPT": str(receipt),
               "ASG_TEST_SETUP_EXIT": "10", "ASG_TEST_PATH_EXIT": "0",
               "HOME": str(profile), "USERPROFILE": str(profile),
               "LOCALAPPDATA": str(self.workspace / "powershell-runtime-cache")}
        result = self.run_ps_install_options(root, manifest, checksums, prefix, options, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        setup = ["--robot", "--db", catalog, "setup", "--install-prefix", str(prefix)]
        for host in hosts:
            setup += ["--host", host]
        for provider, (_, path) in histories.items():
            setup += ["--history", provider, path]
        setup += ["--no-autostart"]
        self.assertEqual(self.command_receipts(receipt), [
            setup, ["--robot", "--db", catalog, "path", "install", "--install-prefix", str(prefix)]])
        self.assertEqual(self.file_snapshot(profile), before)
        self.assertEqual(self.file_snapshot(root), package_before)
        installed = self.file_snapshot(prefix)
        legacy = {"HostChoice": ["Claude", "Codex"], "NoPath": True,
                  "ClaudeHistory": histories["claude-code"][1], "CodexHistory": histories["codex"][1]}
        result = self.run_ps_install_options(root, manifest, checksums, prefix, legacy, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.command_receipts(receipt)[2:], [[
            "--robot", "setup", "--install-prefix", str(prefix), "--host", "claude", "--host", "codex",
            "--history", "claude-code", histories["claude-code"][1], "--history", "codex", histories["codex"][1]]])
        self.assertEqual(self.file_snapshot(prefix), installed)
        self.assertEqual(self.file_snapshot(profile), before)
        # A normal -File invocation remains supported for a single new host.
        result = self.run_ps_install(root, manifest, checksums, prefix, env,
            extra_args=("-HostChoice", "workbuddy", "-WorkBuddyHistory", histories["workbuddy"][1], "-NoPath"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.command_receipts(receipt)[3:], [[
            "--robot", "setup", "--install-prefix", str(prefix), "--host", "workbuddy",
            "--history", "workbuddy", histories["workbuddy"][1]]])
        self.assertEqual(self.file_snapshot(prefix), installed)
        if shutil.which("powershell"):
            # Windows PowerShell 5.1 uses legacy native argv quoting. Exercise
            # the actual host/history call as well as the old no-host smoke.
            result = self.run_ps_install_options(root, manifest, checksums, prefix, options, env,
                                                 engine="powershell")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.command_receipts(receipt)[4:], [setup,
                ["--robot", "--db", catalog, "path", "install", "--install-prefix", str(prefix)]])
            self.assertEqual(self.file_snapshot(prefix), installed)
            self.assertEqual(self.file_snapshot(profile), before)

    def test_powershell_setup_failure_retains_verified_install_and_never_registers_path(self) -> None:
        root, manifest, checksums = self.powershell_fixture()
        prefix = self.workspace / "setup failed install"
        receipt = self.workspace / "failed-command-receipt.bin"
        env = {**os.environ, "ASG_TEST_COMMAND_RECEIPT": str(receipt), "ASG_TEST_SETUP_EXIT": "7"}
        result = self.run_ps_install(root, manifest, checksums, prefix, env,
            extra_args=("-HostChoice", "zcode", "-ZCodeHistory", "literal selected history"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected setup failed", result.stderr)
        self.assertEqual(self.command_receipts(receipt), [[
            "--robot", "setup", "--install-prefix", str(prefix), "--host", "zcode",
            "--history", "zcode", "literal selected history"]])
        self.assertTrue((prefix / "package-install.json").is_file())
        self.assertEqual((prefix / "release.manifest.json").read_bytes(), manifest.read_bytes())
        self.assertEqual((prefix / "SHA256SUMS").read_bytes(), checksums.read_bytes())
        self.assertTrue((prefix / "agent-session-grep.exe").is_file())

    def test_powershell_invalid_setup_options_reject_before_prefix_lock_or_staging_writes(self) -> None:
        if not shutil.which("pwsh"):
            self.skipTest("PowerShell unavailable for real parameter-binding test")
        root = self.workspace / "scripts/install"
        manifest = self.workspace / "missing.manifest.json"
        checksums = self.workspace / "missing.SHA256SUMS"
        prefix = self.workspace / "must-not-create/installation"
        cases = [
            ({"HostChoice": ["claude", "CLAUDE"]}, "duplicate HostChoice"),
            ({"Catalog": "synthetic.db"}, "post-install options require explicit HostChoice"),
            ({"NoPath": True}, "post-install options require explicit HostChoice"),
            ({"NoAutostart": True}, "post-install options require explicit HostChoice"),
        ]
        for parameter in ["ClaudeHistory", "CodexHistory", "WorkBuddyHistory", "ZCodeHistory",
                          "DeepSeekHarnessHistory", "AntigravityHistory"]:
            cases += [({parameter: "literal history"}, "corresponding explicit HostChoice"),
                      ({"HostChoice": ["claude"], parameter: "  "}, "empty history option value")]
        receipt = self.workspace / "never-command-receipt.bin"
        env = {**os.environ, "ASG_TEST_COMMAND_RECEIPT": str(receipt)}
        before = self.file_snapshot(self.workspace)
        for options, error in cases:
            with self.subTest(options=options):
                result = self.run_ps_install_options(root, manifest, checksums, prefix, options, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                self.assertEqual(self.file_snapshot(self.workspace), before)
                self.assertFalse(prefix.parent.exists())
                self.assertFalse(receipt.exists())
        # Unknown, duplicate and missing parameters fail in PowerShell's binder.
        for args in [
            ("-HostChoice", "tencent-codebuddy"), ("-UnknownOption", "value"),
            ("-WorkBuddyHistory", "one", "-WorkBuddyHistory", "two"),
            ("-HostChoice", "workbuddy", "-WorkBuddyHistory"),
        ]:
            with self.subTest(args=args):
                result = self.run_ps_install(root, manifest, checksums, prefix, env, extra_args=args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("required regular file", result.stderr)
                self.assertEqual(self.file_snapshot(self.workspace), before)
                self.assertFalse(prefix.parent.exists())

    def test_powershell_rejects_flag_history_and_nul_before_any_installer_write(self) -> None:
        if not shutil.which("pwsh"):
            self.skipTest("PowerShell unavailable for real parameter-binding test")
        root = self.workspace / "scripts/install"
        manifest = self.workspace / "missing.manifest.json"
        checksums = self.workspace / "missing.SHA256SUMS"
        prefix = self.workspace / "must-not-create/installation"
        cases = []
        for host, parameter in [("claude", "ClaudeHistory"), ("codex", "CodexHistory"),
                                ("workbuddy", "WorkBuddyHistory"), ("zcode", "ZCodeHistory"),
                                ("deepseek-harness", "DeepSeekHarnessHistory"), ("antigravity", "AntigravityHistory")]:
            cases += [({"HostChoice": [host], parameter: "--no-autostart"}, "history option value cannot start with a flag"),
                      ({"HostChoice": [host], parameter: "selected\0ignored-tail"}, "history option value contains NUL")]
        cases.append(({"HostChoice": ["workbuddy"], "WorkBuddyHistory": "-x"}, "history option value cannot start with a flag"))
        for parameter in ("Manifest", "Checksums", "Prefix", "Catalog"):
            cases.append(({"HostChoice": ["zcode"], parameter: "selected\0ignored-tail"}, "option value contains NUL"))
        receipt = self.workspace / "never-command-receipt.bin"
        env = {**os.environ, "ASG_TEST_COMMAND_RECEIPT": str(receipt)}
        before = self.file_snapshot(self.workspace)
        for engine in ("pwsh", "powershell"):
            if not shutil.which(engine):
                continue
            for options, error in cases:
                with self.subTest(engine=engine, options=options):
                    result = self.run_ps_install_options(root, manifest, checksums, prefix, options, env, engine=engine)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)
                    self.assertEqual(self.file_snapshot(self.workspace), before)
                    self.assertFalse(prefix.parent.exists())
                    self.assertFalse(receipt.exists())

    def test_powershell_install_default_idempotent_and_changed_file_refusal(self) -> None:
        root, manifest, checksums = self.powershell_fixture()
        local = self.workspace / "synthetic-user-local"
        local.mkdir()
        env = {**os.environ, "LOCALAPPDATA": str(local)}
        prefix = local / "agent-session-grep-candidate/bin"
        result = self.run_ps_install(root, manifest, checksums, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        before = {str(path.relative_to(prefix)): path.read_bytes()
                  for path in prefix.rglob("*") if path.is_file()}
        self.assertIn("package-install.json", before)
        self.assertEqual(before["release.manifest.json"], manifest.read_bytes())
        self.assertEqual(before["SHA256SUMS"], checksums.read_bytes())
        self.assertEqual(before["agent-session-grep.exe"], before["asg.exe"])
        self.assertTrue(Path(f"{prefix}.asg-install-lock").is_file())
        result = self.run_ps_install(root, manifest, checksums, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, {str(path.relative_to(prefix)): path.read_bytes()
                                 for path in prefix.rglob("*") if path.is_file()})
        if shutil.which("powershell"):
            result = self.run_ps_install(root, manifest, checksums, env=env, engine="powershell")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (prefix / "asg.exe").write_bytes(b"unrelated replacement")
        result = self.run_ps_install(root, manifest, checksums, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((prefix / "asg.exe").read_bytes(), b"unrelated replacement")
        self.assertEqual((prefix / "current.json").read_bytes(), before["current.json"])
        (prefix / "asg.exe").write_bytes(before["asg.exe"])
        supervisor = next(path for path in prefix.glob("versions/*/asg-supervisor.exe"))
        supervisor.write_bytes(b"changed supervisor")
        result = self.run_ps_install(root, manifest, checksums, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(supervisor.read_bytes(), b"changed supervisor")

    def test_powershell_rejects_tamper_extra_files_and_unowned_prefix(self) -> None:
        root, manifest, checksums = self.powershell_fixture()
        prefix = self.workspace / "installation"
        prefix.mkdir(); (prefix / "asg.exe").write_bytes(b"unrelated")
        result = self.run_ps_install(root, manifest, checksums, prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((prefix / "asg.exe").read_bytes(), b"unrelated")
        unused_prefix = self.workspace / "unused"
        # A Windows junction does not require developer-mode symlink privilege.
        junction = self.workspace / "linked-prefix-parent"
        junction_script = "New-Item -ItemType Junction -Path $env:ASG_TEST_JUNCTION -Target $env:ASG_TEST_JUNCTION_TARGET | Out-Null"
        create_junction = subprocess.run(
            [shutil.which("pwsh"), "-NoProfile", "-Command", junction_script],
            env={**os.environ, "ASG_TEST_JUNCTION": str(junction),
                 "ASG_TEST_JUNCTION_TARGET": str(prefix)},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(create_junction.returncode, 0, create_junction.stderr)
        result = self.run_ps_install(root, manifest, checksums, junction / "nested-install")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((prefix / "nested-install").exists())
        junction.rmdir()
        (root / "unexpected.txt").write_text("extra")
        result = self.run_ps_install(root, manifest, checksums, unused_prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(unused_prefix.exists())
        (root / "unexpected.txt").unlink()
        (root / "README.md").write_text("tampered")
        result = self.run_ps_install(root, manifest, checksums, unused_prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(unused_prefix.exists())

    def test_powershell_bad_launcher_preserves_staging_without_publishing(self) -> None:
        root, manifest, checksums = self.powershell_fixture(broken_launcher=True)
        prefix = self.workspace / "installation"
        result = self.run_ps_install(root, manifest, checksums, prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(prefix.exists())
        staged = list(self.workspace.glob("installation.asg-stage-*"))
        self.assertEqual(len(staged), 1)
        self.assertTrue((staged[0] / "current.json").is_file())
        self.assertIn("staging preserved", result.stderr)

    def test_powershell_rejects_supervisor_version_even_with_matching_package_hash(self) -> None:
        root, manifest, checksums = self.powershell_fixture(broken_supervisor=True)
        prefix = self.workspace / "supervisor-install"
        result = self.run_ps_install(root, manifest, checksums, prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(prefix.exists())
        self.assertIn("supervisor version", result.stderr)
        staged = list(self.workspace.glob("supervisor-install.asg-stage-*"))
        self.assertEqual(len(staged), 1)
        self.assertEqual(len(list(staged[0].glob("versions/*/asg-supervisor.exe"))), 1)

    def posix_fixture(self, *, schemas: tuple[int, int] = (19, 1)):
        # Execute real native fixtures, including architecture validation. WSL
        # supplies a real ELF host on Windows; do not masquerade shell scripts
        # as executables or replace the production host/limit checks.
        if os.name == "nt":
            if not shutil.which("wsl"):
                self.skipTest("native POSIX host unavailable")
            invoke = ["wsl", "--exec"]
            def native_path(path):
                absolute = str(path.resolve()).replace("\\", "/")
                return "/mnt/" + absolute[0].lower() + absolute[2:]
        else:
            invoke = []
            native_path = lambda path: str(path)
        platform = subprocess.run(invoke + ["sh", "-c", "command -v cc && uname -s && uname -m && ulimit -f 32"],
                                  capture_output=True, text=True, errors="backslashreplace", timeout=30)
        if platform.returncode:
            self.skipTest("native POSIX C compiler unavailable")
        _, system, arch = platform.stdout.strip().splitlines()
        target = {("Linux", "x86_64"): "x86_64-unknown-linux-gnu", ("Darwin", "x86_64"): "x86_64-apple-darwin",
                  ("Darwin", "arm64"): "aarch64-apple-darwin"}[(system, arch)]
        args = self.managed_arguments(target, schemas=schemas)
        def compile_fixture(path, product, info="not a launcher"):
            source = path.with_suffix(".c")
            source.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
                'static void u32(FILE*f,unsigned n){for(int i=0;i<4;i++){fputc(n&255,f);n>>=8;}}\n'
                'int main(int n,char**v){if(n==2){'
                f'if(!strcmp(v[1],"--version")){{puts({json.dumps(product + " 0.1.0")});return 0;}}'
                f'if(!strcmp(v[1],"--asg-launcher-info")){{puts({json.dumps(info)});return 0;}}return 24;}}'
                'int setup=0,path=0;for(int i=1;i<n;i++){setup|=!strcmp(v[i],"setup");path|=!strcmp(v[i],"path");}'
                'const char*receipt=getenv("ASG_TEST_COMMAND_RECEIPT");if(!receipt||(!setup&&!path))return 23;'
                'FILE*f=fopen(receipt,"ab");if(!f)return 25;u32(f,n-1);'
                'for(int i=1;i<n;i++){unsigned size=strlen(v[i]);u32(f,size);fwrite(v[i],1,size,f);}if(fclose(f))return 26;'
                'const char*code=getenv(setup?"ASG_TEST_SETUP_EXIT":"ASG_TEST_PATH_EXIT");'
                'puts(setup?"synthetic setup receipt":"synthetic path receipt");return code?atoi(code):0;}', encoding="utf-8")
            subprocess.run(invoke + ["cc", native_path(source), "-o", native_path(path)], check=True,
                           capture_output=True, timeout=30)
        compile_fixture(args["binary"], "agent-session-grep")
        compile_fixture(args["supervisor"], "asg-supervisor")
        info = json.dumps({
            "schema": "asg.launcher-info/v1", "launcher_protocol": 1,
            "target": args["target"], "generation": 1, "version": "0.1.0",
            "source_commit": "a" * 40, "app_sha256": BUILD_MANIFEST.sha256_file(args["binary"]),
            "catalog_schema": args["catalog_schema"], "control_schema": args["control_schema"],
        }, separators=(",", ":"))
        compile_fixture(args["launcher"], "agent-session-grep", info)
        archive, manifest = BUILD_MANIFEST.package_release(**args)
        checksums = args["output_dir"] / "SHA256SUMS"
        BUILD_MANIFEST.write_checksums(args["output_dir"], checksums)
        with tarfile.open(archive) as bundle:
            bundle.extractall(self.workspace / "extracted")
        root = self.workspace / "extracted" / json.loads(manifest.read_bytes())["archive"]["root"]
        return root, manifest, checksums, invoke, native_path

    def test_shell_installer_with_bounded_synthetic_programs(self) -> None:
        root, manifest, checksums, invoke, native_path = self.posix_fixture()
        prefix = self.workspace / "posix-install"
        command = invoke + ["sh", native_path(root / "package-install.sh"), "--manifest", native_path(manifest),
                            "--checksums", native_path(checksums), "--prefix", native_path(prefix)]
        for _ in range(2):
            result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, errors="backslashreplace", timeout=55)
            diagnostics = "".join(path.read_text(errors="replace")[:8192]
                                  for path in self.workspace.glob(".asg-stage.*/probe.err"))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr + diagnostics)
        self.assertTrue((prefix / "package-install.json").is_file())
        self.assertEqual((prefix / "release.manifest.json").read_bytes(), manifest.read_bytes())
        self.assertEqual((prefix / "SHA256SUMS").read_bytes(), checksums.read_bytes())
        supervisor = next(prefix.glob("versions/*/asg-supervisor"))
        supervisor.write_text("unrelated supervisor")
        result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, errors="backslashreplace", timeout=55)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(supervisor.read_text(), "unrelated supervisor")

    def test_shell_six_host_history_forwarding_records_literal_argv_and_legacy_repeat(self) -> None:
        schemas = BUILD_MANIFEST._source_schemas(MODULE_PATH.parents[2])
        self.assertEqual(schemas, (22, 2))
        root, manifest, checksums, invoke, native_path = self.posix_fixture(schemas=schemas)
        prefix = self.workspace / "six host posix installation"
        receipt = self.workspace / "posix-command-receipt.bin"
        profile = self.workspace / "isolated-posix-profile"
        profile.mkdir()
        (profile / "unrelated-config").write_bytes(b"unrelated profile\n")
        hosts = ["claude", "codex", "workbuddy", "zcode", "deepseek-harness", "antigravity"]
        histories = {}
        for host in hosts:
            history = profile / (host + " history & literal;$(not-evaluated) 'quoted' [x]")
            history.mkdir()
            (history / "source").write_bytes(b"synthetic original\n")
            histories[host] = native_path(history) + "/"
        unselected = profile / "unselected-source"
        unselected.mkdir()
        (unselected / "source").write_bytes(b"unselected original\n")
        before = self.file_snapshot(profile)
        package_before = self.file_snapshot(root)
        catalog = native_path(profile / "catalog & literal;$(not-evaluated).db")
        command = invoke + ["env", "ASG_TEST_COMMAND_RECEIPT=" + native_path(receipt),
                            "ASG_TEST_SETUP_EXIT=10", "ASG_TEST_PATH_EXIT=0",
                            "HOME=" + native_path(profile), "XDG_DATA_HOME=" + native_path(profile),
                            "sh", native_path(root / "package-install.sh"), "--manifest", native_path(manifest),
                            "--checksums", native_path(checksums), "--prefix", native_path(prefix)]
        options = ["--catalog", catalog, "--no-autostart"]
        for host in hosts:
            options += ["--host", host, "--" + host + "-history", histories[host]]
        result = subprocess.run(command + options, cwd=self.workspace, capture_output=True,
                                text=True, errors="backslashreplace", timeout=55)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        setup = ["--robot", "--db", catalog, "setup", "--install-prefix", native_path(prefix)]
        for host in hosts:
            setup += ["--host", host]
        for host in hosts:
            setup += ["--history", "claude-code" if host == "claude" else host, histories[host]]
        setup += ["--no-autostart"]
        self.assertEqual(self.command_receipts(receipt), [setup,
            ["--robot", "--db", catalog, "path", "install", "--install-prefix", native_path(prefix)]])
        self.assertEqual(self.file_snapshot(profile), before)
        self.assertEqual(self.file_snapshot(root), package_before)
        installed = self.file_snapshot(prefix)
        legacy = ["--host", "claude", "--host", "codex", "--claude-history", histories["claude"],
                  "--codex-history", histories["codex"], "--no-path"]
        result = subprocess.run(command + legacy, cwd=self.workspace, capture_output=True,
                                text=True, errors="backslashreplace", timeout=55)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.command_receipts(receipt)[2:], [[
            "--robot", "setup", "--install-prefix", native_path(prefix), "--host", "claude", "--host", "codex",
            "--history", "claude-code", histories["claude"], "--history", "codex", histories["codex"]]])
        self.assertEqual(self.file_snapshot(prefix), installed)
        self.assertEqual(self.file_snapshot(profile), before)

    def test_shell_setup_failure_retains_verified_install_and_never_registers_path(self) -> None:
        root, manifest, checksums, invoke, native_path = self.posix_fixture()
        prefix = self.workspace / "failed posix setup install"
        receipt = self.workspace / "failed-posix-command-receipt.bin"
        command = invoke + ["env", "ASG_TEST_COMMAND_RECEIPT=" + native_path(receipt), "ASG_TEST_SETUP_EXIT=7",
                            "sh", native_path(root / "package-install.sh"), "--manifest", native_path(manifest),
                            "--checksums", native_path(checksums), "--prefix", native_path(prefix),
                            "--host", "antigravity", "--antigravity-history", "literal selected history"]
        result = subprocess.run(command, cwd=self.workspace, capture_output=True,
                                text=True, errors="backslashreplace", timeout=55)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected setup failed", result.stderr)
        self.assertEqual(self.command_receipts(receipt), [[
            "--robot", "setup", "--install-prefix", native_path(prefix), "--host", "antigravity",
            "--history", "antigravity", "literal selected history"]])
        self.assertTrue((prefix / "package-install.json").is_file())
        self.assertEqual((prefix / "release.manifest.json").read_bytes(), manifest.read_bytes())
        self.assertEqual((prefix / "SHA256SUMS").read_bytes(), checksums.read_bytes())
        self.assertTrue((prefix / "agent-session-grep").is_file())

    def test_shell_invalid_setup_options_reject_before_prefix_or_staging_writes(self) -> None:
        if os.name == "nt":
            if not shutil.which("wsl"):
                self.skipTest("native POSIX host unavailable")
            invoke = ["wsl", "--exec"]
            def native_path(path):
                absolute = str(path.resolve()).replace("\\", "/")
                return "/mnt/" + absolute[0].lower() + absolute[2:]
        else:
            invoke = []
            native_path = lambda path: str(path)
        script = self.workspace / "scripts/install/package-install.sh"
        manifest = self.workspace / "missing.manifest.json"
        checksums = self.workspace / "missing.SHA256SUMS"
        prefix = self.workspace / "must-not-create/installation"
        command = invoke + ["sh", native_path(script), "--manifest", native_path(manifest),
                            "--checksums", native_path(checksums), "--prefix", native_path(prefix)]
        cases = [
            (["--host", "claude", "--host", "claude"], "duplicate host"),
            (["--host", "tencent-codebuddy"], "unsupported host"),
            (["--catalog", "synthetic.db"], "setup options require explicit --host"),
            (["--no-path"], "setup options require explicit --host"),
            (["--no-autostart"], "setup options require explicit --host"),
            (["--no-path", "--no-path"], "duplicate option"),
            (["--catalog", "one", "--catalog", "two"], "duplicate catalog"),
            (["--manifest", "other"], "duplicate manifest"),
            (["--checksums", "other"], "duplicate checksums"),
            (["--prefix", "other"], "duplicate prefix"),
            (["--unknown", "value"], "unknown option"),
            (["--host"], "missing option value"),
        ]
        for host in ["claude", "codex", "workbuddy", "zcode", "deepseek-harness", "antigravity"]:
            option = "--" + host + "-history"
            cases += [([option, "literal history"], "history requires --host"),
                      (["--host", host, option, "one", option, "two"], "duplicate history"),
                      (["--host", host, option], "missing option value"),
                      (["--host", host, option, "  "], "empty option value"),
                      (["--host", host, option, "-x"], "history option value cannot start with a flag")]
        before = self.file_snapshot(self.workspace)
        for args, error in cases:
            with self.subTest(args=args):
                result = subprocess.run(command + args, cwd=self.workspace, capture_output=True,
                                        text=True, errors="backslashreplace", timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                self.assertEqual(self.file_snapshot(self.workspace), before)
                self.assertFalse(prefix.parent.exists())

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

    def test_checksum_file_contains_real_four_target_archives_manifests_and_inventory(self) -> None:
        output_dir = self.workspace / "shared-release"
        output_dir.mkdir()
        expected = {}
        for target in sorted(BUILD_MANIFEST.MANAGED_TARGETS):
            args = self.managed_arguments(target)
            args["archive_format"] = "zip" if target.endswith("windows-msvc") else "tar.gz"
            args["output_dir"] = output_dir
            archive, manifest = BUILD_MANIFEST.package_release(**args)
            for path in (archive, manifest):
                expected[path.name] = BUILD_MANIFEST.sha256_file(path)
        for name in (BUILD_MANIFEST.DEPENDENCY_JSON_NAME, BUILD_MANIFEST.DEPENDENCY_CSV_NAME):
            path = output_dir / name
            path.write_bytes((self.workspace / "inventory" / name).read_bytes())
            expected[name] = BUILD_MANIFEST.sha256_file(path)
        sums = BUILD_MANIFEST.write_checksums(output_dir, output_dir / "SHA256SUMS")
        actual = {line.split("  ", 1)[1]: line.split("  ", 1)[0]
                  for line in sums.read_text(encoding="utf-8").splitlines()}
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 10)

    def test_checksum_file_rejects_case_aliases_before_overwriting_prior_sums(self) -> None:
        output = self.workspace / "case-checksums"
        output.mkdir()
        (output / "package.zip").write_bytes(b"synthetic payload")
        sums = output / "SHA256SUMS"
        sums.write_bytes(b"existing metadata must survive\n")
        collision = output / "Package.zip"
        collision.write_bytes(b"second spelling")
        candidates = [output / "package.zip", collision]
        with mock.patch.object(BUILD_MANIFEST, "_checksum_candidates", return_value=candidates):
            with self.assertRaisesRegex(ValueError, "case-colliding"):
                BUILD_MANIFEST.write_checksums(output, sums)
        self.assertEqual(sums.read_bytes(), b"existing metadata must survive\n")

    def test_powershell_install_accepts_shared_real_target_sums_and_rejects_single_helper(self) -> None:
        root, manifest, checksums = self.powershell_fixture()
        output_dir = checksums.parent
        for target in sorted(BUILD_MANIFEST.MANAGED_TARGETS - {"x86_64-pc-windows-msvc"}):
            args = self.managed_arguments(target)
            args["output_dir"] = output_dir
            BUILD_MANIFEST.package_release(**args)
        BUILD_MANIFEST.write_checksums(output_dir, checksums)
        prefix = self.workspace / "shared-sums-install"
        result = self.run_ps_install(root, manifest, checksums, prefix)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((prefix / "SHA256SUMS").read_bytes(), checksums.read_bytes())
        metadata = json.loads(manifest.read_bytes())
        removed = next(e for e in metadata["archive"]["files"] if e["name"].endswith("/helpers/update-check.ps1"))
        metadata["archive"]["files"].remove(removed)
        helper = root / removed["name"].removeprefix(metadata["archive"]["root"] + "/")
        helper.unlink()
        tsv = root / "PACKAGE-MANIFEST.tsv"
        tsv.write_text("\n".join(line for line in tsv.read_text(encoding="utf-8").splitlines()
                                  if not line.endswith("/helpers/update-check.ps1")) + "\n", encoding="utf-8", newline="\n")
        metadata["install_manifest_sha256"] = BUILD_MANIFEST.sha256_file(tsv)
        record = next(e for e in metadata["archive"]["files"] if e["name"].endswith("/PACKAGE-MANIFEST.tsv"))
        record["sha256"] = BUILD_MANIFEST.sha256_file(tsv)
        record["size_bytes"] = tsv.stat().st_size
        manifest.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8", newline="\n")
        BUILD_MANIFEST.write_checksums(output_dir, checksums)
        rejected_prefix = self.workspace / "single-helper-install"
        result = self.run_ps_install(root, manifest, checksums, rejected_prefix)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(rejected_prefix.exists())


if __name__ == "__main__":
    unittest.main()
