#!/usr/bin/env python3
"""Build deterministic unsigned release archives and path-free manifests.

The helper reads release inputs from the workspace and writes only beneath an
explicit output directory. Its dependency inventory is intentionally not an
SPDX document: Cargo package metadata may omit or merely declare license data,
so the report preserves that uncertainty instead of inventing a legal verdict.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import re
import stat
import struct
import subprocess
import tempfile
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable

ARCHIVE_SCHEMA = "agent-session-grep.release-archive-manifest/v1"
DEPENDENCY_SCHEMA = "agent-session-grep.third-party-dependencies/v1"
REQUIRED_DOCUMENTS = (
    "README.md",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "CHANGELOG.md",
    "SECURITY.md",
    "NOTICE",
)
DEPENDENCY_JSON_NAME = "THIRD-PARTY-DEPENDENCIES.json"
DEPENDENCY_CSV_NAME = "THIRD-PARTY-DEPENDENCIES.csv"
CLI_PACKAGE = "agent-session-grep-cli"
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\Z")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MANAGED_TARGETS = {
    "x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
}
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
PACKAGE_INSTALLERS = ("package-install.ps1", "package-install.sh")
UPDATE_CHECK_HELPERS = ("update-check.sh", "update-check.ps1")
UNINSTALL_HELPERS = ("package-uninstall.ps1",)
INSTALL_MANIFEST = "PACKAGE-MANIFEST.tsv"
MANAGED_SOURCE_INPUTS = (
    "docs/operations/INSTALL-AND-UPGRADE.md",
    "scripts/install/package-install.ps1", "scripts/install/package-install.sh",
    "scripts/install/update-check.sh", "scripts/install/update-check.ps1",
    "scripts/install/package-uninstall.ps1",
)


def _source_schemas(workspace: Path) -> tuple[int, int]:
    result = []
    for name, constant in (("lib.rs", "SCHEMA_VERSION"), ("control.rs", "VERSION")):
        source = workspace / "crates/agent-session-grep-adapters-sqlite/src" / name
        matches = re.findall(rf"(?m)^(?:pub )?const {constant}: i64 = ([1-9][0-9]*);$",
                             source.read_text(encoding="utf-8"))
        if len(matches) != 1:
            raise ValueError("could not identify the shipped catalog/control schema constant")
        result.append(int(matches[0]))
    return result[0], result[1]


def _git_package_inputs(workspace: Path, source_commit: str) -> dict[str, bytes]:
    """Read only the extra package helpers/docs from immutable regular Git blobs."""
    tree = subprocess.check_output([
        "git", "-C", str(workspace), "ls-tree", "-rz", "--full-tree", source_commit,
        "--", *MANAGED_SOURCE_INPUTS,
    ])
    objects = {}
    for record in tree.rstrip(b"\0").split(b"\0"):
        header, separator, path = record.partition(b"\t")
        fields = header.split()
        name = path.decode("ascii")
        if (not separator or len(fields) != 3 or fields[0] not in (b"100644", b"100755")
                or fields[1] != b"blob" or not re.fullmatch(rb"[0-9a-f]{40}", fields[2])
                or name not in MANAGED_SOURCE_INPUTS or name in objects):
            raise ValueError("managed package inputs must be unique regular Git blobs")
        objects[name] = fields[2].decode("ascii")
    if set(objects) != set(MANAGED_SOURCE_INPUTS):
        raise ValueError("managed package Git input inventory is incomplete")
    return {name: subprocess.check_output(["git", "-C", str(workspace), "cat-file", "blob", oid])
            for name, oid in objects.items()}


def _verify_native_members(members: list[tuple[str, bytes, int]], archive_root: str) -> None:
    """Smoke the exact staged payload without setup, installation or history I/O."""
    with tempfile.TemporaryDirectory(prefix="asg-package-probe-") as temporary:
        root = Path(temporary).resolve()
        for name, content, mode in members:
            path = root / name.removeprefix(archive_root + "/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(mode)
        pointer = _read_json(root / "current.json")
        release = _read_json(root / pointer["dir"] / "release.json")
        alias = "asg.exe" if pointer["app"].endswith(".exe") else "asg"
        expected_info = {
            "schema": "asg.launcher-info/v1", "launcher_protocol": 1, "generation": 1,
            **{key: release[key] for key in ("version", "target", "source_commit", "app_sha256",
                                            "catalog_schema", "control_schema")},
        }
        supervisor = "asg-supervisor.exe" if pointer["app"].endswith(".exe") else "asg-supervisor"
        programs = [(root / pointer["app"], False), (root / alias, False),
                    (root / pointer["dir"] / pointer["app"], False),
                    (root / pointer["dir"] / supervisor, True)]
        for program, is_supervisor in programs:
            arguments = ["--version"] if program.parent != root else ["--version", "--asg-launcher-info"]
            for argument in arguments:
                # Spool only locally, monitor both streams, and terminate on a
                # bounded time/output budget; never emit candidate stderr.
                with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                    with subprocess.Popen([str(program), argument], stdin=subprocess.DEVNULL,
                                          stdout=stdout, stderr=stderr) as process:
                        deadline = time.monotonic() + 30
                        while process.poll() is None:
                            if time.monotonic() >= deadline or max(stdout.tell(), stderr.tell()) > 8192:
                                process.kill()
                                process.wait()
                                raise ValueError("native package probe exceeded time/output limit")
                            time.sleep(0.02)
                        stdout.seek(0); stderr.seek(0)
                        output, error = stdout.read(8193), stderr.read(8193)
                        if process.returncode or error or len(output) > 8192:
                            raise ValueError("native package probe failed")
                if argument == "--version":
                    product = "asg-supervisor" if is_supervisor else "agent-session-grep"
                    expected = f"{product} {pointer['version']}".encode()
                    if output not in (expected, expected + b"\n", expected + b"\r\n"):
                        raise ValueError("native package version mismatch")
                elif json.loads(output) != expected_info:
                    raise ValueError("native launcher identity mismatch")


def _assert_regular_input(path: Path) -> None:
    # Do not resolve first: that would hide a linked input or ancestor.
    for component in (path.absolute(), *path.absolute().parents):
        try:
            info = component.lstat()
        except FileNotFoundError as error:
            raise ValueError(f"required release input is missing: {path.name}") from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"linked release input: {path.name}")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"required regular release input is missing: {path.name}")


def _regular_input(path: Path) -> bytes:
    _assert_regular_input(path)
    return path.read_bytes()


def _executable_target(content: bytes) -> str:
    """Read native image headers without executing a foreign-target program."""
    if content.startswith(b"MZ") and len(content) >= 64:
        offset = struct.unpack_from("<I", content, 60)[0]
        if (len(content) >= offset + 26 and content[offset:offset + 4] == b"PE\0\0"
                and struct.unpack_from("<H", content, offset + 4)[0] == 0x8664
                and struct.unpack_from("<H", content, offset + 24)[0] == 0x20B):
            return "x86_64-pc-windows-msvc"
    if (len(content) >= 64 and content[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", content, 18)[0] == 62
            and struct.unpack_from("<H", content, 16)[0] in (2, 3)):
        return "x86_64-unknown-linux-gnu"
    if len(content) >= 32 and content[:4] == b"\xcf\xfa\xed\xfe":
        cpu, _, kind = struct.unpack_from("<III", content, 4)
        if kind == 2 and cpu in (0x01000007, 0x0100000C):
            return ("x86_64" if cpu == 0x01000007 else "aarch64") + "-apple-darwin"
    raise ValueError("unsupported native executable header")


def _verify_supervisor_image(content: bytes, target: str) -> None:
    if _executable_target(content) != target:
        raise ValueError("supervisor target does not match package target")
    if target.endswith("windows-msvc"):
        offset = struct.unpack_from("<I", content, 60)[0]
        if (len(content) < offset + 94
                or struct.unpack_from("<H", content, offset + 20)[0] < 70
                or struct.unpack_from("<H", content, offset + 92)[0] != 2):
            raise ValueError("Windows supervisor must use the GUI subsystem")


def _validate_members(members: list[tuple[str, bytes, int]]) -> None:
    files: set[str] = set()
    directories: set[str] = set()
    for name, _, mode in members:
        parts = name.split("/")
        if (not all(SAFE_COMPONENT.fullmatch(p) and p not in {".", ".."}
                    and not p.endswith(".") and not re.match(
                        r"(?i)^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)", p
                    ) for p in parts)
                or mode not in (0o644, 0o755)):
            raise ValueError("unsafe archive member")
        folded = name.casefold()
        parents = {"/".join(parts[:i]).casefold() for i in range(1, len(parts))}
        if folded in files or folded in directories or parents & files:
            raise ValueError("archive member collision")
        files.add(folded)
        directories.update(parents)


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _managed_members(
    workspace: Path, binary: Path, launcher: Path, supervisor: Path, dependency_json: Path,
    dependency_csv: Path, archive_root: str, target: str, version: str,
    source_commit: str, source_date_epoch: int, catalog_schema: int,
    control_schema: int,
    git_inputs: dict[str, bytes] | None = None,
) -> list[tuple[str, bytes, int]]:
    matched = SEMVER.fullmatch(version)
    if (not matched or len(version) > 51 or (matched[4] and any(
            part.isdigit() and len(part) > 1 and part.startswith("0")
            for part in matched[4].split(".")))):
        raise ValueError("managed version must be SemVer with at most 51 characters")
    if target not in MANAGED_TARGETS:
        raise ValueError("unsupported managed target")
    if any(type(value) is not int or not 1 <= value <= 0xFFFFFFFF
           for value in (catalog_schema, control_schema)):
        raise ValueError("managed catalog/control schema must be positive u32 integers")
    suffix = ".exe" if target.endswith("windows-msvc") else ""
    app_name = f"agent-session-grep{suffix}"
    supervisor_name = f"asg-supervisor{suffix}"
    if (binary.name != app_name or launcher.name != f"agent-session-grep-launcher{suffix}"
            or supervisor.name != supervisor_name):
        raise ValueError("managed executable input names do not match target")
    app_bytes, launcher_bytes, supervisor_bytes = map(_regular_input, (binary, launcher, supervisor))
    for payload in (app_bytes, launcher_bytes):
        if _executable_target(payload) != target:
            raise ValueError("executable target does not match package target")
    _verify_supervisor_image(supervisor_bytes, target)
    if len({app_bytes, launcher_bytes, supervisor_bytes}) != 3:
        raise ValueError("application, launcher and supervisor must be distinct executables")
    app_sha = sha256_bytes(app_bytes)
    supervisor_sha = sha256_bytes(supervisor_bytes)
    version_dir = f"versions/{version}-{app_sha[:12]}"
    timestamp = dt.datetime.fromtimestamp(source_date_epoch, dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    pointer = {
        "schema": "asg.current/v1", "generation": 1, "version": version,
        "dir": version_dir, "app": app_name, "app_sha256": app_sha,
        "launcher_protocol": 1, "activated_at": timestamp,
    }
    release = {
        "schema": "asg.version/v1", "version": version, "target": target,
        "source_commit": source_commit, "app_sha256": app_sha,
        "catalog_schema": catalog_schema, "control_schema": control_schema,
        "launcher_protocol_min": 1, "launcher_protocol_max": 1,
        "built_at": timestamp,
    }
    entries = [
        (app_name, launcher_bytes, 0o755), (f"asg{suffix}", launcher_bytes, 0o755),
        (f"{version_dir}/{app_name}", app_bytes, 0o755),
        (f"{version_dir}/{supervisor_name}", supervisor_bytes, 0o755),
        (f"{version_dir}/release.json", _json_bytes(release), 0o644),
        ("current.json", _json_bytes(pointer), 0o644),
    ]
    inputs = [(name, workspace / name) for name in REQUIRED_DOCUMENTS]
    inputs.extend([
        (DEPENDENCY_JSON_NAME, dependency_json), (DEPENDENCY_CSV_NAME, dependency_csv),
        ("INSTALL-AND-UPGRADE.md", workspace / "docs/operations/INSTALL-AND-UPGRADE.md"),
    ])
    inputs.extend((name, workspace / "scripts/install" / name) for name in PACKAGE_INSTALLERS)
    for name, path in inputs:
        key = next((key for key in (git_inputs or {}) if workspace / key == path), None)
        content = git_inputs[key] if key is not None else _regular_input(path)
        entries.append((name, content, 0o755 if name.endswith(".sh") else 0o644))
    # Versioned transport helpers share the immutable application directory, so
    # rollback switches the executable and both helpers as one unit. Their
    # digests are pinned by the package file manifest like every other member.
    for name in (*UPDATE_CHECK_HELPERS, *UNINSTALL_HELPERS):
        path = workspace / "scripts/install" / name
        key = next((key for key in (git_inputs or {}) if workspace / key == path), None)
        content = git_inputs[key] if key is not None else _regular_input(path)
        entries.append(
            (f"{version_dir}/helpers/{name}", content, 0o755 if name.endswith(".sh") else 0o644)
        )
    # A deliberately narrow, non-executable wire format for the POSIX installer.
    # Its digest is pinned in the sibling JSON manifest; it in turn pins every
    # extracted payload byte. No JSON interpreter is needed on the end-user host.
    records = [
        "asg.package-files/v1", f"version\t{version}", f"target\t{target}",
        f"source_commit\t{source_commit}", f"app\t{app_name}",
        f"app_sha256\t{app_sha}", f"dir\t{version_dir}",
        f"supervisor\t{supervisor_name}", f"supervisor_sha256\t{supervisor_sha}",
        "launcher_protocol\t1", f"catalog_schema\t{catalog_schema}",
        f"control_schema\t{control_schema}", f"built_at\t{timestamp}",
    ]
    records.extend(f"file\t{sha256_bytes(content)}\t{mode:04o}\t{len(content)}\t{name}"
                   for name, content, mode in sorted(entries))
    entries.append((INSTALL_MANIFEST, ("\n".join(records) + "\n").encode("ascii"), 0o644))
    return [(f"{archive_root}/{name}", content, mode) for name, content, mode in entries]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path.name}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _workspace_version(workspace: Path) -> str:
    manifest = workspace / "Cargo.toml"
    section = None
    versions: list[str] = []
    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        section_match = re.fullmatch(r"\[([^]]+)\]", line)
        if section_match:
            section = section_match.group(1).strip()
            continue
        if section == "workspace.package":
            version_match = re.fullmatch(r'version\s*=\s*"([^"]+)"', line)
            if version_match:
                versions.append(version_match.group(1))
    if len(versions) != 1:
        raise ValueError("Cargo.toml must declare exactly one [workspace.package] version")
    return versions[0]


def _lock_packages(workspace: Path) -> list[dict[str, str | None]]:
    lock_path = workspace / "Cargo.lock"
    content = lock_path.read_text(encoding="utf-8")
    if not re.search(r"(?m)^version\s*=\s*4\s*$", content):
        raise ValueError("Cargo.lock is missing the expected lock format version")
    packages: list[dict[str, str | None]] = []
    blocks = re.finditer(
        r"(?ms)^\[\[package\]\]\s*$\n(.*?)(?=^\[\[package\]\]\s*$|\Z)",
        content,
    )
    for block in blocks:
        fields: dict[str, str | None] = {
            "name": None,
            "version": None,
            "source": None,
            "checksum": None,
        }
        for field in fields:
            match = re.search(
                rf'(?m)^{field}\s*=\s*"([^"]+)"\s*$', block.group(1)
            )
            if match:
                fields[field] = match.group(1)
        if fields["name"] and fields["version"]:
            packages.append(fields)
    if not packages:
        raise ValueError("Cargo.lock contains no package records")
    return packages


def _metadata_workspace_package(
    metadata: dict[str, Any], package_name: str
) -> dict[str, Any]:
    if metadata.get("version") != 1:
        raise ValueError("cargo metadata format version must be 1")
    workspace_members = set(metadata.get("workspace_members", []))
    packages = [
        package
        for package in metadata.get("packages", [])
        if package.get("id") in workspace_members and package.get("name") == package_name
    ]
    if len(packages) != 1:
        raise ValueError(f"cargo metadata must contain one workspace package {package_name}")
    return packages[0]


def validate_release_contract(
    workspace: Path,
    tag: str,
    version: str,
    metadata_path: Path | None = None,
) -> None:
    workspace = workspace.resolve()
    if not SAFE_COMPONENT.fullmatch(version):
        raise ValueError("version contains characters unsafe for an archive name")
    if tag != f"v{version}":
        raise ValueError(f"tag {tag!r} does not match workspace version {version!r}")
    manifest_version = _workspace_version(workspace)
    if manifest_version != version:
        raise ValueError(
            f"Cargo.toml workspace version {manifest_version!r} does not match {version!r}"
        )
    lock_versions = {
        package["version"]
        for package in _lock_packages(workspace)
        if package["name"] == CLI_PACKAGE and package["source"] is None
    }
    if lock_versions != {version}:
        raise ValueError(
            f"Cargo.lock {CLI_PACKAGE} version(s) {sorted(lock_versions)} do not match {version!r}"
        )
    if metadata_path is not None:
        package = _metadata_workspace_package(_read_json(metadata_path), CLI_PACKAGE)
        if package.get("version") != version:
            raise ValueError(
                f"cargo metadata {CLI_PACKAGE} version {package.get('version')!r} "
                f"does not match {version!r}"
            )


def _lock_checksum_index(
    workspace: Path,
) -> dict[tuple[str | None, str | None, str | None], str | None]:
    return {
        (package["name"], package["version"], package["source"]): package[
            "checksum"
        ]
        for package in _lock_packages(workspace)
    }


def _resolved_package_ids(metadata: dict[str, Any]) -> set[str]:
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise ValueError("cargo metadata is missing the resolved dependency graph")
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("cargo metadata resolve.nodes must be a list")
    return {node["id"] for node in nodes if isinstance(node, dict) and "id" in node}


def write_dependency_inventory(
    workspace: Path,
    metadata_path: Path,
    version: str,
    output_dir: Path,
) -> tuple[Path, Path]:
    workspace = workspace.resolve()
    validate_release_contract(workspace, f"v{version}", version, metadata_path)
    metadata = _read_json(metadata_path)
    workspace_members = set(metadata.get("workspace_members", []))
    resolved_ids = _resolved_package_ids(metadata)
    checksums = _lock_checksum_index(workspace)
    dependencies: list[dict[str, Any]] = []
    for package in metadata.get("packages", []):
        package_id = package.get("id")
        if package_id in workspace_members or package_id not in resolved_ids:
            continue
        license_declared = package.get("license") or None
        license_file_present = bool(package.get("license_file"))
        if license_declared:
            license_status = "declared_by_package_metadata_unverified"
        elif license_file_present:
            license_status = "license_file_declared_metadata_not_inspected"
        else:
            license_status = "missing_from_cargo_metadata"
        key = (package.get("name"), package.get("version"), package.get("source"))
        dependencies.append(
            {
                "name": package.get("name"),
                "version": package.get("version"),
                "source": package.get("source"),
                "cargo_lock_checksum": checksums.get(key),
                "license_declared": license_declared,
                "license_file_present": license_file_present,
                "license_status": license_status,
            }
        )
    dependencies.sort(
        key=lambda dependency: (
            dependency["name"] or "",
            dependency["version"] or "",
            dependency["source"] or "",
        )
    )
    report = {
        "schema": DEPENDENCY_SCHEMA,
        "release_version": version,
        "dependency_count": len(dependencies),
        "scope": "Cargo workspace resolved graph, including target/build/dev dependencies",
        "generated_from": ["cargo metadata --locked --format-version 1", "Cargo.lock"],
        "spdx_document": False,
        "license_data_contract": (
            "license_declared is copied from Cargo package metadata and is not an "
            "independent SPDX or legal verification; null means metadata supplied no value"
        ),
        "dependencies": dependencies,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / DEPENDENCY_JSON_NAME
    csv_path = output_dir / DEPENDENCY_CSV_NAME
    _write_json(json_path, report)
    columns = (
        "name",
        "version",
        "source",
        "cargo_lock_checksum",
        "license_declared",
        "license_file_present",
        "license_status",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(dependencies)
    return json_path, csv_path


def _release_members(
    workspace: Path,
    binary: Path,
    dependency_json: Path,
    dependency_csv: Path,
    archive_root: str,
) -> list[tuple[str, bytes, int]]:
    inputs = [(binary.name, binary, 0o755)]
    inputs.extend((name, workspace / name, 0o644) for name in REQUIRED_DOCUMENTS)
    inputs.extend(
        (
            (DEPENDENCY_JSON_NAME, dependency_json, 0o644),
            (DEPENDENCY_CSV_NAME, dependency_csv, 0o644),
        )
    )
    members: list[tuple[str, bytes, int]] = []
    for name, path, mode in inputs:
        if not path.is_file():
            raise ValueError(f"required release input is missing: {name}")
        members.append((f"{archive_root}/{name}", path.read_bytes(), mode))
    return members


def _write_tar_gz(
    archive_path: Path,
    members: Iterable[tuple[str, bytes, int]],
    source_date_epoch: int,
) -> None:
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=source_date_epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for name, content, mode in members:
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mtime = source_date_epoch
                    info.mode = mode
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(content))


def _write_zip(
    archive_path: Path,
    members: Iterable[tuple[str, bytes, int]],
    source_date_epoch: int,
) -> None:
    zip_epoch = max(source_date_epoch, 315_532_800)
    date_time = time.gmtime(zip_epoch)[:6]
    with zipfile.ZipFile(
        archive_path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, content, mode in members:
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.create_system = 3
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def package_release(
    *,
    workspace: Path,
    binary: Path,
    dependency_json: Path,
    dependency_csv: Path,
    target: str,
    tag: str,
    version: str,
    source_commit: str,
    source_date_epoch: int,
    archive_format: str,
    output_dir: Path,
    managed_layout: bool = False,
    launcher: Path | None = None,
    supervisor: Path | None = None,
    catalog_schema: int | None = None,
    control_schema: int | None = None,
    git_package_inputs: bool = False,
    verify_native: bool = False,
) -> tuple[Path, Path]:
    workspace = workspace.resolve()
    validate_release_contract(workspace, tag, version)
    if not SAFE_COMPONENT.fullmatch(target):
        raise ValueError("target contains characters unsafe for an archive name")
    if not SOURCE_COMMIT.fullmatch(source_commit):
        raise ValueError("source commit must be a full lowercase 40-character Git SHA")
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    if archive_format not in {"tar.gz", "zip"}:
        raise ValueError("archive format must be tar.gz or zip")
    dependency_report = _read_json(dependency_json)
    if dependency_report.get("schema") != DEPENDENCY_SCHEMA:
        raise ValueError("third-party dependency JSON has an unsupported schema")
    if dependency_report.get("release_version") != version:
        raise ValueError("third-party dependency JSON version does not match release")

    archive_root = f"agent-session-grep-{tag}-{target}"
    if managed_layout:
        if launcher is None or supervisor is None or catalog_schema is None or control_schema is None:
            raise ValueError("managed layout requires launcher, supervisor, catalog schema and control schema")
        members = _managed_members(
            workspace, binary, launcher, supervisor, dependency_json, dependency_csv, archive_root,
            target, version, source_commit, source_date_epoch, catalog_schema, control_schema,
            _git_package_inputs(workspace, source_commit) if git_package_inputs else None,
        )
    else:
        if git_package_inputs or verify_native or any(value is not None for value in (launcher, supervisor, catalog_schema, control_schema)):
            raise ValueError("launcher, supervisor and schema options require --managed-layout")
        members = _release_members(
            workspace, binary, dependency_json, dependency_csv, archive_root
        )
    _validate_members(members)
    if verify_native:
        _verify_native_members(members, archive_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{archive_root}.{archive_format}"
    if archive_format == "zip":
        _write_zip(archive_path, members, source_date_epoch)
    else:
        _write_tar_gz(archive_path, members, source_date_epoch)

    member_manifest = [
        {
            "name": name,
            "sha256": sha256_bytes(content),
            "size_bytes": len(content),
            "mode": format(mode, "04o"),
        }
        for name, content, mode in members
    ]
    manifest = {
        "schema": ARCHIVE_SCHEMA,
        "release": {
            "tag": tag,
            "version": version,
            "target": target,
            "source_commit": source_commit,
            "source_date_epoch": source_date_epoch,
            "unsigned": True,
        },
        "archive": {
            "filename": archive_path.name,
            "format": archive_format,
            "root": archive_root,
            "sha256": sha256_file(archive_path),
            "size_bytes": archive_path.stat().st_size,
            "files": member_manifest,
        },
        "inputs": {
            "cargo_lock_sha256": sha256_file(workspace / "Cargo.lock"),
            "dependency_inventory_schema": DEPENDENCY_SCHEMA,
        },
        "provenance": {
            "kind": "self-reported-build-metadata",
            "cryptographic_attestation": False,
            "limitation": (
                "This manifest is unsigned metadata, not a signature, notarization, "
                "or GitHub Artifact Attestation."
            ),
        },
    }
    if managed_layout:
        manifest["layout"] = "asg.managed-candidate/v1"
        manifest["install_manifest_sha256"] = next(
            entry["sha256"] for entry in member_manifest
            if entry["name"] == f"{archive_root}/{INSTALL_MANIFEST}"
        )
    manifest_path = output_dir / f"{archive_root}.manifest.json"
    _write_json(manifest_path, manifest)
    return archive_path, manifest_path


def _checksum_candidates(directory: Path, output: Path) -> list[Path]:
    candidates = []
    for path in directory.iterdir():
        if not path.is_file() or path.resolve() == output.resolve():
            continue
        if (
            path.name.endswith((".tar.gz", ".zip", ".manifest.json"))
            or path.name in {DEPENDENCY_JSON_NAME, DEPENDENCY_CSV_NAME}
        ):
            candidates.append(path)
    return sorted(candidates, key=lambda path: path.name)


def write_checksums(directory: Path, output: Path) -> Path:
    directory = directory.resolve()
    if output.parent.resolve() != directory:
        raise ValueError("SHA256SUMS must be written directly in the release directory")
    candidates = _checksum_candidates(directory, output)
    if not candidates:
        raise ValueError("no release artifacts found for SHA256SUMS")
    folded = set()
    for path in candidates:
        if not SAFE_COMPONENT.fullmatch(path.name) or path.name.casefold() in folded:
            raise ValueError("unsafe or case-colliding SHA256SUMS asset name")
        folded.add(path.name.casefold())
        # Reuse the regular/no-link input check before publishing checksums.
        _assert_regular_input(path)
    output.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in candidates),
        encoding="utf-8",
        newline="\n",
    )
    return output


def _path(value: str) -> Path:
    return Path(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate tag/version/lock/metadata")
    validate.add_argument("--workspace", type=_path, required=True)
    validate.add_argument("--tag", required=True)
    validate.add_argument("--version", required=True)
    validate.add_argument("--metadata", type=_path)

    inventory = subparsers.add_parser(
        "inventory", help="write JSON and CSV third-party dependency reports"
    )
    inventory.add_argument("--workspace", type=_path, required=True)
    inventory.add_argument("--metadata", type=_path, required=True)
    inventory.add_argument("--version", required=True)
    inventory.add_argument("--output-dir", type=_path, required=True)

    package = subparsers.add_parser(
        "package", help="build a deterministic archive and provenance manifest"
    )
    package.add_argument("--workspace", type=_path, required=True)
    package.add_argument("--binary", type=_path, required=True)
    package.add_argument("--managed-layout", action="store_true",
                         help="build the extracted-package developer candidate layout")
    package.add_argument("--launcher", type=_path)
    package.add_argument("--supervisor", type=_path)
    package.add_argument("--catalog-schema", type=int)
    package.add_argument("--control-schema", type=int)
    package.add_argument("--git-package-inputs", action="store_true",
                         help="pin extra package helpers/docs to source-commit Git blobs")
    package.add_argument("--verify-native", action="store_true",
                         help="probe staged app, supervisor and both launchers on the native build host")
    package.add_argument("--schemas-from-source", action="store_true",
                         help="read schema versions from the shipped SQLite/control constants")
    package.add_argument("--dependency-json", type=_path, required=True)
    package.add_argument("--dependency-csv", type=_path, required=True)
    package.add_argument("--target", required=True)
    package.add_argument("--tag", required=True)
    package.add_argument("--version", required=True)
    package.add_argument("--source-commit", required=True)
    package.add_argument("--source-date-epoch", type=int, required=True)
    package.add_argument("--archive-format", choices=("tar.gz", "zip"), required=True)
    package.add_argument("--output-dir", type=_path, required=True)

    checksums = subparsers.add_parser(
        "checksums", help="write sorted SHA256SUMS for release assets"
    )
    checksums.add_argument("--directory", type=_path, required=True)
    checksums.add_argument("--output", type=_path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "validate":
        validate_release_contract(args.workspace, args.tag, args.version, args.metadata)
    elif args.command == "inventory":
        write_dependency_inventory(
            args.workspace, args.metadata, args.version, args.output_dir
        )
    elif args.command == "package":
        if args.schemas_from_source:
            if not args.managed_layout or args.catalog_schema is not None or args.control_schema is not None:
                raise ValueError("--schemas-from-source requires managed layout and no explicit schemas")
            args.catalog_schema, args.control_schema = _source_schemas(args.workspace)
        package_release(
            workspace=args.workspace,
            binary=args.binary,
            dependency_json=args.dependency_json,
            dependency_csv=args.dependency_csv,
            target=args.target,
            tag=args.tag,
            version=args.version,
            source_commit=args.source_commit,
            source_date_epoch=args.source_date_epoch,
            archive_format=args.archive_format,
            output_dir=args.output_dir,
            managed_layout=args.managed_layout,
            launcher=args.launcher,
            supervisor=args.supervisor,
            catalog_schema=args.catalog_schema,
            control_schema=args.control_schema,
            git_package_inputs=args.git_package_inputs,
            verify_native=args.verify_native,
        )
    elif args.command == "checksums":
        write_checksums(args.directory, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
