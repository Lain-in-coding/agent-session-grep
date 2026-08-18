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
import gzip
import hashlib
import io
import json
import re
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
    members = _release_members(
        workspace, binary, dependency_json, dependency_csv, archive_root
    )
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
        )
    elif args.command == "checksums":
        write_checksums(args.directory, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
