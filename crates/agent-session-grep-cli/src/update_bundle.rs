//! Offline verification of a release archive bundle.
//!
//! A bundle is the triple `<root>.<format>`, `<root>.manifest.json` and the
//! sibling `SHA256SUMS` produced by `scripts/release/build-manifest.py`. The
//! checksums and manifest are unsigned, self-reported build metadata: this
//! module verifies *consistency* between those files and the archive bytes, not
//! publisher identity. No signature is verified or claimed.
//!
//! The verifier never opens a network connection, never executes an archive
//! member and never mutates an active installation or catalog. It only reads
//! the three bundle files and, on explicit request, writes verified members to
//! a caller-owned private staging directory.
//!
//! All archive metadata is validated before the first staged file is created:
//! member names/types/modes/sizes, the exact whitelist, the package manifest,
//! `current.json`, `release.json`, every member digest and native executable
//! headers. Deadlines are absolute and are never extended.

use crate::{
    CliError,
    package_installation::{
        MAX_CHECKSUM_BYTES, Manifest, RELEASE_TARGETS as MANAGED_TARGETS, absolute,
        native_target_bytes, ordinary, parse_release_checksums, pinned, supervisor_gui_bytes,
        validate_checksum_assets,
    },
    protocol::{CanonicalCode, ProtocolError},
};
use agent_session_grep_launcher::{
    CurrentPointer, ReleaseMetadata,
    metadata::{CURRENT_SCHEMA, LAUNCHER_PROTOCOL, MAX_METADATA_BYTES, RELEASE_SCHEMA},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const ARCHIVE_SCHEMA: &str = "agent-session-grep.release-archive-manifest/v1";
const MANAGED_LAYOUT: &str = "asg.managed-candidate/v1";
const DEPENDENCY_SCHEMA: &str = "agent-session-grep.third-party-dependencies/v1";
const PACKAGE_MANIFEST_NAME: &str = "PACKAGE-MANIFEST.tsv";
const CHECKSUMS_NAME: &str = "SHA256SUMS";

/// Largest accepted compressed archive.
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Largest accepted sum of uncompressed member sizes.
const MAX_TOTAL_UNCOMPRESSED: u64 = 2 * 1024 * 1024 * 1024;
/// Largest accepted single member.
const MAX_MEMBER_BYTES: u64 = 1024 * 1024 * 1024;
/// Release archives currently carry 21 members; keep a bounded allowance for
/// versioned helpers added by a future manifest schema.
const MAX_MEMBERS: usize = 100;
const MAX_MANIFEST_BYTES: u64 = 512 * 1024;
const MAX_CHECKSUMS_BYTES: u64 = MAX_CHECKSUM_BYTES;
const MAX_PACKAGE_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_JSON_METADATA_BYTES: u64 = MAX_METADATA_BYTES as u64;
const MAX_NAME_BYTES: usize = 200;
const READ_BUFFER: usize = 64 * 1024;
/// PE parsing needs the COFF header plus the subsystem field; the offset is
/// bounded to 1 MiB exactly as in the installed-package verifier.
const PE_PREFIX_LIMIT: u64 = 1024 * 1024 + 94;
const ELF_MACHO_PREFIX_LIMIT: u64 = 64;
/// PAX/GNU extension payload bounds for tar headers.
const MAX_TAR_EXTENSION_BYTES: u64 = 64 * 1024;
const MAX_TAR_EXTENSION_TOTAL: u64 = 256 * 1024;
const MAX_TAR_LONG_NAME_BYTES: u64 = 2048;
const MAX_TAR_RAW_HEADERS: usize = MAX_MEMBERS * 4 + 32;
const MAX_TAR_TRAILING_BYTES: u64 = 1024 * 1024;

fn reject(detail: &'static str) -> CliError {
    ProtocolError::new(
        CanonicalCode::SchemaIncompatible,
        format!("release bundle rejected: {detail}"),
    )
    .into()
}

fn io_failure(_: std::io::Error) -> CliError {
    ProtocolError::new(
        CanonicalCode::SourceIo,
        "release bundle I/O failed; the bundle was not accepted",
    )
    .into()
}

fn deadline_failure() -> CliError {
    ProtocolError::new(
        CanonicalCode::SourceIo,
        "release bundle deadline exceeded; the bundle was not accepted",
    )
    .into()
}

fn check_deadline(deadline: Instant) -> Result<(), CliError> {
    if Instant::now() >= deadline {
        Err(deadline_failure())
    } else {
        Ok(())
    }
}

fn ensure(condition: bool, detail: &'static str) -> Result<(), CliError> {
    if condition {
        Ok(())
    } else {
        Err(reject(detail))
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn safe_component(part: &str) -> bool {
    if part.is_empty()
        || part == "."
        || part == ".."
        || part.ends_with('.')
        || part.len() > MAX_NAME_BYTES
        || !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    {
        return false;
    }
    let upper = part.to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or(upper.as_str());
    !matches!(stem, "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

fn safe_member(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains('\\')
        && !value.contains(':')
        && value.split('/').all(safe_component)
}

fn valid_version(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 51
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
    {
        return false;
    }
    let (rest, build) = match value.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (value, None),
    };
    if build.is_some_and(|build| !valid_identifiers(build)) {
        return false;
    }
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|part| valid_number(part)) {
        return false;
    }
    let Some(pre) = pre else {
        return true;
    };
    valid_identifiers(pre)
        && pre.split('.').all(|part| {
            !(part.bytes().all(|b| b.is_ascii_digit()) && part.len() > 1 && part.starts_with('0'))
        })
}

fn valid_number(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn valid_identifiers(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_utc(value: &str) -> bool {
    (20..=35).contains(&value.len()) && (value.ends_with('Z') || value.ends_with("+00:00"))
}

fn expected_app_name(target: &str) -> &'static str {
    if target.ends_with("windows-msvc") {
        "agent-session-grep.exe"
    } else {
        "agent-session-grep"
    }
}

fn expected_alias_name(target: &str) -> &'static str {
    if target.ends_with("windows-msvc") {
        "asg.exe"
    } else {
        "asg"
    }
}

fn expected_supervisor_name(target: &str) -> &'static str {
    if target.ends_with("windows-msvc") {
        "asg-supervisor.exe"
    } else {
        "asg-supervisor"
    }
}

fn expected_format(target: &str) -> &'static str {
    if target.ends_with("windows-msvc") {
        "zip"
    } else {
        "tar.gz"
    }
}

fn expected_member_mode(
    name: &str,
    app: &str,
    alias: &str,
    versioned_app: &str,
    supervisor: &str,
) -> &'static str {
    if name.ends_with("/helpers/update-check.sh")
        || name == app
        || name == alias
        || name == versioned_app
        || name == supervisor
        || name == "package-install.sh"
    {
        "0755"
    } else {
        "0644"
    }
}

/// The fixed 17-member payload whitelist for the managed candidate layout.
/// This mirrors the installed-package verifier; the shared verifier remains
/// authoritative once the caller has staged and published the package.
fn required_package_members(
    app: &str,
    alias: &str,
    dir: &str,
    supervisor: &str,
) -> BTreeSet<String> {
    [
        app.to_owned(),
        alias.to_owned(),
        format!("{dir}/{app}"),
        format!("{dir}/{supervisor}"),
        format!("{dir}/release.json"),
        "current.json".to_owned(),
        "package-install.ps1".to_owned(),
        "package-install.sh".to_owned(),
        "INSTALL-AND-UPGRADE.md".to_owned(),
        "README.md".to_owned(),
        "CHANGELOG.md".to_owned(),
        "LICENSE-MIT".to_owned(),
        "LICENSE-APACHE".to_owned(),
        "NOTICE".to_owned(),
        "SECURITY.md".to_owned(),
        "THIRD-PARTY-DEPENDENCIES.json".to_owned(),
        "THIRD-PARTY-DEPENDENCIES.csv".to_owned(),
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Release manifest (`<root>.manifest.json`)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveManifest {
    schema: String,
    release: ManifestRelease,
    archive: ManifestArchive,
    inputs: ManifestInputs,
    provenance: ManifestProvenance,
    layout: String,
    install_manifest_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRelease {
    tag: String,
    version: String,
    target: String,
    source_commit: String,
    source_date_epoch: u64,
    unsigned: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestArchive {
    filename: String,
    format: String,
    root: String,
    sha256: String,
    size_bytes: u64,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    name: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestInputs {
    cargo_lock_sha256: String,
    dependency_inventory_schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestProvenance {
    kind: String,
    cryptographic_attestation: bool,
    limitation: String,
}

fn validate_manifest(
    manifest: &ArchiveManifest,
    expected_target: &str,
    archive_name: &str,
    manifest_name: &str,
) -> Result<(), CliError> {
    ensure(manifest.schema == ARCHIVE_SCHEMA, "manifest schema")?;
    ensure(manifest.layout == MANAGED_LAYOUT, "manifest layout")?;
    ensure(
        MANAGED_TARGETS.contains(&expected_target),
        "unsupported expected target",
    )?;
    ensure(
        manifest.release.target == expected_target,
        "manifest target mismatch",
    )?;
    ensure(valid_version(&manifest.release.version), "manifest version")?;
    ensure(
        manifest.release.tag == format!("v{}", manifest.release.version),
        "manifest tag",
    )?;
    ensure(
        lower_hex(&manifest.release.source_commit, 40),
        "manifest source commit",
    )?;
    ensure(
        manifest.release.source_date_epoch < 253_402_300_800,
        "manifest source date",
    )?;
    ensure(manifest.release.unsigned, "manifest must be unsigned")?;
    ensure(
        manifest.archive.format == expected_format(expected_target),
        "archive format does not match target",
    )?;
    let expected_root = format!(
        "agent-session-grep-{}-{}",
        manifest.release.tag, manifest.release.target
    );
    ensure(manifest.archive.root == expected_root, "archive root")?;
    ensure(
        manifest.archive.filename
            == format!("{}.{}", manifest.archive.root, manifest.archive.format),
        "archive filename",
    )?;
    ensure(
        manifest.archive.filename == archive_name,
        "archive file name mismatch",
    )?;
    ensure(
        manifest_name == format!("{}.manifest.json", manifest.archive.root),
        "manifest file name mismatch",
    )?;
    ensure(lower_hex(&manifest.archive.sha256, 64), "archive digest")?;
    ensure(
        manifest.archive.size_bytes > 0 && manifest.archive.size_bytes <= MAX_ARCHIVE_BYTES,
        "archive size",
    )?;
    ensure(
        lower_hex(&manifest.install_manifest_sha256, 64),
        "package manifest digest",
    )?;
    ensure(
        lower_hex(&manifest.inputs.cargo_lock_sha256, 64),
        "cargo lock digest",
    )?;
    ensure(
        manifest.inputs.dependency_inventory_schema == DEPENDENCY_SCHEMA,
        "dependency inventory schema",
    )?;
    ensure(
        manifest.provenance.kind == "self-reported-build-metadata",
        "provenance kind",
    )?;
    ensure(
        !manifest.provenance.cryptographic_attestation,
        "manifest must not claim an attestation",
    )?;
    ensure(
        !manifest.provenance.limitation.is_empty()
            && manifest.provenance.limitation.len() <= 1024
            && manifest.provenance.limitation.is_ascii(),
        "provenance limitation",
    )?;
    ensure(
        !manifest.archive.files.is_empty() && manifest.archive.files.len() <= MAX_MEMBERS,
        "manifest member count",
    )?;
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    for file in &manifest.archive.files {
        let relative = file
            .name
            .strip_prefix(&manifest.archive.root)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| reject("manifest member root"))?;
        ensure(safe_member(relative), "manifest member path")?;
        ensure(lower_hex(&file.sha256, 64), "manifest member digest")?;
        ensure(
            matches!(file.mode.as_str(), "0644" | "0755"),
            "manifest member mode",
        )?;
        if relative == PACKAGE_MANIFEST_NAME {
            ensure(file.mode == "0644", "package manifest mode")?;
        }
        ensure(file.size_bytes <= MAX_MEMBER_BYTES, "manifest member size")?;
        total = total
            .checked_add(file.size_bytes)
            .ok_or_else(|| reject("manifest total size"))?;
        ensure(total <= MAX_TOTAL_UNCOMPRESSED, "manifest total size")?;
        ensure(
            names.insert(relative.to_owned()),
            "manifest duplicate member",
        )?;
        ensure(
            folded.insert(relative.to_ascii_lowercase()),
            "manifest case collision",
        )?;
    }
    for name in &names {
        let mut prefix = String::new();
        let parts: Vec<&str> = name.split('/').collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            ensure(
                !names.contains(&prefix),
                "manifest member/directory collision",
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive inventory
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchiveFormat {
    Zip,
    TarGz,
}

struct ArchiveEntry {
    name: String,
    size: u64,
    mode: u16,
}

fn archive_format(value: &str) -> Result<ArchiveFormat, CliError> {
    match value {
        "zip" => Ok(ArchiveFormat::Zip),
        "tar.gz" => Ok(ArchiveFormat::TarGz),
        _ => Err(reject("archive format")),
    }
}

fn mode_number(value: &str) -> Result<u16, CliError> {
    match value {
        "0644" => Ok(0o644),
        "0755" => Ok(0o755),
        _ => Err(reject("member mode")),
    }
}

fn zip_central_count(file: &mut File) -> Result<u64, CliError> {
    let length = file.metadata().map_err(io_failure)?.len();
    ensure(length >= 22, "zip end record")?;
    let tail_length = std::cmp::min(length, 22 + 65_535) as usize;
    file.seek(SeekFrom::Start(length - tail_length as u64))
        .map_err(io_failure)?;
    let mut tail = vec![0u8; tail_length];
    file.read_exact(&mut tail).map_err(io_failure)?;
    let mut found = None;
    for index in (0..=tail_length - 22).rev() {
        if tail[index..index + 4] == [0x50, 0x4b, 0x05, 0x06] {
            let comment = u16::from_le_bytes([tail[index + 20], tail[index + 21]]) as usize;
            if index + 22 + comment == tail_length {
                found = Some(index);
                break;
            }
        }
    }
    let index = found.ok_or_else(|| reject("zip end record"))?;
    let disk = u16::from_le_bytes([tail[index + 4], tail[index + 5]]);
    let directory_disk = u16::from_le_bytes([tail[index + 6], tail[index + 7]]);
    let entries_disk = u16::from_le_bytes([tail[index + 8], tail[index + 9]]);
    let entries_total = u16::from_le_bytes([tail[index + 10], tail[index + 11]]);
    let directory_size = u32::from_le_bytes([
        tail[index + 12],
        tail[index + 13],
        tail[index + 14],
        tail[index + 15],
    ]);
    let directory_offset = u32::from_le_bytes([
        tail[index + 16],
        tail[index + 17],
        tail[index + 18],
        tail[index + 19],
    ]);
    ensure(
        disk == 0
            && directory_disk == 0
            && entries_disk == entries_total
            && directory_size != u32::MAX
            && directory_offset != u32::MAX
            && entries_total != u16::MAX,
        "zip64 or multi-disk archive",
    )?;
    let eocd_absolute = length - tail_length as u64 + index as u64;
    ensure(
        u64::from(directory_offset) + u64::from(directory_size) == eocd_absolute,
        "zip trailing data",
    )?;
    Ok(u64::from(entries_total))
}

fn zip_inventory(file: &mut File, deadline: Instant) -> Result<Vec<ArchiveEntry>, CliError> {
    let declared = zip_central_count(file)?;
    ensure(declared as usize <= MAX_MEMBERS, "archive member count")?;
    file.rewind().map_err(io_failure)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| reject("zip open"))?;
    ensure(
        archive.len() as u64 == declared,
        "zip duplicate member records",
    )?;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        check_deadline(deadline)?;
        let entry = archive
            .by_index(index)
            .map_err(|_| reject("zip member record"))?;
        ensure(!entry.is_dir(), "archive directory member")?;
        ensure(!entry.encrypted(), "encrypted archive member")?;
        ensure(!entry.is_symlink(), "archive symlink member")?;
        ensure(
            matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            ),
            "unsupported zip compression",
        )?;
        let raw_mode = entry
            .unix_mode()
            .ok_or_else(|| reject("missing unix member mode"))?;
        // zip 9 keeps the S_IFREG type bits that zip 7 stripped; both forms
        // must pass the same regular-file gate.
        let kind = raw_mode & 0o170000;
        ensure(kind == 0 || kind == 0o100000, "archive special member type")?;
        let permissions = raw_mode & 0o777;
        ensure(matches!(permissions, 0o644 | 0o755), "archive member mode")?;
        let size = entry.size();
        ensure(size <= MAX_MEMBER_BYTES, "archive member size")?;
        ensure(
            entry.compressed_size() <= MAX_ARCHIVE_BYTES,
            "archive compressed size",
        )?;
        entries.push(ArchiveEntry {
            name: entry
                .name()
                .map_err(|_| reject("zip member name"))?
                .to_string(),
            size,
            mode: permissions as u16,
        });
    }
    Ok(entries)
}

fn tar_inventory(file: &mut File, deadline: Instant) -> Result<Vec<ArchiveEntry>, CliError> {
    file.rewind().map_err(io_failure)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = Vec::new();
    let iterator = archive.entries().map_err(|_| reject("tar open"))?;
    for entry in iterator {
        check_deadline(deadline)?;
        ensure(entries.len() < MAX_MEMBERS, "archive member count")?;
        let entry = entry.map_err(|_| reject("tar member record"))?;
        let kind = entry.header().entry_type();
        ensure(kind.is_file(), "archive non-regular member")?;
        ensure(entry.link_name_bytes().is_none(), "hidden tar link")?;
        let size = entry.size();
        ensure(size <= MAX_MEMBER_BYTES, "archive member size")?;
        let mode = entry
            .header()
            .mode()
            .map_err(|_| reject("tar member mode"))?
            & 0o777;
        ensure(matches!(mode, 0o644 | 0o755), "archive member mode")?;
        let path = entry.path_bytes();
        let name = std::str::from_utf8(&path)
            .map_err(|_| reject("archive member name"))?
            .to_owned();
        entries.push(ArchiveEntry {
            name,
            size,
            mode: mode as u16,
        });
    }
    Ok(entries)
}

fn validate_rooted_path(value: &str, root: &str) -> Result<(), CliError> {
    let relative = value
        .strip_prefix(root)
        .and_then(|value| value.strip_prefix('/'))
        .ok_or_else(|| reject("tar extension path"))?;
    ensure(
        !relative.is_empty() && safe_member(relative),
        "tar extension path",
    )
}

/// Validate one PAX payload strictly. Returns the `size` override, if any.
fn validate_pax_records(payload: &[u8], root: &str, global: bool) -> Result<Option<u64>, CliError> {
    ensure(!payload.is_empty(), "pax record")?;
    let mut position = 0usize;
    let mut size = None;
    while position < payload.len() {
        let space = payload[position..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| reject("pax record"))?
            + position;
        let length: usize = std::str::from_utf8(&payload[position..space])
            .map_err(|_| reject("pax record"))?
            .parse()
            .map_err(|_| reject("pax record"))?;
        let end = position
            .checked_add(length)
            .ok_or_else(|| reject("pax record"))?;
        ensure(end <= payload.len() && end > space + 1, "pax record")?;
        let record = &payload[space + 1..end];
        ensure(record.last() == Some(&b'\n'), "pax record")?;
        let record = &record[..record.len() - 1];
        let equals = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| reject("pax record"))?;
        let key = &record[..equals];
        let value = &record[equals + 1..];
        ensure(
            !key.is_empty()
                && key.len() <= 64
                && key.is_ascii()
                && value.len() <= 4096
                && !value.contains(&0),
            "pax record",
        )?;
        let key = std::str::from_utf8(key).map_err(|_| reject("pax record"))?;
        match key {
            "path" => {
                ensure(!global, "global pax path")?;
                let value = std::str::from_utf8(value).map_err(|_| reject("pax path"))?;
                validate_rooted_path(value, root)?;
            }
            "linkpath" => return Err(reject("pax hidden link")),
            "size" => {
                ensure(!global, "global pax size")?;
                ensure(size.is_none(), "duplicate pax size")?;
                let value = std::str::from_utf8(value).map_err(|_| reject("pax size"))?;
                let parsed: u64 = value.parse().map_err(|_| reject("pax size"))?;
                ensure(parsed <= MAX_MEMBER_BYTES, "pax size")?;
                size = Some(parsed);
            }
            "mtime" | "atime" | "ctime" | "uid" | "gid" | "uname" | "gname" | "charset"
            | "comment" | "hdrcharset" => {}
            _ => return Err(reject("pax keyword")),
        }
        position = end;
    }
    Ok(size)
}

/// Bound and validate raw tar extension headers, hidden links and trailing
/// bytes before any logical member is read or extracted.
fn scan_tar_header_stream(file: &mut File, root: &str, deadline: Instant) -> Result<(), CliError> {
    file.rewind().map_err(io_failure)?;
    let decoder = flate2::read::MultiGzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut raw_headers = 0usize;
    let mut extension_total = 0u64;
    let mut pending: Option<Option<u64>> = None;
    {
        let mut entries = archive.entries().map_err(|_| reject("tar open"))?.raw(true);
        for entry in &mut entries {
            check_deadline(deadline)?;
            raw_headers = raw_headers
                .checked_add(1)
                .ok_or_else(|| reject("tar header count"))?;
            ensure(raw_headers <= MAX_TAR_RAW_HEADERS, "tar header count")?;
            let mut entry = entry.map_err(|_| reject("tar header"))?;
            let kind = entry.header().entry_type();
            let size = entry.size();
            if kind.is_pax_local_extensions() || kind.is_pax_global_extensions() {
                ensure(size <= MAX_TAR_EXTENSION_BYTES, "tar extension size")?;
                extension_total = extension_total
                    .checked_add(size)
                    .ok_or_else(|| reject("tar extension total"))?;
                ensure(
                    extension_total <= MAX_TAR_EXTENSION_TOTAL,
                    "tar extension total",
                )?;
                let payload = read_bounded(&mut entry, MAX_TAR_EXTENSION_BYTES, deadline)?;
                let global = kind.is_pax_global_extensions();
                let pax_size = validate_pax_records(&payload, root, global)?;
                if !global {
                    ensure(pending.is_none(), "tar extension sequence")?;
                    pending = Some(pax_size);
                }
            } else if kind.is_gnu_longname() {
                ensure(pending.is_none(), "tar extension sequence")?;
                ensure(size <= MAX_TAR_LONG_NAME_BYTES, "tar long name size")?;
                extension_total = extension_total
                    .checked_add(size)
                    .ok_or_else(|| reject("tar extension total"))?;
                ensure(
                    extension_total <= MAX_TAR_EXTENSION_TOTAL,
                    "tar extension total",
                )?;
                let payload = read_bounded(&mut entry, MAX_TAR_LONG_NAME_BYTES, deadline)?;
                let name = payload.strip_suffix(&[0]).unwrap_or(&payload);
                ensure(!name.contains(&0), "tar long name")?;
                let name = std::str::from_utf8(name).map_err(|_| reject("tar long name"))?;
                validate_rooted_path(name, root)?;
                pending = Some(None);
            } else if kind.is_gnu_longlink() {
                return Err(reject("tar long link"));
            } else {
                ensure(kind.is_file(), "archive non-regular member")?;
                ensure(size <= MAX_MEMBER_BYTES, "archive member size")?;
                if let Some(Some(override_size)) = pending.take() {
                    ensure(
                        entry
                            .header()
                            .size()
                            .map_err(|_| reject("tar header size"))?
                            == override_size,
                        "pax size mismatch",
                    )?;
                }
            }
        }
    }
    ensure(pending.is_none(), "tar extension sequence")?;
    let decoder = archive.into_inner();
    let mut trailing = Vec::new();
    decoder
        .take(MAX_TAR_TRAILING_BYTES + 1)
        .read_to_end(&mut trailing)
        .map_err(|_| reject("tar trailing data"))?;
    ensure(
        trailing.len() as u64 <= MAX_TAR_TRAILING_BYTES && trailing.iter().all(|byte| *byte == 0),
        "tar trailing data",
    )?;
    Ok(())
}

fn cross_check_entries(
    entries: &[ArchiveEntry],
    manifest: &ArchiveManifest,
) -> Result<(), CliError> {
    ensure(
        entries.len() == manifest.archive.files.len(),
        "archive inventory",
    )?;
    let mut expected = BTreeMap::new();
    for file in &manifest.archive.files {
        let relative = file
            .name
            .strip_prefix(&manifest.archive.root)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| reject("member root"))?;
        expected.insert(relative, file);
    }
    let mut seen = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for entry in entries {
        let relative = entry
            .name
            .strip_prefix(&manifest.archive.root)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| reject("archive member root"))?;
        ensure(safe_member(relative), "archive member path")?;
        let file = expected
            .get(relative)
            .ok_or_else(|| reject("unknown archive member"))?;
        ensure(seen.insert(relative.to_owned()), "duplicate archive member")?;
        ensure(
            folded.insert(relative.to_ascii_lowercase()),
            "archive case collision",
        )?;
        ensure(entry.size == file.size_bytes, "archive member size")?;
        ensure(
            entry.mode == mode_number(&file.mode)?,
            "archive member mode",
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Member streaming
// ---------------------------------------------------------------------------

fn read_bounded(reader: &mut dyn Read, limit: u64, deadline: Instant) -> Result<Vec<u8>, CliError> {
    let mut value = Vec::new();
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        check_deadline(deadline)?;
        let count = reader.read(&mut buffer).map_err(io_failure)?;
        if count == 0 {
            break;
        }
        let next = value
            .len()
            .checked_add(count)
            .ok_or_else(|| reject("metadata size"))?;
        ensure(next as u64 <= limit, "metadata size")?;
        value.extend_from_slice(&buffer[..count]);
    }
    Ok(value)
}

fn hash_and_count(
    reader: &mut dyn Read,
    limit: u64,
    deadline: Instant,
    capture: usize,
) -> Result<(String, u64, Vec<u8>), CliError> {
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut prefix = Vec::new();
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        check_deadline(deadline)?;
        let count = reader.read(&mut buffer).map_err(io_failure)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| reject("member size"))?;
        ensure(total <= limit, "member size")?;
        digest.update(&buffer[..count]);
        if prefix.len() < capture {
            let take = std::cmp::min(capture - prefix.len(), count);
            prefix.extend_from_slice(&buffer[..take]);
        }
    }
    Ok((format!("{:x}", digest.finalize()), total, prefix))
}

fn hash_file<R: Read + Seek>(
    reader: &mut R,
    limit: u64,
    deadline: Instant,
) -> Result<(String, u64), CliError> {
    reader.seek(SeekFrom::Start(0)).map_err(io_failure)?;
    let (digest, total, _) = hash_and_count(reader, limit, deadline, 0)?;
    Ok((digest, total))
}

// ---------------------------------------------------------------------------
// Public verified bundle
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberRole {
    App,
    Alias,
    VersionedApp,
    Supervisor,
    PackageManifest,
    Other,
}

struct VerifiedMember {
    relative: String,
    sha256: String,
    size: u64,
    mode: u16,
    role: MemberRole,
}

/// A fully verified, offline release bundle.
///
/// The archive handle is held open for the lifetime of the value. On Windows
/// it is opened without write/delete sharing, so the source cannot be swapped
/// or modified while it is in use. Nothing is written until
/// [`VerifiedBundle::members_to_new_private_stage`] is called.
pub(crate) struct VerifiedBundle {
    archive: File,
    format: ArchiveFormat,
    root: String,
    version: String,
    target: String,
    source_commit: String,
    relative_dir: String,
    archive_sha256: String,
    manifest_sha256: String,
    app_sha256: String,
    supervisor_sha256: String,
    catalog_schema: u32,
    control_schema: u32,
    launcher_protocol: u32,
    members: Vec<VerifiedMember>,
    deadline: Instant,
}

impl VerifiedBundle {
    /// Verify the bundle triple without creating, modifying or executing
    /// anything on the host filesystem.
    pub(crate) fn open(
        archive: &Path,
        manifest: &Path,
        sums: &Path,
        expected_target: &str,
        deadline: Instant,
    ) -> Result<Self, CliError> {
        check_deadline(deadline)?;
        ensure(
            MANAGED_TARGETS.contains(&expected_target),
            "unsupported expected target",
        )?;

        let archive_path = absolute(archive)?;
        let manifest_path = absolute(manifest)?;
        let sums_path = absolute(sums)?;
        ensure(
            sums_path
                .file_name()
                .is_some_and(|name| name == CHECKSUMS_NAME),
            "checksum file name",
        )?;
        let archive_name = archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| reject("archive file name"))?
            .to_owned();
        let manifest_name = manifest_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| reject("manifest file name"))?
            .to_owned();
        let parent = canonical_parent(&archive_path)?;
        ensure(
            canonical_parent(&manifest_path)? == parent && canonical_parent(&sums_path)? == parent,
            "bundle files must be siblings",
        )?;

        let mut manifest_file = pinned(&manifest_path)?;
        let manifest_bytes = read_bounded(&mut manifest_file, MAX_MANIFEST_BYTES, deadline)?;
        let manifest_sha256 = sha256_bytes(&manifest_bytes);
        let mut sums_file = pinned(&sums_path)?;
        let sums_bytes = read_bounded(&mut sums_file, MAX_CHECKSUMS_BYTES, deadline)?;
        let checksums = parse_release_checksums(&sums_bytes)?;
        ensure(
            checksums
                .get(&archive_name)
                .is_some_and(|value| lower_hex(value, 64)),
            "checksum for archive",
        )?;
        ensure(
            checksums
                .get(&manifest_name)
                .is_some_and(|value| value == &manifest_sha256),
            "checksum for manifest",
        )?;

        let manifest: ArchiveManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| reject("manifest JSON"))?;
        validate_manifest(&manifest, expected_target, &archive_name, &manifest_name)?;
        validate_checksum_assets(&checksums, &manifest.release.version)?;
        ensure(
            checksums
                .get(&archive_name)
                .is_some_and(|value| value == &manifest.archive.sha256),
            "archive checksum mismatch",
        )?;

        let mut archive_file = pinned(&archive_path)?;
        let length = archive_file.metadata().map_err(io_failure)?.len();
        ensure(length <= MAX_ARCHIVE_BYTES, "archive size")?;
        ensure(
            length == manifest.archive.size_bytes,
            "archive size mismatch",
        )?;
        let (archive_sha256, hashed) = hash_file(&mut archive_file, MAX_ARCHIVE_BYTES, deadline)?;
        ensure(hashed == length, "archive size changed")?;
        ensure(
            archive_sha256 == manifest.archive.sha256,
            "archive digest mismatch",
        )?;

        let format = archive_format(&manifest.archive.format)?;
        let entries = match format {
            ArchiveFormat::Zip => zip_inventory(&mut archive_file, deadline)?,
            ArchiveFormat::TarGz => {
                scan_tar_header_stream(&mut archive_file, &manifest.archive.root, deadline)?;
                tar_inventory(&mut archive_file, deadline)?
            }
        };
        cross_check_entries(&entries, &manifest)?;

        let package_name = format!("{}/{}", manifest.archive.root, PACKAGE_MANIFEST_NAME);
        let package_bytes = read_archive_member(
            &mut archive_file,
            format,
            &package_name,
            MAX_PACKAGE_MANIFEST_BYTES,
            deadline,
        )?;
        let package_sha256 = sha256_bytes(&package_bytes);
        ensure(
            package_sha256 == manifest.install_manifest_sha256,
            "package manifest digest",
        )?;
        let package_file = manifest
            .archive
            .files
            .iter()
            .find(|file| file.name == package_name)
            .ok_or_else(|| reject("missing package manifest"))?;
        ensure(
            package_file.sha256 == package_sha256,
            "package manifest inventory digest",
        )?;
        let package = Manifest::parse(&package_bytes)?;
        let verified =
            verify_package_identity(&manifest, &package, &mut archive_file, format, deadline)?;

        Ok(VerifiedBundle {
            archive: archive_file,
            format,
            root: manifest.archive.root.clone(),
            version: verified.version,
            target: verified.target,
            source_commit: verified.source_commit,
            relative_dir: verified.relative_dir,
            archive_sha256,
            manifest_sha256,
            app_sha256: verified.app_sha256,
            supervisor_sha256: verified.supervisor_sha256,
            catalog_schema: verified.catalog_schema,
            control_schema: verified.control_schema,
            launcher_protocol: verified.launcher_protocol,
            members: verified.members,
            deadline,
        })
    }

    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    pub(crate) fn source_commit(&self) -> &str {
        &self.source_commit
    }

    /// Relative immutable version directory inside the installation prefix,
    /// for example `versions/0.2.0-beta.1-0123456789ab`.
    pub(crate) fn relative_dir(&self) -> &str {
        &self.relative_dir
    }

    pub(crate) fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    pub(crate) fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub(crate) fn app_sha256(&self) -> &str {
        &self.app_sha256
    }

    /// Digest from the exact versioned supervisor member, after native-target,
    /// subsystem and full archive/member integrity checks.
    pub(crate) fn supervisor_sha256(&self) -> &str {
        &self.supervisor_sha256
    }

    pub(crate) fn catalog_schema(&self) -> u32 {
        self.catalog_schema
    }

    pub(crate) fn control_schema(&self) -> u32 {
        self.control_schema
    }

    pub(crate) fn launcher_protocol(&self) -> u32 {
        self.launcher_protocol
    }

    /// Stream every verified member into `stage`.
    ///
    /// `stage` must already exist, be absolute, be owned by the caller's
    /// private root, contain no entries and be a real directory rather than a
    /// link. Files are created with `create_new`, written with private
    /// permissions, flushed, verified again against the manifest and only then
    /// made executable/readable. Nothing is deleted on failure: the caller's
    /// update journal owns partial staging artifacts.
    pub(crate) fn members_to_new_private_stage(
        &self,
        stage: &Path,
        deadline: Instant,
    ) -> Result<(), CliError> {
        let deadline = std::cmp::min(deadline, self.deadline);
        check_deadline(deadline)?;
        let stage_path = check_stage(stage)?;

        let mut written = BTreeSet::new();
        let mut source = &self.archive;
        match self.format {
            ArchiveFormat::Zip => {
                source.rewind().map_err(io_failure)?;
                let mut archive =
                    zip::ZipArchive::new(&mut source).map_err(|_| reject("zip open"))?;
                for index in 0..archive.len() {
                    check_deadline(deadline)?;
                    let mut entry = archive
                        .by_index(index)
                        .map_err(|_| reject("zip member record"))?;
                    let name = entry
                        .name()
                        .map_err(|_| reject("zip member name"))?
                        .to_string();
                    let member = self.member(&name)?;
                    ensure(written.insert(member.relative.clone()), "duplicate member")?;
                    let path = stage_member_path(&stage_path, &member.relative)?;
                    let file = create_private_file(&path)?;
                    write_member(&mut entry, file, &path, member, deadline)?;
                }
            }
            ArchiveFormat::TarGz => {
                source.rewind().map_err(io_failure)?;
                let decoder = flate2::read::GzDecoder::new(&mut source);
                let mut archive = tar::Archive::new(decoder);
                let iterator = archive.entries().map_err(|_| reject("tar open"))?;
                for entry in iterator {
                    check_deadline(deadline)?;
                    let mut entry = entry.map_err(|_| reject("tar member record"))?;
                    let path_bytes = entry.path_bytes();
                    let name = std::str::from_utf8(&path_bytes)
                        .map_err(|_| reject("archive member name"))?;
                    let member = self.member(name)?;
                    ensure(written.insert(member.relative.clone()), "duplicate member")?;
                    let path = stage_member_path(&stage_path, &member.relative)?;
                    let file = create_private_file(&path)?;
                    write_member(&mut entry, file, &path, member, deadline)?;
                }
            }
        }
        ensure(
            written.len() == self.members.len(),
            "missing archive member during extraction",
        )?;
        #[cfg(unix)]
        sync_directories(&stage_path)?;

        let (final_digest, final_size) = hash_file(&mut source, MAX_ARCHIVE_BYTES, deadline)?;
        ensure(
            final_size == self.archive_length()? && final_digest == self.archive_sha256,
            "archive changed during extraction",
        )?;
        Ok(())
    }

    fn archive_length(&self) -> Result<u64, CliError> {
        self.archive
            .metadata()
            .map_err(io_failure)
            .map(|meta| meta.len())
    }

    fn member(&self, name: &str) -> Result<&VerifiedMember, CliError> {
        let relative = name
            .strip_prefix(&self.root)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| reject("archive member root"))?;
        self.members
            .iter()
            .find(|member| member.relative == relative)
            .ok_or_else(|| reject("unknown archive member"))
    }
}

fn canonical_parent(path: &Path) -> Result<PathBuf, CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| reject("bundle parent directory"))?;
    fs::canonicalize(parent).map_err(io_failure)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_archive_member(
    archive: &mut File,
    format: ArchiveFormat,
    name: &str,
    limit: u64,
    deadline: Instant,
) -> Result<Vec<u8>, CliError> {
    archive.seek(SeekFrom::Start(0)).map_err(io_failure)?;
    match format {
        ArchiveFormat::Zip => {
            let mut zip = zip::ZipArchive::new(archive).map_err(|_| reject("zip open"))?;
            let mut entry = zip.by_name(name).map_err(|_| reject("missing member"))?;
            ensure(!entry.encrypted(), "encrypted archive member")?;
            read_bounded(&mut entry, limit, deadline)
        }
        ArchiveFormat::TarGz => {
            let decoder = flate2::read::GzDecoder::new(archive);
            let mut tar = tar::Archive::new(decoder);
            let iterator = tar.entries().map_err(|_| reject("tar open"))?;
            for entry in iterator {
                check_deadline(deadline)?;
                let mut entry = entry.map_err(|_| reject("tar member record"))?;
                let path = entry.path_bytes();
                let candidate =
                    std::str::from_utf8(&path).map_err(|_| reject("archive member name"))?;
                if candidate == name {
                    return read_bounded(&mut entry, limit, deadline);
                }
            }
            Err(reject("missing member"))
        }
    }
}

struct PackageIdentity {
    version: String,
    target: String,
    source_commit: String,
    relative_dir: String,
    app_sha256: String,
    supervisor_sha256: String,
    catalog_schema: u32,
    control_schema: u32,
    launcher_protocol: u32,
    members: Vec<VerifiedMember>,
}

fn verify_package_identity(
    manifest: &ArchiveManifest,
    package: &Manifest,
    archive: &mut File,
    format: ArchiveFormat,
    deadline: Instant,
) -> Result<PackageIdentity, CliError> {
    let target = manifest.release.target.as_str();
    let app = expected_app_name(target);
    let alias = expected_alias_name(target);
    let supervisor = expected_supervisor_name(target);
    let version = manifest.release.version.clone();
    let source_commit = manifest.release.source_commit.clone();

    ensure(
        package.field("version")? == version.as_str(),
        "package version",
    )?;
    ensure(package.field("target")? == target, "package target")?;
    ensure(
        package.field("source_commit")? == source_commit.as_str(),
        "package source commit",
    )?;
    ensure(package.field("app")? == app, "package app name")?;
    ensure(
        package.field("supervisor")? == supervisor,
        "package supervisor name",
    )?;
    ensure(
        package
            .field("launcher_protocol")?
            .parse::<u32>()
            .is_ok_and(|value| value == LAUNCHER_PROTOCOL),
        "package launcher protocol",
    )?;
    let app_sha256 = package.field("app_sha256")?.to_owned();
    ensure(lower_hex(&app_sha256, 64), "package app digest")?;
    let supervisor_sha256 = package.field("supervisor_sha256")?.to_owned();
    ensure(
        lower_hex(&supervisor_sha256, 64),
        "package supervisor digest",
    )?;
    let relative_dir = package.field("dir")?.to_owned();
    ensure(safe_member(&relative_dir), "package version directory")?;
    let expected_dir = format!("versions/{}-{}", version, &app_sha256[..12]);
    ensure(relative_dir == expected_dir, "package version directory")?;
    ensure(relative_dir.len() <= 64, "package version directory length")?;
    let catalog_schema = package
        .field("catalog_schema")?
        .parse::<u32>()
        .map_err(|_| reject("package catalog schema"))?;
    let control_schema = package
        .field("control_schema")?
        .parse::<u32>()
        .map_err(|_| reject("package control schema"))?;
    ensure(catalog_schema > 0, "package catalog schema")?;
    ensure(control_schema > 0, "package control schema")?;
    ensure(
        valid_utc(package.field("built_at")?),
        "package build timestamp",
    )?;

    let mut expected_members = required_package_members(app, alias, &relative_dir, supervisor);
    let helpers = [
        format!("{relative_dir}/helpers/update-check.sh"),
        format!("{relative_dir}/helpers/update-check.ps1"),
    ];
    let helper_count = helpers
        .iter()
        .filter(|name| package.members.contains_key(*name))
        .count();
    ensure(
        helper_count == 0 || helper_count == 2,
        "incomplete update helper pair",
    )?;
    if helper_count == 2 {
        expected_members.extend(helpers);
    }
    let uninstall_tail = format!(
        "{relative_dir}/helpers/{}",
        crate::uninstall_command::WINDOWS_TAIL_HELPER
    );
    if package.members.contains_key(&uninstall_tail) {
        ensure(
            helper_count == 2,
            "uninstall helper requires complete update helper pair",
        )?;
        expected_members.insert(uninstall_tail);
    }

    let actual_members: BTreeSet<String> = package.members.keys().cloned().collect();
    ensure(
        actual_members == expected_members,
        "package member whitelist",
    )?;
    let versioned_app_name = format!("{relative_dir}/{app}");
    let supervisor_member_name = format!("{relative_dir}/{supervisor}");
    for (name, member) in &package.members {
        ensure(
            member.mode
                == expected_member_mode(
                    name,
                    app,
                    alias,
                    &versioned_app_name,
                    &supervisor_member_name,
                ),
            "package member mode",
        )?;
    }
    let launcher = package
        .members
        .get(app)
        .ok_or_else(|| reject("missing launcher"))?;
    let alias_member = package
        .members
        .get(alias)
        .ok_or_else(|| reject("missing alias"))?;
    let versioned_app = package
        .members
        .get(&versioned_app_name)
        .ok_or_else(|| reject("missing versioned app"))?;
    let supervisor_member = package
        .members
        .get(&supervisor_member_name)
        .ok_or_else(|| reject("missing supervisor"))?;
    ensure(
        launcher.sha == alias_member.sha,
        "launcher and alias must be identical",
    )?;
    ensure(
        launcher.sha != versioned_app.sha,
        "launcher and application must differ",
    )?;
    ensure(versioned_app.sha == app_sha256, "application digest")?;
    ensure(
        supervisor_member.sha == supervisor_sha256,
        "supervisor digest",
    )?;

    let pointer_name = format!("{}/current.json", manifest.archive.root);
    let release_name = format!("{}/{}/release.json", manifest.archive.root, relative_dir);
    let pointer_bytes = read_archive_member(
        archive,
        format,
        &pointer_name,
        MAX_JSON_METADATA_BYTES,
        deadline,
    )?;
    let release_bytes = read_archive_member(
        archive,
        format,
        &release_name,
        MAX_JSON_METADATA_BYTES,
        deadline,
    )?;
    let pointer: CurrentPointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| reject("current.json"))?;
    let release: ReleaseMetadata =
        serde_json::from_slice(&release_bytes).map_err(|_| reject("release.json"))?;
    ensure(pointer.schema == CURRENT_SCHEMA, "current.json schema")?;
    ensure(release.schema == RELEASE_SCHEMA, "release.json schema")?;
    ensure(pointer.version == version, "current.json version")?;
    ensure(release.version == version, "release.json version")?;
    ensure(release.target == target, "release.json target")?;
    ensure(
        release.source_commit == source_commit,
        "release.json source commit",
    )?;
    ensure(pointer.app == app, "current.json app")?;
    ensure(
        pointer.app_sha256 == app_sha256 && release.app_sha256 == app_sha256,
        "current.json application digest",
    )?;
    ensure(
        pointer.dir == relative_dir,
        "current.json version directory",
    )?;
    ensure(
        pointer.launcher_protocol == LAUNCHER_PROTOCOL,
        "current.json launcher protocol",
    )?;
    ensure(
        valid_utc(&pointer.activated_at),
        "current.json activation timestamp",
    )?;
    ensure(
        release.launcher_protocol_min.get() <= LAUNCHER_PROTOCOL
            && LAUNCHER_PROTOCOL <= release.launcher_protocol_max.get(),
        "release.json launcher protocol",
    )?;
    ensure(
        release.catalog_schema.get() == catalog_schema
            && release.control_schema.get() == control_schema,
        "release.json schema versions",
    )?;
    ensure(
        release.built_at == package.field("built_at")?,
        "release.json build timestamp",
    )?;

    // Every payload member must exactly match the archive manifest inventory
    // after stripping the archive root.
    for file in &manifest.archive.files {
        let relative = file
            .name
            .strip_prefix(&manifest.archive.root)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| reject("manifest member root"))?;
        if relative == PACKAGE_MANIFEST_NAME {
            continue;
        }
        let member = package
            .members
            .get(relative)
            .ok_or_else(|| reject("archive member not in package manifest"))?;
        ensure(
            member.sha == file.sha256 && member.size == file.size_bytes && member.mode == file.mode,
            "package manifest/member mismatch",
        )?;
    }
    for name in package.members.keys() {
        ensure(
            manifest
                .archive
                .files
                .iter()
                .any(|file| file.name == format!("{}/{}", manifest.archive.root, name)),
            "package member missing from archive manifest",
        )?;
    }

    let mut roles: BTreeMap<String, MemberRole> = BTreeMap::new();
    roles.insert(app.to_owned(), MemberRole::App);
    roles.insert(alias.to_owned(), MemberRole::Alias);
    roles.insert(versioned_app_name.clone(), MemberRole::VersionedApp);
    roles.insert(supervisor_member_name.clone(), MemberRole::Supervisor);
    roles.insert(
        PACKAGE_MANIFEST_NAME.to_owned(),
        MemberRole::PackageManifest,
    );

    let (digests, prefixes) =
        verify_member_digests(manifest, archive, format, &roles, target, deadline)?;
    let mut members = Vec::new();
    for file in &manifest.archive.files {
        let relative = file
            .name
            .strip_prefix(&manifest.archive.root)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| reject("manifest member root"))?
            .to_owned();
        ensure(
            digests
                .get(&relative)
                .is_some_and(|digest| digest == &file.sha256),
            "member digest",
        )?;
        let role = roles
            .get(relative.as_str())
            .copied()
            .unwrap_or(MemberRole::Other);
        if matches!(
            role,
            MemberRole::App | MemberRole::Alias | MemberRole::VersionedApp | MemberRole::Supervisor
        ) {
            let prefix = prefixes
                .get(&relative)
                .ok_or_else(|| reject("missing executable prefix"))?;
            native_target_bytes(prefix, target)?;
            if role == MemberRole::Supervisor {
                supervisor_gui_bytes(prefix, target)?;
            }
        }
        members.push(VerifiedMember {
            relative,
            sha256: file.sha256.clone(),
            size: file.size_bytes,
            mode: mode_number(&file.mode)?,
            role,
        });
    }
    ensure(
        members
            .iter()
            .filter(|member| member.role == MemberRole::PackageManifest)
            .count()
            == 1,
        "package manifest role",
    )?;
    ensure(
        members.iter().any(|member| member.role == MemberRole::App)
            && members
                .iter()
                .any(|member| member.role == MemberRole::Alias)
            && members
                .iter()
                .any(|member| member.role == MemberRole::VersionedApp)
            && members
                .iter()
                .any(|member| member.role == MemberRole::Supervisor),
        "executable member roles",
    )?;

    Ok(PackageIdentity {
        version,
        target: target.to_owned(),
        source_commit,
        relative_dir,
        app_sha256,
        supervisor_sha256,
        catalog_schema,
        control_schema,
        launcher_protocol: LAUNCHER_PROTOCOL,
        members,
    })
}

type MemberDigests = BTreeMap<String, String>;
type MemberPrefixes = BTreeMap<String, Vec<u8>>;

fn verify_member_digests(
    manifest: &ArchiveManifest,
    archive: &mut File,
    format: ArchiveFormat,
    roles: &BTreeMap<String, MemberRole>,
    target: &str,
    deadline: Instant,
) -> Result<(MemberDigests, MemberPrefixes), CliError> {
    let capture = if target.ends_with("windows-msvc") {
        PE_PREFIX_LIMIT
    } else {
        ELF_MACHO_PREFIX_LIMIT
    } as usize;
    let mut digests = BTreeMap::new();
    let mut prefixes = BTreeMap::new();
    archive.seek(SeekFrom::Start(0)).map_err(io_failure)?;
    match format {
        ArchiveFormat::Zip => {
            let mut zip = zip::ZipArchive::new(archive).map_err(|_| reject("zip open"))?;
            let declared = zip.len();
            ensure(
                declared == manifest.archive.files.len(),
                "archive inventory",
            )?;
            for index in 0..declared {
                check_deadline(deadline)?;
                let mut entry = zip
                    .by_index(index)
                    .map_err(|_| reject("zip member record"))?;
                let name = entry
                    .name()
                    .map_err(|_| reject("zip member name"))?
                    .to_string();
                let relative = name
                    .strip_prefix(&manifest.archive.root)
                    .and_then(|value| value.strip_prefix('/'))
                    .ok_or_else(|| reject("archive member root"))?
                    .to_owned();
                let expected = manifest
                    .archive
                    .files
                    .iter()
                    .find(|file| file.name == format!("{}/{}", manifest.archive.root, relative))
                    .ok_or_else(|| reject("unknown archive member"))?;
                let capture_here = roles.get(relative.as_str()).is_some_and(|role| {
                    *role != MemberRole::Other && *role != MemberRole::PackageManifest
                });
                let (digest, size, prefix) = hash_and_count(
                    &mut entry,
                    expected.size_bytes,
                    deadline,
                    if capture_here { capture } else { 0 },
                )?;
                ensure(size == expected.size_bytes, "member size")?;
                if capture_here {
                    prefixes.insert(relative.clone(), prefix);
                }
                digests.insert(relative, digest);
            }
        }
        ArchiveFormat::TarGz => {
            let decoder = flate2::read::GzDecoder::new(archive);
            let mut tar = tar::Archive::new(decoder);
            let iterator = tar.entries().map_err(|_| reject("tar open"))?;
            for entry in iterator {
                check_deadline(deadline)?;
                let mut entry = entry.map_err(|_| reject("tar member record"))?;
                let path = entry.path_bytes();
                let name = std::str::from_utf8(&path).map_err(|_| reject("archive member name"))?;
                let relative = name
                    .strip_prefix(&manifest.archive.root)
                    .and_then(|value| value.strip_prefix('/'))
                    .ok_or_else(|| reject("archive member root"))?
                    .to_owned();
                let expected = manifest
                    .archive
                    .files
                    .iter()
                    .find(|file| file.name == format!("{}/{}", manifest.archive.root, relative))
                    .ok_or_else(|| reject("unknown archive member"))?;
                let capture_here = roles.get(relative.as_str()).is_some_and(|role| {
                    *role != MemberRole::Other && *role != MemberRole::PackageManifest
                });
                let (digest, size, prefix) = hash_and_count(
                    &mut entry,
                    expected.size_bytes,
                    deadline,
                    if capture_here { capture } else { 0 },
                )?;
                ensure(size == expected.size_bytes, "member size")?;
                if capture_here {
                    prefixes.insert(relative.clone(), prefix);
                }
                digests.insert(relative, digest);
            }
        }
    }
    ensure(
        digests.len() == manifest.archive.files.len(),
        "missing archive member",
    )?;
    Ok((digests, prefixes))
}

fn check_stage(stage: &Path) -> Result<PathBuf, CliError> {
    ensure(stage.is_absolute(), "stage must be absolute")?;
    let stage_path = absolute(stage)?;
    let metadata = fs::symlink_metadata(&stage_path).map_err(io_failure)?;
    ensure(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "stage must be a real directory",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure(
            metadata.file_attributes() & 0x400 == 0,
            "stage must not be a reparse point",
        )?;
    }
    ordinary(&stage_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure(
            metadata.uid() == unsafe { libc::geteuid() },
            "stage must be owned by the current user",
        )?;
        ensure(metadata.mode() & 0o077 == 0, "stage must be private")?;
    }
    let mut entries = fs::read_dir(&stage_path).map_err(io_failure)?;
    ensure(entries.next().is_none(), "stage must be empty")?;
    Ok(stage_path)
}

fn stage_member_path(stage: &Path, relative: &str) -> Result<PathBuf, CliError> {
    ensure(safe_member(relative), "stage member path")?;
    let mut path = stage.to_path_buf();
    let parts: Vec<&str> = relative.split('/').collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "stage parent directory",
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&path).map_err(io_failure)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                        .map_err(io_failure)?;
                }
            }
            Err(error) => return Err(io_failure(error)),
        }
    }
    path.push(parts[parts.len() - 1]);
    Ok(path)
}

fn create_private_file(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(io_failure)?;
    ensure(
        file.metadata().map_err(io_failure)?.is_file(),
        "staged member must be a regular file",
    )?;
    Ok(file)
}

fn write_member(
    reader: &mut dyn Read,
    mut file: File,
    path: &Path,
    member: &VerifiedMember,
    deadline: Instant,
) -> Result<(), CliError> {
    let _ = path;
    ensure(matches!(member.mode, 0o644 | 0o755), "member mode")?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        check_deadline(deadline)?;
        let count = reader.read(&mut buffer).map_err(io_failure)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| reject("member size"))?;
        ensure(total <= member.size, "member size")?;
        digest.update(&buffer[..count]);
        file.write_all(&buffer[..count]).map_err(io_failure)?;
    }
    ensure(total == member.size, "member size")?;
    ensure(
        format!("{:x}", digest.finalize()) == member.sha256,
        "member digest",
    )?;
    file.sync_all().map_err(io_failure)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(u32::from(member.mode)))
            .map_err(io_failure)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directories(root: &Path) -> Result<(), CliError> {
    let directories = collect_dirs(root)?;
    for directory in directories {
        // Directory fsync is a durability aid, not a portability guarantee on
        // every Unix filesystem. Member files themselves are synced strictly.
        if let Ok(file) = File::open(&directory) {
            let _ = file.sync_all();
        }
    }
    Ok(())
}

#[cfg(unix)]
fn collect_dirs(root: &Path) -> Result<BTreeSet<PathBuf>, CliError> {
    let mut directories = BTreeSet::new();
    directories.insert(root.to_path_buf());
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).map_err(io_failure)? {
            let entry = entry.map_err(io_failure)?;
            if entry.file_type().map_err(io_failure)?.is_dir() {
                let path = entry.path();
                if directories.insert(path.clone()) {
                    stack.push(path);
                }
            }
        }
    }
    Ok(directories)
}

#[cfg(test)]
#[path = "update_bundle_tests.rs"]
mod tests;
