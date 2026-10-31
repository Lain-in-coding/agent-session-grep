//! Canonical installed-package identity verifier shared by setup, supervisor
//! and update/recovery. It reads package records only, never provider history.
use crate::{
    CliError,
    protocol::{CanonicalCode, ProtocolError},
    setup_hosts::ExpectedAsgIdentity,
};
use agent_session_grep_adapters_sqlite::managed_locks::RootIdentity;
use agent_session_grep_launcher::{
    CurrentPointer, ReleaseMetadata, VerifiedApplication, metadata, verify_installation,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

#[cfg(windows)]
use std::io::SeekFrom;

pub(crate) const ARCHIVE_SCHEMA: &str = "agent-session-grep.release-archive-manifest/v1";
pub(crate) const MANAGED_LAYOUT: &str = "asg.managed-candidate/v1";
pub(crate) const STAGE_MANIFEST: &str = "release.manifest.json";
pub(crate) const STAGE_CHECKSUMS: &str = "SHA256SUMS";
pub(crate) const UPDATE_CHECK_HELPERS: [&str; 2] = ["update-check.sh", "update-check.ps1"];
const STAGE_METADATA_LIMIT: u64 = 512 * 1024;
pub(crate) const RELEASE_TARGETS: [&str; 4] = [
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];
pub(crate) const MAX_CHECKSUM_BYTES: u64 = 256 * 1024;

/// Parse the shared release checksum asset once for bundle and installed-state
/// validation. Names stay case-unambiguous on every supported filesystem.
pub(crate) fn parse_release_checksums(bytes: &[u8]) -> Result<BTreeMap<String, String>, CliError> {
    if bytes.len() as u64 > MAX_CHECKSUM_BYTES
        || !bytes.is_ascii()
        || bytes.contains(&b'\r')
        || !bytes.ends_with(b"\n")
    {
        return Err(invalid_install("checksums encoding"));
    }
    let text = std::str::from_utf8(bytes).map_err(invalid_install)?;
    let mut entries = BTreeMap::new();
    let mut folded = BTreeSet::new();
    for line in text.lines() {
        let (sha, name) = line
            .split_once("  ")
            .ok_or_else(|| invalid_install("checksums record"))?;
        if !hex(sha, 64)
            || !safe_member(name)
            || name.contains('/')
            || !name
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !folded.insert(name.to_ascii_lowercase())
            || entries.len() >= 16
        {
            return Err(invalid_install("checksums record"));
        }
        entries.insert(name.to_owned(), sha.to_owned());
    }
    if entries.is_empty() {
        return Err(invalid_install("checksums inventory"));
    }
    Ok(entries)
}

/// Other targets' archive/manifest pairs are valid siblings; their bytes need
/// not be present in a target-specific offline triple. This is a name/format
/// check only. The selected archive and manifest digests are checked separately.
pub(crate) fn validate_checksum_assets(
    entries: &BTreeMap<String, String>,
    version: &str,
) -> Result<(), CliError> {
    let mut allowed = BTreeSet::from([
        "THIRD-PARTY-DEPENDENCIES.json".to_owned(),
        "THIRD-PARTY-DEPENDENCIES.csv".to_owned(),
    ]);
    for target in RELEASE_TARGETS {
        let root = format!("agent-session-grep-v{version}-{target}");
        // Both formats are emitted by the builder's explicit format option.
        // The selected package still enforces its target-specific format.
        allowed.insert(format!("{root}.zip"));
        allowed.insert(format!("{root}.tar.gz"));
        allowed.insert(format!("{root}.manifest.json"));
    }
    if entries.keys().any(|name| !allowed.contains(name)) {
        return Err(invalid_install("checksums release asset"));
    }
    Ok(())
}

/// Digest-pinned immutable helper located in the same version directory as
/// the verified application.
pub(crate) struct InstalledHelper {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageManifest {
    schema: String,
    release: StageRelease,
    archive: StageArchive,
    inputs: StageInputs,
    provenance: StageProvenance,
    layout: String,
    install_manifest_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageInputs {
    cargo_lock_sha256: String,
    dependency_inventory_schema: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageProvenance {
    kind: String,
    cryptographic_attestation: bool,
    limitation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageRelease {
    tag: String,
    version: String,
    target: String,
    source_commit: String,
    source_date_epoch: u64,
    unsigned: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageArchive {
    filename: String,
    format: String,
    root: String,
    sha256: String,
    size_bytes: u64,
    files: Vec<StageFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageFile {
    name: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
}

pub(crate) fn invalid_install(_: impl std::fmt::Debug) -> CliError {
    ProtocolError::new(CanonicalCode::SchemaIncompatible,"installed package identity is unavailable, changed or unsupported; verify the managed candidate before host setup").into()
}
pub(crate) fn absolute(path: &Path) -> Result<PathBuf, CliError> {
    if path.components().any(|c| matches!(c, Component::ParentDir))
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(invalid_install("path"));
    }
    if path.is_absolute() {
        Ok(path.into())
    } else {
        Ok(std::env::current_dir().map_err(invalid_install)?.join(path))
    }
}
pub(crate) fn ordinary(path: &Path) -> Result<(), CliError> {
    if !path.is_absolute() {
        return Err(invalid_install("relative"));
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(invalid_install)?;
        let linked = meta.file_type().is_symlink();
        #[cfg(windows)]
        let linked = {
            use std::os::windows::fs::MetadataExt;
            linked || meta.file_attributes() & 0x400 != 0
        };
        if linked {
            return Err(invalid_install("linked"));
        }
    }
    Ok(())
}

/// Absolute path to the in-box Windows PowerShell executable.
///
/// A bare `powershell.exe` would let CreateProcess search the current
/// directory first, so a check run from an attacker-writable directory could
/// execute a planted binary with the caller's privileges. The system
/// directory is resolved through the API instead of `%Path%`.
#[cfg(windows)]
pub(crate) fn system_powershell() -> Result<PathBuf, CliError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = vec![0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if size == 0 || size >= buffer.len() {
        return Err(invalid_install("system-directory"));
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..size]))
        .join("WindowsPowerShell/v1.0/powershell.exe");
    ordinary(&path)?;
    Ok(path)
}
pub(crate) fn pinned(path: &Path) -> Result<File, CliError> {
    ordinary(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(invalid_install)?;
    let meta = file.metadata().map_err(invalid_install)?;
    if !meta.is_file() {
        return Err(invalid_install("not a file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(invalid_install("ownership"));
        }
    }
    Ok(file)
}
fn bytes(file: &mut File, limit: u64) -> Result<Vec<u8>, CliError> {
    if file.metadata().map_err(invalid_install)?.len() > limit {
        return Err(invalid_install("size"));
    }
    file.rewind().map_err(invalid_install)?;
    let mut value = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut value)
        .map_err(invalid_install)?;
    if value.len() as u64 > limit {
        return Err(invalid_install("size"));
    }
    Ok(value)
}
fn hash(file: &mut File) -> Result<String, CliError> {
    file.rewind().map_err(invalid_install)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(invalid_install)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
pub(crate) fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn safe_member(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        })
}

#[derive(PartialEq, Eq)]
struct ImageStamp {
    identity: (u64, u64),
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    changed: (i64, i64),
}
impl ImageStamp {
    fn read(file: &File) -> Result<Self, CliError> {
        let metadata = file.metadata().map_err(invalid_install)?;
        Ok(Self {
            identity: crate::native_autostart::platform::identity(file).map_err(invalid_install)?,
            len: metadata.len(),
            modified: metadata.modified().map_err(invalid_install)?,
            #[cfg(unix)]
            changed: {
                use std::os::unix::fs::MetadataExt;
                (metadata.ctime(), metadata.ctime_nsec())
            },
        })
    }
}

/// Bind one hash operation to the same physical image before and after it,
/// and again before every later use. The pinned handle is retained.
pub(crate) struct ImagePin {
    path: PathBuf,
    file: File,
    stamp: ImageStamp,
}
impl ImagePin {
    pub(crate) fn open(path: PathBuf) -> Result<Self, CliError> {
        let file = pinned(&path)?;
        let stamp = ImageStamp::read(&file)?;
        Ok(Self { path, file, stamp })
    }

    pub(crate) fn recheck(&self) -> Result<(), CliError> {
        let named = pinned(&self.path)?;
        if ImageStamp::read(&self.file)? != self.stamp || ImageStamp::read(&named)? != self.stamp {
            return Err(invalid_install("image changed"));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallReceipt {
    schema: String,
    product: String,
    version: String,
    target: String,
    source_commit: String,
    launcher_protocol: u32,
    manifest_sha256: String,
    archive_sha256: String,
    package_files_sha256: String,
    #[serde(default)]
    current_sha256: Option<String>,
    #[serde(default)]
    current_generation: Option<u64>,
    #[serde(default)]
    launcher_sha256: Option<String>,
}
pub(crate) struct Member {
    pub(crate) sha: String,
    pub(crate) mode: String,
    pub(crate) size: u64,
}
pub(crate) struct Manifest {
    pub(crate) fields: BTreeMap<String, String>,
    pub(crate) members: BTreeMap<String, Member>,
}
impl Manifest {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, CliError> {
        if !bytes.is_ascii() || bytes.contains(&b'\r') || !bytes.ends_with(b"\n") {
            return Err(invalid_install("manifest encoding"));
        }
        let text = std::str::from_utf8(bytes).map_err(invalid_install)?;
        let mut lines = text.lines();
        if lines.next() != Some("asg.package-files/v1") {
            return Err(invalid_install("manifest schema"));
        }
        let mut fields = BTreeMap::new();
        let mut members = BTreeMap::new();
        let mut folded = BTreeSet::new();
        for line in lines {
            let parts: Vec<_> = line.split('\t').collect();
            match parts.as_slice() {
                ["file", sha, mode, size, name]
                    if hex(sha, 64) && matches!(*mode, "0644" | "0755") && safe_member(name) =>
                {
                    if !folded.insert(name.to_ascii_lowercase()) || members.len() >= 20 {
                        return Err(invalid_install("member collision"));
                    }
                    let size = size.parse::<u64>().map_err(invalid_install)?;
                    members.insert(
                        (*name).into(),
                        Member {
                            sha: (*sha).into(),
                            mode: (*mode).into(),
                            size,
                        },
                    );
                }
                [key, value]
                    if matches!(
                        *key,
                        "version"
                            | "target"
                            | "source_commit"
                            | "app"
                            | "app_sha256"
                            | "supervisor"
                            | "supervisor_sha256"
                            | "dir"
                            | "launcher_protocol"
                            | "catalog_schema"
                            | "control_schema"
                            | "built_at"
                    ) =>
                {
                    if fields.insert((*key).into(), (*value).into()).is_some() {
                        return Err(invalid_install("duplicate metadata"));
                    }
                }
                _ => return Err(invalid_install("manifest record")),
            }
        }
        // Historical packages carry 16 payloads (or 17 with supervisor);
        // Current packages add immutable update-check helpers and one exact
        // versioned uninstall tail helper. Older inventories remain readable.
        if !matches!(
            (fields.len(), members.len()),
            (10, 16) | (12, 17) | (12, 19) | (12, 20)
        ) {
            return Err(invalid_install("manifest inventory"));
        }
        Ok(Self { fields, members })
    }
    pub(crate) fn field(&self, key: &str) -> Result<&str, CliError> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| invalid_install("missing metadata"))
    }
}

/// Holds the verified application and package files throughout composition.
///
/// Binary/launcher guards stay pinned for the lifetime of a normal operation.
/// Mutable package metadata is held separately so an update owner can capture
/// the complete identity, release those pins and then switch the pointer
/// without an open deny-write handle on `current.json`.
pub(crate) struct Installation {
    pub(crate) prefix: PathBuf,
    pub(crate) pointer: CurrentPointer,
    pub(crate) release: ReleaseMetadata,
    /// Digest of `PACKAGE-MANIFEST.tsv` (the package file inventory).
    pub(crate) package_files_sha256: String,
    /// Digest of the release archive manifest recorded by the install receipt.
    pub(crate) manifest_sha256: String,
    pub(crate) archive_sha256: String,
    pub(crate) helpers: BTreeMap<String, InstalledHelper>,
    pub(crate) launcher: PathBuf,
    pub(crate) expected: ExpectedAsgIdentity,
    pub(crate) supervisor: Option<(PathBuf, String)>,
    pub(crate) _application: VerifiedApplication,
    pub(crate) _guards: Vec<File>,
    pub(crate) _metadata: Vec<File>,
}
impl Installation {
    pub(crate) fn helper(&self, name: &str) -> Result<&InstalledHelper, CliError> {
        self.helpers
            .get(name)
            .ok_or_else(|| invalid_install("missing helper"))
    }

    /// Platform-selected immutable update transport helper.
    pub(crate) fn update_check_helper(&self) -> Result<&InstalledHelper, CliError> {
        self.helper(if cfg!(windows) {
            "update-check.ps1"
        } else {
            "update-check.sh"
        })
    }

    /// Release mutable metadata pins after the identity has been captured.
    ///
    /// The verified application and executables used by this process stay
    /// pinned; only receipt/manifest/pointer/release metadata is released.
    pub(crate) fn release_update_pins(&mut self) {
        self._metadata.clear();
    }
}

pub(crate) fn installation(prefix: Option<&Path>) -> Result<Installation, CliError> {
    let running = std::env::current_exe().map_err(invalid_install)?;
    installation_for(
        prefix,
        Some(&running),
        false,
        false,
        SchemaAdmission::Current,
    )
}

/// Verify a staged candidate package that is not executing yet.
///
/// The stage must contain the package members, a journal-generated
/// `package-install.json`, and the release `release.manifest.json` plus
/// `SHA256SUMS` metadata. No running executable is assumed or compared.
pub(crate) fn installation_for_staged(prefix: &Path) -> Result<Installation, CliError> {
    installation_for(Some(prefix), None, false, true, SchemaAdmission::Current)
}

/// Inspect a complete active installation without pretending the running old
/// update process is already the newly selected application. Unlike staging,
/// installed state may contain recorded prior version and private update files.
pub(crate) fn inspect_installation(prefix: &Path) -> Result<Installation, CliError> {
    installation_for(Some(prefix), None, false, false, SchemaAdmission::Current)
}

pub(crate) fn verify_staged_package(prefix: &Path) -> Result<(), CliError> {
    installation_for_staged(prefix).map(|_| ())
}

pub(crate) fn verify_supervisor(prefix: &Path, executable: &Path) -> Result<(), CliError> {
    installation_for(
        Some(prefix),
        Some(executable),
        true,
        false,
        SchemaAdmission::Current,
    )
    .map(|_| ())
}

/// Exact mutable package records that identify the running package. Reads are
/// bounded and short-lived; no handle to them outlives the read.
#[derive(PartialEq, Eq)]
struct PackageRecords {
    receipt: Vec<u8>,
    pointer: Vec<u8>,
    release: Vec<u8>,
    prefix_identity: RootIdentity,
    version_identity: RootIdentity,
}
impl PackageRecords {
    fn read(prefix: &Path) -> Result<Self, CliError> {
        let receipt = bytes(&mut pinned(&prefix.join("package-install.json"))?, 8192)?;
        let pointer = bytes(&mut pinned(&prefix.join("current.json"))?, 8192)?;
        let parsed = CurrentPointer::parse(&pointer).map_err(invalid_install)?;
        let version_dir = prefix.join(&parsed.dir);
        ordinary(&version_dir)?;
        let release = bytes(&mut pinned(&version_dir.join("release.json"))?, 8192)?;
        Ok(Self {
            receipt,
            pointer,
            release,
            prefix_identity: RootIdentity::read(prefix).map_err(invalid_install)?,
            version_identity: RootIdentity::read(&version_dir).map_err(invalid_install)?,
        })
    }
}

/// The installed package this process verified once, at startup. Only the
/// running image stays pinned; mutable metadata pins are released so an
/// update can switch the pointer. Every later use rechecks with bounded reads.
pub(crate) struct RunningPackage {
    prefix: PathBuf,
    pointer: CurrentPointer,
    release: ReleaseMetadata,
    updated: bool,
    records: PackageRecords,
    image: ImagePin,
}
impl RunningPackage {
    /// Full package verification. Call it once per worker lifetime only.
    pub(crate) fn verify() -> Result<Self, CliError> {
        Self::verify_running(&std::env::current_exe().map_err(invalid_install)?)
    }

    fn verify_running(running: &Path) -> Result<Self, CliError> {
        let running = absolute(running)?;
        let before = PackageRecords::read(&running_prefix(&running)?)?;
        let image = ImagePin::open(running.clone())?;
        let installation =
            installation_for(None, Some(&running), false, false, SchemaAdmission::Current)?;
        let member = installation
            .prefix
            .join(&installation.pointer.dir)
            .join(&installation.pointer.app);
        // Equal bytes elsewhere under versions/ are not the selected member.
        if fs::canonicalize(&running).map_err(invalid_install)?
            != fs::canonicalize(&member).map_err(invalid_install)?
        {
            return Err(invalid_install("running member"));
        }
        image.recheck()?;
        let records = PackageRecords::read(&installation.prefix)?;
        let receipt: InstallReceipt =
            serde_json::from_slice(&records.receipt).map_err(invalid_install)?;
        let pointer = CurrentPointer::parse(&records.pointer).map_err(invalid_install)?;
        let release =
            ReleaseMetadata::parse(&records.release, &pointer).map_err(invalid_install)?;
        if before != records
            || serde_json::to_vec(&pointer).map_err(invalid_install)?
                != serde_json::to_vec(&installation.pointer).map_err(invalid_install)?
            || serde_json::to_vec(&release).map_err(invalid_install)?
                != serde_json::to_vec(&installation.release).map_err(invalid_install)?
            // The recorded receipt is the one installation_for verified.
            || receipt.version != pointer.version
            || receipt.package_files_sha256 != installation.package_files_sha256
            || receipt.manifest_sha256 != installation.manifest_sha256
            || receipt.archive_sha256 != installation.archive_sha256
        {
            return Err(invalid_install("package records changed"));
        }
        Ok(Self {
            updated: receipt.schema == "asg.package-install/v2",
            prefix: installation.prefix,
            pointer: installation.pointer,
            release: installation.release,
            records,
            image,
        })
    }

    pub(crate) fn prefix(&self) -> &Path {
        &self.prefix
    }
    pub(crate) fn pointer(&self) -> &CurrentPointer {
        &self.pointer
    }
    pub(crate) fn release(&self) -> &ReleaseMetadata {
        &self.release
    }
    /// Whether the receipt was written by a managed update (v2).
    pub(crate) fn updated(&self) -> bool {
        self.updated
    }

    /// Bounded recheck under the caller's installation lock: the pinned image
    /// stamp and the exact package records. It never rehashes the package.
    pub(crate) fn recheck(&self) -> Result<(), CliError> {
        self.image.recheck()?;
        if PackageRecords::read(&self.prefix)? != self.records {
            return Err(invalid_install("package records changed"));
        }
        Ok(())
    }
}

fn running_prefix(running: &Path) -> Result<PathBuf, CliError> {
    let version = running
        .parent()
        .ok_or_else(|| invalid_install("app location"))?;
    let versions = version
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "versions"))
        .ok_or_else(|| invalid_install("managed location"))?;
    versions
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| invalid_install("prefix"))
}

#[derive(Clone, Copy)]
enum SchemaAdmission {
    Current,
    /// Inspection for the explicitly journalled updater only. Full package
    /// integrity still applies; this is not normal setup/read compatibility.
    ManagedUpdate,
}
impl SchemaAdmission {
    fn allows(self, catalog: u32, control: u32) -> bool {
        let current_catalog =
            u32::try_from(agent_session_grep_adapters_sqlite::SCHEMA_VERSION).ok();
        let current_control =
            u32::try_from(agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION).ok();
        current_control == Some(control)
            && (current_catalog == Some(catalog)
                || (matches!(self, Self::ManagedUpdate)
                    && catalog == 21
                    && current_catalog == Some(22)))
    }
}

/// Verify an active package for a supported, user-triggered update/recovery.
/// The caller must additionally bind its recorded old/new identity and exact
/// updater executable before any catalog/program effect.
pub(crate) fn inspect_installation_for_update(prefix: &Path) -> Result<Installation, CliError> {
    installation_for(
        Some(prefix),
        None,
        false,
        false,
        SchemaAdmission::ManagedUpdate,
    )
}

fn installation_for(
    prefix: Option<&Path>,
    running: Option<&Path>,
    supervisor_entry: bool,
    staged: bool,
    schema_admission: SchemaAdmission,
) -> Result<Installation, CliError> {
    let prefix = match prefix {
        Some(path) => absolute(path)?,
        None => running_prefix(running.ok_or_else(|| invalid_install("app location"))?)?,
    };
    ordinary(&prefix)?;
    let mut metadata_files = Vec::new();
    let mut guard_files = Vec::new();
    let mut receipt_file = pinned(&prefix.join("package-install.json"))?;
    let receipt: InstallReceipt =
        serde_json::from_slice(&bytes(&mut receipt_file, 8192)?).map_err(invalid_install)?;
    metadata_files.push(receipt_file);
    if !matches!(
        receipt.schema.as_str(),
        "asg.package-install/v1" | "asg.package-install/v2"
    ) || receipt.product != "agent-session-grep"
        || receipt.launcher_protocol != 1
        || !hex(&receipt.manifest_sha256, 64)
        || !hex(&receipt.archive_sha256, 64)
        || !hex(&receipt.package_files_sha256, 64)
    {
        return Err(invalid_install("receipt"));
    }
    let updated = receipt.schema == "asg.package-install/v2";
    if updated {
        if receipt.current_sha256.as_ref().is_none_or(|s| !hex(s, 64))
            || receipt.current_generation.is_none_or(|g| g == 0)
            || receipt.launcher_sha256.as_ref().is_none_or(|s| !hex(s, 64))
        {
            return Err(invalid_install("updated receipt"));
        }
    } else if receipt.current_sha256.is_some()
        || receipt.current_generation.is_some()
        || receipt.launcher_sha256.is_some()
    {
        return Err(invalid_install("unexpected receipt overrides"));
    }
    let mut manifest_file = pinned(&prefix.join("PACKAGE-MANIFEST.tsv"))?;
    let content = bytes(&mut manifest_file, 65536)?;
    if format!("{:x}", Sha256::digest(&content)) != receipt.package_files_sha256 {
        return Err(invalid_install("file manifest digest"));
    }
    let manifest = Manifest::parse(&content)?;
    metadata_files.push(manifest_file);
    let mut pointer_file = pinned(&prefix.join("current.json"))?;
    let pointer_bytes = bytes(&mut pointer_file, 8192)?;
    let pointer = CurrentPointer::parse(&pointer_bytes).map_err(invalid_install)?;
    if updated
        && (receipt.current_sha256.as_deref()
            != Some(format!("{:x}", Sha256::digest(&pointer_bytes)).as_str())
            || receipt.current_generation != Some(pointer.generation.get()))
    {
        return Err(invalid_install("updated current pointer"));
    }
    metadata_files.push(pointer_file);
    let release_name = format!("{}/release.json", pointer.dir);
    let app_name = format!("{}/{}", pointer.dir, pointer.app);
    let mut release_file = pinned(&prefix.join(&release_name))?;
    let release = ReleaseMetadata::parse(&bytes(&mut release_file, 8192)?, &pointer)
        .map_err(invalid_install)?;
    metadata_files.push(release_file);
    if (running.is_some()
        && !staged
        && matches!(schema_admission, SchemaAdmission::Current)
        && pointer.version != env!("CARGO_PKG_VERSION"))
        || receipt.version != pointer.version
        || receipt.target != release.target
        || receipt.source_commit != release.source_commit
        || !schema_admission.allows(release.catalog_schema.get(), release.control_schema.get())
    {
        return Err(invalid_install("package version"));
    }
    for (key, value) in [
        ("version", pointer.version.clone()),
        ("target", release.target.clone()),
        ("source_commit", release.source_commit.clone()),
        ("app", pointer.app.clone()),
        ("app_sha256", pointer.app_sha256.clone()),
        ("dir", pointer.dir.clone()),
        ("launcher_protocol", "1".into()),
        ("catalog_schema", release.catalog_schema.to_string()),
        ("control_schema", release.control_schema.to_string()),
        ("built_at", release.built_at.clone()),
    ] {
        if manifest.field(key)? != value {
            return Err(invalid_install("metadata mismatch"));
        }
    }
    let alias = if cfg!(windows) { "asg.exe" } else { "asg" };
    let mut expected: BTreeSet<String> = [
        metadata::APP_NAME,
        alias,
        &app_name,
        &release_name,
        "current.json",
        "package-install.ps1",
        "package-install.sh",
        "INSTALL-AND-UPGRADE.md",
        "README.md",
        "CHANGELOG.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "NOTICE",
        "SECURITY.md",
        "THIRD-PARTY-DEPENDENCIES.json",
        "THIRD-PARTY-DEPENDENCIES.csv",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let supervisor = if manifest.fields.contains_key("supervisor") {
        let basename = if cfg!(windows) {
            "asg-supervisor.exe"
        } else {
            "asg-supervisor"
        };
        let digest = manifest.field("supervisor_sha256")?;
        if manifest.field("supervisor")? != basename || !hex(digest, 64) {
            return Err(invalid_install("supervisor identity"));
        }
        let member = format!("{}/{}", pointer.dir, basename);
        if manifest
            .members
            .get(&member)
            .is_none_or(|m| m.sha != digest)
        {
            return Err(invalid_install("supervisor member"));
        }
        expected.insert(member.clone());
        Some((member, digest.to_owned()))
    } else {
        None
    };
    let mut helper_names: Vec<String> = UPDATE_CHECK_HELPERS
        .iter()
        .map(|name| format!("{}/helpers/{name}", pointer.dir))
        .collect();
    let present = helper_names
        .iter()
        .filter(|name| manifest.members.contains_key(*name))
        .count();
    let tail = format!(
        "{}/helpers/{}",
        pointer.dir,
        crate::uninstall_command::WINDOWS_TAIL_HELPER
    );
    let has_tail = manifest.members.contains_key(&tail);
    if present == 1 || (has_tail && present != 2) {
        return Err(invalid_install("incomplete helper inventory"));
    }
    if present == 2 {
        let expected_count = if has_tail { 20 } else { 19 };
        if (manifest.fields.len(), manifest.members.len()) != (12, expected_count) {
            return Err(invalid_install("helper inventory"));
        }
        expected.extend(helper_names.iter().cloned());
        if has_tail {
            expected.insert(tail.clone());
            helper_names.push(tail);
        }
    } else if !matches!(
        (manifest.fields.len(), manifest.members.len()),
        (10, 16) | (12, 17)
    ) {
        return Err(invalid_install("helper inventory"));
    }
    if manifest.members.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(invalid_install("required members"));
    }
    let helper_sh = format!("{}/helpers/update-check.sh", pointer.dir);
    let helpers: BTreeMap<String, InstalledHelper> = manifest
        .members
        .iter()
        .filter(|(name, _)| helper_names.contains(*name))
        .map(|(name, member)| {
            (
                name.rsplit('/').next().unwrap_or_default().to_owned(),
                InstalledHelper {
                    path: prefix.join(name.as_str()),
                    sha256: member.sha.clone(),
                },
            )
        })
        .collect();
    for (name, member) in &manifest.members {
        let executable = name == metadata::APP_NAME
            || name == alias
            || name == &app_name
            || supervisor.as_ref().is_some_and(|(path, _)| name == path)
            || name == &helper_sh
            || name == "package-install.sh";
        if member.mode != if executable { "0755" } else { "0644" } {
            return Err(invalid_install("mode"));
        }
        let mut file = pinned(&prefix.join(name))?;
        let actual_hash = hash(&mut file)?;
        let override_hash = if updated && name == "current.json" {
            receipt.current_sha256.as_ref()
        } else if updated && (name == metadata::APP_NAME || name == alias) {
            receipt.launcher_sha256.as_ref()
        } else {
            None
        };
        if let Some(expected) = override_hash {
            if actual_hash != *expected
                || file.metadata().map_err(invalid_install)?.len() > 1024 * 1024 * 1024
            {
                return Err(invalid_install("updated member integrity"));
            }
        } else if file.metadata().map_err(invalid_install)?.len() != member.size
            || actual_hash != member.sha
        {
            return Err(invalid_install("member integrity"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file
                .metadata()
                .map_err(invalid_install)?
                .permissions()
                .mode()
                & 0o111
                != if executable { 0o111 } else { 0 }
            {
                return Err(invalid_install("executable mode"));
            }
        }
        if name == metadata::APP_NAME || name == alias || name == &app_name {
            native_target(&mut file, &release.target)?;
        }
        if supervisor.as_ref().is_some_and(|(path, _)| name == path) {
            native_target(&mut file, &release.target)?;
            #[cfg(windows)]
            {
                file.seek(SeekFrom::Start(60)).map_err(invalid_install)?;
                let mut offset = [0; 4];
                file.read_exact(&mut offset).map_err(invalid_install)?;
                file.seek(SeekFrom::Start(
                    u64::from(u32::from_le_bytes(offset)) + 24 + 68,
                ))
                .map_err(invalid_install)?;
                let mut subsystem = [0; 2];
                file.read_exact(&mut subsystem).map_err(invalid_install)?;
                if u16::from_le_bytes(subsystem) != 2 {
                    return Err(invalid_install("supervisor subsystem"));
                }
            }
        }
        if !name.contains('/') && name != metadata::APP_NAME && name != alias
            || name == &release_name
        {
            metadata_files.push(file);
        } else {
            guard_files.push(file);
        }
    }
    let launcher_hash = if updated {
        receipt
            .launcher_sha256
            .as_ref()
            .ok_or_else(|| invalid_install("launcher receipt"))?
    } else {
        &manifest.members[metadata::APP_NAME].sha
    };
    if manifest.members[metadata::APP_NAME].sha != manifest.members[alias].sha
        || launcher_hash == &pointer.app_sha256
        || manifest.members[&app_name].sha != pointer.app_sha256
    {
        return Err(invalid_install("program identity"));
    }
    if supervisor_entry {
        let running = running.ok_or_else(|| invalid_install("app location"))?;
        let (member, digest) = supervisor
            .as_ref()
            .ok_or_else(|| invalid_install("missing supervisor"))?;
        if fs::canonicalize(running).map_err(invalid_install)?
            != fs::canonicalize(prefix.join(member)).map_err(invalid_install)?
            || hash(&mut pinned(running)?)? != *digest
        {
            return Err(invalid_install("supervisor executable"));
        }
    } else if let Some(running) = running
        && hash(&mut pinned(running)?)? != pointer.app_sha256
    {
        return Err(invalid_install("program identity"));
    }
    // v2 must carry the candidate release metadata even though the active
    // pointer and retained launcher differ from the archive. New v1 installs
    // retain this pair too; historical v1 receipts may predate its retention.
    let mut release_metadata_count = 0;
    for name in [STAGE_MANIFEST, STAGE_CHECKSUMS] {
        match fs::symlink_metadata(prefix.join(name)) {
            Ok(_) => release_metadata_count += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(invalid_install(error)),
        }
    }
    if release_metadata_count == 1 {
        return Err(invalid_install("incomplete release metadata"));
    }
    if staged || updated || release_metadata_count == 2 {
        let (stage_manifest, stage_checksums) = verify_stage_metadata(
            &prefix,
            &manifest.members,
            &receipt.package_files_sha256,
            &content,
            &receipt,
            &release,
            staged,
        )?;
        metadata_files.push(stage_manifest);
        metadata_files.push(stage_checksums);
    }
    let application = verify_installation(&prefix).map_err(invalid_install)?;
    let launcher = prefix.join(metadata::APP_NAME);
    let expected_identity = ExpectedAsgIdentity {
        version: pointer.version.clone(),
        launcher_sha256: launcher_hash.clone(),
    };
    let supervisor = supervisor.map(|(name, digest)| (prefix.join(name), digest));
    Ok(Installation {
        prefix,
        pointer,
        release,
        package_files_sha256: receipt.package_files_sha256,
        manifest_sha256: receipt.manifest_sha256,
        archive_sha256: receipt.archive_sha256,
        helpers,
        launcher,
        expected: expected_identity,
        supervisor,
        _application: application,
        _guards: guard_files,
        _metadata: metadata_files,
    })
}
/// Exact regular-file inventory of a staged root; links and devices fail.
fn stage_inventory(prefix: &Path) -> Result<BTreeSet<String>, CliError> {
    let mut result = BTreeSet::new();
    let mut pending = vec![prefix.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(invalid_install)? {
            let path = entry.map_err(invalid_install)?.path();
            let metadata = fs::symlink_metadata(&path).map_err(invalid_install)?;
            if metadata.file_type().is_symlink() {
                return Err(invalid_install("linked stage member"));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(prefix)
                    .map_err(invalid_install)?
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                if !safe_member(&relative) || result.len() >= 64 || !result.insert(relative) {
                    return Err(invalid_install("stage member"));
                }
            } else {
                return Err(invalid_install("stage member type"));
            }
        }
    }
    Ok(result)
}

/// Validate journal-supplied stage metadata and bind it to the package files.
///
/// The stage adds `release.manifest.json` and `SHA256SUMS` to the extracted
/// package; both are verified against the receipt, the package inventory and
/// each other. The archive body itself is not present and is never assumed.
fn verify_stage_metadata(
    prefix: &Path,
    members: &BTreeMap<String, Member>,
    package_files_sha256: &str,
    package_manifest: &[u8],
    receipt: &InstallReceipt,
    release: &ReleaseMetadata,
    strict_inventory: bool,
) -> Result<(File, File), CliError> {
    let mut manifest_file = pinned(&prefix.join(STAGE_MANIFEST))?;
    let manifest_bytes = bytes(&mut manifest_file, STAGE_METADATA_LIMIT)?;
    let stage: StageManifest = serde_json::from_slice(&manifest_bytes).map_err(invalid_install)?;
    if format!("{:x}", Sha256::digest(&manifest_bytes)) != receipt.manifest_sha256 {
        return Err(invalid_install("stage manifest digest"));
    }
    let expected_format = if release.target.ends_with("windows-msvc") {
        "zip"
    } else {
        "tar.gz"
    };
    if stage.schema != ARCHIVE_SCHEMA
        || stage.layout != MANAGED_LAYOUT
        || stage.release.tag != format!("v{}", release.version)
        || stage.release.version != release.version
        || stage.release.target != release.target
        || stage.release.source_commit != release.source_commit
        || stage.install_manifest_sha256 != package_files_sha256
        || !hex(&stage.install_manifest_sha256, 64)
        || stage.archive.sha256 != receipt.archive_sha256
        || !hex(&stage.archive.sha256, 64)
        || stage.archive.format != expected_format
        || stage.archive.root
            != format!("agent-session-grep-v{}-{}", release.version, release.target)
        || stage.archive.filename != format!("{}.{}", stage.archive.root, stage.archive.format)
    {
        return Err(invalid_install("stage manifest identity"));
    }
    if !stage.release.unsigned
        || stage.release.source_date_epoch >= 253_402_300_800
        || stage.archive.size_bytes == 0
        || stage.archive.size_bytes > 2 * 1024 * 1024 * 1024
        || !hex(&stage.inputs.cargo_lock_sha256, 64)
        || stage.inputs.dependency_inventory_schema
            != "agent-session-grep.third-party-dependencies/v1"
        || stage.provenance.kind != "self-reported-build-metadata"
        || stage.provenance.cryptographic_attestation
        || stage.provenance.limitation.is_empty()
        || stage.provenance.limitation.len() > 1024
        || !stage.provenance.limitation.is_ascii()
    {
        return Err(invalid_install("stage manifest contract"));
    }
    let root_prefix = format!("{}/", stage.archive.root);
    let mut inventory: BTreeMap<&str, (&str, u64, &str)> = members
        .iter()
        .map(|(name, member)| {
            (
                name.as_str(),
                (member.sha.as_str(), member.size, member.mode.as_str()),
            )
        })
        .collect();
    inventory.insert(
        "PACKAGE-MANIFEST.tsv",
        (package_files_sha256, package_manifest.len() as u64, "0644"),
    );
    if stage.archive.files.len() != inventory.len() {
        return Err(invalid_install("stage manifest inventory"));
    }
    let mut seen = BTreeSet::new();
    for file in &stage.archive.files {
        let relative = file
            .name
            .strip_prefix(&root_prefix)
            .filter(|relative| safe_member(relative))
            .ok_or_else(|| invalid_install("stage manifest member"))?;
        let (sha, size, mode) = inventory
            .get(relative)
            .ok_or_else(|| invalid_install("stage manifest member"))?;
        if file.sha256 != *sha
            || file.size_bytes != *size
            || file.mode != *mode
            || !seen.insert(relative.to_owned())
        {
            return Err(invalid_install("stage manifest member"));
        }
    }
    let mut expected: BTreeSet<String> = members.keys().cloned().collect();
    for name in [
        "PACKAGE-MANIFEST.tsv",
        "package-install.json",
        STAGE_MANIFEST,
        STAGE_CHECKSUMS,
    ] {
        expected.insert(name.to_owned());
    }
    if strict_inventory && stage_inventory(prefix)? != expected {
        return Err(invalid_install("stage inventory"));
    }
    let manifest_digest = format!("{:x}", Sha256::digest(&manifest_bytes));
    let mut checksums_file = pinned(&prefix.join(STAGE_CHECKSUMS))?;
    let checksums = parse_release_checksums(&bytes(&mut checksums_file, MAX_CHECKSUM_BYTES)?)?;
    validate_checksum_assets(&checksums, &stage.release.version)?;
    let (mut manifest_seen, mut archive_seen) = (false, false);
    for (name, sha) in &checksums {
        let expected = if *name == format!("{}.manifest.json", stage.archive.root) {
            manifest_seen = true;
            Some(manifest_digest.as_str())
        } else if *name == stage.archive.filename {
            archive_seen = true;
            Some(stage.archive.sha256.as_str())
        } else {
            members.get(name).map(|member| member.sha.as_str())
        };
        if expected.is_some_and(|digest| digest != sha) {
            return Err(invalid_install("stage checksums digest"));
        }
    }
    if !manifest_seen || !archive_seen {
        return Err(invalid_install("stage checksums inventory"));
    }
    Ok((manifest_file, checksums_file))
}

fn native_target(file: &mut File, target: &str) -> Result<(), CliError> {
    file.rewind().map_err(invalid_install)?;
    let mut prefix = [0u8; 64];
    file.read_exact(&mut prefix).map_err(invalid_install)?;
    if target == "x86_64-pc-windows-msvc" && prefix.starts_with(b"MZ") {
        let offset =
            u32::from_le_bytes(prefix[60..64].try_into().map_err(invalid_install)?) as usize;
        if offset > 1024 * 1024 {
            return Err(invalid_install("PE offset"));
        }
        file.rewind().map_err(invalid_install)?;
        let mut bytes = vec![0; offset + 94];
        file.read_exact(&mut bytes).map_err(invalid_install)?;
        return native_target_bytes(&bytes, target);
    }
    native_target_bytes(&prefix, target)
}

/// Validate a bounded native image prefix; executable bytes are never run.
pub(crate) fn native_target_bytes(header: &[u8], target: &str) -> Result<(), CliError> {
    if header.len() < 64 {
        return Err(invalid_install("native header"));
    }
    let valid = match target {
        "x86_64-pc-windows-msvc" if header.starts_with(b"MZ") => {
            let offset =
                u32::from_le_bytes(header[60..64].try_into().map_err(invalid_install)?) as usize;
            offset <= 1024 * 1024
                && header.len() >= offset + 26
                && header[offset..offset + 4] == *b"PE\0\0"
                && header[offset + 4..offset + 6] == [0x64, 0x86]
                && header[offset + 24..offset + 26] == [0x0b, 0x02]
        }
        "x86_64-unknown-linux-gnu" => {
            header[..6] == *b"\x7fELF\x02\x01"
                && header[18..20] == [62, 0]
                && matches!(header[16..18], [2, 0] | [3, 0])
        }
        "x86_64-apple-darwin" | "aarch64-apple-darwin" => {
            header[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                && header[12..16] == [2, 0, 0, 0]
                && header[4..8]
                    == if target.starts_with("x86_64") {
                        [7, 0, 0, 1]
                    } else {
                        [12, 0, 0, 1]
                    }
        }
        _ => false,
    };
    if !valid {
        return Err(invalid_install("native target"));
    }
    Ok(())
}
pub(crate) fn supervisor_gui_bytes(header: &[u8], target: &str) -> Result<(), CliError> {
    native_target_bytes(header, target)?;
    if target == "x86_64-pc-windows-msvc" {
        let offset =
            u32::from_le_bytes(header[60..64].try_into().map_err(invalid_install)?) as usize;
        if header.len() < offset + 94 || header[offset + 92..offset + 94] != [2, 0] {
            return Err(invalid_install("supervisor subsystem"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    type FixtureMembers = BTreeMap<String, (Vec<u8>, String)>;

    fn target() -> &'static str {
        if cfg!(windows) {
            "x86_64-pc-windows-msvc"
        } else if cfg!(target_os = "linux") {
            "x86_64-unknown-linux-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
    }

    fn image(label: &[u8]) -> Vec<u8> {
        let mut content = vec![0u8; 256];
        if target().ends_with("windows-msvc") {
            content[..2].copy_from_slice(b"MZ");
            content[60..64].copy_from_slice(&64u32.to_le_bytes());
            content[64..68].copy_from_slice(b"PE\0\0");
            content[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
            content[84..86].copy_from_slice(&240u16.to_le_bytes());
            content[88..90].copy_from_slice(&0x20Bu16.to_le_bytes());
            content[156..158].copy_from_slice(&3u16.to_le_bytes());
        } else if target().ends_with("linux-gnu") {
            content[..6].copy_from_slice(b"\x7fELF\x02\x01");
            content[16..18].copy_from_slice(&2u16.to_le_bytes());
            content[18..20].copy_from_slice(&62u16.to_le_bytes());
        } else {
            content[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            let cpu = if target().starts_with("x86_64") {
                0x0100_0007u32
            } else {
                0x0100_000Cu32
            };
            content[4..8].copy_from_slice(&cpu.to_le_bytes());
            content[12..16].copy_from_slice(&2u32.to_le_bytes());
        }
        content.extend_from_slice(label);
        content
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn write(prefix: &Path, name: &str, content: &[u8], mode: &str) {
        let path = prefix.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if mode == "0755" { 0o755 } else { 0o644 }),
            )
            .unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    fn version_dir() -> String {
        format!(
            "versions/{}-{}",
            env!("CARGO_PKG_VERSION"),
            &digest(&image(b"synthetic application"))[..12]
        )
    }

    fn manifest_text(fields: &[(&str, String)], members: &FixtureMembers) -> Vec<u8> {
        let mut text = String::from("asg.package-files/v1\n");
        for (key, value) in fields {
            text.push_str(&format!("{key}\t{value}\n"));
        }
        for (name, (content, mode)) in members {
            text.push_str(&format!(
                "file\t{}\t{mode}\t{}\t{name}\n",
                digest(content),
                content.len()
            ));
        }
        text.into_bytes()
    }

    fn fixture(prefix: &Path) -> (FixtureMembers, Vec<u8>) {
        fixture_version(prefix, env!("CARGO_PKG_VERSION"))
    }

    fn fixture_version(prefix: &Path, version: &str) -> (FixtureMembers, Vec<u8>) {
        fixture_schema(
            prefix,
            version,
            agent_session_grep_adapters_sqlite::SCHEMA_VERSION as u32,
            agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION as u32,
        )
    }

    fn fixture_schema(
        prefix: &Path,
        version: &str,
        catalog_schema: u32,
        control_schema: u32,
    ) -> (FixtureMembers, Vec<u8>) {
        fixture_schema_with_tail(prefix, version, catalog_schema, control_schema, true)
    }

    fn fixture_schema_with_tail(
        prefix: &Path,
        version: &str,
        catalog_schema: u32,
        control_schema: u32,
        include_tail: bool,
    ) -> (FixtureMembers, Vec<u8>) {
        let target = target();
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let app = format!("agent-session-grep{suffix}");
        let alias = format!("asg{suffix}");
        let supervisor = format!("asg-supervisor{suffix}");
        let launcher = image(b"synthetic launcher");
        let supervisor_image = image(b"synthetic supervisor");
        #[cfg(windows)]
        let supervisor_image = {
            let mut value = supervisor_image;
            value[156..158].copy_from_slice(&2u16.to_le_bytes());
            value
        };
        let application = image(b"synthetic application");
        let app_sha = digest(&application);
        let supervisor_sha = digest(&supervisor_image);
        let dir = format!("versions/{version}-{}", &app_sha[..12]);
        let root = format!("agent-session-grep-v{version}-{target}");
        let archive_format = if cfg!(windows) { "zip" } else { "tar.gz" };
        let source_commit = "a".repeat(40);
        let built_at = "2023-11-14T22:13:20Z";
        let release = json!({
            "schema": "asg.version/v1", "version": version, "target": target,
            "source_commit": source_commit.clone(), "app_sha256": app_sha.clone(),
            "catalog_schema": catalog_schema,
            "control_schema": control_schema, "launcher_protocol_min": 1,
            "launcher_protocol_max": 1, "built_at": built_at,
        });
        let pointer = json!({
            "schema": "asg.current/v1", "generation": 1, "version": version,
            "dir": dir.clone(), "app": app.clone(), "app_sha256": app_sha.clone(),
            "launcher_protocol": 1, "activated_at": built_at,
        });
        let mut members = FixtureMembers::new();
        members.insert(app.clone(), (launcher.clone(), "0755".into()));
        members.insert(alias, (launcher, "0755".into()));
        members.insert(format!("{dir}/{app}"), (application, "0755".into()));
        members.insert(
            format!("{dir}/{supervisor}"),
            (supervisor_image, "0755".into()),
        );
        members.insert(
            format!("{dir}/release.json"),
            (serde_json::to_vec(&release).unwrap(), "0644".into()),
        );
        members.insert(
            "current.json".into(),
            (serde_json::to_vec(&pointer).unwrap(), "0644".into()),
        );
        for name in [
            "package-install.ps1",
            "package-install.sh",
            "INSTALL-AND-UPGRADE.md",
            "README.md",
            "CHANGELOG.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "NOTICE",
            "SECURITY.md",
            "THIRD-PARTY-DEPENDENCIES.json",
            "THIRD-PARTY-DEPENDENCIES.csv",
        ] {
            let mode = if name == "package-install.sh" {
                "0755"
            } else {
                "0644"
            };
            members.insert(
                name.into(),
                (format!("synthetic {name}\n").into_bytes(), mode.into()),
            );
        }
        members.insert(
            format!("{dir}/helpers/update-check.sh"),
            (b"synthetic update-check sh\n".to_vec(), "0755".into()),
        );
        members.insert(
            format!("{dir}/helpers/update-check.ps1"),
            (b"synthetic update-check ps1\n".to_vec(), "0644".into()),
        );
        if include_tail {
            members.insert(
                format!(
                    "{dir}/helpers/{}",
                    crate::uninstall_command::WINDOWS_TAIL_HELPER
                ),
                (b"synthetic uninstall tail ps1\n".to_vec(), "0644".into()),
            );
        }
        let fields = [
            ("version", version.to_owned()),
            ("target", target.to_owned()),
            ("source_commit", source_commit.clone()),
            ("app", app.clone()),
            ("app_sha256", app_sha.clone()),
            ("dir", dir.clone()),
            ("supervisor", supervisor),
            ("supervisor_sha256", supervisor_sha),
            ("launcher_protocol", "1".into()),
            ("catalog_schema", catalog_schema.to_string()),
            ("control_schema", control_schema.to_string()),
            ("built_at", built_at.to_owned()),
        ];
        let tsv = manifest_text(&fields, &members);
        let tsv_sha = digest(&tsv);
        for (name, (content, mode)) in &members {
            write(prefix, name, content, mode);
        }
        write(prefix, "PACKAGE-MANIFEST.tsv", &tsv, "0644");
        let mut inventory: Vec<Value> = members
            .iter()
            .map(|(name, (content, mode))| {
                json!({"name": format!("{root}/{name}"), "sha256": digest(content),
                       "size_bytes": content.len(), "mode": mode})
            })
            .collect();
        inventory.push(json!({"name": format!("{root}/PACKAGE-MANIFEST.tsv"),
                               "sha256": tsv_sha.clone(), "size_bytes": tsv.len(), "mode": "0644"}));
        inventory.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        let archive_sha = "d".repeat(64);
        let stage_manifest = json!({
            "schema": ARCHIVE_SCHEMA,
            "release": {"tag": format!("v{version}"), "version": version,
                        "target": target, "source_commit": source_commit.clone(),
                        "source_date_epoch": 1_700_000_000u64, "unsigned": true},
            "archive": {"filename": format!("{root}.{archive_format}"), "format": archive_format,
                        "root": root.clone(), "sha256": archive_sha.clone(),
                        "size_bytes": 4096u64, "files": inventory},
            "inputs": {"cargo_lock_sha256": "c".repeat(64),
                       "dependency_inventory_schema": "agent-session-grep.third-party-dependencies/v1"},
            "provenance": {"kind": "self-reported-build-metadata", "cryptographic_attestation": false,
                           "limitation": "Unsigned synthetic metadata for package validation tests."},
            "layout": MANAGED_LAYOUT,
            "install_manifest_sha256": tsv_sha.clone(),
        });
        let stage_bytes = serde_json::to_vec(&stage_manifest).unwrap();
        write(prefix, STAGE_MANIFEST, &stage_bytes, "0644");
        let sums = format!(
            "{archive_sha}  {root}.{archive_format}\n{}  {root}.manifest.json\n{}  THIRD-PARTY-DEPENDENCIES.json\n{}  THIRD-PARTY-DEPENDENCIES.csv\n",
            digest(&stage_bytes),
            digest(&members["THIRD-PARTY-DEPENDENCIES.json"].0),
            digest(&members["THIRD-PARTY-DEPENDENCIES.csv"].0),
        );
        write(prefix, STAGE_CHECKSUMS, sums.as_bytes(), "0644");
        let receipt = json!({
            "schema": "asg.package-install/v1", "product": "agent-session-grep",
            "version": version, "target": target,
            "source_commit": source_commit.clone(), "launcher_protocol": 1,
            "manifest_sha256": digest(&stage_bytes),
            "archive_sha256": archive_sha, "package_files_sha256": tsv_sha,
        });
        write(
            prefix,
            "package-install.json",
            &serde_json::to_vec(&receipt).unwrap(),
            "0644",
        );
        (members, tsv)
    }

    fn refresh_receipt(prefix: &Path, tsv: &[u8]) {
        let receipt: InstallReceipt =
            serde_json::from_slice(&fs::read(prefix.join("package-install.json")).unwrap())
                .unwrap();
        let stage = fs::read(prefix.join(STAGE_MANIFEST)).unwrap();
        let value = json!({
            "schema": "asg.package-install/v1", "product": "agent-session-grep",
            "version": receipt.version, "target": receipt.target,
            "source_commit": receipt.source_commit, "launcher_protocol": 1,
            "manifest_sha256": digest(&stage), "archive_sha256": receipt.archive_sha256,
            "package_files_sha256": digest(tsv),
        });
        fs::write(
            prefix.join("package-install.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn staged_package_verifies_helpers_and_releases_metadata_pins() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        let (members, _) = fixture(&prefix);
        let mut install = installation_for_staged(&prefix).expect("valid staged package");
        assert_eq!(install.prefix, prefix);
        assert_eq!(install.helpers.len(), 3);
        for name in [
            "update-check.sh",
            "update-check.ps1",
            crate::uninstall_command::WINDOWS_TAIL_HELPER,
        ] {
            let member = format!("{}/helpers/{name}", install.pointer.dir);
            let helper = install.helper(name).unwrap();
            assert_eq!(helper.path, prefix.join(&member));
            assert_eq!(helper.sha256, digest(&members[&member].0));
        }
        let selected = install.update_check_helper().unwrap();
        assert_eq!(
            selected.path.file_name().unwrap().to_string_lossy(),
            if cfg!(windows) {
                "update-check.ps1"
            } else {
                "update-check.sh"
            }
        );
        // Mutable metadata pins must not survive pointer switching.
        install.release_update_pins();
        fs::write(install.prefix.join("current.json"), b"{}\n").expect("pointer released");
    }

    #[test]
    fn running_package_rechecks_records_without_retaining_mutable_metadata_pins() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        fixture(&prefix);
        let member = prefix.join(version_dir()).join(metadata::APP_NAME);
        let copy = prefix.join("versions/other-copy").join(metadata::APP_NAME);
        write(
            &prefix,
            &format!("versions/other-copy/{}", metadata::APP_NAME),
            &fs::read(&member).unwrap(),
            "0755",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(fs::read(&copy).unwrap(), fs::read(&member).unwrap());
        assert!(RunningPackage::verify_running(&copy).is_err());
        let package = RunningPackage::verify_running(&member).unwrap();
        assert_eq!(package.pointer().generation.get(), 1);
        assert!(!package.updated());
        assert_eq!(package.prefix(), prefix.as_path());
        assert_eq!(package.release().version, env!("CARGO_PKG_VERSION"));
        package.recheck().unwrap();

        for name in [
            PathBuf::from("current.json"),
            PathBuf::from("package-install.json"),
            PathBuf::from(version_dir()).join("release.json"),
        ] {
            let path = prefix.join(name);
            let original = fs::read(&path).unwrap();
            let mut changed = original.clone();
            changed.push(b'\n');
            // Still valid JSON, but any changed byte invalidates the startup pin.
            fs::write(&path, &changed).expect("mutable package record must be released");
            assert!(package.recheck().is_err());
            fs::write(&path, original).unwrap();
            package.recheck().unwrap();
        }
        #[cfg(windows)]
        assert!(fs::write(&member, b"blocked by running image pin").is_err());
        #[cfg(unix)]
        {
            // Unix pins an inode; rechecking must reject in-place byte changes.
            fs::write(&member, b"changed running image").unwrap();
            assert!(package.recheck().is_err());
        }
    }

    #[test]
    fn installed_epoch_permit_requires_control_binding_and_retains_the_update_lock() {
        use crate::update_state::{EpochGate, EpochRefusal, acquire_installation_lock};
        use agent_session_grep_adapters_sqlite::{
            SqliteControlStore,
            managed_locks::{ExclusiveGuard, LockKind},
        };
        use agent_session_grep_ports::control::{ControlId, DesiredUpdates};
        use std::time::{Duration, Instant};

        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let prefix = base.join("installed");
        crate::native_autostart::platform::create_private_directory(&prefix).unwrap();
        fixture(&prefix);
        let member = prefix.join(version_dir()).join(metadata::APP_NAME);
        let gate = EpochGate::Installed(Box::new(RunningPackage::verify_running(&member).unwrap()));
        let root = base.join("private");
        let control = crate::retry_fixture_busy(|| {
            SqliteControlStore::create(
                &root,
                &ControlId::parse("epoch-installation").unwrap(),
                DesiredUpdates::Running,
            )
        });
        let end = Instant::now() + Duration::from_secs(10);
        assert!(matches!(
            gate.permit(&control, end),
            Err(EpochRefusal::Unbound)
        ));
        {
            let lock = acquire_installation_lock(&prefix, end).unwrap();
            let owner = crate::retry_fixture_busy(|| {
                ExclusiveGuard::try_acquire(&root, LockKind::PolicyOwner)
            });
            control
                .with_runtime_deadline(end, || {
                    let bound = control.bind_control_root(&owner)?;
                    control.record_verified_installation_prefix(&prefix, &lock, &bound, end)
                })
                .unwrap();
        }
        let permit = gate.permit(&control, end).unwrap();
        assert!(matches!(
            gate.permit(&control, end),
            Err(EpochRefusal::Busy)
        ));
        drop(permit);
        drop(acquire_installation_lock(&prefix, end).unwrap());
        let pointer = prefix.join("current.json");
        let original = fs::read(&pointer).unwrap();
        let mut changed: Value = serde_json::from_slice(&original).unwrap();
        changed["generation"] = json!(2);
        fs::write(&pointer, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(matches!(
            gate.permit(&control, end),
            Err(EpochRefusal::Changed)
        ));
        fs::write(&pointer, original).unwrap();
        assert!(gate.permit(&control, end).is_ok());
    }

    #[test]
    fn staged_package_rejects_mutated_helper_and_unexpected_members() {
        for name in [
            "update-check.sh",
            "update-check.ps1",
            crate::uninstall_command::WINDOWS_TAIL_HELPER,
        ] {
            for removed in [false, true] {
                let temp = agent_session_grep_testkit::tempdir().unwrap();
                let prefix = temp.path().canonicalize().unwrap();
                fixture(&prefix);
                let helper = prefix.join(format!("{}/helpers/{name}", version_dir()));
                if removed {
                    fs::remove_file(&helper).unwrap();
                } else {
                    let mut bytes = fs::read(&helper).unwrap();
                    bytes[0] ^= 1;
                    fs::write(&helper, bytes).unwrap();
                }
                assert!(
                    installation_for_staged(&prefix).is_err(),
                    "helper {name}, removed={removed}"
                );
            }
        }

        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        fixture(&prefix);
        fs::write(prefix.join("unexpected.bin"), b"extra").unwrap();
        assert!(installation_for_staged(&prefix).is_err());
    }

    #[test]
    fn staged_package_rejects_partial_or_unexpected_helper_roles() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        let (_, tsv) = fixture(&prefix);
        let dir = version_dir();
        let cmd = format!("{dir}/helpers/update-check.cmd");
        let text = String::from_utf8(tsv).unwrap();

        let ps1 = format!("{dir}/helpers/update-check.ps1");
        let mut partial: String = text
            .lines()
            .filter(|line| !line.ends_with(&ps1))
            .collect::<Vec<_>>()
            .join("\n");
        partial.push_str(&format!("\nfile\t{}\t0644\t1\t{cmd}\n", "0".repeat(64)));
        let partial = partial.into_bytes();
        write(&prefix, "PACKAGE-MANIFEST.tsv", &partial, "0644");
        refresh_receipt(&prefix, &partial);
        assert!(installation_for_staged(&prefix).is_err());

        let unexpected = text.replace("README.md", &cmd).into_bytes();
        write(&prefix, "PACKAGE-MANIFEST.tsv", &unexpected, "0644");
        refresh_receipt(&prefix, &unexpected);
        assert!(installation_for_staged(&prefix).is_err());
    }
    fn activate_v2(prefix: &Path, generation: u64) -> Vec<u8> {
        let mut pointer: Value =
            serde_json::from_slice(&fs::read(prefix.join("current.json")).unwrap()).unwrap();
        pointer["generation"] = json!(generation);
        pointer["activated_at"] = json!("2026-10-18T00:00:00Z");
        let pointer_bytes = serde_json::to_vec(&pointer).unwrap();
        write(prefix, "current.json", &pointer_bytes, "0644");
        let retained =
            image(b"previous Beta retained stable launcher with different bytes and size");
        write(prefix, metadata::APP_NAME, &retained, "0755");
        write(
            prefix,
            if cfg!(windows) { "asg.exe" } else { "asg" },
            &retained,
            "0755",
        );
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(prefix.join("package-install.json")).unwrap())
                .unwrap();
        receipt["schema"] = json!("asg.package-install/v2");
        receipt["current_sha256"] = json!(digest(&pointer_bytes));
        receipt["current_generation"] = json!(generation);
        receipt["launcher_sha256"] = json!(digest(&retained));
        write(
            prefix,
            "package-install.json",
            &serde_json::to_vec(&receipt).unwrap(),
            "0644",
        );
        retained
    }

    fn replace_receipt(prefix: &Path, change: impl FnOnce(&mut Value)) {
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(prefix.join("package-install.json")).unwrap())
                .unwrap();
        change(&mut receipt);
        write(
            prefix,
            "package-install.json",
            &serde_json::to_vec(&receipt).unwrap(),
            "0644",
        );
    }

    #[test]
    fn shared_four_target_checksums_accept_other_assets_and_reject_unknown_or_colliding_names() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        fixture(&prefix);
        let mut sums = fs::read_to_string(prefix.join(STAGE_CHECKSUMS)).unwrap();
        for other in RELEASE_TARGETS.into_iter().filter(|t| *t != target()) {
            let root = format!("agent-session-grep-v{}-{other}", env!("CARGO_PKG_VERSION"));
            let format = if other.ends_with("windows-msvc") {
                "zip"
            } else {
                "tar.gz"
            };
            sums.push_str(&format!(
                "{}  {root}.{format}\n{}  {root}.manifest.json\n",
                "e".repeat(64),
                "f".repeat(64)
            ));
        }
        write(&prefix, STAGE_CHECKSUMS, sums.as_bytes(), "0644");
        assert!(installation_for_staged(&prefix).is_ok());
        let unrelated = format!("{sums}{}  unexpected.zip\n", "0".repeat(64));
        write(&prefix, STAGE_CHECKSUMS, unrelated.as_bytes(), "0644");
        assert!(installation_for_staged(&prefix).is_err());
        let collision = format!("{sums}{}  THIRD-PARTY-DEPENDENCIES.JSON\n", "0".repeat(64));
        assert!(parse_release_checksums(collision.as_bytes()).is_err());
    }

    #[test]
    fn candidate_different_version_with_twenty_payload_members_is_verified() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        let version = "0.2.0-beta.91";
        let (members, tsv) = fixture_version(&prefix, version);
        assert_eq!(members.len(), 20);
        let manifest = Manifest::parse(&tsv).unwrap();
        assert_eq!(manifest.fields.len(), 12);
        assert_eq!(manifest.members.len(), 20);
        let installed = installation_for_staged(&prefix).unwrap();
        assert_eq!(installed.pointer.version, version);
        assert_eq!(installed.helpers.len(), 3);
        let stage: Value =
            serde_json::from_slice(&fs::read(prefix.join(STAGE_MANIFEST)).unwrap()).unwrap();
        assert_eq!(stage["archive"]["files"].as_array().unwrap().len(), 21);
    }

    #[test]
    fn historical_nineteen_payload_package_without_uninstall_tail_remains_verified() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        let (members, tsv) = fixture_schema_with_tail(
            &prefix,
            env!("CARGO_PKG_VERSION"),
            agent_session_grep_adapters_sqlite::SCHEMA_VERSION as u32,
            agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION as u32,
            false,
        );
        assert_eq!(members.len(), 19);
        assert_eq!(Manifest::parse(&tsv).unwrap().members.len(), 19);
        let installed = installation_for_staged(&prefix).unwrap();
        assert_eq!(installed.helpers.len(), 2);
        assert!(
            installed
                .helper(crate::uninstall_command::WINDOWS_TAIL_HELPER)
                .is_err()
        );
    }

    #[test]
    fn v2_retained_launcher_and_incremented_pointer_validate_full_current_metadata() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        fixture_version(&prefix, "0.2.0-beta.92");
        let retained = activate_v2(&prefix, 7);
        let installed = inspect_installation(&prefix).unwrap();
        assert_eq!(installed.pointer.generation.get(), 7);
        assert_eq!(installed.expected.launcher_sha256, digest(&retained));
        drop(installed);
        write(
            &prefix,
            "versions/previous-local-build/previous.txt",
            b"owned previous version",
            "0644",
        );
        assert!(inspect_installation(&prefix).is_ok());
        assert!(installation_for_staged(&prefix).is_err());
    }

    #[test]
    fn v2_rejects_generation_pointer_and_retained_launcher_mismatch() {
        for case in 0..4 {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let prefix = temp.path().canonicalize().unwrap();
            fixture(&prefix);
            activate_v2(&prefix, 8);
            match case {
                0 => replace_receipt(&prefix, |r| r["current_generation"] = json!(9)),
                1 => replace_receipt(&prefix, |r| r["current_sha256"] = json!("0".repeat(64))),
                2 => replace_receipt(&prefix, |r| {
                    r.as_object_mut().unwrap().remove("launcher_sha256");
                }),
                _ => write(
                    &prefix,
                    if cfg!(windows) { "asg.exe" } else { "asg" },
                    &image(b"unexpected launcher"),
                    "0755",
                ),
            }
            assert!(inspect_installation(&prefix).is_err(), "v2 mismatch {case}");
        }
    }

    #[test]
    fn v2_never_skips_receipt_manifest_checksum_or_member_integrity() {
        for case in 0..7 {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let prefix = temp.path().canonicalize().unwrap();
            fixture(&prefix);
            activate_v2(&prefix, 2);
            match case {
                0 => {
                    fs::remove_file(prefix.join(STAGE_MANIFEST)).unwrap();
                }
                1 => {
                    fs::remove_file(prefix.join(STAGE_CHECKSUMS)).unwrap();
                }
                2 => replace_receipt(&prefix, |r| r["manifest_sha256"] = json!("0".repeat(64))),
                3 => replace_receipt(&prefix, |r| r["archive_sha256"] = json!("0".repeat(64))),
                4 => {
                    let mut manifest: Value =
                        serde_json::from_slice(&fs::read(prefix.join(STAGE_MANIFEST)).unwrap())
                            .unwrap();
                    manifest["archive"]["files"][0]["size_bytes"] = json!(1);
                    let content = serde_json::to_vec(&manifest).unwrap();
                    write(&prefix, STAGE_MANIFEST, &content, "0644");
                    replace_receipt(&prefix, |r| r["manifest_sha256"] = json!(digest(&content)));
                    let sums = fs::read_to_string(prefix.join(STAGE_CHECKSUMS)).unwrap();
                    let sums = sums
                        .lines()
                        .map(|line| {
                            if line.ends_with(".manifest.json") {
                                format!(
                                    "{}  {}",
                                    digest(&content),
                                    line.split_once("  ").unwrap().1
                                )
                            } else {
                                line.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                    write(&prefix, STAGE_CHECKSUMS, sums.as_bytes(), "0644");
                }
                _ => {
                    let sums = fs::read_to_string(prefix.join(STAGE_CHECKSUMS)).unwrap();
                    let suffix = if case == 5 {
                        ".manifest.json"
                    } else if cfg!(windows) {
                        ".zip"
                    } else {
                        ".tar.gz"
                    };
                    let sums = sums
                        .lines()
                        .map(|line| {
                            if line.ends_with(suffix) {
                                format!("{}  {}", "0".repeat(64), line.split_once("  ").unwrap().1)
                            } else {
                                line.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                    write(&prefix, STAGE_CHECKSUMS, sums.as_bytes(), "0644");
                }
            }
            assert!(
                inspect_installation(&prefix).is_err(),
                "metadata mismatch {case}"
            );
        }
    }

    #[test]
    fn v1_absent_both_metadata_compatibility_never_allows_half_a_pair_or_v2() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        fixture(&prefix);
        fs::remove_file(prefix.join(STAGE_MANIFEST)).unwrap();
        assert!(inspect_installation(&prefix).is_err());
        fs::remove_file(prefix.join(STAGE_CHECKSUMS)).unwrap();
        assert!(inspect_installation(&prefix).is_ok());
        assert!(installation_for_staged(&prefix).is_err());
        activate_v2(&prefix, 3);
        assert!(inspect_installation(&prefix).is_err());
    }

    #[test]
    fn update_inspection_accepts_exact21_package_without_loosening_normal_setup() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().canonicalize().unwrap();
        let (members, _) = fixture_schema(&prefix, "0.0.9-beta.1", 21, 2);
        assert!(inspect_installation(&prefix).is_err());
        assert!(installation_for_staged(&prefix).is_err());
        let installed = inspect_installation_for_update(&prefix).unwrap();
        assert_eq!(installed.release.catalog_schema.get(), 21);
        assert_eq!(installed.release.control_schema.get(), 2);
        assert_eq!(installed.pointer.version, "0.0.9-beta.1");
        let app = format!("{}/{}", installed.pointer.dir, metadata::APP_NAME);
        drop(installed);
        write(&prefix, &app, &image(b"changed21application"), "0755");
        assert!(inspect_installation_for_update(&prefix).is_err());
        write(&prefix, &app, &members[&app].0, "0755");
        assert!(inspect_installation_for_update(&prefix).is_ok());
    }

    #[test]
    fn update_inspection_refuses_unsupported_and_cross_control_packages() {
        for (catalog, control) in [(20, 2), (21, 1), (22, 1), (23, 2), (22, 3)] {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let prefix = temp.path().canonicalize().unwrap();
            fixture_schema(&prefix, "0.0.9-beta.1", catalog, control);
            assert!(inspect_installation_for_update(&prefix).is_err());
        }
    }
}
