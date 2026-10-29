//! Explicit, bounded update check foundation (design section 10.1).
//!
//! Nothing here runs during ordinary reads, indexing, MCP serving or
//! background work. The caller invokes this only for an explicit
//! `update check`.
//!
//! Selection and every trust decision live in Rust. The installed, immutable
//! versioned helpers perform HTTPS transport only and return a small
//! `asg.update-fetch/v1` envelope. The raw page/manifest bytes are written by
//! the helper to a helper-owned temporary file because the shared setup
//! capture deliberately caps stdout at 64 KiB; the helper envelope stays well
//! below that cap. Bytes, the final URL, the temporary location, declared
//! sizes and every digest are revalidated here before use, and the temporary
//! file is removed.
//!
//! The helper accepts only public release coordinates (repository, channel,
//! target, installed version, page or tag/asset). It never receives a local
//! history, catalog, installation path, credential or query. It also never
//! downloads an archive: `check` fetches release metadata plus the small
//! sibling `SHA256SUMS` and `.manifest.json` only.

use crate::setup_hosts::{SetupHostsError, SetupHostsErrorCode, capture_local};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fmt, fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const UPDATE_CHECK_SCHEMA: &str = "asg.update-check/v1";
pub const UPDATE_FETCH_SCHEMA: &str = "asg.update-fetch/v1";
pub const DEFAULT_REPOSITORY: &str = "Lain-in-coding/agent-session-grep";
pub const PAGE_SIZE: u32 = 100;
pub const MAX_PAGES: u32 = 3;
pub const CHECK_DEADLINE: Duration = Duration::from_secs(30);
/// One decompressed release-inventory page.
pub const MAX_PAGE_BYTES: u64 = 4 * 1024 * 1024;
/// One `SHA256SUMS` or sibling `.manifest.json` document.
pub const MAX_METADATA_BYTES: u64 = 512 * 1024;
/// The helper envelope itself is tiny; the shared capture cap is 64 KiB.
pub const MAX_HELPER_ENVELOPE_BYTES: usize = 8 * 1024;
pub const MAX_REPORT_BYTES: usize = 8 * 1024;
pub const MAX_REDIRECTS: u8 = 3;
/// One request plus at most two retries, inside the one caller deadline.
pub const MAX_ATTEMPTS: u8 = 3;

pub const MANAGED_TARGETS: [&str; 4] = [
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];

const ARCHIVE_MANIFEST_SCHEMA: &str = "agent-session-grep.release-archive-manifest/v1";
const MANAGED_LAYOUT: &str = "asg.managed-candidate/v1";
const CHECKSUMS_NAME: &str = "SHA256SUMS";
const TEMP_FILE_PREFIX: &str = "asg-update-check";
const MAX_NAME_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Beta,
    Stable,
}

impl Channel {
    /// The default channel comes from the installed version, never from the
    /// latest release or a network response.
    pub fn from_installed(version: &Version) -> Self {
        if version.pre.is_empty() {
            Self::Stable
        } else {
            Self::Beta
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "beta" => Some(Self::Beta),
            "stable" => Some(Self::Stable),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Beta => "beta",
            Self::Stable => "stable",
        }
    }

    fn admits(self, version: &Version) -> bool {
        match self {
            // Beta users follow prereleases and the stable releases that
            // supersede them.
            Self::Beta => true,
            Self::Stable => version.pre.is_empty(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledIdentity {
    pub version: Version,
    pub target: String,
    pub repository: String,
    pub channel: Channel,
}

impl InstalledIdentity {
    /// Resolve the explicit installed identity. `channel` overrides the
    /// channel derived from the installed SemVer; `repository` overrides the
    /// canonical public repository for tests or forks.
    pub fn new(
        version: &str,
        target: &str,
        channel: Option<Channel>,
        repository: Option<&str>,
    ) -> Result<Self, UpdateCheckError> {
        if version.len() > 64 || version.starts_with('v') {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::InvalidInstalledIdentity,
            ));
        }
        let version = Version::parse(version)
            .map_err(|_| UpdateCheckError::new(UpdateCheckErrorCode::InvalidInstalledIdentity))?;
        if target.len() > MAX_NAME_BYTES || !MANAGED_TARGETS.contains(&target) {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::UnsupportedTarget,
            ));
        }
        let repository = repository.unwrap_or(DEFAULT_REPOSITORY);
        validate_repository(repository)?;
        Ok(Self {
            channel: channel.unwrap_or_else(|| Channel::from_installed(&version)),
            version,
            target: target.to_owned(),
            repository: repository.to_owned(),
        })
    }
}

pub fn native_target() -> Result<&'static str, UpdateCheckError> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return Ok("x86_64-pc-windows-msvc");
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Ok("x86_64-unknown-linux-gnu");
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Ok("x86_64-apple-darwin");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Ok("aarch64-apple-darwin");
    }
    #[allow(unreachable_code)]
    Err(UpdateCheckError::new(
        UpdateCheckErrorCode::UnsupportedTarget,
    ))
}

fn target_archive_format(target: &str) -> Result<&'static str, UpdateCheckError> {
    match target {
        "x86_64-pc-windows-msvc" => Ok("zip"),
        "x86_64-unknown-linux-gnu" | "x86_64-apple-darwin" | "aarch64-apple-darwin" => Ok("tar.gz"),
        _ => Err(UpdateCheckError::new(
            UpdateCheckErrorCode::UnsupportedTarget,
        )),
    }
}

fn validate_repository(repository: &str) -> Result<(), UpdateCheckError> {
    let invalid = || UpdateCheckError::new(UpdateCheckErrorCode::InvalidInstalledIdentity);
    if repository.len() > MAX_NAME_BYTES {
        return Err(invalid());
    }
    let mut parts = repository.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    if owner.is_empty()
        || name.is_empty()
        || owner == "."
        || owner == ".."
        || name == "."
        || name == ".."
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && value != "."
        && value != ".."
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchRequest {
    Page {
        repository: String,
        channel: Channel,
        target: String,
        current_version: String,
        page: u32,
    },
    Asset {
        repository: String,
        tag: String,
        asset: String,
    },
}

impl FetchRequest {
    pub fn page_url(&self) -> String {
        match self {
            Self::Page {
                repository, page, ..
            } => format!(
                "https://api.github.com/repos/{repository}/releases?per_page={PAGE_SIZE}&page={page}"
            ),
            Self::Asset { .. } => String::new(),
        }
    }

    pub fn url(&self) -> String {
        match self {
            Self::Page { .. } => self.page_url(),
            Self::Asset {
                repository,
                tag,
                asset,
            } => format!("https://github.com/{repository}/releases/download/{tag}/{asset}"),
        }
    }

    /// Single-dash flags are accepted by both the installed PowerShell helper
    /// and the POSIX `sh` helper.
    pub fn helper_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        match self {
            Self::Page {
                repository,
                channel,
                target,
                current_version,
                page,
            } => {
                args.extend([
                    "-Mode".into(),
                    "page".into(),
                    "-Repository".into(),
                    repository.into(),
                    "-Channel".into(),
                    channel.as_str().into(),
                    "-Target".into(),
                    target.into(),
                    "-CurrentVersion".into(),
                    current_version.into(),
                    "-Page".into(),
                    page.to_string().into(),
                ]);
            }
            Self::Asset {
                repository,
                tag,
                asset,
            } => {
                args.extend([
                    "-Mode".into(),
                    "asset".into(),
                    "-Repository".into(),
                    repository.into(),
                    "-Tag".into(),
                    tag.into(),
                    "-Asset".into(),
                    asset.into(),
                ]);
            }
        }
        args
    }

    /// The page endpoint must be exactly the canonical public URL. Asset
    /// downloads may redirect only to documented GitHub release/asset hosts.
    pub fn validate_response_url(&self, url: &str) -> Result<(), UpdateCheckError> {
        match self {
            Self::Page { .. } => {
                if url == self.url() {
                    Ok(())
                } else {
                    Err(UpdateCheckError::new(
                        UpdateCheckErrorCode::RedirectRejected,
                    ))
                }
            }
            Self::Asset { .. } => {
                let allowed = [
                    "github.com",
                    "objects.githubusercontent.com",
                    "release-assets.githubusercontent.com",
                ];
                let Some(rest) = url.strip_prefix("https://") else {
                    return Err(UpdateCheckError::new(
                        UpdateCheckErrorCode::RedirectRejected,
                    ));
                };
                let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
                if allowed.contains(&host) && rest.len() > host.len() {
                    Ok(())
                } else {
                    Err(UpdateCheckError::new(
                        UpdateCheckErrorCode::RedirectRejected,
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct FetchedBytes {
    pub final_url: String,
    pub bytes: Vec<u8>,
}

pub trait ReleaseTransport {
    fn fetch(
        &mut self,
        request: &FetchRequest,
        deadline: Instant,
    ) -> Result<FetchedBytes, UpdateCheckError>;
}

/// Production transport. `program` is the installed native PowerShell on
/// Windows (no execution-policy bypass) or `/bin/sh` on Unix; `script` is the
/// immutable versioned helper from the same directory as the application.
pub struct HelperTransport {
    program: PathBuf,
    fixed_args: Vec<OsString>,
}

impl HelperTransport {
    pub fn from_installed_script(program: impl Into<PathBuf>, script: &Path) -> Self {
        let script = script.as_os_str().to_owned();
        #[cfg(windows)]
        let fixed_args = vec![
            OsString::from("-NoProfile"),
            OsString::from("-NonInteractive"),
            OsString::from("-File"),
            script,
        ];
        #[cfg(not(windows))]
        let fixed_args = vec![script];
        Self {
            program: program.into(),
            fixed_args,
        }
    }

    /// Test seam: invoke an arbitrary program with fixed leading arguments.
    pub fn with_fixed_args(program: impl Into<PathBuf>, fixed_args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            fixed_args,
        }
    }
}

impl ReleaseTransport for HelperTransport {
    fn fetch(
        &mut self,
        request: &FetchRequest,
        deadline: Instant,
    ) -> Result<FetchedBytes, UpdateCheckError> {
        if Instant::now() >= deadline {
            return Err(UpdateCheckError::new(UpdateCheckErrorCode::Timeout));
        }
        if !self.program.is_file() {
            return Err(UpdateCheckError::new(UpdateCheckErrorCode::HelperMissing));
        }
        let mut args = self.fixed_args.clone();
        args.extend(request.helper_args());
        let borrowed: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
        let capture =
            capture_local(&self.program, &borrowed, deadline).map_err(map_capture_error)?;
        // Helper stderr is never propagated or interpreted. Stdout is the only
        // helper channel; the scripts keep it to the bounded envelope.
        if !capture.success {
            return Err(parse_helper_error(&capture.stdout));
        }
        parse_helper_success(&capture.stdout, request)
    }
}

fn map_capture_error(error: SetupHostsError) -> UpdateCheckError {
    match error.code {
        SetupHostsErrorCode::ProbeTimeout => UpdateCheckError::new(UpdateCheckErrorCode::Timeout),
        SetupHostsErrorCode::ProbeFailed => {
            UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol)
        }
        _ => UpdateCheckError::new(UpdateCheckErrorCode::HelperFailed),
    }
}

#[derive(Deserialize)]
struct HelperEnvelope {
    schema: String,
    status: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn parse_helper_error(stdout: &[u8]) -> UpdateCheckError {
    if stdout.len() > MAX_HELPER_ENVELOPE_BYTES {
        return UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol);
    }
    let Ok(envelope) = serde_json::from_slice::<HelperEnvelope>(stdout) else {
        return UpdateCheckError::new(UpdateCheckErrorCode::HelperFailed);
    };
    if envelope.schema != UPDATE_FETCH_SCHEMA || envelope.status != "error" {
        return UpdateCheckError::new(UpdateCheckErrorCode::HelperFailed);
    }
    match envelope.error.as_deref() {
        Some("capability") => UpdateCheckError::new(UpdateCheckErrorCode::Capability),
        Some("network") => UpdateCheckError::new(UpdateCheckErrorCode::Network),
        Some("timeout") => UpdateCheckError::new(UpdateCheckErrorCode::Timeout),
        Some("http_status") => UpdateCheckError::new(UpdateCheckErrorCode::HttpStatus),
        Some("redirect_rejected") => UpdateCheckError::new(UpdateCheckErrorCode::RedirectRejected),
        Some("too_large") => UpdateCheckError::new(UpdateCheckErrorCode::ResponseTooLarge),
        Some("usage") => UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol),
        _ => UpdateCheckError::new(UpdateCheckErrorCode::HelperFailed),
    }
}

fn parse_helper_success(
    stdout: &[u8],
    request: &FetchRequest,
) -> Result<FetchedBytes, UpdateCheckError> {
    if stdout.len() > MAX_HELPER_ENVELOPE_BYTES {
        return Err(UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol));
    }
    let envelope = serde_json::from_slice::<HelperEnvelope>(stdout)
        .map_err(|_| UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol))?;
    if envelope.schema != UPDATE_FETCH_SCHEMA || envelope.status != "ok" || envelope.error.is_some()
    {
        return Err(UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol));
    }
    let url = envelope
        .url
        .ok_or_else(|| UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol))?;
    let declared = envelope
        .bytes
        .ok_or_else(|| UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol))?;
    let file = envelope
        .file
        .ok_or_else(|| UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol))?;
    request.validate_response_url(&url)?;
    let limit = match request {
        FetchRequest::Page { .. } => MAX_PAGE_BYTES,
        FetchRequest::Asset { .. } => MAX_METADATA_BYTES,
    };
    if declared > limit {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::ResponseTooLarge,
        ));
    }
    let bytes = read_helper_file(Path::new(&file), declared, limit)?;
    Ok(FetchedBytes {
        final_url: url,
        bytes,
    })
}

fn read_helper_file(path: &Path, declared: u64, limit: u64) -> Result<Vec<u8>, UpdateCheckError> {
    let protocol = || UpdateCheckError::new(UpdateCheckErrorCode::HelperProtocol);
    if !path.is_absolute() {
        return Err(protocol());
    }
    let temp_root = fs::canonicalize(std::env::temp_dir()).map_err(|_| protocol())?;
    let link_meta = fs::symlink_metadata(path).map_err(|_| protocol())?;
    if !link_meta.file_type().is_file() || link_meta.file_type().is_symlink() {
        return Err(protocol());
    }
    let canonical = fs::canonicalize(path).map_err(|_| protocol())?;
    if canonical.parent() != Some(temp_root.as_path()) {
        return Err(protocol());
    }
    let Some(name) = canonical.file_name().and_then(OsStr::to_str) else {
        return Err(protocol());
    };
    if !name.starts_with(TEMP_FILE_PREFIX) {
        return Err(protocol());
    }
    let result = (|| {
        let file = File::open(&canonical).map_err(|_| protocol())?;
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| protocol())?;
        if bytes.len() as u64 > limit || bytes.len() as u64 != declared {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::ResponseTooLarge,
            ));
        }
        Ok(bytes)
    })();
    let _ = fs::remove_file(&canonical);
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCheckErrorCode {
    InvalidInstalledIdentity,
    UnsupportedTarget,
    Capability,
    Network,
    Timeout,
    HttpStatus,
    RedirectRejected,
    ResponseTooLarge,
    MalformedFeed,
    MalformedRelease,
    DuplicateRelease,
    AmbiguousVersion,
    MissingAssets,
    WrongTarget,
    MalformedChecksums,
    MalformedManifest,
    DigestMismatch,
    InventoryTooLarge,
    HelperMissing,
    HelperFailed,
    HelperProtocol,
    Io,
    Internal,
}

#[derive(Debug)]
pub struct UpdateCheckError {
    pub code: UpdateCheckErrorCode,
    pub http_status: Option<u16>,
}

impl UpdateCheckError {
    pub fn new(code: UpdateCheckErrorCode) -> Self {
        Self {
            code,
            http_status: None,
        }
    }

    pub fn with_http_status(code: UpdateCheckErrorCode, status: u16) -> Self {
        Self {
            code,
            http_status: Some(status),
        }
    }

    /// Bounded public error document. It never includes helper stderr, local
    /// paths, URLs or response bodies.
    pub fn to_json(&self) -> Vec<u8> {
        let mut value = Map::new();
        value.insert("schema".into(), json!(UPDATE_CHECK_SCHEMA));
        value.insert("status".into(), json!("error"));
        value.insert("error".into(), json!(self.code));
        if let Some(status) = self.http_status {
            value.insert("http_status".into(), json!(status));
        }
        serde_json::to_vec(&Value::Object(value)).unwrap_or_default()
    }
}

impl fmt::Display for UpdateCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "update check {:?}", self.code)
    }
}

impl std::error::Error for UpdateCheckError {}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AssetReport {
    pub name: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ReleaseReport {
    pub version: String,
    pub tag: String,
    pub archive: AssetReport,
    pub manifest: AssetReport,
    pub checksums: AssetReport,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UpdateCheckReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub channel: Channel,
    pub repository: String,
    pub target: String,
    pub installed_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseReport>,
}

impl UpdateCheckReport {
    pub fn to_json(&self) -> Result<Vec<u8>, UpdateCheckError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| UpdateCheckError::new(UpdateCheckErrorCode::Internal))?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::ResponseTooLarge,
            ));
        }
        Ok(bytes)
    }

    fn up_to_date(installed: &InstalledIdentity) -> Self {
        Self {
            schema: UPDATE_CHECK_SCHEMA,
            status: "up_to_date",
            channel: installed.channel,
            repository: installed.repository.clone(),
            target: installed.target.clone(),
            installed_version: installed.version.to_string(),
            release: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RawRelease {
    id: u64,
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<RawAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawAsset {
    name: String,
    size: u64,
    browser_download_url: String,
}

#[derive(Clone, Debug)]
struct Candidate {
    version: Version,
    tag: String,
    archive: RawAsset,
    manifest: RawAsset,
    checksums: RawAsset,
}

/// Bounded explicit check. The caller owns the one deadline; this function
/// never resets it between pages, retries or metadata documents.
pub fn check(
    transport: &mut dyn ReleaseTransport,
    installed: &InstalledIdentity,
) -> Result<UpdateCheckReport, UpdateCheckError> {
    check_with_deadline(transport, installed, Instant::now() + CHECK_DEADLINE)
}

pub fn check_with_deadline(
    transport: &mut dyn ReleaseTransport,
    installed: &InstalledIdentity,
    deadline: Instant,
) -> Result<UpdateCheckReport, UpdateCheckError> {
    ensure_time(deadline)?;
    let releases = fetch_inventory(transport, installed, deadline)?;
    let Some(candidate) = select_candidate(&releases, installed)? else {
        return Ok(UpdateCheckReport::up_to_date(installed));
    };
    let release = verify_candidate(transport, installed, &candidate, deadline)?;
    Ok(UpdateCheckReport {
        schema: UPDATE_CHECK_SCHEMA,
        status: "update_available",
        channel: installed.channel,
        repository: installed.repository.clone(),
        target: installed.target.clone(),
        installed_version: installed.version.to_string(),
        release: Some(release),
    })
}

fn ensure_time(deadline: Instant) -> Result<(), UpdateCheckError> {
    if Instant::now() >= deadline {
        Err(UpdateCheckError::new(UpdateCheckErrorCode::Timeout))
    } else {
        Ok(())
    }
}

fn fetch_inventory(
    transport: &mut dyn ReleaseTransport,
    installed: &InstalledIdentity,
    deadline: Instant,
) -> Result<Vec<RawRelease>, UpdateCheckError> {
    let mut releases = Vec::new();
    let mut ids = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        ensure_time(deadline)?;
        let request = FetchRequest::Page {
            repository: installed.repository.clone(),
            channel: installed.channel,
            target: installed.target.clone(),
            current_version: installed.version.to_string(),
            page,
        };
        let fetched = transport.fetch(&request, deadline)?;
        request.validate_response_url(&fetched.final_url)?;
        if fetched.bytes.len() as u64 > MAX_PAGE_BYTES {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::ResponseTooLarge,
            ));
        }
        let page_releases = serde_json::from_slice::<Vec<RawRelease>>(&fetched.bytes)
            .map_err(|_| UpdateCheckError::new(UpdateCheckErrorCode::MalformedFeed))?;
        if page_releases.len() > PAGE_SIZE as usize {
            return Err(UpdateCheckError::new(UpdateCheckErrorCode::MalformedFeed));
        }
        if page_releases.is_empty() {
            break;
        }
        let full = page_releases.len() == PAGE_SIZE as usize;
        for release in page_releases {
            if !ids.insert(release.id) {
                return Err(UpdateCheckError::new(
                    UpdateCheckErrorCode::DuplicateRelease,
                ));
            }
            releases.push(release);
        }
        if !full {
            break;
        }
        if page == MAX_PAGES {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::InventoryTooLarge,
            ));
        }
    }
    Ok(releases)
}

fn select_candidate(
    releases: &[RawRelease],
    installed: &InstalledIdentity,
) -> Result<Option<Candidate>, UpdateCheckError> {
    let mut candidates: Vec<(Version, String, &RawRelease)> = Vec::new();
    for release in releases {
        if release.draft {
            continue;
        }
        let version = parse_release_tag(&release.tag_name)?;
        if release.prerelease != !version.pre.is_empty() {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::MalformedRelease,
            ));
        }
        if !installed.channel.admits(&version)
            || version.cmp_precedence(&installed.version) != Ordering::Greater
        {
            continue;
        }
        for (seen, _tag, _) in &candidates {
            if seen.cmp_precedence(&version) == Ordering::Equal {
                if seen == &version {
                    return Err(UpdateCheckError::new(
                        UpdateCheckErrorCode::DuplicateRelease,
                    ));
                }
                return Err(UpdateCheckError::new(
                    UpdateCheckErrorCode::AmbiguousVersion,
                ));
            }
        }
        candidates.push((version, release.tag_name.clone(), release));
    }
    candidates.sort_by(|a, b| b.0.cmp_precedence(&a.0));
    let mut incomplete: Option<Version> = None;
    for (version, tag, release) in candidates {
        match candidate_assets(release, &tag, &installed.repository, &installed.target)? {
            Some(candidate) => return Ok(Some(candidate)),
            None => {
                if incomplete.is_none() {
                    incomplete = Some(version);
                }
            }
        }
    }
    if incomplete.is_some() {
        // A newer release exists but is not installable. Never report
        // "up to date"; the concrete missing-asset state is the honest answer.
        return Err(UpdateCheckError::new(UpdateCheckErrorCode::MissingAssets));
    }
    Ok(None)
}

fn parse_release_tag(tag: &str) -> Result<Version, UpdateCheckError> {
    let Some(raw) = tag.strip_prefix('v') else {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::MalformedRelease,
        ));
    };
    if raw.is_empty() || raw.len() > 64 {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::MalformedRelease,
        ));
    }
    let version = Version::parse(raw)
        .map_err(|_| UpdateCheckError::new(UpdateCheckErrorCode::MalformedRelease))?;
    if tag != format!("v{version}") {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::MalformedRelease,
        ));
    }
    Ok(version)
}

fn candidate_assets(
    release: &RawRelease,
    tag: &str,
    repository: &str,
    target: &str,
) -> Result<Option<Candidate>, UpdateCheckError> {
    let version = parse_release_tag(tag)?;
    let format = target_archive_format(target)?;
    let root = format!("agent-session-grep-{tag}-{target}");
    let archive_name = format!("{root}.{format}");
    let manifest_name = format!("{root}.manifest.json");

    let mut names = BTreeSet::new();
    for asset in &release.assets {
        if !validate_safe_name(&asset.name) || !names.insert(asset.name.as_str()) {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::MalformedRelease,
            ));
        }
    }

    let archive_prefix = format!("{root}.");
    let archives: Vec<&RawAsset> = release
        .assets
        .iter()
        .filter(|asset| {
            asset.name.starts_with(&archive_prefix)
                && (asset.name.ends_with(".zip") || asset.name.ends_with(".tar.gz"))
        })
        .collect();
    if archives.len() > 1 {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::MalformedRelease,
        ));
    }
    let manifests: Vec<&RawAsset> = release
        .assets
        .iter()
        .filter(|asset| {
            asset.name.starts_with(&archive_prefix) && asset.name.ends_with(".manifest.json")
        })
        .collect();
    if manifests.len() > 1 {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::MalformedRelease,
        ));
    }

    let Some(archive) = archives.first().copied() else {
        return Ok(None);
    };
    if archive.name != archive_name {
        return Err(UpdateCheckError::new(UpdateCheckErrorCode::WrongTarget));
    }
    let Some(manifest) = manifests.first().copied() else {
        return Ok(None);
    };
    if manifest.name != manifest_name {
        return Err(UpdateCheckError::new(UpdateCheckErrorCode::WrongTarget));
    }
    let checksums = release
        .assets
        .iter()
        .find(|asset| asset.name == CHECKSUMS_NAME);
    let Some(checksums) = checksums.cloned() else {
        return Ok(None);
    };

    for asset in [archive, manifest, &checksums] {
        if asset.size == 0 {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::MalformedRelease,
            ));
        }
        let expected = format!(
            "https://github.com/{repository}/releases/download/{tag}/{}",
            asset.name
        );
        if asset.browser_download_url != expected {
            return Err(UpdateCheckError::new(
                UpdateCheckErrorCode::MalformedRelease,
            ));
        }
    }

    Ok(Some(Candidate {
        version,
        tag: tag.to_owned(),
        archive: archive.clone(),
        manifest: manifest.clone(),
        checksums,
    }))
}

fn verify_candidate(
    transport: &mut dyn ReleaseTransport,
    installed: &InstalledIdentity,
    candidate: &Candidate,
    deadline: Instant,
) -> Result<ReleaseReport, UpdateCheckError> {
    ensure_time(deadline)?;
    let checksums = fetch_metadata(
        transport,
        installed,
        &candidate.tag,
        CHECKSUMS_NAME,
        MAX_METADATA_BYTES,
        deadline,
    )?;
    let checksums_sha256 = sha256_hex(&checksums);
    let inventory = parse_checksums(&checksums)?;
    let archive_digest = inventory
        .get(&candidate.archive.name)
        .ok_or_else(|| UpdateCheckError::new(UpdateCheckErrorCode::MalformedChecksums))?
        .clone();
    let manifest_digest = inventory
        .get(&candidate.manifest.name)
        .ok_or_else(|| UpdateCheckError::new(UpdateCheckErrorCode::MalformedChecksums))?
        .clone();

    ensure_time(deadline)?;
    let manifest_bytes = fetch_metadata(
        transport,
        installed,
        &candidate.tag,
        &candidate.manifest.name,
        MAX_METADATA_BYTES,
        deadline,
    )?;
    if sha256_hex(&manifest_bytes) != manifest_digest {
        return Err(UpdateCheckError::new(UpdateCheckErrorCode::DigestMismatch));
    }
    parse_manifest(
        &manifest_bytes,
        candidate,
        &installed.target,
        &archive_digest,
    )?;

    Ok(ReleaseReport {
        version: candidate.version.to_string(),
        tag: candidate.tag.clone(),
        archive: AssetReport {
            name: candidate.archive.name.clone(),
            sha256: archive_digest,
        },
        manifest: AssetReport {
            name: candidate.manifest.name.clone(),
            sha256: manifest_digest,
        },
        checksums: AssetReport {
            name: candidate.checksums.name.clone(),
            sha256: checksums_sha256,
        },
    })
}

fn fetch_metadata(
    transport: &mut dyn ReleaseTransport,
    installed: &InstalledIdentity,
    tag: &str,
    asset: &str,
    limit: u64,
    deadline: Instant,
) -> Result<Vec<u8>, UpdateCheckError> {
    let request = FetchRequest::Asset {
        repository: installed.repository.clone(),
        tag: tag.to_owned(),
        asset: asset.to_owned(),
    };
    let fetched = transport.fetch(&request, deadline)?;
    request.validate_response_url(&fetched.final_url)?;
    if fetched.bytes.len() as u64 > limit {
        return Err(UpdateCheckError::new(
            UpdateCheckErrorCode::ResponseTooLarge,
        ));
    }
    Ok(fetched.bytes)
}

fn parse_checksums(bytes: &[u8]) -> Result<BTreeMap<String, String>, UpdateCheckError> {
    let malformed = || UpdateCheckError::new(UpdateCheckErrorCode::MalformedChecksums);
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(malformed());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            return Err(malformed());
        }
        let Some((digest, name)) = line.split_once("  ") else {
            return Err(malformed());
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !validate_safe_name(name)
        {
            return Err(malformed());
        }
        if entries.insert(name.to_owned(), digest.to_owned()).is_some() {
            return Err(malformed());
        }
    }
    if entries.is_empty() {
        return Err(malformed());
    }
    Ok(entries)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveManifest {
    schema: String,
    release: ManifestRelease,
    archive: ManifestArchive,
    inputs: Value,
    provenance: Value,
    layout: String,
    install_manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRelease {
    tag: String,
    version: String,
    target: String,
    source_commit: String,
    #[serde(rename = "source_date_epoch")]
    _source_date_epoch: u64,
    unsigned: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestArchive {
    filename: String,
    format: String,
    root: String,
    sha256: String,
    size_bytes: u64,
    files: Value,
}

fn parse_manifest(
    bytes: &[u8],
    candidate: &Candidate,
    target: &str,
    archive_digest: &str,
) -> Result<(), UpdateCheckError> {
    let malformed = || UpdateCheckError::new(UpdateCheckErrorCode::MalformedManifest);
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(malformed());
    }
    let manifest: ArchiveManifest = serde_json::from_slice(bytes).map_err(|_| malformed())?;
    let format = target_archive_format(target)?;
    let root = format!("agent-session-grep-{}-{target}", candidate.tag);
    let archive_name = format!("{root}.{format}");
    if manifest.schema != ARCHIVE_MANIFEST_SCHEMA
        || manifest.layout != MANAGED_LAYOUT
        || manifest.release.tag != candidate.tag
        || manifest.release.version != candidate.version.to_string()
        || manifest.release.target != target
        || !valid_commit(&manifest.release.source_commit)
        || !manifest.release.unsigned
        || manifest.archive.filename != archive_name
        || manifest.archive.format != format
        || manifest.archive.root != root
        || manifest.archive.sha256 != archive_digest
        || manifest.archive.size_bytes != candidate.archive.size
        || !valid_sha256(&manifest.install_manifest_sha256)
    {
        return Err(malformed());
    }
    let provenance = manifest.provenance.as_object().ok_or_else(malformed)?;
    if provenance.get("cryptographic_attestation") != Some(&Value::Bool(false)) {
        return Err(malformed());
    }
    if let Some(inputs) = manifest.inputs.as_object()
        && let Some(lock) = inputs.get("cargo_lock_sha256")
        && !lock.as_str().is_some_and(valid_sha256)
    {
        return Err(malformed());
    }
    if !manifest.archive.files.is_array() {
        return Err(malformed());
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value != "0000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_defaults_from_installed_semver() {
        let beta = InstalledIdentity::new("0.2.0-beta.1", "x86_64-unknown-linux-gnu", None, None)
            .expect("identity");
        assert_eq!(beta.channel, Channel::Beta);
        let stable = InstalledIdentity::new("0.2.0", "x86_64-unknown-linux-gnu", None, None)
            .expect("identity");
        assert_eq!(stable.channel, Channel::Stable);
    }

    #[test]
    fn rejects_malformed_installed_identity() {
        for version in ["v0.2.0", "0.2", "0.2.0-"] {
            assert!(
                InstalledIdentity::new(version, "x86_64-unknown-linux-gnu", None, None).is_err()
            );
        }
        assert!(InstalledIdentity::new("0.2.0", "not-a-target", None, None).is_err());
        assert!(
            InstalledIdentity::new("0.2.0", "x86_64-unknown-linux-gnu", None, Some("../repo"))
                .is_err()
        );
    }

    #[test]
    fn helper_arguments_carry_only_public_coordinates() {
        let request = FetchRequest::Page {
            repository: DEFAULT_REPOSITORY.into(),
            channel: Channel::Beta,
            target: "x86_64-unknown-linux-gnu".into(),
            current_version: "0.2.0-beta.1".into(),
            page: 2,
        };
        let args: Vec<String> = request
            .helper_args()
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "-Mode",
                "page",
                "-Repository",
                DEFAULT_REPOSITORY,
                "-Channel",
                "beta",
                "-Target",
                "x86_64-unknown-linux-gnu",
                "-CurrentVersion",
                "0.2.0-beta.1",
                "-Page",
                "2",
            ]
        );
        let asset = FetchRequest::Asset {
            repository: DEFAULT_REPOSITORY.into(),
            tag: "v0.2.0".into(),
            asset: CHECKSUMS_NAME.into(),
        };
        assert_eq!(
            asset.url(),
            "https://github.com/Lain-in-coding/agent-session-grep/releases/download/v0.2.0/SHA256SUMS"
        );
    }

    #[test]
    fn page_url_is_exact_and_asset_redirect_hosts_are_bounded() {
        let page = FetchRequest::Page {
            repository: DEFAULT_REPOSITORY.into(),
            channel: Channel::Stable,
            target: "x86_64-unknown-linux-gnu".into(),
            current_version: "0.2.0".into(),
            page: 1,
        };
        assert!(page.validate_response_url(&page.url()).is_ok());
        assert!(
            page.validate_response_url("https://api.github.com.evil.example/x")
                .is_err()
        );
        let asset = FetchRequest::Asset {
            repository: DEFAULT_REPOSITORY.into(),
            tag: "v0.2.0".into(),
            asset: CHECKSUMS_NAME.into(),
        };
        assert!(
            asset
                .validate_response_url(
                    "https://objects.githubusercontent.com/github-production-release-asset/x"
                )
                .is_ok()
        );
        assert!(
            asset
                .validate_response_url("https://evil.example/release/x")
                .is_err()
        );
        assert!(asset.validate_response_url("http://github.com/x").is_err());
    }

    #[test]
    fn error_json_is_bounded_and_path_free() {
        let bytes =
            UpdateCheckError::with_http_status(UpdateCheckErrorCode::HttpStatus, 503).to_json();
        assert!(bytes.len() <= MAX_REPORT_BYTES);
        let value: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(value["schema"], UPDATE_CHECK_SCHEMA);
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"], "http_status");
        assert_eq!(value["http_status"], 503);
    }

    fn page_request() -> FetchRequest {
        FetchRequest::Page {
            repository: DEFAULT_REPOSITORY.into(),
            channel: Channel::Stable,
            target: "x86_64-unknown-linux-gnu".into(),
            current_version: "0.2.0".into(),
            page: 1,
        }
    }

    #[test]
    fn helper_success_envelope_revalidates_and_consumes_the_file() {
        use std::io::Write;
        let request = page_request();
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_FILE_PREFIX)
            .tempfile_in(std::env::temp_dir())
            .expect("temp file");
        file.write_all(b"[]").expect("write");
        file.flush().expect("flush");
        let path = file.into_temp_path();
        let envelope = serde_json::to_vec(&json!({
            "schema": UPDATE_FETCH_SCHEMA,
            "status": "ok",
            "url": request.url(),
            "bytes": 2,
            "file": path.to_string_lossy(),
        }))
        .expect("envelope");
        let fetched = parse_helper_success(&envelope, &request).expect("envelope");
        assert_eq!(fetched.bytes, b"[]");
        assert_eq!(fetched.final_url, request.url());
        assert!(!path.exists());
    }

    #[test]
    fn helper_success_rejects_files_outside_the_temp_root() {
        use std::io::Write;
        let request = page_request();
        let directory = agent_session_grep_testkit::tempdir().expect("temp dir");
        let path = directory.path().join("asg-update-check-file");
        let mut file = File::create(&path).expect("file");
        file.write_all(b"[]").expect("write");
        let envelope = serde_json::to_vec(&json!({
            "schema": UPDATE_FETCH_SCHEMA,
            "status": "ok",
            "url": request.url(),
            "bytes": 2,
            "file": path,
        }))
        .expect("envelope");
        let error = parse_helper_success(&envelope, &request).expect_err("outside");
        assert_eq!(error.code, UpdateCheckErrorCode::HelperProtocol);
    }

    #[test]
    fn helper_success_rejects_declared_size_mismatch_and_oversized_envelopes() {
        use std::io::Write;
        let request = page_request();
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_FILE_PREFIX)
            .tempfile_in(std::env::temp_dir())
            .expect("temp file");
        file.write_all(b"[]").expect("write");
        file.flush().expect("flush");
        let path = file.into_temp_path();
        let envelope = serde_json::to_vec(&json!({
            "schema": UPDATE_FETCH_SCHEMA,
            "status": "ok",
            "url": request.url(),
            "bytes": 3,
            "file": path.to_string_lossy(),
        }))
        .expect("envelope");
        let error = parse_helper_success(&envelope, &request).expect_err("size");
        assert_eq!(error.code, UpdateCheckErrorCode::ResponseTooLarge);

        let oversized = vec![b' '; MAX_HELPER_ENVELOPE_BYTES + 1];
        let error = parse_helper_success(&oversized, &request).expect_err("oversized");
        assert_eq!(error.code, UpdateCheckErrorCode::HelperProtocol);
    }
}
