//! Composition for explicitly selected host registrations. Local ASG checks
//! are independent of host recognition, trust, or model-call acceptance.
//! No host CLI, source discovery, environment mutation or autostart is used.

use crate::host_config::{
    ErrorCode as ConfigErrorCode, Host, HostConfigReceipt, HostConfigStore, McpRegistration, Phase,
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::RootIdentity,
    managed_store::{ManagedStore, validate_catalog_path},
};
use agent_session_grep_ports::{
    PortError, PortResult,
    control::{ControlId, ControlStore},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_CAPTURE: usize = 65536;
const MAX_RECEIPT: u64 = 1024 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_VERSION: &str = "2025-06-18";

/// Supplied by the installation verifier, never derived from probe stdout.
#[derive(Clone)]
pub struct ExpectedAsgIdentity {
    pub version: String,
    pub launcher_sha256: String,
}

/// Identity of the managed state selected for this setup operation. Paths and
/// native identifiers are private; successful probes never replace this binding.
pub struct SetupIdentity {
    catalog: PathBuf,
    root: RootIdentity,
    installation: ControlId,
    incarnation: ControlId,
}
impl SetupIdentity {
    pub fn capture(catalog: &Path) -> PortResult<Self> {
        validate_catalog_path(catalog)?;
        let root = catalog.parent().ok_or_else(setup_changed)?;
        let physical = RootIdentity::read(root)?;
        let control = SqliteControlStore::open_current_read_only(root)?;
        let installation = control.status()?.policy.installation_id;
        let store = ManagedStore::open(catalog, &control)?;
        let identity = Self {
            catalog: catalog.into(),
            root: physical,
            installation,
            incarnation: store.incarnation().clone(),
        };
        drop(store);
        drop(control);
        identity.validate()?;
        Ok(identity)
    }

    /// Capture only the initially selected physical root. Typed Busy retries
    /// retain the first observed installation/incarnation and original end.
    pub(crate) fn capture_before(catalog: &Path, deadline: Instant) -> PortResult<Self> {
        validate_catalog_path(catalog)?;
        let root = catalog.parent().ok_or_else(setup_changed)?;
        let physical = RootIdentity::read(root)?;
        let mut first_installation: Option<ControlId> = None;
        let mut first_incarnation: Option<ControlId> = None;
        loop {
            if Instant::now() >= deadline {
                return Err(PortError::WriterBusy(
                    "setup capture deadline reached".into(),
                ));
            }
            let attempt = (|| {
                if RootIdentity::read(root)? != physical {
                    return Err(setup_changed());
                }
                let control =
                    SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
                control.with_runtime_deadline(deadline, || {
                    if RootIdentity::read(root)? != physical {
                        return Err(setup_changed());
                    }
                    let installation = control.status()?.policy.installation_id;
                    if first_installation
                        .as_ref()
                        .is_some_and(|first| first != &installation)
                    {
                        return Err(setup_changed());
                    }
                    first_installation.get_or_insert_with(|| installation.clone());
                    let store = ManagedStore::open(catalog, &control)?;
                    let incarnation = store.incarnation().clone();
                    if first_incarnation
                        .as_ref()
                        .is_some_and(|first| first != &incarnation)
                    {
                        return Err(setup_changed());
                    }
                    first_incarnation.get_or_insert_with(|| incarnation.clone());
                    drop(store);
                    let identity = Self {
                        catalog: catalog.into(),
                        root: physical,
                        installation,
                        incarnation,
                    };
                    identity.validate_before(deadline)?;
                    Ok(identity)
                })
            })();
            match attempt {
                Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                    std::thread::sleep(
                        Duration::from_millis(5)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                result => return result,
            }
        }
    }

    pub fn validate(&self) -> PortResult<()> {
        self.control().map(drop)
    }

    pub(crate) fn control(&self) -> PortResult<SqliteControlStore> {
        let root = self.catalog.parent().ok_or_else(setup_changed)?;
        if RootIdentity::read(root)? != self.root {
            return Err(setup_changed());
        }
        let control = SqliteControlStore::open_read_only(root, &self.installation)?;
        let store = ManagedStore::open(&self.catalog, &control)?;
        if store.incarnation() != &self.incarnation || RootIdentity::read(root)? != self.root {
            return Err(setup_changed());
        }
        Ok(control)
    }

    pub(crate) fn writable_control(&self) -> PortResult<SqliteControlStore> {
        self.validate()?;
        let root = self.catalog.parent().ok_or_else(setup_changed)?;
        let control = SqliteControlStore::open_existing_writable(root, &self.installation)?;
        self.validate()?;
        Ok(control)
    }

    /// One checked admission using the caller's original end. Busy is returned
    /// to the bounded composition retry; identity mismatch is never retried.
    pub(crate) fn validate_before(&self, deadline: Instant) -> PortResult<()> {
        self.control_before(deadline).map(drop)
    }

    pub(crate) fn control_before(&self, deadline: Instant) -> PortResult<SqliteControlStore> {
        let root = self.catalog.parent().ok_or_else(setup_changed)?;
        if RootIdentity::read(root)? != self.root {
            return Err(setup_changed());
        }
        let control = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
        control.with_runtime_deadline(deadline, || {
            if control.status()?.policy.installation_id != self.installation {
                return Err(setup_changed());
            }
            let store = ManagedStore::open(&self.catalog, &control)?;
            if store.incarnation() != &self.incarnation || RootIdentity::read(root)? != self.root {
                return Err(setup_changed());
            }
            Ok(())
        })?;
        Ok(control)
    }

    pub(crate) fn writable_control_before(
        &self,
        deadline: Instant,
    ) -> PortResult<SqliteControlStore> {
        // Keep A's read-only handle alive through writable admission. No
        // replacement root/installation is adopted to obtain a write handle.
        let witness = self.control_before(deadline)?;
        witness.with_runtime_deadline(deadline, || {
            self.validate_before(deadline)?;
            let root = self.catalog.parent().ok_or_else(setup_changed)?;
            if RootIdentity::read(root)? != self.root {
                return Err(setup_changed());
            }
            let control = SqliteControlStore::open_existing_writable_with_deadline(
                root,
                &self.installation,
                deadline,
            )?;
            self.validate_before(deadline)?;
            Ok(control)
        })
    }
}
fn setup_changed() -> PortError {
    PortError::SnapshotChanged("selected setup identity changed".into())
}

/// Explicit isolated profile roots. ASG config-root overrides affect only
/// the selected host; supplying this struct suppresses every environment lookup.
#[derive(Clone, Default)]
pub struct ProfileRoots {
    pub home: PathBuf,
    pub claude_config_dir: Option<PathBuf>,
    pub codex_home: Option<PathBuf>,
    pub zcode_config_root: Option<PathBuf>,
    pub workbuddy_config_root: Option<PathBuf>,
    pub antigravity_config_root: Option<PathBuf>,
    pub dsh_home: Option<PathBuf>,
}

pub struct SetupHostsRequest {
    pub launcher: PathBuf,
    pub catalog: PathBuf,
    /// The caller's explicit choices. Empty or duplicate choices are rejected.
    pub selected_hosts: Vec<Host>,
    pub expected_identity: ExpectedAsgIdentity,
    pub profiles: Option<ProfileRoots>,
    /// Explicit permission to create missing parents for the selected configs.
    pub create_missing_parents: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationStage {
    Configured,
    Unchanged,
    Conflict,
    Malformed,
    Unowned,
    RecoveryRequired,
    Unsupported,
    Busy,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHandshakeStage {
    Pending,
}
#[derive(Clone, Debug, Serialize)]
pub struct HostStageSummary {
    pub host: Host,
    pub configuration: ConfigurationStage,
    pub owned_by_asg: bool,
    pub host_handshake: HostHandshakeStage,
}
#[derive(Clone, Debug, Serialize)]
pub struct LocalAsgCheck {
    pub version: String,
    pub version_verified: bool,
    pub mcp_initialized: bool,
    pub protocol_version: String,
}

/// Private locator for later removal/repair. Deliberately not Serialize/Debug.
pub struct PrivateReceiptLocator {
    pub host: Host,
    pub config_path: PathBuf,
    pub transaction_root: PathBuf,
    pub transaction_id: String,
    pub receipt_path: PathBuf,
}
impl PrivateReceiptLocator {
    /// Read a bounded private receipt. HostConfigStore still validates ownership.
    pub fn read_receipt(&self) -> Result<HostConfigReceipt> {
        if !valid_transaction_id(&self.transaction_id)
            || self.receipt_path
                != self
                    .transaction_root
                    .join(&self.transaction_id)
                    .join("setup-receipt.json")
        {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
        let receipt = read_sidecar(&self.receipt_path, &self.transaction_id, self.host)?;
        let head = latest_head(&self.transaction_root, &self.transaction_id)?;
        if head.logical != self.config_path
            || head.host != self.host
            || head.receipt.as_ref() != Some(&receipt)
            || !matches!(head.phase, Phase::Verified | Phase::Settled)
        {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
        Ok(receipt)
    }
}
/// Remove an explicitly inventoried host node only when its full receipt chain
/// still belongs to this exact launcher/catalog registration. This does not
/// remove profile directories or retained transaction/conflict artifacts.
pub(crate) fn remove_owned_registration(
    locator: &PrivateReceiptLocator,
    expected: &McpRegistration,
    deadline: Instant,
) -> crate::host_config::Result<HostConfigReceipt> {
    use crate::host_config::{EditStatus, ErrorCode, HostConfigError};
    if Instant::now() >= deadline {
        return Err(ErrorCode::Busy.into());
    }
    ordinary_ancestors(&locator.config_path)
        .map_err(|_| HostConfigError::from(ErrorCode::RecoveryRequired))?;
    if transaction_root(&locator.config_path, locator.host)
        .map_err(|_| HostConfigError::from(ErrorCode::RecoveryRequired))?
        != locator.transaction_root
    {
        return Err(ErrorCode::Unowned.into());
    }
    let original = locator
        .read_receipt()
        .map_err(|_| HostConfigError::from(ErrorCode::RecoveryRequired))?;
    if !original.owned_by_asg {
        return Err(ErrorCode::Unowned.into());
    }
    McpRegistration::new(expected.command.clone(), expected.args.clone())?;
    let value = expected.value(locator.host);
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&value)
                .map_err(|_| HostConfigError::from(ErrorCode::RecoveryRequired))?
        )
    );
    if original.owned_value_sha256.as_deref() != Some(digest.as_str()) {
        return Err(ErrorCode::Unowned.into());
    }
    let store = HostConfigStore::open(
        &locator.config_path,
        &locator.transaction_root,
        locator.host,
    )?;
    let prior = prior_receipt(
        &store,
        &locator.config_path,
        &locator.transaction_root,
        locator.host,
    )
    .map_err(|_| HostConfigError::from(ErrorCode::RecoveryRequired))?
    .ok_or(ErrorCode::RecoveryRequired)?;
    // A completed earlier removal may have no node hash. An unrelated newer
    // registration, including an identical unowned one, is never adopted.
    if !prior.owned_by_asg && prior.status != EditStatus::Removed {
        return Err(ErrorCode::Unowned.into());
    }
    if prior.owned_value_sha256.as_deref() != Some(digest.as_str())
        && !(prior.status == EditStatus::Removed && prior.owned_value_sha256.is_none())
    {
        return Err(ErrorCode::Conflict.into());
    }
    if Instant::now() >= deadline {
        return Err(ErrorCode::Busy.into());
    }
    let removed = store.remove(&prior)?;
    persist_receipt(&locator.config_path, &locator.transaction_root, &removed)
        .map_err(|_| HostConfigError::from(ErrorCode::RecoveryRequired))?;
    if Instant::now() >= deadline {
        // The receipt records the actual completed effect even when the caller
        // must report unfinished work after its original budget was exhausted.
        return Err(ErrorCode::Busy.into());
    }
    Ok(removed)
}
pub struct SetupHostsReport {
    pub local_asg: LocalAsgCheck,
    pub hosts: Vec<HostStageSummary>,
    /// Keep in private installation state; do not send through robot/MCP output.
    pub private_receipts: Vec<PrivateReceiptLocator>,
    /// Completed host stages remain available when a later preflight fails.
    pub interruption: Option<SetupHostsErrorCode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStage {
    AfterProbe,
    BeforeProfile,
    BeforeConfig,
    BeforeReceipt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupHostsErrorCode {
    InvalidSelection,
    InvalidPath,
    IdentityMismatch,
    ProbeFailed,
    ProbeTimeout,
    Io,
    RecoveryRequired,
}
#[derive(Debug)]
pub struct SetupHostsError {
    pub code: SetupHostsErrorCode,
}
impl fmt::Display for SetupHostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "host setup {:?}; inspect the selected local setup inputs",
            self.code
        )
    }
}
impl std::error::Error for SetupHostsError {}
impl From<SetupHostsErrorCode> for SetupHostsError {
    fn from(code: SetupHostsErrorCode) -> Self {
        Self { code }
    }
}
pub type Result<T> = std::result::Result<T, SetupHostsError>;
fn io(_: impl fmt::Debug) -> SetupHostsError {
    SetupHostsErrorCode::Io.into()
}
fn invalid_path() -> SetupHostsError {
    SetupHostsErrorCode::InvalidPath.into()
}
fn valid_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(invalid_path());
    }
    Ok(())
}
fn linked(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}
fn ordinary_ancestors(path: &Path) -> Result<()> {
    valid_path(path)?;
    for path in path.ancestors() {
        match fs::symlink_metadata(path) {
            Ok(meta) if linked(&meta) => return Err(invalid_path()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(())
}
fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ordinary_ancestors(path)?;
    let mut file = open_pinned(path)?;
    if file.metadata().map_err(io)?.len() > limit {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > limit {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    Ok(bytes)
}
fn open_pinned(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Keep the selected binary/receipt from being renamed or overwritten.
        options.share_mode(1).custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() || linked(&metadata) {
        return Err(invalid_path());
    }
    Ok(file)
}
fn digest_file(file: &File) -> Result<String> {
    use std::io::{Seek, SeekFrom};
    let mut file = file.try_clone().map_err(io)?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Invoke only the caller-pinned local ASG executable. No evidence tools are
/// called: --version and one MCP initialize frame cannot import histories.
pub fn check_local_asg(
    launcher: &Path,
    catalog: &Path,
    expected: &ExpectedAsgIdentity,
) -> Result<LocalAsgCheck> {
    ordinary_ancestors(launcher)?;
    ordinary_ancestors(catalog)?;
    if expected.version.is_empty()
        || expected.version.len() > 64
        || !expected
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
        || expected.launcher_sha256.len() != 64
        || !expected
            .launcher_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SetupHostsErrorCode::IdentityMismatch.into());
    }
    // Do not retain a restrictive sharing handle while SQLite opens its own
    // read-only connection (which may update SHM reader bookkeeping).
    drop(open_pinned(catalog)?);
    let binary = open_pinned(launcher)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = binary.metadata().map_err(io)?;
        if meta.mode() & 0o022 != 0
            || meta.mode() & 0o111 == 0
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(SetupHostsErrorCode::IdentityMismatch.into());
        }
    }
    if digest_file(&binary)? != expected.launcher_sha256 {
        return Err(SetupHostsErrorCode::IdentityMismatch.into());
    }
    let output = probe(launcher, &[OsStr::new("--version")], b"")?;
    let version = format!("agent-session-grep {}", expected.version);
    if output != version.as_bytes()
        && output != (version.clone() + "\n").as_bytes()
        && output != (version + "\r\n").as_bytes()
    {
        return Err(SetupHostsErrorCode::IdentityMismatch.into());
    }
    let frame = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":MCP_VERSION,"capabilities":{},"clientInfo":{"name":"asg-setup-self-check","version":"1"}
    }})).map_err(io)?;
    let mut input = frame;
    input.push(b'\n');
    let output = probe(
        launcher,
        &[OsStr::new("--db"), catalog.as_os_str(), OsStr::new("mcp")],
        &input,
    )?;
    let value: Value = serde_json::from_slice(&output)
        .map_err(|_| SetupHostsError::from(SetupHostsErrorCode::ProbeFailed))?;
    if value.get("jsonrpc") != Some(&json!("2.0"))
        || value.get("id") != Some(&json!(1))
        || value.get("error").is_some()
        || value["result"]["protocolVersion"] != MCP_VERSION
        || value["result"]["serverInfo"]["name"] != "agent-session-grep"
        || value["result"]["serverInfo"]["version"] != expected.version
        || !value["result"]["capabilities"]["tools"].is_object()
    {
        return Err(SetupHostsErrorCode::ProbeFailed.into());
    }
    ordinary_ancestors(launcher)?;
    if digest_file(&binary)? != expected.launcher_sha256
        || digest_file(&open_pinned(launcher)?)? != expected.launcher_sha256
    {
        return Err(SetupHostsErrorCode::IdentityMismatch.into());
    }
    Ok(LocalAsgCheck {
        version: expected.version.clone(),
        version_verified: true,
        mcp_initialized: true,
        protocol_version: MCP_VERSION.into(),
    })
}

fn probe(launcher: &Path, args: &[&OsStr], input: &[u8]) -> Result<Vec<u8>> {
    probe_with_timeout(launcher, args, input, PROBE_TIMEOUT)
}

fn probe_with_timeout(
    launcher: &Path,
    args: &[&OsStr],
    input: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let capture = capture_input(launcher, args, input, Instant::now() + timeout)?;
    if !capture.success || !capture.stderr.is_empty() {
        return Err(SetupHostsErrorCode::ProbeFailed.into());
    }
    Ok(capture.stdout)
}

/// Private bounded process output, never a public diagnostic or identity proof.
/// Successful native managers may write warnings; callers validate stdout and
/// ownership separately instead of interpreting empty stderr as success.
pub(crate) struct LocalCapture {
    pub(crate) success: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

/// Reuses the probe's isolated process tree and pipe drain. The caller owns the
/// single operation deadline; each command consumes its remaining time.
pub(crate) fn capture_local(
    program: &Path,
    args: &[&OsStr],
    deadline: Instant,
) -> Result<LocalCapture> {
    capture_input(program, args, b"", deadline)
}

fn capture_input(
    launcher: &Path,
    args: &[&OsStr],
    input: &[u8],
    deadline: Instant,
) -> Result<LocalCapture> {
    if Instant::now() >= deadline {
        return Err(SetupHostsErrorCode::ProbeTimeout.into());
    }
    // Pre-fill only a small fixed control frame, below PIPE_BUF. No blocking
    // writer or reader thread is allowed to outlive the process-tree budget.
    if input.len() > 512 {
        return Err(SetupHostsErrorCode::ProbeFailed.into());
    }
    let (stdin, mut writer) = std::io::pipe().map_err(io)?;
    writer.write_all(input).map_err(io)?;
    drop(writer);
    let (mut stdout, out_writer) = std::io::pipe().map_err(io)?;
    let (mut stderr, err_writer) = std::io::pipe().map_err(io)?;
    process::prepare_reader(&stdout)?;
    process::prepare_reader(&stderr)?;
    // Reserve bounded process-tree cleanup inside the caller's deadline.
    // No timeout/reset may allocate another two-second operation afterward.
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SetupHostsErrorCode::ProbeTimeout.into());
    }
    let reserve = (remaining / 4).min(Duration::from_secs(2));
    let capture_deadline = deadline - reserve;
    let mut child = process::ProbeProcess::spawn(launcher, args, stdin, out_writer, err_writer)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    let outcome = (|| {
        loop {
            if !out_eof {
                out_eof = drain_probe(&mut stdout, &mut out)?;
            }
            if !err_eof {
                err_eof = drain_probe(&mut stderr, &mut err)?;
            }
            if let Some(success) = child.status()?
                && out_eof
                && err_eof
            {
                return Ok(LocalCapture {
                    success,
                    stdout: out,
                    stderr: err,
                });
            }
            if Instant::now() >= capture_deadline {
                return Err(SetupHostsErrorCode::ProbeTimeout.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Even a successful direct child may have left a descendant. Reap only our
    // private process tree, including when capture or parsing failed.
    child.stop(deadline)?;
    if Instant::now() >= deadline {
        return Err(SetupHostsErrorCode::ProbeTimeout.into());
    }
    outcome
}

fn drain_probe(reader: &mut std::io::PipeReader, bytes: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0; 4096];
    loop {
        match process::read_available(reader, &mut buffer).map_err(io)? {
            None => return Ok(false),
            Some(0) => return Ok(true),
            Some(count) => {
                if bytes.len() + count > MAX_CAPTURE {
                    return Err(SetupHostsErrorCode::ProbeFailed.into());
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
    }
}

#[cfg(unix)]
mod process {
    use super::*;
    use std::{
        io::{PipeReader, PipeWriter},
        os::unix::{io::AsRawFd, process::CommandExt},
        process::{Child, Command, Stdio},
    };

    pub(super) fn prepare_reader(reader: &PipeReader) -> Result<()> {
        // SAFETY: borrowed pipe fd; flags do not change ownership.
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                == -1
        {
            return Err(io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    pub(super) fn read_available(
        reader: &mut PipeReader,
        buffer: &mut [u8],
    ) -> std::io::Result<Option<usize>> {
        match reader.read(buffer) {
            Ok(count) => Ok(Some(count)),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    pub(super) struct ProbeProcess {
        child: Child,
        stopped: bool,
    }
    impl ProbeProcess {
        pub(super) fn spawn(
            path: &Path,
            args: &[&OsStr],
            stdin: PipeReader,
            stdout: PipeWriter,
            stderr: PipeWriter,
        ) -> Result<Self> {
            let child = Command::new(path)
                .args(args)
                .process_group(0)
                .stdin(Stdio::from(stdin))
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr))
                .spawn()
                .map_err(io)?;
            Ok(Self {
                child,
                stopped: false,
            })
        }
        pub(super) fn status(&mut self) -> Result<Option<bool>> {
            // Keep the exited leader unreaped until group termination. Reaping
            // here would allow its PID/PGID to be reused before stop() signals.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == -1
            {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(io(error));
            }
            // SAFETY: waitid initializes these fields for an exited child.
            if unsafe { info.si_pid() } == 0 {
                return Ok(None);
            }
            Ok(Some(
                info.si_code == libc::CLD_EXITED && unsafe { info.si_status() } == 0,
            ))
        }
        pub(super) fn stop(&mut self, deadline: Instant) -> Result<()> {
            if self.stopped {
                return Ok(());
            }
            // SAFETY: process group was created for this local probe alone.
            if unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) } == -1
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            while self.status()?.is_none() {
                if Instant::now() >= deadline {
                    return Err(SetupHostsErrorCode::ProbeTimeout.into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            self.child.wait().map_err(io)?;
            self.stopped = true;
            Ok(())
        }
    }
    impl Drop for ProbeProcess {
        fn drop(&mut self) {
            if !self.stopped {
                // Final safeguard is nonblocking. Explicit stop() must verify
                // exit before success; failed cleanup never resets a deadline.
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                let _ = self.child.try_wait();
            }
        }
    }
}

#[cfg(windows)]
mod process {
    use super::*;
    use std::{
        io::{PipeReader, PipeWriter},
        mem::size_of,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::{
        Foundation::{
            ERROR_BROKEN_PIPE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        System::{JobObjects::*, Pipes::PeekNamedPipe, Threading::*},
    };

    pub(super) fn prepare_reader(_: &PipeReader) -> Result<()> {
        Ok(())
    }
    pub(super) fn read_available(
        reader: &mut PipeReader,
        buffer: &mut [u8],
    ) -> std::io::Result<Option<usize>> {
        let mut available = 0;
        // SAFETY: borrowed read-only pipe handle, valid out parameter. This
        // pipe has exactly one reader, so the following read cannot race one.
        if unsafe {
            PeekNamedPipe(
                reader.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(Some(0))
            } else {
                Err(error)
            };
        }
        if available == 0 {
            return Ok(None);
        }
        let count = buffer.len().min(available as usize);
        reader.read(&mut buffer[..count]).map(Some)
    }
    struct Attributes(Vec<usize>);
    impl Attributes {
        fn new() -> Result<Self> {
            let mut size = 0;
            // SAFETY: first call queries size, second initializes aligned storage.
            unsafe {
                InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size);
            }
            if size == 0 {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            let mut data = vec![0usize; size.div_ceil(size_of::<usize>())];
            if unsafe {
                InitializeProcThreadAttributeList(data.as_mut_ptr().cast(), 2, 0, &mut size)
            } == 0
            {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            Ok(Self(data))
        }
        fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.0.as_mut_ptr().cast()
        }
    }
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.raw());
            }
        }
    }
    fn command_line(path: &Path, args: &[&OsStr]) -> Result<Vec<u16>> {
        let mut line = Vec::new();
        for arg in std::iter::once(path.as_os_str()).chain(args.iter().copied()) {
            if !line.is_empty() {
                line.push(b' ' as u16);
            }
            line.push(b'"' as u16);
            let mut slashes = 0;
            for ch in arg.encode_wide() {
                if ch == 0 {
                    return Err(invalid_path());
                }
                if ch == b'\\' as u16 {
                    slashes += 1;
                    continue;
                }
                let count = if ch == b'"' as u16 {
                    2 * slashes + 1
                } else {
                    slashes
                };
                line.extend(std::iter::repeat_n(b'\\' as u16, count));
                line.push(ch);
                slashes = 0;
            }
            line.extend(std::iter::repeat_n(b'\\' as u16, 2 * slashes));
            line.push(b'"' as u16);
            if line.len() >= 32767 {
                return Err(invalid_path());
            }
        }
        line.push(0);
        Ok(line)
    }
    pub(super) struct ProbeProcess {
        process: OwnedHandle,
        job: OwnedHandle,
        stopped: bool,
    }
    impl ProbeProcess {
        pub(super) fn spawn(
            path: &Path,
            args: &[&OsStr],
            stdin: PipeReader,
            stdout: PipeWriter,
            stderr: PipeWriter,
        ) -> Result<Self> {
            let mut line = command_line(path, args)?;
            let executable: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: unnamed noninheritable job with scoped ownership.
            let raw_job = unsafe { CreateJobObjectW(null(), null()) };
            if raw_job.is_null() {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            let job = unsafe { OwnedHandle::from_raw_handle(raw_job) };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    raw_job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            let handles = [
                stdin.as_raw_handle(),
                stdout.as_raw_handle(),
                stderr.as_raw_handle(),
            ];
            for handle in handles {
                if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
                    == 0
                {
                    return Err(SetupHostsErrorCode::ProbeFailed.into());
                }
            }
            let mut attributes = Attributes::new()?;
            let jobs = [raw_job];
            // Windows 10+: the job is attached by CreateProcess before any code
            // runs. Failure is terminal; never spawn then race to attach a job.
            for (kind, values) in [
                (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.as_slice()),
                (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs.as_slice()),
            ] {
                if unsafe {
                    UpdateProcThreadAttribute(
                        attributes.raw(),
                        0,
                        kind as usize,
                        values.as_ptr().cast(),
                        std::mem::size_of_val(values),
                        null_mut(),
                        null(),
                    )
                } == 0
                {
                    return Err(SetupHostsErrorCode::ProbeFailed.into());
                }
            }
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: size_of::<STARTUPINFOEXW>() as u32,
                    dwFlags: STARTF_USESTDHANDLES,
                    hStdInput: handles[0],
                    hStdOutput: handles[1],
                    hStdError: handles[2],
                    ..Default::default()
                },
                lpAttributeList: attributes.raw(),
            };
            let mut info = PROCESS_INFORMATION::default();
            // SAFETY: valid NUL-terminated inputs, initialized attributes and
            // explicitly listed handles live throughout process creation.
            if unsafe {
                CreateProcessW(
                    executable.as_ptr(),
                    line.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    null(),
                    null(),
                    &startup.StartupInfo,
                    &mut info,
                )
            } == 0
            {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
            drop(unsafe { OwnedHandle::from_raw_handle(info.hThread) });
            Ok(Self {
                process,
                job,
                stopped: false,
            })
        }
        pub(super) fn status(&mut self) -> Result<Option<bool>> {
            match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => {
                    let mut exit = 0;
                    if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut exit) } == 0 {
                        return Err(SetupHostsErrorCode::ProbeFailed.into());
                    }
                    Ok(Some(exit == 0))
                }
                _ => Err(SetupHostsErrorCode::ProbeFailed.into()),
            }
        }
        pub(super) fn stop(&mut self, deadline: Instant) -> Result<()> {
            if self.stopped {
                return Ok(());
            }
            if unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } == 0 {
                return Err(SetupHostsErrorCode::ProbeFailed.into());
            }
            loop {
                let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                if unsafe {
                    QueryInformationJobObject(
                        self.job.as_raw_handle(),
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    )
                } == 0
                {
                    return Err(SetupHostsErrorCode::ProbeFailed.into());
                }
                if accounting.ActiveProcesses == 0 && self.status()?.is_some() {
                    self.stopped = true;
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(SetupHostsErrorCode::ProbeTimeout.into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    impl Drop for ProbeProcess {
        fn drop(&mut self) {
            // Nonblocking final safeguard; explicit stop above verifies exit.
            if !self.stopped {
                unsafe {
                    TerminateJobObject(self.job.as_raw_handle(), 1);
                }
            }
        }
    }
}

fn environment_profiles(hosts: &[Host]) -> Result<ProfileRoots> {
    profiles_from_environment(hosts, |name| std::env::var_os(name))
}
fn profiles_from_environment(
    hosts: &[Host],
    mut environment: impl FnMut(&str) -> Option<std::ffi::OsString>,
) -> Result<ProfileRoots> {
    let home = environment(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .ok_or_else(invalid_path)?;
    let mut read = |name: &str| -> Result<Option<PathBuf>> {
        match environment(name) {
            Some(value) if value.is_empty() => Err(invalid_path()),
            Some(value) => Ok(Some(value.into())),
            None => Ok(None),
        }
    };
    Ok(ProfileRoots {
        home,
        claude_config_dir: if hosts.contains(&Host::ClaudeCode) {
            read("CLAUDE_CONFIG_DIR")?
        } else {
            None
        },
        codex_home: if hosts.contains(&Host::Codex) {
            read("CODEX_HOME")?
        } else {
            None
        },
        zcode_config_root: if hosts.contains(&Host::ZCode) {
            read("ASG_ZCODE_CONFIG_ROOT")?
        } else {
            None
        },
        workbuddy_config_root: if hosts.contains(&Host::WorkBuddy) {
            read("ASG_WORKBUDDY_CONFIG_ROOT")?
        } else {
            None
        },
        antigravity_config_root: if hosts.contains(&Host::Antigravity) {
            read("ASG_ANTIGRAVITY_CONFIG_ROOT")?
        } else {
            None
        },
        dsh_home: if hosts.contains(&Host::DeepSeekHarness) {
            read("DSH_HOME")?
        } else {
            None
        },
    })
}
fn config_path(host: Host, profiles: &ProfileRoots) -> Result<PathBuf> {
    let path = match host {
        Host::ClaudeCode => profiles
            .claude_config_dir
            .as_ref()
            .unwrap_or(&profiles.home)
            .join(".claude.json"),
        Host::Codex => profiles
            .codex_home
            .clone()
            .unwrap_or_else(|| profiles.home.join(".codex"))
            .join("config.toml"),
        Host::ZCode => profiles
            .zcode_config_root
            .clone()
            .unwrap_or_else(|| profiles.home.join(".zcode"))
            .join("cli/config.json"),
        Host::WorkBuddy => profiles
            .workbuddy_config_root
            .clone()
            .unwrap_or_else(|| profiles.home.join(".workbuddy"))
            .join("mcp.json"),
        Host::Antigravity => profiles
            .antigravity_config_root
            .clone()
            .unwrap_or_else(|| profiles.home.join(".gemini/config"))
            .join("mcp_config.json"),
        Host::DeepSeekHarness => profiles
            .dsh_home
            .clone()
            .unwrap_or_else(|| profiles.home.join(".dsh"))
            .join("cordis.patch.yml"),
    };
    valid_path(&path)?;
    Ok(path)
}
fn ensure_parent(path: &Path, allow_create: bool) -> Result<()> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => return Err(invalid_path()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    if !allow_create {
        return Err(invalid_path());
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(invalid_path());
    }
    // Existing resolved config symlinks belong to HostConfigStore. Creating a
    // new chain through a link is deliberately outside this permission flag.
    ordinary_ancestors(path)?;
    let parent = path.parent().ok_or_else(invalid_path)?;
    ensure_parent(parent, true)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(e) => Err(io(e)),
    }
}
fn transaction_root(config: &Path, host: Host) -> Result<PathBuf> {
    let actual = match fs::canonicalize(config) {
        Ok(path) => path,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && fs::symlink_metadata(config).is_err() =>
        {
            fs::canonicalize(config.parent().ok_or_else(invalid_path)?)
                .map_err(io)?
                .join(config.file_name().ok_or_else(invalid_path)?)
        }
        Err(e) => return Err(io(e)),
    };
    let name = host.id();
    let hash = format!(
        "{:x}",
        Sha256::digest(actual.as_os_str().as_encoded_bytes())
    );
    Ok(actual
        .parent()
        .ok_or_else(invalid_path)?
        .join(format!(".asg-host-{name}-{}", &hash[..16])))
}

#[derive(Deserialize)]
struct JournalHead {
    schema: String,
    id: String,
    host: Host,
    logical: PathBuf,
    target: PathBuf,
    previous_receipt: Option<String>,
    receipt: Option<HostConfigReceipt>,
    phase: Phase,
    seq: u32,
}
fn valid_transaction_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn latest_head(root: &Path, id: &str) -> Result<JournalHead> {
    if !valid_transaction_id(id) {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    let directory = root.join(id);
    ordinary_ancestors(&directory)?;
    let mut states = BTreeMap::new();
    for entry in fs::read_dir(&directory).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_path())?;
        if let Some(seq) = name
            .strip_prefix("state-")
            .and_then(|s| s.strip_suffix(".json"))
        {
            if seq.len() != 4 {
                return Err(SetupHostsErrorCode::RecoveryRequired.into());
            }
            states.insert(
                seq.parse::<u32>()
                    .map_err(|_| SetupHostsError::from(SetupHostsErrorCode::RecoveryRequired))?,
                entry.path(),
            );
        }
        if states.len() > 128 {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
    }
    let (seq, path) = states
        .last_key_value()
        .ok_or(SetupHostsErrorCode::RecoveryRequired)?;
    if states.keys().copied().ne(0..=*seq) {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    let head: JournalHead = serde_json::from_slice(&read_regular(path, MAX_RECEIPT)?)
        .map_err(|_| SetupHostsError::from(SetupHostsErrorCode::RecoveryRequired))?;
    if head.id != id || head.seq != *seq || head.schema != "asg.host-config-journal/v1" {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    Ok(head)
}
fn prior_receipt(
    store: &HostConfigStore,
    config: &Path,
    root: &Path,
    host: Host,
) -> Result<Option<HostConfigReceipt>> {
    let infos = store
        .inspect_recovery()
        .map_err(|_| SetupHostsError::from(SetupHostsErrorCode::RecoveryRequired))?;
    if infos.is_empty() {
        return Ok(None);
    }
    let mut heads = BTreeMap::new();
    let mut parents = BTreeSet::new();
    for info in infos {
        if !matches!(info.phase, Phase::Verified | Phase::Settled) || info.retained_artifact_changed
        {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
        let head = latest_head(root, &info.transaction_id)?;
        if head.host != host
            || head.logical != config
            || !matches!(head.phase, Phase::Verified | Phase::Settled)
            || head.target.parent() != root.parent()
            || head.receipt.is_none()
        {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
        let sidecar = root.join(&head.id).join("setup-receipt.json");
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                if Some(read_sidecar(&sidecar, &head.id, host)?) != head.receipt {
                    return Err(SetupHostsErrorCode::RecoveryRequired.into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(error)),
        }
        if let Some(parent) = &head.previous_receipt {
            parents.insert(parent.clone());
        }
        heads.insert(head.id.clone(), head);
    }
    if parents.iter().any(|id| !heads.contains_key(id)) {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    let leaves: Vec<_> = heads
        .keys()
        .filter(|id| !parents.contains(*id))
        .cloned()
        .collect();
    if leaves.len() != 1 {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    let mut cursor = Some(leaves[0].clone());
    let mut visited = BTreeSet::new();
    while let Some(id) = cursor {
        if !visited.insert(id.clone()) {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
        cursor = heads
            .get(&id)
            .ok_or(SetupHostsErrorCode::RecoveryRequired)?
            .previous_receipt
            .clone();
    }
    if visited.len() != heads.len() {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    let head = heads
        .remove(&leaves[0])
        .ok_or(SetupHostsErrorCode::RecoveryRequired)?;
    // The actual ownership check remains in HostConfigStore::install. A lost
    // composition receipt is reconstructed from its durable verified journal.
    head.receipt
        .map(Some)
        .ok_or_else(|| SetupHostsErrorCode::RecoveryRequired.into())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptFile {
    schema: String,
    host: Host,
    transaction_id: String,
    receipt: HostConfigReceipt,
}
fn read_sidecar(path: &Path, id: &str, host: Host) -> Result<HostConfigReceipt> {
    let file: ReceiptFile = serde_json::from_slice(&read_regular(path, MAX_RECEIPT)?)
        .map_err(|_| SetupHostsError::from(SetupHostsErrorCode::RecoveryRequired))?;
    if file.schema != "asg.setup-host/v1"
        || file.host != host
        || file.transaction_id != id
        || file.receipt.transaction_id != id
        || file.receipt.host != host
    {
        return Err(SetupHostsErrorCode::RecoveryRequired.into());
    }
    Ok(file.receipt)
}
fn persist_receipt(
    config: &Path,
    root: &Path,
    receipt: &HostConfigReceipt,
) -> Result<PrivateReceiptLocator> {
    let directory = root.join(&receipt.transaction_id);
    ordinary_ancestors(&directory)?;
    let path = directory.join("setup-receipt.json");
    if fs::symlink_metadata(&path).is_ok() {
        if read_sidecar(&path, &receipt.transaction_id, receipt.host)? != *receipt {
            return Err(SetupHostsErrorCode::RecoveryRequired.into());
        }
    } else {
        let value = ReceiptFile {
            schema: "asg.setup-host/v1".into(),
            host: receipt.host,
            transaction_id: receipt.transaction_id.clone(),
            receipt: receipt.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&value).map_err(io)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(io)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let pending = directory.join(format!("setup-receipt-{suffix}.pending"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut output = options.open(&pending).map_err(io)?;
        output.write_all(&bytes).map_err(io)?;
        output.sync_all().map_err(io)?;
        drop(output);
        // No-clobber publish: one record per immutable host transaction.
        match fs::hard_link(&pending, &path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_sidecar(&path, &receipt.transaction_id, receipt.host)? != *receipt {
                    return Err(SetupHostsErrorCode::RecoveryRequired.into());
                }
            }
            Err(e) => return Err(io(e)),
        }
        fs::remove_file(&pending).map_err(io)?;
        #[cfg(unix)]
        {
            File::open(&directory).map_err(io)?.sync_all().map_err(io)?;
        }
    }
    Ok(PrivateReceiptLocator {
        host: receipt.host,
        config_path: config.into(),
        transaction_root: root.into(),
        transaction_id: receipt.transaction_id.clone(),
        receipt_path: path,
    })
}
fn stage(code: ConfigErrorCode) -> ConfigurationStage {
    match code {
        ConfigErrorCode::Conflict => ConfigurationStage::Conflict,
        ConfigErrorCode::Malformed => ConfigurationStage::Malformed,
        ConfigErrorCode::Unowned => ConfigurationStage::Unowned,
        ConfigErrorCode::RecoveryRequired => ConfigurationStage::RecoveryRequired,
        ConfigErrorCode::Unsupported => ConfigurationStage::Unsupported,
        ConfigErrorCode::Busy => ConfigurationStage::Busy,
        ConfigErrorCode::Invalid | ConfigErrorCode::Io => ConfigurationStage::Failed,
    }
}

/// Verify local ASG before any profile write, then register only selected hosts.
/// The caller must verify the package identity and obtain the user's choices.
/// Per-host failures are returned in the report; completed edits stay recorded.
/// This does not repair unfinished journals or establish host acceptance.
pub fn setup_selected_hosts(request: &SetupHostsRequest) -> Result<SetupHostsReport> {
    setup_selected_hosts_checked(request, &mut |_| Ok(()))
}

/// The composition owner rechecks its original managed identity after probes
/// and immediately before every profile/configuration/receipt mutation.
pub fn setup_selected_hosts_checked(
    request: &SetupHostsRequest,
    preflight: &mut dyn FnMut(SetupStage) -> Result<()>,
) -> Result<SetupHostsReport> {
    if request.selected_hosts.is_empty()
        || request.selected_hosts.len() > 6
        || request
            .selected_hosts
            .iter()
            .enumerate()
            .any(|(index, host)| request.selected_hosts[..index].contains(host))
    {
        return Err(SetupHostsErrorCode::InvalidSelection.into());
    }
    let profiles = match &request.profiles {
        Some(profiles) => profiles.clone(),
        None => environment_profiles(&request.selected_hosts)?,
    };
    let paths = request
        .selected_hosts
        .iter()
        .map(|&host| config_path(host, &profiles).map(|path| (host, path)))
        .collect::<Result<Vec<_>>>()?;
    let local_asg = check_local_asg(
        &request.launcher,
        &request.catalog,
        &request.expected_identity,
    )?;
    let registration = McpRegistration::new(
        request.launcher.to_str().ok_or_else(invalid_path)?.into(),
        vec![
            "--db".into(),
            request.catalog.to_str().ok_or_else(invalid_path)?.into(),
            "mcp".into(),
        ],
    )
    .map_err(|_| invalid_path())?;
    let mut report = SetupHostsReport {
        local_asg,
        hosts: Vec::new(),
        private_receipts: Vec::new(),
        interruption: None,
    };
    if let Err(error) = preflight(SetupStage::AfterProbe) {
        report.interruption = Some(error.code);
        return Ok(report);
    }
    for (host, config) in paths {
        let mut summary = HostStageSummary {
            host,
            configuration: ConfigurationStage::Failed,
            owned_by_asg: false,
            host_handshake: HostHandshakeStage::Pending,
        };
        if let Err(error) = preflight(SetupStage::BeforeProfile) {
            report.interruption = Some(error.code);
            report.hosts.push(summary);
            break;
        }
        if ensure_parent(
            config.parent().ok_or_else(invalid_path)?,
            request.create_missing_parents,
        )
        .is_err()
        {
            report.hosts.push(summary);
            continue;
        }
        let root = match transaction_root(&config, host) {
            Ok(root) => root,
            Err(_) => {
                report.hosts.push(summary);
                continue;
            }
        };
        let store = match HostConfigStore::open(&config, &root, host) {
            Ok(store) => store,
            Err(e) => {
                summary.configuration = stage(e.code);
                report.hosts.push(summary);
                continue;
            }
        };
        let prior = match prior_receipt(&store, &config, &root, host) {
            Ok(receipt) => receipt,
            Err(_) => {
                summary.configuration = ConfigurationStage::RecoveryRequired;
                // Incomplete/ambiguous chains still have useful private repair
                // locators. Reading a receipt may fail until explicit recovery.
                if let Ok(infos) = store.inspect_recovery() {
                    for info in infos {
                        report.private_receipts.push(receipt_locator(
                            &config,
                            &root,
                            host,
                            &info.transaction_id,
                        ));
                    }
                }
                report.hosts.push(summary);
                continue;
            }
        };
        if let Err(error) = preflight(SetupStage::BeforeConfig) {
            report.interruption = Some(error.code);
            report.hosts.push(summary);
            break;
        }
        let configured = if host == Host::ZCode {
            store.install_with_zcode_fallback(
                &registration,
                prior.as_ref(),
                &profiles.home.join(".agents/mcp.json"),
            )
        } else {
            store.install(&registration, prior.as_ref())
        };
        match configured {
            Ok(receipt) => {
                summary.configuration =
                    if receipt.status == crate::host_config::EditStatus::Unchanged {
                        ConfigurationStage::Unchanged
                    } else {
                        ConfigurationStage::Configured
                    };
                summary.owned_by_asg = receipt.owned_by_asg;
                // Revalidate a unique receipt chain before reporting completion.
                if prior_receipt(&store, &config, &root, host)
                    .ok()
                    .flatten()
                    .as_ref()
                    != Some(&receipt)
                {
                    summary.configuration = ConfigurationStage::RecoveryRequired;
                }
                if let Err(error) = preflight(SetupStage::BeforeReceipt) {
                    report.interruption = Some(error.code);
                    summary.configuration = ConfigurationStage::RecoveryRequired;
                    report.private_receipts.push(receipt_locator(
                        &config,
                        &root,
                        host,
                        &receipt.transaction_id,
                    ));
                    report.hosts.push(summary);
                    break;
                }
                match persist_receipt(&config, &root, &receipt) {
                    Ok(locator) => report.private_receipts.push(locator),
                    Err(_) => {
                        summary.configuration = ConfigurationStage::RecoveryRequired;
                        report.private_receipts.push(receipt_locator(
                            &config,
                            &root,
                            host,
                            &receipt.transaction_id,
                        ));
                    }
                }
            }
            Err(error) => {
                summary.configuration = stage(error.code);
                if let Some(id) = error
                    .transaction_id
                    .as_deref()
                    .or_else(|| prior.as_ref().map(|p| p.transaction_id.as_str()))
                {
                    report
                        .private_receipts
                        .push(receipt_locator(&config, &root, host, id));
                }
            }
        }
        report.hosts.push(summary);
    }
    Ok(report)
}

fn receipt_locator(config: &Path, root: &Path, host: Host, id: &str) -> PrivateReceiptLocator {
    PrivateReceiptLocator {
        host,
        config_path: config.into(),
        transaction_root: root.into(),
        transaction_id: id.into(),
        receipt_path: root.join(id).join("setup-receipt.json"),
    }
}

#[cfg(test)]
#[path = "setup_hosts_tests.rs"]
mod tests;
