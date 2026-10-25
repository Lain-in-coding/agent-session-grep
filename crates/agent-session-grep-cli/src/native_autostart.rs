//! Owned native login configuration, independent of supervisor execution.
//! No manager, host, shell, source scan or elevation is invoked here. Manager
//! apply/readback belongs to native_manager; configuration presence is not a
//! manager-load or login receipt. Private journals retain observed conflicts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Instant,
};

const MAX_IMAGE: u64 = 1024 * 1024;
const MAX_JOURNAL: u64 = 16 * MAX_IMAGE;
const MAX_TRANSACTIONS: usize = 256;
#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeKind {
    WindowsRun,
    LaunchAgent,
    SystemdUser,
}

/// Explicit roots; Windows paths are always relative to HKCU, never HKLM.
/// Injection is for isolated tests/custom user profiles, not alternate tokens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeLocation {
    WindowsRun { subkey: String },
    LaunchAgent { directory: PathBuf, uid: u32 },
    SystemdUser { directory: PathBuf },
}
impl NativeLocation {
    pub fn current_user() -> Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self::WindowsRun {
                subkey: RUN_KEY.into(),
            })
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Self::LaunchAgent {
                directory: home()?.join("Library/LaunchAgents"),
                uid: unsafe { libc::getuid() },
            })
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let root = match std::env::var_os("XDG_CONFIG_HOME") {
                Some(v) => PathBuf::from(v),
                None => home()?.join(".config"),
            };
            valid_path(&root)?;
            Ok(Self::SystemdUser {
                directory: root.join("systemd/user"),
            })
        }
    }
    fn kind(&self) -> NativeKind {
        match self {
            Self::WindowsRun { .. } => NativeKind::WindowsRun,
            Self::LaunchAgent { .. } => NativeKind::LaunchAgent,
            Self::SystemdUser { .. } => NativeKind::SystemdUser,
        }
    }
    fn directory(&self) -> Option<&Path> {
        match self {
            Self::WindowsRun { .. } => None,
            Self::LaunchAgent { directory, .. } | Self::SystemdUser { directory } => {
                Some(directory)
            }
        }
    }
}
#[cfg(unix)]
fn home() -> Result<PathBuf> {
    let p = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(ErrorCode::Invalid)?;
    valid_path(&p)?;
    Ok(p)
}

/// The caller verifies package membership/native GUI shim identity first.
/// This adapter independently pins and hashes the supervisor before enabling.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorRegistration {
    pub supervisor: PathBuf,
    pub supervisor_sha256: String,
    pub catalog: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationState {
    Present,
    Absent,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutostartReceipt {
    pub schema: String,
    pub installation_id: String,
    pub transaction_id: String,
    pub kind: NativeKind,
    pub entry: String,
    pub state: ConfigurationState,
    pub owned: bool,
    pub before_sha256: Option<String>,
    pub configuration_sha256: Option<String>,
    pub displaced_preserved: bool,
    pub directory_sync_supported: bool,
}
impl fmt::Debug for AutostartReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutostartReceipt")
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("owned", &self.owned)
            .finish_non_exhaustive()
    }
}
pub struct AutostartChange {
    pub receipt: AutostartReceipt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Invalid,
    IdentityMismatch,
    CommandTooLong,
    Unowned,
    Conflict,
    Busy,
    Unsupported,
    Io,
    RecoveryRequired,
}
#[derive(Debug)]
pub struct AutostartError {
    pub code: ErrorCode,
    pub transaction_id: Option<String>,
}
impl fmt::Display for AutostartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native autostart {:?}; inspect private operation state",
            self.code
        )
    }
}
impl std::error::Error for AutostartError {}
impl From<ErrorCode> for AutostartError {
    fn from(code: ErrorCode) -> Self {
        Self {
            code,
            transaction_id: None,
        }
    }
}
pub type Result<T> = std::result::Result<T, AutostartError>;
fn io(_: impl fmt::Debug) -> AutostartError {
    ErrorCode::Io.into()
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn transaction_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random_id() -> Result<String> {
    let mut b = [0; 16];
    getrandom::fill(&mut b).map_err(io)?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(ErrorCode::Busy.into())
    } else {
        Ok(())
    }
}
fn operation_transaction_id(operation_id: &str) -> Result<String> {
    if !valid_id(operation_id) {
        return Err(ErrorCode::Invalid.into());
    }
    Ok(
        digest(format!("asg.native-registration-operation/v1\0{operation_id}").as_bytes())[..32]
            .into(),
    )
}
fn root_token(path: &Path) -> Result<String> {
    ordinary(path, false)?;
    agent_session_grep_adapters_sqlite::managed_locks::RootIdentity::read(path)
        .map(|root| root.control_id().as_str().into())
        .map_err(io)
}
pub(crate) fn registration_prefix(registration: &SupervisorRegistration) -> Result<&Path> {
    let path = &registration.supervisor;
    ordinary(path, false)?;
    let basename = if cfg!(windows) {
        "asg-supervisor.exe"
    } else {
        "asg-supervisor"
    };
    let version = path.parent().ok_or(ErrorCode::Invalid)?;
    let versions = version.parent().ok_or(ErrorCode::Invalid)?;
    let leaf = version
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ErrorCode::Invalid)?;
    if path.file_name().is_none_or(|name| name != basename)
        || versions.file_name().is_none_or(|name| name != "versions")
        || leaf.is_empty()
        || leaf.len() > 64
        || !leaf
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        || path.as_os_str().len() > 4096
        || registration.catalog.as_os_str().len() > 4096
    {
        return Err(ErrorCode::Invalid.into());
    }
    versions.parent().ok_or_else(|| ErrorCode::Invalid.into())
}
fn registration_pair(
    original: &SupervisorRegistration,
    target: &SupervisorRegistration,
) -> Result<(String, String)> {
    let old_prefix = registration_prefix(original)?;
    let next_prefix = registration_prefix(target)?;
    let prefix = root_token(old_prefix)?;
    if root_token(next_prefix)? != prefix
        || fs::canonicalize(old_prefix).map_err(io)? != fs::canonicalize(next_prefix).map_err(io)?
        || original.catalog != target.catalog
    {
        return Err(ErrorCode::IdentityMismatch.into());
    }
    let root = original.catalog.parent().ok_or(ErrorCode::Invalid)?;
    Ok((prefix, root_token(root)?))
}
fn verify_operation_roots(proof: &RegistrationOperationProof, journal_root: &Path) -> Result<()> {
    let (prefix, catalog) = registration_pair(&proof.original, &proof.target)?;
    if proof.schema != "asg.native-registration-operation/v1"
        || prefix != proof.prefix_identity
        || catalog != proof.catalog_root_identity
        || root_token(journal_root)? != proof.journal_root_identity
    {
        return Err(ErrorCode::Conflict.into());
    }
    Ok(())
}

fn valid_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || path
            .to_str()
            .is_none_or(|s| s.chars().any(char::is_control))
    {
        return Err(ErrorCode::Invalid.into());
    }
    Ok(())
}
fn ordinary(path: &Path, missing: bool) -> Result<()> {
    valid_path(path)?;
    for part in path.ancestors() {
        match fs::symlink_metadata(part) {
            Ok(m) if linked(&m) => return Err(ErrorCode::Conflict.into()),
            Ok(_) => {}
            Err(e) if missing && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(())
}
fn linked(m: &fs::Metadata) -> bool {
    if m.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}
fn entry(location: &NativeLocation, installation: &str) -> String {
    let key = &digest(installation.as_bytes())[..16];
    match location.kind() {
        NativeKind::WindowsRun => format!("AgentSessionGrep.{key}"),
        NativeKind::LaunchAgent => format!("com.agentsessions.agent-session-grep.{key}"),
        NativeKind::SystemdUser => format!("agent-session-grep-{key}.service"),
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    kind: u32,
    bytes: Vec<u8>,
}
impl Image {
    fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.kind.to_le_bytes());
        hasher.update(&self.bytes);
        format!("{:x}", hasher.finalize())
    }
}
fn image_hash(image: &Option<Image>) -> Option<String> {
    image.as_ref().map(Image::hash)
}
fn quote_windows(value: &str) -> String {
    let mut output = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        let count = if ch == '"' { 2 * slashes + 1 } else { slashes };
        output.extend(std::iter::repeat_n('\\', count));
        output.push(ch);
        slashes = 0;
    }
    output.extend(std::iter::repeat_n('\\', 2 * slashes));
    output.push('"');
    output
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn systemd_arg(value: &str) -> String {
    let mut result = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '%' => result.push_str("%%"),
            '$' => result.push_str("$$"),
            _ => result.push(ch),
        }
    }
    result.push('"');
    result
}
fn render(
    location: &NativeLocation,
    name: &str,
    registration: &SupervisorRegistration,
) -> Result<Image> {
    valid_path(&registration.supervisor)?;
    valid_path(&registration.catalog)?;
    let supervisor = registration.supervisor.to_str().ok_or(ErrorCode::Invalid)?;
    let catalog = registration.catalog.to_str().ok_or(ErrorCode::Invalid)?;
    let args = [supervisor, "--db", catalog];
    let text = match location.kind() {
        NativeKind::WindowsRun => {
            let command = args.map(quote_windows).join(" ");
            if command.encode_utf16().count() > 260 {
                return Err(ErrorCode::CommandTooLong.into());
            }
            return Ok(Image {
                kind: 1,
                bytes: command
                    .encode_utf16()
                    .chain(Some(0))
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            });
        }
        NativeKind::LaunchAgent => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array>{}</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n",
            xml(name),
            args.map(|s| format!("<string>{}</string>", xml(s)))
                .join("")
        ),
        NativeKind::SystemdUser => format!(
            "[Unit]\nDescription=agent-session-grep user supervisor\n\n[Service]\nType=simple\nExecStart={}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
            args.map(systemd_arg).join(" ")
        ),
    };
    Ok(Image {
        kind: 0,
        bytes: text.into_bytes(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Applied,
    Verified,
    Conflict,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryInfo {
    pub transaction_id: String,
    pub phase: Phase,
    pub retained_artifact_changed: bool,
}
/// Private, bounded operation proof. Never project these locators to public output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationOperationProof {
    pub schema: String,
    pub operation_id: String,
    pub restoring: bool,
    pub original: SupervisorRegistration,
    pub target: SupervisorRegistration,
    pub prior: AutostartReceipt,
    pub prefix_identity: String,
    pub catalog_root_identity: String,
    pub journal_root_identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    id: String,
    installation: String,
    location: NativeLocation,
    entry: String,
    seq: u32,
    phase: Phase,
    before: Option<Image>,
    desired: Option<Image>,
    owned: bool,
    previous: Option<String>,
    before_identity: Option<(u64, u64)>,
    staging_identity: Option<(u64, u64)>,
    registry_proof_before: Option<Image>,
    retained: BTreeMap<String, String>,
    receipt: Option<AutostartReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation: Option<RegistrationOperationProof>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Owner {
    schema: String,
    installation: String,
    location: NativeLocation,
    entry: String,
}

struct OwnedOperation<'a> {
    operation_id: &'a str,
    original: &'a SupervisorRegistration,
    target: &'a SupervisorRegistration,
    prior: &'a AutostartReceipt,
    restoring: bool,
    deadline: Instant,
}

/// Dedicated same-volume private journal root. `open` does not create files.
/// File locations require this root directly below their configuration directory.
pub struct NativeAutostartStore {
    location: NativeLocation,
    root: PathBuf,
    installation: String,
    entry: String,
}
impl NativeAutostartStore {
    pub fn open(
        location: NativeLocation,
        private_journal_root: &Path,
        installation_id: &str,
    ) -> Result<Self> {
        if !valid_id(installation_id) {
            return Err(ErrorCode::Invalid.into());
        }
        ordinary(private_journal_root, true)?;
        match &location {
            NativeLocation::WindowsRun { subkey } => {
                if subkey.is_empty()
                    || subkey.len() > 1024
                    || subkey
                        .split('\\')
                        .any(|s| s.is_empty() || s == "." || s == "..")
                    || subkey.chars().any(|c| c.is_control() || c == '/')
                {
                    return Err(ErrorCode::Invalid.into());
                }
                #[cfg(not(windows))]
                return Err(ErrorCode::Unsupported.into());
            }
            NativeLocation::LaunchAgent { directory, .. }
            | NativeLocation::SystemdUser { directory } => {
                ordinary(directory, true)?;
                if private_journal_root.parent() != Some(directory.as_path()) {
                    return Err(ErrorCode::Invalid.into());
                }
            }
        }
        Ok(Self {
            entry: entry(&location, installation_id),
            location,
            root: private_journal_root.into(),
            installation: installation_id.into(),
        })
    }
    /// Pure default location helper. The caller persists the private root with
    /// its installation receipt; no search of unrelated installations occurs.
    pub fn entry_name(&self) -> &str {
        &self.entry
    }
    pub fn journal_root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn location(&self) -> &NativeLocation {
        &self.location
    }
    fn owner(&self) -> Owner {
        Owner {
            schema: "asg.native-autostart-owner/v1".into(),
            installation: self.installation.clone(),
            location: self.location.clone(),
            entry: self.entry.clone(),
        }
    }
    fn target(&self) -> Option<PathBuf> {
        self.location.directory().map(|d| {
            d.join(if self.location.kind() == NativeKind::LaunchAgent {
                format!("{}.plist", self.entry)
            } else {
                self.entry.clone()
            })
        })
    }
    fn verify_owner(&self) -> Result<()> {
        ordinary(&self.root, false)?;
        platform::validate_private(&self.root).map_err(io)?;
        let owner: Owner = serde_json::from_slice(&read(&self.root.join("owner.json"), 16384)?)
            .map_err(|_| AutostartError::from(ErrorCode::RecoveryRequired))?;
        if owner != self.owner() {
            return Err(ErrorCode::Unowned.into());
        }
        Ok(())
    }
    fn lock(&self, create: bool) -> Result<File> {
        if !self.root.exists() {
            if !create {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            ensure_directory(self.root.parent().ok_or(ErrorCode::Invalid)?)?;
            match platform::create_private_directory(&self.root) {
                Ok(true) => write_new(
                    &self.root.join("owner.json"),
                    &serde_json::to_vec(&self.owner()).map_err(io)?,
                )?,
                Ok(false) => {}
                Err(e) => return Err(io(e)),
            }
        }
        self.verify_owner()?;
        let path = self.root.join("owner.lock");
        ordinary(&path, true)?;
        let file = if create {
            platform::lock_file(&path)
        } else {
            platform::open_file(&path)
        }
        .map_err(io)?;
        let locking = if create {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        locking.map_err(|e| match e {
            fs::TryLockError::WouldBlock => AutostartError::from(ErrorCode::Busy),
            fs::TryLockError::Error(e) => io(e),
        })?;
        self.verify_owner()?;
        Ok(file)
    }
    pub fn enable(
        &self,
        registration: &SupervisorRegistration,
        prior: Option<&AutostartReceipt>,
    ) -> Result<AutostartChange> {
        let desired = render(&self.location, &self.entry, registration)?;
        let _supervisor = verify_supervisor(registration)?;
        self.change(Some(desired), prior, &mut |_| Ok(()))
    }
    /// Replace only the exact still-owned current registration. The caller pins
    /// old/new hashes from immutable package records before its pointer switch.
    /// Repeating the operation ID resumes its journal, including lost success ACKs.
    pub fn replace_owned(
        &self,
        operation_id: &str,
        original: &SupervisorRegistration,
        target: &SupervisorRegistration,
        prior: &AutostartReceipt,
        deadline: Instant,
    ) -> Result<AutostartChange> {
        self.replace_owned_with(
            OwnedOperation {
                operation_id,
                original,
                target,
                prior,
                restoring: false,
                deadline,
            },
            &mut |_| Ok(()),
        )
    }

    /// Restore the preimage of an owned replacement as another durable operation.
    /// Use a distinct stable ID such as "<update-id>-rollback"; retries return the
    /// same restoration receipt. A consumed or edited replacement cannot restore.
    pub fn restore_owned(
        &self,
        operation_id: &str,
        original: &SupervisorRegistration,
        replacement: &AutostartReceipt,
        deadline: Instant,
    ) -> Result<AutostartChange> {
        self.verify_owner()?;
        let old = {
            let _lock = self.lock(false)?;
            self.load(&replacement.transaction_id)?
        };
        let proof = old.operation.ok_or(ErrorCode::Unowned)?;
        if proof.restoring
            || &proof.original != original
            || old.receipt.as_ref() != Some(replacement)
        {
            return Err(ErrorCode::Unowned.into());
        }
        self.replace_owned_with(
            OwnedOperation {
                operation_id,
                original: &proof.target,
                target: original,
                prior: replacement,
                restoring: true,
                deadline,
            },
            &mut |_| Ok(()),
        )
    }

    pub fn operation_proof(&self, operation_id: &str) -> Result<RegistrationOperationProof> {
        let id = operation_transaction_id(operation_id)?;
        let _lock = self.lock(false)?;
        let proof = self
            .load(&id)?
            .operation
            .ok_or(ErrorCode::RecoveryRequired)?;
        if proof.operation_id != operation_id
            || operation_transaction_id(&proof.operation_id)? != id
            || serde_json::to_vec(&proof).map_err(io)?.len() > 65536
        {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        verify_operation_roots(&proof, &self.root)?;
        Ok(proof)
    }

    /// Read the verified result of this exact operation without granting current
    /// authority. A later restoration may supersede it; mutation APIs still
    /// require an unchanged live head and validate the whole ownership chain.
    pub fn operation_receipt(&self, operation_id: &str) -> Result<AutostartReceipt> {
        let id = operation_transaction_id(operation_id)?;
        let _lock = self.lock(false)?;
        let journal = self.load(&id)?;
        let proof = journal
            .operation
            .as_ref()
            .ok_or(ErrorCode::RecoveryRequired)?;
        verify_operation_roots(proof, &self.root)?;
        if proof.operation_id != operation_id
            || journal.phase != Phase::Verified
            || !journal.owned
            || self.artifacts_changed(&journal)?
        {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let receipt = journal
            .receipt
            .as_ref()
            .ok_or(ErrorCode::RecoveryRequired)?;
        if receipt.schema != "asg.native-autostart-receipt/v1"
            || receipt.transaction_id != id
            || receipt.installation_id != self.installation
            || receipt.kind != self.location.kind()
            || receipt.entry != self.entry
            || !receipt.owned
            || receipt.configuration_sha256 != image_hash(&journal.desired)
            || receipt.before_sha256 != image_hash(&journal.before)
            || (receipt.state == ConfigurationState::Present) != journal.desired.is_some()
            || journal.previous.as_deref() != Some(&proof.prior.transaction_id)
            || journal.before.as_ref()
                != Some(&render(&self.location, &self.entry, &proof.original)?)
            || journal.desired.as_ref()
                != Some(&render(&self.location, &self.entry, &proof.target)?)
        {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let _old = verify_supervisor(&proof.original)?;
        let _next = verify_supervisor(&proof.target)?;
        Ok(receipt.clone())
    }

    fn replace_owned_with(
        &self,
        request: OwnedOperation<'_>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<AutostartChange> {
        let OwnedOperation {
            operation_id,
            original,
            target,
            prior,
            restoring,
            deadline,
        } = request;
        let id = operation_transaction_id(operation_id)?;
        if !prior.owned
            || prior.state != ConfigurationState::Present
            || prior.installation_id != self.installation
            || prior.kind != self.location.kind()
            || prior.entry != self.entry
        {
            return Err(ErrorCode::Unowned.into());
        }
        check_deadline(deadline)?;
        self.verify_owner()?;
        let _old = verify_supervisor_before(original, Some(deadline))?;
        let _next = verify_supervisor_before(target, Some(deadline))?;
        let (prefix_identity, catalog_root_identity) = registration_pair(original, target)?;
        let _lock = self.lock(true)?;
        let proof = RegistrationOperationProof {
            schema: "asg.native-registration-operation/v1".into(),
            operation_id: operation_id.into(),
            restoring,
            original: original.clone(),
            target: target.clone(),
            prior: prior.clone(),
            prefix_identity,
            catalog_root_identity,
            journal_root_identity: root_token(&self.root)?,
        };
        if serde_json::to_vec(&proof).map_err(io)?.len() > 65536 {
            return Err(ErrorCode::Invalid.into());
        }
        let desired = render(&self.location, &self.entry, target)?;
        let before = render(&self.location, &self.entry, original)?;
        let infos = self.inspect_locked()?;
        let ancestor = self.load(&prior.transaction_id)?;
        if ancestor.receipt.as_ref() != Some(prior)
            || ancestor.desired.as_ref() != Some(&before)
            || !ancestor.owned
            || ancestor.phase != Phase::Verified
        {
            return Err(ErrorCode::Unowned.into());
        }
        for info in &infos {
            let journal = self.load(&info.transaction_id)?;
            if info.transaction_id != id
                && (info.phase != Phase::Verified || info.retained_artifact_changed)
            {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            if journal.previous.as_deref() == Some(&prior.transaction_id)
                && info.transaction_id != id
            {
                return Err(ErrorCode::Conflict.into());
            }
        }
        let mut bounded = |point| {
            check_deadline(deadline)?;
            verify_operation_roots(&proof, &self.root)?;
            hook(point)
        };
        if infos.iter().any(|info| info.transaction_id == id) {
            let journal = self.load(&id)?;
            if journal.operation.as_ref() != Some(&proof)
                || journal.desired.as_ref() != Some(&desired)
                || journal.before.as_ref() != Some(&before)
                || journal.previous.as_deref() != Some(&prior.transaction_id)
            {
                return Err(ErrorCode::Conflict.into());
            }
            let result = self.recover_locked(&id, &mut bounded)?;
            if self.latest_receipt_locked()?.as_ref() != Some(&result.receipt) {
                return Err(ErrorCode::Conflict.into());
            }
            Ok(result)
        } else {
            if self.latest_receipt_locked()?.as_ref() != Some(prior) {
                return Err(ErrorCode::Conflict.into());
            }
            bounded(TestPoint::Prepared)?;
            self.change_locked(
                Some(desired),
                Some(prior),
                id,
                Some(proof.clone()),
                &mut |point| {
                    check_deadline(deadline)?;
                    verify_operation_roots(&proof, &self.root)?;
                    hook(point)
                },
            )
        }
    }

    pub fn disable(&self, receipt: &AutostartReceipt) -> Result<AutostartChange> {
        if !receipt.owned {
            return Err(ErrorCode::Unowned.into());
        }
        self.change(None, Some(receipt), &mut |_| Ok(()))
    }
    pub fn inspect_recovery(&self) -> Result<Vec<RecoveryInfo>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let _lock = self.lock(false)?;
        self.inspect_locked()
    }
    /// Read only the unique verified ownership chain's current leaf. Never
    /// chooses by timestamp or silently repairs an interrupted transaction.
    /// Returns an unowned receipt for an identical preexisting registration.
    pub fn latest_receipt(&self) -> Result<Option<AutostartReceipt>> {
        if !self.root.exists() {
            return Ok(None);
        }
        let _lock = self.lock(false)?;
        self.latest_receipt_locked()
    }
    fn latest_receipt_locked(&self) -> Result<Option<AutostartReceipt>> {
        let infos = self.inspect_locked()?;
        if infos.is_empty() {
            return Ok(None);
        }
        let mut journals = BTreeMap::new();
        let mut parents = BTreeSet::new();
        for info in infos {
            if info.phase != Phase::Verified || info.retained_artifact_changed {
                return Err(AutostartError {
                    code: ErrorCode::RecoveryRequired,
                    transaction_id: Some(info.transaction_id),
                });
            }
            let journal = self.load(&info.transaction_id)?;
            let receipt = journal
                .receipt
                .as_ref()
                .ok_or(ErrorCode::RecoveryRequired)?;
            if receipt.schema != "asg.native-autostart-receipt/v1"
                || receipt.transaction_id != journal.id
                || receipt.installation_id != self.installation
                || receipt.kind != self.location.kind()
                || receipt.entry != self.entry
                || receipt.configuration_sha256 != image_hash(&journal.desired)
                || receipt.before_sha256 != image_hash(&journal.before)
                || receipt.owned != journal.owned
                || (receipt.state == ConfigurationState::Present) != journal.desired.is_some()
            {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            if let Some(parent) = &journal.previous {
                parents.insert(parent.clone());
            }
            journals.insert(journal.id.clone(), journal);
        }
        if parents.iter().any(|parent| !journals.contains_key(parent)) {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let leaves: Vec<_> = journals
            .keys()
            .filter(|id| !parents.contains(*id))
            .cloned()
            .collect();
        if leaves.len() != 1 {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let mut visited = BTreeSet::new();
        let mut cursor = Some(leaves[0].clone());
        while let Some(id) = cursor {
            if !visited.insert(id.clone()) {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            cursor = journals
                .get(&id)
                .ok_or(ErrorCode::RecoveryRequired)?
                .previous
                .clone();
        }
        if visited.len() != journals.len() {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let receipt = journals
            .remove(&leaves[0])
            .and_then(|j| j.receipt)
            .ok_or(ErrorCode::RecoveryRequired)?;
        if self.observed()?.as_ref().map(Image::hash) != receipt.configuration_sha256 {
            return Err(AutostartError {
                code: ErrorCode::Conflict,
                transaction_id: Some(receipt.transaction_id),
            });
        }
        Ok(Some(receipt))
    }
    /// Serialize manager reconciliation with ASG configuration transactions.
    /// The guard also pins the expected executable; external config changes
    /// are detected before and after each native command.
    pub(crate) fn manager_registration<'a>(
        &'a self,
        receipt: &AutostartReceipt,
        registration: &'a SupervisorRegistration,
    ) -> Result<ManagerRegistration<'a>> {
        self.manager_registration_before(receipt, registration, None)
    }
    pub(crate) fn manager_registration_before<'a>(
        &'a self,
        receipt: &AutostartReceipt,
        registration: &'a SupervisorRegistration,
        deadline: Option<Instant>,
    ) -> Result<ManagerRegistration<'a>> {
        self.verify_owner()?;
        let lock = self.lock(true)?;
        let supervisor = verify_supervisor_before(registration, deadline)?;
        let guard = ManagerRegistration {
            store: self,
            receipt: receipt.clone(),
            registration,
            _directories: DirectoryPins::new(self)?,
            _lock: lock,
            _supervisor: supervisor,
            deadline,
        };
        guard.validate()?;
        Ok(guard)
    }
    fn inspect_locked(&self) -> Result<Vec<RecoveryInfo>> {
        let mut result = Vec::new();
        for e in fs::read_dir(&self.root).map_err(io)? {
            let e = e.map_err(io)?;
            let name = e
                .file_name()
                .into_string()
                .map_err(|_| AutostartError::from(ErrorCode::RecoveryRequired))?;
            if name == "owner.json" || name == "owner.lock" {
                continue;
            }
            if !transaction_id(&name) || result.len() >= MAX_TRANSACTIONS {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            let journal = self.load(&name)?;
            result.push(RecoveryInfo {
                transaction_id: name,
                phase: journal.phase,
                retained_artifact_changed: self.artifacts_changed(&journal)?,
            });
        }
        Ok(result)
    }
    fn save(&self, journal: &mut Journal) -> Result<()> {
        let directory = self.root.join(&journal.id);
        ordinary(&directory, false)?;
        let value = serde_json::to_vec(journal).map_err(io)?;
        write_new(
            &directory.join(format!("state-{:04}.json", journal.seq)),
            &value,
        )?;
        journal.seq += 1;
        Ok(())
    }
    fn load(&self, id: &str) -> Result<Journal> {
        if !transaction_id(id) {
            return Err(ErrorCode::Invalid.into());
        }
        let directory = self.root.join(id);
        ordinary(&directory, false)?;
        platform::validate_private(&directory).map_err(io)?;
        let mut states = BTreeMap::new();
        for e in fs::read_dir(&directory).map_err(io)? {
            let e = e.map_err(io)?;
            let name = e.file_name();
            let name = name.to_str().ok_or(ErrorCode::RecoveryRequired)?;
            if let Some(seq) = name
                .strip_prefix("state-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if seq.len() != 4 {
                    return Err(ErrorCode::RecoveryRequired.into());
                }
                states.insert(seq.parse::<u32>().map_err(io)?, e.path());
            }
        }
        let (&seq, path) = states.last_key_value().ok_or(ErrorCode::RecoveryRequired)?;
        if states.len() > 32 || states.keys().copied().ne(0..=seq) {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let mut j: Journal = serde_json::from_slice(&read(path, MAX_JOURNAL)?)
            .map_err(|_| AutostartError::from(ErrorCode::RecoveryRequired))?;
        if j.schema != "asg.native-autostart-journal/v1"
            || j.id != id
            || j.seq != seq
            || j.installation != self.installation
            || j.location != self.location
            || j.entry != self.entry
        {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        j.seq += 1;
        Ok(j)
    }
    fn artifacts_changed(&self, j: &Journal) -> Result<bool> {
        for (name, sha) in &j.retained {
            if !matches!(name.as_str(), "displaced.bin" | "staged.bin") {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            if digest(&read(&self.root.join(&j.id).join(name), MAX_IMAGE)?) != *sha {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn observed(&self) -> Result<Option<Image>> {
        match &self.location {
            NativeLocation::WindowsRun { subkey } => registry::read(subkey, &self.entry),
            _ => file_image(&self.target().ok_or(ErrorCode::Invalid)?),
        }
    }
    fn change(
        &self,
        desired: Option<Image>,
        prior: Option<&AutostartReceipt>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<AutostartChange> {
        let _lock = self.lock(true)?;
        self.change_locked(desired, prior, random_id()?, None, hook)
    }
    fn change_locked(
        &self,
        desired: Option<Image>,
        prior: Option<&AutostartReceipt>,
        id: String,
        operation: Option<RegistrationOperationProof>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<AutostartChange> {
        let pins = DirectoryPins::new(self)?;
        let infos = self.inspect_locked()?;
        if infos
            .iter()
            .any(|i| i.phase != Phase::Verified || i.retained_artifact_changed)
        {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        let before = self.observed()?;
        let mut owned = before.is_none();
        let mut prior_changed = false;
        if let Some(prior) = prior {
            let j = self.load(&prior.transaction_id)?;
            if j.receipt.as_ref() != Some(prior)
                || j.phase != Phase::Verified
                || prior.installation_id != self.installation
            {
                return Err(ErrorCode::Unowned.into());
            }
            prior_changed = image_hash(&before) != prior.configuration_sha256;
            owned = prior.owned;
            // A prior receipt remains useful for history, but cannot authorize
            // another mutation after a later operation consumed it.
            for info in &infos {
                if self.load(&info.transaction_id)?.previous.as_deref()
                    == Some(&prior.transaction_id)
                {
                    return Err(ErrorCode::Conflict.into());
                }
            }
        }
        if before.is_some() && before != desired && (prior.is_none() || !owned) {
            return Err(ErrorCode::Unowned.into());
        }
        if desired.is_none() && !owned {
            return Err(ErrorCode::Unowned.into());
        }
        platform::create_private_directory(&self.root.join(&id)).map_err(io)?;
        let mut journal = Journal {
            schema: "asg.native-autostart-journal/v1".into(),
            id,
            installation: self.installation.clone(),
            location: self.location.clone(),
            entry: self.entry.clone(),
            seq: 0,
            phase: Phase::Prepared,
            before,
            desired,
            owned,
            previous: prior.map(|r| r.transaction_id.clone()),
            before_identity: match self.target() {
                Some(path) if before_file_exists(&path)? => Some(file_identity(&path)?),
                _ => None,
            },
            staging_identity: None,
            registry_proof_before: match &self.location {
                NativeLocation::WindowsRun { subkey } => {
                    registry::commit_proof(subkey, &self.entry)?
                }
                _ => None,
            },
            retained: BTreeMap::new(),
            receipt: None,
            operation,
        };
        self.save(&mut journal)?;
        let result: Result<AutostartChange> = (|| {
            if prior_changed {
                return Err(ErrorCode::Conflict.into());
            }
            hook(TestPoint::Prepared)?;
            pins.check()?;
            if journal.before != journal.desired {
                match &self.location {
                    NativeLocation::WindowsRun { subkey } => registry::change(
                        subkey,
                        &self.entry,
                        &journal.before,
                        &journal.desired,
                        &journal.id,
                        &journal.registry_proof_before,
                        hook,
                    )?,
                    _ => self.apply_file(&mut journal, hook)?,
                }
                journal.phase = Phase::Applied;
                self.save(&mut journal)?;
            }
            hook(TestPoint::Applied)?;
            pins.check()?;
            let change = self.finish(&mut journal)?;
            hook(TestPoint::Verified)?;
            Ok(change)
        })();
        match result {
            Ok(value) => Ok(value),
            Err(mut e) => {
                e.transaction_id = Some(journal.id.clone());
                if e.code != ErrorCode::RecoveryRequired {
                    if matches!(e.code, ErrorCode::Conflict | ErrorCode::Unowned) {
                        journal.phase = Phase::Conflict;
                    }
                    if self
                        .preserve_current(&journal)
                        .and_then(|_| self.save(&mut journal))
                        .is_err()
                    {
                        e.code = ErrorCode::RecoveryRequired;
                    }
                }
                Err(e)
            }
        }
    }
    fn preserve_current(&self, j: &Journal) -> Result<()> {
        if let Some(current) = self.observed()? {
            let bytes = serde_json::to_vec(&current).map_err(io)?;
            let p = self
                .root
                .join(&j.id)
                .join(format!("observed-{}.json", digest(&bytes)));
            if !p.exists() {
                write_new(&p, &bytes)?;
            }
        }
        Ok(())
    }
    fn finish(&self, j: &mut Journal) -> Result<AutostartChange> {
        if self.observed()? != j.desired || self.artifacts_changed(j)? {
            return Err(ErrorCode::Conflict.into());
        }
        let receipt = AutostartReceipt {
            schema: "asg.native-autostart-receipt/v1".into(),
            installation_id: self.installation.clone(),
            transaction_id: j.id.clone(),
            kind: self.location.kind(),
            entry: self.entry.clone(),
            state: if j.desired.is_some() {
                ConfigurationState::Present
            } else {
                ConfigurationState::Absent
            },
            owned: j.owned,
            before_sha256: image_hash(&j.before),
            configuration_sha256: image_hash(&j.desired),
            displaced_preserved: !j.retained.is_empty()
                || self.location.kind() == NativeKind::WindowsRun,
            directory_sync_supported: cfg!(unix),
        };
        j.phase = Phase::Verified;
        j.receipt = Some(receipt.clone());
        self.save(j)?;
        Ok(AutostartChange { receipt })
    }
    /// Explicit setup/repair may reconcile interrupted owned configuration.
    /// Terminal conflicts and retained-artifact changes never authorize repair.
    pub(crate) fn recover_pending(&self, deadline: Instant) -> Result<usize> {
        let infos = self.inspect_recovery()?;
        let mut recovered = 0;
        for info in infos {
            if Instant::now() >= deadline {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            if info.retained_artifact_changed || info.phase == Phase::Conflict {
                return Err(ErrorCode::Conflict.into());
            }
            if info.phase != Phase::Verified {
                self.recover(&info.transaction_id)?;
                recovered += 1;
            }
        }
        Ok(recovered)
    }
    #[cfg(test)]
    pub(crate) fn preexisting_registration_for_test(&self, registration: &SupervisorRegistration) {
        let image = render(&self.location, &self.entry, registration).unwrap();
        ensure_directory(self.location.directory().unwrap()).unwrap();
        fs::write(self.target().unwrap(), image.bytes).unwrap();
    }
    /// Reconcile only a prepared/applied operation with verifiable live state.
    /// Terminal conflicts preserve all evidence and require an operator decision.
    pub fn recover(&self, id: &str) -> Result<AutostartChange> {
        if !transaction_id(id) {
            return Err(ErrorCode::Invalid.into());
        }
        self.verify_owner()?;
        let _lock = self.lock(true)?;
        self.recover_locked(id, &mut |_| Ok(()))
    }
    fn recover_locked(
        &self,
        id: &str,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<AutostartChange> {
        let pins = DirectoryPins::new(self)?;
        let mut j = self.load(id)?;
        if let Some(proof) = &j.operation {
            verify_operation_roots(proof, &self.root)?;
            let _old = verify_supervisor(&proof.original)?;
            let _next = verify_supervisor(&proof.target)?;
            if operation_transaction_id(&proof.operation_id)? != id {
                return Err(ErrorCode::RecoveryRequired.into());
            }
        }
        hook(TestPoint::Prepared)?;
        if j.phase == Phase::Conflict || self.artifacts_changed(&j)? {
            return Err(ErrorCode::Conflict.into());
        }
        if j.phase == Phase::Verified {
            let r = j.receipt.ok_or(ErrorCode::RecoveryRequired)?;
            if self.observed()?.as_ref().map(Image::hash) != r.configuration_sha256 {
                return Err(ErrorCode::Conflict.into());
            }
            return Ok(AutostartChange { receipt: r });
        }
        self.reconcile_file_artifacts(&mut j)?;
        self.check_displaced(&j)?;
        let live = self.observed()?;
        if live == j.desired && j.before != j.desired {
            // Matching bytes alone do not establish that ASG performed an
            // interrupted mutation: require its atomically published proof.
            let proven = match &self.location {
                NativeLocation::WindowsRun { subkey } => {
                    registry::commit_proof(subkey, &self.entry)?
                        == Some(Image {
                            kind: 3,
                            bytes: j.id.as_bytes().to_vec(),
                        })
                }
                _ if j.desired.is_some() => {
                    self.target().as_deref().map(file_identity).transpose()? == j.staging_identity
                }
                _ => {
                    let displaced = self.root.join(&j.id).join("displaced.bin");
                    before_file_exists(&displaced)?
                        && Some(file_identity(&displaced)?) == j.before_identity
                }
            };
            if !proven {
                return Err(ErrorCode::RecoveryRequired.into());
            }
        } else if live != j.desired {
            if self.observed()? != j.before {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            match &self.location {
                NativeLocation::WindowsRun { subkey } => registry::change(
                    subkey,
                    &self.entry,
                    &j.before,
                    &j.desired,
                    &j.id,
                    &j.registry_proof_before,
                    hook,
                )?,
                _ => self.apply_file(&mut j, hook)?,
            }
        }
        hook(TestPoint::Applied)?;
        pins.check()?;
        let result = self.finish(&mut j)?;
        hook(TestPoint::Verified)?;
        Ok(result)
    }
    fn apply_file(
        &self,
        j: &mut Journal,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<()> {
        let pins = DirectoryPins::new(self)?;
        let target = self.target().ok_or(ErrorCode::Invalid)?;
        ordinary(&target, true)?;
        if file_image(&target)? != j.before {
            return Err(ErrorCode::Conflict.into());
        }
        let directory = self.root.join(&j.id);
        let staging = directory.join("staged.bin");
        let displaced = directory.join("displaced.bin");
        if let Some(desired) = &j.desired {
            if staging.exists() {
                if read(&staging, MAX_IMAGE)? != desired.bytes {
                    return Err(ErrorCode::RecoveryRequired.into());
                }
            } else {
                write_new(&staging, &desired.bytes)?;
            }
            if j.before.is_some() {
                platform::preserve_mode(&target, &staging).map_err(io)?;
            }
            let staged = file_identity(&staging)?;
            if j.staging_identity.is_some_and(|old| old != staged) {
                return Err(ErrorCode::Conflict.into());
            }
            j.staging_identity = Some(staged);
            self.save(j)?;
        }
        hook(TestPoint::NativeReady)?;
        pins.check()?;
        ordinary(&target, true)?;
        let result = match (&j.before, &j.desired) {
            (None, Some(_)) => platform::move_new(&staging, &target),
            (Some(_), Some(_)) => platform::replace(&target, &staging, &displaced),
            (Some(_), None) => platform::move_new(&target, &displaced),
            (None, None) => Ok(()),
        };
        // Record actual artifacts even when a native call reports partial failure.
        self.reconcile_file_artifacts(j)?;
        if let Err(error) = result {
            return Err(if error.kind() == std::io::ErrorKind::Unsupported {
                ErrorCode::Unsupported.into()
            } else {
                io(error)
            });
        }
        platform::sync_directory(target.parent().ok_or(ErrorCode::Invalid)?).map_err(io)?;
        platform::sync_directory(&directory).map_err(io)?;
        pins.check()?;
        hook(TestPoint::NativeApplied)?;
        if j.before.is_some() && j.retained.is_empty() {
            return Err(ErrorCode::RecoveryRequired.into());
        }
        if let Some(before) = &j.before {
            for name in j.retained.keys() {
                if read(&directory.join(name), MAX_IMAGE)? != before.bytes {
                    // Disable may have moved a racing user's replacement. Restore
                    // only into a still-absent live name with no-clobber publish.
                    if j.desired.is_none() && file_image(&target)?.is_none() {
                        let _restored = fs::hard_link(directory.join(name), &target);
                    }
                    return Err(ErrorCode::Conflict.into());
                }
            }
        }
        Ok(())
    }
    fn reconcile_file_artifacts(&self, j: &mut Journal) -> Result<()> {
        if self.location.kind() == NativeKind::WindowsRun {
            return Ok(());
        }
        let directory = self.root.join(&j.id);
        for name in ["displaced.bin", "staged.bin"] {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let bytes = read(&path, MAX_IMAGE)?;
                    // Before exchange staged.bin is the intended candidate. On
                    // Unix exchange it becomes the actual displaced original.
                    if name == "staged.bin"
                        && j.desired.as_ref().is_some_and(|v| v.bytes == bytes)
                        && !j.retained.contains_key(name)
                    {
                        continue;
                    }
                    let hash = digest(&bytes);
                    if j.retained.get(name).is_some_and(|old| old != &hash) {
                        return Err(ErrorCode::Conflict.into());
                    }
                    j.retained.insert(name.into(), hash);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(e)),
            }
        }
        Ok(())
    }
    fn check_displaced(&self, j: &Journal) -> Result<()> {
        if let Some(before) = &j.before {
            for name in j.retained.keys() {
                if read(&self.root.join(&j.id).join(name), MAX_IMAGE)? != before.bytes {
                    return Err(ErrorCode::Conflict.into());
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct ManagerRegistration<'a> {
    store: &'a NativeAutostartStore,
    receipt: AutostartReceipt,
    registration: &'a SupervisorRegistration,
    _directories: DirectoryPins,
    _lock: File,
    _supervisor: File,
    deadline: Option<Instant>,
}
impl ManagerRegistration<'_> {
    pub(crate) fn location(&self) -> &NativeLocation {
        &self.store.location
    }
    pub(crate) fn entry(&self) -> &str {
        &self.store.entry
    }
    pub(crate) fn target(&self) -> Option<PathBuf> {
        self.store.target()
    }
    /// Only a previously verified ASG-owned image can authorize reloading an
    /// older same-label job. Matching the label alone does not prove ownership.
    pub(crate) fn matches_owned_predecessor(
        &self,
        mut matches: impl FnMut(&[u8]) -> bool,
    ) -> Result<bool> {
        self.validate()?;
        let current = self.store.load(&self.receipt.transaction_id)?;
        let mut cursor = current.previous;
        let mut count = 0;
        while let Some(id) = cursor {
            count += 1;
            if count > MAX_TRANSACTIONS {
                return Err(ErrorCode::RecoveryRequired.into());
            }
            let journal = self.store.load(&id)?;
            if !journal.owned || journal.phase != Phase::Verified {
                return Ok(false);
            }
            if let Some(image) = &journal.desired
                && image.kind == 0
                && matches(&image.bytes)
            {
                return Ok(true);
            }
            cursor = journal.previous;
        }
        Ok(false)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self._directories.check()?;
        self.store.verify_owner()?;
        if self.store.latest_receipt_locked()?.as_ref() != Some(&self.receipt)
            || self.receipt.state != ConfigurationState::Present
            || self.receipt.configuration_sha256.as_deref()
                != Some(
                    render(&self.store.location, &self.store.entry, self.registration)?
                        .hash()
                        .as_str(),
                )
        {
            return Err(ErrorCode::Conflict.into());
        }
        verify_supervisor_before(self.registration, self.deadline).map(drop)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TestPoint {
    Prepared,
    NativeReady,
    #[cfg(windows)]
    RegistryReserved,
    #[cfg(windows)]
    RegistryBeforeCommit,
    NativeApplied,
    Applied,
    Verified,
}

struct DirectoryPins(Vec<(PathBuf, File, (u64, u64))>);
impl DirectoryPins {
    fn new(store: &NativeAutostartStore) -> Result<Self> {
        let mut paths = vec![store.root.clone()];
        if let Some(directory) = store.location.directory() {
            paths.push(directory.into());
        }
        let mut values = Vec::new();
        for path in paths {
            ordinary(&path, false)?;
            let file = platform::directory(&path).map_err(io)?;
            let id = platform::identity(&file).map_err(io)?;
            values.push((path, file, id));
        }
        Ok(Self(values))
    }
    fn check(&self) -> Result<()> {
        for (path, _file, id) in &self.0 {
            ordinary(path, false)?;
            let current = platform::directory(path).map_err(io)?;
            if platform::identity(&current).map_err(io)? != *id {
                return Err(ErrorCode::Conflict.into());
            }
        }
        Ok(())
    }
}

fn ensure_directory(path: &Path) -> Result<()> {
    ordinary(path, true)?;
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => return Err(ErrorCode::Conflict.into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    ensure_directory(path.parent().ok_or(ErrorCode::Invalid)?)?;
    platform::create_private_directory(path).map_err(io)?;
    Ok(())
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ordinary(path, false)?;
    let mut f = platform::open_file(path).map_err(io)?;
    if f.metadata().map_err(io)?.len() > limit {
        return Err(ErrorCode::RecoveryRequired.into());
    }
    let mut value = Vec::new();
    (&mut f)
        .take(limit + 1)
        .read_to_end(&mut value)
        .map_err(io)?;
    if value.len() as u64 > limit {
        return Err(ErrorCode::RecoveryRequired.into());
    }
    Ok(value)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    ordinary(path, true)?;
    let parent = path.parent().ok_or(ErrorCode::Invalid)?;
    let pending = parent.join(format!("write-{}.pending", random_id()?));
    let mut file = platform::create_file(&pending).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    fs::hard_link(&pending, path).map_err(io)?;
    fs::remove_file(pending).map_err(io)?;
    platform::sync_directory(parent).map_err(io)?;
    Ok(())
}
fn file_image(path: &Path) -> Result<Option<Image>> {
    ordinary(path, true)?;
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() || linked(&m) => Err(ErrorCode::Conflict.into()),
        Ok(_) => Ok(Some(Image {
            kind: 0,
            bytes: read(path, MAX_IMAGE)?,
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e)),
    }
}
fn before_file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !linked(&meta) => Ok(true),
        Ok(_) => Err(ErrorCode::Conflict.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(error)),
    }
}
fn file_identity(path: &Path) -> Result<(u64, u64)> {
    ordinary(path, false)?;
    platform::identity(&platform::open_file(path).map_err(io)?).map_err(io)
}
pub(crate) fn verify_supervisor(registration: &SupervisorRegistration) -> Result<File> {
    verify_supervisor_before(registration, None)
}
fn verify_supervisor_before(
    registration: &SupervisorRegistration,
    deadline: Option<Instant>,
) -> Result<File> {
    if let Some(end) = deadline {
        check_deadline(end)?;
    }
    ordinary(&registration.supervisor, false)?;
    ordinary(&registration.catalog, false)?;
    drop(platform::open_file(&registration.catalog).map_err(io)?);
    let mut file = platform::pin_supervisor(&registration.supervisor).map_err(io)?;
    if file.metadata().map_err(io)?.len() > 1024 * 1024 * 1024 {
        return Err(ErrorCode::IdentityMismatch.into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        if let Some(end) = deadline {
            check_deadline(end)?;
        }
        let n = file.read(&mut buffer).map_err(io)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if format!("{:x}", hash.finalize()) != registration.supervisor_sha256 {
        return Err(ErrorCode::IdentityMismatch.into());
    }
    Ok(file)
}

#[cfg(windows)]
pub(crate) mod platform {
    use super::*;
    use std::{
        io,
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    fn failure() -> io::Error {
        io::Error::last_os_error()
    }
    fn unsupported() -> io::Error {
        io::ErrorKind::Unsupported.into()
    }
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn descriptor() -> io::Result<Descriptor> {
        let mut token = ptr::null_mut();
        // SAFETY: native token query uses sized aligned buffers; each returned
        // allocation/handle is released after the security descriptor owns it.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(failure());
        }
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        };
        unsafe {
            CloseHandle(token);
        }
        if result == 0 {
            return Err(failure());
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
            return Err(failure());
        }
        let mut len = 0;
        unsafe {
            while *sid.add(len) != 0 {
                len += 1;
            }
        }
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid, len) });
        unsafe {
            LocalFree(sid.cast());
        }
        let sddl: Vec<u16> = format!("O:{value}D:P(A;OICI;FA;;;{value})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut result = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut result,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(failure());
        }
        Ok(Descriptor(result))
    }
    fn acl(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<Vec<u8>> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            == 0
            || present == 0
            || acl.is_null()
        {
            return Err(unsupported());
        }
        Ok(
            unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize) }
                .to_vec(),
        )
    }
    pub(crate) fn create_private_directory(path: &Path) -> io::Result<bool> {
        let descriptor = descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let created = unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } != 0;
        if !created && failure().kind() != io::ErrorKind::AlreadyExists {
            return Err(failure());
        }
        validate_private(path)?;
        Ok(created)
    }
    pub(crate) fn validate_private(path: &Path) -> io::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || linked(&meta) {
            return Err(unsupported());
        }
        let expected = descriptor()?;
        let mut raw = ptr::null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut raw,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let actual = Descriptor(raw);
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(actual.0, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
            || acl(actual.0)? != acl(expected.0)?
        {
            return Err(unsupported());
        }
        let mut owner = ptr::null_mut();
        let mut expected_owner = ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(actual.0, &mut owner, &mut defaulted) } == 0
            || unsafe {
                GetSecurityDescriptorOwner(expected.0, &mut expected_owner, &mut defaulted)
            } == 0
            || unsafe { EqualSid(owner, expected_owner) } == 0
        {
            return Err(unsupported());
        }
        Ok(())
    }
    pub(crate) fn open_file(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let m = f.metadata()?;
        if !m.is_file() || linked(&m) {
            return Err(unsupported());
        }
        Ok(f)
    }
    pub(super) fn pin_supervisor(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if !f.metadata()?.is_file() || linked(&f.metadata()?) {
            return Err(unsupported());
        }
        Ok(f)
    }
    pub(crate) fn create_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    pub(super) fn lock_file(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if !f.metadata()?.is_file() || linked(&f.metadata()?) {
            return Err(unsupported());
        }
        Ok(f)
    }
    pub(crate) fn directory(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        if !f.metadata()?.is_dir() || linked(&f.metadata()?) {
            return Err(unsupported());
        }
        Ok(f)
    }
    pub(crate) fn identity(file: &File) -> io::Result<(u64, u64)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(failure());
        }
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    pub(super) fn preserve_mode(_: &Path, _: &Path) -> io::Result<()> {
        Ok(())
    } // ReplaceFileW retains target security.
    pub(crate) fn sync_directory(_: &Path) -> io::Result<()> {
        Ok(())
    } // No general unprivileged directory fsync.
    pub(crate) fn move_new(from: &Path, to: &Path) -> io::Result<()> {
        if unsafe {
            MoveFileExW(
                wide(from).as_ptr(),
                wide(to).as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            Err(failure())
        } else {
            Ok(())
        }
    }
    pub(crate) fn replace(target: &Path, staging: &Path, displaced: &Path) -> io::Result<()> {
        if unsafe {
            ReplaceFileW(
                wide(target).as_ptr(),
                wide(staging).as_ptr(),
                wide(displaced).as_ptr(),
                0,
                ptr::null(),
                ptr::null(),
            )
        } == 0
        {
            Err(failure())
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(crate) mod platform {
    use super::*;
    use std::{
        ffi::CString,
        io,
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            io::AsRawFd,
        },
    };
    fn unsupported() -> io::Error {
        io::ErrorKind::Unsupported.into()
    }
    pub(crate) fn create_private_directory(path: &Path) -> io::Result<bool> {
        let created = match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e),
        };
        validate_private(path)?;
        Ok(created)
    }
    pub(crate) fn validate_private(path: &Path) -> io::Result<()> {
        let m = fs::symlink_metadata(path)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err(unsupported());
        }
        Ok(())
    }
    pub(crate) fn open_file(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } {
            return Err(unsupported());
        }
        Ok(f)
    }
    pub(super) fn pin_supervisor(path: &Path) -> io::Result<File> {
        let file = open_file(path)?;
        let mode = file.metadata()?.mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(unsupported());
        }
        Ok(file)
    }
    pub(crate) fn create_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    pub(super) fn lock_file(path: &Path) -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        if !f.metadata()?.is_file() {
            return Err(unsupported());
        }
        Ok(f)
    }
    pub(crate) fn directory(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }
    pub(crate) fn identity(file: &File) -> io::Result<(u64, u64)> {
        let m = file.metadata()?;
        Ok((m.dev(), m.ino()))
    }
    pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
        directory(path)?.sync_all()
    }
    pub(super) fn preserve_mode(target: &Path, staging: &Path) -> io::Result<()> {
        let file = open_file(target)?;
        let meta = file.metadata()?;
        #[cfg(target_os = "linux")]
        let attrs = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
        #[cfg(target_os = "macos")]
        let attrs = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let attrs = -1;
        if attrs != 0 {
            return Err(unsupported());
        }
        fs::set_permissions(staging, fs::Permissions::from_mode(meta.mode() & 0o777))?;
        open_file(staging)?.sync_all()
    }
    fn rename(from: &Path, to: &Path, exchange: bool) -> io::Result<()> {
        let source = directory(from.parent().ok_or_else(unsupported)?)?;
        let dest = directory(to.parent().ok_or_else(unsupported)?)?;
        let a = CString::new(from.file_name().ok_or_else(unsupported)?.as_bytes())
            .map_err(|_| unsupported())?;
        let b = CString::new(to.file_name().ok_or_else(unsupported)?.as_bytes())
            .map_err(|_| unsupported())?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source.as_raw_fd(),
                a.as_ptr(),
                dest.as_raw_fd(),
                b.as_ptr(),
                if exchange {
                    libc::RENAME_EXCHANGE
                } else {
                    libc::RENAME_NOREPLACE
                },
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                source.as_raw_fd(),
                a.as_ptr(),
                dest.as_raw_fd(),
                b.as_ptr(),
                if exchange {
                    libc::RENAME_SWAP
                } else {
                    libc::RENAME_EXCL
                },
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = -1;
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(crate) fn move_new(from: &Path, to: &Path) -> io::Result<()> {
        rename(from, to, false)
    }
    pub(crate) fn replace(target: &Path, staging: &Path, _displaced: &Path) -> io::Result<()> {
        rename(target, staging, true)
    }
}

#[cfg(not(windows))]
mod registry {
    use super::*;
    pub(super) fn read(_: &str, _: &str) -> Result<Option<Image>> {
        Err(ErrorCode::Unsupported.into())
    }
    pub(super) fn commit_proof(_: &str, _: &str) -> Result<Option<Image>> {
        Err(ErrorCode::Unsupported.into())
    }
    pub(super) fn change(
        _: &str,
        _: &str,
        _: &Option<Image>,
        _: &Option<Image>,
        _: &str,
        _: &Option<Image>,
        _: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<()> {
        Err(ErrorCode::Unsupported.into())
    }
}

#[cfg(windows)]
mod registry {
    use super::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Storage::FileSystem::{CommitTransaction, CreateTransaction, RollbackTransaction},
        System::Registry::*,
    };
    pub(super) struct Key(pub(super) HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn error(code: u32) -> AutostartError {
        match code {
            ERROR_TRANSACTIONAL_CONFLICT | ERROR_TRANSACTION_NOT_ACTIVE | ERROR_KEY_DELETED => {
                ErrorCode::Conflict.into()
            }
            ERROR_NOT_SUPPORTED | ERROR_CALL_NOT_IMPLEMENTED => ErrorCode::Unsupported.into(),
            _ => ErrorCode::Io.into(),
        }
    }
    fn query(key: HKEY, name: &str) -> Result<Option<Image>> {
        let name = wide(name);
        let mut size = 0;
        let mut kind = 0;
        let code = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        if u64::from(size) > MAX_IMAGE {
            return Err(ErrorCode::Conflict.into());
        }
        let mut bytes = vec![0; size as usize];
        let code = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if code == ERROR_MORE_DATA {
            return Err(ErrorCode::Conflict.into());
        }
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        bytes.truncate(size as usize);
        Ok(Some(Image { kind, bytes }))
    }
    // Open each component itself, refusing native registry links. Handles pin
    // the opened key objects; retarget/delete becomes a transaction conflict.
    fn open(subkey: &str, transaction: Option<HANDLE>, create: bool) -> Result<Option<Key>> {
        let mut parent = HKEY_CURRENT_USER;
        let mut owned = None;
        for part in subkey.split('\\') {
            let name = wide(part);
            let mut result = ptr::null_mut();
            let rights = if transaction.is_some() {
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY
            } else {
                KEY_QUERY_VALUE
            };
            let code = if let Some(tx) = transaction {
                unsafe {
                    RegOpenKeyTransactedW(
                        parent,
                        name.as_ptr(),
                        REG_OPTION_OPEN_LINK,
                        rights,
                        &mut result,
                        tx,
                        ptr::null(),
                    )
                }
            } else {
                unsafe {
                    RegOpenKeyExW(
                        parent,
                        name.as_ptr(),
                        REG_OPTION_OPEN_LINK,
                        rights,
                        &mut result,
                    )
                }
            };
            let code = if code == ERROR_FILE_NOT_FOUND && create {
                let tx = transaction.ok_or(ErrorCode::Invalid)?;
                unsafe {
                    RegCreateKeyTransactedW(
                        parent,
                        name.as_ptr(),
                        0,
                        ptr::null(),
                        REG_OPTION_NON_VOLATILE,
                        rights,
                        ptr::null(),
                        &mut result,
                        ptr::null_mut(),
                        tx,
                        ptr::null(),
                    )
                }
            } else {
                code
            };
            if code == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if code != ERROR_SUCCESS {
                return Err(error(code));
            }
            let key = Key(result);
            if query(key.0, "SymbolicLinkValue")?.is_some_and(|v| v.kind == REG_LINK) {
                return Err(ErrorCode::Conflict.into());
            }
            parent = key.0;
            owned = Some(key);
        }
        Ok(owned)
    }
    pub(super) fn read(subkey: &str, name: &str) -> Result<Option<Image>> {
        match open(subkey, None, false)? {
            Some(key) => query(key.0, name),
            None => Ok(None),
        }
    }
    fn proof_key(subkey: &str, name: &str) -> String {
        // A child key is not a Run value and is never executed at login. Test
        // proofs stay under the injected test key, never the real Run key.
        format!(r"{subkey}\AgentSessionGrepReceipts\{name}")
    }
    pub(super) fn commit_proof(subkey: &str, name: &str) -> Result<Option<Image>> {
        read(&proof_key(subkey, name), "Transaction")
    }
    struct Transaction(OwnedHandle);
    impl Drop for Transaction {
        fn drop(&mut self) {
            unsafe {
                RollbackTransaction(self.0.as_raw_handle());
            }
        }
    }
    pub(super) fn change(
        subkey: &str,
        name: &str,
        before: &Option<Image>,
        desired: &Option<Image>,
        proof_id: &str,
        proof_before: &Option<Image>,
        hook: &mut dyn FnMut(TestPoint) -> Result<()>,
    ) -> Result<()> {
        // SAFETY: unnamed transaction with no inherited handle. Native registry
        // operations below stay in this transaction until a checked commit.
        let raw = unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 5000, ptr::null())
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(error(unsafe { GetLastError() }));
        }
        let tx = Transaction(unsafe { OwnedHandle::from_raw_handle(raw) });
        let key = match open(subkey, Some(raw), desired.is_some())? {
            Some(key) => key,
            None => {
                return if before.is_none() && desired.is_none() {
                    Ok(())
                } else {
                    Err(ErrorCode::Conflict.into())
                };
            }
        };
        if query(key.0, name)? != *before {
            return Err(ErrorCode::Conflict.into());
        }
        hook(TestPoint::NativeReady)?;
        let value_name = name;
        let name = wide(name);
        let code = match desired {
            Some(image) => unsafe {
                RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    image.kind,
                    image.bytes.as_ptr(),
                    image.bytes.len() as u32,
                )
            },
            None => unsafe { RegDeleteValueW(key.0, name.as_ptr()) },
        };
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        // A transacted query alone is not a value CAS: a non-transacted writer
        // may complete before the first transacted write. After acquiring the
        // transaction's write intent, compare the still-visible committed value.
        // New outside writes either abort/conflict with that intent; commit is
        // checked below. Do not substitute a pre-read plus untransacted set.
        hook(TestPoint::RegistryReserved)?;
        if read(subkey, value_name)? != *before {
            return Err(ErrorCode::Conflict.into());
        }
        let proof = open(&proof_key(subkey, value_name), Some(raw), true)?
            .ok_or(ErrorCode::RecoveryRequired)?;
        if query(proof.0, "Transaction")? != *proof_before {
            return Err(ErrorCode::Conflict.into());
        }
        let proof_name = wide("Transaction");
        let code = unsafe {
            RegSetValueExW(
                proof.0,
                proof_name.as_ptr(),
                0,
                REG_BINARY,
                proof_id.as_ptr(),
                proof_id.len() as u32,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(error(code));
        }
        if commit_proof(subkey, value_name)? != *proof_before {
            return Err(ErrorCode::Conflict.into());
        }
        hook(TestPoint::RegistryBeforeCommit)?;
        if unsafe { CommitTransaction(raw) } == 0 {
            return Err(error(unsafe { GetLastError() }));
        }
        drop(key);
        drop(tx);
        hook(TestPoint::NativeApplied)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_autostart_tests.rs"]
mod tests;
