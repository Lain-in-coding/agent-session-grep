//! Durable, private installation side-effect journal. A phase is a claim about
//! verified effects, never permission to repeat an unacknowledged operation.
//! The caller must hold the installation OS lock for this prefix throughout.
use crate::{
    CliError,
    native_autostart::platform,
    package_installation::{absolute, ordinary},
    protocol::{CanonicalCode, ProtocolError},
    update_check::MANAGED_TARGETS,
};
use agent_session_grep_adapters_sqlite::managed_locks::{
    ExclusiveGuard, JobLockKey, LockKind, RootIdentity,
};
use agent_session_grep_launcher::CurrentPointer;
use agent_session_grep_ports::control::ControlId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::File,
    io::{Read, Write},
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::Instant,
};

pub(crate) const SCHEMA: &str = "asg.update-state/v1";
const MAX_STATE: u64 = 64 * 1024;
const MAX_IMAGE: u64 = 1024 * 1024;

fn error(code: CanonicalCode) -> CliError {
    ProtocolError::new(code, "update state needs verified recovery; inspect update status and retry recover with the owned installation").into()
}
fn invalid() -> CliError {
    error(CanonicalCode::SchemaIncompatible)
}
fn io(_: impl std::fmt::Debug) -> CliError {
    error(CanonicalCode::SourceIo)
}
fn deadline(end: Instant) -> Result<(), CliError> {
    if Instant::now() >= end {
        Err(error(CanonicalCode::WriterBusy))
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    StateIntent,
    StatePublished,
    ReconcileIntent,
    ReconcilePublished,
    ArchiveIntent,
    ArchivePublished,
    ArchiveCleaned,
    MetadataPublished,
}
#[cfg(test)]
thread_local! {
    static INJECTED_FAULT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn fault(point: Fault) -> Result<(), CliError> {
    INJECTED_FAULT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            Err(io("injected journal interruption"))
        } else {
            Ok(())
        }
    })
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_id(value: &str) -> bool {
    ControlId::parse(value).is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Downloaded,
    Verified,
    Quiescing,
    BackedUp,
    Staged,
    Migrated,
    Switched,
    SelfChecked,
    Complete,
    Failed,
    RollbackPending,
    Reconciling,
    RolledBack,
    Attention,
}
impl Phase {
    pub(crate) fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed | Self::RolledBack)
    }
    fn permits(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Downloaded => matches!(next, Self::Verified | Self::Failed),
            Self::Verified => matches!(next, Self::Quiescing | Self::Failed),
            Self::Quiescing => matches!(
                next,
                Self::BackedUp | Self::Failed | Self::RollbackPending | Self::Attention
            ),
            Self::BackedUp => {
                matches!(next, Self::Staged | Self::RollbackPending | Self::Attention)
            }
            Self::Staged => matches!(
                next,
                Self::Migrated | Self::RollbackPending | Self::Attention
            ),
            Self::Migrated => matches!(
                next,
                Self::Switched | Self::RollbackPending | Self::Attention
            ),
            Self::Switched => matches!(
                next,
                Self::SelfChecked | Self::RollbackPending | Self::Attention
            ),
            Self::SelfChecked => matches!(
                next,
                Self::Complete | Self::RollbackPending | Self::Attention
            ),
            Self::RollbackPending => matches!(next, Self::Reconciling | Self::Attention),
            Self::Reconciling => {
                matches!(next, Self::RolledBack | Self::SelfChecked | Self::Attention)
            }
            Self::Attention => matches!(next, Self::Reconciling | Self::RollbackPending),
            Self::Complete | Self::Failed | Self::RolledBack => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionIdentity {
    pub(crate) version: String,
    pub(crate) target: String,
    pub(crate) source_commit: String,
    pub(crate) relative_dir: String,
    pub(crate) app_sha256: String,
    pub(crate) catalog_schema: u32,
    pub(crate) control_schema: u32,
    pub(crate) launcher_protocol: u32,
}
impl VersionIdentity {
    fn validate(&self) -> Result<(), CliError> {
        if semver::Version::parse(&self.version).is_err()
            || !MANAGED_TARGETS.contains(&self.target.as_str())
            || !hex(&self.source_commit, 40)
            || !hex(&self.app_sha256, 64)
            || self.catalog_schema == 0
            || self.control_schema == 0
            || self.launcher_protocol != 1
        {
            return Err(invalid());
        }
        let pointer = self.pointer(1, "2026-01-01T00:00:00Z")?;
        CurrentPointer::parse(&serde_json::to_vec(&pointer).map_err(io)?).map_err(|_| invalid())?;
        Ok(())
    }
    pub(crate) fn pointer(
        &self,
        generation: u64,
        activated_at: &str,
    ) -> Result<CurrentPointer, CliError> {
        Ok(CurrentPointer {
            schema: agent_session_grep_launcher::metadata::CURRENT_SCHEMA.into(),
            generation: NonZeroU64::new(generation).ok_or_else(invalid)?,
            version: self.version.clone(),
            dir: self.relative_dir.clone(),
            app: if self.target.ends_with("windows-msvc") {
                "agent-session-grep.exe"
            } else {
                "agent-session-grep"
            }
            .into(),
            app_sha256: self.app_sha256.clone(),
            launcher_protocol: self.launcher_protocol,
            activated_at: activated_at.into(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub(crate) installation_id: String,
    pub(crate) policy_epoch: u64,
    pub(crate) control_seq: u64,
    pub(crate) desired_updates: String,
    pub(crate) catalog_incarnation: String,
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_schema: u32,
}
impl Checkpoint {
    fn validate(&self) -> Result<(), CliError> {
        if !valid_id(&self.installation_id)
            || !valid_id(&self.catalog_incarnation)
            || !matches!(
                self.desired_updates.as_str(),
                "running" | "paused" | "stopped"
            )
            || self.catalog_schema == 0
            || [self.policy_epoch, self.control_seq, self.catalog_generation]
                .into_iter()
                .any(|value| value > i64::MAX as u64)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn follows(&self, initial: &Self) -> bool {
        self.installation_id == initial.installation_id
            && self.catalog_incarnation == initial.catalog_incarnation
            && self.catalog_schema == initial.catalog_schema
            && self.control_seq >= initial.control_seq
            && self.policy_epoch >= initial.policy_epoch
            && self.catalog_generation >= initial.catalog_generation
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupReference {
    pub(crate) id: String,
    pub(crate) relative_locator: String,
    pub(crate) digest: String,
    pub(crate) size_bytes: u64,
    pub(crate) catalog_incarnation: String,
    pub(crate) catalog_generation: u64,
    pub(crate) schema: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MetadataFile {
    PackageManifest,
    PackageReceipt,
    ReleaseManifest,
    Checksums,
    Current,
    InstallerSh,
    InstallerPowerShell,
    InstallGuide,
    Readme,
    Changelog,
    LicenseMit,
    LicenseApache,
    Notice,
    Security,
    DependenciesJson,
    DependenciesCsv,
}
impl MetadataFile {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::PackageManifest => "PACKAGE-MANIFEST.tsv",
            Self::PackageReceipt => "package-install.json",
            Self::ReleaseManifest => "release.manifest.json",
            Self::Checksums => "SHA256SUMS",
            Self::Current => "current.json",
            Self::InstallerSh => "package-install.sh",
            Self::InstallerPowerShell => "package-install.ps1",
            Self::InstallGuide => "INSTALL-AND-UPGRADE.md",
            Self::Readme => "README.md",
            Self::Changelog => "CHANGELOG.md",
            Self::LicenseMit => "LICENSE-MIT",
            Self::LicenseApache => "LICENSE-APACHE",
            Self::Notice => "NOTICE",
            Self::Security => "SECURITY.md",
            Self::DependenciesJson => "THIRD-PARTY-DEPENDENCIES.json",
            Self::DependenciesCsv => "THIRD-PARTY-DEPENDENCIES.csv",
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::PackageManifest => "package_manifest",
            Self::PackageReceipt => "package_receipt",
            Self::ReleaseManifest => "release_manifest",
            Self::Checksums => "checksums",
            Self::Current => "current",
            Self::InstallerSh => "installer_sh",
            Self::InstallerPowerShell => "installer_powershell",
            Self::InstallGuide => "install_guide",
            Self::Readme => "readme",
            Self::Changelog => "changelog",
            Self::LicenseMit => "license_mit",
            Self::LicenseApache => "license_apache",
            Self::Notice => "notice",
            Self::Security => "security",
            Self::DependenciesJson => "dependencies_json",
            Self::DependenciesCsv => "dependencies_csv",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    file: MetadataFile,
    before_sha256: Option<String>,
    after_sha256: String,
    artifact: String,
}
type MetadataImages = Vec<(MetadataFile, Option<Vec<u8>>, String)>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub(crate) schema: String,
    pub(crate) update_id: String,
    pub(crate) owner_nonce: String,
    pub(crate) seq: u64,
    pub(crate) prefix_binding: String,
    pub(crate) phase: Phase,
    pub(crate) old: VersionIdentity,
    pub(crate) new: VersionIdentity,
    pub(crate) archive_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) old_pointer_generation: u64,
    pub(crate) stable_launcher_sha256: String,
    pub(crate) resumed: bool,
    pub(crate) recovery_incarnation: Option<String>,
    pub(crate) new_pointer_generation: u64,
    pub(crate) catalog: PathBuf,
    pub(crate) checkpoint: Checkpoint,
    /// The once-recorded identity observed after the catalog handles drain.
    /// Earlier local journals decode as None and require recovery before backup.
    #[serde(default)]
    pub(crate) quiesced_checkpoint: Option<Checkpoint>,
    /// Hash of the bounded, journal-owned native operation intent, not an
    /// acknowledgement that the operating system has applied that operation.
    #[serde(default)]
    pub(crate) native_binding_sha256: Option<String>,
    pub(crate) backup: Option<BackupReference>,
    pub(crate) staged: bool,
    pub(crate) migrated: bool,
    pub(crate) self_checked: bool,
    pending: Option<Replacement>,
    effects: Vec<Replacement>,
    pub(crate) error_code: Option<String>,
    pub(crate) cleanup_pending: bool,
}
pub(crate) struct UpdateStart {
    pub(crate) update_id: ControlId,
    pub(crate) owner: ControlId,
    pub(crate) old: VersionIdentity,
    pub(crate) new: VersionIdentity,
    pub(crate) archive_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) old_pointer_generation: u64,
    pub(crate) stable_launcher_sha256: String,
    pub(crate) catalog: PathBuf,
    pub(crate) checkpoint: Checkpoint,
}
impl State {
    pub(crate) fn new(start: UpdateStart) -> Result<Self, CliError> {
        let UpdateStart {
            update_id,
            owner,
            old,
            new,
            archive_sha256,
            manifest_sha256,
            old_pointer_generation,
            stable_launcher_sha256,
            catalog,
            checkpoint,
        } = start;
        let state = Self {
            schema: SCHEMA.into(),
            update_id: update_id.as_str().into(),
            owner_nonce: owner.as_str().into(),
            seq: 1,
            prefix_binding: "unbound".into(),
            phase: Phase::Verified,
            old,
            new,
            archive_sha256,
            manifest_sha256,
            old_pointer_generation,
            stable_launcher_sha256,
            resumed: false,
            recovery_incarnation: None,
            new_pointer_generation: old_pointer_generation.checked_add(1).ok_or_else(invalid)?,
            catalog,
            checkpoint,
            quiesced_checkpoint: None,
            native_binding_sha256: None,
            backup: None,
            staged: false,
            migrated: false,
            self_checked: false,
            pending: None,
            effects: Vec::new(),
            error_code: None,
            cleanup_pending: false,
        };
        state.validate()?;
        Ok(state)
    }
    pub(crate) fn validate(&self) -> Result<(), CliError> {
        self.old.validate()?;
        self.new.validate()?;
        self.checkpoint.validate()?;
        if let Some(quiesced) = &self.quiesced_checkpoint {
            quiesced.validate()?;
            if !quiesced.follows(&self.checkpoint)
                || matches!(self.phase, Phase::Downloaded | Phase::Verified)
            {
                return Err(invalid());
            }
        }
        if self.schema != SCHEMA
            || !valid_id(&self.update_id)
            || !valid_id(&self.owner_nonce)
            || self.seq == 0
            || self.seq > 10000
            || !valid_id(&self.prefix_binding)
            || self.old.target != self.new.target
            || !hex(&self.archive_sha256, 64)
            || !hex(&self.manifest_sha256, 64)
            || !hex(&self.stable_launcher_sha256, 64)
            || self.old_pointer_generation == 0
            || self.new_pointer_generation
                != self
                    .old_pointer_generation
                    .checked_add(1)
                    .ok_or_else(invalid)?
            || !self.catalog.is_absolute()
            || self
                .catalog
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            || self.checkpoint.catalog_schema != self.old.catalog_schema
            || self
                .recovery_incarnation
                .as_ref()
                .is_some_and(|s| !valid_id(s) || s == &self.checkpoint.catalog_incarnation)
            || self
                .native_binding_sha256
                .as_ref()
                .is_some_and(|s| !hex(s, 64))
            || self.effects.len() > 64
            || self.error_code.as_ref().is_some_and(|s| {
                s.len() > 64 || !s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            })
        {
            return Err(invalid());
        }
        if let Some(backup) = &self.backup {
            if !valid_id(&backup.id)
                || !hex(&backup.digest, 64)
                || backup.size_bytes == 0
                || backup.schema == 0
                || !valid_id(&backup.catalog_incarnation)
                || !safe_relative(&backup.relative_locator)
            {
                return Err(invalid());
            }
            let quiesced = self.quiesced_checkpoint.as_ref().ok_or_else(invalid)?;
            if backup.catalog_incarnation != quiesced.catalog_incarnation
                || backup.catalog_generation != quiesced.catalog_generation
                || backup.schema != quiesced.catalog_schema
            {
                return Err(invalid());
            }
        }
        for p in self.effects.iter().chain(self.pending.iter()) {
            if !hex(&p.after_sha256, 64)
                || p.before_sha256.as_ref().is_some_and(|s| !hex(s, 64))
                || !safe_relative(&p.artifact)
            {
                return Err(invalid());
            }
            let (seq, key) = p.artifact.split_once('-').ok_or_else(invalid)?;
            let seq: u64 = seq.parse().map_err(|_| invalid())?;
            if seq == 0 || seq > self.seq || key != p.file.key() {
                return Err(invalid());
            }
        }
        let mut names = std::collections::BTreeSet::new();
        let mut prior_seq = 0;
        let mut images = std::collections::BTreeMap::new();
        for effect in self.effects.iter().chain(self.pending.iter()) {
            let seq = effect
                .artifact
                .split_once('-')
                .ok_or_else(invalid)?
                .0
                .parse::<u64>()
                .map_err(|_| invalid())?;
            if !names.insert(effect.artifact.as_str()) || seq <= prior_seq {
                return Err(invalid());
            }
            prior_seq = seq;
            if let Some(previous) = images.insert(effect.file.key(), effect.after_sha256.as_str())
                && effect.before_sha256.as_deref() != Some(previous)
            {
                return Err(invalid());
            }
        }
        let requires_backup = matches!(
            self.phase,
            Phase::BackedUp
                | Phase::Staged
                | Phase::Migrated
                | Phase::Switched
                | Phase::SelfChecked
                | Phase::Complete
        );
        if (requires_backup && (self.backup.is_none() || self.quiesced_checkpoint.is_none()))
            || (matches!(
                self.phase,
                Phase::Staged
                    | Phase::Migrated
                    | Phase::Switched
                    | Phase::SelfChecked
                    | Phase::Complete
            ) && !self.staged)
            || (matches!(
                self.phase,
                Phase::Migrated | Phase::Switched | Phase::SelfChecked | Phase::Complete
            ) && !self.migrated)
            || (matches!(
                self.phase,
                Phase::Switched | Phase::SelfChecked | Phase::Complete
            ) && !self.effects.iter().any(|p| p.file == MetadataFile::Current))
            || (matches!(self.phase, Phase::SelfChecked | Phase::Complete) && !self.self_checked)
            || (self.phase.terminal() && self.pending.is_some())
            || (self.phase == Phase::Failed
                && (self.backup.is_some()
                    || self.staged
                    || self.migrated
                    || self.self_checked
                    || self.resumed
                    || !self.effects.is_empty()))
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.update_id == other.update_id
            && self.owner_nonce == other.owner_nonce
            && self.prefix_binding == other.prefix_binding
            && self.old == other.old
            && self.new == other.new
            && self.archive_sha256 == other.archive_sha256
            && self.manifest_sha256 == other.manifest_sha256
            && self.old_pointer_generation == other.old_pointer_generation
            && self.new_pointer_generation == other.new_pointer_generation
            && self.stable_launcher_sha256 == other.stable_launcher_sha256
            && self.catalog == other.catalog
            && self.checkpoint == other.checkpoint
    }

    /// A higher sequence is not proof: every adjacent image must describe one
    /// legal change to the same immutable installation and initial checkpoint.
    fn successor_of(&self, prior: &Self) -> Result<(), CliError> {
        self.validate()?;
        prior.validate()?;
        if prior.seq.checked_add(1) != Some(self.seq)
            || !self.same_identity(prior)
            || prior.phase.terminal()
            || !prior.phase.permits(self.phase)
        {
            return Err(invalid());
        }
        if self.quiesced_checkpoint != prior.quiesced_checkpoint
            && !(prior.quiesced_checkpoint.is_none()
                && self.quiesced_checkpoint.is_some()
                && prior.phase == Phase::Quiescing
                && self.phase == Phase::Quiescing
                && prior.backup.is_none()
                && prior.pending.is_none()
                && prior.effects.is_empty())
        {
            return Err(invalid());
        }
        if self.native_binding_sha256 != prior.native_binding_sha256
            && !(prior.native_binding_sha256.is_none()
                && self.native_binding_sha256.is_some()
                && matches!(prior.phase, Phase::Verified | Phase::Quiescing)
                && prior.phase == self.phase
                && prior.backup.is_none()
                && self.backup.is_none()
                && prior.pending.is_none()
                && self.pending.is_none()
                && prior.effects.is_empty()
                && self.effects.is_empty()
                && !self.staged
                && !self.migrated)
        {
            return Err(invalid());
        }
        if self.backup != prior.backup
            && !(prior.backup.is_none()
                && self.backup.is_some()
                && prior.phase == Phase::Quiescing
                && self.phase == Phase::BackedUp
                && prior.quiesced_checkpoint.is_some())
        {
            return Err(invalid());
        }
        if self.recovery_incarnation != prior.recovery_incarnation
            && !(prior.recovery_incarnation.is_none()
                && self.recovery_incarnation.is_some()
                && prior.phase == Phase::Reconciling
                && self.phase == Phase::Reconciling)
        {
            return Err(invalid());
        }
        for (before, after, permitted) in [
            (
                prior.staged,
                self.staged,
                prior.phase == Phase::BackedUp && self.phase == Phase::Staged,
            ),
            (
                prior.migrated,
                self.migrated,
                prior.phase == Phase::Staged && self.phase == Phase::Migrated,
            ),
            (
                prior.self_checked,
                self.self_checked,
                matches!(prior.phase, Phase::Switched | Phase::Reconciling)
                    && self.phase == Phase::SelfChecked,
            ),
            (
                prior.resumed,
                self.resumed,
                prior.phase == Phase::SelfChecked && self.phase == Phase::Complete,
            ),
        ] {
            if before != after && (before || !permitted) {
                return Err(invalid());
            }
        }
        match (&prior.pending, &self.pending) {
            (None, None) if self.effects == prior.effects => {}
            (None, Some(pending)) if self.effects == prior.effects => {
                if pending.artifact.split_once('-').ok_or_else(invalid)?.0 != prior.seq.to_string()
                {
                    return Err(invalid());
                }
            }
            (Some(before), Some(after)) if before == after && self.effects == prior.effects => {}
            (Some(_), None) if self.effects == prior.effects => {
                // Cancelling a durable intent is permitted only in its phase.
                if prior.phase != self.phase {
                    return Err(invalid());
                }
            }
            (Some(before), None)
                if self.effects.len() == prior.effects.len() + 1
                    && self.effects.starts_with(&prior.effects)
                    && self.effects.last() == Some(before)
                    && self.phase == prior.phase => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.contains(['\\', ':'])
        && value.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        })
}

/// Both a real same-root owner and a brief process registry reservation consume
/// the same five-second installation-lock allowance, capped by caller deadline.
pub(crate) fn acquire_installation_lock(
    prefix: &Path,
    end: Instant,
) -> Result<ExclusiveGuard, CliError> {
    let lock_end = std::cmp::min(end, Instant::now() + std::time::Duration::from_secs(5));
    let kind = LockKind::MaintenanceJob(JobLockKey::parse("installation-update").map_err(io)?);
    loop {
        deadline(lock_end)?;
        match ExclusiveGuard::try_acquire(prefix, kind.clone()) {
            Ok(guard) => return Ok(guard),
            Err(agent_session_grep_ports::PortError::WriterBusy(_)) => {
                std::thread::sleep(std::cmp::min(
                    std::time::Duration::from_millis(5),
                    lock_end.saturating_duration_since(Instant::now()),
                ));
            }
            Err(e) => return Err(io(e)),
        }
    }
}

/// Updates cannot derive their own authority from the journal nonce. The real
/// OS lock and the pinned physical directory remain borrowed for this lifetime.
pub(crate) struct Journal<'a> {
    prefix: PathBuf,
    root: PathBuf,
    identity: RootIdentity,
    directory: File,
    _lock: &'a ExclusiveGuard,
    pub(crate) state: State,
    durable: State,
    poisoned: bool,
}
impl<'a> Journal<'a> {
    fn root(
        prefix: &Path,
        guard: &ExclusiveGuard,
        create: bool,
    ) -> Result<(PathBuf, PathBuf, RootIdentity, File), CliError> {
        let prefix = absolute(prefix)?;
        ordinary(&prefix)?;
        let identity = RootIdentity::read(&prefix).map_err(io)?;
        if guard.kind()
            != &LockKind::MaintenanceJob(JobLockKey::parse("installation-update").map_err(io)?)
            || guard.root_identity() != identity
        {
            return Err(invalid());
        }
        let root = prefix.join("update");
        if create {
            platform::create_private_directory(&root).map_err(io)?;
        }
        ordinary(&root)?;
        platform::validate_private(&root).map_err(io)?;
        let directory = platform::directory(&root).map_err(io)?;
        Ok((prefix, root, identity, directory))
    }
    pub(crate) fn create(
        prefix: &Path,
        guard: &'a ExclusiveGuard,
        mut state: State,
        end: Instant,
    ) -> Result<Self, CliError> {
        deadline(end)?;
        let (prefix, root, identity, directory) = Self::root(prefix, guard, true)?;
        recover_archive(&root, &identity, end)?;
        if state_paths(&root)
            .iter()
            .any(|path| fs::symlink_metadata(path).is_ok())
        {
            return Err(invalid());
        }
        state.seq = 1;
        state.prefix_binding = identity.control_id().as_str().into();
        state.validate()?;
        let mut journal = Self {
            prefix,
            root,
            identity,
            directory,
            _lock: guard,
            durable: state.clone(),
            state,
            poisoned: false,
        };
        let run = journal.run_root();
        platform::create_private_directory(&run).map_err(io)?;
        journal.write_state(end)?;
        Ok(journal)
    }
    pub(crate) fn open(
        prefix: &Path,
        guard: &'a ExclusiveGuard,
        end: Instant,
    ) -> Result<Self, CliError> {
        deadline(end)?;
        let (prefix, root, identity, directory) = Self::root(prefix, guard, false)?;
        recover_archive(&root, &identity, end)?;
        reconcile_state(&root, &identity, end)?;
        let bytes = read(&root.join("state.json"), MAX_STATE)?.ok_or_else(invalid)?;
        let state: State = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        state.validate()?;
        let journal = Self {
            prefix,
            root,
            identity,
            directory,
            _lock: guard,
            durable: state.clone(),
            state,
            poisoned: false,
        };
        platform::validate_private(&journal.run_root()).map_err(io)?;
        journal.check()?;
        Ok(journal)
    }
    /// A terminal update can be moved into its already owned run directory
    /// before creating the next one. A working pointer is never reset here.
    pub(crate) fn archive_terminal(
        prefix: &Path,
        guard: &'a ExclusiveGuard,
        end: Instant,
    ) -> Result<(), CliError> {
        deadline(end)?;
        let (_, root, identity, _) = Self::root(prefix, guard, false)?;
        if recover_archive(&root, &identity, end)? {
            return Ok(());
        }
        let journal = Self::open(prefix, guard, end)?;
        if !journal.state.phase.terminal() {
            return Err(invalid());
        }
        // This immutable intent survives removal of the active name. It lets
        // create/recover finish an interrupted archive without reviving a phase.
        write_new(
            &journal.root.join("state.archive.json"),
            &serde_json::to_vec(&journal.durable).map_err(io)?,
        )?;
        #[cfg(test)]
        fault(Fault::ArchiveIntent)?;
        recover_archive(&journal.root, &journal.identity, end)?;
        journal.check()
    }
    pub(crate) fn run_root(&self) -> PathBuf {
        self.root.join(&self.state.update_id)
    }
    pub(crate) fn prefix(&self) -> &Path {
        &self.prefix
    }
    pub(crate) fn poisoned(&self) -> bool {
        self.poisoned
    }
    fn check(&self) -> Result<(), CliError> {
        if self.poisoned {
            return Err(error(CanonicalCode::UpdateRecoveryRequired));
        }
        ordinary(&self.prefix)?;
        ordinary(&self.root)?;
        if RootIdentity::read(&self.prefix).map_err(io)? != self.identity
            || self._lock.root_identity() != self.identity
            || self.state.prefix_binding != self.identity.control_id().as_str()
            || platform::identity(&self.directory).map_err(io)?
                != platform::identity(&platform::directory(&self.root).map_err(io)?).map_err(io)?
        {
            return Err(invalid());
        }
        ordinary(&self.run_root())?;
        platform::validate_private(&self.run_root()).map_err(io)?;
        platform::validate_private(&self.root).map_err(io)
    }

    /// Failed persistence may have reached disk even when acknowledgement did
    /// not. No side-effect API on this handle may run again; reopen under the
    /// same OS owner to reconcile the private slots and obtain a fresh baseline.
    fn mutation<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, CliError>,
    ) -> Result<T, CliError> {
        let result = self.check().and_then(|()| action(self));
        if result.is_err() {
            self.state = self.durable.clone();
            self.poisoned = true;
        }
        result
    }

    fn write_state(&mut self, end: Instant) -> Result<(), CliError> {
        deadline(end)?;
        self.check()?;
        self.state.validate()?;
        let bytes = serde_json::to_vec(&self.state).map_err(io)?;
        if bytes.len() as u64 > MAX_STATE {
            return Err(invalid());
        }
        let next = self.root.join("state.next.json");
        if fs::symlink_metadata(&next).is_ok() {
            return Err(invalid());
        }
        write_new(&next, &bytes)?;
        #[cfg(test)]
        fault(Fault::StateIntent)?;
        publish(
            &self.root.join("state.json"),
            &next,
            &self.root.join("state.previous.json"),
        )?;
        self.check()?;
        let actual = read(&self.root.join("state.json"), MAX_STATE)?.ok_or_else(invalid)?;
        if hash(&actual) != hash(&bytes) {
            return Err(invalid());
        }
        #[cfg(test)]
        fault(Fault::StatePublished)?;
        reconcile_state(&self.root, &self.identity, end)?;
        self.check()
    }
    pub(crate) fn save(&mut self, end: Instant) -> Result<(), CliError> {
        self.mutation(|journal| {
            deadline(end)?;
            if journal.state.seq != journal.durable.seq {
                return Err(invalid());
            }
            let actual = read(&journal.root.join("state.json"), MAX_STATE)?.ok_or_else(invalid)?;
            let actual: State = serde_json::from_slice(&actual).map_err(|_| invalid())?;
            if actual != journal.durable
                || state_paths(&journal.root)
                    .iter()
                    .skip(1)
                    .any(|path| fs::symlink_metadata(path).is_ok())
            {
                return Err(invalid());
            }
            journal.state.seq = journal.state.seq.checked_add(1).ok_or_else(invalid)?;
            journal.state.successor_of(&journal.durable)?;
            journal.write_state(end)?;
            journal.durable = journal.state.clone();
            Ok(())
        })
    }
    pub(crate) fn transition(&mut self, next: Phase, end: Instant) -> Result<(), CliError> {
        self.mutation(|journal| {
            if journal.state.phase != journal.durable.phase || !journal.durable.phase.permits(next)
            {
                return Err(invalid());
            }
            journal.state.phase = next;
            journal.save(end)
        })
    }
    /// Intent is durable before any target mutation. The old metadata bytes are
    /// owned recovery images; no catalog or policy content is copied here.
    pub(crate) fn replace_metadata(
        &mut self,
        file: MetadataFile,
        bytes: &[u8],
        end: Instant,
    ) -> Result<(), CliError> {
        self.mutation(|journal| journal.replace_metadata_inner(file, bytes, end))
    }
    fn replace_metadata_inner(
        &mut self,
        file: MetadataFile,
        bytes: &[u8],
        end: Instant,
    ) -> Result<(), CliError> {
        deadline(end)?;
        self.check()?;
        if self.state.pending.is_some() || bytes.len() as u64 > MAX_IMAGE {
            return Err(invalid());
        }
        let target = self.prefix.join(file.name());
        let before = read(&target, MAX_IMAGE)?;
        let artifact = format!("{}-{}", self.state.seq, file.key());
        let before_path = self.run_root().join(format!("{artifact}.before"));
        let new_path = self.run_root().join(format!("{artifact}.new"));
        self.state.pending = Some(Replacement {
            file,
            before_sha256: before.as_ref().map(|b| hash(b)),
            after_sha256: hash(bytes),
            artifact: artifact.clone(),
        });
        self.save(end)?;
        if let Some(before) = before {
            write_new(&before_path, &before)?;
        }
        write_new(&new_path, bytes)?;
        #[cfg(unix)]
        if file == MetadataFile::InstallerSh {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&new_path, fs::Permissions::from_mode(0o755)).map_err(io)?;
        }
        self.reconcile_metadata(end)
    }
    /// An intent without images can be cancelled only when the original
    /// target is unchanged. Third images are preserved as recovery conflicts.
    pub(crate) fn reconcile_metadata(&mut self, end: Instant) -> Result<(), CliError> {
        self.mutation(|journal| journal.reconcile_metadata_inner(end))
    }
    fn reconcile_metadata_inner(&mut self, end: Instant) -> Result<(), CliError> {
        deadline(end)?;
        self.check()?;
        let Some(p) = self.state.pending.clone() else {
            return Ok(());
        };
        let target = self.prefix.join(p.file.name());
        let new = self.run_root().join(format!("{}.new", p.artifact));
        let before = self.run_root().join(format!("{}.before", p.artifact));
        let displaced = self.run_root().join(format!("{}.displaced", p.artifact));
        let actual = read(&target, MAX_IMAGE)?;
        let actual_hash = actual.as_ref().map(|bytes| hash(bytes));
        let displaced_image = read(&displaced, MAX_IMAGE)?;
        let displaced_hash = displaced_image.as_ref().map(|bytes| hash(bytes));
        if displaced_image.is_some() && displaced_hash != p.before_sha256 {
            return Err(invalid());
        }
        let before_image = read(&before, MAX_IMAGE)?;
        if before_image.is_some()
            && before_image.as_ref().map(|bytes| hash(bytes)) != p.before_sha256
        {
            return Err(invalid());
        }
        let image = read(&new, MAX_IMAGE)?;
        if actual_hash.as_deref() == Some(&p.after_sha256) {
            // Unix exchange can stop before its old staging image is moved to
            // displaced. Validate that image instead of repeating exchange.
            if let Some(bytes) = &image {
                if Some(hash(bytes)) != p.before_sha256 || displaced_image.is_some() {
                    return Err(invalid());
                }
                platform::move_new(&new, &displaced).map_err(io)?;
                platform::sync_directory(&self.run_root()).map_err(io)?;
            }
            if p.before_sha256.is_some() && before_image.is_none() {
                return Err(invalid());
            }
        } else {
            if actual_hash != p.before_sha256
                && !(actual_hash.is_none()
                    && displaced_image.is_some()
                    && displaced_hash == p.before_sha256)
            {
                return Err(invalid());
            }
            let Some(image) = image else {
                if actual_hash != p.before_sha256 || displaced_image.is_some() {
                    return Err(invalid());
                }
                self.state.pending = None;
                return self.save(end);
            };
            if hash(&image) != p.after_sha256
                || (p.before_sha256.is_some() && before_image.is_none())
            {
                return Err(invalid());
            }
            // A displaced file here is owned only if it is exactly the recorded
            // old image. It is never removed just because it has this name.
            if actual_hash.is_some()
                && let Some(bytes) = displaced_image
            {
                remove_matching(&displaced, &bytes, MAX_IMAGE)?;
            }
            publish(&target, &new, &displaced)?;
        }
        if read(&target, MAX_IMAGE)?
            .as_ref()
            .map(|bytes| hash(bytes))
            .as_deref()
            != Some(&p.after_sha256)
        {
            return Err(invalid());
        }
        let displaced_image = read(&displaced, MAX_IMAGE)?;
        if displaced_image.is_some()
            && displaced_image.as_ref().map(|bytes| hash(bytes)) != p.before_sha256
        {
            return Err(invalid());
        }
        #[cfg(test)]
        fault(Fault::MetadataPublished)?;
        self.state.pending = None;
        self.state.effects.push(p);
        self.save(end)
    }
    pub(crate) fn restore_metadata(&mut self, end: Instant) -> Result<(), CliError> {
        self.mutation(|journal| journal.restore_metadata_inner(end))
    }
    fn restore_metadata_inner(&mut self, end: Instant) -> Result<(), CliError> {
        self.reconcile_metadata(end)?;
        // All target hashes are checked against recorded effects before any
        // rollback writes. Third-party changes are preserved for review.
        let entries = self.replacements()?;
        for (file, before, after) in entries.iter().rev() {
            let actual = read(&self.prefix.join(file.name()), MAX_IMAGE)?
                .as_ref()
                .map(|b| hash(b));
            if actual.as_deref() != Some(after) && before.as_ref().map(|b| hash(b)) != actual {
                return Err(invalid());
            }
        }
        for (file, before, after) in entries.into_iter().rev() {
            if let Some(before) = before {
                let target = self.prefix.join(file.name());
                if hash(&before) != after
                    && read(&target, MAX_IMAGE)?
                        .as_ref()
                        .map(|b| hash(b))
                        .as_deref()
                        == Some(&after)
                {
                    self.replace_metadata(file, &before, end)?;
                }
            } else {
                // Missing original files are kept as owned pending cleanup;
                // deleting them is not required to restore the old pointer.
                self.state.cleanup_pending = true;
            }
        }
        self.save(end)
    }
    fn replacements(&self) -> Result<MetadataImages, CliError> {
        let mut result = Vec::new();
        for effect in &self.state.effects {
            if result.iter().any(|(file, _, _)| *file == effect.file) {
                continue;
            }
            let original = match &effect.before_sha256 {
                Some(expected) => {
                    let bytes = read(
                        &self.run_root().join(format!("{}.before", effect.artifact)),
                        MAX_IMAGE,
                    )?
                    .ok_or_else(invalid)?;
                    if hash(&bytes) != *expected {
                        return Err(invalid());
                    }
                    Some(bytes)
                }
                None => None,
            };
            let latest = self
                .state
                .effects
                .iter()
                .rev()
                .find(|p| p.file == effect.file)
                .ok_or_else(invalid)?;
            result.push((effect.file, original, latest.after_sha256.clone()));
        }
        Ok(result)
    }
}
pub(crate) fn read(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, CliError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
        Ok(m) if !m.is_file() => return Err(invalid()),
        Ok(_) => {}
    }
    ordinary(path)?;
    let mut f = platform::open_file(path).map_err(io)?;
    if f.metadata().map_err(io)?.len() > limit {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    (&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(Some(bytes))
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    ordinary(path.parent().ok_or_else(invalid)?)?;
    let mut file = platform::create_file(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    platform::sync_directory(path.parent().ok_or_else(invalid)?).map_err(io)
}
fn publish(target: &Path, next: &Path, previous: &Path) -> Result<(), CliError> {
    if fs::symlink_metadata(target).is_ok() {
        // The caller must validate and clear its own displaced slot first.
        // An existing third image is a conflict, never implicit ownership.
        if fs::symlink_metadata(previous).is_ok() {
            return Err(invalid());
        }
        platform::replace(target, next, previous).map_err(io)?;
        #[cfg(unix)]
        platform::move_new(next, previous).map_err(io)?;
    } else {
        platform::move_new(next, target).map_err(io)?;
    }
    // sync_all uses checked FlushFileBuffers on Windows. ReplaceFileW's
    // unsupported WRITE_THROUGH flag is deliberately not used.
    ordinary(target)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = options.open(target).map_err(io)?;
    if !file.metadata().map_err(io)?.is_file() {
        return Err(invalid());
    }
    file.sync_all().map_err(io)?;
    platform::sync_directory(target.parent().ok_or_else(invalid)?).map_err(io)?;
    if next.parent() != target.parent() {
        platform::sync_directory(next.parent().ok_or_else(invalid)?).map_err(io)?;
    }
    Ok(())
}
const STATE_SLOTS: [&str; 5] = [
    "state.json",
    "state.next.json",
    "state.previous.json",
    "state.reconcile.json",
    "state.reconciled-old.json",
];
fn state_paths(root: &Path) -> [PathBuf; 5] {
    STATE_SLOTS.map(|name| root.join(name))
}
struct StateSlot {
    path: PathBuf,
    bytes: Vec<u8>,
    state: State,
}
fn decode_state(bytes: &[u8], identity: &RootIdentity) -> Result<State, CliError> {
    let state: State = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    state.validate()?;
    if state.prefix_binding != identity.control_id().as_str() {
        return Err(invalid());
    }
    Ok(state)
}
fn load_slots(root: &Path, identity: &RootIdentity) -> Result<Vec<StateSlot>, CliError> {
    let mut slots = Vec::new();
    for path in state_paths(root) {
        if let Some(bytes) = read(&path, MAX_STATE)? {
            let state = decode_state(&bytes, identity)?;
            slots.push(StateSlot { path, bytes, state });
        }
    }
    slots.sort_by_key(|slot| slot.state.seq);
    validate_history(&slots)?;
    Ok(slots)
}
fn validate_history(slots: &[StateSlot]) -> Result<(), CliError> {
    for pair in slots.windows(2) {
        let prior = &pair[0];
        let next = &pair[1];
        if prior.state.seq == next.state.seq {
            if hash(&prior.bytes) != hash(&next.bytes) {
                return Err(invalid());
            }
        } else {
            next.state.successor_of(&prior.state)?;
        }
    }
    Ok(())
}
fn remove_matching(path: &Path, expected: &[u8], limit: u64) -> Result<(), CliError> {
    let actual = read(path, limit)?.ok_or_else(invalid)?;
    if hash(&actual) != hash(expected) {
        return Err(invalid());
    }
    fs::remove_file(path).map_err(io)?;
    platform::sync_directory(path.parent().ok_or_else(invalid)?).map_err(io)
}
fn reconcile_state(root: &Path, identity: &RootIdentity, end: Instant) -> Result<(), CliError> {
    deadline(end)?;
    let slots = load_slots(root, identity)?;
    let max = slots.last().ok_or_else(invalid)?;
    let current = root.join("state.json");
    if let Some(slot) = slots.iter().find(|slot| slot.path == current)
        && max.state.seq > slot.state.seq.checked_add(1).ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    let actual = read(&current, MAX_STATE)?;
    if actual.as_ref().map(|bytes| hash(bytes)) != Some(hash(&max.bytes)) {
        let image = root.join("state.reconcile.json");
        if let Some(bytes) = read(&image, MAX_STATE)? {
            if hash(&bytes) != hash(&max.bytes) {
                remove_matching(&image, &bytes, MAX_STATE)?;
                write_new(&image, &max.bytes)?;
            }
        } else {
            write_new(&image, &max.bytes)?;
        }
        let displaced = root.join("state.reconciled-old.json");
        if actual.is_some()
            && let Some(bytes) = read(&displaced, MAX_STATE)?
        {
            remove_matching(&displaced, &bytes, MAX_STATE)?;
        }
        #[cfg(test)]
        fault(Fault::ReconcileIntent)?;
        publish(&current, &image, &displaced)?;
        #[cfg(test)]
        fault(Fault::ReconcilePublished)?;
    }
    // Validate every possibly displaced image again before removing a slot.
    // Unix exchange can leave the old image at the staging name on interruption.
    let completed = load_slots(root, identity)?;
    let actual = read(&current, MAX_STATE)?.ok_or_else(invalid)?;
    if hash(&actual) != hash(&max.bytes) {
        return Err(invalid());
    }
    for slot in completed {
        deadline(end)?;
        if slot.path != current {
            remove_matching(&slot.path, &slot.bytes, MAX_STATE)?;
        }
    }
    platform::sync_directory(root).map_err(io)
}

/// An archive intent contains the final verified state, not just a nonce. All
/// remaining state slots must precede that exact terminal image before any
/// name is moved or removed. create also calls this after an interrupted exit.
fn recover_archive(root: &Path, identity: &RootIdentity, end: Instant) -> Result<bool, CliError> {
    deadline(end)?;
    let intent = root.join("state.archive.json");
    let Some(bytes) = read(&intent, MAX_STATE)? else {
        return Ok(false);
    };
    let terminal = decode_state(&bytes, identity)?;
    if !terminal.phase.terminal() {
        return Err(invalid());
    }
    let run = root.join(&terminal.update_id);
    ordinary(&run)?;
    platform::validate_private(&run).map_err(io)?;
    let archive = run.join("completed-state.json");
    let archived = read(&archive, MAX_STATE)?;
    if archived
        .as_ref()
        .is_some_and(|value| hash(value) != hash(&bytes))
    {
        return Err(invalid());
    }
    let mut slots = load_slots(root, identity)?;
    slots.push(StateSlot {
        path: intent.clone(),
        bytes: bytes.clone(),
        state: terminal,
    });
    slots.sort_by_key(|slot| slot.state.seq);
    validate_history(&slots)?;
    if slots
        .last()
        .is_none_or(|slot| hash(&slot.bytes) != hash(&bytes))
    {
        return Err(invalid());
    }
    let current = root.join("state.json");
    if archived.is_none() {
        // If an interrupted file move left only the intent, reconstruct only
        // this terminal archive. It can never become a live update again.
        match read(&current, MAX_STATE)? {
            Some(value) if hash(&value) == hash(&bytes) => {
                platform::move_new(&current, &archive).map_err(io)?;
            }
            Some(_) => return Err(invalid()),
            None => write_new(&archive, &bytes)?,
        }
        platform::sync_directory(root).map_err(io)?;
        platform::sync_directory(&run).map_err(io)?;
    }
    #[cfg(test)]
    fault(Fault::ArchivePublished)?;
    for slot in slots {
        deadline(end)?;
        if slot.path != intent {
            if slot.path == current && read(&current, MAX_STATE)?.is_none() {
                continue; // The terminal image was moved into its archive.
            }
            remove_matching(&slot.path, &slot.bytes, MAX_STATE)?;
        }
    }
    #[cfg(test)]
    fault(Fault::ArchiveCleaned)?;
    remove_matching(&intent, &bytes, MAX_STATE)?;
    Ok(true)
}
#[cfg(test)]
#[path = "update_state_tests.rs"]
mod tests;
