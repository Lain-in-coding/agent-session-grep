//! Durable, private installation side-effect journal. A phase is a claim about
//! verified effects, never permission to repeat an unacknowledged operation.
//! The caller must hold the installation OS lock for this prefix throughout.
use crate::{
    CliError,
    native_autostart::platform,
    package_installation::{RunningPackage, absolute, ordinary},
    protocol::{CanonicalCode, ProtocolError},
    update_check::MANAGED_TARGETS,
};
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity},
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
const MAX_SUPERSEDE: u64 = MAX_STATE * 5;
const SUPERSEDE_SCHEMA: &str = "asg.update-supersede/v1";

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
    SupersedeIntentStaged,
    SupersedeIntent,
    SupersedeStaged,
    SupersedePublished,
    SupersedeArchiveStaged,
    SupersedeArchived,
    SupersedeCleaned,
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

/// Why this worker may not publish a cross-cycle discovery epoch now. Exact
/// cycles and background liveness are unaffected by every value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EpochRefusal {
    /// This process did not verify itself as the installed package at startup.
    Unverified,
    /// An update owner holds the installation, or the caller's end passed.
    Busy,
    /// The prefix has no verified binding to this control installation.
    Unbound,
    /// The prefix, running image or package records changed after startup.
    Changed,
    /// The update journal is absent, unfinished or needs owner recovery.
    Unfinished,
    /// A terminal journal does not describe the running package.
    Mismatch,
}

/// The running package as the journal records it.
struct RunningIdentity {
    version: VersionIdentity,
    generation: u64,
    updated: bool,
    installation_id: String,
}

/// Decided once per worker lifetime. An older updater clears its fence and
/// starts the new worker before it journals Complete, so liveness alone is no
/// proof that the update finished.
pub(crate) enum EpochGate {
    Unverified,
    Installed(Box<RunningPackage>),
    /// Test-only developer fixture worker without an installed prefix.
    #[cfg(test)]
    Fixture,
    /// Test-only fixture that still contends on the real installation lock.
    #[cfg(test)]
    FixtureInstallation(PathBuf),
}

/// Held across one epoch commit, so no update owner can start meanwhile.
#[must_use = "hold the installation permit until the epoch commit finishes"]
pub(crate) struct EpochPermit {
    _lock: Option<ExclusiveGuard>,
}

impl EpochGate {
    /// Full package verification, once, at worker startup.
    pub(crate) fn at_startup() -> Self {
        RunningPackage::verify().map_or(Self::Unverified, |package| {
            Self::Installed(Box::new(package))
        })
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self::Fixture
    }

    #[cfg(test)]
    pub(crate) fn fixture_for_installation(prefix: PathBuf) -> Self {
        Self::FixtureInstallation(prefix)
    }

    /// One nonblocking lock attempt plus bounded reads; never waits or repairs
    /// the journal. The caller's original end also applies to test fixtures.
    pub(crate) fn permit(
        &self,
        control: &SqliteControlStore,
        end: Instant,
    ) -> Result<EpochPermit, EpochRefusal> {
        if Instant::now() >= end {
            return Err(EpochRefusal::Busy);
        }
        let package = match self {
            Self::Unverified => return Err(EpochRefusal::Unverified),
            #[cfg(test)]
            Self::Fixture => return Ok(EpochPermit { _lock: None }),
            #[cfg(test)]
            Self::FixtureInstallation(prefix) => {
                let guard = try_epoch_lock(prefix)?;
                if Instant::now() >= end {
                    return Err(EpochRefusal::Busy);
                }
                return Ok(EpochPermit { _lock: Some(guard) });
            }
            Self::Installed(package) => package,
        };
        let prefix = package.prefix();
        let guard = try_epoch_lock(prefix)?;
        if RootIdentity::read(prefix).map_err(|_| EpochRefusal::Changed)? != guard.root_identity() {
            return Err(EpochRefusal::Changed);
        }
        let installation_id = control
            .with_runtime_deadline(end, || control.bind_installation(prefix, &guard))
            .map(|binding| binding.installation_id().as_str().to_owned())
            .map_err(|error| match error {
                agent_session_grep_ports::PortError::WriterBusy(_) => EpochRefusal::Busy,
                _ => EpochRefusal::Unbound,
            })?;
        package.recheck().map_err(|_| EpochRefusal::Changed)?;
        let (pointer, release) = (package.pointer(), package.release());
        let running = RunningIdentity {
            version: VersionIdentity {
                version: pointer.version.clone(),
                target: release.target.clone(),
                source_commit: release.source_commit.clone(),
                relative_dir: pointer.dir.clone(),
                app_sha256: pointer.app_sha256.clone(),
                catalog_schema: release.catalog_schema.get(),
                control_schema: release.control_schema.get(),
                launcher_protocol: pointer.launcher_protocol,
            },
            generation: pointer.generation.get(),
            updated: package.updated(),
            installation_id,
        };
        journal_permits(prefix, &guard.root_identity(), &running)?;
        if Instant::now() >= end {
            return Err(EpochRefusal::Busy);
        }
        Ok(EpochPermit { _lock: Some(guard) })
    }
}

/// The update owner's own lock, attempted once. Contention is never awaited.
fn try_epoch_lock(prefix: &Path) -> Result<ExclusiveGuard, EpochRefusal> {
    let key = JobLockKey::parse("installation-update").map_err(|_| EpochRefusal::Unfinished)?;
    ExclusiveGuard::try_acquire(prefix, LockKind::MaintenanceJob(key)).map_err(
        |error| match error {
            agent_session_grep_ports::PortError::WriterBusy(_) => EpochRefusal::Busy,
            _ => EpochRefusal::Unfinished,
        },
    )
}

/// Names that exist at rest only while a write, supersede or archive is
/// unfinished. Their recovery belongs to the update owner, never to this check.
const EPOCH_RESIDUE: [&str; 5] = [
    "state.supersede.json",
    "state.supersede.intent.next.json",
    "state.supersede.next.json",
    "state.supersede.displaced.json",
    "state.archive.json",
];

/// Read-only: no Journal::open, reconcile or write, and every read is bounded.
/// Only a terminal journal that names the running package permits an epoch.
fn journal_permits(
    prefix: &Path,
    identity: &RootIdentity,
    running: &RunningIdentity,
) -> Result<(), EpochRefusal> {
    let unfinished = |_: CliError| EpochRefusal::Unfinished;
    let root = prefix.join("update");
    match fs::symlink_metadata(&root) {
        // Journal::create makes this directory before any update effect.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if !running.updated && running.generation == 1 {
                Ok(())
            } else {
                Err(EpochRefusal::Mismatch)
            };
        }
        Err(_) => return Err(EpochRefusal::Unfinished),
        Ok(_) => {}
    }
    ordinary(&root).map_err(unfinished)?;
    platform::validate_private(&root).map_err(|_| EpochRefusal::Unfinished)?;
    for name in STATE_SLOTS.iter().skip(1).chain(EPOCH_RESIDUE.iter()) {
        match fs::symlink_metadata(root.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(EpochRefusal::Unfinished),
        }
    }
    let bytes = read(&root.join(STATE_SLOTS[0]), MAX_STATE)
        .map_err(unfinished)?
        .ok_or(EpochRefusal::Unfinished)?;
    let state = decode_state(&bytes, identity).map_err(unfinished)?;
    let run = root.join(&state.update_id);
    ordinary(&run).map_err(unfinished)?;
    platform::validate_private(&run).map_err(|_| EpochRefusal::Unfinished)?;
    if !state.phase.terminal() {
        return Err(EpochRefusal::Unfinished);
    }
    if state.checkpoint.installation_id != running.installation_id {
        return Err(EpochRefusal::Mismatch);
    }
    let selected = match state.phase {
        Phase::Complete if state.error_code.is_some() => return Err(EpochRefusal::Unfinished),
        Phase::Complete => (&state.new, state.new_pointer_generation),
        Phase::Failed | Phase::RolledBack => (&state.old, state.old_pointer_generation),
        _ => return Err(EpochRefusal::Mismatch),
    };
    if selected != (&running.version, running.generation) {
        return Err(EpochRefusal::Mismatch);
    }
    Ok(())
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
        recover_supersede(&root, &identity, end)?;
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

    /// Create a new journal while replacing one verified terminal journal.
    /// The prior state remains the active recovery record until the caller has
    /// completed every preflight check and this method is ready to create the
    /// new journal. If creation fails before publishing any state slot, restore
    /// the exact archived terminal bytes rather than leaving update status with
    /// no journal to inspect.
    pub(crate) fn create_after_terminal(
        prefix: &Path,
        guard: &'a ExclusiveGuard,
        mut state: State,
        end: Instant,
    ) -> Result<Self, CliError> {
        let (prefix, root, identity, directory) = Self::root(prefix, guard, true)?;
        recover_supersede(&root, &identity, end)?;
        recover_archive(&root, &identity, end)?;
        let current = root.join("state.json");
        match fs::symlink_metadata(&current) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self::create(&prefix, guard, state, end);
            }
            Ok(_) => {}
            Err(error) => return Err(io(error)),
        }

        let old_bytes = {
            let journal = Self::open(&prefix, guard, end)?;
            if !journal.state.phase.terminal() {
                return Err(invalid());
            }
            read(&current, MAX_STATE)?.ok_or_else(invalid)?
        };
        state.seq = 1;
        state.prefix_binding = identity.control_id().as_str().into();
        state.validate()?;
        supersede_terminal(&root, &identity, &old_bytes, &state, end)?;
        if read(&current, MAX_STATE)?.as_ref().map(|bytes| hash(bytes))
            != Some(hash(&serde_json::to_vec(&state).map_err(io)?))
        {
            return Err(invalid());
        }
        ordinary(&root.join(&state.update_id))?;
        platform::validate_private(&root.join(&state.update_id)).map_err(io)?;
        Ok(Self {
            prefix,
            root,
            identity,
            directory,
            _lock: guard,
            durable: state.clone(),
            state,
            poisoned: false,
        })
    }

    pub(crate) fn open(
        prefix: &Path,
        guard: &'a ExclusiveGuard,
        end: Instant,
    ) -> Result<Self, CliError> {
        deadline(end)?;
        let (prefix, root, identity, directory) = Self::root(prefix, guard, false)?;
        recover_supersede(&root, &identity, end)?;
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
    #[cfg(test)]
    pub(crate) fn archive_terminal(
        prefix: &Path,
        guard: &'a ExclusiveGuard,
        end: Instant,
    ) -> Result<(), CliError> {
        deadline(end)?;
        let (_, root, identity, _) = Self::root(prefix, guard, false)?;
        recover_supersede(&root, &identity, end)?;
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
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SupersedeIntent {
    schema: String,
    old_update_id: String,
    new_update_id: String,
    old_sha256: String,
    new_sha256: String,
    old_bytes_hex: String,
    new_bytes_hex: String,
}
fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}
fn decode_bytes_hex(value: &str) -> Result<Vec<u8>, CliError> {
    if !value.len().is_multiple_of(2) || !hex(value, value.len()) {
        return Err(invalid());
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
            u8::from_str_radix(text, 16).map_err(|_| invalid())
        })
        .collect()
}
fn supersede_intent_path(root: &Path) -> PathBuf {
    root.join("state.supersede.json")
}
fn supersede_intent_next_path(root: &Path) -> PathBuf {
    root.join("state.supersede.intent.next.json")
}
fn supersede_next_path(root: &Path) -> PathBuf {
    root.join("state.supersede.next.json")
}
fn supersede_displaced_path(root: &Path) -> PathBuf {
    root.join("state.supersede.displaced.json")
}
fn supersede_archive_path(old_run: &Path) -> PathBuf {
    old_run.join("completed-state.json")
}
fn supersede_archive_next_path(old_run: &Path) -> PathBuf {
    old_run.join("completed-state.next.json")
}
/// These names are private transaction staging slots. They never contain the
/// authoritative active journal, so an incomplete write can be discarded only
/// after `read` has established the occupied slot is one regular private file.
fn remove_owned_stage(path: &Path, limit: u64) -> Result<(), CliError> {
    if read(path, limit)?.is_none() {
        return Ok(());
    }
    fs::remove_file(path).map_err(io)?;
    platform::sync_directory(path.parent().ok_or_else(invalid)?).map_err(io)
}
fn recover_supersede_intent_stage(root: &Path) -> Result<(), CliError> {
    let intent = supersede_intent_path(root);
    let next = supersede_intent_next_path(root);
    match fs::symlink_metadata(&intent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            remove_owned_stage(&next, MAX_SUPERSEDE)
        }
        Ok(_) => {
            if fs::symlink_metadata(&next).is_ok() {
                return Err(invalid());
            }
            Ok(())
        }
        Err(error) => Err(io(error)),
    }
}
fn decode_supersede(
    root: &Path,
    identity: &RootIdentity,
) -> Result<Option<DecodedSupersede>, CliError> {
    recover_supersede_intent_stage(root)?;
    let Some(bytes) = read(&supersede_intent_path(root), MAX_SUPERSEDE)? else {
        return Ok(None);
    };
    let intent: SupersedeIntent = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if intent.schema != SUPERSEDE_SCHEMA
        || intent.old_update_id == intent.new_update_id
        || !valid_id(&intent.old_update_id)
        || !valid_id(&intent.new_update_id)
    {
        return Err(invalid());
    }
    let old_bytes = decode_bytes_hex(&intent.old_bytes_hex)?;
    let new_bytes = decode_bytes_hex(&intent.new_bytes_hex)?;
    if old_bytes.len() as u64 > MAX_STATE
        || new_bytes.len() as u64 > MAX_STATE
        || hash(&old_bytes) != intent.old_sha256
        || hash(&new_bytes) != intent.new_sha256
    {
        return Err(invalid());
    }
    let old = decode_state(&old_bytes, identity)?;
    let new_state = decode_state(&new_bytes, identity)?;
    if !old.phase.terminal()
        || old.update_id != intent.old_update_id
        || new_state.update_id != intent.new_update_id
        || new_state.seq != 1
    {
        return Err(invalid());
    }
    Ok(Some(DecodedSupersede {
        intent,
        old_bytes,
        new_bytes,
        old,
    }))
}

struct DecodedSupersede {
    intent: SupersedeIntent,
    old_bytes: Vec<u8>,
    new_bytes: Vec<u8>,
    old: State,
}
fn remove_optional_matching(path: &Path, expected: &[u8]) -> Result<(), CliError> {
    match read(path, MAX_STATE)? {
        Some(actual) if hash(&actual) == hash(expected) => {
            remove_matching(path, &actual, MAX_STATE)
        }
        Some(_) => Err(invalid()),
        None => Ok(()),
    }
}
fn remove_empty_supersede_run(root: &Path, update_id: &str) -> Result<(), CliError> {
    let run = root.join(update_id);
    match fs::symlink_metadata(&run) {
        Ok(_) => {
            ordinary(&run)?;
            platform::validate_private(&run).map_err(io)?;
            if fs::read_dir(&run).map_err(io)?.next().is_some() {
                return Err(invalid());
            }
            fs::remove_dir(&run).map_err(io)?;
            platform::sync_directory(root).map_err(io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(error)),
    }
}
fn ensure_supersede_archive(old_run: &Path, old_bytes: &[u8]) -> Result<(), CliError> {
    let archive = supersede_archive_path(old_run);
    let next = supersede_archive_next_path(old_run);
    match read(&archive, MAX_STATE)? {
        Some(existing) if hash(&existing) == hash(old_bytes) => {
            remove_owned_stage(&next, MAX_STATE)
        }
        Some(_) => Err(invalid()),
        None => {
            remove_owned_stage(&next, MAX_STATE)?;
            write_new(&next, old_bytes)?;
            #[cfg(test)]
            fault(Fault::SupersedeArchiveStaged)?;
            platform::move_new(&next, &archive).map_err(io)?;
            platform::sync_directory(old_run).map_err(io)
        }
    }
}
/// The active state name never disappears during supersession. A durable intent
/// owns the staged new image and the exact old image; recovery either aborts
/// before publication or completes the archive after publication.
fn recover_supersede(root: &Path, identity: &RootIdentity, end: Instant) -> Result<(), CliError> {
    let Some(DecodedSupersede {
        intent,
        old_bytes,
        new_bytes,
        old,
    }) = decode_supersede(root, identity)?
    else {
        return Ok(());
    };
    deadline(end)?;
    let current = root.join("state.json");
    let current_bytes = read(&current, MAX_STATE)?.ok_or_else(invalid)?;
    match hash(&current_bytes) {
        value if value == hash(&old_bytes) => {
            // A process can stop while writing the non-authoritative new-state
            // staging slot. The exact old state is still active, so discard the
            // owned slot and abandon the unpublished transaction.
            remove_owned_stage(&supersede_next_path(root), MAX_STATE)?;
            remove_optional_matching(&supersede_displaced_path(root), &old_bytes)?;
            remove_empty_supersede_run(root, &intent.new_update_id)?;
            remove_matching(
                &supersede_intent_path(root),
                &serde_json::to_vec(&intent).map_err(io)?,
                MAX_SUPERSEDE,
            )?;
        }
        value if value == hash(&new_bytes) => {
            let run = root.join(&intent.new_update_id);
            ordinary(&run)?;
            platform::validate_private(&run).map_err(io)?;
            let old_run = root.join(&old.update_id);
            ordinary(&old_run)?;
            platform::validate_private(&old_run).map_err(io)?;
            // Unix exchange publishes the new active image before moving the
            // exchanged old image from `next` to `displaced`. Validate either
            // exact old-image slot, then finish the archive and clean both.
            match read(&supersede_next_path(root), MAX_STATE)? {
                Some(existing) if hash(&existing) == hash(&old_bytes) => {}
                Some(_) => return Err(invalid()),
                None => {}
            }
            ensure_supersede_archive(&old_run, &old_bytes)?;
            #[cfg(test)]
            fault(Fault::SupersedeArchived)?;
            remove_optional_matching(&supersede_next_path(root), &old_bytes)?;
            remove_optional_matching(&supersede_displaced_path(root), &old_bytes)?;
            remove_matching(
                &supersede_intent_path(root),
                &serde_json::to_vec(&intent).map_err(io)?,
                MAX_SUPERSEDE,
            )?;
        }
        _ => return Err(invalid()),
    }
    platform::sync_directory(root).map_err(io)
}
fn supersede_terminal(
    root: &Path,
    identity: &RootIdentity,
    old_bytes: &[u8],
    new_state: &State,
    end: Instant,
) -> Result<(), CliError> {
    deadline(end)?;
    let old = decode_state(old_bytes, identity)?;
    if !old.phase.terminal() {
        return Err(invalid());
    }
    new_state.validate()?;
    if new_state.prefix_binding != identity.control_id().as_str() || new_state.seq != 1 {
        return Err(invalid());
    }
    let new_bytes = serde_json::to_vec(new_state).map_err(io)?;
    let intent = SupersedeIntent {
        schema: SUPERSEDE_SCHEMA.into(),
        old_update_id: old.update_id.clone(),
        new_update_id: new_state.update_id.clone(),
        old_sha256: hash(old_bytes),
        new_sha256: hash(&new_bytes),
        old_bytes_hex: bytes_hex(old_bytes),
        new_bytes_hex: bytes_hex(&new_bytes),
    };
    let old_run = root.join(&old.update_id);
    ordinary(&old_run)?;
    platform::validate_private(&old_run).map_err(io)?;
    match read(&supersede_archive_path(&old_run), MAX_STATE)? {
        Some(existing) if hash(&existing) == hash(old_bytes) => {}
        Some(_) => return Err(invalid()),
        None => {}
    }
    let intent_bytes = serde_json::to_vec(&intent).map_err(io)?;
    write_new(&supersede_intent_next_path(root), &intent_bytes)?;
    #[cfg(test)]
    fault(Fault::SupersedeIntentStaged)?;
    platform::move_new(
        &supersede_intent_next_path(root),
        &supersede_intent_path(root),
    )
    .map_err(io)?;
    platform::sync_directory(root).map_err(io)?;
    #[cfg(test)]
    fault(Fault::SupersedeIntent)?;
    platform::create_private_directory(&root.join(&new_state.update_id)).map_err(io)?;
    write_new(&supersede_next_path(root), &new_bytes)?;
    #[cfg(test)]
    fault(Fault::SupersedeStaged)?;
    publish(
        &root.join("state.json"),
        &supersede_next_path(root),
        &supersede_displaced_path(root),
    )?;
    #[cfg(test)]
    fault(Fault::SupersedePublished)?;
    let actual = read(&root.join("state.json"), MAX_STATE)?.ok_or_else(invalid)?;
    if hash(&actual) != hash(&new_bytes) {
        return Err(invalid());
    }
    ensure_supersede_archive(&old_run, old_bytes)?;
    #[cfg(test)]
    fault(Fault::SupersedeArchived)?;
    remove_optional_matching(&supersede_next_path(root), &new_bytes)?;
    remove_optional_matching(&supersede_displaced_path(root), old_bytes)?;
    remove_matching(
        &supersede_intent_path(root),
        &serde_json::to_vec(&intent).map_err(io)?,
        MAX_SUPERSEDE,
    )?;
    platform::sync_directory(root).map_err(io)?;
    #[cfg(test)]
    fault(Fault::SupersedeCleaned)?;
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
