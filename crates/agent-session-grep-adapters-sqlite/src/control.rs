//! Separate, private control database. No catalog access and no implicit setup.
use crate::{
    managed_control_lifetime::ControlHandleLease,
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity},
};
use agent_session_grep_ports::{PortError, PortResult, SearchProvider, control::*};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const VERSION: i64 = 2;
/// Current private control schema. Keep VERSION literal for release source parsing.
pub const CONTROL_SCHEMA_VERSION: i64 = VERSION;
const LEGACY_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x41534331;
const BUSY_TIMEOUT: Duration = Duration::from_millis(250);
/// Diagnostic tail only. Every live source/confirmation/barrier reference is
/// loaded in addition, regardless of its age or originating worker boot.
const RUNTIME_HISTORY_TAIL: i64 = 64;
/// Capacity refusal never drops a live token or turns partial inventory into proof.
pub const MAX_RUNTIME_REFERENCES: usize = 16_384;
pub const MAX_RUNTIME_RELATIONS: usize = 65_536;

thread_local! {
    static RUNTIME_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
    static RUNTIME_BUSY_END: Cell<Option<Instant>> = const { Cell::new(None) };
    static RUNTIME_BUSY_ALLOWANCE: Cell<Duration> = const { Cell::new(BUSY_TIMEOUT) };
    static RUNTIME_COMMIT_SEQ: Cell<u64> = const { Cell::new(0) };
}

fn runtime_deadline() -> Option<Instant> {
    RUNTIME_DEADLINE.with(Cell::get)
}
fn runtime_commit_seq() -> u64 {
    RUNTIME_COMMIT_SEQ.with(Cell::get)
}
/// Record a durable mutation completed inside the current runtime scope.
/// Trailing deadline checks must not turn a committed change into a retryable
/// Busy result. A caller without a scope has no trailing runtime check to skip.
pub(crate) fn mark_runtime_committed() {
    if runtime_deadline().is_some() {
        RUNTIME_COMMIT_SEQ.with(|slot| slot.set(slot.get().wrapping_add(1)));
    }
}
fn runtime_tick() -> PortResult<()> {
    if runtime_deadline().is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(PortError::WriterBusy(
            "control runtime deadline reached".into(),
        ));
    }
    Ok(())
}
fn runtime_capacity() -> PortError {
    PortError::WriterBusy("control runtime dependency capacity exceeded".into())
}
struct RuntimeDeadlineScope {
    previous: Option<Instant>,
    previous_busy: Duration,
    entry_commit_seq: u64,
}
impl RuntimeDeadlineScope {
    fn enter(deadline: Instant) -> PortResult<Self> {
        Self::enter_with_busy(deadline, BUSY_TIMEOUT)
    }
    fn enter_with_busy(deadline: Instant, allowance: Duration) -> PortResult<Self> {
        let previous = runtime_deadline();
        let effective = previous.map_or(deadline, |current| current.min(deadline));
        if Instant::now() >= effective {
            return Err(PortError::WriterBusy(
                "control runtime deadline reached".into(),
            ));
        }
        let previous_busy = RUNTIME_BUSY_ALLOWANCE.with(|slot| {
            let prior = slot.get();
            slot.set(prior.min(allowance));
            prior
        });
        RUNTIME_DEADLINE.with(|slot| slot.set(Some(effective)));
        Ok(Self {
            previous,
            previous_busy,
            entry_commit_seq: runtime_commit_seq(),
        })
    }

    fn committed_since_entry(&self) -> bool {
        runtime_commit_seq() != self.entry_commit_seq
    }
}
impl Drop for RuntimeDeadlineScope {
    fn drop(&mut self) {
        RUNTIME_DEADLINE.with(|slot| slot.set(self.previous));
        RUNTIME_BUSY_ALLOWANCE.with(|slot| slot.set(self.previous_busy));
        RUNTIME_BUSY_END.with(|slot| slot.set(None));
    }
}
fn runtime_busy(attempt: i32) -> bool {
    let Some(deadline) = runtime_deadline() else {
        return false;
    };
    let now = Instant::now();
    let end = RUNTIME_BUSY_END.with(|slot| {
        if attempt == 0 || slot.get().is_none() {
            slot.set(Some(
                deadline.min(now + RUNTIME_BUSY_ALLOWANCE.with(Cell::get)),
            ));
        }
        slot.get().unwrap_or(deadline).min(deadline)
    });
    if now >= end {
        return false;
    }
    std::thread::sleep(Duration::from_millis(1).min(end.saturating_duration_since(now)));
    Instant::now() < end
}
fn configure_runtime_deadline(conn: &Connection) -> PortResult<()> {
    if runtime_deadline().is_some() {
        conn.busy_handler(Some(runtime_busy)).map_err(sql_error)?;
        conn.progress_handler(1000, Some(|| runtime_tick().is_err()))
            .map_err(sql_error)?;
    } else {
        conn.busy_timeout(BUSY_TIMEOUT).map_err(sql_error)?;
        conn.progress_handler(0, None::<fn() -> bool>)
            .map_err(sql_error)?;
    }
    Ok(())
}
struct RuntimeDeadlineReset<'a> {
    store: &'a SqliteControlStore,
    scope: Option<RuntimeDeadlineScope>,
}
impl RuntimeDeadlineReset<'_> {
    fn restore(&mut self) -> PortResult<()> {
        drop(self.scope.take());
        configure_runtime_deadline(&self.store.conn.borrow())
    }
}
impl Drop for RuntimeDeadlineReset<'_> {
    fn drop(&mut self) {
        if self.scope.is_some() {
            let _ = self.restore();
        }
    }
}

/// Shared name of the installation prefix's update/journal OS lock. The update
/// journal enforces the same key; maintenance cannot borrow an unrelated job lock.
pub const INSTALLATION_LOCK_KEY: &str = "installation-update";
/// Catalog backups live only below this private, control-root-relative prefix.
const BACKUP_LOCATOR_PREFIX: &str = "backups/";
const MAX_RELATIVE_LOCATOR: usize = 240;

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid control operation".into())
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("unsupported or corrupt control state".into())
}
fn conflict() -> PortError {
    PortError::GenerationMismatch("control state changed".into())
}
fn missing() -> PortError {
    PortError::NotFound("control state not found".into())
}

/// A short process-registry reservation can report Busy even for another
/// private root. Bound admission by the same existing SQLite busy allowance;
/// a real retirement holder still fails Busy, and no deadline proves drain.
fn admit_control_handle(root: &Path, create: bool) -> PortResult<ControlHandleLease> {
    let deadline = runtime_deadline().map_or(Instant::now() + BUSY_TIMEOUT, |end| {
        end.min(Instant::now() + BUSY_TIMEOUT)
    });
    runtime_tick()?;
    loop {
        runtime_tick()?;
        let result = if create {
            ControlHandleLease::try_acquire_for_create(root)
        } else {
            ControlHandleLease::try_acquire(root)
        };
        match result {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(2)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            other => return other,
        }
    }
}
fn io_error<E>(_: E) -> PortError {
    PortError::Backend("private control storage unavailable".into())
}
/// Internal diagnosis uses only fixed stages and numeric causes. Code zero
/// denotes an invariant refusal or an I/O error without an OS code. Never
/// format an OS error, path, SID, descriptor or caller-provided detail here.
fn private_validation_error(stage: &'static str, code: i32, sidecar: bool) -> PortError {
    PortError::Backend(format!(
        "private storage validation failed (stage={stage}, sidecar={}, code={code})",
        u8::from(sidecar),
    ))
}
fn private_validation_io(error: std::io::Error, stage: &'static str) -> PortError {
    private_validation_error(stage, error.raw_os_error().unwrap_or(0), false)
}
fn sql_error(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            PortError::WriterBusy("control storage is busy".into())
        }
        Some(rusqlite::ErrorCode::OperationInterrupted) => {
            PortError::WriterBusy("control runtime deadline reached".into())
        }
        _ => match error.sqlite_error() {
            // Numeric adapter diagnostics only: never relay SQLite's message,
            // SQL, paths, or bound values. Public surfaces keep their fixed
            // private-error projection; synthetic integration tests can inspect
            // the original typed error without installing a logging hook.
            Some(code) => PortError::SchemaIncompatible(format!(
                "control SQLite failure (sqlite_primary={}, sqlite_extended={})",
                code.extended_code & 0xff,
                code.extended_code,
            )),
            None => corrupt(),
        },
    }
}

fn sql_query_error(conn: &Connection, error: rusqlite::Error) -> PortError {
    #[cfg(windows)]
    if error
        .sqlite_error()
        .is_some_and(|code| code.extended_code == rusqlite::ffi::SQLITE_IOERR_TRUNCATE)
    {
        // SAFETY: conn owns the live connection that just returned this error.
        // Read SQLite's saved system errno, not unrelated thread GetLastError.
        let system = unsafe { rusqlite::ffi::sqlite3_system_errno(conn.handle()) };
        return sql_windows_query_error(error, system);
    }
    let _ = conn;
    sql_error(error)
}

#[cfg(windows)]
fn sql_windows_query_error(error: rusqlite::Error, system: i32) -> PortError {
    // Bundled SQLite's winLockSharedMemory may truncate SHM after obtaining
    // DMS while a departing process still maps it. Only the exact mapped-file
    // conflict is retryable; disk/ACL/corruption failures retain their category.
    if system == 1224
        && error
            .sqlite_error()
            .is_some_and(|code| code.extended_code == rusqlite::ffi::SQLITE_IOERR_TRUNCATE)
    {
        PortError::WriterBusy("control shared memory is still mapped".into())
    } else {
        sql_error(error)
    }
}

fn checked_time(value: i64) -> PortResult<()> {
    if value < 0 { Err(invalid()) } else { Ok(()) }
}
fn increment(value: i64) -> PortResult<i64> {
    value.checked_add(1).ok_or_else(corrupt)
}
fn id(value: String) -> PortResult<ControlId> {
    ControlId::parse(&value).map_err(|_| corrupt())
}
fn seq(value: i64) -> PortResult<ControlSeq> {
    ControlSeq::new(value).map_err(|_| corrupt())
}
fn epoch(value: i64) -> PortResult<PolicyEpoch> {
    PolicyEpoch::new(value).map_err(|_| corrupt())
}
fn boolean(value: i64) -> PortResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(corrupt()),
    }
}
fn provider(value: String) -> PortResult<SearchProvider> {
    SearchProvider::parse(&value)
        .filter(|p| p.as_str() == value)
        .ok_or_else(corrupt)
}

macro_rules! wire_enum {
    ($encode:ident, $decode:ident, $ty:ident, {$($variant:ident => $wire:literal),+ $(,)?}) => {
        fn $encode(value: $ty) -> &'static str { match value { $($ty::$variant => $wire),+ } }
        fn $decode(value: &str) -> PortResult<$ty> { match value { $($wire => Ok($ty::$variant)),+, _ => Err(corrupt()) } }
    };
}
wire_enum!(desired_wire, desired_decode, DesiredUpdates, {Running => "running", Paused => "paused", Stopped => "stopped"});
wire_enum!(kind_wire, kind_decode, RootKind, {Root => "root", Exact => "exact"});
wire_enum!(maintenance_wire, maintenance_decode, MaintenanceState, {Idle => "idle", Updating => "updating", Recovering => "recovering", Uninstalling => "uninstalling"});
wire_enum!(phase_wire, phase_decode, MaintenancePhase, {
    Downloaded => "downloaded", Verified => "verified", Quiescing => "quiescing", BackedUp => "backed_up",
    Staged => "staged", Migrated => "migrated", Switched => "switched", SelfChecked => "self_checked",
    Complete => "complete", Failed => "failed", RollbackPending => "rollback_pending", Reconciling => "reconciling",
    RolledBack => "rolled_back", Attention => "attention"
});

// Normative design section 3, independent of the catalog's user_version.
// Future slices must implement typed validators before populating reserved tables.
const SCHEMA: &str = r"
CREATE TABLE control_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
 installation_id TEXT NOT NULL, policy_epoch INTEGER NOT NULL, control_seq INTEGER NOT NULL,
 next_cycle_seq INTEGER NOT NULL, catalog_incarnation TEXT, restart_request_seq INTEGER NOT NULL DEFAULT 0,
 desired_updates TEXT NOT NULL CHECK(desired_updates IN ('running','paused','stopped')),
 autostart_enabled INTEGER NOT NULL CHECK(autostart_enabled IN (0,1)),
 maintenance_state TEXT NOT NULL CHECK(maintenance_state IN ('idle','updating','recovering','uninstalling')),
 maintenance_owner TEXT, maintenance_phase TEXT,
 supervisor_failed INTEGER NOT NULL DEFAULT 0 CHECK(supervisor_failed IN (0,1))
);
CREATE TABLE selections (
 selection_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, canonical_locator TEXT NOT NULL,
 root_kind TEXT NOT NULL CHECK(root_kind IN ('root','exact')), root_identity TEXT,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), revision INTEGER NOT NULL,
 created_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER
);
CREATE TABLE exclusions (
 exclusion_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, canonical_locator TEXT,
 region_kind TEXT NOT NULL CHECK(region_kind IN ('root','exact','source_identity')),
 source_id TEXT, revision INTEGER NOT NULL, created_policy_epoch INTEGER NOT NULL,
 created_at_ms INTEGER NOT NULL
);
CREATE TABLE worker_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), boot_id TEXT, pid_hint INTEGER,
 heartbeat_at_ms INTEGER, effective_state TEXT NOT NULL, last_error TEXT
);
CREATE TABLE source_updates (
 source_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, last_attempt_at_ms INTEGER,
 last_observed_cycle INTEGER, indexed_revision TEXT, receipt_cycle INTEGER,
 catalog_incarnation TEXT, catalog_generation INTEGER,
 coverage TEXT NOT NULL, update_state TEXT NOT NULL, error_code TEXT,
 backfill_state TEXT NOT NULL, missing_first_cycle INTEGER, missing_confirm_cycle INTEGER,
 confirmation_boot_id TEXT, confirmation_root_identity TEXT, confirmation_policy_epoch INTEGER,
 rewrite_candidate_digest TEXT, rewrite_first_cycle INTEGER, rewrite_confirm_cycle INTEGER,
 confirmation_first_monotonic_ms INTEGER
);
CREATE TABLE cycles (
 cycle_seq INTEGER PRIMARY KEY, worker_boot_id TEXT, policy_epoch INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','observing','committed','partial','aborted')),
 admitted_control_seq INTEGER NOT NULL, started_control_seq INTEGER,
 started_at_ms INTEGER, completed_at_ms INTEGER
);
CREATE TABLE cycle_selections (
 cycle_seq INTEGER NOT NULL, selection_id TEXT NOT NULL, selection_revision INTEGER NOT NULL,
 discovery_complete INTEGER NOT NULL DEFAULT 0, root_identity TEXT,
 discovered_count INTEGER NOT NULL DEFAULT 0, observed_count INTEGER NOT NULL DEFAULT 0,
 committed_count INTEGER NOT NULL DEFAULT 0, error_code TEXT,
 PRIMARY KEY(cycle_seq,selection_id)
);
CREATE TABLE barriers (
 barrier_id TEXT PRIMARY KEY, policy_epoch INTEGER NOT NULL, admission_control_seq INTEGER NOT NULL,
 required_cycle_seq INTEGER NOT NULL, state TEXT NOT NULL,
 requested_wait_ms INTEGER NOT NULL, admitted_at_ms INTEGER NOT NULL,
 completed_cycle_seq INTEGER, catalog_incarnation TEXT, error_code TEXT
);
CREATE TABLE barrier_selections (
 barrier_id TEXT NOT NULL, selection_id TEXT NOT NULL, selection_revision INTEGER NOT NULL,
 PRIMARY KEY(barrier_id,selection_id)
);
CREATE TABLE revocation_intents (
 intent_id TEXT PRIMARY KEY, policy_epoch INTEGER NOT NULL UNIQUE, owner_nonce TEXT,
 state TEXT NOT NULL CHECK(state IN ('awaiting_drain','settled')),
 created_at_ms INTEGER NOT NULL, settled_at_ms INTEGER
);
CREATE TABLE purge_jobs (
 job_id TEXT PRIMARY KEY, policy_epoch INTEGER NOT NULL, selection_id TEXT,
 selection_revision INTEGER, state TEXT NOT NULL CHECK(state IN ('pending','claims','artifacts','verifying','complete','blocked')),
 progress_key TEXT, owner_nonce TEXT, attempts INTEGER NOT NULL DEFAULT 0,
 last_error TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
 UNIQUE(policy_epoch,selection_id,selection_revision)
);
CREATE TABLE private_artifacts (
 artifact_id TEXT PRIMARY KEY, kind TEXT NOT NULL, relative_locator TEXT NOT NULL,
 policy_epoch INTEGER NOT NULL, owner_nonce TEXT, state TEXT NOT NULL, digest TEXT
);
CREATE TABLE artifact_sources (
 artifact_id TEXT NOT NULL, source_id TEXT NOT NULL, PRIMARY KEY(artifact_id,source_id)
);
CREATE TABLE backup_manifests (
 backup_id TEXT PRIMARY KEY, purpose TEXT NOT NULL, relative_locator TEXT NOT NULL,
 catalog_incarnation TEXT NOT NULL, catalog_generation INTEGER NOT NULL,
 schema_version INTEGER NOT NULL, digest TEXT NOT NULL, size_bytes INTEGER NOT NULL,
 state TEXT NOT NULL, created_at_ms INTEGER NOT NULL
);
CREATE TABLE backup_sources (
 backup_id TEXT NOT NULL, source_id TEXT NOT NULL, PRIMARY KEY(backup_id,source_id)
);
CREATE TABLE update_receipts (
 update_id TEXT PRIMARY KEY, phase TEXT NOT NULL, from_version TEXT NOT NULL,
 to_version TEXT NOT NULL, target TEXT NOT NULL, source_commit TEXT NOT NULL,
 archive_digest TEXT NOT NULL, manifest_digest TEXT NOT NULL, backup_id TEXT,
 schema_before INTEGER, schema_after INTEGER, generation_before INTEGER, generation_after INTEGER,
 error_code TEXT, started_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, completed_at_ms INTEGER
);
";

const RUNTIME_INDEXES: &str = r"
CREATE INDEX cycles_runtime_state ON cycles(state,cycle_seq);
CREATE INDEX barriers_runtime_state ON barriers(state,barrier_id);
CREATE INDEX barriers_runtime_admission ON barriers(admission_control_seq DESC,barrier_id);
";

const RESERVED_TABLES: &[&str] = &["update_receipts"];

/// Typed classification for private maintenance artifacts. Unknown values fail
/// closed; they never default to a usable backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    CatalogBackup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Registered,
    Complete,
    Quarantined,
    PurgedByPolicy,
}

impl ArtifactState {
    fn wire(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Complete => "complete",
            Self::Quarantined => "quarantined",
            Self::PurgedByPolicy => "purged_by_policy",
        }
    }
    fn decode(value: &str) -> PortResult<Self> {
        match value {
            "registered" => Ok(Self::Registered),
            "complete" => Ok(Self::Complete),
            "quarantined" => Ok(Self::Quarantined),
            "purged_by_policy" => Ok(Self::PurgedByPolicy),
            _ => Err(corrupt()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupPurpose {
    BetaRollback,
}

impl BackupPurpose {
    fn wire(self) -> &'static str {
        match self {
            Self::BetaRollback => "beta_rollback",
        }
    }
    fn decode(value: &str) -> PortResult<Self> {
        match value {
            "beta_rollback" => Ok(Self::BetaRollback),
            _ => Err(corrupt()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    Registered,
    Complete,
    Quarantined,
    PurgedByPolicy,
}

impl BackupState {
    fn wire(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Complete => "complete",
            Self::Quarantined => "quarantined",
            Self::PurgedByPolicy => "purged_by_policy",
        }
    }
    fn decode(value: &str) -> PortResult<Self> {
        match value {
            "registered" => Ok(Self::Registered),
            "complete" => Ok(Self::Complete),
            "quarantined" => Ok(Self::Quarantined),
            "purged_by_policy" => Ok(Self::PurgedByPolicy),
            _ => Err(corrupt()),
        }
    }
    pub fn restorable(self) -> bool {
        self == Self::Complete
    }
}

/// One verified catalog source covered by a backup. Locators stay private; this
/// typed value exists only to re-evaluate the current control policy, which is
/// the sole permission authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredSource {
    pub source_id: ControlId,
    pub provider: SearchProvider,
    pub locator: CanonicalLocator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifact {
    pub artifact_id: ControlId,
    pub kind: ArtifactKind,
    pub relative_locator: String,
    pub policy_epoch: PolicyEpoch,
    pub owner_nonce: Option<ControlId>,
    pub state: ArtifactState,
    pub digest: Option<String>,
    pub source_ids: Vec<ControlId>,
}

/// Control-side backup manifest. The artifact bytes and the sidecar manifest are
/// private; only this typed record is exported for journal composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBackup {
    pub backup_id: ControlId,
    pub purpose: BackupPurpose,
    pub relative_locator: String,
    pub catalog_incarnation: ControlId,
    pub catalog_generation: u64,
    pub schema_version: u32,
    pub digest: Option<String>,
    pub size_bytes: u64,
    pub state: BackupState,
    pub created_at_ms: i64,
    pub source_ids: Vec<ControlId>,
}

/// Durable registration intent, written before any backup content exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRegistration {
    pub backup_id: ControlId,
    pub purpose: BackupPurpose,
    pub relative_locator: String,
    pub catalog_incarnation: ControlId,
    pub catalog_generation: u64,
    pub schema_version: u32,
    pub source_ids: Vec<ControlId>,
}

const PREFIX_BINDING_FILE: &str = "installation-prefix.json";
const MAX_PREFIX_BINDING_BYTES: u64 = 4096;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InstallationPrefixBinding {
    schema: String,
    installation_id: String,
    control_root_id: String,
    prefix_root_id: String,
}

/// Actual installation-prefix OS lock ownership. A journal nonce, PID or
/// timestamp cannot produce this capability.
pub struct InstallationLockAuthority<'a> {
    guard: &'a ExclusiveGuard,
    prefix: PathBuf,
    identity: RootIdentity,
    installation: ControlId,
    control_root: RootIdentity,
}

impl InstallationLockAuthority<'_> {
    pub fn installation_id(&self) -> &ControlId {
        &self.installation
    }
    pub(crate) fn validate(&self, store: &SqliteControlStore) -> PortResult<()> {
        store.validate_live_root()?;
        if self.control_root != store.root_identity
            || self.guard.kind()
                != &LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY)?)
            || self.guard.root_identity() != self.identity
            || RootIdentity::read(&self.prefix)? != self.identity
            || store.status()?.policy.installation_id != self.installation
        {
            return Err(invalid());
        }
        store.verify_installation_prefix(self.identity, &self.installation)?;
        Ok(())
    }
}

/// Native purge uses the existing keyed maintenance-lock domain. This lock
/// never grants installation update or worker authority.
pub const PURGE_LOCK_KEY: &str = "owned-purge";

/// Borrowed, root-bound proof of the actual exclusive purge OS lock. A nonce,
/// age or persisted job owner alone cannot construct this capability.
pub struct PurgeOwner<'a> {
    guard: &'a ExclusiveGuard,
    root: RootIdentity,
    installation: ControlId,
    nonce: ControlId,
}
impl PurgeOwner<'_> {
    pub fn nonce(&self) -> &ControlId {
        &self.nonce
    }
    pub(crate) fn validate(&self, store: &SqliteControlStore) -> PortResult<()> {
        store.validate_live_root()?;
        if self.root != store.root_identity
            || self.guard.root_identity() != self.root
            || self.guard.kind() != &LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY)?)
            || store.status()?.policy.installation_id != self.installation
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeCheckpoint {
    Claimed,
    CatalogCommitted,
    CacheRetired,
    ArtifactsVerified,
}
impl PurgeCheckpoint {
    fn wire(self) -> &'static str {
        match self {
            Self::Claimed => "asg.purge/v1:claimed",
            Self::CatalogCommitted => "asg.purge/v1:catalog_committed",
            Self::CacheRetired => "asg.purge/v1:cache_retired",
            Self::ArtifactsVerified => "asg.purge/v1:artifacts_verified",
        }
    }
    fn decode(value: &str) -> PortResult<Self> {
        match value {
            "asg.purge/v1:claimed" => Ok(Self::Claimed),
            "asg.purge/v1:catalog_committed" => Ok(Self::CatalogCommitted),
            "asg.purge/v1:cache_retired" => Ok(Self::CacheRetired),
            "asg.purge/v1:artifacts_verified" => Ok(Self::ArtifactsVerified),
            _ => Err(corrupt()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeFailure {
    Busy,
    Deadline,
    PolicyChanged,
    UnclassifiedCatalog,
    UnclassifiedArtifact,
    BackupAuthorityMissing,
    ArtifactPending,
    CachePending,
    Storage,
}
impl PurgeFailure {
    fn wire(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Deadline => "deadline",
            Self::PolicyChanged => "policy_changed",
            Self::UnclassifiedCatalog => "unclassified_catalog",
            Self::UnclassifiedArtifact => "unclassified_artifact",
            Self::BackupAuthorityMissing => "backup_authority_missing",
            Self::ArtifactPending => "artifact_pending",
            Self::CachePending => "cache_pending",
            Self::Storage => "storage",
        }
    }
    fn decode(value: &str) -> PortResult<Self> {
        match value {
            "busy" => Ok(Self::Busy),
            "deadline" => Ok(Self::Deadline),
            "policy_changed" => Ok(Self::PolicyChanged),
            "unclassified_catalog" => Ok(Self::UnclassifiedCatalog),
            "unclassified_artifact" => Ok(Self::UnclassifiedArtifact),
            "backup_authority_missing" => Ok(Self::BackupAuthorityMissing),
            "artifact_pending" => Ok(Self::ArtifactPending),
            "cache_pending" => Ok(Self::CachePending),
            "storage" => Ok(Self::Storage),
            _ => Err(corrupt()),
        }
    }
}

/// Runner-only progress carried under the exact verified policy budget.
pub(crate) struct PurgeTransition {
    pub state: PurgeState,
    pub checkpoint: PurgeCheckpoint,
    pub failure: Option<PurgeFailure>,
    pub verified_epoch: PolicyEpoch,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeJobStatus {
    pub job: PurgeJob,
    pub owner_nonce: Option<ControlId>,
    pub checkpoint: Option<PurgeCheckpoint>,
    pub failure: Option<PurgeFailure>,
}

/// Short-lived exclusive proof for control-root mutations. It is deliberately
/// not the maintenance fence and must not be held across a drain/wait.
pub struct ControlRootGuard<'a> {
    guard: &'a ExclusiveGuard,
    identity: RootIdentity,
}

impl ControlRootGuard<'_> {
    pub(crate) fn validate(&self, store: &SqliteControlStore) -> PortResult<()> {
        store.validate_live_root()?;
        if self.guard.kind() != &LockKind::PolicyOwner
            || self.guard.root_identity() != self.identity
            || store.root_identity != self.identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Private policy store. `create` is explicit setup, never a read fallback.
pub struct SqliteControlStore {
    conn: RefCell<Connection>,
    // Rust drops fields in declaration order: SQLite closes before the
    // independently held OS lease can admit terminal retirement.
    handle_lease: ControlHandleLease,
    writable: bool,
    root_identity: RootIdentity,
    private_root: PathBuf,
}

/// Borrowed proof of the real worker lock for this physical control root.
/// Neither the database connection nor its independently owned OS guard can
/// close while the capability is used. A boot ID alone grants no authority.
pub struct LockedWorkerAuthority<'a> {
    store: &'a SqliteControlStore,
    guard: &'a ExclusiveGuard,
    installation: ControlId,
    boot: ControlId,
}

impl LockedWorkerAuthority<'_> {
    pub(crate) fn is_bound_to(&self, store: &SqliteControlStore) -> bool {
        self.store.root_identity == store.root_identity
    }
}

impl WorkerAuthority for LockedWorkerAuthority<'_> {
    fn installation_id(&self) -> &ControlId {
        &self.installation
    }

    fn boot_id(&self) -> &ControlId {
        &self.boot
    }

    fn root_binding(&self) -> PhysicalRootBinding {
        self.guard.root_identity().binding()
    }

    fn validate(&self) -> PortResult<()> {
        self.store.validate_guard(self.guard, LockKind::Background)
    }
}

impl SqliteControlStore {
    /// Read the earliest request end already active on this thread. This only
    /// coordinates caller-owned retries before a control instance is opened;
    /// it grants no SQL, filesystem, worker or maintenance authority.
    pub fn effective_runtime_deadline(requested: Instant) -> Instant {
        runtime_deadline().map_or(requested, |current| current.min(requested))
    }

    /// Scope every control SQL statement and typed row decode to the original
    /// caller deadline. Nested scopes may shorten it, never extend it. Handler
    /// restoration also occurs on error/unwind; this grants no worker authority.
    pub fn with_runtime_deadline<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> PortResult<T>,
    ) -> PortResult<T> {
        let scope = RuntimeDeadlineScope::enter(deadline)?;
        let entry_commit_seq = scope.entry_commit_seq;
        let mut reset = RuntimeDeadlineReset {
            store: self,
            scope: Some(scope),
        };
        configure_runtime_deadline(&self.conn.borrow())?;
        let result = operation().and_then(|value| {
            if runtime_commit_seq() == entry_commit_seq {
                runtime_tick()?;
            }
            Ok(value)
        });
        let restored = reset.restore();
        match (result, restored) {
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    pub fn open_current_read_only_with_deadline(
        root: &Path,
        deadline: Instant,
    ) -> PortResult<Self> {
        Self::open_existing_with_deadline(root, None, false, deadline)
    }
    pub fn open_existing_writable_with_deadline(
        root: &Path,
        installation: &ControlId,
        deadline: Instant,
    ) -> PortResult<Self> {
        Self::open_existing_with_deadline(root, Some(installation), true, deadline)
    }
    fn open_existing_with_deadline(
        root: &Path,
        installation: Option<&ControlId>,
        writable: bool,
        deadline: Instant,
    ) -> PortResult<Self> {
        let scope = RuntimeDeadlineScope::enter(deadline)?;
        let result = Self::open_existing(root, installation, writable).and_then(|store| {
            if !scope.committed_since_entry() {
                runtime_tick()?;
            }
            Ok(store)
        });
        drop(scope);
        if let Ok(store) = &result {
            configure_runtime_deadline(&store.conn.borrow())?;
        }
        result
    }

    pub fn path(private_root: &Path) -> PathBuf {
        private_root.join("control.db")
    }

    /// Private data root. Never part of a public protocol projection.
    pub(crate) fn private_root(&self) -> &Path {
        &self.private_root
    }

    /// Borrow the real installation-prefix OS lock. The returned capability is
    /// valid only while the independently owned guard stays alive and the
    /// prefix still resolves to the same physical directory.
    pub fn bind_installation<'a>(
        &self,
        prefix: &Path,
        guard: &'a ExclusiveGuard,
    ) -> PortResult<InstallationLockAuthority<'a>> {
        self.validate_live_root()?;
        if guard.kind() != &LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY)?) {
            return Err(invalid());
        }
        let prefix = fs::canonicalize(prefix).map_err(io_error)?;
        let identity = RootIdentity::read(&prefix)?;
        if guard.root_identity() != identity {
            return Err(invalid());
        }
        let installation = self.status()?.policy.installation_id;
        self.verify_installation_prefix(identity, &installation)?;
        Ok(InstallationLockAuthority {
            guard,
            prefix,
            identity,
            installation,
            control_root: self.root_identity,
        })
    }

    /// Record the physical prefix only from a package-verified setup caller.
    /// Recovery/bind_installation never creates this association. The real
    /// prefix lock and same-root policy guard are required, maintenance must
    /// be idle, and an existing association can never be silently rebound.
    pub fn record_verified_installation_prefix(
        &self,
        prefix: &Path,
        installation_lock: &ExclusiveGuard,
        control: &ControlRootGuard<'_>,
        deadline: Instant,
    ) -> PortResult<()> {
        if Instant::now() >= deadline {
            return Err(PortError::WriterBusy(
                "installation binding deadline reached".into(),
            ));
        }
        control.validate(self)?;
        if !self.writable
            || installation_lock.kind()
                != &LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY)?)
        {
            return Err(invalid());
        }
        reject_links(prefix)?;
        let identity = RootIdentity::read(prefix)?;
        if installation_lock.root_identity() != identity {
            return Err(invalid());
        }
        let status = self.status()?;
        if status.policy.maintenance.state != MaintenanceState::Idle {
            return Err(invalid());
        }
        let expected = self.prefix_binding(identity, &status.policy.installation_id);
        let path = self.private_root.join(PREFIX_BINDING_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                self.verify_installation_prefix(identity, &status.policy.installation_id)?;
                if Instant::now() >= deadline {
                    return Err(PortError::WriterBusy(
                        "installation binding deadline reached".into(),
                    ));
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        if Instant::now() >= deadline {
            return Err(PortError::WriterBusy(
                "installation binding deadline reached".into(),
            ));
        }
        // First association is an explicit setup side effect, never a fallback
        // during recovery. Flush its private typed receipt before returning.
        let bytes = serde_json::to_vec(&expected).map_err(io_error)?;
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(io_error)?
        };
        #[cfg(windows)]
        let mut file = windows_private::create_file(&path)?;
        #[cfg(not(any(unix, windows)))]
        return Err(io_error(()));
        use std::io::Write;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        #[cfg(unix)]
        fs::File::open(&self.private_root)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        self.verify_installation_prefix(identity, &status.policy.installation_id)?;
        if Instant::now() >= deadline {
            return Err(PortError::WriterBusy(
                "installation binding deadline reached".into(),
            ));
        }
        Ok(())
    }

    fn prefix_binding(
        &self,
        prefix: RootIdentity,
        installation: &ControlId,
    ) -> InstallationPrefixBinding {
        InstallationPrefixBinding {
            schema: "asg.installation-prefix/v1".into(),
            installation_id: installation.as_str().into(),
            control_root_id: self.root_identity.control_id().as_str().into(),
            prefix_root_id: prefix.control_id().as_str().into(),
        }
    }

    fn verify_installation_prefix(
        &self,
        prefix: RootIdentity,
        installation: &ControlId,
    ) -> PortResult<()> {
        let path = self.private_root.join(PREFIX_BINDING_FILE);
        let mut file = self.open_private_read(&path)?;
        let before = file.metadata().map_err(io_error)?;
        if before.len() > MAX_PREFIX_BINDING_BYTES {
            return Err(corrupt());
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_PREFIX_BINDING_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 > MAX_PREFIX_BINDING_BYTES || bytes.len() as u64 != before.len() {
            return Err(corrupt());
        }
        self.validate_private_read(&path, &file)?;
        let binding: InstallationPrefixBinding =
            serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        if binding != self.prefix_binding(prefix, installation) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrow the control root's policy-owner lock for one short mutation.
    pub fn bind_control_root<'a>(
        &self,
        guard: &'a ExclusiveGuard,
    ) -> PortResult<ControlRootGuard<'a>> {
        self.validate_live_root()?;
        if guard.kind() != &LockKind::PolicyOwner || guard.root_identity() != self.root_identity {
            return Err(invalid());
        }
        Ok(ControlRootGuard {
            guard,
            identity: self.root_identity,
        })
    }

    /// Run a purge with the original SQL budget. RefCell makes this scope
    /// connection-local; it does not serialize independent policy writers.
    /// A 1ms busy allowance cannot grow again after time was spent in drain or
    /// file I/O. Long SQL uses the same monotonic interruption deadline.
    pub(crate) fn with_purge_deadline<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> PortResult<T>,
    ) -> PortResult<T> {
        let scope = RuntimeDeadlineScope::enter_with_busy(deadline, Duration::from_millis(1))?;
        let entry_commit_seq = scope.entry_commit_seq;
        let mut reset = RuntimeDeadlineReset {
            store: self,
            scope: Some(scope),
        };
        configure_runtime_deadline(&self.conn.borrow())?;
        let result = operation().and_then(|value| {
            if runtime_commit_seq() == entry_commit_seq {
                runtime_tick()?;
            }
            Ok(value)
        });
        let restored = reset.restore();
        match (result, restored) {
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    pub fn bind_purge_owner<'a>(
        &self,
        guard: &'a ExclusiveGuard,
        nonce: ControlId,
    ) -> PortResult<PurgeOwner<'a>> {
        self.validate_live_root()?;
        if guard.root_identity() != self.root_identity
            || guard.kind() != &LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY)?)
        {
            return Err(invalid());
        }
        Ok(PurgeOwner {
            guard,
            root: self.root_identity,
            installation: self.status()?.policy.installation_id,
            nonce,
        })
    }

    pub fn purge_job_status(&self, job_id: &ControlId) -> PortResult<PurgeJobStatus> {
        if runtime_deadline().is_none() {
            return self.with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || {
                self.purge_job_status(job_id)
            });
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(sql_error)?;
        load_status(&tx)?;
        let result = load_purge_job_status(&tx, job_id)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        mark_runtime_committed();
        Ok(result)
    }

    /// Adopt an unfinished job only with this root's real purge lock. A dead
    /// owner's durable checkpoint survives; timestamps never authorize takeover.
    pub fn claim_purge_job(
        &self,
        expected: ControlSeq,
        owner: &PurgeOwner<'_>,
        control: &ControlRootGuard<'_>,
        job_id: &ControlId,
        now_ms: i64,
    ) -> PortResult<ControlChange<PurgeJobStatus>> {
        owner.validate(self)?;
        control.validate(self)?;
        checked_time(now_ms)?;
        self.mutate(expected, |conn, _| {
            let prior = load_purge_job_status(conn, job_id)?;
            if prior.job.state == PurgeState::Complete { return Ok((false, false, prior)); }
            if prior.owner_nonce.as_ref() == Some(owner.nonce()) && prior.failure.is_none() {
                return Ok((false, false, prior));
            }
            conn.execute(
                "UPDATE purge_jobs SET state='claims',attempts=?1,owner_nonce=?2,progress_key=COALESCE(progress_key,?3),last_error=NULL,updated_at_ms=?4 WHERE job_id=?5",
                params![increment(prior.job.attempts.get())?, owner.nonce().as_str(), PurgeCheckpoint::Claimed.wire(), now_ms, job_id.as_str()],
            ).map_err(sql_error)?;
            Ok((true, false, load_purge_job_status(conn, job_id)?))
        })
    }

    /// Private runner seam: only an OS-owned runner may advance its own job.
    /// Completion checks the exact policy epoch just verified by that runner.
    pub(crate) fn advance_purge_job(
        &self,
        expected: ControlSeq,
        owner: &PurgeOwner<'_>,
        control: &ControlRootGuard<'_>,
        job_id: &ControlId,
        transition: PurgeTransition,
    ) -> PortResult<ControlChange<PurgeJobStatus>> {
        let PurgeTransition {
            state,
            checkpoint,
            failure,
            verified_epoch,
            now_ms,
        } = transition;
        owner.validate(self)?;
        control.validate(self)?;
        checked_time(now_ms)?;
        if state == PurgeState::Pending || (state == PurgeState::Blocked) != failure.is_some() {
            return Err(invalid());
        }
        self.mutate(expected, |conn, current| {
            let prior = load_purge_job_status(conn, job_id)?;
            if prior.owner_nonce.as_ref() != Some(owner.nonce()) { return Err(conflict()); }
            if state == PurgeState::Complete && current.policy.policy_epoch != verified_epoch { return Err(conflict()); }
            let wire = match state {
                PurgeState::Claims => "claims", PurgeState::Artifacts => "artifacts",
                PurgeState::Verifying => "verifying", PurgeState::Complete => "complete", PurgeState::Blocked => "blocked",
                PurgeState::Pending => return Err(invalid()),
            };
            let terminal = matches!(state, PurgeState::Complete | PurgeState::Blocked);
            conn.execute(
                "UPDATE purge_jobs SET state=?1,progress_key=?2,owner_nonce=?3,last_error=?4,updated_at_ms=?5 WHERE job_id=?6",
                params![wire, checkpoint.wire(), (!terminal).then(|| owner.nonce().as_str()), failure.map(PurgeFailure::wire), now_ms, job_id.as_str()],
            ).map_err(sql_error)?;
            let value = load_purge_job_status(conn, job_id)?;
            Ok((true, false, value))
        })
    }

    /// Creates a fresh database only. The immediate parent must already exist;
    /// a new private_root is made user-only, existing permissions are not changed.
    pub fn create(
        private_root: &Path,
        installation: &ControlId,
        desired: DesiredUpdates,
    ) -> PortResult<Self> {
        private_directory(private_root, true)?;
        let handle_lease = admit_control_handle(private_root, true)?;
        let root_identity = handle_lease.root_identity();
        let path = Self::path(private_root);
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(io_error)?
        };
        #[cfg(windows)]
        let file = windows_private::create_file(&path)?;
        #[cfg(not(any(unix, windows)))]
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io_error)?;
        // create_new is the sole creation gate, including existing empty files.
        file.sync_all().map_err(io_error)?;
        drop(file);
        private_file(&path)?;
        let mut conn = connect(&path, true)?;
        let journal: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(sql_error)?;
        if journal != "wal" {
            return Err(corrupt());
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        tx.execute_batch(SCHEMA).map_err(sql_error)?;
        tx.execute_batch(RUNTIME_INDEXES).map_err(sql_error)?;
        tx.execute("INSERT INTO control_meta(singleton,schema_version,installation_id,policy_epoch,control_seq,next_cycle_seq,desired_updates,autostart_enabled,maintenance_state) VALUES(1,2,?1,0,0,1,?2,0,'idle')", params![installation.as_str(), desired_wire(desired)]).map_err(sql_error)?;
        tx.execute(
            "INSERT INTO worker_state(singleton,effective_state) VALUES(1,'offline')",
            [],
        )
        .map_err(sql_error)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(sql_error)?;
        tx.pragma_update(None, "user_version", VERSION)
            .map_err(sql_error)?;
        tx.commit().map_err(sql_error)?;
        mark_runtime_committed();
        let store = Self {
            conn: RefCell::new(conn),
            handle_lease,
            writable: true,
            root_identity,
            private_root: private_root.to_path_buf(),
        };
        if RootIdentity::read(private_root)? != root_identity {
            return Err(corrupt());
        }
        store.handle_lease.validate_admission(private_root)?;
        store.status()?;
        verify_sidecars(&path)?;
        #[cfg(unix)]
        fs::File::open(private_root)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        Ok(store)
    }

    pub fn open_read_only(private_root: &Path, installation: &ControlId) -> PortResult<Self> {
        Self::open_existing(private_root, Some(installation), false)
    }
    pub fn open_existing_writable(
        private_root: &Path,
        installation: &ControlId,
    ) -> PortResult<Self> {
        Self::open_existing(private_root, Some(installation), true)
    }

    /// Discover an existing control identity after schema/private-state checks.
    /// Never creates or resets state. The caller must compare the returned
    /// status installation ID with its managed catalog before using that pair.
    pub fn open_current_read_only(private_root: &Path) -> PortResult<Self> {
        Self::open_existing(private_root, None, false)
    }

    /// Writable counterpart of open_current_read_only. A verified control1
    /// receives only the additive control2 indexes; policies, counters and
    /// receipts are preserved. All policy/worker changes remain explicit.
    pub fn open_current_writable(private_root: &Path) -> PortResult<Self> {
        Self::open_existing(private_root, None, true)
    }

    /// Writable open scoped to the caller's original deadline instead of the
    /// adapter's short default budget.
    pub fn open_current_writable_with_deadline(
        private_root: &Path,
        deadline: Instant,
    ) -> PortResult<Self> {
        Self::open_existing_with_deadline(private_root, None, true, deadline)
    }

    fn open_existing(
        root: &Path,
        installation: Option<&ControlId>,
        writable: bool,
    ) -> PortResult<Self> {
        // Retirement is checked even if the database has already been removed.
        // The lease itself leaves an uninitialized root entirely untouched.
        let handle_lease = admit_control_handle(root, false)?;
        let root_identity = handle_lease.root_identity();
        let path = Self::path(root);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(missing()),
            Err(e) => return Err(io_error(e)),
            Ok(_) => {}
        }
        private_directory(root, false)?;
        private_file(&path)?;
        verify_sidecars(&path)?;
        let store = Self {
            conn: RefCell::new(connect(&path, writable)?),
            handle_lease,
            writable,
            root_identity,
            private_root: root.to_path_buf(),
        };
        if RootIdentity::read(root)? != root_identity {
            return Err(corrupt());
        }
        store.handle_lease.validate_admission(root)?;
        let current = store.status()?;
        if installation.is_some_and(|expected| current.policy.installation_id != *expected) {
            return Err(corrupt());
        }
        if writable {
            store.upgrade_runtime_indexes()?;
        }
        runtime_tick()?;
        verify_sidecars(&path)?;
        Ok(store)
    }

    fn upgrade_runtime_indexes(&self) -> PortResult<()> {
        let mut conn = self.conn.borrow_mut();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(sql_error)?;
        if version == VERSION {
            return Ok(());
        }
        runtime_tick()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        validate_schema(&tx)?;
        let actual: i64 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(sql_error)?;
        if actual == LEGACY_VERSION {
            tx.execute_batch(RUNTIME_INDEXES).map_err(sql_error)?;
            let changed = tx.execute("UPDATE control_meta SET schema_version=?1 WHERE singleton=1 AND schema_version=?2", params![VERSION,LEGACY_VERSION]).map_err(sql_error)?;
            if changed != 1 {
                return Err(corrupt());
            }
            tx.pragma_update(None, "user_version", VERSION)
                .map_err(sql_error)?;
        } else if actual != VERSION {
            return Err(corrupt());
        }
        load_status(&tx)?;
        runtime_tick()?;
        tx.commit()
            .map_err(sql_error)
            .inspect(|_| mark_runtime_committed())
    }

    fn validate_guard(&self, guard: &ExclusiveGuard, kind: LockKind) -> PortResult<()> {
        self.validate_live_root()?;
        if guard.kind() != &kind || guard.root_identity() != self.root_identity {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn matches_root(&self, identity: RootIdentity) -> bool {
        self.root_identity == identity
    }

    pub(crate) fn validate_live_root(&self) -> PortResult<()> {
        self.handle_lease.validate_admission(&self.private_root)?;
        private_directory(&self.private_root, false)?;
        if RootIdentity::read(&self.private_root)? != self.root_identity {
            return Err(invalid());
        }
        Ok(())
    }

    /// Open an owned regular file without following a final link. The same
    /// opened handle is checked for privacy, type, hard links and path identity;
    /// callers keep it alive and recheck it after bounded reads.
    pub(crate) fn open_private_read(&self, path: &Path) -> PortResult<fs::File> {
        self.validate_live_root()?;
        let relative = path
            .strip_prefix(&self.private_root)
            .map_err(|_| invalid())?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(invalid());
        }
        private_directory(path.parent().ok_or_else(invalid)?, false)?;
        private_file(path)?;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            // Native flags for the supported Unix release targets, as in
            // managed_locks. Do not assume Linux flags on macOS.
            #[cfg(target_os = "linux")]
            let flags = 0o400000 | 0o4000 | 0o2000000;
            #[cfg(target_os = "macos")]
            let flags = 0x100 | 0x4 | 0x01000000;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            return Err(io_error(()));
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(flags)
                .open(path)
                .map_err(io_error)?
        };
        #[cfg(windows)]
        let file = windows_private::open_private_read(path)?;
        #[cfg(not(any(unix, windows)))]
        return Err(io_error(()));
        self.validate_private_read(path, &file)?;
        Ok(file)
    }

    pub(crate) fn validate_private_read(&self, path: &Path, file: &fs::File) -> PortResult<()> {
        self.validate_live_root()?;
        private_file(path)?;
        let opened = file.metadata().map_err(io_error)?;
        if !opened.is_file() {
            return Err(io_error(()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            verify_private(path, &opened)?;
            let named = fs::symlink_metadata(path).map_err(io_error)?;
            if opened.dev() != named.dev() || opened.ino() != named.ino() {
                return Err(io_error(()));
            }
        }
        #[cfg(windows)]
        windows_private::validate_private_read(path, file)?;
        Ok(())
    }

    pub(crate) fn create_private_catalog_file(&self, path: &Path) -> PortResult<()> {
        let parent = path.parent().ok_or_else(invalid)?;
        private_directory(parent, false)?;
        if !self.matches_root(RootIdentity::read(parent)?) {
            return Err(invalid());
        }
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(io_error)?
        };
        #[cfg(windows)]
        let file = windows_private::create_file(path)?;
        #[cfg(not(any(unix, windows)))]
        return Err(io_error(()));
        file.sync_all().map_err(io_error)?;
        private_file(path)
    }

    pub(crate) fn validate_catalog_file(&self, path: &Path) -> PortResult<()> {
        private_file(path)?;
        verify_sidecars(path)
    }

    /// Create one new user-only file inside an already-private descendant of
    /// this control root. Unlike catalog creation this accepts owned sub-trees
    /// such as `backups/<id>/`, while still proving containment of the canonical
    /// parent and rejecting links/aliases on every component.
    pub(crate) fn create_private_file_under(&self, path: &Path) -> PortResult<()> {
        if !path.is_absolute() {
            return Err(invalid());
        }
        let parent = path.parent().ok_or_else(invalid)?;
        private_directory(parent, false)?;
        let root = fs::canonicalize(&self.private_root).map_err(io_error)?;
        let canonical = fs::canonicalize(parent).map_err(io_error)?;
        if !canonical.starts_with(&root) {
            return Err(invalid());
        }
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(io_error)?
        };
        #[cfg(windows)]
        let file = windows_private::create_file(path)?;
        #[cfg(not(any(unix, windows)))]
        return Err(io_error(()));
        file.sync_all().map_err(io_error)?;
        private_file(path)
    }

    /// Bind an already acquired exclusive background lock to this installation.
    /// This neither registers nor resumes a worker, and never changes pause.
    pub fn bind_worker<'a>(
        &'a self,
        guard: &'a ExclusiveGuard,
        boot: ControlId,
    ) -> PortResult<LockedWorkerAuthority<'a>> {
        self.validate_guard(guard, LockKind::Background)?;
        Ok(LockedWorkerAuthority {
            store: self,
            guard,
            installation: self.status()?.policy.installation_id,
            boot,
        })
    }

    /// Acknowledge one durable deny only while both real owner and exclusive
    /// emission locks are held on this store's physical root. Obtaining the
    /// emission lock is the caller's bounded drain operation; a timestamp,
    /// database row or writer lease cannot stand in for that proof.
    /// Settlement leaves exclusions, purge jobs and desired updates unchanged.
    pub fn settle_revocation(
        &self,
        expected: ControlSeq,
        owner: &ExclusiveGuard,
        drained: &ExclusiveGuard,
        intent_id: &ControlId,
        now_ms: i64,
    ) -> PortResult<ControlChange<RevocationIntent>> {
        checked_time(now_ms)?;
        self.validate_guard(owner, LockKind::PolicyOwner)?;
        self.validate_guard(drained, LockKind::PolicyEmission)?;
        self.mutate(expected, |conn, current| {
            let mut intent = current
                .policy
                .revocations
                .iter()
                .find(|intent| intent.id == *intent_id)
                .ok_or_else(missing)?
                .clone();
            if intent.state == RevocationState::Settled {
                return Ok((false, false, intent));
            }
            let count = conn
                .execute(
                    "UPDATE revocation_intents SET state='settled',settled_at_ms=?1,owner_nonce=NULL WHERE intent_id=?2 AND state='awaiting_drain'",
                    params![now_ms, intent_id.as_str()],
                )
                .map_err(sql_error)?;
            if count != 1 {
                return Err(conflict());
            }
            intent.state = RevocationState::Settled;
            intent.settled_at_ms = Some(now_ms);
            Ok((true, false, intent))
        })
    }

    fn mutate<T>(
        &self,
        expected: ControlSeq,
        operation: impl FnOnce(&Connection, &ControlStatus) -> PortResult<(bool, bool, T)>,
    ) -> PortResult<ControlChange<T>> {
        if !self.writable {
            return Err(invalid());
        }
        if runtime_deadline().is_none() {
            return self.with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || {
                self.mutate(expected, operation)
            });
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        configure_runtime_deadline(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let current = load_status(&tx)?;
        if current.policy.control_seq != expected {
            return Err(conflict());
        }
        let (changed, policy_changed, value) = operation(&tx, &current)?;
        let next_seq = if changed {
            increment(expected.get())?
        } else {
            expected.get()
        };
        let next_epoch = if policy_changed {
            increment(current.policy.policy_epoch.get())?
        } else {
            current.policy.policy_epoch.get()
        };
        if changed {
            let count = tx.execute("UPDATE control_meta SET control_seq=?1,policy_epoch=?2 WHERE singleton=1 AND control_seq=?3", params![next_seq,next_epoch,expected.get()]).map_err(sql_error)?;
            if count != 1 {
                return Err(conflict());
            }
        }
        if policy_changed {
            invalidate_scheduling(&tx, BackgroundFailure::PolicyChanged, None)?;
        }
        // Decode our own result before acknowledgement; failure rolls back all rows.
        load_status(&tx)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        mark_runtime_committed();
        Ok(ControlChange {
            control_seq: seq(next_seq)?,
            policy_epoch: epoch(next_epoch)?,
            changed,
            value,
        })
    }
}

fn connect(path: &Path, writable: bool) -> PortResult<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
        .map_err(sql_error)?;
    configure_runtime_deadline(&conn)?;
    runtime_tick()?;
    conn.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
    )
    .map_err(|e| sql_query_error(&conn, e))?;
    Ok(conn)
}

fn fresh_id(conn: &Connection, prefix: &str) -> PortResult<ControlId> {
    let random: String = conn
        .query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))
        .map_err(sql_error)?;
    id(format!("{prefix}_{random}"))
}

pub(crate) fn validate_schema(conn: &Connection) -> PortResult<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| sql_query_error(conn, e))?;
    let application: i64 = conn
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(|e| sql_query_error(conn, e))?;
    if !matches!(version, LEGACY_VERSION | VERSION) || application != APPLICATION_ID {
        return Err(corrupt());
    }
    // Compare every column, key and declared constraint to the normative schema.
    // Whitespace is irrelevant, arbitrary extra triggers/views/tables are not.
    let mut stmt = conn
        .prepare("SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| sql_query_error(conn, e))?;
    let entries = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| sql_query_error(conn, e))?;
    let mut expected: Vec<&str> = SCHEMA.split(';').filter(|s| !s.trim().is_empty()).collect();
    if version == VERSION {
        expected.extend(RUNTIME_INDEXES.split(';').filter(|s| !s.trim().is_empty()));
    }
    let mut count = 0;
    for entry in entries {
        runtime_tick()?;
        let (name, sql) = entry.map_err(|e| sql_query_error(conn, e))?;
        let normalized = sql.split_whitespace().collect::<String>();
        if !expected
            .iter()
            .any(|e| e.split_whitespace().collect::<String>() == normalized)
        {
            return Err(corrupt());
        }
        if RESERVED_TABLES.contains(&name.as_str()) {
            // No decoder exists for these future capabilities yet. Fail closed
            // on *all* rows rather than accept unknown enums/receipt semantics.
            let populated: bool = conn
                .query_row(&format!("SELECT EXISTS(SELECT 1 FROM {name})"), [], |r| {
                    r.get(0)
                })
                .map_err(|e| sql_query_error(conn, e))?;
            if populated {
                return Err(corrupt());
            }
        }
        count += 1;
    }
    if count != expected.len() {
        return Err(corrupt());
    }
    Ok(())
}

fn load_status(conn: &Connection) -> PortResult<ControlStatus> {
    let status = load_status_core(conn)?;
    load_runtime(conn, &status)?;
    Ok(status)
}

// Runtime callers decode it once in their own pinned transaction. Normal
// policy callers still perform the complete runtime validation through load_status.
fn load_status_core(conn: &Connection) -> PortResult<ControlStatus> {
    runtime_tick()?;
    validate_schema(conn)?;
    for table in [
        "selections",
        "exclusions",
        "revocation_intents",
        "purge_jobs",
    ] {
        runtime_rows_within(
            conn,
            &format!("SELECT 1 FROM {table}"),
            MAX_RUNTIME_REFERENCES,
        )?;
    }
    let mut stmt = conn.prepare("SELECT schema_version,installation_id,policy_epoch,control_seq,next_cycle_seq,catalog_incarnation,restart_request_seq,desired_updates,autostart_enabled,maintenance_state,maintenance_owner,maintenance_phase,singleton,supervisor_failed FROM control_meta").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let row = rows.next().map_err(sql_error)?.ok_or_else(corrupt)?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(sql_error)?;
    if row.get::<_, i64>(0).map_err(sql_error)? != version
        || row.get::<_, i64>(12).map_err(sql_error)? != 1
    {
        return Err(corrupt());
    }
    let installation_id = id(row.get(1).map_err(sql_error)?)?;
    let policy_epoch = epoch(row.get(2).map_err(sql_error)?)?;
    let control_seq = seq(row.get(3).map_err(sql_error)?)?;
    let next_cycle = seq(row.get(4).map_err(sql_error)?)?;
    if next_cycle.get() == 0 || policy_epoch.get() > control_seq.get() {
        return Err(corrupt());
    }
    let catalog_incarnation = row
        .get::<_, Option<String>>(5)
        .map_err(sql_error)?
        .map(id)
        .transpose()?;
    let restart_request_seq = seq(row.get(6).map_err(sql_error)?)?;
    if restart_request_seq > control_seq {
        return Err(corrupt());
    }
    let desired_updates = desired_decode(&row.get::<_, String>(7).map_err(sql_error)?)?;
    let autostart_enabled = boolean(row.get(8).map_err(sql_error)?)?;
    let supervisor_failed = boolean(row.get(13).map_err(sql_error)?)?;
    let maintenance = MaintenanceFence {
        state: maintenance_decode(&row.get::<_, String>(9).map_err(sql_error)?)?,
        owner: row
            .get::<_, Option<String>>(10)
            .map_err(sql_error)?
            .map(id)
            .transpose()?,
        phase: row
            .get::<_, Option<String>>(11)
            .map_err(sql_error)?
            .as_deref()
            .map(phase_decode)
            .transpose()?,
    };
    maintenance.validate().map_err(|_| corrupt())?;
    if rows.next().map_err(sql_error)?.is_some() {
        return Err(corrupt());
    }
    let selections = load_selections(conn)?;
    let exclusions = load_exclusions(conn, policy_epoch)?;
    let revocations = load_revocations(conn, policy_epoch)?;
    let jobs = load_jobs(conn)?;
    if selections.iter().any(|s| s.revision > control_seq)
        || exclusions.iter().any(|e| e.revision > control_seq)
        || revocations
            .iter()
            .any(|r| !jobs.iter().any(|j| j.policy_epoch == r.policy_epoch))
    {
        return Err(corrupt());
    }
    for job in jobs {
        runtime_tick()?;
        let selection = selections
            .iter()
            .find(|s| Some(&s.id) == job.selection_id.as_ref())
            .ok_or_else(corrupt)?;
        if job
            .selection_revision
            .is_none_or(|r| r > selection.revision)
            || !revocations
                .iter()
                .any(|r| r.policy_epoch == job.policy_epoch)
        {
            return Err(corrupt());
        }
    }
    // Private maintenance artifacts and backup manifests are typed state, not
    // free-form rows. Unknown enums, dangling ownership links or malformed
    // locators fail closed before any caller receives a policy.
    load_backups(conn, policy_epoch)?;
    let status = ControlStatus {
        policy: ReadPolicy {
            installation_id,
            policy_epoch,
            control_seq,
            selections,
            exclusions,
            request_intersection: RequestIntersection::Selected,
            maintenance,
            revocations,
        },
        desired_updates,
        autostart_enabled,
        supervisor_failed,
        restart_request_seq,
        catalog_incarnation,
    };
    Ok(status)
}

fn load_selections(conn: &Connection) -> PortResult<Vec<Selection>> {
    let mut stmt = conn.prepare("SELECT selection_id,provider_id,canonical_locator,root_kind,root_identity,enabled,revision,created_at_ms,revoked_at_ms FROM selections ORDER BY selection_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let s = Selection {
            id: id(r.get(0).map_err(sql_error)?)?,
            region: ScopeRegion {
                provider: provider(r.get(1).map_err(sql_error)?)?,
                locator: CanonicalLocator::parse(&r.get::<_, String>(2).map_err(sql_error)?)
                    .map_err(|_| corrupt())?,
                kind: kind_decode(&r.get::<_, String>(3).map_err(sql_error)?)?,
            },
            root_identity: r
                .get::<_, Option<String>>(4)
                .map_err(sql_error)?
                .map(id)
                .transpose()?,
            enabled: boolean(r.get(5).map_err(sql_error)?)?,
            revision: seq(r.get(6).map_err(sql_error)?)?,
            created_at_ms: r.get(7).map_err(sql_error)?,
            revoked_at_ms: r.get(8).map_err(sql_error)?,
        };
        if s.created_at_ms < 0
            || s.revoked_at_ms.is_some_and(|t| t < 0)
            || s.enabled == s.revoked_at_ms.is_some()
            || result.iter().any(|old: &Selection| old.region == s.region)
        {
            return Err(corrupt());
        }
        result.push(s);
    }
    Ok(result)
}

fn load_exclusions(conn: &Connection, current_epoch: PolicyEpoch) -> PortResult<Vec<Exclusion>> {
    let mut stmt = conn.prepare("SELECT exclusion_id,provider_id,canonical_locator,region_kind,source_id,revision,created_policy_epoch,created_at_ms FROM exclusions ORDER BY exclusion_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let p = provider(r.get(1).map_err(sql_error)?)?;
        let locator: Option<String> = r.get(2).map_err(sql_error)?;
        let kind: String = r.get(3).map_err(sql_error)?;
        let source: Option<String> = r.get(4).map_err(sql_error)?;
        let region = match (kind.as_str(), locator, source) {
            ("source_identity", None, Some(source)) => ExcludedRegion::SourceIdentity {
                provider: p,
                source_id: id(source)?,
            },
            ("root" | "exact", Some(locator), None) => ExcludedRegion::Locator(ScopeRegion {
                provider: p,
                locator: CanonicalLocator::parse(&locator).map_err(|_| corrupt())?,
                kind: kind_decode(&kind)?,
            }),
            _ => return Err(corrupt()),
        };
        let e = Exclusion {
            id: id(r.get(0).map_err(sql_error)?)?,
            region,
            revision: seq(r.get(5).map_err(sql_error)?)?,
            created_policy_epoch: epoch(r.get(6).map_err(sql_error)?)?,
            created_at_ms: r.get(7).map_err(sql_error)?,
        };
        if e.created_at_ms < 0
            || e.created_policy_epoch > current_epoch
            || result.iter().any(|old: &Exclusion| old.region == e.region)
        {
            return Err(corrupt());
        }
        result.push(e);
    }
    Ok(result)
}

fn load_revocations(
    conn: &Connection,
    current_epoch: PolicyEpoch,
) -> PortResult<Vec<RevocationIntent>> {
    let mut stmt = conn.prepare("SELECT intent_id,policy_epoch,state,created_at_ms,settled_at_ms,owner_nonce FROM revocation_intents ORDER BY policy_epoch").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let state = match r.get::<_, String>(2).map_err(sql_error)?.as_str() {
            "awaiting_drain" => RevocationState::AwaitingDrain,
            "settled" => RevocationState::Settled,
            _ => return Err(corrupt()),
        };
        let intent = RevocationIntent {
            id: id(r.get(0).map_err(sql_error)?)?,
            policy_epoch: epoch(r.get(1).map_err(sql_error)?)?,
            state,
            created_at_ms: r.get(3).map_err(sql_error)?,
            settled_at_ms: r.get(4).map_err(sql_error)?,
        };
        r.get::<_, Option<String>>(5)
            .map_err(sql_error)?
            .map(id)
            .transpose()?;
        if intent.policy_epoch > current_epoch
            || intent.created_at_ms < 0
            || intent.settled_at_ms.is_some_and(|t| t < 0)
            || (state == RevocationState::Settled) != intent.settled_at_ms.is_some()
        {
            return Err(corrupt());
        }
        result.push(intent);
    }
    Ok(result)
}

fn load_jobs(conn: &Connection) -> PortResult<Vec<PurgeJob>> {
    let mut stmt = conn.prepare("SELECT job_id,policy_epoch,selection_id,selection_revision,state,attempts,progress_key,owner_nonce,last_error,created_at_ms,updated_at_ms FROM purge_jobs ORDER BY policy_epoch,job_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let state = match r.get::<_, String>(4).map_err(sql_error)?.as_str() {
            "pending" => PurgeState::Pending,
            "claims" => PurgeState::Claims,
            "artifacts" => PurgeState::Artifacts,
            "verifying" => PurgeState::Verifying,
            "complete" => PurgeState::Complete,
            "blocked" => PurgeState::Blocked,
            _ => return Err(corrupt()),
        };
        let job = PurgeJob {
            id: id(r.get(0).map_err(sql_error)?)?,
            policy_epoch: epoch(r.get(1).map_err(sql_error)?)?,
            selection_id: r
                .get::<_, Option<String>>(2)
                .map_err(sql_error)?
                .map(id)
                .transpose()?,
            selection_revision: r
                .get::<_, Option<i64>>(3)
                .map_err(sql_error)?
                .map(seq)
                .transpose()?,
            state,
            attempts: seq(r.get(5).map_err(sql_error)?)?,
        };
        let checkpoint = r
            .get::<_, Option<String>>(6)
            .map_err(sql_error)?
            .as_deref()
            .map(PurgeCheckpoint::decode)
            .transpose()?;
        let owner = r
            .get::<_, Option<String>>(7)
            .map_err(sql_error)?
            .map(id)
            .transpose()?;
        let failure = r
            .get::<_, Option<String>>(8)
            .map_err(sql_error)?
            .as_deref()
            .map(PurgeFailure::decode)
            .transpose()?;
        let valid = match state {
            PurgeState::Pending => {
                job.attempts.get() == 0
                    && checkpoint.is_none()
                    && owner.is_none()
                    && failure.is_none()
            }
            PurgeState::Claims => {
                job.attempts.get() > 0
                    && checkpoint.is_some()
                    && owner.is_some()
                    && failure.is_none()
            }
            PurgeState::Artifacts => {
                job.attempts.get() > 0
                    && matches!(
                        checkpoint,
                        Some(PurgeCheckpoint::CatalogCommitted | PurgeCheckpoint::CacheRetired)
                    )
                    && owner.is_some()
                    && failure.is_none()
            }
            PurgeState::Verifying => {
                job.attempts.get() > 0
                    && checkpoint == Some(PurgeCheckpoint::ArtifactsVerified)
                    && owner.is_some()
                    && failure.is_none()
            }
            PurgeState::Complete => {
                job.attempts.get() > 0
                    && checkpoint == Some(PurgeCheckpoint::ArtifactsVerified)
                    && owner.is_none()
                    && failure.is_none()
            }
            PurgeState::Blocked => {
                job.attempts.get() > 0
                    && checkpoint.is_some()
                    && owner.is_none()
                    && failure.is_some()
            }
        };
        if !valid
            || r.get::<_, i64>(9).map_err(sql_error)? < 0
            || r.get::<_, i64>(10).map_err(sql_error)? < 0
        {
            return Err(corrupt());
        }
        result.push(job);
    }
    Ok(result)
}

fn load_purge_job_status(conn: &Connection, job_id: &ControlId) -> PortResult<PurgeJobStatus> {
    let job = load_jobs(conn)?
        .into_iter()
        .find(|job| job.id == *job_id)
        .ok_or_else(missing)?;
    let (owner, checkpoint, failure): (Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT owner_nonce,progress_key,last_error FROM purge_jobs WHERE job_id=?1",
            [job_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql_error)?;
    Ok(PurgeJobStatus {
        job,
        owner_nonce: owner.map(id).transpose()?,
        checkpoint: checkpoint
            .as_deref()
            .map(PurgeCheckpoint::decode)
            .transpose()?,
        failure: failure.as_deref().map(PurgeFailure::decode).transpose()?,
    })
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Deterministic private relative locator. Never absolute, never aliasing, and
/// confined to the owned backup subtree.
fn valid_relative_locator(value: &str) -> bool {
    value.len() <= MAX_RELATIVE_LOCATOR
        && value.starts_with(BACKUP_LOCATOR_PREFIX)
        && !value.contains(['\\', ':', '\0'])
        && !value.is_empty()
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        })
}

fn backup_locator(backup_id: &ControlId) -> String {
    format!("{BACKUP_LOCATOR_PREFIX}{}/catalog.db", backup_id.as_str())
}

/// Create or validate one private directory for owned maintenance artifacts.
pub(crate) fn ensure_private_directory(path: &Path) -> PortResult<()> {
    private_directory(path, true)
}

pub(crate) fn validate_private_directory(path: &Path) -> PortResult<()> {
    private_directory(path, false)
}

pub(crate) fn catalog_backup_locator(backup_id: &ControlId) -> String {
    backup_locator(backup_id)
}

fn load_artifact_links(
    conn: &Connection,
    table: &str,
    owner: &str,
) -> PortResult<std::collections::BTreeMap<String, Vec<ControlId>>> {
    debug_assert!(matches!(table, "artifact_sources" | "backup_sources"));
    debug_assert!(matches!(owner, "artifact_id" | "backup_id"));
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {owner},source_id FROM {table} ORDER BY {owner},source_id"
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut links: std::collections::BTreeMap<String, Vec<ControlId>> = Default::default();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let key = r.get::<_, String>(0).map_err(sql_error)?;
        let source = id(r.get(1).map_err(sql_error)?)?;
        let list = links.entry(key).or_default();
        if list.last().is_some_and(|last| last >= &source) {
            return Err(corrupt());
        }
        list.push(source);
    }
    Ok(links)
}

fn load_artifacts(
    conn: &Connection,
    current_epoch: PolicyEpoch,
) -> PortResult<Vec<StoredArtifact>> {
    let links = load_artifact_links(conn, "artifact_sources", "artifact_id")?;
    let mut stmt = conn
        .prepare("SELECT artifact_id,kind,relative_locator,policy_epoch,owner_nonce,state,digest FROM private_artifacts ORDER BY artifact_id")
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut result = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let artifact_id = id(r.get(0).map_err(sql_error)?)?;
        match r.get::<_, String>(1).map_err(sql_error)?.as_str() {
            "catalog_backup" => {}
            _ => return Err(corrupt()),
        }
        let relative_locator: String = r.get(2).map_err(sql_error)?;
        if !valid_relative_locator(&relative_locator) {
            return Err(corrupt());
        }
        let policy_epoch = epoch(r.get(3).map_err(sql_error)?)?;
        if policy_epoch > current_epoch {
            return Err(corrupt());
        }
        let owner_nonce = r
            .get::<_, Option<String>>(4)
            .map_err(sql_error)?
            .map(id)
            .transpose()?;
        let state = ArtifactState::decode(&r.get::<_, String>(5).map_err(sql_error)?)?;
        let digest = r.get::<_, Option<String>>(6).map_err(sql_error)?;
        if digest.as_deref().is_some_and(|value| !hex64(value)) {
            return Err(corrupt());
        }
        let owner_ok = match state {
            ArtifactState::Registered | ArtifactState::Complete => owner_nonce.is_some(),
            ArtifactState::Quarantined | ArtifactState::PurgedByPolicy => owner_nonce.is_none(),
        };
        let digest_ok = match state {
            ArtifactState::Registered => digest.is_none(),
            ArtifactState::Quarantined | ArtifactState::PurgedByPolicy => true,
            ArtifactState::Complete => digest.is_some(),
        };
        let sources = links.get(artifact_id.as_str()).cloned().unwrap_or_default();
        if !owner_ok
            || !digest_ok
            || (state == ArtifactState::PurgedByPolicy && !sources.is_empty())
        {
            return Err(corrupt());
        }
        result.push(StoredArtifact {
            artifact_id,
            kind: ArtifactKind::CatalogBackup,
            relative_locator,
            policy_epoch,
            owner_nonce,
            state,
            digest,
            source_ids: sources,
        });
    }
    if links
        .keys()
        .any(|key| !result.iter().any(|a| a.artifact_id.as_str() == key))
    {
        return Err(corrupt());
    }
    Ok(result)
}

fn load_backups(conn: &Connection, current_epoch: PolicyEpoch) -> PortResult<Vec<StoredBackup>> {
    let artifacts = load_artifacts(conn, current_epoch)?;
    let links = load_artifact_links(conn, "backup_sources", "backup_id")?;
    let mut stmt = conn
        .prepare("SELECT backup_id,purpose,relative_locator,catalog_incarnation,catalog_generation,schema_version,digest,size_bytes,state,created_at_ms FROM backup_manifests ORDER BY backup_id")
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut result: Vec<StoredBackup> = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let backup_id = id(r.get(0).map_err(sql_error)?)?;
        let purpose = BackupPurpose::decode(&r.get::<_, String>(1).map_err(sql_error)?)?;
        let relative_locator: String = r.get(2).map_err(sql_error)?;
        if !valid_relative_locator(&relative_locator)
            || relative_locator != backup_locator(&backup_id)
        {
            return Err(corrupt());
        }
        let catalog_incarnation = id(r.get(3).map_err(sql_error)?)?;
        let catalog_generation = count(r.get(4).map_err(sql_error)?)?;
        let schema_version = u32::try_from(r.get::<_, i64>(5).map_err(sql_error)?)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(corrupt)?;
        let digest: String = r.get(6).map_err(sql_error)?;
        let size_bytes = count(r.get(7).map_err(sql_error)?)?;
        let state = BackupState::decode(&r.get::<_, String>(8).map_err(sql_error)?)?;
        let created_at_ms: i64 = r.get(9).map_err(sql_error)?;
        let artifact = artifacts
            .iter()
            .find(|a| a.artifact_id == backup_id)
            .ok_or_else(corrupt)?;
        let digest = match state {
            BackupState::Quarantined | BackupState::PurgedByPolicy
                if digest.is_empty() && size_bytes == 0 =>
            {
                None
            }
            BackupState::Registered => {
                if !digest.is_empty() || size_bytes != 0 {
                    return Err(corrupt());
                }
                None
            }
            _ => {
                if !hex64(&digest) || size_bytes == 0 {
                    return Err(corrupt());
                }
                Some(digest)
            }
        };
        let state_ok = matches!(
            (state, artifact.state),
            (BackupState::Registered, ArtifactState::Registered)
                | (BackupState::Complete, ArtifactState::Complete)
                | (BackupState::Quarantined, ArtifactState::Quarantined)
                | (BackupState::PurgedByPolicy, ArtifactState::PurgedByPolicy)
        );
        let sources = links.get(backup_id.as_str()).cloned().unwrap_or_default();
        if created_at_ms < 0
            || !state_ok
            || artifact.relative_locator != relative_locator
            || artifact.digest != digest
            || artifact.source_ids != sources
            || (state == BackupState::PurgedByPolicy && !sources.is_empty())
        {
            return Err(corrupt());
        }
        result.push(StoredBackup {
            backup_id,
            purpose,
            relative_locator,
            catalog_incarnation,
            catalog_generation,
            schema_version,
            digest,
            size_bytes,
            state,
            created_at_ms,
            source_ids: sources,
        });
    }
    if links
        .keys()
        .any(|key| !result.iter().any(|b| b.backup_id.as_str() == key))
        || artifacts
            .iter()
            .any(|a| !result.iter().any(|b| b.backup_id == a.artifact_id))
    {
        return Err(corrupt());
    }
    Ok(result)
}

impl ControlStore for SqliteControlStore {
    fn read_policy(&self, request: RequestIntersection) -> PortResult<ReadPolicy> {
        let mut policy = self.status()?.policy;
        policy.request_intersection = request;
        Ok(policy)
    }
    fn status(&self) -> PortResult<ControlStatus> {
        if runtime_deadline().is_none() {
            return self.with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || self.status());
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        configure_runtime_deadline(&conn)?;
        let tx = conn.transaction().map_err(sql_error)?;
        let status = load_status(&tx)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        self.validate_live_root()?;
        runtime_tick()?;
        Ok(status)
    }
    fn purge_jobs(&self) -> PortResult<Vec<PurgeJob>> {
        if runtime_deadline().is_none() {
            return self.with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || self.purge_jobs());
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(sql_error)?;
        load_status(&tx)?;
        let jobs = load_jobs(&tx)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        self.validate_live_root()?;
        Ok(jobs)
    }
    fn add_selection(
        &self,
        expected: ControlSeq,
        request: SelectionRequest,
    ) -> PortResult<ControlChange<Selection>> {
        checked_time(request.now_ms)?;
        self.mutate(expected, |conn,current| {
            let existing = current.policy.selections.iter().find(|s| s.region == request.region);
            if let Some(s) = existing.filter(|s| s.enabled) {
                if s.root_identity != request.root_identity { return Err(invalid()); }
                return Ok((false,false,s.clone()));
            }
            let (selection_id,revision,created_at_ms) = match existing {
                Some(s) => (s.id.clone(),increment(s.revision.get())?,s.created_at_ms),
                None => (fresh_id(conn,"sel")?,1,request.now_ms),
            };
            let selection = Selection { id: selection_id, region: request.region.clone(), root_identity: request.root_identity.clone(), enabled: true, revision: seq(revision)?, created_at_ms, revoked_at_ms: None };
            conn.execute("INSERT INTO selections(selection_id,provider_id,canonical_locator,root_kind,root_identity,enabled,revision,created_at_ms,revoked_at_ms) VALUES(?1,?2,?3,?4,?5,1,?6,?7,NULL) ON CONFLICT(selection_id) DO UPDATE SET enabled=1,revision=excluded.revision,root_identity=excluded.root_identity,revoked_at_ms=NULL", params![selection.id.as_str(),selection.region.provider.as_str(),selection.region.locator.as_str(),kind_wire(selection.region.kind),selection.root_identity.as_ref().map(ControlId::as_str),revision,created_at_ms]).map_err(sql_error)?;
            Ok((true,true,selection))
        })
    }
    fn revoke_selection(
        &self,
        expected: ControlSeq,
        selection_id: &ControlId,
        known_source: Option<&ControlId>,
        now_ms: i64,
    ) -> PortResult<ControlChange<Revocation>> {
        checked_time(now_ms)?;
        self.mutate(expected, |conn,current| {
            let selection = current.policy.selections.iter().find(|s| s.id == *selection_id).ok_or_else(missing)?;
            if known_source.is_some() && selection.region.kind != RootKind::Exact { return Err(invalid()); }
            let region = ExcludedRegion::Locator(selection.region.clone());
            let source_region = known_source.map(|s| ExcludedRegion::SourceIdentity { provider: selection.region.provider, source_id: s.clone() });
            let already_denied = current.policy.exclusions.iter().any(|e| e.region == region)
                && source_region.as_ref().is_none_or(|source| current.policy.exclusions.iter().any(|e| e.region == *source));
            if !selection.enabled && already_denied {
                let job = load_jobs(conn)?.into_iter().rev().find(|j| j.selection_id.as_ref() == Some(selection_id)).ok_or_else(corrupt)?;
                let intent = current.policy.revocations.iter().find(|r| r.policy_epoch == job.policy_epoch).ok_or_else(corrupt)?.clone();
                return Ok((false,false,Revocation {intent,purge_job:job}));
            }
            let next_epoch = epoch(increment(current.policy.policy_epoch.get())?)?;
            let revision = seq(increment(selection.revision.get())?)?;
            conn.execute("UPDATE selections SET enabled=0,revision=?1,revoked_at_ms=?2 WHERE selection_id=?3", params![revision.get(),now_ms,selection_id.as_str()]).map_err(sql_error)?;
            for region in std::iter::once(region).chain(source_region) {
                if current.policy.exclusions.iter().any(|e| e.region == region) { continue; }
                let exclusion_id = fresh_id(conn,"exc")?;
                let (p,locator,kind,source) = match &region {
                    ExcludedRegion::Locator(r) => (r.provider,Some(r.locator.as_str()),kind_wire(r.kind),None),
                    ExcludedRegion::SourceIdentity {provider,source_id} => (*provider,None,"source_identity",Some(source_id.as_str())),
                };
                conn.execute("INSERT INTO exclusions VALUES(?1,?2,?3,?4,?5,1,?6,?7)",params![exclusion_id.as_str(),p.as_str(),locator,kind,source,next_epoch.get(),now_ms]).map_err(sql_error)?;
            }
            let intent = RevocationIntent { id:fresh_id(conn,"rev")?, policy_epoch:next_epoch, state:RevocationState::AwaitingDrain, created_at_ms:now_ms, settled_at_ms:None };
            let job = PurgeJob {id:fresh_id(conn,"purge")?,policy_epoch:next_epoch,selection_id:Some(selection_id.clone()),selection_revision:Some(revision),state:PurgeState::Pending,attempts:seq(0)?};
            conn.execute("INSERT INTO revocation_intents(intent_id,policy_epoch,state,created_at_ms) VALUES(?1,?2,'awaiting_drain',?3)",params![intent.id.as_str(),next_epoch.get(),now_ms]).map_err(sql_error)?;
            conn.execute("INSERT INTO purge_jobs(job_id,policy_epoch,selection_id,selection_revision,state,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,'pending',?5,?5)",params![job.id.as_str(),next_epoch.get(),selection_id.as_str(),revision.get(),now_ms]).map_err(sql_error)?;
            Ok((true,true,Revocation {intent,purge_job:job}))
        })
    }
    fn remove_exclusion(
        &self,
        expected: ControlSeq,
        exclusion_id: &ControlId,
    ) -> PortResult<ControlChange<Exclusion>> {
        self.mutate(expected, |conn, current| {
            let exclusion = current
                .policy
                .exclusions
                .iter()
                .find(|e| e.id == *exclusion_id)
                .ok_or_else(missing)?
                .clone();
            conn.execute(
                "DELETE FROM exclusions WHERE exclusion_id=?1",
                [exclusion_id.as_str()],
            )
            .map_err(sql_error)?;
            Ok((true, true, exclusion))
        })
    }
    fn set_desired_updates(
        &self,
        expected: ControlSeq,
        desired: DesiredUpdates,
    ) -> PortResult<ControlChange<DesiredUpdates>> {
        self.mutate(expected, |conn,current| {
            if current.desired_updates == desired { return Ok((false,false,desired)); }
            let restart = if desired == DesiredUpdates::Running { increment(current.restart_request_seq.get())? } else { current.restart_request_seq.get() };
            conn.execute("UPDATE control_meta SET desired_updates=?1,restart_request_seq=?2 WHERE singleton=1",params![desired_wire(desired),restart]).map_err(sql_error)?;
            if desired != DesiredUpdates::Running {
                let reason = if desired == DesiredUpdates::Paused { BackgroundFailure::Paused } else { BackgroundFailure::Stopped };
                invalidate_scheduling(conn, reason, None)?;
            }
            Ok((true,false,desired))
        })
    }
    fn set_maintenance(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        fence: MaintenanceFence,
    ) -> PortResult<ControlChange<MaintenanceFence>> {
        fence.validate()?;
        if fence.owner.as_ref().is_some_and(|o| o != owner) {
            return Err(invalid());
        }
        self.mutate(expected, |conn,current| {
            if current.policy.maintenance.owner.as_ref().is_some_and(|o| o != owner) { return Err(conflict()); }
            if current.policy.maintenance == fence { return Ok((false,false,fence.clone())); }
            conn.execute("UPDATE control_meta SET maintenance_state=?1,maintenance_owner=?2,maintenance_phase=?3 WHERE singleton=1",params![maintenance_wire(fence.state),fence.owner.as_ref().map(ControlId::as_str),fence.phase.map(phase_wire)]).map_err(sql_error)?;
            if fence.state != MaintenanceState::Idle {
                invalidate_scheduling(conn, BackgroundFailure::Upgrading, None)?;
            }
            Ok((true,false,fence.clone()))
        })
    }
}

fn reject_links(path: &Path) -> PortResult<()> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)
            .map_err(|error| private_validation_io(error, "ancestor_metadata"))?;
        if meta.file_type().is_symlink() {
            return Err(private_validation_error("ancestor_symlink", 0, false));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(private_validation_error("ancestor_reparse", 0, false));
            }
        }
    }
    Ok(())
}
fn private_directory(path: &Path, create: bool) -> PortResult<()> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    if create && !path.try_exists().map_err(io_error)? {
        reject_links(path.parent().ok_or_else(invalid)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(io_error)?;
        }
        #[cfg(windows)]
        windows_private::create_directory(path)?;
        #[cfg(not(any(unix, windows)))]
        return Err(io_error(()));
    }
    reject_links(path)?;
    let meta = fs::symlink_metadata(path)
        .map_err(|error| private_validation_io(error, "directory_metadata"))?;
    if !meta.is_dir() {
        return Err(private_validation_error("directory_kind", 0, false));
    }
    verify_private(path, &meta)
}
pub(crate) fn validate_private_owned_file(path: &Path) -> PortResult<()> {
    private_file(path)
}

/// Create one new user-only file in an existing private directory. The caller
/// retains the open handle and its physical parent capability through writes.
/// This never creates directories or replaces an existing file.
pub(crate) fn create_private_owned_file(path: &Path) -> PortResult<fs::File> {
    private_directory(path.parent().ok_or_else(invalid)?, false)?;
    #[cfg(windows)]
    {
        windows_private::create_file(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(io_error)
    }
    #[cfg(not(any(unix, windows)))]
    Err(io_error(()))
}

fn private_file(path: &Path) -> PortResult<()> {
    reject_links(path.parent().ok_or_else(invalid)?)?;
    let meta = fs::symlink_metadata(path)
        .map_err(|error| private_validation_io(error, "file_metadata"))?;
    private_file_observed(path, &meta, false)
}

fn private_file_observed(path: &Path, meta: &fs::Metadata, sidecar: bool) -> PortResult<()> {
    if !meta.is_file() {
        return Err(private_validation_error("observed_file_kind", 0, sidecar));
    }
    if meta.file_type().is_symlink() {
        return Err(private_validation_error("observed_symlink", 0, sidecar));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(private_validation_error("observed_reparse", 0, sidecar));
        }
        windows_private::verify_file(path, sidecar)
    }
    #[cfg(not(windows))]
    {
        let _ = sidecar;
        verify_private(path, meta)
    }
}

fn private_file_io(error: std::io::Error, sidecar: bool) -> PortError {
    private_file_io_at(error, sidecar, "file_io")
}

fn private_file_io_at(error: std::io::Error, sidecar: bool, stage: &'static str) -> PortError {
    let code = error.raw_os_error().unwrap_or(0);
    // SQLite can unlink WAL/SHM on its last close after we observe a sidecar.
    // This invalidates this validation attempt; it never proves the new path
    // safe. Callers can retry only under their existing admission deadline.
    if (sidecar && error.kind() == std::io::ErrorKind::NotFound)
        || (cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33 | 303)))
    {
        PortError::WriterBusy(format!(
            "private storage changed during validation (stage={stage}, sidecar={}, code={code})",
            u8::from(sidecar),
        ))
    } else {
        private_validation_error(stage, code, sidecar)
    }
}

fn verify_private(path: &Path, meta: &fs::Metadata) -> PortResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid has no pointer or lifetime preconditions.
        if meta.permissions().mode() & 0o077 != 0
            || meta.uid() != unsafe { geteuid() }
            || (meta.is_file() && meta.nlink() != 1)
        {
            return Err(io_error(()));
        }
        let _ = path;
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = meta;
        windows_private::verify(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        Err(io_error(()))
    }
}
fn verify_sidecars(path: &Path) -> PortResult<()> {
    reject_links(path.parent().ok_or_else(invalid)?)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match fs::symlink_metadata(&sidecar) {
            Ok(meta) => private_file_observed(&sidecar, &meta, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(private_file_io_at(e, true, "sidecar_metadata")),
        }
    }
    Ok(())
}

wire_enum!(update_wire, update_decode, UpdateState, {
    Running=>"running", Idle=>"idle", Paused=>"paused", Stopped=>"stopped", Offline=>"offline",
    Busy=>"busy", Failed=>"failed", Deferred=>"deferred", Upgrading=>"upgrading"
});
wire_enum!(failure_wire, failure_decode, BackgroundFailure, {
    Paused=>"paused", Stopped=>"stopped", Offline=>"offline", Busy=>"busy", Failed=>"failed",
    Deferred=>"deferred", Upgrading=>"upgrading", PolicyChanged=>"policy_changed", Timeout=>"timeout",
    ScopeUnverified=>"scope_unverified", SourceChanged=>"source_changed", WorkerRestarted=>"worker_restarted",
    CatalogChanged=>"catalog_changed", RewritePending=>"rewrite_pending", DeletionPending=>"deletion_pending"
});
wire_enum!(coverage_wire, coverage_decode, Coverage, { Empty=>"empty", Partial=>"partial", Complete=>"complete" });
wire_enum!(backfill_wire, backfill_decode, BackfillState, { Pending=>"pending", Running=>"running", Complete=>"complete", Deferred=>"deferred" });
wire_enum!(cycle_wire, cycle_decode, CycleState, { Queued=>"queued", Observing=>"observing", Committed=>"committed", Partial=>"partial", Aborted=>"aborted" });
wire_enum!(barrier_wire, barrier_decode, BarrierState, { Pending=>"pending", AwaitingCatalog=>"awaiting_catalog", Blocked=>"blocked" });

fn cycle_seq(n: i64) -> PortResult<CycleSeq> {
    CycleSeq::new(n).map_err(|_| corrupt())
}
fn count(n: i64) -> PortResult<u64> {
    u64::try_from(n).map_err(|_| corrupt())
}
fn sql_count(n: u64) -> PortResult<i64> {
    i64::try_from(n).map_err(|_| invalid())
}
fn optional_failure(r: &rusqlite::Row<'_>, i: usize) -> PortResult<Option<BackgroundFailure>> {
    r.get::<_, Option<String>>(i)
        .map_err(sql_error)?
        .as_deref()
        .map(failure_decode)
        .transpose()
}
fn optional_id(r: &rusqlite::Row<'_>, i: usize) -> PortResult<Option<ControlId>> {
    r.get::<_, Option<String>>(i)
        .map_err(sql_error)?
        .map(id)
        .transpose()
}
fn optional_seq(r: &rusqlite::Row<'_>, i: usize) -> PortResult<Option<ControlSeq>> {
    r.get::<_, Option<i64>>(i)
        .map_err(sql_error)?
        .map(seq)
        .transpose()
}
fn optional_cycle(r: &rusqlite::Row<'_>, i: usize) -> PortResult<Option<CycleSeq>> {
    r.get::<_, Option<i64>>(i)
        .map_err(sql_error)?
        .map(cycle_seq)
        .transpose()
}
fn optional_time(r: &rusqlite::Row<'_>, i: usize) -> PortResult<Option<i64>> {
    let value: Option<i64> = r.get(i).map_err(sql_error)?;
    if value.is_some_and(|v| v < 0) {
        return Err(corrupt());
    }
    Ok(value)
}
struct RuntimeState {
    next_cycle: CycleSeq,
    worker: WorkerStatus,
    cycles: Vec<ObservationCycle>,
    barriers: Vec<LatestBarrier>,
    sources: Vec<SourceProgress>,
}
impl RuntimeState {
    fn cycle(&self, n: CycleSeq) -> PortResult<&ObservationCycle> {
        let position = self
            .cycles
            .binary_search_by_key(&n, |cycle| cycle.token.cycle_seq)
            .map_err(|_| missing())?;
        Ok(&self.cycles[position])
    }
}

fn load_worker(conn: &Connection) -> PortResult<WorkerStatus> {
    let mut stmt=conn.prepare("SELECT singleton,boot_id,pid_hint,heartbeat_at_ms,effective_state,last_error FROM worker_state").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let r = rows.next().map_err(sql_error)?.ok_or_else(corrupt)?;
    if r.get::<_, i64>(0).map_err(sql_error)? != 1 {
        return Err(corrupt());
    }
    let pid = r
        .get::<_, Option<i64>>(2)
        .map_err(sql_error)?
        .map(|v| u32::try_from(v).map_err(|_| corrupt()))
        .transpose()?;
    let worker = WorkerStatus {
        boot_id: optional_id(r, 1)?,
        pid_hint: pid,
        heartbeat_at_ms: optional_time(r, 3)?,
        state: update_decode(&r.get::<_, String>(4).map_err(sql_error)?)?,
        error: optional_failure(r, 5)?,
    };
    if rows.next().map_err(sql_error)?.is_some()
        || pid == Some(0)
        || (worker.boot_id.is_some() != pid.is_some())
        || (worker.boot_id.is_none()
            && (worker.state != UpdateState::Offline
                || worker.heartbeat_at_ms.is_some()
                || worker.error.is_some()))
        || (worker.boot_id.is_some() && worker.heartbeat_at_ms.is_none())
    {
        return Err(corrupt());
    }
    Ok(worker)
}
fn load_cycles(
    conn: &Connection,
    status: &ControlStatus,
    next: CycleSeq,
) -> PortResult<Vec<ObservationCycle>> {
    let mut stmt=conn.prepare("SELECT cycle_seq,worker_boot_id,policy_epoch,state,admitted_control_seq,started_control_seq,started_at_ms,completed_at_ms FROM cycles WHERE cycle_seq IN (SELECT cycle_seq FROM asg_runtime_cycles) ORDER BY cycle_seq").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut cycles = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let c = ObservationCycle {
            token: ObservationToken {
                cycle_seq: cycle_seq(r.get(0).map_err(sql_error)?)?,
                worker_boot_id: id(r.get(1).map_err(sql_error)?)?,
            },
            policy_epoch: epoch(r.get(2).map_err(sql_error)?)?,
            state: cycle_decode(&r.get::<_, String>(3).map_err(sql_error)?)?,
            admitted_control_seq: seq(r.get(4).map_err(sql_error)?)?,
            started_control_seq: optional_seq(r, 5)?,
            started_at_ms: optional_time(r, 6)?,
            completed_at_ms: optional_time(r, 7)?,
            selections: Vec::new(),
        };
        if c.token.cycle_seq >= next
            || c.policy_epoch > status.policy.policy_epoch
            || c.admitted_control_seq > status.policy.control_seq
            || c.started_control_seq
                .is_some_and(|s| s <= c.admitted_control_seq || s > status.policy.control_seq)
            || c.started_control_seq.is_some() != c.started_at_ms.is_some()
            || (c.state == CycleState::Queued
                && (c.started_control_seq.is_some() || c.completed_at_ms.is_some()))
            || (matches!(
                c.state,
                CycleState::Observing | CycleState::Committed | CycleState::Partial
            ) && c.started_control_seq.is_none())
            || (c.state == CycleState::Observing && c.completed_at_ms.is_some())
            || (matches!(c.state, CycleState::Committed | CycleState::Partial)
                && c.completed_at_ms.is_none())
        {
            return Err(corrupt());
        }
        cycles.push(c);
    }
    let mut stmt=conn.prepare("SELECT cycle_seq,selection_id,selection_revision,discovery_complete,root_identity,discovered_count,observed_count,committed_count,error_code FROM cycle_selections WHERE cycle_seq IN (SELECT cycle_seq FROM asg_runtime_cycles) ORDER BY cycle_seq,selection_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let n = cycle_seq(r.get(0).map_err(sql_error)?)?;
        // cycles are ordered by their primary key. Keep every typed
        // validation below while avoiding a full historical scan per row.
        let position = cycles
            .binary_search_by_key(&n, |cycle| cycle.token.cycle_seq)
            .map_err(|_| corrupt())?;
        let c = &mut cycles[position];
        let s = CycleSelection {
            selection: SelectionRevision {
                selection_id: id(r.get(1).map_err(sql_error)?)?,
                revision: seq(r.get(2).map_err(sql_error)?)?,
                root_identity: id(r.get(4).map_err(sql_error)?)?,
            },
            discovery_complete: boolean(r.get(3).map_err(sql_error)?)?,
            discovered_count: count(r.get(5).map_err(sql_error)?)?,
            observed_count: count(r.get(6).map_err(sql_error)?)?,
            committed_count: count(r.get(7).map_err(sql_error)?)?,
            error: optional_failure(r, 8)?,
        };
        let selection_index = status
            .policy
            .selections
            .binary_search_by(|selected| selected.id.cmp(&s.selection.selection_id))
            .map_err(|_| corrupt())?;
        let selected = &status.policy.selections[selection_index];
        if s.selection.revision.get() == 0
            || s.selection.revision > selected.revision
            || s.committed_count > s.observed_count
            || s.observed_count > s.discovered_count
            || (s.discovery_complete && s.error.is_some())
            || (c.state == CycleState::Queued
                && (s.discovery_complete || s.discovered_count != 0 || s.error.is_some()))
        {
            return Err(corrupt());
        }
        c.selections.push(s);
    }
    for cycle in &cycles {
        runtime_tick()?;
        if cycle.selections.is_empty() {
            return Err(corrupt());
        }
        if cycle.state == CycleState::Committed {
            for selection in &cycle.selections {
                runtime_tick()?;
                if !selection.discovery_complete
                    || selection.error.is_some()
                    || selection.committed_count != selection.discovered_count
                {
                    return Err(corrupt());
                }
            }
        }
    }
    Ok(cycles)
}

fn load_barriers(
    conn: &Connection,
    status: &ControlStatus,
    cycles: &[ObservationCycle],
) -> PortResult<Vec<LatestBarrier>> {
    let mut stmt=conn.prepare("SELECT barrier_id,policy_epoch,admission_control_seq,required_cycle_seq,state,requested_wait_ms,admitted_at_ms,completed_cycle_seq,catalog_incarnation,error_code FROM barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_runtime_barriers) ORDER BY barrier_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut barriers = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let wait = u32::try_from(r.get::<_, i64>(5).map_err(sql_error)?).map_err(|_| corrupt())?;
        let b = LatestBarrier {
            id: id(r.get(0).map_err(sql_error)?)?,
            policy_epoch: epoch(r.get(1).map_err(sql_error)?)?,
            admission_control_seq: seq(r.get(2).map_err(sql_error)?)?,
            required_cycle_seq: cycle_seq(r.get(3).map_err(sql_error)?)?,
            state: barrier_decode(&r.get::<_, String>(4).map_err(sql_error)?)?,
            requested_wait_ms: wait,
            admitted_at_ms: r.get(6).map_err(sql_error)?,
            completed_cycle_seq: optional_cycle(r, 7)?,
            error: optional_failure(r, 9)?,
            selections: Vec::new(),
        };
        let position = cycles
            .binary_search_by_key(&b.required_cycle_seq, |cycle| cycle.token.cycle_seq)
            .map_err(|_| corrupt())?;
        let c = &cycles[position];
        if wait > MAX_LATEST_WAIT_MS
            || b.admitted_at_ms < 0
            || b.policy_epoch != c.policy_epoch
            || b.admission_control_seq > status.policy.control_seq
            || b.admission_control_seq < c.admitted_control_seq
            || c.started_control_seq
                .is_some_and(|s| s <= b.admission_control_seq)
            || optional_id(r, 8)?.is_some()
            || (b.state == BarrierState::Blocked) != b.error.is_some()
            || (b.state == BarrierState::AwaitingCatalog && b.completed_cycle_seq.is_none())
            || (b.state == BarrierState::Pending
                && (b.completed_cycle_seq.is_some()
                    || !matches!(c.state, CycleState::Queued | CycleState::Observing)))
            || b.completed_cycle_seq.is_some_and(|n| {
                n != c.token.cycle_seq
                    || !matches!(
                        c.state,
                        CycleState::Committed | CycleState::Partial | CycleState::Aborted
                    )
            })
        {
            return Err(corrupt());
        }
        barriers.push(b);
    }
    let mut stmt=conn.prepare("SELECT barrier_id,selection_id,selection_revision FROM barrier_selections WHERE barrier_id IN (SELECT barrier_id FROM asg_runtime_barriers) ORDER BY barrier_id,selection_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let bid = id(r.get(0).map_err(sql_error)?)?;
        let position = barriers
            .binary_search_by(|barrier| barrier.id.cmp(&bid))
            .map_err(|_| corrupt())?;
        let b = &mut barriers[position];
        let selection = id(r.get(1).map_err(sql_error)?)?;
        let revision = seq(r.get(2).map_err(sql_error)?)?;
        let position = cycles
            .binary_search_by_key(&b.required_cycle_seq, |cycle| cycle.token.cycle_seq)
            .map_err(|_| corrupt())?;
        let c = &cycles[position];
        let selected = c
            .selections
            .binary_search_by(|selected| selected.selection.selection_id.cmp(&selection))
            .map_err(|_| corrupt())?;
        let s = &c.selections[selected];
        if s.selection.revision != revision {
            return Err(corrupt());
        }
        b.selections.push(s.selection.clone());
    }
    if barriers.iter().any(|b| b.selections.is_empty()) {
        return Err(corrupt());
    }
    Ok(barriers)
}

fn observation(cycles: &[ObservationCycle], n: CycleSeq) -> PortResult<ObservationToken> {
    let position = cycles
        .binary_search_by_key(&n, |cycle| cycle.token.cycle_seq)
        .map_err(|_| corrupt())?;
    let c = &cycles[position];
    if c.started_control_seq.is_none() {
        return Err(corrupt());
    }
    Ok(c.token.clone())
}
fn load_sources(conn: &Connection, cycles: &[ObservationCycle]) -> PortResult<Vec<SourceProgress>> {
    let mut stmt=conn.prepare("SELECT source_id,provider_id,last_attempt_at_ms,last_observed_cycle,indexed_revision,receipt_cycle,catalog_incarnation,catalog_generation,coverage,update_state,error_code,backfill_state,missing_first_cycle,missing_confirm_cycle,confirmation_boot_id,confirmation_root_identity,confirmation_policy_epoch,rewrite_candidate_digest,rewrite_first_cycle,rewrite_confirm_cycle,confirmation_first_monotonic_ms FROM source_updates ORDER BY source_id").map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    let mut sources = Vec::new();
    while let Some(r) = rows.next().map_err(sql_error)? {
        runtime_tick()?;
        let last = optional_cycle(r, 3)?
            .map(|n| observation(cycles, n))
            .transpose()?;
        let receipt = match (
            optional_id(r, 4)?,
            optional_cycle(r, 5)?,
            optional_id(r, 6)?,
            optional_seq(r, 7)?,
        ) {
            (Some(revision), Some(n), Some(catalog_incarnation), Some(catalog_generation)) => {
                Some(SourceReceiptSummary {
                    token: observation(cycles, n)?,
                    revision,
                    catalog_incarnation,
                    catalog_generation,
                })
            }
            (None, None, None, None) => None,
            _ => return Err(corrupt()),
        };
        let missing_first = optional_cycle(r, 12)?;
        let missing_confirm = optional_cycle(r, 13)?;
        let boot = optional_id(r, 14)?;
        let root = optional_id(r, 15)?;
        let policy = optional_seq(r, 16)?;
        let digest = optional_id(r, 17)?;
        let rewrite_first = optional_cycle(r, 18)?;
        let rewrite_confirm = optional_cycle(r, 19)?;
        let monotonic = optional_seq(r, 20)?;
        let confirmation = match (missing_first, rewrite_first, boot, root, policy, monotonic) {
            (None, None, None, None, None, None)
                if missing_confirm.is_none() && rewrite_confirm.is_none() && digest.is_none() =>
            {
                None
            }
            (
                first,
                other,
                Some(worker_boot_id),
                Some(root_identity),
                Some(p),
                Some(first_monotonic_ms),
            ) => {
                let (kind, first_cycle, confirm_cycle) = match (first, other, digest) {
                    (Some(f), None, None) if rewrite_confirm.is_none() => {
                        (ConfirmationKind::Deletion, f, missing_confirm)
                    }
                    (None, Some(f), Some(candidate_digest)) if missing_confirm.is_none() => (
                        ConfirmationKind::Rewrite { candidate_digest },
                        f,
                        rewrite_confirm,
                    ),
                    _ => return Err(corrupt()),
                };
                Some(PendingConfirmation {
                    kind,
                    first_cycle,
                    confirm_cycle,
                    worker_boot_id,
                    root_identity,
                    policy_epoch: epoch(p.get())?,
                    first_monotonic_ms,
                })
            }
            _ => return Err(corrupt()),
        };
        let s = SourceProgress {
            source_id: id(r.get(0).map_err(sql_error)?)?,
            provider: provider(r.get(1).map_err(sql_error)?)?,
            last_attempt_at_ms: optional_time(r, 2)?,
            last_observation: last,
            receipt,
            coverage: coverage_decode(&r.get::<_, String>(8).map_err(sql_error)?)?,
            update_state: update_decode(&r.get::<_, String>(9).map_err(sql_error)?)?,
            error: optional_failure(r, 10)?,
            backfill_state: backfill_decode(&r.get::<_, String>(11).map_err(sql_error)?)?,
            confirmation,
        };
        if s.receipt.as_ref().is_some_and(|p| {
            s.last_observation
                .as_ref()
                .is_some_and(|o| p.token.cycle_seq > o.cycle_seq)
        }) || (s.coverage == Coverage::Complete
            && (s.error.is_some()
                || s.receipt
                    .as_ref()
                    .is_none_or(|r| s.last_observation.as_ref() != Some(&r.token))))
            || (s.last_observation.is_some() && s.last_attempt_at_ms.is_none())
            || (s.confirmation.is_some()
                && (s.update_state != UpdateState::Deferred || s.coverage == Coverage::Complete))
        {
            return Err(corrupt());
        }
        if let Some(c) = &s.confirmation {
            validate_confirmation(c, cycles).map_err(|_| corrupt())?;
        }
        sources.push(s);
    }
    Ok(sources)
}
fn validate_confirmation(c: &PendingConfirmation, cycles: &[ObservationCycle]) -> PortResult<()> {
    if c.confirm_cycle.is_some_and(|n| n <= c.first_cycle) {
        return Err(invalid());
    }
    for n in std::iter::once(c.first_cycle).chain(c.confirm_cycle) {
        let position = cycles
            .binary_search_by_key(&n, |cycle| cycle.token.cycle_seq)
            .map_err(|_| invalid())?;
        let cycle = &cycles[position];
        if cycle.token.worker_boot_id != c.worker_boot_id
            || cycle.policy_epoch != c.policy_epoch
            || cycle.started_control_seq.is_none()
            || !cycle
                .selections
                .iter()
                .any(|s| s.selection.root_identity == c.root_identity)
        {
            return Err(invalid());
        }
    }
    Ok(())
}
/// Materialize only the current scheduling graph and a small diagnostic tail.
/// Historical facts remain stored. A caller asking for an older exact token
/// explicitly adds that token and its barrier dependencies before decoding.
fn runtime_rows_within(conn: &Connection, query: &str, limit: usize) -> PortResult<()> {
    runtime_tick()?;
    let count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM ({query} LIMIT ?1)"),
            [i64::try_from(limit + 1).map_err(|_| runtime_capacity())?],
            |r| r.get(0),
        )
        .map_err(sql_error)?;
    if count > limit as i64 {
        return Err(runtime_capacity());
    }
    Ok(())
}
fn validate_staged_capacity(conn: &Connection) -> PortResult<()> {
    for query in [
        "SELECT 1 FROM asg_runtime_cycles",
        "SELECT 1 FROM asg_runtime_barriers",
        "SELECT 1 FROM source_updates",
    ] {
        runtime_rows_within(conn, query, MAX_RUNTIME_REFERENCES)?;
    }
    for query in [
        "SELECT 1 FROM cycle_selections WHERE cycle_seq IN (SELECT cycle_seq FROM asg_runtime_cycles)",
        "SELECT 1 FROM barrier_selections WHERE barrier_id IN (SELECT barrier_id FROM asg_runtime_barriers)",
    ] {
        runtime_rows_within(conn, query, MAX_RUNTIME_RELATIONS)?;
    }
    Ok(())
}

fn stage_runtime(
    conn: &Connection,
    requested_cycle: Option<CycleSeq>,
    requested_barrier: Option<&ControlId>,
) -> PortResult<()> {
    runtime_tick()?;
    for query in [
        "SELECT 1 FROM cycles WHERE state IN ('queued','observing')",
        "SELECT 1 FROM barriers WHERE state='pending'",
        "SELECT 1 FROM source_updates",
    ] {
        runtime_rows_within(conn, query, MAX_RUNTIME_REFERENCES)?;
    }
    conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS asg_runtime_cycles(cycle_seq INTEGER PRIMARY KEY) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS asg_runtime_barriers(barrier_id TEXT PRIMARY KEY) WITHOUT ROWID;
        DELETE FROM asg_runtime_cycles; DELETE FROM asg_runtime_barriers;
        INSERT INTO asg_runtime_cycles SELECT cycle_seq FROM cycles WHERE state IN ('queued','observing');
        INSERT INTO asg_runtime_barriers SELECT barrier_id FROM barriers WHERE state='pending';").map_err(sql_error)?;
    conn.execute("INSERT OR IGNORE INTO asg_runtime_cycles SELECT cycle_seq FROM cycles ORDER BY cycle_seq DESC LIMIT ?1", [RUNTIME_HISTORY_TAIL]).map_err(sql_error)?;
    conn.execute("INSERT OR IGNORE INTO asg_runtime_barriers SELECT barrier_id FROM barriers ORDER BY admission_control_seq DESC,barrier_id LIMIT ?1", [RUNTIME_HISTORY_TAIL]).map_err(sql_error)?;
    if let Some(number) = requested_cycle {
        conn.execute(
            "INSERT OR IGNORE INTO asg_runtime_cycles VALUES(?1)",
            [number.get()],
        )
        .map_err(sql_error)?;
    }
    if let Some(identifier) = requested_barrier {
        conn.execute(
            "INSERT OR IGNORE INTO asg_runtime_barriers VALUES(?1)",
            [identifier.as_str()],
        )
        .map_err(sql_error)?;
    }
    conn.execute_batch("INSERT OR IGNORE INTO asg_runtime_cycles
        SELECT required_cycle_seq FROM barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_runtime_barriers)
        UNION SELECT completed_cycle_seq FROM barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_runtime_barriers) AND completed_cycle_seq IS NOT NULL;
        INSERT OR IGNORE INTO asg_runtime_cycles
        SELECT last_observed_cycle FROM source_updates WHERE last_observed_cycle IS NOT NULL
        UNION SELECT receipt_cycle FROM source_updates WHERE receipt_cycle IS NOT NULL
        UNION SELECT missing_first_cycle FROM source_updates WHERE missing_first_cycle IS NOT NULL
        UNION SELECT missing_confirm_cycle FROM source_updates WHERE missing_confirm_cycle IS NOT NULL
        UNION SELECT rewrite_first_cycle FROM source_updates WHERE rewrite_first_cycle IS NOT NULL
        UNION SELECT rewrite_confirm_cycle FROM source_updates WHERE rewrite_confirm_cycle IS NOT NULL;").map_err(sql_error)?;
    validate_staged_capacity(conn)
}

fn load_runtime(conn: &Connection, status: &ControlStatus) -> PortResult<RuntimeState> {
    load_runtime_for(conn, status, None, None)
}

fn load_runtime_for(
    conn: &Connection,
    status: &ControlStatus,
    requested_cycle: Option<CycleSeq>,
    requested_barrier: Option<&ControlId>,
) -> PortResult<RuntimeState> {
    stage_runtime(conn, requested_cycle, requested_barrier)?;
    load_staged_runtime(conn, status)
}

fn load_staged_runtime(conn: &Connection, status: &ControlStatus) -> PortResult<RuntimeState> {
    validate_staged_capacity(conn)?;
    let next_cycle = cycle_seq(
        conn.query_row(
            "SELECT next_cycle_seq FROM control_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql_error)?,
    )?;
    let worker = load_worker(conn)?;
    let cycles = load_cycles(conn, status, next_cycle)?;
    let mut observing = false;
    for cycle in &cycles {
        runtime_tick()?;
        if cycle.state == CycleState::Observing {
            if observing {
                return Err(corrupt());
            }
            observing = true;
        }
        if matches!(cycle.state, CycleState::Queued | CycleState::Observing) {
            if worker.boot_id.as_ref() != Some(&cycle.token.worker_boot_id)
                || cycle.policy_epoch != status.policy.policy_epoch
                || status.desired_updates != DesiredUpdates::Running
                || status.policy.maintenance.state != MaintenanceState::Idle
            {
                return Err(corrupt());
            }
            for selection in &cycle.selections {
                runtime_tick()?;
                let index = status
                    .policy
                    .selections
                    .binary_search_by(|current| current.id.cmp(&selection.selection.selection_id))
                    .map_err(|_| corrupt())?;
                let current = &status.policy.selections[index];
                if !current.enabled
                    || current.revision != selection.selection.revision
                    || current.root_identity.as_ref() != Some(&selection.selection.root_identity)
                {
                    return Err(corrupt());
                }
            }
        }
    }
    let barriers = load_barriers(conn, status, &cycles)?;
    let sources = load_sources(conn, &cycles)?;
    for source in &sources {
        runtime_tick()?;
        if source
            .receipt
            .as_ref()
            .is_some_and(|r| status.catalog_incarnation.as_ref() != Some(&r.catalog_incarnation))
        {
            return Err(corrupt());
        }
        if let Some(confirm) = &source.confirmation
            && (worker.boot_id.as_ref() != Some(&confirm.worker_boot_id)
                || confirm.policy_epoch != status.policy.policy_epoch
                || source.last_observation.as_ref().is_none_or(|o| {
                    o.cycle_seq != confirm.confirm_cycle.unwrap_or(confirm.first_cycle)
                })
                || source.error
                    != Some(match confirm.kind {
                        ConfirmationKind::Deletion => BackgroundFailure::DeletionPending,
                        ConfirmationKind::Rewrite { .. } => BackgroundFailure::RewritePending,
                    }))
        {
            return Err(corrupt());
        }
        for token in source
            .last_observation
            .iter()
            .chain(source.receipt.iter().map(|r| &r.token))
        {
            let position = cycles
                .binary_search_by_key(&token.cycle_seq, |cycle| cycle.token.cycle_seq)
                .map_err(|_| corrupt())?;
            let c = &cycles[position];
            if c.token != *token {
                return Err(corrupt());
            }
            let mut provider_proven = false;
            for selection in &c.selections {
                runtime_tick()?;
                let index = status
                    .policy
                    .selections
                    .binary_search_by(|current| current.id.cmp(&selection.selection.selection_id))
                    .map_err(|_| corrupt())?;
                if status.policy.selections[index].region.provider == source.provider {
                    provider_proven = true;
                    break;
                }
            }
            if !provider_proven {
                return Err(corrupt());
            }
        }
    }
    Ok(RuntimeState {
        next_cycle,
        worker,
        cycles,
        barriers,
        sources,
    })
}

fn invalidate_scheduling(
    conn: &Connection,
    reason: BackgroundFailure,
    now: Option<i64>,
) -> PortResult<()> {
    conn.execute("UPDATE cycles SET state='aborted',completed_at_ms=COALESCE(?1,completed_at_ms) WHERE state IN ('queued','observing')",[now]).map_err(sql_error)?;
    conn.execute("UPDATE barriers SET state='blocked',error_code=?1 WHERE state IN ('pending','awaiting_catalog')",[failure_wire(reason)]).map_err(sql_error)?;
    conn.execute("UPDATE source_updates SET coverage=CASE WHEN receipt_cycle IS NULL THEN 'empty' ELSE 'partial' END,update_state='deferred',error_code=?1,backfill_state='pending',missing_first_cycle=NULL,missing_confirm_cycle=NULL,confirmation_boot_id=NULL,confirmation_root_identity=NULL,confirmation_policy_epoch=NULL,rewrite_candidate_digest=NULL,rewrite_first_cycle=NULL,rewrite_confirm_cycle=NULL,confirmation_first_monotonic_ms=NULL",[failure_wire(reason)]).map_err(sql_error)?;
    Ok(())
}

fn authority_matches(
    target_root: RootIdentity,
    a: &dyn WorkerAuthority,
    status: &ControlStatus,
    runtime: &RuntimeState,
    current: bool,
) -> PortResult<()> {
    a.validate()?;
    if a.root_binding() != target_root.binding()
        || a.installation_id() != &status.policy.installation_id
        || (current && runtime.worker.boot_id.as_ref() != Some(a.boot_id()))
    {
        return Err(conflict());
    }
    Ok(())
}
fn blocked_reason(status: &ControlStatus, worker: &WorkerStatus) -> Option<BackgroundFailure> {
    match status.desired_updates {
        DesiredUpdates::Paused => return Some(BackgroundFailure::Paused),
        DesiredUpdates::Stopped => return Some(BackgroundFailure::Stopped),
        _ => {}
    }
    if status.policy.maintenance.state != MaintenanceState::Idle {
        return Some(BackgroundFailure::Upgrading);
    }
    if worker.boot_id.is_none() {
        return Some(BackgroundFailure::Offline);
    }
    match worker.state {
        UpdateState::Offline => Some(BackgroundFailure::Offline),
        UpdateState::Paused => Some(BackgroundFailure::Paused),
        UpdateState::Stopped => Some(BackgroundFailure::Stopped),
        UpdateState::Busy => Some(BackgroundFailure::Busy),
        UpdateState::Deferred => Some(BackgroundFailure::Deferred),
        UpdateState::Upgrading => Some(BackgroundFailure::Upgrading),
        UpdateState::Failed => Some(BackgroundFailure::Failed),
        _ => None,
    }
}
fn validate_selection_set(
    status: &ControlStatus,
    selections: &mut [SelectionRevision],
) -> PortResult<()> {
    if selections.is_empty() || selections.len() > 4096 {
        return Err(invalid());
    }
    selections.sort_by(|a, b| a.selection_id.cmp(&b.selection_id));
    if selections
        .windows(2)
        .any(|s| s[0].selection_id == s[1].selection_id)
    {
        return Err(invalid());
    }
    for s in selections {
        runtime_tick()?;
        let selected_index = status
            .policy
            .selections
            .binary_search_by(|selected| selected.id.cmp(&s.selection_id))
            .map_err(|_| invalid())?;
        let selected = &status.policy.selections[selected_index];
        if !selected.enabled
            || selected.revision != s.revision
            || selected.root_identity.as_ref() != Some(&s.root_identity)
        {
            return Err(conflict());
        }
    }
    Ok(())
}
fn cycle_owned<'a>(
    target_root: RootIdentity,
    runtime: &'a RuntimeState,
    status: &ControlStatus,
    a: &dyn WorkerAuthority,
    n: CycleSeq,
) -> PortResult<&'a ObservationCycle> {
    authority_matches(target_root, a, status, runtime, true)?;
    let c = runtime.cycle(n)?;
    if c.token.worker_boot_id != *a.boot_id() || c.policy_epoch != status.policy.policy_epoch {
        return Err(conflict());
    }
    Ok(c)
}
fn allocate_cycle(
    conn: &Connection,
    status: &ControlStatus,
    runtime: &RuntimeState,
    selections: &[SelectionRevision],
) -> PortResult<ObservationCycle> {
    // Exact selected sets coalesce; differing sets use another global sequence.
    // This conservative compatibility rule never widens request relevance.
    if let Some(c) = runtime.cycles.iter().find(|c| {
        c.state == CycleState::Queued
            && c.policy_epoch == status.policy.policy_epoch
            && runtime.worker.boot_id.as_ref() == Some(&c.token.worker_boot_id)
            && c.selections
                .iter()
                .map(|s| &s.selection)
                .eq(selections.iter())
    }) {
        return Ok(c.clone());
    }
    if runtime.cycles.len() >= MAX_RUNTIME_REFERENCES {
        return Err(runtime_capacity());
    }
    runtime_tick()?;
    let boot = runtime.worker.boot_id.as_ref().ok_or_else(invalid)?;
    let n = runtime.next_cycle;
    let next = increment(n.get())?;
    let admitted = seq(increment(status.policy.control_seq.get())?)?;
    conn.execute(
        "UPDATE control_meta SET next_cycle_seq=?1 WHERE singleton=1",
        [next],
    )
    .map_err(sql_error)?;
    conn.execute("INSERT INTO cycles(cycle_seq,worker_boot_id,policy_epoch,state,admitted_control_seq) VALUES(?1,?2,?3,'queued',?4)",params![n.get(),boot.as_str(),status.policy.policy_epoch.get(),admitted.get()]).map_err(sql_error)?;
    let mut selected = Vec::new();
    for s in selections {
        runtime_tick()?;
        conn.execute("INSERT INTO cycle_selections(cycle_seq,selection_id,selection_revision,root_identity) VALUES(?1,?2,?3,?4)",params![n.get(),s.selection_id.as_str(),s.revision.get(),s.root_identity.as_str()]).map_err(sql_error)?;
        selected.push(CycleSelection {
            selection: s.clone(),
            discovery_complete: false,
            discovered_count: 0,
            observed_count: 0,
            committed_count: 0,
            error: None,
        });
    }
    Ok(ObservationCycle {
        token: ObservationToken {
            cycle_seq: n,
            worker_boot_id: boot.clone(),
        },
        policy_epoch: status.policy.policy_epoch,
        state: CycleState::Queued,
        admitted_control_seq: admitted,
        started_control_seq: None,
        started_at_ms: None,
        completed_at_ms: None,
        selections: selected,
    })
}

/// Complete content-free references captured under worker and history-reader
/// ownership. A later control sequence invalidates this inventory.
#[derive(Debug, Clone)]
pub(crate) struct ControlHistoryDependencies {
    pub control_seq: ControlSeq,
    pub policy_epoch: PolicyEpoch,
    pub installation: ControlId,
    pub incarnation: Option<ControlId>,
    pub cycles: Vec<CycleSeq>,
    pub receipts: Vec<agent_session_grep_ports::managed::RevisionId>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ControlHistoryCounts {
    pub barriers: usize,
    pub cycles: usize,
    pub has_more: bool,
}

impl SqliteControlStore {
    /// Explicit start/reset wakes an exhausted supervisor without changing
    /// permission, pause, stop, maintenance, or claiming a live worker.
    pub fn request_background_start(
        &self,
        expected: ControlSeq,
    ) -> PortResult<ControlChange<ControlSeq>> {
        self.mutate(expected, |conn, current| {
            let request = seq(increment(current.restart_request_seq.get())?)?;
            conn.execute(
                "UPDATE control_meta SET restart_request_seq=?1 WHERE singleton=1",
                [request.get()],
            )
            .map_err(sql_error)?;
            Ok((true, false, request))
        })
    }

    pub(crate) fn capture_history_dependencies(
        &self,
        authority: &dyn WorkerAuthority,
        readers: &ExclusiveGuard,
        deadline: Instant,
    ) -> PortResult<ControlHistoryDependencies> {
        self.with_runtime_deadline(deadline, || {
            self.validate_guard(readers, LockKind::HistoryReaders)?;
            readers.validate_current(&self.private_root)?;
            let mut conn = self.conn.borrow_mut();
            let tx = conn.transaction().map_err(sql_error)?;
            let status = load_status_core(&tx)?;
            let runtime = load_runtime(&tx, &status)?;
            authority_matches(self.root_identity, authority, &status, &runtime, true)?;
            if status.policy.maintenance.state != MaintenanceState::Idle {
                return Err(conflict());
            }
            let mut cycles = std::collections::BTreeSet::new();
            let mut receipts = std::collections::BTreeSet::new();
            for source in &runtime.sources {
                runtime_tick()?;
                for token in source
                    .last_observation
                    .iter()
                    .chain(source.receipt.iter().map(|receipt| &receipt.token))
                {
                    cycles.insert(token.cycle_seq);
                }
                if let Some(receipt) = &source.receipt {
                    receipts.insert(agent_session_grep_ports::managed::RevisionId::parse(
                        receipt.revision.as_str(),
                    )?);
                }
                if let Some(confirmation) = &source.confirmation {
                    cycles.insert(confirmation.first_cycle);
                    if let Some(cycle) = confirmation.confirm_cycle {
                        cycles.insert(cycle);
                    }
                }
            }
            for barrier in &runtime.barriers {
                runtime_tick()?;
                cycles.insert(barrier.required_cycle_seq);
                if let Some(cycle) = barrier.completed_cycle_seq {
                    cycles.insert(cycle);
                }
            }
            for cycle in &runtime.cycles {
                runtime_tick()?;
                if matches!(cycle.state, CycleState::Queued | CycleState::Observing) {
                    cycles.insert(cycle.token.cycle_seq);
                }
            }
            if cycles.len() > MAX_RUNTIME_REFERENCES || receipts.len() > MAX_RUNTIME_REFERENCES {
                return Err(PortError::WriterBusy(
                    "history dependency inventory exceeds capacity".into(),
                ));
            }
            let value = ControlHistoryDependencies {
                control_seq: status.policy.control_seq,
                policy_epoch: status.policy.policy_epoch,
                installation: status.policy.installation_id,
                incarnation: status.catalog_incarnation,
                cycles: cycles.into_iter().collect(),
                receipts: receipts.into_iter().collect(),
            };
            runtime_tick()?;
            tx.commit().map_err(sql_error)?;
            Ok(value)
        })
    }

    /// Catalog retention commits first. Failure here only retains additional
    /// scheduling proof. No source, confirmation or pending-barrier token is
    /// deleted; these counters never establish catalog freshness.
    pub(crate) fn prune_history(
        &self,
        authority: &dyn WorkerAuthority,
        readers: &ExclusiveGuard,
        captured: &ControlHistoryDependencies,
        retained: &[ObservationToken],
        deadline: Instant,
    ) -> PortResult<ControlHistoryCounts> {
        self.with_runtime_deadline(deadline, || {
            if !self.writable || retained.len() > MAX_RUNTIME_REFERENCES {
                return Err(invalid());
            }
            self.validate_guard(readers, LockKind::HistoryReaders)?;
            readers.validate_current(&self.private_root)?;
            let mut conn = self.conn.borrow_mut();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let status = load_status_core(&tx)?;
            let runtime = load_runtime(&tx, &status)?;
            authority_matches(self.root_identity, authority, &status, &runtime, true)?;
            if status.policy.control_seq != captured.control_seq
                || status.policy.policy_epoch != captured.policy_epoch
                || status.policy.installation_id != captured.installation
                || status.catalog_incarnation != captured.incarnation
                || status.policy.maintenance.state != MaintenanceState::Idle
            {
                return Err(conflict());
            }
            tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS asg_history_keep(cycle_seq INTEGER PRIMARY KEY) WITHOUT ROWID;
                CREATE TEMP TABLE IF NOT EXISTS asg_history_remove_cycles(cycle_seq INTEGER PRIMARY KEY) WITHOUT ROWID;
                CREATE TEMP TABLE IF NOT EXISTS asg_history_remove_barriers(barrier_id TEXT PRIMARY KEY) WITHOUT ROWID;
                DELETE FROM asg_history_keep; DELETE FROM asg_history_remove_cycles; DELETE FROM asg_history_remove_barriers;").map_err(sql_error)?;
            for token in retained {
                runtime_tick()?;
                let boot: Option<String> = tx
                    .query_row(
                        "SELECT worker_boot_id FROM cycles WHERE cycle_seq=?1",
                        [token.cycle_seq.get()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql_error)?;
                if boot.as_deref() != Some(token.worker_boot_id.as_str()) {
                    return Err(corrupt());
                }
                tx.execute(
                    "INSERT OR IGNORE INTO asg_history_keep VALUES(?1)",
                    [token.cycle_seq.get()],
                )
                .map_err(sql_error)?;
            }
            for cycle in &captured.cycles {
                runtime_tick()?;
                tx.execute(
                    "INSERT OR IGNORE INTO asg_history_keep VALUES(?1)",
                    [cycle.get()],
                )
                .map_err(sql_error)?;
            }
            // The drain proves no live request still waits on a completed or
            // blocked barrier. Keep a diagnostic tail and all pending work.
            tx.execute("INSERT INTO asg_history_remove_barriers SELECT barrier_id FROM barriers WHERE state IN ('blocked','awaiting_catalog') AND barrier_id NOT IN (SELECT barrier_id FROM barriers ORDER BY admission_control_seq DESC,barrier_id LIMIT ?1) LIMIT 64", [RUNTIME_HISTORY_TAIL]).map_err(sql_error)?;
            // Validate every candidate before deleting any row. The live
            // status bound is not permission to erase malformed old records.
            tx.execute_batch("INSERT OR IGNORE INTO asg_runtime_barriers SELECT barrier_id FROM asg_history_remove_barriers;
                INSERT OR IGNORE INTO asg_runtime_cycles SELECT required_cycle_seq FROM barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_history_remove_barriers)
                UNION SELECT completed_cycle_seq FROM barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_history_remove_barriers) AND completed_cycle_seq IS NOT NULL;").map_err(sql_error)?;
            load_staged_runtime(&tx, &status)?;
            tx.execute("DELETE FROM barrier_selections WHERE barrier_id IN (SELECT barrier_id FROM asg_history_remove_barriers)", []).map_err(sql_error)?;
            let barriers = tx.execute("DELETE FROM barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_history_remove_barriers)", []).map_err(sql_error)?;
            tx.execute_batch("INSERT OR IGNORE INTO asg_history_keep SELECT required_cycle_seq FROM barriers UNION SELECT completed_cycle_seq FROM barriers WHERE completed_cycle_seq IS NOT NULL;").map_err(sql_error)?;
            tx.execute("INSERT OR IGNORE INTO asg_history_keep SELECT cycle_seq FROM cycles ORDER BY cycle_seq DESC LIMIT ?1", [RUNTIME_HISTORY_TAIL]).map_err(sql_error)?;
            tx.execute_batch("INSERT INTO asg_history_remove_cycles SELECT cycle_seq FROM cycles WHERE state IN ('committed','partial','aborted') AND cycle_seq NOT IN (SELECT cycle_seq FROM asg_history_keep) LIMIT 64;
                INSERT OR IGNORE INTO asg_runtime_cycles SELECT cycle_seq FROM asg_history_remove_cycles;").map_err(sql_error)?;
            // Restage surviving barriers: their just-deleted rows are no longer
            // dependencies, while the selected cycle candidates remain staged.
            tx.execute_batch("DELETE FROM asg_runtime_barriers WHERE barrier_id IN (SELECT barrier_id FROM asg_history_remove_barriers);").map_err(sql_error)?;
            load_staged_runtime(&tx, &status)?;
            tx.execute("DELETE FROM cycle_selections WHERE cycle_seq IN (SELECT cycle_seq FROM asg_history_remove_cycles)", []).map_err(sql_error)?;
            let cycles = tx.execute("DELETE FROM cycles WHERE cycle_seq IN (SELECT cycle_seq FROM asg_history_remove_cycles)", []).map_err(sql_error)?;
            let more_barriers: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM barriers WHERE state IN ('blocked','awaiting_catalog') AND barrier_id NOT IN (SELECT barrier_id FROM barriers ORDER BY admission_control_seq DESC,barrier_id LIMIT ?1))", [RUNTIME_HISTORY_TAIL], |row| row.get(0)).map_err(sql_error)?;
            let more_cycles: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM cycles WHERE state IN ('committed','partial','aborted') AND cycle_seq NOT IN (SELECT cycle_seq FROM asg_history_keep))", [], |row| row.get(0)).map_err(sql_error)?;
            load_status(&tx)?;
            runtime_tick()?;
            tx.commit().map_err(sql_error)?;
            Ok(ControlHistoryCounts {
                barriers,
                cycles,
                has_more: more_barriers || more_cycles,
            })
        })
    }

    /// Mirror verified native registration; the caller owns the native receipt.
    /// Recording this flag alone is not a registration or login receipt.
    pub fn set_autostart_enabled(
        &self,
        expected: ControlSeq,
        enabled: bool,
    ) -> PortResult<ControlChange<bool>> {
        self.mutate(expected, |conn, current| {
            if current.autostart_enabled == enabled {
                return Ok((false, false, enabled));
            }
            conn.execute(
                "UPDATE control_meta SET autostart_enabled=?1 WHERE singleton=1",
                [enabled],
            )
            .map_err(sql_error)?;
            Ok((true, false, enabled))
        })
    }

    pub fn report_supervisor_failure(
        &self,
        expected: ControlSeq,
        guard: &ExclusiveGuard,
        failed: bool,
    ) -> PortResult<ControlChange<()>> {
        self.validate_guard(guard, LockKind::Supervisor)?;
        self.mutate(expected, |conn, current| {
            if current.supervisor_failed == failed {
                return Ok((false, false, ()));
            }
            conn.execute(
                "UPDATE control_meta SET supervisor_failed=?1 WHERE singleton=1",
                [failed],
            )
            .map_err(sql_error)?;
            Ok((true, false, ()))
        })
    }

    fn read_runtime<T>(
        &self,
        read: impl FnOnce(&ControlStatus, &RuntimeState) -> PortResult<T>,
    ) -> PortResult<T> {
        self.read_runtime_for(None, None, read)
    }

    fn read_runtime_for<T>(
        &self,
        requested_cycle: Option<CycleSeq>,
        requested_barrier: Option<&ControlId>,
        read: impl FnOnce(&ControlStatus, &RuntimeState) -> PortResult<T>,
    ) -> PortResult<T> {
        if runtime_deadline().is_none() {
            return self.with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || {
                self.read_runtime_for(requested_cycle, requested_barrier, read)
            });
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        configure_runtime_deadline(&conn)?;
        let tx = conn.transaction().map_err(sql_error)?;
        let status = load_status_core(&tx)?;
        let runtime = load_runtime_for(&tx, &status, requested_cycle, requested_barrier)?;
        let value = read(&status, &runtime)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        Ok(value)
    }

    /// The managed catalog facade calls this only with its verified live
    /// incarnation and a worker capability bound to this physical root. This
    /// repairs a summary forward; it never changes catalog identity or policy.
    pub(crate) fn reconcile_catalog_summary(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        incarnation: &ControlId,
        now_ms: i64,
    ) -> PortResult<ControlChange<()>> {
        checked_time(now_ms)?;
        self.mutate(expected, |conn, status| {
            let runtime = load_runtime(conn, status)?;
            authority_matches(self.root_identity, authority, status, &runtime, true)?;
            if status.policy.maintenance.state != MaintenanceState::Idle {
                return Err(conflict());
            }
            if status.catalog_incarnation.as_ref() == Some(incarnation) {
                return Ok((false, false, ()));
            }
            invalidate_scheduling(conn, BackgroundFailure::CatalogChanged, Some(now_ms))?;
            conn.execute("UPDATE source_updates SET last_observed_cycle=NULL,indexed_revision=NULL,receipt_cycle=NULL,catalog_incarnation=NULL,catalog_generation=NULL,coverage='empty'", []).map_err(sql_error)?;
            conn.execute("UPDATE barriers SET state='blocked',error_code='catalog_changed',completed_cycle_seq=NULL,catalog_incarnation=NULL", []).map_err(sql_error)?;
            conn.execute("UPDATE control_meta SET catalog_incarnation=?1 WHERE singleton=1", [incarnation.as_str()]).map_err(sql_error)?;
            Ok((true, false, ()))
        })
    }

    /// Repair a missing commit acknowledgement from an authenticated catalog
    /// head, including a receipt owned by an earlier worker boot. This is only
    /// a progress mirror; it never completes barriers or grants permissions.
    pub(crate) fn reconcile_source_summary(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        binding: &agent_session_grep_ports::managed::SourceBinding,
        receipt: &agent_session_grep_ports::managed::RevisionRef,
    ) -> PortResult<ControlChange<()>> {
        self.mutate(expected, |conn, status| {
            let runtime =
                load_runtime_for(conn, status, Some(CycleSeq::new(receipt.cycle_seq)?), None)?;
            authority_matches(self.root_identity, authority, status, &runtime, true)?;
            if status.policy.maintenance.state != MaintenanceState::Idle {
                return Err(conflict());
            }
            let source = ControlId::parse(binding.source_id.as_str())?;
            let locator = CanonicalLocator::parse(&binding.source_path)?;
            let incarnation = ControlId::parse(&receipt.catalog_incarnation)?;
            if !status
                .policy
                .allows_source(binding.provider, &locator, &source)
                || status.catalog_incarnation.as_ref() != Some(&incarnation)
                || !receipt.published
            {
                return Err(conflict());
            }
            let cycle = runtime
                .cycles
                .iter()
                .find(|c| c.token.cycle_seq.get() == receipt.cycle_seq)
                .ok_or_else(conflict)?;
            if cycle.token.worker_boot_id.as_str() != receipt.worker_boot_id
                || cycle.policy_epoch.get() != receipt.policy_epoch
                || cycle.started_control_seq.map(ControlSeq::get)
                    != Some(receipt.started_control_seq)
            {
                return Err(conflict());
            }
            let summary = SourceReceiptSummary {
                token: cycle.token.clone(),
                revision: ControlId::parse(receipt.revision_id.as_str())?,
                catalog_incarnation: incarnation,
                catalog_generation: ControlSeq::new(
                    receipt.committed_generation.ok_or_else(invalid)?,
                )?,
            };
            let prior = runtime.sources.iter().find(|s| s.source_id == source);
            if prior.and_then(|p| p.receipt.as_ref()) == Some(&summary) {
                return Ok((false, false, ()));
            }
            if prior.is_some_and(|p| p.provider != binding.provider)
                || prior.and_then(|p| p.receipt.as_ref()).is_some_and(|p| {
                    p.catalog_incarnation == summary.catalog_incarnation
                        && (p.catalog_generation > summary.catalog_generation
                            || p.token.cycle_seq > summary.token.cycle_seq)
                })
            {
                return Err(conflict());
            }
            let mut progress = prior.cloned().unwrap_or(SourceProgress {
                source_id: source,
                provider: binding.provider,
                last_attempt_at_ms: None,
                last_observation: None,
                receipt: None,
                coverage: Coverage::Partial,
                update_state: runtime.worker.state,
                backfill_state: BackfillState::Pending,
                error: runtime.worker.error,
                confirmation: None,
            });
            // Preserve a later failed/pending observation and its confirmation;
            // publishing an older head does not erase newer scheduling facts.
            if progress
                .last_observation
                .as_ref()
                .is_none_or(|t| t.cycle_seq < summary.token.cycle_seq)
            {
                progress.last_observation = Some(summary.token.clone());
                progress.last_attempt_at_ms = Some(receipt.observed_at_ms);
            }
            progress.receipt = Some(summary);
            progress.coverage = Coverage::Partial;
            write_source(conn, &progress)?;
            Ok((true, false, ()))
        })
    }
}

/// One maintenance fence is owned by one nonce. No wall-clock/PID takeover:
/// only the real installation lock plus the exact journal owner can adopt it.
fn require_fence(
    current: &ControlStatus,
    owner: &ControlId,
    states: &[MaintenanceState],
) -> PortResult<()> {
    let fence = &current.policy.maintenance;
    if !states.contains(&fence.state) || fence.owner.as_ref() != Some(owner) {
        return Err(conflict());
    }
    Ok(())
}

fn coverage_matches(sources: &[ControlId], coverage: &[CoveredSource]) -> PortResult<()> {
    let mut unique = std::collections::BTreeSet::new();
    if coverage.len() != sources.len()
        || coverage.iter().any(|c| !unique.insert(c.source_id.clone()))
        || unique.iter().ne(sources.iter())
    {
        return Err(invalid());
    }
    Ok(())
}

fn withdrawn(policy: &ReadPolicy, coverage: &[CoveredSource]) -> bool {
    coverage
        .iter()
        .any(|source| !policy.allows_source(source.provider, &source.locator, &source.source_id))
}

impl SqliteControlStore {
    /// Typed artifact inventory for owned purge and journal composition.
    pub fn artifact_records(&self) -> PortResult<Vec<StoredArtifact>> {
        if runtime_deadline().is_none() {
            return self
                .with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || self.artifact_records());
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(sql_error)?;
        let status = load_status(&tx)?;
        let records = load_artifacts(&tx, status.policy.policy_epoch)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        Ok(records)
    }

    /// Typed backup inventory. Registered/completed tombstones are distinct;
    /// withdrawn tombstones never become restorable.
    pub fn backup_records(&self) -> PortResult<Vec<StoredBackup>> {
        if runtime_deadline().is_none() {
            return self
                .with_runtime_deadline(Instant::now() + BUSY_TIMEOUT, || self.backup_records());
        }
        runtime_tick()?;
        self.validate_live_root()?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(sql_error)?;
        let status = load_status(&tx)?;
        let records = load_backups(&tx, status.policy.policy_epoch)?;
        runtime_tick()?;
        tx.commit().map_err(sql_error)?;
        Ok(records)
    }

    /// Install or advance a maintenance fence. Both the real installation lock
    /// and the control-root policy-owner guard are required; a bare nonce is
    /// not authorization. A different live owner is never displaced.
    pub fn begin_maintenance(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        fence: MaintenanceFence,
    ) -> PortResult<ControlChange<MaintenanceFence>> {
        control.validate(self)?;
        installation.validate(self)?;
        fence.validate()?;
        if fence.state == MaintenanceState::Idle || fence.owner.as_ref() != Some(owner) {
            return Err(invalid());
        }
        self.mutate(expected, |conn, current| {
            if current
                .policy
                .maintenance
                .owner
                .as_ref()
                .is_some_and(|existing| existing != owner)
            {
                return Err(conflict());
            }
            if current.policy.maintenance == fence {
                return Ok((false, false, fence.clone()));
            }
            conn.execute(
                "UPDATE control_meta SET maintenance_state=?1,maintenance_owner=?2,maintenance_phase=?3 WHERE singleton=1",
                params![
                    maintenance_wire(fence.state),
                    fence.owner.as_ref().map(ControlId::as_str),
                    fence.phase.map(phase_wire)
                ],
            )
            .map_err(sql_error)?;
            invalidate_scheduling(conn, BackgroundFailure::Upgrading, None)?;
            Ok((true, false, fence.clone()))
        })
    }

    /// Clear only this caller's fence. It never clears a different owner and
    /// never touches policy, pause or revoke intents.
    pub fn clear_maintenance(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
    ) -> PortResult<ControlChange<MaintenanceFence>> {
        control.validate(self)?;
        installation.validate(self)?;
        self.mutate(expected, |conn, current| {
            if current.policy.maintenance.owner.as_ref() != Some(owner) {
                return Err(conflict());
            }
            let idle = MaintenanceFence::idle();
            conn.execute(
                "UPDATE control_meta SET maintenance_state='idle',maintenance_owner=NULL,maintenance_phase=NULL WHERE singleton=1",
                [],
            )
            .map_err(sql_error)?;
            Ok((true, false, idle))
        })
    }

    /// Adopt a fence recorded under a different nonce. Requires the live
    /// installation-prefix lock and the exact owner ID read from the verified
    /// update journal; age, PID or a matching phase are insufficient.
    pub fn recover_maintenance(
        &self,
        expected: ControlSeq,
        caller: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        journal_owner: &ControlId,
        fence: MaintenanceFence,
    ) -> PortResult<ControlChange<MaintenanceFence>> {
        control.validate(self)?;
        installation.validate(self)?;
        fence.validate()?;
        if fence.state == MaintenanceState::Idle
            || fence.owner.as_ref() != Some(caller)
            || caller == journal_owner
        {
            return Err(invalid());
        }
        self.mutate(expected, |conn, current| {
            let current_fence = &current.policy.maintenance;
            if current_fence.state == MaintenanceState::Idle
                || current_fence.owner.as_ref() != Some(journal_owner)
            {
                return Err(conflict());
            }
            conn.execute(
                "UPDATE control_meta SET maintenance_state=?1,maintenance_owner=?2,maintenance_phase=?3 WHERE singleton=1",
                params![
                    maintenance_wire(fence.state),
                    fence.owner.as_ref().map(ControlId::as_str),
                    fence.phase.map(phase_wire)
                ],
            )
            .map_err(sql_error)?;
            invalidate_scheduling(conn, BackgroundFailure::Upgrading, None)?;
            Ok((true, false, fence))
        })
    }

    /// Record artifact and covered source ownership before any backup content
    /// exists. Repeating the same intent is idempotent; conflicting reuse fails.
    pub fn register_backup(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        registration: &BackupRegistration,
        now_ms: i64,
    ) -> PortResult<ControlChange<StoredBackup>> {
        control.validate(self)?;
        installation.validate(self)?;
        checked_time(now_ms)?;
        if !valid_relative_locator(&registration.relative_locator)
            || registration.relative_locator != backup_locator(&registration.backup_id)
            || registration.schema_version == 0
            || !registration
                .source_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(invalid());
        }
        self.mutate(expected, |conn, current| {
            require_fence(
                current,
                owner,
                &[MaintenanceState::Updating, MaintenanceState::Recovering],
            )?;
            let existing = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == registration.backup_id);
            if let Some(existing) = existing {
                let same = existing.purpose == registration.purpose
                    && existing.relative_locator == registration.relative_locator
                    && existing.catalog_incarnation == registration.catalog_incarnation
                    && existing.catalog_generation == registration.catalog_generation
                    && existing.schema_version == registration.schema_version
                    && existing.source_ids == registration.source_ids;
                if !same
                    || !matches!(
                        existing.state,
                        BackupState::Registered | BackupState::Complete
                    )
                {
                    return Err(conflict());
                }
                return Ok((false, false, existing));
            }
            conn.execute(
                "INSERT INTO private_artifacts(artifact_id,kind,relative_locator,policy_epoch,owner_nonce,state,digest) VALUES(?1,'catalog_backup',?2,?3,?4,'registered',NULL)",
                params![
                    registration.backup_id.as_str(),
                    registration.relative_locator,
                    current.policy.policy_epoch.get(),
                    owner.as_str()
                ],
            )
            .map_err(sql_error)?;
            conn.execute(
                "INSERT INTO backup_manifests(backup_id,purpose,relative_locator,catalog_incarnation,catalog_generation,schema_version,digest,size_bytes,state,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,'',0,'registered',?7)",
                params![
                    registration.backup_id.as_str(),
                    registration.purpose.wire(),
                    registration.relative_locator,
                    registration.catalog_incarnation.as_str(),
                    sql_count(registration.catalog_generation)?,
                    i64::from(registration.schema_version),
                    now_ms
                ],
            )
            .map_err(sql_error)?;
            for source in &registration.source_ids {
                conn.execute(
                    "INSERT INTO artifact_sources(artifact_id,source_id) VALUES(?1,?2)",
                    params![registration.backup_id.as_str(), source.as_str()],
                )
                .map_err(sql_error)?;
                conn.execute(
                    "INSERT INTO backup_sources(backup_id,source_id) VALUES(?1,?2)",
                    params![registration.backup_id.as_str(), source.as_str()],
                )
                .map_err(sql_error)?;
            }
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == registration.backup_id)
                .ok_or_else(corrupt)?;
            Ok((true, false, record))
        })
    }

    /// Promote a registered backup to complete only after its content and
    /// sidecar manifest were written and verified by the caller.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the existing maintenance API and its independent OS capabilities explicit"
    )]
    pub fn complete_backup(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        backup_id: &ControlId,
        digest: &str,
        size_bytes: u64,
    ) -> PortResult<ControlChange<StoredBackup>> {
        control.validate(self)?;
        installation.validate(self)?;
        if !hex64(digest) || size_bytes == 0 {
            return Err(invalid());
        }
        self.mutate(expected, |conn, current| {
            require_fence(
                current,
                owner,
                &[MaintenanceState::Updating, MaintenanceState::Recovering],
            )?;
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == *backup_id)
                .ok_or_else(missing)?;
            match record.state {
                BackupState::Complete => {
                    if record.digest.as_deref() == Some(digest) && record.size_bytes == size_bytes
                    {
                        return Ok((false, false, record));
                    }
                    return Err(conflict());
                }
                BackupState::Registered => {}
                BackupState::Quarantined | BackupState::PurgedByPolicy => {
                    return Err(conflict());
                }
            }
            let size = sql_count(size_bytes)?;
            let changed = conn
                .execute(
                    "UPDATE backup_manifests SET digest=?1,size_bytes=?2,state=?3 WHERE backup_id=?4 AND state='registered'",
                    params![digest, size, BackupState::Complete.wire(), backup_id.as_str()],
                )
                .map_err(sql_error)?;
            let artifact = conn
                .execute(
                    "UPDATE private_artifacts SET state=?1,digest=?2 WHERE artifact_id=?3 AND state='registered'",
                    params![ArtifactState::Complete.wire(), digest, backup_id.as_str()],
                )
                .map_err(sql_error)?;
            if changed != 1 || artifact != 1 {
                return Err(conflict());
            }
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == *backup_id)
                .ok_or_else(corrupt)?;
            Ok((true, false, record))
        })
    }

    pub(crate) fn quarantine_unclassified_backup(
        &self,
        expected: ControlSeq,
        owner: &PurgeOwner<'_>,
        control: &ControlRootGuard<'_>,
        backup_id: &ControlId,
    ) -> PortResult<ControlChange<StoredBackup>> {
        owner.validate(self)?;
        control.validate(self)?;
        self.mutate(expected, |conn, current| {
            let prior = load_backups(conn, current.policy.policy_epoch)?.into_iter()
                .find(|backup| backup.backup_id == *backup_id).ok_or_else(missing)?;
            if prior.state == BackupState::PurgedByPolicy
                || (prior.state == BackupState::Quarantined && prior.digest.is_none()) {
                return Ok((false, false, prior));
            }
            // A missing verified digest is the typed unclassified-quarantine
            // sentinel. Preserve its source accounting; later purge cannot
            // mistake this for an authorized policy-quarantined image.
            conn.execute("UPDATE backup_manifests SET state='quarantined',digest='',size_bytes=0 WHERE backup_id=?1", [backup_id.as_str()]).map_err(sql_error)?;
            conn.execute("UPDATE private_artifacts SET state='quarantined',digest=NULL,owner_nonce=NULL WHERE artifact_id=?1", [backup_id.as_str()]).map_err(sql_error)?;
            let backup = load_backups(conn, current.policy.policy_epoch)?.into_iter()
                .find(|backup| backup.backup_id == *backup_id).ok_or_else(corrupt)?;
            Ok((true, false, backup))
        })
    }

    /// Persist a withdrawal intent before file I/O. Coverage and the verified
    /// digest remain accounted for while deletion is pending. A later reallow
    /// cannot turn this quarantined image into a restorable backup.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn quarantine_backup(
        &self,
        expected: ControlSeq,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        backup_id: &ControlId,
        coverage: &[CoveredSource],
        digest: &str,
        size_bytes: u64,
        now_ms: i64,
    ) -> PortResult<ControlChange<StoredBackup>> {
        control.validate(self)?;
        installation.validate(self)?;
        checked_time(now_ms)?;
        if !hex64(digest) || size_bytes == 0 {
            return Err(invalid());
        }
        self.mutate(expected, |conn, current| {
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter().find(|backup| backup.backup_id == *backup_id).ok_or_else(missing)?;
            coverage_matches(&record.source_ids, coverage)?;
            if record.state == BackupState::Quarantined {
                if record.digest.as_deref() != Some(digest) || record.size_bytes != size_bytes {
                    return Err(conflict());
                }
                return Ok((false, false, record));
            }
            if !matches!(record.state, BackupState::Registered | BackupState::Complete)
                || (record.state == BackupState::Complete
                    && (record.digest.as_deref() != Some(digest) || record.size_bytes != size_bytes))
                || !withdrawn(&current.policy, coverage)
            {
                return Err(invalid());
            }
            conn.execute(
                "UPDATE backup_manifests SET state='quarantined',digest=?1,size_bytes=?2 WHERE backup_id=?3",
                params![digest, sql_count(size_bytes)?, backup_id.as_str()],
            ).map_err(sql_error)?;
            conn.execute(
                "UPDATE private_artifacts SET state='quarantined',digest=?1,owner_nonce=NULL WHERE artifact_id=?2",
                params![digest, backup_id.as_str()],
            ).map_err(sql_error)?;
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter().find(|backup| backup.backup_id == *backup_id).ok_or_else(corrupt)?;
            Ok((true, false, record))
        })
    }

    /// Finalize a previously authorized withdrawal after the caller confirms
    /// the owned artifact is absent. Until then quarantine retains coverage.
    /// This terminal tombstone survives later policy changes.
    pub(crate) fn finalize_backup_purge(
        &self,
        expected: ControlSeq,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        backup_id: &ControlId,
        sources: &[ControlId],
        now_ms: i64,
    ) -> PortResult<ControlChange<StoredBackup>> {
        control.validate(self)?;
        installation.validate(self)?;
        checked_time(now_ms)?;
        self.mutate(expected, |conn, current| {
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == *backup_id)
                .ok_or_else(missing)?;
            if record.state == BackupState::PurgedByPolicy {
                return Ok((false, false, record));
            }
            if record.source_ids != sources {
                return Err(invalid());
            }
            if record.state != BackupState::Quarantined {
                return Err(invalid());
            }
            conn.execute(
                "UPDATE backup_manifests SET state=?1 WHERE backup_id=?2 AND state='quarantined'",
                params![BackupState::PurgedByPolicy.wire(), backup_id.as_str()],
            )
            .map_err(sql_error)?;
            conn.execute(
                "UPDATE private_artifacts SET state=?1,owner_nonce=NULL WHERE artifact_id=?2",
                params![ArtifactState::PurgedByPolicy.wire(), backup_id.as_str()],
            )
            .map_err(sql_error)?;
            conn.execute(
                "DELETE FROM backup_sources WHERE backup_id=?1",
                [backup_id.as_str()],
            )
            .map_err(sql_error)?;
            conn.execute(
                "DELETE FROM artifact_sources WHERE artifact_id=?1",
                [backup_id.as_str()],
            )
            .map_err(sql_error)?;
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == *backup_id)
                .ok_or_else(corrupt)?;
            Ok((true, false, record))
        })
    }

    /// Only the maintenance facade holding the real exclusive catalog handle
    /// can repair this summary from a catalog it just read. Permission and
    /// desired update intent are never restored from a checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reset_after_catalog_recovery(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        catalog_handles: &ExclusiveGuard,
        actual_incarnation: &ControlId,
        now_ms: i64,
    ) -> PortResult<ControlChange<ControlId>> {
        control.validate(self)?;
        installation.validate(self)?;
        self.validate_guard(catalog_handles, LockKind::CatalogHandles)?;
        checked_time(now_ms)?;
        self.mutate(expected, |conn, current| {
            require_fence(
                current,
                owner,
                &[MaintenanceState::Recovering, MaintenanceState::Updating],
            )?;
            if current.catalog_incarnation.as_ref() == Some(actual_incarnation) {
                return Ok((false, false, actual_incarnation.clone()));
            }
            invalidate_recovery_progress(conn, actual_incarnation, now_ms)?;
            Ok((true, false, actual_incarnation.clone()))
        })
    }

    /// Publish the control consequences of a restored, verified side file:
    /// rotate the catalog incarnation, invalidate every progress/barrier/
    /// confirmation claim and schedule re-observation. Policy, pause and deny
    /// intents are preserved; the backup is rechecked against the current deny
    /// set inside this transaction.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the existing maintenance API and its independent OS capabilities explicit"
    )]
    pub fn apply_catalog_restore(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        control: &ControlRootGuard<'_>,
        installation: &InstallationLockAuthority<'_>,
        backup_id: &ControlId,
        new_incarnation: &ControlId,
        coverage: &[CoveredSource],
        now_ms: i64,
    ) -> PortResult<ControlChange<ControlId>> {
        control.validate(self)?;
        installation.validate(self)?;
        checked_time(now_ms)?;
        self.mutate(expected, |conn, current| {
            require_fence(
                current,
                owner,
                &[MaintenanceState::Recovering, MaintenanceState::Updating],
            )?;
            let record = load_backups(conn, current.policy.policy_epoch)?
                .into_iter()
                .find(|backup| backup.backup_id == *backup_id)
                .ok_or_else(missing)?;
            if !record.state.restorable() || record.catalog_incarnation == *new_incarnation {
                return Err(invalid());
            }
            coverage_matches(&record.source_ids, coverage)?;
            if withdrawn(&current.policy, coverage) {
                return Err(invalid());
            }
            if current.catalog_incarnation.as_ref() == Some(new_incarnation) {
                return Ok((false, false, new_incarnation.clone()));
            }
            invalidate_recovery_progress(conn, new_incarnation, now_ms)?;
            Ok((true, false, new_incarnation.clone()))
        })
    }
}

fn invalidate_recovery_progress(
    conn: &Connection,
    incarnation: &ControlId,
    now_ms: i64,
) -> PortResult<()> {
    conn.execute(
        "UPDATE control_meta SET catalog_incarnation=?1 WHERE singleton=1",
        [incarnation.as_str()],
    )
    .map_err(sql_error)?;
    conn.execute("UPDATE cycles SET state='aborted',completed_at_ms=COALESCE(completed_at_ms,?1) WHERE state IN ('queued','observing')",[now_ms]).map_err(sql_error)?;
    conn.execute("DELETE FROM barrier_selections", [])
        .map_err(sql_error)?;
    conn.execute("DELETE FROM barriers", [])
        .map_err(sql_error)?;
    conn.execute("UPDATE source_updates SET last_observed_cycle=NULL,indexed_revision=NULL,receipt_cycle=NULL,catalog_incarnation=NULL,catalog_generation=NULL,coverage='empty',update_state='deferred',error_code='catalog_changed',backfill_state='pending',missing_first_cycle=NULL,missing_confirm_cycle=NULL,confirmation_boot_id=NULL,confirmation_root_identity=NULL,confirmation_policy_epoch=NULL,rewrite_candidate_digest=NULL,rewrite_first_cycle=NULL,rewrite_confirm_cycle=NULL,confirmation_first_monotonic_ms=NULL",[]).map_err(sql_error)?;
    conn.execute(
        "UPDATE worker_state SET effective_state=CASE
             WHEN boot_id IS NULL THEN 'offline'
             WHEN (SELECT desired_updates FROM control_meta WHERE singleton=1)='paused' THEN 'paused'
             WHEN (SELECT desired_updates FROM control_meta WHERE singleton=1)='stopped' THEN 'stopped'
             ELSE 'upgrading' END,
         last_error=CASE WHEN boot_id IS NULL THEN NULL ELSE 'catalog_changed' END",
        [],
    ).map_err(sql_error)?;
    Ok(())
}

impl BackgroundControl for SqliteControlStore {
    fn background_status(&self) -> PortResult<BackgroundStatus> {
        self.read_runtime(|s, r| {
            Ok(BackgroundStatus {
                control_seq: s.policy.control_seq,
                next_cycle_seq: r.next_cycle,
                worker: r.worker.clone(),
            })
        })
    }
    fn register_worker(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        pid_hint: u32,
        now_ms: i64,
    ) -> PortResult<ControlChange<WorkerStatus>> {
        checked_time(now_ms)?;
        if pid_hint == 0 {
            return Err(invalid());
        }
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime(conn,status)?;
            authority_matches(self.root_identity,authority,status,&runtime,false)?;
            if runtime.worker.boot_id.as_ref()==Some(authority.boot_id()) {
                if runtime.worker.pid_hint!=Some(pid_hint) || runtime.worker.state==UpdateState::Offline { return Err(conflict()); }
                return Ok((false,false,runtime.worker));
            }
            let reused: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM cycles WHERE worker_boot_id=?1)", [authority.boot_id().as_str()], |row| row.get(0)).map_err(sql_error)?;
            if reused { return Err(conflict()); }
            // Only the live OS capability authorizes replacement. Timestamps
            // and PID reuse are never consulted to steal the old ownership.
            invalidate_scheduling(conn,BackgroundFailure::WorkerRestarted,Some(now_ms))?;
            let state=match status.desired_updates {
                DesiredUpdates::Paused=>UpdateState::Paused,DesiredUpdates::Stopped=>UpdateState::Stopped,
                DesiredUpdates::Running if status.policy.maintenance.state!=MaintenanceState::Idle=>UpdateState::Upgrading,
                DesiredUpdates::Running=>UpdateState::Idle,
            };
            conn.execute("UPDATE worker_state SET boot_id=?1,pid_hint=?2,heartbeat_at_ms=?3,effective_state=?4,last_error=NULL WHERE singleton=1",params![authority.boot_id().as_str(),i64::from(pid_hint),now_ms,update_wire(state)]).map_err(sql_error)?;
            Ok((true,false,WorkerStatus {boot_id:Some(authority.boot_id().clone()),pid_hint:Some(pid_hint),heartbeat_at_ms:Some(now_ms),state,error:None}))
        })
    }
    fn heartbeat_worker(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        state: UpdateState,
        error: Option<BackgroundFailure>,
        now_ms: i64,
    ) -> PortResult<ControlChange<WorkerStatus>> {
        checked_time(now_ms)?;
        if state == UpdateState::Offline {
            return Err(invalid());
        }
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime(conn,status)?;
            authority_matches(self.root_identity,authority,status,&runtime,true)?;
            if runtime.worker.state==UpdateState::Offline { return Err(conflict()); }
            if (status.desired_updates==DesiredUpdates::Paused && state!=UpdateState::Paused)
                || (status.desired_updates==DesiredUpdates::Stopped && state!=UpdateState::Stopped)
                || (status.desired_updates==DesiredUpdates::Running && status.policy.maintenance.state!=MaintenanceState::Idle && state!=UpdateState::Upgrading) { return Err(conflict()); }
            conn.execute("UPDATE worker_state SET heartbeat_at_ms=?1,effective_state=?2,last_error=?3 WHERE singleton=1",params![now_ms,update_wire(state),error.map(failure_wire)]).map_err(sql_error)?;
            Ok((true,false,WorkerStatus {heartbeat_at_ms:Some(now_ms),state,error,..runtime.worker}))
        })
    }
    fn stop_worker(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        now_ms: i64,
    ) -> PortResult<ControlChange<WorkerStatus>> {
        checked_time(now_ms)?;
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime(conn,status)?;
            authority_matches(self.root_identity,authority,status,&runtime,true)?;
            if runtime.worker.state==UpdateState::Offline { return Ok((false,false,runtime.worker)); }
            invalidate_scheduling(conn,BackgroundFailure::Offline,Some(now_ms))?;
            conn.execute("UPDATE worker_state SET heartbeat_at_ms=?1,effective_state='offline',last_error=NULL WHERE singleton=1",[now_ms]).map_err(sql_error)?;
            Ok((true,false,WorkerStatus {heartbeat_at_ms:Some(now_ms),state:UpdateState::Offline,error:None,..runtime.worker}))
        })
    }
    fn queue_cycle(
        &self,
        expected: ControlSeq,
        mut selections: Vec<SelectionRevision>,
    ) -> PortResult<ControlChange<CycleAdmission>> {
        self.mutate(expected, |conn, status| {
            validate_selection_set(status, &mut selections)?;
            let runtime = load_runtime(conn, status)?;
            if let Some(reason) = blocked_reason(status, &runtime.worker) {
                return Ok((false, false, CycleAdmission::Blocked(reason)));
            }
            let cycle = allocate_cycle(conn, status, &runtime, &selections)?;
            let changed = cycle.token.cycle_seq == runtime.next_cycle;
            Ok((changed, false, CycleAdmission::Queued(cycle)))
        })
    }
    fn start_cycle(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        number: CycleSeq,
        now_ms: i64,
    ) -> PortResult<ControlChange<ObservationCycle>> {
        checked_time(now_ms)?;
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime(conn,status)?;
            let cycle=cycle_owned(self.root_identity,&runtime,status,authority,number)?;
            if blocked_reason(status,&runtime.worker).is_some() || cycle.state!=CycleState::Queued
                || runtime.cycles.iter().any(|c|c.state==CycleState::Observing) { return Err(conflict()); }
            let mut selections=cycle.selections.iter().map(|s|s.selection.clone()).collect::<Vec<_>>();
            validate_selection_set(status,&mut selections)?;
            let started=seq(increment(expected.get())?)?;
            if runtime.barriers.iter().any(|b|b.required_cycle_seq==number && b.admission_control_seq>=started) { return Err(conflict()); }
            conn.execute("UPDATE cycles SET state='observing',started_control_seq=?1,started_at_ms=?2 WHERE cycle_seq=?3",params![started.get(),now_ms,number.get()]).map_err(sql_error)?;
            Ok((true,false,ObservationCycle {state:CycleState::Observing,started_control_seq:Some(started),started_at_ms:Some(now_ms),..cycle.clone()}))
        })
    }
    fn finish_cycle(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        number: CycleSeq,
        finish: CycleFinish,
        now_ms: i64,
    ) -> PortResult<ControlChange<ObservationCycle>> {
        checked_time(now_ms)?;
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime_for(conn,status,Some(number),None)?;
            let c=cycle_owned(self.root_identity,&runtime,status,authority,number)?;
            let state=match finish {CycleFinish::Committed=>CycleState::Committed,CycleFinish::Partial=>CycleState::Partial,CycleFinish::Aborted=>CycleState::Aborted};
            if c.state==state { return Ok((false,false,c.clone())); }
            if c.state!=CycleState::Observing && !(c.state==CycleState::Queued && state==CycleState::Aborted) { return Err(conflict()); }
            if state!=CycleState::Aborted && blocked_reason(status,&runtime.worker).is_some() { return Err(conflict()); }
            if state==CycleState::Committed && c.selections.iter().any(|s|!s.discovery_complete || s.error.is_some() || s.committed_count!=s.discovered_count) { return Err(invalid()); }
            conn.execute("UPDATE cycles SET state=?1,completed_at_ms=?2 WHERE cycle_seq=?3",params![cycle_wire(state),now_ms,number.get()]).map_err(sql_error)?;
            if state==CycleState::Aborted {
                conn.execute("UPDATE barriers SET state='blocked',error_code='deferred' WHERE required_cycle_seq=?1 AND state='pending'",[number.get()]).map_err(sql_error)?;
            } else {
                // This flag schedules catalog verification; it is never success.
                conn.execute("UPDATE barriers SET state=?1,completed_cycle_seq=?2 WHERE required_cycle_seq=?2 AND state='pending'",params![barrier_wire(BarrierState::AwaitingCatalog),number.get()]).map_err(sql_error)?;
            }
            Ok((true,false,ObservationCycle {state,completed_at_ms:Some(now_ms),..c.clone()}))
        })
    }
    fn cycle(&self, number: CycleSeq) -> PortResult<ObservationCycle> {
        self.read_runtime_for(Some(number), None, |_, r| Ok(r.cycle(number)?.clone()))
    }
    fn admit_latest(
        &self,
        expected: ControlSeq,
        mut request: LatestRequest,
    ) -> PortResult<ControlChange<LatestAdmission>> {
        checked_time(request.now_ms)?;
        if request.max_wait_ms > MAX_LATEST_WAIT_MS {
            return Err(invalid());
        }
        self.mutate(expected,|conn,status| {
            validate_selection_set(status,&mut request.selections)?;
            let runtime=load_runtime(conn,status)?;
            if let Some(reason)=blocked_reason(status,&runtime.worker) { return Ok((false,false,LatestAdmission::Blocked(reason))); }
            if runtime.barriers.len() >= MAX_RUNTIME_REFERENCES { return Err(runtime_capacity()); }
            let cycle=allocate_cycle(conn,status,&runtime,&request.selections)?;
            let barrier=LatestBarrier {id:fresh_id(conn,"barrier")?,policy_epoch:status.policy.policy_epoch,admission_control_seq:seq(increment(expected.get())?)?,required_cycle_seq:cycle.token.cycle_seq,state:BarrierState::Pending,requested_wait_ms:request.max_wait_ms,admitted_at_ms:request.now_ms,completed_cycle_seq:None,error:None,selections:request.selections.clone()};
            conn.execute("INSERT INTO barriers(barrier_id,policy_epoch,admission_control_seq,required_cycle_seq,state,requested_wait_ms,admitted_at_ms) VALUES(?1,?2,?3,?4,'pending',?5,?6)",params![barrier.id.as_str(),barrier.policy_epoch.get(),barrier.admission_control_seq.get(),barrier.required_cycle_seq.get(),i64::from(barrier.requested_wait_ms),barrier.admitted_at_ms]).map_err(sql_error)?;
            for s in &request.selections {
                conn.execute("INSERT INTO barrier_selections VALUES(?1,?2,?3)",params![barrier.id.as_str(),s.selection_id.as_str(),s.revision.get()]).map_err(sql_error)?;
            }
            Ok((true,false,LatestAdmission::Queued(barrier)))
        })
    }
    fn barrier(&self, identifier: &ControlId) -> PortResult<LatestBarrier> {
        self.read_runtime_for(None, Some(identifier), |status, r| {
            let mut b = r
                .barriers
                .iter()
                .find(|b| b.id == *identifier)
                .ok_or_else(missing)?
                .clone();
            let block = if b.policy_epoch != status.policy.policy_epoch {
                Some(BackgroundFailure::PolicyChanged)
            } else {
                blocked_reason(status, &r.worker)
            };
            if let Some(error) = block {
                b.state = BarrierState::Blocked;
                b.error = Some(error);
            }
            Ok(b)
        })
    }
    fn acknowledge_discovery(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        ack: DiscoveryAcknowledgement,
    ) -> PortResult<ControlChange<CycleSelection>> {
        if ack.committed_count > ack.observed_count
            || ack.observed_count > ack.discovered_count
            || (ack.complete && ack.error.is_some())
        {
            return Err(invalid());
        }
        let discovered = sql_count(ack.discovered_count)?;
        let observed = sql_count(ack.observed_count)?;
        let committed = sql_count(ack.committed_count)?;
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime(conn,status)?;
            let c=cycle_owned(self.root_identity,&runtime,status,authority,ack.token.cycle_seq)?;
            if c.token!=ack.token || c.state!=CycleState::Observing || blocked_reason(status,&runtime.worker).is_some() { return Err(conflict()); }
            let prior=c.selections.iter().find(|s|s.selection==ack.selection).ok_or_else(conflict)?;
            let value=CycleSelection {selection:ack.selection.clone(),discovery_complete:ack.complete,discovered_count:ack.discovered_count,observed_count:ack.observed_count,committed_count:ack.committed_count,error:ack.error};
            if prior==&value { return Ok((false,false,value)); }
            if (prior.discovery_complete && (!ack.complete || ack.discovered_count != prior.discovered_count))
                || ack.discovered_count < prior.discovered_count || ack.observed_count < prior.observed_count
                || ack.committed_count < prior.committed_count { return Err(conflict()); }
            conn.execute("UPDATE cycle_selections SET discovery_complete=?1,discovered_count=?2,observed_count=?3,committed_count=?4,error_code=?5 WHERE cycle_seq=?6 AND selection_id=?7",params![i64::from(ack.complete),discovered,observed,committed,ack.error.map(failure_wire),ack.token.cycle_seq.get(),ack.selection.selection_id.as_str()]).map_err(sql_error)?;
            Ok((true,false,value))
        })
    }
    fn acknowledge_source(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        ack: SourceAcknowledgement,
    ) -> PortResult<ControlChange<SourceProgress>> {
        checked_time(ack.attempted_at_ms)?;
        self.mutate(expected, |conn, status| {
            let runtime = load_runtime(conn, status)?;
            let c = cycle_owned(
                self.root_identity,
                &runtime,
                status,
                authority,
                ack.token.cycle_seq,
            )?;
            if c.token != ack.token
                || c.state != CycleState::Observing
                || blocked_reason(status, &runtime.worker).is_some()
                || !c.selections.iter().any(|s| s.selection == ack.selection)
            {
                return Err(conflict());
            }
            let selected = status
                .policy
                .selections
                .iter()
                .find(|s| s.id == ack.selection.selection_id)
                .ok_or_else(conflict)?;
            if selected.region.provider != ack.provider {
                return Err(invalid());
            }
            let prior = runtime
                .sources
                .iter()
                .find(|s| s.source_id == ack.source_id);
            if prior.is_some_and(|s| {
                s.provider != ack.provider
                    || s.last_observation
                        .as_ref()
                        .is_some_and(|o| o.cycle_seq > ack.token.cycle_seq)
            }) {
                return Err(conflict());
            }
            if let Some(receipt) = &ack.receipt
                && (receipt.token != ack.token
                    || status.catalog_incarnation.as_ref() != Some(&receipt.catalog_incarnation)
                    || prior.and_then(|s| s.receipt.as_ref()).is_some_and(|p| {
                        p.catalog_incarnation == receipt.catalog_incarnation
                            && p.catalog_generation > receipt.catalog_generation
                    }))
            {
                return Err(conflict());
            }
            if ack.coverage == Coverage::Complete && (ack.receipt.is_none() || ack.error.is_some())
            {
                return Err(invalid());
            }
            if matches!(
                ack.update_state,
                UpdateState::Paused | UpdateState::Stopped | UpdateState::Upgrading
            ) {
                return Err(invalid());
            }
            if let Some(confirm) = &ack.confirmation {
                validate_confirmation(confirm, &runtime.cycles)?;
                let reason = match confirm.kind {
                    ConfirmationKind::Deletion => BackgroundFailure::DeletionPending,
                    ConfirmationKind::Rewrite { .. } => BackgroundFailure::RewritePending,
                };
                if confirm.worker_boot_id != ack.token.worker_boot_id
                    || confirm.policy_epoch != status.policy.policy_epoch
                    || confirm.root_identity != ack.selection.root_identity
                    || confirm.confirm_cycle.unwrap_or(confirm.first_cycle) != ack.token.cycle_seq
                    || ack.update_state != UpdateState::Deferred
                    || ack.coverage == Coverage::Complete
                    || ack.error != Some(reason)
                    || ack.receipt.is_some()
                {
                    return Err(invalid());
                }
            }
            let progress = SourceProgress {
                source_id: ack.source_id.clone(),
                provider: ack.provider,
                last_attempt_at_ms: Some(ack.attempted_at_ms),
                last_observation: Some(ack.token.clone()),
                receipt: ack
                    .receipt
                    .clone()
                    .or_else(|| prior.and_then(|s| s.receipt.clone())),
                coverage: ack.coverage,
                update_state: ack.update_state,
                backfill_state: ack.backfill_state,
                error: ack.error,
                confirmation: ack.confirmation.clone(),
            };
            if prior == Some(&progress) {
                return Ok((false, false, progress));
            }
            write_source(conn, &progress)?;
            Ok((true, false, progress))
        })
    }
    fn source_progress(&self, source: &ControlId) -> PortResult<Option<SourceProgress>> {
        self.read_runtime(|_, r| Ok(r.sources.iter().find(|s| s.source_id == *source).cloned()))
    }
    fn reset_progress(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        catalog_incarnation: &ControlId,
        now_ms: i64,
    ) -> PortResult<ControlChange<()>> {
        checked_time(now_ms)?;
        self.mutate(expected,|conn,status| {
            let runtime=load_runtime(conn,status)?;
            authority_matches(self.root_identity,authority,status,&runtime,true)?;
            if !matches!(status.policy.maintenance.state,MaintenanceState::Recovering|MaintenanceState::Updating) { return Err(invalid()); }
            invalidate_scheduling(conn,BackgroundFailure::CatalogChanged,Some(now_ms))?;
            conn.execute("UPDATE source_updates SET last_observed_cycle=NULL,indexed_revision=NULL,receipt_cycle=NULL,catalog_incarnation=NULL,catalog_generation=NULL,coverage='empty'",[]).map_err(sql_error)?;
            conn.execute("UPDATE barriers SET state='blocked',error_code='catalog_changed',completed_cycle_seq=NULL,catalog_incarnation=NULL",[]).map_err(sql_error)?;
            conn.execute("UPDATE control_meta SET catalog_incarnation=?1 WHERE singleton=1",[catalog_incarnation.as_str()]).map_err(sql_error)?;
            Ok((true,false,()))
        })
    }
}

fn write_source(conn: &Connection, p: &SourceProgress) -> PortResult<()> {
    let receipt = p.receipt.as_ref();
    let confirmation = p.confirmation.as_ref();
    let (missing_first, missing_confirm, rewrite_digest, rewrite_first, rewrite_confirm) =
        match confirmation {
            Some(c) => match &c.kind {
                ConfirmationKind::Deletion => (
                    Some(c.first_cycle.get()),
                    c.confirm_cycle.map(CycleSeq::get),
                    None,
                    None,
                    None,
                ),
                ConfirmationKind::Rewrite { candidate_digest } => (
                    None,
                    None,
                    Some(candidate_digest.as_str()),
                    Some(c.first_cycle.get()),
                    c.confirm_cycle.map(CycleSeq::get),
                ),
            },
            None => (None, None, None, None, None),
        };
    conn.execute("INSERT INTO source_updates(source_id,provider_id,last_attempt_at_ms,last_observed_cycle,indexed_revision,receipt_cycle,catalog_incarnation,catalog_generation,coverage,update_state,error_code,backfill_state,missing_first_cycle,missing_confirm_cycle,confirmation_boot_id,confirmation_root_identity,confirmation_policy_epoch,rewrite_candidate_digest,rewrite_first_cycle,rewrite_confirm_cycle,confirmation_first_monotonic_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21) ON CONFLICT(source_id) DO UPDATE SET last_attempt_at_ms=excluded.last_attempt_at_ms,last_observed_cycle=excluded.last_observed_cycle,indexed_revision=excluded.indexed_revision,receipt_cycle=excluded.receipt_cycle,catalog_incarnation=excluded.catalog_incarnation,catalog_generation=excluded.catalog_generation,coverage=excluded.coverage,update_state=excluded.update_state,error_code=excluded.error_code,backfill_state=excluded.backfill_state,missing_first_cycle=excluded.missing_first_cycle,missing_confirm_cycle=excluded.missing_confirm_cycle,confirmation_boot_id=excluded.confirmation_boot_id,confirmation_root_identity=excluded.confirmation_root_identity,confirmation_policy_epoch=excluded.confirmation_policy_epoch,rewrite_candidate_digest=excluded.rewrite_candidate_digest,rewrite_first_cycle=excluded.rewrite_first_cycle,rewrite_confirm_cycle=excluded.rewrite_confirm_cycle,confirmation_first_monotonic_ms=excluded.confirmation_first_monotonic_ms",
        params![p.source_id.as_str(),p.provider.as_str(),p.last_attempt_at_ms,p.last_observation.as_ref().map(|o|o.cycle_seq.get()),receipt.map(|r|r.revision.as_str()),receipt.map(|r|r.token.cycle_seq.get()),receipt.map(|r|r.catalog_incarnation.as_str()),receipt.map(|r|r.catalog_generation.get()),coverage_wire(p.coverage),update_wire(p.update_state),p.error.map(failure_wire),backfill_wire(p.backfill_state),missing_first,missing_confirm,confirmation.map(|c|c.worker_boot_id.as_str()),confirmation.map(|c|c.root_identity.as_str()),confirmation.map(|c|c.policy_epoch.get()),rewrite_digest,rewrite_first,rewrite_confirm,confirmation.map(|c|c.first_monotonic_ms.get())]).map_err(sql_error)?;
    Ok(())
}

// These narrow Win32 declarations avoid adding dependencies/features to the
// workspace. ACL work stays in the adapter; no shell, identity command or
// helper executable is used. All allocated descriptors have RAII ownership.
#[cfg(windows)]
mod windows_private {
    use super::{
        PortResult, io_error, private_file_io, private_file_io_at, private_validation_error,
        private_validation_io,
    };
    use std::{
        ffi::c_void,
        fs::{File, OpenOptions},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
        ptr,
    };

    #[repr(C)]
    struct Acl {
        revision: u8,
        reserved: u8,
        size: u16,
        count: u16,
        reserved2: u16,
    }
    #[repr(C)]
    struct AceHeader {
        kind: u8,
        flags: u8,
        size: u16,
    }
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            buffer: *mut c_void,
            len: u32,
            needed: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: *mut c_void,
            kind: u32,
            info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut Acl,
            sacl: *mut *mut Acl,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
        fn IsValidAcl(acl: *const Acl) -> i32;
        fn IsValidSid(sid: *mut c_void) -> i32;
        fn GetLengthSid(sid: *mut c_void) -> u32;
        fn EqualSid(left: *mut c_void, right: *mut c_void) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            attributes: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
    }

    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: descriptors and SID strings come from LocalAlloc-backed
            // Win32 APIs; ownership is unique and null is accepted by LocalFree.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct Handle(*mut c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: this is an owned token handle returned by OpenProcessToken.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct User(Vec<usize>);
    impl User {
        fn current() -> PortResult<Self> {
            let mut token = ptr::null_mut();
            // SAFETY: pseudo process handle is valid; output points to local storage.
            if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) } == 0 {
                return Err(private_validation_io(
                    std::io::Error::last_os_error(),
                    "token_open",
                ));
            }
            let token = Handle(token);
            let mut needed = 0;
            // SAFETY: a null zero-size buffer requests required TOKEN_USER size.
            unsafe {
                GetTokenInformation(token.0, 1, ptr::null_mut(), 0, &mut needed);
            }
            if !(std::mem::size_of::<usize>() as u32..=65536).contains(&needed) {
                return Err(private_validation_error("token_size", 0, false));
            }
            let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
            // SAFETY: buffer is pointer-aligned and at least needed bytes long.
            if unsafe {
                GetTokenInformation(token.0, 1, buffer.as_mut_ptr().cast(), needed, &mut needed)
            } == 0
            {
                return Err(private_validation_io(
                    std::io::Error::last_os_error(),
                    "token_information",
                ));
            }
            Ok(Self(buffer))
        }
        fn sid(&self) -> *mut c_void {
            // SAFETY: successful TOKEN_USER starts with SID_AND_ATTRIBUTES.Sid;
            // the returned pointer remains inside our owned token-information buffer.
            unsafe { *self.0.as_ptr().cast::<*mut c_void>() }
        }
        fn sid_text(&self) -> PortResult<String> {
            let mut text = ptr::null_mut();
            // SAFETY: sid references a live TOKEN_USER buffer, output is local.
            if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
                return Err(io_error(()));
            }
            let owned = Local(text.cast());
            let mut len = 0;
            // SAFETY: ConvertSidToStringSidW returns a null-terminated SID string.
            unsafe {
                while *text.add(len) != 0 {
                    len += 1;
                }
            }
            // SAFETY: the scanned range is within the live Win32 allocation.
            let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
                .map_err(io_error);
            drop(owned);
            result
        }
    }
    fn wide(path: &Path) -> PortResult<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io_error(()));
        }
        value.push(0);
        Ok(value)
    }
    pub(super) fn create_directory(path: &Path) -> PortResult<()> {
        let descriptor = descriptor()?;
        let attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0,
            inherit: 0,
        };
        let name = wide(path)?;
        // SAFETY: both structures live through this call; DACL is installed at creation.
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            return Err(io_error(()));
        }
        Ok(())
    }

    fn descriptor() -> PortResult<Local> {
        let user = User::current()?;
        let sid = user.sid_text()?;
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        // SAFETY: string is terminated; output pointers are valid and optional size is null.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io_error(()));
        }
        Ok(Local(descriptor))
    }

    pub(super) fn create_file(path: &Path) -> PortResult<std::fs::File> {
        use std::os::windows::io::FromRawHandle;
        let descriptor = descriptor()?;
        let attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0,
            inherit: 0,
        };
        let name = wide(path)?;
        // SAFETY: terminated name and descriptor live through CreateFileW.
        // CREATE_NEW never overwrites an existing file or follows its symlink.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x40000000,
                0,
                &attributes,
                1,
                0x80,
                ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(io_error(()));
        }
        // SAFETY: valid owned file handle, ownership transfers exactly once.
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }
    pub(super) fn verify(path: &Path) -> PortResult<()> {
        let file = open_for_verification(path, false)?;
        verify_handle(&file, false, false)
    }

    pub(super) fn verify_file(path: &Path, sidecar: bool) -> PortResult<()> {
        let file = open_for_verification(path, sidecar)?;
        verify_handle(&file, true, sidecar)
    }

    pub(super) fn open_private_read(path: &Path) -> PortResult<File> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, READ_CONTROL,
        };
        // Deny write/delete sharing while verification pins the backup image.
        let file = OpenOptions::new()
            .read(true)
            .access_mode(0x80000000 | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| private_file_io(error, false))?;
        verify_handle(&file, true, false)?;
        Ok(file)
    }

    pub(super) fn validate_private_read(path: &Path, file: &File) -> PortResult<()> {
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        verify_handle(file, true, false)?;
        let named = open_for_verification(path, false)?;
        verify_handle(&named, true, false)?;
        let mut opened_info = BY_HANDLE_FILE_INFORMATION::default();
        let mut named_info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: both Files own live handles; each output is the exact matching
        // writable structure and remains alive until the call returns.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut opened_info) } == 0
            || unsafe { GetFileInformationByHandle(named.as_raw_handle(), &mut named_info) } == 0
        {
            return Err(private_file_io(std::io::Error::last_os_error(), false));
        }
        if (
            opened_info.dwVolumeSerialNumber,
            opened_info.nFileIndexHigh,
            opened_info.nFileIndexLow,
        ) != (
            named_info.dwVolumeSerialNumber,
            named_info.nFileIndexHigh,
            named_info.nFileIndexLow,
        ) {
            return Err(io_error(()));
        }
        Ok(())
    }

    fn open_for_verification(path: &Path, sidecar: bool) -> PortResult<File> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };
        OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map_err(|e| private_file_io_at(e, sidecar, "handle_open"))
    }

    fn verify_handle(file: &File, regular_file: bool, sidecar: bool) -> PortResult<()> {
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns a live handle, and info is the matching writable buffer.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(private_file_io_at(
                std::io::Error::last_os_error(),
                sidecar,
                "handle_information",
            ));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(private_validation_error("handle_reparse", 0, sidecar));
        }
        if regular_file && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(private_validation_error("handle_file_kind", 0, sidecar));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 && info.nNumberOfLinks > 1 {
            return Err(private_validation_error("handle_links", 0, sidecar));
        }
        let mut standard = FILE_STANDARD_INFO::default();
        // SAFETY: same live handle and matching structure/class with exact size.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
        } == 0
        {
            return Err(private_file_io_at(
                std::io::Error::last_os_error(),
                sidecar,
                "handle_standard_information",
            ));
        }
        if standard.NumberOfLinks > 1 && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(private_validation_error(
                "handle_standard_links",
                0,
                sidecar,
            ));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            && standard.NumberOfLinks != 1
            && !standard.DeletePending
        {
            return Err(private_validation_error("handle_unlinked", 0, sidecar));
        }
        let user = User::current()?;
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: SE_FILE_OBJECT, OWNER|DACL into valid pointers. Query the same
        // nofollow handle whose attributes were validated above, never its name.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                1,
                5,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(private_file_io_at(
                std::io::Error::from_raw_os_error(result as i32),
                sidecar,
                "security_information",
            ));
        }
        let _owned = Local(descriptor);
        if owner.is_null() {
            return Err(private_validation_error(
                "security_owner_missing",
                0,
                sidecar,
            ));
        }
        if acl.is_null() {
            return Err(private_validation_error("security_acl_missing", 0, sidecar));
        }
        // SAFETY: owner/acl borrow the live descriptor returned by Win32.
        if unsafe { EqualSid(owner, user.sid()) } == 0 {
            return Err(private_validation_error("security_owner", 0, sidecar));
        }
        // SAFETY: ACL borrows the live descriptor returned by Win32.
        if unsafe { IsValidAcl(acl) } == 0 {
            return Err(private_validation_error("security_acl", 0, sidecar));
        }
        // SAFETY: ACL was validated and remains owned for the entire loop.
        let count = unsafe { (*acl).count };
        let mut grants = false;
        for index in 0..u32::from(count) {
            let mut ace = ptr::null_mut();
            // SAFETY: index is bounded by validated ACL count and output is local.
            if unsafe { GetAce(acl, index, &mut ace) } == 0 {
                return Err(private_validation_error(
                    "security_ace_query",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    sidecar,
                ));
            }
            if ace.is_null() {
                return Err(private_validation_error("security_ace_missing", 0, sidecar));
            }
            // SAFETY: GetAce returned a valid ACE in the live ACL allocation.
            let header = unsafe { &*ace.cast::<AceHeader>() };
            // Standard deny ACEs cannot grant rights. All other nonstandard ACEs
            // fail closed rather than guess object/callback SID offsets.
            if header.kind == 1 {
                continue;
            }
            if header.kind != 0 || header.size < 16 {
                return Err(private_validation_error("security_ace_kind", 0, sidecar));
            }
            // SAFETY: ACCESS_ALLOWED_ACE places SidStart after header and mask;
            // validated ACE has at least the SID header bytes.
            let sid = unsafe { ace.cast::<u8>().add(8).cast() };
            // SAFETY: SID points into a validated ACE. Length is checked before comparison.
            if unsafe {
                IsValidSid(sid) == 0
                    || GetLengthSid(sid) > u32::from(header.size) - 8
                    || EqualSid(sid, user.sid()) == 0
            } {
                return Err(private_validation_error("security_ace_sid", 0, sidecar));
            }
            grants = true;
        }
        if !grants {
            return Err(private_validation_error(
                "security_grant_missing",
                0,
                sidecar,
            ));
        }
        // A delete-pending file is retryable only after all available safety
        // checks pass. Never relabel an observed unsafe ACL as contention.
        if standard.DeletePending {
            return Err(private_file_io_at(
                std::io::Error::from_raw_os_error(303),
                sidecar,
                "handle_delete_pending",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod sidecar_tests {
        use super::*;
        use crate::control::{
            SqliteControlStore, private_file, private_file_observed, sql_error, sql_query_error,
            sql_windows_query_error, verify_sidecars,
        };
        use agent_session_grep_ports::{
            PortError,
            control::{ControlId, ControlStore, DesiredUpdates},
        };
        use rusqlite::Connection;
        use std::{
            fs, io,
            time::{Duration, Instant},
        };

        fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("private");
            create_directory(&root).unwrap();
            let db = root.join("synthetic.db");
            drop(create_file(&db).unwrap());
            (temp, root, db)
        }

        fn sidecar(db: &Path, suffix: &str) -> std::path::PathBuf {
            let mut path = db.as_os_str().to_os_string();
            path.push(suffix);
            path.into()
        }

        fn allow_everyone(path: &Path) {
            #[link(name = "advapi32")]
            unsafe extern "system" {
                fn SetFileSecurityW(path: *const u16, info: u32, descriptor: *mut c_void) -> i32;
            }
            let sddl: Vec<_> = "D:P(A;;FA;;;WD)".encode_utf16().chain(Some(0)).collect();
            let mut descriptor = ptr::null_mut();
            // SAFETY: terminated synthetic SDDL and writable output pointer.
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        1,
                        &mut descriptor,
                        ptr::null_mut(),
                    )
                },
                0
            );
            let descriptor = Local(descriptor);
            let path = wide(path).unwrap();
            // SAFETY: only this disposable file is changed; the descriptor and
            // terminated name remain live. Set its protected DACL, not owner.
            assert_ne!(
                unsafe { SetFileSecurityW(path.as_ptr(), 0x80000004, descriptor.0) },
                0
            );
        }

        #[test]
        fn validation_diagnostics_keep_only_fixed_stage_and_numeric_cause() {
            let error = io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic private path and content must not appear",
            );
            let PortError::Backend(detail) =
                private_file_io_at(error, true, "security_information")
            else {
                panic!("permission refusal must remain a hard failure");
            };
            assert_eq!(
                detail,
                "private storage validation failed (stage=security_information, sidecar=1, code=0)",
            );
            let PortError::Backend(detail) =
                private_file_io_at(io::Error::from_raw_os_error(5), true, "handle_open")
            else {
                panic!("access denial must remain a hard failure");
            };
            assert_eq!(
                detail,
                "private storage validation failed (stage=handle_open, sidecar=1, code=5)",
            );
        }

        #[test]
        fn sqlite_last_close_between_observation_and_validation_is_retryable() {
            let (_temp, _root, db) = setup();
            let connection = Connection::open(&db).unwrap();
            connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE synthetic(value); INSERT INTO synthetic VALUES(1);").unwrap();
            let wal = sidecar(&db, "-wal");
            let shm = sidecar(&db, "-shm");
            let observed_wal = fs::symlink_metadata(&wal).unwrap();
            let observed_shm = fs::symlink_metadata(&shm).unwrap();
            verify_sidecars(&db).unwrap();
            drop(connection); // SQLite itself checkpoints and unlinks its sidecars.
            assert!(!wal.exists());
            assert!(!shm.exists());
            for (path, observed) in [(&wal, &observed_wal), (&shm, &observed_shm)] {
                assert!(matches!(
                    private_file_observed(path, observed, true),
                    Err(PortError::WriterBusy(_))
                ));
            }
            verify_sidecars(&db).unwrap(); // A fresh absence is allowed.
            assert!(matches!(private_file(&wal), Err(PortError::Backend(_))));
        }

        #[test]
        fn security_check_stays_on_opened_object_after_path_replacement() {
            let (_temp, root, db) = setup();
            let wal = sidecar(&db, "-wal");
            drop(create_file(&wal).unwrap());
            let opened = open_for_verification(&wal, true).unwrap();
            let saved = root.join("saved-wal");
            fs::rename(&wal, &saved).unwrap();
            drop(create_file(&wal).unwrap());
            allow_everyone(&wal);
            // The opened original still passes; the replacement must not.
            verify_handle(&opened, true, true).unwrap();
            assert!(matches!(verify_sidecars(&db), Err(PortError::Backend(_))));
            // Querying a saved unsafe object cannot borrow the replacement ACL.
            let unsafe_opened = open_for_verification(&wal, true).unwrap();
            fs::rename(&wal, root.join("unsafe-wal")).unwrap();
            drop(create_file(&wal).unwrap());
            verify_sidecars(&db).unwrap();
            assert!(matches!(
                verify_handle(&unsafe_opened, true, true),
                Err(PortError::Backend(_))
            ));
        }

        #[test]
        fn delete_pending_private_handle_is_retryable_and_unsafe_acl_is_not() {
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
            };
            for unsafe_acl in [false, true] {
                let (_temp, _root, db) = setup();
                let wal = sidecar(&db, "-wal");
                drop(create_file(&wal).unwrap());
                if unsafe_acl {
                    allow_everyone(&wal);
                }
                let file = OpenOptions::new()
                    .access_mode(DELETE | 0x20000 | 0x80)
                    .share_mode(7)
                    .custom_flags(0x00200000)
                    .open(&wal)
                    .unwrap();
                let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                // SAFETY: valid owned disposable handle with DELETE access and
                // matching FILE_DISPOSITION_INFO payload/class.
                assert_ne!(
                    unsafe {
                        SetFileInformationByHandle(
                            file.as_raw_handle(),
                            FileDispositionInfo,
                            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                        )
                    },
                    0
                );
                let result = verify_handle(&file, true, true);
                if unsafe_acl {
                    assert!(matches!(result, Err(PortError::Backend(ref detail))
                        if detail == "private storage validation failed (stage=security_ace_sid, sidecar=1, code=0)"));
                } else {
                    assert!(matches!(result, Err(PortError::WriterBusy(ref detail))
                        if detail == "private storage changed during validation (stage=handle_delete_pending, sidecar=1, code=303)"));
                }
            }
        }

        #[test]
        fn metadata_only_open_and_transient_errors_preserve_fail_closed_validation() {
            let (_temp, root, db) = setup();
            let wal = sidecar(&db, "-wal");
            drop(create_file(&wal).unwrap());
            let held = OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&wal)
                .unwrap();
            let started = Instant::now();
            // Metadata/READ_CONTROL access does not conflict with an exclusive
            // data-reader handle. Do not ask for GENERIC_READ just to validate.
            verify_sidecars(&db).unwrap();
            assert!(started.elapsed() < Duration::from_secs(1));
            drop(held);
            verify_sidecars(&db).unwrap();
            fs::hard_link(&wal, root.join("alias")).unwrap();
            assert!(
                matches!(verify_sidecars(&db), Err(PortError::Backend(ref detail))
                if detail == "private storage validation failed (stage=handle_links, sidecar=1, code=0)")
            );
            fs::remove_file(&wal).unwrap();
            create_directory(&wal).unwrap();
            assert!(matches!(verify_sidecars(&db), Err(PortError::Backend(_))));
            for code in [2, 3, 32, 33, 303] {
                assert!(matches!(
                    private_file_io(io::Error::from_raw_os_error(code), true),
                    PortError::WriterBusy(_)
                ));
            }
            assert!(matches!(
                private_file_io(io::Error::from_raw_os_error(5), true),
                PortError::Backend(_)
            ));
        }

        #[test]
        fn observed_file_replaced_by_junction_is_rejected_without_following() {
            let (_temp, root, db) = setup();
            let wal = sidecar(&db, "-wal");
            drop(create_file(&wal).unwrap());
            let observed = fs::symlink_metadata(&wal).unwrap();
            fs::remove_file(&wal).unwrap();
            let target = root.join("target");
            create_directory(&target).unwrap();
            let output = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:ASG_TEST_SIDECAR -Target $env:ASG_TEST_TARGET | Out-Null"])
                .env("ASG_TEST_SIDECAR", &wal).env("ASG_TEST_TARGET", &target)
                .output().unwrap();
            assert!(
                output.status.success(),
                "synthetic junction creation failed"
            );
            assert!(matches!(
                private_file_observed(&wal, &observed, true),
                Err(PortError::Backend(_))
            ));
            assert!(matches!(verify_sidecars(&db), Err(PortError::Backend(_))));
            assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        }

        #[test]
        fn unmapped_validation_handle_does_not_cause_sqlite_shm_truncate_failure() {
            use windows_sys::Win32::Storage::FileSystem::SetEndOfFile;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn CreateFileMappingW(
                    file: *mut c_void,
                    security: *const c_void,
                    protect: u32,
                    high: u32,
                    low: u32,
                    name: *const u16,
                ) -> *mut c_void;
                fn MapViewOfFile(
                    mapping: *mut c_void,
                    access: u32,
                    high: u32,
                    low: u32,
                    size: usize,
                ) -> *mut c_void;
                fn UnmapViewOfFile(view: *const c_void) -> i32;
            }
            struct Mapping {
                view: *mut c_void,
                _handle: Handle,
            }
            impl Drop for Mapping {
                fn drop(&mut self) {
                    // SAFETY: uniquely owned view from MapViewOfFile, still live.
                    unsafe {
                        UnmapViewOfFile(self.view);
                    }
                }
            }
            let (_temp, root, _db) = setup();
            let control = SqliteControlStore::create(
                &root,
                &ControlId::parse("synthetic-installation").unwrap(),
                DesiredUpdates::Running,
            )
            .unwrap();
            let expected = control.status().unwrap();
            drop(control);
            let db = SqliteControlStore::path(&root);
            let shm = sidecar(&db, "-shm");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&shm)
                .unwrap();
            file.set_len(65536).unwrap();
            let checked = open_for_verification(&shm, true).unwrap();
            verify_handle(&checked, true, true).unwrap();
            // SAFETY: owned writable file; unnamed PAGE_READWRITE mapping.
            let handle = unsafe {
                CreateFileMappingW(file.as_raw_handle(), ptr::null(), 4, 0, 0, ptr::null())
            };
            assert!(!handle.is_null());
            let handle = Handle(handle);
            // SAFETY: valid mapping handle, FILE_MAP_WRITE, bounds inside file.
            let view = unsafe { MapViewOfFile(handle.0, 2, 0, 0, 65536) };
            assert!(!view.is_null());
            let mapping = Mapping {
                view,
                _handle: handle,
            };
            // Fresh file cursor is at zero. Windows refuses truncation while a
            // view is mapped, even though no SQLite DMS lock remains.
            // SAFETY: live writable file handle; only this synthetic SHM file.
            assert_eq!(unsafe { SetEndOfFile(file.as_raw_handle()) }, 0);
            let os_code = io::Error::last_os_error().raw_os_error();
            assert_eq!(os_code, Some(1224)); // ERROR_USER_MAPPED_FILE
            let reopened =
                Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .unwrap();
            let error = reopened
                .query_row("SELECT count(*) FROM control_meta", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap_err();
            assert_eq!(
                error.sqlite_error().unwrap().extended_code,
                rusqlite::ffi::SQLITE_IOERR_TRUNCATE
            );
            assert!(matches!(
                sql_query_error(&reopened, error),
                PortError::WriterBusy(_)
            ));
            drop(reopened);
            assert!(matches!(
                SqliteControlStore::open_current_read_only(&root),
                Err(PortError::WriterBusy(_))
            ));
            drop(mapping);
            // Keep both ordinary and ACL-validation handles open: neither maps
            // memory, and neither prevents recovery after the view is unmapped.
            let reopened = SqliteControlStore::open_current_read_only(&root).unwrap();
            assert_eq!(reopened.status().unwrap(), expected);
            drop(reopened);
            drop(checked);
            drop(file);
        }

        #[test]
        fn sql_diagnostics_contain_only_codes_and_keep_error_classification() {
            let error = rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR_SHMOPEN),
                Some("synthetic SQL/path details must stay private".into()),
            );
            let PortError::SchemaIncompatible(message) = sql_error(error) else {
                panic!("classification changed")
            };
            assert_eq!(
                message,
                format!(
                    "control SQLite failure (sqlite_primary=10, sqlite_extended={})",
                    rusqlite::ffi::SQLITE_IOERR_SHMOPEN
                )
            );
            assert!(!message.contains("synthetic"));
            assert!(matches!(
                sql_error(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    None,
                )),
                PortError::WriterBusy(_)
            ));
            for (code, system) in [
                (rusqlite::ffi::SQLITE_IOERR_TRUNCATE, 0),
                (rusqlite::ffi::SQLITE_IOERR_TRUNCATE, 5),
                (rusqlite::ffi::SQLITE_IOERR_TRUNCATE, 112),
                (rusqlite::ffi::SQLITE_IOERR_SHMOPEN, 1224),
                (rusqlite::ffi::SQLITE_CORRUPT, 1224),
            ] {
                assert!(matches!(
                    sql_windows_query_error(
                        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None,),
                        system
                    ),
                    PortError::SchemaIncompatible(_)
                ));
            }
        }
    }
}

#[cfg(test)]
mod runtime_deadline_tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn fixture() -> (tempfile::TempDir, SqliteControlStore) {
        let temp = tempfile::tempdir().unwrap();
        let control = SqliteControlStore::create(
            &temp.path().join("private"),
            &ControlId::parse("synthetic-deadline-installation").unwrap(),
            DesiredUpdates::Paused,
        )
        .unwrap();
        (temp, control)
    }

    #[test]
    fn committed_mutation_survives_trailing_deadline_expiry() {
        let (_temp, control) = fixture();
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = control.with_runtime_deadline(deadline, || {
            let change = control.mutate(ControlSeq::new(0).unwrap(), |_, _| {
                Ok((false, false, "committed-value"))
            })?;
            assert_eq!(change.value, "committed-value");
            // The commit above was durable; simulate the trailing wall-clock
            // check observing that the original deadline has passed.
            RUNTIME_DEADLINE.with(|slot| slot.set(Some(Instant::now())));
            assert!(matches!(runtime_tick(), Err(PortError::WriterBusy(_))));
            Ok(change)
        });
        let change = result.expect("committed result must not become WriterBusy");
        assert_eq!(change.value, "committed-value");
        assert_eq!(control.status().unwrap().policy.control_seq.get(), 0);
    }

    #[test]
    fn sql_progress_interrupts_long_statement_and_restores_connection_handler() {
        let (_temp, control) = fixture();
        let result = control.with_runtime_deadline(Instant::now() + Duration::from_millis(5), || {
            let conn = control.conn.borrow();
            let raw: rusqlite::Result<i64> = conn.query_row(
                "WITH RECURSIVE n(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM n WHERE value<1000000) SELECT sum(value) FROM n",
                [], |row| row.get(0),
            );
            assert!(matches!(&raw, Err(error) if error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted)));
            raw.map_err(sql_error)
        });
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(runtime_deadline().is_none());
        let sum: i64 = control.conn.borrow().query_row(
            "WITH RECURSIVE n(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM n WHERE value<10000) SELECT sum(value) FROM n",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(sum, 50_005_000);
        assert!(control.status().is_ok());
    }

    #[test]
    fn row_decoder_checks_original_deadline_after_sql_yields_before_bad_field_decode() {
        use rusqlite::functions::FunctionFlags;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let (_temp, control) = fixture();
        let conn = Connection::open_in_memory().unwrap();
        let arrived = Arc::new(AtomicBool::new(false));
        let called = arrived.clone();
        conn.create_scalar_function(
            "expire_row_budget",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| {
                called.store(true, Ordering::Relaxed);
                // Represents a row yielded by SQLite after an external/callback
                // wait. The control row decoder must check before allocating
                // or parsing the intentionally malformed identifier below.
                RUNTIME_DEADLINE.with(|slot| slot.set(Some(Instant::now())));
                Ok("malformed identifier with spaces".to_string())
            },
        )
        .unwrap();
        conn.execute_batch(
            "CREATE VIEW selections AS SELECT expire_row_budget() AS selection_id,
            'codex' AS provider_id, '/synthetic' AS canonical_locator, 'root' AS root_kind,
            'synthetic-root' AS root_identity, 1 AS enabled, 1 AS revision,
            1 AS created_at_ms, NULL AS revoked_at_ms",
        )
        .unwrap();
        let result = control.with_runtime_deadline(Instant::now() + Duration::from_secs(1), || {
            load_selections(&conn)
        });
        assert!(arrived.load(Ordering::Relaxed));
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(runtime_deadline().is_none());
        assert!(control.status().is_ok());
    }

    #[test]
    fn nested_scope_uses_earliest_deadline_and_restores_outer_on_error() {
        let (_temp, control) = fixture();
        let outer = Instant::now() + Duration::from_secs(1);
        control
            .with_runtime_deadline(outer, || {
                assert_eq!(runtime_deadline(), Some(outer));
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(outer + Duration::from_secs(1)),
                    outer
                );
                control.with_runtime_deadline(outer + Duration::from_secs(1), || {
                    assert_eq!(runtime_deadline(), Some(outer));
                    assert_eq!(
                        SqliteControlStore::effective_runtime_deadline(
                            outer + Duration::from_secs(2)
                        ),
                        outer
                    );
                    Ok(())
                })?;
                let earlier = Instant::now() + Duration::from_millis(20);
                let result: PortResult<()> = control.with_runtime_deadline(earlier, || {
                    assert_eq!(runtime_deadline(), Some(earlier));
                    assert_eq!(
                        SqliteControlStore::effective_runtime_deadline(outer),
                        earlier
                    );
                    Err(PortError::NotFound("synthetic missing value".into()))
                });
                assert!(matches!(result, Err(PortError::NotFound(_))));
                assert_eq!(runtime_deadline(), Some(outer));
                control.status().map(|_| ())
            })
            .unwrap();
        assert!(runtime_deadline().is_none());
    }

    #[test]
    fn expired_nested_scope_and_unwind_do_not_poison_later_requests() {
        let (_temp, control) = fixture();
        let outer = Instant::now() + Duration::from_secs(1);
        control
            .with_runtime_deadline(outer, || {
                let result: PortResult<()> = control.with_runtime_deadline(Instant::now(), || {
                    panic!("expired callback must not execute")
                });
                assert!(matches!(result, Err(PortError::WriterBusy(_))));
                assert_eq!(runtime_deadline(), Some(outer));
                Ok(())
            })
            .unwrap();
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let _: PortResult<()> =
                control.with_runtime_deadline(outer, || panic!("synthetic unwind"));
        }));
        assert!(panicked.is_err());
        assert!(runtime_deadline().is_none());
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), BUSY_TIMEOUT);
        assert!(control.status().is_ok());
    }

    #[test]
    fn history_capture_and_prune_keep_outer_deadline_and_restore_after_busy() {
        let (_temp, control) = fixture();
        let root = control.private_root().to_path_buf();
        let background = ExclusiveGuard::try_acquire(&root, LockKind::Background).unwrap();
        let worker = control
            .bind_worker(
                &background,
                ControlId::parse("synthetic-history-boot").unwrap(),
            )
            .unwrap();
        control
            .register_worker(
                control.status().unwrap().policy.control_seq,
                &worker,
                std::process::id(),
                1,
            )
            .unwrap();
        let readers = ExclusiveGuard::try_acquire(&root, LockKind::HistoryReaders).unwrap();
        let outer = Instant::now() + Duration::from_secs(1);
        let captured = control
            .with_runtime_deadline(outer, || {
                let captured = control.capture_history_dependencies(
                    &worker,
                    &readers,
                    outer + Duration::from_secs(1),
                )?;
                assert_eq!(runtime_deadline(), Some(outer));
                Ok(captured)
            })
            .unwrap();
        assert!(captured.cycles.is_empty());
        assert!(runtime_deadline().is_none());
        let raw = Connection::open(SqliteControlStore::path(&root)).unwrap();
        raw.execute_batch("BEGIN IMMEDIATE").unwrap();
        let deadline = Instant::now() + Duration::from_millis(25);
        let refused = control.with_runtime_deadline(deadline, || {
            control.prune_history(
                &worker,
                &readers,
                &captured,
                &[],
                deadline + Duration::from_secs(1),
            )
        });
        assert!(matches!(refused, Err(PortError::WriterBusy(_))));
        assert!(runtime_deadline().is_none());
        raw.execute_batch("ROLLBACK").unwrap();
        let counts = control
            .prune_history(
                &worker,
                &readers,
                &captured,
                &[],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(counts, ControlHistoryCounts::default());
        assert!(control.status().is_ok());
    }

    #[test]
    fn purge_inner_scope_keeps_original_deadline_and_one_millisecond_busy_cap() {
        let (_temp, control) = fixture();
        let outer = Instant::now() + Duration::from_secs(1);
        control
            .with_runtime_deadline(outer, || {
                control.with_purge_deadline(outer + Duration::from_secs(1), || {
                    assert_eq!(runtime_deadline(), Some(outer));
                    assert_eq!(
                        RUNTIME_BUSY_ALLOWANCE.with(Cell::get),
                        Duration::from_millis(1)
                    );
                    control.status().map(|_| ())
                })?;
                assert_eq!(runtime_deadline(), Some(outer));
                assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), BUSY_TIMEOUT);
                Ok(())
            })
            .unwrap();
    }
}
