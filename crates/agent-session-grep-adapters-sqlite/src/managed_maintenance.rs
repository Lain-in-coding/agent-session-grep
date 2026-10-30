//! Authorized managed-catalog maintenance: Beta-to-Beta offline upgrade and
//! rollback backups, policy compatibility readback and owned purge.
//!
//! Every operation here is reachable only with real OS capabilities:
//! - the installation-prefix update lock ([`InstallationLockAuthority`]),
//! - a `PolicyOwner` control-root guard for short control mutations,
//! - the durable maintenance fence owned by this nonce, and
//! - an exclusive `catalog-handles` guard plus the writer lease after drain.
//!
//! The catalog connection never escapes this module. Backup content is produced
//! with SQLite's logical backup API; raw WAL/control/policy/history/cache files
//! are never copied.
use crate::{
    SCHEMA_VERSION, SqliteControlStore, SqliteStore, WriterLease,
    control::{
        BackupPurpose, BackupRegistration, BackupState, CoveredSource, InstallationLockAuthority,
        StoredBackup, catalog_backup_locator, ensure_private_directory, retry_seq_race_before,
        validate_private_directory,
    },
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity, SharedGuard},
    managed_store::{APPLICATION_ID, validate_catalog_path},
};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider,
    control::{
        CanonicalLocator, ControlId, ControlStore, MaintenanceState, ReadPolicy,
        RequestIntersection,
    },
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, backup};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const MANIFEST_SCHEMA: &str = "asg.catalog-backup/v1";
const BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_MANIFEST: u64 = 256 * 1024;
const VERIFY_BUDGET: Duration = Duration::from_secs(10);
const COPY_STEP_PAGES: std::ffi::c_int = 128;

fn invalid(reason: &'static str) -> PortError {
    PortError::InvalidRequest(reason.into())
}
fn incompatible(reason: &'static str) -> PortError {
    PortError::SchemaIncompatible(reason.into())
}
fn busy(reason: &'static str) -> PortError {
    PortError::WriterBusy(reason.into())
}
fn storage() -> PortError {
    PortError::Backend("managed maintenance storage is unavailable".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            busy("managed maintenance storage is busy")
        }
        Some(rusqlite::ErrorCode::OperationInterrupted) => {
            busy("managed maintenance SQL exceeded its deadline")
        }
        _ => incompatible("managed maintenance SQLite state is incompatible"),
    }
}

/// A verification error is transient when it reflects the environment rather
/// than the backup's own bytes: IO failures (CANTOPEN on a momentarily locked
/// or scanned file, IOERR read failures, full disks) can clear on retry, so
/// they must not quarantine a verified backup. Typed classification failures
/// (identity/integrity/coverage mismatch, malformed manifest) remain
/// quarantine-worthy.
pub fn verification_is_transient(error: &PortError) -> bool {
    matches!(error, PortError::SourceIo(_) | PortError::Backend(_))
}

/// Conservative refusal reasons surfaced to the update journal. None of these
/// is reported as a successful backup/restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupAttention {
    PolicyMismatch,
    CoverageMismatch,
    AccountingMismatch,
}

/// Verified catalog identity as read from the file itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogIdentity {
    pub installation: ControlId,
    pub incarnation: ControlId,
    pub schema: u32,
    pub generation: u64,
}

/// Public (journal-safe) backup metadata. No raw source path or content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMetadata {
    pub backup_id: ControlId,
    pub purpose: BackupPurpose,
    pub relative_locator: String,
    pub installation: ControlId,
    pub catalog_incarnation: ControlId,
    pub catalog_generation: u64,
    pub schema_version: u32,
    pub digest: String,
    pub size_bytes: u64,
    pub source_ids: Vec<ControlId>,
}

/// Result of one backup attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupOutcome {
    Created(BackupMetadata),
    Attention(BackupAttention),
}

/// Result of a restore preparation. A refusal is explicit, never success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    Prepared(Box<RestorePreparation>),
    Attention(BackupAttention),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePreparation {
    side_path: PathBuf,
    installation: ControlId,
    incarnation: ControlId,
    generation: u64,
    schema: u32,
    coverage: Vec<CoveredSource>,
    backup_id: ControlId,
    journal_path: PathBuf,
    digest: String,
    size_bytes: u64,
}
impl RestorePreparation {
    pub fn side_path(&self) -> &Path {
        &self.side_path
    }
    pub fn incarnation(&self) -> &ControlId {
        &self.incarnation
    }
    pub fn catalog_generation(&self) -> u64 {
        self.generation
    }
    pub fn schema_version(&self) -> u32 {
        self.schema
    }
    pub fn backup_id(&self) -> &ControlId {
        &self.backup_id
    }
    pub fn coverage(&self) -> &[CoveredSource] {
        &self.coverage
    }
    pub fn installation_id(&self) -> &ControlId {
        &self.installation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeOutcome {
    Purged {
        metadata: BackupMetadata,
        artifact_removed: bool,
    },
    NotWithdrawn,
    /// Durable nonrestorable withdrawal; source accounting remains intact
    /// until the owned files can actually be removed.
    PendingCleanup {
        metadata: BackupMetadata,
    },
    Attention(BackupAttention),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarManifest {
    schema: String,
    backup_id: String,
    purpose: String,
    installation_id: String,
    catalog_incarnation: String,
    catalog_generation: u64,
    schema_version: u32,
    digest: String,
    size_bytes: u64,
    source_ids: Vec<String>,
    created_at_ms: i64,
}

/// A live catalog opened for maintenance only. It owns the exclusive handle
/// gate and writer lease; no raw SQL or connection is exported.
pub struct MaintenanceCatalog {
    conn: Option<Connection>,
    pin: Option<fs::File>,
    path: PathBuf,
    _lease: WriterLease,
    _handles: ExclusiveGuard,
    root: RootIdentity,
    installation: ControlId,
    identity: CatalogIdentity,
}

impl MaintenanceCatalog {
    /// Open the managed catalog under a durable `updating`/`recovering` fence.
    ///
    /// The caller must already have drained cooperating readers; this function
    /// proves it by taking `catalog-handles` exclusively and only then the
    /// writer lease. It never takes a shared handle and then waits for the
    /// exclusive one, and it never opens SQLite with automatic migration.
    pub fn open_authorized(
        control: &SqliteControlStore,
        installation: &InstallationLockAuthority<'_>,
        owner: &ControlId,
        catalog: &Path,
        deadline: Instant,
    ) -> PortResult<Self> {
        installation.validate(control)?;
        require_fence(control, owner)?;
        validate_catalog_path(catalog)?;
        let root_path = catalog
            .parent()
            .ok_or_else(|| invalid("catalog root is invalid"))?;
        let root = RootIdentity::read(root_path)?;
        if !control.matches_root(root) {
            return Err(invalid("catalog is not under this control root"));
        }
        control.validate_catalog_file(catalog)?;
        let installation_id = installation.installation_id().clone();

        let handles = acquire_exclusive(root_path, LockKind::CatalogHandles, deadline)?;
        if handles.root_identity() != root {
            return Err(invalid("catalog root changed during admission"));
        }
        let lease = acquire_lease(root_path, deadline)?;
        let pin = open_catalog_pin(control, catalog)?;
        let conn = open_read_write(catalog, deadline)?;
        let identity = validate_compatible_identity(&conn, &installation_id)?;
        control.validate_private_read(catalog, &pin)?;
        require_fence(control, owner)?;
        if RootIdentity::read(root_path)? != root {
            return Err(invalid("catalog root changed during drain"));
        }
        Ok(Self {
            conn: Some(conn),
            pin: Some(pin),
            path: catalog.to_path_buf(),
            _lease: lease,
            _handles: handles,
            root,
            installation: installation_id,
            identity,
        })
    }

    pub fn identity(&self) -> &CatalogIdentity {
        &self.identity
    }

    pub fn root_identity(&self) -> RootIdentity {
        self.root
    }

    /// Migrate only this drained, installation-owned catalog. The canonical
    /// additive tail runs in one caller transaction; no receipt, namespace,
    /// generation, incarnation or control permission is reconstructed.
    pub fn migrate_to_current(
        &mut self,
        control: &SqliteControlStore,
        installation: &InstallationLockAuthority<'_>,
        owner: &ControlId,
        deadline: Instant,
    ) -> PortResult<CatalogIdentity> {
        control.with_runtime_deadline(deadline, || {
            self.validate_authority(control, installation, owner)?;
            check_deadline(deadline)?;
            let policy = require_fence(control, owner)?;
            let expected = self.identity.clone();
            let path = self.path.clone();
            let pin = self.pin.as_ref().ok_or_else(storage)?;
            let conn = self.conn.as_mut().ok_or_else(storage)?;
            set_sql_deadline(conn, deadline)?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            if validate_compatible_identity(&tx, &expected.installation)? != expected {
                return Err(incompatible("maintenance catalog identity changed"));
            }
            let coverage = read_coverage(&tx, deadline)?;
            verify_quick_integrity(&tx)?;
            verify_derived_integrity(&tx, deadline)?;
            let destructive_epoch: i64 = tx
                .query_row(
                    "SELECT destructive_epoch FROM store_metadata WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            SqliteStore::migrate_managed_in_transaction(&tx)?;
            let migrated = validate_identity(&tx, &expected.installation)?;
            if migrated.incarnation != expected.incarnation
                || migrated.generation != expected.generation
                || read_coverage(&tx, deadline)? != coverage
                || tx
                    .query_row(
                        "SELECT destructive_epoch FROM store_metadata WHERE singleton=1",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .map_err(sql)?
                    != destructive_epoch
            {
                return Err(incompatible("catalog migration changed its preimage"));
            }
            verify_quick_integrity(&tx)?;
            verify_derived_integrity(&tx, deadline)?;
            control.validate_private_read(&path, pin)?;
            installation.validate(control)?;
            if require_fence(control, owner)? != policy {
                return Err(busy("control policy changed during catalog migration"));
            }
            check_deadline(deadline)?;
            tx.commit().map_err(sql)?;
            self.identity = migrated.clone();
            self.validate_authority(control, installation, owner)?;
            check_deadline(deadline)?;
            Ok(migrated)
        })
    }

    /// Rotate a catalog after interrupted update recovery without replacing
    /// unchanged evidence with an older backup. The intent's incarnation is
    /// generated and persisted by the installation journal before this call.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_after_recovery(
        &mut self,
        control: &SqliteControlStore,
        installation: &InstallationLockAuthority<'_>,
        owner: &ControlId,
        original: &ControlId,
        recovery: &ControlId,
        now_ms: i64,
        deadline: Instant,
    ) -> PortResult<()> {
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        control.with_runtime_deadline(deadline, || {
            self.validate_authority(control, installation, owner)?;
            check_deadline(deadline)?;
            if original == recovery || now_ms < 0 {
                return Err(invalid("invalid recovery incarnation or timestamp"));
            }
            set_sql_deadline(self.connection()?, deadline)?;
            let actual = validate_compatible_identity(self.connection()?, &self.installation)?;
            if actual.incarnation != *original && actual.incarnation != *recovery {
                return Err(incompatible("unexpected catalog during recovery"));
            }
            let committed_identity = if actual.incarnation == *original {
                let tx = self
                    .conn
                    .as_mut()
                    .ok_or_else(storage)?
                    .transaction()
                    .map_err(sql)?;
                crate::managed::retain_receipts_after_recovery(
                    &tx,
                    original.as_str(),
                    recovery.as_str(),
                    owner.as_str(),
                )?;
                let changed = tx.execute(
                    "UPDATE catalog_meta SET catalog_incarnation=?1 WHERE singleton=1 AND catalog_incarnation=?2",
                    [recovery.as_str(), original.as_str()],
                ).map_err(sql)?;
                if changed != 1 {
                    return Err(incompatible("catalog recovery identity changed"));
                }
                tx.execute(
                    "UPDATE store_metadata SET destructive_epoch=destructive_epoch+1 WHERE singleton=1",
                    [],
                )
                .map_err(sql)?;
                let rotated = validate_compatible_identity(&tx, &self.installation)?;
                if rotated.incarnation != *recovery
                    || rotated.generation != actual.generation
                    || rotated.schema != actual.schema
                {
                    return Err(incompatible("catalog recovery identity changed"));
                }
                tx.commit().map_err(sql)?;
                rotated
            } else {
                actual
            };
            // Publish the identity read from the committed transaction before
            // any fallible control acknowledgement. A Busy acknowledgement
            // must leave this facade consistent with the durable catalog side
            // effect, and the acknowledgement remains under the same original
            // runtime deadline as catalog admission and publication.
            self.identity = committed_identity;
            let guard =
                acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let bound = control.bind_control_root(&guard)?;
            control.reset_after_catalog_recovery(
                control.status()?.policy.control_seq,
                owner,
                &bound,
                installation,
                &self._handles,
                &self.identity.incarnation,
                now_ms,
            )?;
            check_deadline(deadline)
        })
    }

    fn validate_authority(
        &self,
        control: &SqliteControlStore,
        installation: &InstallationLockAuthority<'_>,
        owner: &ControlId,
    ) -> PortResult<()> {
        installation.validate(control)?;
        if self.installation != *installation.installation_id()
            || !control.matches_root(self.root)
            || self._handles.root_identity() != self.root
        {
            return Err(invalid(
                "maintenance catalog is not bound to this installation",
            ));
        }
        self._handles.validate_current(control.private_root())?;
        let pin = self.pin.as_ref().ok_or_else(storage)?;
        control.validate_private_read(&self.path, pin)?;
        require_fence(control, owner)?;
        Ok(())
    }

    fn connection(&self) -> PortResult<&Connection> {
        self.conn.as_ref().ok_or_else(storage)
    }

    /// Full physical coverage read from the verified catalog snapshot.
    pub fn coverage(&self) -> PortResult<Vec<CoveredSource>> {
        let deadline = Instant::now() + VERIFY_BUDGET;
        set_sql_deadline(self.connection()?, deadline)?;
        read_coverage(self.connection()?, deadline)
    }

    /// Create (or reconcile) one logical catalog backup. Ownership rows are
    /// committed before any content bytes are written.
    #[expect(
        clippy::too_many_arguments,
        reason = "Retain the existing journal call contract with explicit lock authority and deadline"
    )]
    pub fn create_backup(
        &self,
        control: &SqliteControlStore,
        installation: &InstallationLockAuthority<'_>,
        owner: &ControlId,
        backup_id: &ControlId,
        purpose: BackupPurpose,
        now_ms: i64,
        deadline: Instant,
    ) -> PortResult<BackupOutcome> {
        self.validate_authority(control, installation, owner)?;
        check_deadline(deadline)?;
        set_sql_deadline(self.connection()?, deadline)?;
        // Pin identity, coverage and the backup source in one read snapshot.
        let snapshot = self.connection()?.unchecked_transaction().map_err(sql)?;
        let actual = validate_compatible_identity(&snapshot, &self.installation)?;
        if actual != self.identity {
            return Err(incompatible("maintenance catalog identity changed"));
        }
        let check: String = self
            .connection()?
            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
            .map_err(sql)?;
        if check != "ok" {
            return Err(incompatible("catalog integrity is unavailable"));
        }
        let coverage = match read_coverage(&snapshot, deadline) {
            Ok(coverage) => coverage,
            Err(PortError::SchemaIncompatible(_)) => {
                return Ok(BackupOutcome::Attention(BackupAttention::CoverageMismatch));
            }
            Err(error) => return Err(error),
        };
        let policy = control.read_policy(RequestIntersection::Selected)?;
        if coverage.iter().any(|source| {
            !policy.allows_source(source.provider, &source.locator, &source.source_id)
        }) {
            return Ok(BackupOutcome::Attention(BackupAttention::PolicyMismatch));
        }
        let registration = BackupRegistration {
            backup_id: backup_id.clone(),
            purpose,
            relative_locator: catalog_backup_locator(backup_id),
            catalog_incarnation: self.identity.incarnation.clone(),
            catalog_generation: self.identity.generation,
            schema_version: self.identity.schema,
            source_ids: coverage.iter().map(|s| s.source_id.clone()).collect(),
        };
        let registered = {
            let guard = acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let control_root = control.bind_control_root(&guard)?;
            control.register_backup(
                control.status()?.policy.control_seq,
                owner,
                &control_root,
                installation,
                &registration,
                now_ms,
            )?
        };
        if registered.value.state == BackupState::Complete {
            let metadata = metadata_from(&registered.value, &self.installation)?;
            verify_artifact(control, &metadata, deadline)?;
            return Ok(BackupOutcome::Created(metadata));
        }

        let path = artifact_path(control, &registration.relative_locator)?;
        prepare_artifact_parent(control, &path)?;
        if path.try_exists().map_err(|_| storage())?
            || manifest_path(&path)?.try_exists().map_err(|_| storage())?
        {
            return Ok(BackupOutcome::Attention(
                BackupAttention::AccountingMismatch,
            ));
        }
        control.create_private_file_under(&path)?;
        let mut destination = open_read_write(&path, deadline)?;
        write_logical_copy(&snapshot, &mut destination, deadline)?;
        set_sql_deadline(&destination, deadline)?;
        verify_derived_integrity(&destination, deadline)?;
        if validate_compatible_identity(&destination, &self.installation)? != actual
            || read_coverage(&destination, deadline)? != coverage
        {
            return Err(incompatible(
                "backup snapshot does not match its registered coverage",
            ));
        }
        destination
            .query_row("PRAGMA journal_mode=DELETE", [], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sql)?;
        drop(destination);
        let (digest, size_bytes) = hash_file(control, &path, deadline)?;
        write_sidecar(
            control,
            backup_id,
            purpose,
            &self.identity,
            &self.installation,
            &registration.source_ids,
            &digest,
            size_bytes,
            now_ms,
        )?;
        let candidate = BackupMetadata {
            backup_id: backup_id.clone(),
            purpose,
            relative_locator: registration.relative_locator.clone(),
            installation: self.installation.clone(),
            catalog_incarnation: actual.incarnation,
            catalog_generation: actual.generation,
            schema_version: actual.schema,
            digest: digest.clone(),
            size_bytes,
            source_ids: registration.source_ids.clone(),
        };
        verify_artifact(control, &candidate, deadline)?;
        let completed = {
            let guard = acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let control_root = control.bind_control_root(&guard)?;
            let policy = control.read_policy(RequestIntersection::Selected)?;
            if withdrawn(&policy, &coverage) {
                control.quarantine_backup(
                    policy.control_seq,
                    &control_root,
                    installation,
                    backup_id,
                    &coverage,
                    &digest,
                    size_bytes,
                    now_ms,
                )?;
                return Ok(BackupOutcome::Attention(BackupAttention::PolicyMismatch));
            }
            control.complete_backup(
                policy.control_seq,
                owner,
                &control_root,
                installation,
                backup_id,
                &digest,
                size_bytes,
            )?
        };
        let metadata = metadata_from(&completed.value, &self.installation)?;
        verify_artifact(control, &metadata, deadline)?;
        self.validate_authority(control, installation, owner)?;
        check_deadline(deadline)?;
        Ok(BackupOutcome::Created(metadata))
    }
}

/// Verify one completed backup from control metadata, artifact bytes and the
/// sidecar manifest. Returns the coverage needed for policy readback.
pub struct VerifiedBackup {
    metadata: BackupMetadata,
    coverage: Vec<CoveredSource>,
}
impl VerifiedBackup {
    pub fn metadata(&self) -> &BackupMetadata {
        &self.metadata
    }
    pub fn coverage(&self) -> &[CoveredSource] {
        &self.coverage
    }
}

pub fn verify_backup(
    control: &SqliteControlStore,
    backup_id: &ControlId,
) -> PortResult<VerifiedBackup> {
    verify_backup_until(control, backup_id, Instant::now() + VERIFY_BUDGET)
}

/// Verification consumes the caller's original monotonic budget. Retries and
/// nested artifact reads never reset it.
pub fn verify_backup_until(
    control: &SqliteControlStore,
    backup_id: &ControlId,
    deadline: Instant,
) -> PortResult<VerifiedBackup> {
    control.with_runtime_deadline(deadline, || {
        check_deadline(deadline)?;
        let record = backup_record(control, backup_id)?;
        if record.state != BackupState::Complete {
            return Err(incompatible("backup is not complete"));
        }
        verify_record(control, &record, deadline)
    })
}

fn backup_record(control: &SqliteControlStore, backup_id: &ControlId) -> PortResult<StoredBackup> {
    control.validate_live_root()?;
    control
        .backup_records()?
        .into_iter()
        .find(|backup| backup.backup_id == *backup_id)
        .ok_or_else(|| PortError::NotFound("backup is not registered".into()))
}

/// Losing control_seq may be retried only against the same accounted backup,
/// or the exact idempotent result of this transition. In particular, a changed
/// digest, size, locator or coverage never becomes a retryable sequence race.
pub(crate) fn backup_retry_is_current(
    control: &SqliteControlStore,
    before: &StoredBackup,
    terminal: BackupState,
) -> PortResult<bool> {
    let current = backup_record(control, &before.backup_id)?;
    let mut settled = before.clone();
    settled.state = terminal;
    if terminal == BackupState::PurgedByPolicy {
        settled.source_ids.clear();
    }
    Ok(current == *before || current == settled)
}

fn verify_record(
    control: &SqliteControlStore,
    record: &StoredBackup,
    deadline: Instant,
) -> PortResult<VerifiedBackup> {
    check_deadline(deadline)?;
    let installation = control.status()?.policy.installation_id;
    let metadata = metadata_from(record, &installation)?;
    let artifact = verify_artifact(control, &metadata, deadline)?;
    let conn = open_read_only(&artifact.path, deadline)?;
    let snapshot = conn.unchecked_transaction().map_err(sql)?;
    let identity = validate_compatible_identity(&snapshot, &installation)?;
    if identity.schema != metadata.schema_version
        || identity.incarnation != metadata.catalog_incarnation
        || identity.generation != metadata.catalog_generation
    {
        return Err(incompatible("backup identity does not match its manifest"));
    }
    let integrity: String = snapshot
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sql)?;
    if integrity != "ok" {
        return Err(incompatible("backup integrity does not match its manifest"));
    }
    let coverage = read_coverage(&snapshot, deadline)?;
    let sources: Vec<&ControlId> = coverage.iter().map(|source| &source.source_id).collect();
    if sources.iter().copied().ne(metadata.source_ids.iter()) {
        return Err(incompatible("backup coverage does not match its manifest"));
    }
    drop(snapshot);
    drop(conn);
    artifact.validate(control)?;
    check_deadline(deadline)?;
    Ok(VerifiedBackup { metadata, coverage })
}

/// Prepare an owned side image for the CURRENT program. A compatible old
/// backup is migrated only in this private copy; its immutable bytes/manifest
/// keep their original schema. This mode is not program rollback.
pub fn prepare_restore(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    backup_id: &ControlId,
    new_incarnation: &ControlId,
    side_path: &Path,
    deadline: Instant,
) -> PortResult<RestoreOutcome> {
    prepare_restore_mode(
        control,
        installation,
        owner,
        backup_id,
        new_incarnation,
        side_path,
        deadline,
        RestoreMode::Current,
    )
}

/// Prepare an exact-schema rollback image. Schema21 retains historical receipt
/// lineage; schema20 has no such schema and is deliberately refused here.
pub fn prepare_restore_exact(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    backup_id: &ControlId,
    new_incarnation: &ControlId,
    side_path: &Path,
    deadline: Instant,
) -> PortResult<RestoreOutcome> {
    prepare_restore_mode(
        control,
        installation,
        owner,
        backup_id,
        new_incarnation,
        side_path,
        deadline,
        RestoreMode::Exact,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum RestoreMode {
    Current,
    Exact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreIntent {
    schema: String,
    installation: String,
    control_root: String,
    owner: String,
    backup_id: String,
    backup_digest: String,
    original_incarnation: String,
    generation: u64,
    original_schema: u32,
    restore_schema: u32,
    recovery: String,
    side_name: String,
    mode: RestoreMode,
    source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestorePreimage {
    live_name: String,
    backup_id: String,
    incarnation: String,
    generation: u64,
    schema: u32,
    digest: String,
    size_bytes: u64,
    file_identity: String,
    source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", deny_unknown_fields)]
enum RestoreEvent {
    Intent { intent: RestoreIntent },
    Owned { file_identity: String },
    Prepared { digest: String, size_bytes: u64 },
    Publishing { preimage: RestorePreimage },
    Published,
    Applied,
}

struct RestoreJournal {
    path: PathBuf,
    intent: RestoreIntent,
    file_identity: Option<String>,
    prepared: Option<(String, u64)>,
    preimage: Option<RestorePreimage>,
    published: bool,
    applied: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep both public restore modes on the existing explicit capability/deadline contract"
)]
fn prepare_restore_mode(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    backup_id: &ControlId,
    new_incarnation: &ControlId,
    side_path: &Path,
    deadline: Instant,
    mode: RestoreMode,
) -> PortResult<RestoreOutcome> {
    control.with_runtime_deadline(deadline, || {
        installation.validate(control)?;
        require_fence(control, owner)?;
        check_deadline(deadline)?;
        let verified = match verify_backup_until(control, backup_id, deadline) {
            Ok(value) => value,
            Err(PortError::InvalidRequest(_) | PortError::SchemaIncompatible(_)) => {
                return Ok(RestoreOutcome::Attention(BackupAttention::AccountingMismatch));
            }
            Err(error) => return Err(error),
        };
        if withdrawn(&control.read_policy(RequestIntersection::Selected)?, verified.coverage()) {
            return Ok(RestoreOutcome::Attention(BackupAttention::PolicyMismatch));
        }
        let metadata = verified.metadata();
        if new_incarnation == &metadata.catalog_incarnation
            || (mode == RestoreMode::Exact && metadata.schema_version < 21) {
            return Err(incompatible("exact rollback requires a retained-receipt schema and a new incarnation"));
        }
        prepare_side_path(control, side_path)?;
        let owned_side_path=control.private_root().join(side_path.file_name().ok_or_else(storage)?);
        let side_path=owned_side_path.as_path();
        let side_name = side_path.file_name().and_then(|v| v.to_str())
            .ok_or_else(|| invalid("restore side name is invalid"))?.to_owned();
        let expected = RestoreIntent {
            schema: "asg.catalog-restore/v1".into(),
            installation: installation.installation_id().as_str().into(),
            control_root: physical_root_id(control.private_root())?,
            owner: owner.as_str().into(), backup_id: backup_id.as_str().into(),
            backup_digest: metadata.digest.clone(),
            original_incarnation: metadata.catalog_incarnation.as_str().into(),
            generation: metadata.catalog_generation, original_schema: metadata.schema_version,
            restore_schema: if mode == RestoreMode::Current { SCHEMA_VERSION as u32 } else { metadata.schema_version },
            recovery: new_incarnation.as_str().into(), side_name, mode,
            source_ids: metadata.source_ids.iter().map(|id| id.as_str().into()).collect(),
        };
        let journal_path = restore_journal_path(control, &expected);
        let mut journal = if journal_path.try_exists().map_err(|_| storage())? {
            let journal = read_restore_journal(control, &journal_path, deadline)?;
            if journal.intent != expected { return Err(incompatible("restore intent conflicts with its ownership receipt")); }
            journal
        } else {
            if fs::symlink_metadata(side_path).is_ok() {
                return Err(invalid("restore side path is not owned by this operation"));
            }
            create_restore_journal(control, &journal_path, &expected, deadline)?;
            read_restore_journal(control, &journal_path, deadline)?
        };
        if journal.prepared.is_none() {
            let file_identity = match &journal.file_identity {
                Some(identity) => {
                    let pin = open_catalog_pin(control, side_path)?;
                    if physical_file_id(&pin)? != *identity { return Err(incompatible("restore side file was replaced")); }
                    identity.clone()
                }
                None => {
                    if fs::symlink_metadata(side_path).is_ok() { return Err(invalid("restore side creation is ambiguous")); }
                    control.create_private_file_under(side_path)?;
                    let pin = open_catalog_pin(control, side_path)?;
                    let identity = physical_file_id(&pin)?;
                    append_restore_event(control, &journal_path, &RestoreEvent::Owned { file_identity: identity.clone() }, deadline)?;
                    identity
                }
            };
            let pinned = verify_artifact(control, metadata, deadline)?;
            let source = open_read_only(&pinned.path, deadline)?;
            let side_pin = open_catalog_pin(control, side_path)?;
            if physical_file_id(&side_pin)? != file_identity { return Err(incompatible("restore side changed before copying")); }
            let mut destination = open_read_write(side_path, deadline)?;
            write_logical_copy(&source, &mut destination, deadline)?;
            set_sql_deadline(&destination, deadline)?;
            let tx = destination.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
            let original = validate_compatible_identity(&tx, installation.installation_id())?;
            if original.schema != metadata.schema_version || original.incarnation != metadata.catalog_incarnation
                || original.generation != metadata.catalog_generation {
                return Err(incompatible("restore copy does not match its immutable backup"));
            }
            if mode == RestoreMode::Current { SqliteStore::migrate_managed_in_transaction(&tx)?; }
            crate::managed::retain_receipts_after_recovery(
                &tx, metadata.catalog_incarnation.as_str(), new_incarnation.as_str(), owner.as_str(),
            )?;
            // Restore keeps exact historical receipt bytes but invalidates
            // currentness/discovery until a newly authorized observation.
            tx.execute("UPDATE source_heads SET update_state='unknown',observed_cycle_seq=NULL WHERE update_state='current'",[]).map_err(sql)?;
            tx.execute("DELETE FROM discovery_sources",[]).map_err(sql)?;
            tx.execute("DELETE FROM discovery_receipts",[]).map_err(sql)?;
            tx.execute("UPDATE catalog_meta SET catalog_incarnation=?1 WHERE singleton=1 AND catalog_incarnation=?2", [new_incarnation.as_str(), metadata.catalog_incarnation.as_str()]).map_err(sql)?;
            verify_quick_integrity(&tx)?;
            verify_derived_integrity(&tx, deadline)?;
            if read_coverage(&tx, deadline)? != verified.coverage { return Err(incompatible("restored catalog coverage changed")); }
            let prepared = validate_compatible_identity(&tx, installation.installation_id())?;
            if prepared.schema != expected.restore_schema || prepared.incarnation != *new_incarnation || prepared.generation != expected.generation {
                return Err(incompatible("restored catalog identity changed"));
            }
            installation.validate(control)?;
            if withdrawn(&require_fence(control, owner)?, verified.coverage()) {
                return Ok(RestoreOutcome::Attention(BackupAttention::PolicyMismatch));
            }
            control.validate_private_read(side_path, &side_pin)?;
            check_deadline(deadline)?;
            tx.commit().map_err(sql)?;
            destination.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get::<_, String>(0)).map_err(sql)?;
            drop(destination);
            drop(side_pin);
            drop(source);
            pinned.validate(control)?;
            sync_catalog_file(control, side_path)?;
            let (digest, size_bytes) = hash_file(control, side_path, deadline)?;
            append_restore_event(control, &journal_path, &RestoreEvent::Prepared { digest, size_bytes }, deadline)?;
            journal = read_restore_journal(control, &journal_path, deadline)?;
        }
        let (digest, size_bytes) = journal.prepared.clone().ok_or_else(storage)?;
        let prepared = RestorePreparation {
            side_path: side_path.to_path_buf(), installation: installation.installation_id().clone(),
            incarnation: new_incarnation.clone(), generation: expected.generation,
            schema: expected.restore_schema, coverage: verified.coverage().to_vec(), backup_id: backup_id.clone(),
            journal_path, digest, size_bytes,
        };
        let candidate = if let Some(preimage) = &journal.preimage {
            let live = control.private_root().join(&preimage.live_name);
            if restored_image_matches(control, &live, &prepared, deadline)? { live } else { side_path.to_path_buf() }
        } else { side_path.to_path_buf() };
        verify_restored_image(control, &candidate, &prepared, deadline)?;
        installation.validate(control)?;
        if withdrawn(&require_fence(control, owner)?, verified.coverage()) {
            return Ok(RestoreOutcome::Attention(BackupAttention::PolicyMismatch));
        }
        check_deadline(deadline)?;
        Ok(RestoreOutcome::Prepared(Box::new(prepared)))
    })
}

/// Replace this drained live image and confirm control recovery only after
/// exact-schema/hash/coverage readback. Interrupted publication is reconciled
/// from the typed journal and registered displaced backup; no old image is lost.
pub fn apply_restore(
    catalog: &mut MaintenanceCatalog,
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    preparation: &RestorePreparation,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<ControlId> {
    let result = control.with_runtime_deadline(deadline, || {
        catalog.validate_authority(control, installation, owner)?;
        if now_ms < 0 || preparation.installation != catalog.installation {
            return Err(invalid("invalid restore publication authority"));
        }
        let mut journal = read_restore_journal(control, &preparation.journal_path, deadline)?;
        validate_preparation_journal(preparation, owner, &journal)?;
        if withdrawn(&require_fence(control, owner)?, &preparation.coverage) {
            return Err(invalid("restore coverage has been withdrawn"));
        }
        if journal.preimage.is_none() {
            if preparation.side_path == catalog.path {
                return Err(invalid("restore side and live names collide"));
            }
            verify_restored_image(control, &preparation.side_path, preparation, deadline)?;
            let conn = catalog.connection()?;
            set_sql_deadline(conn, deadline)?;
            verify_quick_integrity(conn)?;
            verify_derived_integrity(conn, deadline)?;
            let identity = validate_compatible_identity(conn, &catalog.installation)?;
            if identity != catalog.identity {
                return Err(incompatible("live catalog identity changed before restore"));
            }
            let coverage = read_coverage(conn, deadline)?;
            let checkpoint_busy: i64 = conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                .map_err(sql)?;
            if checkpoint_busy != 0 {
                return Err(busy("catalog checkpoint could not drain"));
            }
            conn.query_row("PRAGMA journal_mode=DELETE", [], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sql)?;
            catalog.conn.take();
            let mut pin = catalog.pin.take().ok_or_else(storage)?;
            sync_catalog_file(control, &catalog.path)?;
            let file_identity = physical_file_id(&pin)?;
            let (digest, size_bytes) = hash_opened(control, &catalog.path, &mut pin, deadline)?;
            let backup_id = displaced_backup_id(&journal.intent);
            let preimage = RestorePreimage {
                live_name: catalog
                    .path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .ok_or_else(storage)?
                    .into(),
                backup_id: backup_id.as_str().into(),
                incarnation: identity.incarnation.as_str().into(),
                generation: identity.generation,
                schema: identity.schema,
                digest,
                size_bytes,
                file_identity,
                source_ids: coverage
                    .iter()
                    .map(|s| s.source_id.as_str().into())
                    .collect(),
            };
            register_restore_preimage(control, installation, owner, &preimage, now_ms, deadline)?;
            append_restore_event(
                control,
                &preparation.journal_path,
                &RestoreEvent::Publishing { preimage },
                deadline,
            )?;
            drop(pin); // Windows replacement requires all old SQLite/file handles closed.
            journal = read_restore_journal(control, &preparation.journal_path, deadline)?;
        }
        let preimage = journal.preimage.as_ref().ok_or_else(storage)?.clone();
        if preimage.live_name
            != catalog
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(storage)?
        {
            return Err(incompatible("restore journal targets another catalog"));
        }
        let displaced = artifact_path(
            control,
            &catalog_backup_locator(&ControlId::parse(&preimage.backup_id)?),
        )?;
        catalog.conn.take();
        catalog.pin.take();
        if !restored_image_matches(control, &catalog.path, preparation, deadline)? {
            verify_restore_preimage(control, &catalog.path, &preimage, deadline)?;
            if fs::symlink_metadata(&displaced).is_ok() {
                return Err(invalid("restore displaced path is already occupied"));
            }
            verify_restored_image(control, &preparation.side_path, preparation, deadline)?;
            installation.validate(control)?;
            catalog._handles.validate_current(control.private_root())?;
            if withdrawn(&require_fence(control, owner)?, preparation.coverage()) {
                return Err(invalid("restore policy changed before publication"));
            }
            match exchange_restore_images(&catalog.path, &preparation.side_path, &displaced) {
                Ok(()) => {}
                Err(error) => {
                    // The exchange may have succeeded before archiving the old
                    // side. Keep both observed versions and reconcile on retry.
                    if !restored_image_matches(control, &catalog.path, preparation, deadline)? {
                        let _ = reopen_maintenance_catalog(catalog, control, deadline);
                        return Err(publication_error(error));
                    }
                }
            }
        }
        verify_restored_image(control, &catalog.path, preparation, deadline)?;
        if !displaced.try_exists().map_err(|_| storage())? {
            verify_restore_preimage(control, &preparation.side_path, &preimage, deadline)?;
            publish_no_replace(&preparation.side_path, &displaced).map_err(publication_error)?;
        }
        verify_restore_preimage(control, &displaced, &preimage, deadline)?;
        finalize_restore_preimage(control, installation, owner, &preimage, now_ms, deadline)?;
        if !journal.published {
            append_restore_event(
                control,
                &preparation.journal_path,
                &RestoreEvent::Published,
                deadline,
            )?;
        }
        reopen_maintenance_catalog(catalog, control, deadline)?;
        verify_restored_identity(catalog.connection()?, preparation)?;
        catalog.validate_authority(control, installation, owner)?;
        let changed = {
            let guard = acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let bound = control.bind_control_root(&guard)?;
            control.apply_catalog_restore(
                control.status()?.policy.control_seq,
                owner,
                &bound,
                installation,
                preparation.backup_id(),
                preparation.incarnation(),
                preparation.coverage(),
                now_ms,
            )?
        };
        if !journal.applied {
            append_restore_event(
                control,
                &preparation.journal_path,
                &RestoreEvent::Applied,
                deadline,
            )?;
        }
        check_deadline(deadline)?;
        Ok(changed.value)
    });
    if result.is_err()
        && catalog.conn.is_none()
        && Instant::now() < deadline
        && fs::symlink_metadata(&catalog.path).is_ok()
    {
        let _ = reopen_maintenance_catalog(catalog, control, deadline);
    }
    result
}

/// Content-free proof of one exact restore receipt. This is private inventory,
/// not permission to read/delete source history or to classify a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReceiptArtifact {
    relative_locator: String,
    size_bytes: u64,
    blake3_digest: String,
    complete: bool,
}
impl RestoreReceiptArtifact {
    pub fn relative_locator(&self) -> &str {
        &self.relative_locator
    }
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    pub fn blake3_digest(&self) -> &str {
        &self.blake3_digest
    }
    pub fn complete(&self) -> bool {
        self.complete
    }
}

/// An exact owned, unpublished content image. Do not route it through a
/// settings-only inventory class: its source coverage requires governed purge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreStagedImage {
    relative_locator: String,
    schema_version: u32,
    digest: String,
    size_bytes: u64,
    source_ids: Vec<ControlId>,
}
impl RestoreStagedImage {
    pub fn relative_locator(&self) -> &str {
        &self.relative_locator
    }
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn blake3_digest(&self) -> &str {
        &self.digest
    }
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    pub fn source_ids(&self) -> &[ControlId] {
        &self.source_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreInventory {
    receipts: Vec<RestoreReceiptArtifact>,
    staged_images: Vec<RestoreStagedImage>,
    incomplete: bool,
}
impl RestoreInventory {
    pub fn receipts(&self) -> &[RestoreReceiptArtifact] {
        &self.receipts
    }
    pub fn staged_images(&self) -> &[RestoreStagedImage] {
        &self.staged_images
    }
    /// Partial/unconsumed stages block closure, even when their exact file is
    /// owned. Unknown files are never included as classified artifacts.
    pub fn incomplete(&self) -> bool {
        self.incomplete
    }
}

/// Verify finite restore journals and all referenced owned versions. Only
/// terminal receipts are safe for the CLI's CatalogRestoreReceipt inventory
/// class. Partial content stages remain explicitly incomplete for purge.
pub fn inspect_restore_inventory(
    control: &SqliteControlStore,
    catalog: &Path,
    deadline: Instant,
) -> PortResult<RestoreInventory> {
    control.with_runtime_deadline(deadline, || {
        check_deadline(deadline)?;
        validate_catalog_path(catalog)?;
        if catalog.parent() != Some(control.private_root()) {
            return Err(invalid("restore inventory is in another root"));
        }
        let root = RootIdentity::read(control.private_root())?;
        if !control.matches_root(root) {
            return Err(invalid("restore inventory root changed"));
        }
        let before = control.status()?;
        let mut result = RestoreInventory {
            receipts: Vec::new(),
            staged_images: Vec::new(),
            incomplete: false,
        };
        let mut paths = Vec::new();
        let mut visited = 0_usize;
        for entry in fs::read_dir(control.private_root()).map_err(|_| storage())? {
            check_deadline(deadline)?;
            visited += 1;
            if visited > 4096 {
                return Err(incompatible("restore inventory exceeds its file bound"));
            }
            let entry = entry.map_err(|_| storage())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name
                .strip_prefix("restore-")
                .and_then(|s| s.strip_suffix(".jsonl"))
                .is_some_and(|id| {
                    id.len() == 32
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                paths.push(entry.path());
            }
        }
        paths.sort();
        for path in paths {
            check_deadline(deadline)?;
            let journal = read_restore_journal(control, &path, deadline)?;
            let side = control.private_root().join(&journal.intent.side_name);
            let verified = match verify_backup_until(
                control,
                &ControlId::parse(&journal.intent.backup_id)?,
                deadline,
            ) {
                Ok(value) => Some(value),
                Err(
                    PortError::InvalidRequest(_)
                    | PortError::NotFound(_)
                    | PortError::SchemaIncompatible(_),
                ) => {
                    let record =
                        backup_record(control, &ControlId::parse(&journal.intent.backup_id)?)?;
                    if record.state != BackupState::PurgedByPolicy
                        || record.digest.as_deref() != Some(journal.intent.backup_digest.as_str())
                        || record.catalog_incarnation.as_str()
                            != journal.intent.original_incarnation
                        || record.catalog_generation != journal.intent.generation
                        || record.schema_version != journal.intent.original_schema
                    {
                        return Err(incompatible(
                            "restore inventory backup is not verified or purged",
                        ));
                    }
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(verified) = &verified
                && (verified.metadata.digest != journal.intent.backup_digest
                    || verified.metadata.schema_version != journal.intent.original_schema
                    || verified.metadata.catalog_generation != journal.intent.generation
                    || verified.metadata.catalog_incarnation.as_str()
                        != journal.intent.original_incarnation
                    || verified
                        .metadata
                        .source_ids
                        .iter()
                        .map(ControlId::as_str)
                        .ne(journal.intent.source_ids.iter().map(String::as_str)))
            {
                return Err(incompatible("restore inventory backup lineage changed"));
            }
            let mut terminal = journal.applied;
            if let Some(preimage) = &journal.preimage {
                if preimage.live_name
                    != catalog
                        .file_name()
                        .and_then(|v| v.to_str())
                        .ok_or_else(storage)?
                {
                    return Err(incompatible(
                        "restore inventory references another live catalog",
                    ));
                }
                let displaced_id = ControlId::parse(&preimage.backup_id)?;
                let record = backup_record(control, &displaced_id)?;
                if record.catalog_incarnation.as_str() != preimage.incarnation
                    || record.schema_version != preimage.schema
                    || record.catalog_generation != preimage.generation
                    || (record.state != BackupState::PurgedByPolicy
                        && record
                            .source_ids
                            .iter()
                            .map(ControlId::as_str)
                            .ne(preimage.source_ids.iter().map(String::as_str)))
                {
                    return Err(incompatible("restore displaced inventory lineage changed"));
                }
                let displaced = artifact_path(control, &record.relative_locator)?;
                if record.state == BackupState::Complete {
                    verify_restore_preimage(control, &displaced, preimage, deadline)?;
                    if record.digest.as_deref() != Some(preimage.digest.as_str())
                        || record.size_bytes != preimage.size_bytes
                    {
                        return Err(incompatible("restore displaced inventory hash changed"));
                    }
                } else if record.state != BackupState::PurgedByPolicy {
                    terminal = false;
                }
            } else {
                terminal = false;
            }
            match fs::symlink_metadata(&side) {
                Ok(_) => {
                    terminal = false;
                    let pin = control.open_private_read(&side)?;
                    let physical_id = physical_file_id(&pin)?;
                    drop(pin);
                    let is_preimage = journal
                        .preimage
                        .as_ref()
                        .is_some_and(|p| p.file_identity == physical_id);
                    if Some(physical_id) != journal.file_identity && !is_preimage {
                        return Err(incompatible("restore inventory side identity changed"));
                    }
                    let (digest, size_bytes) = hash_file(control, &side, deadline)?;
                    if let Some((expected, size)) = &journal.prepared {
                        let original_side = if let Some(preimage) = &journal.preimage {
                            digest == preimage.digest && size_bytes == preimage.size_bytes
                        } else {
                            false
                        };
                        if !original_side && (&digest != expected || size_bytes != *size) {
                            return Err(incompatible("restore stage hash changed"));
                        }
                    }
                    let (schema_version, source_ids) = if is_preimage {
                        let preimage = journal.preimage.as_ref().ok_or_else(storage)?;
                        verify_restore_preimage(control, &side, preimage, deadline)?;
                        (preimage.schema, &preimage.source_ids)
                    } else {
                        (journal.intent.restore_schema, &journal.intent.source_ids)
                    };
                    result.staged_images.push(RestoreStagedImage {
                        relative_locator: journal.intent.side_name.clone(),
                        schema_version,
                        digest,
                        size_bytes,
                        source_ids: source_ids
                            .iter()
                            .map(|id| ControlId::parse(id))
                            .collect::<PortResult<_>>()?,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(storage()),
            }
            if verified.is_none() && !terminal {
                result.incomplete = true;
            }
            let (digest, size_bytes) = hash_file(control, &path, deadline)?;
            result.receipts.push(RestoreReceiptArtifact {
                relative_locator: path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .ok_or_else(storage)?
                    .into(),
                size_bytes,
                blake3_digest: digest,
                complete: terminal,
            });
            result.incomplete |= !terminal;
        }
        let after = control.status()?;
        if !control.matches_root(root) || before.policy != after.policy {
            return Err(busy("restore inventory policy changed"));
        }
        check_deadline(deadline)?;
        Ok(result)
    })
}

/// Upper bound for one restore ownership journal.
///
/// The intent event embeds the full source id list of the catalog it is
/// restoring. It is the only surviving copy once the backup record has been
/// purged by policy, so the bound must scale with the catalog rather than with
/// a fixed event count: 256 KiB held roughly 6k ids and made restore fail
/// closed forever on larger installations. The journal is a private local
/// file written only during an explicit restore.
const MAX_RESTORE_JOURNAL: u64 = 64 * 1024 * 1024;

fn restore_journal_path(control: &SqliteControlStore, intent: &RestoreIntent) -> PathBuf {
    let key = blake3::hash(
        format!(
            "{}:{}:{}",
            intent.backup_id, intent.recovery, intent.side_name
        )
        .as_bytes(),
    )
    .to_hex();
    control
        .private_root()
        .join(format!("restore-{}.jsonl", &key[..32]))
}
fn displaced_backup_id(intent: &RestoreIntent) -> ControlId {
    let key = blake3::hash(
        format!(
            "{}:{}:{}:displaced",
            intent.backup_id, intent.recovery, intent.side_name
        )
        .as_bytes(),
    )
    .to_hex();
    // Fixed prefix plus32 hex is below the ControlId bound.
    ControlId::parse(&format!("restore_prior_{}", &key[..32]))
        .expect("generated control identifier")
}

fn create_restore_journal(
    control: &SqliteControlStore,
    path: &Path,
    intent: &RestoreIntent,
    deadline: Instant,
) -> PortResult<()> {
    check_deadline(deadline)?;
    control.create_private_file_under(path)?;
    append_restore_event(
        control,
        path,
        &RestoreEvent::Intent {
            intent: intent.clone(),
        },
        deadline,
    )
}
fn append_restore_event(
    control: &SqliteControlStore,
    path: &Path,
    event: &RestoreEvent,
    deadline: Instant,
) -> PortResult<()> {
    use std::io::{Seek, SeekFrom, Write};
    check_deadline(deadline)?;
    control.validate_catalog_file(path)?;
    let pin = open_catalog_pin(control, path)?;
    let before = pin.metadata().map_err(|_| storage())?.len();
    let mut bytes = serde_json::to_vec(event).map_err(|_| storage())?;
    bytes.push(b'\n');
    if before
        .checked_add(bytes.len() as u64)
        .is_none_or(|size| size > MAX_RESTORE_JOURNAL)
    {
        return Err(incompatible("restore ownership journal is too large"));
    }
    #[cfg(unix)]
    let mut file = {
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        ))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Per-architecture constants shared with managed_locks: the
            // x86_64 Linux value is O_LARGEFILE on aarch64.
            let flags = crate::managed_locks::platform::NOFOLLOW
                | crate::managed_locks::platform::NONBLOCK
                | crate::managed_locks::platform::CLOEXEC;
            fs::OpenOptions::new()
                .append(true)
                .custom_flags(flags)
                .open(path)
                .map_err(|_| storage())?
        }
        #[cfg(not(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        )))]
        {
            return Err(storage());
        }
    };
    #[cfg(windows)]
    let mut file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
            READ_CONTROL,
        };
        fs::OpenOptions::new()
            .append(true)
            .access_mode(0x40000000 | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| storage())?
    };
    #[cfg(not(any(unix, windows)))]
    return Err(storage());
    control.validate_private_read(path, &file)?;
    if physical_file_id(&file)? != physical_file_id(&pin)? {
        return Err(incompatible(
            "restore ownership journal changed before append",
        ));
    }
    if file.metadata().map_err(|_| storage())?.len() != before {
        return Err(incompatible("restore journal changed during append"));
    }
    // Explicit GENERIC_WRITE on Windows overrides append-only access. Seek
    // the verified owned file to its end while the installation lock is held.
    file.seek(SeekFrom::End(0)).map_err(|_| storage())?;
    file.write_all(&bytes).map_err(|_| storage())?;
    file.sync_all().map_err(|_| storage())?;
    control.validate_private_read(path, &file)?;
    check_deadline(deadline)
}
fn read_restore_journal(
    control: &SqliteControlStore,
    path: &Path,
    deadline: Instant,
) -> PortResult<RestoreJournal> {
    check_deadline(deadline)?;
    let mut file = control.open_private_read(path)?;
    let before = file.metadata().map_err(|_| storage())?;
    if before.len() == 0 || before.len() > MAX_RESTORE_JOURNAL {
        return Err(incompatible("restore ownership journal is invalid"));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        check_deadline(deadline)?;
        let size = file.read(&mut buffer).map_err(|_| storage())?;
        if size == 0 {
            break;
        }
        if (bytes.len() as u64).saturating_add(size as u64) > MAX_RESTORE_JOURNAL {
            return Err(incompatible("restore ownership journal exceeds its bound"));
        }
        bytes.extend_from_slice(&buffer[..size]);
    }
    control.validate_private_read(path, &file)?;
    if bytes.last() != Some(&b'\n')
        || !same_file_observation(&before, &file.metadata().map_err(|_| storage())?)
    {
        return Err(incompatible("restore ownership journal is torn or changed"));
    }
    let mut result: Option<RestoreJournal> = None;
    for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
        check_deadline(deadline)?;
        let event: RestoreEvent = serde_json::from_slice(line)
            .map_err(|_| incompatible("restore ownership journal is malformed"))?;
        match (&mut result, event) {
            (None, RestoreEvent::Intent { intent }) => {
                validate_restore_intent(&intent)?;
                if intent.installation != control.status()?.policy.installation_id.as_str()
                    || intent.control_root != physical_root_id(control.private_root())?
                    || restore_journal_path(control, &intent) != path
                {
                    return Err(incompatible(
                        "restore ownership journal is not bound to this installation",
                    ));
                }
                result = Some(RestoreJournal {
                    path: path.to_path_buf(),
                    intent,
                    file_identity: None,
                    prepared: None,
                    preimage: None,
                    published: false,
                    applied: false,
                });
            }
            (Some(journal), RestoreEvent::Owned { file_identity })
                if journal.file_identity.is_none() && journal.prepared.is_none() =>
            {
                if !hex_digest(&file_identity) {
                    return Err(incompatible("restore file identity is invalid"));
                }
                journal.file_identity = Some(file_identity);
            }
            (Some(journal), RestoreEvent::Prepared { digest, size_bytes })
                if journal.file_identity.is_some() && journal.prepared.is_none() =>
            {
                if !hex_digest(&digest) || size_bytes == 0 {
                    return Err(incompatible("prepared restore digest is invalid"));
                }
                journal.prepared = Some((digest, size_bytes));
            }
            (Some(journal), RestoreEvent::Publishing { preimage })
                if journal.prepared.is_some() && journal.preimage.is_none() =>
            {
                validate_preimage(&preimage)?;
                if preimage.backup_id != displaced_backup_id(&journal.intent).as_str() {
                    return Err(incompatible("restore displaced image is not owned"));
                }
                journal.preimage = Some(preimage);
            }
            (Some(journal), RestoreEvent::Published)
                if journal.preimage.is_some() && !journal.published =>
            {
                journal.published = true
            }
            (Some(journal), RestoreEvent::Applied) if journal.published && !journal.applied => {
                journal.applied = true
            }
            _ => {
                return Err(incompatible(
                    "restore ownership journal has ambiguous steps",
                ));
            }
        }
    }
    check_deadline(deadline)?;
    result.ok_or_else(|| incompatible("restore ownership journal is empty"))
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_restore_intent(intent: &RestoreIntent) -> PortResult<()> {
    if intent.schema != "asg.catalog-restore/v1"
        || !hex_digest(&intent.control_root)
        || !hex_digest(&intent.backup_digest)
        || !matches!(intent.original_schema, 20..=22)
        || !matches!(intent.restore_schema, 21..=22)
        || (intent.mode == RestoreMode::Current && intent.restore_schema != SCHEMA_VERSION as u32)
        || (intent.mode == RestoreMode::Exact && intent.restore_schema != intent.original_schema)
        || intent.original_incarnation == intent.recovery
        || !intent.source_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(incompatible("restore intent metadata is invalid"));
    }
    for id in [
        &intent.installation,
        &intent.owner,
        &intent.backup_id,
        &intent.original_incarnation,
        &intent.recovery,
    ] {
        ControlId::parse(id).map_err(|_| incompatible("restore intent identity is invalid"))?;
    }
    for id in &intent.source_ids {
        ControlId::parse(id).map_err(|_| incompatible("restore source identity is invalid"))?;
    }
    let side = Path::new(&intent.side_name);
    if side.components().count() != 1
        || !matches!(side.components().next(), Some(Component::Normal(_)))
        || side.extension().and_then(|v| v.to_str()) != Some("db")
        || matches!(intent.side_name.as_str(), "catalog.db" | "control.db")
    {
        return Err(invalid("restore intent path is invalid"));
    }
    validate_catalog_path(side)
}
fn validate_preimage(preimage: &RestorePreimage) -> PortResult<()> {
    ControlId::parse(&preimage.backup_id)?;
    ControlId::parse(&preimage.incarnation)?;
    if !hex_digest(&preimage.digest)
        || !hex_digest(&preimage.file_identity)
        || preimage.size_bytes == 0
        || !matches!(preimage.schema, 20..=22)
        || !preimage.source_ids.windows(2).all(|p| p[0] < p[1])
    {
        return Err(incompatible("restore preimage is invalid"));
    }
    for id in &preimage.source_ids {
        ControlId::parse(id)?;
    }
    let name = Path::new(&preimage.live_name);
    if name.components().count() != 1
        || !matches!(name.components().next(), Some(Component::Normal(_)))
    {
        return Err(invalid("restore live path is invalid"));
    }
    validate_catalog_path(name)
}
fn validate_preparation_journal(
    preparation: &RestorePreparation,
    owner: &ControlId,
    journal: &RestoreJournal,
) -> PortResult<()> {
    let intent = &journal.intent;
    if intent.owner != owner.as_str()
        || intent.installation != preparation.installation.as_str()
        || intent.backup_id != preparation.backup_id.as_str()
        || intent.recovery != preparation.incarnation.as_str()
        || intent.generation != preparation.generation
        || intent.restore_schema != preparation.schema
        || journal.path != preparation.journal_path
        || journal.prepared.as_ref() != Some(&(preparation.digest.clone(), preparation.size_bytes))
        || intent.side_name
            != preparation
                .side_path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(storage)?
        || intent
            .source_ids
            .iter()
            .map(String::as_str)
            .ne(preparation.coverage.iter().map(|s| s.source_id.as_str()))
    {
        return Err(incompatible(
            "restore preparation is not the owned journal image",
        ));
    }
    Ok(())
}
fn verify_restored_identity(conn: &Connection, preparation: &RestorePreparation) -> PortResult<()> {
    let identity = validate_compatible_identity(conn, &preparation.installation)?;
    if identity.incarnation != preparation.incarnation
        || identity.generation != preparation.generation
        || identity.schema != preparation.schema
    {
        return Err(incompatible(
            "restored image does not match requested program schema/identity",
        ));
    }
    Ok(())
}
fn verify_restored_image(
    control: &SqliteControlStore,
    path: &Path,
    preparation: &RestorePreparation,
    deadline: Instant,
) -> PortResult<()> {
    let mut pin = control.open_private_read(path)?;
    require_standalone_image(path)?;
    if hash_opened(control, path, &mut pin, deadline)?
        != (preparation.digest.clone(), preparation.size_bytes)
    {
        return Err(incompatible("restored image hash changed"));
    }
    let conn = open_read_only(path, deadline)?;
    verify_restored_identity(&conn, preparation)?;
    verify_quick_integrity(&conn)?;
    if read_coverage(&conn, deadline)? != preparation.coverage {
        return Err(incompatible("restored image source accounting changed"));
    }
    control.validate_private_read(path, &pin)?;
    check_deadline(deadline)
}
fn restored_image_matches(
    control: &SqliteControlStore,
    path: &Path,
    preparation: &RestorePreparation,
    deadline: Instant,
) -> PortResult<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(storage()),
        Ok(_) => match verify_restored_image(control, path, preparation, deadline) {
            Ok(()) => Ok(true),
            Err(PortError::SchemaIncompatible(_)) => Ok(false),
            Err(error) => Err(error),
        },
    }
}
fn verify_restore_preimage(
    control: &SqliteControlStore,
    path: &Path,
    preimage: &RestorePreimage,
    deadline: Instant,
) -> PortResult<()> {
    let mut pin = control.open_private_read(path)?;
    require_standalone_image(path)?;
    if physical_file_id(&pin)? != preimage.file_identity
        || hash_opened(control, path, &mut pin, deadline)?
            != (preimage.digest.clone(), preimage.size_bytes)
    {
        return Err(incompatible("restore displaced preimage changed"));
    }
    let conn = open_read_only(path, deadline)?;
    let identity = validate_compatible_identity(&conn, &control.status()?.policy.installation_id)?;
    if identity.incarnation.as_str() != preimage.incarnation
        || identity.generation != preimage.generation
        || identity.schema != preimage.schema
        || read_coverage(&conn, deadline)?
            .iter()
            .map(|s| s.source_id.as_str())
            .ne(preimage.source_ids.iter().map(String::as_str))
    {
        return Err(incompatible(
            "restore displaced preimage accounting changed",
        ));
    }
    control.validate_private_read(path, &pin)?;
    check_deadline(deadline)
}
fn register_restore_preimage(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    preimage: &RestorePreimage,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<()> {
    let backup_id = ControlId::parse(&preimage.backup_id)?;
    let registration = BackupRegistration {
        backup_id: backup_id.clone(),
        purpose: BackupPurpose::BetaRollback,
        relative_locator: catalog_backup_locator(&backup_id),
        catalog_incarnation: ControlId::parse(&preimage.incarnation)?,
        catalog_generation: preimage.generation,
        schema_version: preimage.schema,
        source_ids: preimage
            .source_ids
            .iter()
            .map(|id| ControlId::parse(id))
            .collect::<PortResult<_>>()?,
    };
    {
        let guard = acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
        let bound = control.bind_control_root(&guard)?;
        control.register_backup(
            control.status()?.policy.control_seq,
            owner,
            &bound,
            installation,
            &registration,
            now_ms,
        )?;
    }
    prepare_artifact_parent(
        control,
        &artifact_path(control, &registration.relative_locator)?,
    )
}
fn finalize_restore_preimage(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    owner: &ControlId,
    preimage: &RestorePreimage,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<()> {
    let backup_id = ControlId::parse(&preimage.backup_id)?;
    let artifact = artifact_path(control, &catalog_backup_locator(&backup_id))?;
    if !manifest_path(&artifact)?
        .try_exists()
        .map_err(|_| storage())?
    {
        write_sidecar(
            control,
            &backup_id,
            BackupPurpose::BetaRollback,
            &CatalogIdentity {
                installation: installation.installation_id().clone(),
                incarnation: ControlId::parse(&preimage.incarnation)?,
                generation: preimage.generation,
                schema: preimage.schema,
            },
            installation.installation_id(),
            &preimage
                .source_ids
                .iter()
                .map(|id| ControlId::parse(id))
                .collect::<PortResult<Vec<_>>>()?,
            &preimage.digest,
            preimage.size_bytes,
            now_ms,
        )?;
    }
    let metadata = BackupMetadata {
        backup_id: backup_id.clone(),
        purpose: BackupPurpose::BetaRollback,
        relative_locator: catalog_backup_locator(&backup_id),
        installation: installation.installation_id().clone(),
        catalog_incarnation: ControlId::parse(&preimage.incarnation)?,
        catalog_generation: preimage.generation,
        schema_version: preimage.schema,
        digest: preimage.digest.clone(),
        size_bytes: preimage.size_bytes,
        source_ids: preimage
            .source_ids
            .iter()
            .map(|id| ControlId::parse(id))
            .collect::<PortResult<_>>()?,
    };
    verify_artifact(control, &metadata, deadline)?;
    let guard = acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
    let bound = control.bind_control_root(&guard)?;
    control.complete_backup(
        control.status()?.policy.control_seq,
        owner,
        &bound,
        installation,
        &backup_id,
        &preimage.digest,
        preimage.size_bytes,
    )?;
    Ok(())
}
fn reopen_maintenance_catalog(
    catalog: &mut MaintenanceCatalog,
    control: &SqliteControlStore,
    deadline: Instant,
) -> PortResult<()> {
    catalog._handles.validate_current(control.private_root())?;
    let pin = open_catalog_pin(control, &catalog.path)?;
    let conn = open_read_write(&catalog.path, deadline)?;
    let identity = validate_compatible_identity(&conn, &catalog.installation)?;
    control.validate_private_read(&catalog.path, &pin)?;
    catalog.conn = Some(conn);
    catalog.pin = Some(pin);
    catalog.identity = identity;
    Ok(())
}
fn physical_file_id(file: &fs::File) -> PortResult<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let info = file.metadata().map_err(|_| storage())?;
        Ok(
            blake3::hash(format!("{}:{}", info.dev(), info.ino()).as_bytes())
                .to_hex()
                .to_string(),
        )
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the owned File has a live handle; output has the matching ABI.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(storage());
        }
        Ok(blake3::hash(
            format!(
                "{}:{}:{}",
                info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(storage())
    }
}
fn physical_root_id(path: &Path) -> PortResult<String> {
    validate_private_directory(path)?;
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };
        fs::OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| storage())?
    };
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_os = "linux")]
        let flags = 0o200000 | 0o400000 | 0o2000000;
        #[cfg(target_os = "macos")]
        let flags = 0x100000 | 0x100 | 0x01000000;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(storage());
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|_| storage())?
    };
    #[cfg(not(any(unix, windows)))]
    return Err(storage());
    if !file.metadata().map_err(|_| storage())?.is_dir() {
        return Err(storage());
    }
    physical_file_id(&file)
}

fn sync_catalog_file(control: &SqliteControlStore, path: &Path) -> PortResult<()> {
    let pin = open_catalog_pin(control, path)?;
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
            READ_CONTROL,
        };
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(0xc0000000 | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| storage())?
    };
    #[cfg(not(windows))]
    let file = pin.try_clone().map_err(|_| storage())?;
    control.validate_private_read(path, &file)?;
    if physical_file_id(&file)? != physical_file_id(&pin)? {
        return Err(incompatible("catalog changed before file synchronization"));
    }
    file.sync_all().map_err(|_| storage())
}
fn publication_error(error: std::io::Error) -> PortError {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => invalid("restore archive already exists"),
        std::io::ErrorKind::PermissionDenied => {
            busy("restore publication is blocked by an open file")
        }
        _ => storage(),
    }
}

#[cfg(windows)]
fn exchange_restore_images(live: &Path, side: &Path, displaced: &Path) -> std::io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let live = wide(live);
    let side = wide(side);
    let displaced = wide(displaced);
    // SAFETY: three terminated owned buffers survive the native call. All live
    // SQLite and non-delete-sharing pins have been closed by the caller.
    if unsafe {
        ReplaceFileW(
            live.as_ptr(),
            side.as_ptr(),
            displaced.as_ptr(),
            0,
            ptr::null(),
            ptr::null(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(windows)]
fn publish_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let source = wide(source);
    let destination = wide(destination);
    // No REPLACE_EXISTING: an independently-created archive is preserved.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(unix)]
fn exchange_restore_images(live: &Path, side: &Path, displaced: &Path) -> std::io::Result<()> {
    unix_rename(live, side, true)?;
    publish_no_replace(side, displaced)
}
#[cfg(unix)]
fn publish_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    unix_rename(source, destination, false)
}
#[cfg(unix)]
fn unix_rename(source: &Path, destination: &Path, exchange: bool) -> std::io::Result<()> {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, io::AsRawFd},
    };
    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn renameat2(
            old_dir: i32,
            old_path: *const std::ffi::c_char,
            new_dir: i32,
            new_path: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn renameatx_np(
            old_dir: i32,
            old_path: *const std::ffi::c_char,
            new_dir: i32,
            new_path: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    let source_parent = source
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let source_directory = fs::File::open(source_parent)?;
    let destination_directory = fs::File::open(destination_parent)?;
    let source_name = CString::new(
        source
            .file_name()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
            .as_bytes(),
    )?;
    let destination_name = CString::new(
        destination
            .file_name()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
            .as_bytes(),
    )?;
    #[cfg(target_os = "linux")]
    // SAFETY: pinned directory fds and terminated sibling names survive the call.
    let result = unsafe {
        renameat2(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            destination_directory.as_raw_fd(),
            destination_name.as_ptr(),
            if exchange { 2 } else { 1 },
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        renameatx_np(
            source_directory.as_raw_fd(),
            source_name.as_ptr(),
            destination_directory.as_raw_fd(),
            destination_name.as_ptr(),
            if exchange { 2 } else { 4 },
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    source_directory.sync_all()?;
    destination_directory.sync_all()
}
#[cfg(not(any(unix, windows)))]
fn exchange_restore_images(_live: &Path, _side: &Path, _displaced: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}
#[cfg(not(any(unix, windows)))]
fn publish_no_replace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Remove a withdrawn backup and record a content-free `purged_by_policy`
/// tombstone. Locked files stay explicitly pending instead of becoming
/// restorable or being reported clean.
pub fn purge_backup(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    backup_id: &ControlId,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<PurgeOutcome> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    control.with_runtime_deadline(deadline, || {
        purge_backup_in_scope(control, installation, backup_id, now_ms, deadline)
    })
}

fn purge_backup_in_scope(
    control: &SqliteControlStore,
    installation: &InstallationLockAuthority<'_>,
    backup_id: &ControlId,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<PurgeOutcome> {
    installation.validate(control)?;
    check_deadline(deadline)?;
    let record = backup_record(control, backup_id)?;
    let metadata = metadata_from(&record, installation.installation_id())?;
    match verify_cleanup_remnants(control, &metadata, deadline) {
        Ok(()) => {}
        Err(PortError::WriterBusy(_)) => return Err(busy("backup cleanup verification is busy")),
        Err(_) => return Ok(PurgeOutcome::Attention(BackupAttention::AccountingMismatch)),
    }
    if record.state == BackupState::PurgedByPolicy {
        // Old terminal receipts with leftover files still get real cleanup;
        // absence is never inferred from the control row alone.
        let removed = remove_artifact(control, &metadata, deadline)?;
        return Ok(PurgeOutcome::Purged {
            metadata,
            artifact_removed: removed,
        });
    }
    let (metadata, quarantined) = if record.state == BackupState::Quarantined {
        // A previous attempt may already have removed the sidecar or database.
        // Its durable coverage/digest remain the cleanup authority after
        // reallow. Do not require a now-impossible complete-image verification.
        (metadata, record)
    } else {
        let verified = match verify_record(control, &record, deadline) {
            Ok(verified) => verified,
            Err(PortError::InvalidRequest(_) | PortError::SchemaIncompatible(_)) => {
                return Ok(PurgeOutcome::Attention(BackupAttention::AccountingMismatch));
            }
            Err(error) => return Err(error),
        };
        let changed = retry_seq_race_before(
            deadline,
            || {
                let guard =
                    acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
                let bound = control.bind_control_root(&guard)?;
                let policy = control.read_policy(RequestIntersection::Selected)?;
                // Reallow during a sequence race must still prevent a new
                // withdrawal. A prior durable quarantine remains authoritative.
                if !withdrawn(&policy, verified.coverage()) {
                    return Ok(None);
                }
                control
                    .quarantine_backup(
                        policy.control_seq,
                        &bound,
                        installation,
                        backup_id,
                        verified.coverage(),
                        &verified.metadata.digest,
                        verified.metadata.size_bytes,
                        now_ms,
                    )
                    .map(Some)
            },
            || backup_retry_is_current(control, &record, BackupState::Quarantined),
        )?;
        let Some(changed) = changed else {
            return Ok(PurgeOutcome::NotWithdrawn);
        };
        (
            metadata_from(&changed.value, installation.installation_id())?,
            changed.value,
        )
    };
    // PolicyOwner is not held while validating, hashing or unlinking files.
    if !remove_artifact(control, &metadata, deadline)? {
        return Ok(PurgeOutcome::PendingCleanup { metadata });
    }
    let finalized = retry_seq_race_before(
        deadline,
        || {
            let guard = acquire_exclusive(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let bound = control.bind_control_root(&guard)?;
            control.finalize_backup_purge(
                control.status()?.policy.control_seq,
                &bound,
                installation,
                backup_id,
                &quarantined.source_ids,
                now_ms,
            )
        },
        || backup_retry_is_current(control, &quarantined, BackupState::PurgedByPolicy),
    )?;
    Ok(PurgeOutcome::Purged {
        metadata: metadata_from(&finalized.value, installation.installation_id())?,
        artifact_removed: true,
    })
}

fn require_fence(control: &SqliteControlStore, owner: &ControlId) -> PortResult<ReadPolicy> {
    let policy = control.read_policy(RequestIntersection::Selected)?;
    let fence = &policy.maintenance;
    if !matches!(
        fence.state,
        MaintenanceState::Updating | MaintenanceState::Recovering
    ) || fence.owner.as_ref() != Some(owner)
    {
        return Err(invalid("maintenance fence is not owned by this operation"));
    }
    Ok(policy)
}

fn withdrawn(policy: &ReadPolicy, coverage: &[CoveredSource]) -> bool {
    coverage
        .iter()
        .any(|source| !policy.allows_source(source.provider, &source.locator, &source.source_id))
}

fn acquire_exclusive(root: &Path, kind: LockKind, deadline: Instant) -> PortResult<ExclusiveGuard> {
    loop {
        check_deadline(deadline)?;
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            result => return result,
        }
    }
}

fn acquire_lease(root: &Path, deadline: Instant) -> PortResult<WriterLease> {
    loop {
        check_deadline(deadline)?;
        match WriterLease::try_acquire(root) {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            result => return result,
        }
    }
}

fn check_deadline(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        return Err(busy("managed maintenance deadline reached"));
    }
    Ok(())
}

pub(crate) fn set_sql_deadline(conn: &Connection, deadline: Instant) -> PortResult<()> {
    check_deadline(deadline)?;
    conn.busy_timeout(
        deadline
            .saturating_duration_since(Instant::now())
            .min(BUSY_TIMEOUT),
    )
    .map_err(sql)?;
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(sql)
}

/// Source-free, read-only update admission. A compatible identity is not a
/// query/evidence permission and never triggers a schema migration.
pub fn inspect_catalog_identity(
    control: &SqliteControlStore,
    catalog: &Path,
    deadline: Instant,
) -> PortResult<CatalogIdentity> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    control.with_runtime_deadline(deadline, || {
        check_deadline(deadline)?;
        control.validate_live_root()?;
        validate_catalog_path(catalog)?;
        let parent = catalog
            .parent()
            .ok_or_else(|| invalid("catalog parent is unavailable"))?;
        let root = RootIdentity::read(parent)?;
        if !control.matches_root(root) {
            return Err(invalid("catalog is not in the control root"));
        }
        let before = control.status()?;
        if before.policy.maintenance.state != MaintenanceState::Idle {
            return Err(busy("catalog identity admission requires idle maintenance"));
        }
        let handles = loop {
            check_deadline(deadline)?;
            match SharedGuard::try_acquire(parent, LockKind::CatalogHandles) {
                Ok(guard) => break guard,
                Err(PortError::WriterBusy(_)) => std::thread::sleep(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ),
                Err(error) => return Err(error),
            }
        };
        let pin = open_catalog_pin(control, catalog)?;
        let conn = open_read_only(catalog, deadline)?;
        let snapshot = conn.unchecked_transaction().map_err(sql)?;
        let identity = validate_compatible_identity(&snapshot, &before.policy.installation_id)?;
        if before
            .catalog_incarnation
            .as_ref()
            .is_some_and(|incarnation| incarnation != &identity.incarnation)
        {
            return Err(incompatible("catalog incarnation does not match control"));
        }
        drop(snapshot);
        if validate_compatible_identity(&conn, &before.policy.installation_id)? != identity {
            return Err(busy("catalog identity changed during admission"));
        }
        handles.validate_current(parent)?;
        control.validate_private_read(catalog, &pin)?;
        let after = control.status()?;
        if !control.matches_root(root)
            || after.policy != before.policy
            || after.catalog_incarnation != before.catalog_incarnation
            || after.desired_updates != before.desired_updates
        {
            return Err(busy("catalog policy changed during identity admission"));
        }
        check_deadline(deadline)?;
        Ok(identity)
    })
}

// Writable catalogs need a pin that permits our SQLite writes but refuses
// reparse/hardlink aliases and, on Windows, native deletion/rename sharing.
fn open_catalog_pin(control: &SqliteControlStore, path: &Path) -> PortResult<fs::File> {
    control.validate_catalog_file(path)?;
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
            READ_CONTROL,
        };
        fs::OpenOptions::new()
            .read(true)
            .access_mode(0x80000000 | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| storage())?
    };
    #[cfg(not(windows))]
    let file = control.open_private_read(path)?;
    control.validate_private_read(path, &file)?;
    Ok(file)
}

fn verify_quick_integrity(conn: &Connection) -> PortResult<()> {
    let result: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sql)?;
    if result != "ok" {
        return Err(incompatible("catalog integrity is unavailable"));
    }
    Ok(())
}

fn open_read_only(path: &Path, deadline: Instant) -> PortResult<Connection> {
    check_deadline(deadline)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    set_sql_deadline(&conn, deadline)?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
        .map_err(sql)?;
    Ok(conn)
}

fn open_read_write(path: &Path, deadline: Instant) -> PortResult<Connection> {
    check_deadline(deadline)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    set_sql_deadline(&conn, deadline)?;
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(sql)?;
    Ok(conn)
}

/// Strict current-schema identity remains the purge/runtime admission guard.
pub(crate) fn validate_identity(
    conn: &Connection,
    installation: &ControlId,
) -> PortResult<CatalogIdentity> {
    let identity = validate_compatible_identity(conn, installation)?;
    if identity.schema != SCHEMA_VERSION as u32 {
        return Err(incompatible("managed catalog schema is not current"));
    }
    Ok(identity)
}

fn validate_compatible_identity(
    conn: &Connection,
    installation: &ControlId,
) -> PortResult<CatalogIdentity> {
    let application: i64 = conn
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(sql)?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql)?;
    if application != APPLICATION_ID || !matches!(version, 20..=22) {
        return Err(incompatible("managed catalog identity is unavailable"));
    }
    let (catalog_installation, incarnation, generation): (String, String, i64) = conn
        .query_row(
            "SELECT catalog_meta.installation_id,catalog_meta.catalog_incarnation,store_metadata.active_generation FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND store_metadata.managed_mode=1 AND store_metadata.projection_contract_version=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql)?;
    if catalog_installation != installation.as_str() {
        return Err(incompatible("catalog installation does not match control"));
    }
    let generation =
        u64::try_from(generation).map_err(|_| incompatible("catalog generation is invalid"))?;
    Ok(CatalogIdentity {
        installation: installation.clone(),
        incarnation: ControlId::parse(&incarnation)
            .map_err(|_| incompatible("catalog incarnation is invalid"))?,
        schema: u32::try_from(version).map_err(|_| incompatible("catalog schema is invalid"))?,
        generation,
    })
}

fn read_coverage(conn: &Connection, deadline: Instant) -> PortResult<Vec<CoveredSource>> {
    check_deadline(deadline)?;
    if !catalog_coverage_is_classified(conn)? || !catalog_journal_is_content_free(conn, deadline)? {
        return Err(incompatible(
            "catalog contains unclassified physical source coverage",
        ));
    }
    let mut stmt = conn
        .prepare("SELECT source_id,provider_id,source_path FROM source_bindings ORDER BY source_id")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    let mut coverage = Vec::new();
    while let Some(row) = rows.next().map_err(sql)? {
        check_deadline(deadline)?;
        let source_id = ControlId::parse(&row.get::<_, String>(0).map_err(sql)?)
            .map_err(|_| incompatible("catalog source identity is invalid"))?;
        let provider_wire: String = row.get(1).map_err(sql)?;
        let provider = SearchProvider::parse(&provider_wire)
            .filter(|provider| provider.as_str() == provider_wire)
            .ok_or_else(|| incompatible("catalog source provider is invalid"))?;
        let locator = CanonicalLocator::parse(&row.get::<_, String>(2).map_err(sql)?)
            .map_err(|_| incompatible("catalog source locator is invalid"))?;
        // Retain the opaque binding/namespace after withdrawal. Only the exact
        // empty revoked sentinel is outside physical content coverage; an
        // unpublished or merely unselected binding still needs accounting.
        if source_binding_is_retired(conn, source_id.as_str(), locator.as_str())? {
            continue;
        }
        if coverage
            .last()
            .is_some_and(|last: &CoveredSource| last.source_id >= source_id)
        {
            return Err(incompatible("catalog source coverage is not unique"));
        }
        coverage.push(CoveredSource {
            source_id,
            provider,
            locator,
        });
    }
    Ok(coverage)
}

/// Whether a preserved source binding is the exact content-free purge sentinel.
/// Callers install the original SQL deadline before invoking this predicate.
pub(crate) fn source_binding_is_retired(
    conn: &Connection,
    source: &str,
    path: &str,
) -> PortResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM source_heads WHERE source_id=?1 AND update_state='revoked'
             AND visible_revision_id IS NULL AND latest_receipt_id IS NULL
             AND content_set_digest IS NULL AND last_attempt_id IS NULL AND observed_cycle_seq IS NULL)
         AND NOT EXISTS(SELECT 1 FROM source_revision_receipts WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM source_projections WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM source_occurrences WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM source_entity_projections WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM source_session_projections WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM source_scope_claims WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM discovery_sources WHERE source_id=?1)
         AND NOT EXISTS(SELECT 1 FROM source_scans WHERE source_path=?2)
         AND NOT EXISTS(SELECT 1 FROM source_membership WHERE source_path=?2)
         AND NOT EXISTS(SELECT 1 FROM source_placement_membership WHERE source_path=?2)
         AND NOT EXISTS(SELECT 1 FROM source_relation_scans WHERE source_path=?2)
         AND NOT EXISTS(SELECT 1 FROM source_session_resume_claims WHERE source_path=?2)
         AND NOT EXISTS(SELECT 1 FROM tool_activity_membership WHERE source_path=?2)
         AND NOT EXISTS(SELECT 1 FROM usage_event_membership WHERE source_path=?2)",
        rusqlite::params![source,path], |row| row.get(0),
    ).map_err(sql)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationDigest {
    format: String,
    digest: String,
}

/// The managed outbox retains only commitments. Old relation/replacement or
/// relocation manifests can retain native metadata without source attribution.
/// Refuse those images instead of rewriting recovery/audit evidence or claiming
/// that a projection-only purge removed every physical fact.
pub(crate) fn catalog_journal_is_content_free(
    conn: &Connection,
    deadline: Instant,
) -> PortResult<bool> {
    const MAX_DETAIL_BYTES: i64 = 256 * 1024;
    set_sql_deadline(conn, deadline)?;
    let oversized: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM index_batches WHERE
            length(CAST(upsert_ids_json AS BLOB))+length(CAST(delete_ids_json AS BLOB))+
            length(CAST(relation_upserts_json AS BLOB))+length(CAST(relation_deletes_json AS BLOB))+
            length(CAST(source_replacements_json AS BLOB))+length(CAST(relocation_json AS BLOB))+
            COALESCE(length(CAST(detail_summary_json AS BLOB)),0)>?1)",
            [MAX_DETAIL_BYTES],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if oversized {
        return Ok(false);
    }
    let mut stmt = conn.prepare(
        "SELECT operation_id,upsert_ids_json,delete_ids_json,relation_upserts_json,relation_deletes_json,
                source_replacements_json,relocation_json,detail_format,detail_summary_json FROM index_batches"
    ).map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        check_deadline(deadline)?;
        for index in 1..=4 {
            let raw: String = row.get(index).map_err(sql)?;
            if !matches!(serde_json::from_str::<serde_json::Value>(&raw), Ok(serde_json::Value::Array(values)) if values.is_empty())
            {
                return Ok(false);
            }
        }
        let replacements: String = row.get(5).map_err(sql)?;
        let Ok(commitments) = serde_json::from_str::<Vec<ObservationDigest>>(&replacements) else {
            return Ok(false);
        };
        if commitments.iter().any(|value| {
            value.format != "asg.managed-observation/v1"
                || value.digest.len() != 64
                || !value
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Ok(false);
        }
        let relocation: String = row.get(6).map_err(sql)?;
        if !matches!(
            serde_json::from_str::<serde_json::Value>(&relocation),
            Ok(serde_json::Value::Null)
        ) {
            return Ok(false);
        }
        let operation: String = row.get(0).map_err(sql)?;
        let format: String = row.get(7).map_err(sql)?;
        let summary: Option<String> = row.get(8).map_err(sql)?;
        // Reuse the catalog's typed format decoder. Do not expose its raw
        // operation-name diagnostics across this maintenance boundary.
        if crate::decode_aggregated_journal_detail(&operation, &format, summary.as_deref()).is_err()
            || (format == crate::JOURNAL_DETAIL_FORMAT_AGGREGATED_V1 && !commitments.is_empty())
        {
            return Ok(false);
        }
        check_deadline(deadline)?;
    }
    Ok(true)
}

/// A whole-catalog backup covers every physically retained source, including
/// unpublished bindings and legacy/derived membership. Unknown ownership is
/// never approximated by the current selected set or a content scan.
pub(crate) fn catalog_coverage_is_classified(conn: &Connection) -> PortResult<bool> {
    let foreign_key_error = conn
        .prepare("PRAGMA foreign_key_check")
        .map_err(sql)?
        .exists([])
        .map_err(sql)?;
    if foreign_key_error {
        return Ok(false);
    }
    let unclassified: bool = conn.query_row(
        "WITH retained_paths(source_path) AS (
             SELECT source_path FROM source_scans
             UNION SELECT source_path FROM source_membership
             UNION SELECT source_path FROM source_placement_membership
             UNION SELECT source_path FROM source_relation_scans
             UNION SELECT source_path FROM source_session_resume_claims
             UNION SELECT source_path FROM tool_activity_membership
             UNION SELECT source_path FROM usage_event_membership
         ), retained_entities(entity_id) AS (
             SELECT message_id FROM source_membership
             UNION SELECT document_id FROM source_membership WHERE document_id IS NOT NULL
             UNION SELECT message_id FROM source_projections
             UNION SELECT entity_id FROM source_entity_projections
         ), retained_source_ids(source_id) AS (
             SELECT source_id FROM source_heads
             UNION SELECT source_id FROM source_revision_receipts
             UNION SELECT source_id FROM source_projections
             UNION SELECT source_id FROM source_occurrences
             UNION SELECT source_id FROM source_entity_projections
             UNION SELECT source_id FROM source_session_projections
             UNION SELECT source_id FROM source_scope_claims
             UNION SELECT source_id FROM discovery_sources
         )
         SELECT EXISTS(
             SELECT 1 FROM retained_paths p
             LEFT JOIN source_bindings b ON b.source_path=p.source_path
             WHERE b.source_id IS NULL
         ) OR EXISTS(
             SELECT 1 FROM retained_source_ids s
             LEFT JOIN source_bindings b USING(source_id)
             WHERE b.source_id IS NULL
         ) OR EXISTS(
             SELECT 1 FROM source_scans s JOIN source_bindings b USING(source_path)
             WHERE s.provider_id IS NULL OR s.provider_id<>b.provider_id
         ) OR EXISTS(
             SELECT 1 FROM source_session_resume_claims s JOIN source_bindings b USING(source_path)
             WHERE s.provider_id<>b.provider_id
         ) OR EXISTS(
             SELECT 1 FROM source_occurrences s JOIN source_bindings b USING(source_id)
             WHERE s.provider_id<>b.provider_id
         ) OR EXISTS(
             SELECT 1 FROM catalog c WHERE NOT EXISTS(
                 SELECT 1 FROM retained_entities e WHERE e.entity_id=c.id
             )
         ) OR EXISTS(
             SELECT 1 FROM fts_ids i WHERE NOT EXISTS(
                 SELECT 1 FROM retained_entities e WHERE e.entity_id=i.wire_id
             )
         ) OR EXISTS(
             SELECT 1 FROM fts f WHERE NOT EXISTS(
                 SELECT 1 FROM fts_ids i WHERE i.fts_rowid=f.rowid
             )
         ) OR EXISTS(
             SELECT 1 FROM message_vec v WHERE NOT EXISTS(
                 SELECT 1 FROM retained_entities e WHERE e.entity_id=v.wire_id
             )
         ) OR EXISTS(
             SELECT 1 FROM message_placements p WHERE NOT EXISTS(
                 SELECT 1 FROM source_placement_membership s WHERE s.placement_id=p.placement_id
             )
         ) OR EXISTS(
             SELECT 1 FROM message_edges e WHERE NOT EXISTS(
                 SELECT 1 FROM source_placement_membership s WHERE s.placement_id=e.child_placement_id
             )
         ) OR EXISTS(
             SELECT 1 FROM tool_activities a WHERE NOT EXISTS(
                 SELECT 1 FROM tool_activity_membership s WHERE s.activity_id=a.activity_id
             )
         ) OR EXISTS(
             SELECT 1 FROM usage_events u WHERE NOT EXISTS(
                 SELECT 1 FROM usage_event_membership s WHERE s.usage_id=u.usage_id
             )
         ) OR EXISTS(
             SELECT 1 FROM session_titles t WHERE NOT EXISTS(
                 SELECT 1 FROM retained_entities e WHERE e.entity_id=t.session_wire
             )
         ) OR EXISTS(
             SELECT 1 FROM session_repo_slugs r WHERE NOT EXISTS(
                 SELECT 1 FROM retained_entities e WHERE e.entity_id=r.session_wire
             )
         ) OR EXISTS(
             SELECT 1 FROM session_fts_ids i WHERE NOT EXISTS(
                 SELECT 1 FROM retained_entities e WHERE e.entity_id=i.session_wire
             )
         ) OR EXISTS(
             SELECT 1 FROM session_fts f WHERE NOT EXISTS(
                 SELECT 1 FROM session_fts_ids i WHERE i.fts_rowid=f.rowid
             )
         )",
        [],
        |row| row.get(0),
    ).map_err(sql)?;
    Ok(!unclassified)
}

/// Validate existing in-database FTS and its external-content correspondence.
/// No source projection is generated, changed or granted permission here.
pub(crate) fn verify_derived_integrity(conn: &Connection, deadline: Instant) -> PortResult<()> {
    set_sql_deadline(conn, deadline)?;
    for command in [
        "INSERT INTO fts(fts) VALUES('integrity-check')",
        "INSERT INTO session_fts(session_fts) VALUES('integrity-check')",
        "INSERT INTO projection_fts(projection_fts,rank) VALUES('integrity-check',1)",
        "INSERT INTO session_metadata_fts(session_metadata_fts,rank) VALUES('integrity-check',1)",
    ] {
        check_deadline(deadline)?;
        conn.execute(command, []).map_err(sql)?;
    }
    check_deadline(deadline)
}

/// Logical copy with the SQLite backup API. The source snapshot is consistent,
/// including committed WAL content; no raw database/WAL bytes are copied.
fn write_logical_copy(
    source: &Connection,
    destination: &mut Connection,
    deadline: Instant,
) -> PortResult<()> {
    let copy = backup::Backup::new(source, destination).map_err(sql)?;
    loop {
        if Instant::now() >= deadline {
            return Err(busy("catalog backup exceeded its deadline"));
        }
        match copy.step(COPY_STEP_PAGES).map_err(sql)? {
            backup::StepResult::Done => break,
            backup::StepResult::More | backup::StepResult::Busy | backup::StepResult::Locked => {
                std::thread::sleep(Duration::from_millis(1))
            }
            _ => return Err(incompatible("catalog backup step is unsupported")),
        }
    }
    Ok(())
}

fn hash_file(
    control: &SqliteControlStore,
    path: &Path,
    deadline: Instant,
) -> PortResult<(String, u64)> {
    let mut file = control.open_private_read(path)?;
    hash_opened(control, path, &mut file, deadline)
}

fn hash_opened(
    control: &SqliteControlStore,
    path: &Path,
    file: &mut fs::File,
    deadline: Instant,
) -> PortResult<(String, u64)> {
    check_deadline(deadline)?;
    let before = file.metadata().map_err(|_| storage())?;
    let limit = before.len();
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        check_deadline(deadline)?;
        let remaining = limit.saturating_sub(size).saturating_add(1);
        let chunk = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = file.read(&mut buffer[..chunk]).map_err(|_| storage())?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| incompatible("backup size overflow"))?;
        if size > limit {
            return Err(incompatible("backup changed during verification"));
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| storage())?;
    if size != limit || !same_file_observation(&before, &after) {
        return Err(incompatible("backup changed during verification"));
    }
    control.validate_private_read(path, file)?;
    check_deadline(deadline)?;
    Ok((hasher.finalize().to_hex().to_string(), size))
}

fn same_file_observation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        (
            before.file_size(),
            before.last_write_time(),
            before.file_attributes(),
        ) == (
            after.file_size(),
            after.last_write_time(),
            after.file_attributes(),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (before, after);
        false
    }
}

fn artifact_path(control: &SqliteControlStore, relative_locator: &str) -> PortResult<PathBuf> {
    let mut path = control.private_root().to_path_buf();
    for part in relative_locator.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(invalid("backup locator is invalid"));
        }
        path.push(part);
    }
    Ok(path)
}

fn manifest_path(artifact: &Path) -> PortResult<PathBuf> {
    let parent = artifact
        .parent()
        .ok_or_else(|| invalid("backup locator is invalid"))?;
    Ok(parent.join("manifest.json"))
}

fn prepare_artifact_parent(control: &SqliteControlStore, artifact: &Path) -> PortResult<()> {
    let root = control
        .private_root()
        .canonicalize()
        .map_err(|_| storage())?;
    let directory = artifact
        .parent()
        .ok_or_else(|| invalid("backup locator is invalid"))?;
    let backups = directory
        .parent()
        .ok_or_else(|| invalid("backup locator is invalid"))?;
    ensure_private_directory(backups)?;
    ensure_private_directory(directory)?;
    let canonical = directory.canonicalize().map_err(|_| storage())?;
    if !canonical.starts_with(&root) {
        return Err(invalid("backup locator escapes the private root"));
    }
    validate_private_directory(directory)?;
    Ok(())
}

fn prepare_side_path(control: &SqliteControlStore, side_path: &Path) -> PortResult<()> {
    if !side_path.is_absolute()
        || side_path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("restore side path is invalid"));
    }
    let parent = side_path
        .parent()
        .ok_or_else(|| invalid("restore side path is invalid"))?;
    let root = control
        .private_root()
        .canonicalize()
        .map_err(|_| storage())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| invalid("restore side parent is unavailable"))?;
    if !canonical_parent.starts_with(&root) {
        return Err(invalid("restore side path escapes the private root"));
    }
    validate_private_directory(&canonical_parent)?;
    validate_catalog_path(side_path)?;
    if !control.matches_root(RootIdentity::read(parent)?)
        || matches!(
            side_path.file_name().and_then(|v| v.to_str()),
            Some("catalog.db" | "control.db")
        )
        || side_path.extension().and_then(|v| v.to_str()) != Some("db")
    {
        return Err(invalid(
            "restore side path must be a distinct catalog sibling",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_sidecar(
    control: &SqliteControlStore,
    backup_id: &ControlId,
    purpose: BackupPurpose,
    identity: &CatalogIdentity,
    installation: &ControlId,
    source_ids: &[ControlId],
    digest: &str,
    size_bytes: u64,
    now_ms: i64,
) -> PortResult<()> {
    let path = artifact_path(control, &catalog_backup_locator(backup_id))?;
    let sidecar = manifest_path(&path)?;
    if sidecar.try_exists().map_err(|_| storage())? {
        return Err(invalid("backup sidecar already exists"));
    }
    let manifest = SidecarManifest {
        schema: MANIFEST_SCHEMA.into(),
        backup_id: backup_id.as_str().into(),
        purpose: match purpose {
            BackupPurpose::BetaRollback => "beta_rollback".into(),
        },
        installation_id: installation.as_str().into(),
        catalog_incarnation: identity.incarnation.as_str().into(),
        catalog_generation: identity.generation,
        schema_version: identity.schema,
        digest: digest.into(),
        size_bytes,
        source_ids: source_ids
            .iter()
            .map(|id| id.as_str().to_string())
            .collect(),
        created_at_ms: now_ms,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(|_| storage())?;
    control.create_private_file_under(&sidecar)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&sidecar)
        .map_err(|_| storage())?;
    use std::io::Write;
    file.write_all(&bytes).map_err(|_| storage())?;
    file.sync_all().map_err(|_| storage())?;
    drop(file);
    control.validate_catalog_file(&sidecar)
}

struct VerifiedArtifact {
    path: PathBuf,
    file: fs::File,
    observation: fs::Metadata,
    sidecar: PathBuf,
    sidecar_file: fs::File,
    sidecar_observation: fs::Metadata,
}
impl VerifiedArtifact {
    fn validate(&self, control: &SqliteControlStore) -> PortResult<()> {
        control.validate_private_read(&self.path, &self.file)?;
        control.validate_private_read(&self.sidecar, &self.sidecar_file)?;
        if !same_file_observation(
            &self.observation,
            &self.file.metadata().map_err(|_| storage())?,
        ) || !same_file_observation(
            &self.sidecar_observation,
            &self.sidecar_file.metadata().map_err(|_| storage())?,
        ) {
            return Err(incompatible("backup changed after its verified read"));
        }
        require_standalone_image(&self.path)
    }
}

fn require_standalone_image(path: &Path) -> PortResult<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match fs::symlink_metadata(PathBuf::from(name)) {
            Ok(_) => return Err(incompatible("backup has unverified SQLite sidecars")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage()),
        }
    }
    Ok(())
}

fn verify_manifest_file(
    control: &SqliteControlStore,
    sidecar: &Path,
    metadata: &BackupMetadata,
    deadline: Instant,
) -> PortResult<(fs::File, fs::Metadata)> {
    check_deadline(deadline)?;
    let mut sidecar_file = control.open_private_read(sidecar)?;
    let before = sidecar_file.metadata().map_err(|_| storage())?;
    if before.len() > MAX_MANIFEST {
        return Err(incompatible("backup manifest is oversized"));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        check_deadline(deadline)?;
        let remaining = (MAX_MANIFEST + 1).saturating_sub(bytes.len() as u64) as usize;
        let chunk = remaining.min(buffer.len());
        let read = sidecar_file
            .read(&mut buffer[..chunk])
            .map_err(|_| storage())?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(incompatible("backup manifest is oversized"));
        }
    }
    if !same_file_observation(&before, &sidecar_file.metadata().map_err(|_| storage())?) {
        return Err(incompatible("backup manifest changed during verification"));
    }
    control.validate_private_read(sidecar, &sidecar_file)?;
    let manifest: SidecarManifest =
        serde_json::from_slice(&bytes).map_err(|_| incompatible("backup manifest is invalid"))?;
    let source_ids: Vec<&str> = manifest.source_ids.iter().map(String::as_str).collect();
    let expected: Vec<&str> = metadata.source_ids.iter().map(ControlId::as_str).collect();
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.backup_id != metadata.backup_id.as_str()
        || manifest.purpose != "beta_rollback"
        || manifest.installation_id != metadata.installation.as_str()
        || manifest.catalog_incarnation != metadata.catalog_incarnation.as_str()
        || manifest.catalog_generation != metadata.catalog_generation
        || manifest.schema_version != metadata.schema_version
        || manifest.digest != metadata.digest
        || manifest.size_bytes != metadata.size_bytes
        || source_ids != expected
    {
        return Err(incompatible(
            "backup manifest does not match control ownership",
        ));
    }
    check_deadline(deadline)?;
    Ok((sidecar_file, before))
}

fn verify_catalog_image_file(
    control: &SqliteControlStore,
    path: &Path,
    metadata: &BackupMetadata,
    deadline: Instant,
) -> PortResult<(fs::File, fs::Metadata)> {
    check_deadline(deadline)?;
    let mut file = control.open_private_read(path)?;
    let (digest, size) = hash_opened(control, path, &mut file, deadline)?;
    if digest != metadata.digest || size != metadata.size_bytes {
        return Err(incompatible("backup content does not match its manifest"));
    }
    let observation = file.metadata().map_err(|_| storage())?;
    check_deadline(deadline)?;
    Ok((file, observation))
}

fn verify_artifact(
    control: &SqliteControlStore,
    metadata: &BackupMetadata,
    deadline: Instant,
) -> PortResult<VerifiedArtifact> {
    check_deadline(deadline)?;
    let path = artifact_path(control, &metadata.relative_locator)?;
    require_standalone_image(&path)?;
    let sidecar = manifest_path(&path)?;
    let (sidecar_file, before) = verify_manifest_file(control, &sidecar, metadata, deadline)?;
    let (file, observation) = verify_catalog_image_file(control, &path, metadata, deadline)?;
    let artifact = VerifiedArtifact {
        path,
        file,
        observation,
        sidecar,
        sidecar_file,
        sidecar_observation: before,
    };
    artifact.validate(control)?;
    check_deadline(deadline)?;
    Ok(artifact)
}

fn artifact_absent(control: &SqliteControlStore, metadata: &BackupMetadata) -> PortResult<bool> {
    let path = artifact_path(control, &metadata.relative_locator)?;
    let sidecar = manifest_path(&path)?;
    control.validate_live_root()?;
    for candidate in [&path, &sidecar] {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage()),
        }
    }
    Ok(true)
}

fn verify_cleanup_remnants(
    control: &SqliteControlStore,
    metadata: &BackupMetadata,
    deadline: Instant,
) -> PortResult<()> {
    control.validate_live_root()?;
    check_deadline(deadline)?;
    let path = artifact_path(control, &metadata.relative_locator)?;
    let sidecar = manifest_path(&path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("backup locator is invalid"))?;
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(storage()),
        Ok(_) => validate_private_directory(parent)?,
    }
    require_standalone_image(&path)?;
    for candidate in [&sidecar, &path] {
        check_deadline(deadline)?;
        match fs::symlink_metadata(candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(storage()),
            Ok(_) => {}
        }
        // Retained terminal/quarantine metadata alone does not authorize
        // deleting a replacement. Reverify whichever original file survives.
        let (file, before) = if candidate == &sidecar {
            verify_manifest_file(control, candidate, metadata, deadline)?
        } else {
            verify_catalog_image_file(control, candidate, metadata, deadline)?
        };
        control.validate_private_read(candidate, &file)?;
        if !same_file_observation(&before, &file.metadata().map_err(|_| storage())?) {
            return Err(incompatible("backup cleanup remnant changed"));
        }
    }
    check_deadline(deadline)
}

fn remove_artifact(
    control: &SqliteControlStore,
    metadata: &BackupMetadata,
    deadline: Instant,
) -> PortResult<bool> {
    control.validate_live_root()?;
    check_deadline(deadline)?;
    let path = artifact_path(control, &metadata.relative_locator)?;
    let sidecar = manifest_path(&path)?;
    let mut removed = true;
    for candidate in [&sidecar, &path] {
        check_deadline(deadline)?;
        match fs::symlink_metadata(candidate) {
            Ok(meta) if meta.is_file() => {
                control.validate_catalog_file(candidate)?;
                if fs::remove_file(candidate).is_err() {
                    removed = false;
                }
            }
            Ok(_) => return Err(invalid("owned backup path is not a regular file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => removed = false,
        }
    }
    if removed && let Some(parent) = path.parent() {
        match fs::symlink_metadata(parent) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return artifact_absent(control, metadata);
            }
            Err(_) => return Err(storage()),
            Ok(_) => validate_private_directory(parent)?,
        }
        match fs::remove_dir(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => removed = false,
        }
    }
    Ok(removed && artifact_absent(control, metadata)?)
}

fn metadata_from(record: &StoredBackup, installation: &ControlId) -> PortResult<BackupMetadata> {
    Ok(BackupMetadata {
        backup_id: record.backup_id.clone(),
        purpose: record.purpose,
        relative_locator: record.relative_locator.clone(),
        installation: installation.clone(),
        catalog_incarnation: record.catalog_incarnation.clone(),
        catalog_generation: record.catalog_generation,
        schema_version: record.schema_version,
        digest: record
            .digest
            .clone()
            .ok_or_else(|| incompatible("backup has no verified digest"))?,
        size_bytes: record.size_bytes,
        source_ids: record.source_ids.clone(),
    })
}
