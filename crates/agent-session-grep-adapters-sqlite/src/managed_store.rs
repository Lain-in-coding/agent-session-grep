//! Managed catalog composition. No legacy CatalogStore or raw connection escapes.
//! Content publication reuses the existing durable outbox and generation CAS.
//! Receipt-only observations are atomic without advancing content generation.
use crate::{
    CanonicalBatchManifest, NoopRepoSlugResolver, RelationManifests, SCHEMA_VERSION,
    SEMANTIC_SIMILARITY_FLOOR_DEFAULT, SourceBatch, SqliteControlStore, SqliteStore, WriterLease,
    managed,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity, SharedGuard},
};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider,
    control::{
        BackgroundControl, CanonicalLocator, ControlId, ControlStore, CycleSeq, CycleState,
        DesiredUpdates, MaintenanceState, ObservationCycle, ReadPolicy, RequestIntersection,
        SelectionRevision, WorkerAuthority,
    },
    managed::{
        DiscoveryObservation, DiscoverySource, Publication, RevisionId, RevisionRef,
        SelectionProof, SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed catalog operation".into())
}

impl crate::managed_discovery::OriginalCycleValidator for SqliteControlStore {
    fn cycle(&self, number: CycleSeq, end: Instant) -> PortResult<ObservationCycle> {
        self.with_runtime_deadline(end, || BackgroundControl::cycle(self, number))
    }
}

#[derive(Clone, Copy)]
enum DiscoveryPublication {
    ExactCycle,
    PlainEpoch,
}

pub(crate) const APPLICATION_ID: i64 = 0x41534732;

/// Limit the file retained after a WAL reset, not a WAL pinned by readers.
pub(crate) const JOURNAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalDeferral {
    /// A maintenance/emission fence, or a busy control read at admission.
    Fence,
    CatalogHandles,
    WriterLease,
    Sqlite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalCheckpointOutcome {
    Reset,
    Deferred(WalDeferral),
    NotApplicable,
}

/// Physical checkpoint observations only; none of these fields publish proof.
#[derive(Clone, Debug)]
pub struct WalCheckpointReport {
    pub outcome: WalCheckpointOutcome,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
    /// Absent if admission stopped before the catalog identity was read.
    pub incarnation: Option<ControlId>,
    pub wal_bytes_before: Option<u64>,
    pub wal_bytes_after: Option<u64>,
    /// Includes I/O, whose wall time is not bounded by the zero busy timeout.
    pub elapsed: Duration,
    // Same-call Debug evidence only; never changes admission or physical work.
    initial_admission: Option<AdmissionObservation>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AdmissionObservation {
    requested_end: Instant,
    effective_end: Instant,
    entered_remaining_us: i128,
    returned_remaining_us: Option<i128>,
    result: Option<&'static str>,
}

impl std::fmt::Debug for AdmissionObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionObservation")
            .field("requested_end", &self.requested_end)
            .field("effective_end", &self.effective_end)
            .field("entered_remaining_us", &self.entered_remaining_us)
            .field("returned_remaining_us", &self.returned_remaining_us)
            .field("result", &self.result)
            .finish()
    }
}

fn remaining_us(end: Instant, now: Instant) -> i128 {
    if end >= now {
        end.duration_since(now).as_micros() as i128
    } else {
        -(now.duration_since(end).as_micros() as i128)
    }
}

fn admission_result<T>(result: &PortResult<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(PortError::WriterBusy(message)) => match message.as_str() {
            "control runtime deadline reached" => "deadline",
            "control storage is busy" => "control_busy",
            "managed control fence is active" => "active_fence",
            _ => "other",
        },
        Err(_) => "other",
    }
}

fn checkpoint_storage(error: rusqlite::Error) -> PortError {
    use rusqlite::ErrorCode;
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy) => {
            PortError::WriterBusy("managed catalog checkpoint is busy".into())
        }
        Some(ErrorCode::DatabaseLocked) => {
            PortError::Backend("managed checkpoint connection is locked".into())
        }
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
            PortError::Backend("managed checkpoint storage is corrupt".into())
        }
        _ => PortError::Backend("managed checkpoint storage unavailable".into()),
    }
}

pub(crate) fn apply_journal_size_limit(
    conn: &Connection,
    map_error: fn(rusqlite::Error) -> PortError,
) -> PortResult<()> {
    let limit = JOURNAL_SIZE_LIMIT_BYTES;
    #[cfg(test)]
    let limit = wal_tests::LIMIT.with(|value| value.get()).unwrap_or(limit);
    conn.pragma_update(None, "journal_size_limit", limit)
        .map_err(map_error)?;
    let actual: i64 = conn
        .pragma_query_value(None, "journal_size_limit", |row| row.get(0))
        .map_err(map_error)?;
    if actual != limit {
        return Err(PortError::Backend(
            "managed catalog journal limit was not applied".into(),
        ));
    }
    #[cfg(test)]
    wal_tests::record_pragmas(conn);
    Ok(())
}

/// Match the database and intent using ordinary file names, never Win32 alias
/// trimming, device names or alternate streams. Check before any filesystem I/O.
pub fn validate_catalog_path(path: &Path) -> PortResult<()> {
    if path.as_os_str().is_empty() {
        return Err(invalid());
    }
    #[cfg(windows)]
    for component in path.components() {
        use std::path::{Component, Prefix};
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_)
                | Prefix::VerbatimDisk(_)
                | Prefix::UNC(_, _)
                | Prefix::VerbatimUNC(_, _) => {}
                _ => return Err(invalid()),
            },
            Component::Normal(part) => {
                let name = part.to_str().ok_or_else(invalid)?;
                if name.starts_with(' ')
                    || name.ends_with([' ', '.'])
                    || name.contains([':', '*', '?', '"', '<', '>', '|'])
                    || name.chars().any(char::is_control)
                {
                    return Err(invalid());
                }
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                if matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
                ) || ["COM", "LPT"].iter().any(|prefix| {
                    stem.strip_prefix(prefix).is_some_and(|n| {
                        matches!(
                            n,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                }) {
                    return Err(invalid());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn creation_intent_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".asg-managed-create");
    PathBuf::from(name)
}

/// Existence denies legacy adoption, including an empty marker after a crash.
/// Marker contents never grant ownership or authorize recovery.
pub(crate) fn reject_creation_intent(path: &Path) -> PortResult<()> {
    match std::fs::symlink_metadata(creation_intent_path(path)) {
        Ok(_) => Err(incompatible()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(incompatible()),
    }
}

fn reserve_creation(path: &Path, control: &SqliteControlStore) -> PortResult<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(invalid()),
    }
    let marker = creation_intent_path(path);
    control.create_private_catalog_file(&marker)?;
    // Flush the creation intent before a database inode can exist. The marker
    // remains after success and failure; owned uninstall handles its removal.
    #[cfg(unix)]
    std::fs::File::open(path.parent().ok_or_else(invalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| incompatible())?;
    Ok(())
}

/// What an existing path may be while `create` runs again.
enum ExistingCreation {
    /// Reserved by this installation but no catalog was activated yet. The
    /// schema may be absent or partially migrated; only an empty, unmanaged
    /// store qualifies, so a damaged established catalog is never rebuilt.
    Pristine,
    /// Activation already committed; an identical retry adopts it.
    Initialized(ControlId),
}

fn inspect_existing_creation(
    path: &Path,
    control: &SqliteControlStore,
    installation: &ControlId,
) -> PortResult<ExistingCreation> {
    // Only a path reserved by this installer's creation intent may resume.
    if std::fs::symlink_metadata(creation_intent_path(path)).is_err() {
        return Err(invalid());
    }
    control.validate_catalog_file(path)?;
    let conn = connect(path, false)?;
    let application: i64 = conn
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(storage)?;
    if application != APPLICATION_ID {
        return Err(incompatible());
    }
    if let Ok(incarnation) = identity(&conn, installation) {
        return Ok(ExistingCreation::Initialized(incarnation));
    }
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage)?;
    if version > SCHEMA_VERSION {
        return Err(incompatible());
    }
    let rows = |table: &str| -> PortResult<i64> {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if !exists {
            return Ok(0);
        }
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(storage)
    };
    if rows("catalog_meta")? != 0 || rows("catalog")? != 0 || rows("index_batches")? != 0 {
        return Err(incompatible());
    }
    // `store_metadata.managed_mode` is set only by activation.
    let has_managed_mode: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM pragma_table_info('store_metadata') WHERE name='managed_mode'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if has_managed_mode {
        let managed_mode: i64 = conn
            .query_row(
                "SELECT managed_mode FROM store_metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if managed_mode != 0 {
            return Err(incompatible());
        }
    }
    Ok(ExistingCreation::Pristine)
}
fn incompatible() -> PortError {
    PortError::SchemaIncompatible("managed catalog identity is unavailable or incompatible".into())
}
fn changed() -> PortError {
    PortError::GenerationMismatch("managed catalog or policy changed".into())
}
fn history_cache_error(error: crate::managed_cache::CacheError) -> PortError {
    use crate::managed_cache::{CacheError, CacheUnavailable};
    match error {
        CacheError::Unavailable(CacheUnavailable::Busy | CacheUnavailable::Deadline) => {
            PortError::WriterBusy("history cache dependency capture is busy".into())
        }
        CacheError::Unavailable(CacheUnavailable::Storage) => {
            PortError::SourceIo("history cache dependency storage unavailable".into())
        }
        CacheError::Unavailable(
            CacheUnavailable::PolicyChanged | CacheUnavailable::ClockChanged,
        ) => PortError::GenerationMismatch("history cache dependencies changed".into()),
        _ => PortError::SchemaIncompatible("history cache dependencies invalid".into()),
    }
}

fn storage(error: rusqlite::Error) -> PortError {
    #[cfg(test)]
    baseline_deadline_tests::observe_storage_error(&error);
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => PortError::WriterBusy("managed catalog is busy".into()),
        _ => incompatible(),
    }
}

fn acquire_handles(root: &Path) -> PortResult<SharedGuard> {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match SharedGuard::try_acquire(root, LockKind::CatalogHandles) {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// A managed connection owns the shared handle gate; writes also own the writer
/// lease. Its internal legacy store is only a reuse boundary, never a read API.
pub struct ManagedStore {
    inner: SqliteStore,
    installation: ControlId,
    incarnation: ControlId,
    root: RootIdentity,
}

/// A small dependency-preserving housekeeping batch. This is not freshness
/// or purge completion and exposes no source path, receipt or worker token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryRetentionReport {
    pub catalog: crate::managed_history::HistoryCounts,
    pub control_cycles_deleted: usize,
    pub control_barriers_deleted: usize,
    pub has_more: bool,
    pub control_pending: bool,
}

/// Internal parser identity inputs. Never include these in a public response.
pub struct SourceNamespace {
    pub namespace_id: String,
    pub input: String,
}

/// Private scheduling inputs, including unpublished bindings needed for restart.
#[derive(Debug, Clone)]
pub struct BackgroundSource {
    pub binding: SourceBinding,
    pub latest_receipt: Option<RevisionRef>,
    pub indexed_len: Option<u64>,
    pub superseded: bool,
}

struct RefreshInstallation {
    path: String,
    namespace: String,
    provider: String,
    input: String,
    origin: String,
    location_provider: String,
    root_key: String,
    root: String,
    state: String,
    created: i64,
}

/// Minted and consumed only by the single admitted refresh entry below.
struct VerifiedRefresh<'a> {
    prior: &'a RevisionRef,
    observation: &'a SourceObservation,
    snapshot: &'a agent_session_grep_ports::SourceSnapshot,
    deadline: Instant,
}

impl std::fmt::Debug for SourceNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceNamespace([private])")
    }
}

/// Internal activation capability: the receiving root remains exclusively
/// drained and the writer lease is borrowed, never reacquired by migration.
pub(crate) struct LegacyActivation<'a> {
    pub connection: &'a Connection,
    pub control: &'a SqliteControlStore,
    pub lease: &'a WriterLease,
    pub handles: &'a ExclusiveGuard,
    pub installation: &'a ControlId,
    pub incarnation: &'a ControlId,
    pub now_ms: i64,
    pub deadline: Instant,
}

impl ManagedStore {
    pub(crate) fn activate_legacy_copy(input: LegacyActivation<'_>) -> PortResult<()> {
        let deadline = SqliteControlStore::effective_runtime_deadline(input.deadline);
        crate::managed_maintenance::set_sql_deadline(input.connection, deadline)?;
        let root = input.handles.root_identity();
        let lease_root = input.lease.path().parent().ok_or_else(invalid)?;
        if input.handles.kind() != &LockKind::CatalogHandles
            || RootIdentity::read(lease_root)? != root
            || !input.control.matches_root(root)
        {
            return Err(invalid());
        }
        let status = input.control.with_runtime_deadline(deadline, || {
            #[cfg(test)]
            activation_deadline_tests::observe(deadline, true);
            input.control.status()
        })?;
        #[cfg(test)]
        activation_deadline_tests::observe(deadline, false);
        if status.policy.installation_id != *input.installation
            || status
                .catalog_incarnation
                .as_ref()
                .is_some_and(|current| current != input.incarnation)
        {
            return Err(changed());
        }
        let tx = input.connection.unchecked_transaction().map_err(storage)?;
        managed::activate_legacy_copy_in_tx(
            &tx,
            input.installation.as_str(),
            input.incarnation.as_str(),
            input.now_ms,
        )?;
        tx.commit().map_err(storage)
    }
    /// Explicit empty setup only. Existing catalogs (including legacy ones)
    /// are never adopted or migrated here. Side-path legacy import is separate.
    pub fn create(
        path: &Path,
        control: &SqliteControlStore,
        incarnation: ControlId,
        now_ms: i64,
    ) -> PortResult<Self> {
        Self::create_inner(path, control, incarnation, now_ms, None)
    }

    /// Use the original request end only for the control admission read.
    /// Catalog creation and its acknowledgement retain their existing ordering.
    pub fn create_with_deadline(
        path: &Path,
        control: &SqliteControlStore,
        incarnation: ControlId,
        now_ms: i64,
        deadline: Instant,
    ) -> PortResult<Self> {
        #[cfg(test)]
        setup_deadline_tests::observe_entry(deadline);
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        Self::create_inner(path, control, incarnation, now_ms, Some(deadline))
    }

    fn create_inner(
        path: &Path,
        control: &SqliteControlStore,
        incarnation: ControlId,
        now_ms: i64,
        deadline: Option<Instant>,
    ) -> PortResult<Self> {
        validate_catalog_path(path)?;
        if now_ms < 0 || !path.is_absolute() {
            return Err(invalid());
        }
        let root_path = path.parent().ok_or_else(invalid)?;
        let handles = acquire_handles(root_path)?;
        let root = handles.root_identity();
        let policy = setup_admission(control, root, deadline)?;
        let lease = WriterLease::try_acquire(root_path)?;
        let resume = match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                reserve_creation(path, control)?;
                control.create_private_catalog_file(path)?;
                None
            }
            Ok(_) => Some(inspect_existing_creation(
                path,
                control,
                &policy.installation_id,
            )?),
            Err(_) => return Err(incompatible()),
        };
        let conn = connect(path, true)?;
        let fresh = resume.is_none();
        if let Some(existing) = resume {
            match existing {
                ExistingCreation::Initialized(existing_incarnation) => {
                    // The previous attempt committed activation but never
                    // returned (crash or ack loss). An identical retry adopts
                    // that catalog; a different incarnation is a mismatch.
                    if existing_incarnation != incarnation {
                        return Err(changed());
                    }
                    control.validate_catalog_file(path)?;
                    return Ok(Self::from_parts(
                        conn,
                        Some(lease),
                        handles,
                        policy.installation_id,
                        incarnation,
                    ));
                }
                ExistingCreation::Pristine => {}
            }
        }
        // Reserve this file for the policy-enforcing facade before any schema
        // work. A crash after initialization but before activation must not let
        // a legacy writer adopt the partly initialized managed catalog.
        if fresh {
            conn.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(storage)?;
        }
        SqliteStore::init(&conn)?;
        let tx = conn.unchecked_transaction().map_err(storage)?;
        managed::initialize_catalog_in_tx(
            &tx,
            policy.installation_id.as_str(),
            incarnation.as_str(),
            now_ms,
        )?;
        tx.commit().map_err(storage)?;
        #[cfg(test)]
        setup_deadline_tests::observe_commit();
        control.validate_catalog_file(path)?;
        #[cfg(test)]
        setup_deadline_tests::observe_validated();
        Ok(Self::from_parts(
            conn,
            Some(lease),
            handles,
            policy.installation_id,
            incarnation,
        ))
    }

    pub fn open(path: &Path, control: &SqliteControlStore) -> PortResult<Self> {
        Self::open_existing(path, control, false, None)
    }

    /// Read-only open with the original end at the control admission boundary.
    pub fn open_with_deadline(
        path: &Path,
        control: &SqliteControlStore,
        deadline: Instant,
    ) -> PortResult<Self> {
        #[cfg(test)]
        setup_deadline_tests::observe_entry(deadline);
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        Self::open_existing(path, control, false, Some(deadline))
    }

    pub fn open_for_write(path: &Path, control: &SqliteControlStore) -> PortResult<Self> {
        Self::open_existing(path, control, true, None)
    }

    /// Try one physical reset at a boundary with no caller-owned catalog
    /// connection. Background authority is required, but Running intent is not.
    /// Every catalog lock is tried once. Only admission reads share a control
    /// deadline; physical I/O and post-close validation cannot lose their result
    /// merely because that read budget has elapsed.
    pub fn checkpoint_wal(
        path: &Path,
        control: &SqliteControlStore,
        authority: &crate::control::LockedWorkerAuthority<'_>,
        expected_incarnation: Option<&ControlId>,
    ) -> PortResult<WalCheckpointReport> {
        let started = Instant::now();
        let control_end = started + Duration::from_millis(BUSY_TIMEOUT_MILLIS);
        #[cfg(test)]
        let control_end = wal_tests::CONTROL_END
            .with(|end| end.get())
            .unwrap_or(control_end);
        validate_catalog_path(path)?;
        control.validate_catalog_file(path)?;
        let mut report = WalCheckpointReport {
            outcome: WalCheckpointOutcome::NotApplicable,
            log_frames: -1,
            checkpointed_frames: -1,
            incarnation: None,
            wal_bytes_before: None,
            wal_bytes_after: None,
            elapsed: Duration::ZERO,
            initial_admission: None,
        };
        let handles = match SharedGuard::try_acquire(
            path.parent().ok_or_else(invalid)?,
            LockKind::CatalogHandles,
        ) {
            Ok(handles) => Some(handles),
            Err(PortError::WriterBusy(_)) => {
                report.outcome = WalCheckpointOutcome::Deferred(WalDeferral::CatalogHandles);
                None
            }
            Err(error) => return Err(error),
        };
        let result = (|| {
            let Some(handles) = handles.as_ref() else {
                return Ok(());
            };
            #[cfg(test)]
            wal_tests::admission_enter(wal_tests::AdmissionStage::Initial, control_end);
            let effective_end = SqliteControlStore::effective_runtime_deadline(control_end);
            let initial = report.initial_admission.insert(AdmissionObservation {
                requested_end: control_end,
                effective_end,
                entered_remaining_us: remaining_us(effective_end, Instant::now()),
                returned_remaining_us: None,
                result: None,
            });
            let admitted =
                checkpoint_admission(control, authority, handles.root_identity(), control_end);
            initial.returned_remaining_us = Some(remaining_us(effective_end, Instant::now()));
            initial.result = Some(admission_result(&admitted));
            #[cfg(test)]
            wal_tests::admission_return(wal_tests::AdmissionStage::Initial, &admitted);
            let policy = match admitted {
                Ok(policy) => policy,
                Err(PortError::WriterBusy(_)) => {
                    report.outcome = WalCheckpointOutcome::Deferred(WalDeferral::Fence);
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let target = CheckpointTarget {
                policy,
                expected_incarnation: expected_incarnation.cloned(),
                control_end,
            };
            let lease = match WriterLease::try_acquire(control.private_root()) {
                Ok(lease) => lease,
                Err(PortError::WriterBusy(_)) => {
                    report.outcome = WalCheckpointOutcome::Deferred(WalDeferral::WriterLease);
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let pin = crate::managed_maintenance::open_catalog_pin(control, path)?;
            let checkpoint =
                checkpoint_catalog(path, control, authority, &target, &pin, &mut report);
            // Keep the pin and shared gate through the post-close sample so a
            // maintenance swap cannot splice another catalog into this report.
            drop(lease);
            checkpoint?;
            #[cfg(test)]
            wal_tests::after_close();
            control.validate_private_read(path, &pin)?;
            control.validate_catalog_file(path)?;
            control.validate_live_root()?;
            report.wal_bytes_after = Self::wal_len(path)?;
            drop(pin);
            Ok(())
        })();
        if matches!(result, Ok(())) && report.wal_bytes_after.is_none() {
            control.validate_catalog_file(path)?;
            control.validate_live_root()?;
            report.wal_bytes_after = Self::wal_len(path)?;
        }
        drop(handles);
        result?;
        report.elapsed = started.elapsed();
        Ok(report)
    }

    /// Missing sidecars are normal after SQLite closes its last connection.
    pub fn wal_len(path: &Path) -> PortResult<Option<u64>> {
        validate_catalog_path(path)?;
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        match std::fs::symlink_metadata(Path::new(&wal)) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                Ok(Some(metadata.len()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(PortError::Backend(
                "managed checkpoint sidecar unavailable".into(),
            )),
        }
    }

    fn open_existing(
        path: &Path,
        control: &SqliteControlStore,
        writable: bool,
        deadline: Option<Instant>,
    ) -> PortResult<Self> {
        validate_catalog_path(path)?;
        control.validate_catalog_file(path)?;
        let handles = acquire_handles(path.parent().ok_or_else(invalid)?)?;
        let policy = setup_admission(control, handles.root_identity(), deadline)?;
        if writable && control.lifecycle_status()?.desired_updates != DesiredUpdates::Running {
            return Err(PortError::WriterBusy(
                "managed updates are paused or stopped".into(),
            ));
        }
        let lease = if writable {
            Some(WriterLease::try_acquire(
                path.parent().ok_or_else(invalid)?,
            )?)
        } else {
            None
        };
        let conn = connect(path, writable)?;
        let incarnation = identity(&conn, &policy.installation_id)?;
        let store = Self::from_parts(conn, lease, handles, policy.installation_id, incarnation);
        if writable {
            store.inner.recover_interrupted()?;
        }
        control.validate_catalog_file(path)?;
        #[cfg(test)]
        setup_deadline_tests::observe_validated();
        Ok(store)
    }

    fn from_parts(
        conn: Connection,
        lease: Option<WriterLease>,
        handles: SharedGuard,
        installation: ControlId,
        incarnation: ControlId,
    ) -> Self {
        let root = handles.root_identity();
        Self {
            inner: SqliteStore {
                conn: RefCell::new(conn),
                _lease: lease,
                semantic_model_id: RefCell::new(None),
                semantic_similarity_floor: Cell::new(SEMANTIC_SIMILARITY_FLOOR_DEFAULT),
                repo_slug_resolver: RefCell::new(Box::new(NoopRepoSlugResolver)),
                pending_installations: RefCell::new(BTreeMap::new()),
                relocation_clock: crate::unix_ms,
                _catalog_handles: Some(handles),
            },
            installation,
            incarnation,
            root,
        }
    }

    pub fn incarnation(&self) -> &ControlId {
        &self.incarnation
    }

    /// Read the active content generation through an already-authorized
    /// read-only managed handle. This deliberately grants no history-reader
    /// capability and does not create that lock file during inventory.
    pub fn inspected_generation(&self) -> PortResult<u64> {
        self.inner.active_generation()
    }

    /// Reserve the existing installation identity before canonical staging.
    /// The reservation is private memory until an observation receipt commits.
    /// Even an incomplete observation preserves identity across restart, while
    /// its unverified content remains unpublished. No provider file is opened.
    pub fn reserve_namespace(
        &self,
        control: &SqliteControlStore,
        observation: &SourceObservation,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        legacy_input: &str,
    ) -> PortResult<SourceNamespace> {
        self.reserve_namespace_inner(control, observation, worker, legacy_input)
    }

    /// Reserve parser identity under the source attempt's original end. Both
    /// control authorization and catalog resolution inherit the earliest scope;
    /// the reservation remains private memory until an observation commits.
    pub fn reserve_namespace_with_deadline(
        &self,
        control: &SqliteControlStore,
        observation: &SourceObservation,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        legacy_input: &str,
        deadline: Instant,
    ) -> PortResult<SourceNamespace> {
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                crate::with_retryable_sql_interrupt(|| {
                    self.reserve_namespace_inner(control, observation, worker, legacy_input)
                })
            })
        })
    }

    fn reserve_namespace_inner(
        &self,
        control: &SqliteControlStore,
        observation: &SourceObservation,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        legacy_input: &str,
    ) -> PortResult<SourceNamespace> {
        if self.inner._lease.is_none() {
            return Err(invalid());
        }
        #[cfg(test)]
        baseline_deadline_tests::observe_namespace_authorization();
        self.authorize_observation(control, worker, observation)?;
        let path = &observation.binding.source_path;
        #[cfg(test)]
        baseline_deadline_tests::observe_namespace_resolution(&self.inner.conn.borrow())?;
        let input = self.inner.resolve_or_allocate_installation_namespace(
            observation.binding.provider.as_str(),
            path,
            legacy_input,
        )?;
        let key = agent_session_grep_application::relocation::normalize_absolute_path(path)?;
        let pending = self.inner.pending_installations.borrow().get(&key).cloned();
        let assignment = match pending {
            Some(assignment) => assignment,
            None => SqliteStore::assignment_for_source(&self.inner.conn.borrow(), path)?
                .ok_or_else(incompatible)?,
        };
        Ok(SourceNamespace {
            namespace_id: assignment.namespace_id().into(),
            input,
        })
    }

    /// No source content is opened here. Caller supplies an already verified
    /// full source snapshot, including rewrite/deletion hold classification.
    pub fn commit_source(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        batch: &SourceBatch,
        observation: &SourceObservation,
    ) -> PortResult<Publication> {
        self.commit_source_with_context(
            control,
            worker,
            batch,
            observation,
            &agent_session_grep_ports::source_context::SourcePublicationContext::default(),
            Instant::now() + Duration::from_secs(10),
        )
    }

    pub fn commit_source_with_context(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        batch: &SourceBatch,
        observation: &SourceObservation,
        context: &agent_session_grep_ports::source_context::SourcePublicationContext,
        deadline: Instant,
    ) -> PortResult<Publication> {
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.commit_source_context_inner(
                    control,
                    worker,
                    batch,
                    observation,
                    context,
                    deadline,
                )
            })
        })
    }

    /// Verify the admitted attempt's entire captured snapshot and atomically
    /// refresh its receipt. Only Ineligible permits full publication using the
    /// same captured input and earliest end; errors may require reconciliation.
    #[expect(
        clippy::too_many_arguments,
        reason = "Reviewed single-entry verification contract"
    )]
    pub fn refresh_verified_unchanged_source(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        expected_prior: &RevisionRef,
        observation: &SourceObservation,
        snapshot: &agent_session_grep_ports::SourceSnapshot,
        sqlite_byte_limit: u64,
        deadline: Instant,
    ) -> PortResult<crate::managed_refresh::RefreshOutcome> {
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                use crate::managed_refresh::{self, RefreshOutcome};
                if self.inner._lease.is_none() {
                    return Err(invalid());
                }
                managed_refresh::validate_input(
                    observation,
                    snapshot,
                    sqlite_byte_limit,
                    deadline,
                )?;
                self.authorize_observation(control, worker, observation)?;
                // Neither a caller-constructed snapshot nor an old receipt is
                // final verification. Validate the actual attempt before I/O.
                let miss = {
                    let mut conn = self.inner.conn.borrow_mut();
                    let tx = conn
                        .transaction_with_behavior(TransactionBehavior::Deferred)
                        .map_err(storage)?;
                    let policy = admission(control, self.root)?;
                    let miss = managed_refresh::check_baseline(
                        &tx,
                        expected_prior,
                        observation,
                        snapshot,
                        &policy,
                        deadline,
                    )?;
                    let installation = self.refresh_installation_in_tx(&tx, observation)?;
                    tx.rollback().map_err(storage)?;
                    miss.or(installation)
                };
                if let Some(miss) = miss {
                    return Ok(RefreshOutcome::Ineligible(miss));
                }
                self.authorize_observation(control, worker, observation)?;
                managed_refresh::verify_source_path(&observation.binding, deadline)?;
                crate::source_fs::verify_snapshot_with_deadline(
                    Path::new(&observation.binding.source_path),
                    snapshot,
                    sqlite_byte_limit,
                    deadline,
                )?;
                self.consume_verified_refresh(
                    control,
                    worker,
                    VerifiedRefresh {
                        prior: expected_prior,
                        observation,
                        snapshot,
                        deadline,
                    },
                )
            })
        })
    }

    fn consume_verified_refresh(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        verified: VerifiedRefresh<'_>,
    ) -> PortResult<crate::managed_refresh::RefreshOutcome> {
        use crate::managed_refresh::{self, RefreshOutcome};
        let VerifiedRefresh {
            prior,
            observation,
            snapshot,
            deadline,
        } = verified;
        self.authorize_observation(control, worker, observation)?;
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        self.authorize_observation(control, worker, observation)?;
        let policy = admission(control, self.root)?;
        let installation = self.refresh_installation_in_tx(&tx, observation)?;
        let result = managed_refresh::publish_refresh_in_tx(
            &tx,
            prior,
            observation,
            snapshot,
            &policy,
            installation,
            deadline,
        )?;
        if matches!(result, RefreshOutcome::Ineligible(_)) {
            tx.rollback().map_err(storage)?;
            return Ok(result);
        }
        self.authorize_observation(control, worker, observation)?;
        managed_refresh::time(deadline)?;
        tx.commit().map_err(storage)?;
        Ok(result)
    }

    fn refresh_installation_in_tx(
        &self,
        conn: &Connection,
        observation: &SourceObservation,
    ) -> PortResult<Option<crate::managed_refresh::RefreshIneligible>> {
        use crate::managed_refresh::RefreshIneligible;
        use agent_session_grep_application::relocation::{
            legacy_installation_namespace, normalize_absolute_path, path_is_within,
        };
        use rusqlite::OptionalExtension;
        let binding = &observation.binding;
        let key = normalize_absolute_path(&binding.source_path)?;
        let now = (self.inner.relocation_clock)()?;
        let mut statement = conn
            .prepare(
                "SELECT root_locator FROM installation_locations
                 WHERE state='retired' AND retired_until_ms>?1 AND provider_id=?2",
            )
            .map_err(storage)?;
        for root in statement
            .query_map(params![now, binding.provider.as_str()], |r| {
                r.get::<_, String>(0)
            })
            .map_err(storage)?
        {
            if path_is_within(&binding.source_path, &root.map_err(storage)?)? {
                return Err(changed());
            }
        }
        let pending = self.inner.pending_installations.borrow();
        let reserved = pending.contains_key(&key);
        if let Some(assignment) = pending.get(&key)
            && binding.namespace_id.as_deref() != Some(assignment.namespace_id())
        {
            return Err(changed());
        }
        let row: Option<RefreshInstallation> = conn
            .query_row(
                "SELECT s.source_path,s.namespace_id,n.provider_id,n.namespace_input,n.origin,
                        l.provider_id,l.root_key,l.root_locator,l.state,n.created_at_ms
                 FROM source_installations s
                 LEFT JOIN installation_namespaces n ON n.namespace_id=s.namespace_id
                 LEFT JOIN installation_locations l ON l.namespace_id=s.namespace_id AND l.state='current'
                 WHERE s.source_key=?1",
                [&key],
                |r| Ok(RefreshInstallation {
                    path: r.get(0)?, namespace: r.get(1)?, provider: r.get(2)?,
                    input: r.get(3)?, origin: r.get(4)?, location_provider: r.get(5)?,
                    root_key: r.get(6)?, root: r.get(7)?, state: r.get(8)?, created: r.get(9)?,
                }),
            )
            .optional()
            .map_err(storage)?;
        let Some(RefreshInstallation {
            path,
            namespace,
            provider,
            input,
            origin,
            location_provider,
            root_key,
            root,
            state,
            created,
        }) = row
        else {
            return Err(incompatible());
        };
        if path != binding.source_path || binding.namespace_id.as_deref() != Some(&namespace) {
            return Err(changed());
        }
        if provider != binding.provider.as_str()
            || location_provider != provider
            || state != "current"
            || root_key != normalize_absolute_path(&root)?
            || !path_is_within(&binding.source_path, &root)?
            || created < 0
        {
            return Err(incompatible());
        }
        ControlId::parse(&namespace).map_err(|_| incompatible())?;
        match origin.as_str() {
            "legacy-v1" => {
                // A relocated legacy namespace keeps its frozen seed, so the
                // tuple is proven from its stored fields, never from the
                // current path. The id must be the canonical derivation, and
                // the seed must be an exact output of the frozen derivation.
                let rest = input
                    .strip_prefix(provider.as_str())
                    .and_then(|rest| rest.strip_prefix(':'))
                    .ok_or_else(incompatible)?;
                let probe = format!("{rest}/asg-refresh-probe");
                if namespace
                    != format!(
                        "ins_v1_{}",
                        crate::relocation::digest_fields(
                            b"asg-legacy-installation-v1",
                            &[&provider, &input],
                        )
                    )
                    || legacy_installation_namespace(&probe, &provider) != input
                {
                    return Err(incompatible());
                }
                Ok(Some(RefreshIneligible::InstallationProof))
            }
            "allocated-v1" => {
                let suffix = namespace.strip_prefix("ins_v1_").ok_or_else(incompatible)?;
                if suffix.len() != 64
                    || !suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || input != format!("installation-v1:{suffix}")
                {
                    return Err(incompatible());
                }
                Ok(reserved.then_some(RefreshIneligible::InstallationProof))
            }
            _ => Err(incompatible()),
        }
    }

    fn commit_source_context_inner(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        batch: &SourceBatch,
        observation: &SourceObservation,
        context: &agent_session_grep_ports::source_context::SourcePublicationContext,
        deadline: Instant,
    ) -> PortResult<Publication> {
        if self.inner._lease.is_none() {
            return Err(invalid());
        }
        self.authorize_observation(control, worker, observation)?;
        let installation = self.inner.installation_for_source_commit(batch)?;
        if installation.as_ref().map(|a| a.namespace_id())
            != observation.binding.namespace_id.as_deref()
        {
            return Err(changed());
        }
        let manifest = observation_manifest(batch, observation, context)?;
        let base = self.generation()?;
        let target = base.checked_add(1).ok_or_else(invalid)?;
        // Validate exact projection facts before writing a durable content
        // intent. Rolling this transaction back publishes neither rows nor FTS.
        let preview = {
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let policy = admission(control, self.root)?;
            let result = crate::managed_source_context::publish_source_with_context_in_tx(
                &tx,
                batch,
                observation,
                context,
                &policy,
                target,
                deadline,
            )?;
            if let Some(assignment) = &installation {
                SqliteStore::persist_installation_in_tx(
                    &tx,
                    &batch.source_path,
                    assignment,
                    observation.committed_at_ms,
                    false,
                )?;
            }
            tx.rollback().map_err(storage)?;
            result
        };
        let relations = RelationManifests::default();
        let pending = if preview.content_changed {
            Some(
                self.inner
                    .begin_index_batch_with_manifest(&manifest, &[], &[], &relations)?,
            )
        } else {
            None
        };
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some(pending) = &pending {
            SqliteStore::verify_pending_in_tx(&tx, pending, &[], &[], &relations, &manifest)?;
        } else {
            let actual: i64 = tx
                .query_row(
                    "SELECT active_generation FROM store_metadata WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if actual != base {
                return Err(changed());
            }
        }
        self.authorize_observation(control, worker, observation)?;
        let policy = admission(control, self.root)?;
        let mut publication = crate::managed_source_context::publish_source_with_context_in_tx(
            &tx,
            batch,
            observation,
            context,
            &policy,
            target,
            deadline,
        )?;
        if let Some(assignment) = &installation {
            SqliteStore::persist_installation_in_tx(
                &tx,
                &batch.source_path,
                assignment,
                observation.committed_at_ms,
                false,
            )?;
        }
        if publication.content_changed != preview.content_changed {
            return Err(changed());
        }
        if publication.content_changed {
            let count = tx.execute("UPDATE store_metadata SET active_generation=?1 WHERE singleton=1 AND active_generation=?2", params![target,base]).map_err(storage)?;
            if count != 1 {
                return Err(changed());
            }
        }
        managed::finalize_publications_in_tx(&tx, std::slice::from_mut(&mut publication))?;
        if publication.receipt.published {
            tx.execute("INSERT INTO source_scans(source_path,scanned_at_ms,len_bytes,fingerprint,provider_id,parser_version) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(source_path) DO UPDATE SET scanned_at_ms=excluded.scanned_at_ms,len_bytes=excluded.len_bytes,fingerprint=excluded.fingerprint,provider_id=excluded.provider_id,parser_version=excluded.parser_version",params![batch.source_path,observation.observed_at_ms,batch.len_bytes,observation.revision_digest,observation.binding.provider.as_str(),observation.parser_version]).map_err(storage)?;
        }
        if let Some(pending) = pending {
            let count=tx.execute("UPDATE index_batches SET state='activated',durable_point='activated',committed_at_ms=?2 WHERE operation_id=?1 AND state='building'",params![pending.operation_id,observation.committed_at_ms]).map_err(storage)?;
            if count != 1 {
                return Err(changed());
            }
        }
        // A concurrent deny remains authoritative even if it commits after
        // this check. Such content cannot be read and its purge remains pending.
        self.authorize_observation(control, worker, observation)?;
        tx.commit().map_err(storage)?;
        self.inner
            .clear_installation_reservations(std::iter::once(batch.source_path.as_str()));
        Ok(publication)
    }

    fn generation(&self) -> PortResult<i64> {
        self.inner
            .conn
            .borrow()
            .query_row(
                "SELECT active_generation FROM store_metadata WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(storage)
    }

    pub fn source_binding_for_locator(
        &self,
        control: &SqliteControlStore,
        provider: SearchProvider,
        locator: &CanonicalLocator,
    ) -> PortResult<Option<SourceBinding>> {
        Ok(self
            .background_sources(control)?
            .into_iter()
            .find(|s| {
                s.binding.provider == provider
                    && CanonicalLocator::parse(&s.binding.source_path).is_ok_and(|p| p == *locator)
            })
            .map(|s| s.binding))
    }

    pub fn reserve_namespace_for_surface(
        &self,
        control: &SqliteControlStore,
        observation: &SourceObservation,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        surface_root: &CanonicalLocator,
        physical_identity: &ControlId,
        deadline: Instant,
    ) -> PortResult<SourceNamespace> {
        control.with_runtime_deadline(deadline, || {
            self.authorize_observation(control, worker, observation)?;
            let locator = CanonicalLocator::parse(&observation.binding.source_path)?;
            if !surface_root.contains(&locator)
                || !matches!(
                    observation.binding.provider.as_str(),
                    "antigravity" | "deepseek-harness"
                )
            {
                return Err(invalid());
            }
            let input = self.inner.resolve_or_allocate_surface_namespace(
                observation.binding.provider.as_str(),
                &observation.binding.source_path,
                surface_root.as_str(),
                physical_identity.as_str(),
            )?;
            let key = agent_session_grep_application::relocation::normalize_absolute_path(
                &observation.binding.source_path,
            )?;
            let pending = self.inner.pending_installations.borrow().get(&key).cloned();
            let assignment = match pending {
                Some(a) => a,
                None => SqliteStore::assignment_for_source(
                    &self.inner.conn.borrow(),
                    &observation.binding.source_path,
                )?
                .ok_or_else(incompatible)?,
            };
            self.authorize_observation(control, worker, observation)?;
            Ok(SourceNamespace {
                namespace_id: assignment.namespace_id().into(),
                input,
            })
        })
    }

    pub fn publication_context(
        &self,
        control: &SqliteControlStore,
        receipt: &RevisionRef,
        deadline: Instant,
    ) -> PortResult<agent_session_grep_ports::source_context::SourcePublicationContext> {
        control.with_runtime_deadline(deadline, || {
            let policy = admission(control, self.root)?;
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn.transaction().map_err(storage)?;
            let result = crate::managed_source_context::publication_context(
                &tx, receipt, &policy, deadline,
            )?;
            tx.rollback().map_err(storage)?;
            if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(result)
        })
    }

    pub fn authority_prior(
        &self,
        control: &SqliteControlStore,
        key: &agent_session_grep_ports::source_context::SourceAuthorityKey,
        deadline: Instant,
    ) -> PortResult<Option<agent_session_grep_ports::source_context::SourceAuthorityPrior>> {
        control.with_runtime_deadline(deadline, || {
            let policy = admission(control, self.root)?;
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn.transaction().map_err(storage)?;
            let result =
                crate::managed_source_context::authority_prior(&tx, key, &policy, deadline)?;
            tx.rollback().map_err(storage)?;
            if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(result)
        })
    }

    pub fn source_current(
        &self,
        receipt: &RevisionRef,
        control: &SqliteControlStore,
        deadline: Instant,
    ) -> PortResult<bool> {
        control.with_runtime_deadline(deadline, || {
            let policy = admission(control, self.root)?;
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn.transaction().map_err(storage)?;
            if crate::managed_receipt::read_checked(&tx, receipt.revision_id.as_str(), None)?
                != *receipt
            {
                return Err(changed());
            }
            let current = crate::managed_source_context::receipt_context_current(
                &tx,
                receipt.revision_id.as_str(),
                Some(&policy),
                deadline,
            )?;
            tx.rollback().map_err(storage)?;
            if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(current)
        })
    }

    pub fn background_sources(
        &self,
        control: &SqliteControlStore,
    ) -> PortResult<Vec<BackgroundSource>> {
        let policy = admission(control, self.root)?;
        if policy.installation_id != self.installation {
            return Err(changed());
        }
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn.transaction().map_err(storage)?;
        let mut stmt=tx.prepare("SELECT b.source_id,b.source_path,b.provider_id,b.namespace_id,b.root_identity,h.latest_receipt_id,s.len_bytes FROM source_bindings b JOIN source_heads h USING(source_id) LEFT JOIN source_scans s USING(source_path) ORDER BY b.source_id").map_err(storage)?;
        let mut rows = stmt.query([]).map_err(storage)?;
        let mut sources = Vec::new();
        while let Some(row) = rows.next().map_err(storage)? {
            let source_id = SourceId::parse(&row.get::<_, String>(0).map_err(storage)?)?;
            let source_path: String = row.get(1).map_err(storage)?;
            let locator = CanonicalLocator::parse(&source_path)?;
            let provider_wire: String = row.get(2).map_err(storage)?;
            let provider = SearchProvider::parse(&provider_wire)
                .filter(|p| p.as_str() == provider_wire)
                .ok_or_else(incompatible)?;
            let source = ControlId::parse(source_id.as_str())?;
            let namespace_id: Option<String> = row.get(3).map_err(storage)?;
            let root_identity: String = row.get(4).map_err(storage)?;
            ControlId::parse(&root_identity)?;
            if !policy.allows_source(provider, &locator, &source) {
                continue;
            }
            let receipt: Option<String> = row.get(5).map_err(storage)?;
            let latest_receipt = receipt
                .map(|id| crate::managed_receipt::read_checked(&tx, &id, Some(source_id.as_str())))
                .transpose()?;
            let len: Option<i64> = row.get(6).map_err(storage)?;
            let indexed_len = len
                .map(|n| u64::try_from(n).map_err(|_| incompatible()))
                .transpose()?;
            sources.push(BackgroundSource {
                binding: SourceBinding {
                    source_id,
                    source_path,
                    provider,
                    namespace_id,
                    root_identity,
                },
                latest_receipt,
                indexed_len,
                superseded: !crate::managed_source_context::source_read_eligible(
                    &tx,
                    source.as_str(),
                )?,
            });
        }
        drop(rows);
        drop(stmt);
        tx.commit().map_err(storage)?;
        if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
            return Err(changed());
        }
        Ok(sources)
    }

    /// Catalog-only scheduling baselines. No provider file is opened, no mtime
    /// is invented, and the worker must retain its own successful capture hint.
    pub fn current_plain_baselines(
        &self,
        control: &SqliteControlStore,
        deadline: Instant,
    ) -> PortResult<Vec<BackgroundSource>> {
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                let policy = admission(control, self.root)?;
                if policy.installation_id != self.installation {
                    return Err(changed());
                }
                let _history =
                    SharedGuard::try_acquire(control.private_root(), LockKind::HistoryReaders)?;
                let ownership =
                    crate::managed_discovery::OriginalCycleProof::new(control, deadline);
                let mut conn = self.inner.conn.borrow_mut();
                let tx = conn.transaction().map_err(storage)?;
                #[cfg(test)]
                baseline_deadline_tests::observe_query(&tx, deadline)?;
                let mut statement = tx
                    .prepare(
                        "SELECT source_id,source_path,provider_id,namespace_id,root_identity
                 FROM source_bindings WHERE provider_id IN ('claude-code','codex')
                 ORDER BY source_id",
                    )
                    .map_err(storage)?;
                let mut rows = statement.query([]).map_err(storage)?;
                let mut baselines = Vec::new();
                let mut examined = 0usize;
                while let Some(row) = rows.next().map_err(storage)? {
                    context_deadline(deadline)?;
                    examined = examined.checked_add(1).ok_or_else(invalid)?;
                    if examined > agent_session_grep_ports::source_context::MAX_AUTHORITY_KEYS {
                        return Err(PortError::WriterBusy(
                            "managed baseline capacity exceeded".into(),
                        ));
                    }
                    let source_id = SourceId::parse(&row.get::<_, String>(0).map_err(storage)?)?;
                    let source_path: String = row.get(1).map_err(storage)?;
                    let provider_wire: String = row.get(2).map_err(storage)?;
                    let provider = SearchProvider::parse(&provider_wire)
                        .filter(|provider| provider.as_str() == provider_wire)
                        .ok_or_else(incompatible)?;
                    let namespace_id: Option<String> = row.get(3).map_err(storage)?;
                    let root_identity: String = row.get(4).map_err(storage)?;
                    ControlId::parse(&root_identity)?;
                    let Some(namespace) = namespace_id.as_ref() else {
                        continue;
                    };
                    ControlId::parse(namespace)?;
                    let locator = CanonicalLocator::parse(&source_path)?;
                    let key = agent_session_grep_application::relocation::normalize_absolute_path(
                        &source_path,
                    )?;
                    let assignment: bool = tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM source_installations s
                     JOIN installation_namespaces n ON n.namespace_id=s.namespace_id
                     JOIN installation_locations l ON l.namespace_id=s.namespace_id
                     WHERE s.source_key=?1 AND s.source_path=?2 AND s.namespace_id=?3
                       AND n.provider_id=?4 AND l.provider_id=?4 AND l.state='current'
                       AND n.origin!='legacy-v1')",
                            params![key, source_path, namespace, provider.as_str()],
                            |row| row.get(0),
                        )
                        .map_err(storage)?;
                    if !assignment {
                        continue;
                    }
                    if !policy.allows_source(
                        provider,
                        &locator,
                        &ControlId::parse(source_id.as_str())?,
                    ) {
                        continue;
                    }
                    let Some(receipt) = crate::managed_discovery::current_plain_baseline(
                        &tx, &source_id, &policy, deadline,
                    )?
                    else {
                        continue;
                    };
                    if receipt.catalog_incarnation != self.incarnation.as_str()
                        || !crate::managed_discovery::validate_receipt_ownership(
                            &tx, &receipt, &ownership, deadline,
                        )?
                    {
                        continue;
                    }
                    let len: i64 = tx
                        .query_row(
                            "SELECT len_bytes FROM source_scans WHERE source_path=?1",
                            [&source_path],
                            |row| row.get(0),
                        )
                        .map_err(storage)?;
                    baselines.push(BackgroundSource {
                        binding: SourceBinding {
                            source_id,
                            source_path,
                            provider,
                            namespace_id,
                            root_identity,
                        },
                        latest_receipt: Some(receipt),
                        indexed_len: Some(u64::try_from(len).map_err(|_| incompatible())?),
                        superseded: false,
                    });
                }
                drop(rows);
                drop(statement);
                tx.rollback().map_err(storage)?;
                if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                    return Err(changed());
                }
                context_deadline(deadline)?;
                Ok(baselines)
            })
        })
    }

    /// Repair catalog identity and committed source heads already verified by
    /// this live connection. Never restore permissions, pause, or barrier state.
    pub fn reconcile_progress(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
    ) -> PortResult<()> {
        let policy = admission(control, self.root)?;
        if policy.installation_id != self.installation
            || worker.installation_id() != &self.installation
            || !worker.is_bound_to(control)
        {
            return Err(invalid());
        }
        control.reconcile_catalog_summary(
            control.status()?.policy.control_seq,
            worker,
            &self.incarnation,
            crate::unix_ms()?,
        )?;
        for source in self.background_sources(control)? {
            if let Some(receipt) = source.latest_receipt {
                if receipt.catalog_incarnation != self.incarnation.as_str() {
                    let conn = self.inner.conn.borrow();
                    if !managed::retained_receipt_matches(
                        &conn,
                        &receipt,
                        self.incarnation.as_str(),
                        self.generation()?,
                    )? {
                        return Err(incompatible());
                    }
                    // Restored evidence remains readable, but is not current
                    // control progress. Only a fresh source observation repairs
                    // the receipt and its source projection provenance.
                    continue;
                }
                control.reconcile_source_summary(
                    control.status()?.policy.control_seq,
                    worker,
                    &source.binding,
                    &receipt,
                )?;
            }
        }
        Ok(())
    }

    /// Run one bounded history batch while owning the existing catalog writer
    /// lease. Live requests hold the separate shared reader guard even while
    /// latest drops a SQLite snapshot, so retention never invalidates an active
    /// barrier or continuation. Busy/unknown dependencies authorize no cleanup.
    pub fn retain_history(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        deadline: Instant,
    ) -> PortResult<HistoryRetentionReport> {
        control.with_runtime_deadline(deadline, || {
            if self.inner._lease.is_none()
                || !worker.is_bound_to(control)
                || worker.installation_id() != &self.installation
            {
                return Err(invalid());
            }
            worker.validate()?;
            let policy = admission(control, self.root)?;
            let readers =
                ExclusiveGuard::try_acquire(control.private_root(), LockKind::HistoryReaders)?;
            let captured = control.capture_history_dependencies(worker, &readers, deadline)?;
            if captured.installation != self.installation
                || captured.policy_epoch != policy.policy_epoch
                || captured.incarnation.as_ref() != Some(&self.incarnation)
            {
                return Err(changed());
            }
            let cache = crate::managed_cache::ManagedCache::at(control.private_root(), control)
                .map_err(history_cache_error)?;
            let cache_revisions = cache
                .history_revisions(control, &readers, crate::unix_ms()?, deadline)
                .map_err(history_cache_error)?;
            let pruned = {
                let mut conn = self.inner.conn.borrow_mut();
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(storage)?;
                let (generation, destructive_epoch): (i64, i64) = tx.query_row(
                "SELECT active_generation,destructive_epoch FROM store_metadata WHERE singleton=1",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(storage)?;
                let dependencies = crate::managed_history::HistoryDependencies {
                    installation_id: self.installation.clone(),
                    snapshot: agent_session_grep_ports::managed::ReadSnapshot {
                        catalog_incarnation: self.incarnation.as_str().into(),
                        generation,
                        destructive_epoch,
                        policy_epoch: captured.policy_epoch.get(),
                    },
                    keep_cycles: captured.cycles.clone(),
                    keep_receipts: captured.receipts.clone(),
                };
                let result = crate::managed_history::prune_with_cycle_validator_in_tx(
                    &tx,
                    &dependencies,
                    &cache_revisions,
                    crate::managed_history::HistoryLimits::default(),
                    deadline,
                    control,
                )?;
                let now = admission(control, self.root)?;
                if now.policy_epoch != captured.policy_epoch
                    || now.control_seq != captured.control_seq
                {
                    return Err(changed());
                }
                readers.validate_current(control.private_root())?;
                if Instant::now() >= deadline {
                    return Err(PortError::WriterBusy(
                        "history retention deadline reached".into(),
                    ));
                }
                tx.commit().map_err(storage)?;
                result
            };
            let mut report = HistoryRetentionReport {
                catalog: pruned.counts,
                has_more: pruned.has_more,
                ..HistoryRetentionReport::default()
            };
            match pruned.cycles {
                crate::managed_history::CycleRetention::PendingCatalogPrune => {
                    report.control_pending = true;
                }
                crate::managed_history::CycleRetention::Complete(tokens) => {
                    match control.prune_history(worker, &readers, &captured, &tokens, deadline) {
                        Ok(counts) => {
                            report.control_cycles_deleted = counts.cycles;
                            report.control_barriers_deleted = counts.barriers;
                            report.has_more |= counts.has_more;
                        }
                        Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                            report.control_pending = true;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(report)
        })
    }

    pub fn commit_discovery(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: &[SourceId],
        _now_ms: i64,
    ) -> PortResult<()> {
        self.commit_discovery_with_deadline(
            control,
            worker,
            cycle,
            selection,
            sources,
            Instant::now() + Duration::from_secs(10),
        )
    }

    /// Complete one selection using the caller's original cycle deadline.
    /// Requires the existing writer lease and a root-bound observing worker.
    /// Exact source/context receipts and policy are checked in this transaction.
    pub fn commit_discovery_with_deadline(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: &[SourceId],
        deadline: Instant,
    ) -> PortResult<()> {
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.publish_discovery(
                    control,
                    worker,
                    cycle,
                    selection,
                    Some(sources),
                    deadline,
                    DiscoveryPublication::ExactCycle,
                )
            })
        })
    }

    /// Close the newest plain-source discovery fence using independently owned
    /// current receipts. This never turns an old source hash into a new one.
    pub fn commit_discovery_epoch_with_deadline(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: &[SourceId],
        deadline: Instant,
    ) -> PortResult<()> {
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.publish_discovery(
                    control,
                    worker,
                    cycle,
                    selection,
                    Some(sources),
                    deadline,
                    DiscoveryPublication::PlainEpoch,
                )
            })
        })
    }

    /// Fence older discovery proofs before filesystem observation begins. A
    /// crash or failed enumeration must leave this attempt visibly incomplete.
    pub fn begin_discovery(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        _now_ms: i64,
    ) -> PortResult<()> {
        self.begin_discovery_with_deadline(
            control,
            worker,
            cycle,
            selection,
            Instant::now() + Duration::from_secs(10),
        )
    }

    /// Record the incomplete fence before enumeration, under the same original
    /// deadline as the eventual source commits and complete discovery.
    pub fn begin_discovery_with_deadline(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        deadline: Instant,
    ) -> PortResult<()> {
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.publish_discovery(
                    control,
                    worker,
                    cycle,
                    selection,
                    None,
                    deadline,
                    DiscoveryPublication::ExactCycle,
                )
            })
        })
    }

    fn with_context_sql_deadline<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> PortResult<T>,
    ) -> PortResult<T> {
        context_deadline(deadline)?;
        let mut reset = ContextSqlDeadline {
            connection: &self.inner.conn,
            active: true,
        };
        {
            let conn = self.inner.conn.borrow();
            conn.busy_handler(Some(|_attempt| {
                let retry = false;
                #[cfg(test)]
                baseline_deadline_tests::observe_busy(_attempt, retry);
                retry
            }))
            .map_err(storage)?;
            conn.progress_handler(
                1000,
                Some(move || {
                    let interrupted = Instant::now() >= deadline;
                    #[cfg(test)]
                    baseline_deadline_tests::observe_progress(deadline, interrupted);
                    interrupted
                }),
            )
            .map_err(storage)?;
        }
        let result = operation().and_then(|value| {
            context_deadline(deadline)?;
            Ok(value)
        });
        let restored = reset.restore();
        match (result, restored) {
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "One publisher serves exact cycles and plain epochs"
    )]
    fn publish_discovery(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: Option<&[SourceId]>,
        deadline: Instant,
        publication: DiscoveryPublication,
    ) -> PortResult<()> {
        context_deadline(deadline)?;
        if self.inner._lease.is_none() {
            return Err(invalid());
        }
        let policy = admission(control, self.root)?;
        worker.validate()?;
        if !worker.is_bound_to(control)
            || policy.installation_id != self.installation
            || cycle.policy_epoch != policy.policy_epoch
            || cycle.token.worker_boot_id != *worker.boot_id()
            || control.lifecycle_status()?.desired_updates != DesiredUpdates::Running
        {
            return Err(changed());
        }
        let active = control.cycle(cycle.token.cycle_seq)?;
        if active.state != CycleState::Observing
            || active.token != cycle.token
            || active.started_control_seq != cycle.started_control_seq
            || !active.selections.iter().any(|s| &s.selection == selection)
        {
            return Err(changed());
        }
        let selected = policy
            .selections
            .iter()
            .find(|s| {
                s.enabled
                    && s.id == selection.selection_id
                    && s.revision == selection.revision
                    && s.root_identity.as_ref() == Some(&selection.root_identity)
            })
            .ok_or_else(changed)?;
        let _history = if matches!(publication, DiscoveryPublication::PlainEpoch) {
            if !matches!(
                selected.region.provider,
                SearchProvider::Claude | SearchProvider::Codex
            ) {
                return Err(invalid());
            }
            Some(SharedGuard::try_acquire(
                control.private_root(),
                LockKind::HistoryReaders,
            )?)
        } else {
            None
        };
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut receipts = Vec::new();
        if sources
            .is_some_and(|s| s.len() > agent_session_grep_ports::source_context::MAX_AUTHORITY_KEYS)
        {
            return Err(invalid());
        }
        for source in sources.unwrap_or_default() {
            context_deadline(deadline)?;
            let (path,provider,receipt):(String,String,String)=tx.query_row("SELECT b.source_path,b.provider_id,h.latest_receipt_id FROM source_bindings b JOIN source_heads h USING(source_id) WHERE source_id=?1",[source.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(storage)?;
            let locator = CanonicalLocator::parse(&path)?;
            if provider != selected.region.provider.as_str()
                || !selected.region.matches(selected.region.provider, &locator)
                || !policy.allows_source(
                    selected.region.provider,
                    &locator,
                    &ControlId::parse(source.as_str())?,
                )
            {
                return Err(changed());
            }
            receipts.push(DiscoverySource {
                source_id: source.clone(),
                revision_id: RevisionId::parse(&receipt)?,
            });
        }
        let observation = DiscoveryObservation {
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: worker.boot_id().as_str().into(),
            catalog_incarnation: self.incarnation.as_str().into(),
            policy_epoch: policy.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.ok_or_else(invalid)?.get(),
            selection: SelectionProof {
                selection_id: selection.selection_id.as_str().into(),
                selection_revision: selection.revision.get(),
                root_identity: selection.root_identity.as_str().into(),
            },
            sources: receipts,
            complete: sources.is_some(),
        };
        match publication {
            DiscoveryPublication::ExactCycle => {
                crate::managed_discovery::publish_with_deadline_in_tx(
                    &tx,
                    &observation,
                    Some(&policy),
                    deadline,
                )?;
            }
            DiscoveryPublication::PlainEpoch => {
                crate::managed_discovery::publish_epoch_with_deadline_in_tx(
                    &tx,
                    &observation,
                    &policy,
                    deadline,
                    control,
                )?;
            }
        }
        if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
            return Err(changed());
        }
        context_deadline(deadline)?;
        tx.commit().map_err(storage)
    }

    fn authorize_observation(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        o: &SourceObservation,
    ) -> PortResult<()> {
        let policy = admission(control, self.root)?;
        worker.validate()?;
        if !worker.is_bound_to(control)
            || worker.installation_id() != &self.installation
            || policy.installation_id != self.installation
            || o.catalog_incarnation != self.incarnation.as_str()
            || o.worker_boot_id != worker.boot_id().as_str()
            || o.policy_epoch != policy.policy_epoch.get()
            || control.lifecycle_status()?.desired_updates != DesiredUpdates::Running
        {
            return Err(changed());
        }
        let source = ControlId::parse(o.binding.source_id.as_str())?;
        let locator = CanonicalLocator::parse(&o.binding.source_path)?;
        if !policy.allows_source(o.binding.provider, &locator, &source) {
            return Err(invalid());
        }
        let cycle = control.cycle(CycleSeq::new(o.cycle_seq)?)?;
        if cycle.state != CycleState::Observing
            || cycle.token.worker_boot_id != *worker.boot_id()
            || cycle.policy_epoch != policy.policy_epoch
            || cycle.started_control_seq.map(|s| s.get()) != Some(o.started_control_seq)
            || o.selections.is_empty()
        {
            return Err(changed());
        }
        for proof in &o.selections {
            let valid = policy.selections.iter().any(|s| {
                s.enabled
                    && s.id.as_str() == proof.selection_id
                    && s.revision.get() == proof.selection_revision
                    && s.root_identity.as_ref().map(ControlId::as_str)
                        == Some(proof.root_identity.as_str())
                    && s.region.matches(o.binding.provider, &locator)
                    && cycle.selections.iter().any(|c| {
                        c.selection.selection_id == s.id
                            && c.selection.revision == s.revision
                            && c.selection.root_identity.as_str() == proof.root_identity
                    })
            });
            if !valid {
                return Err(changed());
            }
        }
        Ok(())
    }

    /// Caller must still recheck policy while holding the emission gate before
    /// publishing rendered output. The callback cannot retain a SQLite handle.
    pub fn with_read<T>(
        &self,
        control: &SqliteControlStore,
        request: RequestIntersection,
        deadline: Instant,
        read: impl FnOnce(&managed::ManagedRead<'_>) -> PortResult<T>,
    ) -> PortResult<T> {
        control.with_runtime_deadline(deadline, || {
            admission(control, self.root)?;
            let _history_read = loop {
                if Instant::now() >= deadline {
                    return Err(PortError::WriterBusy(
                        "managed history admission deadline reached".into(),
                    ));
                }
                match SharedGuard::try_acquire(control.private_root(), LockKind::HistoryReaders) {
                    Ok(guard) => break guard,
                    Err(PortError::WriterBusy(_)) => std::thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    Err(error) => return Err(error),
                }
            };
            let mut policy = admission(control, self.root)?;
            policy.request_intersection = request;
            if policy.installation_id != self.installation {
                return Err(changed());
            }
            let conn = self.inner.conn.borrow();
            let snapshot = managed::ManagedRead::begin_authorized_with_cycle_validator(
                &conn,
                &policy,
                self.incarnation.as_str(),
                deadline,
                control,
            )?;
            let result = read(&snapshot)?;
            let current = admission(control, self.root)?;
            if current.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(result)
        })
    }
}

fn context_deadline(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(PortError::WriterBusy(
            "managed catalog deadline reached".into(),
        ))
    } else {
        Ok(())
    }
}
struct ContextSqlDeadline<'a> {
    connection: &'a RefCell<Connection>,
    active: bool,
}
impl ContextSqlDeadline<'_> {
    fn restore(&mut self) -> PortResult<()> {
        let conn = self.connection.borrow();
        conn.progress_handler(0, None::<fn() -> bool>)
            .map_err(storage)?;
        // The deadline scope installed `busy_handler(|_| false)`; leaving it
        // in place made every later call fail immediately on transient BUSY
        // instead of waiting. Reinstate the connection's busy timeout, which
        // replaces the custom handler.
        conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MILLIS))
            .map_err(storage)?;
        self.active = false;
        Ok(())
    }
}
impl Drop for ContextSqlDeadline<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.restore();
        }
    }
}

fn setup_admission(
    control: &SqliteControlStore,
    root: RootIdentity,
    deadline: Option<Instant>,
) -> PortResult<ReadPolicy> {
    match deadline {
        Some(deadline) => {
            let result = control.with_runtime_deadline(deadline, || admission(control, root));
            #[cfg(test)]
            setup_deadline_tests::observe_restored(deadline);
            result
        }
        None => admission(control, root),
    }
}

fn admission(control: &SqliteControlStore, root: RootIdentity) -> PortResult<ReadPolicy> {
    if !control.matches_root(root) {
        return Err(invalid());
    }
    #[cfg(test)]
    setup_deadline_tests::observe_policy();
    let policy = control.read_policy(RequestIntersection::Selected)?;
    if policy.maintenance.state != MaintenanceState::Idle || policy.emission_blocked() {
        return Err(PortError::WriterBusy(
            "managed control fence is active".into(),
        ));
    }
    Ok(policy)
}
/// Wait budget for transient SQLITE_BUSY on managed connections. Restored after
/// any deadline-scoped call reinstalls its immediate busy handler.
const BUSY_TIMEOUT_MILLIS: u64 = 250;

fn connect(path: &Path, writable: bool) -> PortResult<Connection> {
    connect_with(
        path,
        writable,
        Duration::from_millis(BUSY_TIMEOUT_MILLIS),
        storage,
    )
}

fn connect_with(
    path: &Path,
    writable: bool,
    busy_timeout: Duration,
    map_error: fn(rusqlite::Error) -> PortError,
) -> PortResult<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
        .map_err(map_error)?;
    conn.busy_timeout(busy_timeout).map_err(map_error)?;
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(map_error)?;
    if writable {
        apply_journal_size_limit(&conn, map_error)?;
    }
    SqliteStore::register_scalar_functions(&conn)?;
    Ok(conn)
}
fn identity(conn: &Connection, installation: &ControlId) -> PortResult<ControlId> {
    identity_with(conn, installation, storage)
}

fn identity_with(
    conn: &Connection,
    installation: &ControlId,
    map_error: fn(rusqlite::Error) -> PortError,
) -> PortResult<ControlId> {
    let application_id: i64 = conn
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(map_error)?;
    if application_id != APPLICATION_ID {
        return Err(incompatible());
    }
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(map_error)?;
    if version != SCHEMA_VERSION {
        return Err(incompatible());
    }
    crate::managed_source_context::validate_schema(conn).map_err(|error| {
        // The shared validator predates the checkpoint error taxonomy. Recover
        // a storage result code immediately, before another SQL operation can
        // replace it; semantic schema mismatches retain their typed error.
        // SAFETY: this borrowed connection remains live on the calling thread.
        // The SQLite accessor only reads its last error and retains no pointer.
        let code = unsafe { rusqlite::ffi::sqlite3_extended_errcode(conn.handle()) };
        match code & 0xff {
            rusqlite::ffi::SQLITE_BUSY
            | rusqlite::ffi::SQLITE_LOCKED
            | rusqlite::ffi::SQLITE_IOERR
            | rusqlite::ffi::SQLITE_FULL
            | rusqlite::ffi::SQLITE_CANTOPEN
            | rusqlite::ffi::SQLITE_READONLY
            | rusqlite::ffi::SQLITE_PROTOCOL
            | rusqlite::ffi::SQLITE_CORRUPT
            | rusqlite::ffi::SQLITE_NOTADB => map_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            )),
            _ => error,
        }
    })?;
    let (actual,incarnation):(String,String)=conn.query_row("SELECT installation_id,catalog_incarnation FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(map_error)?;
    if actual != installation.as_str() {
        return Err(incompatible());
    }
    ControlId::parse(&incarnation).map_err(|_| incompatible())
}

struct CheckpointTarget {
    policy: ReadPolicy,
    expected_incarnation: Option<ControlId>,
    control_end: Instant,
}

fn checkpoint_admission(
    control: &SqliteControlStore,
    authority: &crate::control::LockedWorkerAuthority<'_>,
    root: RootIdentity,
    end: Instant,
) -> PortResult<ReadPolicy> {
    #[cfg(test)]
    wal_tests::observe_admission_end(end);
    control.with_runtime_deadline(end, || {
        if !control.matches_root(root) || !authority.is_bound_to(control) {
            return Err(invalid());
        }
        authority.validate()?;
        let policy = admission(control, root)?;
        if authority.installation_id() != &policy.installation_id {
            return Err(invalid());
        }
        Ok(policy)
    })
}

fn checkpoint_catalog(
    path: &Path,
    control: &SqliteControlStore,
    authority: &crate::control::LockedWorkerAuthority<'_>,
    target: &CheckpointTarget,
    pin: &std::fs::File,
    report: &mut WalCheckpointReport,
) -> PortResult<()> {
    let opened = (|| {
        // Install the zero timeout before even the connection pragmas can
        // touch the schema. No ordinary open/recovery or retry loop runs here.
        let conn = connect_with(path, true, Duration::ZERO, checkpoint_storage)?;
        {
            let tx = conn.unchecked_transaction().map_err(checkpoint_storage)?;
            // Pin and read the schema with the checkpoint error mapping before
            // the shared schema validator runs under this same read snapshot.
            tx.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(checkpoint_storage)?;
            report.incarnation = Some(identity_with(
                &tx,
                &target.policy.installation_id,
                checkpoint_storage,
            )?);
            tx.commit().map_err(checkpoint_storage)?;
        }
        Ok(conn)
    })();
    let conn = match opened {
        Ok(conn) => conn,
        Err(PortError::WriterBusy(_)) => {
            report.outcome = WalCheckpointOutcome::Deferred(WalDeferral::Sqlite);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    control.validate_private_read(path, pin)?;
    if target
        .expected_incarnation
        .as_ref()
        .is_some_and(|expected| report.incarnation.as_ref() != Some(expected))
    {
        return Err(changed());
    }
    #[cfg(test)]
    wal_tests::before_checkpoint();
    #[cfg(test)]
    wal_tests::admission_enter(wal_tests::AdmissionStage::Pretruncate, target.control_end);
    let admitted = checkpoint_admission(
        control,
        authority,
        RootIdentity::read(path.parent().ok_or_else(invalid)?)?,
        target.control_end,
    );
    #[cfg(test)]
    wal_tests::admission_return(wal_tests::AdmissionStage::Pretruncate, &admitted);
    let current = match admitted {
        Ok(current) => current,
        Err(PortError::WriterBusy(_)) => {
            report.outcome = WalCheckpointOutcome::Deferred(WalDeferral::Fence);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if current.installation_id != target.policy.installation_id
        || current.policy_epoch != target.policy.policy_epoch
    {
        return Err(changed());
    }
    // File/privacy checks are independent of SQLite Busy and the control budget.
    control.validate_private_read(path, pin)?;
    control.validate_catalog_file(path)?;
    control.validate_live_root()?;
    report.wal_bytes_before = ManagedStore::wal_len(path)?;
    #[cfg(test)]
    wal_tests::observe_physical_attempt();
    let counts = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(checkpoint_storage);
    let (busy, log, checkpointed): (i64, i64, i64) = match counts {
        Ok(counts) => counts,
        Err(PortError::WriterBusy(_)) => {
            report.outcome = WalCheckpointOutcome::Deferred(WalDeferral::Sqlite);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    report.log_frames = log;
    report.checkpointed_frames = checkpointed;
    report.outcome = if busy != 0 {
        WalCheckpointOutcome::Deferred(WalDeferral::Sqlite)
    } else if log == -1 {
        WalCheckpointOutcome::NotApplicable
    } else {
        WalCheckpointOutcome::Reset
    };
    #[cfg(test)]
    wal_tests::after_checkpoint();
    Ok(())
}

fn observation_manifest(
    batch: &SourceBatch,
    o: &SourceObservation,
    context: &agent_session_grep_ports::source_context::SourcePublicationContext,
) -> PortResult<CanonicalBatchManifest> {
    // Commit the complete immutable input to a digest; no original transcript
    // text or native resume values are retained in the outbox detail columns.
    let claims: Vec<_> = batch
        .resume_claims
        .iter()
        .map(crate::resume_claim_value)
        .collect();
    let activities: Vec<_> = batch
        .activities
        .iter()
        .map(|a| serde_json::json!([a.message_id, a.activity]))
        .collect();
    let usages: Vec<_> = batch
        .usage_events
        .iter()
        .map(|u| serde_json::json!([u.session_id, u.message_id, u.usage]))
        .collect();
    let proofs: Vec<_> = o
        .selections
        .iter()
        .map(|p| serde_json::json!([p.selection_id, p.selection_revision, p.root_identity]))
        .collect();
    let context_bytes = crate::managed_source_context::context_manifest(context)?;
    let context_value: serde_json::Value =
        serde_json::from_slice(&context_bytes).map_err(|_| invalid())?;
    let value = serde_json::json!({"context":context_value,"format":"asg.managed-observation/v1","entries":batch.entries,"placements":batch.placements,"edges":batch.edges,"activities":activities,"usages":usages,"claims":claims,"complete":batch.relation_complete,"length":batch.len_bytes,"fingerprint":batch.fingerprint,"provider":batch.provider_id,
        "source":[o.binding.source_id.as_str(),o.binding.source_path,o.binding.provider.as_str(),o.binding.namespace_id,o.binding.root_identity],"revision":[o.revision_id.as_str(),o.revision_digest],"parser":o.parser_version,"state":format!("{:?}",o.state),"token":[o.cycle_seq,o.worker_boot_id],"incarnation":o.catalog_incarnation,"epoch":o.policy_epoch,"started":o.started_control_seq,"observed":o.observed_at_ms,"committed":o.committed_at_ms,"selections":proofs,"repositories":o.repositories});
    let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    Ok(CanonicalBatchManifest {
        upsert_ids: Vec::new(),
        delete_ids: Vec::new(),
        relation_upserts_json: "[]".into(),
        relation_deletes_json: "[]".into(),
        source_replacements_json:
            serde_json::json!([{"format":"asg.managed-observation/v1","digest":digest}]).to_string(),
        relocation_json: "null".into(),
        operation_digest: digest,
    })
}

#[cfg(test)]
mod setup_deadline_tests {
    use super::*;

    struct Observation {
        requested: Instant,
        expected: Instant,
        previous: Instant,
        probe: Instant,
        // API entry, policy read, restored read, catalog commit, final validation.
        counts: [usize; 5],
        expire_after_commit: bool,
    }

    thread_local! {
        static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
    }

    struct Recording;

    impl Recording {
        fn start(requested: Instant, expected: Instant, expire_after_commit: bool) -> Self {
            let probe = requested + Duration::from_secs(10);
            let previous = SqliteControlStore::effective_runtime_deadline(probe);
            OBSERVATION.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(Observation {
                    requested,
                    expected,
                    previous,
                    probe,
                    counts: [0; 5],
                    expire_after_commit,
                });
            });
            Self
        }

        fn finish(self) -> [usize; 5] {
            let observed = OBSERVATION.with(|slot| slot.borrow_mut().take().unwrap());
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(observed.probe),
                observed.previous,
                "catalog entry must restore the caller's scope"
            );
            observed.counts
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            OBSERVATION.with(|slot| *slot.borrow_mut() = None);
        }
    }

    pub(super) fn observe_entry(received: Instant) {
        OBSERVATION.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                assert_eq!(received, observed.requested, "catalog receiving end");
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(observed.probe),
                    observed.previous,
                    "the catalog entry must not own a whole-operation scope"
                );
                observed.counts[0] += 1;
            }
        });
    }

    pub(super) fn observe_policy() {
        OBSERVATION.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(observed.probe),
                    observed.expected,
                    "the real read_policy call must receive the original effective end"
                );
                observed.counts[1] += 1;
            }
        });
    }

    pub(super) fn observe_restored(received: Instant) {
        OBSERVATION.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                assert_eq!(received, observed.expected);
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(observed.probe),
                    observed.previous,
                    "admission must restore the scope before any catalog effect"
                );
                observed.counts[2] += 1;
            }
        });
    }

    pub(super) fn observe_commit() {
        let expire = OBSERVATION.with(|slot| {
            let mut slot = slot.borrow_mut();
            let observed = slot.as_mut()?;
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(observed.probe),
                observed.previous,
                "catalog COMMIT must not be inside the admission scope"
            );
            observed.counts[3] += 1;
            observed.expire_after_commit.then_some(observed.expected)
        });
        if let Some(end) = expire {
            std::thread::sleep(end.saturating_duration_since(Instant::now()));
            assert!(Instant::now() >= end);
        }
    }

    pub(super) fn observe_validated() {
        OBSERVATION.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(observed.probe),
                    observed.previous,
                    "final physical validation must retain the caller's scope"
                );
                observed.counts[4] += 1;
            }
        });
    }

    fn id(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, SqliteControlStore) {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let control = SqliteControlStore::create(
            &root,
            &id("setup-deadline-installation"),
            DesiredUpdates::Paused,
        )
        .unwrap();
        (temp, root, catalog, control)
    }

    fn assert_released(root: &Path) {
        drop(ExclusiveGuard::try_acquire(root, LockKind::CatalogHandles).unwrap());
        drop(WriterLease::try_acquire(root).unwrap());
    }

    #[test]
    fn setup_create_and_open_keep_original_admission_end_and_restore_scope() {
        for nested in [false, true] {
            let (_temp, root, catalog, control) = fixture();
            let before = control
                .with_runtime_deadline(Instant::now() + Duration::from_secs(5), || {
                    control.read_policy(RequestIntersection::Selected)
                })
                .unwrap();
            let end = Instant::now() + Duration::from_secs(5);
            let requested = end
                + if nested {
                    Duration::from_secs(1)
                } else {
                    Duration::ZERO
                };
            let run = || -> PortResult<()> {
                let recording = Recording::start(requested, end, false);
                let store = ManagedStore::create_with_deadline(
                    &catalog,
                    &control,
                    id("catalog"),
                    1,
                    requested,
                )?;
                assert_eq!(recording.finish(), [1, 1, 1, 1, 1]);
                assert_eq!(store.installation, before.installation_id);
                assert_eq!(store.incarnation(), &id("catalog"));
                drop(store);
                let recording = Recording::start(requested, end, false);
                let store = ManagedStore::open_with_deadline(&catalog, &control, requested)?;
                assert_eq!(recording.finish(), [1, 1, 1, 0, 1]);
                assert_eq!(store.installation, before.installation_id);
                assert_eq!(store.incarnation(), &id("catalog"));
                drop(store);
                assert_released(&root);
                Ok(())
            };
            if nested {
                control.with_runtime_deadline(end, run).unwrap();
            } else {
                run().unwrap();
            }
            let after = control
                .with_runtime_deadline(Instant::now() + Duration::from_secs(5), || control.status())
                .unwrap();
            assert_eq!(after.policy.installation_id, before.installation_id);
            assert_eq!(after.policy.control_seq, before.control_seq);
            assert_eq!(after.policy.policy_epoch, before.policy_epoch);
            assert_eq!(after.desired_updates, DesiredUpdates::Paused);
        }
    }

    #[test]
    fn expired_setup_admission_preserves_files_and_releases_handles() {
        let (_temp, root, catalog, control) = fixture();
        let expired = Instant::now() - Duration::from_millis(1);
        let recording = Recording::start(expired, expired, false);
        assert!(matches!(
            ManagedStore::create_with_deadline(&catalog, &control, id("catalog"), 1, expired),
            Err(PortError::WriterBusy(_))
        ));
        assert_eq!(recording.finish(), [1, 0, 1, 0, 0]);
        assert!(!catalog.exists());
        assert!(!creation_intent_path(&catalog).exists());
        assert_released(&root);

        drop(
            ManagedStore::create_with_deadline(
                &catalog,
                &control,
                id("catalog"),
                1,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap(),
        );
        let before = std::fs::read(&catalog).unwrap();
        let intent_before = std::fs::read(creation_intent_path(&catalog)).unwrap();
        let recording = Recording::start(expired, expired, false);
        assert!(matches!(
            ManagedStore::open_with_deadline(&catalog, &control, expired),
            Err(PortError::WriterBusy(_))
        ));
        assert_eq!(recording.finish(), [1, 0, 1, 0, 0]);
        assert_eq!(std::fs::read(&catalog).unwrap(), before);
        assert_eq!(
            std::fs::read(creation_intent_path(&catalog)).unwrap(),
            intent_before
        );
        assert_released(&root);
    }

    #[test]
    fn setup_admission_keeps_wrong_root_and_corrupt_catalog_refusals() {
        let (_temp, root, catalog, control) = fixture();
        let (_other_temp, _other_root, _other_catalog, other_control) = fixture();
        let end = Instant::now() + Duration::from_secs(5);
        let recording = Recording::start(end, end, false);
        assert!(matches!(
            ManagedStore::create_with_deadline(&catalog, &other_control, id("catalog"), 1, end),
            Err(PortError::InvalidRequest(_))
        ));
        assert_eq!(recording.finish(), [1, 0, 1, 0, 0]);
        assert!(!catalog.exists());
        assert!(!creation_intent_path(&catalog).exists());
        assert_released(&root);

        control.create_private_catalog_file(&catalog).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        let recording = Recording::start(end, end, false);
        assert!(matches!(
            ManagedStore::open_with_deadline(&catalog, &control, end),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert_eq!(recording.finish(), [1, 1, 1, 0, 0]);
        assert_eq!(std::fs::metadata(&catalog).unwrap().len(), 0);
        assert_released(&root);
    }

    #[test]
    fn catalog_commit_is_not_reversed_when_admission_end_expires() {
        let (_temp, root, catalog, control) = fixture();
        let end = Instant::now() + Duration::from_secs(5);
        let recording = Recording::start(end, end, true);
        let store = ManagedStore::create_with_deadline(&catalog, &control, id("catalog"), 1, end)
            .expect("a completed catalog commit must survive expiry of its earlier read end");
        assert!(Instant::now() >= end);
        assert_eq!(recording.finish(), [1, 1, 1, 1, 1]);
        assert_eq!(store.installation, id("setup-deadline-installation"));
        assert_eq!(store.incarnation(), &id("catalog"));
        let generation = store.inspected_generation().unwrap();
        drop(store);
        let reopened = ManagedStore::open_with_deadline(
            &catalog,
            &control,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(reopened.incarnation(), &id("catalog"));
        assert_eq!(reopened.inspected_generation().unwrap(), generation);
        drop(reopened);
        assert_released(&root);
    }
}

#[cfg(test)]
pub(crate) mod activation_deadline_tests {
    use super::*;

    struct Observation {
        expected: Instant,
        previous: Instant,
        probe: Instant,
        counts: [usize; 2],
    }

    thread_local! {
        static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
    }

    pub(crate) struct Recording;

    impl Recording {
        pub(crate) fn finish(self) -> [usize; 2] {
            let observed = OBSERVATION.with(|slot| slot.borrow_mut().take().unwrap());
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(observed.probe),
                observed.previous
            );
            observed.counts
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            OBSERVATION.with(|slot| *slot.borrow_mut() = None);
        }
    }

    pub(crate) fn record(expected: Instant) -> Recording {
        let probe = expected + Duration::from_secs(10);
        let previous = SqliteControlStore::effective_runtime_deadline(probe);
        OBSERVATION.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Observation {
                expected,
                previous,
                probe,
                counts: [0, 0],
            });
        });
        Recording
    }

    pub(super) fn observe(received: Instant, inside: bool) {
        OBSERVATION.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                assert_eq!(received, observed.expected);
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(observed.probe),
                    if inside {
                        observed.expected
                    } else {
                        observed.previous
                    },
                    "activation restores the status scope before catalog COMMIT"
                );
                observed.counts[usize::from(!inside)] += 1;
            }
        });
    }
}

#[cfg(test)]
mod baseline_deadline_tests {
    use super::*;
    use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
    use rusqlite::functions::FunctionFlags;
    use std::sync::{Arc, Mutex};

    const FINITE_SQL: &str = "WITH RECURSIVE n(x) AS (
        VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000)
        SELECT sum(x) FROM n";

    #[derive(Clone, Copy, Debug)]
    struct Query {
        same_connection: bool,
        busy_timeout: i64,
        sql_end: Instant,
        effective_end: Instant,
    }

    #[derive(Clone, Debug)]
    struct Observations {
        connection: *const Connection,
        query: Option<Query>,
        query_calls: u32,
        busy_calls: u32,
        first_busy_attempt: Option<i32>,
        retried: bool,
        progress_calls: u32,
        progress_end: Option<Instant>,
        progress_end_changed: bool,
        interrupted: bool,
        storage_error_calls: u32,
        storage_code: Option<rusqlite::ErrorCode>,
        storage_extended: Option<i32>,
        namespace_authorizations: u32,
        namespace_authorization_end: Option<Instant>,
        interrupt_namespace_resolution: bool,
        namespace_interrupt_installed: bool,
        namespace_interrupt_hits: u32,
    }

    thread_local! {
        static OBSERVATIONS: RefCell<Option<Observations>> = const { RefCell::new(None) };
    }

    struct Recording;
    impl Recording {
        fn start(connection: &Connection) -> Self {
            OBSERVATIONS.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(Observations {
                    connection,
                    query: None,
                    query_calls: 0,
                    busy_calls: 0,
                    first_busy_attempt: None,
                    retried: false,
                    progress_calls: 0,
                    progress_end: None,
                    progress_end_changed: false,
                    interrupted: false,
                    storage_error_calls: 0,
                    storage_code: None,
                    storage_extended: None,
                    namespace_authorizations: 0,
                    namespace_authorization_end: None,
                    interrupt_namespace_resolution: false,
                    namespace_interrupt_installed: false,
                    namespace_interrupt_hits: 0,
                });
            });
            Self
        }

        fn start_with_namespace_interrupt(connection: &Connection) -> Self {
            let recording = Self::start(connection);
            OBSERVATIONS.with(|slot| {
                slot.borrow_mut()
                    .as_mut()
                    .unwrap()
                    .interrupt_namespace_resolution = true;
            });
            recording
        }

        fn snapshot(&self) -> Observations {
            OBSERVATIONS.with(|slot| slot.borrow().as_ref().unwrap().clone())
        }
    }
    impl Drop for Recording {
        fn drop(&mut self) {
            OBSERVATIONS.with(|slot| slot.borrow_mut().take());
        }
    }

    pub(super) fn observe_namespace_authorization() {
        OBSERVATIONS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                observed.namespace_authorizations += 1;
                observed.namespace_authorization_end =
                    Some(SqliteControlStore::effective_runtime_deadline(
                        Instant::now() + Duration::from_secs(60),
                    ));
            }
        });
    }

    pub(super) fn observe_namespace_resolution(connection: &Connection) -> PortResult<()> {
        if !OBSERVATIONS.with(|slot| slot.borrow().is_some()) {
            return Ok(());
        }
        observe_query(
            connection,
            SqliteControlStore::effective_runtime_deadline(
                Instant::now() + Duration::from_secs(60),
            ),
        )?;
        let interrupt = OBSERVATIONS.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|observed| observed.interrupt_namespace_resolution)
        });
        if interrupt {
            connection
                .progress_handler(1, Some(observe_namespace_interrupt))
                .map_err(storage)?;
            OBSERVATIONS.with(|slot| {
                slot.borrow_mut()
                    .as_mut()
                    .unwrap()
                    .namespace_interrupt_installed = true;
            });
        }
        Ok(())
    }

    pub(super) fn observe_namespace_interrupt() -> bool {
        OBSERVATIONS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                observed.namespace_interrupt_hits =
                    observed.namespace_interrupt_hits.saturating_add(1);
            }
        });
        true
    }

    pub(super) fn observe_query(connection: &Connection, sql_end: Instant) -> PortResult<()> {
        if !OBSERVATIONS.with(|slot| slot.borrow().is_some()) {
            return Ok(());
        }
        let busy_timeout = connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .map_err(storage)?;
        OBSERVATIONS.with(|slot| {
            let mut slot = slot.borrow_mut();
            let observed = slot.as_mut().unwrap();
            observed.query_calls = observed.query_calls.saturating_add(1);
            observed.query.get_or_insert(Query {
                same_connection: std::ptr::eq(connection, observed.connection),
                busy_timeout,
                sql_end,
                effective_end: SqliteControlStore::effective_runtime_deadline(
                    sql_end + Duration::from_secs(5),
                ),
            });
        });
        let total: i64 = connection
            .query_row(FINITE_SQL, [], |row| row.get(0))
            .map_err(storage)?;
        assert_eq!(total, 50_005_000);
        Ok(())
    }

    pub(super) fn observe_busy(attempt: i32, retry: bool) {
        OBSERVATIONS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                observed.busy_calls = observed.busy_calls.saturating_add(1);
                observed.first_busy_attempt.get_or_insert(attempt);
                observed.retried |= retry;
            }
        });
    }

    pub(super) fn observe_progress(deadline: Instant, interrupted: bool) {
        OBSERVATIONS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                observed.progress_calls = observed.progress_calls.saturating_add(1);
                let first = observed.progress_end.get_or_insert(deadline);
                observed.progress_end_changed |= *first != deadline;
                observed.interrupted |= interrupted;
            }
        });
    }

    pub(super) fn observe_storage_error(error: &rusqlite::Error) {
        OBSERVATIONS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                if observed.storage_error_calls == 0 {
                    observed.storage_code = error.sqlite_error_code();
                    observed.storage_extended = match error {
                        rusqlite::Error::SqliteFailure(code, _) => Some(code.extended_code),
                        _ => None,
                    };
                }
                observed.storage_error_calls += 1;
            }
        });
    }

    fn publication_batch(observation: &SourceObservation, text: &str) -> SourceBatch {
        let native = |kind, value| StableId::native_checked(kind, value).unwrap();
        let message = native(IdKind::Message, "deadline-message");
        let session = native(IdKind::Session, "deadline-session");
        let document = native(IdKind::Document, "deadline-document");
        SourceBatch {
            source_path: observation.binding.source_path.clone(),
            entries: vec![
                (
                    message.clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "role": "user", "text": text, "timestamp": null
                    }))
                    .unwrap(),
                    text.into(),
                ),
                (
                    session.clone(),
                    serde_json::to_vec(&serde_json::json!({"documents": [document.as_str()]}))
                        .unwrap(),
                    String::new(),
                ),
                (
                    document.clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "provider": "claude-code", "variant": "synthetic",
                        "fingerprint": observation.revision_digest, "len": 100
                    }))
                    .unwrap(),
                    String::new(),
                ),
            ],
            placements: vec![MessagePlacement::new(
                session, document, message, 0, false, None,
            )],
            edges: Vec::new(),
            activities: Vec::new(),
            usage_events: Vec::new(),
            relation_complete: true,
            len_bytes: Some(100),
            fingerprint: Some(observation.revision_digest.clone()),
            provider_id: Some("claude-code".into()),
            resume_claims: Vec::new(),
        }
    }

    fn prepare_publication(
        fixture: &wal_tests::Fixture,
    ) -> (ManagedStore, SourceObservation, SourceBatch) {
        use agent_session_grep_ports::{
            control::CycleAdmission, managed::ObservationState,
            source_context::SourcePublicationContext,
        };
        let control = &fixture.control;
        let end = Instant::now() + Duration::from_secs(10);
        control
            .with_runtime_deadline(end, || {
                let selection = fixture.select();
                let worker = control.bind_worker(&fixture.worker_lock, wal_tests::id("boot"))?;
                control.register_worker(control.status()?.policy.control_seq, &worker, 1, 1)?;
                let admitted = control
                    .queue_cycle(
                        control.status()?.policy.control_seq,
                        vec![SelectionRevision {
                            selection_id: selection.id.clone(),
                            revision: selection.revision,
                            root_identity: selection.root_identity.clone().unwrap(),
                        }],
                    )?
                    .value;
                let CycleAdmission::Queued(cycle) = admitted else {
                    panic!("synthetic publication cycle was refused");
                };
                let cycle = control
                    .start_cycle(
                        control.status()?.policy.control_seq,
                        &worker,
                        cycle.token.cycle_seq,
                        2,
                    )?
                    .value;
                let store = ManagedStore::open_for_write(&fixture.catalog, control)?;
                let mut observation = SourceObservation {
                    binding: SourceBinding {
                        source_id: SourceId::parse("deadline-source")?,
                        source_path: selection.region.locator.as_str().into(),
                        provider: SearchProvider::Claude,
                        namespace_id: None,
                        root_identity: selection.root_identity.as_ref().unwrap().as_str().into(),
                    },
                    revision_id: RevisionId::parse("deadline-first")?,
                    revision_digest: "synthetic-original-digest".into(),
                    parser_version: 1,
                    state: ObservationState::Complete,
                    cycle_seq: cycle.token.cycle_seq.get(),
                    worker_boot_id: cycle.token.worker_boot_id.as_str().into(),
                    catalog_incarnation: "catalog".into(),
                    policy_epoch: cycle.policy_epoch.get(),
                    started_control_seq: cycle.started_control_seq.unwrap().get(),
                    observed_at_ms: 3,
                    committed_at_ms: 4,
                    selections: vec![SelectionProof {
                        selection_id: selection.id.as_str().into(),
                        selection_revision: selection.revision.get(),
                        root_identity: selection.root_identity.as_ref().unwrap().as_str().into(),
                    }],
                    repositories: Vec::new(),
                };
                let legacy =
                    agent_session_grep_application::relocation::legacy_installation_namespace(
                        &observation.binding.source_path,
                        "claude-code",
                    );
                let namespace = store.reserve_namespace_with_deadline(
                    control,
                    &observation,
                    &worker,
                    &legacy,
                    end,
                )?;
                observation.binding.namespace_id = Some(namespace.namespace_id);
                let batch = publication_batch(&observation, "original deadline evidence");
                let published = store.commit_source_with_context(
                    control,
                    &worker,
                    &batch,
                    &observation,
                    &SourcePublicationContext::default(),
                    end,
                )?;
                assert!(published.content_changed && published.receipt.published);
                assert_eq!(published.receipt.committed_generation, Some(1));
                observation.revision_id = RevisionId::parse("deadline-next")?;
                observation.revision_digest = "synthetic-next-digest".into();
                observation.observed_at_ms = 5;
                observation.committed_at_ms = 6;
                let next = publication_batch(&observation, "replacement deadline evidence");
                Ok((store, observation, next))
            })
            .unwrap()
    }

    type EvidenceRows = Vec<(&'static str, Vec<Vec<rusqlite::types::Value>>)>;

    fn publication_evidence(store: &ManagedStore) -> EvidenceRows {
        let conn = store.inner.conn.borrow();
        [
            "store_metadata",
            "catalog_meta",
            "source_heads",
            "source_revision_receipts",
            "source_projections",
            "source_scope_claims",
            "source_occurrences",
            "source_entity_projections",
            "source_session_projections",
            "source_publication_contexts",
            "source_context_heads",
            "source_scans",
            "catalog",
            "fts",
            "fts_ids",
        ]
        .into_iter()
        .map(|table| {
            let mut statement = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (table, rows)
        })
        .collect()
    }

    fn batch_states(store: &ManagedStore) -> Vec<(String, String, String)> {
        store
            .inner
            .conn
            .borrow()
            .prepare(
                "SELECT operation_id,state,durable_point FROM index_batches ORDER BY operation_id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    #[derive(Default)]
    struct TriggerObservation {
        end: Option<Instant>,
        wait: bool,
        calls: u32,
        received_end: Option<Instant>,
        entered_before_end: bool,
    }

    fn install_publication_trigger(store: &ManagedStore) -> Arc<Mutex<TriggerObservation>> {
        let observed = Arc::new(Mutex::new(TriggerObservation::default()));
        let hook = observed.clone();
        let conn = store.inner.conn.borrow();
        conn.create_scalar_function(
            "synthetic_publication_wait",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| {
                let (end, wait) = {
                    let mut observed = hook.lock().unwrap();
                    let end = observed.end.expect("original test end");
                    observed.calls += 1;
                    observed.received_end = Some(SqliteControlStore::effective_runtime_deadline(
                        end + Duration::from_secs(10),
                    ));
                    observed.entered_before_end = Instant::now() < end;
                    (end, observed.wait)
                };
                if wait {
                    // The real progress handler, not this callback, interrupts
                    // the INSERT. Never query or mutate its connection here.
                    while let Some(remaining) = end.checked_duration_since(Instant::now()) {
                        std::thread::sleep(remaining);
                    }
                }
                Ok(0_i64)
            },
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TEMP TRIGGER synthetic_publication_deadline
             BEFORE INSERT ON source_scans BEGIN
               SELECT synthetic_publication_wait();
               SELECT (WITH RECURSIVE n(x) AS
                 (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000)
                 SELECT sum(x) FROM n);
             END;",
        )
        .unwrap();
        observed
    }

    fn assert_publication_handlers_restored(
        store: &ManagedStore,
        recording: &Recording,
        original_end: Instant,
    ) {
        let before = recording.snapshot().progress_calls;
        let conn = store.inner.conn.borrow();
        assert!(
            conn.is_autocommit(),
            "the failed apply transaction is still active"
        );
        assert_eq!(
            conn.pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))
                .unwrap(),
            BUSY_TIMEOUT_MILLIS as i64
        );
        assert_eq!(
            conn.query_row(FINITE_SQL, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            50_005_000
        );
        assert_eq!(recording.snapshot().progress_calls, before);
        let probe = original_end + Duration::from_secs(10);
        assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    }

    #[test]
    fn namespace_deadline_expired_skips_authorization_and_resolution() {
        let fixture = wal_tests::Fixture::new();
        let (store, observation, _) = prepare_publication(&fixture);
        let worker = fixture
            .control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                fixture
                    .control
                    .bind_worker(&fixture.worker_lock, wal_tests::id("boot"))
            })
            .unwrap();
        let prior = publication_evidence(&store);
        let pending = store.inner.pending_installations.borrow().clone();
        let recording = Recording::start(&store.inner.conn.borrow());
        let end = Instant::now();
        let result = store.reserve_namespace_with_deadline(
            &fixture.control,
            &observation,
            &worker,
            "unused-expired-input",
            end,
        );
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        let observed = recording.snapshot();
        assert_eq!(observed.namespace_authorizations, 0);
        assert_eq!(observed.query_calls, 0);
        assert_eq!(*store.inner.pending_installations.borrow(), pending);
        assert_eq!(publication_evidence(&store), prior);
        assert_publication_handlers_restored(&store, &recording, end);
    }

    #[test]
    fn namespace_deadline_keeps_earlier_scope_and_committed_identity() {
        let fixture = wal_tests::Fixture::new();
        let (store, observation, _) = prepare_publication(&fixture);
        let control = &fixture.control;
        let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
            &observation.binding.source_path,
            observation.binding.provider.as_str(),
        );
        let (worker, expected) = control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                let worker = control.bind_worker(&fixture.worker_lock, wal_tests::id("boot"))?;
                let expected = store.reserve_namespace(control, &observation, &worker, &legacy)?;
                Ok((worker, expected))
            })
            .unwrap();
        let prior = publication_evidence(&store);
        let pending = store.inner.pending_installations.borrow().clone();
        let writes: i64 = store
            .inner
            .conn
            .borrow()
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        let recording = Recording::start(&store.inner.conn.borrow());
        let outer = Instant::now() + Duration::from_secs(10);
        let requested = outer + Duration::from_secs(10);
        let actual = control
            .with_runtime_deadline(outer, || {
                let result = store.reserve_namespace_with_deadline(
                    control,
                    &observation,
                    &worker,
                    &legacy,
                    requested,
                )?;
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(requested),
                    outer
                );
                Ok(result)
            })
            .unwrap();
        assert_eq!(actual.namespace_id, expected.namespace_id);
        assert_eq!(actual.input, expected.input);
        let observed = recording.snapshot();
        assert_eq!(observed.namespace_authorizations, 1);
        assert_eq!(observed.namespace_authorization_end, Some(outer));
        assert_eq!(observed.query_calls, 1);
        let query = observed.query.expect("namespace resolution was reached");
        assert!(query.same_connection);
        assert_eq!(query.sql_end, outer);
        assert_eq!(query.effective_end, outer);
        assert_eq!(query.busy_timeout, 0);
        assert!(observed.progress_calls > 0);
        assert_eq!(observed.progress_end, Some(outer));
        assert!(!observed.progress_end_changed);
        assert!(!observed.interrupted);
        assert!(!observed.retried);
        assert_publication_handlers_restored(&store, &recording, outer);
        assert_eq!(publication_evidence(&store), prior);
        assert_eq!(*store.inner.pending_installations.borrow(), pending);
        let after_writes: i64 = store
            .inner
            .conn
            .borrow()
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            after_writes, writes,
            "reservation must not persist identity or evidence"
        );
    }

    #[test]
    fn namespace_resolution_interrupt_is_busy_without_reserving_identity() {
        let fixture = wal_tests::Fixture::new();
        let (store, observation, _) = prepare_publication(&fixture);
        let control = &fixture.control;
        let worker = control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                control.bind_worker(&fixture.worker_lock, wal_tests::id("boot"))
            })
            .unwrap();
        let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
            &observation.binding.source_path,
            observation.binding.provider.as_str(),
        );
        let prior = publication_evidence(&store);
        let pending = store.inner.pending_installations.borrow().clone();
        let namespaces_before: i64 = store
            .inner
            .conn
            .borrow()
            .query_row("SELECT count(*) FROM installation_namespaces", [], |row| {
                row.get(0)
            })
            .unwrap();
        let writes_before: i64 = store
            .inner
            .conn
            .borrow()
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        let recording = Recording::start_with_namespace_interrupt(&store.inner.conn.borrow());
        let end = Instant::now() + Duration::from_secs(10);
        let result =
            store.reserve_namespace_with_deadline(control, &observation, &worker, &legacy, end);
        assert!(
            matches!(result, Err(PortError::WriterBusy(_))),
            "{result:?}"
        );
        let observed = recording.snapshot();
        assert_eq!(observed.namespace_authorizations, 1);
        assert_eq!(observed.namespace_authorization_end, Some(end));
        assert_eq!(observed.query_calls, 1);
        assert!(observed.namespace_interrupt_installed);
        assert!(observed.namespace_interrupt_hits > 0);
        assert_eq!(*store.inner.pending_installations.borrow(), pending);
        assert_eq!(publication_evidence(&store), prior);
        let namespaces_after: i64 = store
            .inner
            .conn
            .borrow()
            .query_row("SELECT count(*) FROM installation_namespaces", [], |row| {
                row.get(0)
            })
            .unwrap();
        let writes_after: i64 = store
            .inner
            .conn
            .borrow()
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(namespaces_after, namespaces_before);
        assert_eq!(writes_after, writes_before);
        assert_publication_handlers_restored(&store, &recording, end);
    }

    #[test]
    fn namespace_deadline_preserves_policy_and_source_refusals() {
        let fixture = wal_tests::Fixture::new();
        let (store, observation, _) = prepare_publication(&fixture);
        let control = &fixture.control;
        let worker = control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                control.bind_worker(&fixture.worker_lock, wal_tests::id("boot"))
            })
            .unwrap();
        let prior = publication_evidence(&store);
        let pending = store.inner.pending_installations.borrow().clone();
        for changed_epoch in [false, true] {
            let mut refused = observation.clone();
            if changed_epoch {
                refused.policy_epoch += 1;
            } else {
                refused.binding.provider = SearchProvider::Codex;
            }
            let end = Instant::now() + Duration::from_secs(10);
            let legacy_error = control
                .with_runtime_deadline(end, || {
                    store.reserve_namespace(control, &refused, &worker, "unused-refused-input")
                })
                .expect_err("legacy authorization must refuse");
            let recording = Recording::start(&store.inner.conn.borrow());
            let bounded_error = store
                .reserve_namespace_with_deadline(
                    control,
                    &refused,
                    &worker,
                    "unused-refused-input",
                    end,
                )
                .expect_err("bounded authorization must refuse");
            match (legacy_error, bounded_error) {
                (PortError::InvalidRequest(before), PortError::InvalidRequest(after))
                    if !changed_epoch =>
                {
                    assert_eq!(before, after);
                }
                (PortError::GenerationMismatch(before), PortError::GenerationMismatch(after))
                    if changed_epoch =>
                {
                    assert_eq!(before, after);
                }
                (before, after) => panic!("namespace refusal changed: {before:?}, {after:?}"),
            }
            let observed = recording.snapshot();
            assert_eq!(observed.namespace_authorizations, 1);
            assert_eq!(observed.namespace_authorization_end, Some(end));
            assert_eq!(observed.query_calls, 0);
            assert_publication_handlers_restored(&store, &recording, end);
            assert_eq!(publication_evidence(&store), prior);
            assert_eq!(*store.inner.pending_installations.borrow(), pending);
        }
    }

    #[test]
    fn publication_insert_interrupt_is_busy_and_preserves_prior_evidence() {
        use agent_session_grep_ports::source_context::SourcePublicationContext;
        let fixture = wal_tests::Fixture::new();
        let (store, observation, batch) = prepare_publication(&fixture);
        let worker = fixture
            .control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                fixture
                    .control
                    .bind_worker(&fixture.worker_lock, wal_tests::id("boot"))
            })
            .unwrap();
        let prior = publication_evidence(&store);
        let prior_batches = batch_states(&store);
        assert_eq!(prior_batches.len(), 1);
        assert_eq!(prior_batches[0].1, "activated");
        let trigger = install_publication_trigger(&store);
        let recording = Recording::start(&store.inner.conn.borrow());
        let original_end = Instant::now() + Duration::from_secs(10);
        {
            let mut observed = trigger.lock().unwrap();
            observed.end = Some(original_end);
            observed.wait = true;
        }
        let result = store.commit_source_with_context(
            &fixture.control,
            &worker,
            &batch,
            &observation,
            &SourcePublicationContext::default(),
            original_end,
        );
        let observed = recording.snapshot();
        assert_eq!(
            trigger.lock().unwrap().calls,
            1,
            "INSERT trigger was not reached once"
        );
        assert!(trigger.lock().unwrap().entered_before_end);
        assert_eq!(trigger.lock().unwrap().received_end, Some(original_end));
        assert!(observed.interrupted, "{observed:?}");
        assert_eq!(observed.progress_end, Some(original_end));
        assert!(!observed.progress_end_changed);
        assert_eq!(observed.storage_error_calls, 1, "{observed:?}");
        assert_eq!(
            observed.storage_code,
            Some(rusqlite::ErrorCode::OperationInterrupted)
        );
        assert_eq!(
            observed.storage_extended,
            Some(rusqlite::ffi::SQLITE_INTERRUPT)
        );
        assert!(
            matches!(result, Err(PortError::WriterBusy(_))),
            "{result:?}"
        );
        assert_publication_handlers_restored(&store, &recording, original_end);
        assert_eq!(publication_evidence(&store), prior);
        let after_batches = batch_states(&store);
        assert!(after_batches.contains(&prior_batches[0]));
        let pending = after_batches
            .iter()
            .filter(|row| row.1 == "building")
            .collect::<Vec<_>>();
        assert_eq!(after_batches.len(), prior_batches.len() + 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].2, "intent");
        let operation = pending[0].0.clone();
        drop(recording);
        drop(store);

        let recovered = fixture
            .control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                ManagedStore::open_for_write(&fixture.catalog, &fixture.control)
            })
            .unwrap();
        assert_eq!(publication_evidence(&recovered), prior);
        let recovered_batches = batch_states(&recovered);
        assert!(recovered_batches.contains(&prior_batches[0]));
        assert_eq!(recovered_batches.len(), after_batches.len());
        assert_eq!(
            recovered_batches
                .iter()
                .find(|row| row.0 == operation)
                .unwrap()
                .1,
            "aborted"
        );
        assert!(!recovered_batches.iter().any(|row| row.1 == "building"));
    }

    #[test]
    fn publication_insert_without_expiry_commits_and_restores_handlers() {
        use agent_session_grep_ports::source_context::SourcePublicationContext;
        let fixture = wal_tests::Fixture::new();
        let (store, observation, batch) = prepare_publication(&fixture);
        let worker = fixture
            .control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                fixture
                    .control
                    .bind_worker(&fixture.worker_lock, wal_tests::id("boot"))
            })
            .unwrap();
        let trigger = install_publication_trigger(&store);
        let recording = Recording::start(&store.inner.conn.borrow());
        let original_end = Instant::now() + Duration::from_secs(10);
        trigger.lock().unwrap().end = Some(original_end);
        let publication = store
            .commit_source_with_context(
                &fixture.control,
                &worker,
                &batch,
                &observation,
                &SourcePublicationContext::default(),
                original_end,
            )
            .unwrap();
        assert_eq!(trigger.lock().unwrap().calls, 1);
        assert_eq!(trigger.lock().unwrap().received_end, Some(original_end));
        assert!(publication.content_changed && publication.receipt.published);
        assert_eq!(publication.receipt.revision_id, observation.revision_id);
        assert_eq!(publication.receipt.committed_generation, Some(2));
        assert!(!recording.snapshot().interrupted);
        assert_eq!(recording.snapshot().storage_error_calls, 0);
        assert_publication_handlers_restored(&store, &recording, original_end);
        assert!(batch_states(&store).iter().all(|row| row.1 == "activated"));
        assert_eq!(batch_states(&store).len(), 2);
    }

    #[test]
    fn publication_missing_column_remains_schema_incompatible() {
        use agent_session_grep_ports::source_context::SourcePublicationContext;
        let fixture = wal_tests::Fixture::new();
        let (store, observation, batch) = prepare_publication(&fixture);
        let worker = fixture
            .control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                fixture
                    .control
                    .bind_worker(&fixture.worker_lock, wal_tests::id("boot"))
            })
            .unwrap();
        store
            .inner
            .conn
            .borrow()
            .execute_batch(
                "ALTER TABLE source_scans RENAME COLUMN parser_version TO synthetic_missing_column",
            )
            .unwrap();
        let prior = publication_evidence(&store);
        let recording = Recording::start(&store.inner.conn.borrow());
        let original_end = Instant::now() + Duration::from_secs(10);
        let result = store.commit_source_with_context(
            &fixture.control,
            &worker,
            &batch,
            &observation,
            &SourcePublicationContext::default(),
            original_end,
        );
        let observed = recording.snapshot();
        assert!(
            matches!(result, Err(PortError::SchemaIncompatible(_))),
            "{result:?}"
        );
        assert!(!observed.interrupted);
        assert_eq!(observed.storage_error_calls, 1);
        assert_eq!(observed.storage_extended, Some(rusqlite::ffi::SQLITE_ERROR));
        assert_publication_handlers_restored(&store, &recording, original_end);
        assert_eq!(publication_evidence(&store), prior);
    }

    #[test]
    fn plain_baselines_scope_real_query_and_restore_handlers_after_success_and_busy() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let id = |value| ControlId::parse(value).unwrap();
        let control =
            SqliteControlStore::create(&root, &id("installation"), DesiredUpdates::Running)
                .unwrap();
        let preparation_end = Instant::now() + Duration::from_secs(5);
        let (blocker, store) = control
            .with_runtime_deadline(preparation_end, || {
                drop(ManagedStore::create(&catalog, &control, id("catalog"), 1)?);
                let blocker = Connection::open(&catalog).map_err(storage)?;
                let mode: String = blocker
                    .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
                    .map_err(storage)?;
                assert_eq!(mode, "delete");
                Ok((blocker, ManagedStore::open(&catalog, &control)?))
            })
            .unwrap();
        for blocked in [true, false] {
            if blocked {
                blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
            }
            let recording = Recording::start(&store.inner.conn.borrow());
            let original_end = Instant::now() + Duration::from_secs(1);
            let requested_end = original_end + Duration::from_secs(5);
            let probe = requested_end + Duration::from_secs(5);
            let previous_end = SqliteControlStore::effective_runtime_deadline(probe);
            let result = control.with_runtime_deadline(original_end, || {
                let result = store.current_plain_baselines(&control, requested_end);
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(probe),
                    original_end
                );
                result
            });
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                previous_end
            );
            let observed = recording.snapshot();
            assert_eq!(observed.query_calls, 1, "{observed:?}");
            let query = observed.query.expect("the real baseline query was reached");
            assert!(query.same_connection);
            assert_eq!(query.busy_timeout, 0, "{observed:?}");
            assert_eq!(query.sql_end, original_end);
            assert_eq!(query.effective_end, original_end);
            assert!(!observed.retried, "{observed:?}");
            assert!(observed.progress_calls > 0, "{observed:?}");
            assert_eq!(observed.progress_end, Some(original_end));
            assert!(!observed.progress_end_changed);
            assert!(!observed.interrupted);
            if blocked {
                assert!(
                    matches!(result, Err(PortError::WriterBusy(reason)) if reason == "managed catalog is busy")
                );
                assert_eq!(observed.busy_calls, 1, "{observed:?}");
                assert_eq!(observed.first_busy_attempt, Some(0));
                drop(ExclusiveGuard::try_acquire(&root, LockKind::HistoryReaders).unwrap());
                blocker.execute_batch("ROLLBACK").unwrap();
            } else {
                assert!(result.unwrap().is_empty());
                assert_eq!(observed.busy_calls, 0, "{observed:?}");
            }
            let conn = store.inner.conn.borrow();
            assert_eq!(
                conn.pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))
                    .unwrap(),
                BUSY_TIMEOUT_MILLIS as i64
            );
            let total: i64 = conn.query_row(FINITE_SQL, [], |row| row.get(0)).unwrap();
            assert_eq!(total, 50_005_000);
            assert_eq!(
                recording.snapshot().progress_calls,
                observed.progress_calls,
                "the old deadline callback must be cleared, even before its end"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod wal_tests {
    use super::*;
    use agent_session_grep_ports::control::{
        MaintenanceFence, MaintenancePhase, RootKind, ScopeRegion, SelectionRequest,
    };

    thread_local! {
        pub(super) static LIMIT: Cell<Option<i64>> = const { Cell::new(None) };
        pub(super) static CONTROL_END: Cell<Option<Instant>> = const { Cell::new(None) };
        static AFTER_CHECKPOINT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        static BEFORE_CHECKPOINT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        static AFTER_CLOSE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        static PRAGMAS: RefCell<Vec<(i64, i64, i64, i64)>> = const { RefCell::new(Vec::new()) };
        static PREPARED_CHECKPOINT: RefCell<Option<PreparedCheckpoint>> = const { RefCell::new(None) };
        static ADMISSION_DIAGNOSTIC: RefCell<Option<AdmissionDiagnostic>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Copy)]
    pub(super) enum AdmissionStage {
        Initial,
        Pretruncate,
    }

    impl AdmissionStage {
        fn index(self) -> usize {
            match self {
                Self::Initial => 0,
                Self::Pretruncate => 1,
            }
        }
    }

    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    struct AdmissionDiagnostic {
        slots: [Option<AdmissionObservation>; 2],
        physical_attempts: usize,
        unexpected_observation: bool,
    }

    impl std::fmt::Debug for AdmissionDiagnostic {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WalAdmissions")
                .field("initial", &self.slots[0])
                .field("pretruncate", &self.slots[1])
                .field("physical_attempts", &self.physical_attempts)
                .field("unexpected_observation", &self.unexpected_observation)
                .finish()
        }
    }

    struct ObserveAdmissions {
        previous: Option<AdmissionDiagnostic>,
    }

    impl ObserveAdmissions {
        fn start() -> Self {
            Self {
                previous: ADMISSION_DIAGNOSTIC
                    .with(|slot| slot.replace(Some(AdmissionDiagnostic::default()))),
            }
        }

        fn snapshot(&self) -> AdmissionDiagnostic {
            ADMISSION_DIAGNOSTIC.with(|slot| (*slot.borrow()).unwrap())
        }
    }

    impl Drop for ObserveAdmissions {
        fn drop(&mut self) {
            ADMISSION_DIAGNOSTIC.with(|slot| *slot.borrow_mut() = self.previous.take());
        }
    }

    // Enabled only by the targeted tests and collector regressions. No TLS
    // borrow spans admission; disabled observation samples no clocks or errors.
    pub(super) fn admission_enter(stage: AdmissionStage, end: Instant) {
        ADMISSION_DIAGNOSTIC.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(observed) = slot.as_mut() else {
                return;
            };
            if observed.slots[stage.index()].is_some() {
                observed.unexpected_observation = true;
                return;
            }
            let effective_end = SqliteControlStore::effective_runtime_deadline(end);
            observed.slots[stage.index()] = Some(AdmissionObservation {
                requested_end: end,
                effective_end,
                entered_remaining_us: remaining_us(effective_end, Instant::now()),
                returned_remaining_us: None,
                result: None,
            });
        });
    }

    pub(super) fn admission_return<T>(stage: AdmissionStage, result: &PortResult<T>) {
        ADMISSION_DIAGNOSTIC.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(observed) = slot.as_mut() else {
                return;
            };
            let Some(entry) = observed.slots[stage.index()].as_mut() else {
                observed.unexpected_observation = true;
                return;
            };
            if entry.result.is_some() {
                observed.unexpected_observation = true;
                return;
            }
            entry.returned_remaining_us = Some(remaining_us(entry.effective_end, Instant::now()));
            entry.result = Some(admission_result(result));
        });
    }

    #[test]
    fn wal_admission_diagnostic_classifies_only_exact_errors() {
        assert_eq!(admission_result(&Ok::<_, PortError>(())), "ok");
        for (message, expected) in [
            ("control runtime deadline reached", "deadline"),
            ("control storage is busy", "control_busy"),
            ("managed control fence is active", "active_fence"),
            ("control runtime deadline reached extra", "other"),
            ("unclassified synthetic refusal", "other"),
        ] {
            let result: PortResult<()> = Err(PortError::WriterBusy(message.into()));
            assert_eq!(admission_result(&result), expected);
        }
        let result: PortResult<()> = Err(PortError::Backend(
            "control runtime deadline reached".into(),
        ));
        assert_eq!(admission_result(&result), "other");
        let now = Instant::now();
        assert_eq!(remaining_us(now, now), 0);
        assert_eq!(remaining_us(now + Duration::from_micros(1), now), 1);
        assert_eq!(remaining_us(now, now + Duration::from_micros(1)), -1);
    }

    #[test]
    fn wal_admission_diagnostic_restores_nested_collectors_and_unwind() {
        let previous = ADMISSION_DIAGNOSTIC.with(|slot| *slot.borrow());
        {
            let outer = ObserveAdmissions::start();
            let end = Instant::now() + Duration::from_secs(1);
            admission_enter(AdmissionStage::Initial, end);
            let entered = outer.snapshot().slots[0].unwrap();
            assert_eq!(entered.requested_end, end);
            assert_eq!(
                entered.effective_end,
                SqliteControlStore::effective_runtime_deadline(end)
            );
            assert_eq!(entered.returned_remaining_us, None);
            assert_eq!(entered.result, None);
            let result: PortResult<()> = Err(PortError::WriterBusy(
                "control runtime deadline reached".into(),
            ));
            admission_return(AdmissionStage::Initial, &result);
            let retained = outer.snapshot();
            assert_eq!(retained.slots[0].unwrap().result, Some("deadline"));
            assert!(retained.slots[0].unwrap().returned_remaining_us.is_some());
            {
                let inner = ObserveAdmissions::start();
                assert_eq!(inner.snapshot(), AdmissionDiagnostic::default());
                admission_enter(AdmissionStage::Initial, end);
                admission_return(AdmissionStage::Initial, &Ok::<_, PortError>(()));
                admission_enter(AdmissionStage::Pretruncate, end);
                admission_return(AdmissionStage::Pretruncate, &Ok::<_, PortError>(()));
                observe_physical_attempt();
                let observed = inner.snapshot();
                assert_eq!(observed.slots[0].unwrap().result, Some("ok"));
                assert_eq!(observed.slots[1].unwrap().result, Some("ok"));
                assert_eq!(observed.physical_attempts, 1);
                admission_enter(AdmissionStage::Initial, end + Duration::from_secs(1));
                assert_eq!(inner.snapshot().slots, observed.slots);
                assert!(inner.snapshot().unexpected_observation);
            }
            assert_eq!(outer.snapshot(), retained);
            let unwound = std::panic::catch_unwind(|| {
                let inner = ObserveAdmissions::start();
                admission_enter(AdmissionStage::Initial, end);
                let result: PortResult<()> = Err(PortError::WriterBusy(
                    "unclassified synthetic refusal".into(),
                ));
                admission_return(AdmissionStage::Initial, &result);
                assert_eq!(inner.snapshot().slots[0].unwrap().result, Some("other"));
                assert!(!format!("{:?}", inner.snapshot()).contains("unclassified synthetic"));
                admission_enter(AdmissionStage::Pretruncate, end);
                assert_eq!(inner.snapshot().slots[1].unwrap().result, None);
                panic!("synthetic admission observer unwind");
            });
            assert!(unwound.is_err());
            assert_eq!(outer.snapshot(), retained);
        }
        assert_eq!(ADMISSION_DIAGNOSTIC.with(|slot| *slot.borrow()), previous);
    }

    struct PreparedCheckpoint {
        end: Instant,
        admissions: usize,
        physical_attempts: usize,
    }

    struct ObservePreparedCheckpoint {
        previous_end: Option<Instant>,
        previous_observer: Option<PreparedCheckpoint>,
    }

    impl ObservePreparedCheckpoint {
        fn start(end: Instant) -> Self {
            Self {
                previous_end: CONTROL_END.with(|slot| slot.replace(Some(end))),
                previous_observer: PREPARED_CHECKPOINT.with(|slot| {
                    slot.replace(Some(PreparedCheckpoint {
                        end,
                        admissions: 0,
                        physical_attempts: 0,
                    }))
                }),
            }
        }

        fn finish(self) -> (usize, usize) {
            let observed = PREPARED_CHECKPOINT.with(|slot| slot.borrow_mut().take().unwrap());
            (observed.admissions, observed.physical_attempts)
        }
    }

    impl Drop for ObservePreparedCheckpoint {
        fn drop(&mut self) {
            CONTROL_END.with(|slot| slot.set(self.previous_end));
            PREPARED_CHECKPOINT.with(|slot| *slot.borrow_mut() = self.previous_observer.take());
        }
    }

    pub(super) fn observe_admission_end(end: Instant) {
        PREPARED_CHECKPOINT.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                assert_eq!(end, observed.end, "prepared checkpoint admission end");
                observed.admissions += 1;
            }
        });
    }

    pub(super) fn observe_physical_attempt() {
        PREPARED_CHECKPOINT.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                observed.physical_attempts += 1;
            }
        });
        ADMISSION_DIAGNOSTIC.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                observed.physical_attempts = observed.physical_attempts.saturating_add(1);
            }
        });
    }

    pub(super) fn after_checkpoint() {
        AFTER_CHECKPOINT.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
    }

    pub(super) fn before_checkpoint() {
        BEFORE_CHECKPOINT.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
    }

    pub(super) fn after_close() {
        AFTER_CLOSE.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
    }

    pub(super) fn record_pragmas(conn: &Connection) {
        PRAGMAS.with(|records| records.borrow_mut().push(pragmas(conn)));
    }

    pub(crate) fn take_pragmas() -> Vec<(i64, i64, i64, i64)> {
        PRAGMAS.with(|records| std::mem::take(&mut *records.borrow_mut()))
    }

    pub(crate) fn pragmas(conn: &Connection) -> (i64, i64, i64, i64) {
        let value = |key| {
            conn.pragma_query_value(None, key, |row| row.get(0))
                .unwrap()
        };
        (
            value("journal_size_limit"),
            value("synchronous"),
            value("wal_autocheckpoint"),
            value("busy_timeout"),
        )
    }

    pub(crate) fn id(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }

    pub(crate) struct Fixture {
        pub(crate) control: SqliteControlStore,
        pub(super) worker_lock: ExclusiveGuard,
        pub(crate) catalog: PathBuf,
        pub(crate) root: PathBuf,
        _temp: tempfile::TempDir,
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let root = temp.path().join("private");
            let control =
                SqliteControlStore::create(&root, &id("installation"), DesiredUpdates::Running)
                    .unwrap();
            let catalog = root.join("catalog.db");
            drop(ManagedStore::create(&catalog, &control, id("catalog"), 1).unwrap());
            let worker_lock = ExclusiveGuard::try_acquire(&root, LockKind::Background).unwrap();
            Self {
                control,
                worker_lock,
                catalog,
                root,
                _temp: temp,
            }
        }

        fn checkpoint(&self) -> PortResult<WalCheckpointReport> {
            let authority = self
                .control
                .bind_worker(&self.worker_lock, id("boot"))
                .unwrap();
            ManagedStore::checkpoint_wal(&self.catalog, &self.control, &authority, None)
        }

        fn reader(&self) -> Connection {
            let conn = connect(&self.catalog, false).unwrap();
            conn.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
            conn
        }

        fn seed(&self) -> Connection {
            let conn = connect(&self.catalog, true).unwrap();
            conn.execute_batch(
                "CREATE TABLE wal_fixture(id INTEGER PRIMARY KEY, proof TEXT, body BLOB);
                INSERT INTO wal_fixture VALUES(1,'proof-one',zeroblob(4096));",
            )
            .unwrap();
            conn
        }

        pub(crate) fn select(&self) -> agent_session_grep_ports::control::Selection {
            self.control
                .add_selection(
                    self.control.status().unwrap().policy.control_seq,
                    SelectionRequest {
                        region: ScopeRegion {
                            provider: SearchProvider::Claude,
                            locator: CanonicalLocator::from_path(
                                &self._temp.path().join("source.jsonl"),
                            )
                            .unwrap(),
                            kind: RootKind::Exact,
                        },
                        root_identity: Some(id("source-root")),
                        now_ms: 1,
                    },
                )
                .unwrap()
                .value
        }

        fn desired(&self, desired: DesiredUpdates) {
            self.control
                .set_desired_updates(self.control.status().unwrap().policy.control_seq, desired)
                .unwrap();
        }
    }

    fn snapshot(conn: &Connection) -> (i64, String) {
        conn.query_row("SELECT count(*),min(proof) FROM wal_fixture", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
    }

    fn report_initial_observation(
        report: &WalCheckpointReport,
        observed: &AdmissionDiagnostic,
    ) -> AdmissionObservation {
        let initial = report
            .initial_admission
            .expect("initial admission was called");
        let enclosing = observed.slots[0].unwrap();
        assert_eq!(initial.requested_end, enclosing.requested_end);
        assert_eq!(initial.effective_end, enclosing.effective_end);
        assert_eq!(initial.result, enclosing.result);
        // Existing hooks bracket the exact production observation and one call.
        assert!(initial.entered_remaining_us <= enclosing.entered_remaining_us);
        let returned = initial.returned_remaining_us.unwrap();
        assert!(returned >= enclosing.returned_remaining_us.unwrap());
        assert!(initial.entered_remaining_us >= returned);
        assert!(!observed.unexpected_observation);
        initial
    }

    #[test]
    fn wal_checkpoint_initial_report_records_healthy_call_order() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let reader = fixture.reader();
        let before = snapshot(&reader);
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        // Reuse the existing prepared-fixture end for the diagnostic checks.
        // The production checkpoint's 250ms admission end is unchanged.
        let end = Instant::now() + Duration::from_secs(5);
        let prepared = ObservePreparedCheckpoint::start(end);
        let diagnostic = ObserveAdmissions::start();
        let report =
            ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None)
                .unwrap();
        assert_eq!(report.outcome, WalCheckpointOutcome::Reset);
        let observed = diagnostic.snapshot();
        let initial = report_initial_observation(&report, &observed);
        let pretruncate = observed.slots[1].unwrap();
        assert_eq!(initial.requested_end, end);
        assert_eq!(initial.effective_end, end);
        assert_eq!(initial.result, Some("ok"));
        assert_eq!(pretruncate.result, Some("ok"));
        assert_eq!(pretruncate.requested_end, end);
        assert_eq!(pretruncate.effective_end, end);
        assert!(initial.returned_remaining_us.unwrap() >= pretruncate.entered_remaining_us);
        assert_eq!(observed.physical_attempts, 1);
        assert_eq!(prepared.finish(), (2, 1));
        drop(diagnostic);
        let cloned = report.clone();
        assert_eq!(cloned.initial_admission, Some(initial));
        assert!(format!("{cloned:?}").contains("initial_admission: Some(AdmissionObservation"));
        assert_eq!(report.wal_bytes_after, Some(0));
        assert_eq!(snapshot(&reader), before);
    }

    #[test]
    fn wal_checkpoint_initial_report_records_fence_under_earlier_nested_end() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let _reader = fixture.reader();
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        fixture
            .control
            .set_maintenance(
                fixture.control.status().unwrap().policy.control_seq,
                &id("owner"),
                MaintenanceFence {
                    state: MaintenanceState::Updating,
                    owner: Some(id("owner")),
                    phase: Some(MaintenancePhase::Quiescing),
                },
            )
            .unwrap();
        let before = std::fs::read(&fixture.catalog).unwrap();
        let wal = std::fs::read(fixture.root.join("catalog.db-wal")).unwrap();
        take_pragmas();
        let requested_end = Instant::now() + Duration::from_secs(5);
        let earlier_end = requested_end - Duration::from_secs(1);
        let probe = requested_end + Duration::from_secs(1);
        let previous_end = SqliteControlStore::effective_runtime_deadline(probe);
        let prepared = ObservePreparedCheckpoint::start(requested_end);
        let diagnostic = ObserveAdmissions::start();
        let report = fixture
            .control
            .with_runtime_deadline(earlier_end, || {
                fixture.control.with_runtime_deadline(requested_end, || {
                    ManagedStore::checkpoint_wal(
                        &fixture.catalog,
                        &fixture.control,
                        &authority,
                        None,
                    )
                })
            })
            .unwrap();
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            previous_end
        );
        assert_eq!(
            report.outcome,
            WalCheckpointOutcome::Deferred(WalDeferral::Fence)
        );
        let observed = diagnostic.snapshot();
        let initial = report_initial_observation(&report, &observed);
        assert_eq!(initial.requested_end, requested_end);
        assert_eq!(initial.effective_end, earlier_end);
        assert_eq!(initial.result, Some("active_fence"));
        assert!(initial.entered_remaining_us > 0);
        assert!(initial.returned_remaining_us.unwrap() > 0);
        assert_eq!(observed.slots[1], None);
        assert_eq!(observed.physical_attempts, 0);
        assert_eq!(prepared.finish(), (1, 0));
        assert!(report.incarnation.is_none());
        assert!(report.wal_bytes_before.is_none());
        assert!(take_pragmas().is_empty());
        assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
        assert_eq!(
            std::fs::read(fixture.root.join("catalog.db-wal")).unwrap(),
            wal
        );
    }

    #[test]
    fn wal_checkpoint_initial_report_records_expiry_without_catalog_open() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let _reader = fixture.reader();
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        let before = std::fs::read(&fixture.catalog).unwrap();
        let wal = std::fs::read(fixture.root.join("catalog.db-wal")).unwrap();
        take_pragmas();
        let expired = Instant::now();
        let prepared = ObservePreparedCheckpoint::start(expired);
        let diagnostic = ObserveAdmissions::start();
        let report =
            ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None)
                .unwrap();
        assert_eq!(
            report.outcome,
            WalCheckpointOutcome::Deferred(WalDeferral::Fence)
        );
        let observed = diagnostic.snapshot();
        let initial = report_initial_observation(&report, &observed);
        assert_eq!(initial.requested_end, expired);
        assert_eq!(initial.effective_end, expired);
        assert_eq!(initial.result, Some("deadline"));
        assert!(initial.entered_remaining_us <= 0);
        assert!(initial.returned_remaining_us.unwrap() <= 0);
        assert_eq!(observed.slots[1], None);
        assert_eq!(observed.physical_attempts, 0);
        assert_eq!(prepared.finish(), (1, 0));
        assert!(CONTROL_END.with(|slot| slot.get().is_none()));
        assert!(report.incarnation.is_none());
        assert!(report.wal_bytes_before.is_none());
        assert!(take_pragmas().is_empty());
        assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
        assert_eq!(
            std::fs::read(fixture.root.join("catalog.db-wal")).unwrap(),
            wal
        );
    }

    #[test]
    fn wal_checkpoint_preserves_pinned_rows_then_resets_after_reader_gap() {
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let reader = fixture.reader();
        reader.execute_batch("BEGIN").unwrap();
        let before = snapshot(&reader);
        writer
            .execute_batch(
                "INSERT INTO wal_fixture SELECT 2,'proof-two',zeroblob(4096);
            UPDATE wal_fixture SET proof='proof-new' WHERE id=1;",
            )
            .unwrap();
        let bytes = ManagedStore::wal_len(&fixture.catalog).unwrap();
        let report = fixture.checkpoint().unwrap();
        assert_eq!(
            report.outcome,
            WalCheckpointOutcome::Deferred(WalDeferral::Sqlite)
        );
        assert!(report.checkpointed_frames < report.log_frames);
        assert_eq!(report.wal_bytes_before, bytes);
        assert_eq!(report.wal_bytes_after, bytes);
        assert_eq!(snapshot(&reader), before);
        reader.execute_batch("COMMIT").unwrap();
        let report = fixture.checkpoint().unwrap();
        assert_eq!(report.outcome, WalCheckpointOutcome::Reset);
        assert_eq!(report.incarnation, Some(id("catalog")));
        assert_eq!(report.wal_bytes_after, Some(0));
        assert_eq!(snapshot(&fixture.reader()), (2, "proof-new".into()));
        assert_eq!(
            reader
                .query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert_eq!(
            reader
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn wal_checkpoint_sqlite_writer_contention_uses_zero_busy_timeout() {
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let _idle = fixture.reader();
        writer
            .execute_batch("BEGIN IMMEDIATE; UPDATE wal_fixture SET proof='uncommitted';")
            .unwrap();
        PRAGMAS.with(|values| values.borrow_mut().clear());
        let diagnostic = ObserveAdmissions::start();
        let report = fixture.checkpoint().unwrap();
        assert_eq!(
            report.outcome,
            WalCheckpointOutcome::Deferred(WalDeferral::Sqlite),
            "WAL admission diagnostic: incarnation_present={} frames=({}, {}) {:?}",
            report.incarnation.is_some(),
            report.log_frames,
            report.checkpointed_frames,
            diagnostic.snapshot()
        );
        drop(diagnostic);
        assert!(report.log_frames >= 0);
        assert_eq!(report.log_frames, report.checkpointed_frames);
        assert_eq!(
            PRAGMAS.with(|values| values.borrow().clone()),
            [(JOURNAL_SIZE_LIMIT_BYTES, 2, 1000, 0)]
        );
        writer.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn wal_checkpoint_result_survives_expired_control_time_after_physical_attempt() {
        for pinned in [false, true] {
            let fixture = Fixture::new();
            let writer = fixture.seed();
            let reader = fixture.reader();
            if pinned {
                reader.execute_batch("BEGIN").unwrap();
                snapshot(&reader);
            }
            writer
                .execute("UPDATE wal_fixture SET proof='later'", [])
                .unwrap();
            let observer = SqliteControlStore::open_current_read_only(&fixture.root).unwrap();
            let called = std::rc::Rc::new(Cell::new(false));
            AFTER_CHECKPOINT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new({
                    let called = called.clone();
                    move || {
                        let future = Instant::now() + Duration::from_secs(10);
                        assert_eq!(
                            SqliteControlStore::effective_runtime_deadline(future),
                            future
                        );
                        // The control read budget is already out of scope. An
                        // expired control read cannot overwrite physical work.
                        assert!(matches!(
                            observer.with_runtime_deadline(Instant::now(), || -> PortResult<()> {
                                panic!("expired read entered")
                            }),
                            Err(PortError::WriterBusy(_))
                        ));
                        called.set(true);
                    }
                }));
            });
            let report = fixture.checkpoint().unwrap();
            assert!(called.get());
            assert_eq!(report.incarnation, Some(id("catalog")));
            assert!(report.elapsed > Duration::ZERO);
            if pinned {
                assert_eq!(
                    report.outcome,
                    WalCheckpointOutcome::Deferred(WalDeferral::Sqlite)
                );
                assert!(report.checkpointed_frames < report.log_frames);
                assert_eq!(report.wal_bytes_before, report.wal_bytes_after);
                reader.execute_batch("COMMIT").unwrap();
            } else {
                assert_eq!(report.outcome, WalCheckpointOutcome::Reset);
                assert_eq!(report.wal_bytes_after, Some(0));
            }
        }
    }

    #[test]
    fn wal_checkpoint_expired_admission_never_opens_the_catalog() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let _reader = fixture.reader();
        let bytes = ManagedStore::wal_len(&fixture.catalog).unwrap();
        take_pragmas();
        CONTROL_END.with(|end| end.set(Some(Instant::now())));
        let report = fixture.checkpoint();
        CONTROL_END.with(|end| end.set(None));
        let report = report.unwrap();
        assert_eq!(
            report.outcome,
            WalCheckpointOutcome::Deferred(WalDeferral::Fence)
        );
        assert!(report.incarnation.is_none());
        assert_eq!((report.log_frames, report.checkpointed_frames), (-1, -1));
        assert!(take_pragmas().is_empty());
        assert_eq!(ManagedStore::wal_len(&fixture.catalog).unwrap(), bytes);
    }

    #[test]
    fn wal_checkpoint_gate_contention_does_not_open_catalog() {
        let fixture = Fixture::new();
        let _idle = fixture.reader();
        for gate in [WalDeferral::CatalogHandles, WalDeferral::WriterLease] {
            let handles = (gate == WalDeferral::CatalogHandles).then(|| {
                ExclusiveGuard::try_acquire(&fixture.root, LockKind::CatalogHandles).unwrap()
            });
            let lease = (gate == WalDeferral::WriterLease)
                .then(|| WriterLease::try_acquire(&fixture.root).unwrap());
            PRAGMAS.with(|values| values.borrow_mut().clear());
            let report = fixture.checkpoint().unwrap();
            assert_eq!(report.outcome, WalCheckpointOutcome::Deferred(gate));
            assert_eq!((report.log_frames, report.checkpointed_frames), (-1, -1));
            assert!(report.incarnation.is_none());
            assert!(PRAGMAS.with(|values| values.borrow().is_empty()));
            drop(lease);
            drop(handles);
        }
    }

    #[test]
    fn wal_checkpoint_fence_and_emission_refuse_before_open() {
        for emission in [false, true] {
            let fixture = Fixture::new();
            let _idle = fixture.reader();
            if emission {
                let selection = fixture.select();
                fixture
                    .control
                    .revoke_selection(
                        fixture.control.status().unwrap().policy.control_seq,
                        &selection.id,
                        None,
                        2,
                    )
                    .unwrap();
            } else {
                fixture
                    .control
                    .set_maintenance(
                        fixture.control.status().unwrap().policy.control_seq,
                        &id("owner"),
                        MaintenanceFence {
                            state: MaintenanceState::Updating,
                            owner: Some(id("owner")),
                            phase: Some(MaintenancePhase::Quiescing),
                        },
                    )
                    .unwrap();
            }
            PRAGMAS.with(|values| values.borrow_mut().clear());
            assert_eq!(
                fixture.checkpoint().unwrap().outcome,
                WalCheckpointOutcome::Deferred(WalDeferral::Fence)
            );
            assert!(PRAGMAS.with(|values| values.borrow().is_empty()));
        }
    }

    #[test]
    fn wal_checkpoint_accepts_paused_and_stopped_without_recovery() {
        let fixture = Fixture::new();
        let store = ManagedStore::open_for_write(&fixture.catalog, &fixture.control).unwrap();
        let pending = store.inner.begin_index_batch(&[], &[]).unwrap();
        drop(store);
        let writer = fixture.seed();
        let _idle = fixture.reader();
        for desired in [DesiredUpdates::Paused, DesiredUpdates::Stopped] {
            fixture.desired(desired);
            writer
                .execute("UPDATE wal_fixture SET body=zeroblob(8192)", [])
                .unwrap();
            let diagnostic = ObserveAdmissions::start();
            let report = fixture.checkpoint().unwrap();
            assert_eq!(
                report.outcome,
                WalCheckpointOutcome::Reset,
                "WAL admission diagnostic for {desired:?}: incarnation_present={} frames=({}, {}) {:?}",
                report.incarnation.is_some(),
                report.log_frames,
                report.checkpointed_frames,
                diagnostic.snapshot()
            );
            drop(diagnostic);
            assert_eq!(ManagedStore::wal_len(&fixture.catalog).unwrap(), Some(0));
            assert_eq!(fixture.control.status().unwrap().desired_updates, desired);
            let state: String = writer
                .query_row(
                    "SELECT state FROM index_batches WHERE operation_id=?1",
                    [&pending.operation_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, "building");
        }
    }

    #[test]
    fn wal_checkpoint_known_incarnation_mismatch_does_not_touch_frames() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let _reader = fixture.reader();
        let before = std::fs::read(&fixture.catalog).unwrap();
        let wal = std::fs::read(fixture.root.join("catalog.db-wal")).unwrap();
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        assert!(matches!(
            ManagedStore::checkpoint_wal(
                &fixture.catalog,
                &fixture.control,
                &authority,
                Some(&id("other-catalog"))
            ),
            Err(PortError::GenerationMismatch(_))
        ));
        assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
        assert_eq!(
            std::fs::read(fixture.root.join("catalog.db-wal")).unwrap(),
            wal
        );
    }

    #[test]
    fn wal_checkpoint_retains_catalog_gate_until_post_close_sample() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let _reader = fixture.reader();
        let sampled = std::rc::Rc::new(Cell::new(false));
        AFTER_CLOSE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new({
                let root = fixture.root.clone();
                let sampled = sampled.clone();
                move || {
                    assert!(matches!(
                        ExclusiveGuard::try_acquire(&root, LockKind::CatalogHandles),
                        Err(PortError::WriterBusy(_))
                    ));
                    // The lease and SQLite connection have already closed.
                    drop(WriterLease::try_acquire(&root).unwrap());
                    let conn = connect(&root.join("catalog.db"), true).unwrap();
                    conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK").unwrap();
                    sampled.set(true);
                }
            }));
        });
        let report = fixture.checkpoint().unwrap();
        assert!(sampled.get());
        assert_eq!(report.outcome, WalCheckpointOutcome::Reset);
        assert_eq!(report.incarnation, Some(id("catalog")));
        assert_eq!(report.wal_bytes_after, Some(0));
        drop(ExclusiveGuard::try_acquire(&fixture.root, LockKind::CatalogHandles).unwrap());
    }

    #[test]
    fn wal_checkpoint_sample_precedes_an_exclusive_catalog_replacement() {
        use std::sync::mpsc;
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let idle = fixture.reader();
        let replacement = fixture.root.join("replacement.db");
        drop(ManagedStore::create(&replacement, &fixture.control, id("replacement"), 2).unwrap());
        drop(writer);
        let (probe_tx, probe_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let (replace_tx, replace_rx) = mpsc::channel();
        let actor_root = fixture.root.clone();
        let actor = std::thread::spawn(move || {
            probe_rx.recv().unwrap();
            let blocked = matches!(
                ExclusiveGuard::try_acquire(&actor_root, LockKind::CatalogHandles),
                Err(PortError::WriterBusy(_))
            );
            result_tx.send(blocked).unwrap();
            replace_rx.recv().unwrap();
            let _handles =
                ExclusiveGuard::try_acquire(&actor_root, LockKind::CatalogHandles).unwrap();
            let _lease = WriterLease::try_acquire(&actor_root).unwrap();
            std::fs::rename(
                actor_root.join("catalog.db"),
                actor_root.join("retained.db"),
            )
            .unwrap();
            std::fs::rename(
                actor_root.join("replacement.db"),
                actor_root.join("catalog.db"),
            )
            .unwrap();
        });
        AFTER_CLOSE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                probe_tx.send(()).unwrap();
                assert!(result_rx.recv().unwrap());
            }));
        });
        let report = fixture.checkpoint().unwrap();
        assert_eq!(report.outcome, WalCheckpointOutcome::Reset);
        assert_eq!(report.incarnation, Some(id("catalog")));
        assert_eq!(report.wal_bytes_after, Some(0));
        drop(idle);
        // SQLite owns sidecar cleanup; no manual WAL/SHM file operations.
        drop(connect(&fixture.catalog, true).unwrap());
        replace_tx.send(()).unwrap();
        actor.join().unwrap();
        assert_eq!(
            identity(
                &connect(&fixture.catalog, false).unwrap(),
                &id("installation")
            )
            .unwrap(),
            id("replacement")
        );
    }

    #[test]
    fn wal_checkpoint_pretruncate_fence_and_revoke_preserve_database_and_wal() {
        for emission in [false, true] {
            let fixture = Fixture::new();
            let selection = fixture.select();
            let _writer = fixture.seed();
            let _reader = fixture.reader();
            let before = std::fs::read(&fixture.catalog).unwrap();
            let wal = std::fs::read(fixture.root.join("catalog.db-wal")).unwrap();
            let actor =
                SqliteControlStore::open_existing_writable(&fixture.root, &id("installation"))
                    .unwrap();
            BEFORE_CHECKPOINT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let seq = actor.status().unwrap().policy.control_seq;
                    if emission {
                        actor.revoke_selection(seq, &selection.id, None, 2).unwrap();
                    } else {
                        actor
                            .set_maintenance(
                                seq,
                                &id("owner"),
                                MaintenanceFence {
                                    state: MaintenanceState::Updating,
                                    owner: Some(id("owner")),
                                    phase: Some(MaintenancePhase::Quiescing),
                                },
                            )
                            .unwrap();
                    }
                }));
            });
            let diagnostic = ObserveAdmissions::start();
            let report = fixture.checkpoint().unwrap();
            assert_eq!(
                report.outcome,
                WalCheckpointOutcome::Deferred(WalDeferral::Fence)
            );
            assert_eq!((report.log_frames, report.checkpointed_frames), (-1, -1));
            let observed = diagnostic.snapshot();
            let initial = observed.slots[0].unwrap();
            let pretruncate = observed.slots[1].unwrap();
            assert_eq!(initial.result, Some("ok"));
            assert_eq!(pretruncate.result, Some("active_fence"));
            assert_eq!(initial.requested_end, pretruncate.requested_end);
            assert_eq!(initial.effective_end, pretruncate.effective_end);
            assert!(initial.returned_remaining_us.is_some());
            assert!(pretruncate.returned_remaining_us.is_some());
            assert_eq!(observed.physical_attempts, 0);
            assert!(!observed.unexpected_observation);
            drop(diagnostic);
            assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
            assert_eq!(
                std::fs::read(fixture.root.join("catalog.db-wal")).unwrap(),
                wal
            );
        }
    }

    #[test]
    fn wal_checkpoint_validates_real_sidecars_and_rejects_hardlinks() {
        for suffix in ["-wal", "-shm"] {
            let fixture = Fixture::new();
            let _writer = fixture.seed();
            let _reader = fixture.reader();
            fixture
                .control
                .validate_catalog_file(&fixture.catalog)
                .unwrap();
            // This fixture tests sidecar ownership, not 250ms throughput.
            // Only admission receives this explicit preparation end; physical
            // I/O and its final validation remain outside the runtime scope.
            let end = SqliteControlStore::effective_runtime_deadline(
                Instant::now() + Duration::from_secs(5),
            );
            let authority = fixture
                .control
                .with_runtime_deadline(end, || {
                    fixture
                        .control
                        .bind_worker(&fixture.worker_lock, id("boot"))
                })
                .unwrap();
            let observation = ObservePreparedCheckpoint::start(end);
            assert_eq!(
                ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None,)
                    .unwrap()
                    .outcome,
                WalCheckpointOutcome::Reset
            );
            assert_eq!(observation.finish(), (2, 1));
            assert!(CONTROL_END.with(|slot| slot.get().is_none()));
            fixture
                .control
                .validate_catalog_file(&fixture.catalog)
                .unwrap();
            let sidecar = fixture.root.join(format!("catalog.db{suffix}"));
            assert!(sidecar.is_file());
            let alias = fixture.root.join("synthetic-alias");
            std::fs::hard_link(&sidecar, &alias).unwrap();
            let before = std::fs::read(&sidecar).unwrap();
            // The ordinary checkpoint rejects the real hardlink before any
            // control admission or physical operation.
            let observation = ObservePreparedCheckpoint::start(end);
            CONTROL_END.with(|slot| slot.set(None));
            assert!(matches!(
                ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None,),
                Err(PortError::Backend(_))
            ));
            assert_eq!(observation.finish(), (0, 0));
            assert_eq!(std::fs::read(&sidecar).unwrap(), before);
            assert!(alias.exists());
        }
    }

    #[test]
    fn prepared_checkpoint_expiry_refuses_without_physical_work_and_restores_hook() {
        let fixture = Fixture::new();
        let _writer = fixture.seed();
        let _reader = fixture.reader();
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        let before = std::fs::read(fixture.root.join("catalog.db-wal")).unwrap();
        let expired = Instant::now();
        let outer = ObservePreparedCheckpoint::start(expired);
        {
            let nested = ObservePreparedCheckpoint::start(expired);
            let previous = ADMISSION_DIAGNOSTIC.with(|slot| *slot.borrow());
            let diagnostic = ObserveAdmissions::start();
            let report =
                ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None)
                    .unwrap();
            assert_eq!(
                report.outcome,
                WalCheckpointOutcome::Deferred(WalDeferral::Fence)
            );
            assert_eq!((report.log_frames, report.checkpointed_frames), (-1, -1));
            let observed = diagnostic.snapshot();
            let initial = observed.slots[0].unwrap();
            assert_eq!(initial.requested_end, expired);
            assert_eq!(
                initial.effective_end,
                SqliteControlStore::effective_runtime_deadline(expired)
            );
            assert_eq!(initial.result, Some("deadline"));
            assert!(initial.entered_remaining_us <= 0);
            assert!(
                initial
                    .returned_remaining_us
                    .is_some_and(|remaining| remaining <= 0)
            );
            assert_eq!(observed.slots[1], None);
            assert_eq!(observed.physical_attempts, 0);
            assert!(!observed.unexpected_observation);
            drop(diagnostic);
            assert_eq!(ADMISSION_DIAGNOSTIC.with(|slot| *slot.borrow()), previous);
            assert_eq!(nested.finish(), (1, 0));
        }
        assert_eq!(CONTROL_END.with(Cell::get), Some(expired));
        assert_eq!(outer.finish(), (0, 0));
        assert!(CONTROL_END.with(|slot| slot.get().is_none()));
        assert_eq!(
            std::fs::read(fixture.root.join("catalog.db-wal")).unwrap(),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn wal_checkpoint_refuses_nonprivate_sidecar_mode_without_repair() {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["-wal", "-shm"] {
            let fixture = Fixture::new();
            let _writer = fixture.seed();
            let _reader = fixture.reader();
            let sidecar = fixture.root.join(format!("catalog.db{suffix}"));
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644)).unwrap();
            let before = std::fs::read(&sidecar).unwrap();
            assert!(fixture.checkpoint().is_err());
            assert_eq!(
                std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(std::fs::read(&sidecar).unwrap(), before);
        }
    }

    #[cfg(windows)]
    #[test]
    fn wal_checkpoint_refuses_broad_sidecar_acl_without_repair() {
        use std::process::Command;
        for suffix in ["-wal", "-shm"] {
            let fixture = Fixture::new();
            let _writer = fixture.seed();
            let _reader = fixture.reader();
            let sidecar = fixture.root.join(format!("catalog.db{suffix}"));
            assert!(
                Command::new("icacls")
                    .arg(&sidecar)
                    .args(["/grant", "*S-1-1-0:(R)"])
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            let before_acl = Command::new("icacls").arg(&sidecar).output().unwrap();
            let before = std::fs::read(&sidecar).unwrap();
            assert!(fixture.checkpoint().is_err());
            assert_eq!(std::fs::read(&sidecar).unwrap(), before);
            assert_eq!(
                Command::new("icacls")
                    .arg(&sidecar)
                    .output()
                    .unwrap()
                    .stdout,
                before_acl.stdout
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn wal_checkpoint_refuses_sidecar_reparse_without_touching_target() {
        use std::os::windows::fs::MetadataExt;
        use std::process::Command;
        let fixture = Fixture::new();
        let target = fixture.root.join("synthetic-reparse-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"unchanged").unwrap();
        let sidecar = fixture.root.join("catalog.db-wal");
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&sidecar)
            .arg(&target)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(fixture.checkpoint().is_err());
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"unchanged"
        );
        assert_ne!(
            std::fs::symlink_metadata(&sidecar)
                .unwrap()
                .file_attributes()
                & 0x400,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn wal_checkpoint_refuses_sidecar_symlink_without_touching_target() {
        let fixture = Fixture::new();
        let target = fixture.root.join("synthetic-link-target");
        std::fs::write(&target, b"unchanged").unwrap();
        let sidecar = fixture.root.join("catalog.db-wal");
        std::os::unix::fs::symlink(&target, &sidecar).unwrap();
        assert!(fixture.checkpoint().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        assert!(
            std::fs::symlink_metadata(&sidecar)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn wal_limit_applies_to_first_commit_after_automatic_checkpoint_and_reset() {
        struct Limit;
        impl Drop for Limit {
            fn drop(&mut self) {
                LIMIT.with(|value| value.set(None));
            }
        }
        LIMIT.with(|value| value.set(Some(256 * 1024)));
        let _limit = Limit;
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let reader = fixture.reader();
        reader.execute_batch("BEGIN").unwrap();
        snapshot(&reader);
        writer
            .execute_batch(
                "WITH RECURSIVE rows(n) AS (SELECT 2 UNION ALL SELECT n+1 FROM rows WHERE n<1100)
            INSERT INTO wal_fixture SELECT n,'bulk',zeroblob(4096) FROM rows;",
            )
            .unwrap();
        let pinned = ManagedStore::wal_len(&fixture.catalog).unwrap().unwrap();
        assert!(pinned > 256 * 1024 && pinned < 6 * 1024 * 1024);
        reader.execute_batch("COMMIT").unwrap();
        // The first post-gap commit completes the default autocheckpoint.
        // Its successor starts the reset and applies this connection's limit.
        writer
            .execute("UPDATE wal_fixture SET proof='gap' WHERE id=1", [])
            .unwrap();
        writer
            .execute("UPDATE wal_fixture SET proof='reset' WHERE id=1", [])
            .unwrap();
        assert!(ManagedStore::wal_len(&fixture.catalog).unwrap().unwrap() <= 256 * 1024);
        assert_eq!(snapshot(&reader).0, 1100);
    }

    #[test]
    fn wal_limit_is_connection_local_and_present_on_all_store_writers() {
        PRAGMAS.with(|values| values.borrow_mut().clear());
        let fixture = Fixture::new();
        assert_eq!(
            PRAGMAS.with(|values| values.borrow().clone()),
            [(JOURNAL_SIZE_LIMIT_BYTES, 2, 1000, 250)]
        );
        let writer = ManagedStore::open_for_write(&fixture.catalog, &fixture.control).unwrap();
        assert_eq!(
            pragmas(&writer.inner.conn.borrow()),
            (JOURNAL_SIZE_LIMIT_BYTES, 2, 1000, 250)
        );
        drop(writer);
        let reader = fixture.reader();
        assert_eq!(pragmas(&reader), (-1, 2, 1000, 250));
        PRAGMAS.with(|values| values.borrow_mut().clear());
        fixture.checkpoint().unwrap();
        assert_eq!(
            PRAGMAS.with(|values| values.borrow().clone()),
            [(JOURNAL_SIZE_LIMIT_BYTES, 2, 1000, 0)]
        );
    }

    #[test]
    fn wal_checkpoint_rejects_identity_and_authority_mismatches() {
        for change in [
            "PRAGMA application_id=0",
            "PRAGMA user_version=1",
            "UPDATE catalog_meta SET installation_id='foreign'",
            "DROP TRIGGER source_publication_context_immutable",
        ] {
            let fixture = Fixture::new();
            let conn = connect(&fixture.catalog, true).unwrap();
            conn.execute_batch(change).unwrap();
            let before = std::fs::read(&fixture.catalog).unwrap();
            assert!(matches!(
                fixture.checkpoint(),
                Err(PortError::SchemaIncompatible(_))
            ));
            assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
        }
        let fixture = Fixture::new();
        let foreign = Fixture::new();
        // Bind the synthetic foreign worker before exercising checkpoint refusal.
        let preparation_end = Instant::now() + Duration::from_secs(30);
        let authority = foreign
            .control
            .with_runtime_deadline(preparation_end, || {
                foreign
                    .control
                    .bind_worker(&foreign.worker_lock, id("foreign-boot"))
            })
            .expect("foreign worker fixture preparation");
        assert!(matches!(
            ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None),
            Err(PortError::InvalidRequest(_))
        ));
        assert!(matches!(
            ManagedStore::checkpoint_wal(&foreign.catalog, &fixture.control, &authority, None),
            Err(PortError::InvalidRequest(_))
        ));
    }

    #[test]
    fn wal_checkpoint_rejects_authority_after_control_retirement() {
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let _idle = fixture.reader();
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        assert!(authority.validate().is_ok());
        // Existence invalidates control admission without reading marker data.
        std::fs::write(
            fixture
                .root
                .join(crate::managed_control_lifetime::RETIREMENT_PENDING_MARKER),
            b"synthetic retirement",
        )
        .unwrap();
        let before = std::fs::read(&fixture.catalog).unwrap();
        let wal = ManagedStore::wal_len(&fixture.catalog).unwrap();
        take_pragmas();
        assert!(matches!(
            authority.validate(),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert!(matches!(
            ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert!(take_pragmas().is_empty());
        assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
        assert_eq!(ManagedStore::wal_len(&fixture.catalog).unwrap(), wal);
        drop(writer);
    }

    #[test]
    fn wal_checkpoint_keeps_the_bound_physical_root() {
        let fixture = Fixture::new();
        let retained = fixture._temp.path().join("retained-private");
        let authority = fixture
            .control
            .bind_worker(&fixture.worker_lock, id("boot"))
            .unwrap();
        #[cfg(windows)]
        {
            // Live root handles deny deletion/rename on Windows.
            assert!(std::fs::rename(&fixture.root, &retained).is_err());
            assert!(authority.validate().is_ok());
            assert!(fixture.checkpoint().is_ok());
        }
        #[cfg(unix)]
        {
            std::fs::rename(&fixture.root, &retained).unwrap();
            let replacement = SqliteControlStore::create(
                &fixture.root,
                &id("replacement"),
                DesiredUpdates::Running,
            )
            .unwrap();
            drop(
                ManagedStore::create(&fixture.catalog, &replacement, id("replacement-catalog"), 2)
                    .unwrap(),
            );
            let before = std::fs::read(&fixture.catalog).unwrap();
            assert!(authority.validate().is_err());
            assert!(matches!(
                ManagedStore::checkpoint_wal(&fixture.catalog, &fixture.control, &authority, None),
                Err(PortError::InvalidRequest(_))
            ));
            assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
        }
    }

    #[test]
    fn wal_checkpoint_delete_mode_is_unchanged_and_not_applicable() {
        let fixture = Fixture::new();
        let conn = connect(&fixture.catalog, true).unwrap();
        conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
        let before = std::fs::read(&fixture.catalog).unwrap();
        let report = fixture.checkpoint().unwrap();
        assert_eq!(report.outcome, WalCheckpointOutcome::NotApplicable);
        assert_eq!((report.log_frames, report.checkpointed_frames), (-1, -1));
        assert_eq!(report.wal_bytes_after, None);
        assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
    }

    #[test]
    fn wal_checkpoint_sql_error_mapping_preserves_storage_failures() {
        use rusqlite::ffi;
        for code in [
            ffi::SQLITE_BUSY,
            ffi::SQLITE_LOCKED,
            ffi::SQLITE_IOERR,
            ffi::SQLITE_IOERR_FSYNC,
            ffi::SQLITE_FULL,
            ffi::SQLITE_CANTOPEN,
            ffi::SQLITE_READONLY,
            ffi::SQLITE_PROTOCOL,
            ffi::SQLITE_CORRUPT,
            ffi::SQLITE_NOTADB,
        ] {
            let error =
                checkpoint_storage(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None));
            if code == ffi::SQLITE_BUSY {
                assert!(matches!(error, PortError::WriterBusy(_)));
            } else {
                assert!(matches!(error, PortError::Backend(_)));
            }
        }
    }

    #[test]
    fn wal_checkpoint_corrupt_file_is_a_storage_error() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.catalog, b"synthetic invalid database").unwrap();
        let before = std::fs::read(&fixture.catalog).unwrap();
        assert!(matches!(fixture.checkpoint(), Err(PortError::Backend(_))));
        assert_eq!(std::fs::read(&fixture.catalog).unwrap(), before);
    }

    #[test]
    fn wal_checkpoint_releases_all_catalog_resources_on_return() {
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let idle = fixture.reader();
        drop(writer);
        fixture.checkpoint().unwrap();
        let writer = connect(&fixture.catalog, true).unwrap();
        writer.execute_batch("BEGIN EXCLUSIVE; ROLLBACK").unwrap();
        let handles = ExclusiveGuard::try_acquire(&fixture.root, LockKind::CatalogHandles).unwrap();
        let lease = WriterLease::try_acquire(&fixture.root).unwrap();
        drop(lease);
        drop(handles);
        drop(idle);
    }

    #[test]
    fn wal_checkpoint_error_and_deferral_release_owned_resources() {
        let fixture = Fixture::new();
        let writer = fixture.seed();
        let idle = fixture.reader();
        idle.execute_batch("BEGIN").unwrap();
        snapshot(&idle);
        writer
            .execute("UPDATE wal_fixture SET proof='later'", [])
            .unwrap();
        assert_eq!(
            fixture.checkpoint().unwrap().outcome,
            WalCheckpointOutcome::Deferred(WalDeferral::Sqlite)
        );
        idle.execute_batch("COMMIT").unwrap();
        for invalid_identity in [false, true] {
            if invalid_identity {
                writer.pragma_update(None, "application_id", 0).unwrap();
                assert!(matches!(
                    fixture.checkpoint(),
                    Err(PortError::SchemaIncompatible(_))
                ));
            }
            writer.execute_batch("BEGIN EXCLUSIVE; ROLLBACK").unwrap();
            let handles =
                ExclusiveGuard::try_acquire(&fixture.root, LockKind::CatalogHandles).unwrap();
            let lease = WriterLease::try_acquire(&fixture.root).unwrap();
            drop(lease);
            drop(handles);
        }
    }
}
