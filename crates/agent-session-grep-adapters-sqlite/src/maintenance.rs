//! Online maintenance of an existing catalog. This module never migrates,
//! replaces, restores, or opens a provider database.
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use agent_session_grep_ports::maintenance::*;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension,
    backup::{Backup, StepResult},
    types::ValueRef,
};
use serde::{Deserialize, Serialize};

use crate::*;

const PREVIEW_COMPACTION_ID: &str =
    "cmp_m1_0000000000000000000000000000000000000000000000000000000000000000";
const SPACE_RESERVE: u64 = 8 * 1024 * 1024;

/// Stateless composition surface; construction performs no I/O.
#[derive(Default)]
pub struct SqliteMaintenanceCatalog;
impl SqliteMaintenanceCatalog {
    pub fn new() -> Self {
        Self
    }
}

fn port_failure(error: PortError) -> MaintenanceFailure {
    use MaintenanceFailureKind as K;
    match error {
        PortError::WriterBusy(_) => K::Busy,
        PortError::GenerationMismatch(_) | PortError::SnapshotChanged(_) => K::SelectionChanged,
        PortError::SchemaIncompatible(_) => K::UnsupportedTarget,
        PortError::NotFound(_) => K::TargetChanged,
        _ => K::Backend,
    }
    .into()
}
fn io_failure(error: std::io::Error) -> MaintenanceFailure {
    use MaintenanceFailureKind as K;
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => K::PermissionDenied,
        std::io::ErrorKind::StorageFull => K::InsufficientSpace,
        std::io::ErrorKind::NotFound => K::TargetChanged,
        _ => K::Backend,
    }
    .into()
}
fn sql_failure(error: rusqlite::Error) -> MaintenanceFailure {
    use MaintenanceFailureKind as K;
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => K::Busy,
        Some(rusqlite::ErrorCode::DiskFull) => K::InsufficientSpace,
        Some(rusqlite::ErrorCode::PermissionDenied | rusqlite::ErrorCode::ReadOnly) => {
            K::PermissionDenied
        }
        Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
            K::IntegrityFailed
        }
        _ => K::Backend,
    }
    .into()
}
fn public_failure(error: MaintenanceFailure) -> PortError {
    match error.kind {
        MaintenanceFailureKind::Busy => PortError::WriterBusy("catalog maintenance is busy".into()),
        MaintenanceFailureKind::UnsupportedTarget => PortError::SchemaIncompatible(
            "maintenance requires an existing current-schema catalog".into(),
        ),
        MaintenanceFailureKind::TargetChanged => {
            PortError::NotFound("maintenance catalog is missing or changed".into())
        }
        _ => PortError::Backend("catalog maintenance inspection failed".into()),
    }
}

/// Resolve an existing target, or a missing filename beneath an existing parent.
/// Does not open SQLite, create directories, or acquire the catalog lease.
pub fn maintenance_target_path(target: &Path) -> PortResult<PathBuf> {
    if target.exists() {
        return fs::canonicalize(target).map_err(|e| public_failure(io_failure(e)));
    }
    let name = target
        .file_name()
        .ok_or_else(|| PortError::InvalidRequest("catalog filename is required".into()))?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)
        .map_err(|e| public_failure(io_failure(e)))?
        .join(name))
}
pub fn maintenance_root(target: &Path) -> PortResult<PathBuf> {
    maintenance_target_path(target)?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| PortError::InvalidRequest("catalog parent is required".into()))
}
fn private_directory(path: &Path) -> MaintenanceResult<()> {
    if !path.exists() {
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => sync_directory(path.parent().ok_or(MaintenanceFailureKind::Backend)?)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_failure(e)),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(io_failure)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(MaintenanceFailureKind::PermissionDenied.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(MaintenanceFailureKind::PermissionDenied.into());
        }
    }
    Ok(())
}
/// The caller sets child-only TMPDIR/TEMP/TMP/SQLITE_TMPDIR to this directory.
/// Never mutate SQLite's process-global temp_directory pragma.
pub fn worker_temp_directory(root: &Path) -> PortResult<PathBuf> {
    let maintenance = root.join(".maintenance");
    private_directory(&maintenance).map_err(public_failure)?;
    let temporary = maintenance.join("tmp");
    private_directory(&temporary).map_err(public_failure)?;
    Ok(temporary)
}
fn sync_directory(path: &Path) -> MaintenanceResult<()> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(io_failure)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Hash OS identity, not size/mtime/content. Windows uses the full 128-bit
/// FILE_ID_INFO (the older 64-bit index is not unique on ReFS).
fn file_identity(path: &Path) -> MaintenanceResult<String> {
    let file = File::open(path).map_err(io_failure)?;
    let metadata = file.metadata().map_err(io_failure)?;
    if !metadata.is_file() {
        return Err(MaintenanceFailureKind::UnsupportedTarget.into());
    }
    let mut hash = blake3::Hasher::new();
    hash_field(&mut hash, b"maintenance-file-identity-v1");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hash_field(&mut hash, &metadata.dev().to_le_bytes());
        hash_field(&mut hash, &metadata.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        let mut identity = FILE_ID_INFO::default();
        // SAFETY: file owns a live handle, the output points to an initialized
        // FILE_ID_INFO and its exact size is passed. No pointer escapes.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut identity as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(MaintenanceFailureKind::UnsupportedTarget.into());
        }
        hash_field(&mut hash, &identity.VolumeSerialNumber.to_le_bytes());
        hash_field(&mut hash, &identity.FileId.Identifier);
        hash_field(&mut hash, &metadata.creation_time().to_le_bytes());
    }
    #[cfg(not(any(unix, windows)))]
    return Err(MaintenanceFailureKind::UnsupportedTarget.into());
    Ok(hash.finalize().to_hex().to_string())
}

/// Process lifetime high-water working set, not a fabricated per-job delta.
/// Zero means unavailable on this platform; it must not be reported as measured.
fn peak_process_memory() -> u64 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::{
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::GetCurrentProcess,
        };
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        // SAFETY: pseudo-handle names the current process; counters is a valid
        // writable buffer of cb bytes and all values are read only on success.
        if unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut counters,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            )
        } != 0
        {
            return counters.PeakWorkingSetSize as u64;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            if let Some(kib) = status.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse::<u64>().ok())
            }) {
                return kib.saturating_mul(1024);
            }
        }
    }
    0
}
fn schema(conn: &Connection) -> MaintenanceResult<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(sql_failure)?;
    if version != SCHEMA_VERSION {
        return Err(MaintenanceFailureKind::UnsupportedTarget.into());
    }
    Ok(())
}
fn generation(conn: &Connection) -> MaintenanceResult<u64> {
    conn.query_row(
        "SELECT active_generation FROM store_metadata WHERE singleton=1",
        [],
        |r| row_u64(r, 0),
    )
    .map_err(sql_failure)
}
fn target_matches(target: &MaintenanceTarget) -> MaintenanceResult<PathBuf> {
    let path = fs::canonicalize(&target.canonical_path).map_err(io_failure)?;
    if path.to_str() != Some(target.canonical_path.as_str())
        || file_identity(&path)? != target.file_identity
        || target.schema_version != SCHEMA_VERSION as u32
    {
        return Err(MaintenanceFailureKind::TargetChanged.into());
    }
    Ok(path)
}
fn selection_items(selection: &MaintenanceSelection) -> Vec<JournalCompactionPreviewItem> {
    selection
        .batches
        .iter()
        .map(|item| JournalCompactionPreviewItem {
            operation_id: item.operation_id.clone(),
            state: item.state.clone(),
            base_generation: item.base_generation,
            target_generation: item.target_generation,
            operation_digest: item.operation_digest.clone(),
            detail_digest: item.detail_digest.clone(),
            fields: item
                .fields
                .iter()
                .map(|f| JournalDetailFieldPreview {
                    field: f.field.clone(),
                    bytes: f.bytes,
                    items: f.items,
                })
                .collect(),
        })
        .collect()
}
fn selection_from(preview: JournalCompactionPreview) -> MaintenanceSelection {
    MaintenanceSelection {
        plan_digest: preview.plan_digest,
        aggregated_fields: preview.aggregated_fields,
        detail_bytes_before: preview.detail_bytes_before,
        estimated_detail_bytes_after: preview.estimated_detail_bytes_after,
        estimated_saved_bytes: preview.estimated_saved_bytes,
        batches: preview
            .batches
            .into_iter()
            .map(|item| MaintenanceSelectionItem {
                operation_id: item.operation_id,
                state: item.state,
                base_generation: item.base_generation,
                target_generation: item.target_generation,
                operation_digest: item.operation_digest,
                detail_digest: item.detail_digest,
                fields: item
                    .fields
                    .into_iter()
                    .map(|f| MaintenanceFieldSummary {
                        field: f.field,
                        bytes: f.bytes,
                        items: f.items,
                    })
                    .collect(),
            })
            .collect(),
    }
}
fn token(target: &MaintenanceTarget, selection: &MaintenanceSelection) -> String {
    let mut hash = blake3::Hasher::new();
    for part in [
        "maintenance-plan-v1",
        &target.canonical_path,
        &target.file_identity,
        &target.schema_version.to_string(),
        &selection.plan_digest,
    ] {
        hash_field(&mut hash, part.as_bytes());
    }
    format!("maint_v1_{}", hash.finalize().to_hex())
}

impl MaintenanceCatalog for SqliteMaintenanceCatalog {
    fn reconcile(&self, job: &MaintenanceJob) -> MaintenanceResult<bool> {
        let path = target_matches(&job.target)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(sql_failure)?;
        conn.busy_timeout(Duration::ZERO).map_err(sql_failure)?;
        let tx = conn.unchecked_transaction().map_err(sql_failure)?;
        schema(&tx)?;
        let committed = committed_audit(&tx, job)?;
        target_matches(&job.target)?;
        Ok(committed)
    }

    fn preview(&self, target: &str) -> PortResult<MaintenancePreview> {
        let inspect = || -> MaintenanceResult<MaintenancePreview> {
            let path = fs::canonicalize(target).map_err(io_failure)?;
            let identity = file_identity(&path)?;
            let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(sql_failure)?;
            conn.busy_timeout(Duration::ZERO).map_err(sql_failure)?;
            let tx = conn.unchecked_transaction().map_err(sql_failure)?;
            schema(&tx)?;
            let selection = selection_from(
                SqliteStore::preview_journal_compaction_with_id(&tx, PREVIEW_COMPACTION_ID.into())
                    .map_err(port_failure)?,
            );
            let target = MaintenanceTarget {
                canonical_path: path
                    .to_str()
                    .ok_or(MaintenanceFailureKind::UnsupportedTarget)?
                    .to_owned(),
                file_identity: identity,
                schema_version: SCHEMA_VERSION as u32,
            };
            target_matches(&target)?;
            Ok(MaintenancePreview {
                token: token(&target, &selection),
                target,
                selection,
                footprint: footprint(&path)?,
            })
        };
        inspect().map_err(public_failure)
    }
    fn acquire(&self, job: &MaintenanceJob) -> MaintenanceResult<Box<dyn MaintenanceSession + '_>> {
        if job.max_write_seconds == 0 {
            return Err(MaintenanceFailureKind::Backend.into());
        }
        if job.phase == MaintenancePhase::Cleanup && job.cleanup_started {
            return Ok(Box::new(CleanupSession));
        }
        let path = target_matches(&job.target)?;
        let root = path
            .parent()
            .ok_or(MaintenanceFailureKind::UnsupportedTarget)?;
        let lease = WriterLease::try_acquire(root).map_err(port_failure)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_secs(job.max_write_seconds))
            .ok_or(MaintenanceFailureKind::Backend)?;
        target_matches(&job.target)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(sql_failure)?;
        conn.busy_timeout(Duration::ZERO).map_err(sql_failure)?;
        schema(&conn)?;
        // No recovery, migration, journal-mode change or reprojection here.
        target_matches(&job.target)?;
        Ok(Box::new(SqliteMaintenanceSession {
            conn,
            _lease: lease,
            path,
            started,
            deadline,
            baseline: None,
        }))
    }
}

struct SqliteMaintenanceSession {
    // Connection closes BEFORE the lease is released.
    conn: Connection,
    _lease: WriterLease,
    path: PathBuf,
    started: Instant,
    deadline: Instant,
    baseline: Option<String>,
}

fn checked_file_size(path: &Path) -> MaintenanceResult<u64> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(m.len()),
        Ok(_) => Err(MaintenanceFailureKind::PermissionDenied.into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(io_failure(e)),
    }
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
/// Count published backups/ownership separately from incomplete copies and
/// sidecars, including retained older jobs without ever removing their files.
fn tree_sizes(directory: &Path) -> MaintenanceResult<(u64, u64)> {
    if !directory.exists() {
        return Ok((0, 0));
    }
    let metadata = fs::symlink_metadata(directory).map_err(io_failure)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(MaintenanceFailureKind::PermissionDenied.into());
    }
    let (mut backups, mut temporary) = (0u64, 0u64);
    for entry in fs::read_dir(directory).map_err(io_failure)? {
        let entry = entry.map_err(io_failure)?;
        if entry.file_type().map_err(io_failure)?.is_dir() {
            let (b, t) = tree_sizes(&entry.path())?;
            backups = backups.saturating_add(b);
            temporary = temporary.saturating_add(t);
        } else {
            let bytes = checked_file_size(&entry.path())?;
            if entry.file_name() == "before.sqlite" || entry.file_name() == "owner.json" {
                backups = backups.saturating_add(bytes);
            } else {
                temporary = temporary.saturating_add(bytes);
            }
        }
    }
    Ok((backups, temporary))
}
fn footprint(path: &Path) -> MaintenanceResult<MaintenanceFootprint> {
    let mut result = auxiliary_footprint(path)?;
    result.catalog_bytes = checked_file_size(path)?;
    result.wal_bytes = checked_file_size(&sidecar(path, "-wal"))?;
    result.shm_bytes = checked_file_size(&sidecar(path, "-shm"))?;
    Ok(result)
}
fn auxiliary_footprint(path: &Path) -> MaintenanceResult<MaintenanceFootprint> {
    let root = path
        .parent()
        .ok_or(MaintenanceFailureKind::UnsupportedTarget)?
        .join(".maintenance");
    let queue = root.join("queue.sqlite");
    let (backups, copies) = tree_sizes(&root.join("jobs"))?;
    let (temporary_named_backups, temporary) = tree_sizes(&root.join("tmp"))?;
    Ok(MaintenanceFootprint {
        catalog_bytes: 0,
        wal_bytes: 0,
        shm_bytes: 0,
        queue_bytes: checked_file_size(&queue)?
            .saturating_add(checked_file_size(&sidecar(&queue, "-wal"))?)
            .saturating_add(checked_file_size(&sidecar(&queue, "-shm"))?)
            .saturating_add(checked_file_size(&sidecar(&queue, "-journal"))?),
        backup_bytes: backups,
        temporary_bytes: copies
            .saturating_add(temporary)
            .saturating_add(temporary_named_backups),
    })
}
fn total(footprint: &MaintenanceFootprint) -> u64 {
    [
        footprint.catalog_bytes,
        footprint.wal_bytes,
        footprint.shm_bytes,
        footprint.queue_bytes,
        footprint.backup_bytes,
        footprint.temporary_bytes,
    ]
    .into_iter()
    .fold(0, u64::saturating_add)
}
fn preflight(conn: &Connection, root: &Path, backup_needed: bool) -> MaintenanceResult<()> {
    preflight_available(
        conn,
        backup_needed,
        fs4::available_space(root).map_err(io_failure)?,
    )
}
fn preflight_available(
    conn: &Connection,
    backup_needed: bool,
    available: u64,
) -> MaintenanceResult<()> {
    let pages: u64 = conn
        .query_row("PRAGMA page_count", [], |r| row_u64(r, 0))
        .map_err(sql_failure)?;
    let page_size: u64 = conn
        .query_row("PRAGMA page_size", [], |r| row_u64(r, 0))
        .map_err(sql_failure)?;
    // Remaining backup, VACUUM's temporary copy + rebuilt DB/WAL, and reserve.
    let required = pages
        .saturating_mul(page_size)
        .saturating_mul(if backup_needed { 3 } else { 2 })
        .saturating_add(SPACE_RESERVE);
    if available < required {
        return Err(MaintenanceFailureKind::InsufficientSpace.into());
    }
    Ok(())
}

fn validate_selection(
    conn: &Connection,
    selection: &MaintenanceSelection,
) -> MaintenanceResult<()> {
    let items = selection_items(selection);
    if items.is_empty()
        || journal_plan_digest(&items) != selection.plan_digest
        || selection.aggregated_fields != JOURNAL_COMPACTION_FIELDS
        || items.windows(2).any(|pair| {
            (pair[0].target_generation, &pair[0].operation_id)
                >= (pair[1].target_generation, &pair[1].operation_id)
        })
    {
        return Err(MaintenanceFailureKind::SelectionChanged.into());
    }
    let mut statement = conn.prepare(
        "SELECT state, base_generation, target_generation, operation_digest, detail_format,
        upsert_ids_json, delete_ids_json, relation_upserts_json, relation_deletes_json, source_replacements_json
        FROM index_batches WHERE operation_id=?1").map_err(sql_failure)?;
    for item in &items {
        let row = statement
            .query_row([&item.operation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row_u64(row, 1)?,
                    row_u64(row, 2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    [
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ],
                ))
            })
            .optional()
            .map_err(sql_failure)?
            .ok_or(MaintenanceFailureKind::SelectionChanged)?;
        let (state, base, target, digest, format, details) = row;
        if !JOURNAL_TERMINAL_STATES.contains(&state.as_str())
            || format != JOURNAL_DETAIL_FORMAT_FULL
            || state != item.state
            || base != item.base_generation
            || target != item.target_generation
            || digest != item.operation_digest
            || journal_detail_digest(&details) != item.detail_digest
            || item.fields.len() != JOURNAL_COMPACTION_FIELDS.len()
        {
            return Err(MaintenanceFailureKind::SelectionChanged.into());
        }
        for ((name, text), field) in JOURNAL_COMPACTION_FIELDS
            .iter()
            .zip(&details)
            .zip(&item.fields)
        {
            if *name != field.field
                || text.len() as u64 != field.bytes
                || journal_detail_item_count(&item.operation_id, name, text)
                    .map_err(port_failure)?
                    != field.items
            {
                return Err(MaintenanceFailureKind::SelectionChanged.into());
            }
        }
    }
    Ok(())
}
fn committed_audit(conn: &Connection, job: &MaintenanceJob) -> MaintenanceResult<bool> {
    let stored = StoredJournalCompaction::load(conn, &job.compaction_id).map_err(port_failure)?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    let plan: JournalCompactionPlan = serde_json::from_str(&stored.plan_json)
        .map_err(|_| MaintenanceFailureKind::IntegrityFailed)?;
    if stored.event.state != "committed"
        || stored.event.plan_digest != job.selection.plan_digest
        || plan.version != JOURNAL_COMPACTION_PLAN_VERSION
        || plan.compaction_id != job.compaction_id
        || plan.aggregated_fields != job.selection.aggregated_fields
        || plan.items != selection_items(&job.selection)
    {
        return Err(MaintenanceFailureKind::SelectionChanged.into());
    }
    for item in &plan.items {
        let summary: Option<String> = conn.query_row("SELECT detail_summary_json FROM index_batches WHERE operation_id=?1 AND detail_format=?2",
            rusqlite::params![item.operation_id,JOURNAL_DETAIL_FORMAT_AGGREGATED_V1], |r| r.get(0)).optional().map_err(sql_failure)?.flatten();
        let summary: AggregatedJournalDetail =
            serde_json::from_str(&summary.ok_or(MaintenanceFailureKind::IntegrityFailed)?)
                .map_err(|_| MaintenanceFailureKind::IntegrityFailed)?;
        validate_aggregated_journal_detail(&item.operation_id, &summary).map_err(port_failure)?;
        if summary.compaction_id != job.compaction_id || summary.detail_digest != item.detail_digest
        {
            return Err(MaintenanceFailureKind::IntegrityFailed.into());
        }
    }
    Ok(true)
}
fn atomic_compact(conn: &mut Connection, job: &MaintenanceJob) -> MaintenanceResult<()> {
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(sql_failure)?;
    if committed_audit(&tx, job)? {
        return Ok(());
    }
    validate_selection(&tx, &job.selection)?;
    let items = selection_items(&job.selection);
    let plan = JournalCompactionPlan {
        version: JOURNAL_COMPACTION_PLAN_VERSION,
        compaction_id: job.compaction_id.clone(),
        aggregated_fields: job.selection.aggregated_fields.clone(),
        items,
    };
    let after: u64 = plan
        .items
        .iter()
        .map(|item| aggregated_journal_detail_bytes(&job.compaction_id, item).map_err(port_failure))
        .collect::<MaintenanceResult<Vec<_>>>()?
        .into_iter()
        .sum();
    let before = job.selection.detail_bytes_before;
    if after >= before {
        return Err(MaintenanceFailureKind::SelectionChanged.into());
    }
    let number = |value: u64| {
        i64::try_from(value).map_err(|_| MaintenanceFailure::from(MaintenanceFailureKind::Backend))
    };
    tx.execute("INSERT INTO journal_compactions(compaction_id,state,plan_json,plan_digest,affected_batches,detail_bytes_before,detail_bytes_after,saved_bytes,created_at_ms)
        VALUES(?1,'staged',?2,?3,?4,?5,?6,?7,?8)", rusqlite::params![
        job.compaction_id, serde_json::to_string(&plan).map_err(|_|MaintenanceFailureKind::Backend)?,
        job.selection.plan_digest, number(plan.items.len() as u64)?, number(before)?, number(after)?, number(before-after)?, unix_ms().map_err(port_failure)?
    ]).map_err(sql_failure)?;
    // Audit insert + exact selected rows + committed acknowledgement share ONE
    // transaction. The legacy staged/recovery API never sees partial new work.
    SqliteStore::apply_journal_compaction_in(&tx, &job.compaction_id).map_err(port_failure)?;
    tx.commit().map_err(sql_failure)
}

fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn hash_query(conn: &Connection, sql: &str, hash: &mut blake3::Hasher) -> MaintenanceResult<()> {
    let mut statement = conn.prepare(sql).map_err(sql_failure)?;
    let columns = statement.column_count();
    let mut rows = statement.query([]).map_err(sql_failure)?;
    while let Some(row) = rows.next().map_err(sql_failure)? {
        hash_field(hash, b"row");
        for column in 0..columns {
            match row.get_ref(column).map_err(sql_failure)? {
                ValueRef::Null => hash_field(hash, b"null"),
                ValueRef::Integer(value) => {
                    hash_field(hash, b"integer");
                    hash_field(hash, &value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hash_field(hash, b"real");
                    hash_field(hash, &value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => {
                    hash_field(hash, b"text");
                    hash_field(hash, value);
                }
                ValueRef::Blob(value) => {
                    hash_field(hash, b"blob");
                    hash_field(hash, value);
                }
            }
        }
    }
    Ok(())
}
/// Stream logical contents rather than DB bytes or implicit rowids. FTS logical
/// rowids ARE explicit here: their sidecar mapping and ranking must survive VACUUM.
/// The digest normalizes journal detail to its pre-compaction commitment, and
/// excludes only the separately checked compaction audit.
fn invariants(conn: &Connection) -> MaintenanceResult<String> {
    let mut hash = blake3::Hasher::new();
    hash_field(&mut hash, b"maintenance-invariants-v1");
    hash_query(
        conn,
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        &mut hash,
    )?;
    let mut statement = conn.prepare("SELECT name FROM pragma_table_list WHERE schema='main' AND type IN ('table','virtual') AND name NOT LIKE 'sqlite_%' AND name <> 'journal_compactions' ORDER BY name").map_err(sql_failure)?;
    let tables = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(sql_failure)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_failure)?;
    for table in tables {
        hash_field(&mut hash, table.as_bytes());
        if table == "index_batches" {
            hash_query(
                conn,
                "SELECT operation_id,base_generation,target_generation,state,operation_digest,durable_point,created_at_ms,committed_at_ms,error_code,relocation_json FROM index_batches ORDER BY operation_id",
                &mut hash,
            )?;
            let mut details = conn.prepare("SELECT detail_format,detail_summary_json,upsert_ids_json,delete_ids_json,relation_upserts_json,relation_deletes_json,source_replacements_json FROM index_batches ORDER BY operation_id").map_err(sql_failure)?;
            let mut rows = details.query([]).map_err(sql_failure)?;
            while let Some(row) = rows.next().map_err(sql_failure)? {
                let format: String = row.get(0).map_err(sql_failure)?;
                let digest = if format == JOURNAL_DETAIL_FORMAT_FULL {
                    journal_detail_digest(&[
                        row.get(2).map_err(sql_failure)?,
                        row.get(3).map_err(sql_failure)?,
                        row.get(4).map_err(sql_failure)?,
                        row.get(5).map_err(sql_failure)?,
                        row.get(6).map_err(sql_failure)?,
                    ])
                } else if format == JOURNAL_DETAIL_FORMAT_AGGREGATED_V1 {
                    let summary: String = row.get(1).map_err(sql_failure)?;
                    let summary: AggregatedJournalDetail = serde_json::from_str(&summary)
                        .map_err(|_| MaintenanceFailureKind::IntegrityFailed)?;
                    summary.detail_digest
                } else {
                    return Err(MaintenanceFailureKind::UnsupportedTarget.into());
                };
                hash_field(&mut hash, digest.as_bytes());
            }
            continue;
        }
        let quoted = quote_identifier(&table);
        let columns = conn
            .prepare(&format!("SELECT * FROM {quoted} LIMIT 0"))
            .map_err(sql_failure)?
            .column_count();
        let order = (1..=columns)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let (projection, order) = if table == "fts" || table == "session_fts" {
            ("rowid,*", "rowid".to_owned())
        } else {
            ("*", order)
        };
        hash_query(
            conn,
            &format!("SELECT {projection} FROM {quoted} ORDER BY {order}"),
            &mut hash,
        )?;
    }
    Ok(hash.finalize().to_hex().to_string())
}
fn check_integrity(conn: &Connection, fts_command: bool) -> MaintenanceResult<()> {
    schema(conn)?;
    let mut statement = conn
        .prepare("PRAGMA integrity_check")
        .map_err(sql_failure)?;
    let mut rows = statement.query([]).map_err(sql_failure)?;
    if rows
        .next()
        .map_err(sql_failure)?
        .ok_or(MaintenanceFailureKind::IntegrityFailed)?
        .get::<_, String>(0)
        .map_err(sql_failure)?
        != "ok"
        || rows.next().map_err(sql_failure)?.is_some()
    {
        return Err(MaintenanceFailureKind::IntegrityFailed.into());
    }
    drop(rows);
    drop(statement);
    for sql in [
        "SELECT EXISTS(SELECT 1 FROM fts_ids i LEFT JOIN fts f ON f.rowid=i.fts_rowid WHERE i.fts_rowid IS NOT NULL AND (f.rowid IS NULL OR f.id<>i.id_json)) OR EXISTS(SELECT 1 FROM fts f LEFT JOIN fts_ids i ON i.fts_rowid=f.rowid WHERE i.wire_id IS NULL)",
        "SELECT EXISTS(SELECT 1 FROM session_fts_ids i LEFT JOIN session_fts f ON f.rowid=i.fts_rowid WHERE f.rowid IS NULL OR f.session_wire<>i.session_wire) OR EXISTS(SELECT 1 FROM session_fts f LEFT JOIN session_fts_ids i ON i.fts_rowid=f.rowid WHERE i.session_wire IS NULL)",
    ] {
        if conn
            .query_row(sql, [], |r| r.get::<_, bool>(0))
            .map_err(sql_failure)?
        {
            return Err(MaintenanceFailureKind::IntegrityFailed.into());
        }
    }
    if fts_command {
        conn.execute_batch("INSERT INTO fts(fts) VALUES('integrity-check'); INSERT INTO session_fts(session_fts) VALUES('integrity-check');").map_err(sql_failure)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct BackupOwner {
    version: u32,
    job_id: String,
    token: String,
    compaction_id: String,
    target_path: String,
    target_identity: String,
}
fn owner(job: &MaintenanceJob) -> BackupOwner {
    BackupOwner {
        version: 1,
        job_id: job.id.clone(),
        token: job.token.clone(),
        compaction_id: job.compaction_id.clone(),
        target_path: job.target.canonical_path.clone(),
        target_identity: job.target.file_identity.clone(),
    }
}
fn backup_relative_path(job: &MaintenanceJob) -> String {
    let mut hash = blake3::Hasher::new();
    hash_field(&mut hash, job.id.as_bytes());
    hash_field(&mut hash, job.token.as_bytes());
    format!(
        ".maintenance/jobs/{}/before.sqlite",
        hash.finalize().to_hex()
    )
}
fn backup_path(job: &MaintenanceJob, backup: &MaintenanceBackup) -> MaintenanceResult<PathBuf> {
    if backup.relative_path != backup_relative_path(job) {
        return Err(MaintenanceFailureKind::IntegrityFailed.into());
    }
    let root = Path::new(&job.target.canonical_path)
        .parent()
        .ok_or(MaintenanceFailureKind::TargetChanged)?;
    Ok(root.join(&backup.relative_path))
}
fn create_private_file(path: &Path) -> MaintenanceResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io_failure)
}
fn validate_owned_directory(
    job: &MaintenanceJob,
    path: &Path,
    create: bool,
) -> MaintenanceResult<PathBuf> {
    let root = Path::new(&job.target.canonical_path)
        .parent()
        .ok_or(MaintenanceFailureKind::TargetChanged)?;
    let directory = path
        .parent()
        .ok_or(MaintenanceFailureKind::IntegrityFailed)?;
    for ancestor in [
        root.join(".maintenance"),
        root.join(".maintenance/jobs"),
        directory.to_owned(),
    ] {
        if !create && !ancestor.exists() {
            return Err(MaintenanceFailureKind::IntegrityFailed.into());
        }
        private_directory(&ancestor)?;
        if !fs::canonicalize(&ancestor)
            .map_err(io_failure)?
            .starts_with(root)
        {
            return Err(MaintenanceFailureKind::PermissionDenied.into());
        }
    }
    let marker = directory.join("owner.json");
    let expected = owner(job);
    if !marker.exists() && create {
        let bytes = serde_json::to_vec(&expected).map_err(|_| MaintenanceFailureKind::Backend)?;
        let mut file = create_private_file(&marker)?;
        file.write_all(&bytes).map_err(io_failure)?;
        file.sync_all().map_err(io_failure)?;
        sync_directory(directory)?;
    }
    checked_file_size(&marker)?;
    let actual: BackupOwner = serde_json::from_slice(&fs::read(&marker).map_err(io_failure)?)
        .map_err(|_| MaintenanceFailureKind::IntegrityFailed)?;
    if actual != expected {
        return Err(MaintenanceFailureKind::IntegrityFailed.into());
    }
    Ok(directory.to_owned())
}
fn install_progress(
    conn: &Connection,
    deadline: Instant,
    control: &MaintenanceControl,
) -> MaintenanceResult<()> {
    let control = control.clone();
    conn.progress_handler(
        1000,
        Some(move || control.check().is_err() || Instant::now() >= deadline),
    )
    .map_err(sql_failure)
}
fn verify_backup(
    path: &Path,
    backup: &MaintenanceBackup,
    deadline: Instant,
    control: &MaintenanceControl,
) -> MaintenanceResult<()> {
    if checked_file_size(path)? == 0 {
        return Err(MaintenanceFailureKind::IntegrityFailed.into());
    }
    let conn =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(sql_failure)?;
    conn.busy_timeout(Duration::ZERO).map_err(sql_failure)?;
    install_progress(&conn, deadline, control)?;
    check_integrity(&conn, false)?;
    if generation(&conn)? != backup.source_generation
        || invariants(&conn)? != backup.invariant_digest
    {
        return Err(MaintenanceFailureKind::IntegrityFailed.into());
    }
    Ok(())
}
fn remove_owned_file(path: &Path) -> MaintenanceResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(io_failure)
        }
        Ok(_) => Err(MaintenanceFailureKind::PermissionDenied.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_failure(error)),
    }
}

impl SqliteMaintenanceSession {
    fn check(&self, control: &MaintenanceControl) -> MaintenanceResult<()> {
        control.check()?;
        if Instant::now() >= self.deadline {
            return Err(MaintenanceFailureKind::BudgetExhausted.into());
        }
        Ok(())
    }
    fn fresh_intent(&self, job: &MaintenanceJob) -> MaintenanceResult<MaintenanceBackup> {
        Ok(MaintenanceBackup {
            relative_path: backup_relative_path(job),
            source_generation: generation(&self.conn)?,
            invariant_digest: invariants(&self.conn)?,
            verified: false,
        })
    }
    fn backup(
        &self,
        job: &MaintenanceJob,
        control: &MaintenanceControl,
        result: &mut MaintenanceStageResult,
    ) -> MaintenanceResult<()> {
        let mut intent = job
            .backup
            .clone()
            .ok_or(MaintenanceFailureKind::IntegrityFailed)?;
        let path = backup_path(job, &intent)?;
        let directory = validate_owned_directory(job, &path, true)?;
        let temporary = directory.join("copy.sqlite");
        // A published, verified snapshot belongs to this job forever. Later
        // catalog generations are neither a reason to replace nor restore it.
        if path.exists() {
            verify_backup(&path, &intent, self.deadline, control)?;
        } else {
            if intent.verified {
                return Err(MaintenanceFailureKind::IntegrityFailed.into());
            }
            if temporary.exists() {
                // A crash after a complete copy but before publication can be
                // adopted. Invalid/incomplete owned copies may be discarded.
                match verify_backup(&temporary, &intent, self.deadline, control) {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.kind,
                            MaintenanceFailureKind::IntegrityFailed
                                | MaintenanceFailureKind::UnsupportedTarget
                                | MaintenanceFailureKind::Backend
                        ) =>
                    {
                        self.check(control)?;
                        remove_owned_file(&temporary)?;
                        for suffix in ["-wal", "-shm", "-journal"] {
                            remove_owned_file(&sidecar(&temporary, suffix))?;
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            if !temporary.exists() {
                let current = self.fresh_intent(job)?;
                if current.source_generation != intent.source_generation
                    || current.invariant_digest != intent.invariant_digest
                {
                    // Queue must persist the new snapshot intent BEFORE any copy.
                    result.backup = Some(current);
                    result.next_phase = Some(MaintenancePhase::Backup);
                    return Ok(());
                }
                preflight(
                    &self.conn,
                    self.path
                        .parent()
                        .ok_or(MaintenanceFailureKind::TargetChanged)?,
                    true,
                )?;
                self.check(control)?;
                let file = create_private_file(&temporary)?;
                file.sync_all().map_err(io_failure)?;
                drop(file);
                let mut copied =
                    Connection::open_with_flags(&temporary, OpenFlags::SQLITE_OPEN_READ_WRITE)
                        .map_err(sql_failure)?;
                copied.busy_timeout(Duration::ZERO).map_err(sql_failure)?;
                install_progress(&copied, self.deadline, control)?;
                {
                    let transaction = self.conn.unchecked_transaction().map_err(sql_failure)?;
                    // Pin the source snapshot before the first incremental step.
                    if generation(&transaction)? != intent.source_generation {
                        return Err(MaintenanceFailureKind::SelectionChanged.into());
                    }
                    let backup = Backup::new(&transaction, &mut copied).map_err(sql_failure)?;
                    loop {
                        self.check(control)?;
                        match backup.step(128).map_err(sql_failure)? {
                            StepResult::Done => break,
                            StepResult::More => {}
                            StepResult::Busy | StepResult::Locked => {
                                return Err(MaintenanceFailureKind::Busy.into());
                            }
                            _ => return Err(MaintenanceFailureKind::Backend.into()),
                        }
                    }
                    // Backup::Drop finishes before copied may be accessed.
                }
                self.check(control)?;
                copied
                    .execute_batch("PRAGMA journal_mode=DELETE;")
                    .map_err(sql_failure)?;
                check_integrity(&copied, true)?;
                if generation(&copied)? != intent.source_generation
                    || invariants(&copied)? != intent.invariant_digest
                {
                    return Err(MaintenanceFailureKind::IntegrityFailed.into());
                }
                copied.close().map_err(|(_, error)| sql_failure(error))?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&temporary)
                    .and_then(|f| f.sync_all())
                    .map_err(io_failure)?;
            }
            self.check(control)?;
            // An adopted crash-time copy may still have a WAL. Finalize it on
            // EVERY publication path, never publish only its main file.
            let copied = Connection::open_with_flags(&temporary, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(sql_failure)?;
            copied.busy_timeout(Duration::ZERO).map_err(sql_failure)?;
            install_progress(&copied, self.deadline, control)?;
            copied
                .execute_batch("PRAGMA journal_mode=DELETE;")
                .map_err(sql_failure)?;
            check_integrity(&copied, true)?;
            copied.close().map_err(|(_, error)| sql_failure(error))?;
            verify_backup(&temporary, &intent, self.deadline, control)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temporary)
                .and_then(|f| f.sync_all())
                .map_err(io_failure)?;
            self.check(control)?;
            // hard_link is atomic no-clobber publication. Both names are within
            // one private directory and filesystem. Never rename over a target.
            fs::hard_link(&temporary, &path).map_err(io_failure)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .and_then(|f| f.sync_all())
                .map_err(io_failure)?;
            sync_directory(&directory)?;
            verify_backup(&path, &intent, self.deadline, control)?;
        }
        remove_owned_file(&temporary)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            remove_owned_file(&sidecar(&temporary, suffix))?;
        }
        sync_directory(&directory)?;
        intent.verified = true;
        result.backup = Some(intent);
        Ok(())
    }
    fn run_stage(
        &mut self,
        phase: MaintenancePhase,
        job: &MaintenanceJob,
        control: &MaintenanceControl,
    ) -> MaintenanceResult<MaintenanceStageResult> {
        self.check(control)?;
        target_matches(&job.target)?;
        install_progress(&self.conn, self.deadline, control)?;
        if self.baseline.is_none() {
            self.baseline = Some(invariants(&self.conn)?);
        }
        let mut result = MaintenanceStageResult {
            metrics: job.metrics.clone(),
            logical_compaction_committed: job.logical_compaction_committed,
            ..Default::default()
        };
        if total(&result.metrics.before) == 0 {
            result.metrics.before = footprint(&self.path)?;
        }
        match phase {
            MaintenancePhase::Validate => {
                if committed_audit(&self.conn, job)? {
                    result.logical_compaction_committed = true;
                    result.next_phase = Some(MaintenancePhase::Vacuum);
                } else {
                    validate_selection(&self.conn, &job.selection)?;
                    preflight(
                        &self.conn,
                        self.path
                            .parent()
                            .ok_or(MaintenanceFailureKind::TargetChanged)?,
                        job.backup.as_ref().is_none_or(|b| !b.verified),
                    )?;
                    result.backup = Some(self.fresh_intent(job)?);
                }
            }
            MaintenancePhase::Backup => self.backup(job, control, &mut result)?,
            MaintenancePhase::Compact => {
                let backup = job
                    .backup
                    .as_ref()
                    .filter(|b| b.verified)
                    .ok_or(MaintenanceFailureKind::IntegrityFailed)?;
                let path = backup_path(job, backup)?;
                validate_owned_directory(job, &path, false)?;
                verify_backup(&path, backup, self.deadline, control)?;
                atomic_compact(&mut self.conn, job)?;
                result.logical_compaction_committed = true;
            }
            MaintenancePhase::Vacuum => {
                if !committed_audit(&self.conn, job)? {
                    return Err(MaintenanceFailureKind::IntegrityFailed.into());
                }
                preflight(
                    &self.conn,
                    self.path
                        .parent()
                        .ok_or(MaintenanceFailureKind::TargetChanged)?,
                    false,
                )?;
                self.conn.execute_batch("VACUUM;").map_err(sql_failure)?;
                target_matches(&job.target)?;
            }
            MaintenancePhase::Checkpoint => {
                let (busy, log, done): (i64, i64, i64) = self
                    .conn
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .map_err(sql_failure)?;
                if busy != 0 || (log >= 0 && log != done) {
                    return Err(MaintenanceFailureKind::Busy.into());
                }
            }
            MaintenancePhase::Verify => {
                check_integrity(&self.conn, true)?;
                if !committed_audit(&self.conn, job)?
                    || self.baseline.as_deref() != Some(invariants(&self.conn)?.as_str())
                {
                    return Err(MaintenanceFailureKind::IntegrityFailed.into());
                }
            }
            MaintenancePhase::Cleanup => {
                if self.baseline.as_deref() != Some(invariants(&self.conn)?.as_str()) {
                    return Err(MaintenanceFailureKind::IntegrityFailed.into());
                }
                cleanup_files(job).map_err(|_| MaintenanceFailureKind::CleanupFailed)?;
            }
            MaintenancePhase::Done => {}
        }
        if matches!(phase, MaintenancePhase::Compact | MaintenancePhase::Vacuum)
            && self.baseline.as_deref() != Some(invariants(&self.conn)?.as_str())
        {
            return Err(MaintenanceFailureKind::IntegrityFailed.into());
        }
        result.metrics.peak_memory_bytes =
            result.metrics.peak_memory_bytes.max(peak_process_memory());
        result.metrics.after = footprint(&self.path).map_err(|error| {
            if phase == MaintenancePhase::Cleanup {
                MaintenanceFailureKind::CleanupFailed.into()
            } else {
                error
            }
        })?;
        result.metrics.reclaimed_bytes =
            total(&result.metrics.before).saturating_sub(total(&result.metrics.after));
        result.metrics.max_writer_lock_millis = result
            .metrics
            .max_writer_lock_millis
            .max(self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        Ok(result)
    }
}
impl MaintenanceSession for SqliteMaintenanceSession {
    fn execute(
        &mut self,
        phase: MaintenancePhase,
        job: &MaintenanceJob,
        control: &MaintenanceControl,
    ) -> MaintenanceResult<MaintenanceStageResult> {
        match self.run_stage(phase, job, control) {
            Ok(result) => Ok(result), // A committed stage MUST be acknowledged even at the deadline.
            Err(error) => {
                self.check(control)?;
                Err(error)
            }
        }
    }
}
fn cleanup_files(job: &MaintenanceJob) -> MaintenanceResult<()> {
    let backup = job
        .backup
        .as_ref()
        .ok_or(MaintenanceFailureKind::CleanupFailed)?;
    let path = backup_path(job, backup)?;
    let directory = path.parent().ok_or(MaintenanceFailureKind::CleanupFailed)?;
    if !directory.exists() {
        return Ok(());
    }
    // A previous cleanup may have removed the marker last and crashed before
    // removing the now-empty directory. No recursive deletion is ever used.
    if !directory.join("owner.json").exists() {
        if fs::symlink_metadata(directory)
            .map_err(io_failure)?
            .file_type()
            .is_symlink()
        {
            return Err(MaintenanceFailureKind::CleanupFailed.into());
        }
        fs::remove_dir(directory).map_err(io_failure)?;
        return sync_directory(
            directory
                .parent()
                .ok_or(MaintenanceFailureKind::CleanupFailed)?,
        );
    }
    validate_owned_directory(job, &path, false)?;
    let allowed = [
        "before.sqlite",
        "copy.sqlite",
        "copy.sqlite-wal",
        "copy.sqlite-shm",
        "copy.sqlite-journal",
        "owner.json",
    ];
    for entry in fs::read_dir(directory).map_err(io_failure)? {
        let entry = entry.map_err(io_failure)?;
        if !allowed.iter().any(|name| entry.file_name() == *name) {
            return Err(MaintenanceFailureKind::CleanupFailed.into());
        }
    }
    for name in allowed {
        remove_owned_file(&directory.join(name))?;
    }
    sync_directory(directory)?;
    fs::remove_dir(directory).map_err(io_failure)?;
    sync_directory(
        directory
            .parent()
            .ok_or(MaintenanceFailureKind::CleanupFailed)?,
    )
}

/// After the queue's durable cleanup cutoff, recovery must finish owned cleanup
/// even if the catalog has since disappeared, changed, or acquired a writer.
struct CleanupSession;
impl MaintenanceSession for CleanupSession {
    fn holds_writer_lease(&self) -> bool {
        false
    }
    fn execute(
        &mut self,
        phase: MaintenancePhase,
        job: &MaintenanceJob,
        control: &MaintenanceControl,
    ) -> MaintenanceResult<MaintenanceStageResult> {
        if phase != MaintenancePhase::Cleanup || !job.cleanup_started {
            return Err(MaintenanceFailureKind::CleanupFailed.into());
        }
        if control.paused.load(std::sync::atomic::Ordering::Acquire) {
            return Err(MaintenanceFailureKind::Paused.into());
        }
        cleanup_files(job).map_err(|_| MaintenanceFailureKind::CleanupFailed)?;
        let mut metrics = job.metrics.clone();
        let auxiliary = auxiliary_footprint(Path::new(&job.target.canonical_path))
            .map_err(|_| MaintenanceFailureKind::CleanupFailed)?;
        metrics.after.queue_bytes = auxiliary.queue_bytes;
        metrics.after.backup_bytes = auxiliary.backup_bytes;
        metrics.after.temporary_bytes = auxiliary.temporary_bytes;
        metrics.peak_memory_bytes = metrics.peak_memory_bytes.max(peak_process_memory());
        metrics.reclaimed_bytes = total(&metrics.before).saturating_sub(total(&metrics.after));
        Ok(MaintenanceStageResult {
            logical_compaction_committed: job.logical_compaction_committed,
            metrics,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests;
