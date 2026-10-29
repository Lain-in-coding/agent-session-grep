//! Explicit first managed activation from a read-only schema-19 logical copy.
//! No provider source, legacy inode, WAL, control policy or canonical namespace
//! is rewritten. Copied merged rows are unverified and never become evidence.
use crate::{
    SqliteControlStore, WriterLease,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_maintenance::{set_sql_deadline, verify_derived_integrity},
    managed_store::{APPLICATION_ID, LegacyActivation, ManagedStore, validate_catalog_path},
};
use agent_session_grep_domain::{SessionIdentityNamespace, StableId};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider,
    control::{ControlId, ControlStore, MaintenanceState},
};
use rusqlite::{Connection, OpenFlags, backup, types::ValueRef};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
const INTENT_SCHEMA: &str = "asg.legacy-migration/v1";
const MAX_LOGICAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_CELL_BYTES: usize = 16 * 1024 * 1024;
const TABLES: [&str; 24] = [
    "catalog",
    "store_metadata",
    "index_batches",
    "fts_ids",
    "source_membership",
    "source_scans",
    "message_placements",
    "message_edges",
    "source_placement_membership",
    "source_relation_scans",
    "source_session_resume_claims",
    "message_vec",
    "session_fts_ids",
    "tool_activities",
    "tool_activity_membership",
    "session_titles",
    "usage_events",
    "usage_event_membership",
    "session_repo_slugs",
    "installation_namespaces",
    "installation_locations",
    "source_installations",
    "installation_relocations",
    "journal_compactions",
];
fn invalid() -> PortError {
    PortError::InvalidRequest("invalid legacy migration request".into())
}
fn incompatible() -> PortError {
    PortError::SchemaIncompatible(
        "legacy migration requires verified recovery or a supported pre-Beta catalog".into(),
    )
}
fn changed() -> PortError {
    PortError::SnapshotChanged("legacy migration snapshot changed".into())
}
fn io() -> PortError {
    PortError::SourceIo("legacy migration private storage unavailable".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => busy(),
        _ => incompatible(),
    }
}
fn busy() -> PortError {
    PortError::WriterBusy("legacy migration deadline or receiving gate is busy".into())
}
fn check(end: Instant) -> PortResult<()> {
    if Instant::now() >= end {
        Err(busy())
    } else {
        Ok(())
    }
}

/// Private inspection proof, rechecked against the backend snapshot before
/// publication. Source locators/namespace inputs stay private; no handle escapes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyInspection {
    source: PathBuf,
    source_identity: String,
    generation: u64,
    logical_bytes: u64,
    canonical_entities: u64,
    namespace_count: u64,
    namespace_digest: String,
    identity_digest: String,
    snapshot_digest: String,
}
impl std::fmt::Debug for LegacyInspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacyInspection([private])")
    }
}
impl LegacyInspection {
    pub fn schema_version(&self) -> u32 {
        19
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn namespace_count(&self) -> u64 {
        self.namespace_count
    }
    pub fn namespace_digest(&self) -> &str {
        &self.namespace_digest
    }
    pub fn canonical_entities(&self) -> u64 {
        self.canonical_entities
    }
    pub fn identity_digest(&self) -> &str {
        &self.identity_digest
    }
}
/// The destination is a NEW file directly in the already-private control root.
/// Parent explicitly prepares installation/incarnation in control beforehand.
pub struct LegacyMigrationRequest<'a> {
    pub source: &'a Path,
    pub destination: &'a Path,
    pub inspected: &'a LegacyInspection,
    pub installation: &'a ControlId,
    pub incarnation: &'a ControlId,
    pub operation: &'a ControlId,
    pub now_ms: i64,
    pub deadline: Instant,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReceipt {
    pub operation: ControlId,
    pub installation: ControlId,
    pub incarnation: ControlId,
    pub generation: u64,
    pub canonical_entities: u64,
    pub namespace_digest: String,
    /// Explicit classification: copied merged rows have no source proof.
    pub classification: LegacyClassification,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyClassification {
    MergedUnverified,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    operation: String,
    installation: String,
    incarnation: String,
    root_identity: String,
    destination: String,
    policy_epoch: i64,
    inspected: LegacyInspection,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileBinding {
    schema: String,
    operation: String,
    identity: String,
}
fn suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
fn marker(path: &Path) -> PathBuf {
    suffix(path, ".asg-managed-create")
}
fn bound(path: &Path) -> PathBuf {
    suffix(path, ".asg-legacy-file")
}
fn file_exists(path: &Path) -> PortResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(io()),
    }
}
fn write_record(
    control: &SqliteControlStore,
    path: &Path,
    value: &impl Serialize,
) -> PortResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid());
    }
    control.create_private_catalog_file(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| io())?;
    file.write_all(&bytes).map_err(|_| io())?;
    file.sync_all().map_err(|_| io())?;
    sync_parent(path)
}
fn read_record<T: serde::de::DeserializeOwned>(
    control: &SqliteControlStore,
    path: &Path,
) -> PortResult<T> {
    let mut file = control.open_private_read(path)?;
    if file.metadata().map_err(|_| io())?.len() > MAX_RECORD_BYTES {
        return Err(incompatible());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| io())?;
    control.validate_private_read(path, &file)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(incompatible());
    }
    serde_json::from_slice(&bytes).map_err(|_| incompatible())
}
fn pin_owned(
    control: &SqliteControlStore,
    path: &Path,
    expected_identity: &str,
) -> PortResult<File> {
    control.validate_catalog_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Permit SQLite reads/writes, but retain the inode against deletion or
        // replacement while its connection operates. Reader marks are allowed.
        options
            .access_mode(0x80000000 | 0x00020000 | 0x00000080)
            .custom_flags(0x00200000)
            .share_mode(3);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o4000 | 0o2000000);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x100 | 0x4 | 0x01000000);
    }
    let file = options.open(path).map_err(|_| io())?;
    control.validate_private_read(path, &file)?;
    if file_identity(&file)? != expected_identity {
        return Err(changed());
    }
    Ok(file)
}
fn sync_owned(
    control: &SqliteControlStore,
    path: &Path,
    expected_identity: &str,
) -> PortResult<()> {
    control.validate_catalog_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000).share_mode(1);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o4000 | 0o2000000);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x100 | 0x4 | 0x01000000);
    }
    let file = options.open(path).map_err(|_| io())?;
    control.validate_private_read(path, &file)?;
    if file_identity(&file)? != expected_identity {
        return Err(changed());
    }
    file.sync_all().map_err(|_| io())?;
    drop(file);
    sync_parent(path)
}
fn sync_parent(path: &Path) -> PortResult<()> {
    #[cfg(unix)]
    File::open(path.parent().ok_or_else(invalid)?)
        .and_then(|file| file.sync_all())
        .map_err(|_| io())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn ordinary_source(path: &Path) -> PortResult<()> {
    validate_catalog_path(path)?;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid());
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| io())?;
        if metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
        }
    }
    if !fs::metadata(path).map_err(|_| io())?.is_file() {
        return Err(invalid());
    }
    Ok(())
}
fn source_file(path: &Path) -> PortResult<File> {
    ordinary_source(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000).share_mode(7);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o4000 | 0o2000000);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x100 | 0x4 | 0x01000000);
    }
    let file = options.open(path).map_err(|_| io())?;
    if !file.metadata().map_err(|_| io())?.is_file() {
        return Err(invalid());
    }
    Ok(file)
}
fn file_identity(file: &File) -> PortResult<String> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"asg-legacy-file-identity-v1\0");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(|_| io())?;
        if m.nlink() != 1 {
            return Err(invalid());
        }
        digest.update(&m.dev().to_le_bytes());
        digest.update(&m.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io());
        }
        if info.nNumberOfLinks != 1 {
            return Err(invalid());
        }
        digest.update(&info.dwVolumeSerialNumber.to_le_bytes());
        digest.update(&info.nFileIndexHigh.to_le_bytes());
        digest.update(&info.nFileIndexLow.to_le_bytes());
    }
    #[cfg(not(any(unix, windows)))]
    return Err(incompatible());
    Ok(digest.finalize().to_hex().to_string())
}
fn source_connection(path: &Path, end: Instant) -> PortResult<Connection> {
    check(end)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    set_sql_deadline(&conn, end)?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA foreign_keys=ON;")
        .map_err(sql)?;
    Ok(conn)
}
fn number(conn: &Connection, query: &str) -> PortResult<u64> {
    let value: i64 = conn.query_row(query, [], |row| row.get(0)).map_err(sql)?;
    u64::try_from(value).map_err(|_| incompatible())
}
fn field(hash: &mut blake3::Hasher, bytes: &[u8]) -> PortResult<()> {
    if bytes.len() > MAX_CELL_BYTES {
        return Err(incompatible());
    }
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    Ok(())
}
fn digest_query(conn: &Connection, query: &str, end: Instant) -> PortResult<String> {
    let mut hash = blake3::Hasher::new();
    field(&mut hash, query.as_bytes())?;
    let mut statement = conn.prepare(query).map_err(sql)?;
    let columns = statement.column_count();
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        check(end)?;
        hash.update(b"row\0");
        for column in 0..columns {
            match row.get_ref(column).map_err(sql)? {
                ValueRef::Null => {
                    hash.update(b"n");
                }
                ValueRef::Integer(value) => {
                    hash.update(b"i");
                    field(&mut hash, &value.to_le_bytes())?;
                }
                ValueRef::Real(value) => {
                    hash.update(b"r");
                    field(&mut hash, &value.to_bits().to_le_bytes())?;
                }
                ValueRef::Text(value) => {
                    hash.update(b"t");
                    field(&mut hash, value)?;
                }
                ValueRef::Blob(value) => {
                    hash.update(b"b");
                    field(&mut hash, value)?;
                }
            }
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}
fn validate_legacy(conn: &Connection, end: Instant) -> PortResult<()> {
    if number(conn, "PRAGMA user_version")? != 19 || number(conn, "PRAGMA application_id")? != 0 {
        return Err(incompatible());
    }
    let mut statement = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").map_err(sql)?;
    let mut names = std::collections::BTreeSet::new();
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        check(end)?;
        let name: String = row.get(0).map_err(sql)?;
        let fts = ["fts", "session_fts"].iter().any(|prefix| {
            name == *prefix
                || ["_data", "_idx", "_content", "_docsize", "_config"]
                    .iter()
                    .any(|suffix| name == format!("{prefix}{suffix}"))
        });
        if !TABLES.contains(&name.as_str()) && !fts {
            return Err(incompatible());
        }
        names.insert(name);
    }
    if TABLES.iter().any(|name| !names.contains(*name)) {
        return Err(incompatible());
    }
    let invalid_state: bool = conn.query_row(
        "SELECT (SELECT count(*) FROM store_metadata)<>1
          OR EXISTS(SELECT 1 FROM pragma_table_info('store_metadata') WHERE name IN ('managed_mode','projection_contract_version','destructive_epoch'))
          OR EXISTS(SELECT 1 FROM sqlite_schema WHERE type IN ('view','trigger') AND name NOT LIKE 'sqlite_%')
          OR EXISTS(SELECT 1 FROM index_batches WHERE state NOT IN ('activated','aborted','superseded') OR detail_format NOT IN ('full','aggregated_v1') OR base_generation<0 OR target_generation<>base_generation+1)
          OR EXISTS(SELECT 1 FROM journal_compactions WHERE state NOT IN ('committed','abandoned'))
          OR EXISTS(SELECT 1 FROM installation_namespaces WHERE origin NOT IN ('legacy-v1','allocated-v1') OR created_at_ms<0)
          OR EXISTS(SELECT 1 FROM installation_locations WHERE state NOT IN ('current','retired') OR (state='current' AND retired_until_ms IS NOT NULL) OR (state='retired' AND retired_until_ms IS NULL))",
        [], |row| row.get(0),
    ).map_err(sql)?;
    if invalid_state {
        return Err(incompatible());
    }
    let integrity: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(sql)?;
    if integrity != "ok"
        || conn
            .prepare("PRAGMA foreign_key_check")
            .map_err(sql)?
            .query([])
            .map_err(sql)?
            .next()
            .map_err(sql)?
            .is_some()
    {
        return Err(incompatible());
    }
    // A recorded provider-native Session must still agree with its frozen
    // namespace seed; no new root or control installation ID enters derivation.
    let mut statement = conn.prepare("SELECT n.provider_id,n.namespace_input,c.session_id,c.provider_session_id FROM source_session_resume_claims c JOIN source_installations s USING(source_path) JOIN installation_namespaces n USING(namespace_id) WHERE c.provider_session_id_state='resolved'").map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        check(end)?;
        let provider: String = row.get(0).map_err(sql)?;
        let input: String = row.get(1).map_err(sql)?;
        let session: String = row.get(2).map_err(sql)?;
        let native: String = row.get(3).map_err(sql)?;
        if SearchProvider::parse(&provider).is_none_or(|p| p.as_str() != provider)
            || StableId::native_session_scoped(
                &SessionIdentityNamespace {
                    provider_id: &provider,
                    installation_namespace: &input,
                },
                &native,
            )
            .as_str()
                != session
        {
            return Err(incompatible());
        }
    }
    Ok(())
}
fn inspect_snapshot(
    conn: &Connection,
    source: &Path,
    identity: &str,
    end: Instant,
) -> PortResult<LegacyInspection> {
    validate_legacy(conn, end)?;
    let bytes = number(conn, "PRAGMA page_count")?
        .checked_mul(number(conn, "PRAGMA page_size")?)
        .ok_or_else(incompatible)?;
    if bytes == 0 || bytes > MAX_LOGICAL_BYTES {
        return Err(incompatible());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"asg-legacy-snapshot-v1\0");
    for table in TABLES {
        let digest = digest_query(conn, &format!("SELECT * FROM {table} ORDER BY rowid"), end)?;
        field(&mut hash, table.as_bytes())?;
        field(&mut hash, digest.as_bytes())?;
    }
    Ok(LegacyInspection {
        source: source.into(),
        source_identity: identity.into(),
        logical_bytes: bytes,
        generation: number(
            conn,
            "SELECT active_generation FROM store_metadata WHERE singleton=1",
        )?,
        canonical_entities: number(conn, "SELECT count(*) FROM catalog")?,
        namespace_count: number(conn, "SELECT count(*) FROM installation_namespaces")?,
        namespace_digest: digest_query(
            conn,
            "SELECT namespace_id,provider_id,namespace_input,origin,created_at_ms FROM installation_namespaces ORDER BY namespace_id",
            end,
        )?,
        identity_digest: digest_query(
            conn,
            "SELECT c.id,i.id_json FROM catalog c LEFT JOIN fts_ids i ON i.wire_id=c.id ORDER BY c.id",
            end,
        )?,
        snapshot_digest: hash.finalize().to_hex().to_string(),
    })
}
/// No migration or writer lease on the source. The read transaction pins
/// committed WAL data; SQLite may update only its normal SHM reader marks.
pub fn inspect_legacy(source: &Path, deadline: Instant) -> PortResult<LegacyInspection> {
    check(deadline)?;
    crate::managed_store::reject_creation_intent(source)?;
    let file = source_file(source)?;
    let identity = file_identity(&file)?;
    let conn = source_connection(source, deadline)?;
    let tx = conn.unchecked_transaction().map_err(sql)?;
    let result = inspect_snapshot(&tx, source, &identity, deadline)?;
    if file_identity(&source_file(source)?)? != identity {
        return Err(changed());
    }
    tx.commit().map_err(sql)?;
    Ok(result)
}
fn acquire(root: &Path, kind: LockKind, end: Instant) -> PortResult<ExclusiveGuard> {
    loop {
        check(end)?;
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(1).min(end.saturating_duration_since(Instant::now())),
            ),
            result => return result,
        }
    }
}
fn lease(root: &Path, end: Instant) -> PortResult<WriterLease> {
    loop {
        check(end)?;
        match WriterLease::try_acquire(root) {
            Err(PortError::WriterBusy(_)) => std::thread::sleep(
                Duration::from_millis(1).min(end.saturating_duration_since(Instant::now())),
            ),
            result => return result.map_err(|_| io()),
        }
    }
}
fn authorize(
    request: &LegacyMigrationRequest<'_>,
    control: &SqliteControlStore,
    root: RootIdentity,
) -> PortResult<i64> {
    check(request.deadline)?;
    if !control.matches_root(root) {
        return Err(invalid());
    }
    let status = control.status()?;
    if status.policy.installation_id != *request.installation
        || status
            .catalog_incarnation
            .as_ref()
            .is_some_and(|current| current != request.incarnation)
    {
        return Err(incompatible());
    }
    if status.policy.maintenance.state != MaintenanceState::Idle || status.policy.emission_blocked()
    {
        return Err(busy());
    }
    Ok(status.policy.policy_epoch.get())
}
fn finish_receipt(request: &LegacyMigrationRequest<'_>) -> MigrationReceipt {
    MigrationReceipt {
        operation: request.operation.clone(),
        installation: request.installation.clone(),
        incarnation: request.incarnation.clone(),
        generation: request.inspected.generation,
        canonical_entities: request.inspected.canonical_entities,
        namespace_digest: request.inspected.namespace_digest.clone(),
        classification: LegacyClassification::MergedUnverified,
    }
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Copied,
    Activated,
}
#[cfg(test)]
thread_local! { static INTERRUPT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
fn fault(point: Fault) -> PortResult<()> {
    INTERRUPT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            Err(io())
        } else {
            Ok(())
        }
    })
}
/// A failed or interrupted destination is retained under its immutable private
/// intent. Only the same request and physical file can be reconciled. Missing
/// file binding/corrupt state requires explicit owned cleanup, never adoption.
pub fn migrate_legacy(
    request: LegacyMigrationRequest<'_>,
    control: &SqliteControlStore,
) -> PortResult<MigrationReceipt> {
    check(request.deadline)?;
    validate_catalog_path(request.destination)?;
    if !request.destination.is_absolute()
        || request.now_ms < 0
        || request.source != request.inspected.source
        || request
            .destination
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    let root = request.destination.parent().ok_or_else(invalid)?;
    let receiving = RootIdentity::read(root)?;
    if !control.matches_root(receiving)
        || receiving == RootIdentity::read(request.source.parent().ok_or_else(invalid)?)?
    {
        return Err(invalid());
    }
    let handles = acquire(root, LockKind::CatalogHandles, request.deadline)?;
    let writer = lease(root, request.deadline)?;
    let initial_epoch = {
        let policy = acquire(root, LockKind::PolicyOwner, request.deadline)?;
        control.bind_control_root(&policy)?;
        authorize(&request, control, receiving)?
    };
    let intent = Intent {
        schema: INTENT_SCHEMA.into(),
        operation: request.operation.as_str().into(),
        installation: request.installation.as_str().into(),
        incarnation: request.incarnation.as_str().into(),
        root_identity: receiving.control_id().as_str().into(),
        destination: request
            .destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(invalid)?
            .into(),
        policy_epoch: initial_epoch,
        inspected: request.inspected.clone(),
    };
    let reserved = file_exists(&marker(request.destination))?;
    if reserved {
        if read_record::<Intent>(control, &marker(request.destination))? != intent {
            return Err(changed());
        }
    } else {
        if file_exists(request.destination)? || file_exists(&bound(request.destination))? {
            return Err(invalid());
        }
        if fs4::available_space(root).map_err(|_| io())?
            < request
                .inspected
                .logical_bytes
                .checked_mul(3)
                .ok_or_else(incompatible)?
        {
            return Err(io());
        }
        write_record(control, &marker(request.destination), &intent)?;
    }
    if !file_exists(request.destination)? {
        if file_exists(&bound(request.destination))? {
            return Err(incompatible());
        }
        control.create_private_catalog_file(request.destination)?;
        let file = control.open_private_read(request.destination)?;
        let binding = FileBinding {
            schema: INTENT_SCHEMA.into(),
            operation: request.operation.as_str().into(),
            identity: file_identity(&file)?,
        };
        drop(file);
        write_record(control, &bound(request.destination), &binding)?;
    }
    let binding: FileBinding = read_record(control, &bound(request.destination))?;
    if binding.schema != INTENT_SCHEMA || binding.operation != request.operation.as_str() {
        return Err(incompatible());
    }
    let destination_pin = pin_owned(control, request.destination, &binding.identity)?;
    let mut destination = Connection::open_with_flags(
        request.destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    set_sql_deadline(&destination, request.deadline)?;
    destination
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(sql)?;
    let version = number(&destination, "PRAGMA user_version")?;
    if (20..=crate::SCHEMA_VERSION as u64).contains(&version) {
        // Reconciliation verifies the same activation before acknowledgement;
        // it never recopies legacy data over later managed source publications.
        let integrity: String = destination
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(sql)?;
        if integrity != "ok" {
            return Err(incompatible());
        }
        verify_derived_integrity(&destination, request.deadline)?;
        let (installation, incarnation, generation): (String,String,i64) = destination.query_row(
            "SELECT installation_id,catalog_incarnation,active_generation FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1", [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).map_err(sql)?;
        if installation != intent.installation
            || incarnation != intent.incarnation
            || number(&destination, "PRAGMA application_id")? != APPLICATION_ID as u64
            || generation < request.inspected.generation as i64
        {
            return Err(incompatible());
        }
        if version < crate::SCHEMA_VERSION as u64 {
            // Upgrade the already-bound activation in place under the same
            // catalog/writer guards. Never recopy newer managed facts or grant
            // historical receipt authority merely because the schema changed.
            crate::SqliteStore::migrate(&destination)?;
            verify_derived_integrity(&destination, request.deadline)?;
        }
        destination
            .query_row("PRAGMA journal_mode=DELETE", [], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sql)?;
        drop(destination);
        control.validate_private_read(request.destination, &destination_pin)?;
        drop(destination_pin);
        sync_owned(control, request.destination, &binding.identity)?;
        authorize(&request, control, receiving)?;
        return Ok(finish_receipt(&request));
    }
    if version != 0 && version != 19 {
        return Err(incompatible());
    }
    crate::managed_store::reject_creation_intent(request.source)?;
    let pinned_source = source_file(request.source)?;
    let source_identity = file_identity(&pinned_source)?;
    if source_identity != request.inspected.source_identity {
        return Err(changed());
    }
    let source = source_connection(request.source, request.deadline)?;
    let snapshot = source.unchecked_transaction().map_err(sql)?;
    if inspect_snapshot(
        &snapshot,
        request.source,
        &source_identity,
        request.deadline,
    )? != *request.inspected
    {
        return Err(changed());
    }
    {
        let copy = backup::Backup::new(&snapshot, &mut destination).map_err(sql)?;
        loop {
            check(request.deadline)?;
            match copy.step(128).map_err(sql)? {
                backup::StepResult::Done => break,
                backup::StepResult::More => {}
                backup::StepResult::Busy | backup::StepResult::Locked => std::thread::sleep(
                    Duration::from_millis(1)
                        .min(request.deadline.saturating_duration_since(Instant::now())),
                ),
                _ => return Err(incompatible()),
            }
        }
    }
    set_sql_deadline(&destination, request.deadline)?;
    destination
        .query_row("PRAGMA journal_mode=DELETE", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sql)?;
    if inspect_snapshot(
        &destination,
        request.source,
        &source_identity,
        request.deadline,
    )? != *request.inspected
    {
        return Err(changed());
    }
    if file_identity(&source_file(request.source)?)? != source_identity {
        return Err(changed());
    }
    snapshot.commit().map_err(sql)?;
    drop(source);
    drop(pinned_source);
    #[cfg(test)]
    fault(Fault::Copied)?;
    verify_legacy_indexes(&destination)?;
    {
        let policy = acquire(root, LockKind::PolicyOwner, request.deadline)?;
        control.bind_control_root(&policy)?;
        if authorize(&request, control, receiving)? != initial_epoch {
            return Err(changed());
        }
        control.validate_private_read(request.destination, &destination_pin)?;
        ManagedStore::activate_legacy_copy(LegacyActivation {
            connection: &destination,
            control,
            lease: &writer,
            handles: &handles,
            installation: request.installation,
            incarnation: request.incarnation,
            now_ms: request.now_ms,
            deadline: request.deadline,
        })?;
    }
    #[cfg(test)]
    fault(Fault::Activated)?;
    verify_derived_integrity(&destination, request.deadline)?;
    destination
        .query_row("PRAGMA journal_mode=DELETE", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sql)?;
    drop(destination);
    control.validate_private_read(request.destination, &destination_pin)?;
    drop(destination_pin);
    sync_owned(control, request.destination, &binding.identity)?;
    control.validate_catalog_file(request.destination)?;
    Ok(finish_receipt(&request))
}
fn verify_legacy_indexes(conn: &Connection) -> PortResult<()> {
    for table in ["fts", "session_fts"] {
        conn.execute(
            &format!("INSERT INTO {table}({table}) VALUES('integrity-check')"),
            [],
        )
        .map_err(sql)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_ports::control::DesiredUpdates;
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn id(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }
    fn legacy(path: &Path) {
        drop(crate::SqliteStore::open_for_write(path.to_str().unwrap()).unwrap());
        let conn = Connection::open(path).unwrap();
        let model = Connection::open_in_memory().unwrap();
        model
            .execute_batch("PRAGMA foreign_keys=ON; BEGIN")
            .unwrap();
        crate::managed::create_schema(&model).unwrap();
        let objects = model.prepare("SELECT type,name,sql FROM sqlite_schema WHERE type IN ('table','trigger') AND name NOT LIKE 'sqlite_%'").unwrap()
            .query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?))).unwrap()
            .collect::<Result<Vec<_>,_>>().unwrap();
        let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
        conn.execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE")
            .unwrap();
        for (kind, name, _) in &objects {
            if kind == "trigger" {
                conn.execute_batch(&format!("DROP TRIGGER {}", quote(name)))
                    .unwrap();
            }
        }
        for (kind, name, sql) in &objects {
            if kind == "table" && sql.starts_with("CREATE VIRTUAL TABLE") {
                conn.execute_batch(&format!("DROP TABLE {}", quote(name)))
                    .unwrap();
            }
        }
        for (kind, name, _) in &objects {
            if kind == "table" {
                conn.execute_batch(&format!("DROP TABLE IF EXISTS {}", quote(name)))
                    .unwrap();
            }
        }
        conn.execute_batch("ALTER TABLE store_metadata DROP COLUMN projection_contract_version; ALTER TABLE store_metadata DROP COLUMN managed_mode; ALTER TABLE store_metadata DROP COLUMN destructive_epoch; PRAGMA application_id=0; PRAGMA user_version=19; COMMIT;").unwrap();
    }
    #[test]
    fn lost_copy_and_activation_acknowledgements_recover_same_inode_once() {
        for (point, old_managed_schema) in [
            (Fault::Copied, false),
            (Fault::Activated, false),
            (Fault::Activated, true),
        ] {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let source = temp.path().join("legacy.db");
            legacy(&source);
            let control = SqliteControlStore::create(
                &temp.path().join("managed"),
                &id("installation"),
                DesiredUpdates::Paused,
            )
            .unwrap();
            let destination = temp.path().join("managed/catalog.db");
            let inspected = inspect_legacy(&source, end()).unwrap();
            let run = || {
                migrate_legacy(
                    LegacyMigrationRequest {
                        source: &source,
                        destination: &destination,
                        inspected: &inspected,
                        installation: &id("installation"),
                        incarnation: &id("incarnation"),
                        operation: &id("migration"),
                        now_ms: 1,
                        deadline: end(),
                    },
                    &control,
                )
            };
            INTERRUPT.with(|slot| slot.set(Some(point)));
            assert!(run().is_err());
            if old_managed_schema {
                // Exact previous managed schema, with no restore lineage:
                // reconciliation must migrate this same activated inode.
                Connection::open(&destination)
                    .unwrap()
                    .execute_batch("DROP TABLE retained_source_receipts; PRAGMA user_version=20;")
                    .unwrap();
            }
            assert!(marker(&destination).exists());
            assert!(bound(&destination).exists());
            let before = file_identity(&control.open_private_read(&destination).unwrap()).unwrap();
            let receipt = run().unwrap();
            assert_eq!(receipt.generation, 0);
            assert_eq!(
                file_identity(&control.open_private_read(&destination).unwrap()).unwrap(),
                before
            );
            assert_eq!(
                Connection::open(&destination)
                    .unwrap()
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                crate::SCHEMA_VERSION
            );
            assert_eq!(
                Connection::open(&source)
                    .unwrap()
                    .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                19
            );
            assert_eq!(
                control.status().unwrap().desired_updates,
                DesiredUpdates::Paused
            );
        }
    }
    #[test]
    fn identity_bound_target_replacement_is_never_recopied() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let source = temp.path().join("legacy.db");
        legacy(&source);
        let control = SqliteControlStore::create(
            &temp.path().join("managed"),
            &id("installation"),
            DesiredUpdates::Paused,
        )
        .unwrap();
        let destination = temp.path().join("managed/catalog.db");
        let inspected = inspect_legacy(&source, end()).unwrap();
        let run = || {
            migrate_legacy(
                LegacyMigrationRequest {
                    source: &source,
                    destination: &destination,
                    inspected: &inspected,
                    installation: &id("installation"),
                    incarnation: &id("incarnation"),
                    operation: &id("migration"),
                    now_ms: 1,
                    deadline: end(),
                },
                &control,
            )
        };
        INTERRUPT.with(|slot| slot.set(Some(Fault::Copied)));
        assert!(run().is_err());
        fs::rename(&destination, destination.with_extension("retained")).unwrap();
        control.create_private_catalog_file(&destination).unwrap();
        assert!(matches!(run(), Err(PortError::SnapshotChanged(_))));
        assert_eq!(fs::metadata(&destination).unwrap().len(), 0);
    }
}
