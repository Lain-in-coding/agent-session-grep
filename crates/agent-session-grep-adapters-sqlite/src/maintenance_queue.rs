//! Durable root-scoped queue. This module never opens the catalog.
use agent_session_grep_ports::{PortError, PortResult, maintenance::*};
use fs4::fs_std::FileExt;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    cell::RefCell,
    collections::HashSet,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};

const QUEUE_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x41534d31;
fn backend<E>(_: E) -> PortError {
    PortError::Backend("maintenance queue operation failed".into())
}
fn sql_error(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            PortError::WriterBusy("maintenance queue is busy".into())
        }
        _ => backend(error),
    }
}
fn incompatible() -> PortError {
    PortError::SchemaIncompatible("unsupported maintenance queue".into())
}
fn missing() -> PortError {
    PortError::NotFound("maintenance job not found".into())
}

pub struct SqliteMaintenanceQueue {
    conn: RefCell<Connection>,
}
impl SqliteMaintenanceQueue {
    pub fn path(root: &Path) -> PathBuf {
        root.join(".maintenance").join("queue.sqlite")
    }
    /// Explicit authorized creation only. Existing unsupported queues are never migrated.
    pub fn open(root: &Path) -> PortResult<Self> {
        let path = Self::path(root);
        let directory = path.parent().ok_or_else(incompatible)?;
        // Only the newly-created maintenance directory receives private mode;
        // never alter permissions of the caller's existing data root.
        std::fs::create_dir_all(root).map_err(backend)?;
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        match builder.create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(backend(error)),
        }
        let mut conn = Connection::open(&path).map_err(sql_error)?;
        conn.busy_timeout(Duration::from_secs(2))
            .map_err(sql_error)?;
        conn.execute_batch("PRAGMA synchronous=FULL")
            .map_err(sql_error)?;
        {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let version: i64 = tx
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(sql_error)?;
            let app: i64 = tx
                .query_row("PRAGMA application_id", [], |r| r.get(0))
                .map_err(sql_error)?;
            if version == 0 && app == 0 {
                let tables: i64 = tx
                    .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
                    .map_err(sql_error)?;
                if tables != 0 {
                    return Err(incompatible());
                }
                tx.execute_batch("CREATE TABLE queue_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1), paused INTEGER NOT NULL CHECK(paused IN (0,1)));
                    INSERT INTO queue_control VALUES(1,0);
                    CREATE TABLE jobs(id TEXT PRIMARY KEY, token TEXT NOT NULL UNIQUE, target TEXT NOT NULL, record TEXT NOT NULL, revision INTEGER NOT NULL, cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0,1)));
                    PRAGMA application_id=1095978289; PRAGMA user_version=1;").map_err(sql_error)?;
            } else if version != QUEUE_VERSION || app != APPLICATION_ID {
                return Err(incompatible());
            }
            tx.commit().map_err(sql_error)?;
        }
        Self::from_connection(conn, true)
    }
    /// Read-only open. Missing roots/queues return None without creating any files.
    pub fn open_existing(root: &Path) -> PortResult<Option<Self>> {
        Self::existing(root, false)
    }
    pub fn open_existing_writable(root: &Path) -> PortResult<Option<Self>> {
        Self::existing(root, true)
    }
    fn existing(root: &Path, writable: bool) -> PortResult<Option<Self>> {
        let path = Self::path(root);
        match path.try_exists() {
            Ok(false) => return Ok(None),
            Err(e) => return Err(backend(e)),
            Ok(true) => {}
        }
        let flags = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        Self::from_connection(
            Connection::open_with_flags(path, flags).map_err(sql_error)?,
            writable,
        )
        .map(Some)
    }
    fn from_connection(conn: Connection, writable: bool) -> PortResult<Self> {
        conn.busy_timeout(Duration::from_secs(2))
            .map_err(sql_error)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(sql_error)?;
        let application_id: i64 = conn
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(sql_error)?;
        if version != QUEUE_VERSION || application_id != APPLICATION_ID {
            return Err(incompatible());
        }
        if writable {
            conn.execute_batch("PRAGMA synchronous=FULL")
                .map_err(sql_error)?;
        }
        conn.query_row(
            "SELECT paused FROM queue_control WHERE singleton=1",
            [],
            |r| r.get::<_, bool>(0),
        )
        .map_err(sql_error)?;
        Ok(Self {
            conn: RefCell::new(conn),
        })
    }
}
fn decode(record: String, revision: i64, cancelled: bool) -> PortResult<MaintenanceJob> {
    let mut job: MaintenanceJob = serde_json::from_str(&record).map_err(|_| incompatible())?;
    job.revision = u64::try_from(revision).map_err(|_| incompatible())?;
    job.cancel_requested = cancelled;
    Ok(job)
}
fn load(conn: &Connection, id: &str) -> PortResult<MaintenanceJob> {
    let row = conn
        .query_row(
            "SELECT record,revision,cancel_requested FROM jobs WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(sql_error)?;
    let (record, revision, cancelled) = row.ok_or_else(missing)?;
    decode(record, revision, cancelled)
}
impl MaintenanceQueue for SqliteMaintenanceQueue {
    fn enqueue(&self, job: &MaintenanceJob) -> PortResult<MaintenanceJob> {
        validate_write_budget(job.max_write_seconds)?;
        let record = serde_json::to_string(job).map_err(backend)?;
        let mut conn = self.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        tx.execute("INSERT INTO jobs(id,token,target,record,revision,cancel_requested) VALUES(?1,?2,?3,?4,0,0) ON CONFLICT(token) DO NOTHING", params![job.id,job.token,job.target.canonical_path,record]).map_err(sql_error)?;
        let id: String = tx
            .query_row("SELECT id FROM jobs WHERE token=?1", [&job.token], |r| {
                r.get(0)
            })
            .map_err(sql_error)?;
        let accepted = load(&tx, &id)?;
        tx.commit().map_err(sql_error)?;
        Ok(accepted)
    }
    fn find_by_token(&self, token: &str) -> PortResult<Option<MaintenanceJob>> {
        let conn = self.conn.borrow();
        let id: Option<String> = conn
            .query_row("SELECT id FROM jobs WHERE token=?1", [token], |r| r.get(0))
            .optional()
            .map_err(sql_error)?;
        id.map(|id| load(&conn, &id)).transpose()
    }
    fn get(&self, id: &str) -> PortResult<MaintenanceJob> {
        load(&self.conn.borrow(), id)
    }
    fn list(&self, target: Option<&str>) -> PortResult<Vec<MaintenanceJob>> {
        let conn = self.conn.borrow();
        let mut stmt = conn.prepare("SELECT record,revision,cancel_requested FROM jobs WHERE (?1 IS NULL OR target=?1) ORDER BY rowid").map_err(sql_error)?;
        let rows = stmt
            .query_map([target], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(sql_error)?;
        rows.map(|r| {
            let (record, revision, cancelled) = r.map_err(sql_error)?;
            decode(record, revision, cancelled)
        })
        .collect()
    }
    fn save_progress(&self, job: &MaintenanceJob) -> PortResult<MaintenanceJob> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let current = load(&tx, &job.id)?;
        if current.revision != job.revision {
            return Err(PortError::GenerationMismatch(
                "maintenance job changed".into(),
            ));
        }
        if current.token != job.token
            || current.compaction_id != job.compaction_id
            || current.target != job.target
            || current.selection != job.selection
        {
            return Err(PortError::InvalidRequest(
                "maintenance authorization cannot change".into(),
            ));
        }
        validate_write_budget(job.max_write_seconds)?;
        if job.cleanup_started && !current.cleanup_started {
            if current.cancel_requested {
                return Ok(current);
            }
            if current.phase != MaintenancePhase::Cleanup || job.phase != MaintenancePhase::Cleanup
            {
                return Err(PortError::InvalidRequest(
                    "cleanup commitment requires the cleanup phase".into(),
                ));
            }
        }
        let mut saved = job.clone();
        saved.cleanup_started |= current.cleanup_started;
        saved.cancel_requested = current.cancel_requested;
        if current.state == MaintenanceState::Cancelled
            && saved.phase != MaintenancePhase::Done
            && !saved.cleanup_started
        {
            saved.state = MaintenanceState::Cancelled;
            saved.reason = Some(MaintenanceFailureKind::Cancelled);
        }
        saved.revision = current.revision.checked_add(1).ok_or_else(incompatible)?;
        let record = serde_json::to_string(&saved).map_err(backend)?;
        tx.execute(
            "UPDATE jobs SET record=?1,revision=?2 WHERE id=?3",
            params![
                record,
                i64::try_from(saved.revision).map_err(|_| incompatible())?,
                saved.id
            ],
        )
        .map_err(sql_error)?;
        tx.commit().map_err(sql_error)?;
        Ok(saved)
    }
    fn request_cancel(&self, id: &str) -> PortResult<MaintenanceJob> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let mut job = load(&tx, id)?;
        if job.state != MaintenanceState::Completed
            && !job.cleanup_started
            && job.phase != MaintenancePhase::Done
        {
            job.cancel_requested = true;
            if job.phase == MaintenancePhase::Compact
                && !job.logical_compaction_committed
                && !job.logical_compaction_reconciled
            {
                // A killed executor may have committed without acknowledging.
                // Keep this runnable until a read-only audit probe resolves it.
                if job.state != MaintenanceState::Running {
                    job.state = MaintenanceState::Queued;
                }
            } else if job.state != MaintenanceState::Running {
                job.state = MaintenanceState::Cancelled;
                job.reason = Some(MaintenanceFailureKind::Cancelled);
            }
            let record = serde_json::to_string(&job).map_err(backend)?;
            tx.execute(
                "UPDATE jobs SET record=?1,cancel_requested=1 WHERE id=?2",
                params![record, id],
            )
            .map_err(sql_error)?;
        }
        tx.commit().map_err(sql_error)?;
        Ok(job)
    }
    fn set_paused(&self, paused: bool) -> PortResult<()> {
        self.conn
            .borrow()
            .execute(
                "UPDATE queue_control SET paused=?1 WHERE singleton=1",
                [paused],
            )
            .map_err(sql_error)?;
        Ok(())
    }
    fn control(&self, id: Option<&str>) -> PortResult<MaintenanceQueueControl> {
        let conn = self.conn.borrow();
        let paused = conn
            .query_row(
                "SELECT paused FROM queue_control WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        let cancel_requested = if let Some(id) = id {
            conn.query_row("SELECT cancel_requested FROM jobs WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sql_error)?
            .ok_or_else(missing)?
        } else {
            false
        };
        Ok(MaintenanceQueueControl {
            paused,
            cancel_requested,
        })
    }
}

fn held_locks() -> &'static Mutex<HashSet<PathBuf>> {
    static LOCKS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashSet::new()))
}
/// OS-held guard. Lock files are NEVER deleted: unlinking could split authority.
pub struct QueueLock {
    file: File,
    key: PathBuf,
}
impl QueueLock {
    /// Status probe never creates a directory or lock file and does not wake.
    pub fn worker_running(root: &Path) -> PortResult<bool> {
        let path = root.join(".maintenance").join("worker.lock");
        let key = match std::fs::canonicalize(&path) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(backend(error)),
        };
        if held_locks().lock().map_err(backend)?.contains(&key) {
            return Ok(true);
        }
        let file = File::open(&key).map_err(backend)?;
        match file.try_lock_exclusive() {
            Ok(true) => {
                FileExt::unlock(&file).map_err(backend)?;
                Ok(false)
            }
            Ok(false) => Ok(true),
            Err(error) if lock_contention(&error) => Ok(true),
            Err(error) => Err(backend(error)),
        }
    }
    pub fn try_worker(root: &Path) -> PortResult<Option<Self>> {
        Self::acquire(root, "worker.lock", false)
    }
    pub fn lifecycle(root: &Path) -> PortResult<Self> {
        Self::acquire(root, "lifecycle.lock", true)?
            .ok_or_else(|| PortError::WriterBusy("maintenance lifecycle is busy".into()))
    }
    fn acquire(root: &Path, name: &str, wait: bool) -> PortResult<Option<Self>> {
        // An authorized producer creates the queue before requesting guards.
        let directory = root.join(".maintenance");
        let directory = std::fs::canonicalize(directory).map_err(backend)?;
        let key = directory.join(name);
        loop {
            let claimed = held_locks().lock().map_err(backend)?.insert(key.clone());
            if !claimed {
                if !wait {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let result = (|| {
                let file = OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .open(&key)
                    .map_err(backend)?;
                if wait {
                    file.lock_exclusive().map_err(backend)?;
                } else {
                    match file.try_lock_exclusive() {
                        Ok(true) => {}
                        Ok(false) => return Ok(None),
                        Err(error) if lock_contention(&error) => return Ok(None),
                        Err(error) => return Err(backend(error)),
                    }
                }
                Ok(Some(Self {
                    file,
                    key: key.clone(),
                }))
            })();
            if !matches!(result, Ok(Some(_))) {
                held_locks().lock().map_err(backend)?.remove(&key);
            }
            return result;
        }
    }
}
impl Drop for QueueLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
        if let Ok(mut locks) = held_locks().lock() {
            locks.remove(&self.key);
        }
    }
}

fn lock_contention(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    if matches!(error.raw_os_error(), Some(32 | 33)) {
        return true;
    }
    false
}
