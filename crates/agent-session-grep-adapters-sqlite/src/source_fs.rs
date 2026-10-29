//! Read-only source snapshots with streaming fingerprints and logical WAL backup.
//!
//! Deadline APIs retain the caller's original Instant through acquisition,
//! hashing, verification and every FileSource reopen/read. SQLite byte limits
//! are explicit 128/256 MiB choices. Existing APIs retain the 128 MiB limit.
//! No source database or WAL bytes are written; SQLite may maintain SHM reader
//! bookkeeping. A completed fingerprint observes one pinned logical snapshot,
//! never an mtime-only freshness claim. Final verification remains mandatory.

use agent_session_grep_ports::{
    JSON_FAMILY_MAX_SOURCE_BYTES, PortError, PortResult, ReadOnlySource, SourceSnapshot,
};
use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Fixed filesystem buffer used by capture, parse readers, and verification.
pub const SOURCE_IO_BUFFER_BYTES: usize = 64 * 1024;
const SQLITE_256_MIB: u64 = 256 * 1024 * 1024;
const SQLITE_STEP_BYTES: i64 = 1024 * 1024;
const MAX_BUSY_RETRIES: usize = 256;

fn backend<E: std::fmt::Display>(_: E) -> PortError {
    PortError::SourceIo("source snapshot I/O is unavailable".into())
}
fn timeout() -> PortError {
    PortError::WriterBusy("source snapshot is busy or deadline exceeded".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => timeout(),
        _ => backend(error),
    }
}
fn too_large() -> PortError {
    PortError::SourceIo("SQLite source exceeds supported snapshot size".into())
}

#[derive(Clone, Copy)]
struct SnapshotBudget {
    sqlite_byte_limit: u64,
    deadline: Option<Instant>,
}
impl SnapshotBudget {
    fn compatibility() -> Self {
        Self {
            sqlite_byte_limit: agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
            deadline: None,
        }
    }
    fn bounded(sqlite_byte_limit: u64, deadline: Instant) -> PortResult<Self> {
        if sqlite_byte_limit != agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES
            && sqlite_byte_limit != SQLITE_256_MIB
        {
            return Err(PortError::InvalidRequest(
                "unsupported SQLite snapshot byte limit".into(),
            ));
        }
        let budget = Self {
            sqlite_byte_limit,
            deadline: Some(deadline),
        };
        budget.check()?;
        Ok(budget)
    }
    fn check(self) -> PortResult<()> {
        if self.deadline.is_some_and(|end| Instant::now() >= end) {
            Err(timeout())
        } else {
            Ok(())
        }
    }
    fn pause(self) -> PortResult<()> {
        self.check()?;
        let duration = self.deadline.map_or(Duration::from_millis(2), |end| {
            Duration::from_millis(2).min(end.saturating_duration_since(Instant::now()))
        });
        std::thread::sleep(duration);
        self.check()
    }
    fn check_len(self, len: u64) -> PortResult<()> {
        if len > self.sqlite_byte_limit {
            Err(too_large())
        } else {
            Ok(())
        }
    }
}

fn mtime_ms(meta: &std::fs::Metadata) -> PortResult<i64> {
    let modified = meta.modified().map_err(backend)?;
    i64::try_from(
        modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .map_err(backend)
}

fn fingerprint_reader(reader: &mut dyn Read, budget: SnapshotBudget) -> PortResult<(u64, String)> {
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; SOURCE_IO_BUFFER_BYTES];
    loop {
        budget.check()?;
        let read = reader.read(&mut chunk).map_err(backend)?;
        budget.check()?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| backend("byte count overflow"))?;
    }
    budget.check()?;
    Ok((total, hasher.finalize().to_hex().to_string()))
}

fn verify_metadata(meta: &std::fs::Metadata, snap: &SourceSnapshot) -> PortResult<()> {
    if meta.len() != snap.len {
        return Err(PortError::SnapshotChanged(format!(
            "len {} -> {}",
            snap.len,
            meta.len()
        )));
    }
    let current_mtime = mtime_ms(meta)?;
    if current_mtime != snap.mtime_ms {
        return Err(PortError::SnapshotChanged(format!(
            "mtime {} -> {current_mtime}",
            snap.mtime_ms
        )));
    }
    Ok(())
}

/// Compatibility capture: streaming files and SQLite logical images <=128 MiB.
pub fn capture(path: &Path) -> PortResult<SourceSnapshot> {
    capture_budget(path, SnapshotBudget::compatibility())
}
/// One original deadline for source read admission, pinned logical backup,
/// and fixed-buffer hashing. Only 128 MiB and 256 MiB SQLite limits are supported.
pub fn capture_with_deadline(
    path: &Path,
    sqlite_byte_limit: u64,
    deadline: Instant,
) -> PortResult<SourceSnapshot> {
    capture_budget(path, SnapshotBudget::bounded(sqlite_byte_limit, deadline)?)
}
fn capture_budget(path: &Path, budget: SnapshotBudget) -> PortResult<SourceSnapshot> {
    budget.check()?;
    let mut file = File::open(path).map_err(backend)?;
    budget.check()?;
    let mut header = [0; 16];
    let read = file.read(&mut header).map_err(backend)?;
    budget.check()?;
    if read == header.len() && &header == b"SQLite format 3\0" {
        let copy = sqlite_snapshot(path, budget)?;
        let mut snapshot = capture_file(&copy, budget)?;
        budget.check_len(snapshot.len)?;
        snapshot.path = path.to_string_lossy().into_owned();
        snapshot.mtime_ms = mtime_ms(&file.metadata().map_err(backend)?)?;
        snapshot.fingerprint.insert_str(0, "sqlite:");
        budget.check()?;
        return Ok(snapshot);
    }
    capture_file(path, budget)
}
fn sqlite_retry<T>(
    budget: SnapshotBudget,
    mut operation: impl FnMut() -> rusqlite::Result<T>,
) -> PortResult<T> {
    for _ in 0..MAX_BUSY_RETRIES {
        budget.check()?;
        match operation() {
            Err(error)
                if budget.deadline.is_some()
                    && matches!(
                        error.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        )
                    ) =>
            {
                budget.pause()?
            }
            value => {
                let value = value.map_err(sql)?;
                budget.check()?;
                return Ok(value);
            }
        }
    }
    Err(timeout())
}
/// Pin a read-only WAL snapshot before the size check and stepped Backup API.
/// The destination is disposable owned state. No SQL writes target the source.
fn sqlite_snapshot(path: &Path, budget: SnapshotBudget) -> PortResult<tempfile::TempPath> {
    budget.check()?;
    let source =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(sql)?;
    source
        .busy_timeout(if budget.deadline.is_some() {
            Duration::ZERO
        } else {
            Duration::from_secs(1)
        })
        .map_err(sql)?;
    if let Some(end) = budget.deadline {
        source
            .progress_handler(1000, Some(move || Instant::now() >= end))
            .map_err(sql)?;
    }
    source
        .pragma_update(None, "cache_size", -2048)
        .map_err(sql)?;
    source.execute_batch("BEGIN;").map_err(sql)?;
    sqlite_retry(budget, || {
        source.execute_batch("SELECT rootpage FROM sqlite_schema LIMIT 1;")
    })?;
    let pages: i64 = sqlite_retry(budget, || {
        source.query_row("PRAGMA page_count", [], |row| row.get(0))
    })?;
    let page_size: i64 = sqlite_retry(budget, || {
        source.query_row("PRAGMA page_size", [], |row| row.get(0))
    })?;
    if pages < 1 || !(512..=65_536).contains(&page_size) || !(page_size as u64).is_power_of_two() {
        return Err(backend("invalid SQLite snapshot geometry"));
    }
    let expected_len = pages
        .checked_mul(page_size)
        .and_then(|len| u64::try_from(len).ok())
        .ok_or_else(too_large)?;
    budget.check_len(expected_len)?;
    budget.check()?;
    let destination = tempfile::NamedTempFile::new()
        .map_err(backend)?
        .into_temp_path();
    let mut target = Connection::open_with_flags(&destination, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(sql)?;
    target.busy_timeout(Duration::ZERO).map_err(sql)?;
    target
        .pragma_update(None, "page_size", page_size)
        .map_err(sql)?;
    target
        .pragma_update(None, "cache_size", -2048)
        .map_err(sql)?;
    let max_pages =
        i64::try_from(budget.sqlite_byte_limit / page_size as u64).map_err(|_| too_large())?;
    target
        .pragma_update(None, "max_page_count", max_pages)
        .map_err(sql)?;
    target
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
        .map_err(sql)?;
    if let Some(end) = budget.deadline {
        target
            .progress_handler(1000, Some(move || Instant::now() >= end))
            .map_err(sql)?;
    }
    {
        let backup = Backup::new(&source, &mut target).map_err(sql)?;
        // At most 1 MiB of pages per step, independent of SQLite's page size.
        let pages_per_step = (SQLITE_STEP_BYTES / page_size).max(1) as i32;
        let mut busy_attempts = 0;
        loop {
            budget.check()?;
            let step = backup.step(pages_per_step).map_err(sql)?;
            budget.check()?;
            match step {
                StepResult::Done | StepResult::More => {
                    let progress = backup.progress();
                    if i64::from(progress.pagecount) != pages
                        || progress.remaining < 0
                        || progress.remaining > progress.pagecount
                    {
                        return Err(PortError::SnapshotChanged(
                            "SQLite logical snapshot geometry changed".into(),
                        ));
                    }
                    budget.check_len(progress.pagecount as u64 * page_size as u64)?;
                    busy_attempts = 0;
                    if step == StepResult::Done {
                        break;
                    }
                }
                StepResult::Busy | StepResult::Locked => {
                    busy_attempts += 1;
                    if busy_attempts >= MAX_BUSY_RETRIES {
                        return Err(timeout());
                    }
                    budget.pause()?;
                }
                _ => return Err(backend("unsupported SQLite backup result")),
            }
        }
    }
    target.close().map_err(|(_, error)| sql(error))?;
    budget.check()?;
    let len = std::fs::metadata(&destination).map_err(backend)?.len();
    if len != expected_len {
        return Err(PortError::SnapshotChanged(
            "SQLite logical snapshot length changed".into(),
        ));
    }
    budget.check_len(len)?;
    budget.check()?;
    Ok(destination)
}

fn capture_file(path: &Path, budget: SnapshotBudget) -> PortResult<SourceSnapshot> {
    budget.check()?;
    let file = File::open(path).map_err(backend)?;
    let meta = file.metadata().map_err(backend)?;
    budget.check()?;
    let len = meta.len();
    let mtime = mtime_ms(&meta)?;
    let mut captured = file.take(len);
    let (read_len, fingerprint) = fingerprint_reader(&mut captured, budget)?;
    if read_len != len {
        return Err(PortError::SnapshotChanged(format!(
            "len changed during capture {len} -> {read_len}"
        )));
    }
    let snap = SourceSnapshot {
        path: path.to_string_lossy().into_owned(),
        len,
        mtime_ms: mtime,
        fingerprint,
    };
    post_read_verify(path, &snap)?;
    budget.check()?;
    Ok(snap)
}

/// Repeatable read-only captured range. Clones preserve the same deadline/cap.
#[derive(Clone)]
pub struct FileSource {
    path: PathBuf,
    snapshot: SourceSnapshot,
    _temporary: Option<std::sync::Arc<tempfile::TempPath>>,
    budget: SnapshotBudget,
}
fn reader_time(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "source snapshot deadline exceeded",
        ))
    } else {
        Ok(())
    }
}
struct DeadlineReader<R> {
    inner: R,
    deadline: Option<Instant>,
}
impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        reader_time(self.deadline)?;
        let chunk_len = buf.len().min(SOURCE_IO_BUFFER_BYTES);
        let read = self.inner.read(&mut buf[..chunk_len])?;
        reader_time(self.deadline)?;
        Ok(read)
    }
}
impl<R: BufRead> BufRead for DeadlineReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        reader_time(self.deadline)?;
        let buf = self.inner.fill_buf()?;
        reader_time(self.deadline)?;
        Ok(buf)
    }
    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }
}
impl ReadOnlySource for FileSource {
    fn len(&self) -> u64 {
        self.snapshot.len
    }
    fn open(&self) -> PortResult<Box<dyn BufRead + Send + '_>> {
        self.budget.check()?;
        if self._temporary.is_some() {
            self.budget.check_len(self.snapshot.len)?;
        }
        let file = File::open(&self.path).map_err(backend)?;
        verify_metadata(&file.metadata().map_err(backend)?, &self.snapshot)?;
        self.budget.check()?;
        Ok(Box::new(DeadlineReader {
            inner: BufReader::with_capacity(SOURCE_IO_BUFFER_BYTES, file.take(self.snapshot.len)),
            deadline: self.budget.deadline,
        }))
    }
}

/// Compatibility reopening: <=128 MiB logical SQLite snapshots.
pub fn open_snapshot_source(path: &Path, snapshot: &SourceSnapshot) -> PortResult<FileSource> {
    open_snapshot_source_budget(path, snapshot, SnapshotBudget::compatibility())
}
pub fn open_snapshot_source_with_deadline(
    path: &Path,
    snapshot: &SourceSnapshot,
    sqlite_byte_limit: u64,
    deadline: Instant,
) -> PortResult<FileSource> {
    open_snapshot_source_budget(
        path,
        snapshot,
        SnapshotBudget::bounded(sqlite_byte_limit, deadline)?,
    )
}
fn open_snapshot_source_budget(
    path: &Path,
    snapshot: &SourceSnapshot,
    budget: SnapshotBudget,
) -> PortResult<FileSource> {
    budget.check()?;
    if snapshot.fingerprint.starts_with("sqlite:") {
        budget.check_len(snapshot.len)?;
        let copy = sqlite_snapshot(path, budget)?;
        let current = capture_file(&copy, budget)?;
        verify_sqlite_snapshot(snapshot, &current)?;
        budget.check()?;
        return Ok(FileSource {
            path: copy.to_path_buf(),
            snapshot: current,
            _temporary: Some(std::sync::Arc::new(copy)),
            budget,
        });
    }
    let meta = std::fs::metadata(path).map_err(backend)?;
    verify_metadata(&meta, snapshot)?;
    budget.check()?;
    Ok(FileSource {
        path: path.to_path_buf(),
        snapshot: snapshot.clone(),
        _temporary: None,
        budget,
    })
}

/// Final compatibility verification: metadata + full captured-range fingerprint.
pub fn verify_snapshot(path: &Path, snapshot: &SourceSnapshot) -> PortResult<()> {
    verify_snapshot_budget(path, snapshot, SnapshotBudget::compatibility())
}
pub fn verify_snapshot_with_deadline(
    path: &Path,
    snapshot: &SourceSnapshot,
    sqlite_byte_limit: u64,
    deadline: Instant,
) -> PortResult<()> {
    verify_snapshot_budget(
        path,
        snapshot,
        SnapshotBudget::bounded(sqlite_byte_limit, deadline)?,
    )
}
fn verify_snapshot_budget(
    path: &Path,
    snapshot: &SourceSnapshot,
    budget: SnapshotBudget,
) -> PortResult<()> {
    budget.check()?;
    if snapshot.fingerprint.starts_with("sqlite:") {
        budget.check_len(snapshot.len)?;
        let copy = sqlite_snapshot(path, budget)?;
        let current = capture_file(&copy, budget)?;
        verify_sqlite_snapshot(snapshot, &current)?;
        return budget.check();
    }
    let file = File::open(path).map_err(backend)?;
    verify_metadata(&file.metadata().map_err(backend)?, snapshot)?;
    let mut captured = file.take(snapshot.len);
    let (len, fingerprint) = fingerprint_reader(&mut captured, budget)?;
    if len != snapshot.len {
        return Err(PortError::SnapshotChanged(format!(
            "len changed during verification {} -> {len}",
            snapshot.len
        )));
    }
    if fingerprint != snapshot.fingerprint {
        return Err(PortError::SnapshotChanged(
            "fingerprint changed (content replaced at same len)".into(),
        ));
    }
    post_read_verify(path, snapshot)?;
    budget.check()
}
fn verify_sqlite_snapshot(expected: &SourceSnapshot, current: &SourceSnapshot) -> PortResult<()> {
    if expected.len != current.len
        || expected.fingerprint.strip_prefix("sqlite:") != Some(current.fingerprint.as_str())
    {
        Err(PortError::SnapshotChanged(
            "SQLite logical content changed".into(),
        ))
    } else {
        Ok(())
    }
}
fn post_read_verify(path: &Path, snap: &SourceSnapshot) -> PortResult<()> {
    let meta_after = std::fs::metadata(path).map_err(backend)?;
    verify_metadata(&meta_after, snap).map_err(|error| match error {
        PortError::SnapshotChanged(detail) => {
            PortError::SnapshotChanged(format!("source changed during verification: {detail}"))
        }
        other => other,
    })
}
/// Capture and return a repeatable reader source; no transcript-sized `Vec`.
pub fn read_verified(path: &Path) -> PortResult<(SourceSnapshot, FileSource)> {
    let snapshot = capture(path)?;
    let source = open_snapshot_source(path, &snapshot)?;
    verify_snapshot(path, &snapshot)?;
    Ok((snapshot, source))
}

/// 基于已有快照元数据的只读路径发现器（实现 [`SourceDiscovery`] 的最小落地）。
///
/// 构造时给定一组已 capture 的快照；`discover` 返回它们的克隆，
/// `read_verified` 按路径重读并校验三元组。用于测试与组合根装配。
pub struct SnapshotFs {
    snapshots: Vec<SourceSnapshot>,
}

impl SnapshotFs {
    pub fn new(snapshots: Vec<SourceSnapshot>) -> Self {
        Self { snapshots }
    }
}

impl agent_session_grep_ports::SourceDiscovery for SnapshotFs {
    fn discover(&self) -> PortResult<Vec<SourceSnapshot>> {
        Ok(self.snapshots.clone())
    }

    fn read_verified(&self, snapshot: &SourceSnapshot) -> PortResult<Vec<u8>> {
        // 兼容的整读路径：生产 ingest 已改走 `ReadOnlySource` 流式；这里保留
        // 给测试/旧字节调用方，但显式硬上限（与 JSON 系 manifest 一致），
        // 绝不无界整读。
        if snapshot.len > JSON_FAMILY_MAX_SOURCE_BYTES {
            return Err(PortError::SourceIo(format!(
                "legacy verified-byte read exceeds bounded limit {JSON_FAMILY_MAX_SOURCE_BYTES}"
            )));
        }
        let path = Path::new(&snapshot.path);
        let source = open_snapshot_source(path, snapshot)?;
        let mut reader = source.open()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(snapshot.len as usize)
            .map_err(|_| PortError::SourceIo("bounded source allocation failed".into()))?;
        let mut chunk = [0_u8; SOURCE_IO_BUFFER_BYTES];
        loop {
            let read = reader.read(&mut chunk).map_err(backend)?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        verify_snapshot(path, snapshot)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sqlite_capture_reads_wal_and_detects_wal_only_changes_without_writing_source() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let path = dir.path().join("live.db");
        let writer = rusqlite::Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t(value); INSERT INTO t VALUES('first');").unwrap();
        let wal = path.with_extension("db-wal");
        let main_before = std::fs::read(&path).unwrap();
        let wal_before = std::fs::read(&wal).unwrap();
        let snapshot = capture(&path).unwrap();
        let source = open_snapshot_source(&path, &snapshot).unwrap();
        let reader = rusqlite::Connection::open_with_flags(
            &source.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            reader
                .query_row("SELECT value FROM t", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "first"
        );
        verify_snapshot(&path, &snapshot).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), main_before);
        assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
        writer
            .execute("INSERT INTO t VALUES('second')", [])
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), main_before);
        assert!(matches!(
            verify_snapshot(&path, &snapshot),
            Err(PortError::SnapshotChanged(_))
        ));
        let next = capture(&path).unwrap();
        assert_ne!(next.fingerprint, snapshot.fingerprint);
        // A checkpoint performed by the external writer changes physical
        // files only; the captured logical source remains current.
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        verify_snapshot(&path, &next).unwrap();
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        p
    }

    #[test]
    fn capture_and_verify_stable_file() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "a.jsonl", b"hello stable content");
        let snap = capture(&p).unwrap();
        assert_eq!(
            snap.fingerprint,
            blake3::hash(b"hello stable content").to_hex().to_string()
        );
        assert_eq!(snap.len, 20);
        verify_snapshot(&p, &snap).unwrap();
    }

    #[test]
    fn append_is_detected() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "a.jsonl", b"hello");
        let snap = capture(&p).unwrap();
        // 追加
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(b" world").unwrap();
        }
        let err = verify_snapshot(&p, &snap).unwrap_err();
        assert!(matches!(err, PortError::SnapshotChanged(ref m) if m.contains("len")));
    }

    #[test]
    fn append_between_stat_and_read_is_detected_after_read() {
        // 复核读取窗口内追加：首次 stat 后、read 完成后文件才被追加。指纹校验
        // 只覆盖读取范围（按旧 len 截断），追加的字节重建后不会被指纹识别；
        // verify_snapshot 必须在读取后再次核对 len+mtime 才能检出。
        // 真实竞态（stat→read 之间追加）无法在单测里确定性复现，因此直接驱动
        // 读后复检函数 post_read_verify——它必须在读取完成后捕获 len/mtime 变化。
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "a.jsonl", b"hello world!!!!!");
        let snap = capture(&p).unwrap();
        // 捕获后截短内容：等价于"read 已完成、源在窗口内被改写"的状态。
        std::fs::write(&p, b"12345").unwrap();
        let err = post_read_verify(&p, &snap).unwrap_err();
        assert!(
            matches!(err, PortError::SnapshotChanged(ref m) if m.contains("source changed during verification")),
            "got {err:?}"
        );
    }

    #[test]
    fn truncate_is_detected() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "a.jsonl", b"hello world!!!!!");
        let snap = capture(&p).unwrap();
        {
            let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_len(5).unwrap();
        }
        let err = verify_snapshot(&p, &snap).unwrap_err();
        assert!(matches!(err, PortError::SnapshotChanged(ref m) if m.contains("len")));
    }

    #[test]
    fn equal_length_content_replacement_is_detected_by_fingerprint() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "a.jsonl", b"AAAAAAAAAA"); // 10 bytes
        // 捕获原始 mtime，替换后逐字节恢复，使 len 与 mtime 都与快照一致，
        // fingerprint 成为唯一能检出等长异容替换的信号。
        let original_modified = std::fs::metadata(&p).unwrap().modified().unwrap();
        let snap = capture(&p).unwrap();

        std::fs::write(&p, b"BBBBBBBBBB").unwrap();
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(original_modified)
            .unwrap();
        let restored = std::fs::metadata(&p).unwrap();
        assert_eq!(
            mtime_ms(&restored).unwrap(),
            snap.mtime_ms,
            "mtime 必须被恢复，fingerprint 才是唯一信号"
        );
        assert_eq!(restored.len(), snap.len, "替换必须等长");

        let err = verify_snapshot(&p, &snap).unwrap_err();
        assert!(
            matches!(err, PortError::SnapshotChanged(ref m) if m.contains("fingerprint changed")),
            "got {err:?}"
        );
    }

    #[test]
    fn snapshot_fs_read_verified_roundtrip() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "s.jsonl", b"payload-bytes");
        let snap = capture(&p).unwrap();
        let fs = SnapshotFs::new(vec![snap.clone()]);
        use agent_session_grep_ports::SourceDiscovery;
        let discovered = fs.discover().unwrap();
        assert_eq!(discovered.len(), 1);
        let bytes = fs.read_verified(&snap).unwrap();
        assert_eq!(bytes, b"payload-bytes");
    }

    #[test]
    fn read_verified_returns_repeatable_source() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "s.jsonl", b"line one\nline two\n");
        let (snap, source) = read_verified(&p).unwrap();
        assert_eq!(snap.len, 18);
        let mut reader = source.open().unwrap();
        let mut text = String::new();
        reader.read_to_string(&mut text).unwrap();
        assert_eq!(text, "line one\nline two\n");
    }

    #[test]
    fn file_source_reader_detects_replacement_at_reopen() {
        // 等长异容替换后重新 open：metadata 一致（len+mtime 相同）仍会读到替换
        // 内容——这正是 ReadOnlySource 只读视图的诚实边界；提交前 verify_snapshot
        // 用 fingerprint 兜住（等长替换检测测试已覆盖）。
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let p = write_file(dir.path(), "a.jsonl", b"AAAAAAAAAA");
        let original_modified = std::fs::metadata(&p).unwrap().modified().unwrap();
        let snap = capture(&p).unwrap();
        std::fs::write(&p, b"BBBBBBBBBB").unwrap();
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(original_modified)
            .unwrap();
        let source = open_snapshot_source(&p, &snap).unwrap();
        let mut reader = source.open().unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"BBBBBBBBBB");
    }

    #[test]
    fn snapshot_fs_read_verified_rejects_oversized_source() {
        // 兼容整读路径必须诚实拒绝超过 JSON 系上限的源，而非按大文件分配。
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let big = vec![b'x'; (JSON_FAMILY_MAX_SOURCE_BYTES as usize) + 1];
        let p = write_file(dir.path(), "big.jsonl", &big);
        let snap = capture(&p).unwrap();
        let fs = SnapshotFs::new(vec![snap.clone()]);
        use agent_session_grep_ports::SourceDiscovery;
        let err = fs.read_verified(&snap).unwrap_err();
        assert!(
            matches!(err, PortError::SourceIo(ref m) if m.contains("bounded limit")),
            "got {err:?}"
        );
    }
}
