//! Synthetic filesystem and SQLite/WAL only. No host profile or real histories.
use agent_session_grep_adapters_sqlite::{
    capture, capture_with_deadline, open_snapshot_source, open_snapshot_source_with_deadline,
    verify_snapshot, verify_snapshot_with_deadline,
};
use agent_session_grep_ports::{
    PortError, ReadOnlySource, SQLITE_MAX_SOURCE_BYTES, SourceSnapshot,
};
use rusqlite::Connection;
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SOURCE_IO_BUFFER_BYTES: usize = 64 * 1024;
const SQLITE_256_MIB: u64 = 256 * 1024 * 1024;
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn hash_file(path: &Path) -> String {
    let mut source = fs::File::open(path).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut chunk = [0_u8; SOURCE_IO_BUFFER_BYTES];
    loop {
        let read = source.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    hasher.finalize().to_hex().to_string()
}
fn stable_identity(path: &Path) -> u64 {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let file = fs::File::open(path).unwrap();
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        assert_ne!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
            0
        );
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().ino()
    }
    #[cfg(not(any(windows, unix)))]
    {
        fs::metadata(path).unwrap().len()
    }
}
fn dummy_snapshot(path: &Path) -> SourceSnapshot {
    SourceSnapshot {
        path: path.to_string_lossy().into_owned(),
        len: 0,
        mtime_ms: 0,
        fingerprint: "sqlite:".into(),
    }
}

#[test]
fn expired_deadline_and_unsupported_limits_precede_source_io() {
    let temp = tempfile::tempdir().unwrap();
    let absent = temp.path().join("absent/source.db");
    let snapshot = dummy_snapshot(&absent);
    assert!(matches!(
        capture_with_deadline(&absent, SQLITE_MAX_SOURCE_BYTES, Instant::now()),
        Err(PortError::WriterBusy(_))
    ));
    assert!(matches!(
        open_snapshot_source_with_deadline(
            &absent,
            &snapshot,
            SQLITE_MAX_SOURCE_BYTES,
            Instant::now()
        ),
        Err(PortError::WriterBusy(_))
    ));
    assert!(matches!(
        verify_snapshot_with_deadline(&absent, &snapshot, SQLITE_MAX_SOURCE_BYTES, Instant::now()),
        Err(PortError::WriterBusy(_))
    ));
    for limit in [
        0,
        1,
        SQLITE_MAX_SOURCE_BYTES - 1,
        SQLITE_MAX_SOURCE_BYTES + 1,
        SQLITE_256_MIB + 1,
        u64::MAX,
    ] {
        assert!(matches!(
            capture_with_deadline(&absent, limit, end()),
            Err(PortError::InvalidRequest(_))
        ));
        assert!(matches!(
            open_snapshot_source_with_deadline(&absent, &snapshot, limit, end()),
            Err(PortError::InvalidRequest(_))
        ));
        assert!(matches!(
            verify_snapshot_with_deadline(&absent, &snapshot, limit, end()),
            Err(PortError::InvalidRequest(_))
        ));
    }
    assert!(!absent.parent().unwrap().exists());
}

#[test]
fn text_snapshot_deadline_preserves_full_hash_and_equal_length_rewrite_detection() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("synthetic.jsonl");
    let bytes = vec![b'a'; SOURCE_IO_BUFFER_BYTES * 3 + 7];
    fs::write(&path, &bytes).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let deadline = end();
    let snapshot = capture_with_deadline(&path, SQLITE_MAX_SOURCE_BYTES, deadline).unwrap();
    assert_eq!(snapshot.len, bytes.len() as u64);
    assert_eq!(
        snapshot.fingerprint,
        blake3::hash(&bytes).to_hex().to_string()
    );
    let source =
        open_snapshot_source_with_deadline(&path, &snapshot, SQLITE_MAX_SOURCE_BYTES, deadline)
            .unwrap();
    let mut reader = source.open().unwrap();
    let mut first = [0_u8; 11];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"aaaaaaaaaaa");
    drop(reader);
    let mut reopened = source.open().unwrap();
    let mut whole = Vec::new();
    reopened.read_to_end(&mut whole).unwrap();
    assert_eq!(whole, bytes);
    drop(reopened);
    verify_snapshot_with_deadline(&path, &snapshot, SQLITE_MAX_SOURCE_BYTES, deadline).unwrap();
    fs::write(&path, vec![b'b'; bytes.len()]).unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    assert!(matches!(
        verify_snapshot_with_deadline(&path, &snapshot, SQLITE_MAX_SOURCE_BYTES, deadline),
        Err(PortError::SnapshotChanged(_))
    ));
}

#[test]
fn file_source_deadline_is_shared_by_clone_reopen_read_and_fill_buf() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("synthetic.jsonl");
    fs::write(&path, vec![b'x'; SOURCE_IO_BUFFER_BYTES * 2]).unwrap();
    let snapshot = capture(&path).unwrap();
    let deadline = Instant::now() + Duration::from_millis(300);
    let source =
        open_snapshot_source_with_deadline(&path, &snapshot, SQLITE_MAX_SOURCE_BYTES, deadline)
            .unwrap();
    let cloned = source.clone();
    let mut reader = source.open().unwrap();
    let mut small = [0; 8];
    reader.read_exact(&mut small).unwrap();
    let wait = deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5);
    std::thread::sleep(wait);
    assert_eq!(
        reader.read(&mut small).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        reader.fill_buf().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(matches!(source.open(), Err(PortError::WriterBusy(_))));
    assert!(matches!(cloned.open(), Err(PortError::WriterBusy(_))));
}

#[test]
fn file_source_single_read_stays_within_fixed_chunk_even_for_large_caller_buffer() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("synthetic.jsonl");
    fs::write(&path, vec![b'x'; SOURCE_IO_BUFFER_BYTES * 4]).unwrap();
    let snapshot = capture_with_deadline(&path, SQLITE_MAX_SOURCE_BYTES, end()).unwrap();
    let source =
        open_snapshot_source_with_deadline(&path, &snapshot, SQLITE_MAX_SOURCE_BYTES, end())
            .unwrap();
    let mut reader = source.open().unwrap();
    let mut buffer = vec![0; SOURCE_IO_BUFFER_BYTES * 3];
    let read = reader.read(&mut buffer).unwrap();
    assert_eq!(read, SOURCE_IO_BUFFER_BYTES);
}

#[test]
fn logical_deadline_snapshot_includes_wal_and_preserves_source_inode_db_and_wal() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("live.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE facts(value); INSERT INTO facts VALUES('first synthetic observation');").unwrap();
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let identity = stable_identity(&path);
    let before_db = hash_file(&path);
    let before_wal = hash_file(&wal);
    let deadline = end();
    let snapshot = capture_with_deadline(&path, SQLITE_256_MIB, deadline).unwrap();
    assert!(snapshot.fingerprint.starts_with("sqlite:"));
    let source =
        open_snapshot_source_with_deadline(&path, &snapshot, SQLITE_256_MIB, deadline).unwrap();
    let copy = temp.path().join("private-copy.db");
    let mut output = fs::File::create(&copy).unwrap();
    std::io::copy(&mut source.open().unwrap(), &mut output).unwrap();
    output.flush().unwrap();
    drop(output);
    let reader =
        Connection::open_with_flags(&copy, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        reader
            .query_row("SELECT value FROM facts", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "first synthetic observation"
    );
    drop(reader);
    verify_snapshot_with_deadline(&path, &snapshot, SQLITE_256_MIB, deadline).unwrap();
    assert_eq!(stable_identity(&path), identity);
    assert_eq!(hash_file(&path), before_db);
    assert_eq!(hash_file(&wal), before_wal);
    writer
        .execute(
            "INSERT INTO facts VALUES('second synthetic observation')",
            [],
        )
        .unwrap();
    assert_eq!(hash_file(&path), before_db);
    assert!(matches!(
        verify_snapshot_with_deadline(&path, &snapshot, SQLITE_256_MIB, deadline),
        Err(PortError::SnapshotChanged(_))
    ));
    let next = capture_with_deadline(&path, SQLITE_256_MIB, deadline).unwrap();
    writer
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    verify_snapshot_with_deadline(&path, &next, SQLITE_256_MIB, deadline).unwrap();
}

#[test]
fn source_write_lock_exhausts_only_original_budget_and_returns_no_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("locked.db");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch("CREATE TABLE t(value); INSERT INTO t VALUES(1);")
        .unwrap();
    let before = hash_file(&path);
    writer.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(50);
    assert!(matches!(
        capture_with_deadline(&path, SQLITE_MAX_SOURCE_BYTES, deadline),
        Err(PortError::WriterBusy(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    writer.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(hash_file(&path), before);
    assert!(capture_with_deadline(&path, SQLITE_MAX_SOURCE_BYTES, end()).is_ok());
}

#[test]
fn malformed_and_missing_sources_return_content_free_errors_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let absent = temp.path().join("private-synthetic-source");
    let error = capture_with_deadline(&absent, SQLITE_MAX_SOURCE_BYTES, end()).unwrap_err();
    assert!(matches!(error, PortError::SourceIo(_)));
    assert!(!error.to_string().contains("private-synthetic-source"));
    assert!(!absent.exists());
    let malformed = temp.path().join("invalid.db");
    fs::write(&malformed, b"SQLite format 3\0broken synthetic body").unwrap();
    let before = hash_file(&malformed);
    assert!(capture_with_deadline(&malformed, SQLITE_MAX_SOURCE_BYTES, end()).is_err());
    assert_eq!(hash_file(&malformed), before);
}

#[test]
fn above_128_mib_logical_snapshot_requires_explicit_256_mib_and_is_never_truncated() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("large-synthetic.db");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch(
            "PRAGMA page_size=65536; CREATE TABLE padding(value BLOB); PRAGMA user_version=42;",
        )
        .unwrap();
    // SQLite creates synthetic padding without a transcript-sized Rust buffer.
    writer
        .execute(
            "INSERT INTO padding VALUES(zeroblob(?1))",
            [SQLITE_MAX_SOURCE_BYTES as i64 + 1024 * 1024],
        )
        .unwrap();
    let logical_len: i64 = writer
        .query_row(
            "SELECT page_count*page_size FROM pragma_page_count,pragma_page_size",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        (logical_len as u64) > SQLITE_MAX_SOURCE_BYTES && (logical_len as u64) < SQLITE_256_MIB
    );
    let before = hash_file(&path);
    let identity = stable_identity(&path);
    assert!(matches!(capture(&path), Err(PortError::SourceIo(_))));
    assert!(matches!(
        capture_with_deadline(&path, SQLITE_MAX_SOURCE_BYTES, end()),
        Err(PortError::SourceIo(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    let snapshot = capture_with_deadline(&path, SQLITE_256_MIB, deadline).unwrap();
    assert_eq!(snapshot.len, logical_len as u64);
    assert!(matches!(
        open_snapshot_source(&path, &snapshot),
        Err(PortError::SourceIo(_))
    ));
    assert!(matches!(
        verify_snapshot(&path, &snapshot),
        Err(PortError::SourceIo(_))
    ));
    let source =
        open_snapshot_source_with_deadline(&path, &snapshot, SQLITE_256_MIB, deadline).unwrap();
    let mut reader = source.open().unwrap();
    let mut original = fs::File::open(&path).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; SOURCE_IO_BUFFER_BYTES];
    let mut original_chunk = [0_u8; SOURCE_IO_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        original.read_exact(&mut original_chunk[..read]).unwrap();
        if total == 0 {
            // Backup commits its own change counter, schema cookie and valid-for
            // counter. Every remaining byte, including all overflow pages and
            // user_version, must match this rollback-mode synthetic source.
            assert!(read >= 100);
            for field in [24..28, 40..44, 92..96] {
                original_chunk[field.clone()].copy_from_slice(&chunk[field]);
            }
        }
        assert!(
            chunk[..read] == original_chunk[..read],
            "logical payload mismatch at {total}"
        );
        total += read as u64;
    }
    assert_eq!(total, snapshot.len);
    assert_eq!(original.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(
        snapshot.fingerprint,
        format!("sqlite:{}", hasher.finalize().to_hex())
    );
    drop(reader);
    verify_snapshot_with_deadline(&path, &snapshot, SQLITE_256_MIB, deadline).unwrap();
    assert_eq!(hash_file(&path), before);
    assert_eq!(stable_identity(&path), identity);
    assert!(Instant::now() < deadline);
}
