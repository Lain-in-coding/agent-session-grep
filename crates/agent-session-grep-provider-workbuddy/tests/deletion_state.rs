//! Synthetic in-memory and disposable WAL SQLite images only. This validates
//! metadata classification; real DB/WAL acquisition remains a main-layer
//! responsibility, and JSONL file presence is deliberately not deletion proof.
use agent_session_grep_provider_workbuddy::{
    SessionDeletionState as State, SessionStateError as Error, inspect_session_state,
    inspect_session_states,
};
use rusqlite::{Connection, MAIN_DB, params};
use std::time::{Duration, Instant};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn image() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE sessions(id TEXT,deleted_at,transport,cwd)")
        .unwrap();
    db
}
fn snapshot(db: &Connection) -> Vec<u8> {
    db.serialize(MAIN_DB).unwrap().to_vec()
}
#[test]
fn active_deleted_cloud_orphan_matrix_uses_only_observed_db_state() {
    let db = image();
    for (id, deleted, transport) in [
        ("active-local", None, Some("local")),
        ("deleted-local", Some(42), Some("local")),
        ("active-cloud", None, Some("cloud")),
        ("deleted-cloud", Some(42), Some("cloud")),
        ("unknown-transport", None, Some("future")),
        ("no-transport", None, None),
    ] {
        db.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,?4)",
            params![id, deleted, transport, "/synthetic/project"],
        )
        .unwrap();
    }
    let bytes = snapshot(&db);
    let before = bytes.clone();
    for (id, expected) in [
        ("active-local", State::ActiveLocal),
        ("deleted-local", State::SoftDeleted),
        ("active-cloud", State::CloudUnavailable),
        ("deleted-cloud", State::SoftDeleted),
        ("unknown-transport", State::OrphanUnknown),
        ("no-transport", State::OrphanUnknown),
        ("missing-row", State::OrphanUnknown),
    ] {
        let observed = inspect_session_state(&bytes, id, deadline()).unwrap();
        assert_eq!(observed.state, expected);
        assert_eq!(
            observed.cwd.as_deref(),
            (id != "missing-row").then_some("/synthetic/project")
        );
    }
    assert_eq!(bytes, before);
}
#[test]
fn unreadable_or_unsupported_snapshot_is_error_never_deleted_or_empty_success() {
    for bytes in [vec![], b"not a sqlite database".to_vec(), vec![0; 200]] {
        assert_eq!(
            inspect_session_state(&bytes, "session", deadline()),
            Err(Error::Unreadable)
        );
    }
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE unrelated(value TEXT)")
        .unwrap();
    assert_eq!(
        inspect_session_state(&snapshot(&db), "session", deadline()),
        Err(Error::UnsupportedSchema)
    );
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE sessions(id TEXT,cwd TEXT)")
        .unwrap();
    assert_eq!(
        inspect_session_state(&snapshot(&db), "session", deadline()),
        Err(Error::UnsupportedSchema)
    );
    let db = image();
    db.execute(
        "INSERT INTO sessions VALUES('invalid','not-a-delete-time','local',NULL)",
        [],
    )
    .unwrap();
    assert_eq!(
        inspect_session_state(&snapshot(&db), "invalid", deadline()),
        Err(Error::UnsupportedSchema)
    );
}
#[test]
fn zero_deletion_time_is_present_cwd_is_private_and_duplicate_ids_are_ambiguous() {
    let db = image();
    db.execute(
        "INSERT INTO sessions VALUES('zero',0,'local',?1)",
        ["/synthetic/private-cwd"],
    )
    .unwrap();
    let state = inspect_session_state(&snapshot(&db), "zero", deadline()).unwrap();
    assert_eq!(state.state, State::SoftDeleted);
    assert_eq!(state.cwd.as_deref(), Some("/synthetic/private-cwd"));
    assert!(!format!("{state:?}").contains("/synthetic"));
    db.execute(
        "INSERT INTO sessions VALUES('duplicate',NULL,'local',NULL)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO sessions VALUES('duplicate',1,'local',NULL)",
        [],
    )
    .unwrap();
    assert_eq!(
        inspect_session_state(&snapshot(&db), "duplicate", deadline()),
        Err(Error::AmbiguousSession)
    );
}
#[test]
fn parameters_are_bound_and_expired_deadline_is_not_replaced_by_a_new_budget() {
    let db = image();
    db.execute("INSERT INTO sessions VALUES('real',1,'local',NULL)", [])
        .unwrap();
    let bytes = snapshot(&db);
    assert_eq!(
        inspect_session_state(&bytes, "x' OR 1=1 --", deadline())
            .unwrap()
            .state,
        State::OrphanUnknown
    );
    assert_eq!(
        inspect_session_state(&bytes, "real", Instant::now()),
        Err(Error::Deadline)
    );
    assert_eq!(
        inspect_session_state(&bytes, "  ", deadline()),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        inspect_session_state(&bytes, "real", deadline())
            .unwrap()
            .state,
        State::SoftDeleted
    );
}
#[test]
fn invalid_or_mixed_sqlite_header_versions_refuse_without_mutating_the_logical_input() {
    let db = image();
    for (write, read) in [(0, 0), (3, 3), (1, 2), (2, 1), (0, 1), (1, 3)] {
        let mut bytes = snapshot(&db);
        bytes[18] = write;
        bytes[19] = read;
        let before = bytes.clone();
        assert_eq!(
            inspect_session_state(&bytes, "missing", deadline()),
            Err(Error::Unreadable)
        );
        assert_eq!(
            inspect_session_states(&bytes, deadline()),
            Err(Error::Unreadable)
        );
        assert_eq!(bytes, before);
    }
}
#[test]
fn snapshot_size_limit_is_enforced_before_deserialize() {
    let too_large = vec![0; agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES as usize + 1];
    assert_eq!(
        inspect_session_state(&too_large, "session", deadline()),
        Err(Error::SnapshotTooLarge)
    );
    assert_eq!(
        inspect_session_states(&too_large, deadline()),
        Err(Error::SnapshotTooLarge)
    );
}

#[test]
fn large_cwd_and_invalid_row_types_do_not_produce_authoritative_active_or_deleted_state() {
    let db = image();
    db.execute(
        "INSERT INTO sessions VALUES('oversized',NULL,'local',?1)",
        ["x".repeat(65_537)],
    )
    .unwrap();
    db.execute(
        "INSERT INTO sessions VALUES('bad-cwd',NULL,'local',X'FF')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO sessions VALUES('negative-delete',-1,'local',NULL)",
        [],
    )
    .unwrap();
    let bytes = snapshot(&db);
    for id in ["oversized", "bad-cwd", "negative-delete"] {
        assert_eq!(
            inspect_session_state(&bytes, id, deadline()),
            Err(Error::UnsupportedSchema)
        );
    }
}

#[test]
fn native_session_ids_use_exact_text_equality_without_column_collation_or_numeric_coercion() {
    for collation in ["NOCASE", "RTRIM"] {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(&format!(
            "CREATE TABLE sessions(id TEXT COLLATE {collation},deleted_at,transport,cwd)"
        ))
        .unwrap();
        db.execute(
            "INSERT INTO sessions VALUES(?1,1,'local',NULL)",
            ["SyntheticId "],
        )
        .unwrap();
        let bytes = snapshot(&db);
        assert_eq!(
            inspect_session_state(&bytes, "SyntheticId ", deadline())
                .unwrap()
                .state,
            State::SoftDeleted
        );
        for unrelated in ["syntheticid ", "SyntheticId", "SyntheticId  "] {
            assert_eq!(
                inspect_session_state(&bytes, unrelated, deadline())
                    .unwrap()
                    .state,
                State::OrphanUnknown
            );
        }
    }
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE sessions(id NUMERIC,deleted_at,transport,cwd);
        INSERT INTO sessions VALUES(1,1,'local',NULL)",
    )
    .unwrap();
    let bytes = snapshot(&db);
    for unrelated in ["1", "01", "1.0", "1e0"] {
        assert_eq!(
            inspect_session_state(&bytes, unrelated, deadline())
                .unwrap()
                .state,
            State::OrphanUnknown
        );
    }
}

#[test]
fn actual_wal_online_backup_with_version_two_header_is_readable_and_input_stays_immutable() {
    use rusqlite::backup::{Backup, StepResult};
    let temp = tempfile::tempdir().unwrap();
    let source_path = temp.path().join("synthetic-source.sqlite");
    let source = Connection::open(&source_path).unwrap();
    source
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
        CREATE TABLE sessions(id TEXT,deleted_at,transport,cwd);",
        )
        .unwrap();
    source
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    source
        .execute(
            "INSERT INTO sessions VALUES('wal-deleted',42,'local',?1)",
            ["/synthetic/wal-project"],
        )
        .unwrap();
    source
        .execute(
            "INSERT INTO sessions VALUES('wal-active',NULL,'local',NULL)",
            [],
        )
        .unwrap();
    source
        .execute(
            "INSERT INTO sessions VALUES('wal-cloud',NULL,'cloud',NULL)",
            [],
        )
        .unwrap();
    assert!(
        std::fs::metadata(source_path.with_extension("sqlite-wal"))
            .unwrap()
            .len()
            > 0
    );
    let source_main_before = std::fs::read(&source_path).unwrap();
    let source_wal_before = std::fs::read(source_path.with_extension("sqlite-wal")).unwrap();
    let mut target = Connection::open(temp.path().join("synthetic-logical.sqlite")).unwrap();
    target
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    {
        let backup = Backup::new(&source, &mut target).unwrap();
        assert_eq!(backup.step(-1).unwrap(), StepResult::Done);
    }
    let bytes = snapshot(&target);
    // This is an actual SQLite online-backup image, not a changed test header.
    assert_eq!(&bytes[18..20], &[2, 2]);
    let before = bytes.clone();
    for (id, expected) in [
        ("wal-deleted", State::SoftDeleted),
        ("wal-active", State::ActiveLocal),
        ("wal-cloud", State::CloudUnavailable),
        ("not-present", State::OrphanUnknown),
    ] {
        assert_eq!(
            inspect_session_state(&bytes, id, deadline()).unwrap().state,
            expected
        );
    }
    assert_eq!(
        inspect_session_state(&bytes, "wal-deleted", deadline())
            .unwrap()
            .cwd
            .as_deref(),
        Some("/synthetic/wal-project")
    );
    let batch = inspect_session_states(&bytes, deadline()).unwrap();
    assert_eq!(batch.len(), 3);
    for (id, observed) in batch {
        assert_eq!(
            observed,
            inspect_session_state(&bytes, &id, deadline()).unwrap()
        );
    }
    assert_eq!(bytes, before);
    assert_eq!(std::fs::read(&source_path).unwrap(), source_main_before);
    assert_eq!(
        std::fs::read(source_path.with_extension("sqlite-wal")).unwrap(),
        source_wal_before
    );
}

#[test]
fn batch_scans_each_observed_session_once_and_matches_single_lookup_without_content() {
    let db = image();
    // The helper sees only metadata, even when arbitrary message content exists.
    db.execute_batch(
        "CREATE TABLE messages(body BLOB);
        INSERT INTO messages VALUES(X'00FF00');",
    )
    .unwrap();
    for (id, deleted, transport, cwd) in [
        (
            "local",
            None,
            Some("local"),
            Some("  /synthetic/exact cwd  "),
        ),
        ("deleted", Some(0), Some("local"), None),
        ("cloud", None, Some("cloud"), Some("/synthetic/cloud")),
        ("deleted-cloud", Some(42), Some("cloud"), None),
        ("future", None, Some("future-transport"), None),
        ("null", None, None, Some("  ")),
        ("exact-id ", None, Some("local"), None),
    ] {
        db.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,?4)",
            params![id, deleted, transport, cwd],
        )
        .unwrap();
    }
    let bytes = snapshot(&db);
    let before = bytes.clone();
    let batch = inspect_session_states(&bytes, deadline()).unwrap();
    assert_eq!(batch.len(), 7);
    let ids: Vec<_> = batch.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "cloud",
            "deleted",
            "deleted-cloud",
            "exact-id ",
            "future",
            "local",
            "null"
        ]
    );
    for (id, observed) in &batch {
        assert_eq!(
            *observed,
            inspect_session_state(&bytes, id, deadline()).unwrap()
        );
    }
    let local = batch.iter().find(|(id, _)| id == "local").unwrap();
    assert_eq!(local.1.state, State::ActiveLocal);
    assert_eq!(local.1.cwd.as_deref(), Some("  /synthetic/exact cwd  "));
    for id in ["future", "null"] {
        assert_eq!(
            batch.iter().find(|(key, _)| key == id).unwrap().1.state,
            State::OrphanUnknown
        );
    }
    assert!(batch.iter().all(|(id, _)| id != "absent"));
    assert_eq!(
        inspect_session_state(&bytes, "absent", deadline())
            .unwrap()
            .state,
        State::OrphanUnknown
    );
    assert_eq!(bytes, before);
}

#[test]
fn batch_duplicate_native_ids_refuse_all_rows_but_column_collation_never_merges_distinct_ids() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "CREATE TABLE sessions(id TEXT COLLATE NOCASE,deleted_at,transport,cwd);
        INSERT INTO sessions VALUES('CaseId',NULL,'local',NULL);
        INSERT INTO sessions VALUES('caseid',NULL,'cloud',NULL);
        INSERT INTO sessions VALUES('CaseId ',NULL,'future',NULL);",
    )
    .unwrap();
    let bytes = snapshot(&db);
    let batch = inspect_session_states(&bytes, deadline()).unwrap();
    assert_eq!(
        batch.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        ["CaseId", "CaseId ", "caseid"]
    );
    db.execute("INSERT INTO sessions VALUES('caseid',1,'local',NULL)", [])
        .unwrap();
    let bytes = snapshot(&db);
    let before = bytes.clone();
    assert_eq!(
        inspect_session_states(&bytes, deadline()),
        Err(Error::AmbiguousSession)
    );
    assert_eq!(bytes, before);
}

#[test]
fn batch_invalid_id_or_state_fields_refuse_whole_batch_after_valid_rows() {
    use rusqlite::types::Value;
    for (id, deleted, transport, cwd) in [
        (
            Value::Null,
            Value::Null,
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Integer(7),
            Value::Null,
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Blob(b"id".to_vec()),
            Value::Null,
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Text("  ".into()),
            Value::Null,
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Text("invalid".into()),
            Value::Integer(-1),
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Text("invalid".into()),
            Value::Real(1.5),
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Text("invalid".into()),
            Value::Text("deleted".into()),
            Value::Text("local".into()),
            Value::Null,
        ),
        (
            Value::Text("invalid".into()),
            Value::Null,
            Value::Integer(1),
            Value::Null,
        ),
        (
            Value::Text("invalid".into()),
            Value::Integer(0),
            Value::Blob(b"local".to_vec()),
            Value::Null,
        ),
        (
            Value::Text("invalid".into()),
            Value::Null,
            Value::Text("local".into()),
            Value::Integer(1),
        ),
        (
            Value::Text("invalid".into()),
            Value::Null,
            Value::Text("local".into()),
            Value::Blob(vec![255]),
        ),
        (
            Value::Text("invalid".into()),
            Value::Null,
            Value::Text("local".into()),
            Value::Text("x".repeat(65_537)),
        ),
    ] {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE sessions(id,deleted_at,transport,cwd);
            INSERT INTO sessions VALUES('first-valid',NULL,'local',NULL)",
        )
        .unwrap();
        db.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,?4)",
            params![id, deleted, transport, cwd],
        )
        .unwrap();
        let bytes = snapshot(&db);
        let before = bytes.clone();
        assert_eq!(
            inspect_session_states(&bytes, deadline()),
            Err(Error::UnsupportedSchema)
        );
        assert_eq!(bytes, before);
    }
    for invalid in [
        "INSERT INTO sessions VALUES(CAST(X'FF' AS TEXT),NULL,'local',NULL)",
        "INSERT INTO sessions VALUES('invalid',NULL,CAST(X'FF' AS TEXT),NULL)",
        "INSERT INTO sessions VALUES('invalid',NULL,'local',CAST(X'FF' AS TEXT))",
    ] {
        let db = image();
        db.execute_batch(invalid).unwrap();
        assert_eq!(
            inspect_session_states(&snapshot(&db), deadline()),
            Err(Error::UnsupportedSchema)
        );
    }
}

#[test]
fn batch_empty_valid_table_is_distinct_from_unsupported_schema_or_unreadable_image() {
    let bytes = snapshot(&image());
    assert!(
        inspect_session_states(&bytes, deadline())
            .unwrap()
            .is_empty()
    );
    for bytes in [vec![], b"not a database".to_vec(), vec![0; 200]] {
        assert_eq!(
            inspect_session_states(&bytes, deadline()),
            Err(Error::Unreadable)
        );
    }
    for schema in [
        "CREATE TABLE unrelated(id TEXT)",
        "CREATE TABLE sessions(id TEXT,cwd TEXT)",
    ] {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(schema).unwrap();
        assert_eq!(
            inspect_session_states(&snapshot(&db), deadline()),
            Err(Error::UnsupportedSchema)
        );
    }
}

#[test]
fn batch_expired_deadline_refuses_without_installing_a_new_budget() {
    let db = image();
    db.execute("INSERT INTO sessions VALUES('valid',NULL,'local',NULL)", [])
        .unwrap();
    let bytes = snapshot(&db);
    let before = bytes.clone();
    let expired = Instant::now();
    assert_eq!(
        inspect_session_states(&bytes, expired),
        Err(Error::Deadline)
    );
    assert_eq!(
        inspect_session_states(&bytes, expired),
        Err(Error::Deadline)
    );
    assert_eq!(bytes, before);
    assert_eq!(
        inspect_session_states(&bytes, deadline()).unwrap()[0]
            .1
            .state,
        State::ActiveLocal
    );
}

#[test]
fn batch_row_bound_rejects_instead_of_returning_a_truncated_authoritative_inventory() {
    let db = image();
    db.execute_batch(
        "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<65536)
        INSERT INTO sessions SELECT printf('synthetic-%06d',i),NULL,'local',NULL FROM n",
    )
    .unwrap();
    let bytes = snapshot(&db);
    let end = Instant::now() + Duration::from_secs(10);
    assert_eq!(inspect_session_states(&bytes, end).unwrap().len(), 65_536);
    db.execute(
        "INSERT INTO sessions VALUES('over-bound',NULL,'local',NULL)",
        [],
    )
    .unwrap();
    let bytes = snapshot(&db);
    assert_eq!(
        inspect_session_states(&bytes, end),
        Err(Error::InspectionTooLarge)
    );
}

#[test]
fn batch_native_id_and_total_content_bounds_never_truncate_values() {
    let db = image();
    let long_id = "synthetic-".to_string() + &"x".repeat(8192) + " ";
    db.execute(
        "INSERT INTO sessions VALUES(?1,NULL,'local',NULL)",
        [&long_id],
    )
    .unwrap();
    let batch = inspect_session_states(&snapshot(&db), deadline()).unwrap();
    assert_eq!(batch[0].0, long_id);
    db.execute(
        "INSERT INTO sessions VALUES(?1,NULL,'local',NULL)",
        ["x".repeat(agent_session_grep_ports::STREAM_RECORD_MAX_BYTES as usize + 1)],
    )
    .unwrap();
    assert_eq!(
        inspect_session_states(&snapshot(&db), deadline()),
        Err(Error::InspectionTooLarge)
    );
    let db = image();
    db.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<513)
        INSERT INTO sessions SELECT printf('synthetic-%06d',i),NULL,'local',replace(hex(zeroblob(32768)),'0','x') FROM n")
        .unwrap();
    let bytes = snapshot(&db);
    let before = bytes.clone();
    assert_eq!(
        inspect_session_states(&bytes, Instant::now() + Duration::from_secs(10)),
        Err(Error::InspectionTooLarge)
    );
    assert_eq!(bytes, before);
}
