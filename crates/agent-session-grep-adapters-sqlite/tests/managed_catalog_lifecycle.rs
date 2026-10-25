//! Synthetic catalogs and real OS handle locks; no provider histories.
use agent_session_grep_adapters_sqlite::{
    CatalogOpenAdmission, CatalogOpenIdentity, RepoSlugResolver, SCHEMA_VERSION, SqliteStore,
    WriterLease, managed,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
};
use agent_session_grep_domain::{IdKind, StableId};
use agent_session_grep_ports::{CatalogStore, PortError, PortResult, control::ControlId};
use rusqlite::Connection;
use std::{
    cell::Cell,
    path::{Path, PathBuf},
    rc::Rc,
};

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn message() -> StableId {
    StableId::native_checked(IdKind::Message, "synthetic-message").unwrap()
}
fn assert_busy<T>(result: PortResult<T>) {
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
}
fn exclusive(root: &Path) -> PortResult<ExclusiveGuard> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    loop {
        match ExclusiveGuard::try_acquire(root, LockKind::CatalogHandles) {
            Err(PortError::WriterBusy(_)) if std::time::Instant::now() < deadline => {
                std::thread::yield_now()
            }
            result => return result,
        }
    }
}

// Build an actual v19 fixture by removing the additive v20 objects/columns from
// an empty current catalog, preserving the legacy catalog and installation tables.
fn legacy_fixture(path: &Path) {
    drop(SqliteStore::open_for_write(p(path)).unwrap());
    let conn = Connection::open(path).unwrap();
    let managed_schema = Connection::open_in_memory().unwrap();
    managed_schema
        .execute_batch("PRAGMA foreign_keys=ON; BEGIN")
        .unwrap();
    managed::create_schema(&managed_schema).unwrap();
    let mut stmt=managed_schema.prepare("SELECT type,name,sql FROM sqlite_schema WHERE type IN ('table','trigger') AND name NOT LIKE 'sqlite_%'").unwrap();
    let objects = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    conn.execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE")
        .unwrap();
    let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
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
    conn.execute_batch(
        "ALTER TABLE store_metadata DROP COLUMN projection_contract_version;
        ALTER TABLE store_metadata DROP COLUMN managed_mode;
        ALTER TABLE store_metadata DROP COLUMN destructive_epoch;
        PRAGMA user_version=19; COMMIT;",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO catalog(id,payload) VALUES(?1,?2)",
        rusqlite::params![message().as_str(), b"legacy body".as_slice()],
    )
    .unwrap();
}

#[test]
fn additive_v20_migration_preserves_legacy_bytes_and_has_no_fabricated_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    legacy_fixture(&path);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        SqliteStore::open(p(&path)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let store = SqliteStore::open_for_write(p(&path)).unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        agent_session_grep_adapters_sqlite::SCHEMA_VERSION
    );
    assert_eq!(SCHEMA_VERSION, 22);
    assert_eq!(store.get(&message()).unwrap().unwrap(), b"legacy body");
    let conn = Connection::open(&path).unwrap();
    let metadata: (i64, i64, i64) = conn
        .query_row(
            "SELECT projection_contract_version,managed_mode,destructive_epoch FROM store_metadata",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(metadata, (0, 0, 0));
    for table in [
        "catalog_meta",
        "source_bindings",
        "source_heads",
        "source_revision_receipts",
        "source_projections",
        "source_occurrences",
        "source_entity_projections",
        "source_session_projections",
        "receipt_selection_claims",
        "source_scope_claims",
        "retained_source_receipts",
    ] {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "{table}"
        );
    }
    drop(conn);
    drop(store);
    let reopened = SqliteStore::open(p(&path)).unwrap();
    assert_eq!(reopened.get(&message()).unwrap().unwrap(), b"legacy body");
}

#[test]
fn failed_v20_ddl_rolls_back_columns_tables_and_version_together() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    legacy_fixture(&path);
    let conn = Connection::open(&path).unwrap();
    // A late name collision causes failure after metadata and earlier managed DDL.
    conn.execute_batch("CREATE TABLE source_occurrences(marker TEXT); INSERT INTO source_occurrences VALUES('keep')").unwrap();
    drop(conn);
    assert!(SqliteStore::open_for_write(p(&path)).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        19
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM pragma_table_info('store_metadata') WHERE name='managed_mode'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(conn.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN ('catalog_meta','source_bindings','source_projections')",[],|r|r.get::<_,i64>(0)).unwrap(),0);
    assert_eq!(
        conn.query_row("SELECT marker FROM source_occurrences", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "keep"
    );
    drop(conn);
    drop(exclusive(temp.path()).unwrap());
    drop(WriterLease::try_acquire(temp.path()).unwrap());
}

#[test]
fn readers_writer_and_relocation_hold_shared_lifetime_until_last_close() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    let writer = SqliteStore::open_for_write(p(&path)).unwrap();
    let first = SqliteStore::open(p(&path)).unwrap();
    let second = SqliteStore::open(p(&path)).unwrap();
    assert_busy(exclusive(temp.path()));
    drop(writer);
    assert_busy(exclusive(temp.path()));
    drop(first);
    assert_busy(exclusive(temp.path()));
    drop(second);
    drop(exclusive(temp.path()).unwrap());
    let relocation = SqliteStore::open_for_relocation(p(&path)).unwrap();
    assert_busy(exclusive(temp.path()));
    drop(relocation);
    drop(exclusive(temp.path()).unwrap());
}

struct CheckDropOrder {
    root: PathBuf,
    path: PathBuf,
    checked: Rc<Cell<bool>>,
}
impl RepoSlugResolver for CheckDropOrder {
    fn resolve(&self, _: &str) -> Option<String> {
        None
    }
}
impl Drop for CheckDropOrder {
    fn drop(&mut self) {
        // Fields preceding this resolver must already be destroyed, while the
        // final lifetime guard still holds. Inspect real locks and SQLite state.
        assert_busy(exclusive(&self.root));
        drop(WriterLease::try_acquire(&self.root).unwrap());
        let conn = Connection::open(&self.path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        conn.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; ROLLBACK")
            .unwrap();
        self.checked.set(true);
    }
}
#[test]
fn sqlite_and_writer_lease_drop_before_catalog_handle_guard() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    let checked = Rc::new(Cell::new(false));
    let store = SqliteStore::open_for_write(p(&path)).unwrap();
    store.set_repo_slug_resolver(Box::new(CheckDropOrder {
        root: temp.path().to_owned(),
        path,
        checked: checked.clone(),
    }));
    drop(store);
    assert!(checked.get());
    drop(exclusive(temp.path()).unwrap());
}

#[test]
fn exclusive_gate_blocks_opens_before_catalog_or_writer_creation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    drop(SqliteStore::open_for_write(p(&path)).unwrap());
    let gate = exclusive(temp.path()).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_busy(SqliteStore::open(p(&path)));
    assert_busy(SqliteStore::open_for_write(p(&path)));
    assert_busy(SqliteStore::open_for_relocation(p(&path)));
    let absent = temp.path().join("absent.db");
    assert_busy(SqliteStore::open_for_write(p(&absent)));
    assert!(!absent.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(gate);
    drop(SqliteStore::open(p(&path)).unwrap());
}

struct RejectAdmission {
    root: PathBuf,
    called: Cell<bool>,
}
impl CatalogOpenAdmission for RejectAdmission {
    fn recheck(&self, identity: RootIdentity) -> PortResult<CatalogOpenIdentity> {
        assert_eq!(identity, RootIdentity::read(&self.root).unwrap());
        assert_busy(exclusive(&self.root));
        assert!(!self.root.join("catalog.db").exists());
        assert!(!self.root.join("writer.lock").exists());
        self.called.set(true);
        Err(PortError::WriterBusy("catalog maintenance fence".into()))
    }
}
#[test]
fn typed_admission_runs_under_shared_gate_before_sqlite_and_writer_lease() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    let admission = RejectAdmission {
        root: temp.path().to_owned(),
        called: Cell::new(false),
    };
    assert_busy(SqliteStore::open_for_write_guarded(p(&path), &admission));
    assert!(admission.called.get());
    assert!(!path.exists());
    drop(exclusive(temp.path()).unwrap());
}

#[test]
fn missing_read_opens_create_nothing_and_reject_unknown_schema_without_migration() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing").join("catalog.db");
    assert!(SqliteStore::open(p(&missing)).is_err());
    assert!(!missing.parent().unwrap().exists());
    let missing = temp.path().join("catalog.db");
    assert!(SqliteStore::open(p(&missing)).is_err());
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    let conn = Connection::open(&missing).unwrap();
    conn.execute_batch("PRAGMA user_version=999; CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES('keep')").unwrap();
    drop(conn);
    let before = std::fs::read(&missing).unwrap();
    assert!(matches!(
        SqliteStore::open(p(&missing)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(std::fs::read(&missing).unwrap(), before);
    drop(exclusive(temp.path()).unwrap());
}

struct ExpectedManaged;
impl CatalogOpenAdmission for ExpectedManaged {
    fn recheck(&self, _: RootIdentity) -> PortResult<CatalogOpenIdentity> {
        Ok(CatalogOpenIdentity::Managed {
            installation_id: ControlId::parse("installation").unwrap(),
            catalog_incarnation: ControlId::parse("incarnation").unwrap(),
        })
    }
}
#[test]
fn managed_marker_blocks_every_legacy_open_even_with_control_missing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    drop(SqliteStore::open_for_write(p(&path)).unwrap());
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE")
            .unwrap();
        managed::initialize_catalog_in_tx(&conn, "installation", "incarnation", 1).unwrap();
        conn.execute_batch("COMMIT").unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        SqliteStore::open(p(&path)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(matches!(
        SqliteStore::open_for_write(p(&path)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(matches!(
        SqliteStore::open_for_relocation(p(&path)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(matches!(
        SqliteStore::open_guarded(p(&path), &ExpectedManaged),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!temp.path().join("control.db").exists());
    drop(exclusive(temp.path()).unwrap());
}

#[test]
fn subprocess_catalog_holder() {
    use std::io::{BufRead, Write};
    let Some(path) = std::env::var_os("ASG_TEST_CATALOG_HOLDER_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let store = match std::env::var("ASG_TEST_CATALOG_HOLDER_MODE")
        .unwrap()
        .as_str()
    {
        "reader" => SqliteStore::open(p(&path)).unwrap(),
        "writer" => SqliteStore::open_for_write(p(&path)).unwrap(),
        "relocation" => SqliteStore::open_for_relocation(p(&path)).unwrap(),
        _ => panic!("invalid synthetic mode"),
    };
    println!("CATALOG_HOLDER_READY");
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().lock().read_line(&mut input).unwrap();
    assert_eq!(input.trim(), "close");
    drop(store);
}

#[test]
fn separate_process_catalog_handle_blocks_exclusive_until_process_closes_store() {
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    drop(SqliteStore::open_for_write(p(&path)).unwrap());
    for mode in ["reader", "writer", "relocation"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "subprocess_catalog_holder",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASG_TEST_CATALOG_HOLDER_PATH", &path)
            .env("ASG_TEST_CATALOG_HOLDER_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            if output.read_line(&mut line).unwrap() == 0 {
                let failed = child.wait_with_output().unwrap();
                panic!("holder exited before readiness: {:?}", failed.status);
            }
            if line.contains("CATALOG_HOLDER_READY") {
                break;
            }
        }
        assert_busy(exclusive(temp.path()));
        writeln!(child.stdin.take().unwrap(), "close").unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
        drop(exclusive(temp.path()).unwrap());
    }
}
