//! All catalogs/history bytes are synthetic. WAL/inode and guard assertions use
//! actual SQLite/OS handles; injected checkpoints are not power-loss evidence.
use super::*;
use agent_session_grep_adapters_sqlite::{SqliteStore, managed, managed_store::ManagedStore};
use agent_session_grep_domain::{IdKind, MessagePlacement, SessionIdentityNamespace, StableId};
use agent_session_grep_ports::{
    control::RequestIntersection,
    managed::{ProjectionQuery, ProjectionRead},
};
use rusqlite::{Connection, OpenFlags, params};

fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn hash(path: &Path) -> String {
    blake3::hash(&fs::read(path).unwrap()).to_hex().to_string()
}
fn identity(path: &Path) -> (u64, u64) {
    platform::identity(&platform::open_file(path).unwrap()).unwrap()
}
fn options(source: &Path) -> Options {
    Options {
        source: source.into(),
        prefix: None,
    }
}
fn inject(point: Fault) {
    INJECTED.with(|slot| slot.set(Some(point)));
}
fn control_creation_bytes(root: &Path, installation: &str, desired: &str) -> Vec<u8> {
    let root_id = RootIdentity::read(root).unwrap().control_id();
    serde_json::to_vec(&json!({
        "schema": "asg.control-create-intent/v2",
        "root": root_id.as_str(),
        "installation": installation,
        "desired": desired,
    }))
    .unwrap()
}
fn write_control_creation_record(root: &Path, name: &str, bytes: &[u8]) {
    platform::create_private_directory(root).unwrap();
    let mut file = platform::create_file(&root.join(name)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    platform::sync_directory(root).unwrap();
}
fn write_empty_control_create_lock(root: &Path) {
    let file = platform::create_file(&root.join("control-create.lock")).unwrap();
    file.sync_all().unwrap();
    drop(file);
    platform::sync_directory(root).unwrap();
}
fn code(value: Result<Value, CliError>) -> CanonicalCode {
    value.unwrap_err().0.code
}

fn schema19(path: &Path) {
    // Derive the managed additions from the exported schema builder; do not
    // keep another hand-maintained list of v20 tables in this fixture.
    drop(SqliteStore::open_for_write(p(path)).unwrap());
    let conn = Connection::open(path).unwrap();
    let model = Connection::open_in_memory().unwrap();
    model
        .execute_batch("PRAGMA foreign_keys=ON; BEGIN")
        .unwrap();
    managed::create_schema(&model).unwrap();
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

struct Fixture {
    source: PathBuf,
    destination: PathBuf,
    legacy: Connection,
    session: StableId,
    message: StableId,
    // The SQLite connection must close before Windows temp cleanup.
    temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let source_root = temp.path().join("legacy");
        fs::create_dir(&source_root).unwrap();
        let source = source_root.join("catalog.db");
        schema19(&source);
        let legacy = Connection::open(&source).unwrap();
        legacy
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA foreign_keys=ON;",
            )
            .unwrap();
        let history = temp.path().join("synthetic-history.jsonl");
        fs::write(&history, b"synthetic history").unwrap();
        let key = agent_session_grep_application::relocation::normalize_absolute_path(p(&history))
            .unwrap();
        let session = StableId::native_session_scoped(
            &SessionIdentityNamespace {
                provider_id: "claude-code",
                installation_namespace: "legacy-fixture-namespace",
            },
            "synthetic-native-session",
        );
        let message = StableId::native_checked(IdKind::Message, "synthetic-message").unwrap();
        let document = StableId::native_checked(IdKind::Document, "synthetic-document").unwrap();
        let placement = MessagePlacement::new(
            session.clone(),
            document.clone(),
            message.clone(),
            0,
            false,
            None,
        );
        let tx = legacy.unchecked_transaction().unwrap();
        tx.execute("INSERT INTO installation_namespaces VALUES('namespace_one','claude-code','legacy-fixture-namespace','legacy-v1',1)", []).unwrap();
        tx.execute(
            "INSERT INTO installation_locations VALUES('claude-code',?2,?1,'namespace_one','current',NULL)",
            params![
                p(temp.path()),
                agent_session_grep_application::relocation::normalize_absolute_path(p(temp.path()))
                    .unwrap()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO source_installations VALUES(?1,?2,'namespace_one')",
            params![p(&history), key],
        )
        .unwrap();
        tx.execute("INSERT INTO source_scans(source_path,scanned_at_ms,len_bytes,fingerprint,provider_id,parser_version) VALUES(?1,1,17,'legacy-fingerprint','claude-code',3)", [p(&history)]).unwrap();
        for (entity, payload) in [
            (
                &message,
                json!({"role":"user","text":"merged withdrawn synthetic phrase","timestamp":null}),
            ),
            (&session, json!({"documents":[document.as_str()]})),
            (
                &document,
                json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":"legacy-fingerprint","len":17}),
            ),
        ] {
            tx.execute(
                "INSERT INTO catalog(id,payload) VALUES(?1,?2)",
                params![entity.as_str(), serde_json::to_vec(&payload).unwrap()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO fts_ids(wire_id,id_json) VALUES(?1,?2)",
                params![entity.as_str(), serde_json::to_string(entity).unwrap()],
            )
            .unwrap();
        }
        tx.execute(
            "INSERT INTO fts(id,text) VALUES(?1,'merged withdrawn synthetic phrase')",
            [message.as_str()],
        )
        .unwrap();
        tx.execute(
            "UPDATE fts_ids SET fts_rowid=?1 WHERE wire_id=?2",
            params![tx.last_insert_rowid(), message.as_str()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO source_membership(source_path,message_id,document_id) VALUES(?1,?2,?3)",
            params![p(&history), message.as_str(), document.as_str()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO message_placements VALUES(?1,?2,?3,?4,0,0,NULL,NULL)",
            params![
                placement.id.as_str(),
                session.as_str(),
                document.as_str(),
                message.as_str()
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO source_placement_membership VALUES(?1,?2)",
            params![p(&history), placement.id.as_str()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO source_relation_scans VALUES(?1,7)",
            [p(&history)],
        )
        .unwrap();
        tx.execute("UPDATE store_metadata SET active_generation=7", [])
            .unwrap();
        tx.commit().unwrap();
        let destination = temp.path().join("managed/catalog.db");
        Self {
            temp,
            source,
            destination,
            legacy,
            session,
            message,
        }
    }
    fn run(&self) -> Result<Value, CliError> {
        execute(p(&self.destination), options(&self.source), end())
    }
    fn root(&self) -> &Path {
        self.destination.parent().unwrap()
    }
    fn intent(&self) -> Intent {
        read_intent(&self.root().join(INTENT)).unwrap()
    }
    fn control(&self) -> SqliteControlStore {
        let deadline = end();
        let installation = {
            let current =
                SqliteControlStore::open_current_read_only_with_deadline(self.root(), deadline)
                    .unwrap();
            let installation = current.status().unwrap().policy.installation_id;
            drop(current);
            installation
        };
        SqliteControlStore::open_existing_writable_with_deadline(
            self.root(),
            &installation,
            deadline,
        )
        .unwrap()
    }
}

#[test]
fn explicit_arguments_reject_ambiguous_or_duplicate_paths_before_effects() {
    for args in [
        vec!["migrate"],
        vec!["migrate", "legacy.db"],
        vec!["migrate", "--from"],
        vec!["migrate", "--from", "one", "--from", "two"],
        vec!["migrate", "--from", "one", "--force"],
        vec![
            "migrate",
            "--from",
            "one",
            "--install-prefix",
            "p",
            "--install-prefix",
            "q",
        ],
    ] {
        let args: Vec<_> = args.into_iter().map(str::to_owned).collect();
        assert_eq!(
            parse(&args).err().unwrap().0.code,
            CanonicalCode::InvalidRequest
        );
    }
    let parsed = parse(&[
        "migrate".into(),
        "--install-prefix".into(),
        "prefix".into(),
        "--from".into(),
        "legacy.db".into(),
    ])
    .unwrap();
    assert_eq!(parsed.source, PathBuf::from("legacy.db"));
    assert!(is_command(&["migrate".into()]));
    assert!(!is_command(&["migration".into()]));
    assert!(HELP.contains("--from <legacy-catalog>"));
}

#[test]
fn active_wal_and_idle_legacy_reader_survive_with_unchanged_bytes_and_identity() {
    let fixture = Fixture::new();
    let wal = suffix(&fixture.source, "-wal");
    assert!(fs::metadata(&wal).unwrap().len() > 32);
    let before = (
        hash(&fixture.source),
        hash(&wal),
        identity(&fixture.source),
        identity(&wal),
    );
    let reader =
        Connection::open_with_flags(&fixture.source, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let prior: i64 = reader
        .query_row("SELECT COUNT(*) FROM catalog", [], |row| row.get(0))
        .unwrap();
    let data = fixture.run().unwrap();
    assert_eq!(data["phase"], "managed_activated");
    assert_eq!(data["desired_updates"], "paused");
    assert_eq!(data["selected_scopes"], 0);
    assert_eq!(data["canonical_entities"], 3);
    assert_eq!(
        before,
        (
            hash(&fixture.source),
            hash(&wal),
            identity(&fixture.source),
            identity(&wal)
        )
    );
    assert_eq!(
        reader
            .query_row("SELECT COUNT(*) FROM catalog", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        prior
    );
    reader.execute_batch("COMMIT").unwrap();
    assert_eq!(
        fixture
            .legacy
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        19
    );
    let destination = Connection::open(&fixture.destination).unwrap();
    let namespace: String = destination
        .query_row(
            "SELECT namespace_input FROM installation_namespaces WHERE namespace_id='namespace_one'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(namespace, "legacy-fixture-namespace");
    assert!(
        destination
            .query_row(
                "SELECT 1 FROM catalog WHERE id=?1",
                [fixture.session.as_str()],
                |row| row.get::<_, i64>(0)
            )
            .is_ok()
    );
    assert_eq!(
        destination
            .query_row("SELECT COUNT(*) FROM source_bindings", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        destination
            .query_row("SELECT COUNT(*) FROM source_revision_receipts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    drop(destination);
    let control = fixture.control();
    let store = ManagedStore::open(&fixture.destination, &control).unwrap();
    store
        .with_read(&control, RequestIntersection::Selected, end(), |view| {
            assert!(
                view.messages(
                    std::slice::from_ref(&fixture.message),
                    &ProjectionQuery::default()
                )?[0]
                    .is_none()
            );
            assert!(
                view.query_lexical("withdrawn", &ProjectionQuery::default(), 8)?
                    .hits
                    .is_empty()
            );
            Ok(())
        })
        .unwrap();
    drop(store);
    assert!(SqliteStore::open_for_write(p(&fixture.destination)).is_err());
}

#[test]
fn flushed_and_published_intents_recover_same_operation_and_incarnation() {
    for point in [
        Fault::IntentFlushed,
        Fault::IntentPublished,
        Fault::ControlCreated,
        Fault::Activated,
    ] {
        let fixture = Fixture::new();
        inject(point);
        assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
        let stored = if exists(&fixture.root().join(INTENT)).unwrap() {
            fixture.intent()
        } else {
            read_intent(&fixture.root().join(PENDING)).unwrap()
        };
        let recovered = fixture.run().unwrap();
        assert_eq!(recovered["recovered"], true);
        let confirmed = fixture.intent();
        assert_eq!(confirmed.operation, stored.operation);
        assert_eq!(confirmed.incarnation, stored.incarnation);
        assert_eq!(confirmed.installation, stored.installation);
        let before = (
            identity(&fixture.destination),
            hash(&fixture.root().join(INTENT)),
        );
        assert_eq!(fixture.run().unwrap()["recovered"], true);
        assert_eq!(
            before,
            (
                identity(&fixture.destination),
                hash(&fixture.root().join(INTENT))
            )
        );
    }
}

#[test]
fn alias_root_and_occupied_receiving_root_are_refused_before_effects() {
    let fixture = Fixture::new();
    let alias = fixture.source.parent().unwrap().join("other.db");
    assert_eq!(
        code(execute(p(&alias), options(&fixture.source), end())),
        CanonicalCode::InvalidRequest
    );
    assert!(!alias.exists());
    assert!(!fixture.source.parent().unwrap().join(INTENT).exists());
    platform::create_private_directory(fixture.root()).unwrap();
    let unrelated = fixture.root().join("keep");
    fs::write(&unrelated, b"unrelated").unwrap();
    assert_eq!(code(fixture.run()), CanonicalCode::InvalidRequest);
    assert_eq!(fs::read(unrelated).unwrap(), b"unrelated");
    assert!(!fixture.root().join(INTENT).exists());
    assert!(!fixture.root().join("control.db").exists());
}

#[test]
fn invalid_prefix_and_unsupported_legacy_create_no_receiving_state() {
    let fixture = Fixture::new();
    let prefix = fixture.temp.path().join("unverified-prefix");
    fs::create_dir(&prefix).unwrap();
    assert_eq!(
        code(execute(
            p(&fixture.destination),
            Options {
                source: fixture.source.clone(),
                prefix: Some(prefix)
            },
            end()
        )),
        CanonicalCode::SchemaIncompatible
    );
    assert!(!fixture.root().exists());
    fixture
        .legacy
        .execute_batch("PRAGMA user_version=21")
        .unwrap();
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().exists());
}

#[test]
fn missing_control_after_activation_is_not_recreated_or_legacy_served() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let before = (hash(&fixture.destination), identity(&fixture.destination));
    fs::remove_file(fixture.root().join("control.db")).unwrap();
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().join("control.db").exists());
    assert_eq!(
        before,
        (hash(&fixture.destination), identity(&fixture.destination))
    );
    assert!(SqliteStore::open_for_write(p(&fixture.destination)).is_err());
    assert_eq!(
        fixture
            .legacy
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        19
    );
}

#[test]
fn empty_control_or_corrupt_pending_intent_remains_diagnosable_without_reset() {
    let fixture = Fixture::new();
    inject(Fault::IntentPublished);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let control_path = fixture.root().join("control.db");
    drop(platform::create_file(&control_path).unwrap());
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert_eq!(fs::metadata(&control_path).unwrap().len(), 0);
    assert!(!fixture.destination.exists());
    let other = Fixture::new();
    inject(Fault::IntentFlushed);
    assert_eq!(code(other.run()), CanonicalCode::SourceIo);
    fs::write(other.root().join(PENDING), b"{}").unwrap();
    assert_eq!(code(other.run()), CanonicalCode::SchemaIncompatible);
    assert!(!other.root().join(INTENT).exists());
    assert!(!other.root().join("control.db").exists());
}

#[test]
fn immutable_intent_rejects_root_replacement_and_source_mutation_without_recopy() {
    let fixture = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let moved = fixture.temp.path().join("moved-root");
    fs::rename(fixture.root(), &moved).unwrap();
    platform::create_private_directory(fixture.root()).unwrap();
    fs::copy(moved.join(INTENT), fixture.root().join(INTENT)).unwrap();
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().join("control.db").exists());
    let other = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(other.run()), CanonicalCode::SourceIo);
    other
        .legacy
        .execute("UPDATE store_metadata SET active_generation=8", [])
        .unwrap();
    assert_eq!(code(other.run()), CanonicalCode::SourceChanged);
    assert!(other.root().join(INTENT).exists());
}

#[test]
fn actual_command_and_catalog_guards_refuse_live_conflicts_then_release() {
    let fixture = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let key = LockKind::MaintenanceJob(JobLockKey::parse("legacy-migration").unwrap());
    let guard =
        crate::retry_fixture_busy(|| ExclusiveGuard::try_acquire(fixture.root(), key.clone()));
    assert_eq!(
        code(execute(
            p(&fixture.destination),
            options(&fixture.source),
            Instant::now() + Duration::from_millis(60)
        )),
        CanonicalCode::WriterBusy
    );
    assert!(!fixture.destination.exists());
    drop(guard);
    let reader = crate::retry_fixture_busy(|| {
        agent_session_grep_adapters_sqlite::managed_locks::SharedGuard::try_acquire(
            fixture.root(),
            LockKind::CatalogHandles,
        )
    });
    assert_eq!(
        code(execute(
            p(&fixture.destination),
            options(&fixture.source),
            Instant::now() + Duration::from_millis(60)
        )),
        CanonicalCode::WriterBusy
    );
    assert!(!fixture.destination.exists());
    drop(reader);
    fixture.run().unwrap();
    drop(crate::retry_fixture_busy(|| {
        ExclusiveGuard::try_acquire(fixture.root(), LockKind::CatalogHandles)
    }));
    drop(WriterLease::try_acquire(fixture.source.parent().unwrap()).unwrap());
}

#[test]
fn retry_preserves_pause_and_never_publishes_new_legacy_bytes() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let control = fixture.control();
    control
        .with_runtime_deadline(end(), || {
            let status = control.status()?;
            control.set_desired_updates(status.policy.control_seq, DesiredUpdates::Stopped)
        })
        .unwrap();
    fixture
        .legacy
        .execute("UPDATE store_metadata SET active_generation=8", [])
        .unwrap();
    let result = fixture.run().unwrap();
    assert_eq!(result["desired_updates"], "stopped");
    assert_eq!(result["generation"], 7);
    assert_eq!(
        control
            .with_runtime_deadline(end(), || control.status())
            .unwrap()
            .desired_updates,
        DesiredUpdates::Stopped
    );
    assert_eq!(
        Connection::open(&fixture.destination)
            .unwrap()
            .query_row("SELECT active_generation FROM store_metadata", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        7
    );
}

#[test]
fn frames_and_errors_are_content_free_in_all_output_modes() {
    let fixture = Fixture::new();
    let data = fixture.run().unwrap();
    let frame = protocol::success_envelope(
        "migrate",
        Outcome::Partial,
        data.clone(),
        0,
        &protocol::Page::default(),
        &[],
        Some("migration-test"),
        RetrievalMode::Lexical,
        &Default::default(),
    );
    for content in [
        frame,
        crate::human::render_success(
            "migrate",
            Outcome::Partial,
            &data,
            &protocol::Page::default(),
        )
        .join("\n"),
    ] {
        assert!(!content.contains(p(&fixture.source)));
        assert!(!content.contains(p(fixture.temp.path())));
        assert!(!content.contains("legacy-fixture-namespace"));
        assert!(!content.contains("withdrawn synthetic phrase"));
        assert!(content.len() < 8192);
    }
    for category in [
        CanonicalCode::SourceIo,
        CanonicalCode::SchemaIncompatible,
        CanonicalCode::SourceChanged,
        CanonicalCode::WriterBusy,
    ] {
        let message = error(category).0.message;
        assert!(!message.contains(p(&fixture.source)));
        assert!(message.len() < 512);
    }
}

#[cfg(windows)]
#[test]
fn windows_case_alias_cannot_select_the_legacy_root_as_receiving_root() {
    let fixture = Fixture::new();
    let alias = fixture
        .source
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_uppercase();
    let target = Path::new(&alias).join("new.db");
    assert_eq!(
        code(execute(p(&target), options(&fixture.source), end())),
        CanonicalCode::InvalidRequest
    );
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn linked_receiving_root_is_rejected_before_intent_or_catalog_creation() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let alias = fixture.temp.path().join("alias");
    symlink(fixture.source.parent().unwrap(), &alias).unwrap();
    assert_eq!(
        code(execute(
            p(&alias.join("new.db")),
            options(&fixture.source),
            end()
        )),
        CanonicalCode::InvalidRequest
    );
    assert!(!fixture.source.parent().unwrap().join(INTENT).exists());
}

#[test]
fn lost_control_before_catalog_marker_never_recreates_or_loses_policy() {
    let fixture = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    assert!(!fixture.destination.exists());
    assert!(!suffix(&fixture.destination, ".asg-managed-create").exists());
    let intent = fixture.intent();
    let before = hash(&fixture.root().join(CONTROL_STARTED));
    fs::remove_file(fixture.root().join("control.db")).unwrap();
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().join("control.db").exists());
    assert_eq!(hash(&fixture.root().join(CONTROL_STARTED)), before);
    assert_eq!(fixture.intent().installation, intent.installation);
    assert_eq!(fixture.intent().incarnation, intent.incarnation);
}

#[test]
fn control_precreation_interruption_is_diagnosed_without_assuming_no_prior_policy() {
    let fixture = Fixture::new();
    inject(Fault::ControlIntent);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    assert!(fixture.root().join(CONTROL_STARTED).exists());
    assert!(!fixture.root().join("control.db").exists());
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().join("control.db").exists());
    assert!(!fixture.destination.exists());
}

#[test]
fn migration_recovers_only_matching_unpublished_paused_control_creation() {
    let fixture = Fixture::new();
    inject(Fault::ControlIntent);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let start: ControlStart = read_private(&fixture.root().join(CONTROL_STARTED)).unwrap();
    let installation = ControlId::parse(&start.installation).unwrap();
    write_empty_control_create_lock(fixture.root());
    let bytes = control_creation_bytes(fixture.root(), installation.as_str(), "paused");
    write_control_creation_record(fixture.root(), CONTROL_CREATE_INTENT, &bytes);

    let result = fixture.run().unwrap();
    assert_eq!(result["phase"], "managed_activated");
    assert_eq!(result["recovered"], true);
    assert_eq!(result["desired_updates"], "paused");
    assert!(fixture.destination.exists());
    let control = SqliteControlStore::open_read_only(fixture.root(), &installation).unwrap();
    let status = control.status().unwrap();
    assert_eq!(status.policy.installation_id, installation);
    assert_eq!(status.desired_updates, DesiredUpdates::Paused);
    assert!(!fixture.root().join(CONTROL_CREATE_INTENT).exists());
    assert!(!fixture.root().join(CONTROL_CREATE_PUBLISH).exists());
    assert!(!fixture.root().join(CONTROL_CREATE_PENDING).exists());
}

#[test]
fn migration_recovers_unpublished_stopped_identity_without_resetting_desired() {
    let fixture = Fixture::new();
    inject(Fault::ControlIntent);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let start: ControlStart = read_private(&fixture.root().join(CONTROL_STARTED)).unwrap();
    write_empty_control_create_lock(fixture.root());
    let bytes = control_creation_bytes(fixture.root(), &start.installation, "stopped");
    write_control_creation_record(fixture.root(), CONTROL_CREATE_INTENT, &bytes);

    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().join("control.db").exists());
    assert!(!fixture.destination.exists());
    assert_eq!(
        fs::read(fixture.root().join(CONTROL_CREATE_INTENT)).unwrap(),
        bytes
    );
}

#[test]
fn migration_refuses_mismatched_creation_intent_without_mutating_it() {
    for (installation_suffix, desired) in [("_other", "paused"), ("", "running")] {
        let fixture = Fixture::new();
        inject(Fault::ControlIntent);
        assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
        let start: ControlStart = read_private(&fixture.root().join(CONTROL_STARTED)).unwrap();
        let installation = if installation_suffix.is_empty() {
            start.installation.clone()
        } else {
            format!("{}{}", start.installation, installation_suffix)
        };
        write_empty_control_create_lock(fixture.root());
        let bytes = control_creation_bytes(fixture.root(), &installation, desired);
        write_control_creation_record(fixture.root(), CONTROL_CREATE_INTENT, &bytes);
        let started_before = fs::read(fixture.root().join(CONTROL_STARTED)).unwrap();
        let source_before = hash(&fixture.source);

        assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
        assert!(!fixture.destination.exists());
        assert!(!fixture.root().join("control.db").exists());
        assert!(!fixture.root().join(CONTROL_CREATE_PENDING).exists());
        assert_eq!(
            fs::read(fixture.root().join(CONTROL_CREATE_INTENT)).unwrap(),
            bytes
        );
        assert_eq!(
            fs::read(fixture.root().join(CONTROL_STARTED)).unwrap(),
            started_before
        );
        assert_eq!(hash(&fixture.source), source_before);
    }
}

#[test]
fn migration_refuses_published_creation_marker_without_final_control() {
    let fixture = Fixture::new();
    inject(Fault::ControlIntent);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let start: ControlStart = read_private(&fixture.root().join(CONTROL_STARTED)).unwrap();
    write_empty_control_create_lock(fixture.root());
    let bytes = control_creation_bytes(fixture.root(), &start.installation, "paused");
    write_control_creation_record(fixture.root(), CONTROL_CREATE_INTENT, &bytes);
    // The marker is the exact original v2 intent wire image.
    write_control_creation_record(fixture.root(), CONTROL_CREATE_PUBLISH, &bytes);
    let before = (
        fs::read(fixture.root().join(CONTROL_CREATE_INTENT)).unwrap(),
        fs::read(fixture.root().join(CONTROL_CREATE_PUBLISH)).unwrap(),
        fs::read(fixture.root().join(CONTROL_STARTED)).unwrap(),
    );

    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.destination.exists());
    assert!(!fixture.root().join("control.db").exists());
    assert_eq!(
        fs::read(fixture.root().join(CONTROL_CREATE_INTENT)).unwrap(),
        before.0
    );
    assert_eq!(
        fs::read(fixture.root().join(CONTROL_CREATE_PUBLISH)).unwrap(),
        before.1
    );
    assert_eq!(
        fs::read(fixture.root().join(CONTROL_STARTED)).unwrap(),
        before.2
    );
}

#[test]
fn migration_rebuilds_exact_intent_when_publish_marker_and_stage_both_remain() {
    let fixture = Fixture::new();
    inject(Fault::ControlIntent);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let start: ControlStart = read_private(&fixture.root().join(CONTROL_STARTED)).unwrap();
    write_empty_control_create_lock(fixture.root());
    let bytes = control_creation_bytes(fixture.root(), &start.installation, "paused");
    write_control_creation_record(fixture.root(), CONTROL_CREATE_INTENT, &bytes);
    write_control_creation_record(fixture.root(), CONTROL_CREATE_PUBLISH, &bytes);
    write_control_creation_record(fixture.root(), CONTROL_CREATE_PENDING, b"partial stage");

    let result = fixture.run().unwrap();
    assert_eq!(result["phase"], "managed_activated");
    assert_eq!(result["desired_updates"], "paused");
    assert!(fixture.destination.exists());
    let installation = ControlId::parse(&start.installation).unwrap();
    let control = SqliteControlStore::open_read_only(fixture.root(), &installation).unwrap();
    assert_eq!(
        control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert!(!fixture.root().join(CONTROL_CREATE_INTENT).exists());
    assert!(!fixture.root().join(CONTROL_CREATE_PUBLISH).exists());
    assert!(!fixture.root().join(CONTROL_CREATE_PENDING).exists());
}

#[test]
fn creation_intent_without_control_start_is_not_adopted() {
    let fixture = Fixture::new();
    inject(Fault::IntentPublished);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    assert!(!fixture.root().join(CONTROL_STARTED).exists());
    let intent = fixture.intent();
    write_empty_control_create_lock(fixture.root());
    let bytes = control_creation_bytes(fixture.root(), &intent.installation, "paused");
    write_control_creation_record(fixture.root(), CONTROL_CREATE_INTENT, &bytes);

    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert!(!fixture.root().join(CONTROL_STARTED).exists());
    assert!(!fixture.root().join("control.db").exists());
    assert!(!fixture.destination.exists());
    assert_eq!(
        fs::read(fixture.root().join(CONTROL_CREATE_INTENT)).unwrap(),
        bytes
    );
}

#[test]
fn corrupt_or_missing_control_start_binding_cannot_adopt_existing_policy() {
    let fixture = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(fixture.run()), CanonicalCode::SourceIo);
    let control_hash = hash(&fixture.root().join("control.db"));
    fs::remove_file(fixture.root().join(CONTROL_STARTED)).unwrap();
    assert_eq!(code(fixture.run()), CanonicalCode::SchemaIncompatible);
    assert_eq!(hash(&fixture.root().join("control.db")), control_hash);
    let other = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(other.run()), CanonicalCode::SourceIo);
    fs::write(other.root().join(CONTROL_STARTED), b"{}").unwrap();
    assert_eq!(code(other.run()), CanonicalCode::SchemaIncompatible);
    assert!(!other.destination.exists());
}

fn inspect_artifacts(f: &Fixture) -> Result<Vec<ClassifiedPrivateArtifact>, CliError> {
    let control = f.control();
    let deadline = end();
    inspect_private_artifacts(
        &f.destination,
        &control,
        RootIdentity::read(f.root()).unwrap(),
        control
            .with_runtime_deadline(deadline, || control.status())
            .unwrap()
            .policy
            .policy_epoch,
        deadline,
    )
}
fn tree_names(root: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn migration_inspector_is_read_only_bounded_and_returns_only_exact_binding_records() {
    let f = Fixture::new();
    f.run().unwrap();
    let before = (
        hash(&f.source),
        hash(&suffix(&f.source, "-wal")),
        identity(&f.source),
        hash(&f.destination),
        identity(&f.destination),
        tree_names(f.root()),
        hash(&f.root().join(INTENT)),
        hash(&f.root().join(CONTROL_STARTED)),
    );
    assert_eq!(inspect_artifacts(&f).unwrap().len(), 4);
    assert_eq!(inspect_artifacts(&f).unwrap().len(), 4);
    assert_eq!(
        before,
        (
            hash(&f.source),
            hash(&suffix(&f.source, "-wal")),
            identity(&f.source),
            hash(&f.destination),
            identity(&f.destination),
            tree_names(f.root()),
            hash(&f.root().join(INTENT)),
            hash(&f.root().join(CONTROL_STARTED))
        )
    );
    let control = f.control();
    let deadline = end();
    let epoch = control
        .with_runtime_deadline(deadline, || control.status())
        .unwrap()
        .policy
        .policy_epoch;
    let artifacts = inspect_artifacts(&f).unwrap();
    control
        .with_runtime_deadline(deadline, || {
            PrivateArtifactInventory::bind(
                &control,
                RootIdentity::read(f.root()).unwrap(),
                epoch,
                artifacts,
            )
        })
        .unwrap();
    let status = control
        .with_runtime_deadline(deadline, || control.status())
        .unwrap();
    assert_eq!(status.desired_updates, DesiredUpdates::Paused);
    assert!(status.policy.selections.is_empty());
}

#[test]
fn migration_inspector_does_not_adopt_arbitrary_files_or_unknown_marker_fields() {
    let f = Fixture::new();
    f.run().unwrap();
    fs::write(f.root().join("unknown.json"), b"unclassified private bytes").unwrap();
    // The returned list contains only known files; unknown siblings still block
    // adapter root accounting and cannot be hidden behind this inspection.
    assert_eq!(inspect_artifacts(&f).unwrap().len(), 4);
    let marker = suffix(&f.destination, ".asg-managed-create");
    let mut value: Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    value["unknown"] = json!("unclassified private bytes");
    fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(inspect_artifacts(&f).is_err());
    assert!(f.root().join("unknown.json").exists());
    assert_eq!(
        f.legacy
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        19
    );
}

#[test]
fn migration_inspector_refuses_source_rewrite_receiver_replacement_and_missing_control() {
    let f = Fixture::new();
    f.run().unwrap();
    f.legacy
        .execute("UPDATE store_metadata SET active_generation=8", [])
        .unwrap();
    assert_eq!(
        inspect_artifacts(&f).unwrap_err().0.code,
        CanonicalCode::SourceChanged
    );
    let other = Fixture::new();
    other.run().unwrap();
    let replaced = other.root().join("replacement.db");
    fs::copy(&other.destination, &replaced).unwrap();
    fs::remove_file(&other.destination).unwrap();
    fs::rename(replaced, &other.destination).unwrap();
    assert!(inspect_artifacts(&other).is_err());
    let missing = Fixture::new();
    missing.run().unwrap();
    let control = missing.control();
    // Actual Windows deny-delete sharing is part of control lifetime protection.
    #[cfg(windows)]
    assert!(fs::remove_file(missing.root().join("control.db")).is_err());
    drop(control);
    fs::remove_file(missing.root().join("control.db")).unwrap();
    assert!(SqliteControlStore::open_current_read_only(missing.root()).is_err());
    assert!(missing.run().is_err());
    assert!(!missing.root().join("control.db").exists());
}

#[test]
fn migration_inspector_root_epoch_and_partial_state_are_fail_closed_without_redo() {
    let f = Fixture::new();
    f.run().unwrap();
    let control = f.control();
    let epoch = control.status().unwrap().policy.policy_epoch;
    let wrong = agent_session_grep_testkit::tempdir().unwrap();
    assert!(
        inspect_private_artifacts(
            &f.destination,
            &control,
            RootIdentity::read(wrong.path()).unwrap(),
            epoch,
            end()
        )
        .is_err()
    );
    assert!(
        inspect_private_artifacts(
            &f.destination,
            &control,
            RootIdentity::read(f.root()).unwrap(),
            PolicyEpoch::new(epoch.get() + 1).unwrap(),
            end()
        )
        .is_err()
    );
    assert_eq!(
        inspect_private_artifacts(
            &f.destination,
            &control,
            RootIdentity::read(f.root()).unwrap(),
            epoch,
            Instant::now()
        )
        .unwrap_err()
        .0
        .code,
        CanonicalCode::WriterBusy
    );
    let partial = Fixture::new();
    inject(Fault::ControlCreated);
    assert_eq!(code(partial.run()), CanonicalCode::SourceIo);
    assert!(inspect_artifacts(&partial).is_err());
    assert!(!partial.destination.exists());
    assert!(!suffix(&partial.destination, ".asg-managed-create").exists());
}

#[test]
fn ordinary_managed_catalog_without_migration_intent_has_no_adopted_inventory() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("managed");
    let control = crate::retry_fixture_busy(|| {
        SqliteControlStore::create(
            &root,
            &ControlId::parse("ordinary-install").unwrap(),
            DesiredUpdates::Paused,
        )
    });
    let catalog = root.join("catalog.db");
    drop(
        ManagedStore::create(
            &catalog,
            &control,
            ControlId::parse("ordinary-incarnation").unwrap(),
            1,
        )
        .unwrap(),
    );
    assert!(
        inspect_private_artifacts(
            &catalog,
            &control,
            RootIdentity::read(&root).unwrap(),
            control.status().unwrap().policy.policy_epoch,
            end()
        )
        .unwrap()
        .is_empty()
    );
    fs::write(root.join("legacy-migration-command.pending"), b"{}").unwrap();
    assert!(
        inspect_private_artifacts(
            &catalog,
            &control,
            RootIdentity::read(&root).unwrap(),
            control.status().unwrap().policy.policy_epoch,
            end()
        )
        .is_err()
    );
}
