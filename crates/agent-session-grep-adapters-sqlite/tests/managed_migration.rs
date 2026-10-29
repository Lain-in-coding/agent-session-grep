//! Synthetic schema-19 legacy catalogs; actual WAL and receiving OS locks.
use agent_session_grep_adapters_sqlite::{
    SourceBatch, SqliteControlStore, SqliteStore, managed,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_migration::{LegacyInspection, LegacyMigrationRequest, inspect_legacy, migrate_legacy},
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, SessionIdentityNamespace, StableId};
use agent_session_grep_ports::{
    PortError, SearchProvider, SourceResumeClaim,
    control::*,
    managed::{
        ObservationState, ProjectionQuery, ProjectionRead, RevisionId, SelectionProof,
        SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::{Connection, params};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn key_path(path: &Path) -> String {
    agent_session_grep_application::relocation::normalize_absolute_path(p(path)).unwrap()
}
fn hash(path: &Path) -> String {
    blake3::hash(&fs::read(path).unwrap()).to_hex().to_string()
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}
fn downgrade_empty(path: &Path) {
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
    _temp: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
    history: PathBuf,
    control: SqliteControlStore,
    legacy: Connection,
    session: StableId,
    message: StableId,
    document: StableId,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let legacy_root = temp.path().join("legacy");
        fs::create_dir(&legacy_root).unwrap();
        let history = temp.path().join("history.jsonl");
        fs::write(&history, b"synthetic history").unwrap();
        let source = legacy_root.join("legacy.db");
        downgrade_empty(&source);
        let legacy = Connection::open(&source).unwrap();
        legacy
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA foreign_keys=ON;",
            )
            .unwrap();
        let session = StableId::native_session_scoped(
            &SessionIdentityNamespace {
                provider_id: "claude-code",
                installation_namespace: "frozen-legacy-seed",
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
        tx.execute("INSERT INTO installation_namespaces VALUES('namespace_one','claude-code','frozen-legacy-seed','legacy-v1',1)",[]).unwrap();
        tx.execute(
            "INSERT INTO installation_locations VALUES(?1,?2,?3,'namespace_one','current',NULL)",
            params!["claude-code", key_path(temp.path()), p(temp.path())],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO source_installations VALUES(?1,?2,'namespace_one')",
            params![p(&history), key_path(&history)],
        )
        .unwrap();
        tx.execute("INSERT INTO source_scans(source_path,scanned_at_ms,len_bytes,fingerprint,provider_id,parser_version) VALUES(?1,1,17,'legacy-fingerprint','claude-code',3)",[p(&history)]).unwrap();
        for (entity, payload) in [
            (
                &message,
                serde_json::json!({"role":"user","text":"public fragment merged withdrawn phrase","timestamp":null}),
            ),
            (
                &session,
                serde_json::json!({"documents":[document.as_str()]}),
            ),
            (
                &document,
                serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":"legacy-fingerprint","len":17}),
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
            "INSERT INTO fts(id,text) VALUES(?1,'public fragment merged withdrawn phrase')",
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
        tx.execute("INSERT INTO source_session_resume_claims VALUES(?1,?2,'claude-code','synthetic-native-session','resolved',NULL,'missing',0)",params![p(&history),session.as_str()]).unwrap();
        tx.execute("UPDATE store_metadata SET active_generation=7", [])
            .unwrap();
        tx.commit().unwrap();
        let control = SqliteControlStore::create(
            &temp.path().join("managed"),
            &id("explicit-installation"),
            DesiredUpdates::Paused,
        )
        .unwrap();
        let destination = temp.path().join("managed/catalog.db");
        Self {
            _temp: temp,
            source,
            destination,
            history,
            control,
            legacy,
            session,
            message,
            document,
        }
    }
    fn migrate(
        &self,
        inspected: &LegacyInspection,
        deadline: Instant,
    ) -> Result<agent_session_grep_adapters_sqlite::managed_migration::MigrationReceipt, PortError>
    {
        migrate_legacy(
            LegacyMigrationRequest {
                source: &self.source,
                destination: &self.destination,
                inspected,
                installation: &id("explicit-installation"),
                incarnation: &id("managed-incarnation"),
                operation: &id("migration-one"),
                now_ms: 2,
                deadline,
            },
            &self.control,
        )
    }
    fn scalar(&self, sql: &str) -> i64 {
        Connection::open(&self.destination)
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }
}
#[test]
fn logical_wal_copy_keeps_source_inode_db_wal_bytes_and_canonical_namespaces() {
    let f = Fixture::new();
    let db_before = hash(&f.source);
    let wal = sibling(&f.source, "-wal");
    let wal_before = hash(&wal);
    let source_before = inspect_legacy(&f.source, end()).unwrap();
    assert_eq!(source_before.generation(), 7);
    assert_eq!(source_before.canonical_entities(), 3);
    assert_eq!(source_before.namespace_count(), 1);
    let receipt = f.migrate(&source_before, end()).unwrap();
    assert_eq!(receipt.generation, 7);
    assert_eq!(receipt.namespace_digest, source_before.namespace_digest());
    assert_eq!(hash(&f.source), db_before);
    assert_eq!(hash(&wal), wal_before);
    assert_eq!(inspect_legacy(&f.source, end()).unwrap(), source_before);
    assert_eq!(
        f.legacy
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        19
    );
    assert_eq!(
        f.scalar("PRAGMA user_version"),
        agent_session_grep_adapters_sqlite::SCHEMA_VERSION
    );
    let conn = Connection::open(&f.destination).unwrap();
    let copied: String=conn.query_row("SELECT namespace_input FROM installation_namespaces WHERE namespace_id='namespace_one'",[],|row|row.get(0)).unwrap();
    assert_eq!(copied, "frozen-legacy-seed");
    let canonical: String = conn
        .query_row(
            "SELECT id_json FROM fts_ids WHERE wire_id=?1",
            [f.session.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<StableId>(&canonical).unwrap(),
        f.session
    );
    for table in [
        "source_bindings",
        "source_projections",
        "source_occurrences",
        "source_revision_receipts",
        "source_entity_projections",
    ] {
        assert_eq!(f.scalar(&format!("SELECT count(*) FROM {table}")), 0);
    }
    assert!(matches!(
        SqliteStore::open(p(&f.destination)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
}
#[test]
fn copied_merged_text_is_hidden_until_selected_reimport_uses_same_namespace() {
    let f = Fixture::new();
    let inspected = inspect_legacy(&f.source, end()).unwrap();
    f.migrate(&inspected, end()).unwrap();
    let store = ManagedStore::open(&f.destination, &f.control).unwrap();
    store
        .with_read(&f.control, RequestIntersection::Selected, end(), |read| {
            assert!(
                read.query_lexical("withdrawn", &ProjectionQuery::default(), 5)?
                    .hits
                    .is_empty()
            );
            assert!(
                read.messages(
                    std::slice::from_ref(&f.message),
                    &ProjectionQuery::default()
                )?[0]
                    .is_none()
            );
            Ok(())
        })
        .unwrap();
    drop(store);
    let selected = f
        .control
        .add_selection(
            f.control.status().unwrap().policy.control_seq,
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: CanonicalLocator::from_path(&f.history).unwrap(),
                    kind: RootKind::Exact,
                },
                root_identity: Some(id("source-root")),
                now_ms: 3,
            },
        )
        .unwrap()
        .value;
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Running,
        )
        .unwrap();
    let worker_lock =
        ExclusiveGuard::try_acquire(f.destination.parent().unwrap(), LockKind::Background).unwrap();
    let worker = f.control.bind_worker(&worker_lock, id("boot-one")).unwrap();
    f.control
        .register_worker(
            f.control.status().unwrap().policy.control_seq,
            &worker,
            4,
            1,
        )
        .unwrap();
    let store = ManagedStore::open_for_write(&f.destination, &f.control).unwrap();
    store.reconcile_progress(&f.control, &worker).unwrap();
    let cycle = match f
        .control
        .queue_cycle(
            f.control.status().unwrap().policy.control_seq,
            vec![SelectionRevision {
                selection_id: selected.id.clone(),
                revision: selected.revision,
                root_identity: id("source-root"),
            }],
        )
        .unwrap()
        .value
    {
        CycleAdmission::Queued(c) => c,
        _ => panic!("fresh queue"),
    };
    let cycle = f
        .control
        .start_cycle(
            f.control.status().unwrap().policy.control_seq,
            &worker,
            cycle.token.cycle_seq,
            5,
        )
        .unwrap()
        .value;
    let mut observation = SourceObservation {
        binding: SourceBinding {
            source_id: SourceId::parse("verified-source").unwrap(),
            source_path: p(&f.history).into(),
            provider: SearchProvider::Claude,
            namespace_id: Some("namespace_one".into()),
            root_identity: "source-root".into(),
        },
        revision_id: RevisionId::parse("revision-one").unwrap(),
        revision_digest: "verified-fingerprint".into(),
        parser_version: 3,
        state: ObservationState::Complete,
        cycle_seq: cycle.token.cycle_seq.get(),
        worker_boot_id: "boot-one".into(),
        catalog_incarnation: "managed-incarnation".into(),
        policy_epoch: cycle.policy_epoch.get(),
        started_control_seq: cycle.started_control_seq.unwrap().get(),
        observed_at_ms: 6,
        committed_at_ms: 7,
        selections: vec![SelectionProof {
            selection_id: selected.id.as_str().into(),
            selection_revision: selected.revision.get(),
            root_identity: "source-root".into(),
        }],
        repositories: vec![],
    };
    let namespace = store
        .reserve_namespace(&f.control, &observation, &worker, "wrong-new-seed")
        .unwrap();
    assert_eq!(namespace.input, "frozen-legacy-seed");
    assert_eq!(namespace.namespace_id, "namespace_one");
    observation.binding.namespace_id = Some(namespace.namespace_id);
    let batch=SourceBatch { source_path:p(&f.history).into(),entries:vec![
        (f.message.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":"public fragment","timestamp":null})).unwrap(),"public fragment".into()),
        (f.session.clone(),serde_json::to_vec(&serde_json::json!({"documents":[f.document.as_str()]})).unwrap(),String::new()),
        (f.document.clone(),serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":"verified-fingerprint","len":17})).unwrap(),String::new())
    ],placements:vec![MessagePlacement::new(f.session.clone(),f.document.clone(),f.message.clone(),0,false,None)],edges:vec![],activities:vec![],usage_events:vec![],relation_complete:true,len_bytes:Some(17),fingerprint:Some("verified-fingerprint".into()),provider_id:Some("claude-code".into()),resume_claims:vec![SourceResumeClaim {
        provider_id:"claude-code".into(),session_id:f.session.as_str().into(),
        provider_session_id:Some("synthetic-native-session".into()),provider_session_id_state:"resolved".into(),
        original_working_directory:None,original_working_directory_state:"missing".into(),pair_observed:false,
    }] };
    store
        .commit_source(&f.control, &worker, &batch, &observation)
        .unwrap();
    store
        .with_read(&f.control, RequestIntersection::Selected, end(), |read| {
            assert!(
                read.query_lexical("withdrawn", &ProjectionQuery::default(), 5)?
                    .hits
                    .is_empty()
            );
            let message = read.messages(
                std::slice::from_ref(&f.message),
                &ProjectionQuery::default(),
            )?[0]
                .clone()
                .unwrap();
            assert_eq!(message.message.text, "public fragment");
            assert_eq!(message.message.id, f.message);
            Ok(())
        })
        .unwrap();
    drop(store);
    drop(worker);
    let revoked = f
        .control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &selected.id,
            None,
            8,
        )
        .unwrap()
        .value;
    assert!(matches!(
        ManagedStore::open(&f.destination, &f.control),
        Err(PortError::WriterBusy(_))
    ));
    let owner = ExclusiveGuard::try_acquire(f.destination.parent().unwrap(), LockKind::PolicyOwner)
        .unwrap();
    let drained =
        ExclusiveGuard::try_acquire(f.destination.parent().unwrap(), LockKind::PolicyEmission)
            .unwrap();
    f.control
        .settle_revocation(
            f.control.status().unwrap().policy.control_seq,
            &owner,
            &drained,
            &revoked.intent.id,
            9,
        )
        .unwrap();
    drop(drained);
    drop(owner);
    let store = ManagedStore::open(&f.destination, &f.control).unwrap();
    store
        .with_read(&f.control, RequestIntersection::Selected, end(), |read| {
            assert!(
                read.query_lexical("public", &ProjectionQuery::default(), 5)?
                    .hits
                    .is_empty()
            );
            assert!(
                read.messages(
                    std::slice::from_ref(&f.message),
                    &ProjectionQuery::default()
                )?[0]
                    .is_none()
            );
            Ok(())
        })
        .unwrap();
}
#[test]
fn destination_gate_busy_and_expired_deadline_create_no_migration_artifacts() {
    let f = Fixture::new();
    let inspected = inspect_legacy(&f.source, end()).unwrap();
    let held = agent_session_grep_adapters_sqlite::managed_locks::SharedGuard::try_acquire(
        f.destination.parent().unwrap(),
        LockKind::CatalogHandles,
    )
    .unwrap();
    assert!(matches!(
        f.migrate(&inspected, Instant::now() + Duration::from_millis(30)),
        Err(PortError::WriterBusy(_))
    ));
    assert!(!f.destination.exists());
    assert!(!sibling(&f.destination, ".asg-managed-create").exists());
    drop(held);
    assert!(matches!(
        f.migrate(&inspected, Instant::now()),
        Err(PortError::WriterBusy(_))
    ));
    assert!(!f.destination.exists());
}
#[test]
fn changed_source_and_wrong_installation_fail_closed_without_activation() {
    let f = Fixture::new();
    let inspected = inspect_legacy(&f.source, end()).unwrap();
    let wrong = migrate_legacy(
        LegacyMigrationRequest {
            source: &f.source,
            destination: &f.destination,
            inspected: &inspected,
            installation: &id("other-installation"),
            incarnation: &id("managed-incarnation"),
            operation: &id("migration-one"),
            now_ms: 1,
            deadline: end(),
        },
        &f.control,
    );
    assert!(matches!(wrong, Err(PortError::SchemaIncompatible(_))));
    assert!(!f.destination.exists());
    f.legacy
        .execute("UPDATE store_metadata SET active_generation=8", [])
        .unwrap();
    assert!(matches!(
        f.migrate(&inspected, end()),
        Err(PortError::SnapshotChanged(_))
    ));
    assert!(matches!(
        SqliteStore::open_for_write(p(&f.destination)),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(
        f.legacy
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        19
    );
}
#[test]
fn unsupported_or_unfinished_legacy_catalog_is_not_reset() {
    for newer in [false, true] {
        let f = Fixture::new();
        if newer {
            f.legacy.execute_batch("PRAGMA user_version=21").unwrap();
        } else {
            f.legacy.execute("INSERT INTO index_batches(operation_id,base_generation,target_generation,state,operation_digest,upsert_ids_json,delete_ids_json,durable_point,created_at_ms) VALUES('pending',7,8,'building','opaque','[]','[]','building',1)",[]).unwrap();
        }
        let db = hash(&f.source);
        let wal = hash(&sibling(&f.source, "-wal"));
        assert!(matches!(
            inspect_legacy(&f.source, end()),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert_eq!(hash(&f.source), db);
        assert_eq!(hash(&sibling(&f.source, "-wal")), wal);
        assert!(!f.destination.exists());
    }
}
#[test]
fn repeated_same_intent_does_not_recopy_or_advance_generation() {
    let f = Fixture::new();
    let inspected = inspect_legacy(&f.source, end()).unwrap();
    let first = f.migrate(&inspected, end()).unwrap();
    let before = hash(&f.destination);
    f.legacy
        .execute("UPDATE store_metadata SET active_generation=8", [])
        .unwrap();
    let second = f.migrate(&inspected, end()).unwrap();
    assert_eq!(first, second);
    assert_eq!(hash(&f.destination), before);
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 7);
}
#[test]
fn malformed_marker_or_unbound_inode_is_not_adopted() {
    for malformed in [true, false] {
        let f = Fixture::new();
        let inspected = inspect_legacy(&f.source, end()).unwrap();
        if malformed {
            fs::write(sibling(&f.destination, ".asg-managed-create"), b"broken").unwrap();
        } else {
            fs::write(&f.destination, b"unbound").unwrap();
        }
        assert!(f.migrate(&inspected, end()).is_err());
        if malformed {
            assert_eq!(
                fs::read(sibling(&f.destination, ".asg-managed-create")).unwrap(),
                b"broken"
            );
        } else {
            assert_eq!(fs::read(&f.destination).unwrap(), b"unbound");
        }
    }
}
#[test]
fn wrong_native_namespace_mapping_is_refused_without_rekeying() {
    let f = Fixture::new();
    f.legacy
        .execute(
            "UPDATE installation_namespaces SET namespace_input='different-seed'",
            [],
        )
        .unwrap();
    assert!(matches!(
        inspect_legacy(&f.source, end()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(!f.destination.exists());
}
