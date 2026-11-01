//! Synthetic sources through the real worker, namespace and publication seams.
use agent_session_grep_adapters_sqlite::{
    PARSER_SEMANTIC_VERSION, SourceBatch, SqliteControlStore, capture_with_deadline,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_refresh::{RefreshIneligible, RefreshOutcome},
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{
    PortError, SourceResumeClaim, SourceSnapshot,
    control::*,
    managed::{
        ObservationState, ProjectionQuery, ProjectionRead, Publication, RepositoryClaim,
        RevisionId, RevisionRef, SelectionProof, SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::{Connection, types::Value};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn current(control: &SqliteControlStore) -> ControlSeq {
    control.status().unwrap().policy.control_seq
}
fn entity(kind: IdKind) -> StableId {
    StableId::native_checked(kind, "refresh-fixture").unwrap()
}

struct Fixture {
    root: PathBuf,
    catalog: PathBuf,
    source: PathBuf,
    control: SqliteControlStore,
    worker_lock: ExclusiveGuard,
    selection: SelectionRevision,
    snapshot: SourceSnapshot,
    session: RefCell<StableId>,
    // Connections and OS guards must close before Windows temp cleanup.
    temp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_deadline(end())
    }

    fn new_with_deadline(deadline: Instant) -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let source = temp.path().join("synthetic.jsonl");
        std::fs::write(
            &source,
            b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"refresh original\"}}\n",
        )
        .unwrap();
        let catalog = root.join("catalog.db");
        let control = SqliteControlStore::create_with_deadline(
            &root,
            &id("fixture-installation"),
            DesiredUpdates::Running,
            deadline,
        )
        .unwrap();
        let (selection, worker_lock) = control
            .with_runtime_deadline(deadline, || {
                let selected = control
                    .add_selection(
                        current(&control),
                        SelectionRequest {
                            region: ScopeRegion {
                                provider: agent_session_grep_ports::SearchProvider::Claude,
                                locator: CanonicalLocator::from_path(temp.path()).unwrap(),
                                kind: RootKind::Root,
                            },
                            root_identity: Some(id("source-root")),
                            now_ms: 1,
                        },
                    )?
                    .value;
                let worker_lock = ExclusiveGuard::try_acquire(&root, LockKind::Background)?;
                let worker = control.bind_worker(&worker_lock, id("boot-one"))?;
                control.register_worker(current(&control), &worker, 1, 1)?;
                let selection = SelectionRevision {
                    selection_id: selected.id,
                    revision: selected.revision,
                    root_identity: id("source-root"),
                };
                drop(worker);
                Ok((selection, worker_lock))
            })
            .unwrap();
        let snapshot = capture_with_deadline(
            &source,
            agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
            deadline,
        )
        .unwrap();
        Self {
            temp,
            root,
            catalog,
            source,
            control,
            worker_lock,
            selection,
            snapshot,
            session: RefCell::new(entity(IdKind::Session)),
        }
    }

    fn operation<T>(
        &self,
        operation: impl FnOnce(Instant) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        // One original fixture-operation end also bounds control admission.
        // A caller's earlier end must win; the operation is never replayed.
        let deadline = SqliteControlStore::effective_runtime_deadline(end());
        self.control
            .with_runtime_deadline(deadline, || operation(deadline))
    }

    fn create(&self) -> ManagedStore {
        self.operation(|_| ManagedStore::create(&self.catalog, &self.control, id("catalog-one"), 1))
            .unwrap()
    }

    fn observe(&self, revision: &str, binding: Option<&SourceBinding>) -> SourceObservation {
        self.operation(|_| {
            let worker = self
                .control
                .bind_worker(&self.worker_lock, id("boot-one"))?;
            let queued = match self
                .control
                .queue_cycle(current(&self.control), vec![self.selection.clone()])?
                .value
            {
                CycleAdmission::Queued(cycle) => cycle,
                other => panic!("fixture cycle must be queued: {other:?}"),
            };
            let cycle = self
                .control
                .start_cycle(current(&self.control), &worker, queued.token.cycle_seq, 2)?
                .value;
            Ok(SourceObservation {
                binding: binding.cloned().unwrap_or_else(|| SourceBinding {
                    source_id: SourceId::parse("source-one").unwrap(),
                    source_path: self.source.to_str().unwrap().into(),
                    provider: agent_session_grep_ports::SearchProvider::Claude,
                    namespace_id: None,
                    root_identity: "source-root".into(),
                }),
                revision_id: RevisionId::parse(revision).unwrap(),
                revision_digest: self.snapshot.fingerprint.clone(),
                parser_version: PARSER_SEMANTIC_VERSION,
                state: ObservationState::Complete,
                cycle_seq: cycle.token.cycle_seq.get(),
                worker_boot_id: "boot-one".into(),
                catalog_incarnation: "catalog-one".into(),
                policy_epoch: cycle.policy_epoch.get(),
                started_control_seq: cycle.started_control_seq.unwrap().get(),
                observed_at_ms: 3,
                committed_at_ms: 4,
                selections: vec![SelectionProof {
                    selection_id: self.selection.selection_id.as_str().into(),
                    selection_revision: self.selection.revision.get(),
                    root_identity: self.selection.root_identity.as_str().into(),
                }],
                repositories: Vec::new(),
            })
        })
        .unwrap()
    }

    fn finish(&self, observation: &SourceObservation) {
        let probe = end() + Duration::from_secs(30);
        let previous = SqliteControlStore::effective_runtime_deadline(probe);
        let mut calls = 0;
        let mut finish = |deadline| {
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                deadline,
                "fixture finish must enter its operation scope before bind"
            );
            let worker = self
                .control
                .bind_worker(&self.worker_lock, id("boot-one"))?;
            let before = self.control.status()?.policy.control_seq;
            calls += 1;
            let finished = self.control.finish_cycle(
                before,
                &worker,
                CycleSeq::new(observation.cycle_seq).unwrap(),
                CycleFinish::Partial,
                5,
            )?;
            assert!(finished.changed);
            assert_eq!(finished.control_seq.get(), before.get() + 1);
            assert_eq!(finished.value.state, CycleState::Partial);
            assert_eq!(finished.value.token.cycle_seq.get(), observation.cycle_seq);
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                deadline
            );
            Ok::<_, PortError>(())
        };
        self.operation(&mut finish).unwrap();
        assert_eq!(calls, 1);
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            previous
        );
    }

    fn batch(&self, text: &str) -> SourceBatch {
        SourceBatch {
            source_path: self.source.to_str().unwrap().into(),
            entries: vec![
                (
                    entity(IdKind::Message),
                    serde_json::to_vec(&serde_json::json!({
                        "role": "user", "text": text, "timestamp": null,
                    }))
                    .unwrap(),
                    text.into(),
                ),
                (
                    self.session.borrow().clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "documents": [entity(IdKind::Document).as_str()],
                    }))
                    .unwrap(),
                    String::new(),
                ),
                (
                    entity(IdKind::Document),
                    serde_json::to_vec(&serde_json::json!({
                        "provider": "claude-code", "variant": "claude-code/jsonl-v1",
                        "fingerprint": self.snapshot.fingerprint, "len": self.snapshot.len,
                    }))
                    .unwrap(),
                    String::new(),
                ),
            ],
            placements: vec![MessagePlacement::new(
                self.session.borrow().clone(),
                entity(IdKind::Document),
                entity(IdKind::Message),
                0,
                false,
                None,
            )],
            edges: Vec::new(),
            activities: Vec::new(),
            usage_events: Vec::new(),
            relation_complete: true,
            len_bytes: Some(self.snapshot.len as i64),
            fingerprint: Some(self.snapshot.fingerprint.clone()),
            provider_id: Some("claude-code".into()),
            resume_claims: vec![SourceResumeClaim {
                provider_id: "claude-code".into(),
                session_id: self.session.borrow().as_str().into(),
                provider_session_id: Some("fixture-native".into()),
                provider_session_id_state: "resolved".into(),
                original_working_directory: Some(self.temp.path().to_str().unwrap().into()),
                original_working_directory_state: "resolved".into(),
                pair_observed: true,
            }],
        }
    }

    fn seed(&self, store: &ManagedStore, repositories: bool) -> (SourceObservation, Publication) {
        self.seed_with_parser(store, repositories, PARSER_SEMANTIC_VERSION)
    }

    fn seed_with_parser(
        &self,
        store: &ManagedStore,
        repositories: bool,
        parser: u32,
    ) -> (SourceObservation, Publication) {
        self.operation(|deadline| {
            let mut observation = self.observe("revision-one", None);
            observation.parser_version = parser;
            let worker = self
                .control
                .bind_worker(&self.worker_lock, id("boot-one"))?;
            let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
                &observation.binding.source_path,
                observation.binding.provider.as_str(),
            );
            let namespace =
                store.reserve_namespace(&self.control, &observation, &worker, &legacy)?;
            *self.session.borrow_mut() = StableId::native_session_scoped(
                &agent_session_grep_domain::SessionIdentityNamespace {
                    provider_id: observation.binding.provider.as_str(),
                    installation_namespace: &namespace.input,
                },
                "fixture-native",
            );
            observation.binding.namespace_id = Some(namespace.namespace_id);
            if repositories {
                observation.repositories.push(RepositoryClaim {
                    session_id: self.session.borrow().clone(),
                    slug: "synthetic-repository".into(),
                });
            }
            let publication = store.commit_source_with_context(
                &self.control,
                &worker,
                &self.batch("refresh original"),
                &observation,
                &Default::default(),
                deadline,
            )?;
            self.finish(&observation);
            Ok((observation, publication))
        })
        .unwrap()
    }

    /// Frozen seed recorded at the installation's previous location. A
    /// relocation keeps it, so it differs from a seed of today's path.
    fn relocated_legacy_seed(&self) -> String {
        use agent_session_grep_application::relocation::legacy_installation_namespace;
        let seed = legacy_installation_namespace(
            r"C:\FormerRoot\.claude\projects\fixture\synthetic.jsonl",
            "claude-code",
        );
        assert_ne!(
            seed,
            legacy_installation_namespace(self.source.to_str().unwrap(), "claude-code")
        );
        seed
    }

    /// Registers the source under a `legacy-v1` tuple before its first full
    /// publication, so the real namespace and publication seams bind to it.
    /// The id is computed independently from the frozen field encoding.
    fn seed_legacy_namespace(&self, prefix: &str, input: &str) -> String {
        use agent_session_grep_application::relocation::{
            installation_root, normalize_absolute_path,
        };
        let mut hash = blake3::Hasher::new();
        let fields: [&[u8]; 3] = [
            b"asg-legacy-installation-v1",
            b"claude-code",
            input.as_bytes(),
        ];
        for field in fields {
            hash.update(&(field.len() as u64).to_le_bytes());
            hash.update(field);
        }
        let namespace = format!("{prefix}{}", hash.finalize().to_hex());
        let source = self.source.to_str().unwrap();
        let root = installation_root(source, "claude-code").unwrap();
        let conn = Connection::open(&self.catalog).unwrap();
        conn.execute(
            "INSERT INTO installation_namespaces(namespace_id,provider_id,namespace_input,origin,created_at_ms)
             VALUES(?1,'claude-code',?2,'legacy-v1',1)",
            rusqlite::params![namespace, input],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO installation_locations(provider_id,root_key,root_locator,namespace_id,state,retired_until_ms)
             VALUES('claude-code',?1,?2,?3,'current',NULL)",
            rusqlite::params![normalize_absolute_path(&root).unwrap(), root, namespace],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_installations(source_path,source_key,namespace_id) VALUES(?1,?2,?3)",
            rusqlite::params![source, normalize_absolute_path(source).unwrap(), namespace],
        )
        .unwrap();
        namespace
    }

    fn recover(&self, deadline: Instant) {
        use agent_session_grep_adapters_sqlite::{
            control::BackupPurpose,
            managed_locks::JobLockKey,
            managed_maintenance::{BackupOutcome, MaintenanceCatalog},
        };
        let prefix = self.temp.path().join("installed");
        std::fs::create_dir(&prefix).unwrap();
        let installation_lock = ExclusiveGuard::try_acquire(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
        )
        .unwrap();
        let owner_lock = ExclusiveGuard::try_acquire(&self.root, LockKind::PolicyOwner).unwrap();
        let bound = self.control.bind_control_root(&owner_lock).unwrap();
        self.control
            .record_verified_installation_prefix(&prefix, &installation_lock, &bound, deadline)
            .unwrap();
        let installation = self
            .control
            .bind_installation(&prefix, &installation_lock)
            .unwrap();
        self.control
            .set_desired_updates(current(&self.control), DesiredUpdates::Paused)
            .unwrap();
        self.control
            .begin_maintenance(
                current(&self.control),
                &id("recovery-owner"),
                &bound,
                &installation,
                MaintenanceFence {
                    state: MaintenanceState::Recovering,
                    owner: Some(id("recovery-owner")),
                    phase: Some(MaintenancePhase::Reconciling),
                },
            )
            .unwrap();
        drop(owner_lock);
        let mut catalog = MaintenanceCatalog::open_authorized(
            &self.control,
            &installation,
            &id("recovery-owner"),
            &self.catalog,
            deadline,
        )
        .unwrap();
        assert!(matches!(
            catalog
                .create_backup(
                    &self.control,
                    &installation,
                    &id("recovery-owner"),
                    &id("proof-backup"),
                    BackupPurpose::BetaRollback,
                    6,
                    deadline,
                )
                .unwrap(),
            BackupOutcome::Created(_)
        ));
        catalog
            .rotate_after_recovery(
                &self.control,
                &installation,
                &id("recovery-owner"),
                &id("catalog-one"),
                &id("recovered-catalog"),
                7,
                deadline,
            )
            .unwrap();
        drop(catalog);
        self.control
            .set_maintenance(
                current(&self.control),
                &id("recovery-owner"),
                MaintenanceFence::idle(),
            )
            .unwrap();
        self.control
            .set_desired_updates(current(&self.control), DesiredUpdates::Running)
            .unwrap();
        let worker = self
            .control
            .bind_worker(&self.worker_lock, id("boot-one"))
            .unwrap();
        self.control
            .register_worker(current(&self.control), &worker, 1, 9)
            .unwrap();
        self.control
            .heartbeat_worker(current(&self.control), &worker, UpdateState::Idle, None, 10)
            .unwrap();
    }

    fn refresh(
        &self,
        store: &ManagedStore,
        prior: &RevisionRef,
        observation: &SourceObservation,
    ) -> Result<RefreshOutcome, PortError> {
        self.operation(|deadline| {
            let worker = self
                .control
                .bind_worker(&self.worker_lock, id("boot-one"))?;
            store.refresh_verified_unchanged_source(
                &self.control,
                &worker,
                prior,
                observation,
                &self.snapshot,
                agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
                deadline,
            )
        })
    }

    fn sql(&self, statement: &str) {
        Connection::open(&self.catalog)
            .unwrap()
            .execute_batch(statement)
            .unwrap();
    }
    fn corrupt_sql(&self, statement: &str) {
        let conn = Connection::open(&self.catalog).unwrap();
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute_batch(statement).unwrap();
    }
    fn scalar(&self, statement: &str) -> i64 {
        Connection::open(&self.catalog)
            .unwrap()
            .query_row(statement, [], |r| r.get(0))
            .unwrap()
    }
    fn tables(&self) -> BTreeMap<String, Vec<Vec<Value>>> {
        Self::dump(&self.catalog)
    }
    fn control_tables(&self) -> BTreeMap<String, Vec<Vec<Value>>> {
        let path = SqliteControlStore::path(&self.root);
        assert!(path.is_file(), "control database must already exist");
        Self::dump(&path)
    }
    fn dump(path: &Path) -> BTreeMap<String, Vec<Vec<Value>>> {
        let conn = Connection::open(path).unwrap();
        let names: Vec<String> = conn.prepare(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        ).unwrap().query_map([], |r| r.get(0)).unwrap()
            .collect::<Result<_, _>>().unwrap();
        names
            .into_iter()
            .map(|name| {
                let mut statement = conn.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
                let width = statement.column_count();
                let mut records = statement
                    .query_map([], |r| {
                        (0..width)
                            .map(|i| r.get::<_, Value>(i))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                records.sort_by_key(|row| format!("{row:?}"));
                (name, records)
            })
            .collect()
    }
}

#[test]
fn fixture_finish_uses_one_operation_end_and_restores_scope() {
    let f = Fixture::new();
    let store = f.create();
    let (first, _) = f.seed(&store, false);
    let second = f.observe("revision-two", Some(&first.binding));
    let probe = end() + Duration::from_secs(30);
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    // Deliberately outside seed's scope: its outer end must not mask a
    // missing finish scope. finish checks the exact end before binding and
    // verifies one mutation, one sequence increment and the original token.
    f.finish(&second);
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    let outer = end();
    f.control
        .with_runtime_deadline(outer, || {
            f.operation(|deadline| {
                assert_eq!(deadline, outer);
                assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
                let cycle = f.control.cycle(CycleSeq::new(second.cycle_seq).unwrap())?;
                assert_eq!(cycle.state, CycleState::Partial);
                assert_eq!(cycle.completed_at_ms, Some(5));
                Ok(())
            })?;
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            Ok(())
        })
        .unwrap();
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
}

#[test]
fn refresh_matches_full_noop_without_touching_facts_fts_generation_or_namespace() {
    let f = Fixture::new();
    let store = f.create();
    let (first, prior) = f.seed(&store, false);
    let second = f.observe("revision-two", Some(&first.binding));
    let baseline = f.tables();
    let full = f
        .operation(|deadline| {
            let worker = f.control.bind_worker(&f.worker_lock, id("boot-one"))?;
            store.commit_source_with_context(
                &f.control,
                &worker,
                &f.batch("refresh original"),
                &second,
                &Default::default(),
                deadline,
            )
        })
        .unwrap();
    let full_tables = f.tables();
    // Revert only the disposable synthetic no-op publication. Both paths now
    // start from the same real catalog, token, namespace and prior receipts.
    f.sql("UPDATE source_context_heads SET revision_id='revision-one';
        DELETE FROM source_publication_contexts WHERE revision_id='revision-two';
        UPDATE source_heads SET latest_receipt_id='revision-one',last_attempt_id='revision-one',observed_cycle_seq=1;
        DELETE FROM receipt_selection_claims WHERE revision_id='revision-two';
        DELETE FROM source_revision_receipts WHERE revision_id='revision-two';");
    assert_eq!(baseline, f.tables());
    let RefreshOutcome::Refreshed(refreshed) = f.refresh(&store, &prior.receipt, &second).unwrap()
    else {
        panic!("plain unchanged source must refresh")
    };
    assert_eq!(refreshed, full);
    assert_eq!(f.tables(), full_tables);
    for (table, rows) in baseline {
        if !matches!(
            table.as_str(),
            "source_heads"
                | "source_revision_receipts"
                | "receipt_selection_claims"
                | "source_scope_claims"
                | "source_publication_contexts"
                | "source_context_heads"
                | "source_scans"
        ) {
            assert_eq!(f.tables()[&table], rows, "refresh changed {table}");
        }
    }
    assert!(!refreshed.content_changed && !refreshed.destructive);
    assert_eq!(refreshed.required_generation, prior.required_generation);
    store
        .with_read(&f.control, RequestIntersection::Selected, end(), |read| {
            assert_eq!(
                read.messages(&[entity(IdKind::Message)], &ProjectionQuery::default())?[0]
                    .as_ref()
                    .unwrap()
                    .message
                    .id,
                entity(IdKind::Message)
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn prior_repository_projection_requires_real_full_path_removal() {
    let f = Fixture::new();
    let store = f.create();
    let (first, prior) = f.seed(&store, true);
    let second = f.observe("revision-two", Some(&first.binding));
    let before = f.tables();
    assert_eq!(
        f.refresh(&store, &prior.receipt, &second).unwrap(),
        RefreshOutcome::Ineligible(RefreshIneligible::PriorRepositoryProjection),
    );
    assert_eq!(f.tables(), before);
    let full = f
        .operation(|deadline| {
            let worker = f.control.bind_worker(&f.worker_lock, id("boot-one"))?;
            store.commit_source_with_context(
                &f.control,
                &worker,
                &f.batch("refresh original"),
                &second,
                &Default::default(),
                deadline,
            )
        })
        .unwrap();
    assert!(full.content_changed && full.destructive);
    assert_eq!(full.required_generation, prior.required_generation + 1);
    assert_eq!(
        f.scalar("SELECT count(*) FROM source_entity_projections WHERE kind='repo_identity'"),
        0
    );
}

#[test]
fn same_size_same_mtime_change_before_final_hash_is_an_error_without_writes() {
    let f = Fixture::new();
    let store = f.create();
    let (first, prior) = f.seed(&store, false);
    let second = f.observe("revision-two", Some(&first.binding));
    let before = f.tables();
    let metadata = std::fs::metadata(&f.source).unwrap();
    let mut bytes = std::fs::read(&f.source).unwrap();
    let index = bytes.iter().position(|byte| *byte == b'r').unwrap();
    bytes[index] = b'R';
    std::fs::write(&f.source, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&f.source)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
        .unwrap();
    assert!(matches!(
        f.refresh(&store, &prior.receipt, &second),
        Err(PortError::SnapshotChanged(_))
    ));
    assert_eq!(f.tables(), before);
}

#[test]
fn wrong_attempt_and_revoked_or_paused_input_never_open_a_missing_source() {
    for mode in [
        "attempt", "paused", "revoked", "boot", "root", "snapshot", "prior",
    ] {
        let f = Fixture::new();
        let store = f.create();
        let (first, prior) = f.seed(&store, false);
        let mut second = f.observe("revision-two", Some(&first.binding));
        let mut expected = prior.receipt.clone();
        match mode {
            "attempt" => second.started_control_seq = first.started_control_seq,
            "paused" => {
                f.operation(|_| {
                    f.control
                        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
                })
                .unwrap();
            }
            "revoked" => {
                f.operation(|_| {
                    f.control.revoke_selection(
                        current(&f.control),
                        &f.selection.selection_id,
                        None,
                        8,
                    )
                })
                .unwrap();
            }
            "boot" => second.worker_boot_id = "wrong-boot".into(),
            "root" => second.binding.root_identity = "other-root".into(),
            "snapshot" => second.revision_digest = "bad-fingerprint".into(),
            "prior" => expected.observed_at_ms += 1,
            _ => unreachable!(),
        }
        std::fs::remove_file(&f.source).unwrap();
        let before = f.tables();
        let result = f.refresh(&store, &expected, &second);
        assert!(result.is_err(), "{mode} must fail");
        assert!(
            !matches!(result, Err(PortError::SourceIo(_))),
            "{mode} opened source"
        );
        assert_eq!(f.tables(), before, "{mode} changed catalog");
    }
}

#[test]
fn expired_nested_end_wins_and_sqlite_writer_busy_never_falls_back() {
    let f = Fixture::new();
    let store = f.create();
    let (first, prior) = f.seed(&store, false);
    let second = f.observe("revision-two", Some(&first.binding));
    let before = f.tables();
    let worker = f
        .operation(|_| f.control.bind_worker(&f.worker_lock, id("boot-one")))
        .unwrap();
    let result = f.control.with_runtime_deadline(Instant::now(), || {
        store.refresh_verified_unchanged_source(
            &f.control,
            &worker,
            &prior.receipt,
            &second,
            &f.snapshot,
            agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
            end(),
        )
    });
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    let lock = Connection::open(&f.catalog).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        f.refresh(&store, &prior.receipt, &second),
        Err(PortError::WriterBusy(_))
    ));
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.tables(), before);
}

#[test]
fn corrupt_lineage_in_each_projection_branch_is_never_ineligible() {
    for table in [
        "source_projections",
        "source_occurrences",
        "source_entity_projections",
        "source_session_projections",
        "source_heads",
    ] {
        let f = Fixture::new();
        let store = f.create();
        let (first, prior) = f.seed(&store, false);
        let second = f.observe("revision-two", Some(&first.binding));
        let column = if table == "source_heads" {
            "visible_revision_id"
        } else {
            "revision_id"
        };
        f.corrupt_sql(&format!("UPDATE {table} SET {column}='missing-receipt'"));
        let before = f.tables();
        assert!(matches!(
            f.refresh(&store, &prior.receipt, &second),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert_eq!(f.tables(), before, "corrupt {table} must remain unchanged");
    }
}

#[test]
fn content_or_context_digest_corruption_is_not_hidden_by_repository_miss() {
    for mutation in [
        "UPDATE source_projections SET payload=x'00'",
        "UPDATE source_heads SET content_set_digest=printf('%064d',0)",
        "UPDATE source_session_projections SET search_text='corrupt'",
        "DROP TRIGGER source_publication_context_immutable;
         UPDATE source_publication_contexts SET context_digest=printf('%064d',0);
         CREATE TRIGGER source_publication_context_immutable BEFORE UPDATE ON source_publication_contexts
         BEGIN SELECT RAISE(ABORT,'immutable source context'); END;",
    ] {
        let f = Fixture::new();
        let store = f.create();
        let (first, prior) = f.seed(&store, true);
        let second = f.observe("revision-two", Some(&first.binding));
        f.sql(mutation);
        let before = f.tables();
        assert!(matches!(f.refresh(&store, &prior.receipt, &second), Err(PortError::SchemaIncompatible(_))));
        assert_eq!(f.tables(), before);
    }
}

#[test]
fn recognized_parser_scan_and_kind_misses_preserve_all_tables() {
    for mode in [
        "parser",
        "scan",
        "repositories",
        "changed",
        "namespace",
        "kind",
    ] {
        let f = Fixture::new();
        let store = f.create();
        // A legal legacy tuple must exist before the first full publication.
        let legacy = (mode == "namespace")
            .then(|| f.seed_legacy_namespace("ins_v1_", &f.relocated_legacy_seed()));
        let (first, prior) = f.seed(&store, false);
        if let Some(legacy) = &legacy {
            assert_eq!(first.binding.namespace_id.as_ref(), Some(legacy));
        }
        let mut second = f.observe("revision-two", Some(&first.binding));
        let mut snapshot = f.snapshot.clone();
        let expected = match mode {
            "parser" => {
                second.parser_version += 1;
                RefreshIneligible::ParserVersion
            }
            "scan" => {
                f.sql("UPDATE source_scans SET parser_version=0");
                RefreshIneligible::ParserVersion
            }
            "repositories" => {
                second.repositories.push(RepositoryClaim {
                    session_id: f.session.borrow().clone(),
                    slug: "synthetic".into(),
                });
                RefreshIneligible::Repositories
            }
            "changed" => {
                snapshot.fingerprint = blake3::hash(b"changed").to_hex().to_string();
                second.revision_digest = snapshot.fingerprint.clone();
                RefreshIneligible::DigestOrLength
            }
            "namespace" => {
                // Bound above to a proven legacy tuple with a relocated seed.
                RefreshIneligible::InstallationProof
            }
            "kind" => {
                snapshot.len = 0;
                RefreshIneligible::SourceKind
            }
            _ => unreachable!(),
        };
        let before = f.tables();
        assert_eq!(
            f.operation(|deadline| {
                let worker = f.control.bind_worker(&f.worker_lock, id("boot-one"))?;
                store.refresh_verified_unchanged_source(
                    &f.control,
                    &worker,
                    &prior.receipt,
                    &second,
                    &snapshot,
                    agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
                    deadline,
                )
            })
            .unwrap(),
            RefreshOutcome::Ineligible(expected),
        );
        assert_eq!(f.tables(), before, "{mode} mutated catalog");
    }
}

#[test]
fn corrupt_legacy_namespace_tuple_is_an_error_without_catalog_or_control_writes() {
    for mode in ["digest", "id-prefix", "input-provider", "input-shape"] {
        // One scenario end bounds every preparation read and the refresh.
        let deadline = end();
        let f = Fixture::new_with_deadline(deadline);
        f.control
            .with_runtime_deadline(deadline, || {
                let store = f.create();
                let seed = f.relocated_legacy_seed();
                // Every tuple is consistent enough for the first full
                // publication; only the refresh proof checks its derivation.
                let (prefix, input) = match mode {
                    "digest" => ("ins_v1_", seed.as_str()),
                    "id-prefix" => ("ins_v0_", seed.as_str()),
                    "input-provider" => ("ins_v1_", "codex:C:/FormerRoot/.codex"),
                    "input-shape" => ("ins_v1_", r"claude-code:C:\FormerRoot\.claude"),
                    _ => unreachable!(),
                };
                let namespace = f.seed_legacy_namespace(prefix, input);
                let (first, prior) = f.seed(&store, false);
                assert_eq!(first.binding.namespace_id.as_ref(), Some(&namespace));
                if mode == "digest" {
                    // A well-formed seed that no longer derives the stored id.
                    f.sql(
                        "UPDATE installation_namespaces
                         SET namespace_input='claude-code:C:/MovedRoot/.claude'",
                    );
                }
                let second = f.observe("revision-two", Some(&first.binding));
                let worker = f
                    .control
                    .bind_worker(&f.worker_lock, id("boot-one"))
                    .unwrap();
                let catalog_rows = f.tables();
                let control_rows = f.control_tables();
                let result = store.refresh_verified_unchanged_source(
                    &f.control,
                    &worker,
                    &prior.receipt,
                    &second,
                    &f.snapshot,
                    agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES,
                    deadline,
                );
                assert!(
                    matches!(result, Err(PortError::SchemaIncompatible(_))),
                    "{mode} legacy tuple must be a hard error: {result:?}"
                );
                assert_eq!(f.tables(), catalog_rows, "{mode} mutated catalog");
                assert_eq!(f.control_tables(), control_rows, "{mode} mutated control");
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn uniformly_old_parser_proof_requires_full_current_baseline_without_refresh_writes() {
    let deadline = end();
    let f = Fixture::new_with_deadline(deadline);
    f.control.with_runtime_deadline(deadline, || {
        let store = f.create();
        let old_parser = PARSER_SEMANTIC_VERSION - 1;
        let (first, prior) = f.seed_with_parser(&store, false, old_parser);
        let mut second = f.observe("revision-two", Some(&first.binding));
        second.parser_version = old_parser;
        assert_eq!(f.scalar("SELECT parser_version FROM source_scans"), i64::from(old_parser));
        assert_eq!(f.scalar("SELECT parser_version FROM source_revision_receipts WHERE revision_id='revision-one'"), i64::from(old_parser));
        let before = f.tables();
        assert_eq!(f.refresh(&store, &prior.receipt, &second).unwrap(),
            RefreshOutcome::Ineligible(RefreshIneligible::ParserVersion));
        assert_eq!(f.tables(), before);
        second.parser_version = PARSER_SEMANTIC_VERSION;
        let worker = f.control.bind_worker(&f.worker_lock, id("boot-one")).unwrap();
        let full = store.commit_source_with_context(
            &f.control, &worker, &f.batch("refresh original"), &second,
            &Default::default(), deadline,
        ).unwrap();
        assert!(!full.content_changed && !full.destructive);
        assert_eq!(full.required_generation, prior.required_generation);
        assert_eq!(f.scalar("SELECT parser_version FROM source_scans"), i64::from(PARSER_SEMANTIC_VERSION));
        assert_eq!(f.scalar("SELECT parser_version FROM source_revision_receipts WHERE revision_id='revision-two'"), i64::from(PARSER_SEMANTIC_VERSION));
        f.finish(&second);
        let third = f.observe("revision-three", Some(&first.binding));
        assert!(matches!(f.refresh(&store, &full.receipt, &third).unwrap(),
            RefreshOutcome::Refreshed(_)));
        Ok(())
    }).unwrap();
}

#[test]
fn publication_fault_rolls_back_every_refresh_row_and_duplicate_retry_is_error() {
    let f = Fixture::new();
    let store = f.create();
    let (first, prior) = f.seed(&store, false);
    let second = f.observe("revision-two", Some(&first.binding));
    f.sql(
        "CREATE TRIGGER injected_refresh_fault BEFORE UPDATE ON source_scans
        BEGIN SELECT RAISE(ABORT,'synthetic refresh failure'); END;",
    );
    let before = f.tables();
    assert!(f.refresh(&store, &prior.receipt, &second).is_err());
    assert_eq!(f.tables(), before);
    f.sql("DROP TRIGGER injected_refresh_fault");
    assert!(matches!(
        f.refresh(&store, &prior.receipt, &second).unwrap(),
        RefreshOutcome::Refreshed(_)
    ));
    let after = f.tables();
    assert!(f.refresh(&store, &prior.receipt, &second).is_err());
    assert_eq!(f.tables(), after);
}

#[test]
fn verified_restore_requires_full_rebind_and_mixed_retained_pointers_never_hide_corruption() {
    for branch in [
        "source_projections",
        "source_occurrences",
        "source_entity_projections",
        "source_session_projections",
        "source_heads",
    ] {
        // Preparation reads share the scenario end instead of creating their
        // own 250ms status budget. Busy/expiry still fails every assertion.
        let deadline = end();
        let f = Fixture::new_with_deadline(deadline);
        f.control
            .with_runtime_deadline(deadline, || {
                let store = f.create();
                let (first, prior) = f.seed(&store, false);
                drop(store);
                f.recover(deadline);
                let store = ManagedStore::open_for_write(&f.catalog, &f.control).unwrap();
                let worker = f
                    .control
                    .bind_worker(&f.worker_lock, id("boot-one"))
                    .unwrap();
                let mut second = f.observe("revision-two", Some(&first.binding));
                second.catalog_incarnation = "recovered-catalog".into();
                let before = f.tables();
                assert_eq!(
                    f.refresh(&store, &prior.receipt, &second).unwrap(),
                    RefreshOutcome::Ineligible(RefreshIneligible::RetainedEvidence)
                );
                assert_eq!(f.tables(), before);
                let full = store
                    .commit_source_with_context(
                        &f.control,
                        &worker,
                        &f.batch("refresh original"),
                        &second,
                        &Default::default(),
                        deadline,
                    )
                    .unwrap();
                assert!(!full.content_changed && !full.destructive);
                assert_eq!(full.required_generation, prior.required_generation);
                f.finish(&second);
                let third = f.observe("revision-three", Some(&first.binding));
                let mut third = third;
                third.catalog_incarnation = "recovered-catalog".into();
                let column = if branch == "source_heads" {
                    "visible_revision_id"
                } else {
                    "revision_id"
                };
                f.sql(&format!("UPDATE {branch} SET {column}='revision-one'"));
                let mixed = f.tables();
                assert_eq!(
                    f.refresh(&store, &full.receipt, &third).unwrap(),
                    RefreshOutcome::Ineligible(RefreshIneligible::RetainedEvidence)
                );
                assert_eq!(f.tables(), mixed);
                let corrupt_branch = if branch == "source_occurrences" {
                    "source_projections"
                } else {
                    "source_occurrences"
                };
                // The union visits revision-one before this dangling revision;
                // a recognized retained miss cannot stop the remaining checks.
                f.corrupt_sql(&format!(
                    "UPDATE {corrupt_branch} SET revision_id='zz-missing-receipt'"
                ));
                let corrupt = f.tables();
                assert!(matches!(
                    f.refresh(&store, &full.receipt, &third),
                    Err(PortError::SchemaIncompatible(_))
                ));
                assert_eq!(f.tables(), corrupt);
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn lost_ack_reconciliation_keeps_the_committed_refresh_and_direct_content_receipt() {
    let f = Fixture::new();
    let store = f.create();
    let (first, prior) = f.seed(&store, false);
    let second = f.observe("revision-two", Some(&first.binding));
    let RefreshOutcome::Refreshed(refresh) = f.refresh(&store, &prior.receipt, &second).unwrap()
    else {
        panic!("expected refresh")
    };
    let after = f.tables();
    assert!(f.refresh(&store, &prior.receipt, &second).is_err());
    assert_eq!(f.tables(), after);
    assert!(
        store
            .source_current(&refresh.receipt, &f.control, end())
            .unwrap()
    );
    let progress = f
        .operation(|_| {
            let worker = f.control.bind_worker(&f.worker_lock, id("boot-one"))?;
            store.reconcile_progress(&f.control, &worker)?;
            f.control.source_progress(&id("source-one"))
        })
        .unwrap()
        .unwrap();
    assert_eq!(progress.receipt.unwrap().revision.as_str(), "revision-two");
    assert_eq!(
        f.scalar("SELECT count(*) FROM source_revision_receipts WHERE revision_id='revision-one'"),
        1
    );
    assert_eq!(f.scalar("SELECT count(*) FROM source_revision_receipts WHERE revision_id='revision-two' AND content_revision_id='revision-one'"), 1);
}
