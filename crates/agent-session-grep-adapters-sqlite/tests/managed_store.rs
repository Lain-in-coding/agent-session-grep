//! Synthetic private roots only. Exercises actual control + locks + catalog.
use agent_session_grep_adapters_sqlite::{
    SourceBatch, SqliteControlStore, SqliteStore,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{
    PortError, SearchProvider,
    control::*,
    managed::{
        ObservationState, ProjectionQuery, ProjectionRead, RevisionId, SelectionProof,
        SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::Connection;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn id(s: &str) -> ControlId {
    ControlId::parse(s).unwrap()
}
fn current(c: &SqliteControlStore) -> ControlSeq {
    c.status().unwrap().policy.control_seq
}
fn prepare<T>(
    control: &SqliteControlStore,
    end: Instant,
    operation: impl FnOnce() -> Result<T, PortError>,
) -> Result<T, PortError> {
    let active_end = SqliteControlStore::effective_runtime_deadline(end);
    let probe = end + Duration::from_secs(5);
    let previous_end = SqliteControlStore::effective_runtime_deadline(probe);
    let result = control.with_runtime_deadline(end, || {
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            active_end
        );
        let result = operation();
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            active_end
        );
        result
    });
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe),
        previous_end
    );
    result
}
fn entity(kind: IdKind) -> StableId {
    StableId::native_checked(kind, "shared-fixture").unwrap()
}
fn acquire(root: &std::path::Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => panic!("fixture lock acquisition failed: {result:?}"),
        }
    }
}
struct Fixture {
    root: PathBuf,
    catalog: PathBuf,
    control: SqliteControlStore,
    worker_lock: ExclusiveGuard,
    observation: SourceObservation,
    // Connections and OS guards must close before Windows temp cleanup.
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let catalog = root.join("catalog.db");
        let control =
            SqliteControlStore::create(&root, &id("fixture-installation"), DesiredUpdates::Running)
                .unwrap();
        let preparation_end = Instant::now() + Duration::from_secs(5);
        let (selected, worker_lock, cycle) = prepare(&control, preparation_end, || {
            let selected = control
                .add_selection(
                    current(&control),
                    SelectionRequest {
                        region: ScopeRegion {
                            provider: SearchProvider::Claude,
                            locator: CanonicalLocator::from_path(temp.path()).unwrap(),
                            kind: RootKind::Root,
                        },
                        root_identity: Some(id("source-root")),
                        now_ms: 1,
                    },
                )?
                .value;
            let worker_lock = acquire(&root, LockKind::Background);
            let worker = control.bind_worker(&worker_lock, id("boot-one"))?;
            control.register_worker(current(&control), &worker, 1, 1)?;
            let revision = SelectionRevision {
                selection_id: selected.id.clone(),
                revision: selected.revision,
                root_identity: id("source-root"),
            };
            let cycle = match control
                .queue_cycle(current(&control), vec![revision])?
                .value
            {
                CycleAdmission::Queued(c) => c,
                _ => panic!("expected cycle"),
            };
            let token = cycle.token.clone();
            let cycle = control
                .start_cycle(current(&control), &worker, cycle.token.cycle_seq, 2)?
                .value;
            assert_eq!(cycle.token, token);
            drop(worker);
            Ok((selected, worker_lock, cycle))
        })
        .unwrap();
        let observation = SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse("source-one").unwrap(),
                source_path: temp.path().join("synthetic.jsonl").to_str().unwrap().into(),
                provider: SearchProvider::Claude,
                namespace_id: None,
                root_identity: "source-root".into(),
            },
            revision_id: RevisionId::parse("revision-one").unwrap(),
            revision_digest: "full-fingerprint".into(),
            parser_version: 1,
            state: ObservationState::Complete,
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: "boot-one".into(),
            catalog_incarnation: "catalog-one".into(),
            policy_epoch: cycle.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.unwrap().get(),
            observed_at_ms: 3,
            committed_at_ms: 4,
            selections: vec![SelectionProof {
                selection_id: selected.id.as_str().into(),
                selection_revision: selected.revision.get(),
                root_identity: "source-root".into(),
            }],
            repositories: Vec::new(),
        };
        Self {
            _temp: temp,
            root,
            catalog,
            control,
            worker_lock,
            observation,
        }
    }
    fn create(&self) -> ManagedStore {
        self.create_with_deadline(Instant::now() + Duration::from_secs(5))
            .unwrap()
    }
    fn create_with_deadline(&self, end: Instant) -> Result<ManagedStore, PortError> {
        prepare(&self.control, end, || {
            ManagedStore::create(&self.catalog, &self.control, id("catalog-one"), 1)
        })
    }
    fn batch(&self, text: &str) -> SourceBatch {
        SourceBatch {
            source_path:self.observation.binding.source_path.clone(),
            entries:vec![
                (entity(IdKind::Message),serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":null})).unwrap(),text.into()),
                (entity(IdKind::Session),serde_json::to_vec(&serde_json::json!({"documents":[entity(IdKind::Document).as_str()]})).unwrap(),String::new()),
                (entity(IdKind::Document),serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":"full-fingerprint","len":100})).unwrap(),String::new()),
            ],placements:vec![MessagePlacement::new(entity(IdKind::Session),entity(IdKind::Document),entity(IdKind::Message),0,false,None)],edges:Vec::new(),activities:Vec::new(),usage_events:Vec::new(),relation_complete:true,len_bytes:Some(100),fingerprint:Some("full-fingerprint".into()),provider_id:Some("claude-code".into()),resume_claims:Vec::new(),
        }
    }
    fn scalar(&self, sql: &str) -> i64 {
        Connection::open(&self.catalog)
            .unwrap()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    }
}

#[test]
fn fixture_preparation_keeps_one_cycle_and_restores_the_callers_end() {
    let f = Fixture::new();
    let outer_end = Instant::now() + Duration::from_secs(5);
    let requested_end = outer_end + Duration::from_secs(5);
    let probe = requested_end + Duration::from_secs(5);
    let before = prepare(&f.control, outer_end, || {
        let status = f.control.status()?;
        assert_eq!(status.policy.control_seq.get(), 4);
        assert_eq!(status.policy.policy_epoch.get(), 1);
        assert_eq!(status.policy.selections.len(), 1);
        let background = f.control.background_status()?;
        assert_eq!(background.next_cycle_seq.get(), 2);
        let cycle = f.control.cycle(CycleSeq::new(f.observation.cycle_seq)?)?;
        assert_eq!(cycle.state, CycleState::Observing);
        assert_eq!(cycle.token.worker_boot_id, id("boot-one"));
        assert_eq!(
            cycle.started_control_seq.unwrap().get(),
            f.observation.started_control_seq
        );
        Ok((status, background, cycle))
    })
    .unwrap();
    let store = f
        .control
        .with_runtime_deadline(outer_end, || {
            let store = f.create_with_deadline(requested_end)?;
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                outer_end
            );
            Ok(store)
        })
        .unwrap();
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    assert_eq!(f.scalar("SELECT count(*) FROM catalog_meta"), 1);
    assert_eq!(f.scalar("SELECT count(*) FROM index_batches"), 0);
    assert!(matches!(
        f.create_with_deadline(requested_end),
        Err(PortError::WriterBusy(reason)) if reason == "writer lease is already held"
    ));
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    drop(store);
    let after = prepare(&f.control, requested_end, || {
        Ok((
            f.control.status()?,
            f.control.background_status()?,
            f.control.cycle(CycleSeq::new(f.observation.cycle_seq)?)?,
        ))
    })
    .unwrap();
    assert_eq!(after, before, "create must not replay control preparation");
}

#[test]
fn fixture_preparation_refuses_expiry_and_does_not_retry_or_leak_a_scope() {
    let f = Fixture::new();
    let end = Instant::now() + Duration::from_secs(5);
    let probe = end + Duration::from_secs(5);
    let mut calls = 0;
    let refused = prepare(&f.control, end, || {
        calls += 1;
        let _ = f.control.status()?;
        Err::<(), _>(PortError::WriterBusy("synthetic fixture refusal".into()))
    });
    assert!(
        matches!(refused, Err(PortError::WriterBusy(reason)) if reason == "synthetic fixture refusal")
    );
    assert_eq!(calls, 1, "a failed preparation must not be retried");
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    let files = || {
        let mut names = std::fs::read_dir(&f.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let before = files();
    assert!(matches!(
        f.create_with_deadline(Instant::now() - Duration::from_millis(1)),
        Err(PortError::WriterBusy(reason)) if reason == "control runtime deadline reached"
    ));
    assert_eq!(files(), before, "expired create must leave no intent or DB");
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = prepare::<()>(&f.control, end, || {
            calls += 1;
            panic!("synthetic fixture preparation unwind");
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(calls, 2);
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    assert_eq!(
        prepare(&f.control, end, || f.control.status())
            .unwrap()
            .policy
            .control_seq
            .get(),
        4
    );
}

#[test]
fn crash_before_activation_resumes_a_pristine_managed_catalog() {
    let f = Fixture::new();
    drop(ManagedStore::create(&f.catalog, &f.control, id("inc-one"), 1).unwrap());
    // Simulate a crash between schema initialization and activation: the
    // managed application id stays, but no identity was committed.
    let conn = Connection::open(&f.catalog).unwrap();
    conn.execute_batch(
        "DELETE FROM catalog_meta;
         UPDATE store_metadata SET managed_mode=0, projection_contract_version=0;",
    )
    .unwrap();
    drop(conn);
    drop(ManagedStore::create(&f.catalog, &f.control, id("inc-two"), 2).unwrap());
    let reopened = ManagedStore::open(&f.catalog, &f.control).unwrap();
    assert_eq!(
        *reopened.incarnation(),
        id("inc-two"),
        "resumed creation must commit the new incarnation"
    );
}

#[test]
fn repeated_create_is_idempotent_for_the_same_incarnation_only() {
    let f = Fixture::new();
    drop(ManagedStore::create(&f.catalog, &f.control, id("inc-same"), 1).unwrap());
    drop(
        ManagedStore::create(&f.catalog, &f.control, id("inc-same"), 1)
            .expect("identical create retry adopts the activated catalog"),
    );
    assert!(matches!(
        ManagedStore::create(&f.catalog, &f.control, id("inc-other"), 2),
        Err(PortError::GenerationMismatch(_))
    ));
}

#[test]
fn create_refuses_an_existing_catalog_without_its_creation_intent() {
    let f = Fixture::new();
    drop(ManagedStore::create(&f.catalog, &f.control, id("inc-marker"), 1).unwrap());
    let mut marker = f.catalog.as_os_str().to_os_string();
    marker.push(".asg-managed-create");
    std::fs::remove_file(std::path::PathBuf::from(marker)).unwrap();
    assert!(ManagedStore::create(&f.catalog, &f.control, id("inc-marker"), 1).is_err());
}

#[test]
fn managed_publication_outbox_and_receipt_are_atomic_and_legacy_is_hidden() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    let publication = store
        .commit_source(
            &f.control,
            &worker,
            &f.batch("original proof"),
            &f.observation,
        )
        .unwrap();
    assert!(publication.content_changed);
    assert_eq!(publication.receipt.committed_generation, Some(1));
    assert_eq!(
        f.scalar("SELECT count(*) FROM index_batches WHERE state='activated'"),
        1
    );
    assert_eq!(f.scalar("SELECT count(*) FROM catalog"), 0);
    let texts = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            Instant::now() + Duration::from_secs(5),
            |r| {
                assert_eq!(r.snapshot().generation, 1);
                Ok(r.query_lexical("proof", &ProjectionQuery::default(), 5)?
                    .hits
                    .into_iter()
                    .map(|h| h.projection.message.text)
                    .collect::<Vec<_>>())
            },
        )
        .unwrap();
    assert_eq!(texts, vec!["original proof"]);
    drop(store);
    assert!(matches!(
        SqliteStore::open(f.catalog.to_str().unwrap()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(ManagedStore::open(&f.catalog, &f.control).is_ok());
}

#[test]
fn no_op_observation_updates_receipt_without_new_generation_or_outbox() {
    let f = Fixture::new();
    let store = f.create();
    let batch = f.batch("same proof");
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    store
        .commit_source(&f.control, &worker, &batch, &f.observation)
        .unwrap();
    let mut observed = f.observation.clone();
    observed.revision_id = RevisionId::parse("revision-two").unwrap();
    let second = store
        .commit_source(&f.control, &worker, &batch, &observed)
        .unwrap();
    assert!(!second.content_changed);
    assert_eq!(second.receipt.committed_generation, Some(1));
    assert_eq!(f.scalar("SELECT count(*) FROM index_batches"), 1);
    assert_eq!(f.scalar("SELECT count(*) FROM source_revision_receipts"), 2);
    let read = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            Instant::now() + Duration::from_secs(5),
            |r| r.source_progress(),
        )
        .unwrap();
    assert_eq!(
        read[0].latest_receipt.as_ref().unwrap().revision_id,
        observed.revision_id
    );
}

#[test]
fn plain_baselines_refuse_catalog_contention_at_once_and_honor_an_expired_outer_end() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    store
        .commit_source(
            &f.control,
            &worker,
            &f.batch("original evidence survives a refused baseline read"),
            &f.observation,
        )
        .unwrap();
    drop(store);

    // Rollback journal mode makes this real SQLite writer block catalog reads.
    // All setup ends before the caller's measured deadline begins.
    let blocker = Connection::open(&f.catalog).unwrap();
    let mode: String = blocker
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    let catalog_before = std::fs::read(&f.catalog).unwrap();
    let control_before = f.control.status().unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let started = Instant::now();
    let original_end = started + Duration::from_secs(1);
    let refused = f.control.with_runtime_deadline(original_end, || {
        store.current_plain_baselines(&f.control, original_end + Duration::from_secs(5))
    });
    let elapsed = started.elapsed();
    assert!(
        matches!(refused, Err(PortError::WriterBusy(reason)) if reason == "managed catalog is busy"),
        "the real catalog lock must cause the refusal",
    );
    // Without the SQL deadline scope the catalog would wait its 250 ms busy timeout.
    assert!(elapsed < Duration::from_millis(200), "elapsed: {elapsed:?}");
    let history = ExclusiveGuard::try_acquire(&f.root, LockKind::HistoryReaders).unwrap();
    drop(history);
    assert_eq!(f.control.status().unwrap(), control_before);
    assert_eq!(std::fs::read(&f.catalog).unwrap(), catalog_before);

    blocker.execute_batch("ROLLBACK").unwrap();
    // The same unlocked call succeeds below. Inside a caller scope whose end
    // has already passed, a fresh 5 s budget must not let it run.
    let outer_end = Instant::now() + Duration::from_millis(200);
    let mut inner = None;
    let outer = f.control.with_runtime_deadline(outer_end, || {
        while Instant::now() < outer_end {
            std::thread::sleep(outer_end.saturating_duration_since(Instant::now()));
        }
        let fresh_budget = Instant::now() + Duration::from_secs(5);
        inner = Some(store.current_plain_baselines(&f.control, fresh_budget));
        Ok(())
    });
    assert!(outer.is_err());
    let inner = inner.expect("the outer scope admits the call before its end");
    assert!(
        matches!(inner, Err(PortError::WriterBusy(reason))
            if reason == "control runtime deadline reached"),
        "the expired outer end must refuse the nested call",
    );
    assert!(
        store
            .current_plain_baselines(&f.control, Instant::now() + Duration::from_secs(5))
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.control.status().unwrap(), control_before);
    assert_eq!(std::fs::read(&f.catalog).unwrap(), catalog_before);
    store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            Instant::now() + Duration::from_secs(5),
            |read| {
                let original = read
                    .messages(&[entity(IdKind::Message)], &ProjectionQuery::default())?
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    original.message.text,
                    "original evidence survives a refused baseline read",
                );
                assert_eq!(
                    original.proof.revision.revision_id,
                    f.observation.revision_id
                );
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn partial_and_pause_cannot_publish_new_evidence() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    let mut observation = f.observation.clone();
    observation.state = ObservationState::Incomplete;
    let partial = store
        .commit_source(&f.control, &worker, &f.batch("not published"), &observation)
        .unwrap();
    assert!(!partial.receipt.published);
    assert_eq!(f.scalar("SELECT count(*) FROM source_projections"), 0);
    assert_eq!(f.scalar("SELECT count(*) FROM index_batches"), 0);
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    assert!(
        store
            .commit_source(
                &f.control,
                &worker,
                &f.batch("still not published"),
                &f.observation
            )
            .is_err()
    );
    assert_eq!(f.scalar("SELECT count(*) FROM source_revision_receipts"), 1);
    drop(store);
    assert!(ManagedStore::open_for_write(&f.catalog, &f.control).is_err());
    assert!(ManagedStore::open(&f.catalog, &f.control).is_ok());
}

#[test]
fn failed_apply_keeps_only_building_intent_and_reopen_aborts_it() {
    let f = Fixture::new();
    let store = f.create();
    let conn = Connection::open(&f.catalog).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_real_apply BEFORE INSERT ON source_projections WHEN EXISTS(SELECT 1 FROM index_batches WHERE state='building') BEGIN SELECT RAISE(ABORT,'synthetic apply failure'); END;").unwrap();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    assert!(
        store
            .commit_source(
                &f.control,
                &worker,
                &f.batch("rollback proof"),
                &f.observation
            )
            .is_err()
    );
    assert_eq!(f.scalar("SELECT count(*) FROM source_revision_receipts"), 0);
    assert_eq!(f.scalar("SELECT count(*) FROM source_bindings"), 0);
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 0);
    assert_eq!(
        f.scalar("SELECT count(*) FROM index_batches WHERE state='building'"),
        1
    );
    conn.execute_batch("DROP TRIGGER fail_real_apply").unwrap();
    drop(conn);
    drop(store);
    let reopened = ManagedStore::open_for_write(&f.catalog, &f.control).unwrap();
    assert_eq!(
        f.scalar("SELECT count(*) FROM index_batches WHERE state='aborted'"),
        1
    );
    reopened
        .commit_source(
            &f.control,
            &worker,
            &f.batch("rollback proof"),
            &f.observation,
        )
        .unwrap();
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 1);
}

#[test]
fn wrong_control_root_and_maintenance_cannot_open_or_write() {
    let f = Fixture::new();
    let store = f.create();
    let other = Fixture::new();
    assert!(ManagedStore::open(&f.catalog, &other.control).is_err());
    let wrong_worker = other
        .control
        .bind_worker(&other.worker_lock, id("boot-one"))
        .unwrap();
    assert!(
        store
            .commit_source(
                &f.control,
                &wrong_worker,
                &f.batch("cross root"),
                &f.observation
            )
            .is_err()
    );
    let owner = id("maintenance-owner");
    f.control
        .set_maintenance(
            current(&f.control),
            &owner,
            MaintenanceFence {
                state: MaintenanceState::Updating,
                owner: Some(owner.clone()),
                phase: Some(MaintenancePhase::Reconciling),
            },
        )
        .unwrap();
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    assert!(
        store
            .with_read(
                &f.control,
                RequestIntersection::Selected,
                Instant::now() + Duration::from_secs(5),
                |r| Ok(r.snapshot().clone())
            )
            .is_err()
    );
    assert!(matches!(
        ExclusiveGuard::try_acquire(&f.root, LockKind::CatalogHandles),
        Err(PortError::WriterBusy(_))
    ));
    drop(store);
    drop(acquire(&f.root, LockKind::CatalogHandles));
}

#[test]
fn partial_attempt_pins_namespace_across_reopen_without_publishing_content() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
        &f.observation.binding.source_path,
        "claude-code",
    );
    let namespace = store
        .reserve_namespace(&f.control, &f.observation, &worker, &legacy)
        .unwrap();
    let mut partial = f.observation.clone();
    partial.binding.namespace_id = Some(namespace.namespace_id.clone());
    partial.state = ObservationState::Incomplete;
    store
        .commit_source(&f.control, &worker, &f.batch("not yet evidence"), &partial)
        .unwrap();
    assert_eq!(f.scalar("SELECT count(*) FROM installation_namespaces"), 1);
    assert_eq!(f.scalar("SELECT count(*) FROM source_projections"), 0);
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 0);
    drop(store);
    let reopened = ManagedStore::open_for_write(&f.catalog, &f.control).unwrap();
    let next = reopened
        .reserve_namespace(&f.control, &partial, &worker, &legacy)
        .unwrap();
    assert_eq!(next.namespace_id, namespace.namespace_id);
    assert_eq!(next.input, namespace.input);
    let mut complete = partial;
    complete.state = ObservationState::Complete;
    complete.revision_id = RevisionId::parse("complete-after-reopen").unwrap();
    reopened
        .commit_source(
            &f.control,
            &worker,
            &f.batch("verified after reopen"),
            &complete,
        )
        .unwrap();
    let hits = reopened
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            Instant::now() + Duration::from_secs(5),
            |r| r.query_lexical("verified", &ProjectionQuery::default(), 5),
        )
        .unwrap();
    assert_eq!(hits.hits.len(), 1);
    assert_eq!(f.scalar("SELECT count(*) FROM installation_namespaces"), 1);
}

#[test]
fn managed_setup_reservation_blocks_legacy_adoption_before_activation() {
    let f = Fixture::new();
    // Model a crash after the new file's identity was durably reserved, before
    // schema setup. The reserved header must never become a legacy catalog.
    let conn = Connection::open(&f.catalog).unwrap();
    conn.pragma_update(None, "application_id", 0x41534732_i64)
        .unwrap();
    drop(conn);
    let before = std::fs::read(&f.catalog).unwrap();
    assert!(matches!(
        SqliteStore::open_for_write(f.catalog.to_str().unwrap()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(std::fs::read(&f.catalog).unwrap(), before);
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    assert!(ManagedStore::create(&f.catalog, &f.control, id("catalog-one"), 1).is_err());
    assert_eq!(std::fs::read(&f.catalog).unwrap(), before);
}

#[test]
fn creation_intent_blocks_legacy_even_before_sqlite_header_exists() {
    let f = Fixture::new();
    let marker = f.root.join("catalog.db.asg-managed-create");
    std::fs::write(&marker, []).unwrap();
    // A crash before database creation leaves only the durable intent.
    assert!(matches!(
        SqliteStore::open_for_write(f.catalog.to_str().unwrap()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert!(!f.catalog.exists());
    let unrelated = f.root.join("unrelated.db");
    drop(SqliteStore::open_for_write(unrelated.to_str().unwrap()).unwrap());
    // A crash after create_new but before application_id leaves an empty file.
    std::fs::write(&f.catalog, []).unwrap();
    for result in [
        SqliteStore::open(f.catalog.to_str().unwrap()),
        SqliteStore::open_for_write(f.catalog.to_str().unwrap()),
        SqliteStore::open_for_relocation(f.catalog.to_str().unwrap()),
    ] {
        assert!(matches!(result, Err(PortError::SchemaIncompatible(_))));
    }
    assert_eq!(std::fs::metadata(&f.catalog).unwrap().len(), 0);
    assert!(marker.exists());
}

#[cfg(windows)]
#[test]
fn windows_aliases_cannot_separate_database_from_creation_intent() {
    let f = Fixture::new();
    for name in [
        "catalog.db.",
        "catalog.db ",
        "catalog.db:history",
        "catalog.db::$DATA",
        "CON.db",
        "LPT¹.db",
    ] {
        let path = f.root.join(name);
        assert!(
            ManagedStore::create(&path, &f.control, id("catalog-one"), 1).is_err(),
            "{name}"
        );
        assert!(!f.catalog.exists(), "{name} created the ordinary catalog");
        assert!(!f.root.join("catalog.db.asg-managed-create").exists());
        assert!(
            SqliteStore::open_for_write(path.to_str().unwrap()).is_err(),
            "{name}"
        );
        assert!(!f.catalog.exists());
    }
    std::fs::write(f.root.join("catalog.db.asg-managed-create"), []).unwrap();
    std::fs::write(&f.catalog, []).unwrap();
    for name in ["catalog.db.", "catalog.db ", "catalog.db:history"] {
        assert!(SqliteStore::open_for_write(f.root.join(name).to_str().unwrap()).is_err());
    }
    assert_eq!(std::fs::metadata(&f.catalog).unwrap().len(), 0);
}

#[test]
fn latest_requires_same_snapshot_discovery_and_exact_published_receipts() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    store.reconcile_progress(&f.control, &worker).unwrap();
    let proof = &f.observation.selections[0];
    let selection = SelectionRevision {
        selection_id: id(&proof.selection_id),
        revision: ControlSeq::new(proof.selection_revision).unwrap(),
        root_identity: id(&proof.root_identity),
    };
    let barrier = match f
        .control
        .admit_latest(
            current(&f.control),
            LatestRequest {
                selections: vec![selection.clone()],
                max_wait_ms: 5000,
                now_ms: 4,
            },
        )
        .unwrap()
        .value
    {
        LatestAdmission::Queued(b) => b,
        _ => panic!("expected latest admission"),
    };
    let cycle = f
        .control
        .start_cycle(current(&f.control), &worker, barrier.required_cycle_seq, 5)
        .unwrap()
        .value;
    let mut observed = f.observation.clone();
    observed.cycle_seq = cycle.token.cycle_seq.get();
    observed.started_control_seq = cycle.started_control_seq.unwrap().get();
    let published = store
        .commit_source(&f.control, &worker, &f.batch("proof for latest"), &observed)
        .unwrap();
    let check = || {
        store
            .with_read(
                &f.control,
                RequestIntersection::Selected,
                Instant::now() + Duration::from_secs(5),
                |r| r.latest_satisfied(&barrier),
            )
            .unwrap()
    };
    assert!(
        !check(),
        "source receipt without completed discovery is insufficient"
    );
    store
        .begin_discovery(&f.control, &worker, &cycle, &selection, 6)
        .unwrap();
    store
        .begin_discovery(&f.control, &worker, &cycle, &selection, 6)
        .unwrap();
    assert!(!check(), "incomplete discovery never proves latest");
    store
        .commit_discovery(
            &f.control,
            &worker,
            &cycle,
            &selection,
            std::slice::from_ref(&observed.binding.source_id),
            6,
        )
        .unwrap();
    assert!(check());
    assert!(
        store
            .begin_discovery(&f.control, &worker, &cycle, &selection, 6)
            .is_err(),
        "a completed receipt cannot be reopened"
    );
    assert_eq!(
        f.scalar("SELECT active_generation FROM store_metadata"),
        published.receipt.committed_generation.unwrap()
    );
    store
        .commit_discovery(
            &f.control,
            &worker,
            &cycle,
            &selection,
            std::slice::from_ref(&observed.binding.source_id),
            7,
        )
        .unwrap();
    assert_eq!(f.scalar("SELECT count(*) FROM discovery_receipts"), 1);
    // A newer observed source revision invalidates the exact discovered set.
    let mut later = observed.clone();
    later.revision_id = RevisionId::parse("newer-receipt").unwrap();
    store
        .commit_source(&f.control, &worker, &f.batch("proof changed"), &later)
        .unwrap();
    assert!(!check());
    assert!(
        store
            .commit_discovery(
                &f.control,
                &worker,
                &cycle,
                &selection,
                std::slice::from_ref(&observed.binding.source_id),
                8
            )
            .is_err(),
        "completed discovery is immutable"
    );
    assert_eq!(f.scalar("SELECT count(*) FROM discovery_sources"), 1);
}

#[test]
fn catalog_progress_reconciliation_retains_pause_and_is_idempotent() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let policy = f.control.status().unwrap().policy;
    store.reconcile_progress(&f.control, &worker).unwrap();
    let after = f.control.status().unwrap();
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(after.policy.policy_epoch, policy.policy_epoch);
    assert_eq!(after.catalog_incarnation, Some(id("catalog-one")));
    assert!(
        f.control
            .cycle(CycleSeq::new(f.observation.cycle_seq).unwrap())
            .unwrap()
            .state
            == CycleState::Aborted
    );
    store.reconcile_progress(&f.control, &worker).unwrap();
    assert_eq!(f.control.status().unwrap(), after);
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 0);
}

#[test]
fn committed_source_acknowledgement_is_repaired_after_worker_restart_while_paused() {
    let f = Fixture::new();
    let store = f.create();
    {
        let worker = f
            .control
            .bind_worker(&f.worker_lock, id("boot-one"))
            .unwrap();
        store
            .commit_source(
                &f.control,
                &worker,
                &f.batch("committed before acknowledgement"),
                &f.observation,
            )
            .unwrap();
    }
    let source = id(f.observation.binding.source_id.as_str());
    assert!(f.control.source_progress(&source).unwrap().is_none());
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-two"))
        .unwrap();
    f.control
        .register_worker(current(&f.control), &worker, 2, 10)
        .unwrap();
    let policy = f.control.status().unwrap().policy;
    store.reconcile_progress(&f.control, &worker).unwrap();
    let progress = f.control.source_progress(&source).unwrap().unwrap();
    assert_eq!(
        progress.receipt.as_ref().unwrap().revision,
        id(f.observation.revision_id.as_str())
    );
    assert_eq!(
        progress.receipt.as_ref().unwrap().token.worker_boot_id,
        id("boot-one")
    );
    assert_eq!(
        progress.coverage,
        Coverage::Partial,
        "a recovered receipt is not a new observation"
    );
    assert_eq!(progress.update_state, UpdateState::Paused);
    let after = f.control.status().unwrap();
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(after.policy.policy_epoch, policy.policy_epoch);
    store.reconcile_progress(&f.control, &worker).unwrap();
    assert_eq!(f.control.status().unwrap(), after);
    assert_eq!(
        f.control.source_progress(&source).unwrap().unwrap(),
        progress
    );
}

#[test]
fn old_catalog_handle_cannot_reconcile_into_replacement_installation_in_same_root() {
    let f = Fixture::new();
    let store = f.create();
    let physical_root = f.worker_lock.root_identity();
    // Model replacement control identity without replacing the directory or
    // closing the old catalog handle. The new worker owns the real OS guard.
    {
        let connection = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
        connection.execute(
            "UPDATE control_meta SET installation_id='replacement-installation',catalog_incarnation='replacement-catalog'",
            [],
        ).unwrap();
    }
    let replacement = SqliteControlStore::open_current_writable(&f.root).unwrap();
    let worker = replacement
        .bind_worker(&f.worker_lock, id("replacement-boot"))
        .unwrap();
    replacement
        .register_worker(current(&replacement), &worker, 2, 10)
        .unwrap();
    let before = replacement.status().unwrap();
    let runtime_before = replacement.background_status().unwrap();
    let cycle_before = replacement
        .cycle(CycleSeq::new(f.observation.cycle_seq).unwrap())
        .unwrap();
    assert_eq!(f.worker_lock.root_identity(), physical_root);
    assert!(store.reconcile_progress(&replacement, &worker).is_err());
    assert_eq!(
        replacement.status().unwrap(),
        before,
        "failed reconciliation changed control identity or sequence"
    );
    assert_eq!(replacement.background_status().unwrap(), runtime_before);
    assert_eq!(
        replacement
            .cycle(CycleSeq::new(f.observation.cycle_seq).unwrap())
            .unwrap(),
        cycle_before
    );
    assert_eq!(
        replacement.status().unwrap().catalog_incarnation,
        Some(id("replacement-catalog"))
    );
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 0);
}

#[test]
fn repaired_old_ack_preserves_newer_failed_observation_and_pending_confirmation() {
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    store.reconcile_progress(&f.control, &worker).unwrap();
    let selected = f.control.status().unwrap().policy.selections[0].clone();
    let selection = SelectionRevision {
        selection_id: selected.id,
        revision: selected.revision,
        root_identity: selected.root_identity.unwrap(),
    };
    let start = |now| {
        let cycle = match f
            .control
            .queue_cycle(current(&f.control), vec![selection.clone()])
            .unwrap()
            .value
        {
            CycleAdmission::Queued(c) => c,
            _ => panic!("expected observation cycle"),
        };
        f.control
            .start_cycle(current(&f.control), &worker, cycle.token.cycle_seq, now)
            .unwrap()
            .value
    };
    let committed = start(10);
    let mut observation = f.observation.clone();
    observation.cycle_seq = committed.token.cycle_seq.get();
    observation.started_control_seq = committed.started_control_seq.unwrap().get();
    observation.observed_at_ms = 11;
    observation.committed_at_ms = 12;
    let publication = store
        .commit_source(
            &f.control,
            &worker,
            &f.batch("synthetic accepted"),
            &observation,
        )
        .unwrap();
    f.control
        .finish_cycle(
            current(&f.control),
            &worker,
            committed.token.cycle_seq,
            CycleFinish::Partial,
            13,
        )
        .unwrap();
    let later = start(14);
    let source = id(observation.binding.source_id.as_str());
    let prior = f
        .control
        .acknowledge_source(
            current(&f.control),
            &worker,
            SourceAcknowledgement {
                source_id: source.clone(),
                provider: observation.binding.provider,
                token: later.token.clone(),
                selection: selection.clone(),
                attempted_at_ms: 15,
                coverage: Coverage::Partial,
                update_state: UpdateState::Deferred,
                backfill_state: BackfillState::Pending,
                error: Some(BackgroundFailure::RewritePending),
                receipt: None,
                confirmation: Some(PendingConfirmation {
                    kind: ConfirmationKind::Rewrite {
                        candidate_digest: id("synthetic-candidate"),
                    },
                    first_cycle: later.token.cycle_seq,
                    confirm_cycle: None,
                    worker_boot_id: later.token.worker_boot_id.clone(),
                    root_identity: selection.root_identity,
                    policy_epoch: later.policy_epoch,
                    first_monotonic_ms: ControlSeq::new(1).unwrap(),
                }),
            },
        )
        .unwrap()
        .value;
    assert!(prior.receipt.is_none());
    store.reconcile_progress(&f.control, &worker).unwrap();
    let after = f.control.source_progress(&source).unwrap().unwrap();
    assert_eq!(after.last_observation, prior.last_observation);
    assert_eq!(after.last_attempt_at_ms, prior.last_attempt_at_ms);
    assert_eq!(after.confirmation, prior.confirmation);
    assert_eq!(after.error, prior.error);
    assert_eq!(after.update_state, prior.update_state);
    assert_eq!(after.coverage, prior.coverage);
    assert_eq!(after.backfill_state, prior.backfill_state);
    assert_eq!(
        after.receipt.as_ref().unwrap().revision,
        id(publication.receipt.revision_id.as_str())
    );
    let status = f.control.status().unwrap();
    store.reconcile_progress(&f.control, &worker).unwrap();
    assert_eq!(f.control.status().unwrap(), status);
    assert_eq!(f.control.source_progress(&source).unwrap().unwrap(), after);
}

#[test]
fn verified_recovery_retains_exact_original_evidence_while_paused() {
    use agent_session_grep_adapters_sqlite::{
        control::BackupPurpose,
        managed_locks::JobLockKey,
        managed_maintenance::{BackupOutcome, MaintenanceCatalog},
    };
    use agent_session_grep_application::{
        AppRequest,
        managed::{ManagedApp, ManagedPartial, ManagedRequestContext},
    };
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    store
        .commit_source(
            &f.control,
            &worker,
            &f.batch("retained original evidence"),
            &f.observation,
        )
        .unwrap();
    drop(store);
    let prefix = f._temp.path().join("installed");
    std::fs::create_dir(&prefix).unwrap();
    let installation_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
    );
    let owner_lock = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&owner_lock).unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    f.control
        .record_verified_installation_prefix(&prefix, &installation_lock, &bound, end)
        .unwrap();
    let installation = f
        .control
        .bind_installation(&prefix, &installation_lock)
        .unwrap();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    f.control
        .begin_maintenance(
            current(&f.control),
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
        &f.control,
        &installation,
        &id("recovery-owner"),
        &f.catalog,
        end,
    )
    .unwrap();
    assert!(matches!(
        catalog
            .create_backup(
                &f.control,
                &installation,
                &id("recovery-owner"),
                &id("proof-backup"),
                BackupPurpose::BetaRollback,
                6,
                end
            )
            .unwrap(),
        BackupOutcome::Created(_)
    ));
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("recovery-owner"),
            &id("catalog-one"),
            &id("recovered-catalog"),
            7,
            end,
        )
        .unwrap();
    drop(catalog);
    f.control
        .set_maintenance(
            current(&f.control),
            &id("recovery-owner"),
            MaintenanceFence::idle(),
        )
        .unwrap();
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    store
        .with_read(&f.control, RequestIntersection::Selected, end, |read| {
            let expired = || false;
            let app = ManagedApp::new(
                read,
                ManagedRequestContext {
                    intersection: ProjectionQuery::default(),
                    budget: agent_session_grep_application::ResponseBudget::default(),
                    now_ms: 10,
                    current_repo: None,
                    deadline_expired: &expired,
                },
            )
            .unwrap();
            let result = app
                .handle(AppRequest::Get {
                    id: entity(IdKind::Message),
                })
                .unwrap();
            assert!(result.partial.contains(&ManagedPartial::RetainedEvidence));
            assert_eq!(
                result.evidence[0].proof.revision.catalog_incarnation,
                "catalog-one"
            );
            assert_eq!(read.scope_freshness(&[])?.pending_sources, 1);
            assert_eq!(read.scope_freshness(&[])?.verified_sources, 0);
            assert_eq!(
                read.scope_freshness(&[])?.last_verified_observation_at_ms,
                None
            );
            assert!(read.retained_revision_allowed(&result.evidence[0].proof.revision)?);
            Ok(())
        })
        .unwrap();
    drop(store);
    let conn = Connection::open(&f.catalog).unwrap();
    conn.execute(
        "UPDATE source_revision_receipts SET catalog_incarnation='unrelated-origin'",
        [],
    )
    .unwrap();
    drop(conn);
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    assert!(
        store
            .with_read(&f.control, RequestIntersection::Selected, end, |read| read
                .scope_freshness(&[]))
            .is_err()
    );
}

#[test]
fn dependency_retention_keeps_original_evidence_old_receipt_and_live_request_then_converges() {
    use agent_session_grep_adapters_sqlite::managed_locks::SharedGuard;
    let f = Fixture::new();
    let store = f.create();
    let worker = f
        .control
        .bind_worker(&f.worker_lock, id("boot-one"))
        .unwrap();
    let batch = f.batch("unchanged original evidence survives history retention");
    let selected = f.control.status().unwrap().policy.selections[0].clone();
    let selection = SelectionRevision {
        selection_id: selected.id,
        revision: selected.revision,
        root_identity: id("source-root"),
    };
    let finish = |cycle: &ObservationCycle,
                  publication: &agent_session_grep_ports::managed::Publication| {
        f.control
            .acknowledge_source(
                current(&f.control),
                &worker,
                SourceAcknowledgement {
                    source_id: id(f.observation.binding.source_id.as_str()),
                    provider: SearchProvider::Claude,
                    token: cycle.token.clone(),
                    selection: selection.clone(),
                    attempted_at_ms: 3,
                    coverage: Coverage::Complete,
                    update_state: UpdateState::Idle,
                    backfill_state: BackfillState::Complete,
                    error: None,
                    receipt: Some(SourceReceiptSummary {
                        token: cycle.token.clone(),
                        revision: id(publication.receipt.revision_id.as_str()),
                        catalog_incarnation: id("catalog-one"),
                        catalog_generation: ControlSeq::new(1).unwrap(),
                    }),
                    confirmation: None,
                },
            )
            .unwrap();
        f.control
            .acknowledge_discovery(
                current(&f.control),
                &worker,
                DiscoveryAcknowledgement {
                    token: cycle.token.clone(),
                    selection: selection.clone(),
                    complete: true,
                    discovered_count: 1,
                    observed_count: 1,
                    committed_count: 1,
                    error: None,
                },
            )
            .unwrap();
        store
            .commit_discovery(
                &f.control,
                &worker,
                cycle,
                &selection,
                std::slice::from_ref(&f.observation.binding.source_id),
                4,
            )
            .unwrap();
        f.control
            .finish_cycle(
                current(&f.control),
                &worker,
                cycle.token.cycle_seq,
                CycleFinish::Committed,
                5,
            )
            .unwrap();
    };
    // Real startup first binds the control summary to the catalog, aborting
    // the fixture's pre-catalog cycle. New observations use a later token.
    let fixture_end = Instant::now() + Duration::from_secs(120);
    f.control
        .with_runtime_deadline(fixture_end, || {
            store.reconcile_progress(&f.control, &worker).unwrap();
            let CycleAdmission::Queued(first) = f
                .control
                .queue_cycle(current(&f.control), vec![selection.clone()])
                .unwrap()
                .value
            else {
                panic!("fixture cycle blocked")
            };
            let first = f
                .control
                .start_cycle(current(&f.control), &worker, first.token.cycle_seq, 2)
                .unwrap()
                .value;
            let mut first_observation = f.observation.clone();
            first_observation.cycle_seq = first.token.cycle_seq.get();
            first_observation.started_control_seq = first.started_control_seq.unwrap().get();
            let publication = store
                .commit_source(&f.control, &worker, &batch, &first_observation)
                .unwrap();
            finish(&first, &publication);
            for index in 2..=144 {
                let CycleAdmission::Queued(queued) = f
                    .control
                    .queue_cycle(current(&f.control), vec![selection.clone()])
                    .unwrap()
                    .value
                else {
                    panic!("fixture cycle blocked")
                };
                let cycle = f
                    .control
                    .start_cycle(current(&f.control), &worker, queued.token.cycle_seq, 2)
                    .unwrap()
                    .value;
                let mut observation = f.observation.clone();
                observation.revision_id =
                    RevisionId::parse(&format!("retention-receipt-{index}")).unwrap();
                observation.cycle_seq = cycle.token.cycle_seq.get();
                observation.started_control_seq = cycle.started_control_seq.unwrap().get();
                let publication = store
                    .commit_source(&f.control, &worker, &batch, &observation)
                    .unwrap();
                assert!(!publication.content_changed);
                finish(&cycle, &publication);
            }
            let reader = SharedGuard::try_acquire(&f.root, LockKind::HistoryReaders).unwrap();
            let before = f.scalar("SELECT count(*) FROM source_revision_receipts");
            assert!(matches!(
                store.retain_history(&f.control, &worker, Instant::now() + Duration::from_secs(5)),
                Err(PortError::WriterBusy(_))
            ));
            assert_eq!(
                f.scalar("SELECT count(*) FROM source_revision_receipts"),
                before
            );
            drop(reader);
            let mut pending = true;
            let original_seq = f.control.status().unwrap().policy.control_seq;
            for _ in 0..12 {
                let report = store
                    .retain_history(&f.control, &worker, Instant::now() + Duration::from_secs(5))
                    .unwrap();
                pending = report.has_more || report.control_pending;
                if !pending {
                    break;
                }
            }
            assert!(!pending, "bounded history batches failed to converge");
            assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 1);
            assert_eq!(f.scalar("SELECT destructive_epoch FROM store_metadata"), 0);
            assert_eq!(f.scalar("SELECT count(*) FROM index_batches"), 1);
            assert_eq!(f.scalar("SELECT count(*) FROM source_revision_receipts"), 3);
            assert_eq!(f.scalar("SELECT count(*) FROM discovery_receipts"), 1);
            let raw = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
            assert_eq!(
                raw.query_row("SELECT count(*) FROM cycles", [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                65
            );
            assert_eq!(f.control.status().unwrap().policy.control_seq, original_seq);
            assert_eq!(
                f.control
                    .cycle(first.token.cycle_seq)
                    .unwrap()
                    .token
                    .worker_boot_id,
                id("boot-one")
            );
            assert_eq!(
                f.control
                    .source_progress(&id("source-one"))
                    .unwrap()
                    .unwrap()
                    .receipt
                    .unwrap()
                    .revision,
                id("retention-receipt-144")
            );
            store
                .with_read(
                    &f.control,
                    RequestIntersection::Selected,
                    Instant::now() + Duration::from_secs(5),
                    |read| {
                        let result = read
                            .messages(&[entity(IdKind::Message)], &ProjectionQuery::default())?
                            .into_iter()
                            .next()
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            result.message.text,
                            "unchanged original evidence survives history retention"
                        );
                        assert_eq!(result.proof.revision.revision_id, f.observation.revision_id);
                        Ok(())
                    },
                )
                .unwrap();
            Ok(())
        })
        .unwrap();
    drop(store);
    let reopened = ManagedStore::open(&f.catalog, &f.control).unwrap();
    assert_eq!(
        reopened.background_sources(&f.control).unwrap()[0]
            .latest_receipt
            .as_ref()
            .unwrap()
            .revision_id,
        RevisionId::parse("retention-receipt-144").unwrap()
    );
}
