//! Real SQLite/WAL and OS-lock tests under synthetic private roots.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    control::{BackupPurpose, BackupRegistration, BackupState},
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind},
    managed_maintenance::{
        BackupAttention, BackupOutcome, MaintenanceCatalog, PurgeOutcome, RestoreOutcome,
        apply_restore, inspect_catalog_identity, inspect_restore_inventory, prepare_restore,
        prepare_restore_exact, purge_backup, verify_backup, verify_backup_until,
    },
    managed_store::ManagedStore,
};
use agent_session_grep_ports::{PortError, SearchProvider, control::*};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn id(v: &str) -> ControlId {
    ControlId::parse(v).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn assert_preparation_end(end: Instant) {
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(end + Duration::from_secs(1)),
        end
    );
}
fn prepare<T>(
    control: &SqliteControlStore,
    end: Instant,
    operation: impl FnOnce(Instant) -> Result<T, PortError>,
) -> Result<T, PortError> {
    let probe = end + Duration::from_secs(1);
    let previous = SqliteControlStore::effective_runtime_deadline(probe);
    let end = SqliteControlStore::effective_runtime_deadline(end);
    let result = control.with_runtime_deadline(end, || {
        assert_preparation_end(end);
        let result = operation(end);
        assert_preparation_end(end);
        result
    });
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe),
        previous
    );
    result
}
fn acquire(root: &Path, kind: LockKind) -> ExclusiveGuard {
    acquire_until(root, kind, end())
}
fn acquire_until(root: &Path, kind: LockKind, end: Instant) -> ExclusiveGuard {
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(g) => return g,
            Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(1))
            }
            e => panic!("lock: {e:?}"),
        }
    }
}
fn retry_expected_success<T>(
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    // These fixtures require success, but unrelated parallel tests can delay
    // the short default control runtime check even though each fixture owns
    // its root. Retry only typed contention inside one explicit bounded scope;
    // failure-path tests below keep asserting WriterBusy without this helper.
    let end = end();
    loop {
        match operation() {
            Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(5));
            }
            result => return result,
        }
    }
}
struct Fixture {
    root: PathBuf,
    prefix: PathBuf,
    catalog: PathBuf,
    control: SqliteControlStore,
    installation_lock: ExclusiveGuard,
    // Connections and OS guards must close before Windows temp cleanup.
    _tmp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let preparation_end = end();
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("data");
        let prefix = temp.path().join("install");
        std::fs::create_dir(&prefix).unwrap();
        let control = SqliteControlStore::create_with_deadline(
            &root,
            &id("installation"),
            DesiredUpdates::Running,
            preparation_end,
        )
        .unwrap();
        let catalog = root.join("catalog.db");
        let installation_lock = acquire_until(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
            preparation_end,
        );
        let mut preparation_calls = 0;
        prepare(&control, preparation_end, |end| {
            preparation_calls += 1;
            prepare_catalog_and_prefix(&control, &root, &catalog, &prefix, &installation_lock, end)
        })
        .unwrap();
        assert_eq!(preparation_calls, 1);
        Self {
            _tmp: temp,
            root,
            prefix,
            catalog,
            control,
            installation_lock,
        }
    }
    fn fence(&self, owner: &str) {
        // Parallel fixtures contend on real OS/SQLite setup even though each
        // uses its own private root. Give setup one explicit bounded scope;
        // tests that assert caller deadlines still pass their own short ends.
        retry_expected_success(|| {
            self.control.with_runtime_deadline(end(), || {
                let installation = self
                    .control
                    .bind_installation(&self.prefix, &self.installation_lock)?;
                let lock = acquire(&self.root, LockKind::PolicyOwner);
                let bound = self.control.bind_control_root(&lock)?;
                self.control.begin_maintenance(
                    self.control.status()?.policy.control_seq,
                    &id(owner),
                    &bound,
                    &installation,
                    MaintenanceFence {
                        state: MaintenanceState::Updating,
                        owner: Some(id(owner)),
                        phase: Some(MaintenancePhase::Quiescing),
                    },
                )?;
                Ok(())
            })
        })
        .unwrap();
    }
    fn backup(&self) -> agent_session_grep_adapters_sqlite::managed_maintenance::BackupMetadata {
        let outcome = retry_expected_success(|| {
            let installation = self
                .control
                .bind_installation(&self.prefix, &self.installation_lock)?;
            let catalog = MaintenanceCatalog::open_authorized(
                &self.control,
                &installation,
                &id("owner"),
                &self.catalog,
                end(),
            )?;
            catalog.create_backup(
                &self.control,
                &installation,
                &id("owner"),
                &id("backup"),
                BackupPurpose::BetaRollback,
                2,
                end(),
            )
        })
        .unwrap();
        let BackupOutcome::Created(metadata) = outcome else {
            panic!("backup refused")
        };
        metadata
    }
}
fn prepare_catalog_and_prefix(
    control: &SqliteControlStore,
    root: &Path,
    catalog: &Path,
    prefix: &Path,
    installation_lock: &ExclusiveGuard,
    end: Instant,
) -> Result<(), PortError> {
    assert_preparation_end(end);
    drop(ManagedStore::create(
        catalog,
        control,
        id("original_incarnation"),
        1,
    )?);
    let guard = acquire_until(root, LockKind::PolicyOwner, end);
    let bound = control.bind_control_root(&guard)?;
    control.record_verified_installation_prefix(prefix, installation_lock, &bound, end)?;
    assert_preparation_end(end);
    Ok(())
}
#[test]
fn fixture_catalog_preparation_missing_scope_or_expired_end_has_no_effects() {
    let f = Fixture::new();
    let requested_end = end();
    let probe = requested_end + Duration::from_secs(1);
    let catalog = f.root.join("uncreated-catalog.db");
    let before = prepare(&f.control, requested_end, |_| f.control.status()).unwrap();
    let missing_scope = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = prepare_catalog_and_prefix(
            &f.control,
            &f.root,
            &catalog,
            &f.prefix,
            &f.installation_lock,
            requested_end,
        );
    }));
    assert!(missing_scope.is_err());
    let mut preparation_calls = 0;
    let expired = prepare(&f.control, Instant::now(), |end| {
        preparation_calls += 1;
        prepare_catalog_and_prefix(
            &f.control,
            &f.root,
            &catalog,
            &f.prefix,
            &f.installation_lock,
            end,
        )
    });
    assert!(matches!(expired, Err(PortError::WriterBusy(_))));
    assert_eq!(preparation_calls, 0);
    assert!(!catalog.exists());
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    assert_eq!(
        prepare(&f.control, requested_end, |_| f.control.status()).unwrap(),
        before
    );
}
#[test]
fn normal_open_stays_closed_while_authorized_maintenance_works() {
    let f = Fixture::new();
    f.fence("owner");
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    let installation =
        retry_expected_success(|| f.control.bind_installation(&f.prefix, &f.installation_lock))
            .unwrap();
    let catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    assert_eq!(catalog.identity().incarnation, id("original_incarnation"));
    assert!(
        MaintenanceCatalog::open_authorized(
            &f.control,
            &installation,
            &id("other"),
            &f.catalog,
            Instant::now() + Duration::from_millis(25)
        )
        .is_err()
    );
}
#[test]
fn exclusive_gate_proves_drain_before_any_catalog_maintenance() {
    let f = Fixture::new();
    let reader = ManagedStore::open(&f.catalog, &f.control).unwrap();
    f.fence("owner");
    let installation =
        retry_expected_success(|| f.control.bind_installation(&f.prefix, &f.installation_lock))
            .unwrap();
    let started = Instant::now();
    assert!(
        MaintenanceCatalog::open_authorized(
            &f.control,
            &installation,
            &id("owner"),
            &f.catalog,
            started + Duration::from_millis(30)
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(150));
    drop(reader);
    assert!(
        MaintenanceCatalog::open_authorized(
            &f.control,
            &installation,
            &id("owner"),
            &f.catalog,
            end()
        )
        .is_ok()
    );
}
#[test]
fn real_same_root_guard_and_journal_owner_are_required_for_nonce_adoption() {
    let f = Fixture::new();
    f.fence("previous");
    let installation =
        retry_expected_success(|| f.control.bind_installation(&f.prefix, &f.installation_lock))
            .unwrap();
    let lock = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&lock).unwrap();
    let fence = MaintenanceFence {
        state: MaintenanceState::Recovering,
        owner: Some(id("new")),
        phase: Some(MaintenancePhase::Reconciling),
    };
    assert!(
        f.control
            .begin_maintenance(
                f.control.status().unwrap().policy.control_seq,
                &id("new"),
                &bound,
                &installation,
                fence.clone()
            )
            .is_err()
    );
    assert!(
        f.control
            .recover_maintenance(
                f.control.status().unwrap().policy.control_seq,
                &id("new"),
                &bound,
                &installation,
                &id("wrong"),
                fence.clone()
            )
            .is_err()
    );
    f.control
        .recover_maintenance(
            f.control.status().unwrap().policy.control_seq,
            &id("new"),
            &bound,
            &installation,
            &id("previous"),
            fence,
        )
        .unwrap();
    assert_eq!(
        f.control.status().unwrap().policy.maintenance.owner,
        Some(id("new"))
    );
    let other = acquire(&f.root, LockKind::Background);
    assert!(f.control.bind_installation(&f.prefix, &other).is_err());
    assert!(f.control.bind_control_root(&f.installation_lock).is_err());
    assert!(
        ExclusiveGuard::try_acquire(
            &f.prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap())
        )
        .is_err()
    );
}
#[test]
fn logical_wal_backup_is_bound_and_never_copies_control_pause() {
    let f = Fixture::new();
    let raw = rusqlite::Connection::open(&f.catalog).unwrap();
    raw.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    raw.execute(
        "UPDATE store_metadata SET active_generation=7 WHERE singleton=1",
        [],
    )
    .unwrap();
    let mut wal = f.catalog.as_os_str().to_os_string();
    wal.push("-wal");
    assert!(std::fs::metadata(PathBuf::from(wal)).unwrap().len() > 0);
    f.fence("owner");
    let meta = f.backup();
    drop(raw);
    assert_eq!(meta.catalog_generation, 7);
    let path = f.root.join(&meta.relative_locator);
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row("SELECT active_generation FROM store_metadata", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert!(
        conn.prepare("SELECT desired_updates FROM control_meta")
            .is_err()
    );
    drop(conn);
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    let verified = verify_backup(&f.control, &id("backup")).unwrap();
    assert_eq!(verified.metadata().digest, meta.digest);
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let restored = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &id("backup"),
        &id("fresh_incarnation"),
        &f.root.join("restore.db"),
        end(),
    )
    .unwrap();
    assert!(matches!(restored, RestoreOutcome::Prepared(_)));
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
}
#[test]
fn interrupted_backup_is_owned_before_content_and_is_not_silently_overwritten() {
    let f = Fixture::new();
    f.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    assert!(
        catalog
            .create_backup(
                &f.control,
                &installation,
                &id("owner"),
                &id("expired"),
                BackupPurpose::BetaRollback,
                2,
                Instant::now()
            )
            .is_err()
    );
    assert!(f.control.backup_records().unwrap().is_empty());
    // Simulate an interruption after the durable registration and first bytes.
    // The owner intent is real; only the provider-free partial bytes are synthetic.
    let registration = BackupRegistration {
        backup_id: id("partial"),
        purpose: BackupPurpose::BetaRollback,
        relative_locator: "backups/partial/catalog.db".into(),
        catalog_incarnation: id("original_incarnation"),
        catalog_generation: 0,
        schema_version: catalog.identity().schema,
        source_ids: vec![],
    };
    {
        let guard = acquire(&f.root, LockKind::PolicyOwner);
        let bound = retry_expected_success(|| f.control.bind_control_root(&guard)).unwrap();
        retry_expected_success(|| {
            f.control.register_backup(
                f.control.status().unwrap().policy.control_seq,
                &id("owner"),
                &bound,
                &installation,
                &registration,
                2,
            )
        })
        .unwrap();
    }
    let path = f.root.join(&registration.relative_locator);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [f.root.join("backups"), path.parent().unwrap().to_path_buf()] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    std::fs::write(&path, b"synthetic interrupted logical backup").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let content = std::fs::read(&path).unwrap();
    assert!(matches!(
        catalog
            .create_backup(
                &f.control,
                &installation,
                &id("owner"),
                &id("partial"),
                BackupPurpose::BetaRollback,
                2,
                end()
            )
            .unwrap(),
        BackupOutcome::Attention(_)
    ));
    assert_eq!(std::fs::read(path).unwrap(), content);
    assert_eq!(
        f.control.backup_records().unwrap().pop().unwrap().state,
        BackupState::Registered
    );
}
#[test]
fn unsupported_reserved_rows_and_dangling_links_fail_closed() {
    let f = Fixture::new();
    let raw = rusqlite::Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    raw.execute(
        "INSERT INTO artifact_sources(artifact_id,source_id) VALUES('ghost','source')",
        [],
    )
    .unwrap();
    assert!(f.control.status().is_err());
    raw.execute("DELETE FROM artifact_sources", []).unwrap();
    assert!(f.control.status().is_ok());
    raw.execute("INSERT INTO private_artifacts VALUES('bad','unknown','backups/bad/catalog.db',0,'owner','registered',NULL)",[]).unwrap();
    assert!(f.control.status().is_err());
}

fn source_locator(relative: &str) -> CanonicalLocator {
    #[cfg(windows)]
    let absolute = format!(r"C:\synthetic\{}", relative.replace('/', "\\"));
    #[cfg(not(windows))]
    let absolute = format!("/synthetic/{relative}");
    CanonicalLocator::parse(&absolute).unwrap()
}

fn select(f: &Fixture, relative: &str, kind: RootKind) -> Selection {
    retry_expected_success(|| {
        f.control.add_selection(
            f.control.status()?.policy.control_seq,
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: source_locator(relative),
                    kind,
                },
                root_identity: Some(id("synthetic_source_root")),
                now_ms: 3,
            },
        )
    })
    .unwrap()
    .value
}

fn bind_source(f: &Fixture, source: &str, relative: &str) {
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute(
        "INSERT INTO source_bindings(source_id,source_path,provider_id,root_identity,bound_at_ms) VALUES(?1,?2,'claude-code','synthetic_source_root',1)",
        rusqlite::params![source, source_locator(relative).as_str()],
    ).unwrap();
}

fn recovery_discovery(f: &Fixture, as_of: bool, end: Instant) {
    prepare(&f.control, end, |end| {
        recovery_discovery_in_scope(f, as_of, end)
    })
    .unwrap();
}
fn recovery_discovery_in_scope(f: &Fixture, as_of: bool, end: Instant) -> Result<(), PortError> {
    use agent_session_grep_adapters_sqlite::{PARSER_SEMANTIC_VERSION, SourceBatch};
    use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
    use agent_session_grep_ports::managed::{
        ObservationState, RevisionId, SelectionProof, SourceBinding, SourceId, SourceObservation,
    };

    assert_preparation_end(end);
    let selected = f
        .control
        .add_selection(
            f.control.status()?.policy.control_seq,
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Claude,
                    locator: source_locator("selected"),
                    kind: RootKind::Root,
                },
                root_identity: Some(id("synthetic_source_root")),
                now_ms: 3,
            },
        )?
        .value;
    let selection = SelectionRevision {
        selection_id: selected.id.clone(),
        revision: selected.revision,
        root_identity: selected.root_identity.clone().unwrap(),
    };
    let lock = acquire_until(&f.root, LockKind::Background, end);
    let worker = f.control.bind_worker(&lock, id("recovery_boot"))?;
    f.control
        .register_worker(f.control.status()?.policy.control_seq, &worker, 1, 4)?;
    let store = ManagedStore::open_for_write(&f.catalog, &f.control)?;
    store.reconcile_progress(&f.control, &worker)?;
    let CycleAdmission::Queued(queued) = f
        .control
        .queue_cycle(
            f.control.status()?.policy.control_seq,
            vec![selection.clone()],
        )?
        .value
    else {
        panic!("fixture cycle refused")
    };
    let cycle = f
        .control
        .start_cycle(
            f.control.status()?.policy.control_seq,
            &worker,
            queued.token.cycle_seq,
            5,
        )?
        .value;
    let message = StableId::native_checked(IdKind::Message, "recovery_message").unwrap();
    let session = StableId::native_checked(IdKind::Session, "recovery_session").unwrap();
    let document = StableId::native_checked(IdKind::Document, "recovery_document").unwrap();
    let text = "  original recovery needle\n\tpreserve spaces  ";
    let observation = SourceObservation {
        binding: SourceBinding {
            source_id: SourceId::parse("recovery_source").unwrap(),
            source_path: source_locator("selected/source.jsonl").as_str().into(),
            provider: SearchProvider::Claude,
            namespace_id: None,
            root_identity: selection.root_identity.as_str().into(),
        },
        revision_id: RevisionId::parse("recovery_revision").unwrap(),
        revision_digest: "b".repeat(64),
        parser_version: PARSER_SEMANTIC_VERSION,
        state: ObservationState::Complete,
        cycle_seq: cycle.token.cycle_seq.get(),
        worker_boot_id: worker.boot_id().as_str().into(),
        catalog_incarnation: "original_incarnation".into(),
        policy_epoch: cycle.policy_epoch.get(),
        started_control_seq: cycle.started_control_seq.unwrap().get(),
        observed_at_ms: 6,
        committed_at_ms: 7,
        selections: vec![SelectionProof {
            selection_id: selection.selection_id.as_str().into(),
            selection_revision: selection.revision.get(),
            root_identity: selection.root_identity.as_str().into(),
        }],
        repositories: vec![],
    };
    let batch = SourceBatch {
        source_path: observation.binding.source_path.clone(),
        entries: vec![
            (
                message.clone(),
                serde_json::to_vec(
                    &serde_json::json!({"role":"user","text":text,"timestamp":null}),
                )
                .unwrap(),
                text.into(),
            ),
            (
                session.clone(),
                serde_json::to_vec(&serde_json::json!({"documents":[document.as_str()]})).unwrap(),
                String::new(),
            ),
            (
                document.clone(),
                serde_json::to_vec(&serde_json::json!({
                    "provider":"claude-code","variant":"synthetic-v1",
                    "fingerprint":observation.revision_digest,"len":100
                }))
                .unwrap(),
                String::new(),
            ),
        ],
        placements: vec![MessagePlacement::new(
            session, document, message, 0, false, None,
        )],
        edges: vec![],
        activities: vec![],
        usage_events: vec![],
        relation_complete: true,
        len_bytes: Some(100),
        fingerprint: Some(observation.revision_digest.clone()),
        provider_id: Some("claude-code".into()),
        resume_claims: vec![],
    };
    store.begin_discovery_with_deadline(&f.control, &worker, &cycle, &selection, end)?;
    store.commit_source_with_context(
        &f.control,
        &worker,
        &batch,
        &observation,
        &Default::default(),
        end,
    )?;
    store.commit_discovery_with_deadline(
        &f.control,
        &worker,
        &cycle,
        &selection,
        std::slice::from_ref(&observation.binding.source_id),
        end,
    )?;
    f.control.finish_cycle(
        f.control.status()?.policy.control_seq,
        &worker,
        cycle.token.cycle_seq,
        CycleFinish::Aborted,
        9,
    )?;
    if as_of {
        let CycleAdmission::Queued(queued) = f
            .control
            .queue_cycle(
                f.control.status()?.policy.control_seq,
                vec![selection.clone()],
            )?
            .value
        else {
            panic!("fixture epoch refused")
        };
        let later = f
            .control
            .start_cycle(
                f.control.status()?.policy.control_seq,
                &worker,
                queued.token.cycle_seq,
                10,
            )?
            .value;
        store.begin_discovery_with_deadline(&f.control, &worker, &later, &selection, end)?;
        // The real plain-epoch facade closes the later admitted cycle with the
        // original receipt, re-proving that the earlier cycle owns it.
        store.commit_discovery_epoch_with_deadline(
            &f.control,
            &worker,
            &later,
            &selection,
            std::slice::from_ref(&observation.binding.source_id),
            end,
        )?;
        // Both complete fences name the current head receipt, and that receipt
        // still belongs to the earlier cycle: the later fence is as-of.
        let first = rusqlite::types::Value::Integer(cycle.token.cycle_seq.get());
        let second = rusqlite::types::Value::Integer(later.token.cycle_seq.get());
        let yes = rusqlite::types::Value::Integer(1);
        assert!(later.token.cycle_seq.get() > cycle.token.cycle_seq.get());
        assert_eq!(
            recovery_rows(
                &f.catalog,
                "SELECT d.cycle_seq,d.complete,r.cycle_seq,r.revision_id=h.latest_receipt_id \
                 FROM discovery_receipts d JOIN discovery_sources s \
                 ON s.cycle_seq=d.cycle_seq AND s.selection_id=d.selection_id \
                 JOIN source_revision_receipts r ON r.revision_id=s.revision_id \
                 JOIN source_heads h ON h.source_id=s.source_id ORDER BY d.cycle_seq",
            ),
            vec![
                vec![first.clone(), yes.clone(), first.clone(), yes.clone()],
                vec![second, yes.clone(), first, yes],
            ]
        );
        f.control.finish_cycle(
            f.control.status()?.policy.control_seq,
            &worker,
            later.token.cycle_seq,
            CycleFinish::Aborted,
            11,
        )?;
    }
    assert_preparation_end(end);
    Ok(())
}

#[test]
fn fixture_discovery_preparation_keeps_one_end_and_single_effects() {
    for as_of in [false, true] {
        let f = Fixture::new();
        let outer = end();
        let probe = outer + Duration::from_secs(1);
        let mut preparation_calls = 0;
        f.control
            .with_runtime_deadline(outer, || {
                let before = f.control.status()?;
                prepare(&f.control, probe, |end| {
                    assert_eq!(end, outer);
                    preparation_calls += 1;
                    recovery_discovery_in_scope(&f, as_of, end)
                })?;
                assert_preparation_end(outer);
                let after = f.control.status()?;
                assert_eq!(
                    after.policy.selections.len(),
                    before.policy.selections.len() + 1
                );
                assert_eq!(
                    after.policy.policy_epoch.get(),
                    before.policy.policy_epoch.get() + 1
                );
                assert_eq!(after.desired_updates, before.desired_updates);
                Ok(())
            })
            .unwrap();
        assert_eq!(preparation_calls, 1);
        assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
        let count = if as_of { 2 } else { 1 };
        assert_eq!(
            recovery_rows(
                &SqliteControlStore::path(&f.root),
                "SELECT count(*),sum(state='aborted') FROM cycles",
            ),
            vec![vec![
                rusqlite::types::Value::Integer(count),
                rusqlite::types::Value::Integer(count),
            ]]
        );
        assert_eq!(
            recovery_rows(&f.catalog, "SELECT count(*) FROM source_revision_receipts"),
            vec![vec![rusqlite::types::Value::Integer(1)]]
        );
    }
}
#[test]
fn fixture_discovery_preparation_missing_scope_or_expired_end_has_no_effects() {
    let f = Fixture::new();
    let requested_end = end();
    let probe = requested_end + Duration::from_secs(1);
    let before = prepare(&f.control, requested_end, |_| f.control.status()).unwrap();
    let originals = recovery_originals(&f.catalog);
    let missing_scope = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = recovery_discovery_in_scope(&f, true, requested_end);
    }));
    assert!(missing_scope.is_err());
    let mut preparation_calls = 0;
    let expired = prepare(&f.control, Instant::now(), |end| {
        preparation_calls += 1;
        recovery_discovery_in_scope(&f, true, end)
    });
    assert!(matches!(expired, Err(PortError::WriterBusy(_))));
    assert_eq!(preparation_calls, 0);
    let failed: Result<(), PortError> = prepare(&f.control, requested_end, |_| {
        Err(PortError::InvalidRequest("fixture sentinel".into()))
    });
    assert!(matches!(failed, Err(PortError::InvalidRequest(_))));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), PortError> =
            prepare(&f.control, requested_end, |_| panic!("fixture sentinel"));
    }));
    assert!(unwind.is_err());
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    assert_eq!(
        prepare(&f.control, requested_end, |_| f.control.status()).unwrap(),
        before
    );
    assert_eq!(recovery_originals(&f.catalog), originals);
}

fn recovery_rows(path: &Path, query: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = conn.prepare(query).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn recovery_originals(path: &Path) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "source_bindings",
        "source_heads",
        "source_revision_receipts",
        "receipt_selection_claims",
        "source_scope_claims",
        "source_projections",
        "source_occurrences",
        "source_entity_projections",
        "source_session_projections",
        "source_scans",
        "source_publication_contexts",
        "source_context_heads",
        "index_batches",
    ]
    .iter()
    .map(|table| recovery_rows(path, &format!("SELECT * FROM {table} ORDER BY rowid")))
    .collect()
}

#[test]
fn normal_exact_discovery_open_preserves_original_content_and_proof() {
    let f = Fixture::new();
    recovery_discovery(&f, false, end());
    let originals = recovery_originals(&f.catalog);
    let discoveries = recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts");
    let members = recovery_rows(&f.catalog, "SELECT * FROM discovery_sources");
    assert_eq!(discoveries.len(), 1);
    assert_eq!(members.len(), 1);
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    drop(store);
    assert_eq!(recovery_originals(&f.catalog), originals);
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts"),
        discoveries
    );
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM discovery_sources"),
        members
    );
}

#[test]
fn owned_recovery_clears_as_of_discovery_and_replay_without_changing_original_receipts() {
    let f = Fixture::new();
    recovery_discovery(&f, true, end());
    let denied = select(&f, "denied", RootKind::Root);
    f.control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &denied.id,
            None,
            12,
        )
        .unwrap();
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    f.fence("owner");
    let originals = recovery_originals(&f.catalog);
    let discoveries = recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts");
    let members = recovery_rows(&f.catalog, "SELECT * FROM discovery_sources");
    assert_eq!(discoveries.len(), 2);
    assert_eq!(members.len(), 2);
    let before = f.control.status().unwrap();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            13,
            end(),
        )
        .unwrap();
    assert!(recovery_rows(&f.catalog, "SELECT * FROM discovery_sources").is_empty());
    assert!(recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts").is_empty());
    assert_eq!(recovery_originals(&f.catalog), originals);
    let after = f.control.status().unwrap();
    assert_eq!(after.desired_updates, before.desired_updates);
    assert_eq!(after.policy.selections, before.policy.selections);
    assert_eq!(after.policy.exclusions, before.policy.exclusions);
    assert_eq!(after.policy.revocations, before.policy.revocations);

    // Reproduce a pre-fix committed rotation whose disposable proof survived.
    let mut conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    let tx = conn.transaction().unwrap();
    for row in &discoveries {
        tx.execute(
            "INSERT INTO discovery_receipts(cycle_seq,selection_id,selection_revision,\
             worker_boot_id,policy_epoch,started_control_seq,catalog_incarnation,\
             root_identity,source_set_digest,complete,committed_generation) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params_from_iter(row),
        )
        .unwrap();
    }
    for row in &members {
        tx.execute(
            "INSERT INTO discovery_sources VALUES(?1,?2,?3,?4)",
            rusqlite::params_from_iter(row),
        )
        .unwrap();
    }
    tx.commit().unwrap();
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            14,
            end(),
        )
        .unwrap();
    assert!(recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts").is_empty());
    assert!(recovery_rows(&f.catalog, "SELECT * FROM discovery_sources").is_empty());
    assert_eq!(recovery_originals(&f.catalog), originals);
    assert_eq!(f.control.status().unwrap(), after);
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT destructive_epoch FROM store_metadata"),
        vec![vec![rusqlite::types::Value::Integer(1)]],
    );
}

#[test]
fn discovery_cleanup_refuses_wrong_owner_root_and_expired_nested_end_without_effects() {
    let f = Fixture::new();
    recovery_discovery(&f, true, end());
    let other = Fixture::new();
    f.fence("owner");
    other.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let other_installation = other
        .control
        .bind_installation(&other.prefix, &other.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    let before = f.control.status().unwrap();
    let originals = recovery_originals(&f.catalog);
    let discoveries = recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts");
    let members = recovery_rows(&f.catalog, "SELECT * FROM discovery_sources");
    assert!(
        catalog
            .clear_discovery_after_recovery(&f.control, &installation, &id("other_owner"), end(),)
            .is_err()
    );
    assert!(
        catalog
            .rotate_after_recovery(
                &f.control,
                &installation,
                &id("owner"),
                &id("original_incarnation"),
                &id("original_incarnation"),
                12,
                end(),
            )
            .is_err()
    );
    assert!(
        catalog
            .clear_discovery_after_recovery(
                &other.control,
                &other_installation,
                &id("owner"),
                end(),
            )
            .is_err()
    );
    assert!(
        f.control
            .with_runtime_deadline(Instant::now(), || {
                catalog.clear_discovery_after_recovery(
                    &f.control,
                    &installation,
                    &id("owner"),
                    end(),
                )
            })
            .is_err()
    );
    assert!(
        catalog
            .rotate_after_recovery(
                &f.control,
                &installation,
                &id("owner"),
                &id("original_incarnation"),
                &id("recovered"),
                12,
                Instant::now(),
            )
            .is_err()
    );
    assert_eq!(recovery_originals(&f.catalog), originals);
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts"),
        discoveries
    );
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM discovery_sources"),
        members
    );
    assert_eq!(f.control.status().unwrap(), before);
    assert_eq!(catalog.identity().incarnation, id("original_incarnation"));
}

#[test]
fn discovery_cleanup_rolls_back_both_tables_when_parent_delete_fails() {
    let f = Fixture::new();
    recovery_discovery(&f, true, end());
    f.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    let originals = recovery_originals(&f.catalog);
    let discoveries = recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts");
    let members = recovery_rows(&f.catalog, "SELECT * FROM discovery_sources");
    let before = f.control.status().unwrap();
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER refuse_discovery_delete BEFORE DELETE ON discovery_receipts
         BEGIN SELECT RAISE(ABORT,'synthetic deletion fault'); END;",
    )
    .unwrap();
    assert!(matches!(
        catalog.clear_discovery_after_recovery(&f.control, &installation, &id("owner"), end()),
        Err(PortError::SchemaIncompatible(_)),
    ));
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM discovery_sources"),
        members
    );
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts"),
        discoveries
    );
    assert_eq!(recovery_originals(&f.catalog), originals);
    assert_eq!(f.control.status().unwrap(), before);
    assert_eq!(catalog.identity().incarnation, id("original_incarnation"));
    conn.execute_batch("DROP TRIGGER refuse_discovery_delete")
        .unwrap();
    catalog
        .clear_discovery_after_recovery(&f.control, &installation, &id("owner"), end())
        .unwrap();
    let identity = catalog.identity().clone();
    let retained = recovery_rows(&f.catalog, "SELECT * FROM retained_source_receipts");
    catalog
        .clear_discovery_after_recovery(&f.control, &installation, &id("owner"), end())
        .unwrap();
    assert_eq!(catalog.identity(), &identity);
    assert_eq!(
        recovery_rows(&f.catalog, "SELECT * FROM retained_source_receipts"),
        retained,
    );
    assert!(recovery_rows(&f.catalog, "SELECT * FROM discovery_sources").is_empty());
    assert!(recovery_rows(&f.catalog, "SELECT * FROM discovery_receipts").is_empty());
    assert_eq!(recovery_originals(&f.catalog), originals);
    assert_eq!(f.control.status().unwrap(), before);
}

#[test]
fn installation_association_is_explicit_and_wrong_prefix_cannot_authorize_recovery() {
    let f = Fixture::new();
    let unbound_root = f._tmp.path().join("unbound");
    let unbound =
        SqliteControlStore::create(&unbound_root, &id("installation"), DesiredUpdates::Running)
            .unwrap();
    assert!(
        unbound
            .bind_installation(&f.prefix, &f.installation_lock)
            .is_err()
    );
    assert!(!unbound_root.join("installation-prefix.json").exists());
    let prefix_guard = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&prefix_guard).unwrap();
    let receipt_before = std::fs::read(f.root.join("installation-prefix.json")).unwrap();
    f.control
        .record_verified_installation_prefix(&f.prefix, &f.installation_lock, &bound, end())
        .unwrap();
    assert_eq!(
        receipt_before,
        std::fs::read(f.root.join("installation-prefix.json")).unwrap()
    );
    assert!(
        f.control
            .record_verified_installation_prefix(
                &f.prefix,
                &f.installation_lock,
                &bound,
                Instant::now()
            )
            .is_err()
    );
    let wrong_prefix = f._tmp.path().join("other_install");
    std::fs::create_dir(&wrong_prefix).unwrap();
    let wrong_lock = acquire(
        &wrong_prefix,
        LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
    );
    assert!(
        f.control
            .bind_installation(&wrong_prefix, &wrong_lock)
            .is_err()
    );
    assert!(
        f.control
            .record_verified_installation_prefix(&wrong_prefix, &wrong_lock, &bound, end())
            .is_err()
    );
    assert_eq!(
        receipt_before,
        std::fs::read(f.root.join("installation-prefix.json")).unwrap()
    );
    drop(prefix_guard);
    f.fence("owner");
    let right_installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let wrong_control_lock = acquire(&unbound_root, LockKind::PolicyOwner);
    let wrong_control = unbound.bind_control_root(&wrong_control_lock).unwrap();
    let before = f.control.status().unwrap();
    assert!(
        f.control
            .clear_maintenance(
                before.policy.control_seq,
                &id("owner"),
                &wrong_control,
                &right_installation
            )
            .is_err()
    );
    let same_id_other_installation = {
        let other_bound = unbound.bind_control_root(&wrong_control_lock).unwrap();
        unbound
            .record_verified_installation_prefix(
                &f.prefix,
                &f.installation_lock,
                &other_bound,
                end(),
            )
            .unwrap();
        unbound
            .bind_installation(&f.prefix, &f.installation_lock)
            .unwrap()
    };
    let right_policy_lock = acquire(&f.root, LockKind::PolicyOwner);
    let right_control = f.control.bind_control_root(&right_policy_lock).unwrap();
    assert!(
        f.control
            .clear_maintenance(
                before.policy.control_seq,
                &id("owner"),
                &right_control,
                &same_id_other_installation
            )
            .is_err()
    );
    assert_eq!(f.control.status().unwrap(), before);
    assert!(f.control.bind_control_root(&f.installation_lock).is_err());
    assert!(
        ExclusiveGuard::try_acquire(
            &f.prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap())
        )
        .is_err()
    );
}

#[test]
fn backup_and_rotation_reject_another_control_root_even_with_matching_installation_id() {
    let f = Fixture::new();
    let other = Fixture::new();
    f.fence("owner");
    other.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let other_installation = other
        .control
        .bind_installation(&other.prefix, &other.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    let before = f.control.status().unwrap();
    assert!(
        catalog
            .create_backup(
                &other.control,
                &other_installation,
                &id("owner"),
                &id("wrong_backup"),
                BackupPurpose::BetaRollback,
                5,
                end()
            )
            .is_err()
    );
    assert!(
        catalog
            .rotate_after_recovery(
                &other.control,
                &other_installation,
                &id("owner"),
                &id("original_incarnation"),
                &id("recovered"),
                5,
                end()
            )
            .is_err()
    );
    assert_eq!(catalog.identity().incarnation, id("original_incarnation"));
    assert_eq!(f.control.status().unwrap(), before);
    assert!(other.control.backup_records().unwrap().is_empty());
}

#[test]
fn manifest_reads_are_size_bounded_and_verification_keeps_callers_deadline() {
    let f = Fixture::new();
    f.fence("owner");
    let metadata = f.backup();
    let before = f.control.status().unwrap();
    let started = Instant::now();
    assert!(matches!(
        verify_backup_until(&f.control, &id("backup"), started),
        Err(PortError::WriterBusy(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(f.control.status().unwrap(), before);
    let manifest = f
        .root
        .join(&metadata.relative_locator)
        .parent()
        .unwrap()
        .join("manifest.json");
    let original = std::fs::read(&manifest).unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&manifest)
        .unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    drop(file);
    assert!(matches!(
        verify_backup(&f.control, &id("backup")),
        Err(PortError::SchemaIncompatible(_))
    ));
    std::fs::write(&manifest, &original).unwrap();
    assert!(verify_backup(&f.control, &id("backup")).is_ok());
    let db = f.root.join(&metadata.relative_locator);
    let mut sidecar = db.as_os_str().to_os_string();
    sidecar.push("-wal");
    std::fs::write(PathBuf::from(&sidecar), b"unverified synthetic sidecar").unwrap();
    assert!(matches!(
        verify_backup(&f.control, &id("backup")),
        Err(PortError::SchemaIncompatible(_))
    ));
    std::fs::remove_file(PathBuf::from(sidecar)).unwrap();
    assert!(verify_backup(&f.control, &id("backup")).is_ok());
}

#[test]
fn linked_backup_manifest_is_rejected_without_reading_another_inode() {
    let f = Fixture::new();
    f.fence("owner");
    let metadata = f.backup();
    let path = f
        .root
        .join(&metadata.relative_locator)
        .parent()
        .unwrap()
        .join("manifest.json");
    let alias = f.root.join("manifest_hardlink");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(verify_backup(&f.control, &id("backup")).is_err());
    std::fs::remove_file(&alias).unwrap();
    assert!(verify_backup(&f.control, &id("backup")).is_ok());
}

#[cfg(unix)]
#[test]
fn manifest_symlink_and_fifo_are_rejected_without_blocking() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    let f = Fixture::new();
    f.fence("owner");
    let metadata = f.backup();
    let path = f
        .root
        .join(&metadata.relative_locator)
        .parent()
        .unwrap()
        .join("manifest.json");
    let displaced = path.with_extension("original");
    std::fs::rename(&path, &displaced).unwrap();
    symlink(&displaced, &path).unwrap();
    assert!(verify_backup(&f.control, &id("backup")).is_err());
    std::fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    unsafe extern "C" {
        fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    }
    // SAFETY: name is a live NUL-terminated path; no pointer escapes this call.
    assert_eq!(unsafe { mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = Instant::now();
    assert!(verify_backup(&f.control, &id("backup")).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&displaced, &path).unwrap();
    assert!(verify_backup(&f.control, &id("backup")).is_ok());
}

#[test]
fn whole_catalog_coverage_rejects_unclassified_legacy_membership_and_derived_rows() {
    let f = Fixture::new();
    select(&f, "selected", RootKind::Root);
    bind_source(&f, "allowed_source", "selected/source");
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute(
        "INSERT INTO source_membership(source_path,message_id) VALUES(?1,'msg_v1_unclassified')",
        [source_locator("unselected/source").as_str()],
    )
    .unwrap();
    drop(conn);
    f.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    assert_eq!(
        catalog
            .create_backup(
                &f.control,
                &installation,
                &id("owner"),
                &id("unclassified"),
                BackupPurpose::BetaRollback,
                6,
                end()
            )
            .unwrap(),
        BackupOutcome::Attention(BackupAttention::CoverageMismatch)
    );
    assert!(f.control.backup_records().unwrap().is_empty());
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute("DELETE FROM source_membership", []).unwrap();
    conn.execute("INSERT INTO message_vec(wire_id,model_id,dimension,embedding) VALUES('msg_v1_orphan','synthetic_model',1,X'00000000')", []).unwrap();
    assert_eq!(
        catalog
            .create_backup(
                &f.control,
                &installation,
                &id("owner"),
                &id("orphan_derived"),
                BackupPurpose::BetaRollback,
                6,
                end()
            )
            .unwrap(),
        BackupOutcome::Attention(BackupAttention::CoverageMismatch)
    );
    assert!(f.control.backup_records().unwrap().is_empty());
}

#[test]
fn classified_legacy_and_in_db_derived_rows_are_included_in_logical_backup() {
    let f = Fixture::new();
    select(&f, "selected", RootKind::Root);
    bind_source(&f, "source_a", "selected/source");
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute(
        "INSERT INTO catalog(id,payload) VALUES('msg_v1_classified',X'01')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_membership(source_path,message_id) VALUES(?1,'msg_v1_classified')",
        [source_locator("selected/source").as_str()],
    )
    .unwrap();
    conn.execute("INSERT INTO message_vec(wire_id,model_id,dimension,embedding) VALUES('msg_v1_classified','synthetic_model',1,X'00000000')", []).unwrap();
    conn.execute(
        "INSERT INTO fts(id,text) VALUES('synthetic_message_identity','classified legacy needle')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO fts_ids(wire_id,id_json,fts_rowid) VALUES('msg_v1_classified','synthetic_message_identity',?1)", [conn.last_insert_rowid()]).unwrap();
    conn.execute(
        "INSERT INTO source_revision_receipts(revision_id,source_id,revision_seq,revision_digest,parser_version,completeness,published,cycle_seq,worker_boot_id,catalog_incarnation,policy_epoch,started_control_seq,committed_generation,observed_at_ms,committed_at_ms) VALUES('revision_a','source_a',1,'synthetic_digest',1,'complete',1,1,'synthetic_boot','original_incarnation',0,1,0,1,1)", [],
    ).unwrap();
    conn.execute(
        "INSERT INTO source_projections(projection_id,source_id,revision_id,message_id,payload,payload_digest,index_text,index_digest,fts_text) VALUES('projection_a','source_a','revision_a','msg_v1_projected',X'01','synthetic_digest','managed needle','synthetic_index_digest','managed needle')", [],
    ).unwrap();
    conn.execute(
        "INSERT INTO projection_fts_stats VALUES(?1,2,'synthetic_index_digest')",
        [conn.last_insert_rowid()],
    )
    .unwrap();
    drop(conn);
    f.fence("owner");
    let metadata = f.backup();
    assert_eq!(metadata.source_ids, vec![id("source_a")]);
    let backup = rusqlite::Connection::open_with_flags(
        f.root.join(&metadata.relative_locator),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        backup
            .query_row("SELECT COUNT(*) FROM catalog", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        backup
            .query_row("SELECT COUNT(*) FROM message_vec", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    for query in [
        "SELECT COUNT(*) FROM fts WHERE fts MATCH 'needle'",
        "SELECT COUNT(*) FROM projection_fts WHERE projection_fts MATCH 'needle'",
    ] {
        assert_eq!(
            backup
                .query_row(query, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    drop(backup);
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let prepared = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &id("backup"),
        &id("fts_restore"),
        &f.root.join("fts_restore.db"),
        end(),
    )
    .unwrap();
    assert!(matches!(prepared, RestoreOutcome::Prepared(_)));
    assert_eq!(
        verify_backup(&f.control, &id("backup"))
            .unwrap()
            .coverage()
            .len(),
        1
    );
}

#[test]
fn restore_rechecks_revoke_after_preparation_and_never_clears_pause_or_deny() {
    let f = Fixture::new();
    let selected = select(&f, "selected", RootKind::Root);
    bind_source(&f, "source_a", "selected/source");
    f.fence("owner");
    f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let prepared = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &id("backup"),
        &id("restored"),
        &f.root.join("restored.db"),
        end(),
    )
    .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepared else {
        panic!("restore refused before revoke")
    };
    f.control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &selected.id,
            None,
            7,
        )
        .unwrap();
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    let before = f.control.status().unwrap();
    let jobs = f.control.purge_jobs().unwrap();
    let lock = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&lock).unwrap();
    assert!(
        f.control
            .apply_catalog_restore(
                before.policy.control_seq,
                &id("owner"),
                &bound,
                &installation,
                prepared.backup_id(),
                prepared.incarnation(),
                prepared.coverage(),
                8
            )
            .is_err()
    );
    assert_eq!(f.control.status().unwrap(), before);
    assert_eq!(f.control.purge_jobs().unwrap(), jobs);
    drop(lock);
    assert_eq!(
        prepare_restore(
            &f.control,
            &installation,
            &id("owner"),
            &id("backup"),
            &id("restored_again"),
            &f.root.join("refused.db"),
            end()
        )
        .unwrap(),
        RestoreOutcome::Attention(BackupAttention::PolicyMismatch)
    );
    assert!(!f.root.join("refused.db").exists());
}

#[test]
fn rotate_after_recovery_is_idempotent_and_preserves_pause_denial_and_audit() {
    let f = Fixture::new();
    let selected = select(&f, "selected", RootKind::Root);
    f.control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &selected.id,
            None,
            4,
        )
        .unwrap();
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    f.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    let policy_before = f.control.status().unwrap().policy;
    let jobs_before = f.control.purge_jobs().unwrap();
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            8,
            end(),
        )
        .unwrap();
    let after = f.control.status().unwrap();
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(after.policy.policy_epoch, policy_before.policy_epoch);
    assert_eq!(after.policy.selections, policy_before.selections);
    assert_eq!(after.policy.exclusions, policy_before.exclusions);
    assert_eq!(after.policy.revocations, policy_before.revocations);
    assert_eq!(f.control.purge_jobs().unwrap(), jobs_before);
    assert_eq!(after.catalog_incarnation, Some(id("recovered")));
    let raw = rusqlite::Connection::open(&f.catalog).unwrap();
    assert_eq!(
        raw.query_row("SELECT destructive_epoch FROM store_metadata", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row("SELECT active_generation FROM store_metadata", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            20,
            end(),
        )
        .unwrap();
    assert_eq!(f.control.status().unwrap(), after);
    assert_eq!(
        raw.query_row("SELECT destructive_epoch FROM store_metadata", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    drop(catalog);
    let mut reopened = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    reopened
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            30,
            end(),
        )
        .unwrap();
    assert_eq!(f.control.status().unwrap(), after);
    assert!(
        reopened
            .rotate_after_recovery(
                &f.control,
                &installation,
                &id("other_owner"),
                &id("original_incarnation"),
                &id("recovered"),
                30,
                end()
            )
            .is_err()
    );
    assert!(
        reopened
            .rotate_after_recovery(
                &f.control,
                &installation,
                &id("owner"),
                &id("unexpected"),
                &id("other_recovery"),
                30,
                end()
            )
            .is_err()
    );
    assert_eq!(f.control.status().unwrap(), after);
}

fn backup_sequence_contender(root: &Path) -> std::thread::JoinHandle<()> {
    let root = root.to_path_buf();
    let (ready, held) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let conn = rusqlite::Connection::open(SqliteControlStore::path(&root)).unwrap();
        conn.execute_batch(
            "BEGIN IMMEDIATE; UPDATE control_meta SET control_seq=control_seq+1 WHERE singleton=1",
        )
        .unwrap();
        ready.send(()).unwrap();
        // The first CAS exhausts the default 250ms allowance. A later attempt
        // reads the old sequence while this commit is still held, then loses
        // that CAS when the transaction is released.
        std::thread::sleep(Duration::from_millis(400));
        conn.execute_batch("COMMIT").unwrap();
    });
    held.recv_timeout(Duration::from_secs(5)).unwrap();
    thread
}

#[test]
fn backup_quarantine_retries_busy_and_sequence_race_in_the_same_request() {
    let f = Fixture::new();
    let selected = select(&f, "selected", RootKind::Root);
    bind_source(&f, "source_a", "selected/source");
    f.fence("owner");
    let metadata = f.backup();
    let installation =
        retry_expected_success(|| f.control.bind_installation(&f.prefix, &f.installation_lock))
            .unwrap();
    retry_expected_success(|| {
        f.control.revoke_selection(
            f.control.status()?.policy.control_seq,
            &selected.id,
            None,
            6,
        )
    })
    .unwrap();
    let before = f.control.status().unwrap();
    let contender = backup_sequence_contender(&f.root);
    let outcome = purge_backup(&f.control, &installation, &id("backup"), 7, end());
    contender.join().unwrap();
    assert!(matches!(
        outcome.unwrap(),
        PurgeOutcome::Purged {
            artifact_removed: true,
            ..
        }
    ));
    assert!(!f.root.join(&metadata.relative_locator).exists());
    let terminal = f.control.backup_records().unwrap().pop().unwrap();
    assert_eq!(terminal.state, BackupState::PurgedByPolicy);
    assert_eq!(terminal.digest.as_deref(), Some(metadata.digest.as_str()));
    assert_eq!(terminal.size_bytes, metadata.size_bytes);
    assert!(terminal.source_ids.is_empty());
    let after = f.control.status().unwrap();
    // Exactly one competing sequence write, one quarantine and one finalize.
    assert_eq!(
        after.policy.control_seq.get(),
        before.policy.control_seq.get() + 3
    );
    assert_eq!(after.policy.policy_epoch, before.policy.policy_epoch);
    assert_eq!(after.policy.exclusions, before.policy.exclusions);
    assert_eq!(after.desired_updates, before.desired_updates);
}

#[cfg(windows)]
#[test]
fn failed_unlink_retains_quarantine_accounting_across_reallow_then_retries() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let selected = select(&f, "selected", RootKind::Root);
    bind_source(&f, "source_a", "selected/source");
    f.fence("owner");
    let metadata = f.backup();
    let path = f.root.join(&metadata.relative_locator);
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1 | 2)
        .open(&path)
        .unwrap();
    let installation =
        retry_expected_success(|| f.control.bind_installation(&f.prefix, &f.installation_lock))
            .unwrap();
    retry_expected_success(|| {
        f.control.revoke_selection(
            f.control.status()?.policy.control_seq,
            &selected.id,
            None,
            6,
        )
    })
    .unwrap();
    assert!(matches!(
        purge_backup(&f.control, &installation, &id("backup"), 7, end()).unwrap(),
        PurgeOutcome::PendingCleanup { .. }
    ));
    let pending = retry_expected_success(|| f.control.backup_records())
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(pending.state, BackupState::Quarantined);
    assert_eq!(pending.source_ids, vec![id("source_a")]);
    assert_eq!(pending.digest.as_deref(), Some(metadata.digest.as_str()));
    // Policy mutations can run while the pending artifact is held elsewhere.
    select(&f, "selected", RootKind::Root);
    let exclusions = retry_expected_success(|| f.control.status())
        .unwrap()
        .policy
        .exclusions;
    for excluded in exclusions {
        retry_expected_success(|| {
            f.control
                .remove_exclusion(f.control.status()?.policy.control_seq, &excluded.id)
        })
        .unwrap();
    }
    assert!(verify_backup(&f.control, &id("backup")).is_err());
    drop(pinned);
    let before_finalize = f.control.status().unwrap();
    let contender = backup_sequence_contender(&f.root);
    let finalized = purge_backup(&f.control, &installation, &id("backup"), 9, end());
    contender.join().unwrap();
    assert!(matches!(
        finalized.unwrap(),
        PurgeOutcome::Purged {
            artifact_removed: true,
            ..
        }
    ));
    assert!(!path.exists());
    let terminal = retry_expected_success(|| f.control.backup_records())
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(terminal.state, BackupState::PurgedByPolicy);
    assert!(terminal.source_ids.is_empty());
    assert_eq!(
        f.control.status().unwrap().policy.control_seq.get(),
        before_finalize.policy.control_seq.get() + 2,
        "one writer and one finalization; cleanup must not quarantine again"
    );
    assert!(matches!(
        purge_backup(&f.control, &installation, &id("backup"), 10, end()).unwrap(),
        PurgeOutcome::Purged {
            artifact_removed: true,
            ..
        }
    ));
}

#[test]
fn recovery_reconciles_catalog_commit_before_control_ack_without_rotating_twice() {
    let f = Fixture::new();
    f.fence("owner");
    let raw_control = rusqlite::Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    raw_control
        .execute(
            "UPDATE control_meta SET catalog_incarnation='original_incarnation' WHERE singleton=1",
            [],
        )
        .unwrap();
    drop(raw_control);
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    let before = f.control.status().unwrap();
    // Hold PolicyOwner so the catalog side effect commits but its control
    // acknowledgement cannot acquire the real lock within the same budget.
    let blocked_owner = acquire(&f.root, LockKind::PolicyOwner);
    // The budget must cover the catalog transaction so the injected contention
    // reaches the control acknowledgement rather than expiring beforehand.
    assert!(matches!(
        catalog.rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            9,
            Instant::now() + Duration::from_secs(2),
        ),
        Err(PortError::WriterBusy(_))
    ));
    let committed_catalog = rusqlite::Connection::open(&f.catalog).unwrap();
    assert_eq!(
        committed_catalog
            .query_row(
                "SELECT catalog_incarnation FROM catalog_meta WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "recovered"
    );
    assert_eq!(
        committed_catalog
            .query_row("SELECT destructive_epoch FROM store_metadata", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    drop(committed_catalog);
    assert_eq!(catalog.identity().incarnation, id("recovered"));
    assert_eq!(f.control.status().unwrap(), before);
    drop(blocked_owner);
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            10,
            end(),
        )
        .unwrap();
    let after = f.control.status().unwrap();
    assert_eq!(after.catalog_incarnation, Some(id("recovered")));
    let raw_catalog = rusqlite::Connection::open(&f.catalog).unwrap();
    assert_eq!(
        raw_catalog
            .query_row("SELECT destructive_epoch FROM store_metadata", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            11,
            end(),
        )
        .unwrap();
    assert_eq!(f.control.status().unwrap(), after);
}

#[test]
fn recovery_clears_catalog_progress_barriers_and_confirmations_retaining_audit_attempts() {
    let f = Fixture::new();
    let selected = select(&f, "selected", RootKind::Root);
    let selection = SelectionRevision {
        selection_id: selected.id.clone(),
        revision: selected.revision,
        root_identity: selected.root_identity.clone().unwrap(),
    };
    let raw_identity = rusqlite::Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    raw_identity
        .execute(
            "UPDATE control_meta SET catalog_incarnation='original_incarnation' WHERE singleton=1",
            [],
        )
        .unwrap();
    drop(raw_identity);
    let worker_lock = acquire(&f.root, LockKind::Background);
    let worker = f.control.bind_worker(&worker_lock, id("boot")).unwrap();
    f.control
        .register_worker(
            f.control.status().unwrap().policy.control_seq,
            &worker,
            1,
            4,
        )
        .unwrap();
    let admitted = f
        .control
        .admit_latest(
            f.control.status().unwrap().policy.control_seq,
            LatestRequest {
                selections: vec![selection.clone()],
                max_wait_ms: 100,
                now_ms: 5,
            },
        )
        .unwrap();
    let LatestAdmission::Queued(barrier) = admitted.value else {
        panic!("barrier refused")
    };
    let cycle = f
        .control
        .start_cycle(
            f.control.status().unwrap().policy.control_seq,
            &worker,
            barrier.required_cycle_seq,
            6,
        )
        .unwrap()
        .value;
    let ack = SourceAcknowledgement {
        source_id: id("source_a"),
        provider: SearchProvider::Claude,
        token: cycle.token.clone(),
        selection,
        attempted_at_ms: 7,
        coverage: Coverage::Complete,
        update_state: UpdateState::Idle,
        backfill_state: BackfillState::Complete,
        error: None,
        receipt: Some(SourceReceiptSummary {
            token: cycle.token.clone(),
            revision: id("revision"),
            catalog_incarnation: id("original_incarnation"),
            catalog_generation: ControlSeq::new(0).unwrap(),
        }),
        confirmation: None,
    };
    f.control
        .acknowledge_source(f.control.status().unwrap().policy.control_seq, &worker, ack)
        .unwrap();
    f.fence("owner");
    // inject a durable rewrite confirmation from before the interrupted update
    // after admission was closed; its referenced observed cycle remains audit.
    let raw = rusqlite::Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    raw.execute(
        "UPDATE source_updates SET error_code='rewrite_pending',rewrite_candidate_digest='candidate',rewrite_first_cycle=?1,confirmation_boot_id='boot',confirmation_root_identity='synthetic_source_root',confirmation_policy_epoch=?2,confirmation_first_monotonic_ms=10 WHERE source_id='source_a'",
        rusqlite::params![cycle.token.cycle_seq.get(), cycle.policy_epoch.get()],
    ).unwrap();
    assert!(
        f.control
            .source_progress(&id("source_a"))
            .unwrap()
            .unwrap()
            .confirmation
            .is_some()
    );
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            12,
            end(),
        )
        .unwrap();
    let progress = f.control.source_progress(&id("source_a")).unwrap().unwrap();
    assert!(progress.receipt.is_none());
    assert!(progress.last_observation.is_none());
    assert!(progress.confirmation.is_none());
    assert_eq!(progress.last_attempt_at_ms, Some(7));
    assert_eq!(progress.coverage, Coverage::Empty);
    assert_eq!(progress.error, Some(BackgroundFailure::CatalogChanged));
    assert_eq!(progress.backfill_state, BackfillState::Pending);
    assert!(matches!(
        f.control.barrier(&barrier.id),
        Err(PortError::NotFound(_))
    ));
    assert_eq!(
        f.control.cycle(cycle.token.cycle_seq).unwrap().state,
        CycleState::Aborted
    );
    let status = f.control.status().unwrap();
    catalog
        .rotate_after_recovery(
            &f.control,
            &installation,
            &id("owner"),
            &id("original_incarnation"),
            &id("recovered"),
            13,
            end(),
        )
        .unwrap();
    assert_eq!(f.control.status().unwrap(), status);
    assert_eq!(
        f.control.source_progress(&id("source_a")).unwrap().unwrap(),
        progress
    );
}

const CONTEXT_TABLES: &[&str] = &[
    "source_dependencies",
    "source_context_heads",
    "source_authority_members",
    "source_authority_tombstones",
    "source_authority_transitions",
    "source_authorities",
    "source_publication_contexts",
];

/// Only establish the historical preimage: remove the additive22 schema from a
/// fresh synthetic catalog. Test outcomes call the actual governed migration.
fn historical_schema(f: &Fixture, schema: u32) {
    assert!(matches!(schema, 20 | 21));
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    for table in CONTEXT_TABLES {
        tx.execute_batch(&format!("DROP TABLE {table}")).unwrap();
    }
    if schema == 20 {
        tx.execute_batch("DROP TABLE retained_source_receipts")
            .unwrap();
    }
    tx.pragma_update(None, "user_version", schema).unwrap();
    tx.commit().unwrap();
}

fn historical_content(f: &Fixture) -> Selection {
    let selected = select(f, "selected", RootKind::Root);
    bind_source(f, "source_a", "selected/source");
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute(
        "UPDATE store_metadata SET active_generation=7 WHERE singleton=1",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO installation_namespaces VALUES('namespace_a','claude-code','synthetic_input','allocated-v1',1)",[]).unwrap();
    conn.execute("INSERT INTO installation_locations VALUES('claude-code','synthetic_root_key','synthetic_locator','namespace_a','current',NULL)",[]).unwrap();
    conn.execute(
        "INSERT INTO source_installations VALUES(?1,'synthetic_source_key','namespace_a')",
        [source_locator("selected/source").as_str()],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_bindings SET namespace_id='namespace_a' WHERE source_id='source_a'",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO source_revision_receipts(revision_id,source_id,revision_seq,revision_digest,parser_version,completeness,published,cycle_seq,worker_boot_id,catalog_incarnation,policy_epoch,started_control_seq,content_revision_id,content_set_digest,committed_generation,observed_at_ms,committed_at_ms) VALUES('revision_a','source_a',1,'synthetic_digest',1,'complete',1,1,'synthetic_boot','original_incarnation',0,1,'revision_a',?1,7,11,12)",["a".repeat(64)]).unwrap();
    conn.execute("INSERT INTO source_heads(source_id,visible_revision_id,latest_receipt_id,content_set_digest,last_attempt_id,update_state,observed_cycle_seq) VALUES('source_a','revision_a','revision_a',?1,'revision_a','current',1)",["a".repeat(64)]).unwrap();
    conn.execute(
        "INSERT INTO source_scope_claims VALUES('source_a',?1,?2,0,11)",
        rusqlite::params![selected.id.as_str(), selected.revision.get()],
    )
    .unwrap();
    conn.execute("INSERT INTO source_projections(projection_id,source_id,revision_id,message_id,payload,payload_digest,index_text,index_digest,fts_text) VALUES('projection_a','source_a','revision_a','msg_v1_projected',X'01002020','synthetic_digest','original needle','synthetic_index_digest','original needle')",[]).unwrap();
    conn.execute(
        "INSERT INTO projection_fts_stats VALUES(?1,2,'synthetic_index_digest')",
        [conn.last_insert_rowid()],
    )
    .unwrap();
    selected
}

fn schema(path: &Path) -> u32 {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}
fn has_table(path: &Path, name: &str) -> bool {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )
    .unwrap()
}
fn finish_fence(f: &Fixture, owner: &str) {
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let guard = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&guard).unwrap();
    f.control
        .clear_maintenance(
            f.control.status().unwrap().policy.control_seq,
            &id(owner),
            &bound,
            &installation,
        )
        .unwrap();
}

#[test]
fn readonly_identity_admits_exact_old_schema_without_mutating_or_granting_read_access() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    let before = std::fs::read(&f.catalog).unwrap();
    let identity = inspect_catalog_identity(&f.control, &f.catalog, end()).unwrap();
    assert_eq!(identity.schema, 21);
    assert_eq!(identity.incarnation, id("original_incarnation"));
    assert_eq!(identity.generation, 0);
    assert_eq!(std::fs::read(&f.catalog).unwrap(), before);
    assert!(!has_table(&f.catalog, "source_publication_contexts"));
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    f.fence("owner");
    assert!(matches!(
        inspect_catalog_identity(&f.control, &f.catalog, end()),
        Err(PortError::WriterBusy(_))
    ));
}

#[test]
fn readonly_identity_rejects_wrong_root_invalid_identity_and_expired_or_locked_admission() {
    let f = Fixture::new();
    let other = Fixture::new();
    assert!(inspect_catalog_identity(&f.control, &other.catalog, end()).is_err());
    assert!(matches!(
        inspect_catalog_identity(&f.control, &f.catalog, Instant::now()),
        Err(PortError::WriterBusy(_))
    ));
    let guard = acquire(&f.root, LockKind::CatalogHandles);
    assert!(matches!(
        inspect_catalog_identity(
            &f.control,
            &f.catalog,
            Instant::now() + Duration::from_millis(20)
        ),
        Err(PortError::WriterBusy(_))
    ));
    drop(guard);
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.execute(
        "UPDATE catalog_meta SET installation_id='another_installation'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        inspect_catalog_identity(&f.control, &f.catalog, end()),
        Err(PortError::SchemaIncompatible(_))
    ));
}

#[test]
fn owned_schema21_migration_preserves_identity_namespace_originals_and_control_denials() {
    let f = Fixture::new();
    historical_content(&f);
    historical_schema(&f, 21);
    let denied = select(&f, "denied", RootKind::Root);
    f.control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &denied.id,
            None,
            5,
        )
        .unwrap();
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    f.fence("owner");
    let before = f.control.status().unwrap();
    let jobs = f.control.purge_jobs().unwrap();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    let original = catalog.identity().clone();
    let migrated = catalog
        .migrate_to_current(&f.control, &installation, &id("owner"), end())
        .unwrap();
    assert_eq!(migrated.schema, 22);
    assert_eq!(migrated.installation, original.installation);
    assert_eq!(migrated.incarnation, original.incarnation);
    assert_eq!(migrated.generation, 7);
    assert_eq!(
        catalog
            .migrate_to_current(&f.control, &installation, &id("owner"), end())
            .unwrap(),
        migrated
    );
    assert_eq!(f.control.status().unwrap(), before);
    assert_eq!(f.control.purge_jobs().unwrap(), jobs);
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT payload FROM source_projections WHERE projection_id='projection_a'",
            [],
            |r| r.get::<_, Vec<u8>>(0)
        )
        .unwrap(),
        [1, 0, 32, 32]
    );
    assert_eq!(
        conn.query_row("SELECT namespace_id FROM source_installations", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap(),
        "namespace_a"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM projection_fts WHERE projection_fts MATCH 'needle'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    for table in CONTEXT_TABLES {
        assert_eq!(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM retained_source_receipts", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
}

#[test]
fn managed20_uses_canonical_owned_transaction_and_adds_no_receipt_or_context_proof() {
    let f = Fixture::new();
    historical_content(&f);
    historical_schema(&f, 20);
    f.fence("owner");
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    assert_eq!(catalog.identity().schema, 20);
    assert_eq!(
        catalog
            .migrate_to_current(&f.control, &installation, &id("owner"), end())
            .unwrap()
            .schema,
        22
    );
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    for table in [
        "retained_source_receipts",
        "source_publication_contexts",
        "source_dependencies",
        "source_authorities",
    ] {
        assert_eq!(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn schema_migration_requires_fence_drain_owner_identity_and_original_deadline() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    assert!(
        MaintenanceCatalog::open_authorized(
            &f.control,
            &installation,
            &id("owner"),
            &f.catalog,
            end()
        )
        .is_err()
    );
    f.fence("owner");
    let reader = agent_session_grep_adapters_sqlite::managed_locks::SharedGuard::try_acquire(
        &f.root,
        LockKind::CatalogHandles,
    )
    .unwrap();
    assert!(matches!(
        MaintenanceCatalog::open_authorized(
            &f.control,
            &installation,
            &id("owner"),
            &f.catalog,
            Instant::now() + Duration::from_millis(20)
        ),
        Err(PortError::WriterBusy(_))
    ));
    drop(reader);
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    assert!(
        catalog
            .migrate_to_current(&f.control, &installation, &id("wrong_owner"), end())
            .is_err()
    );
    assert!(matches!(
        catalog.migrate_to_current(&f.control, &installation, &id("owner"), Instant::now()),
        Err(PortError::WriterBusy(_))
    ));
    assert_eq!(schema(&f.catalog), 21);
    assert!(!has_table(&f.catalog, "source_dependencies"));
    let raw = rusqlite::Connection::open(&f.catalog).unwrap();
    raw.execute("UPDATE store_metadata SET active_generation=1", [])
        .unwrap();
    drop(raw);
    assert!(matches!(
        catalog.migrate_to_current(&f.control, &installation, &id("owner"), end()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(schema(&f.catalog), 21);
}

#[test]
fn canonical_migration_rolls_back_all_additive_tables_if_ddl_preimage_is_invalid() {
    let f = Fixture::new();
    historical_schema(&f, 20);
    let raw = rusqlite::Connection::open(&f.catalog).unwrap();
    raw.execute("CREATE TABLE source_dependencies(unowned INTEGER)", [])
        .unwrap();
    drop(raw);
    f.fence("owner");
    let before = f.control.status().unwrap();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    assert!(
        catalog
            .migrate_to_current(&f.control, &installation, &id("owner"), end())
            .is_err()
    );
    assert_eq!(schema(&f.catalog), 20);
    assert!(!has_table(&f.catalog, "retained_source_receipts"));
    assert!(!has_table(&f.catalog, "source_publication_contexts"));
    assert_eq!(f.control.status().unwrap(), before);
}

#[test]
fn old21_backup_defaults_to_current22_without_mutating_registered_original_image() {
    let f = Fixture::new();
    historical_content(&f);
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    assert_eq!(metadata.schema_version, 21);
    let backup = f.root.join(&metadata.relative_locator);
    let original = std::fs::read(&backup).unwrap();
    assert_eq!(
        verify_backup(&f.control, &metadata.backup_id)
            .unwrap()
            .metadata(),
        &metadata
    );
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("current_recovery"),
        &f.root.join("current_restore.db"),
        end(),
    )
    .unwrap() else {
        panic!("restore refused")
    };
    assert_eq!(prepared.schema_version(), 22);
    assert_eq!(schema(prepared.side_path()), 22);
    assert_eq!(std::fs::read(&backup).unwrap(), original);
    assert_eq!(
        verify_backup(&f.control, &metadata.backup_id)
            .unwrap()
            .metadata()
            .schema_version,
        21
    );
    let conn = rusqlite::Connection::open_with_flags(
        prepared.side_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        conn.query_row("SELECT payload FROM source_projections", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        [1, 0, 32, 32]
    );
    assert_eq!(
        conn.query_row(
            "SELECT catalog_incarnation FROM source_revision_receipts",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "original_incarnation"
    );
    assert_eq!(
        conn.query_row(
            "SELECT observed_at_ms FROM source_revision_receipts",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        11
    );
    assert_eq!(
        conn.query_row(
            "SELECT retained_incarnation FROM retained_source_receipts",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "current_recovery"
    );
    assert_eq!(
        conn.query_row("SELECT update_state FROM source_heads", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "unknown"
    );
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    assert!(inventory.incomplete());
    assert_eq!(inventory.staged_images().len(), 1);
    assert!(!inventory.receipts()[0].complete());
}

#[test]
fn exact21_program_rollback_preserves_backup_and_publishes_before_control_ack() {
    use agent_session_grep_ports::managed::ProjectionRead;
    let f = Fixture::new();
    historical_content(&f);
    historical_schema(&f, 21);
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    f.fence("owner");
    let metadata = f.backup();
    let backup = f.root.join(&metadata.relative_locator);
    let original = std::fs::read(&backup).unwrap();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    catalog
        .migrate_to_current(&f.control, &installation, &id("owner"), end())
        .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("rollback_recovery"),
        &f.root.join("rollback.db"),
        end(),
    )
    .unwrap() else {
        panic!("exact restore refused")
    };
    assert_eq!(prepared.schema_version(), 21);
    assert!(!has_table(
        prepared.side_path(),
        "source_publication_contexts"
    ));
    let before = f.control.status().unwrap();
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &prepared,
        20,
        end(),
    )
    .unwrap();
    assert_eq!(catalog.identity().schema, 21);
    assert_eq!(catalog.identity().incarnation, id("rollback_recovery"));
    assert_eq!(catalog.identity().generation, 7);
    assert!(!prepared.side_path().exists());
    assert_eq!(schema(&f.catalog), 21);
    assert_eq!(std::fs::read(&backup).unwrap(), original);
    let after = f.control.status().unwrap();
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(after.policy.selections, before.policy.selections);
    assert_eq!(after.policy.revocations, before.policy.revocations);
    assert_eq!(after.catalog_incarnation, Some(id("rollback_recovery")));
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    assert!(!inventory.incomplete());
    assert!(inventory.staged_images().is_empty());
    assert_eq!(inventory.receipts().len(), 1);
    assert!(inventory.receipts()[0].complete());
    let displaced = f
        .control
        .backup_records()
        .unwrap()
        .into_iter()
        .find(|b| b.backup_id != metadata.backup_id)
        .unwrap();
    assert_eq!(displaced.schema_version, 22);
    assert_eq!(displaced.state, BackupState::Complete);
    assert!(verify_backup(&f.control, &displaced.backup_id).is_ok());
    drop(catalog);
    finish_fence(&f, "owner");
    // The current program still refuses21. This lower-level historical read
    // seam shows retained originals are readable by the exact21 projection
    // contract, not that an unbuilt old native program has been accepted.
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    let _handles = agent_session_grep_adapters_sqlite::managed_locks::SharedGuard::try_acquire(
        &f.root,
        LockKind::CatalogHandles,
    )
    .unwrap();
    let conn = rusqlite::Connection::open_with_flags(
        &f.catalog,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let read = agent_session_grep_adapters_sqlite::managed::ManagedRead::begin_authorized(
        &conn,
        &f.control
            .read_policy(RequestIntersection::Selected)
            .unwrap(),
        "rollback_recovery",
        end(),
    )
    .unwrap();
    let progress = read.source_progress().unwrap();
    assert_eq!(progress.len(), 1);
    let receipt = progress[0].latest_receipt.as_ref().unwrap();
    assert!(read.retained_revision_allowed(receipt).unwrap());
    assert_eq!(receipt.catalog_incarnation, "original_incarnation");
    assert_eq!(receipt.observed_at_ms, 11);
    assert_ne!(
        receipt.catalog_incarnation,
        read.snapshot().catalog_incarnation
    );
    drop(read);
    drop(conn);
    drop(_handles);
    let admitted = inspect_catalog_identity(&f.control, &f.catalog, end()).unwrap();
    assert_eq!(admitted.schema, 21);
}

#[test]
fn repeated_exact_prepare_reuses_only_the_owned_unchanged_side_and_rejects_independent_file() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let side = f.root.join("repeat.db");
    let first = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("repeat_recovery"),
        &side,
        end(),
    )
    .unwrap();
    let before = std::fs::read(&side).unwrap();
    assert_eq!(
        prepare_restore_exact(
            &f.control,
            &installation,
            &id("owner"),
            &metadata.backup_id,
            &id("repeat_recovery"),
            &side,
            end()
        )
        .unwrap(),
        first
    );
    assert_eq!(std::fs::read(&side).unwrap(), before);
    let collision = f.root.join("collision.db");
    std::fs::write(&collision, b"unowned synthetic data").unwrap();
    assert!(
        prepare_restore_exact(
            &f.control,
            &installation,
            &id("owner"),
            &metadata.backup_id,
            &id("collision_recovery"),
            &collision,
            end()
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(&collision).unwrap(),
        b"unowned synthetic data"
    );
    std::fs::write(&side, b"edited owned side").unwrap();
    assert!(
        prepare_restore_exact(
            &f.control,
            &installation,
            &id("owner"),
            &metadata.backup_id,
            &id("repeat_recovery"),
            &side,
            end()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&side).unwrap(), b"edited owned side");
}

#[test]
fn old20_current_recovery_is_verified_but_exact20_program_rollback_is_refused() {
    let f = Fixture::new();
    historical_content(&f);
    historical_schema(&f, 20);
    f.fence("owner");
    let metadata = f.backup();
    assert_eq!(metadata.schema_version, 20);
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    assert!(
        prepare_restore_exact(
            &f.control,
            &installation,
            &id("owner"),
            &metadata.backup_id,
            &id("exact20"),
            &f.root.join("exact20.db"),
            end()
        )
        .is_err()
    );
    assert!(!f.root.join("exact20.db").exists());
    let RestoreOutcome::Prepared(prepared) = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("current20"),
        &f.root.join("current20.db"),
        end(),
    )
    .unwrap() else {
        panic!("current recovery refused")
    };
    assert_eq!(prepared.schema_version(), 22);
    assert_eq!(schema(prepared.side_path()), 22);
    assert_eq!(schema(&f.root.join(metadata.relative_locator)), 20);
}

#[test]
fn retry_owned_side_after_copy_commit_before_prepared_receipt_is_idempotent() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let side = f.root.join("interrupted_prepare.db");
    let RestoreOutcome::Prepared(prepared) = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("interrupted_prepare"),
        &side,
        end(),
    )
    .unwrap() else {
        panic!("refused")
    };
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    let receipt = f.root.join(inventory.receipts()[0].relative_locator());
    let original = std::fs::read(&receipt).unwrap();
    let mut lines: Vec<_> = original.split_inclusive(|byte| *byte == b'\n').collect();
    let prepared_line = lines.pop().unwrap();
    assert!(String::from_utf8_lossy(prepared_line).contains("Prepared"));
    std::fs::write(&receipt, lines.concat()).unwrap();
    // The independently pinned owned side is recopied from immutable backup;
    // generation/receipt lineage are not rotated twice.
    let repeated = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("interrupted_prepare"),
        &side,
        end(),
    )
    .unwrap();
    let RestoreOutcome::Prepared(repeated) = repeated else {
        panic!("retry refused")
    };
    assert_eq!(repeated.schema_version(), prepared.schema_version());
    assert_eq!(repeated.incarnation(), prepared.incarnation());
    assert_eq!(repeated.catalog_generation(), prepared.catalog_generation());
}

#[test]
fn exact_restore_retry_after_publication_before_control_ack_retains_displaced_and_paused_state() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    catalog
        .migrate_to_current(&f.control, &installation, &id("owner"), end())
        .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("ack_recovery"),
        &f.root.join("ack_restore.db"),
        end(),
    )
    .unwrap() else {
        panic!("refused")
    };
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &prepared,
        20,
        end(),
    )
    .unwrap();
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    let path = f.root.join(inventory.receipts()[0].relative_locator());
    let bytes = std::fs::read(&path).unwrap();
    let mut lines: Vec<_> = bytes.split_inclusive(|b| *b == b'\n').collect();
    assert!(String::from_utf8_lossy(lines.pop().unwrap()).contains("Applied"));
    std::fs::write(&path, lines.concat()).unwrap();
    let raw = rusqlite::Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    raw.execute(
        "UPDATE control_meta SET catalog_incarnation='original_incarnation'",
        [],
    )
    .unwrap();
    drop(raw);
    let before = f.control.status().unwrap();
    drop(catalog);
    let retry = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("ack_recovery"),
        prepared.side_path(),
        end(),
    )
    .unwrap();
    let RestoreOutcome::Prepared(retry) = retry else {
        panic!("retry refused")
    };
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &retry,
        21,
        end(),
    )
    .unwrap();
    assert_eq!(schema(&f.catalog), 21);
    assert_eq!(
        f.control.status().unwrap().catalog_incarnation,
        Some(id("ack_recovery"))
    );
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        before.desired_updates
    );
    assert_eq!(f.control.backup_records().unwrap().len(), 2);
    let after = f.control.status().unwrap();
    let receipt = std::fs::read(&path).unwrap();
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &retry,
        22,
        end(),
    )
    .unwrap();
    assert_eq!(f.control.status().unwrap(), after);
    assert_eq!(std::fs::read(&path).unwrap(), receipt);
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    assert!(!inventory.incomplete());
    assert!(inventory.staged_images().is_empty());
}

#[test]
fn exact_restore_failure_keeps_live_and_side_when_displaced_path_is_independently_occupied() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    catalog
        .migrate_to_current(&f.control, &installation, &id("owner"), end())
        .unwrap();
    let side = f.root.join("occupied.db");
    let recovery = id("occupied_recovery");
    let RestoreOutcome::Prepared(prepared) = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &recovery,
        &side,
        end(),
    )
    .unwrap() else {
        panic!("refused")
    };
    let key = blake3::hash(
        format!(
            "{}:{}:{}:displaced",
            metadata.backup_id.as_str(),
            recovery.as_str(),
            "occupied.db"
        )
        .as_bytes(),
    )
    .to_hex();
    let prior = f
        .root
        .join("backups")
        .join(format!("restore_prior_{}", &key[..32]))
        .join("catalog.db");
    std::fs::create_dir(prior.parent().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            prior.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    std::fs::write(&prior, b"independent displaced candidate").unwrap();
    let before = f.control.status().unwrap();
    let side_bytes = std::fs::read(&side).unwrap();
    assert!(
        apply_restore(
            &mut catalog,
            &f.control,
            &installation,
            &id("owner"),
            &prepared,
            20,
            end()
        )
        .is_err()
    );
    assert_eq!(schema(&f.catalog), 22);
    assert_eq!(
        std::fs::read(&prior).unwrap(),
        b"independent displaced candidate"
    );
    assert_eq!(std::fs::read(&side).unwrap(), side_bytes);
    assert_eq!(
        f.control.status().unwrap().catalog_incarnation,
        before.catalog_incarnation
    );
    assert_eq!(catalog.identity().schema, 22);
}

#[cfg(windows)]
#[test]
fn native_file_delete_sharing_blocks_restore_without_losing_current_and_retry_succeeds() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    catalog
        .migrate_to_current(&f.control, &installation, &id("owner"), end())
        .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("sharing_recovery"),
        &f.root.join("sharing.db"),
        end(),
    )
    .unwrap() else {
        panic!("refused")
    };
    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&f.catalog)
        .unwrap();
    let status = f.control.status().unwrap();
    assert!(
        apply_restore(
            &mut catalog,
            &f.control,
            &installation,
            &id("owner"),
            &prepared,
            20,
            end()
        )
        .is_err()
    );
    assert_eq!(schema(&f.catalog), 22);
    assert!(prepared.side_path().exists());
    assert_eq!(
        f.control.status().unwrap().catalog_incarnation,
        status.catalog_incarnation
    );
    drop(blocker);
    drop(catalog);
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &prepared,
        21,
        end(),
    )
    .unwrap();
    assert_eq!(schema(&f.catalog), 21);
}

#[test]
fn restored_current22_ordinary_read_keeps_whitespace_and_historical_proof_while_paused() {
    use agent_session_grep_adapters_sqlite::{SourceBatch, managed};
    use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
    use agent_session_grep_ports::managed::{
        ObservationState, ProjectionQuery, ProjectionRead, RevisionId, SelectionProof,
        SourceBinding, SourceId, SourceObservation,
    };
    let f = Fixture::new();
    let selected = select(&f, "selected", RootKind::Root);
    historical_schema(&f, 21);
    let message = StableId::native_checked(IdKind::Message, "original_message").unwrap();
    let session = StableId::native_checked(IdKind::Session, "original_session").unwrap();
    let document = StableId::native_checked(IdKind::Document, "original_document").unwrap();
    let text = "  original retained needle\n\twith spaces  ";
    let digest = "b".repeat(64);
    let observation = SourceObservation {
        binding: SourceBinding {
            source_id: SourceId::parse("source_a").unwrap(),
            source_path: source_locator("selected/source").as_str().into(),
            provider: SearchProvider::Claude,
            namespace_id: None,
            root_identity: "synthetic_source_root".into(),
        },
        revision_id: RevisionId::parse("revision_a").unwrap(),
        revision_digest: digest.clone(),
        parser_version: 1,
        state: ObservationState::Complete,
        cycle_seq: 1,
        worker_boot_id: "synthetic_boot".into(),
        catalog_incarnation: "original_incarnation".into(),
        policy_epoch: 0,
        started_control_seq: 1,
        observed_at_ms: 11,
        committed_at_ms: 12,
        selections: vec![SelectionProof {
            selection_id: selected.id.as_str().into(),
            selection_revision: selected.revision.get(),
            root_identity: "synthetic_source_root".into(),
        }],
        repositories: vec![],
    };
    let batch=SourceBatch{source_path:observation.binding.source_path.clone(),entries:vec![(session.clone(),serde_json::to_vec(&serde_json::json!({"title":"Original session","documents":[document.as_str()]})).unwrap(),String::new()),(document.clone(),serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":digest,"len":100})).unwrap(),String::new()),(message.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":"2026-10-19T00:00:00Z"})).unwrap(),text.into())],placements:vec![MessagePlacement::new(session,document,message.clone(),0,false,None)],edges:vec![],activities:vec![],usage_events:vec![],relation_complete:true,len_bytes:Some(100),fingerprint:Some(observation.revision_digest.clone()),provider_id:Some("claude-code".into()),resume_claims:vec![]};
    let conn = rusqlite::Connection::open(&f.catalog).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    let publication = managed::publish_source_in_tx(&tx, &batch, &observation, 1).unwrap();
    tx.execute("UPDATE store_metadata SET active_generation=1", [])
        .unwrap();
    managed::finalize_publications_in_tx(&tx, &mut [publication]).unwrap();
    tx.commit().unwrap();
    drop(conn);
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("paused_recovery"),
        &f.root.join("paused.db"),
        end(),
    )
    .unwrap() else {
        panic!("refused")
    };
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &prepared,
        20,
        end(),
    )
    .unwrap();
    drop(catalog);
    finish_fence(&f, "owner");
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    store
        .with_read(&f.control, RequestIntersection::Selected, end(), |read| {
            let values =
                read.messages(std::slice::from_ref(&message), &ProjectionQuery::default())?;
            let value = values[0].as_ref().unwrap();
            assert_eq!(value.message.text, text);
            assert_eq!(
                value.proof.revision.catalog_incarnation,
                "original_incarnation"
            );
            assert_eq!(value.proof.revision.observed_at_ms, 11);
            assert!(read.retained_revision_allowed(&value.proof.revision)?);
            assert_ne!(
                value.proof.revision.catalog_incarnation,
                read.snapshot().catalog_incarnation
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    f.control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &selected.id,
            None,
            21,
        )
        .unwrap();
    // The durable revoke blocks emission immediately while its real drain is
    // pending. Recovery never clears that denial to manufacture an empty read.
    assert!(matches!(
        store.with_read(&f.control, RequestIntersection::Selected, end(), |read| {
            read.messages(std::slice::from_ref(&message), &ProjectionQuery::default())
                .map(|_| ())
        }),
        Err(PortError::WriterBusy(_))
    ));
    assert!(
        !f.control
            .read_policy(RequestIntersection::Selected)
            .unwrap()
            .allows_source(
                SearchProvider::Claude,
                &source_locator("selected/source"),
                &id("source_a")
            )
    );
}

#[test]
fn completed_restore_receipt_stays_classifiable_after_policy_purges_covered_backups() {
    let f = Fixture::new();
    let selected = historical_content(&f);
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    let RestoreOutcome::Prepared(prepared) = prepare_restore(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("purged_inventory"),
        &f.root.join("purged_inventory.db"),
        end(),
    )
    .unwrap() else {
        panic!("refused")
    };
    let mut catalog = MaintenanceCatalog::open_authorized(
        &f.control,
        &installation,
        &id("owner"),
        &f.catalog,
        end(),
    )
    .unwrap();
    apply_restore(
        &mut catalog,
        &f.control,
        &installation,
        &id("owner"),
        &prepared,
        20,
        end(),
    )
    .unwrap();
    drop(catalog);
    f.control
        .revoke_selection(
            f.control.status().unwrap().policy.control_seq,
            &selected.id,
            None,
            21,
        )
        .unwrap();
    for backup in f.control.backup_records().unwrap() {
        assert!(matches!(
            purge_backup(&f.control, &installation, &backup.backup_id, 22, end()).unwrap(),
            PurgeOutcome::Purged {
                artifact_removed: true,
                ..
            }
        ));
    }
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    assert!(!inventory.incomplete());
    assert!(inventory.staged_images().is_empty());
    assert!(inventory.receipts()[0].complete());
}

#[test]
fn copied_restore_receipt_cannot_authorize_another_physical_control_root() {
    let f = Fixture::new();
    historical_schema(&f, 21);
    f.fence("owner");
    let metadata = f.backup();
    let installation = f
        .control
        .bind_installation(&f.prefix, &f.installation_lock)
        .unwrap();
    prepare_restore_exact(
        &f.control,
        &installation,
        &id("owner"),
        &metadata.backup_id,
        &id("copied_receipt"),
        &f.root.join("copied.db"),
        end(),
    )
    .unwrap();
    let inventory = inspect_restore_inventory(&f.control, &f.catalog, end()).unwrap();
    let receipt = &inventory.receipts()[0];
    let other = Fixture::new();
    let destination = other.root.join(receipt.relative_locator());
    std::fs::copy(f.root.join(receipt.relative_locator()), &destination).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(inspect_restore_inventory(&other.control, &other.catalog, end()).is_err());
}
