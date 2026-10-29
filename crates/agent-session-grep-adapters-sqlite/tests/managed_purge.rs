//! Synthetic file-backed SQLite/WAL fixtures only. No real histories or profiles.
use agent_session_grep_adapters_sqlite::{
    SourceBatch, SqliteControlStore,
    control::{BackupPurpose, BackupState, PurgeCheckpoint, PurgeFailure},
    managed_cache::{
        CacheBinding, CacheCandidate, CacheInsert, CachePageRequest, InsertOutcome, ManagedCache,
    },
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity, SharedGuard},
    managed_maintenance::{BackupOutcome, MaintenanceCatalog},
    managed_purge::{
        ClassifiedPrivateArtifact, PrivateArtifactClass, PrivateArtifactInventory, PurgeStage,
        purge_lock_kind, run, run_with_inventory,
    },
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{PortError, SearchProvider, control::*, managed::*};
use rusqlite::{Connection, params};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(8)
}
fn current(control: &SqliteControlStore) -> ControlSeq {
    retry_expected_success(|| control.status())
        .unwrap()
        .policy
        .control_seq
}
fn retry_expected_success<T>(
    mut operation: impl FnMut() -> Result<T, PortError>,
) -> Result<T, PortError> {
    // Each fixture owns a private root. Retry only typed contention inside one
    // bounded readiness scope because parallel test binaries can briefly starve
    // the production 250ms runtime check without creating a real writer.
    let end = deadline();
    loop {
        match operation() {
            Err(PortError::WriterBusy(_)) if Instant::now() < end => std::thread::yield_now(),
            result => return result,
        }
    }
}
fn acquire(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let end = deadline();
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < end => std::thread::yield_now(),
            error => panic!("synthetic lock acquisition: {error:?}"),
        }
    }
}
fn entity(kind: IdKind) -> StableId {
    StableId::native_checked(kind, "shared-purge-fixture").unwrap()
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    catalog: PathBuf,
    control: SqliteControlStore,
    selection_a: Selection,
    source_a: PathBuf,
    source_b: PathBuf,
    generation: u64,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("owned-data");
        let catalog = root.join("catalog.db");
        let source_a = temp.path().join("synthetic-a.jsonl");
        let source_b = temp.path().join("synthetic-b.jsonl");
        fs::write(&source_a, b"synthetic read-only source sentinel A").unwrap();
        fs::write(&source_b, b"synthetic read-only source sentinel B").unwrap();
        let control =
            SqliteControlStore::create(&root, &id("installation"), DesiredUpdates::Running)
                .unwrap();
        let fixture_end = Instant::now() + Duration::from_secs(30);
        let select = |path: &Path| {
            control
                .with_runtime_deadline(fixture_end, || {
                    control.add_selection(
                        current(&control),
                        SelectionRequest {
                            region: ScopeRegion {
                                provider: SearchProvider::Claude,
                                locator: CanonicalLocator::from_path(path).unwrap(),
                                kind: RootKind::Exact,
                            },
                            root_identity: Some(id("synthetic-source-root")),
                            now_ms: 1,
                        },
                    )
                })
                .unwrap()
                .value
        };
        let selection_a = select(&source_a);
        let selection_b = select(&source_b);
        let store = ManagedStore::create(&catalog, &control, id("catalog"), 1).unwrap();
        drop(store);
        let background = acquire(&root, LockKind::Background);
        let worker = control
            .with_runtime_deadline(fixture_end, || control.bind_worker(&background, id("boot")))
            .unwrap();
        control
            .with_runtime_deadline(fixture_end, || {
                control.register_worker(current(&control), &worker, 1, 1)
            })
            .unwrap();
        let selections: Vec<_> = [&selection_a, &selection_b]
            .into_iter()
            .map(|selection| SelectionRevision {
                selection_id: selection.id.clone(),
                revision: selection.revision,
                root_identity: selection.root_identity.clone().unwrap(),
            })
            .collect();
        let CycleAdmission::Queued(cycle) = control
            .with_runtime_deadline(fixture_end, || {
                control.queue_cycle(current(&control), selections.clone())
            })
            .unwrap()
            .value
        else {
            panic!("cycle denied")
        };
        let cycle = control
            .with_runtime_deadline(fixture_end, || {
                control.start_cycle(current(&control), &worker, cycle.token.cycle_seq, 2)
            })
            .unwrap()
            .value;
        let store = control
            .with_runtime_deadline(fixture_end, || {
                ManagedStore::open_for_write(&catalog, &control)
            })
            .unwrap();
        for (source, path, selection, text) in [
            (
                "source-a",
                &source_a,
                &selection_a,
                "allowed common proof withdrawn_secret",
            ),
            ("source-b", &source_b, &selection_b, "allowed common proof"),
        ] {
            let observation = SourceObservation {
                binding: SourceBinding {
                    source_id: SourceId::parse(source).unwrap(),
                    source_path: path.to_str().unwrap().into(),
                    provider: SearchProvider::Claude,
                    namespace_id: None,
                    root_identity: "synthetic-source-root".into(),
                },
                revision_id: RevisionId::parse(&format!("revision-{source}")).unwrap(),
                revision_digest: format!("synthetic-{source}"),
                parser_version: 1,
                state: ObservationState::Complete,
                cycle_seq: cycle.token.cycle_seq.get(),
                worker_boot_id: "boot".into(),
                catalog_incarnation: "catalog".into(),
                policy_epoch: cycle.policy_epoch.get(),
                started_control_seq: cycle.started_control_seq.unwrap().get(),
                observed_at_ms: 3,
                committed_at_ms: 4,
                selections: vec![SelectionProof {
                    selection_id: selection.id.as_str().into(),
                    selection_revision: selection.revision.get(),
                    root_identity: "synthetic-source-root".into(),
                }],
                repositories: vec![],
            };
            let batch = SourceBatch {
                source_path: observation.binding.source_path.clone(),
                entries: vec![
                    (entity(IdKind::Message), serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":null})).unwrap(), text.into()),
                    (StableId::native_checked(IdKind::Message, "second-purge-fixture").unwrap(), serde_json::to_vec(&serde_json::json!({"role":"assistant","text":"second common proof","timestamp":null})).unwrap(), "second common proof".into()),
                    (entity(IdKind::Session), serde_json::to_vec(&serde_json::json!({"documents":[entity(IdKind::Document).as_str()]})).unwrap(), String::new()),
                    (entity(IdKind::Document), serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":observation.revision_digest,"len":100})).unwrap(), String::new()),
                ], placements: vec![
                    MessagePlacement::new(entity(IdKind::Session), entity(IdKind::Document), entity(IdKind::Message), 0, false, None),
                    MessagePlacement::new(entity(IdKind::Session), entity(IdKind::Document), StableId::native_checked(IdKind::Message, "second-purge-fixture").unwrap(), 1, false, None),
                ],
                edges: vec![], activities: vec![], usage_events: vec![], relation_complete: true, len_bytes: Some(100),
                fingerprint: Some(observation.revision_digest.clone()), provider_id: Some("claude-code".into()), resume_claims: vec![],
            };
            control
                .with_runtime_deadline(fixture_end, || {
                    store.commit_source(&control, &worker, &batch, &observation)
                })
                .unwrap();
        }
        let generation = store
            .with_read(
                &control,
                RequestIntersection::Selected,
                deadline(),
                |read| Ok(read.snapshot().generation as u64),
            )
            .unwrap();
        drop(store);
        Self {
            _temp: temp,
            root,
            catalog,
            control,
            selection_a,
            source_a,
            source_b,
            generation,
        }
    }
    fn revoke(&self) -> ControlId {
        self.control
            .with_runtime_deadline(deadline(), || {
                self.control.revoke_selection(
                    current(&self.control),
                    &self.selection_a.id,
                    Some(&id("source-a")),
                    10,
                )
            })
            .unwrap()
            .value
            .purge_job
            .id
    }
    fn run(&self, nonce: &str) -> agent_session_grep_adapters_sqlite::managed_purge::PurgeReport {
        let guard = acquire(&self.root, purge_lock_kind().unwrap());
        let owner = self
            .control
            .with_runtime_deadline(deadline(), || {
                self.control.bind_purge_owner(&guard, id(nonce))
            })
            .unwrap();
        run(&self.control, &self.catalog, &owner, None, 20, deadline()).unwrap()
    }
    fn count(&self, query: &str) -> i64 {
        Connection::open_with_flags(&self.catalog, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row(query, [], |row| row.get(0))
            .unwrap()
    }
}
#[test]
fn paused_purge_removes_withdrawn_source_preserves_shared_allowed_original_and_deny() {
    let f = Fixture::new();
    let job = f.revoke();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let policy = f.control.status().unwrap().policy;
    let source_a = fs::read(&f.source_a).unwrap();
    let source_b = fs::read(&f.source_b).unwrap();
    let report = f.run("purge-owner");
    assert!(report.complete(), "{report:?}");
    assert_eq!(report.sources_retired, 1);
    assert_eq!(report.generation, Some(f.generation + 1));
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Complete
    );
    let after = f.control.status().unwrap();
    assert_eq!(after.desired_updates, DesiredUpdates::Paused);
    assert_eq!(after.policy.exclusions, policy.exclusions);
    assert_eq!(after.policy.policy_epoch, policy.policy_epoch);
    assert!(
        after
            .policy
            .revocations
            .iter()
            .all(|intent| intent.state == RevocationState::Settled)
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        0
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_revision_receipts WHERE source_id='source-a'"),
        0
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-b'"),
        2
    );
    assert_eq!(
        f.count(
            "SELECT COUNT(*) FROM projection_fts WHERE projection_fts MATCH 'withdrawn_secret'"
        ),
        0
    );
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    let text = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                Ok(read
                    .query_lexical("allowed", &ProjectionQuery::default(), 5)?
                    .hits[0]
                    .projection
                    .message
                    .text
                    .clone())
            },
        )
        .unwrap();
    assert_eq!(text, "allowed common proof");
    assert_eq!(fs::read(&f.source_a).unwrap(), source_a);
    assert_eq!(fs::read(&f.source_b).unwrap(), source_b);
    drop(store);
    let repeated = f.run("new-owner");
    assert!(repeated.complete());
    assert_eq!(repeated.sources_retired, 0);
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        (f.generation + 1) as i64
    );
}
#[test]
fn stopped_purge_sanitizes_shared_legacy_fts_vector_without_changing_allowed_projection() {
    let f = Fixture::new();
    let conn = Connection::open(&f.catalog).unwrap();
    conn.execute(
        "INSERT INTO catalog(id,payload) VALUES(?1,?2)",
        params![
            entity(IdKind::Message).as_str(),
            b"withdrawn_secret legacy merged".as_slice()
        ],
    )
    .unwrap();
    for source in [&f.source_a, &f.source_b] {
        conn.execute(
            "INSERT INTO source_membership(source_path,message_id) VALUES(?1,?2)",
            params![source.to_str().unwrap(), entity(IdKind::Message).as_str()],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO fts(id,text) VALUES('synthetic_identity','withdrawn_secret legacy')",
        [],
    )
    .unwrap();
    let rowid = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO fts_ids VALUES(?1,'synthetic_identity',?2)",
        params![entity(IdKind::Message).as_str(), rowid],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO message_vec VALUES(?1,'synthetic-model',1,X'00000000')",
        [entity(IdKind::Message).as_str()],
    )
    .unwrap();
    drop(conn);
    f.revoke();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Stopped)
        .unwrap();
    let report = f.run("stopped-owner");
    assert!(report.complete(), "{report:?}");
    for table in [
        "catalog",
        "fts",
        "fts_ids",
        "message_vec",
        "source_membership",
    ] {
        assert_eq!(
            f.count(&format!("SELECT COUNT(*) FROM {table}")),
            0,
            "{table}"
        );
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-b'"),
        2
    );
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Stopped
    );
    let db = fs::read(&f.catalog).unwrap();
    assert!(
        !db.windows(b"withdrawn_secret".len())
            .any(|part| part == b"withdrawn_secret")
    );
}
#[test]
fn emission_and_catalog_busy_preserve_content_and_resume_same_job_after_os_release() {
    let f = Fixture::new();
    let job = f.revoke();
    for kind in [LockKind::PolicyEmission, LockKind::CatalogHandles] {
        let blocker = SharedGuard::try_acquire(&f.root, kind).unwrap();
        let guard = acquire(&f.root, purge_lock_kind().unwrap());
        let owner = f
            .control
            .bind_purge_owner(&guard, id("waiting-owner"))
            .unwrap();
        let started = Instant::now();
        match run(
            &f.control,
            &f.catalog,
            &owner,
            None,
            20,
            started + Duration::from_millis(40),
        ) {
            Ok(report) => assert!(!report.complete()),
            Err(PortError::WriterBusy(_)) => {}
            other => panic!("blocked drain must be incomplete or bounded busy: {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
            2
        );
        assert_ne!(
            f.control.purge_job_status(&job).unwrap().job.state,
            PurgeState::Complete
        );
        drop(guard);
        drop(blocker);
    }
    assert!(f.run("resumed-owner").complete());
}
#[test]
fn wrong_lock_or_physical_root_cannot_claim_or_run_a_job() {
    let f = Fixture::new();
    let other = Fixture::new();
    let job = f.revoke();
    let wrong = acquire(&f.root, LockKind::Background);
    assert!(f.control.bind_purge_owner(&wrong, id("wrong")).is_err());
    let lock = acquire(&other.root, purge_lock_kind().unwrap());
    let owner = other
        .control
        .bind_purge_owner(&lock, id("foreign"))
        .unwrap();
    let before = f.control.status().unwrap();
    assert!(run(&f.control, &f.catalog, &owner, None, 20, deadline()).is_err());
    let policy = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&policy).unwrap();
    assert!(
        f.control
            .claim_purge_job(current(&f.control), &owner, &bound, &job, 20)
            .is_err()
    );
    assert_eq!(f.control.status().unwrap(), before);
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Pending
    );
}
#[test]
fn durable_catalog_commit_retries_after_artifact_stage_interruption_without_double_generation() {
    let f = Fixture::new();
    let job = f.revoke();
    let unclassified = f.root.join("backups").join("unknown");
    fs::create_dir_all(&unclassified).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [f.root.join("backups"), unclassified.clone()] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    fs::write(
        unclassified.join("catalog.db"),
        b"unknown owned backup bytes",
    )
    .unwrap();
    let first = f.run("first-owner");
    assert_eq!(first.catalog, PurgeStage::Complete);
    assert_eq!(
        first.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
    assert!(!first.complete());
    let after = f.count("SELECT active_generation FROM store_metadata");
    let checkpoint = f.control.purge_job_status(&job).unwrap();
    assert_eq!(checkpoint.job.state, PurgeState::Blocked);
    assert!(checkpoint.checkpoint.is_some());
    let second = f.run("second-owner");
    assert_eq!(second.catalog, PurgeStage::Complete);
    assert!(!second.complete());
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        after
    );
    assert!(unclassified.join("catalog.db").exists());
    assert!(!f.control.status().unwrap().policy.exclusions.is_empty());
}
#[test]
fn rollback_backup_needs_explicit_installation_authority_and_remains_nonrestorable() {
    let f = Fixture::new();
    let prefix = verified_prefix(&f);
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let installation = f.control.bind_installation(&prefix, &install_lock).unwrap();
    assert!(matches!(
        create_backup(&f, &installation, "rollback"),
        BackupOutcome::Created(_)
    ));
    f.revoke();
    let first = f.run("no-install-authority");
    assert_eq!(
        first.backups,
        PurgeStage::Pending(PurgeFailure::BackupAuthorityMissing)
    );
    assert!(!first.complete());
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("with-install-authority"))
        .unwrap();
    let complete = run(
        &f.control,
        &f.catalog,
        &owner,
        Some(&installation),
        20,
        deadline(),
    )
    .unwrap();
    assert!(complete.complete(), "{complete:?}");
    assert_eq!(
        f.control.backup_records().unwrap()[0].state,
        BackupState::PurgedByPolicy
    );
    assert!(!f.root.join("backups/rollback/catalog.db").exists());
}

fn verified_prefix(f: &Fixture) -> PathBuf {
    let prefix = f._temp.path().join("verified-prefix");
    fs::create_dir(&prefix).unwrap();
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let policy_lock = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&policy_lock).unwrap();
    f.control
        .record_verified_installation_prefix(&prefix, &install_lock, &bound, deadline())
        .unwrap();
    prefix
}
fn create_backup(
    f: &Fixture,
    installation: &agent_session_grep_adapters_sqlite::control::InstallationLockAuthority<'_>,
    backup: &str,
) -> BackupOutcome {
    {
        let policy_lock = acquire(&f.root, LockKind::PolicyOwner);
        let bound = f.control.bind_control_root(&policy_lock).unwrap();
        f.control
            .begin_maintenance(
                current(&f.control),
                &id("backup-owner"),
                &bound,
                installation,
                MaintenanceFence {
                    state: MaintenanceState::Updating,
                    owner: Some(id("backup-owner")),
                    phase: Some(MaintenancePhase::BackedUp),
                },
            )
            .unwrap();
    }
    let result = {
        let catalog = MaintenanceCatalog::open_authorized(
            &f.control,
            installation,
            &id("backup-owner"),
            &f.catalog,
            deadline(),
        )
        .unwrap();
        catalog
            .create_backup(
                &f.control,
                installation,
                &id("backup-owner"),
                &id(backup),
                BackupPurpose::BetaRollback,
                5,
                deadline(),
            )
            .unwrap()
    };
    let policy_lock = acquire(&f.root, LockKind::PolicyOwner);
    let bound = f.control.bind_control_root(&policy_lock).unwrap();
    f.control
        .clear_maintenance(
            current(&f.control),
            &id("backup-owner"),
            &bound,
            installation,
        )
        .unwrap();
    result
}
#[test]
fn purged_content_free_bindings_allow_new_policy_compatible_backup() {
    let f = Fixture::new();
    f.revoke();
    assert!(f.run("purge-first").complete());
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_bindings WHERE source_id='source-a'"),
        1
    );
    let prefix = verified_prefix(&f);
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let installation = f.control.bind_installation(&prefix, &install_lock).unwrap();
    let BackupOutcome::Created(metadata) = create_backup(&f, &installation, "after-purge") else {
        panic!("empty withdrawn binding incorrectly counted as backup content")
    };
    assert_eq!(metadata.source_ids, vec![id("source-b")]);
    let verified = agent_session_grep_adapters_sqlite::managed_maintenance::verify_backup_until(
        &f.control,
        &id("after-purge"),
        deadline(),
    )
    .unwrap();
    assert_eq!(verified.coverage().len(), 1);
    assert!(f.run("verify-complete").complete());
    assert!(f.root.join("backups/after-purge/catalog.db").exists());
}
#[test]
fn corrupted_registered_backup_is_quarantined_with_accounting_and_never_silently_deleted() {
    let f = Fixture::new();
    let prefix = verified_prefix(&f);
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let installation = f.control.bind_installation(&prefix, &install_lock).unwrap();
    assert!(matches!(
        create_backup(&f, &installation, "corrupt"),
        BackupOutcome::Created(_)
    ));
    let path = f.root.join("backups/corrupt/catalog.db");
    fs::write(&path, b"synthetic unclassified replacement bytes").unwrap();
    f.revoke();
    for nonce in ["quarantine-first", "quarantine-second"] {
        let guard = acquire(&f.root, purge_lock_kind().unwrap());
        let owner = f.control.bind_purge_owner(&guard, id(nonce)).unwrap();
        let report = run(
            &f.control,
            &f.catalog,
            &owner,
            Some(&installation),
            20,
            deadline(),
        )
        .unwrap();
        assert!(!report.complete());
        assert_eq!(
            report.backups,
            PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
        );
        let record = f.control.backup_records().unwrap().remove(0);
        assert_eq!(record.state, BackupState::Quarantined);
        // Terminal quarantine keeps the last verified digest so rollback
        // accounting survives; the corrupted replacement is never deleted.
        assert!(record.digest.is_some());
        assert_eq!(record.source_ids, vec![id("source-a"), id("source-b")]);
        assert_eq!(
            f.control.artifact_records().unwrap()[0].source_ids,
            record.source_ids
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic unclassified replacement bytes"
        );
        assert!(
            agent_session_grep_adapters_sqlite::managed_maintenance::verify_backup_until(
                &f.control,
                &id("corrupt"),
                deadline()
            )
            .is_err()
        );
    }
}

#[test]
fn legacy_digestless_quarantine_does_not_block_remaining_backups_or_job_completion() {
    let f = Fixture::new();
    let prefix = verified_prefix(&f);
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let installation = f.control.bind_installation(&prefix, &install_lock).unwrap();
    assert!(matches!(
        create_backup(&f, &installation, "legacy-digestless"),
        BackupOutcome::Created(_)
    ));
    // Reproduce the historical digest-less quarantine tombstone exactly as an
    // older build wrote it: state flips, digest/size are cleared.
    {
        let conn = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
        conn.execute(
            "UPDATE backup_manifests SET state='quarantined',digest='',size_bytes=0 WHERE backup_id='legacy-digestless'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE private_artifacts SET state='quarantined',digest=NULL,owner_nonce=NULL WHERE artifact_id='legacy-digestless'",
            [],
        )
        .unwrap();
    }
    let job = f.revoke();
    let report = f.run("digestless-contained");
    // The digest-less tombstone is contained rather than deletable, but the
    // withdrawn source and every other stage must still finish cleanly.
    assert!(report.complete(), "{report:?}");
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Complete
    );
    let record = f
        .control
        .backup_records()
        .unwrap()
        .into_iter()
        .find(|backup| backup.backup_id == id("legacy-digestless"))
        .unwrap();
    assert_eq!(record.state, BackupState::Quarantined);
    assert_eq!(record.digest, None);
}

#[test]
fn transient_backend_verification_failure_never_quarantines_a_rollback_backup() {
    let f = Fixture::new();
    let prefix = verified_prefix(&f);
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let installation = f.control.bind_installation(&prefix, &install_lock).unwrap();
    assert!(matches!(
        create_backup(&f, &installation, "transient-io"),
        BackupOutcome::Created(_)
    ));
    let job = f.revoke();
    let manifest = f.root.join("backups/transient-io/manifest.json");
    let original = fs::read(&manifest).unwrap();
    // A directory replacement turns the sidecar read into a transient OS
    // I/O refusal (Backend on Windows), never a typed artifact defect.
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    let report = f.run("transient-io-owner");
    assert_eq!(report.backups, PurgeStage::Pending(PurgeFailure::Storage));
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Blocked
    );
    let record = f.control.backup_records().unwrap().remove(0);
    assert_eq!(record.state, BackupState::Complete);
    assert!(record.digest.is_some());
    // Removing the obstruction lets verification classify the artifact again;
    // this fixture intentionally has no installation authority for deletion.
    fs::remove_dir(&manifest).unwrap();
    fs::write(&manifest, &original).unwrap();
    let recovered = f.run("transient-io-retry");
    assert_ne!(
        recovered.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
    assert_ne!(
        f.control.backup_records().unwrap().remove(0).state,
        BackupState::Quarantined
    );
}
#[test]
fn genuine_cached_candidates_are_retired_and_physical_private_cache_contains_no_withdrawn_text() {
    let f = Fixture::new();
    let binding = CacheBinding::new(
        "common",
        "lexical-v1",
        &ProjectionQuery::default(),
        "none",
        "score-desc-id-asc-v1",
    )
    .unwrap();
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    let end = deadline();
    let cursor = store
        .with_read(&f.control, RequestIntersection::Selected, end, |read| {
            let mut candidates: Vec<_> = read
                .list(&ProjectionQuery::default(), false, 10)?
                .entries
                .into_iter()
                .filter(|entry| entry.id().kind() == IdKind::Message)
                .map(|entry| CacheCandidate { entry, score: 1.0 })
                .collect();
            // Ask for the original from the long, currently allowed source explicitly
            // to ensure the cached body really contains the later withdrawn fact.
            let chosen = read
                .query_lexical("withdrawn_secret", &ProjectionQuery::default(), 1)?
                .hits
                .remove(0)
                .projection;
            let candidate = candidates
                .iter_mut()
                .find(|candidate| candidate.entry.id() == &chosen.message.id)
                .unwrap();
            candidate.entry = ProjectionListEntry::Message(Box::new(chosen));
            Ok(
                match cache.insert(
                    &f.control,
                    read,
                    CacheInsert {
                        binding: &binding,
                        candidates: &candidates,
                        next_offset: 1,
                        truncated: true,
                        now_ms: 5,
                        deadline: end,
                    },
                ) {
                    InsertOutcome::Stored(cursor) => cursor,
                    other => panic!("synthetic real cache insert failed: {other:?}"),
                },
            )
        })
        .unwrap();
    drop(store);
    let cache_path = ManagedCache::path(&f.root);
    let before: Vec<u8> =
        Connection::open_with_flags(&cache_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row("SELECT result_payload FROM result_sets", [], |row| {
                row.get(0)
            })
            .unwrap();
    assert!(
        before
            .windows(b"withdrawn_secret".len())
            .any(|value| value == b"withdrawn_secret")
    );
    f.revoke();
    assert!(f.run("cache-purge").complete());
    let retained: i64 =
        Connection::open_with_flags(&cache_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM result_sets", [], |row| row.get(0))
            .unwrap();
    assert_eq!(retained, 0);
    let bytes = fs::read(&cache_path).unwrap();
    assert!(
        !bytes
            .windows(b"withdrawn_secret".len())
            .any(|value| value == b"withdrawn_secret")
    );
    let store = ManagedStore::open(&f.catalog, &f.control).unwrap();
    let result = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                Ok(cache.page(
                    &f.control,
                    read,
                    CachePageRequest {
                        binding: &binding,
                        cursor: cursor.as_str(),
                        limit: 1,
                        now_ms: 21,
                        deadline: deadline(),
                    },
                ))
            },
        )
        .unwrap();
    assert!(result.is_err());
}
#[test]
fn unclassified_legacy_outbox_metadata_blocks_purge_without_rewriting_recovery_evidence() {
    let f = Fixture::new();
    let conn = Connection::open(&f.catalog).unwrap();
    let detail =
        serde_json::json!([{"source_path": f.source_a, "native_resume":"withdrawn_secret"}])
            .to_string();
    conn.execute("INSERT INTO index_batches(operation_id,base_generation,target_generation,state,operation_digest,upsert_ids_json,delete_ids_json,durable_point,created_at_ms,source_replacements_json) VALUES('synthetic-legacy',?1,?2,'aborted','synthetic-digest','[]','[]','aborted',1,?3)", params![f.generation as i64, (f.generation+1) as i64, detail]).unwrap();
    drop(conn);
    let job = f.revoke();
    let report = f.run("legacy-review");
    assert!(!report.complete());
    assert_eq!(
        report.catalog,
        PurgeStage::Pending(PurgeFailure::UnclassifiedCatalog)
    );
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        f.generation as i64
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        2
    );
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Blocked
    );
    let after: String = Connection::open_with_flags(
        &f.catalog,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT source_replacements_json FROM index_batches WHERE operation_id='synthetic-legacy'",
        [],
        |row| row.get(0),
    )
    .unwrap();
    assert_eq!(after, detail);
}

// A real subprocess exits without Drop after the durable claim. The parent
// uses no stdout reader, bounds every poll, and kills/reaps on any failed test.
const CHILD_ROOT: &str = "ASG_SYNTHETIC_PURGE_CHILD_ROOT";
const CHILD_JOB: &str = "ASG_SYNTHETIC_PURGE_CHILD_JOB";
const CHILD_READY: &str = "ASG_SYNTHETIC_PURGE_CHILD_READY";
const CHILD_EXIT: &str = "ASG_SYNTHETIC_PURGE_CHILD_EXIT";
struct ReapedChild(Child);
impl Drop for ReapedChild {
    fn drop(&mut self) {
        if !self.0.try_wait().is_ok_and(|status| status.is_some()) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
#[test]
fn child_claim_fixture() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let control = SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
    let guard = acquire(&root, purge_lock_kind().unwrap());
    let owner = control
        .bind_purge_owner(&guard, id("crashed-owner"))
        .unwrap();
    {
        let policy = acquire(&root, LockKind::PolicyOwner);
        let bound = control.bind_control_root(&policy).unwrap();
        control
            .claim_purge_job(
                current(&control),
                &owner,
                &bound,
                &id(&std::env::var(CHILD_JOB).unwrap()),
                20,
            )
            .unwrap();
    }
    let ready = PathBuf::from(std::env::var_os(CHILD_READY).unwrap());
    let exit = PathBuf::from(std::env::var_os(CHILD_EXIT).unwrap());
    fs::write(ready, b"durable claim under real OS lock").unwrap();
    let end = deadline();
    while !exit.exists() {
        assert!(
            Instant::now() < end,
            "parent did not request the synthetic crash"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    std::process::exit(37);
}
#[test]
fn real_process_exit_releases_os_owner_and_resumes_durable_claim_without_changing_pause_or_deny() {
    let f = Fixture::new();
    let job = f.revoke();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let ready = f._temp.path().join("child-ready");
    let exit = f._temp.path().join("child-exit");
    let end = deadline();
    let mut child = ReapedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_claim_fixture", "--nocapture"])
            .env(CHILD_ROOT, &f.root)
            .env(CHILD_JOB, job.as_str())
            .env(CHILD_READY, &ready)
            .env(CHILD_EXIT, &exit)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    while !ready.exists() {
        assert!(
            Instant::now() < end,
            "synthetic child did not reach its durable claim"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "synthetic child exited before its claim"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        ExclusiveGuard::try_acquire(&f.root, purge_lock_kind().unwrap()),
        Err(PortError::WriterBusy(_))
    ));
    let claim = f.control.purge_job_status(&job).unwrap();
    assert_eq!(claim.owner_nonce, Some(id("crashed-owner")));
    assert_eq!(claim.checkpoint, Some(PurgeCheckpoint::Claimed));
    fs::write(exit, b"exit without Drop").unwrap();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < end,
            "synthetic child did not exit within its original budget"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.code(), Some(37));
    let report = f.run("recovered-owner");
    assert!(report.complete(), "{report:?}");
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.attempts.get(),
        2
    );
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert!(!f.control.status().unwrap().policy.exclusions.is_empty());
    assert_eq!(report.generation, Some(f.generation + 1));
    assert!(f.run("verify-again").complete());
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        (f.generation + 1) as i64
    );
}

#[cfg(windows)]
#[test]
fn quarantined_backup_replacement_after_partial_unlink_is_retained_as_unknown() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let prefix = verified_prefix(&f);
    let install_lock = acquire(
        &prefix,
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                "installation-update",
            )
            .unwrap(),
        ),
    );
    let installation = f.control.bind_installation(&prefix, &install_lock).unwrap();
    assert!(matches!(
        create_backup(&f, &installation, "replace-pending"),
        BackupOutcome::Created(_)
    ));
    let path = f.root.join("backups/replace-pending/catalog.db");
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1 | 2)
        .open(&path)
        .unwrap();
    let job = f.revoke();
    {
        let guard = acquire(&f.root, purge_lock_kind().unwrap());
        let owner = f
            .control
            .bind_purge_owner(&guard, id("pending-original"))
            .unwrap();
        let report = run(
            &f.control,
            &f.catalog,
            &owner,
            Some(&installation),
            20,
            deadline(),
        )
        .unwrap();
        assert_eq!(
            report.backups,
            PurgeStage::Pending(PurgeFailure::ArtifactPending)
        );
        assert_eq!(
            report
                .jobs
                .iter()
                .find(|value| value.id == job)
                .unwrap()
                .state,
            PurgeState::Blocked
        );
        assert!(f.control.backup_records().unwrap()[0].digest.is_some());
    }
    drop(held);
    fs::write(&path, b"synthetic replacement of quarantined data").unwrap();
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("replacement-review"))
        .unwrap();
    let report = run(
        &f.control,
        &f.catalog,
        &owner,
        Some(&installation),
        21,
        deadline(),
    )
    .unwrap();
    assert_eq!(
        report.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
    let record = f.control.backup_records().unwrap().remove(0);
    assert_eq!(record.state, BackupState::Quarantined);
    assert!(record.digest.is_some());
    assert_eq!(record.source_ids, vec![id("source-a"), id("source-b")]);
    assert_eq!(
        fs::read(&path).unwrap(),
        b"synthetic replacement of quarantined data"
    );
}
#[test]
fn writer_lease_and_sqlite_writer_block_purge_with_no_partial_content_commit() {
    let f = Fixture::new();
    let job = f.revoke();
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("blocked-writer"))
        .unwrap();
    let lease = agent_session_grep_adapters_sqlite::WriterLease::try_acquire(&f.root).unwrap();
    match run(
        &f.control,
        &f.catalog,
        &owner,
        None,
        20,
        Instant::now() + Duration::from_millis(40),
    ) {
        Ok(report) => assert!(!report.complete()),
        Err(PortError::WriterBusy(_)) => {}
        other => panic!("writer lease contention was not bounded: {other:?}"),
    }
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        f.generation as i64
    );
    drop(lease);
    let conn = Connection::open(&f.catalog).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    match run(
        &f.control,
        &f.catalog,
        &owner,
        None,
        20,
        Instant::now() + Duration::from_millis(40),
    ) {
        Ok(report) => assert!(!report.complete()),
        Err(PortError::WriterBusy(_)) => {}
        other => panic!("SQLite writer contention was not bounded: {other:?}"),
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        2
    );
    assert_ne!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Complete
    );
    conn.execute_batch("ROLLBACK").unwrap();
    drop(conn);
    drop(guard);
    assert!(f.run("writer-retry").complete());
}

#[test]
fn control_writer_contention_consumes_original_deadline_and_does_not_poison_reused_store() {
    let f = Fixture::new();
    let job = f.revoke();
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("control-busy"))
        .unwrap();
    let conn = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    assert!(matches!(
        run(
            &f.control,
            &f.catalog,
            &owner,
            None,
            20,
            started + Duration::from_millis(40)
        ),
        Err(PortError::WriterBusy(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        2
    );
    conn.execute_batch("ROLLBACK").unwrap();
    drop(conn);
    drop(guard);
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Pending
    );
    assert!(f.run("control-retry").complete());
    // The original connection remains usable beyond the expired run budget.
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
}

#[test]
fn transient_control_writer_is_retried_inside_one_purge_slice_and_claims_only_once() {
    let f = Fixture::new();
    let job = f.revoke();
    f.control
        .set_desired_updates(current(&f.control), DesiredUpdates::Paused)
        .unwrap();
    let source_a = fs::read(&f.source_a).unwrap();
    let source_b = fs::read(&f.source_b).unwrap();
    let root = f.root.clone();
    let catalog = f.catalog.clone();
    let report = std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (run_tx, run_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let runner = scope.spawn(move || {
            let control =
                SqliteControlStore::open_existing_writable(&root, &id("installation")).unwrap();
            let guard = acquire(&root, purge_lock_kind().unwrap());
            let owner = control
                .bind_purge_owner(&guard, id("same-slice-owner"))
                .unwrap();
            ready_tx.send(()).unwrap();
            run_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let end = Instant::now() + Duration::from_secs(5);
            result_tx
                .send(run(&control, &catalog, &owner, None, 20, end))
                .unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let writer = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        run_tx.send(()).unwrap();
        // Exceeds the inner 1ms allowance and the default 250ms allowance.
        // The same invocation must still own the job after this real refusal.
        std::thread::sleep(Duration::from_millis(350));
        let before_release = result_rx.try_recv();
        writer.execute_batch("ROLLBACK").unwrap();
        assert!(
            matches!(before_release, Err(std::sync::mpsc::TryRecvError::Empty)),
            "purge returned before its original slice ended: {before_release:?}"
        );
        let report = result_rx
            .recv_timeout(Duration::from_secs(8))
            .unwrap()
            .unwrap();
        runner.join().unwrap();
        report
    });
    assert!(report.complete(), "{report:?}");
    let progress = f.control.purge_job_status(&job).unwrap();
    assert_eq!(progress.job.state, PurgeState::Complete);
    assert_eq!(progress.job.attempts.get(), 1);
    assert_eq!(
        progress.checkpoint,
        Some(PurgeCheckpoint::ArtifactsVerified)
    );
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert!(!f.control.status().unwrap().policy.exclusions.is_empty());
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        (f.generation + 1) as i64
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-b'"),
        2
    );
    assert_eq!(fs::read(&f.source_a).unwrap(), source_a);
    assert_eq!(fs::read(&f.source_b).unwrap(), source_b);
}

#[test]
fn nested_purge_control_writer_uses_earlier_end_and_preserves_original_job() {
    let f = Fixture::new();
    let job = f.revoke();
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("nested-control-owner"))
        .unwrap();
    let writer = Connection::open(SqliteControlStore::path(&f.root)).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    let result = f
        .control
        .with_runtime_deadline(started + Duration::from_millis(20), || {
            run(
                &f.control,
                &f.catalog,
                &owner,
                None,
                20,
                started + Duration::from_secs(1),
            )
        });
    let elapsed = started.elapsed();
    writer.execute_batch("ROLLBACK").unwrap();
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    assert!(
        elapsed < Duration::from_millis(150),
        "nested control elapsed: {elapsed:?}"
    );
    let progress = f.control.purge_job_status(&job).unwrap();
    assert_eq!(progress.job.state, PurgeState::Pending);
    assert_eq!(progress.job.attempts.get(), 0);
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        f.generation as i64
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        2
    );
    drop(guard);
    assert!(f.run("nested-control-retry").complete());
}

#[test]
fn nested_purge_catalog_handle_drain_uses_earlier_end_and_resumes_same_job() {
    let f = Fixture::new();
    let job = f.revoke();
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("nested-catalog-owner"))
        .unwrap();
    let admission_end = deadline();
    let held = loop {
        match SharedGuard::try_acquire(&f.root, LockKind::CatalogHandles) {
            Ok(guard) => break guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < admission_end => {
                std::thread::yield_now()
            }
            Err(error) => panic!("synthetic catalog hold: {error:?}"),
        }
    };
    let started = Instant::now();
    let result = f
        .control
        .with_runtime_deadline(started + Duration::from_millis(40), || {
            run(
                &f.control,
                &f.catalog,
                &owner,
                None,
                20,
                started + Duration::from_secs(1),
            )
        });
    let elapsed = started.elapsed();
    drop(held);
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    assert!(
        elapsed < Duration::from_millis(200),
        "nested catalog drain elapsed: {elapsed:?}"
    );
    let progress = f.control.purge_job_status(&job).unwrap();
    assert_ne!(progress.job.state, PurgeState::Complete);
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        f.generation as i64
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        2
    );
    // Use the same OS owner to resolve the original durable job after release.
    let report = run(&f.control, &f.catalog, &owner, None, 21, deadline()).unwrap();
    assert!(report.complete(), "{report:?}");
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.attempts.get(),
        1
    );
}

#[test]
fn expired_purge_run_keeps_original_pending_job_and_catalog_generation() {
    let f = Fixture::new();
    let job = f.revoke();
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("expired-slice-owner"))
        .unwrap();
    let result = run(&f.control, &f.catalog, &owner, None, 20, Instant::now());
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    let progress = f.control.purge_job_status(&job).unwrap();
    assert_eq!(progress.job.state, PurgeState::Pending);
    assert_eq!(progress.job.attempts.get(), 0);
    assert_eq!(
        f.count("SELECT active_generation FROM store_metadata"),
        f.generation as i64
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        2
    );
}

#[test]
fn unclassified_owned_side_catalog_is_preserved_and_prevents_terminal_job() {
    let f = Fixture::new();
    let side = f.root.join("interrupted-restore.db");
    fs::write(&side, b"synthetic unclassified side-image withdrawn_secret").unwrap();
    let job = f.revoke();
    let report = f.run("side-inventory");
    assert_eq!(report.catalog, PurgeStage::Complete);
    assert_eq!(
        report.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
    assert!(!report.complete());
    assert_eq!(
        f.control.purge_job_status(&job).unwrap().job.state,
        PurgeState::Blocked
    );
    assert_eq!(
        fs::read(&side).unwrap(),
        b"synthetic unclassified side-image withdrawn_secret"
    );
}

fn private_artifact(
    f: &Fixture,
    class: PrivateArtifactClass,
    relative: &str,
    bytes: &[u8],
) -> ClassifiedPrivateArtifact {
    let path = f.root.join(relative);
    if let Some(parent) = path.parent() {
        let mut descendants = Vec::new();
        let mut current = parent;
        while current != f.root && !current.exists() {
            descendants.push(current.to_path_buf());
            current = current.parent().unwrap();
        }
        for directory in descendants.into_iter().rev() {
            fs::create_dir(&directory).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
    }
    fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    ClassifiedPrivateArtifact::new(
        class,
        relative,
        bytes.len() as u64,
        blake3::hash(bytes).to_hex().as_str(),
    )
    .unwrap()
}
fn inventory(f: &Fixture, artifacts: Vec<ClassifiedPrivateArtifact>) -> PrivateArtifactInventory {
    PrivateArtifactInventory::bind(
        &f.control,
        RootIdentity::read(&f.root).unwrap(),
        f.control.status().unwrap().policy.policy_epoch,
        artifacts,
    )
    .unwrap()
}
fn run_inventory(
    f: &Fixture,
    evidence: &PrivateArtifactInventory,
) -> agent_session_grep_ports::PortResult<
    agent_session_grep_adapters_sqlite::managed_purge::PurgeReport,
> {
    let guard = acquire(&f.root, purge_lock_kind().unwrap());
    let owner = f
        .control
        .bind_purge_owner(&guard, id("classified-purge"))
        .unwrap();
    run_with_inventory(
        &f.control,
        &f.catalog,
        &owner,
        None,
        evidence,
        30,
        deadline(),
    )
}
fn asserted_artifact_pending(f: &Fixture, evidence: &PrivateArtifactInventory) {
    let report = run_inventory(f, evidence).unwrap();
    assert_eq!(report.catalog, PurgeStage::Complete);
    assert_eq!(
        report.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
    assert!(!report.complete());
}

#[test]
fn control_lifetime_and_exact_known_job_locks_are_content_free_accounted_artifacts() {
    let f = Fixture::new();
    let handles = SharedGuard::try_acquire(&f.root, LockKind::ControlHandles).unwrap();
    for key in ["user-path", "legacy-migration"] {
        drop(acquire(
            &f.root,
            LockKind::MaintenanceJob(
                agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(key).unwrap(),
            ),
        ));
    }
    f.revoke();
    assert!(f.run("lifetime-accounting").complete());
    drop(handles);
    // A rendezvous name does not permit retaining arbitrary bytes in a lock.
    let key = "legacy-migration";
    let encoded: String = key.bytes().map(|byte| format!("{byte:02x}")).collect();
    fs::write(
        f.root.join(format!("maintenance-job-{encoded}.lock")),
        b"unexpected-content",
    )
    .unwrap();
    let report = f.run("modified-lock");
    assert_eq!(
        report.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
}

#[test]
fn classified_settings_layouts_are_preserved_while_withdrawn_corpus_is_purged() {
    use PrivateArtifactClass::*;
    let f = Fixture::new();
    f.revoke();
    let policy_before = f.control.status().unwrap().policy;
    let operation = "a".repeat(32);
    let setup = format!("setup-hosts-{operation}.json");
    let autostart = format!("setup-autostart-{operation}.json");
    // Synthetic caller-classified evidence; these are actual CLI layout names,
    // not host execution or proof that arbitrary wrappers become trustworthy.
    let files = vec![
        (
            SetupInventory,
            setup,
            br#"{"schema":"asg.setup-host-inventory/v1","receipts":[]}"#.to_vec(),
        ),
        (
            SetupInventory,
            autostart,
            br#"{"schema":"asg.setup-autostart-inventory/v1"}"#.to_vec(),
        ),
        (
            NativeRegistration,
            "native-autostart/owner.json".into(),
            br#"{"schema":"asg.native-autostart-owner/v1"}"#.to_vec(),
        ),
        (
            NativeRegistration,
            format!("native-autostart/{operation}/state-0001.json"),
            br#"{"schema":"asg.native-autostart-journal/v1"}"#.to_vec(),
        ),
        (
            NativeRegistration,
            "native-autostart/owner.lock".into(),
            vec![],
        ),
        (
            UserPathRegistration,
            "user-path/owner.json".into(),
            br#"{"schema":"asg.user-path-binding/v1"}"#.to_vec(),
        ),
        (
            UserPathRegistration,
            format!("user-path/{operation}/intent.json"),
            br#"{"schema":"asg.user-path-intent/v1"}"#.to_vec(),
        ),
        (
            UserPathRegistration,
            format!("user-path/{operation}/operation.json"),
            br#"{"schema":"asg.user-path-intent/v1"}"#.to_vec(),
        ),
        (
            UserPathRegistration,
            format!("user-path/{operation}/receipt.json"),
            br#"{"schema":"asg.user-path-receipt/v1"}"#.to_vec(),
        ),
        (
            UserPathRegistration,
            format!("user-path/{operation}/before.bin"),
            b"synthetic user settings PATH before; withdrawn_secret is a setting".to_vec(),
        ),
        (
            UserPathRegistration,
            format!("user-path/{operation}/after.bin"),
            b"synthetic user settings PATH after".to_vec(),
        ),
        (
            UpdateJournal,
            "update/state.json".into(),
            br#"{"schema":"asg.update-state/v1"}"#.to_vec(),
        ),
        (
            UpdateJournal,
            "update/upgrade-fixture/native-binding.json".into(),
            br#"{"schema":"asg.update-native-binding/v1"}"#.to_vec(),
        ),
        (
            UpdateJournal,
            "update/upgrade-fixture/2-current.before".into(),
            br#"{"schema":"asg.current/v1"}"#.to_vec(),
        ),
        (
            LegacyMigrationIntent,
            "legacy-migration-command.json".into(),
            br#"{"schema":"asg.legacy-migration-command/v1"}"#.to_vec(),
        ),
        (
            LegacyMigrationIntent,
            "catalog.db.asg-legacy-file".into(),
            br#"{"schema":"asg.legacy-migration/v1"}"#.to_vec(),
        ),
    ];
    let evidence: Vec<_> = files
        .iter()
        .map(|(class, name, bytes)| private_artifact(&f, *class, name, bytes))
        .collect();
    // The original run stays conservative for callers that have no proof.
    let before = f.run("unclassified-integrations");
    assert_eq!(
        before.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
    let report = run_inventory(&f, &inventory(&f, evidence)).unwrap();
    assert!(report.complete(), "{report:?}");
    for (_, name, bytes) in files {
        assert_eq!(fs::read(f.root.join(name)).unwrap(), bytes);
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM source_projections WHERE source_id='source-a'"),
        0
    );
    assert_eq!(
        f.control.status().unwrap().policy.exclusions,
        policy_before.exclusions
    );
    assert_eq!(
        f.control.status().unwrap().desired_updates,
        DesiredUpdates::Running
    );
}

#[test]
fn arbitrary_json_corpus_paths_aliases_and_oversize_are_not_classifiable() {
    use PrivateArtifactClass::*;
    let digest = blake3::hash(b"synthetic").to_hex().to_string();
    for (class, path) in [
        (SetupInventory, "anything.json"),
        (SetupInventory, "setup-hosts-invalid.json"),
        (UserPathRegistration, "catalog.db"),
        (UserPathRegistration, "continuations.db"),
        (UpdateJournal, "backups/one/catalog.db"),
        (UpdateJournal, "update/one/stage/catalog.db"),
        (LegacyMigrationIntent, "other.db"),
        (NativeRegistration, "native-autostart/owner.json/more"),
        (UserPathRegistration, "user-path/../owner.json"),
        (UserPathRegistration, "user-path\\owner.json"),
        (UserPathRegistration, "/user-path/owner.json"),
        (SetupInventory, "setup-hosts-*.json"),
    ] {
        assert!(
            ClassifiedPrivateArtifact::new(class, path, 9, &digest).is_err(),
            "{path}"
        );
    }
    assert!(
        ClassifiedPrivateArtifact::new(
            UserPathRegistration,
            "user-path/owner.json",
            65537,
            &digest
        )
        .is_err()
    );
    assert!(
        ClassifiedPrivateArtifact::new(
            NativeRegistration,
            "native-autostart/owner.lock",
            1,
            &digest
        )
        .is_err()
    );
    assert!(
        ClassifiedPrivateArtifact::new(
            UserPathRegistration,
            "user-path/owner.json",
            0,
            "not-a-digest"
        )
        .is_err()
    );
    let f = Fixture::new();
    f.revoke();
    fs::write(
        f.root.join(format!("setup-hosts-{}.json", "b".repeat(32))),
        b"{\"schema\":\"asg.setup-host-inventory/v1\",\"unexpected\":\"withdrawn_secret\"}",
    )
    .unwrap();
    let report = f.run("arbitrary-wrapper");
    assert_eq!(
        report.backups,
        PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact)
    );
}

#[test]
fn unlisted_directory_siblings_and_changed_or_missing_evidence_stay_pending() {
    use PrivateArtifactClass::*;
    let f = Fixture::new();
    f.revoke();
    let artifact = private_artifact(
        &f,
        UserPathRegistration,
        "user-path/owner.json",
        b"synthetic settings",
    );
    let evidence = inventory(&f, vec![artifact]);
    let unknown = f.root.join("user-path/unknown.json");
    fs::write(&unknown, b"unclassified withdrawn_secret").unwrap();
    asserted_artifact_pending(&f, &evidence);
    assert_eq!(
        fs::read(&unknown).unwrap(),
        b"unclassified withdrawn_secret"
    );
    fs::remove_file(&unknown).unwrap();
    // Same size but changed bytes invalidate the exact classification digest.
    fs::write(f.root.join("user-path/owner.json"), b"synthetic changed!").unwrap();
    asserted_artifact_pending(&f, &evidence);
    fs::remove_file(f.root.join("user-path/owner.json")).unwrap();
    asserted_artifact_pending(&f, &evidence);
}

#[test]
fn inventory_root_epoch_and_duplicate_bindings_cannot_be_reused_for_new_policy() {
    let f = Fixture::new();
    f.revoke();
    let root = RootIdentity::read(&f.root).unwrap();
    let epoch = f.control.status().unwrap().policy.policy_epoch;
    let evidence = inventory(&f, vec![]);
    let wrong = agent_session_grep_testkit::tempdir().unwrap();
    assert!(
        PrivateArtifactInventory::bind(
            &f.control,
            RootIdentity::read(wrong.path()).unwrap(),
            epoch,
            vec![]
        )
        .is_err()
    );
    let digest = blake3::hash(b"settings").to_hex().to_string();
    let artifact = ClassifiedPrivateArtifact::new(
        PrivateArtifactClass::UserPathRegistration,
        "user-path/owner.json",
        8,
        &digest,
    )
    .unwrap();
    assert!(
        PrivateArtifactInventory::bind(&f.control, root, epoch, vec![artifact.clone(), artifact])
            .is_err()
    );
    let expected = f.control.status().unwrap().policy;
    f.control
        .add_selection(
            current(&f.control),
            SelectionRequest {
                region: ScopeRegion {
                    provider: SearchProvider::Codex,
                    kind: RootKind::Exact,
                    locator: CanonicalLocator::from_path(&f.source_a).unwrap(),
                },
                root_identity: Some(id("independent-provider-root")),
                now_ms: 30,
            },
        )
        .unwrap();
    assert!(PrivateArtifactInventory::bind(&f.control, root, epoch, vec![]).is_err());
    assert!(matches!(
        run_inventory(&f, &evidence),
        Err(PortError::GenerationMismatch(_))
    ));
    assert_eq!(
        f.control.status().unwrap().policy.exclusions,
        expected.exclusions
    );
    assert_eq!(
        f.control.purge_jobs().unwrap()[0].state,
        PurgeState::Pending
    );
}

#[test]
fn private_inventory_entry_and_total_byte_limits_do_not_allow_unbounded_work() {
    let f = Fixture::new();
    let root = RootIdentity::read(&f.root).unwrap();
    let epoch = f.control.status().unwrap().policy.policy_epoch;
    let digest = blake3::hash(b"settings").to_hex().to_string();
    let many: Vec<_> = (0..4097)
        .map(|i| {
            ClassifiedPrivateArtifact::new(
                PrivateArtifactClass::SetupInventory,
                &format!("setup-hosts-{i:032x}.json"),
                1,
                &digest,
            )
            .unwrap()
        })
        .collect();
    assert!(PrivateArtifactInventory::bind(&f.control, root, epoch, many).is_err());
    let heavy: Vec<_> = (0..65)
        .map(|i| {
            ClassifiedPrivateArtifact::new(
                PrivateArtifactClass::SetupInventory,
                &format!("setup-hosts-{i:032x}.json"),
                1024 * 1024,
                &digest,
            )
            .unwrap()
        })
        .collect();
    assert!(PrivateArtifactInventory::bind(&f.control, root, epoch, heavy).is_err());
}

#[test]
fn classified_inventory_cannot_hide_unregistered_corpus_backup() {
    let f = Fixture::new();
    f.revoke();
    let artifact = private_artifact(
        &f,
        PrivateArtifactClass::UserPathRegistration,
        "user-path/owner.json",
        b"settings",
    );
    let evidence = inventory(&f, vec![artifact]);
    let unknown = f.root.join("backups/unregistered");
    fs::create_dir_all(&unknown).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [f.root.join("backups"), unknown.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    fs::write(
        unknown.join("catalog.db"),
        b"unclassified withdrawn_secret backup",
    )
    .unwrap();
    asserted_artifact_pending(&f, &evidence);
    assert!(unknown.join("catalog.db").exists());
}

#[test]
fn declared_files_must_be_private_single_link_files_and_debug_stays_redacted() {
    let f = Fixture::new();
    f.revoke();
    let artifact = private_artifact(
        &f,
        PrivateArtifactClass::UserPathRegistration,
        "user-path/owner.json",
        b"settings",
    );
    let evidence = inventory(&f, vec![artifact.clone()]);
    let outside = f._temp.path().join("linked-settings");
    fs::hard_link(f.root.join("user-path/owner.json"), &outside).unwrap();
    asserted_artifact_pending(&f, &evidence);
    assert_eq!(fs::read(outside).unwrap(), b"settings");
    assert!(!format!("{artifact:?}").contains("user-path"));
    assert!(!format!("{evidence:?}").contains(f.root.to_str().unwrap()));
}

#[cfg(unix)]
#[test]
fn writable_or_symlinked_classified_settings_do_not_satisfy_owned_accounting() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    f.revoke();
    let artifact = private_artifact(
        &f,
        PrivateArtifactClass::UserPathRegistration,
        "user-path/owner.json",
        b"settings",
    );
    let evidence = inventory(&f, vec![artifact]);
    let path = f.root.join("user-path/owner.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    asserted_artifact_pending(&f, &evidence);
    fs::remove_file(&path).unwrap();
    let outside = f._temp.path().join("settings");
    fs::write(&outside, b"settings").unwrap();
    symlink(&outside, &path).unwrap();
    asserted_artifact_pending(&f, &evidence);
    assert_eq!(fs::read(outside).unwrap(), b"settings");
}

#[test]
fn catalog_restore_receipt_class_has_one_bounded_root_layout_and_never_accepts_images() {
    let class = PrivateArtifactClass::CatalogRestoreReceipt;
    let digest = blake3::hash(b"synthetic content-free inventory")
        .to_hex()
        .to_string();
    let relative = format!("restore-{}.jsonl", "a".repeat(32));
    assert!(ClassifiedPrivateArtifact::new(class, &relative, 256 * 1024, &digest).is_ok());
    assert!(ClassifiedPrivateArtifact::new(class, &relative, 256 * 1024 + 1, &digest).is_err());
    for path in [
        "restore-abcd.jsonl".to_string(),
        format!("restore-{}.jsonl", "a".repeat(31)),
        format!("restore-{}.jsonl", "A".repeat(32)),
        format!("restore-{}.json", "a".repeat(32)),
        format!("restore-{}.db", "a".repeat(32)),
        format!("nested/{relative}"),
        format!("{relative}/anything"),
        format!("/{relative}"),
        format!("backups/restore_prior_{}/catalog.db", "a".repeat(32)),
        format!("backups/restore_prior_{}/manifest.json", "a".repeat(32)),
        "stage/catalog.db".to_string(),
    ] {
        assert!(ClassifiedPrivateArtifact::new(class, &path, 1, &digest).is_err());
    }
}
#[test]
fn classified_restore_receipt_preserves_owned_record_but_unknown_stage_stays_pending() {
    let f = Fixture::new();
    f.revoke();
    let relative = format!("restore-{}.jsonl", "b".repeat(32));
    // Only demonstrates the adapter inventory boundary; the maintenance caller
    // must first validate the complete typed journal and ownership chain.
    let bytes = br#"{"event":"synthetic_owned_receipt","schema":1}"#;
    let artifact = private_artifact(
        &f,
        PrivateArtifactClass::CatalogRestoreReceipt,
        &relative,
        bytes,
    );
    let evidence = inventory(&f, vec![artifact]);
    assert!(run_inventory(&f, &evidence).unwrap().complete());
    assert_eq!(fs::read(f.root.join(&relative)).unwrap(), bytes);
    let unclassified = f.root.join("restore-stage.db");
    fs::write(&unclassified, b"synthetic unregistered content image").unwrap();
    asserted_artifact_pending(&f, &evidence);
    assert_eq!(
        fs::read(&unclassified).unwrap(),
        b"synthetic unregistered content image"
    );
    assert_eq!(fs::read(f.root.join(&relative)).unwrap(), bytes);
}

#[test]
fn public_dsh_authority_rewrite_revoke_purge_completes_without_source_writes_or_resurrection() {
    use agent_session_grep_domain::SessionIdentityNamespace;
    use agent_session_grep_ports::{SourceResumeClaim, source_context::*};
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let catalog = root.join("catalog.db");
    let surface_path = temp.path().join(".dsh").join("sessions");
    let source_path = surface_path
        .join("synthetic-project")
        .join("synthetic-native")
        .join("session.v4.jsonl.zstd");
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    // Provider compression/parse was verified by the CLI worker slice. This
    // adapter test consumes the independently admitted canonical v4 batch and
    // checks that the storage/purge consumer never changes any source bytes.
    let source_before = b"synthetic admitted DSH v4 source sentinel before rewrite";
    let source_after = b"synthetic admitted DSH v4 source sentinel after rewrite";
    fs::write(&source_path, source_before).unwrap();
    let provider = SearchProvider::parse("deepseek-harness").unwrap();
    let control =
        SqliteControlStore::create(&root, &id("dsh-installation"), DesiredUpdates::Running)
            .unwrap();
    let surface = CanonicalLocator::from_path(&surface_path).unwrap();
    let selected = control
        .add_selection(
            current(&control),
            SelectionRequest {
                region: ScopeRegion {
                    provider,
                    locator: surface.clone(),
                    kind: RootKind::Root,
                },
                root_identity: Some(id("dsh-physical-root")),
                now_ms: 1,
            },
        )
        .unwrap()
        .value;
    let selection = SelectionRevision {
        selection_id: selected.id.clone(),
        revision: selected.revision,
        root_identity: id("dsh-physical-root"),
    };
    let lock = acquire(&root, LockKind::Background);
    let worker = control.bind_worker(&lock, id("dsh-boot")).unwrap();
    control
        .register_worker(current(&control), &worker, 1, 1)
        .unwrap();
    let start_cycle = |now: i64| {
        let admitted = control
            .queue_cycle(current(&control), vec![selection.clone()])
            .unwrap()
            .value;
        let queued = match admitted {
            CycleAdmission::Queued(c) => c,
            _ => panic!("synthetic observing cycle was not queued"),
        };
        control
            .start_cycle(current(&control), &worker, queued.token.cycle_seq, now)
            .unwrap()
            .value
    };
    let make_observation =
        |cycle: &ObservationCycle, revision: &str, digest: &str| SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse("dsh-source").unwrap(),
                source_path: source_path.to_str().unwrap().into(),
                provider,
                namespace_id: None,
                root_identity: "dsh-physical-root".into(),
            },
            revision_id: RevisionId::parse(revision).unwrap(),
            revision_digest: digest.into(),
            parser_version: 1,
            state: ObservationState::Complete,
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: "dsh-boot".into(),
            catalog_incarnation: "dsh-catalog".into(),
            policy_epoch: cycle.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.unwrap().get(),
            observed_at_ms: 3,
            committed_at_ms: 4,
            selections: vec![SelectionProof {
                selection_id: selected.id.as_str().into(),
                selection_revision: selected.revision.get(),
                root_identity: "dsh-physical-root".into(),
            }],
            repositories: Vec::new(),
        };
    let acknowledge = |cycle: &ObservationCycle, publication: &Publication| {
        control
            .acknowledge_source(
                current(&control),
                &worker,
                SourceAcknowledgement {
                    source_id: id("dsh-source"),
                    provider,
                    token: cycle.token.clone(),
                    selection: selection.clone(),
                    attempted_at_ms: publication.receipt.observed_at_ms,
                    coverage: Coverage::Complete,
                    update_state: UpdateState::Idle,
                    backfill_state: BackfillState::Complete,
                    error: None,
                    receipt: Some(SourceReceiptSummary {
                        token: cycle.token.clone(),
                        revision: id(publication.receipt.revision_id.as_str()),
                        catalog_incarnation: id("dsh-catalog"),
                        catalog_generation: ControlSeq::new(
                            publication.receipt.committed_generation.unwrap(),
                        )
                        .unwrap(),
                    }),
                    confirmation: None,
                },
            )
            .unwrap();
        control
            .acknowledge_discovery(
                current(&control),
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
    };
    let store = ManagedStore::create(&catalog, &control, id("dsh-catalog"), 1).unwrap();
    store.reconcile_progress(&control, &worker).unwrap();
    let cycle = start_cycle(2);
    let mut initial = make_observation(&cycle, "dsh-original-receipt", "dsh-original-digest");
    let namespace = store
        .reserve_namespace_for_surface(
            &control,
            &initial,
            &worker,
            &surface,
            &id("dsh-physical-root"),
            deadline(),
        )
        .unwrap();
    initial.binding.namespace_id = Some(namespace.namespace_id.clone());
    let session = StableId::native_session_scoped(
        &SessionIdentityNamespace {
            provider_id: provider.as_str(),
            installation_namespace: &namespace.input,
        },
        "synthetic-native",
    );
    let message = StableId::native_checked(IdKind::Message, "synthetic-native-message").unwrap();
    let document = StableId::native_checked(IdKind::Document, "synthetic-dsh-document").unwrap();
    let make_batch = |observation: &SourceObservation, text: &str, len: u64| {
        SourceBatch {
        source_path:observation.binding.source_path.clone(),
        entries:vec![
            (message.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":null})).unwrap(),text.into()),
            (session.clone(),serde_json::to_vec(&serde_json::json!({"documents":[document.as_str()]})).unwrap(),String::new()),
            (document.clone(),serde_json::to_vec(&serde_json::json!({"provider":provider.as_str(),"variant":"v4","fingerprint":observation.revision_digest,"len":len})).unwrap(),String::new()),
        ],placements:vec![MessagePlacement::new(session.clone(),document.clone(),message.clone(),0,false,None)],edges:Vec::new(),activities:Vec::new(),usage_events:Vec::new(),relation_complete:true,len_bytes:Some(i64::try_from(len).unwrap()),fingerprint:Some(observation.revision_digest.clone()),provider_id:Some(provider.as_str().into()),
        resume_claims:vec![SourceResumeClaim {provider_id:provider.as_str().into(),session_id:session.as_str().into(),provider_session_id:Some("synthetic-native".into()),provider_session_id_state:"resolved".into(),original_working_directory:None,original_working_directory_state:"missing".into(),pair_observed:false}],
    }
    };
    let key = SourceAuthorityKey {
        provider,
        surface_id: id("dsh-surface"),
        surface_root: surface.clone(),
        surface_identity: id("dsh-physical-root"),
        native_session: NativeSessionId::parse("synthetic-native").unwrap(),
        session_id: session.clone(),
    };
    let first_context = SourcePublicationContext {
        dependencies: Vec::new(),
        authority: Some(SourceAuthorityTransition {
            key: key.clone(),
            expected_prior: None,
        }),
    };
    store
        .begin_discovery_with_deadline(&control, &worker, &cycle, &selection, deadline())
        .unwrap();
    let first = store
        .commit_source_with_context(
            &control,
            &worker,
            &make_batch(
                &initial,
                "dsh original before rewrite",
                source_before.len() as u64,
            ),
            &initial,
            &first_context,
            deadline(),
        )
        .unwrap();
    assert!(first.receipt.published);
    acknowledge(&cycle, &first);
    store
        .commit_discovery_with_deadline(
            &control,
            &worker,
            &cycle,
            &selection,
            std::slice::from_ref(&initial.binding.source_id),
            deadline(),
        )
        .unwrap();
    control
        .finish_cycle(
            current(&control),
            &worker,
            cycle.token.cycle_seq,
            CycleFinish::Committed,
            5,
        )
        .unwrap();
    assert_eq!(fs::read(&source_path).unwrap(), source_before);
    // The synthetic producer, not ASG, replaces its transcript before a new
    // admitted cycle; publication keeps the canonical session/source binding.
    fs::write(&source_path, source_after).unwrap();
    let rewritten_cycle = start_cycle(6);
    let mut rewritten = make_observation(
        &rewritten_cycle,
        "dsh-rewrite-receipt",
        "dsh-rewrite-digest",
    );
    rewritten.binding.namespace_id = Some(namespace.namespace_id.clone());
    rewritten.observed_at_ms = 7;
    rewritten.committed_at_ms = 8;
    let prior = store
        .authority_prior(&control, &key, deadline())
        .unwrap()
        .unwrap();
    let rewrite_context = SourcePublicationContext {
        dependencies: Vec::new(),
        authority: Some(SourceAuthorityTransition {
            key: key.clone(),
            expected_prior: Some(prior),
        }),
    };
    let batch = make_batch(
        &rewritten,
        "dsh replacement original after rewrite",
        source_after.len() as u64,
    );
    store
        .begin_discovery_with_deadline(&control, &worker, &rewritten_cycle, &selection, deadline())
        .unwrap();
    let published = store
        .commit_source_with_context(
            &control,
            &worker,
            &batch,
            &rewritten,
            &rewrite_context,
            deadline(),
        )
        .unwrap();
    assert!(published.destructive);
    acknowledge(&rewritten_cycle, &published);
    store
        .commit_discovery_with_deadline(
            &control,
            &worker,
            &rewritten_cycle,
            &selection,
            std::slice::from_ref(&rewritten.binding.source_id),
            deadline(),
        )
        .unwrap();
    control
        .finish_cycle(
            current(&control),
            &worker,
            rewritten_cycle.token.cycle_seq,
            CycleFinish::Committed,
            9,
        )
        .unwrap();
    let c = Connection::open(&catalog).unwrap();
    assert_eq!(
        c.query_row(
            "SELECT COUNT(*) FROM index_batches WHERE state='activated'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        c.query_row(
            "SELECT COUNT(*) FROM source_authority_members WHERE state='active'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        c.query_row("SELECT COUNT(*) FROM source_revision_receipts", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
    assert_eq!(
        c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert!(
        !c.prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap()
    );
    let generation = store
        .with_read(&control, RequestIntersection::Selected, deadline(), |r| {
            let hits = r
                .query_lexical("replacement", &ProjectionQuery::default(), 5)?
                .hits;
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].projection.message.id, message);
            Ok(r.snapshot().generation as u64)
        })
        .unwrap();
    drop(c);
    drop(store);
    drop(worker);
    drop(lock);
    let revoked = control
        .revoke_selection(current(&control), &selected.id, None, 10)
        .unwrap()
        .value;
    let policy = control.read_policy(RequestIntersection::Selected).unwrap();
    let guard = acquire(&root, purge_lock_kind().unwrap());
    let owner = control
        .bind_purge_owner(&guard, id("dsh-public-purge"))
        .unwrap();
    let report = run(&control, &catalog, &owner, None, 11, deadline()).unwrap();
    assert!(
        report.complete(),
        "real DSH authority purge remained pending: {report:?}"
    );
    assert_eq!(report.sources_retired, 1);
    assert_eq!(report.generation, Some(generation + 1));
    let job = control.purge_job_status(&revoked.purge_job.id).unwrap();
    assert_eq!(job.job.state, PurgeState::Complete);
    assert_eq!(job.job.attempts.get(), 1);
    let c =
        Connection::open_with_flags(&catalog, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert!(
        !c.prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap()
    );
    for table in [
        "source_revision_receipts",
        "source_publication_contexts",
        "source_dependencies",
        "source_authorities",
        "source_authority_transitions",
        "source_authority_members",
        "source_projections",
        "source_occurrences",
        "source_entity_projections",
        "source_session_projections",
        "source_scans",
        "catalog",
    ] {
        assert_eq!(
            c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "unretired data in {table}"
        );
    }
    assert_eq!(
        c.query_row(
            "SELECT COUNT(*) FROM source_authority_tombstones WHERE source_id='dsh-source'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert!(
        !agent_session_grep_adapters_sqlite::managed_source_context::source_read_eligible(
            &c,
            "dsh-source"
        )
        .unwrap()
    );
    assert_eq!(
        c.query_row(
            "SELECT COUNT(*) FROM projection_fts WHERE projection_fts MATCH 'replacement'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        control
            .read_policy(RequestIntersection::Selected)
            .unwrap()
            .exclusions,
        policy.exclusions
    );
    assert_eq!(fs::read(&source_path).unwrap(), source_after);
    drop(c);
    // An idempotent terminal retry cannot advance content again.
    assert!(
        run(&control, &catalog, &owner, None, 12, deadline())
            .unwrap()
            .complete()
    );
    assert_eq!(
        control
            .purge_job_status(&revoked.purge_job.id)
            .unwrap()
            .job
            .attempts
            .get(),
        1
    );
    assert_eq!(fs::read(&source_path).unwrap(), source_after);
}
