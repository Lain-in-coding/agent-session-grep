use super::*;
use std::sync::atomic::Ordering;

struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    adapter: SqliteMaintenanceCatalog,
}
fn batch(revision: usize) -> SourceBatch {
    let session = StableId::native(IdKind::Session, "maintenance-session");
    let document = StableId::native(IdKind::Document, "maintenance-document");
    let mut entries = Vec::new();
    let mut placements = Vec::new();
    let mut members = Vec::new();
    for index in 0..200 {
        let id = StableId::native(IdKind::Message, &format!("maintenance-message-{index}"));
        let text = format!(
            "maintenance body {index} {} {}",
            "汉字 filler ".repeat(24),
            if index == 199 {
                "x".repeat(revision + 1)
            } else {
                String::new()
            }
        );
        let payload=serde_json::json!({"role":"user","text":text,"session":session.as_str(),"sessions":[session.as_str()],"parent":null,"parent_native_id":null,"is_sidechain":false,"span":{"start":0,"end":8}}).to_string().into_bytes();
        entries.push((id.clone(), payload, text));
        placements.push(MessagePlacement::new(
            session.clone(),
            document.clone(),
            id.clone(),
            index,
            false,
            None,
        ));
        members.push(id);
    }
    entries.push((session,serde_json::json!({"document":document.as_str(),"documents":[document.as_str()],"messages":members.iter().map(|id|id.as_str()).collect::<Vec<_>>()} ).to_string().into_bytes(),String::new()));
    entries.push((document,serde_json::json!({"provider":"synthetic","variant":"synthetic/jsonl-v1","fingerprint":"0123456789abcdef","len":128}).to_string().into_bytes(),String::new()));
    SourceBatch {
        source_path: "synthetic-maintenance.jsonl".into(),
        entries,
        placements,
        edges: vec![],
        activities: vec![],
        usage_events: vec![],
        relation_complete: true,
        len_bytes: Some(65536),
        fingerprint: Some(format!("revision-{revision}")),
        provider_id: None,
        resume_claims: vec![],
    }
}
impl Fixture {
    fn new(revisions: usize) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("catalog.sqlite");
        let store = SqliteStore::open_for_write(path.to_str().unwrap()).unwrap();
        for revision in 0..revisions {
            assert!(
                store
                    .commit_source_batches_if_changed(&[batch(revision)])
                    .unwrap()
            );
        }
        drop(store);
        Self {
            _temp: temp,
            path,
            adapter: SqliteMaintenanceCatalog::new(),
        }
    }
    fn job(&self) -> MaintenanceJob {
        let preview = self.adapter.preview(self.path.to_str().unwrap()).unwrap();
        let digest = blake3::hash(preview.token.as_bytes()).to_hex().to_string();
        MaintenanceJob {
            id: format!("test_{digest}"),
            token: preview.token,
            compaction_id: format!("cmp_m1_{digest}"),
            target: preview.target,
            selection: preview.selection,
            max_write_seconds: 30,
            state: MaintenanceState::Queued,
            phase: MaintenancePhase::Validate,
            reason: None,
            attempts: 0,
            consecutive_budget_exhaustions: 0,
            next_retry_at_ms: 0,
            cancel_requested: false,
            backup: None,
            logical_compaction_committed: false,
            logical_compaction_reconciled: false,
            cleanup_started: false,
            metrics: MaintenanceMetrics::default(),
            created_at_ms: 0,
            updated_at_ms: 0,
            revision: 0,
        }
    }
    fn connection(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
    fn commit(&self, revision: usize) {
        let store = SqliteStore::open_for_write(self.path.to_str().unwrap()).unwrap();
        assert!(
            store
                .commit_source_batches_if_changed(&[batch(revision)])
                .unwrap()
        );
    }
}
fn next(phase: MaintenancePhase) -> MaintenancePhase {
    use MaintenancePhase::*;
    match phase {
        Validate => Backup,
        Backup => Compact,
        Compact => Vacuum,
        Vacuum => Checkpoint,
        Checkpoint => Verify,
        Verify => Cleanup,
        Cleanup | Done => Done,
    }
}
fn advance(session: &mut dyn MaintenanceSession, job: &mut MaintenanceJob) {
    let result = session
        .execute(job.phase, job, &MaintenanceControl::default())
        .unwrap_or_else(|e| panic!("phase {:?}: {e}", job.phase));
    if let Some(backup) = result.backup {
        job.backup = Some(backup);
    }
    job.logical_compaction_committed = result.logical_compaction_committed;
    job.metrics = result.metrics;
    job.phase = result.next_phase.unwrap_or_else(|| next(job.phase));
}
fn until(session: &mut dyn MaintenanceSession, job: &mut MaintenanceJob, phase: MaintenancePhase) {
    while job.phase != phase {
        advance(session, job);
    }
}

#[test]
fn soak_physically_reclaims_and_preserves_schema_generation_fts_identity() {
    let fixture = Fixture::new(21);
    let mut job = fixture.job();
    assert_eq!(job.selection.batches.len(), 21);
    let original_identity = job.target.file_identity.clone();
    let before = invariants(&fixture.connection()).unwrap();
    let old_generation = generation(&fixture.connection()).unwrap();
    let original_bytes = fs::metadata(&fixture.path).unwrap().len();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Done);
    drop(session);
    assert_eq!(file_identity(&fixture.path).unwrap(), original_identity);
    assert_eq!(invariants(&fixture.connection()).unwrap(), before);
    assert_eq!(generation(&fixture.connection()).unwrap(), old_generation);
    assert_eq!(
        fixture
            .connection()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        19
    );
    assert!(job.metrics.after.catalog_bytes < original_bytes);
    assert!(total(&job.metrics.after) < total(&job.metrics.before));
    assert_eq!(job.metrics.after.backup_bytes, 0);
    assert!(job.metrics.reclaimed_bytes > 0);
    eprintln!(
        "physical maintenance: {}",
        serde_json::to_string(&job.metrics).unwrap()
    );
}

#[test]
fn preview_is_read_only_stable_and_missing_or_old_catalog_is_not_created_or_migrated() {
    let fixture = Fixture::new(1);
    let first = fixture.job();
    let second = fixture.job();
    assert_eq!(first.token, second.token);
    assert!(!fixture.path.parent().unwrap().join(".maintenance").exists());
    let missing = fixture.path.with_file_name("missing.sqlite");
    assert!(fixture.adapter.preview(missing.to_str().unwrap()).is_err());
    assert!(!missing.exists());
    fixture
        .connection()
        .execute_batch("PRAGMA user_version=18")
        .unwrap();
    assert!(matches!(
        fixture.adapter.preview(fixture.path.to_str().unwrap()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(
        fixture
            .connection()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        18
    );
}

#[test]
fn later_batches_are_excluded_and_selected_drift_rolls_back_without_audit() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    fixture.commit(1);
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Vacuum);
    drop(session);
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM index_batches WHERE detail_format='full'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    let other = Fixture::new(2);
    let mut job = other.job();
    let mut session = other.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Compact);
    drop(session);
    other
        .connection()
        .execute(
            "UPDATE index_batches SET operation_digest='changed' WHERE operation_id=?1",
            [&job.selection.batches[1].operation_id],
        )
        .unwrap();
    let mut session = other.adapter.acquire(&job).unwrap();
    assert_eq!(
        session
            .execute(job.phase, &job, &MaintenanceControl::default())
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::SelectionChanged
    );
    assert_eq!(
        other
            .connection()
            .query_row("SELECT count(*) FROM journal_compactions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        other
            .connection()
            .query_row(
                "SELECT count(*) FROM index_batches WHERE detail_format='full'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn backup_publication_and_logical_commit_ack_gaps_are_reconciled_once() {
    let fixture = Fixture::new(2);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    assert_eq!(job.phase, MaintenancePhase::Backup);
    let published = session
        .execute(job.phase, &job, &MaintenanceControl::default())
        .unwrap();
    assert!(published.backup.unwrap().verified);
    drop(session); // queue ack lost
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    let backup = backup_path(&job, job.backup.as_ref().unwrap()).unwrap();
    let backup_identity = file_identity(&backup).unwrap();
    let committed = session
        .execute(job.phase, &job, &MaintenanceControl::default())
        .unwrap();
    assert!(committed.logical_compaction_committed);
    drop(session);
    assert!(fixture.adapter.reconcile(&job).unwrap()); // read-only cancellation/status probe
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    assert_eq!(file_identity(&backup).unwrap(), backup_identity);
    assert_eq!(
        fixture
            .connection()
            .query_row("SELECT count(*) FROM journal_compactions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    until(session.as_mut(), &mut job, MaintenancePhase::Done);
}

#[test]
fn resumed_backup_refreshes_intent_before_copy_and_verified_backup_stays_original() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    drop(session);
    let original_generation = job.backup.as_ref().unwrap().source_generation;
    fixture.commit(1);
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    assert_eq!(job.phase, MaintenancePhase::Backup);
    assert!(job.backup.as_ref().unwrap().source_generation > original_generation);
    assert!(
        !backup_path(&job, job.backup.as_ref().unwrap())
            .unwrap()
            .exists()
    );
    advance(session.as_mut(), &mut job);
    let saved_generation = job.backup.as_ref().unwrap().source_generation;
    drop(session);
    fixture.commit(2);
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Done);
    assert_eq!(
        job.backup.as_ref().unwrap().source_generation,
        saved_generation
    );
    assert_eq!(generation(&fixture.connection()).unwrap(), 3);
}

#[test]
fn checkpoint_defers_for_long_reader_and_resume_does_not_repeat_vacuum() {
    let fixture = Fixture::new(2);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Compact);
    let reader = fixture.connection();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM index_batches;")
        .unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Checkpoint);
    assert_eq!(
        session
            .execute(job.phase, &job, &MaintenanceControl::default())
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::Busy
    );
    drop(session);
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Done);
    assert_eq!(job.metrics.after.wal_bytes, 0);
}

#[test]
fn cancel_pause_and_cleanup_failure_keep_the_verified_backup() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Compact);
    let backup = backup_path(&job, job.backup.as_ref().unwrap()).unwrap();
    let control = MaintenanceControl::default();
    control.cancelled.store(true, Ordering::Release);
    assert_eq!(
        session
            .execute(job.phase, &job, &control)
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::Cancelled
    );
    assert!(backup.exists());
    control.cancelled.store(false, Ordering::Release);
    control.paused.store(true, Ordering::Release);
    assert_eq!(
        session
            .execute(job.phase, &job, &control)
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::Paused
    );
    until(session.as_mut(), &mut job, MaintenancePhase::Cleanup);
    let foreign = backup.with_file_name("foreign-file");
    fs::write(&foreign, b"not owned").unwrap();
    assert_eq!(
        session
            .execute(job.phase, &job, &MaintenanceControl::default())
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::CleanupFailed
    );
    assert!(backup.exists());
    fs::remove_file(foreign).unwrap();
    advance(session.as_mut(), &mut job);
    assert!(!backup.exists());
}

#[test]
fn replacement_target_and_competing_writer_fail_closed() {
    let fixture = Fixture::new(1);
    let job = fixture.job();
    let session = fixture.adapter.acquire(&job).unwrap();
    assert_eq!(
        fixture.adapter.acquire(&job).err().unwrap().kind,
        MaintenanceFailureKind::Busy
    );
    drop(session);
    let previous = fixture.path.with_file_name("previous.sqlite");
    fs::rename(&fixture.path, &previous).unwrap();
    fs::copy(&previous, &fixture.path).unwrap();
    assert_eq!(
        fixture.adapter.acquire(&job).err().unwrap().kind,
        MaintenanceFailureKind::TargetChanged
    );
    assert_eq!(
        fixture.adapter.reconcile(&job).err().unwrap().kind,
        MaintenanceFailureKind::TargetChanged
    );
}

#[test]
fn atomic_update_failure_leaves_no_staged_audit_or_partial_compaction() {
    let fixture = Fixture::new(2);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Compact);
    fixture.connection().execute_batch("CREATE TRIGGER deny_compaction BEFORE UPDATE OF detail_format ON index_batches BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    assert!(
        session
            .execute(job.phase, &job, &MaintenanceControl::default())
            .is_err()
    );
    assert_eq!(
        fixture
            .connection()
            .query_row("SELECT count(*) FROM journal_compactions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        fixture
            .connection()
            .query_row(
                "SELECT count(*) FROM index_batches WHERE detail_format='full'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn broken_fts_sidecar_is_detected_before_logical_mutation() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    fixture.connection().execute_batch("UPDATE fts_ids SET fts_rowid=987654321 WHERE fts_rowid=(SELECT min(fts_rowid) FROM fts_ids)").unwrap();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    assert_eq!(
        session
            .execute(job.phase, &job, &MaintenanceControl::default())
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::IntegrityFailed
    );
    assert!(!fixture.adapter.reconcile(&job).unwrap());
}

#[test]
fn writer_deadline_is_not_renewed_between_stages() {
    let fixture = Fixture::new(1);
    let job = fixture.job();
    let path = fs::canonicalize(&fixture.path).unwrap();
    let lease = WriterLease::try_acquire(path.parent().unwrap()).unwrap();
    let started = Instant::now();
    let mut session = SqliteMaintenanceSession {
        conn: fixture.connection(),
        _lease: lease,
        path,
        started,
        deadline: started,
        baseline: None,
    };
    assert_eq!(
        session
            .execute(
                MaintenancePhase::Validate,
                &job,
                &MaintenanceControl::default()
            )
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::BudgetExhausted
    );
    assert!(!fixture.adapter.reconcile(&job).unwrap());
}

#[test]
fn a_completed_stage_does_not_renew_deadline_for_backup_compact_or_vacuum() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let path = fs::canonicalize(&fixture.path).unwrap();
    let started = Instant::now();
    let mut session = SqliteMaintenanceSession {
        conn: fixture.connection(),
        _lease: WriterLease::try_acquire(path.parent().unwrap()).unwrap(),
        path,
        started,
        deadline: started + Duration::from_secs(30),
        baseline: None,
    };
    for phase in [
        MaintenancePhase::Backup,
        MaintenancePhase::Compact,
        MaintenancePhase::Vacuum,
        MaintenancePhase::Checkpoint,
    ] {
        until(&mut session, &mut job, phase);
        let before = invariants(&fixture.connection()).unwrap();
        session.deadline = Instant::now();
        assert_eq!(
            session
                .execute(job.phase, &job, &MaintenanceControl::default())
                .err()
                .unwrap()
                .kind,
            MaintenanceFailureKind::BudgetExhausted
        );
        assert_eq!(invariants(&fixture.connection()).unwrap(), before);
        assert_eq!(job.max_write_seconds, 30);
        // Test-only simulate a NEW authorized acquisition's budget; production
        // code has no path that renews an existing session's deadline.
        session.deadline = Instant::now() + Duration::from_secs(30);
    }
}

#[test]
fn incomplete_owned_copy_is_discarded_but_published_backup_is_never_clobbered() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    let path = backup_path(&job, job.backup.as_ref().unwrap()).unwrap();
    let directory = validate_owned_directory(&job, &path, true).unwrap();
    fs::write(
        directory.join("copy.sqlite"),
        b"incomplete owned sqlite copy",
    )
    .unwrap();
    advance(session.as_mut(), &mut job);
    assert!(job.backup.as_ref().unwrap().verified);
    let original = fs::read(&path).unwrap();
    // A corrupted final backup is retained for diagnosis, never overwritten.
    fs::write(&path, b"foreign or corrupted publication").unwrap();
    let error = session
        .execute(
            MaintenancePhase::Backup,
            &job,
            &MaintenanceControl::default(),
        )
        .err()
        .unwrap();
    assert_eq!(error.kind, MaintenanceFailureKind::IntegrityFailed);
    assert_eq!(
        fs::read(&path).unwrap(),
        b"foreign or corrupted publication"
    );
    assert!(!original.is_empty());
}

#[test]
fn mid_backup_cancel_is_interruptible_and_resume_uses_one_verified_copy() {
    let fixture = Fixture::new(21);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    let backup = backup_path(&job, job.backup.as_ref().unwrap()).unwrap();
    let temporary = backup.with_file_name("copy.sqlite");
    let control = MaintenanceControl::default();
    let flag = control.cancelled.clone();
    let monitor = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if temporary.exists() {
                flag.store(true, Ordering::Release);
                return;
            }
            std::thread::yield_now();
        }
        panic!("copy never started");
    });
    let outcome = session.execute(job.phase, &job, &control);
    monitor.join().unwrap();
    assert_eq!(
        outcome.err().unwrap().kind,
        MaintenanceFailureKind::Cancelled
    );
    assert!(!fixture.adapter.reconcile(&job).unwrap());
    drop(session);
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    assert!(job.backup.as_ref().unwrap().verified);
    let directory = backup.parent().unwrap();
    assert_eq!(fs::read_dir(directory).unwrap().count(), 2); // owner + final backup
}

#[test]
fn destructive_stage_checks_invariants_before_checkpoint_can_defer() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Vacuum);
    let reader = fixture.connection();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM index_batches")
        .unwrap();
    // Synthetic uncooperative writer violates a live generation invariant while
    // the cooperative writer lease is held. A successful VACUUM must not ack it
    // and then lose the pre-attempt baseline at a busy checkpoint boundary.
    fixture
        .connection()
        .execute_batch("UPDATE store_metadata SET active_generation=active_generation+1")
        .unwrap();
    assert_eq!(
        session
            .execute(job.phase, &job, &MaintenanceControl::default())
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::IntegrityFailed
    );
    assert_eq!(job.phase, MaintenancePhase::Vacuum);
    reader.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn cleanup_ack_gap_resumes_without_catalog_or_writer_lease() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Cleanup);
    job.cleanup_started = true;
    let result = session
        .execute(job.phase, &job, &MaintenanceControl::default())
        .unwrap();
    assert_eq!(result.metrics.after.backup_bytes, 0);
    drop(session); // queue ack lost
    fs::remove_file(&fixture.path).unwrap();
    let lease = WriterLease::try_acquire(fixture.path.parent().unwrap()).unwrap();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    assert_eq!(job.phase, MaintenancePhase::Done);
    assert!(!fixture.path.exists());
    drop(lease);
}

#[test]
fn post_delete_measurement_error_is_resumable_cleanup_failure() {
    let fixture = Fixture::new(1);
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    until(session.as_mut(), &mut job, MaintenancePhase::Cleanup);
    job.cleanup_started = true;
    let backup = backup_path(&job, job.backup.as_ref().unwrap()).unwrap();
    let obstruction = fixture.path.parent().unwrap().join(".maintenance/tmp");
    fs::write(&obstruction, b"synthetic metrics obstruction").unwrap();
    let error = session
        .execute(job.phase, &job, &MaintenanceControl::default())
        .err()
        .unwrap();
    assert_eq!(error.kind, MaintenanceFailureKind::CleanupFailed);
    assert!(!backup.exists());
    drop(session);
    fs::remove_file(obstruction).unwrap();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    assert!(!session.holds_writer_lease());
    advance(session.as_mut(), &mut job);
    assert_eq!(job.phase, MaintenancePhase::Done);
}

#[test]
fn disk_preflight_fails_before_backup_and_partial_copy_footprint_is_separate() {
    let fixture = Fixture::new(1);
    assert_eq!(
        preflight_available(&fixture.connection(), true, 0)
            .err()
            .unwrap()
            .kind,
        MaintenanceFailureKind::InsufficientSpace
    );
    assert!(preflight_available(&fixture.connection(), false, u64::MAX).is_ok());
    let mut job = fixture.job();
    let mut session = fixture.adapter.acquire(&job).unwrap();
    advance(session.as_mut(), &mut job);
    let backup = backup_path(&job, job.backup.as_ref().unwrap()).unwrap();
    let directory = validate_owned_directory(&job, &backup, true).unwrap();
    fs::write(directory.join("copy.sqlite"), b"synthetic partial copy").unwrap();
    let measured = footprint(&fixture.path).unwrap();
    assert_eq!(measured.temporary_bytes, 22);
    assert_eq!(
        measured.backup_bytes,
        fs::metadata(directory.join("owner.json")).unwrap().len()
    );
    assert!(!backup.exists());
}

#[test]
fn new_preview_accounts_utf8_bytes_not_sqlite_character_length() {
    let fixture = Fixture::new(1);
    // Terminal synthetic manifest: an opaque Unicode source locator is legitimate
    // journal detail; preview must count its UTF-8 representation, not characters.
    fixture.connection().execute_batch("UPDATE index_batches SET source_replacements_json=replace(source_replacements_json,'synthetic-maintenance.jsonl','合成维护来源.jsonl')").unwrap();
    let job = fixture.job();
    let conn = fixture.connection();
    let (bytes,characters):(i64,i64)=conn.query_row("SELECT length(CAST(source_replacements_json AS BLOB)),length(source_replacements_json) FROM index_batches",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert!(bytes > characters);
    let field = job.selection.batches[0]
        .fields
        .iter()
        .find(|f| f.field == "source_replacements_json")
        .unwrap();
    assert_eq!(field.bytes, bytes as u64);
}
