//! Queue integration tests only use synthetic manifests and isolated roots.
use agent_session_grep_adapters_sqlite::maintenance_queue::{QueueLock, SqliteMaintenanceQueue};
use agent_session_grep_ports::{PortError, maintenance::*};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

fn job(id: &str) -> MaintenanceJob {
    MaintenanceJob {
        id: id.into(),
        token: format!("plan-{id}"),
        compaction_id: format!("cmp-{id}"),
        target: MaintenanceTarget {
            canonical_path: "/synthetic/private/catalog".into(),
            file_identity: "identity".into(),
            schema_version: 19,
        },
        selection: MaintenanceSelection {
            plan_digest: "digest".into(),
            aggregated_fields: vec![],
            batches: vec![],
            detail_bytes_before: 1000,
            estimated_detail_bytes_after: 100,
            estimated_saved_bytes: 900,
        },
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
#[test]
fn missing_queue_reads_do_not_create_anything() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("absent");
    assert!(
        SqliteMaintenanceQueue::open_existing(&root)
            .unwrap()
            .is_none()
    );
    assert!(
        SqliteMaintenanceQueue::open_existing_writable(&root)
            .unwrap()
            .is_none()
    );
    assert!(!QueueLock::worker_running(&root).unwrap());
    assert!(!root.exists());
}
#[test]
fn durable_idempotency_cancel_pause_and_cas_are_independent_of_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let accepted = queue.enqueue(&job("one")).unwrap();
    let mut duplicate = job("different");
    duplicate.token = accepted.token.clone();
    assert_eq!(queue.enqueue(&duplicate).unwrap().id, accepted.id);
    let other = SqliteMaintenanceQueue::open_existing_writable(dir.path())
        .unwrap()
        .unwrap();
    let stale = queue.get("one").unwrap();
    other.request_cancel("one").unwrap();
    other.set_paused(true).unwrap();
    let preserved = queue.save_progress(&stale).unwrap();
    assert!(preserved.cancel_requested);
    assert_eq!(preserved.state, MaintenanceState::Cancelled);
    assert!(queue.control(None).unwrap().paused);
    assert!(matches!(
        queue.save_progress(&stale),
        Err(PortError::GenerationMismatch(_))
    ));
    drop(queue);
    drop(other);
    let reopened = SqliteMaintenanceQueue::open_existing(dir.path())
        .unwrap()
        .unwrap();
    assert!(reopened.control(Some("one")).unwrap().cancel_requested);
    assert!(reopened.control(None).unwrap().paused);
    assert_eq!(reopened.list(None).unwrap().len(), 1);
    assert!(reopened.set_paused(false).is_err());
}
#[test]
fn running_cancel_does_not_lose_progress_or_control() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let mut j = job("one");
    j.state = MaintenanceState::Running;
    queue.enqueue(&j).unwrap();
    let other = SqliteMaintenanceQueue::open_existing_writable(dir.path())
        .unwrap()
        .unwrap();
    let mut stale = queue.get("one").unwrap();
    other.request_cancel("one").unwrap();
    stale.phase = MaintenancePhase::Backup;
    let saved = queue.save_progress(&stale).unwrap();
    assert!(saved.cancel_requested);
    assert_eq!(saved.phase, MaintenancePhase::Backup);
}
#[test]
fn cancelling_uncertain_compact_remains_runnable_with_unknown_public_commit() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let mut j = job("one");
    j.state = MaintenanceState::Deferred;
    j.phase = MaintenancePhase::Compact;
    queue.enqueue(&j).unwrap();
    let cancelled = queue.request_cancel("one").unwrap();
    assert_eq!(cancelled.state, MaintenanceState::Queued);
    assert!(cancelled.cancel_requested);
    assert_eq!(cancelled.summary().logical_compaction_committed, None);
}
#[test]
fn immutable_selection_cannot_be_expanded_by_progress() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let mut saved = queue.enqueue(&job("one")).unwrap();
    saved.target.file_identity = "replacement".into();
    assert!(matches!(
        queue.save_progress(&saved),
        Err(PortError::InvalidRequest(_))
    ));
}
#[test]
fn completed_token_survives_reopen_and_cancel_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let mut complete = queue.enqueue(&job("one")).unwrap();
    complete.state = MaintenanceState::Completed;
    complete.phase = MaintenancePhase::Done;
    queue.save_progress(&complete).unwrap();
    drop(queue);
    let queue = SqliteMaintenanceQueue::open_existing_writable(dir.path())
        .unwrap()
        .unwrap();
    let same = queue.enqueue(&job("one")).unwrap();
    assert_eq!(same.state, MaintenanceState::Completed);
    assert!(!queue.request_cancel("one").unwrap().cancel_requested);
}
#[test]
fn concurrent_first_open_is_serialized_inside_initialization_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let root = root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let q = SqliteMaintenanceQueue::open(&root).unwrap();
                q.enqueue(&job(&format!("{i}"))).unwrap();
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(
        SqliteMaintenanceQueue::open_existing(&root)
            .unwrap()
            .unwrap()
            .list(None)
            .unwrap()
            .len(),
        8
    );
}
#[test]
fn unsupported_queue_is_not_migrated_and_errors_hide_paths() {
    let dir = tempfile::tempdir().unwrap();
    drop(SqliteMaintenanceQueue::open(dir.path()).unwrap());
    let conn = rusqlite::Connection::open(SqliteMaintenanceQueue::path(dir.path())).unwrap();
    conn.execute_batch("PRAGMA user_version=2").unwrap();
    drop(conn);
    for result in [
        SqliteMaintenanceQueue::open(dir.path()),
        SqliteMaintenanceQueue::open_existing(dir.path()).map(|v| v.unwrap()),
    ] {
        let error = match result {
            Err(e) => e,
            Ok(_) => panic!("must reject"),
        };
        assert!(matches!(error, PortError::SchemaIncompatible(_)));
        assert!(!format!("{error:?}").contains(&dir.path().display().to_string()));
    }
    let conn = rusqlite::Connection::open(SqliteMaintenanceQueue::path(dir.path())).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}
#[test]
fn worker_probe_is_readonly_and_guards_release() {
    let dir = tempfile::tempdir().unwrap();
    drop(SqliteMaintenanceQueue::open(dir.path()).unwrap());
    assert!(!QueueLock::worker_running(dir.path()).unwrap());
    assert!(!dir.path().join(".maintenance/worker.lock").exists());
    let lock = QueueLock::try_worker(dir.path()).unwrap().unwrap();
    assert!(QueueLock::worker_running(dir.path()).unwrap());
    assert!(QueueLock::try_worker(dir.path()).unwrap().is_none());
    drop(lock);
    assert!(!QueueLock::worker_running(dir.path()).unwrap());
    assert!(QueueLock::try_worker(dir.path()).unwrap().is_some());
}
#[cfg(unix)]
#[test]
fn maintenance_directory_is_private_without_chmod_parent() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let before = std::fs::metadata(dir.path()).unwrap().permissions().mode();
    drop(SqliteMaintenanceQueue::open(dir.path()).unwrap());
    assert_eq!(
        std::fs::metadata(dir.path().join(".maintenance"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode(),
        before
    );
}
fn child(root: &Path, role: &str) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "queue_child", "--nocapture"])
        .env("ASG_QUEUE_TEST_ROOT", root)
        .env("ASG_QUEUE_TEST_ROLE", role)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd.spawn().unwrap()
}
fn wait_file(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "child timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn queue_child() {
    let Some(root) = std::env::var_os("ASG_QUEUE_TEST_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    match std::env::var("ASG_QUEUE_TEST_ROLE").unwrap().as_str() {
        "worker" => {
            let _guard = QueueLock::try_worker(root).unwrap().unwrap();
            std::fs::write(root.join("ready"), b"").unwrap();
            wait_file(&root.join("release"));
        }
        "producer" => {
            std::fs::write(root.join("producer_started"), b"").unwrap();
            let _guard = QueueLock::lifecycle(root).unwrap();
            let queue = SqliteMaintenanceQueue::open_existing_writable(root)
                .unwrap()
                .unwrap();
            queue.enqueue(&job("child")).unwrap();
            std::fs::write(root.join("enqueued"), b"").unwrap();
        }
        _ => panic!("unknown test role"),
    }
}
#[test]
fn process_worker_lock_is_authoritative_and_crash_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    drop(SqliteMaintenanceQueue::open(dir.path()).unwrap());
    let mut process = child(dir.path(), "worker");
    wait_file(&dir.path().join("ready"));
    assert!(QueueLock::worker_running(dir.path()).unwrap());
    assert!(QueueLock::try_worker(dir.path()).unwrap().is_none());
    process.kill().unwrap();
    process.wait().unwrap();
    assert!(QueueLock::try_worker(dir.path()).unwrap().is_some());
}
#[test]
fn producer_enqueue_cannot_cross_worker_final_check_lifecycle_guard() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let lifecycle = QueueLock::lifecycle(dir.path()).unwrap();
    let worker = QueueLock::try_worker(dir.path()).unwrap().unwrap();
    let mut process = child(dir.path(), "producer");
    wait_file(&dir.path().join("producer_started"));
    assert!(!dir.path().join("enqueued").exists());
    assert!(queue.list(None).unwrap().is_empty());
    drop(worker);
    drop(lifecycle);
    wait_file(&dir.path().join("enqueued"));
    assert!(process.wait().unwrap().success());
    assert_eq!(queue.get("child").unwrap().id, "child");
    assert!(!QueueLock::worker_running(dir.path()).unwrap());
}

#[test]
fn cleanup_claim_atomically_refuses_prior_cancel_and_closes_later_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let mut before = job("before");
    before.state = MaintenanceState::Running;
    before.phase = MaintenancePhase::Cleanup;
    let mut claim = queue.enqueue(&before).unwrap();
    queue.request_cancel("before").unwrap();
    claim.cleanup_started = true;
    let refused = queue.save_progress(&claim).unwrap();
    assert!(!refused.cleanup_started);
    assert!(refused.cancel_requested);
    let mut after = job("after");
    after.state = MaintenanceState::Running;
    after.phase = MaintenancePhase::Cleanup;
    let mut claim = queue.enqueue(&after).unwrap();
    claim.cleanup_started = true;
    let accepted = queue.save_progress(&claim).unwrap();
    assert!(accepted.summary().cancellation_closed);
    let too_late = queue.request_cancel("after").unwrap();
    assert!(!too_late.cancel_requested);
    assert!(too_late.summary().cancellation_closed);
}
#[test]
fn authoritative_done_progress_is_not_overridden_by_prior_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let queue = SqliteMaintenanceQueue::open(dir.path()).unwrap();
    let mut j = job("one");
    j.phase = MaintenancePhase::Cleanup;
    let mut done = queue.enqueue(&j).unwrap();
    queue.request_cancel("one").unwrap();
    done.phase = MaintenancePhase::Done;
    done.state = MaintenanceState::Completed;
    assert_eq!(
        queue.save_progress(&done).unwrap().state,
        MaintenanceState::Completed
    );
}
