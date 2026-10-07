//! Real-process online maintenance evidence. Every catalog and source is synthetic.
use agent_session_grep_adapters_sqlite::{
    SourceBatch, SqliteStore,
    maintenance_queue::{QueueLock, SqliteMaintenanceQueue},
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::maintenance::{MaintenanceJob, MaintenanceQueue, MaintenanceState};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_asg");

struct Fixture {
    root: tempfile::TempDir,
    db: PathBuf,
}
impl Fixture {
    fn empty() -> Self {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("catalog.sqlite");
        Self { root, db }
    }
    fn seeded(revisions: usize) -> Self {
        Self::seeded_messages(revisions, 200)
    }
    fn seeded_messages(revisions: usize, message_count: usize) -> Self {
        let fixture = Self::empty();
        let store = SqliteStore::open_for_write(fixture.db.to_str().unwrap()).unwrap();
        for revision in 0..revisions {
            assert!(
                store
                    .commit_source_batches_if_changed(&[batch(revision, message_count)])
                    .unwrap()
            );
        }
        drop(store);
        fixture
    }
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .arg("--db")
            .arg(&self.db)
            .arg("--robot")
            .args(args)
            .env("RUST_BACKTRACE", "1")
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let output = self.cli(args);
        assert!(
            output.status.success(),
            "{args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let frame: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(frame["schema_version"], "1.1");
        assert_eq!(frame["ok"], true);
        assert_eq!(frame["outcome"], "success");
        // Maintenance output contains no private target, source body, or native IDs.
        if args.first() == Some(&"journal") {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(!text.contains("retention-message"));
            assert!(!text.contains("canonical_path"));
            assert!(!text.contains("file_identity"));
            assert!(!text.contains("source_replacements_json"));
            assert!(!text.contains(&self.root.path().to_string_lossy().replace('\\', "\\\\")));
        }
        frame["data"].clone()
    }
    fn preview(&self) -> String {
        self.ok(&["journal", "preview"])["plan"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn submit(&self, token: &str) -> String {
        self.ok(&["journal", "submit", "--plan", token])["job"]["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn queue(&self) -> SqliteMaintenanceQueue {
        SqliteMaintenanceQueue::open_existing(self.root.path())
            .unwrap()
            .unwrap()
    }
    fn job(&self, id: &str) -> MaintenanceJob {
        self.queue().get(id).unwrap()
    }
    fn wait(&self, id: &str, predicate: impl Fn(&MaintenanceJob) -> bool) -> MaintenanceJob {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let job = self.job(id);
            if predicate(&job) {
                return job;
            }
            assert!(
                job.state.is_runnable(),
                "unexpected terminal state: {:?}",
                job.summary()
            );
            assert!(
                Instant::now() < deadline,
                "maintenance timed out: {:?}",
                job.summary()
            );
            thread::sleep(Duration::from_millis(40));
        }
    }
    fn completed(&self, id: &str) -> MaintenanceJob {
        let job = self.wait(id, |job| !job.state.is_runnable());
        assert_eq!(
            job.state,
            MaintenanceState::Completed,
            "{:?}",
            job.summary()
        );
        job
    }
    fn stopped(&self) {
        self.ok(&["journal", "worker", "stop"]);
        let deadline = Instant::now() + Duration::from_secs(10);
        while QueueLock::worker_running(self.root.path()).unwrap() {
            assert!(Instant::now() < deadline, "worker failed to stop");
            thread::sleep(Duration::from_millis(40));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if SqliteMaintenanceQueue::path(self.root.path()).exists() {
            let _ = self.cli(&["journal", "worker", "stop"]);
            for _ in 0..250 {
                if !QueueLock::worker_running(self.root.path()).unwrap_or(false) {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn batch(revision: usize, message_count: usize) -> SourceBatch {
    let session = StableId::native(IdKind::Session, "retention-session");
    let document = StableId::native(IdKind::Document, "retention-document");
    let mut entries = Vec::new();
    let mut placements = Vec::new();
    for index in 0..message_count {
        let id = StableId::native(IdKind::Message, &format!("retention-message-{index}"));
        let mut text = format!("retention body {index} {}", "filler".repeat(24));
        if index + 1 == message_count {
            text.push_str(&format!("{} revision-{revision:04}", "x".repeat(revision)));
        }
        let payload = json!({"role": "user", "text": text, "session": session.as_str(), "sessions": [session.as_str()], "is_sidechain": false}).to_string().into_bytes();
        entries.push((id.clone(), payload, text));
        placements.push(MessagePlacement::new(
            session.clone(),
            document.clone(),
            id,
            index as u32,
            false,
            None,
        ));
    }
    let members: Vec<&str> = entries.iter().map(|(id, _, _)| id.as_str()).collect();
    let payload = json!({"document": document.as_str(), "documents": [document.as_str()], "messages": members}).to_string().into_bytes();
    entries.push((session, payload, String::new()));
    entries.push((document, json!({"provider": "synthetic", "variant": "synthetic/jsonl-v1", "fingerprint": "0123456789abcdef", "len": 128}).to_string().into_bytes(), String::new()));
    SourceBatch {
        source_path: "retention-source.jsonl".into(),
        entries,
        placements,
        edges: Vec::new(),
        activities: Vec::new(),
        usage_events: Vec::new(),
        relation_complete: true,
        len_bytes: Some(56_320),
        fingerprint: Some(format!("fp-{revision:04}")),
        provider_id: None,
        resume_claims: Vec::new(),
    }
}
fn commit(store: &SqliteStore, revision: usize) {
    assert!(
        store
            .commit_source_batches_if_changed(&[batch(revision, 200)])
            .unwrap()
    );
}
fn bytes(root: &Path) -> u64 {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                bytes(&entry.path())
            } else {
                entry.metadata().unwrap().len()
            }
        })
        .sum()
}
// Live sampling tolerates only files removed between enumeration and stat.
// This is a sampled lower bound, not an invented instantaneous peak.
fn sample_bytes(root: &Path) -> u64 {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(error) => panic!("disk measurement failed: {error}"),
    };
    entries
        .map(|entry| {
            let entry = entry.unwrap();
            match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => sample_bytes(&entry.path()),
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(error) => panic!("disk measurement failed: {error}"),
            }
        })
        .sum()
}

fn scalar(db: &Path, sql: &str) -> i64 {
    Connection::open(db)
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

#[test]
fn invalid_requests_help_and_queue_status_never_open_or_create_catalog() {
    let f = Fixture::empty();
    for args in [
        vec!["journal"],
        vec!["journal", "submit"],
        vec![
            "journal",
            "submit",
            "--plan",
            "x",
            "--max-write-seconds",
            "0",
        ],
        vec![
            "journal",
            "submit",
            "--plan",
            "x",
            "--max-write-seconds",
            "18446744073709551615",
        ],
        vec!["journal", "preview", "--db", "secret"],
        vec!["journal", "status", "--robot"],
        vec!["journal", "cancel", "secret/path"],
        vec!["journal", "retry", "x", "--plan", "y"],
    ] {
        let output = f.cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let frame: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(frame["command"], "journal");
    }
    for args in [
        vec!["journal", "--help"],
        vec!["journal", "submit", "--help"],
        vec!["journal", "worker", "start", "--help"],
    ] {
        assert!(f.cli(&args).status.success());
    }
    assert_eq!(
        f.ok(&["journal", "status"])["worker"]["queue_exists"],
        false
    );
    assert!(!f.db.exists());
    assert!(!f.root.path().join(".maintenance").exists());
    f.ok(&["index", "synthetic", "synthetic body"]);
    assert!(
        !f.root.path().join(".maintenance").exists(),
        "ordinary write without queue must not create one"
    );
    f.preview();
    assert!(!f.root.path().join(".maintenance").exists());
}

#[test]
fn physical_reclamation_detaches_and_preserves_search_and_generation() {
    physical_evidence(200);
}

#[test]
#[ignore = "explicit enlarged-dataset measurement; reference fixture remains in normal CI"]
fn enlarged_physical_reclamation_evidence() {
    physical_evidence(2000);
}

fn physical_evidence(message_count: usize) {
    let f = Fixture::seeded_messages(21, message_count);
    let before_db = fs::metadata(&f.db).unwrap().len();
    let before_total = bytes(f.root.path());
    let before_search = f.ok(&["search", "retention"]);
    let generation = scalar(
        &f.db,
        "SELECT active_generation FROM store_metadata WHERE singleton=1",
    );
    let started = Instant::now();
    let token = f.preview();
    let id = f.submit(&token); // Parent CLI has exited; only detached worker can progress.
    let sampled_peak_disk = std::cell::Cell::new(before_total);
    let completed = f.wait(&id, |job| {
        sampled_peak_disk.set(sampled_peak_disk.get().max(sample_bytes(f.root.path())));
        !job.state.is_runnable()
    });
    assert_eq!(
        completed.state,
        MaintenanceState::Completed,
        "{:?}",
        completed.summary()
    );
    assert_eq!(
        completed.max_write_seconds, 30,
        "measurement never silently expands the budget"
    );
    let after_search = f.ok(&["search", "retention"]);
    assert_eq!(before_search, after_search);
    assert_eq!(
        scalar(
            &f.db,
            "SELECT active_generation FROM store_metadata WHERE singleton=1"
        ),
        generation
    );
    assert_eq!(scalar(&f.db, "PRAGMA user_version"), 19);
    assert_eq!(f.submit(&token), id, "completed token remains idempotent");
    f.stopped();
    let after_db = fs::metadata(&f.db).unwrap().len();
    let after_total = bytes(f.root.path());
    println!(
        "maintenance_evidence {}",
        json!({"fixture_messages": message_count, "sampled_peak_disk_bytes": sampled_peak_disk.get(), "disk_sample_interval_ms": 40, "peak_disk_measurement": "sampled_lower_bound", "revisions": 21, "before_db_bytes": before_db, "after_db_bytes": after_db, "before_total_bytes": before_total, "after_total_bytes": after_total, "reclaimed_db_bytes": before_db.saturating_sub(after_db), "reclaimed_total_bytes": before_total.saturating_sub(after_total), "elapsed_ms": started.elapsed().as_millis(), "metrics": completed.metrics})
    );
    assert!(after_db < before_db, "catalog must physically shrink");
    assert!(
        after_total < before_total,
        "queue and retained files must not erase the saving"
    );
    assert!(!completed.backup.as_ref().is_some_and(|backup| {
        f.root
            .path()
            .join(".maintenance")
            .join(&backup.relative_path)
            .exists()
    }));
}

#[test]
fn busy_worker_retries_after_lease_release_without_another_cli_invocation() {
    let f = Fixture::seeded(3);
    let token = f.preview();
    let writer = SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap();
    let id = f.submit(&token);
    f.wait(&id, |job| {
        job.state == MaintenanceState::Deferred && job.attempts >= 1
    });
    assert!(QueueLock::worker_running(f.root.path()).unwrap());
    drop(writer);
    let job = f.completed(&id); // Poll queue directly: absolutely no CLI wake after release.
    assert!(job.attempts >= 2);
}

#[test]
fn pause_is_persistent_reads_do_not_wake_and_new_batches_are_excluded() {
    let f = Fixture::seeded(3);
    f.stopped();
    let token = f.preview();
    let id = f.submit(&token);
    assert!(!QueueLock::worker_running(f.root.path()).unwrap());
    let before = f.job(&id).selection.batches.len();
    let store = SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap();
    commit(&store, 4);
    drop(store);
    f.ok(&["index", "extra", "new ordinary write"]);
    f.ok(&["journal", "status"]);
    f.preview();
    f.ok(&["search", "retention"]);
    assert!(!QueueLock::worker_running(f.root.path()).unwrap());
    assert_eq!(f.job(&id).state, MaintenanceState::Queued);
    f.ok(&["journal", "worker", "start"]);
    let job = f.completed(&id);
    assert_eq!(job.selection.batches.len(), before);
    assert!(
        f.ok(&["journal", "preview"])["affected_batches"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn changed_preview_is_rejected_and_missing_catalog_status_cancel_still_work() {
    let f = Fixture::seeded(2);
    f.stopped();
    let token = f.preview();
    let store = SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap();
    commit(&store, 3);
    drop(store);
    let rejected = f.cli(&["journal", "submit", "--plan", &token]);
    assert!(!rejected.status.success());
    assert_eq!(f.queue().list(None).unwrap().len(), 0);
    let id = f.submit(&f.preview());
    fs::remove_file(&f.db).unwrap();
    assert_eq!(
        f.ok(&["journal", "status", &id])["jobs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.ok(&["journal", "cancel", &id]);
    assert!(f.job(&id).cancel_requested);
    assert!(!f.db.exists());
}

#[test]
fn checkpoint_reader_defers_then_progresses_without_another_request() {
    let f = Fixture::seeded(3);
    let reader = Connection::open(&f.db).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM index_batches;")
        .unwrap();
    let id = f.submit(&f.preview());
    let deferred = f.wait(&id, |job| {
        job.state == MaintenanceState::Deferred && job.logical_compaction_committed
    });
    assert!(matches!(
        deferred.phase,
        agent_session_grep_ports::maintenance::MaintenancePhase::Checkpoint
    ));
    let vacuum_durations = deferred
        .metrics
        .stage_millis
        .iter()
        .filter(|stage| {
            matches!(
                stage.phase,
                agent_session_grep_ports::maintenance::MaintenancePhase::Vacuum
            )
        })
        .count();
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    let completed = f.completed(&id);
    assert_eq!(
        completed
            .metrics
            .stage_millis
            .iter()
            .filter(|stage| matches!(
                stage.phase,
                agent_session_grep_ports::maintenance::MaintenancePhase::Vacuum
            ))
            .count(),
        vacuum_durations
    );
}

#[test]
fn crash_resume_and_single_worker_lock_use_authorized_write_wake() {
    let f = Fixture::seeded(3);
    f.stopped();
    let id = f.submit(&f.preview());
    let queue = SqliteMaintenanceQueue::open_existing_writable(f.root.path())
        .unwrap()
        .unwrap();
    queue.set_paused(false).unwrap();
    drop(queue);
    let writer = SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap();
    let spawn = || {
        Command::new(BIN)
            .arg("--db")
            .arg(&f.db)
            .args(["journal", "worker", "__run"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut worker = spawn();
    f.wait(&id, |job| job.state == MaintenanceState::Deferred);
    let mut competing = spawn();
    assert!(
        competing.wait().unwrap().success(),
        "second worker must exit without executing"
    );
    worker.kill().unwrap();
    worker.wait().unwrap();
    drop(writer);
    f.ok(&["journal", "status"]);
    f.preview();
    f.ok(&["search", "retention"]);
    assert!(f.cli(&["--help"]).status.success());
    assert!(f.cli(&["--version"]).status.success());
    assert!(
        !QueueLock::worker_running(f.root.path()).unwrap(),
        "read-only commands must not recover crashed worker"
    );
    f.ok(&["index", "wake-after-crash", "synthetic"]);
    f.completed(&id);
}

#[test]
fn spawn_failure_keeps_accepted_job_and_explicit_start_resumes_it() {
    let f = Fixture::seeded(2);
    f.stopped();
    let token = f.preview();
    let accepted = f.submit(&token);
    let queue = SqliteMaintenanceQueue::open_existing_writable(f.root.path())
        .unwrap()
        .unwrap();
    queue.set_paused(false).unwrap();
    drop(queue);
    // A file cannot serve as a private temporary directory. Never clobber it.
    let obstruction = f.root.path().join(".maintenance").join("tmp");
    fs::write(&obstruction, b"owned synthetic obstruction").unwrap();
    let output = f.cli(&["journal", "submit", "--plan", &token]);
    assert!(output.status.success());
    let frame: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!frame["warnings"].as_array().unwrap().is_empty());
    assert_eq!(frame["data"]["worker"]["state"], "start_failed");
    let id = frame["data"]["job"]["id"].as_str().unwrap();
    assert_eq!(id, accepted);
    assert_eq!(f.job(id).state, MaintenanceState::Queued);
    assert_eq!(
        fs::read(&obstruction).unwrap(),
        b"owned synthetic obstruction"
    );
    fs::remove_file(&obstruction).unwrap();
    f.ok(&["journal", "worker", "start"]);
    f.completed(id);
}

#[test]
fn cancellation_is_independent_of_catalog_writer_contention() {
    let f = Fixture::seeded(3);
    let writer = SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap();
    let id = f.submit(&f.preview());
    f.wait(&id, |job| job.state == MaintenanceState::Deferred);
    f.ok(&["journal", "cancel", &id]);
    let cancelled = f.wait(&id, |job| job.state == MaintenanceState::Cancelled);
    assert!(!cancelled.logical_compaction_committed);
    drop(writer);
    assert_eq!(f.ok(&["journal", "preview"])["affected_batches"], 3);
}

#[test]
fn enqueue_competing_with_final_idle_exit_has_no_lost_wake() {
    let f = Fixture::seeded(2);
    let first = f.submit(&f.preview());
    f.completed(&first);
    let store = SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap();
    commit(&store, 3);
    drop(store);
    let token = f.preview();
    // Hold the exact lifecycle lock used by both the worker's final idle check
    // and producers. Both contenders queue here; either acquisition order is safe.
    let lifecycle = QueueLock::lifecycle(f.root.path()).unwrap();
    thread::sleep(Duration::from_millis(30_500));
    let submitter = Command::new(BIN)
        .arg("--db")
        .arg(&f.db)
        .arg("--robot")
        .args(["journal", "submit", "--plan", &token])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    drop(lifecycle);
    let output = submitter.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let frame: Value = serde_json::from_slice(&output.stdout).unwrap();
    f.completed(frame["data"]["job"]["id"].as_str().unwrap());
}

#[test]
fn broken_pipe_on_success_still_releases_writer_and_wakes_saved_work() {
    let f = Fixture::seeded(2);
    f.stopped();
    let id = f.submit(&f.preview());
    let queue = SqliteMaintenanceQueue::open_existing_writable(f.root.path())
        .unwrap()
        .unwrap();
    queue.set_paused(false).unwrap();
    drop(queue);
    let mut writer = Command::new(BIN)
        .arg("--db")
        .arg(&f.db)
        .arg("--robot")
        .args(["index", "closed-consumer", "synthetic body"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(writer.stdout.take());
    assert!(writer.wait().unwrap().success());
    f.completed(&id);
}

#[test]
fn worker_uses_persisted_job_target_not_later_db_argument() {
    let f = Fixture::seeded(2);
    f.stopped();
    let id = f.submit(&f.preview());
    let unrelated = f.root.path().join("unrelated.sqlite");
    fs::write(
        &unrelated,
        b"not a catalog; queue control must not open this",
    )
    .unwrap();
    let output = Command::new(BIN)
        .arg("--db")
        .arg(&unrelated)
        .arg("--robot")
        .args(["journal", "status"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let frame: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(frame["data"]["jobs"].as_array().unwrap().is_empty());
    let output = Command::new(BIN)
        .arg("--db")
        .arg(&unrelated)
        .arg("--robot")
        .args(["journal", "worker", "start"])
        .output()
        .unwrap();
    assert!(output.status.success());
    f.completed(&id);
    assert_eq!(
        fs::read(&unrelated).unwrap(),
        b"not a catalog; queue control must not open this"
    );
}

#[test]
fn empty_preview_cannot_submit_and_unsupported_catalog_is_not_migrated() {
    let f = Fixture::empty();
    drop(SqliteStore::open_for_write(f.db.to_str().unwrap()).unwrap());
    let preview = f.ok(&["journal", "preview"]);
    assert_eq!(preview["affected_batches"], 0);
    let output = f.cli(&[
        "journal",
        "submit",
        "--plan",
        preview["plan"].as_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(f.queue().list(None).unwrap().is_empty());
    Connection::open(&f.db)
        .unwrap()
        .execute_batch("PRAGMA user_version=999;")
        .unwrap();
    let output = f.cli(&["journal", "preview"]);
    assert_eq!(output.status.code(), Some(9));
    assert_eq!(scalar(&f.db, "PRAGMA user_version"), 999);
    assert!(
        f.ok(&["journal", "status"])["jobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
