//! Real CLI child processes over disposable synthetic profiles only.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_store::ManagedStore,
};
use agent_session_grep_ports::{
    PortError,
    control::{
        BackgroundControl, BarrierState, CanonicalLocator, ControlId, ControlStore, CycleState,
        DesiredUpdates, LatestBarrier, MaintenanceFence, MaintenancePhase, MaintenanceState,
        PurgeState, RequestIntersection, UpdateState,
    },
    managed::{ProjectionQuery, ProjectionRead},
};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
fn run(db: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(["--robot", "--db"])
        .arg(db)
        .args(args)
        .output()
        .unwrap()
}
#[track_caller]
fn successful(output: Output) -> Value {
    assert!(
        matches!(output.status.code(), Some(0 | 10)),
        "CLI failed: exit={:?}, canonical_code={:?}",
        output.status.code(),
        serde_json::from_slice::<Value>(&output.stdout)
            .ok()
            .and_then(|envelope| envelope["error"]["canonical_code"]
                .as_str()
                .map(str::to_owned))
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
}
fn claude(id: &str, text: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(
        &json!({"type":"user","uuid":id,"sessionId":"synthetic-session",
        "timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":text}}),
    )
    .unwrap();
    bytes.push(b'\n');
    bytes
}
fn codex(id: &str, text: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"timestamp":"2026-01-01T00:00:00Z","type":"response_item",
        "payload":{"type":"message","id":id,"role":"user","content":[{"type":"input_text","text":text}]}})).unwrap();
    bytes.push(b'\n');
    bytes
}

struct Fixture {
    _temp: tempfile::TempDir,
    db: PathBuf,
    history: PathBuf,
    child: Option<Child>,
    purge_child: Option<Child>,
}
impl Fixture {
    fn new(provider: &str) -> Self {
        Self::selected(provider, |root| {
            let history = root.join("history");
            fs::create_dir(&history).unwrap();
            history
        })
    }
    fn selected(provider: &str, prepare: impl FnOnce(&Path) -> PathBuf) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("private").join("catalog.db");
        let history = prepare(temp.path());
        successful(run(&db, &["setup"]));
        successful(run(&db, &["background", "pause"]));
        successful(run(
            &db,
            &[
                "sources",
                "add",
                "--provider",
                provider,
                history.to_str().unwrap(),
            ],
        ));
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let result = (|| -> PortResult<()> {
                let witness = SqliteControlStore::open_current_read_only_with_deadline(
                    db.parent().unwrap(),
                    end,
                )?;
                let installation = witness
                    .with_runtime_deadline(end, || witness.status())?
                    .policy
                    .installation_id;
                drop(witness);
                let control = SqliteControlStore::open_existing_writable_with_deadline(
                    db.parent().unwrap(),
                    &installation,
                    end,
                )?;
                control.with_runtime_deadline(end, || {
                    control.set_desired_updates(
                        control.status()?.policy.control_seq,
                        DesiredUpdates::Running,
                    )?;
                    Ok(())
                })
            })();
            match result {
                Ok(()) => break,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < end =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("synthetic fixture setup failed: {error:?}"),
            }
        }
        Self {
            _temp: temp,
            db,
            history,
            child: None,
            purge_child: None,
        }
    }
    fn control(&self) -> SqliteControlStore {
        let root = self.db.parent().unwrap();
        let physical = RootIdentity::read(root).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            assert_eq!(RootIdentity::read(root).unwrap(), physical);
            match SqliteControlStore::open_current_read_only_with_deadline(root, end) {
                Ok(control) => return control,
                Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("synthetic fixture control admission failed: {error:?}"),
            }
        }
    }
    fn desired(&self, desired: DesiredUpdates) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result = (|| -> PortResult<()> {
                let root = self.db.parent().unwrap();
                let witness =
                    SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
                let installation = witness
                    .with_runtime_deadline(deadline, || witness.status())?
                    .policy
                    .installation_id;
                drop(witness);
                let control = SqliteControlStore::open_existing_writable_with_deadline(
                    root,
                    &installation,
                    deadline,
                )?;
                control.with_runtime_deadline(deadline, || {
                    control.set_desired_updates(control.status()?.policy.control_seq, desired)?;
                    Ok(())
                })
            })();
            match result {
                Ok(()) => return,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => panic!("set desired updates failed: {error:?}"),
            }
        }
    }
    /// Add a root without letting the control CLI autostart a second worker.
    fn add_selected(&self, path: &Path) {
        self.desired(DesiredUpdates::Paused);
        successful(run(
            &self.db,
            &[
                "sources",
                "add",
                "--provider",
                "claude",
                path.to_str().unwrap(),
            ],
        ));
        self.desired(DesiredUpdates::Running);
    }
    fn spawn(&mut self) {
        let mut command = Command::new(BIN);
        command
            .arg("__managed-background")
            .arg("--db")
            .arg(&self.db)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        self.child = Some(command.spawn().unwrap());
        self.wait(|f| {
            let worker = f.control().background_status().unwrap().worker;
            worker.pid_hint == f.child.as_ref().map(Child::id)
        });
    }
    #[track_caller]
    fn wait(&self, mut predicate: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if predicate(self) {
                return;
            }
            if Instant::now() >= deadline {
                // Bounded content-free diagnostics distinguish worker death,
                // contention and proof deferral without printing source paths.
                match self.control().background_status() {
                    Ok(status) => eprintln!(
                        "synthetic worker state={:?}, error={:?}, pid_matches={}, next_cycle={:?}",
                        status.worker.state,
                        status.worker.error,
                        status.worker.pid_hint == self.child.as_ref().map(Child::id),
                        status.next_cycle_seq,
                    ),
                    Err(error) => eprintln!("synthetic worker status unavailable: {error:?}"),
                }
                let end = Instant::now() + Duration::from_secs(1);
                let control = self.control();
                let diagnostics = ManagedStore::open(&self.db, &control).and_then(|store| {
                    store.with_read(&control, RequestIntersection::Selected, end, |read| {
                        read.source_progress()
                    })
                });
                match diagnostics {
                    Ok(sources) => {
                        eprintln!("synthetic source count={}", sources.len());
                        for source in sources.iter().take(4) {
                            if let Some(receipt) = &source.last_attempt {
                                eprintln!(
                                    "synthetic receipt published={}, cycle={}",
                                    receipt.published, receipt.cycle_seq
                                );
                            }
                        }
                    }
                    Err(error) => eprintln!("synthetic source diagnostics unavailable: {error:?}"),
                }
                if let Ok(conn) = Connection::open_with_flags(
                    SqliteControlStore::path(self.db.parent().unwrap()),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
                ) {
                    conn.busy_timeout(Duration::ZERO).unwrap();
                    if let Ok(mut rows) =
                        conn.prepare("SELECT update_state,error_code FROM source_updates LIMIT 4")
                        && let Ok(values) = rows.query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                        })
                    {
                        for value in values.flatten() {
                            eprintln!("synthetic control source state={:?}", value);
                        }
                    }
                    if let Ok(mut rows) = conn.prepare("SELECT c.cycle_seq,c.state,s.discovery_complete,s.discovered_count,s.observed_count,s.committed_count,s.error_code FROM cycles c JOIN cycle_selections s USING(cycle_seq) ORDER BY c.cycle_seq DESC LIMIT 4")
                        && let Ok(values) = rows.query_map([], |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, i64>(4)?,
                                row.get::<_, i64>(5)?,
                                row.get::<_, Option<String>>(6)?,
                            ))
                        })
                    {
                        for value in values.flatten() {
                            eprintln!("synthetic cycle summary={:?}", value);
                        }
                    }
                    if let Ok(mut rows) =
                        conn.prepare("SELECT state,attempts FROM purge_jobs LIMIT 4")
                        && let Ok(values) = rows.query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                        })
                    {
                        for value in values.flatten() {
                            eprintln!("synthetic purge summary={:?}", value);
                        }
                    }
                }
                panic!("synthetic background condition timed out");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn has_text(&self, text: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let control = self.control();
            let opened = ManagedStore::open(&self.db, &control);
            // Windows briefly denies sidecar handles while the child worker
            // checkpoints; retry within this bounded read budget instead of
            // treating a transient open as terminal validation failure.
            let result = match opened {
                Ok(store) => {
                    store.with_read(&control, RequestIntersection::Selected, deadline, |read| {
                        read.query_lexical(text, &ProjectionQuery::default(), 16)
                    })
                }
                Err(PortError::Backend(reason)) if !reason.contains("code=5") => {
                    panic!("managed catalog private-file validation failed: {reason}")
                }
                Err(error) => Err(error),
            };
            if let Err(PortError::Backend(reason)) = &result
                && !reason.contains("code=5")
            {
                panic!("managed catalog private-file validation failed: {reason}")
            }
            match result {
                Ok(page) => {
                    return page
                        .hits
                        .iter()
                        .any(|h| h.projection.message.text.contains(text));
                }
                Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(PortError::Backend(_)) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(PortError::WriterBusy(_)) => {
                    panic!("managed source query timed out while busy")
                }
                Err(PortError::SnapshotChanged(_)) => {
                    panic!("managed source query snapshot changed")
                }
                Err(PortError::GenerationMismatch(_)) => {
                    panic!("managed source query generation changed")
                }
                Err(PortError::InvalidRequest(_)) => panic!("managed source query invalid"),
                Err(PortError::NotFound(_)) => panic!("managed source query not found"),
                Err(PortError::SourceIo(_)) => panic!("managed source query I/O failure"),
                Err(PortError::SchemaIncompatible(_)) => {
                    panic!("managed source query schema failure")
                }
                Err(PortError::Backend(_)) => panic!("managed source query backend failure"),
                Err(PortError::DeadlineExceeded(_)) => {
                    panic!("managed source query deadline exceeded")
                }
            }
        }
    }
    fn has_held_receipt(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let control = self.control();
            let result = ManagedStore::open(&self.db, &control).and_then(|store| {
                store.with_read(&control, RequestIntersection::Selected, deadline, |read| {
                    read.source_progress()
                })
            });
            match result {
                Ok(sources) => {
                    return sources
                        .iter()
                        .any(|s| s.last_attempt.as_ref().is_some_and(|r| !r.published));
                }
                Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => panic!("synthetic held-receipt observation failed: {error:?}"),
            }
        }
    }
    /// Suppress the untracked autostart only while the public revoke commits,
    /// then run the same real purge entry as a child owned by this fixture.
    /// Public startup acceptance is separate from these source lifecycle tests.
    fn revoke(&mut self, selection: &ControlId) {
        assert!(self.purge_child.is_none(), "fixture purge is already owned");
        let root = self.db.parent().unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        let guard = loop {
            match ExclusiveGuard::try_acquire(
                root,
                agent_session_grep_adapters_sqlite::managed_purge::purge_lock_kind().unwrap(),
            ) {
                Ok(guard) => break guard,
                Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("synthetic purge ownership failed: {error:?}"),
            }
        };
        let report = successful(run(&self.db, &["sources", "revoke", selection.as_str()]));
        assert_eq!(report["cleanup"]["requested"], false);
        if report["cleanup"]["pending"] == true {
            assert_eq!(report["cleanup"]["reason"], "owner_present");
        }
        drop(guard);
        let mut command = Command::new(BIN);
        command
            .arg("__managed-purge")
            .arg("--db")
            .arg(&self.db)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        self.purge_child = Some(command.spawn().unwrap());
    }

    /// A blocked purge remains alive independently of pause/stop. Request its
    /// cooperative exit with a fixture-owned maintenance fence; if unavailable,
    /// terminate only the exact returned Child handle and prove that it exited.
    fn stop_purge_for_teardown(&mut self, end: Instant) -> Result<(), &'static str> {
        let Some(child) = self.purge_child.as_mut() else {
            return Ok(());
        };
        if child
            .try_wait()
            .map_err(|_| "purge exit observation failed")?
            .is_some()
        {
            self.purge_child = None;
            return Ok(());
        }
        let root = self.db.parent().ok_or("fixture root unavailable")?;
        let physical = RootIdentity::read(root).map_err(|_| "fixture root identity unavailable")?;
        let owner = ControlId::parse("synthetic-fixture-teardown").unwrap();
        loop {
            if Instant::now() >= end {
                break;
            }
            let fenced = (|| -> PortResult<()> {
                if RootIdentity::read(root)? != physical {
                    return Err(PortError::GenerationMismatch("fixture root changed".into()));
                }
                let witness = SqliteControlStore::open_current_read_only_with_deadline(root, end)?;
                let identity = witness
                    .with_runtime_deadline(end, || witness.status())?
                    .policy
                    .installation_id;
                drop(witness);
                let control =
                    SqliteControlStore::open_existing_writable_with_deadline(root, &identity, end)?;
                control.with_runtime_deadline(end, || {
                    let status = control.status()?;
                    if status.policy.maintenance.state == MaintenanceState::Idle {
                        control.set_maintenance(
                            status.policy.control_seq,
                            &owner,
                            MaintenanceFence {
                                state: MaintenanceState::Uninstalling,
                                owner: Some(owner.clone()),
                                phase: Some(MaintenancePhase::Quiescing),
                            },
                        )?;
                    }
                    Ok(())
                })
            })();
            match fenced {
                Ok(()) => break,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < end =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        while Instant::now() < end {
            if child
                .try_wait()
                .map_err(|_| "purge exit observation failed")?
                .is_some()
            {
                self.purge_child = None;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill().map_err(|_| "owned purge termination failed")?;
        child
            .wait()
            .map_err(|_| "owned purge termination unconfirmed")?;
        self.purge_child = None;
        Ok(())
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
            }
            child.wait().unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Never remove the catalog while any fixture-owned child may retry it.
        self._temp.disable_cleanup(true);
        let mut failure = None;
        if let Some(mut child) = self.child.take() {
            let stopped = child.try_wait().and_then(|status| {
                if status.is_none() {
                    child.kill()?;
                }
                child.wait().map(|_| ())
            });
            if stopped.is_err() {
                failure = Some("owned background termination unconfirmed");
            }
        }
        if let Err(error) = self.stop_purge_for_teardown(Instant::now() + Duration::from_secs(5)) {
            failure = Some(error);
        }
        if let Some(error) = failure {
            if std::thread::panicking() {
                eprintln!("synthetic child teardown failed; root retained: {error}");
            } else {
                panic!("synthetic child teardown failed; root retained: {error}");
            }
        } else {
            self._temp.disable_cleanup(false);
        }
    }
}

#[test]
fn real_child_imports_both_providers_and_preserves_original_bytes() {
    for provider in ["claude", "codex"] {
        let mut f = Fixture::new(provider);
        let bytes = if provider == "claude" {
            claude("synthetic-claude", "uniqueimportneedle")
        } else {
            codex("synthetic-codex", "uniqueimportneedle")
        };
        let path = f.history.join("synthetic.jsonl");
        fs::write(&path, &bytes).unwrap();
        f.spawn();
        f.wait(|f| f.has_text("uniqueimportneedle"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(matches!(
            ExclusiveGuard::try_acquire(f.db.parent().unwrap(), LockKind::Background),
            Err(PortError::WriterBusy(_))
        ));
        let sources = ManagedStore::open(&f.db, &f.control())
            .unwrap()
            .background_sources(&f.control())
            .unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[0].latest_receipt.as_ref().unwrap().published);
    }
}

/// A held background lock alone is not liveness: update and uninstall drain
/// intentionally keep the lock after the worker exits. Offline worker state
/// must report running=false even while the lock is still held.
#[test]
fn held_lock_with_offline_worker_record_reports_not_running() {
    let mut f = Fixture::new("claude");
    let path = f.history.join("offline.jsonl");
    fs::write(&path, claude("offline-case", "offlineholdneedle")).unwrap();
    f.spawn();
    f.wait(|f| {
        f.control()
            .background_status()
            .unwrap()
            .worker
            .heartbeat_at_ms
            .is_some()
    });
    f.desired(DesiredUpdates::Stopped);
    f.wait(|f| f.control().background_status().unwrap().worker.state == UpdateState::Offline);
    assert!(f.child.as_mut().unwrap().try_wait().unwrap().is_some());
    f.child = None;
    let root = f.db.parent().unwrap();
    let drain = ExclusiveGuard::try_acquire(root, LockKind::Background).unwrap();
    let control = f.control();
    assert_eq!(
        control.background_status().unwrap().worker.state,
        UpdateState::Offline
    );
    let status = successful(run(&f.db, &["background", "status"]));
    assert_eq!(status["running"], false);
    assert_eq!(status["effective_state"], "offline");
    drop(drain);
}

/// A lock held by a live registered worker with a fresh heartbeat is running.
#[test]
fn held_lock_with_live_worker_and_fresh_heartbeat_reports_running() {
    let mut f = Fixture::new("claude");
    let path = f.history.join("live.jsonl");
    fs::write(&path, claude("live-case", "liveheartbeatneedle")).unwrap();
    f.spawn();
    f.wait(|f| {
        f.control()
            .background_status()
            .unwrap()
            .worker
            .heartbeat_at_ms
            .is_some()
    });
    let status = successful(run(&f.db, &["background", "status"]));
    assert_eq!(status["running"], true);
    assert_eq!(status["desired_updates"], "running");
    assert!(matches!(
        status["effective_state"].as_str(),
        Some("running") | Some("idle") | Some("busy") | Some("deferred")
    ));
}

#[test]
fn pause_restart_new_files_and_append_use_real_control_and_catalog_receipts() {
    let mut f = Fixture::new("claude");
    let first = f.history.join("first.jsonl");
    let mut original = claude("first", "beforepauseneedle");
    fs::write(&first, &original).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("beforepauseneedle"));
    successful(run(&f.db, &["background", "pause"]));
    f.wait(|f| {
        f.control().background_status().unwrap().worker.state
            == agent_session_grep_ports::control::UpdateState::Paused
    });
    let second = f.history.join("second.jsonl");
    let new = claude("second", "afterresumeneedle");
    fs::write(&second, &new).unwrap();
    let append = claude("append", "appendedneedle");
    OpenOptions::new()
        .append(true)
        .open(&first)
        .unwrap()
        .write_all(&append)
        .unwrap();
    original.extend(append);
    let paused_cycle = f.control().background_status().unwrap().next_cycle_seq;
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        f.control().background_status().unwrap().next_cycle_seq,
        paused_cycle
    );
    assert!(!f.has_text("afterresumeneedle"));
    assert!(!f.has_text("appendedneedle"));
    assert!(f.has_text("beforepauseneedle"));
    let boot = f.control().background_status().unwrap().worker.boot_id;
    f.terminate();
    f.spawn();
    assert_eq!(
        f.control().status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert_ne!(
        f.control().background_status().unwrap().worker.boot_id,
        boot
    );
    successful(run(&f.db, &["background", "resume"]));
    f.wait(|f| f.has_text("afterresumeneedle") && f.has_text("appendedneedle"));
    assert_eq!(fs::read(first).unwrap(), original);
    assert_eq!(fs::read(second).unwrap(), new);
    successful(run(&f.db, &["background", "stop"]));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = f.child.as_mut().unwrap().try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "stop did not release worker");
        std::thread::sleep(Duration::from_millis(25));
    }
    f.child = None;
    assert!(ExclusiveGuard::try_acquire(f.db.parent().unwrap(), LockKind::Background).is_ok());
}

#[test]
fn maintenance_exits_live_and_new_workers_zero_without_changing_intent() {
    use agent_session_grep_ports::control::{
        ControlId, MaintenanceFence, MaintenancePhase, MaintenanceState, UpdateState,
    };
    for (maintenance, desired) in [
        (MaintenanceState::Updating, DesiredUpdates::Running),
        (MaintenanceState::Recovering, DesiredUpdates::Paused),
        (MaintenanceState::Uninstalling, DesiredUpdates::Running),
    ] {
        let mut f = Fixture::new("claude");
        let path = f.history.join("maintenance.jsonl");
        let original = claude("maintenance", "maintenanceoriginalneedle");
        fs::write(&path, &original).unwrap();
        f.spawn();
        let control = SqliteControlStore::open_current_writable(f.db.parent().unwrap()).unwrap();
        let owner = ControlId::parse("synthetic-maintenance-owner").unwrap();
        let fence = MaintenanceFence {
            state: maintenance,
            owner: Some(owner.clone()),
            phase: Some(MaintenancePhase::Quiescing),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match control.set_desired_updates(control.status().unwrap().policy.control_seq, desired)
            {
                Ok(_) => break,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => panic!("setting synthetic desired intent failed"),
            }
        }
        loop {
            match control.set_maintenance(
                control.status().unwrap().policy.control_seq,
                &owner,
                fence.clone(),
            ) {
                Ok(_) => break,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => panic!("setting synthetic maintenance fence failed"),
            }
        }
        for already_fenced in [false, true] {
            if already_fenced {
                f.spawn();
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = f.child.as_mut().unwrap().try_wait().unwrap() {
                    assert_eq!(
                        status.code(),
                        Some(0),
                        "maintenance must be a clean worker exit: state={maintenance:?}, already_fenced={already_fenced}, desired={desired:?}"
                    );
                    f.child = None;
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "worker waited under maintenance instead of exiting"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            assert_eq!(control.status().unwrap().desired_updates, desired);
            assert_eq!(control.status().unwrap().policy.maintenance, fence);
            assert_eq!(
                control.background_status().unwrap().worker.state,
                UpdateState::Offline
            );
            assert!(
                ExclusiveGuard::try_acquire(f.db.parent().unwrap(), LockKind::Background).is_ok()
            );
            assert!(
                ExclusiveGuard::try_acquire(f.db.parent().unwrap(), LockKind::CatalogHandles)
                    .is_ok()
            );
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }
}

#[test]
fn malformed_empty_and_missing_root_retain_previous_evidence() {
    use agent_session_grep_ports::control::BackgroundFailure;
    let mut f = Fixture::new("claude");
    let path = f.history.join("stable.jsonl");
    let bytes = claude("retained", "retainevidenceneedle");
    fs::write(&path, &bytes).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("retainevidenceneedle"));
    let prior = m2_source_for_path(&f, &path).latest_receipt.unwrap();
    fs::write(&path, b"{\"type\":").unwrap();
    // A rejected malformed parse publishes no catalog attempt. Its typed
    // control failure must be observed while the exact old receipt survives.
    f.wait(|f| {
        f.control()
            .source_progress(
                &ControlId::parse(m2_source_for_path(f, &path).binding.source_id.as_str()).unwrap(),
            )
            .unwrap()
            .is_some_and(|progress| {
                progress.error == Some(BackgroundFailure::ScopeUnverified)
                    && progress
                        .last_observation
                        .is_some_and(|token| token.cycle_seq.get() > prior.cycle_seq)
            })
    });
    assert_eq!(m2_source_for_path(&f, &path).latest_receipt.unwrap(), prior);
    assert!(f.has_text("retainevidenceneedle"));
    fs::write(&path, b"").unwrap();
    std::thread::sleep(Duration::from_secs(6));
    assert!(f.has_text("retainevidenceneedle"));
    let offline = f._temp.path().join("offline");
    fs::rename(&f.history, &offline).unwrap();
    std::thread::sleep(Duration::from_secs(6));
    assert!(f.has_text("retainevidenceneedle"));
    assert_eq!(fs::read(offline.join("stable.jsonl")).unwrap(), b"");
}

#[test]
fn duplicate_child_cannot_replace_live_boot_and_query_does_not_start_worker() {
    let mut f = Fixture::new("claude");
    successful(run(&f.db, &["background", "status"]));
    assert!(
        f.control()
            .background_status()
            .unwrap()
            .worker
            .boot_id
            .is_none()
    );
    f.spawn();
    let boot = f.control().background_status().unwrap().worker.boot_id;
    let duplicate = Command::new(BIN)
        .arg("__managed-background")
        .arg("--db")
        .arg(&f.db)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty() && duplicate.stderr.is_empty());
    assert_eq!(
        f.control().background_status().unwrap().worker.boot_id,
        boot
    );
}

#[test]
fn deleted_source_requires_durable_hold_and_restart_begins_a_new_grace_period() {
    let mut f = Fixture::new("claude");
    let path = f.history.join("deleted.jsonl");
    fs::write(&path, claude("delete-case", "deletionretainedneedle")).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("deletionretainedneedle"));
    fs::remove_file(&path).unwrap();
    f.wait(|f| {
        let c = f.control();
        let sources = ManagedStore::open(&f.db, &c)
            .unwrap()
            .background_sources(&c)
            .unwrap();
        c.source_progress(
            &agent_session_grep_ports::control::ControlId::parse(
                sources[0].binding.source_id.as_str(),
            )
            .unwrap(),
        )
        .unwrap()
        .is_some_and(|p| p.confirmation.is_some())
    });
    assert!(f.has_text("deletionretainedneedle"));
    f.terminate();
    f.spawn();
    std::thread::sleep(Duration::from_secs(2));
    assert!(f.has_text("deletionretainedneedle"));
    f.wait(|f| !f.has_text("deletionretainedneedle"));
    assert!(!path.exists());
}

#[test]
fn equal_size_rewrite_is_held_then_published_and_old_roots_are_not_starved() {
    let mut f = Fixture::new("claude");
    let old = f.history.join("old.jsonl");
    let recent = f.history.join("recent.jsonl");
    let original = claude("rewritten", "rewritefirstneedle");
    let replacement = claude("rewritten", "rewritenextxneedle");
    assert_eq!(original.len(), replacement.len());
    fs::write(&old, claude("old-message", "olderhistoryneedle")).unwrap();
    fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
    fs::write(&recent, original).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("rewritefirstneedle") && f.has_text("olderhistoryneedle"));
    let modified = fs::metadata(&recent).unwrap().modified().unwrap();
    fs::write(&recent, &replacement).unwrap();
    fs::File::options()
        .write(true)
        .open(&recent)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    f.wait(|f| f.has_held_receipt());
    assert!(f.has_text("rewritefirstneedle"));
    assert!(!f.has_text("rewritenextxneedle"));
    f.wait(|f| f.has_text("rewritenextxneedle"));
    assert!(!f.has_text("rewritefirstneedle"));
    assert_eq!(fs::read(recent).unwrap(), replacement);
}

#[test]
fn valid_shrink_waits_for_two_verified_cycles_and_five_seconds_for_both_providers() {
    use agent_session_grep_ports::control::{ConfirmationKind, ControlId};
    use sha2::{Digest, Sha256};
    for provider in ["claude", "codex"] {
        let mut f = Fixture::new(provider);
        let path = f.history.join("shrinking.jsonl");
        let record = if provider == "claude" { claude } else { codex };
        let retained = record("retained", "shrinkretainedneedle");
        let mut original = retained.clone();
        original.extend(record("removed-one", "shrinkremovedneedle"));
        original.extend(record("removed-two", "shrinksecondremovedneedle"));
        fs::write(&path, original).unwrap();
        f.spawn();
        f.wait(|f| f.has_text("shrinkremovedneedle") && f.has_text("shrinkretainedneedle"));
        let c = f.control();
        let before = ManagedStore::open(&f.db, &c)
            .unwrap()
            .background_sources(&c)
            .unwrap()
            .remove(0);
        let source_id = ControlId::parse(before.binding.source_id.as_str()).unwrap();
        let rewritten_at = Instant::now();
        fs::write(&path, &retained).unwrap();
        let fingerprint = blake3::hash(&retained).to_hex().to_string();
        let digest = format!("digest_{:x}", Sha256::digest(fingerprint.as_bytes()));
        let mut first = None;
        f.wait(|f| {
            let confirmation = c.source_progress(&source_id).unwrap().and_then(|p| p.confirmation);
            if let Some(candidate) = confirmation.filter(|candidate| matches!(&candidate.kind,
                ConfirmationKind::Rewrite { candidate_digest } if candidate_digest.as_str() == digest)) {
                first = Some(candidate);
                f.has_held_receipt()
            } else { false }
        });
        let first = first.expect("matching durable confirmation was observed");
        assert!(matches!(first.kind, ConfirmationKind::Rewrite { .. }));
        assert!(f.has_text("shrinkremovedneedle"));
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            f.has_text("shrinkremovedneedle"),
            "complete parsing cannot bypass the grace period"
        );
        f.wait(|f| !f.has_text("shrinkremovedneedle"));
        assert!(rewritten_at.elapsed() >= Duration::from_secs(5));
        assert!(f.has_text("shrinkretainedneedle"));
        assert!(!f.has_text("shrinksecondremovedneedle"));
        let after = ManagedStore::open(&f.db, &c)
            .unwrap()
            .background_sources(&c)
            .unwrap()
            .remove(0);
        let receipt = after.latest_receipt.as_ref().unwrap();
        assert!(receipt.published && receipt.cycle_seq > first.first_cycle.get());
        assert_eq!(receipt.worker_boot_id, first.worker_boot_id.as_str());
        assert_eq!(receipt.digest, blake3::hash(&retained).to_hex().as_str());
        assert_eq!(after.indexed_len, Some(retained.len() as u64));
        assert_eq!(after.binding, before.binding);
        assert_eq!(fs::read(path).unwrap(), retained);
    }
}

#[test]
fn public_start_returns_pipe_eof_while_its_background_worker_remains_alive() {
    let f = Fixture::new("claude");
    let path = f.history.join("public.jsonl");
    let bytes = claude("public-start", "publicbackgroundneedle");
    fs::write(&path, &bytes).unwrap();
    let db = f.db.clone();
    let history = f.history.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || {
        let result = run(
            &db,
            &[
                "sources",
                "add",
                "--provider",
                "claude",
                history.to_str().unwrap(),
            ],
        );
        let _ = send.send(result);
    });
    // Collect stdout AND stderr to EOF, not merely the parent's exit status.
    let output = receive.recv_timeout(Duration::from_secs(8));
    let received_before_stop = output.is_ok();
    let worker_was_alive = matches!(
        ExclusiveGuard::try_acquire(f.db.parent().unwrap(), LockKind::Background),
        Err(PortError::WriterBusy(_))
    );
    if received_before_stop {
        successful(output.unwrap());
        f.wait(|f| f.has_text("publicbackgroundneedle"));
    }
    // Always release our detached synthetic worker, including a regression.
    let c = SqliteControlStore::open_current_writable(f.db.parent().unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match c.set_desired_updates(
            c.status().unwrap().policy.control_seq,
            DesiredUpdates::Stopped,
        ) {
            Ok(_) => break,
            Err(PortError::GenerationMismatch(_) | PortError::WriterBusy(_))
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(_) => panic!("synthetic worker stop failed"),
        }
    }
    f.wait(|f| ExclusiveGuard::try_acquire(f.db.parent().unwrap(), LockKind::Background).is_ok());
    caller.join().unwrap();
    assert!(
        received_before_stop,
        "parent pipe EOF waited for background worker exit"
    );
    assert!(
        worker_was_alive,
        "startup did not leave an independently running worker"
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn latest_barrier_requires_post_admission_discovery_and_source_receipts() {
    use agent_session_grep_ports::control::{LatestAdmission, LatestRequest, SelectionRevision};
    let mut f = Fixture::new("claude");
    let path = f.history.join("latest.jsonl");
    fs::write(&path, claude("latest-source", "latestproofneedle")).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("latestproofneedle"));
    let control = SqliteControlStore::open_current_writable(f.db.parent().unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let barrier = loop {
        let status = control.status().unwrap();
        let selections = status
            .policy
            .selections
            .iter()
            .filter(|s| s.enabled)
            .map(|s| SelectionRevision {
                selection_id: s.id.clone(),
                revision: s.revision,
                root_identity: s.root_identity.clone().unwrap(),
            })
            .collect();
        let result = control.admit_latest(
            status.policy.control_seq,
            LatestRequest {
                selections,
                max_wait_ms: 5000,
                now_ms: 1,
            },
        );
        match result {
            Ok(change) => match change.value {
                LatestAdmission::Queued(barrier) => break barrier,
                LatestAdmission::Blocked(_) => (),
            },
            Err(PortError::GenerationMismatch(_) | PortError::WriterBusy(_)) => (),
            Err(_) => panic!("latest admission failed"),
        }
        assert!(
            Instant::now() < deadline,
            "latest admission did not become available"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    f.wait(|f| latest_satisfied(f, &barrier));
    let c = f.control();
    let source = ManagedStore::open(&f.db, &c)
        .unwrap()
        .background_sources(&c)
        .unwrap();
    assert!(
        source[0].latest_receipt.as_ref().unwrap().cycle_seq >= barrier.required_cycle_seq.get()
    );
    drop(source);
    drop(c);
    fs::remove_file(&path).unwrap();
    f.wait(|f| !f.has_text("latestproofneedle"));
    let deadline = Instant::now() + Duration::from_secs(5);
    let after_delete = loop {
        let status = control.status().unwrap();
        let result = control.admit_latest(
            status.policy.control_seq,
            LatestRequest {
                selections: barrier.selections.clone(),
                max_wait_ms: 5000,
                now_ms: 2,
            },
        );
        if let Ok(change) = result
            && let LatestAdmission::Queued(barrier) = change.value
        {
            break barrier;
        }
        assert!(
            Instant::now() < deadline,
            "post-deletion latest admission unavailable"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    f.wait(|f| {
        let c = f.control();
        let store = ManagedStore::open(&f.db, &c).unwrap();
        store
            .with_read(
                &c,
                RequestIntersection::Selected,
                Instant::now() + Duration::from_secs(2),
                |read| read.latest_satisfied(&after_delete),
            )
            .unwrap()
    });
    let c = f.control();
    let sources = ManagedStore::open(&f.db, &c)
        .unwrap()
        .background_sources(&c)
        .unwrap();
    let receipt = sources[0].latest_receipt.as_ref().unwrap();
    assert_eq!(receipt.digest, "confirmed_absent");
    assert!(receipt.cycle_seq >= after_delete.required_cycle_seq.get());
    let previous_cycle = receipt.cycle_seq;
    fs::write(f.history.join("new-malformed.jsonl"), b"{\"type\":").unwrap();
    f.wait(|f| {
        let c = f.control();
        let runtime = c.background_status().unwrap();
        let cycle = c
            .cycle(
                agent_session_grep_ports::control::CycleSeq::new(runtime.next_cycle_seq.get() - 1)
                    .unwrap(),
            )
            .unwrap();
        cycle.token.cycle_seq.get() > previous_cycle
            && cycle.state == agent_session_grep_ports::control::CycleState::Partial
    });
    let store = ManagedStore::open(&f.db, &c).unwrap();
    assert!(
        !store
            .with_read(
                &c,
                RequestIntersection::Selected,
                Instant::now() + Duration::from_secs(2),
                |read| read.latest_satisfied(&after_delete)
            )
            .unwrap(),
        "new failed source must invalidate old discovery proof"
    );
}

fn admit_latest_barrier(f: &Fixture, now_ms: i64) -> LatestBarrier {
    admit_latest_barrier_for(f, now_ms, None)
}

fn admit_latest_barrier_for(
    f: &Fixture,
    now_ms: i64,
    locator: Option<&CanonicalLocator>,
) -> LatestBarrier {
    use agent_session_grep_ports::control::{LatestAdmission, LatestRequest, SelectionRevision};
    let deadline = Instant::now() + Duration::from_secs(20);
    let root = f.db.parent().unwrap();
    let physical = RootIdentity::read(root).unwrap();
    let witness = f.control();
    let installation = witness
        .with_runtime_deadline(deadline, || witness.status())
        .unwrap()
        .policy
        .installation_id;
    drop(witness);
    let control = loop {
        assert_eq!(RootIdentity::read(root).unwrap(), physical);
        match SqliteControlStore::open_existing_writable_with_deadline(
            root,
            &installation,
            deadline,
        ) {
            Ok(control) => break control,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("synthetic latest control admission failed: {error:?}"),
        }
    };
    loop {
        let status = match control.with_runtime_deadline(deadline, || control.status()) {
            Ok(status) => status,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => continue,
            Err(error) => panic!("synthetic latest status failed: {error:?}"),
        };
        let selections = status
            .policy
            .selections
            .iter()
            .filter(|s| s.enabled && locator.is_none_or(|locator| &s.region.locator == locator))
            .map(|s| SelectionRevision {
                selection_id: s.id.clone(),
                revision: s.revision,
                root_identity: s.root_identity.clone().unwrap(),
            })
            .collect();
        match control.with_runtime_deadline(deadline, || {
            control.admit_latest(
                status.policy.control_seq,
                LatestRequest {
                    selections,
                    max_wait_ms: 5000,
                    now_ms,
                },
            )
        }) {
            Ok(change) => match change.value {
                LatestAdmission::Queued(barrier) => return barrier,
                LatestAdmission::Blocked(_) => (),
            },
            Err(PortError::GenerationMismatch(_) | PortError::WriterBusy(_)) => (),
            Err(_) => panic!("latest admission failed"),
        }
        assert!(
            Instant::now() < deadline,
            "latest admission did not become available"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn latest_satisfied(f: &Fixture, barrier: &LatestBarrier) -> bool {
    let control = f.control();
    let Ok(store) = ManagedStore::open(&f.db, &control) else {
        return false;
    };
    store
        .with_read(
            &control,
            RequestIntersection::Selected,
            Instant::now() + Duration::from_secs(2),
            |read| read.latest_satisfied(barrier),
        )
        .unwrap_or(false)
}

#[test]
fn overlapping_parent_and_child_roots_import_one_transcript_for_both_claims() {
    for child_first in [false, true] {
        let mut f = Fixture::new("claude");
        let nested = f.history.join("nested");
        fs::create_dir(&nested).unwrap();
        let path = nested.join("synthetic.jsonl");
        let bytes = claude("nested", "overlapneedle");
        fs::write(&path, &bytes).unwrap();
        if child_first {
            f.add_selected(&nested);
        }
        f.spawn();
        if !child_first {
            f.add_selected(&nested);
        }
        f.wait(|f| f.has_text("overlapneedle"));
        let barrier = admit_latest_barrier(&f, 1);
        f.wait(|f| latest_satisfied(f, &barrier));
        let control = f.control();
        let sources = ManagedStore::open(&f.db, &control)
            .unwrap()
            .background_sources(&control)
            .unwrap();
        assert_eq!(
            sources.len(),
            1,
            "overlapping roots must resolve to one durable source"
        );
        assert!(sources[0].latest_receipt.as_ref().unwrap().published);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn revoked_parent_root_cannot_be_reallowed_by_surviving_child() {
    let mut f = Fixture::new("claude");
    let nested = f.history.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(
        nested.join("synthetic.jsonl"),
        claude("nested", "revokeoverlapneedle"),
    )
    .unwrap();
    f.add_selected(&nested);
    f.spawn();
    f.wait(|f| f.has_text("revokeoverlapneedle"));
    let control = f.control();
    let parent_locator =
        CanonicalLocator::from_path(&fs::canonicalize(&f.history).unwrap()).unwrap();
    let parent = control
        .status()
        .unwrap()
        .policy
        .selections
        .into_iter()
        .find(|selection| selection.region.locator == parent_locator)
        .expect("parent selection exists")
        .id;
    f.revoke(&parent);
    f.wait(|f| !f.has_text("revokeoverlapneedle"));
    assert!(!f.has_text("revokeoverlapneedle"));
}

#[test]
fn offline_selected_root_keeps_partial_coverage_without_blocking_healthy_evidence() {
    let mut f = Fixture::new("claude");
    let healthy = f.history.join("healthy");
    let offline = f.history.join("offline");
    fs::create_dir(&healthy).unwrap();
    fs::create_dir(&offline).unwrap();
    let path = healthy.join("healthy.jsonl");
    fs::write(&path, claude("healthy", "healthyneedle")).unwrap();
    fs::write(
        offline.join("offline.jsonl"),
        claude("offline", "offlineneedle"),
    )
    .unwrap();
    f.add_selected(&offline);
    f.spawn();
    f.wait(|f| f.has_text("healthyneedle") && f.has_text("offlineneedle"));
    let barrier = admit_latest_barrier(&f, 1);
    f.wait(|f| latest_satisfied(f, &barrier));
    fs::remove_dir_all(&offline).unwrap();
    f.wait(|f| !latest_satisfied(f, &barrier));
    assert!(f.has_text("healthyneedle"));
    // The healthy root keeps publishing even while its own coverage stays
    // partial because another selected root cannot be observed.
    let mut appended = fs::read(&path).unwrap();
    appended.extend(claude("healthy-two", "healthyafterneedle"));
    fs::write(&path, appended).unwrap();
    f.wait(|f| f.has_text("healthyafterneedle"));
    assert!(!latest_satisfied(&f, &barrier));
}

#[test]
fn overlapping_roots_keep_one_confirmation_root_across_rotation() {
    let mut f = Fixture::new("claude");
    let nested = f.history.join("nested");
    fs::create_dir(&nested).unwrap();
    let path = nested.join("rewrite.jsonl");
    let original = claude("rotated", "rotationfirstneedle");
    let replacement = claude("rotated", "rotationnextxneedle");
    assert_eq!(original.len(), replacement.len());
    fs::write(&path, &original).unwrap();
    f.add_selected(&nested);
    f.spawn();
    f.wait(|f| f.has_text("rotationfirstneedle"));
    let barrier = admit_latest_barrier(&f, 1);
    f.wait(|f| latest_satisfied(f, &barrier));
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, &replacement).unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    f.wait(|f| f.has_held_receipt());
    assert!(f.has_text("rotationfirstneedle"));
    // Fairness rotation must not move the advisory root and restart the grace
    // period between overlapping selections.
    f.wait(|f| f.has_text("rotationnextxneedle"));
    assert!(!f.has_text("rotationfirstneedle"));
    assert_eq!(fs::read(&path).unwrap(), replacement);
}

#[cfg(any(unix, windows))]
struct RejectedDirectoryLink(PathBuf);

#[cfg(any(unix, windows))]
impl RejectedDirectoryLink {
    fn new(path: PathBuf, target: &Path) -> Self {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &path).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let output = Command::new("cmd")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&path)
                .arg(target)
                .creation_flags(0x0800_0000)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "synthetic junction creation failed"
            );
        }
        Self(path)
    }
}

#[cfg(any(unix, windows))]
impl Drop for RejectedDirectoryLink {
    fn drop(&mut self) {
        // Remove the synthetic link entry only; never traverse its target.
        #[cfg(unix)]
        let _ = fs::remove_file(&self.0);
        #[cfg(windows)]
        let _ = fs::remove_dir(&self.0);
    }
}

#[cfg(any(unix, windows))]
#[test]
fn overlapping_healthy_child_publishes_rewrite_while_parent_discovery_is_incomplete() {
    let mut f = Fixture::new("claude");
    let nested = f.history.join("nested");
    fs::create_dir(&nested).unwrap();
    let path = nested.join("rewrite.jsonl");
    let original = claude("overlap-rewrite", "childbeforexneedle");
    let replacement = claude("overlap-rewrite", "childafterxxneedle");
    assert_eq!(original.len(), replacement.len());
    fs::write(&path, &original).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("childbeforexneedle"));
    // Import through the parent first so its historical binding root cannot
    // accidentally be the already healthy child under review.
    let parent_locator =
        CanonicalLocator::from_path(&fs::canonicalize(&f.history).unwrap()).unwrap();
    f.add_selected(&nested);
    let child_locator = CanonicalLocator::from_path(&fs::canonicalize(&nested).unwrap()).unwrap();
    let all = admit_latest_barrier(&f, 1);
    let parent = admit_latest_barrier_for(&f, 2, Some(&parent_locator));
    let child = admit_latest_barrier_for(&f, 3, Some(&child_locator));
    f.wait(|f| {
        latest_satisfied(f, &all) && latest_satisfied(f, &parent) && latest_satisfied(f, &child)
    });
    let child_root = child.selections[0].root_identity.clone();

    let rejected_target = f._temp.path().join("unselected-target");
    fs::create_dir(&rejected_target).unwrap();
    let rejected_path = rejected_target.join("ignored.jsonl");
    let rejected_bytes = claude("unselected", "unselectedlinkneedle");
    fs::write(&rejected_path, &rejected_bytes).unwrap();
    let _link = RejectedDirectoryLink::new(f.history.join("rejected-link"), &rejected_target);
    // The refused sibling makes only the parent discovery incomplete. Its
    // absence must not turn the independently complete child into a failed root.
    f.wait(|f| !latest_satisfied(f, &all));
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, &replacement).unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    f.wait(|f| f.has_held_receipt());
    assert!(f.has_text("childbeforexneedle"));
    let sources = {
        let control = f.control();
        ManagedStore::open(&f.db, &control)
            .unwrap()
            .background_sources(&control)
            .unwrap()
    };
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].binding.root_identity,
        parent.selections[0].root_identity.as_str()
    );
    let progress = f
        .control()
        .source_progress(
            &agent_session_grep_ports::control::ControlId::parse(
                sources[0].binding.source_id.as_str(),
            )
            .unwrap(),
        )
        .unwrap()
        .unwrap();
    let confirmation = progress.confirmation.unwrap();
    assert_eq!(confirmation.root_identity, child_root);
    assert!(matches!(
        confirmation.kind,
        agent_session_grep_ports::control::ConfirmationKind::Rewrite { .. }
    ));
    assert!(!latest_satisfied(&f, &child));
    assert!(!latest_satisfied(&f, &parent));

    f.wait(|f| f.has_text("childafterxxneedle") && latest_satisfied(f, &child));
    assert!(!f.has_text("childbeforexneedle"));
    assert!(!latest_satisfied(&f, &parent));
    assert!(!latest_satisfied(&f, &all));
    assert!(!f.has_text("unselectedlinkneedle"));
    assert_eq!(fs::read(&path).unwrap(), replacement);
    assert_eq!(fs::read(&rejected_path).unwrap(), rejected_bytes);
}

#[test]
fn completed_codex_rollout_with_known_environment_metadata_publishes_and_keeps_evidence() {
    let mut f = Fixture::new("codex");
    let path = f.history.join("current.jsonl");
    let mut bytes = serde_json::to_vec(
        &json!({"type":"session_meta","timestamp":"2026-01-01T00:00:00Z",
        "payload":{"session_id":"synthetic-modern-codex","cli_version":"0.163.0"}}),
    )
    .unwrap();
    bytes.push(b'\n');
    bytes.extend(codex(
        "known-environment",
        "<environment_context>\n  <cwd>synthetic</cwd>\n</environment_context>",
    ));
    bytes.extend(codex(
        "decision",
        "moderncodex original bounded retry decision",
    ));
    bytes.extend(
        serde_json::to_vec(&json!({"type":"token_usage_record","payload":{"additive":"ignored"}}))
            .unwrap(),
    );
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("moderncodex"));
    assert!(!f.has_text("environment_context"));
    f.wait(|f| {
        ManagedStore::open(&f.db, &f.control())
            .unwrap()
            .background_sources(&f.control())
            .unwrap()
            .iter()
            .all(|s| s.latest_receipt.as_ref().is_some_and(|r| r.published))
    });
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mut appended = bytes.clone();
    appended.extend(codex("continued", "moderncodex continuedwork proof"));
    fs::write(&path, &appended).unwrap();
    f.wait(|f| f.has_text("continuedwork"));
    assert_eq!(fs::read(&path).unwrap(), appended);
}

/// Codex reports cumulative session usage, converted to per-turn deltas. Two
/// turns that each add the same tokens produce two identical session-level
/// observations with one content-addressed id. The real worker must publish
/// the rollout (folding the repeat) instead of rejecting it as invalid, which
/// left every later update of an ordinary session unpublished.
#[test]
fn codex_rollout_with_equal_usage_deltas_still_publishes() {
    let mut f = Fixture::new("codex");
    let path = f.history.join("current.jsonl");
    let token_count = |input: u64, output: u64| {
        let mut bytes = serde_json::to_vec(
            &json!({"timestamp":"2026-01-01T00:00:00Z","type":"event_msg",
            "payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":input,
            "cached_input_tokens":0,"output_tokens":output,"reasoning_output_tokens":0}}}}),
        )
        .unwrap();
        bytes.push(b'\n');
        bytes
    };
    let mut bytes = serde_json::to_vec(
        &json!({"type":"session_meta","timestamp":"2026-01-01T00:00:00Z",
        "payload":{"session_id":"synthetic-equal-usage","cli_version":"0.163.0"}}),
    )
    .unwrap();
    bytes.push(b'\n');
    bytes.extend(codex("first-turn", "equalusage first turn"));
    bytes.extend(token_count(10, 2));
    bytes.extend(codex("second-turn", "equalusage second turn"));
    bytes.extend(token_count(20, 4));
    bytes.extend(codex("third-turn", "equalusage third turn"));
    bytes.extend(token_count(30, 6));
    fs::write(&path, &bytes).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("equalusage"));
    f.wait(|f| {
        ManagedStore::open(&f.db, &f.control())
            .unwrap()
            .background_sources(&f.control())
            .unwrap()
            .iter()
            .all(|s| s.latest_receipt.as_ref().is_some_and(|r| r.published))
    });
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

// M2 production-worker regressions. Fixtures own every source write, while the
// real worker must keep the original DB/WAL/transcript bytes unchanged.
use agent_session_grep_adapters_sqlite::managed::ManagedRead;
use agent_session_grep_ports::{
    PortResult,
    control::ObservationCycle,
    managed::{EntityData, EntityKind, LexicalHit, ResumeValue},
    source_context::{DependencyResolution, UnresolvedDependency},
};
use rusqlite::{Connection, params};

fn m2_rows(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>()
        .into_bytes()
}
fn m2_read<T>(f: &Fixture, mut operation: impl FnMut(&ManagedRead<'_>) -> PortResult<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let control = f.control();
        let result = ManagedStore::open(&f.db, &control).and_then(|store| {
            store.with_read(&control, RequestIntersection::Selected, deadline, |read| {
                operation(read)
            })
        });
        match result {
            Ok(value) => return value,
            Err(
                PortError::WriterBusy(_)
                | PortError::GenerationMismatch(_)
                | PortError::SnapshotChanged(_),
            ) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("synthetic M2 catalog read failed: {error:?}"),
        }
    }
}
fn m2_hits(f: &Fixture, text: &str) -> Vec<LexicalHit> {
    m2_read(f, |read| {
        read.query_lexical(text, &ProjectionQuery::default(), 64)
            .map(|page| page.hits)
    })
}
fn m2_sources(
    f: &Fixture,
) -> Vec<agent_session_grep_adapters_sqlite::managed_store::BackgroundSource> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let control = f.control();
        let result = ManagedStore::open(&f.db, &control)
            .and_then(|store| store.background_sources(&control));
        match result {
            Ok(sources) => return sources,
            Err(
                PortError::WriterBusy(_)
                | PortError::GenerationMismatch(_)
                | PortError::SnapshotChanged(_),
            ) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("synthetic M2 source read failed: {error:?}"),
        }
    }
}
#[track_caller]
fn m2_cycle_attempted(f: &Fixture, barrier: &LatestBarrier) -> (LatestBarrier, ObservationCycle) {
    let mut barrier = barrier.clone();
    let mut aborted = Vec::new();
    for attempt in 0..4 {
        let deadline = Instant::now() + Duration::from_secs(35);
        let cycle = loop {
            let control = f.control();
            let cycle = m2_read_with_retry(deadline, || {
                control
                    .with_runtime_deadline(deadline, || control.cycle(barrier.required_cycle_seq))
            });
            match cycle.state {
                CycleState::Committed | CycleState::Partial | CycleState::Aborted => break cycle,
                CycleState::Queued | CycleState::Observing if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                CycleState::Queued | CycleState::Observing => {
                    panic!("synthetic M2 latest cycle exceeded its observation deadline")
                }
            }
        };
        if cycle.state != CycleState::Aborted {
            return (barrier, cycle);
        }
        let control = f.control();
        let blocked = m2_read_with_retry(deadline, || {
            control.with_runtime_deadline(deadline, || control.barrier(&barrier.id))
        });
        assert_eq!(blocked.state, BarrierState::Blocked);
        assert!(!latest_satisfied(f, &barrier));
        aborted.push((
            cycle.token.cycle_seq.get(),
            blocked.error,
            cycle
                .selections
                .iter()
                .map(|selection| {
                    (
                        selection.discovery_complete,
                        selection.discovered_count,
                        selection.observed_count,
                        selection.committed_count,
                        selection.error,
                    )
                })
                .collect::<Vec<_>>(),
        ));
        if attempt == 3 {
            break;
        }
        barrier = admit_latest_barrier(
            f,
            barrier
                .admitted_at_ms
                .saturating_add(i64::from(attempt) + 1),
        );
    }
    let worker = f
        .control()
        .background_status()
        .ok()
        .map(|status| status.worker.state);
    panic!(
        "synthetic M2 latest barriers were repeatedly aborted: worker={worker:?}, cycles={aborted:?}"
    )
}
fn m2_read_with_retry<T>(deadline: Instant, mut read: impl FnMut() -> PortResult<T>) -> T {
    loop {
        match read() {
            Ok(value) => return value,
            Err(
                PortError::WriterBusy(_)
                | PortError::GenerationMismatch(_)
                | PortError::SnapshotChanged(_),
            ) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("synthetic M2 control read failed: {error:?}"),
        }
    }
}
fn m2_post_revoke_cycle_attempted(f: &Fixture, now_ms: i64) -> ObservationCycle {
    let barrier = admit_latest_barrier(f, now_ms);
    m2_cycle_attempted(f, &barrier).1
}
fn m2_selection(f: &Fixture, path: &Path) -> ControlId {
    let locator = CanonicalLocator::from_path(&fs::canonicalize(path).unwrap()).unwrap();
    f.control()
        .status()
        .unwrap()
        .policy
        .selections
        .into_iter()
        .find(|selection| selection.enabled && selection.region.locator == locator)
        .unwrap()
        .id
}
fn m2_add_selection(f: &Fixture, provider: &str, path: &Path) {
    f.desired(DesiredUpdates::Paused);
    successful(run(
        &f.db,
        &[
            "sources",
            "add",
            "--provider",
            provider,
            path.to_str().unwrap(),
        ],
    ));
    f.desired(DesiredUpdates::Running);
}
fn m2_source_for_path(
    f: &Fixture,
    path: &Path,
) -> agent_session_grep_adapters_sqlite::managed_store::BackgroundSource {
    let locator = CanonicalLocator::from_path(&fs::canonicalize(path).unwrap()).unwrap();
    m2_sources(f)
        .into_iter()
        .find(|source| source.binding.source_path == locator.as_str())
        .unwrap()
}
fn m2_receipt_current(f: &Fixture, path: &Path) -> bool {
    let Some(receipt) = m2_source_for_path(f, path).latest_receipt else {
        return false;
    };
    let control = f.control();
    ManagedStore::open(&f.db, &control)
        .and_then(|store| {
            store.source_current(&receipt, &control, Instant::now() + Duration::from_secs(2))
        })
        .unwrap_or(false)
}
fn m2_assert_no_metadata_enrichment(f: &Fixture, text: &str) {
    let hits = m2_hits(f, text);
    assert!(!hits.is_empty());
    let sessions = hits
        .iter()
        .map(|hit| {
            let occurrence = hit.projection.occurrence.as_ref().unwrap();
            assert_eq!(
                occurrence.data.project_id, None,
                "DB cwd must not invent a transcript project"
            );
            occurrence.data.placement.session_id.clone()
        })
        .collect::<Vec<_>>();
    m2_read(f, |read| {
        for entity in read.entities(EntityKind::Session, &sessions, &ProjectionQuery::default())? {
            let EntityData::Session(session) = entity.data else {
                panic!("expected a Session projection");
            };
            assert_eq!(session.repo_slug, None);
        }
        for entity in read.entities(EntityKind::Resume, &sessions, &ProjectionQuery::default())? {
            let EntityData::Resume(resume) = entity.data else {
                panic!("expected Resume projection");
            };
            assert_eq!(resume.original_working_directory, ResumeValue::Missing);
            assert!(!resume.pair_observed);
        }
        Ok(())
    });
    assert!(!f.has_text("metadataonlycwdneedle"));
}

fn m2_wb_transcript(native: &str, text: &str) -> Vec<u8> {
    m2_rows(&[
        json!({"type":"session-meta","sessionId":native,"timestamp":0,"meta":{"codebuddy.ai/hostKind":"workbuddy"}}),
        json!({"type":"message","id":format!("{native}-message"),"sessionId":native,"timestamp":1700000000123_i64,"role":"user","content":[{"type":"text","text":text}],"__codebuddyLocal":{"synthetic":true}}),
    ])
}
fn m2_wb_database(path: &Path, states: &[(&str, Option<i64>, &str)]) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE sessions(id TEXT PRIMARY KEY,deleted_at INTEGER,transport TEXT,cwd TEXT);",
    )
    .unwrap();
    for (native, deleted, transport) in states {
        conn.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,'metadataonlycwdneedle')",
            params![native, deleted, transport],
        )
        .unwrap();
    }
}

#[test]
fn m2_workbuddy_independent_metadata_selection_revoke_and_paused_original() {
    let native = "synthetic-wb-session";
    let original = m2_wb_transcript(native, "wbindependentoriginalneedle");
    let mut f = Fixture::selected("workbuddy", |root| {
        let surface = root.join(".workbuddy");
        let projects = surface.join("projects");
        let project = projects.join("synthetic-project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("session.jsonl"), &original).unwrap();
        m2_wb_database(&surface.join("workbuddy.db"), &[(native, None, "local")]);
        projects
    });
    let source = f.history.join("synthetic-project/session.jsonl");
    let metadata = f.history.parent().unwrap().join("workbuddy.db");
    let metadata_before = fs::read(&metadata).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("wbindependentoriginalneedle"));
    assert_eq!(
        m2_sources(&f).len(),
        1,
        "unselected sibling metadata must not be bound or scanned"
    );
    let transcript = m2_source_for_path(&f, &source);
    let control = f.control();
    let context = ManagedStore::open(&f.db, &control)
        .unwrap()
        .publication_context(
            &control,
            transcript.latest_receipt.as_ref().unwrap(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(context.dependencies.len(), 1);
    assert!(matches!(
        context.dependencies[0].resolution,
        DependencyResolution::Unresolved(UnresolvedDependency::NotSelected)
    ));
    let pending = admit_latest_barrier(&f, 1);
    let (pending, attempted) = m2_cycle_attempted(&f, &pending);
    assert!(
        attempted
            .selections
            .iter()
            .all(|selection| !selection.discovery_complete)
    );
    assert!(!latest_satisfied(&f, &pending));
    m2_assert_no_metadata_enrichment(&f, "wbindependentoriginalneedle");

    m2_add_selection(&f, "workbuddy", &metadata);
    f.wait(|f| m2_receipt_current(f, &source));
    let complete = admit_latest_barrier(&f, 2);
    f.wait(|f| latest_satisfied(f, &complete));
    m2_assert_no_metadata_enrichment(&f, "wbindependentoriginalneedle");
    let metadata_selection = m2_selection(&f, &metadata);
    f.revoke(&metadata_selection);
    f.wait(|f| !m2_receipt_current(f, &source));
    assert!(f.has_text("wbindependentoriginalneedle"));
    m2_assert_no_metadata_enrichment(&f, "wbindependentoriginalneedle");
    let withdrawn = m2_post_revoke_cycle_attempted(&f, 3);
    assert_eq!(withdrawn.state, CycleState::Partial);
    f.desired(DesiredUpdates::Paused);
    f.terminate();
    f.spawn();
    assert_eq!(
        f.control().status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
    assert!(f.has_text("wbindependentoriginalneedle"));
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&metadata).unwrap(), metadata_before);
}

#[test]
fn m2_workbuddy_successful_metadata_receipt_does_not_complete_missing_cloud_or_orphan_root() {
    for (native, transport) in [
        ("synthetic-active-missing", "local"),
        ("synthetic-cloud", "cloud"),
        ("synthetic-orphan", "future-unknown"),
    ] {
        let mut f = Fixture::selected("workbuddy", |root| {
            let surface = root.join(".workbuddy");
            fs::create_dir_all(surface.join("projects")).unwrap();
            m2_wb_database(&surface.join("workbuddy.db"), &[(native, None, transport)]);
            surface
        });
        f.spawn();
        f.wait(|f| {
            m2_sources(f).iter().any(|source| {
                source
                    .latest_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.published)
            })
        });
        let barrier = admit_latest_barrier(&f, 10);
        let (barrier, attempted) = m2_cycle_attempted(&f, &barrier);
        assert!(
            attempted
                .selections
                .iter()
                .all(|selection| !selection.discovery_complete)
        );
        assert!(
            !latest_satisfied(&f, &barrier),
            "metadata success cannot invent missing local/cloud originals"
        );
        let stats = m2_read(&f, |read| read.stats(&ProjectionQuery::default(), 16));
        assert_eq!(stats.catalog_count, 0);
        assert_eq!(stats.placements, 0);
    }
}

#[test]
fn m2_workbuddy_exact_metadata_selection_proves_only_empty_content_receipt() {
    let mut f = Fixture::selected("workbuddy", |root| {
        let surface = root.join(".workbuddy");
        fs::create_dir(&surface).unwrap();
        let metadata = surface.join("workbuddy.db");
        m2_wb_database(&metadata, &[("synthetic-cloud", None, "cloud")]);
        metadata
    });
    let before = fs::read(&f.history).unwrap();
    f.spawn();
    let barrier = admit_latest_barrier(&f, 11);
    f.wait(|f| latest_satisfied(f, &barrier));
    let sources = m2_sources(&f);
    assert_eq!(sources.len(), 1);
    assert!(sources[0].latest_receipt.as_ref().unwrap().published);
    let stats = m2_read(&f, |read| read.stats(&ProjectionQuery::default(), 16));
    assert_eq!(stats.catalog_count, 0);
    assert_eq!(stats.placements, 0);
    assert_eq!(fs::read(&f.history).unwrap(), before);
}

#[test]
fn m2_workbuddy_soft_delete_requires_observed_hold_and_new_boot_confirmation() {
    let native = "synthetic-wb-delete";
    let original = m2_wb_transcript(native, "wbsoftdeleteoriginalneedle");
    let mut f = Fixture::selected("workbuddy", |root| {
        let surface = root.join(".workbuddy");
        let project = surface.join("projects/synthetic-project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("session.jsonl"), &original).unwrap();
        m2_wb_database(&surface.join("workbuddy.db"), &[(native, None, "local")]);
        surface
    });
    let path = f.history.join("projects/synthetic-project/session.jsonl");
    let metadata = f.history.join("workbuddy.db");
    f.spawn();
    f.wait(|f| f.has_text("wbsoftdeleteoriginalneedle"));
    let barrier = admit_latest_barrier(&f, 20);
    f.wait(|f| latest_satisfied(f, &barrier));
    Connection::open(&metadata)
        .unwrap()
        .execute("UPDATE sessions SET deleted_at=1000 WHERE id=?1", [native])
        .unwrap();
    let metadata_after = fs::read(&metadata).unwrap();
    f.wait(Fixture::has_held_receipt);
    assert!(f.has_text("wbsoftdeleteoriginalneedle"));
    f.terminate();
    f.spawn();
    f.wait(Fixture::has_held_receipt);
    assert!(f.has_text("wbsoftdeleteoriginalneedle"));
    f.wait(|f| !f.has_text("wbsoftdeleteoriginalneedle"));
    let completed = admit_latest_barrier(&f, 21);
    f.wait(|f| latest_satisfied(f, &completed));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read(&metadata).unwrap(), metadata_after);
}

fn m2_dsh_frame(rows: &[Value]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(&m2_rows(rows)).unwrap();
    encoder.finish().unwrap()
}
fn m2_dsh_source(native: &str, text: &str) -> Vec<u8> {
    let mut bytes = m2_dsh_frame(&[json!({"type":"session","version":4,"id":native,
        "createdAt":0,"cwd":"/synthetic/project","isSeeded":false,"delegationDepth":0})]);
    bytes.extend(m2_dsh_frame(&[
        json!({"type":"user/message","seq":0,"time":1700000000123_u64,
        "surfaceOp":"append","data":{"id":format!("{native}-message"),"role":"user",
        "content":[{"type":"text","text":text}],"source":{"kind":"user"}}}),
    ]));
    bytes
}
#[test]
fn m2_dsh_highest_generation_future_refusal_and_restart_keep_one_original() {
    let native = "synthetic-dsh";
    let original = m2_dsh_source(native, "dshcanonicaloriginalneedle");
    let mut f = Fixture::selected("deepseek-harness", |root| {
        let history = root.join(".dsh/sessions");
        let session = history.join("synthetic-project").join(native);
        fs::create_dir_all(&session).unwrap();
        fs::write(
            session.join("session.v3.jsonl.zstd"),
            m2_dsh_source(native, "dshobsoletegenerationneedle"),
        )
        .unwrap();
        fs::write(session.join("session.v4.jsonl.zstd"), &original).unwrap();
        history
    });
    let session = f.history.join("synthetic-project").join(native);
    let path = session.join("session.v4.jsonl.zstd");
    f.spawn();
    f.wait(|f| f.has_text("dshcanonicaloriginalneedle"));
    let latest = admit_latest_barrier(&f, 101);
    f.wait(|f| latest_satisfied(f, &latest));
    assert!(!f.has_text("dshobsoletegenerationneedle"));
    let before = m2_hits(&f, "dshcanonicaloriginalneedle");
    assert_eq!(before.len(), 1);
    let canonical = before[0]
        .projection
        .occurrence
        .as_ref()
        .unwrap()
        .data
        .placement
        .session_id
        .clone();
    fs::write(
        session.join("session.v99.jsonl.zstd"),
        m2_dsh_source(native, "dshfuturemustnotpublishneedle"),
    )
    .unwrap();
    let blocked = admit_latest_barrier(&f, 102);
    let (blocked, _) = m2_cycle_attempted(&f, &blocked);
    assert!(!latest_satisfied(&f, &blocked));
    assert!(f.has_text("dshcanonicaloriginalneedle"));
    assert!(!f.has_text("dshfuturemustnotpublishneedle"));
    f.terminate();
    f.spawn();
    let restarted = admit_latest_barrier(&f, 103);
    let (restarted, _) = m2_cycle_attempted(&f, &restarted);
    assert!(!latest_satisfied(&f, &restarted));
    assert_eq!(
        m2_hits(&f, "dshcanonicaloriginalneedle")[0]
            .projection
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .placement
            .session_id,
        canonical
    );
    assert_eq!(fs::read(&path).unwrap(), original);
}
#[test]
fn m2_dsh_same_native_ids_in_distinct_surfaces_remain_independent() {
    let native = "synthetic-dsh-shared";
    let mut f = Fixture::selected("deepseek-harness", |root| {
        let history = root.join("first/.dsh/sessions");
        let session = history.join("project").join(native);
        fs::create_dir_all(&session).unwrap();
        fs::write(
            session.join("session.v4.jsonl.zstd"),
            m2_dsh_source(native, "dshseparatesurfaceneedle"),
        )
        .unwrap();
        history
    });
    let second = f._temp.path().join("second/.dsh/sessions");
    let session = second.join("project").join(native);
    fs::create_dir_all(&session).unwrap();
    fs::write(
        session.join("session.v4.jsonl.zstd"),
        m2_dsh_source(native, "dshseparatesurfaceneedle"),
    )
    .unwrap();
    m2_add_selection(&f, "deepseek-harness", &second);
    f.spawn();
    // Identical native Message IDs are intentionally one lexical hit. Their
    // source occurrences must still retain the two independent Sessions.
    f.wait(|f| {
        m2_read(f, |read| {
            let page =
                read.query_lexical("dshseparatesurfaceneedle", &ProjectionQuery::default(), 64)?;
            let Some(hit) = page.hits.first() else {
                return Ok(false);
            };
            Ok(read
                .message_contexts(
                    &hit.projection.message.id,
                    &ProjectionQuery::default(),
                    64,
                    64,
                )?
                .candidate_count
                == 2)
        })
    });
    m2_read(&f, |read| {
        let page =
            read.query_lexical("dshseparatesurfaceneedle", &ProjectionQuery::default(), 64)?;
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].claim_count, 2);
        let contexts = read.message_contexts(
            &page.hits[0].projection.message.id,
            &ProjectionQuery::default(),
            64,
            64,
        )?;
        assert_eq!(contexts.candidate_count, 2);
        assert!(!contexts.truncated);
        let mut sessions = std::collections::BTreeSet::new();
        let mut sources = std::collections::BTreeSet::new();
        for candidate in contexts.candidates {
            sessions.insert(candidate.session_id.as_str().to_owned());
            assert_eq!(candidate.occurrences.len(), 1);
            let evidence = &candidate.occurrences[0];
            assert_eq!(
                evidence.occurrence.data.placement.session_id,
                candidate.session_id
            );
            sources.insert(evidence.proof.source_id.as_str().to_owned());
        }
        assert_eq!(sessions.len(), 2);
        assert_eq!(sources.len(), 2);
        Ok(())
    });
    let latest = admit_latest_barrier(&f, 104);
    f.wait(|f| latest_satisfied(f, &latest));
}

fn m2_ag_varint(mut number: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while number >= 128 {
        bytes.push((number as u8 & 127) | 128);
        number >>= 7;
    }
    bytes.push(number as u8);
    bytes
}
fn m2_ag_scalar(field: u32, number: u64) -> Vec<u8> {
    let mut bytes = m2_ag_varint(u64::from(field) << 3);
    bytes.extend(m2_ag_varint(number));
    bytes
}
fn m2_ag_text(field: u32, value: &str) -> Vec<u8> {
    let mut bytes = m2_ag_varint((u64::from(field) << 3) | 2);
    bytes.extend(m2_ag_varint(value.len() as u64));
    bytes.extend(value.as_bytes());
    bytes
}
fn m2_ag_database(path: &Path, native: &str, text: &str) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("CREATE TABLE trajectory_meta(trajectory_id TEXT PRIMARY KEY,cascade_id TEXT,trajectory_type INTEGER,source INTEGER);
        CREATE TABLE steps(idx INTEGER PRIMARY KEY,step_type INTEGER NOT NULL,status INTEGER NOT NULL,
        has_subtrajectory NUMERIC NOT NULL DEFAULT 0,metadata BLOB,error_details BLOB,permissions BLOB,
        task_details BLOB,render_info BLOB,step_payload BLOB,step_format INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE trajectory_metadata_blob(id TEXT PRIMARY KEY,data BLOB);").unwrap();
    conn.execute(
        "INSERT INTO trajectory_meta VALUES('fedcba98-7654-3210-fedc-ba9876543210',?1,4,17)",
        [native],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO trajectory_metadata_blob VALUES('main',?1)",
        [m2_ag_text(6, native)],
    )
    .unwrap();
    let payload = m2_ag_text(2, text);
    let mut step = m2_ag_scalar(1, 14);
    step.extend(m2_ag_scalar(4, 3));
    step.extend(m2_ag_varint((19 << 3) | 2));
    step.extend(m2_ag_varint(payload.len() as u64));
    step.extend(payload);
    conn.execute(
        "INSERT INTO steps(idx,step_type,status,step_payload) VALUES(0,14,3,?1)",
        [step],
    )
    .unwrap();
}
fn m2_ag_full(text: &str) -> Vec<u8> {
    m2_rows(&[
        json!({"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","content":text}),
    ])
}
#[test]
fn m2_antigravity_full_and_database_transition_is_atomic_and_excludes_mirrors() {
    let native = "01234567-89ab-cdef-0123-456789abcdef";
    let mut f = Fixture::selected("antigravity", |root| {
        let surface = root.join("antigravity");
        fs::create_dir_all(surface.join("conversations")).unwrap();
        fs::create_dir_all(
            surface
                .join("brain")
                .join(native)
                .join(".system_generated/logs/chunks"),
        )
        .unwrap();
        m2_ag_database(
            &surface.join("conversations").join(format!("{native}.db")),
            native,
            "agdatabaseoriginalneedle",
        );
        surface
    });
    let database = f.history.join("conversations").join(format!("{native}.db"));
    let logs = f
        .history
        .join("brain")
        .join(native)
        .join(".system_generated/logs");
    let full = logs.join("transcript_full.jsonl");
    let database_before = fs::read(&database).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("agdatabaseoriginalneedle"));
    let old = m2_hits(&f, "agdatabaseoriginalneedle")[0]
        .projection
        .occurrence
        .as_ref()
        .unwrap()
        .data
        .placement
        .session_id
        .clone();
    fs::write(
        logs.join("chunks/mirror.jsonl"),
        m2_ag_full("agmirrormustnotpublishneedle"),
    )
    .unwrap();
    fs::write(
        logs.join("transcript.jsonl"),
        m2_ag_full("agshortmustnotpublishneedle"),
    )
    .unwrap();
    fs::write(&full, m2_ag_full("agfulloriginalneedle")).unwrap();
    f.wait(|f| f.has_text("agfulloriginalneedle") && !f.has_text("agdatabaseoriginalneedle"));
    assert!(!f.has_text("agmirrormustnotpublishneedle"));
    assert!(!f.has_text("agshortmustnotpublishneedle"));
    let new = m2_hits(&f, "agfulloriginalneedle")[0]
        .projection
        .occurrence
        .as_ref()
        .unwrap()
        .data
        .placement
        .session_id
        .clone();
    assert_eq!(new, old);
    let latest = admit_latest_barrier(&f, 105);
    f.wait(|f| latest_satisfied(f, &latest));
    let original = fs::read(&full).unwrap();
    let mut partial = original.clone();
    partial.extend(br#"{"step_index":"#);
    fs::write(&full, partial).unwrap();
    let blocked = admit_latest_barrier(&f, 106);
    let (blocked, _) = m2_cycle_attempted(&f, &blocked);
    assert!(!latest_satisfied(&f, &blocked));
    assert!(f.has_text("agfulloriginalneedle"));
    assert!(!f.has_text("agdatabaseoriginalneedle"));
    fs::write(&full, &original).unwrap();
    let resumed = admit_latest_barrier(&f, 107);
    f.wait(|f| latest_satisfied(f, &resumed));
    assert_eq!(fs::read(&database).unwrap(), database_before);
    assert_eq!(fs::read(&full).unwrap(), original);
}

fn m2_zcode_database(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
        CREATE TABLE session(id TEXT PRIMARY KEY,project_id TEXT,parent_id TEXT,directory TEXT,version TEXT,time_created INTEGER,time_updated INTEGER,revert TEXT);
        CREATE TABLE message(id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER);
        CREATE TABLE part(id TEXT PRIMARY KEY,message_id TEXT NOT NULL REFERENCES message(id) ON DELETE CASCADE,session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,time_created INTEGER,time_updated INTEGER,data TEXT,sequence INTEGER);
        CREATE TABLE session_entry(id TEXT PRIMARY KEY,session_id TEXT,kind TEXT,data TEXT);").unwrap();
    conn.execute("INSERT INTO session VALUES('synthetic-z-parent','project',NULL,'/synthetic/project','0.16.9',1000,2000,NULL)", []).unwrap();
    conn.execute("INSERT INTO session VALUES('synthetic-z-child','project','synthetic-z-parent','/synthetic/project','0.16.9',1000,2000,NULL)", []).unwrap();
    conn
}
fn m2_zcode_message(conn: &Connection, id: &str, native: &str, text: &str, seq: i64) {
    conn.execute(
        "INSERT INTO message VALUES(?1,?2,1000,2000,?3,?4)",
        params![id, native, json!({"role":"user"}).to_string(), seq],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO part VALUES(?1,?2,?3,1000,2000,?4,0)",
        params![
            format!("{id}-part"),
            id,
            native,
            json!({"type":"text","text":text}).to_string()
        ],
    )
    .unwrap();
}
#[test]
fn m2_zcode_wal_parent_child_rewrite_and_pause_preserve_source_bytes() {
    let mut writer = None;
    let mut f = Fixture::selected("zcode", |root| {
        let surface = root.join(".zcode/cli/db");
        fs::create_dir_all(&surface).unwrap();
        let conn = m2_zcode_database(&surface.join("db.sqlite"));
        m2_zcode_message(
            &conn,
            "synthetic-z-first",
            "synthetic-z-parent",
            "zcodeparentoriginalneedle",
            0,
        );
        m2_zcode_message(
            &conn,
            "synthetic-z-child-first",
            "synthetic-z-child",
            "zcodechildoriginalneedle",
            0,
        );
        writer = Some(conn);
        surface
    });
    let database = f.history.join("db.sqlite");
    let wal = PathBuf::from(format!("{}-wal", database.to_str().unwrap()));
    let before = fs::read(&database).unwrap();
    let wal_before = fs::read(&wal).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("zcodeparentoriginalneedle") && f.has_text("zcodechildoriginalneedle"));
    let latest = admit_latest_barrier(&f, 108);
    f.wait(|f| latest_satisfied(f, &latest));
    assert_eq!(fs::read(&database).unwrap(), before);
    assert_eq!(fs::read(&wal).unwrap(), wal_before);
    m2_zcode_message(
        writer.as_ref().unwrap(),
        "synthetic-z-new",
        "synthetic-z-parent",
        "zcodewalincrementneedle",
        1,
    );
    let committed = fs::read(&database).unwrap();
    let wal_committed = fs::read(&wal).unwrap();
    f.wait(|f| f.has_text("zcodewalincrementneedle"));
    let updated = admit_latest_barrier(&f, 109);
    f.wait(|f| latest_satisfied(f, &updated));
    f.desired(DesiredUpdates::Paused);
    f.terminate();
    f.spawn();
    assert!(f.has_text("zcodeparentoriginalneedle"));
    assert!(f.has_text("zcodewalincrementneedle"));
    assert_eq!(fs::read(&database).unwrap(), committed);
    assert_eq!(fs::read(&wal).unwrap(), wal_committed);
}

#[test]
fn m2_dsh_torn_and_corrupt_frames_keep_original_until_complete_rewrite() {
    let native = "synthetic-dsh-integrity";
    let original = m2_dsh_source(native, "dshintegrityoriginalneedle");
    let mut f = Fixture::selected("deepseek-harness", |root| {
        let history = root.join(".dsh/sessions");
        let session = history.join("project").join(native);
        fs::create_dir_all(&session).unwrap();
        fs::write(session.join("session.v4.jsonl.zstd"), &original).unwrap();
        history
    });
    let source = f
        .history
        .join("project")
        .join(native)
        .join("session.v4.jsonl.zstd");
    f.spawn();
    f.wait(|f| f.has_text("dshintegrityoriginalneedle"));
    let initial = admit_latest_barrier(&f, 200);
    f.wait(|f| latest_satisfied(f, &initial));
    let before = m2_hits(&f, "dshintegrityoriginalneedle")[0]
        .projection
        .clone();
    let frame = m2_dsh_frame(&[
        json!({"type":"user/message","seq":1,"time":1700000000124_u64,
        "surfaceOp":"append","data":{"id":"synthetic-integrity-later","role":"user",
        "content":[{"type":"text","text":"dshintegrityappendneedle"}],"source":{"kind":"user"}}}),
    ]);
    let mut complete = original.clone();
    complete.extend(&frame);
    let mut torn = original.clone();
    torn.extend(&frame[..frame.len() - 3]);
    fs::write(&source, &torn).unwrap();
    let pending = admit_latest_barrier(&f, 201);
    let (pending, _) = m2_cycle_attempted(&f, &pending);
    assert!(!latest_satisfied(&f, &pending));
    assert!(f.has_text("dshintegrityoriginalneedle"));
    assert!(!f.has_text("dshintegrityappendneedle"));
    assert!(!m2_receipt_current(&f, &source));
    assert_eq!(fs::read(&source).unwrap(), torn);
    let mut corrupt = complete.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&source, &corrupt).unwrap();
    let failed = admit_latest_barrier(&f, 202);
    let (failed, _) = m2_cycle_attempted(&f, &failed);
    assert!(!latest_satisfied(&f, &failed));
    assert!(f.has_text("dshintegrityoriginalneedle"));
    assert!(!f.has_text("dshintegrityappendneedle"));
    assert_eq!(fs::read(&source).unwrap(), corrupt);
    fs::write(&source, &complete).unwrap();
    f.wait(Fixture::has_held_receipt);
    assert!(f.has_text("dshintegrityoriginalneedle"));
    assert!(!f.has_text("dshintegrityappendneedle"));
    f.terminate();
    f.spawn();
    f.wait(Fixture::has_held_receipt);
    assert!(!f.has_text("dshintegrityappendneedle"));
    f.wait(|f| f.has_text("dshintegrityappendneedle"));
    let refreshed = admit_latest_barrier(&f, 203);
    f.wait(|f| latest_satisfied(f, &refreshed));
    let after = m2_hits(&f, "dshintegrityoriginalneedle")[0]
        .projection
        .clone();
    assert_eq!(after.message.id, before.message.id);
    assert_eq!(
        after.occurrence.unwrap().data.placement.session_id,
        before.occurrence.unwrap().data.placement.session_id
    );
    assert_eq!(fs::read(&source).unwrap(), complete);
    let selected = m2_selection(&f, &f.history);
    f.revoke(&selected);
    assert!(!f.has_text("dshintegrityoriginalneedle"));
    assert!(!f.has_text("dshintegrityappendneedle"));
    assert_eq!(fs::read(&source).unwrap(), complete);
}

#[test]
fn m2_antigravity_full_absence_requires_new_boot_grace_before_database_fallback() {
    let native = "12345678-9abc-def0-1234-56789abcdef0";
    let original = m2_ag_full("agabsencefullneedle");
    let mut f = Fixture::selected("antigravity", |root| {
        let surface = root.join("antigravity");
        fs::create_dir_all(surface.join("conversations")).unwrap();
        let logs = surface
            .join("brain")
            .join(native)
            .join(".system_generated/logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("transcript_full.jsonl"), &original).unwrap();
        m2_ag_database(
            &surface.join("conversations").join(format!("{native}.db")),
            native,
            "agabsencedatabaseneedle",
        );
        surface
    });
    let database = f.history.join("conversations").join(format!("{native}.db"));
    let full = f
        .history
        .join("brain")
        .join(native)
        .join(".system_generated/logs/transcript_full.jsonl");
    let database_before = fs::read(&database).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("agabsencefullneedle"));
    let ready = admit_latest_barrier(&f, 210);
    f.wait(|f| latest_satisfied(f, &ready));
    let native_session = m2_hits(&f, "agabsencefullneedle")[0]
        .projection
        .occurrence
        .as_ref()
        .unwrap()
        .data
        .placement
        .session_id
        .clone();
    assert!(!f.has_text("agabsencedatabaseneedle"));
    let fallback_held = |f: &Fixture| {
        let locator = CanonicalLocator::from_path(&database).unwrap();
        m2_sources(f)
            .iter()
            .find(|s| s.binding.source_path == locator.as_str())
            .is_some_and(|s| {
                f.control()
                    .source_progress(&ControlId::parse(s.binding.source_id.as_str()).unwrap())
                    .unwrap()
                    .is_some_and(|p| p.confirmation.is_some())
            })
    };
    fs::remove_file(&full).unwrap();
    // A new DB representation has no published evidence yet, so its pending
    // observation lives in control progress, not the readable evidence census.
    f.wait(fallback_held);
    assert!(f.has_text("agabsencefullneedle"));
    assert!(!f.has_text("agabsencedatabaseneedle"));
    f.terminate();
    f.spawn();
    f.wait(fallback_held);
    assert!(f.has_text("agabsencefullneedle"));
    assert!(!f.has_text("agabsencedatabaseneedle"));
    f.wait(|f| f.has_text("agabsencedatabaseneedle") && !f.has_text("agabsencefullneedle"));
    let fallback = admit_latest_barrier(&f, 211);
    f.wait(|f| latest_satisfied(f, &fallback));
    assert_eq!(
        m2_hits(&f, "agabsencedatabaseneedle")[0]
            .projection
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .placement
            .session_id,
        native_session
    );
    fs::write(&full, &original).unwrap();
    f.wait(|f| f.has_text("agabsencefullneedle") && !f.has_text("agabsencedatabaseneedle"));
    let restored = admit_latest_barrier(&f, 212);
    f.wait(|f| latest_satisfied(f, &restored));
    assert_eq!(
        m2_hits(&f, "agabsencefullneedle")[0]
            .projection
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .placement
            .session_id,
        native_session
    );
    assert_eq!(fs::read(&database).unwrap(), database_before);
    assert_eq!(fs::read(&full).unwrap(), original);
}

#[test]
fn m2_workbuddy_unrelated_metadata_churn_does_not_reset_delete_and_restore_proof() {
    use agent_session_grep_ports::control::ConfirmationKind;
    let native = "synthetic-wb-churn";
    let original = m2_wb_transcript(native, "wbsemanticoriginalneedle");
    let mut f = Fixture::selected("workbuddy", |root| {
        let surface = root.join(".workbuddy");
        let project = surface.join("projects/project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("session.jsonl"), &original).unwrap();
        m2_wb_database(&surface.join("workbuddy.db"), &[(native, None, "local")]);
        surface
    });
    let metadata = f.history.join("workbuddy.db");
    let source = f.history.join("projects/project/session.jsonl");
    f.spawn();
    f.wait(|f| f.has_text("wbsemanticoriginalneedle"));
    let ready = admit_latest_barrier(&f, 220);
    f.wait(|f| latest_satisfied(f, &ready));
    let canonical = m2_hits(&f, "wbsemanticoriginalneedle")[0]
        .projection
        .occurrence
        .as_ref()
        .unwrap()
        .data
        .placement
        .session_id
        .clone();
    Connection::open(&metadata)
        .unwrap()
        .execute("UPDATE sessions SET deleted_at=1000 WHERE id=?1", [native])
        .unwrap();
    let source_id = m2_source_for_path(&f, &source).binding.source_id;
    let source_id = ControlId::parse(source_id.as_str()).unwrap();
    let mut first = None;
    f.wait(|f| {
        let confirmation = f
            .control()
            .source_progress(&source_id)
            .ok()
            .flatten()
            .and_then(|progress| progress.confirmation);
        if let Some(candidate) = confirmation.filter(|candidate| {
            matches!(
                &candidate.kind,
                ConfirmationKind::Rewrite { candidate_digest }
                    if candidate_digest.as_str().starts_with("metadata_")
            )
        }) {
            first = Some(candidate);
            f.has_held_receipt()
        } else {
            false
        }
    });
    let first = first.expect("soft-delete confirmation was observed");
    for index in 0..3 {
        Connection::open(&metadata)
            .unwrap()
            .execute(
                "UPDATE sessions SET cwd=?1 WHERE id=?2",
                params![format!("unrelated-churn-{index}"), native],
            )
            .unwrap();
        let barrier = admit_latest_barrier(&f, 221 + index);
        let _ = m2_cycle_attempted(&f, &barrier);
        let progress = f.control().source_progress(&source_id).unwrap().unwrap();
        if let Some(current) = progress.confirmation {
            assert!(matches!(
                current.kind,
                ConfirmationKind::Rewrite { ref candidate_digest }
                    if candidate_digest.as_str().starts_with("metadata_")
            ));
            assert_eq!(current.first_cycle, first.first_cycle);
            assert_eq!(current.first_monotonic_ms, first.first_monotonic_ms);
        } else {
            assert!(
                !f.has_text("wbsemanticoriginalneedle"),
                "confirmation may clear only after the original evidence is retired"
            );
        }
    }
    f.wait(|f| !f.has_text("wbsemanticoriginalneedle"));
    let deleted = admit_latest_barrier(&f, 225);
    let (deleted, _) = m2_cycle_attempted(&f, &deleted);
    f.wait(|f| latest_satisfied(f, &deleted));
    // Repeated identical deletion state remains current rather than starting
    // another five-second confirmation for already-removed original content.
    let still_deleted = admit_latest_barrier(&f, 226);
    let (still_deleted, _) = m2_cycle_attempted(&f, &still_deleted);
    f.wait(|f| latest_satisfied(f, &still_deleted));
    Connection::open(&metadata)
        .unwrap()
        .execute("UPDATE sessions SET deleted_at=NULL WHERE id=?1", [native])
        .unwrap();
    let metadata_after = fs::read(&metadata).unwrap();
    f.wait(|f| f.has_text("wbsemanticoriginalneedle"));
    let restored = admit_latest_barrier(&f, 227);
    let (restored, _) = m2_cycle_attempted(&f, &restored);
    f.wait(|f| latest_satisfied(f, &restored));
    assert_eq!(
        m2_hits(&f, "wbsemanticoriginalneedle")[0]
            .projection
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .placement
            .session_id,
        canonical
    );
    m2_assert_no_metadata_enrichment(&f, "wbsemanticoriginalneedle");
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&metadata).unwrap(), metadata_after);
}

#[test]
fn m2_zcode_unknown_part_keeps_child_until_complete_graph_confirms_removal() {
    let mut writer = None;
    let mut f = Fixture::selected("zcode", |root| {
        let surface = root.join(".zcode/cli/db");
        fs::create_dir_all(&surface).unwrap();
        let conn = m2_zcode_database(&surface.join("db.sqlite"));
        m2_zcode_message(
            &conn,
            "synthetic-z-stable",
            "synthetic-z-parent",
            "zcodestableparentneedle",
            0,
        );
        m2_zcode_message(
            &conn,
            "synthetic-z-retired",
            "synthetic-z-child",
            "zcoderetainedchildneedle",
            0,
        );
        writer = Some(conn);
        surface
    });
    let database = f.history.join("db.sqlite");
    let wal = PathBuf::from(format!("{}-wal", database.to_str().unwrap()));
    f.spawn();
    f.wait(|f| f.has_text("zcodestableparentneedle") && f.has_text("zcoderetainedchildneedle"));
    let ready = admit_latest_barrier(&f, 230);
    f.wait(|f| latest_satisfied(f, &ready));
    let native_session = m2_hits(&f, "zcodestableparentneedle")[0]
        .projection
        .occurrence
        .as_ref()
        .unwrap()
        .data
        .placement
        .session_id
        .clone();
    writer.as_ref().unwrap().execute(
        "INSERT INTO part VALUES('synthetic-unknown','synthetic-z-retired','synthetic-z-child',1000,2000,?1,1)",
        [json!({"type":"future-unknown-part","text":"zcodeunknownmustnotpublishneedle"}).to_string()]).unwrap();
    let db_partial = fs::read(&database).unwrap();
    let wal_partial = fs::read(&wal).unwrap();
    let partial = admit_latest_barrier(&f, 231);
    let (partial, _) = m2_cycle_attempted(&f, &partial);
    assert!(!latest_satisfied(&f, &partial));
    assert!(f.has_text("zcoderetainedchildneedle"));
    assert!(!f.has_text("zcodeunknownmustnotpublishneedle"));
    assert_eq!(fs::read(&database).unwrap(), db_partial);
    assert_eq!(fs::read(&wal).unwrap(), wal_partial);
    writer
        .as_ref()
        .unwrap()
        .execute("DELETE FROM session WHERE id='synthetic-z-child'", [])
        .unwrap();
    let db_after = fs::read(&database).unwrap();
    let wal_after = fs::read(&wal).unwrap();
    f.wait(Fixture::has_held_receipt);
    assert!(f.has_text("zcoderetainedchildneedle"));
    f.wait(|f| !f.has_text("zcoderetainedchildneedle"));
    assert!(f.has_text("zcodestableparentneedle"));
    let complete = admit_latest_barrier(&f, 232);
    f.wait(|f| latest_satisfied(f, &complete));
    assert_eq!(
        m2_hits(&f, "zcodestableparentneedle")[0]
            .projection
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .placement
            .session_id,
        native_session
    );
    assert_eq!(fs::read(&database).unwrap(), db_after);
    assert_eq!(fs::read(&wal).unwrap(), wal_after);
}

#[test]
fn owned_purge_child_completes_before_synthetic_directory_cleanup() {
    let mut f = Fixture::new("claude");
    let path = f.history.join("teardown.jsonl");
    let bytes = claude("teardown", "purgeteardownoriginalneedle");
    fs::write(&path, &bytes).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("purgeteardownoriginalneedle"));
    let selection = m2_selection(&f, &f.history);
    f.revoke(&selection);
    f.wait(|f| {
        f.control()
            .purge_jobs()
            .unwrap()
            .iter()
            .all(|job| job.state == PurgeState::Complete)
    });
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = f.purge_child.as_mut().unwrap().try_wait().unwrap() {
            assert!(
                status.success(),
                "owned purge completion did not exit successfully"
            );
            f.purge_child = None;
            break;
        }
        assert!(Instant::now() < end, "completed purge child did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let root = f._temp.path().to_owned();
    drop(f);
    assert!(
        !root.exists(),
        "drained synthetic directory was not cleaned up"
    );
}

#[test]
fn transient_control_writer_does_not_end_background_lifetime_or_lose_next_update() {
    let mut f = Fixture::new("claude");
    let path = f.history.join("control-contention.jsonl");
    let original = claude("first", "controlcontentionoriginalneedle");
    fs::write(&path, &original).unwrap();
    f.spawn();
    f.wait(|f| f.has_text("controlcontentionoriginalneedle"));
    let old_boot = f.control().background_status().unwrap().worker.boot_id;
    let contender = Connection::open(SqliteControlStore::path(f.db.parent().unwrap())).unwrap();
    contender.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&claude("next", "controlcontentionnextneedle"))
        .unwrap();
    file.flush().unwrap();
    drop(file);
    // More than a normal control tick and a cadence, within the source budget.
    // The same worker must survive the refused tick and publish after release.
    std::thread::sleep(Duration::from_millis(1600));
    assert!(
        f.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "a transient control writer ended the owned background lifetime"
    );
    contender.execute_batch("ROLLBACK").unwrap();
    f.wait(|f| f.has_text("controlcontentionnextneedle"));
    assert_eq!(
        f.control().background_status().unwrap().worker.boot_id,
        old_boot
    );
    assert!(f.has_text("controlcontentionoriginalneedle"));
}
