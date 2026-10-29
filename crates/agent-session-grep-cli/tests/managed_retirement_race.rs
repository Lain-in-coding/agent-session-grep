//! Real CLI callers and real OS leases over synthetic private roots only.
//! No source data, user registration, service or installation is changed.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    control::{INSTALLATION_LOCK_KEY, PURGE_LOCK_KEY},
    managed_control_lifetime::{RETIREMENT_MARKER, RetirementDrainGuards, RetirementIntent},
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind},
    managed_store::ManagedStore,
};
use agent_session_grep_ports::{PortError, SearchProvider, control::*};
use rusqlite::Connection;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn lock(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => std::thread::yield_now(),
            Err(error) => panic!("synthetic lock acquisition failed: {error:?}"),
        }
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    db: PathBuf,
    control: Option<SqliteControlStore>,
    background: Option<ExclusiveGuard>,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let selected = temp.path().join("synthetic-selected");
        fs::create_dir(&selected).unwrap();
        let db = root.join("catalog.db");
        let control = SqliteControlStore::create(
            &root,
            &id("synthetic-installation"),
            DesiredUpdates::Running,
        )
        .unwrap();
        let selection = control
            .add_selection(
                ControlSeq::new(0).unwrap(),
                SelectionRequest {
                    region: ScopeRegion {
                        provider: SearchProvider::Codex,
                        locator: CanonicalLocator::from_path(&selected).unwrap(),
                        kind: RootKind::Root,
                    },
                    root_identity: Some(id("synthetic-selected-root")),
                    now_ms: 1,
                },
            )
            .unwrap();
        let background = lock(&root, LockKind::Background);
        {
            let worker = control
                .bind_worker(&background, id("synthetic-boot"))
                .unwrap();
            control
                .register_worker(selection.control_seq, &worker, std::process::id(), 2)
                .unwrap();
            let store = ManagedStore::create(&db, &control, id("synthetic-catalog"), 3).unwrap();
            store.reconcile_progress(&control, &worker).unwrap();
        }
        Self {
            _temp: temp,
            root,
            db,
            control: Some(control),
            background: Some(background),
        }
    }
    fn close_control(&mut self) {
        drop(self.control.take());
    }
    fn spawn(&self, latest: bool) -> Caller {
        let mut command = Command::new(BIN);
        command
            .args(["--robot", "--db"])
            .arg(&self.db)
            .args(["search", "synthetic"]);
        if latest {
            command.args(["--latest", "--max-wait-ms", "8000"]);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        Caller {
            child: Some(command.spawn().unwrap()),
        }
    }
}
struct Caller {
    child: Option<Child>,
}
impl Caller {
    fn running(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }
    fn exited_diagnostic(&mut self) -> String {
        use std::io::Read;
        let child = self.child.as_mut().unwrap();
        let status = child.try_wait().unwrap();
        let mut bytes = Vec::new();
        if let Some(mut stdout) = child.stdout.take() {
            stdout.read_to_end(&mut bytes).unwrap();
        }
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            format!(
                "exit={status:?}, code={}, message={}",
                value["error"]["code"], value["error"]["message"]
            )
        } else {
            format!("exit={status:?}, malformed public envelope")
        }
    }
    fn wait(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.running() {
            assert!(
                Instant::now() < deadline,
                "bounded synthetic CLI completion failed"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for Caller {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn wait_for_control_lease(root: &Path, caller: &mut Caller) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            caller.running(),
            "caller exited before owning its control lease"
        );
        match ExclusiveGuard::try_acquire(root, LockKind::ControlHandles) {
            Err(PortError::WriterBusy(_)) => return,
            Ok(guard) => drop(guard),
            Err(error) => panic!("unexpected synthetic control lock error: {error:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "control lease handshake did not complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn wait_for_barrier(root: &Path, caller: &mut Caller) {
    let conn = Connection::open(SqliteControlStore::path(root)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if !caller.running() {
            panic!(
                "latest caller exited before durable admission: {}",
                caller.exited_diagnostic()
            );
        }
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM barriers WHERE state='pending'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if count == 1 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "latest admission handshake did not complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn assert_private_output(output: &Output, root: &Path) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(&root.display().to_string()));
        assert!(!text.contains("synthetic-installation"));
        assert!(!text.contains("synthetic-catalog"));
    }
}

#[test]
fn cli_keeps_control_lease_while_waiting_for_history_readers() {
    let mut f = Fixture::new();
    f.close_control();
    // Exact OS ownership is the scheduling handshake. No test sleep stands in
    // for evidence that the caller has passed its retirement admission.
    drop(lock(&f.root, LockKind::ControlHandles));
    let history = lock(&f.root, LockKind::HistoryReaders);
    let mut caller = f.spawn(false);
    wait_for_control_lease(&f.root, &mut caller);
    assert!(matches!(
        ExclusiveGuard::try_acquire(&f.root, LockKind::ControlHandles),
        Err(PortError::WriterBusy(_))
    ));
    assert!(caller.running());
    assert!(!f.root.join(RETIREMENT_MARKER).exists());
    drop(history);
    let output = caller.wait();
    assert_private_output(&output, &f.root);
    assert!(
        matches!(output.status.code(), Some(0 | 10)),
        "synthetic managed search failed: {:?}",
        serde_json::from_slice::<Value>(&output.stdout)
            .ok()
            .map(|v| v["error"].clone())
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "partial");
    assert_eq!(value["data"]["hits"].as_array().unwrap().len(), 0);
    assert_eq!(value["data"]["freshness"]["latest_requested"], false);
    assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
    drop(lock(&f.root, LockKind::ControlHandles));
}

#[test]
fn latest_retains_control_and_history_leases_until_pause_finishes_request() {
    let mut f = Fixture::new();
    f.close_control();
    let mut caller = f.spawn(true);
    wait_for_barrier(&f.root, &mut caller);
    assert!(matches!(
        ExclusiveGuard::try_acquire(&f.root, LockKind::ControlHandles),
        Err(PortError::WriterBusy(_))
    ));
    assert!(matches!(
        ExclusiveGuard::try_acquire(&f.root, LockKind::HistoryReaders),
        Err(PortError::WriterBusy(_))
    ));
    let control = SqliteControlStore::open_current_writable(&f.root).unwrap();
    control
        .set_desired_updates(
            control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    drop(control);
    let output = caller.wait();
    assert!(matches!(output.status.code(), Some(0 | 10)));
    assert_private_output(&output, &f.root);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
    assert_eq!(value["data"]["freshness"]["reason"], "paused");
    drop(lock(&f.root, LockKind::ControlHandles));
    drop(lock(&f.root, LockKind::HistoryReaders));
}

#[test]
fn real_terminal_owner_publishes_marker_before_denied_cli_can_create_history_lock() {
    let mut f = Fixture::new();
    let prefix = f._temp.path().join("synthetic-prefix");
    fs::create_dir(&prefix).unwrap();
    let installation = lock(
        &prefix,
        LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap()),
    );
    let control = f.control.as_ref().unwrap();
    let policy = lock(&f.root, LockKind::PolicyOwner);
    let bound = control.bind_control_root(&policy).unwrap();
    control
        .record_verified_installation_prefix(
            &prefix,
            &installation,
            &bound,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    let installed = control.bind_installation(&prefix, &installation).unwrap();
    control
        .begin_maintenance(
            control.status().unwrap().policy.control_seq,
            &id("synthetic-uninstall"),
            &bound,
            &installed,
            MaintenanceFence {
                state: MaintenanceState::Uninstalling,
                owner: Some(id("synthetic-uninstall")),
                phase: Some(MaintenancePhase::Quiescing),
            },
        )
        .unwrap();
    drop(policy);
    let intent = RetirementIntent::bind(
        control,
        &f.db,
        &prefix,
        &installation,
        &id("synthetic-uninstall"),
    )
    .unwrap();
    f.close_control();
    drop(f.background.take());
    let policy_owner = lock(&f.root, LockKind::PolicyOwner);
    let emission = lock(&f.root, LockKind::PolicyEmission);
    let catalog = lock(&f.root, LockKind::CatalogHandles);
    let background = lock(&f.root, LockKind::Background);
    let supervisor = lock(&f.root, LockKind::Supervisor);
    let purge = lock(
        &f.root,
        LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY).unwrap()),
    );
    let retirement = intent
        .try_acquire(RetirementDrainGuards {
            policy_owner: &policy_owner,
            emission: &emission,
            catalog_handles: &catalog,
            background: &background,
            supervisor: &supervisor,
            purge: &purge,
        })
        .unwrap();
    assert!(!f.root.join("history-readers.lock").exists());
    let caller = f.spawn(false);
    retirement.publish_marker().unwrap();
    retirement.validate_marker().unwrap();
    drop(retirement);
    let output = caller.wait();
    assert!(!output.status.success());
    assert_private_output(&output, &f.root);
    assert!(!f.root.join("history-readers.lock").exists());
    // A later denied admission, after exclusive retirement has ended, is still
    // fail closed. The durable marker is never removed by normal requests.
    let again = f.spawn(false).wait();
    assert!(!again.status.success());
    assert!(!f.root.join("history-readers.lock").exists());
    assert_private_output(&again, &f.root);
    assert!(f.root.join(RETIREMENT_MARKER).exists());
}
