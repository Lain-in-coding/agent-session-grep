//! Synthetic installation/control roots and owned subprocesses only. This is
//! supervisor evidence, not login registration or native-manager acceptance.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_store::ManagedStore,
};
use agent_session_grep_cli::managed_supervisor::{
    HEALTHY_RESET, MAX_UNEXPECTED_EXITS, RestartPolicy, Supervisor, SupervisorState, restart_delay,
};
use agent_session_grep_launcher::metadata::{APP_NAME, BUILD_TARGET};
use agent_session_grep_ports::{PortError, control::*};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
const SHIM: &str = env!("CARGO_BIN_EXE_asg-supervisor");

fn seq(n: i64) -> ControlSeq {
    ControlSeq::new(n).unwrap()
}
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn seconds(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn pure_retry_schedule_caps_and_fifth_crash_latches() {
    assert_eq!(
        (1..=8)
            .map(|n| restart_delay(n).as_secs())
            .collect::<Vec<_>>(),
        [1, 2, 4, 8, 16, 30, 30, 30]
    );
    let mut policy = RestartPolicy::new(seq(1));
    let mut now = Duration::ZERO;
    for n in 1..=MAX_UNEXPECTED_EXITS {
        policy.record_exit(now, -1, false);
        assert_eq!(policy.unexpected_exits(), n);
        if n < MAX_UNEXPECTED_EXITS {
            assert_eq!(policy.state(now), SupervisorState::Backoff);
            now += restart_delay(n);
            assert_eq!(
                policy.state(now - Duration::from_nanos(1)),
                SupervisorState::Backoff
            );
            assert_eq!(policy.state(now), SupervisorState::Ready);
        }
    }
    assert_eq!(policy.state(now), SupervisorState::BackgroundFailed);
    policy.record_healthy_active(seconds(86_400));
    assert_eq!(
        policy.state(seconds(86_400)),
        SupervisorState::BackgroundFailed
    );
    policy.observe_restart(seq(1)).unwrap();
    assert_eq!(policy.state(now), SupervisorState::BackgroundFailed);
    policy.observe_restart(seq(2)).unwrap();
    assert_eq!(policy.state(now), SupervisorState::Ready);
    assert_eq!(policy.unexpected_exits(), 0);
    assert!(policy.observe_restart(seq(1)).is_err());
}

#[test]
fn pure_budget_uses_healthy_runtime_not_wall_or_wait_time() {
    let mut policy = RestartPolicy::new(seq(0));
    policy.record_exit(seconds(10), 1, false);
    assert_eq!(policy.state(seconds(100_000)), SupervisorState::Ready);
    assert_eq!(policy.unexpected_exits(), 1);
    policy.record_healthy_active(HEALTHY_RESET - Duration::from_nanos(1));
    assert_eq!(policy.unexpected_exits(), 1);
    policy.record_healthy_active(Duration::from_nanos(1));
    assert_eq!(policy.unexpected_exits(), 0);
    policy.record_exit(seconds(100_001), 1, false);
    assert_eq!(policy.state(seconds(100_002)), SupervisorState::Ready);
}

#[test]
fn pure_clean_stop_and_maintenance_never_crash_loop() {
    for (code, intentional) in [(0, false), (0, true), (17, true)] {
        let mut policy = RestartPolicy::new(seq(1));
        policy.record_exit(seconds(1), code, intentional);
        assert_eq!(policy.unexpected_exits(), 0);
        assert_eq!(policy.state(seconds(1000)), SupervisorState::CleanIdle);
        policy.observe_restart(seq(2)).unwrap();
        assert_eq!(policy.state(seconds(1000)), SupervisorState::Ready);
    }
}

fn application_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| fs::read(BIN).unwrap())
}

struct Fixture {
    _temp: tempfile::TempDir,
    prefix: PathBuf,
    catalog: PathBuf,
    shim: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let prefix = root.join("installed candidate");
        let catalog = root.join("private/catalog.db");
        let digest = format!("{:x}", Sha256::digest(application_bytes()));
        let version = env!("CARGO_PKG_VERSION");
        let dir = format!("versions/{version}-{}", &digest[..12]);
        fs::create_dir_all(prefix.join(&dir)).unwrap();
        let executable = prefix.join(&dir).join(APP_NAME);
        fs::write(&executable, application_bytes()).unwrap();
        let shim = prefix.join(&dir).join(if cfg!(windows) {
            "asg-supervisor.exe"
        } else {
            "asg-supervisor"
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(
            prefix.join("current.json"),
            serde_json::to_vec(&json!({
                "schema":"asg.current/v1", "generation":1, "version":version,
                "dir":dir, "app":APP_NAME, "app_sha256":digest,
                "launcher_protocol":1, "activated_at":"2026-10-17T00:00:00Z"
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            prefix.join(&dir).join("release.json"),
            serde_json::to_vec(&json!({
                "schema":"asg.version/v1", "version":version, "target":BUILD_TARGET,
                "source_commit":"a".repeat(40), "app_sha256":digest,
                "catalog_schema":agent_session_grep_adapters_sqlite::SCHEMA_VERSION,
                "control_schema":agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION, "launcher_protocol_min":1, "launcher_protocol_max":1,
                "built_at":"2026-10-17T00:00:00Z"
            }))
            .unwrap(),
        )
        .unwrap();
        let control = SqliteControlStore::create(
            catalog.parent().unwrap(),
            &id("supervisor-fixture"),
            DesiredUpdates::Running,
        )
        .unwrap();
        drop(ManagedStore::create(&catalog, &control, id("catalog-one"), 1).unwrap());
        Self {
            _temp: temp,
            prefix,
            catalog,
            shim,
        }
    }

    fn complete_package(&self) {
        use std::collections::BTreeMap;
        let pointer: serde_json::Value =
            serde_json::from_slice(&fs::read(self.prefix.join("current.json")).unwrap()).unwrap();
        let dir = pointer["dir"].as_str().unwrap();
        let shim_name = self.shim.file_name().unwrap().to_str().unwrap();
        let shim_bytes = fs::read(SHIM).unwrap();
        let shim_digest = format!("{:x}", Sha256::digest(&shim_bytes));
        fs::write(&self.shim, &shim_bytes).unwrap();
        let alias = if cfg!(windows) { "asg.exe" } else { "asg" };
        // These native fixture aliases are only integrity inputs, never run.
        // Reuse the existing small native test executable, not another large
        // debug CLI image. Their hashes remain distinct from the worker image.
        let launcher = fs::read(env!("CARGO_BIN_EXE_resume-smoke-provider")).unwrap();
        fs::write(self.prefix.join(APP_NAME), &launcher).unwrap();
        fs::write(self.prefix.join(alias), &launcher).unwrap();
        let mut members = BTreeMap::from([
            (APP_NAME.to_owned(), true),
            (alias.to_owned(), true),
            (format!("{dir}/{APP_NAME}"), true),
            (format!("{dir}/{shim_name}"), true),
            (format!("{dir}/release.json"), false),
            ("current.json".into(), false),
        ]);
        for name in [
            "package-install.ps1",
            "package-install.sh",
            "INSTALL-AND-UPGRADE.md",
            "README.md",
            "CHANGELOG.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "NOTICE",
            "SECURITY.md",
            "THIRD-PARTY-DEPENDENCIES.json",
            "THIRD-PARTY-DEPENDENCIES.csv",
        ] {
            fs::write(self.prefix.join(name), b"synthetic package member\n").unwrap();
            members.insert(name.into(), name == "package-install.sh");
        }
        let mut manifest = format!(
            "asg.package-files/v1\nversion\t{}\ntarget\t{}\nsource_commit\t{}\napp\t{}\napp_sha256\t{}\ndir\t{}\nlauncher_protocol\t1\ncatalog_schema\t{}\ncontrol_schema\t{}\nbuilt_at\t2026-10-17T00:00:00Z\nsupervisor\t{}\nsupervisor_sha256\t{}\n",
            env!("CARGO_PKG_VERSION"),
            BUILD_TARGET,
            "a".repeat(40),
            APP_NAME,
            pointer["app_sha256"].as_str().unwrap(),
            dir,
            agent_session_grep_adapters_sqlite::SCHEMA_VERSION,
            agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION,
            shim_name,
            shim_digest
        );
        for (name, executable) in members {
            let path = self.prefix.join(&name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
                )
                .unwrap();
            }
            let bytes = fs::read(path).unwrap();
            manifest.push_str(&format!(
                "file\t{:x}\t{}\t{}\t{}\n",
                Sha256::digest(&bytes),
                if executable { "0755" } else { "0644" },
                bytes.len(),
                name
            ));
        }
        fs::write(self.prefix.join("PACKAGE-MANIFEST.tsv"), &manifest).unwrap();
        let receipt = json!({"schema":"asg.package-install/v1", "product":"agent-session-grep", "version":env!("CARGO_PKG_VERSION"), "target":BUILD_TARGET, "source_commit":"a".repeat(40), "launcher_protocol":1, "manifest_sha256":"b".repeat(64), "archive_sha256":"c".repeat(64), "package_files_sha256":format!("{:x}", Sha256::digest(manifest.as_bytes()))});
        fs::write(
            self.prefix.join("package-install.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
    }

    fn control(&self) -> SqliteControlStore {
        fixture_retry(|| SqliteControlStore::open_current_writable(self.catalog.parent().unwrap()))
            .unwrap()
    }

    fn desired(&self, desired: DesiredUpdates) {
        let control = self.control();
        retry_control(&control, |seq| {
            control.set_desired_updates(seq, desired).map(|_| ())
        });
    }

    fn start_request(&self) {
        let control = self.control();
        retry_control(&control, |seq| {
            control.request_background_start(seq).map(|_| ())
        });
    }

    fn supervised(&self) -> Harness<'_> {
        Harness {
            fixture: self,
            supervisor: Supervisor::open(&self.prefix, &self.catalog).unwrap(),
        }
    }

    fn shim(&self) -> OwnedProcess {
        let child = Command::new(&self.shim)
            .arg("--prefix")
            .arg(&self.prefix)
            .arg("--db")
            .arg(&self.catalog)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        OwnedProcess(child)
    }
}

fn retry_control(
    control: &SqliteControlStore,
    mut operation: impl FnMut(ControlSeq) -> Result<(), PortError>,
) {
    fixture_retry(|| {
        control
            .status()
            .and_then(|status| operation(status.policy.control_seq))
    })
    .unwrap();
}

fn fixture_retry<T>(mut operation: impl FnMut() -> Result<T, PortError>) -> Result<T, PortError> {
    let deadline = Instant::now() + seconds(5);
    loop {
        match operation() {
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            result => return result,
        }
    }
}

struct Harness<'a> {
    fixture: &'a Fixture,
    supervisor: Supervisor,
}
impl Harness<'_> {
    fn until(
        &mut self,
        mut predicate: impl FnMut(&Supervisor, SupervisorState) -> bool,
    ) -> SupervisorState {
        let deadline = Instant::now() + seconds(15);
        loop {
            let state = self.supervisor.tick().unwrap_or_else(|error| {
                panic!(
                    "supervisor tick failed after {} crashes: {error:?}",
                    self.supervisor.policy().unexpected_exits()
                );
            });
            if predicate(&self.supervisor, state) {
                return state;
            }
            assert!(
                Instant::now() < deadline,
                "supervisor condition timed out: {state:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn ready(&mut self) -> u32 {
        self.until(|supervisor, _| {
            let worker = self.fixture.control().background_status().unwrap().worker;
            supervisor.child_id().is_some()
                && worker.pid_hint == supervisor.child_id()
                && matches!(worker.state, UpdateState::Idle | UpdateState::Paused)
        });
        self.supervisor.child_id().unwrap()
    }
}
impl Drop for Harness<'_> {
    fn drop(&mut self) {
        let stopped = fixture_retry(|| {
            let control =
                SqliteControlStore::open_current_writable(self.fixture.catalog.parent().unwrap())?;
            let seq = control.status()?.policy.control_seq;
            control
                .set_desired_updates(seq, DesiredUpdates::Stopped)
                .map(|_| ())
        });
        if let Err(error) = stopped {
            eprintln!("synthetic supervisor cleanup could not persist stop: {error:?}");
            return;
        }
        let deadline = Instant::now() + seconds(5);
        while Instant::now() < deadline {
            match self.supervisor.tick() {
                Ok(SupervisorState::Finished) => return,
                Err(_) => return,
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

struct OwnedProcess(Child);
impl OwnedProcess {
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + seconds(10);
        loop {
            if let Some(exit) = self.0.try_wait().unwrap() {
                return exit;
            }
            assert!(Instant::now() < deadline, "owned subprocess exit timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

// Fault injection is restricted to the child returned by this Supervisor,
// never the durable PID hint. Windows pins the handle before termination.
fn crash_owned(supervisor: &Supervisor) {
    let pid = supervisor.child_id().expect("owned child");
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess},
        };
        // SAFETY: pid was produced by this test's own live child; immediately
        // acquire its process handle and use only that handle for fault injection.
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            assert!(!handle.is_null());
            assert_ne!(TerminateProcess(handle, 23), 0);
            assert_ne!(CloseHandle(handle), 0);
        }
    }
    #[cfg(unix)]
    // SAFETY: this live process is our unreaped child, preventing PID reuse.
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGKILL) }, 0);
}

#[test]
fn actual_image_startup_admission_is_separate_from_live_control_polls() {
    let fixture = Fixture::new();
    let mut harness = fixture.supervised();
    // This is the actual CLI image, not a substituted helper or smaller stub.
    // It must reach a real owned worker under the default parallel test run.
    let worker = harness.ready();
    let pointer = fixture.prefix.join("current.json");
    let original = fs::read(&pointer).unwrap();
    fs::write(&pointer, b"{}\n").unwrap();
    // Live control observation neither rehashes the large image nor rereads
    // package metadata. Its worker and original control authority stay bound.
    assert_eq!(harness.supervisor.tick().unwrap(), SupervisorState::Running);
    assert_eq!(harness.supervisor.child_id(), Some(worker));
    fixture.desired(DesiredUpdates::Stopped);
    harness.until(|_, state| state == SupervisorState::Finished);
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
    fs::write(&pointer, original).unwrap();
    fixture.desired(DesiredUpdates::Running);
    fixture.start_request();
    let restarted = harness.ready();
    assert_ne!(worker, restarted);
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
}

#[test]
fn real_worker_pause_retains_process_and_stop_releases_both_locks() {
    let fixture = Fixture::new();
    let mut harness = fixture.supervised();
    let pid = harness.ready();
    fixture.desired(DesiredUpdates::Paused);
    harness.until(|s, state| state == SupervisorState::Paused && s.child_id() == Some(pid));
    std::thread::sleep(seconds(2));
    assert_eq!(harness.supervisor.tick().unwrap(), SupervisorState::Paused);
    assert_eq!(harness.supervisor.child_id(), Some(pid));
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
    fixture.start_request();
    assert_eq!(harness.supervisor.tick().unwrap(), SupervisorState::Paused);
    fixture.desired(DesiredUpdates::Stopped);
    harness.until(|_, state| state == SupervisorState::Finished);
    assert_eq!(harness.supervisor.child_id(), None);
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
    drop(harness);
    drop(
        ExclusiveGuard::try_acquire(fixture.catalog.parent().unwrap(), LockKind::Background)
            .unwrap(),
    );
    drop(
        ExclusiveGuard::try_acquire(fixture.catalog.parent().unwrap(), LockKind::Supervisor)
            .unwrap(),
    );
}

#[test]
fn real_unexpected_exit_recovers_and_exhaustion_waits_for_explicit_start() {
    let fixture = Fixture::new();
    let mut harness = fixture.supervised();
    for n in 1..=MAX_UNEXPECTED_EXITS {
        harness.ready();
        crash_owned(&harness.supervisor);
        harness.until(|s, _| s.child_id().is_none());
        assert_eq!(harness.supervisor.policy().unexpected_exits(), n);
        if n < MAX_UNEXPECTED_EXITS {
            assert_eq!(harness.supervisor.tick().unwrap(), SupervisorState::Backoff);
        }
    }
    assert_eq!(
        harness.supervisor.tick().unwrap(),
        SupervisorState::BackgroundFailed
    );
    assert!(fixture.control().status().unwrap().supervisor_failed);
    let stable = fixture.control().status().unwrap().policy.control_seq;
    std::thread::sleep(seconds(2));
    assert_eq!(
        harness.supervisor.tick().unwrap(),
        SupervisorState::BackgroundFailed
    );
    assert_eq!(
        fixture.control().status().unwrap().policy.control_seq,
        stable
    );
    fixture.start_request();
    harness.ready();
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
    assert!(!fixture.control().status().unwrap().supervisor_failed);
}

#[test]
fn real_duplicate_supervisor_is_silent_and_never_steals_child() {
    let fixture = Fixture::new();
    fixture.complete_package();
    let mut harness = fixture.supervised();
    let pid = harness.ready();
    assert!(matches!(
        Supervisor::open(&fixture.prefix, &fixture.catalog),
        Err(PortError::WriterBusy(_))
    ));
    let mut second = fixture.shim();
    assert!(second.wait().success());
    use std::io::Read;
    let mut output = Vec::new();
    second
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    second
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    assert!(output.is_empty());
    assert_eq!(harness.supervisor.child_id(), Some(pid));
    assert_eq!(harness.supervisor.tick().unwrap(), SupervisorState::Running);
}

#[test]
fn real_maintenance_drains_worker_without_counting_a_crash() {
    let fixture = Fixture::new();
    let mut harness = fixture.supervised();
    harness.ready();
    let control = fixture.control();
    let owner = id("maintenance-owner");
    let lock = ExclusiveGuard::try_acquire(
        fixture.catalog.parent().unwrap(),
        LockKind::MaintenanceJob(
            agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse("supervisor-test")
                .unwrap(),
        ),
    )
    .unwrap();
    retry_control(&control, |seq| {
        control
            .set_maintenance(
                seq,
                &owner,
                MaintenanceFence {
                    state: MaintenanceState::Updating,
                    owner: Some(owner.clone()),
                    phase: Some(MaintenancePhase::Quiescing),
                },
            )
            .map(|_| ())
    });
    harness.until(|_, state| state == SupervisorState::Finished);
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
    assert_eq!(
        control.status().unwrap().desired_updates,
        DesiredUpdates::Running
    );
    drop(
        ExclusiveGuard::try_acquire(fixture.catalog.parent().unwrap(), LockKind::CatalogHandles)
            .unwrap(),
    );
    drop(lock);
}

#[test]
fn already_paused_login_keeps_control_worker_available() {
    let fixture = Fixture::new();
    fixture.desired(DesiredUpdates::Paused);
    let mut harness = fixture.supervised();
    let pid = harness.ready();
    assert_eq!(harness.supervisor.tick().unwrap(), SupervisorState::Paused);
    assert_eq!(harness.supervisor.child_id(), Some(pid));
    assert_eq!(
        fixture.control().status().unwrap().desired_updates,
        DesiredUpdates::Paused
    );
}

#[test]
fn stopped_before_launch_never_creates_worker() {
    let fixture = Fixture::new();
    fixture.desired(DesiredUpdates::Stopped);
    let mut harness = fixture.supervised();
    assert_eq!(
        harness.supervisor.tick().unwrap(),
        SupervisorState::Finished
    );
    assert_eq!(harness.supervisor.child_id(), None);
    assert!(
        fixture
            .control()
            .background_status()
            .unwrap()
            .worker
            .boot_id
            .is_none()
    );
}

#[test]
fn another_background_owner_is_left_alive_without_spawning() {
    let fixture = Fixture::new();
    let guard =
        ExclusiveGuard::try_acquire(fixture.catalog.parent().unwrap(), LockKind::Background)
            .unwrap();
    let mut harness = fixture.supervised();
    assert_eq!(
        harness.supervisor.tick().unwrap(),
        SupervisorState::OtherWorker
    );
    assert_eq!(harness.supervisor.child_id(), None);
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
    drop(guard);
    harness.ready();
}

#[test]
fn explicit_start_arriving_with_clean_exit_is_not_lost() {
    let fixture = Fixture::new();
    let mut harness = fixture.supervised();
    harness.ready();
    fixture.desired(DesiredUpdates::Stopped);
    let deadline = Instant::now() + seconds(5);
    while fixture.control().background_status().unwrap().worker.state != UpdateState::Offline {
        assert!(Instant::now() < deadline, "worker did not acknowledge stop");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Keep the supervisor from observing the clean exit until the explicit
    // start arrives. Both facts must be consumed without losing the request.
    std::thread::sleep(Duration::from_millis(100));
    fixture.desired(DesiredUpdates::Running);
    fixture.start_request();
    harness.ready();
    assert_eq!(harness.supervisor.policy().unexpected_exits(), 0);
}

#[cfg(unix)]
#[test]
fn replaced_install_root_is_rejected_before_spawn() {
    let fixture = Fixture::new();
    let mut supervisor = Supervisor::open(&fixture.prefix, &fixture.catalog).unwrap();
    let original = fixture.prefix.with_extension("moved");
    fs::rename(&fixture.prefix, &original).unwrap();
    fs::create_dir(&fixture.prefix).unwrap();
    assert!(matches!(
        supervisor.tick(),
        Err(PortError::GenerationMismatch(_))
    ));
    assert_eq!(supervisor.child_id(), None);
}

#[test]
fn changed_pointer_and_unbound_catalog_fail_before_spawn() {
    let fixture = Fixture::new();
    let mut supervisor = Supervisor::open(&fixture.prefix, &fixture.catalog).unwrap();
    let pointer = fixture.prefix.join("current.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&pointer).unwrap()).unwrap();
    value["generation"] = json!(2);
    fs::write(&pointer, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(
        supervisor.tick(),
        Err(PortError::GenerationMismatch(_))
    ));
    assert_eq!(supervisor.child_id(), None);
    drop(supervisor);
    let wrong = fixture.catalog.parent().unwrap().join("not-a-catalog.db");
    assert!(Supervisor::open(&fixture.prefix, &wrong).is_err());
    assert!(!wrong.exists());
}

#[test]
fn malformed_shim_request_is_content_free_and_creates_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("absent");
    let result = Command::new(SHIM)
        .args(["--prefix", "private-input-marker", "--db"])
        .arg(&missing)
        .arg("unexpected")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty() && result.stderr.is_empty());
    assert!(!missing.exists());
}

#[test]
fn public_open_honors_an_earlier_active_runtime_scope_before_package_access() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    let root = base.join("private");
    let prefix = base.join("missing-package-metadata");
    fs::create_dir(&prefix).unwrap();
    let catalog = root.join("catalog.db");
    let control = SqliteControlStore::create(
        &root,
        &id("supervisor-runtime-scope"),
        DesiredUpdates::Stopped,
    )
    .unwrap();
    let before = control.status().unwrap();
    let before_root = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    let entered = std::cell::Cell::new(false);
    let short_end = Instant::now() + Duration::from_millis(100);
    let result = control.with_runtime_deadline(short_end, || {
        entered.set(true);
        std::thread::sleep(
            short_end.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        );
        Supervisor::open(&prefix, &catalog)
    });
    assert!(entered.get(), "runtime deadline scope did not enter");
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>(),
        before_root
    );
    assert!(fs::read_dir(&prefix).unwrap().next().is_none());
    assert!(!catalog.exists());
    let after = SqliteControlStore::open_current_read_only(&root)
        .unwrap()
        .status()
        .unwrap();
    assert_eq!(after, before);
    assert!(
        SqliteControlStore::open_current_read_only(&root)
            .unwrap()
            .background_status()
            .unwrap()
            .worker
            .boot_id
            .is_none()
    );
}

#[test]
fn standalone_version_reports_only_packaging_identity() {
    let output = Command::new(SHIM).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        concat!("asg-supervisor ", env!("CARGO_PKG_VERSION"), "\n").as_bytes()
    );
    assert!(output.stderr.is_empty());
    let invalid = Command::new(SHIM)
        .args(["--version", "extra"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty() && invalid.stderr.is_empty());
}

#[test]
fn installed_shim_derives_prefix_without_cwd_and_exits_clean_on_stop() {
    let fixture = Fixture::new();
    fixture.complete_package();
    let child = Command::new(&fixture.shim)
        .arg("--db")
        .arg(&fixture.catalog)
        .current_dir(fixture.catalog.parent().unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut process = OwnedProcess(child);
    let deadline = Instant::now() + seconds(20);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "installed supervisor exited before ready"
        );
        if fixture_retry(|| {
            let control = fixture.control();
            control
                .with_runtime_deadline(Instant::now() + seconds(5), || control.background_status())
                .map(|status| status.worker.boot_id.is_some())
        })
        .unwrap()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "installed supervisor did not spawn worker"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    fixture.desired(DesiredUpdates::Stopped);
    assert!(process.wait().success());
    use std::io::Read;
    let mut output = Vec::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    assert!(output.is_empty());
    drop(
        ExclusiveGuard::try_acquire(fixture.catalog.parent().unwrap(), LockKind::Background)
            .unwrap(),
    );
}

#[test]
fn installed_shim_rejects_corrupt_package_without_spawning() {
    let fixture = Fixture::new();
    fixture.complete_package();
    fs::write(
        fixture.prefix.join("README.md"),
        b"corrupt synthetic package member",
    )
    .unwrap();
    let output = Command::new(&fixture.shim)
        .arg("--db")
        .arg(&fixture.catalog)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(9));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(
        fixture
            .control()
            .background_status()
            .unwrap()
            .worker
            .boot_id
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn windows_shim_is_gui_subsystem() {
    let bytes = fs::read(SHIM).unwrap();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let subsystem = u16::from_le_bytes(bytes[pe + 24 + 68..pe + 24 + 70].try_into().unwrap());
    assert_eq!(
        subsystem, 2,
        "Windows GUI subsystem prevents console allocation"
    );
}
