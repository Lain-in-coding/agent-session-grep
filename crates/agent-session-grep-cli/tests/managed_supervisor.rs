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
        let temp = agent_session_grep_testkit::tempdir().unwrap();
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

#[derive(Debug, Clone, Copy)]
struct PauseSample {
    now: Instant,
    child: Option<u32>,
    exits: u8,
}

// Only the pause-retention scenario uses this seam; ordinary until is unchanged.
trait PauseProbe {
    fn sample(&self) -> PauseSample;
    fn tick(&mut self, end: Instant) -> Result<SupervisorState, PortError>;
    fn start_once(&mut self, end: Instant) -> Result<(), PortError>;
    fn sleep(&mut self, duration: Duration);
}

fn pause_end() -> Instant {
    SqliteControlStore::effective_runtime_deadline(Instant::now() + seconds(15))
}

fn pause_scope<T>(
    control: &SqliteControlStore,
    end: Instant,
    operation: impl FnOnce() -> Result<T, PortError>,
) -> Result<T, PortError> {
    let probe = end + seconds(30);
    let previous = SqliteControlStore::effective_runtime_deadline(probe);
    let effective = SqliteControlStore::effective_runtime_deadline(end);
    let result = control.with_runtime_deadline(end, || {
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            effective
        );
        operation()
    });
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe),
        previous
    );
    result
}

fn pause_start_once(control: &SqliteControlStore, end: Instant) -> Result<(), PortError> {
    pause_scope(control, end, || {
        let current = control.status()?;
        control
            .request_background_start(current.policy.control_seq)
            .map(|_| ())
    })
}

struct LivePause<'a> {
    supervisor: &'a mut Supervisor,
    control: &'a SqliteControlStore,
}

impl PauseProbe for LivePause<'_> {
    fn sample(&self) -> PauseSample {
        PauseSample {
            now: Instant::now(),
            child: self.supervisor.child_id(),
            exits: self.supervisor.policy().unexpected_exits(),
        }
    }

    fn tick(&mut self, end: Instant) -> Result<SupervisorState, PortError> {
        // The real tick still computes its own earlier 250 ms control end.
        pause_scope(self.control, end, || self.supervisor.tick())
    }

    fn start_once(&mut self, end: Instant) -> Result<(), PortError> {
        pause_start_once(self.control, end)
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn check_pause_sample(sample: PauseSample, end: Instant, pid: u32, phase: &str, calls: usize) {
    assert!(
        sample.now < end,
        "{phase}: pause end expired after {calls} calls: {sample:?}"
    );
    assert_eq!(
        sample.child,
        Some(pid),
        "{phase}: child changed: {sample:?}"
    );
    assert_eq!(sample.exits, 0, "{phase}: unexpected exit: {sample:?}");
}

fn paused_before(probe: &mut impl PauseProbe, end: Instant, pid: u32, phase: &str) -> usize {
    let mut calls = 0;
    loop {
        check_pause_sample(probe.sample(), end, pid, phase, calls);
        let result = probe.tick(end);
        calls += 1;
        let after = probe.sample();
        check_pause_sample(after, end, pid, phase, calls);
        match result {
            Ok(SupervisorState::Paused) => return calls,
            Ok(SupervisorState::Busy) => {
                probe.sleep(Duration::from_millis(50).min(end - after.now));
            }
            other => panic!("{phase}: non-pause result after {calls} calls: {other:?}; {after:?}"),
        }
    }
}

fn pause_start_before(probe: &mut impl PauseProbe, end: Instant, pid: u32) {
    let mut calls = 0;
    loop {
        check_pause_sample(probe.sample(), end, pid, "start request", calls);
        let result = probe.start_once(end);
        calls += 1;
        let after = probe.sample();
        check_pause_sample(after, end, pid, "start request", calls);
        match result {
            Ok(()) => return,
            Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                probe.sleep(Duration::from_millis(10).min(end - after.now));
            }
            error => panic!("start request: nonretryable result after {calls} calls: {error:?}"),
        }
    }
}

fn pause_retention_before(probe: &mut impl PauseProbe, end: Instant, pid: u32) {
    paused_before(probe, end, pid, "initial pause");
    let before = probe.sample();
    check_pause_sample(before, end, pid, "hold", 0);
    assert!(
        end - before.now >= seconds(2),
        "hold: insufficient remaining time"
    );
    probe.sleep(seconds(2));
    check_pause_sample(probe.sample(), end, pid, "hold", 0);
    paused_before(probe, end, pid, "after hold");
    pause_start_before(probe, end, pid);
    paused_before(probe, end, pid, "after start request");
}

#[derive(Debug)]
struct PauseStep {
    result: Result<SupervisorState, PortError>,
    elapsed: Duration,
    child: Option<u32>,
    exits: u8,
}

impl PauseStep {
    fn state(state: SupervisorState) -> Self {
        Self {
            result: Ok(state),
            elapsed: Duration::ZERO,
            child: Some(7),
            exits: 0,
        }
    }
}

struct ScriptedPause {
    sample: PauseSample,
    ticks: std::collections::VecDeque<PauseStep>,
    starts: std::collections::VecDeque<(Result<(), PortError>, Duration)>,
    tick_ends: Vec<Instant>,
    start_ends: Vec<Instant>,
    sleeps: Vec<Duration>,
}

impl ScriptedPause {
    fn new(now: Instant, ticks: impl IntoIterator<Item = PauseStep>) -> Self {
        Self {
            sample: PauseSample {
                now,
                child: Some(7),
                exits: 0,
            },
            ticks: ticks.into_iter().collect(),
            starts: Default::default(),
            tick_ends: Vec::new(),
            start_ends: Vec::new(),
            sleeps: Vec::new(),
        }
    }
}

impl PauseProbe for ScriptedPause {
    fn sample(&self) -> PauseSample {
        self.sample
    }

    fn tick(&mut self, end: Instant) -> Result<SupervisorState, PortError> {
        self.tick_ends.push(end);
        let step = self.ticks.pop_front().expect("unexpected extra pause poll");
        self.sample.now += step.elapsed;
        self.sample.child = step.child;
        self.sample.exits = step.exits;
        step.result
    }

    fn start_once(&mut self, end: Instant) -> Result<(), PortError> {
        self.start_ends.push(end);
        let (result, elapsed) = self.starts.pop_front().expect("unexpected extra start CAS");
        self.sample.now += elapsed;
        result
    }

    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
        self.sample.now += duration;
    }
}

#[test]
fn pause_poll_retries_only_busy_and_requires_a_real_paused_observation() {
    let now = Instant::now();
    let end = now + seconds(15);
    let mut probe = ScriptedPause::new(
        now,
        [
            PauseStep::state(SupervisorState::Busy),
            PauseStep::state(SupervisorState::Paused),
        ],
    );
    assert_eq!(paused_before(&mut probe, end, 7, "synthetic"), 2);
    assert_eq!(probe.tick_ends, [end, end]);
    assert_eq!(probe.sleeps, [Duration::from_millis(50)]);
    assert!(probe.ticks.is_empty());

    for step in [
        PauseStep::state(SupervisorState::Running),
        PauseStep {
            result: Err(PortError::WriterBusy("synthetic tick error".into())),
            ..PauseStep::state(SupervisorState::Paused)
        },
        PauseStep {
            result: Err(PortError::SchemaIncompatible("synthetic schema".into())),
            ..PauseStep::state(SupervisorState::Paused)
        },
        PauseStep {
            child: Some(8),
            ..PauseStep::state(SupervisorState::Paused)
        },
        PauseStep {
            child: None,
            ..PauseStep::state(SupervisorState::Paused)
        },
        PauseStep {
            exits: 1,
            ..PauseStep::state(SupervisorState::Paused)
        },
    ] {
        let mut probe = ScriptedPause::new(now, [step, PauseStep::state(SupervisorState::Paused)]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            paused_before(&mut probe, end, 7, "synthetic")
        }));
        assert!(result.is_err(), "non-Busy must not wait for a later Paused");
        assert_eq!(probe.tick_ends, [end]);
        assert!(probe.sleeps.is_empty());
        assert_eq!(probe.ticks.len(), 1);
    }
}

#[test]
fn pause_poll_checks_entry_and_result_time_and_caps_busy_waits() {
    let now = Instant::now();
    for (end, child, exits) in [
        (now, Some(7), 0),
        (now + seconds(1), Some(8), 0),
        (now + seconds(1), Some(7), 1),
    ] {
        let mut probe = ScriptedPause::new(now, [PauseStep::state(SupervisorState::Paused)]);
        probe.sample.child = child;
        probe.sample.exits = exits;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                paused_before(&mut probe, end, 7, "entry")
            }))
            .is_err()
        );
        assert!(probe.tick_ends.is_empty());
    }
    let end = now + Duration::from_millis(75);
    let mut busy = ScriptedPause::new(
        now,
        [
            PauseStep::state(SupervisorState::Busy),
            PauseStep::state(SupervisorState::Busy),
        ],
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            paused_before(&mut busy, end, 7, "persistent busy")
        }))
        .is_err()
    );
    assert_eq!(busy.tick_ends, [end, end]);
    assert_eq!(
        busy.sleeps,
        [Duration::from_millis(50), Duration::from_millis(25)]
    );
    assert_eq!(busy.sample.now, end);

    for elapsed in [Duration::from_millis(75), Duration::from_millis(76)] {
        let mut late = ScriptedPause::new(
            now,
            [PauseStep {
                elapsed,
                ..PauseStep::state(SupervisorState::Paused)
            }],
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                paused_before(&mut late, end, 7, "late paused")
            }))
            .is_err()
        );
        assert_eq!(late.tick_ends, [end]);
        assert!(late.sleeps.is_empty());
    }
}

#[test]
fn pause_hold_and_start_share_the_initial_end_without_replaying_success() {
    let now = Instant::now();
    let end = now + seconds(15);
    let mut probe = ScriptedPause::new(
        now,
        [
            PauseStep::state(SupervisorState::Paused),
            PauseStep::state(SupervisorState::Busy),
            PauseStep::state(SupervisorState::Paused),
            PauseStep::state(SupervisorState::Paused),
        ],
    );
    probe.starts.extend([
        (
            Err(PortError::WriterBusy("synthetic contention".into())),
            Duration::ZERO,
        ),
        (
            Err(PortError::GenerationMismatch("synthetic CAS".into())),
            Duration::ZERO,
        ),
        (Ok(()), Duration::from_millis(10)),
    ]);
    pause_retention_before(&mut probe, end, 7);
    assert_eq!(probe.tick_ends, [end; 4]);
    assert_eq!(probe.start_ends, [end; 3]);
    assert_eq!(
        probe.sleeps,
        [
            seconds(2),
            Duration::from_millis(50),
            Duration::from_millis(10),
            Duration::from_millis(10)
        ]
    );
    assert_eq!(probe.sample.now, now + Duration::from_millis(2080));
    assert!(probe.starts.is_empty() && probe.ticks.is_empty());

    let mut short = ScriptedPause::new(now, [PauseStep::state(SupervisorState::Paused)]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pause_retention_before(&mut short, now + Duration::from_millis(1999), 7)
        }))
        .is_err()
    );
    assert!(short.sleeps.is_empty() && short.start_ends.is_empty());

    let mut exhausted = ScriptedPause::new(
        now,
        [
            PauseStep::state(SupervisorState::Paused),
            PauseStep::state(SupervisorState::Paused),
            PauseStep::state(SupervisorState::Paused),
        ],
    );
    exhausted
        .starts
        .push_back((Ok(()), Duration::from_millis(1)));
    let end = now + Duration::from_millis(2001);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pause_retention_before(&mut exhausted, end, 7)
        }))
        .is_err()
    );
    assert_eq!(exhausted.tick_ends, [end; 2]);
    assert_eq!(exhausted.start_ends, [end]);
    assert_eq!(exhausted.sample.now, end);
}

#[test]
fn pause_start_refuses_expiry_and_nonretryable_errors() {
    let now = Instant::now();
    for (end, first, expected_calls) in [
        (now, Ok(()), 0),
        (
            now + seconds(1),
            Err(PortError::Backend("synthetic".into())),
            1,
        ),
    ] {
        let mut probe = ScriptedPause::new(now, []);
        probe
            .starts
            .extend([(first, Duration::ZERO), (Ok(()), Duration::ZERO)]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pause_start_before(&mut probe, end, 7)
            }))
            .is_err()
        );
        assert_eq!(probe.start_ends.len(), expected_calls);
        assert!(probe.sleeps.is_empty());
    }
    let mut busy = ScriptedPause::new(now, []);
    busy.starts.push_back((
        Err(PortError::WriterBusy("synthetic".into())),
        Duration::ZERO,
    ));
    let end = now + Duration::from_millis(7);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pause_start_before(&mut busy, end, 7)
        }))
        .is_err()
    );
    assert_eq!(busy.start_ends, [end]);
    assert_eq!(busy.sleeps, [Duration::from_millis(7)]);
}

#[test]
fn pause_scope_preserves_the_earlier_end_and_real_start_effect() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let control = SqliteControlStore::create(
        &temp.path().join("private"),
        &id("synthetic-pause-scope"),
        DesiredUpdates::Paused,
    )
    .unwrap();
    let probe = Instant::now() + seconds(60);
    let previous = SqliteControlStore::effective_runtime_deadline(probe);
    let outer = Instant::now() + seconds(10);
    control
        .with_runtime_deadline(outer, || {
            let end = pause_end();
            assert_eq!(end, outer);
            pause_scope(&control, end, || {
                assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), end);
                Ok(())
            })?;
            let before = control.status()?;
            pause_start_once(&control, end)?;
            let after = control.status()?;
            assert_eq!(
                after.restart_request_seq.get(),
                before.restart_request_seq.get() + 1
            );
            assert_eq!(
                after.policy.control_seq.get(),
                before.policy.control_seq.get() + 1
            );
            assert_eq!(after.desired_updates, DesiredUpdates::Paused);
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe),
        previous
    );
    let end = pause_end();
    assert!(matches!(
        pause_scope(&control, end, || {
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), end);
            Err::<(), _>(PortError::Backend("synthetic".into()))
        }),
        Err(PortError::Backend(_))
    ));
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe),
        previous
    );
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
    let end = pause_end();
    let control = SqliteControlStore::open_current_writable_with_deadline(
        fixture.catalog.parent().unwrap(),
        end,
    )
    .unwrap();
    pause_retention_before(
        &mut LivePause {
            supervisor: &mut harness.supervisor,
            control: &control,
        },
        end,
        pid,
    );
    drop(control);
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
    let temporary = agent_session_grep_testkit::tempdir().unwrap();
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
    let temporary = agent_session_grep_testkit::tempdir().unwrap();
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
