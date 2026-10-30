//! Selected-history worker. Only an explicit control action starts this process.
//! The OS background lock owns its entire lifetime; catalog leases cover one
//! publication at a time. Public reports contain no source locators or content.
use crate::{
    CliError, ProtocolError, app_clock_ms,
    managed_source_discovery::{self, SourceDescriptor, SourceKind},
};
use agent_session_grep_adapters_sqlite::{
    PARSER_SEMANTIC_VERSION, SourceBatch, SqliteControlStore, capture_with_deadline,
    control::LockedWorkerAuthority,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_store::{BackgroundSource, ManagedStore},
    open_snapshot_source_with_deadline, verify_snapshot_with_deadline,
};
use agent_session_grep_application::StagedBatch;
use agent_session_grep_domain::{SessionIdentityNamespace, StableId};
use agent_session_grep_ports::{
    PortError, PortResult, ReadOnlySource, SearchProvider, SourceSnapshot,
    control::*,
    managed::{
        ObservationState, Publication, RevisionId, SelectionProof, SourceBinding, SourceId,
        SourceObservation,
    },
    source_context::{
        DependencyResolution, LifecycleState, MetadataDependencyProof, NativeSessionId,
        SourceAuthorityKey, SourceAuthorityTransition, SourceDependency, SourcePublicationContext,
        StateDigest, UnresolvedDependency,
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

const CHILD: &str = "__managed-background";
const CADENCE: Duration = Duration::from_secs(1);
const CONFIRMATION_MS: i64 = 5_000;
/// One short control step: a status read, a heartbeat or a quiesce check.
/// Each SQLite lock wait inside any control call keeps its own 250ms allowance.
const CONTROL_BUDGET: Duration = Duration::from_millis(250);
// The worker heartbeats once per cadence (one second). A held lock corroborates
// a live worker only within a bounded multiple of that cadence, so a lock left
// by an exited worker during update/uninstall drain cannot read as running.
const LIVE_WORKER_WINDOW_MS: i64 = 30_000;
const SOURCE_OBSERVATION_BUDGET: Duration = Duration::from_secs(30);
const MAX_DISCOVERY_PATHS: usize = 65_536;
const SOURCE_SLICE_ATTEMPTS: usize = 3;
const SOURCE_HINT_BATCH: usize = 64;

/// The monotonic confirmation clock and failures whose invalidation could not
/// be recorded in control. Ordinary cycle aborts do not invalidate other
/// sources. These boot-local marks retain only the affected source, metadata
/// dependency or exact discovery region; a new epoch already invalidates every
/// old confirmation. Capacity exhaustion ends this worker before more source
/// work, so an unrecorded failure can never be silently forgotten.
struct ObservationClock {
    started: Instant,
    failures: RefCell<LostFailures>,
}

#[derive(Default)]
struct LostFailures {
    epoch: Option<PolicyEpoch>,
    sources: BTreeMap<SourceId, CycleSeq>,
    metadata: BTreeMap<SourceId, CycleSeq>,
    roots: Vec<LostRootFailure>,
    exhausted: bool,
}

struct LostRootFailure {
    region: ScopeRegion,
    identity: ControlId,
    all: Option<CycleSeq>,
    deletion_only: Option<CycleSeq>,
}

#[derive(Clone, Copy)]
enum RootConfirmations {
    All,
    DeletionOnly,
}

fn root_failure_confirmations(complete: bool) -> RootConfirmations {
    if complete {
        RootConfirmations::DeletionOnly
    } else {
        RootConfirmations::All
    }
}

enum FailureScope {
    Source(SourceId),
    Metadata(SourceId),
    Root {
        selection: Selection,
        confirmations: RootConfirmations,
    },
}

impl ObservationClock {
    fn new(started: Instant) -> Self {
        Self {
            started,
            failures: RefCell::new(LostFailures::default()),
        }
    }

    fn check_capacity(&self) -> PortResult<()> {
        if self.failures.borrow().exhausted {
            return Err(PortError::Backend(
                "background failure invalidation capacity exceeded".into(),
            ));
        }
        Ok(())
    }

    fn record_failure(
        &self,
        cycle: &ObservationCycle,
        scope: FailureScope,
        acknowledge: impl FnOnce() -> PortResult<()>,
    ) -> PortResult<()> {
        let result = acknowledge();
        if result.is_err() {
            self.remember_failure(cycle, scope);
        }
        result
    }

    fn remember_failure(&self, cycle: &ObservationCycle, scope: FailureScope) {
        let mut failures = self.failures.borrow_mut();
        if failures.epoch != Some(cycle.policy_epoch) {
            *failures = LostFailures {
                epoch: Some(cycle.policy_epoch),
                ..LostFailures::default()
            };
        }
        let seq = cycle.token.cycle_seq;
        match scope {
            FailureScope::Source(id) => {
                failures
                    .sources
                    .entry(id)
                    .and_modify(|old| *old = (*old).max(seq))
                    .or_insert(seq);
            }
            FailureScope::Metadata(id) => {
                failures
                    .metadata
                    .entry(id)
                    .and_modify(|old| *old = (*old).max(seq))
                    .or_insert(seq);
            }
            FailureScope::Root {
                selection,
                confirmations,
            } => {
                if let Some(root) = selection.root_identity {
                    let watermarks =
                        if let Some(index) = failures.roots.iter().position(|lost| {
                            lost.region == selection.region && lost.identity == root
                        }) {
                            &mut failures.roots[index]
                        } else {
                            failures.roots.push(LostRootFailure {
                                region: selection.region,
                                identity: root,
                                all: None,
                                deletion_only: None,
                            });
                            failures.roots.last_mut().expect("inserted root failure")
                        };
                    // Complete discovery invalidates only absence proofs;
                    // keep that watermark separate from observation gaps
                    // that invalidate both deletion and rewrite proofs.
                    let latest = match confirmations {
                        RootConfirmations::All => &mut watermarks.all,
                        RootConfirmations::DeletionOnly => &mut watermarks.deletion_only,
                    };
                    *latest = (*latest).max(Some(seq));
                } else {
                    failures.exhausted = true;
                }
            }
        }
        failures.exhausted |=
            failures.sources.len() + failures.metadata.len() + failures.roots.len()
                > MAX_DISCOVERY_PATHS;
    }

    fn lost_after(
        &self,
        source: &ConfirmationSource<'_>,
        selection: &Selection,
        kind: &ConfirmationKind,
        epoch: PolicyEpoch,
    ) -> Option<CycleSeq> {
        let failures = self.failures.borrow();
        if failures.epoch != Some(epoch) {
            return None;
        }
        let mut latest = failures.sources.get(source.id).copied();
        for context in source.contexts {
            for dependency in &context.dependencies {
                if let DependencyResolution::Resolved(proof) = &dependency.resolution {
                    latest = latest.max(failures.metadata.get(&proof.binding.source_id).copied());
                }
            }
        }
        for lost in &failures.roots {
            if selection.root_identity.as_ref() == Some(&lost.identity)
                && lost
                    .region
                    .matches(selection.region.provider, source.locator)
            {
                latest = latest.max(lost.all);
                if matches!(kind, ConfirmationKind::Deletion) {
                    latest = latest.max(lost.deletion_only);
                }
            }
        }
        latest
    }
}

fn record_root_failure(
    clock: &ObservationClock,
    cycle: &ObservationCycle,
    selection: Selection,
    confirmations: RootConfirmations,
    should_acknowledge: impl FnOnce() -> PortResult<bool>,
    acknowledge: impl FnOnce() -> PortResult<()>,
) -> PortResult<()> {
    clock.record_failure(
        cycle,
        FailureScope::Root {
            selection,
            confirmations,
        },
        || {
            if should_acknowledge()? {
                acknowledge()
            } else {
                Ok(())
            }
        },
    )
}

struct ConfirmationSource<'a> {
    id: &'a SourceId,
    locator: &'a CanonicalLocator,
    contexts: &'a [&'a SourcePublicationContext],
}

#[derive(Debug, Serialize)]
pub(crate) struct StartReport {
    pub started: bool,
    pub already_running: bool,
    pub ready: bool,
    pub reason: Option<&'static str>,
    pub latest_satisfied: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct StatusReport {
    pub running: bool,
    pub desired_updates: &'static str,
    pub effective_state: &'static str,
    pub latest_satisfied: bool,
    pub startup: &'static str,
}

fn cli(error: PortError) -> CliError {
    ProtocolError::from_private_port_error(error).into()
}
fn unavailable() -> PortError {
    PortError::SourceIo("selected history is unavailable".into())
}
fn changed() -> PortError {
    PortError::SnapshotChanged("managed observation changed".into())
}
fn invalid() -> PortError {
    PortError::InvalidRequest("managed background request is invalid".into())
}
fn fresh_id(prefix: &str) -> PortResult<ControlId> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
    ControlId::parse(&format!("{prefix}_{}", hex(&bytes)))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn root(db: &Path) -> PortResult<&Path> {
    if !db.is_absolute() {
        return Err(invalid());
    }
    db.parent().ok_or_else(invalid)
}

/// Used before ordinary CLI argument decoding. Child stdout/stderr are always
/// silent, including malformed arguments and failures; control is the status API.
pub(crate) fn intercept(args: &[OsString]) -> Option<i32> {
    if args.first().is_none_or(|a| a != CHILD) {
        return None;
    }
    Some(if args.len() != 3 || args[1] != "--db" {
        2
    } else {
        match run_child(Path::new(&args[2])) {
            Ok(()) => 0,
            Err(error) => ProtocolError::from_private_port_error(error)
                .code
                .exit_code(),
        }
    })
}

/// Explicit launch only. Never changes desired state or installs autostart.
/// A timeout is not success and does not kill another worker by its stored PID.
pub(crate) fn start(db: &Path, budget: Duration) -> Result<StartReport, CliError> {
    let private = root(db).map_err(cli)?;
    let control = SqliteControlStore::open_current_read_only(private).map_err(cli)?;
    let current = control.status().map_err(cli)?;
    if current.desired_updates != DesiredUpdates::Running {
        return Ok(StartReport {
            started: false,
            already_running: false,
            ready: false,
            reason: Some(if current.desired_updates == DesiredUpdates::Paused {
                "paused"
            } else {
                "stopped"
            }),
            latest_satisfied: false,
        });
    }
    if current.policy.maintenance.state != MaintenanceState::Idle {
        return Ok(StartReport {
            started: false,
            already_running: false,
            ready: false,
            reason: Some("upgrading"),
            latest_satisfied: false,
        });
    }
    let catalog = ManagedStore::open(db, &control).map_err(cli)?;
    let incarnation = catalog.incarnation().clone();
    drop(catalog);
    match ExclusiveGuard::try_acquire(private, LockKind::Background) {
        Ok(guard) => drop(guard),
        Err(PortError::WriterBusy(_)) => {
            return Ok(StartReport {
                started: false,
                already_running: true,
                ready: false,
                reason: Some("worker_owns_lock"),
                latest_satisfied: false,
            });
        }
        Err(error) => return Err(cli(error)),
    }
    let old_boot = control.background_status().map_err(cli)?.worker.boot_id;
    let deadline = Instant::now() + budget.min(Duration::from_secs(5));
    let executable = std::env::current_exe().map_err(|_| cli(unavailable()))?;
    let mut child = DetachedChild::spawn(&executable, db).map_err(cli)?;
    loop {
        if child.exited().map_err(cli)? {
            return Ok(StartReport {
                started: true,
                already_running: false,
                ready: false,
                reason: Some("worker_exited"),
                latest_satisfied: false,
            });
        }
        // A poll refused by contention or by the caller's runtime end is "not
        // ready yet"; the loop's own deadline still reports startup_timeout.
        let ready = control.background_status().and_then(|status| {
            let worker = status.worker;
            Ok(worker.boot_id.is_some()
                && worker.boot_id != old_boot
                && worker.pid_hint == Some(child.id())
                && control.status()?.catalog_incarnation.as_ref() == Some(&incarnation))
        });
        let ready = match ready {
            Ok(ready) => ready,
            Err(PortError::WriterBusy(_)) => false,
            Err(error) => return Err(cli(error)),
        };
        if ready {
            match ExclusiveGuard::try_acquire(private, LockKind::Background) {
                Err(PortError::WriterBusy(_)) => {
                    return Ok(StartReport {
                        started: true,
                        already_running: false,
                        ready: true,
                        reason: None,
                        latest_satisfied: false,
                    });
                }
                Ok(guard) => drop(guard),
                Err(error) => return Err(cli(error)),
            }
        }
        if Instant::now() >= deadline {
            return Ok(StartReport {
                started: true,
                already_running: false,
                ready: false,
                reason: Some("startup_timeout"),
                latest_satisfied: false,
            });
        }
        std::thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(unix)]
pub(crate) struct DetachedChild(std::process::Child);
#[cfg(unix)]
impl DetachedChild {
    fn spawn(executable: &Path, db: &Path) -> PortResult<Self> {
        Self::spawn_for(executable, db, CHILD)
    }
    pub(crate) fn spawn_for(executable: &Path, db: &Path, command: &str) -> PortResult<Self> {
        use std::{
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        Command::new(executable)
            .arg(command)
            .arg("--db")
            .arg(db)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map(Self)
            .map_err(|_| unavailable())
    }
    pub(crate) fn id(&self) -> u32 {
        self.0.id()
    }
    pub(crate) fn try_wait(&mut self) -> PortResult<Option<i32>> {
        use std::os::unix::process::ExitStatusExt;
        self.0
            .try_wait()
            .map(|status| {
                status.map(|status| {
                    status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
                })
            })
            .map_err(|_| unavailable())
    }
    fn exited(&mut self) -> PortResult<bool> {
        self.try_wait().map(|status| status.is_some())
    }
}

#[cfg(windows)]
pub(crate) struct DetachedChild {
    handle: std::os::windows::io::OwnedHandle,
    pid: u32,
}
#[cfg(windows)]
impl DetachedChild {
    fn spawn(executable: &Path, db: &Path) -> PortResult<Self> {
        Self::spawn_for(executable, db, CHILD)
    }
    pub(crate) fn spawn_for(executable: &Path, db: &Path, command: &str) -> PortResult<Self> {
        use std::{
            os::windows::{
                ffi::OsStrExt,
                io::{FromRawHandle, OwnedHandle},
            },
            ptr::null,
        };
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
        };
        let executable_wide: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        if executable_wide[..executable_wide.len() - 1].contains(&0) {
            return Err(invalid());
        }
        let mut line = Vec::new();
        for argument in [
            executable.as_os_str(),
            std::ffi::OsStr::new(command),
            std::ffi::OsStr::new("--db"),
            db.as_os_str(),
        ] {
            if !line.is_empty() {
                line.push(b' ' as u16);
            }
            quote_windows(argument, &mut line)?;
        }
        line.push(0);
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: all wide strings are terminated, command line is mutable,
        // pointers live across the call. Crucially bInheritHandles=FALSE: Rust
        // Command's null stdio still enables general handle inheritance on
        // Windows, retaining a caller's extra stdout/stderr pipe write handles.
        // This console-free worker requires no inherited handles whatsoever.
        let created = unsafe {
            CreateProcessW(
                executable_wide.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_NO_WINDOW,
                null(),
                null(),
                &startup,
                &mut process,
            )
        };
        if created == 0 {
            return Err(unavailable());
        }
        // SAFETY: success returned independently owned process/thread handles.
        let handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
        drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
        Ok(Self {
            handle,
            pid: process.dwProcessId,
        })
    }
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }
    pub(crate) fn try_wait(&mut self) -> PortResult<Option<i32>> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{GetExitCodeProcess, WaitForSingleObject},
        };
        // SAFETY: handle remains live and the zero timeout never blocks.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => {
                let mut exit = 0;
                // SAFETY: a live process handle and writable output; waiting
                // above proved termination, so STILL_ACTIVE is not guessed.
                if unsafe { GetExitCodeProcess(self.handle.as_raw_handle(), &mut exit) } == 0 {
                    return Err(unavailable());
                }
                Ok(Some(exit as i32))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(unavailable()),
        }
    }
    fn exited(&mut self) -> PortResult<bool> {
        self.try_wait().map(|status| status.is_some())
    }
}

#[cfg(windows)]
fn quote_windows(argument: &std::ffi::OsStr, line: &mut Vec<u16>) -> PortResult<()> {
    use std::os::windows::ffi::OsStrExt;
    line.push(b'"' as u16);
    let mut slashes = 0;
    for ch in argument.encode_wide() {
        if ch == 0 {
            return Err(invalid());
        }
        if ch == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        line.extend(std::iter::repeat_n(
            b'\\' as u16,
            slashes * if ch == b'"' as u16 { 2 } else { 1 },
        ));
        slashes = 0;
        if ch == b'"' as u16 {
            line.push(b'\\' as u16);
        }
        line.push(ch);
    }
    line.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    line.push(b'"' as u16);
    Ok(())
}

/// Content-free liveness. The control heartbeat alone never establishes
/// liveness or freshness. No catalog is opened, and no worker is started by
/// status. A held background lock is necessary but not sufficient: update and
/// uninstall drain intentionally keep the lock after the worker exits, so a
/// dead worker record must never report running. The lock only counts when
/// the registered worker state is not Offline and its heartbeat is fresh.
pub(crate) fn status(db: &Path) -> Result<StatusReport, CliError> {
    observe(db).map_err(cli)
}

/// Typed form of [`status`]. A caller inside a control runtime scope can retry
/// a Busy observation within its own original end.
pub(crate) fn observe(db: &Path) -> PortResult<StatusReport> {
    let private = root(db)?;
    let control = SqliteControlStore::open_current_read_only(private)?;
    let current = control.status()?;
    let worker = control.background_status()?.worker;
    let lock_busy = if !private
        .join("background.lock")
        .try_exists()
        .map_err(|_| unavailable())?
    {
        false
    } else {
        match ExclusiveGuard::try_acquire(private, LockKind::Background) {
            Ok(guard) => {
                drop(guard);
                false
            }
            Err(PortError::WriterBusy(_)) => true,
            Err(error) => return Err(error),
        }
    };
    let running = lock_busy
        && worker.state != UpdateState::Offline
        && worker
            .heartbeat_at_ms
            .is_some_and(|at| app_clock_ms() - at <= LIVE_WORKER_WINDOW_MS);
    Ok(StatusReport {
        running,
        desired_updates: match current.desired_updates {
            DesiredUpdates::Running => "running",
            DesiredUpdates::Paused => "paused",
            DesiredUpdates::Stopped => "stopped",
        },
        effective_state: if !running {
            "offline"
        } else {
            state_name(worker.state)
        },
        latest_satisfied: false,
        startup: "explicit_process_only",
    })
}

fn state_name(state: UpdateState) -> &'static str {
    match state {
        UpdateState::Running => "running",
        UpdateState::Idle => "idle",
        UpdateState::Paused => "paused",
        UpdateState::Stopped => "stopped",
        UpdateState::Offline => "offline",
        UpdateState::Busy => "busy",
        UpdateState::Failed => "failed",
        UpdateState::Deferred => "deferred",
        UpdateState::Upgrading => "upgrading",
    }
}

fn control_change<T>(
    control: &SqliteControlStore,
    operation: impl FnMut(ControlSeq) -> PortResult<T>,
) -> PortResult<T> {
    control_change_before(control, Instant::now() + CONTROL_BUDGET, operation)
}

fn control_change_before<T>(
    control: &SqliteControlStore,
    deadline: Instant,
    mut operation: impl FnMut(ControlSeq) -> PortResult<T>,
) -> PortResult<T> {
    control.with_runtime_deadline(deadline, || {
        loop {
            observation_deadline(deadline)?;
            let result = control
                .status()
                .and_then(|s| operation(s.policy.control_seq));
            match result {
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                other => return other,
            }
        }
    })
}

pub(crate) fn run_child(db: &Path) -> PortResult<()> {
    let private = root(db)?;
    let guard = ExclusiveGuard::try_acquire(private, LockKind::Background)?;
    // Startup has one existing five-second admission budget, distinct from a
    // steady-state 250ms control tick. Transient startup contention must not
    // leave a registered but exited worker after its PID was acknowledged.
    let startup_end = Instant::now() + Duration::from_secs(5);
    let witness = SqliteControlStore::open_current_read_only_with_deadline(private, startup_end)?;
    let installation = witness
        .with_runtime_deadline(startup_end, || witness.status())?
        .policy
        .installation_id;
    drop(witness);
    let control = SqliteControlStore::open_existing_writable_with_deadline(
        private,
        &installation,
        startup_end,
    )?;
    let worker_boot = fresh_id("worker")?;
    let authority =
        control.with_runtime_deadline(startup_end, || control.bind_worker(&guard, worker_boot))?;
    control_change_before(&control, startup_end, |seq| {
        control.register_worker(seq, &authority, std::process::id(), app_clock_ms())
    })?;
    if quiesce_before(&control, &authority, startup_end)? {
        return Ok(());
    }
    let initialized = control_change_before(&control, startup_end, |_| {
        // Recheck before EVERY retried catalog admission: a fence arriving
        // after PID registration is intentional shutdown, not catalog Busy
        // that should consume the entire startup deadline.
        let current = control.status()?;
        if current.desired_updates == DesiredUpdates::Stopped
            || current.policy.maintenance.state != MaintenanceState::Idle
        {
            control.stop_worker(current.policy.control_seq, &authority, app_clock_ms())?;
            return Ok(true);
        }
        let catalog = ManagedStore::open(db, &control)?;
        catalog.reconcile_progress(&control, &authority)?;
        Ok(false)
    })?;
    if initialized {
        return Ok(());
    }
    let boot = ObservationClock::new(Instant::now());
    let mut rounds = 0_u64;
    let mut history_pending = true;
    let mut pending_cycle = None;
    let mut schedule = SourceScheduleState::default();
    loop {
        boot.check_capacity()?;
        let tick = Instant::now();
        // A contended short control operation is a deferred cadence, not an
        // unexpected process exit. The next cadence is a new bounded attempt;
        // schema/identity failures still terminate and remain visible.
        match quiesce_if_requested(&control, &authority) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(PortError::WriterBusy(_)) => {
                std::thread::sleep(CADENCE.saturating_sub(tick.elapsed()));
                continue;
            }
            Err(error) => return Err(error),
        }
        let current =
            match control.with_runtime_deadline(tick + CONTROL_BUDGET, || control.status()) {
                Ok(current) => current,
                Err(PortError::WriterBusy(_)) => {
                    std::thread::sleep(CADENCE.saturating_sub(tick.elapsed()));
                    continue;
                }
                Err(error) => return Err(error),
            };
        let (state, error) = if current.desired_updates == DesiredUpdates::Paused {
            (UpdateState::Paused, Some(BackgroundFailure::Paused))
        } else {
            // One cycle runs about five sequential control changes before
            // observation (heartbeat, prior finish, policy, queue, start),
            // each with a status read and a durable commit. They share this
            // tick's cadence, as history retention below does. A single
            // CONTROL_BUDGET for all of them starved every cycle on a slow or
            // contended disk although no lock was ever held.
            match run_cycle(
                db,
                &control,
                &authority,
                &boot,
                rounds,
                tick + CADENCE,
                &mut pending_cycle,
                &mut schedule,
            ) {
                Ok(complete) => (
                    if complete {
                        UpdateState::Idle
                    } else {
                        UpdateState::Deferred
                    },
                    if complete {
                        None
                    } else {
                        Some(BackgroundFailure::Deferred)
                    },
                ),
                Err(error) => (failure_state(&error), Some(failure(&error))),
            }
        };
        // A concurrent pause/stop owns the desired state. Derive the heartbeat
        // again on every CAS retry so stale activity cannot overwrite it.
        let stopped = control_change(&control, |seq| {
            let now = control.status()?;
            if now.desired_updates == DesiredUpdates::Stopped
                || now.policy.maintenance.state != MaintenanceState::Idle
            {
                control.stop_worker(seq, &authority, app_clock_ms())?;
                return Ok(true);
            }
            let (state, error) = match now.desired_updates {
                DesiredUpdates::Paused => (UpdateState::Paused, Some(BackgroundFailure::Paused)),
                _ => (state, error),
            };
            control.heartbeat_worker(seq, &authority, state, error, app_clock_ms())?;
            Ok(false)
        });
        match stopped {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(PortError::WriterBusy(_)) => {
                std::thread::sleep(CADENCE.saturating_sub(tick.elapsed()));
                continue;
            }
            Err(error) => return Err(error),
        }
        if current.desired_updates == DesiredUpdates::Running
            && (history_pending || rounds.is_multiple_of(16))
        {
            // Disposable history maintenance shares the current cadence budget.
            // Live reader contention leaves the entire inventory untouched; it
            // does not change the completed source cycle's freshness result.
            history_pending = match retain_runtime_history(db, &control, &authority, tick + CADENCE)
            {
                Ok(pending) => pending,
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => true,
                Err(error) => {
                    let reason = failure(&error);
                    match control_change(&control, |seq| {
                        control.heartbeat_worker(
                            seq,
                            &authority,
                            failure_state(&error),
                            Some(reason),
                            app_clock_ms(),
                        )
                    }) {
                        Ok(_) | Err(PortError::WriterBusy(_)) => {}
                        Err(error) => return Err(error),
                    }
                    true
                }
            };
        }
        rounds = rounds.wrapping_add(1);
        std::thread::sleep(CADENCE.saturating_sub(tick.elapsed()));
    }
}

fn retain_runtime_history(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    deadline: Instant,
) -> PortResult<bool> {
    if Instant::now() >= deadline {
        return Err(PortError::WriterBusy(
            "history cadence budget exhausted".into(),
        ));
    }
    let writer = ManagedStore::open_for_write(db, control)?;
    loop {
        let report = writer.retain_history(control, authority, deadline)?;
        let pending = report.has_more || report.control_pending;
        if !pending || Instant::now() + Duration::from_millis(20) >= deadline {
            return Ok(pending);
        }
        // An incomplete token inventory can require catalog batches before
        // control cleanup; do not spin if no bounded cleanup made progress.
        if report.catalog.receipts_deleted == 0
            && report.catalog.discoveries_deleted == 0
            && report.control_cycles_deleted == 0
            && report.control_barriers_deleted == 0
        {
            return Ok(pending);
        }
    }
}

/// Maintenance requires releasing this worker's catalog and lifecycle handles.
/// Only the runtime summary is stopped; desired pause and the owner's fence
/// remain intact so the supervisor can distinguish intentional exit from crash.
fn quiesce_if_requested(
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
) -> PortResult<bool> {
    quiesce_before(control, authority, Instant::now() + CONTROL_BUDGET)
}

fn quiesce_before(
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    end: Instant,
) -> PortResult<bool> {
    control_change_before(control, end, |seq| {
        let current = control.status()?;
        if current.desired_updates == DesiredUpdates::Stopped
            || current.policy.maintenance.state != MaintenanceState::Idle
        {
            // The catalog image/rows are untouched. Ending only the control
            // worker summary is sufficient for an intentional fenced exit.
            control.stop_worker(seq, authority, app_clock_ms())?;
            Ok(true)
        } else {
            Ok(false)
        }
    })
}

fn failure(error: &PortError) -> BackgroundFailure {
    match error {
        PortError::WriterBusy(_) => BackgroundFailure::Busy,
        PortError::SnapshotChanged(_) | PortError::GenerationMismatch(_) => {
            BackgroundFailure::SourceChanged
        }
        PortError::SourceIo(_) | PortError::NotFound(_) => BackgroundFailure::Offline,
        PortError::InvalidRequest(_) => BackgroundFailure::ScopeUnverified,
        _ => BackgroundFailure::Failed,
    }
}
fn failure_state(error: &PortError) -> UpdateState {
    match error {
        PortError::WriterBusy(_) => UpdateState::Busy,
        PortError::SnapshotChanged(_) | PortError::GenerationMismatch(_) => UpdateState::Deferred,
        _ => UpdateState::Failed,
    }
}

fn selection_revision(selection: &Selection) -> PortResult<SelectionRevision> {
    Ok(SelectionRevision {
        selection_id: selection.id.clone(),
        revision: selection.revision,
        root_identity: selection.root_identity.clone().ok_or_else(invalid)?,
    })
}

fn check_policy(control: &SqliteControlStore, policy: &ReadPolicy) -> PortResult<()> {
    let current = control.status()?;
    if current.desired_updates != DesiredUpdates::Running
        || current.policy.maintenance.state != MaintenanceState::Idle
        || current.policy.policy_epoch != policy.policy_epoch
        || current.policy.installation_id != policy.installation_id
    {
        return Err(changed());
    }
    Ok(())
}

fn verify_root(selection: &Selection) -> PortResult<()> {
    if selection.region.kind == RootKind::Exact {
        let path = Path::new(selection.region.locator.as_str());
        let parent = path.parent().ok_or_else(invalid)?;
        let request = crate::managed_control::source_selection(selection.region.provider, parent)
            .map_err(|_| unavailable())?;
        if request.region.kind != RootKind::Root || request.root_identity != selection.root_identity
        {
            return Err(changed());
        }
        return Ok(());
    }
    let request = crate::managed_control::source_selection(
        selection.region.provider,
        Path::new(selection.region.locator.as_str()),
    )
    .map_err(|_| unavailable())?;
    if request.region != selection.region || request.root_identity != selection.root_identity {
        return Err(changed());
    }
    Ok(())
}

fn source_id(
    policy: &ReadPolicy,
    provider: SearchProvider,
    locator: &CanonicalLocator,
) -> PortResult<SourceId> {
    let mut hash = Sha256::new();
    for part in [
        "asg-managed-source-v1",
        policy.installation_id.as_str(),
        provider.as_str(),
        locator.as_str(),
    ] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    SourceId::parse(&format!("source_{}", hex(&hash.finalize())))
}

/// Reuse setup's component-by-component no-link check before every source-open
/// stage. Canonical containment and global exclusions precede all content I/O.
fn admit(
    control: &SqliteControlStore,
    policy: &ReadPolicy,
    selection: &Selection,
    path: &Path,
    id: &SourceId,
    end: Instant,
) -> PortResult<CanonicalLocator> {
    observation_deadline(end)?;
    check_policy(control, policy)?;
    observation_deadline(end)?;
    verify_root(selection)?;
    let lexical = CanonicalLocator::from_path(path)?;
    let id = ControlId::parse(id.as_str())?;
    if !selection
        .region
        .matches(selection.region.provider, &lexical)
        || !policy.allows_source(selection.region.provider, &lexical, &id)
    {
        return Err(invalid());
    }
    observation_deadline(end)?;
    let verified = crate::managed_control::source_selection(selection.region.provider, path)
        .map_err(|_| unavailable())?;
    if verified.region.kind != RootKind::Exact || verified.region.locator != lexical {
        return Err(changed());
    }
    check_policy(control, policy)?;
    Ok(lexical)
}

#[derive(Clone)]
struct Discovered {
    path: PathBuf,
    id: SourceId,
    hint: SourceHint,
    descriptor: SourceDescriptor,
    original_end: Instant,
}
struct Discovery {
    files: Vec<Discovered>,
    complete: bool,
}

fn discover(
    control: &SqliteControlStore,
    policy: &ReadPolicy,
    selection: &Selection,
    known: &BTreeMap<String, BackgroundSource>,
    end: Instant,
) -> PortResult<Discovery> {
    observation_deadline(end)?;
    check_policy(control, policy)?;
    verify_root(selection)?;
    let mut result = Discovery {
        files: Vec::new(),
        complete: true,
    };
    let mut pending = managed_source_discovery::traversal_roots(
        selection.region.provider,
        Path::new(selection.region.locator.as_str()),
        selection.region.kind,
    )?;
    let mut visited = 0usize;
    while let Some(path) = pending.pop() {
        observation_deadline(end)?;
        visited = visited.checked_add(1).ok_or_else(discovery_capacity)?;
        if visited > MAX_DISCOVERY_PATHS {
            return Err(discovery_capacity());
        }
        check_policy(control, policy)?;
        let locator = CanonicalLocator::from_path(&path)?;
        let id = known
            .get(locator.as_str())
            .filter(|source| source.binding.provider == selection.region.provider)
            .map(|source| Ok(source.binding.source_id.clone()))
            .unwrap_or_else(|| source_id(policy, selection.region.provider, &locator))?;
        // A planner never grants adjacent metadata access. The selected exact
        // region and provider-global exclusions are checked before any open.
        if !selection
            .region
            .matches(selection.region.provider, &locator)
            || !policy.allows_source(
                selection.region.provider,
                &locator,
                &ControlId::parse(id.as_str())?,
            )
        {
            continue;
        }
        if matches!(std::fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            // Known missing sources enter the independently complete-root
            // absence path; missing optional native history children add none.
            continue;
        }
        let request =
            match crate::managed_control::source_selection(selection.region.provider, &path) {
                Ok(request) => request,
                Err(_) => {
                    result.complete = false;
                    continue;
                }
            };
        if request.region.locator != locator {
            result.complete = false;
            continue;
        }
        if request.region.kind == RootKind::Root {
            if !managed_source_discovery::descend(selection.region.provider, &path) {
                continue;
            }
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    for entry in entries {
                        observation_deadline(end)?;
                        match entry {
                            Ok(entry) => {
                                if pending.len() >= MAX_DISCOVERY_PATHS {
                                    return Err(discovery_capacity());
                                }
                                pending.push(entry.path());
                            }
                            Err(_) => result.complete = false,
                        }
                    }
                }
                Err(_) => result.complete = false,
            }
        } else if let Some(descriptor) = managed_source_discovery::describe(
            selection.region.provider,
            &path,
            selection.region.kind == RootKind::Exact,
        ) {
            if result.files.len() >= MAX_DISCOVERY_PATHS {
                return Err(discovery_capacity());
            }
            observation_deadline(end)?;
            let hint = SourceHint::from_metadata(
                &std::fs::symlink_metadata(&path).map_err(|_| unavailable())?,
            )?;
            result.files.push(Discovered {
                path,
                id,
                hint,
                descriptor,
                original_end: end,
            });
        } else if selection.region.kind == RootKind::Exact {
            result.complete = false;
        }
    }
    observation_deadline(end)?;
    verify_root(selection)?;
    result.files.sort_by(|left, right| {
        right
            .hint
            .mtime_ms
            .cmp(&left.hint.mtime_ms)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(result)
}
fn observation_deadline(end: Instant) -> PortResult<()> {
    observation_deadline_at(end, Instant::now())
}
fn discovery_capacity() -> PortError {
    PortError::WriterBusy("managed source discovery capacity exceeded".into())
}

struct PendingCycle {
    token: ObservationToken,
    finish: CycleFinish,
}

/// Retain an exact owned completion across a refused control tick. A later
/// cadence resolves it before admitting another cycle; a policy-aborted cycle
/// stays aborted and can never be resurrected from this process-local intent.
fn finish_pending_cycle(
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    pending: &mut Option<PendingCycle>,
    end: Instant,
) -> PortResult<()> {
    let Some(intent) = pending.as_ref() else {
        return Ok(());
    };
    control.with_runtime_deadline(end, || {
        let cycle = control.cycle(intent.token.cycle_seq)?;
        if cycle.token != intent.token || intent.token.worker_boot_id != *authority.boot_id() {
            return Err(changed());
        }
        if matches!(cycle.state, CycleState::Queued | CycleState::Observing) {
            control_change_before(control, end, |seq| {
                control.finish_cycle(
                    seq,
                    authority,
                    intent.token.cycle_seq,
                    intent.finish,
                    app_clock_ms(),
                )
            })?;
        }
        Ok(())
    })?;
    *pending = None;
    Ok(())
}

/// Own the queued token before start can commit without an acknowledgement.
/// Until observation returns, only an abort is justified; a refused start must
/// leave this exact intent for the next cadence instead of stranding Observing.
fn start_cycle_with_pending(
    control: &SqliteControlStore,
    queued: &ObservationCycle,
    pending: &mut Option<PendingCycle>,
    end: Instant,
    mut start: impl FnMut(ControlSeq) -> PortResult<ObservationCycle>,
) -> PortResult<ObservationCycle> {
    if pending.is_some() || queued.state != CycleState::Queued {
        return Err(invalid());
    }
    *pending = Some(PendingCycle {
        token: queued.token.clone(),
        finish: CycleFinish::Aborted,
    });
    control_change_before(control, end, |seq| {
        let cycle = start(seq)?;
        if cycle.token != queued.token {
            return Err(changed());
        }
        Ok(cycle)
    })
}

#[allow(clippy::too_many_arguments)]
fn run_cycle(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    boot: &ObservationClock,
    round: u64,
    end: Instant,
    pending: &mut Option<PendingCycle>,
    schedule: &mut SourceScheduleState,
) -> PortResult<bool> {
    // The same live worker may have reported Busy/Deferred after a refused
    // completion. Restore activity under current intent/fence before finish,
    // whose control admission rejects those advisory states. A pause, stop or
    // maintenance fence is a permanent refusal for this attempt: report it
    // immediately instead of retrying the heartbeat until the caller deadline,
    // which would consume the whole observation budget on every cadence.
    control_change_before(control, end, |seq| {
        let current = control.status()?;
        if current.desired_updates != DesiredUpdates::Running
            || current.policy.maintenance.state != MaintenanceState::Idle
        {
            return Err(changed());
        }
        control.heartbeat_worker(seq, authority, UpdateState::Running, None, app_clock_ms())
    })?;
    finish_pending_cycle(control, authority, pending, end)?;
    let policy = control
        .with_runtime_deadline(end, || control.read_policy(RequestIntersection::Selected))?;
    let mut selections = policy
        .selections
        .iter()
        .filter(|s| s.enabled)
        .cloned()
        .collect::<Vec<_>>();
    if selections.is_empty() {
        return Ok(true);
    }
    // Rotate the first selection as well as processing every candidate. An old
    // root cannot be permanently behind a continuously busy recent root.
    let rotation = round as usize % selections.len();
    selections.rotate_left(rotation);
    let revisions = selections
        .iter()
        .map(selection_revision)
        .collect::<PortResult<Vec<_>>>()?;
    let queued = control_change_before(control, end, |seq| {
        control.queue_cycle(seq, revisions.clone())
    })?;
    let CycleAdmission::Queued(queued) = queued.value else {
        return Err(changed());
    };
    let cycle = start_cycle_with_pending(control, &queued, pending, end, |seq| {
        control
            .start_cycle(seq, authority, queued.token.cycle_seq, app_clock_ms())
            .map(|change| change.value)
    })?;
    let result = observe_cycle(
        db,
        control,
        authority,
        &policy,
        &selections,
        &cycle,
        boot,
        schedule,
    );
    pending.as_mut().ok_or_else(invalid)?.finish = match &result {
        Ok(true) => CycleFinish::Committed,
        Ok(false) => CycleFinish::Partial,
        Err(_) => CycleFinish::Aborted,
    };
    finish_pending_cycle(control, authority, pending, end)?;
    result
}

struct RootState<'a> {
    selection: &'a Selection,
    revision: SelectionRevision,
    discovery: PortResult<Discovery>,
    original_end: Instant,
}

struct SharedSource {
    path: PathBuf,
    id: SourceId,
    hint: SourceHint,
    roots: Vec<usize>,
    provider: SearchProvider,
    descriptor: SourceDescriptor,
    original_end: Instant,
}

enum ObservationOutcome {
    NotScheduled,
    Attempted {
        published: bool,
        claimed: BTreeSet<usize>,
        failed: Option<BackgroundFailure>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceHint {
    len: u64,
    mtime_ms: i64,
}

impl SourceHint {
    fn from_metadata(metadata: &std::fs::Metadata) -> PortResult<Self> {
        Ok(Self {
            len: metadata.len(),
            // Match SourceSnapshot precision, including pre-epoch timestamps.
            mtime_ms: i64::try_from(
                metadata
                    .modified()
                    .map_err(|_| unavailable())?
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .map_err(|_| unavailable())?,
        })
    }

    fn from_snapshot(snapshot: &SourceSnapshot) -> Self {
        Self {
            len: snapshot.len,
            mtime_ms: snapshot.mtime_ms,
        }
    }
}

struct SourceAttemptResult {
    current: bool,
    successful: Option<SuccessfulSourceAttempt>,
}

struct SuccessfulSourceAttempt {
    baseline: BackgroundSource,
    hint: SourceHint,
    revisitable: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SourceLane {
    Metadata,
    Active,
    #[default]
    Cold,
    Verification,
}

#[derive(PartialEq, Eq)]
struct ScheduleIdentity {
    installation: ControlId,
    incarnation: ControlId,
    epoch: PolicyEpoch,
    selections: Vec<SelectionRevision>,
}

struct SourceDebt {
    ticket: u64,
    verified: Option<(RevisionId, SourceHint)>,
    dirty: bool,
}

/// Tickets rotate only when an attempt starts. An expired first turn keeps its
/// place across cycles and class promotion; hints never move a hot source ahead.
#[derive(Default)]
struct SourceScheduleState {
    identity: Option<ScheduleIdentity>,
    sources: BTreeMap<SourceId, SourceDebt>,
    next_ticket: u64,
    active_attempts: u8,
    next_debt: SourceLane,
    probe_after: Option<SourceId>,
    next_probe: Option<Instant>,
    #[cfg(test)]
    hooks: ScheduleTestHooks,
}

impl SourceScheduleState {
    fn prepare(&mut self, policy: &ReadPolicy, incarnation: &ControlId) -> PortResult<()> {
        let mut selections = policy
            .selections
            .iter()
            .filter(|selection| selection.enabled)
            .map(selection_revision)
            .collect::<PortResult<Vec<_>>>()?;
        selections.sort_by(|a, b| a.selection_id.cmp(&b.selection_id));
        let identity = ScheduleIdentity {
            installation: policy.installation_id.clone(),
            incarnation: incarnation.clone(),
            epoch: policy.policy_epoch,
            selections,
        };
        if self.identity.as_ref() != Some(&identity) {
            self.sources.clear();
            self.next_ticket = 0;
            self.active_attempts = 0;
            self.next_debt = SourceLane::Cold;
            self.probe_after = None;
            self.next_probe = None;
            self.identity = Some(identity);
        }
        Ok(())
    }

    fn ticket(&mut self) -> PortResult<u64> {
        let ticket = self.next_ticket;
        self.next_ticket = ticket.checked_add(1).ok_or_else(discovery_capacity)?;
        Ok(ticket)
    }

    fn register(&mut self, id: &SourceId, prior: Option<&BackgroundSource>) -> PortResult<()> {
        if !self.sources.contains_key(id) {
            if self.sources.len() >= MAX_DISCOVERY_PATHS {
                return Err(discovery_capacity());
            }
            let ticket = self.ticket()?;
            self.sources.insert(
                id.clone(),
                SourceDebt {
                    ticket,
                    verified: None,
                    dirty: false,
                },
            );
        }
        let debt = self.sources.get_mut(id).ok_or_else(invalid)?;
        if debt.verified.as_ref().is_some_and(|(revision, _)| {
            prior
                .and_then(|p| p.latest_receipt.as_ref())
                .is_none_or(|receipt| !receipt.published || &receipt.revision_id != revision)
        }) {
            // A possibly committed failure is reconciled from the real head in
            // the next cycle. Never attach a remembered hint to another receipt.
            debt.verified = None;
        }
        Ok(())
    }

    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(now) = &self.hooks.now {
            return Instant::now() + now.get();
        }
        Instant::now()
    }
}

#[cfg(test)]
type ScheduleEventHook = Box<dyn FnMut(ScheduleTestEvent<'_>) -> PortResult<()>>;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
enum SourceAttemptPhase {
    #[default]
    Prepare,
    Publication,
    Currentness,
    Acknowledgement,
}

#[cfg(test)]
#[derive(Default)]
struct ScheduleTestHooks {
    now: Option<std::rc::Rc<std::cell::Cell<Duration>>>,
    probe_due: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    source_phase: std::cell::Cell<SourceAttemptPhase>,
    on_event: Option<RefCell<ScheduleEventHook>>,
}

#[cfg(test)]
enum ScheduleTestEvent<'a> {
    Planned,
    BeforeProbe(&'a SourceId, Instant),
    BeforeAttempt(&'a SourceId, Instant, SourceLane),
    AfterAdmissionFailure(&'a SourceId, Instant, BackgroundFailure),
    AfterAttempt(&'a SourceId, SourceLane),
    AfterNotScheduled(&'a SourceId),
    Published(&'a SourceId, Instant),
    SourceFailed {
        id: &'a SourceId,
        phase: SourceAttemptPhase,
        error: &'a PortError,
        revisit: bool,
        remaining: Duration,
    },
    Finalizing,
}

#[cfg(test)]
impl ScheduleTestHooks {
    fn event(&self, event: ScheduleTestEvent<'_>) -> PortResult<()> {
        if let Some(hook) = &self.on_event {
            return hook.borrow_mut()(event);
        }
        Ok(())
    }
}

struct SourceTurn {
    original_end: Instant,
    first_pending: bool,
    lane: Option<SourceLane>,
    probe: bool,
    revisitable: bool,
    last_slice: Option<u64>,
}

enum ScheduledTurn {
    NotScheduled(SourceId),
    Attempt(SourceId, SourceLane),
}

struct CycleSchedule<'a> {
    state: &'a mut SourceScheduleState,
    turns: BTreeMap<SourceId, SourceTurn>,
    queues: [BTreeSet<(u64, SourceId)>; 4],
    probes: BTreeSet<SourceId>,
    expirations: BTreeSet<(Instant, SourceId)>,
    first_pending: usize,
    slice: u64,
    slice_attempts: usize,
    slice_started: Instant,
}

impl<'a> CycleSchedule<'a> {
    fn new(state: &'a mut SourceScheduleState) -> Self {
        let slice_started = state.now();
        Self {
            state,
            turns: BTreeMap::new(),
            queues: Default::default(),
            probes: BTreeSet::new(),
            expirations: BTreeSet::new(),
            first_pending: 0,
            slice: 0,
            slice_attempts: 0,
            slice_started,
        }
    }

    fn add(
        &mut self,
        id: &SourceId,
        prior: Option<&BackgroundSource>,
        lane: SourceLane,
        end: Instant,
        probe: bool,
    ) -> PortResult<()> {
        if self.turns.len() >= MAX_DISCOVERY_PATHS || self.turns.contains_key(id) {
            return Err(discovery_capacity());
        }
        self.state.register(id, prior)?;
        self.turns.insert(
            id.clone(),
            SourceTurn {
                original_end: end,
                first_pending: true,
                lane: None,
                probe,
                revisitable: false,
                last_slice: None,
            },
        );
        self.expirations.insert((end, id.clone()));
        if probe {
            self.probes.insert(id.clone());
        }
        self.first_pending += 1;
        self.set_lane(id, Some(lane));
        Ok(())
    }

    fn set_lane(&mut self, id: &SourceId, lane: Option<SourceLane>) {
        let turn = self.turns.get_mut(id).expect("registered source turn");
        if turn.lane == lane {
            return;
        }
        let key = (self.state.sources[id].ticket, id.clone());
        if let Some(previous) = turn.lane {
            self.queues[previous as usize].remove(&key);
        }
        if let Some(next) = lane {
            self.queues[next as usize].insert(key);
        }
        turn.lane = lane;
    }

    fn hint(&mut self, id: &SourceId, hint: SourceHint, indexed_len: Option<u64>) {
        let turn = &self.turns[id];
        if !turn.probe || (!turn.first_pending && !turn.revisitable) {
            return;
        }
        let debt = self
            .state
            .sources
            .get_mut(id)
            .expect("registered source debt");
        debt.dirty |= debt
            .verified
            .as_ref()
            .map(|(_, verified)| *verified != hint)
            .unwrap_or_else(|| indexed_len.is_some_and(|len| len != hint.len));
        if debt.dirty {
            self.set_lane(id, Some(SourceLane::Active));
        }
    }

    fn probe_batch(&mut self, now: Instant) -> Vec<SourceId> {
        use std::ops::Bound::{Excluded, Unbounded};
        #[cfg(test)]
        if self
            .state
            .hooks
            .probe_due
            .as_ref()
            .is_some_and(|due| due.replace(false))
        {
            self.state.next_probe = None;
        }
        if self.first_pending == 0
            || self.state.next_probe.is_some_and(|next| now < next)
            || !self.queues[SourceLane::Metadata as usize].is_empty()
        {
            return Vec::new();
        }
        self.state.next_probe = Some(now + CADENCE);
        let keys = if let Some(after) = &self.state.probe_after {
            self.probes
                .range((Excluded(after.clone()), Unbounded))
                .chain(self.probes.range(..=after.clone()))
                .take(SOURCE_HINT_BATCH)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            self.probes
                .iter()
                .take(SOURCE_HINT_BATCH)
                .cloned()
                .collect()
        };
        self.state.probe_after = keys.last().cloned();
        keys.into_iter()
            .filter(|id| {
                let turn = &self.turns[id];
                turn.probe && now < turn.original_end && (turn.first_pending || turn.revisitable)
            })
            .collect()
    }

    fn next(&mut self, now: Instant) -> Option<ScheduledTurn> {
        while self.expirations.first().is_some_and(|(end, _)| *end <= now) {
            let (_, id) = self.expirations.pop_first().expect("expired turn");
            self.set_lane(&id, None);
            self.probes.remove(&id);
            let turn = self.turns.get_mut(&id).expect("registered source turn");
            turn.revisitable = false;
            if turn.first_pending {
                turn.first_pending = false;
                self.first_pending -= 1;
                return Some(ScheduledTurn::NotScheduled(id));
            }
        }
        if self.first_pending == 0 {
            // No quiet-period wait and no source-count cycle cutoff. Dirty
            // revisits wait for the next independently admitted discovery.
            return None;
        }
        if self.slice_attempts >= SOURCE_SLICE_ATTEMPTS
            || now.saturating_duration_since(self.slice_started) >= CADENCE
        {
            self.slice = self.slice.wrapping_add(1);
            self.slice_attempts = 0;
            self.slice_started = now;
        }
        let first = |lane: SourceLane| {
            self.queues[lane as usize]
                .iter()
                .find(|(_, id)| self.turns[id].last_slice != Some(self.slice))
                .map(|(_, id)| id.clone())
        };
        if let Some(id) = first(SourceLane::Metadata) {
            return Some(ScheduledTurn::Attempt(id, SourceLane::Metadata));
        }
        let active = first(SourceLane::Active);
        let cold = first(SourceLane::Cold);
        let verification = first(SourceLane::Verification);
        let debt = match (cold, verification) {
            (Some(cold), Some(verification)) => Some(if self.state.next_debt == SourceLane::Cold {
                (cold, SourceLane::Cold)
            } else {
                (verification, SourceLane::Verification)
            }),
            (Some(id), None) => Some((id, SourceLane::Cold)),
            (None, Some(id)) => Some((id, SourceLane::Verification)),
            (None, None) => None,
        };
        if (self.state.active_attempts < 2 || debt.is_none())
            && let Some(id) = active
        {
            return Some(ScheduledTurn::Attempt(id, SourceLane::Active));
        }
        debt.map(|(id, lane)| ScheduledTurn::Attempt(id, lane))
    }

    fn started(&mut self, id: &SourceId, lane: SourceLane) -> PortResult<()> {
        let ticket = self.state.ticket()?;
        self.set_lane(id, None);
        self.probes.remove(id);
        self.state.sources.get_mut(id).ok_or_else(invalid)?.ticket = ticket;
        let turn = self.turns.get_mut(id).ok_or_else(invalid)?;
        if turn.first_pending {
            turn.first_pending = false;
            self.first_pending -= 1;
        }
        turn.revisitable = false;
        turn.last_slice = Some(self.slice);
        self.slice_attempts += 1;
        match lane {
            SourceLane::Metadata => {}
            SourceLane::Active => {
                self.state.active_attempts = (self.state.active_attempts + 1).min(2);
            }
            SourceLane::Cold | SourceLane::Verification => {
                self.state.active_attempts = 0;
                self.state.next_debt = if lane == SourceLane::Cold {
                    SourceLane::Verification
                } else {
                    SourceLane::Cold
                };
            }
        }
        Ok(())
    }

    fn succeeded(&mut self, id: &SourceId, success: &SuccessfulSourceAttempt) {
        let debt = self
            .state
            .sources
            .get_mut(id)
            .expect("registered source debt");
        debt.verified = Some((
            success
                .baseline
                .latest_receipt
                .as_ref()
                .expect("published receipt")
                .revision_id
                .clone(),
            success.hint,
        ));
        debt.dirty = false;
        let turn = self.turns.get_mut(id).expect("registered source turn");
        // probe is false for sources first imported in this cycle.
        turn.revisitable = turn.probe && success.revisitable;
        if turn.revisitable {
            self.probes.insert(id.clone());
        }
    }
}

/// One separately admitted logical metadata observation. Only the state map
/// survives parsing; provider cwd or any DB body is never copied into text.
struct WorkBuddyMetadata {
    source: Discovered,
    snapshot: SourceSnapshot,
    binding: SourceBinding,
    receipt: agent_session_grep_ports::managed::RevisionRef,
    selection: SelectionProof,
    claims: Vec<Selection>,
    states: BTreeMap<String, LifecycleState>,
    observed_natives: std::cell::RefCell<BTreeSet<NativeSessionId>>,
}

fn workbuddy_states(
    content: &dyn ReadOnlySource,
    end: Instant,
) -> PortResult<BTreeMap<String, LifecycleState>> {
    observation_deadline(end)?;
    if content.len() > agent_session_grep_ports::SQLITE_MAX_SOURCE_BYTES {
        return Err(discovery_capacity());
    }
    let mut image = Vec::new();
    let mut reader = content.open()?;
    let mut chunk = [0_u8; 65_536];
    loop {
        observation_deadline(end)?;
        let read = reader.read(&mut chunk).map_err(|_| unavailable())?;
        observation_deadline(end)?;
        if read == 0 {
            break;
        }
        let size = image
            .len()
            .checked_add(read)
            .ok_or_else(discovery_capacity)?;
        if size as u64 > content.len() {
            return Err(changed());
        }
        image.try_reserve(read).map_err(|_| discovery_capacity())?;
        image.extend_from_slice(&chunk[..read]);
    }
    if image.len() as u64 != content.len() {
        return Err(changed());
    }
    let rows = agent_session_grep_provider_workbuddy::inspect_session_states(&image, end).map_err(
        |error| {
            if Instant::now() >= end
                || error == agent_session_grep_provider_workbuddy::SessionStateError::Deadline
            {
                PortError::WriterBusy("managed metadata observation deadline reached".into())
            } else {
                invalid()
            }
        },
    )?;
    drop(image);
    let mut states = BTreeMap::new();
    for (native, state) in rows {
        observation_deadline(end)?;
        NativeSessionId::parse(&native)?;
        use agent_session_grep_provider_workbuddy::SessionDeletionState;
        let lifecycle = match state.state {
            SessionDeletionState::ActiveLocal => LifecycleState::ActiveLocal,
            SessionDeletionState::SoftDeleted => LifecycleState::SoftDeleted,
            SessionDeletionState::CloudUnavailable => LifecycleState::CloudUnavailable,
            SessionDeletionState::OrphanUnknown => LifecycleState::OrphanUnknown,
        };
        states.insert(native, lifecycle);
    }
    Ok(states)
}

#[allow(clippy::too_many_arguments)]
fn observe_workbuddy_metadata(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    advisory: &Selection,
    claims: &[&Selection],
    cycle: &ObservationCycle,
    incarnation: &ControlId,
    source: &Discovered,
    prior: Option<&BackgroundSource>,
) -> PortResult<WorkBuddyMetadata> {
    let end = source.original_end;
    let limit = source.descriptor.kind.max_input_bytes();
    let locator = admit(control, policy, advisory, &source.path, &source.id, end)?;
    let snapshot = capture_with_deadline(&source.path, limit, end)?;
    admit(control, policy, advisory, &source.path, &source.id, end)?;
    let content = open_snapshot_source_with_deadline(&source.path, &snapshot, limit, end)?;
    let states = workbuddy_states(&content, end)?;
    let binding = prior.map(|p| p.binding.clone()).unwrap_or(SourceBinding {
        source_id: source.id.clone(),
        source_path: locator.as_str().into(),
        provider: advisory.region.provider,
        namespace_id: None,
        root_identity: advisory
            .root_identity
            .as_ref()
            .ok_or_else(invalid)?
            .as_str()
            .into(),
    });
    let mut observed = observation(
        binding,
        incarnation,
        cycle,
        claims,
        &snapshot.fingerprint,
        ObservationState::Complete,
    )?;
    for claim in claims {
        admit(control, policy, claim, &source.path, &source.id, end)?;
    }
    verify_snapshot_with_deadline(&source.path, &snapshot, limit, end)?;
    let writer = ManagedStore::open_for_write(db, control)?;
    let namespace = writer.reserve_namespace(
        control,
        &observed,
        authority,
        &crate::installation_namespace(locator.as_str(), advisory.region.provider.as_str()),
    )?;
    observed.binding.namespace_id = Some(namespace.namespace_id);
    for claim in claims {
        admit(control, policy, claim, &source.path, &source.id, end)?;
    }
    verify_snapshot_with_deadline(&source.path, &snapshot, limit, end)?;
    observed.committed_at_ms = app_clock_ms();
    let published = writer.commit_source_with_context(
        control,
        authority,
        &empty_batch(locator.as_str(), advisory.region.provider, &snapshot),
        &observed,
        &SourcePublicationContext::default(),
        end,
    )?;
    if !published.receipt.published {
        return Err(changed());
    }
    drop(writer);
    acknowledge(
        control,
        authority,
        advisory,
        cycle,
        &source.id,
        &published,
        ObservationState::Complete,
        None,
    )?;
    Ok(WorkBuddyMetadata {
        source: source.clone(),
        snapshot,
        binding: observed.binding,
        receipt: published.receipt,
        selection: observed
            .selections
            .into_iter()
            .find(|s| s.selection_id == advisory.id.as_str())
            .ok_or_else(invalid)?,
        claims: claims.iter().map(|s| (*s).clone()).collect(),
        states,
        observed_natives: std::cell::RefCell::new(BTreeSet::new()),
    })
}

impl WorkBuddyMetadata {
    fn verify(
        &self,
        control: &SqliteControlStore,
        policy: &ReadPolicy,
        end: Instant,
    ) -> PortResult<()> {
        observation_deadline(end)?;
        for claim in &self.claims {
            admit(
                control,
                policy,
                claim,
                &self.source.path,
                &self.source.id,
                end,
            )?;
        }
        verify_snapshot_with_deadline(
            &self.source.path,
            &self.snapshot,
            self.source.descriptor.kind.max_input_bytes(),
            end,
        )
    }
    fn dependency(&self, native: NativeSessionId) -> PortResult<SourceDependency> {
        let state = self
            .states
            .get(native.as_str())
            .copied()
            .unwrap_or(LifecycleState::OrphanUnknown);
        let mut hash = Sha256::new();
        for field in [
            "asg-workbuddy-state-v1",
            native.as_str(),
            lifecycle_name(state),
            self.binding.source_id.as_str(),
            &self.selection.root_identity,
        ] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(self.selection.selection_revision.to_le_bytes());
        Ok(SourceDependency {
            native_session: native,
            resolution: DependencyResolution::Resolved(Box::new(MetadataDependencyProof {
                binding: self.binding.clone(),
                receipt: self.receipt.clone(),
                selection: self.selection.clone(),
                state,
                state_digest: StateDigest::parse(&hex(&hash.finalize()))?,
            })),
        })
    }
}
fn lifecycle_name(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::ActiveLocal => "active-local",
        LifecycleState::SoftDeleted => "soft-deleted",
        LifecycleState::CloudUnavailable => "cloud-unavailable",
        LifecycleState::OrphanUnknown => "orphan-unknown",
    }
}

/// Verified provider surface identity for authority/namespace only. This is
/// a component identity check, never enumeration or content permission for the
/// surface. Every actual source retains its independent exact admission.
struct AuthoritySurface {
    root: CanonicalLocator,
    identity: ControlId,
    id: ControlId,
}
fn authority_surface(
    control: &SqliteControlStore,
    policy: &ReadPolicy,
    provider: SearchProvider,
    descriptor: &SourceDescriptor,
    end: Instant,
) -> PortResult<Option<AuthoritySurface>> {
    let Some(surface) = descriptor.surface.as_ref().filter(|_| {
        matches!(
            descriptor.kind,
            SourceKind::DeepSeekHarness { .. }
                | SourceKind::AntigravityFull
                | SourceKind::AntigravityDatabase
        )
    }) else {
        return Ok(None);
    };
    observation_deadline(end)?;
    check_policy(control, policy)?;
    let request =
        crate::managed_control::source_selection(provider, surface).map_err(|_| unavailable())?;
    if request.region.kind != RootKind::Root {
        return Err(changed());
    }
    let root = request.region.locator;
    let identity = request.root_identity.ok_or_else(invalid)?;
    let mut hash = Sha256::new();
    for field in [
        "asg-source-surface-v1",
        policy.installation_id.as_str(),
        provider.as_str(),
        root.as_str(),
        identity.as_str(),
    ] {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field.as_bytes());
    }
    observation_deadline(end)?;
    Ok(Some(AuthoritySurface {
        root,
        identity,
        id: ControlId::parse(&format!("surface_{}", hex(&hash.finalize())))?,
    }))
}
fn verified_native_session(
    staged: &mut StagedBatch,
    descriptor: &SourceDescriptor,
) -> PortResult<Option<NativeSessionId>> {
    use agent_session_grep_ports::MetadataResolution;
    match descriptor.kind {
        SourceKind::AntigravityFull | SourceKind::AntigravityDatabase => {
            let expected = descriptor.native_session.as_deref().ok_or_else(invalid)?;
            if staged.report.session_observation.multi_session {
                return Err(invalid());
            }
            match (
                &staged.report.session_native_id,
                &staged.report.session_observation.provider_session_id,
            ) {
                (Some(native), MetadataResolution::Resolved(observed))
                    if native.eq_ignore_ascii_case(expected)
                        && observed.eq_ignore_ascii_case(expected) => {}
                (None, MetadataResolution::Missing)
                    if descriptor.kind == SourceKind::AntigravityFull => {}
                _ => return Err(invalid()),
            }
            // Only this verified exact brain/<uuid>/... layout provides missing
            // transcript Session identity. Message/step IDs remain reconstructed.
            for message in &staged.messages {
                if message.session.as_ref().is_some_and(|identity| {
                    !matches!(&identity.observation.provider_session_id,
                        MetadataResolution::Resolved(native) if native.eq_ignore_ascii_case(expected))
                }) { return Err(invalid()); }
            }
            staged.report.session_native_id = Some(expected.into());
            staged.report.session_observation.provider_session_id =
                MetadataResolution::Resolved(expected.into());
            staged.report.session_observation.pair_observed = false;
            Ok(Some(NativeSessionId::parse(expected)?))
        }
        SourceKind::DeepSeekHarness { .. } => {
            let MetadataResolution::Resolved(native) =
                &staged.report.session_observation.provider_session_id
            else {
                return Err(invalid());
            };
            if staged.report.session_observation.multi_session
                || staged.report.session_native_id.as_deref() != Some(native.as_str())
                || !descriptor.native_session.as_deref().is_some_and(|segment| {
                    managed_source_discovery::dsh_segment_matches(native, segment)
                })
            {
                return Err(invalid());
            }
            Ok(Some(NativeSessionId::parse(native)?))
        }
        _ => Ok(None),
    }
}

fn workbuddy_context(
    control: &SqliteControlStore,
    policy: &ReadPolicy,
    descriptor: &SourceDescriptor,
    staged: Option<&StagedBatch>,
    prior: &SourcePublicationContext,
    metadata: &BTreeMap<String, WorkBuddyMetadata>,
    end: Instant,
) -> PortResult<(SourcePublicationContext, Option<String>)> {
    use agent_session_grep_ports::MetadataResolution;
    let mut natives = prior
        .dependencies
        .iter()
        .map(|d| d.native_session.clone())
        .collect::<BTreeSet<_>>();
    if let Some(staged) = staged {
        let mut observations = vec![&staged.report.session_observation];
        observations.extend(
            staged
                .messages
                .iter()
                .filter_map(|m| m.session.as_ref().map(|s| &s.observation)),
        );
        for observed in observations {
            observation_deadline(end)?;
            if let MetadataResolution::Resolved(native) = &observed.provider_session_id {
                natives.insert(NativeSessionId::parse(native)?);
            }
        }
    }
    if natives.is_empty() {
        return Err(invalid());
    }
    if natives.len() > agent_session_grep_ports::source_context::MAX_SOURCE_DEPENDENCIES {
        return Err(discovery_capacity());
    }
    let metadata_path = descriptor
        .surface
        .as_ref()
        .map(|surface| surface.join("workbuddy.db"));
    let metadata_key = metadata_path
        .as_ref()
        .map(|path| CanonicalLocator::from_path(path))
        .transpose()?;
    let selected = metadata_key
        .as_ref()
        .and_then(|key| metadata.get(key.as_str()));
    if let Some(selected) = selected {
        selected.verify(control, policy, end)?;
        selected
            .observed_natives
            .borrow_mut()
            .extend(natives.iter().cloned());
    }
    let mut context = SourcePublicationContext::default();
    for native in natives {
        let dependency = if let Some(selected) = selected {
            selected.dependency(native)?
        } else {
            // Check permission lexically only; an unselected sibling DB is never
            // opened, even to distinguish missing from unsupported metadata.
            let reason = if let Some(key) = &metadata_key {
                let id = source_id(
                    policy,
                    SearchProvider::parse("workbuddy").ok_or_else(invalid)?,
                    key,
                )?;
                if policy.allows_source(
                    SearchProvider::parse("workbuddy").ok_or_else(invalid)?,
                    key,
                    &ControlId::parse(id.as_str())?,
                ) {
                    UnresolvedDependency::Incomplete
                } else {
                    UnresolvedDependency::NotSelected
                }
            } else {
                UnresolvedDependency::NotSelected
            };
            SourceDependency {
                native_session: native,
                resolution: DependencyResolution::Unresolved(reason),
            }
        };
        context.dependencies.push(dependency);
    }
    context.validate()?;
    Ok((
        context,
        selected
            .map(|selected| CanonicalLocator::from_path(&selected.source.path))
            .transpose()?
            .map(|key| key.as_str().into()),
    ))
}

/// Deterministic advisory root among independently qualifying selections.
/// Keep an eligible confirmation root before the historical binding root, then
/// use the lowest selection id. Scheduling rotation never moves the clock.
fn advisory_selection(
    claimed: &[usize],
    roots: &[RootState<'_>],
    binding_root: Option<&str>,
    confirmation_root: Option<&str>,
) -> usize {
    for preferred in [confirmation_root, binding_root].into_iter().flatten() {
        if let Some(&index) = claimed.iter().find(|&&index| {
            roots[index]
                .selection
                .root_identity
                .as_ref()
                .map(ControlId::as_str)
                == Some(preferred)
        }) {
            return index;
        }
    }
    *claimed
        .iter()
        .min_by(|&&a, &&b| {
            roots[a]
                .selection
                .id
                .as_str()
                .cmp(roots[b].selection.id.as_str())
        })
        .expect("claimed roots are never empty")
}

fn published_baseline(prior: Option<&BackgroundSource>) -> bool {
    prior.is_some_and(|source| {
        !source.superseded
            && source
                .latest_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.published)
    })
}

fn probe_source_hint(
    control: &SqliteControlStore,
    policy: &ReadPolicy,
    roots: &[RootState<'_>],
    source: &SharedSource,
    schedule: &SourceScheduleState,
) -> PortResult<SourceHint> {
    observation_deadline_at(source.original_end, schedule.now())?;
    control.with_runtime_deadline(source.original_end, || {
        for &index in &source.roots {
            observation_deadline_at(source.original_end, schedule.now())?;
            if admit(
                control,
                policy,
                roots[index].selection,
                &source.path,
                &source.id,
                source.original_end,
            )
            .is_ok()
            {
                observation_deadline_at(source.original_end, schedule.now())?;
                let hint = SourceHint::from_metadata(
                    &std::fs::symlink_metadata(&source.path).map_err(|_| unavailable())?,
                )?;
                observation_deadline_at(source.original_end, schedule.now())?;
                return Ok(hint);
            }
        }
        Err(unavailable())
    })
}

fn observation_deadline_at(end: Instant, now: Instant) -> PortResult<()> {
    if now >= end {
        return Err(PortError::WriterBusy(
            "managed source observation deadline reached".into(),
        ));
    }
    Ok(())
}

struct MissingSource<'a> {
    prior: &'a BackgroundSource,
    roots: Vec<usize>,
    original_end: Instant,
}

/// Enumeration facts only. Admission and every filesystem operation stay in
/// the scheduled attempt, after checking the original minimum root deadline.
fn missing_sources<'a>(
    known: &'a BTreeMap<String, BackgroundSource>,
    shared: &BTreeMap<String, SharedSource>,
    roots: &[RootState<'_>],
) -> PortResult<BTreeMap<SourceId, MissingSource<'a>>> {
    let mut missing = BTreeMap::new();
    for prior in known.values() {
        if prior.superseded || shared.contains_key(prior.binding.source_id.as_str()) {
            continue;
        }
        let old = managed_source_discovery::describe(
            prior.binding.provider,
            Path::new(&prior.binding.source_path),
            false,
        );
        if old.as_ref().is_some_and(|old| {
            old.surface.is_some()
                && old.native_session.is_some()
                && shared.values().any(|current| {
                    current.provider == prior.binding.provider
                        && current.descriptor.surface == old.surface
                        && current.descriptor.native_session == old.native_session
                })
        }) {
            continue;
        }
        let locator = CanonicalLocator::parse(&prior.binding.source_path)?;
        let covering = roots
            .iter()
            .enumerate()
            .filter(|(_, root)| {
                root.selection
                    .region
                    .matches(prior.binding.provider, &locator)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if covering.is_empty()
            || !covering.iter().all(|&index| {
                roots[index]
                    .discovery
                    .as_ref()
                    .is_ok_and(|discovery| discovery.complete)
            })
        {
            continue;
        }
        if shared
            .len()
            .checked_add(missing.len())
            .is_none_or(|count| count >= MAX_DISCOVERY_PATHS)
        {
            return Err(discovery_capacity());
        }
        let original_end = covering
            .iter()
            .map(|&index| roots[index].original_end)
            .min()
            .ok_or_else(invalid)?;
        missing.insert(
            prior.binding.source_id.clone(),
            MissingSource {
                prior,
                roots: covering,
                original_end,
            },
        );
    }
    Ok(missing)
}

#[allow(clippy::too_many_arguments)]
fn observe_shared_source(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    roots: &[RootState<'_>],
    inconsistent: &BTreeSet<usize>,
    cycle: &ObservationCycle,
    incarnation: &ControlId,
    group: &SharedSource,
    prior: Option<&BackgroundSource>,
    revisit: bool,
    boot: &ObservationClock,
    metadata: &mut BTreeMap<String, WorkBuddyMetadata>,
    schedule: &SourceScheduleState,
) -> PortResult<(ObservationOutcome, Option<SuccessfulSourceAttempt>)> {
    #[cfg(test)]
    schedule.hooks.source_phase.set(SourceAttemptPhase::Prepare);
    let mut claimed = Vec::new();
    let mut failed = None;
    // A started attempt includes admission failure. Expired work never reaches
    // this helper and therefore never fabricates a source failure acknowledgement.
    let admission = control.with_runtime_deadline(group.original_end, || {
        check_policy(control, policy)?;
        for &index in &group.roots {
            match observation_deadline_at(group.original_end, schedule.now()).and_then(|()| {
                admit(
                    control,
                    policy,
                    roots[index].selection,
                    &group.path,
                    &group.id,
                    group.original_end,
                )
            }) {
                Ok(_) => claimed.push(index),
                Err(error) => {
                    failed.get_or_insert(failure(&error));
                }
            }
        }
        #[cfg(test)]
        if let Some(reason) = failed {
            schedule
                .hooks
                .event(ScheduleTestEvent::AfterAdmissionFailure(
                    &group.id,
                    group.original_end,
                    reason,
                ))?;
        }
        Ok(())
    });
    // A trailing scope failure must not erase an admission failure already
    // observed for this input. Preserve its normal acknowledgement scope.
    if admission.is_err() && failed.is_some() {
        boot.remember_failure(
            cycle,
            if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
                FailureScope::Metadata(group.id.clone())
            } else {
                FailureScope::Source(group.id.clone())
            },
        );
    }
    admission?;
    if claimed.is_empty() || (revisit && claimed.len() != group.roots.len()) {
        let reason = failed.unwrap_or(BackgroundFailure::ScopeUnverified);
        let scope = if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
            FailureScope::Metadata(group.id.clone())
        } else {
            FailureScope::Source(group.id.clone())
        };
        boot.record_failure(cycle, scope, || {
            acknowledge_failure(
                control,
                authority,
                roots[group.roots[0]].selection,
                cycle,
                &group.id,
                reason,
            )
        })?;
        return Ok((
            ObservationOutcome::Attempted {
                published: false,
                claimed: claimed.into_iter().collect(),
                failed: Some(reason),
            },
            None,
        ));
    }
    let qualifying = claimed
        .iter()
        .copied()
        .filter(|index| {
            !inconsistent.contains(index)
                && roots[*index]
                    .discovery
                    .as_ref()
                    .is_ok_and(|discovery| discovery.complete)
        })
        .collect::<Vec<_>>();
    let pending = control
        .with_runtime_deadline(group.original_end, || {
            control.source_progress(&ControlId::parse(group.id.as_str())?)
        })?
        .and_then(|progress| progress.confirmation);
    let advisory = roots[advisory_selection(
        if qualifying.is_empty() {
            &claimed
        } else {
            &qualifying
        },
        roots,
        prior.map(|prior| prior.binding.root_identity.as_str()),
        pending
            .as_ref()
            .filter(|pending| matches!(pending.kind, ConfirmationKind::Rewrite { .. }))
            .map(|pending| pending.root_identity.as_str()),
    )]
    .selection;
    let claims = claimed
        .iter()
        .map(|&index| roots[index].selection)
        .collect::<Vec<_>>();
    let source = Discovered {
        path: group.path.clone(),
        id: group.id.clone(),
        hint: group.hint,
        descriptor: group.descriptor.clone(),
        original_end: group.original_end,
    };
    let result = control.with_runtime_deadline(group.original_end, || {
        observation_deadline_at(group.original_end, schedule.now())?;
        if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
            let observed = observe_workbuddy_metadata(
                db,
                control,
                authority,
                policy,
                advisory,
                &claims,
                cycle,
                incarnation,
                &source,
                prior,
            )?;
            metadata.insert(
                CanonicalLocator::from_path(&group.path)?.as_str().into(),
                observed,
            );
            Ok(SourceAttemptResult {
                current: true,
                successful: None,
            })
        } else if revisit && pending.is_some() {
            Err(changed())
        } else {
            observe_source(
                db,
                control,
                authority,
                policy,
                advisory,
                &claims,
                cycle,
                incarnation,
                &source,
                prior,
                boot,
                !qualifying.is_empty(),
                metadata,
                #[cfg(test)]
                &schedule.hooks,
            )
        }
    });
    match result {
        Ok(mut result) => {
            if let Some(success) = &mut result.successful {
                success.revisitable &= pending.is_none() && claimed.len() == group.roots.len();
            }
            Ok((
                ObservationOutcome::Attempted {
                    published: result.current,
                    claimed: claimed.into_iter().collect(),
                    failed: None,
                },
                result.successful,
            ))
        }
        Err(error) => {
            #[cfg(test)]
            schedule.hooks.event(ScheduleTestEvent::SourceFailed {
                id: &group.id,
                phase: schedule.hooks.source_phase.get(),
                error: &error,
                revisit,
                remaining: group.original_end.saturating_duration_since(Instant::now()),
            })?;
            let reason = failure(&error);
            let scope = if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
                FailureScope::Metadata(group.id.clone())
            } else {
                FailureScope::Source(group.id.clone())
            };
            boot.record_failure(cycle, scope, || {
                acknowledge_failure(control, authority, advisory, cycle, &group.id, reason)
            })?;
            Ok((
                ObservationOutcome::Attempted {
                    published: false,
                    claimed: claimed.into_iter().collect(),
                    failed: Some(reason),
                },
                None,
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn observe_missing_source(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    roots: &[RootState<'_>],
    cycle: &ObservationCycle,
    incarnation: &ControlId,
    source: &MissingSource<'_>,
    boot: &ObservationClock,
    metadata: &BTreeMap<String, WorkBuddyMetadata>,
    schedule: &SourceScheduleState,
) -> PortResult<ObservationOutcome> {
    let prior = source.prior;
    let locator = CanonicalLocator::parse(&prior.binding.source_path)?;
    let id = &prior.binding.source_id;
    let source_id = ControlId::parse(id.as_str())?;
    let mut claimed = Vec::new();
    let mut failed = None;
    let admission = control.with_runtime_deadline(source.original_end, || {
        check_policy(control, policy)?;
        for &index in &source.roots {
            let selection = roots[index].selection;
            match observation_deadline_at(source.original_end, schedule.now())
                .and_then(|()| verify_root(selection))
            {
                Ok(())
                    if selection.region.matches(prior.binding.provider, &locator)
                        && policy.allows_source(prior.binding.provider, &locator, &source_id) =>
                {
                    claimed.push(index);
                }
                Ok(()) => {
                    failed.get_or_insert(BackgroundFailure::ScopeUnverified);
                }
                Err(error) => {
                    failed.get_or_insert(failure(&error));
                }
            }
        }
        #[cfg(test)]
        if let Some(reason) = failed {
            schedule
                .hooks
                .event(ScheduleTestEvent::AfterAdmissionFailure(
                    id,
                    source.original_end,
                    reason,
                ))?;
        }
        Ok(())
    });
    if admission.is_err() && failed.is_some() {
        boot.remember_failure(cycle, FailureScope::Source(id.clone()));
    }
    admission?;
    let advisory = roots[if claimed.is_empty() {
        source.roots[0]
    } else {
        advisory_selection(
            &claimed,
            roots,
            Some(prior.binding.root_identity.as_str()),
            None,
        )
    }]
    .selection;
    let result = if claimed.is_empty() {
        Err(failed.unwrap_or(BackgroundFailure::ScopeUnverified))
    } else {
        let claims = claimed
            .iter()
            .map(|&index| roots[index].selection)
            .collect::<Vec<_>>();
        control
            .with_runtime_deadline(source.original_end, || {
                observation_deadline_at(source.original_end, schedule.now())?;
                observe_missing(
                    db,
                    control,
                    authority,
                    policy,
                    advisory,
                    &claims,
                    cycle,
                    incarnation,
                    prior,
                    boot,
                    metadata,
                    source.original_end,
                )
            })
            .map_err(|error| failure(&error))
    };
    let (published, failed) = match result {
        Ok(confirmed) => (
            confirmed,
            (!confirmed).then_some(BackgroundFailure::DeletionPending),
        ),
        Err(reason) => {
            boot.record_failure(cycle, FailureScope::Source(id.clone()), || {
                acknowledge_failure(control, authority, advisory, cycle, id, reason)
            })?;
            (false, Some(reason))
        }
    };
    Ok(ObservationOutcome::Attempted {
        published,
        claimed: claimed.into_iter().collect(),
        failed,
    })
}

#[allow(clippy::too_many_arguments)]
fn observe_cycle(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    selections: &[Selection],
    cycle: &ObservationCycle,
    boot: &ObservationClock,
    schedule: &mut SourceScheduleState,
) -> PortResult<bool> {
    let store = ManagedStore::open(db, control)?;
    let incarnation = store.incarnation().clone();
    let known = store
        .background_sources(control)?
        .into_iter()
        .map(|s| (s.binding.source_path.clone(), s))
        .collect::<BTreeMap<_, _>>();
    schedule.prepare(policy, &incarnation)?;
    drop(store);
    // Phase 1: fence and enumerate every participating root independently
    // before publishing any source claim.
    let mut roots = Vec::with_capacity(selections.len());
    for selection in selections {
        let original_end = Instant::now() + SOURCE_OBSERVATION_BUDGET;
        let revision = selection_revision(selection)?;
        control.with_runtime_deadline(original_end, || {
            let writer = ManagedStore::open_for_write(db, control)?;
            writer.begin_discovery_with_deadline(control, authority, cycle, &revision, original_end)
        })?;
        let discovery = control.with_runtime_deadline(original_end, || {
            discover(control, policy, selection, &known, original_end)
        });
        roots.push(RootState {
            selection,
            revision,
            discovery,
            original_end,
        });
    }
    // Group by SourceId: overlapping parent/child roots enumerate the same
    // locator and must resolve to one durable source.
    let mut shared = BTreeMap::<String, SharedSource>::new();
    for (index, root) in roots.iter().enumerate() {
        let Ok(discovery) = &root.discovery else {
            continue;
        };
        for file in &discovery.files {
            if !shared.contains_key(file.id.as_str()) && shared.len() >= MAX_DISCOVERY_PATHS {
                return Err(discovery_capacity());
            }
            match shared.entry(file.id.as_str().to_owned()) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let group = entry.get_mut();
                    group.roots.push(index);
                    group.original_end = group.original_end.min(file.original_end);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(SharedSource {
                        path: file.path.clone(),
                        id: file.id.clone(),
                        hint: file.hint,
                        roots: vec![index],
                        provider: root.selection.region.provider,
                        descriptor: file.descriptor.clone(),
                        original_end: file.original_end,
                    });
                }
            }
        }
    }
    // A complete enumeration that covers a source discovered by another root
    // contradicts itself; fail its coverage closed rather than omit evidence.
    let mut inconsistent = BTreeSet::<usize>::new();
    for (index, root) in roots.iter().enumerate() {
        let Ok(discovery) = &root.discovery else {
            continue;
        };
        if !discovery.complete {
            continue;
        }
        for group in shared.values() {
            if group.roots.contains(&index) {
                continue;
            }
            let locator = CanonicalLocator::from_path(&group.path)?;
            if root.selection.region.matches(group.provider, &locator) {
                inconsistent.insert(index);
                break;
            }
        }
    }
    // Phase 2: schedule shared locators with every independently validated
    // selection/root claim. Source revisits replace one final outcome.
    let descriptors = shared
        .values()
        .map(|source| source.descriptor.clone())
        .collect::<Vec<_>>();
    let preferred_indices = managed_source_discovery::authoritative_indices(&descriptors)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let shadowed = shared
        .values()
        .enumerate()
        .filter(|(index, _)| !preferred_indices.contains(index))
        .map(|(_, source)| source.id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    // Metadata prerequisites remain globally first. Only the source service
    // order changes; authority filtering and every selected claim stay intact.
    let missing = missing_sources(&known, &shared, &roots)?;
    if roots
        .iter()
        .all(|root| root.discovery.as_ref().is_ok_and(|d| d.complete))
    {
        schedule.sources.retain(|id, _| {
            (shared.contains_key(id.as_str()) && !shadowed.contains(id.as_str()))
                || missing.contains_key(id)
        });
    }
    let mut scheduler = CycleSchedule::new(schedule);
    for group in shared
        .values()
        .filter(|source| !shadowed.contains(source.id.as_str()))
    {
        let prior = group.path.to_str().and_then(|path| known.get(path));
        let published = published_baseline(prior);
        let lane = if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
            SourceLane::Metadata
        } else if published {
            SourceLane::Verification
        } else {
            SourceLane::Cold
        };
        scheduler.add(
            &group.id,
            prior,
            lane,
            group.original_end,
            published && lane != SourceLane::Metadata,
        )?;
        if published && lane != SourceLane::Metadata {
            scheduler.hint(&group.id, group.hint, prior.and_then(|p| p.indexed_len));
        }
    }
    for (id, source) in &missing {
        scheduler.add(
            id,
            Some(source.prior),
            SourceLane::Verification,
            source.original_end,
            false,
        )?;
    }
    let mut metadata = BTreeMap::<String, WorkBuddyMetadata>::new();
    let mut outcomes = BTreeMap::<String, ObservationOutcome>::new();
    let mut absent = BTreeMap::<String, ObservationOutcome>::new();
    let mut baselines = BTreeMap::<SourceId, BackgroundSource>::new();
    #[cfg(test)]
    scheduler.state.hooks.event(ScheduleTestEvent::Planned)?;
    loop {
        let now = scheduler.state.now();
        for id in scheduler.probe_batch(now) {
            let group = shared.get(id.as_str()).ok_or_else(invalid)?;
            #[cfg(test)]
            scheduler
                .state
                .hooks
                .event(ScheduleTestEvent::BeforeProbe(&id, group.original_end))?;
            // Failed probes neither establish absence nor consume a dirty hint.
            // Re-admit an exact selected path before even reading its metadata.
            if let Ok(hint) = probe_source_hint(control, policy, &roots, group, scheduler.state) {
                let prior = baselines
                    .get(&id)
                    .or_else(|| group.path.to_str().and_then(|path| known.get(path)));
                scheduler.hint(&id, hint, prior.and_then(|prior| prior.indexed_len));
            }
        }
        let Some(turn) = scheduler.next(scheduler.state.now()) else {
            break;
        };
        let (id, lane) = match turn {
            ScheduledTurn::NotScheduled(id) => {
                let covering = if let Some(source) = missing.get(&id) {
                    &source.roots
                } else {
                    &shared[id.as_str()].roots
                };
                // Retiring unstarted work is already an observation gap. Save
                // every affected root before another source or root can fail.
                for &index in covering {
                    let root = &roots[index];
                    let complete = !inconsistent.contains(&index)
                        && root
                            .discovery
                            .as_ref()
                            .is_ok_and(|discovery| discovery.complete);
                    boot.remember_failure(
                        cycle,
                        FailureScope::Root {
                            selection: root.selection.clone(),
                            confirmations: root_failure_confirmations(complete),
                        },
                    );
                }
                boot.check_capacity()?;
                if missing.contains_key(&id) {
                    absent.insert(id.as_str().into(), ObservationOutcome::NotScheduled);
                } else {
                    outcomes.insert(id.as_str().into(), ObservationOutcome::NotScheduled);
                }
                #[cfg(test)]
                scheduler
                    .state
                    .hooks
                    .event(ScheduleTestEvent::AfterNotScheduled(&id))?;
                continue;
            }
            ScheduledTurn::Attempt(id, lane) => (id, lane),
        };
        #[cfg(test)]
        scheduler
            .state
            .hooks
            .event(ScheduleTestEvent::BeforeAttempt(
                &id,
                scheduler.turns[&id].original_end,
                lane,
            ))?;
        // Time can expire during a preceding probe or scheduling boundary. The
        // unstarted item must retire without admission or failure acknowledgement.
        if scheduler.state.now() >= scheduler.turns[&id].original_end {
            continue;
        }
        scheduler.started(&id, lane)?;
        if let Some(source) = missing.get(&id) {
            let outcome = observe_missing_source(
                db,
                control,
                authority,
                policy,
                &roots,
                cycle,
                &incarnation,
                source,
                boot,
                &metadata,
                scheduler.state,
            )?;
            absent.insert(id.as_str().into(), outcome);
        } else {
            let group = shared.get(id.as_str()).ok_or_else(invalid)?;
            let prior = baselines
                .get(&id)
                .or_else(|| group.path.to_str().and_then(|path| known.get(path)));
            let revisit = outcomes.contains_key(id.as_str());
            let (outcome, success) = observe_shared_source(
                db,
                control,
                authority,
                policy,
                &roots,
                &inconsistent,
                cycle,
                &incarnation,
                group,
                prior,
                revisit,
                boot,
                &mut metadata,
                scheduler.state,
            )?;
            if let Some(success) = success {
                scheduler.succeeded(&id, &success);
                baselines.insert(id.clone(), success.baseline);
            }
            outcomes.insert(id.as_str().into(), outcome);
        }
        #[cfg(test)]
        scheduler
            .state
            .hooks
            .event(ScheduleTestEvent::AfterAttempt(&id, lane))?;
    }
    #[cfg(test)]
    scheduler.state.hooks.event(ScheduleTestEvent::Finalizing)?;
    // Phase 3: complete each root's discovery separately from the one shared
    // source observation.
    let mut all_complete = true;
    for (index, root) in roots.iter().enumerate() {
        check_policy(control, policy)?;
        let selection = root.selection;
        let revision = root.revision.clone();
        let mut error = None;
        let mut observed = 0_u64;
        let mut committed = 0_u64;
        let mut ids = Vec::new();
        let mut count = 0_u64;
        let mut complete = false;
        let mut observations_clean = true;
        let mut has_covered_authority_shadow = false;
        if let Ok(discovery) = &root.discovery {
            complete = discovery.complete && !inconsistent.contains(&index);
            let seen = discovery
                .files
                .iter()
                .map(|source| source.path.clone())
                .collect::<BTreeSet<_>>();
            for source in &discovery.files {
                if shadowed.contains(source.id.as_str()) {
                    // Suppressed physical copies cannot publish independent
                    // receipts. A root that also covers the selected active
                    // representation can still prove logical completeness.
                    // An exact/lower-only root stays partial, never falsely empty.
                    let active_here = discovery.files.iter().any(|candidate| {
                        !shadowed.contains(candidate.id.as_str())
                            && candidate.descriptor.surface == source.descriptor.surface
                            && candidate.descriptor.native_session
                                == source.descriptor.native_session
                    });
                    has_covered_authority_shadow |= !active_here;
                    continue;
                }
                ids.push(source.id.clone());
                count += 1;
                let outcome = outcomes.get(source.id.as_str()).ok_or_else(changed)?;
                match outcome {
                    ObservationOutcome::NotScheduled => {
                        observations_clean = false;
                        error.get_or_insert(BackgroundFailure::Deferred);
                    }
                    ObservationOutcome::Attempted {
                        published,
                        claimed,
                        failed,
                    } => {
                        if claimed.contains(&index) {
                            observed += 1;
                            if *published {
                                committed += 1;
                            } else {
                                observations_clean = false;
                                error.get_or_insert(failed.unwrap_or(BackgroundFailure::Deferred));
                            }
                        } else {
                            observations_clean = false;
                            error.get_or_insert(
                                failed.unwrap_or(BackgroundFailure::ScopeUnverified),
                            );
                        }
                    }
                }
            }
            if has_covered_authority_shadow {
                observations_clean = false;
                error.get_or_insert(BackgroundFailure::Deferred);
            }
            if selection.region.kind == RootKind::Root
                && selection.region.provider.as_str() == "workbuddy"
            {
                for auxiliary in metadata.values() {
                    let projects = auxiliary
                        .source
                        .descriptor
                        .surface
                        .as_ref()
                        .map(|surface| surface.join("projects"))
                        .map(|path| CanonicalLocator::from_path(&path))
                        .transpose()?;
                    if projects.as_ref().is_some_and(|projects| {
                        selection
                            .region
                            .matches(selection.region.provider, projects)
                    }) && auxiliary.states.iter().any(|(native, state)| match state {
                        LifecycleState::ActiveLocal => !auxiliary
                            .observed_natives
                            .borrow()
                            .iter()
                            .any(|observed| observed.as_str() == native),
                        LifecycleState::CloudUnavailable | LifecycleState::OrphanUnknown => true,
                        LifecycleState::SoftDeleted => false,
                    }) {
                        observations_clean = false;
                        error.get_or_insert(BackgroundFailure::Deferred);
                    }
                }
            }
            if complete {
                for prior in known.values() {
                    let id = prior.binding.source_id.as_str();
                    if prior.superseded || shared.contains_key(id) {
                        continue;
                    }
                    let old = managed_source_discovery::describe(
                        prior.binding.provider,
                        Path::new(&prior.binding.source_path),
                        false,
                    );
                    if old.as_ref().is_some_and(|old| {
                        old.surface.is_some()
                            && old.native_session.is_some()
                            && shared.values().any(|current| {
                                current.provider == prior.binding.provider
                                    && current.descriptor.surface == old.surface
                                    && current.descriptor.native_session == old.native_session
                            })
                    }) {
                        continue;
                    }
                    let locator = CanonicalLocator::parse(&prior.binding.source_path)?;
                    if !selection.region.matches(prior.binding.provider, &locator) {
                        continue;
                    }
                    if seen.contains(Path::new(&prior.binding.source_path)) {
                        continue;
                    }
                    count += 1;
                    ids.push(prior.binding.source_id.clone());
                    match absent.get(id) {
                        Some(ObservationOutcome::Attempted {
                            published,
                            claimed,
                            failed,
                        }) if claimed.contains(&index) => {
                            observed += 1;
                            if *published {
                                committed += 1;
                            } else {
                                error.get_or_insert(
                                    failed.unwrap_or(BackgroundFailure::DeletionPending),
                                );
                            }
                        }
                        Some(ObservationOutcome::Attempted { failed, .. }) => {
                            observations_clean = false;
                            error.get_or_insert(
                                failed.unwrap_or(BackgroundFailure::ScopeUnverified),
                            );
                        }
                        Some(ObservationOutcome::NotScheduled) => {
                            observations_clean = false;
                            error.get_or_insert(BackgroundFailure::Deferred);
                        }
                        None => {
                            // Another covering root could not prove this absence.
                            complete = false;
                            error.get_or_insert(BackgroundFailure::Deferred);
                        }
                    }
                }
            }
        } else if let Err(discovery_error) = &root.discovery {
            error = Some(failure(discovery_error));
        }
        if !complete
            || !observations_clean
            || error.is_some_and(|e| {
                !matches!(
                    e,
                    BackgroundFailure::DeletionPending
                        | BackgroundFailure::RewritePending
                        | BackgroundFailure::Deferred
                )
            })
        {
            // Observation gaps invalidate a confirmation chain. In particular,
            // an offline root cannot carry a deletion clock across the gap, and
            // it must not clear another root's chain either.
            let own_root = selection.root_identity.clone().ok_or_else(invalid)?;
            for prior in known.values() {
                if prior.superseded {
                    continue;
                }
                if selection.region.matches(
                    prior.binding.provider,
                    &CanonicalLocator::parse(&prior.binding.source_path)?,
                ) {
                    if matches!(
                        outcomes
                            .get(prior.binding.source_id.as_str())
                            .or_else(|| absent.get(prior.binding.source_id.as_str())),
                        Some(ObservationOutcome::NotScheduled)
                    ) {
                        continue;
                    }
                    let source_id = ControlId::parse(prior.binding.source_id.as_str())?;
                    let root_identity = own_root.clone();
                    record_root_failure(
                        boot,
                        cycle,
                        selection.clone(),
                        root_failure_confirmations(complete),
                        || {
                            let held = control
                                .source_progress(&source_id)?
                                .and_then(|progress| progress.confirmation);
                            let matches_root = !held
                                .as_ref()
                                .is_some_and(|held| held.root_identity != root_identity);
                            let matches_kind = !complete
                                || held.as_ref().is_some_and(|held| {
                                    matches!(held.kind, ConfirmationKind::Deletion)
                                });
                            Ok(matches_root && matches_kind)
                        },
                        || {
                            acknowledge_failure(
                                control,
                                authority,
                                selection,
                                cycle,
                                &prior.binding.source_id,
                                error.unwrap_or(BackgroundFailure::Deferred),
                            )
                        },
                    )?;
                }
            }
        }
        if complete && error.is_none() && committed == count {
            observation_deadline_at(root.original_end, scheduler.state.now())?;
            verify_root(selection)?;
            // Re-enumeration detects a new/removed candidate while earlier
            // sources were being parsed; no heartbeat substitutes for this proof.
            let final_set = control.with_runtime_deadline(root.original_end, || {
                discover(control, policy, selection, &known, root.original_end)
            })?;
            let expected: BTreeSet<_> = root
                .discovery
                .as_ref()
                .map_err(|_| changed())?
                .files
                .iter()
                .map(|file| file.id.clone())
                .collect();
            let actual: BTreeSet<_> = final_set.files.into_iter().map(|f| f.id).collect();
            if !final_set.complete || expected != actual {
                complete = false;
                error = Some(BackgroundFailure::SourceChanged);
            } else {
                let result = control.with_runtime_deadline(root.original_end, || {
                    let writer = ManagedStore::open_for_write(db, control)?;
                    writer.commit_discovery_with_deadline(
                        control,
                        authority,
                        cycle,
                        &revision,
                        &ids,
                        root.original_end,
                    )
                });
                if let Err(write_error) = result {
                    error = Some(failure(&write_error));
                }
            }
        }
        if !complete && error.is_none() {
            error = Some(BackgroundFailure::Deferred);
        }
        let ack = DiscoveryAcknowledgement {
            token: cycle.token.clone(),
            selection: revision,
            complete: complete && error.is_none(),
            discovered_count: count,
            observed_count: observed,
            committed_count: committed,
            error,
        };
        all_complete &= ack.complete && ack.committed_count == ack.discovered_count;
        control_change(control, |seq| {
            control.acknowledge_discovery(seq, authority, ack.clone())
        })?;
    }
    Ok(all_complete)
}

fn acknowledge_failure(
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    selection: &Selection,
    cycle: &ObservationCycle,
    id: &SourceId,
    error: BackgroundFailure,
) -> PortResult<()> {
    let ack = SourceAcknowledgement {
        source_id: ControlId::parse(id.as_str())?,
        provider: selection.region.provider,
        token: cycle.token.clone(),
        selection: selection_revision(selection)?,
        attempted_at_ms: app_clock_ms(),
        coverage: Coverage::Partial,
        update_state: UpdateState::Deferred,
        backfill_state: BackfillState::Pending,
        error: Some(error),
        receipt: None,
        confirmation: None,
    };
    control_change(control, |seq| {
        control.acknowledge_source(seq, authority, ack.clone())
    })?;
    Ok(())
}

fn observation(
    binding: SourceBinding,
    incarnation: &ControlId,
    cycle: &ObservationCycle,
    claims: &[&Selection],
    digest: &str,
    state: ObservationState,
) -> PortResult<SourceObservation> {
    let locator = CanonicalLocator::parse(&binding.source_path)?;
    let mut selections = Vec::with_capacity(claims.len());
    for claim in claims {
        // Every claim was independently validated for this locator and root.
        // The selection revision pins that root, so a changed control policy
        // fails closed instead of reusing another root's proof.
        if !claim.enabled
            || !claim.region.matches(binding.provider, &locator)
            || !claim.root_identity.as_ref().is_some_and(|root| {
                cycle.selections.iter().any(|current| {
                    current.selection.selection_id == claim.id
                        && current.selection.revision == claim.revision
                        && &current.selection.root_identity == root
                })
            })
        {
            return Err(changed());
        }
        selections.push(SelectionProof {
            selection_id: claim.id.as_str().into(),
            selection_revision: claim.revision.get(),
            root_identity: claim
                .root_identity
                .as_ref()
                .ok_or_else(invalid)?
                .as_str()
                .into(),
        });
    }
    if selections.is_empty() {
        return Err(changed());
    }
    Ok(SourceObservation {
        binding,
        revision_id: RevisionId::parse(fresh_id("revision")?.as_str())?,
        revision_digest: digest.into(),
        parser_version: PARSER_SEMANTIC_VERSION,
        state,
        cycle_seq: cycle.token.cycle_seq.get(),
        worker_boot_id: cycle.token.worker_boot_id.as_str().into(),
        catalog_incarnation: incarnation.as_str().into(),
        policy_epoch: cycle.policy_epoch.get(),
        started_control_seq: cycle.started_control_seq.ok_or_else(invalid)?.get(),
        observed_at_ms: app_clock_ms(),
        committed_at_ms: app_clock_ms(),
        selections,
        repositories: Vec::new(),
    })
}

fn empty_batch(path: &str, provider: SearchProvider, snapshot: &SourceSnapshot) -> SourceBatch {
    let mut batch = crate::empty_source_batch(path, &snapshot.fingerprint, Some(provider.as_str()));
    batch.len_bytes = i64::try_from(snapshot.len).ok();
    batch
}

fn confirmation(
    control: &SqliteControlStore,
    source: ConfirmationSource<'_>,
    selection: &Selection,
    cycle: &ObservationCycle,
    kind: ConfirmationKind,
    boot: &ObservationClock,
) -> PortResult<(PendingConfirmation, bool)> {
    boot.check_capacity()?;
    let now = i64::try_from(boot.started.elapsed().as_millis()).map_err(|_| invalid())?;
    let root = selection.root_identity.clone().ok_or_else(invalid)?;
    let prior = control
        .source_progress(&ControlId::parse(source.id.as_str())?)?
        .and_then(|p| p.confirmation);
    if let Some(mut prior) = prior.filter(|p| {
        p.kind == kind
            && p.worker_boot_id == cycle.token.worker_boot_id
            && p.root_identity == root
            && p.policy_epoch == cycle.policy_epoch
            && p.first_cycle < cycle.token.cycle_seq
            && p.first_monotonic_ms.get() <= now
    }) {
        let first = control.cycle(prior.first_cycle)?;
        let interrupted = boot
            .lost_after(&source, selection, &kind, cycle.policy_epoch)
            .is_some_and(|lost| prior.first_cycle <= lost)
            || first.state == CycleState::Aborted
            || first
                .selections
                .iter()
                .find(|s| s.selection.selection_id == selection.id)
                .is_none_or(|s| s.selection.revision != selection.revision);
        if interrupted {
            return Ok((
                PendingConfirmation {
                    kind,
                    first_cycle: cycle.token.cycle_seq,
                    confirm_cycle: None,
                    worker_boot_id: cycle.token.worker_boot_id.clone(),
                    root_identity: root,
                    policy_epoch: cycle.policy_epoch,
                    first_monotonic_ms: ControlSeq::new(now)?,
                },
                false,
            ));
        }
        let ready = now - prior.first_monotonic_ms.get() >= CONFIRMATION_MS;
        // Every acknowledgement must bind the current observation token, even
        // when the grace period is still running.
        prior.confirm_cycle = Some(cycle.token.cycle_seq);
        return Ok((prior, ready));
    }
    Ok((
        PendingConfirmation {
            kind,
            first_cycle: cycle.token.cycle_seq,
            confirm_cycle: None,
            worker_boot_id: cycle.token.worker_boot_id.clone(),
            root_identity: root,
            policy_epoch: cycle.policy_epoch,
            first_monotonic_ms: ControlSeq::new(now)?,
        },
        false,
    ))
}

#[allow(clippy::too_many_arguments)]
fn observe_source(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    advisory: &Selection,
    claims: &[&Selection],
    cycle: &ObservationCycle,
    incarnation: &ControlId,
    source: &Discovered,
    prior: Option<&BackgroundSource>,
    boot: &ObservationClock,
    discovery_complete: bool,
    metadata: &BTreeMap<String, WorkBuddyMetadata>,
    #[cfg(test)] hooks: &ScheduleTestHooks,
) -> PortResult<SourceAttemptResult> {
    let end = source.original_end;
    let input_limit = source.descriptor.kind.max_input_bytes();
    observation_deadline(end)?;
    let locator = admit(control, policy, advisory, &source.path, &source.id, end)?;
    let snapshot = capture_with_deadline(&source.path, input_limit, end)?;
    admit(control, policy, advisory, &source.path, &source.id, end)?;
    let content = open_snapshot_source_with_deadline(&source.path, &snapshot, input_limit, end)?;
    let mut state = ObservationState::Complete;
    let mut pending = None;
    if content.is_empty() {
        state = ObservationState::RewritePending;
    } else if matches!(source.descriptor.kind, SourceKind::DeepSeekHarness { version }
        if version != agent_session_grep_provider_dsh::SESSION_FORMAT_VERSION)
    {
        // Filename/header generation agreement is part of native authority.
        // A supported header in a future-generation filename cannot fall back.
        state = ObservationState::Incomplete;
    }
    admit(control, policy, advisory, &source.path, &source.id, end)?;
    let mut parsed = if state == ObservationState::Complete {
        let parsed =
            crate::managed_source_parse::stage(advisory.region.provider.as_str(), &content, end)
                .map_err(|error| {
                    if Instant::now() >= end {
                        PortError::WriterBusy("managed source observation deadline reached".into())
                    } else {
                        match error {
                            agent_session_grep_application::AppError::Port(error) => error,
                            agent_session_grep_application::AppError::Provider(
                                agent_session_grep_ports::ProviderError::SourceChangedDuringRead(_),
                            ) => changed(),
                            agent_session_grep_application::AppError::Provider(
                                agent_session_grep_ports::ProviderError::Io(_),
                            ) => unavailable(),
                            _ => invalid(),
                        }
                    }
                })?;
        if !parsed.completeness.is_complete() {
            state = ObservationState::Incomplete;
        }
        Some((parsed.staged, parsed.variant_id))
    } else {
        None
    };
    let previous_context = if let Some(receipt) = prior.and_then(|p| p.latest_receipt.as_ref()) {
        ManagedStore::open(db, control)?.publication_context(control, receipt, end)?
    } else {
        SourcePublicationContext::default()
    };
    let mut context = previous_context.clone();
    let mut metadata_key = None;
    let mut soft_deleted = false;
    if advisory.region.provider.as_str() == "workbuddy" {
        (context, metadata_key) = workbuddy_context(
            control,
            policy,
            &source.descriptor,
            parsed.as_ref().map(|(staged, _)| staged),
            &previous_context,
            metadata,
            end,
        )?;
        soft_deleted = !context.dependencies.is_empty() && context.dependencies.iter().all(|d|
            matches!(&d.resolution, DependencyResolution::Resolved(proof) if proof.state == LifecycleState::SoftDeleted));
        if soft_deleted {
            let mut hash = Sha256::new();
            for dependency in &context.dependencies {
                if let DependencyResolution::Resolved(proof) = &dependency.resolution {
                    hash.update(dependency.native_session.as_str().as_bytes());
                    hash.update(proof.state_digest.as_str().as_bytes());
                }
            }
            let candidate_digest = ControlId::parse(&format!("metadata_{}", hex(&hash.finalize())))?;
            let already_deleted = prior.and_then(|prior| prior.latest_receipt.as_ref())
                .is_some_and(|receipt| receipt.published)
                && previous_context.dependencies.len() == context.dependencies.len()
                && previous_context.dependencies.iter().zip(&context.dependencies).all(|(previous, current)| {
                    previous.native_session == current.native_session
                        && matches!((&previous.resolution, &current.resolution),
                            (DependencyResolution::Resolved(previous), DependencyResolution::Resolved(current))
                                if previous.state == LifecycleState::SoftDeleted
                                    && previous.state_digest == current.state_digest)
                });
            let (candidate, stable) = confirmation(control, ConfirmationSource {
                id: &source.id, locator: &locator, contexts: &[&previous_context, &context],
            }, advisory, cycle,
                ConfirmationKind::Rewrite { candidate_digest }, boot)?;
            if (stable || already_deleted) && discovery_complete {
                state = ObservationState::Complete;
                pending = None;
            } else {
                state = ObservationState::RewritePending;
                pending = Some(candidate);
            }
        } else if prior.is_some() && context.dependencies.iter().any(|d|
            !matches!(&d.resolution, DependencyResolution::Resolved(proof) if proof.state == LifecycleState::ActiveLocal))
        {
            // Metadata uncertainty cannot shrink/replace existing originals.
            state = ObservationState::Incomplete;
            pending = None;
        }
    }
    let surface = authority_surface(
        control,
        policy,
        advisory.region.provider,
        &source.descriptor,
        end,
    )?;
    let native = parsed
        .as_mut()
        .map(|(staged, _)| verified_native_session(staged, &source.descriptor))
        .transpose()?
        .flatten();
    let changed_known = prior
        .and_then(|p| p.latest_receipt.as_ref())
        .is_some_and(|r| r.digest != snapshot.fingerprint);
    let append = if source.descriptor.kind.is_jsonl()
        && state == ObservationState::Complete
        && changed_known
    {
        admit(control, policy, advisory, &source.path, &source.id, end)?;
        verified_append(&content, &snapshot, prior, end)?
    } else {
        false
    };
    if !soft_deleted
        && (state == ObservationState::RewritePending
            || (state == ObservationState::Complete && changed_known && !append))
    {
        // The advisory root alone carries the confirmation clock, so rotation
        // between overlapping roots cannot restart the grace period.
        let (candidate, stable) = confirmation(
            control,
            ConfirmationSource {
                id: &source.id,
                locator: &locator,
                contexts: &[&previous_context, &context],
            },
            advisory,
            cycle,
            ConfirmationKind::Rewrite {
                candidate_digest: ControlId::parse(&format!(
                    "digest_{}",
                    hex(&Sha256::digest(snapshot.fingerprint.as_bytes()))
                ))?,
            },
            boot,
        )?;
        // A nonempty, fully parsed shrink is a replacement candidate just like
        // an equal-length rewrite. Distinct verified observations and the
        // monotonic grace establish publication eligibility; byte length never
        // makes an otherwise complete candidate permanently ineligible.
        if stable
            && discovery_complete
            && !content.is_empty()
            && state == ObservationState::Complete
        {
            pending = None;
        } else {
            state = ObservationState::RewritePending;
            pending = Some(candidate);
        }
    }
    // The binding root stays historical evidence; each overlapping selection
    // keeps its own independently validated root in the receipt claim.
    let binding = prior.map(|p| p.binding.clone()).unwrap_or(SourceBinding {
        source_id: source.id.clone(),
        source_path: locator.as_str().into(),
        provider: advisory.region.provider,
        namespace_id: None,
        root_identity: advisory
            .root_identity
            .as_ref()
            .ok_or_else(invalid)?
            .as_str()
            .into(),
    });
    let mut observation = observation(
        binding,
        incarnation,
        cycle,
        claims,
        &snapshot.fingerprint,
        state,
    )?;
    admit(control, policy, advisory, &source.path, &source.id, end)?;
    verify_snapshot_with_deadline(&source.path, &snapshot, input_limit, end)?;
    let writer = ManagedStore::open_for_write(db, control)?;
    let namespace = if let Some(surface) = &surface {
        writer.reserve_namespace_for_surface(
            control,
            &observation,
            authority,
            &surface.root,
            &surface.identity,
            end,
        )?
    } else {
        writer.reserve_namespace(
            control,
            &observation,
            authority,
            &crate::installation_namespace(locator.as_str(), advisory.region.provider.as_str()),
        )?
    };
    observation.binding.namespace_id = Some(namespace.namespace_id);
    let batch = if !soft_deleted && let Some((staged, variant)) = &parsed {
        crate::staged_to_source_with_provider_namespace(
            locator.as_str(),
            staged,
            advisory.region.provider.as_str(),
            variant,
            &snapshot.fingerprint,
            snapshot.len,
            Some(advisory.region.provider.as_str()),
            Some(&namespace.input),
        )
        .map_err(|_| invalid())?
    } else {
        empty_batch(locator.as_str(), advisory.region.provider, &snapshot)
    };
    if let (Some(surface), Some(native)) = (&surface, native) {
        let canonical = StableId::native_session_scoped(
            &SessionIdentityNamespace {
                provider_id: advisory.region.provider.as_str(),
                installation_namespace: &namespace.input,
            },
            native.as_str(),
        );
        let key = SourceAuthorityKey {
            provider: advisory.region.provider,
            surface_id: surface.id.clone(),
            surface_root: surface.root.clone(),
            surface_identity: surface.identity.clone(),
            native_session: native,
            session_id: canonical,
        };
        let expected_prior = writer.authority_prior(control, &key, end)?;
        if expected_prior
            .as_ref()
            .is_some_and(|old| old.binding.source_id != source.id)
        {
            let old = expected_prior.as_ref().ok_or_else(invalid)?;
            let old_descriptor = managed_source_discovery::describe(
                old.binding.provider,
                Path::new(&old.binding.source_path),
                false,
            )
            .ok_or_else(invalid)?;
            let fallback = matches!(source.descriptor.kind, SourceKind::AntigravityDatabase)
                && matches!(old_descriptor.kind, SourceKind::AntigravityFull)
                || matches!((source.descriptor.kind, old_descriptor.kind),
                    (SourceKind::DeepSeekHarness { version: current }, SourceKind::DeepSeekHarness { version: previous }) if current < previous);
            if fallback {
                if !matches!(std::fs::symlink_metadata(&old.binding.source_path), Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err(changed());
                }
                let digest = ControlId::parse(&format!(
                    "absent_{}",
                    hex(&Sha256::digest(old.receipt.revision_id.as_str().as_bytes()))
                ))?;
                let (candidate, stable) = confirmation(
                    control,
                    ConfirmationSource {
                        id: &source.id,
                        locator: &locator,
                        contexts: &[&previous_context, &context],
                    },
                    advisory,
                    cycle,
                    ConfirmationKind::Rewrite {
                        candidate_digest: digest,
                    },
                    boot,
                )?;
                if !stable || !discovery_complete {
                    state = ObservationState::RewritePending;
                    pending = Some(candidate);
                    observation.state = state;
                }
            }
        }
        context.authority = Some(SourceAuthorityTransition {
            key,
            expected_prior,
        });
    } else if let Some(transition) = &mut context.authority {
        transition.expected_prior = writer.authority_prior(control, &transition.key, end)?;
    }
    context.validate()?;
    admit(control, policy, advisory, &source.path, &source.id, end)?;
    verify_snapshot_with_deadline(&source.path, &snapshot, input_limit, end)?;
    if let Some(key) = &metadata_key {
        metadata
            .get(key)
            .ok_or_else(changed)?
            .verify(control, policy, end)?;
    }
    if let Some(surface) = &surface {
        let verified = authority_surface(
            control,
            policy,
            advisory.region.provider,
            &source.descriptor,
            end,
        )?
        .ok_or_else(changed)?;
        if verified.root != surface.root
            || verified.identity != surface.identity
            || verified.id != surface.id
        {
            return Err(changed());
        }
    }
    // One shared publication carries every independently validated root claim.
    for claim in claims {
        admit(control, policy, claim, &source.path, &source.id, end)?;
    }
    observation_deadline(end)?;
    observation.committed_at_ms = app_clock_ms();
    #[cfg(test)]
    hooks.source_phase.set(SourceAttemptPhase::Publication);
    let publication = writer.commit_source_with_context(
        control,
        authority,
        &batch,
        &observation,
        &context,
        end,
    )?;
    #[cfg(test)]
    hooks.event(ScheduleTestEvent::Published(&source.id, end))?;
    #[cfg(test)]
    hooks.source_phase.set(SourceAttemptPhase::Currentness);
    let current = publication.receipt.published
        && writer.source_current(&publication.receipt, control, end)?;
    drop(writer);
    #[cfg(test)]
    hooks.source_phase.set(SourceAttemptPhase::Acknowledgement);
    observation_deadline(end)?;
    acknowledge(
        control,
        authority,
        advisory,
        cycle,
        &source.id,
        &publication,
        if publication.receipt.published && !current {
            ObservationState::Incomplete
        } else {
            state
        },
        pending,
    )?;
    Ok(SourceAttemptResult {
        current,
        successful: current.then(|| SuccessfulSourceAttempt {
            baseline: BackgroundSource {
                binding: observation.binding,
                latest_receipt: Some(publication.receipt),
                indexed_len: Some(snapshot.len),
                superseded: false,
            },
            // This is the captured observation, never a later filesystem stat.
            hint: SourceHint::from_snapshot(&snapshot),
            revisitable: source.descriptor.kind == SourceKind::Jsonl
                && matches!(advisory.region.provider.as_str(), "claude-code" | "codex")
                && context.dependencies.is_empty()
                && context.authority.is_none()
                && surface.is_none(),
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn observe_missing(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    advisory: &Selection,
    claims: &[&Selection],
    cycle: &ObservationCycle,
    incarnation: &ControlId,
    prior: &BackgroundSource,
    boot: &ObservationClock,
    metadata: &BTreeMap<String, WorkBuddyMetadata>,
    end: Instant,
) -> PortResult<bool> {
    observation_deadline(end)?;
    // A confirmed absent receipt represents an already empty source. Keep its
    // absence verified without restarting the destructive-confirmation clock.
    let already_absent = prior
        .latest_receipt
        .as_ref()
        .is_some_and(|r| r.published && r.digest == "confirmed_absent");
    verify_root(advisory)?;
    check_policy(control, policy)?;
    let path = Path::new(&prior.binding.source_path);
    let locator = CanonicalLocator::parse(&prior.binding.source_path)?;
    // A missing intermediate directory is ambiguous. Validate every parent;
    // only a missing final regular-file entry is deletion evidence.
    let parent = path.parent().ok_or_else(invalid)?;
    for claim in claims {
        verify_root(claim)?;
        crate::managed_control::source_selection(claim.region.provider, parent)
            .map_err(|_| unavailable())?;
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Ok(_) => return Err(changed()),
        Err(_) => return Err(unavailable()),
    }
    let reader = ManagedStore::open(db, control)?;
    let mut context = prior
        .latest_receipt
        .as_ref()
        .map(|receipt| reader.publication_context(control, receipt, end))
        .transpose()?
        .unwrap_or_default();
    drop(reader);
    let previous_context = context.clone();
    let mut metadata_key = None;
    let candidate_kind = if prior.binding.provider.as_str() == "workbuddy" {
        let descriptor = managed_source_discovery::describe(prior.binding.provider, path, true)
            .ok_or_else(invalid)?;
        if descriptor.kind == SourceKind::WorkBuddyMetadata {
            return Err(unavailable());
        }
        (context, metadata_key) =
            workbuddy_context(control, policy, &descriptor, None, &context, metadata, end)?;
        if !context.dependencies.iter().all(|d| {
            matches!(&d.resolution,
            DependencyResolution::Resolved(proof) if proof.state == LifecycleState::SoftDeleted)
        }) {
            return Err(unavailable());
        }
        let mut hash = Sha256::new();
        for d in &context.dependencies {
            if let DependencyResolution::Resolved(proof) = &d.resolution {
                hash.update(d.native_session.as_str().as_bytes());
                hash.update(proof.state_digest.as_str().as_bytes());
            }
        }
        ConfirmationKind::Rewrite {
            candidate_digest: ControlId::parse(&format!("metadata_{}", hex(&hash.finalize())))?,
        }
    } else {
        ConfirmationKind::Deletion
    };
    let (candidate, confirmed) = confirmation(
        control,
        ConfirmationSource {
            id: &prior.binding.source_id,
            locator: &locator,
            contexts: &[&previous_context, &context],
        },
        advisory,
        cycle,
        candidate_kind.clone(),
        boot,
    )?;
    let confirmed = confirmed || already_absent;
    let state = if confirmed {
        ObservationState::Complete
    } else if matches!(candidate_kind, ConfirmationKind::Rewrite { .. }) {
        ObservationState::RewritePending
    } else {
        ObservationState::DeletionPending
    };
    let snapshot = SourceSnapshot {
        path: prior.binding.source_path.clone(),
        len: 0,
        mtime_ms: 0,
        fingerprint: "confirmed_absent".into(),
    };
    let mut observation = observation(
        prior.binding.clone(),
        incarnation,
        cycle,
        claims,
        &snapshot.fingerprint,
        state,
    )?;
    let writer = ManagedStore::open_for_write(db, control)?;
    let namespace = writer.reserve_namespace(
        control,
        &observation,
        authority,
        &crate::installation_namespace(
            &prior.binding.source_path,
            advisory.region.provider.as_str(),
        ),
    )?;
    observation.binding.namespace_id = Some(namespace.namespace_id);
    if let Some(authority_transition) = &mut context.authority {
        authority_transition.expected_prior =
            writer.authority_prior(control, &authority_transition.key, end)?;
    }
    if let Some(key) = &metadata_key {
        metadata
            .get(key)
            .ok_or_else(changed)?
            .verify(control, policy, end)?;
    }
    for claim in claims {
        verify_root(claim)?;
        check_policy(control, policy)?;
        crate::managed_control::source_selection(claim.region.provider, parent)
            .map_err(|_| unavailable())?;
    }
    if !matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(changed());
    }
    observation_deadline(end)?;
    let publication = writer.commit_source_with_context(
        control,
        authority,
        &empty_batch(
            &prior.binding.source_path,
            advisory.region.provider,
            &snapshot,
        ),
        &observation,
        &context,
        end,
    )?;
    drop(writer);
    acknowledge(
        control,
        authority,
        advisory,
        cycle,
        &prior.binding.source_id,
        &publication,
        state,
        if confirmed { None } else { Some(candidate) },
    )?;
    Ok(confirmed)
}

/// Hash every byte of the previously committed prefix. Length/mtime are only
/// hints. Parsing still uses the entire source and final full verification.
fn verified_append(
    source: &dyn ReadOnlySource,
    snapshot: &SourceSnapshot,
    prior: Option<&BackgroundSource>,
    end: Instant,
) -> PortResult<bool> {
    observation_deadline(end)?;
    let Some(prior) = prior else {
        return Ok(false);
    };
    let Some(length) = prior
        .indexed_len
        .filter(|length| *length > 0 && *length < snapshot.len)
    else {
        return Ok(false);
    };
    let Some(receipt) = &prior.latest_receipt else {
        return Ok(false);
    };
    let mut reader = source.open()?.take(length);
    let mut hash = blake3::Hasher::new();
    let mut bytes = [0_u8; 65536];
    let mut read_length = 0_u64;
    loop {
        observation_deadline(end)?;
        let count = reader.read(&mut bytes).map_err(|_| unavailable())?;
        observation_deadline(end)?;
        if count == 0 {
            break;
        }
        read_length += count as u64;
        hash.update(&bytes[..count]);
    }
    observation_deadline(end)?;
    Ok(read_length == length && hash.finalize().to_hex().as_str() == receipt.digest)
}

#[allow(clippy::too_many_arguments)]
fn acknowledge(
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    selection: &Selection,
    cycle: &ObservationCycle,
    id: &SourceId,
    publication: &Publication,
    state: ObservationState,
    confirmation: Option<PendingConfirmation>,
) -> PortResult<()> {
    let receipt = &publication.receipt;
    let summary = if receipt.published {
        Some(SourceReceiptSummary {
            token: cycle.token.clone(),
            revision: ControlId::parse(receipt.revision_id.as_str())?,
            catalog_incarnation: ControlId::parse(&receipt.catalog_incarnation)?,
            catalog_generation: ControlSeq::new(receipt.committed_generation.ok_or_else(invalid)?)?,
        })
    } else {
        None
    };
    let complete = receipt.published && state == ObservationState::Complete;
    let error = match state {
        ObservationState::Complete => None,
        ObservationState::RewritePending => Some(BackgroundFailure::RewritePending),
        ObservationState::DeletionPending => Some(BackgroundFailure::DeletionPending),
        ObservationState::Unstable => Some(BackgroundFailure::SourceChanged),
        ObservationState::Incomplete => Some(BackgroundFailure::Deferred),
    };
    let ack = SourceAcknowledgement {
        source_id: ControlId::parse(id.as_str())?,
        provider: selection.region.provider,
        token: cycle.token.clone(),
        selection: selection_revision(selection)?,
        attempted_at_ms: app_clock_ms(),
        coverage: if complete {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        update_state: if complete {
            UpdateState::Idle
        } else {
            UpdateState::Deferred
        },
        backfill_state: if complete {
            BackfillState::Complete
        } else {
            BackfillState::Pending
        },
        error,
        receipt: summary,
        confirmation,
    };
    control_change(control, |seq| {
        control.acknowledge_source(seq, authority, ack.clone())
    })?;
    Ok(())
}

#[cfg(test)]
mod control_deadline_tests {
    use super::*;
    use agent_session_grep_ports::managed::{ProjectionQuery, ProjectionRead};
    use std::{cell::Cell, io::Write, rc::Rc};

    struct CycleFixture {
        control: SqliteControlStore,
        worker_lock: ExclusiveGuard,
        selection: Selection,
        db: PathBuf,
        scope_end: Instant,
        // Connections and OS guards must close before Windows temp cleanup.
        _temp: tempfile::TempDir,
    }

    impl CycleFixture {
        fn new() -> Self {
            Self::new_for_provider(SearchProvider::Claude)
        }

        fn new_for_provider(provider: SearchProvider) -> Self {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let root = temp.path().join("private");
            let history = temp.path().join("history");
            std::fs::create_dir(&history).unwrap();
            let db = root.join("catalog.db");
            let control = SqliteControlStore::create(
                &root,
                &ControlId::parse("pending-installation").unwrap(),
                DesiredUpdates::Running,
            )
            .unwrap();
            let scope_end = Instant::now() + Duration::from_secs(30);
            let request = crate::managed_control::source_selection(provider, &history).unwrap();
            let selection = control_change_before(&control, scope_end, |seq| {
                control.add_selection(seq, request.clone())
            })
            .unwrap()
            .value;
            let worker_lock = loop {
                match ExclusiveGuard::try_acquire(&root, LockKind::Background) {
                    Ok(lock) => break lock,
                    Err(PortError::WriterBusy(_)) if Instant::now() < scope_end => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("synthetic worker lock failed: {error:?}"),
                }
            };
            {
                let worker = control
                    .with_runtime_deadline(scope_end, || {
                        control
                            .bind_worker(&worker_lock, ControlId::parse("pending-worker").unwrap())
                    })
                    .unwrap();
                control_change_before(&control, scope_end, |seq| {
                    control.register_worker(seq, &worker, std::process::id(), 1)
                })
                .unwrap();
                let store = ManagedStore::create(
                    &db,
                    &control,
                    ControlId::parse("pending-catalog").unwrap(),
                    1,
                )
                .unwrap();
                control
                    .with_runtime_deadline(scope_end, || {
                        store.reconcile_progress(&control, &worker)
                    })
                    .unwrap();
            }
            Self {
                control,
                worker_lock,
                selection,
                db,
                scope_end,
                _temp: temp,
            }
        }

        fn worker(&self) -> LockedWorkerAuthority<'_> {
            self.control
                .with_runtime_deadline(self.scope_end, || {
                    self.control.bind_worker(
                        &self.worker_lock,
                        ControlId::parse("pending-worker").unwrap(),
                    )
                })
                .unwrap()
        }

        fn read_control<T>(&self, read: impl FnOnce(&SqliteControlStore) -> PortResult<T>) -> T {
            self.control
                .with_runtime_deadline(self.scope_end, || read(&self.control))
                .unwrap()
        }

        fn queued(&self) -> (ObservationCycle, LatestBarrier) {
            let request = LatestRequest {
                selections: vec![selection_revision(&self.selection).unwrap()],
                max_wait_ms: 1000,
                now_ms: 2,
            };
            let admission = control_change_before(&self.control, self.scope_end, |seq| {
                self.control.admit_latest(seq, request.clone())
            })
            .unwrap()
            .value;
            let LatestAdmission::Queued(barrier) = admission else {
                panic!("synthetic latest request was blocked")
            };
            let cycle = self.read_control(|control| control.cycle(barrier.required_cycle_seq));
            (cycle, barrier)
        }

        fn start(
            &self,
            worker: &LockedWorkerAuthority<'_>,
            queued: &ObservationCycle,
        ) -> ObservationCycle {
            control_change_before(&self.control, self.scope_end, |seq| {
                self.control
                    .start_cycle(seq, worker, queued.token.cycle_seq, 3)
            })
            .unwrap()
            .value
        }

        fn write_source(&self, name: &str, provider: SearchProvider, text: &str) -> PathBuf {
            let path = Path::new(self.selection.region.locator.as_str()).join(name);
            std::fs::write(&path, synthetic_record(provider, name, text)).unwrap();
            path
        }

        fn sources(&self) -> Vec<BackgroundSource> {
            self.control
                .with_runtime_deadline(self.scope_end, || {
                    ManagedStore::open(&self.db, &self.control)?.background_sources(&self.control)
                })
                .unwrap()
        }

        fn hits(&self, text: &str) -> usize {
            self.control
                .with_runtime_deadline(self.scope_end, || {
                    ManagedStore::open(&self.db, &self.control)?.with_read(
                        &self.control,
                        RequestIntersection::Selected,
                        self.scope_end,
                        |read| {
                            Ok(read
                                .query_lexical(text, &ProjectionQuery::default(), 100)?
                                .hits
                                .len())
                        },
                    )
                })
                .unwrap()
        }

        fn scheduled(
            &self,
            schedule: &mut SourceScheduleState,
            boot: &ObservationClock,
        ) -> (PortResult<bool>, ObservationCycle, LatestBarrier) {
            let worker = self.worker();
            let policy =
                self.read_control(|control| control.read_policy(RequestIntersection::Selected));
            let selections = policy
                .selections
                .iter()
                .filter(|s| s.enabled)
                .cloned()
                .collect::<Vec<_>>();
            let request = LatestRequest {
                selections: selections
                    .iter()
                    .map(selection_revision)
                    .collect::<PortResult<_>>()
                    .unwrap(),
                max_wait_ms: 1000,
                now_ms: 2,
            };
            let LatestAdmission::Queued(barrier) =
                control_change_before(&self.control, self.scope_end, |seq| {
                    self.control.admit_latest(seq, request.clone())
                })
                .unwrap()
                .value
            else {
                panic!("synthetic latest admission failed");
            };
            let queued = self.read_control(|control| control.cycle(barrier.required_cycle_seq));
            let cycle = self.start(&worker, &queued);
            let result = self.control.with_runtime_deadline(self.scope_end, || {
                observe_cycle(
                    &self.db,
                    &self.control,
                    &worker,
                    &policy,
                    &selections,
                    &cycle,
                    boot,
                    schedule,
                )
            });
            let finish = match &result {
                Ok(true) => CycleFinish::Committed,
                Ok(false) => CycleFinish::Partial,
                Err(_) => CycleFinish::Aborted,
            };
            control_change_before(&self.control, self.scope_end, |seq| {
                self.control
                    .finish_cycle(seq, &worker, cycle.token.cycle_seq, finish, 4)
            })
            .unwrap();
            let terminal = self.read_control(|control| control.cycle(cycle.token.cycle_seq));
            (result, terminal, barrier)
        }

        fn latest(&self, barrier: &LatestBarrier) -> bool {
            self.control
                .with_runtime_deadline(self.scope_end, || {
                    ManagedStore::open(&self.db, &self.control)?.with_read(
                        &self.control,
                        RequestIntersection::Selected,
                        self.scope_end,
                        |read| read.latest_satisfied(barrier),
                    )
                })
                .unwrap()
        }
    }

    fn synthetic_record(provider: SearchProvider, id: &str, text: &str) -> Vec<u8> {
        let row = if provider == SearchProvider::Claude {
            serde_json::json!({"type":"user","uuid":id,"sessionId":"scheduler-session",
                "timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":text}})
        } else {
            serde_json::json!({"timestamp":"2026-01-01T00:00:00Z","type":"response_item",
                "payload":{"type":"message","id":id,"role":"user",
                    "content":[{"type":"input_text","text":text}]}})
        };
        let mut bytes = serde_json::to_vec(&row).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn append_record(path: &Path, provider: SearchProvider, id: &str, text: &str) {
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&synthetic_record(provider, id, text))
            .unwrap();
        file.sync_all().unwrap();
    }

    fn scheduler_hooks(
        elapsed: Rc<Cell<Duration>>,
        hook: impl FnMut(ScheduleTestEvent<'_>) -> PortResult<()> + 'static,
    ) -> ScheduleTestHooks {
        ScheduleTestHooks {
            now: Some(elapsed),
            probe_due: None,
            source_phase: Cell::new(SourceAttemptPhase::Prepare),
            on_event: Some(RefCell::new(Box::new(hook))),
        }
    }

    #[test]
    fn scheduler_warm_append_after_first_turn_revisits_before_backfill_finishes() {
        for provider in [SearchProvider::Claude, SearchProvider::Codex] {
            let fixture = CycleFixture::new_for_provider(provider);
            let warm = fixture.write_source("warm.jsonl", provider, "baseline");
            let mut schedule = SourceScheduleState::default();
            let boot = ObservationClock::new(Instant::now());
            assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
            let prior = fixture.sources().pop().unwrap();
            for n in 0..8 {
                fixture.write_source(
                    &format!("cold-{n}.jsonl"),
                    provider,
                    &format!("history {n}"),
                );
            }
            // Root/child claims must survive every replacement receipt.
            let exact = crate::managed_control::source_selection(provider, &warm).unwrap();
            control_change_before(&fixture.control, fixture.scope_end, |seq| {
                fixture.control.add_selection(seq, exact.clone())
            })
            .unwrap();
            let elapsed = Rc::new(Cell::new(Duration::ZERO));
            let probe_due = Rc::new(Cell::new(false));
            let trace = Rc::new(RefCell::new(Vec::new()));
            let failures = Rc::new(RefCell::new(Vec::new()));
            let warm_id = prior.binding.source_id.clone();
            let visits = Rc::new(Cell::new(0));
            schedule.hooks = scheduler_hooks(elapsed.clone(), {
                let trace = trace.clone();
                let failures = failures.clone();
                let probe_due = probe_due.clone();
                let visits = visits.clone();
                move |event| {
                    match event {
                        ScheduleTestEvent::BeforeProbe(id, end) => {
                            assert!(end > Instant::now(), "probe keeps the admitted end");
                            let _ = id;
                        }
                        ScheduleTestEvent::BeforeAttempt(id, end, lane) => {
                            assert!(end > Instant::now());
                            trace.borrow_mut().push((id.clone(), lane));
                        }
                        ScheduleTestEvent::AfterAttempt(id, _) => {
                            if *id == warm_id {
                                visits.set(visits.get() + 1);
                                if visits.get() == 1 {
                                    append_record(&warm, provider, "append", "afterfirstturn");
                                }
                            }
                            probe_due.set(true);
                        }
                        ScheduleTestEvent::SourceFailed {
                            id,
                            phase,
                            error,
                            revisit,
                            remaining,
                        } => {
                            // Only classify known static diagnostics. Never
                            // retain paths or arbitrary provider/backend text.
                            let detail = match error {
                                PortError::WriterBusy(message) => match message.as_str() {
                                    "control runtime deadline reached" => "control_deadline",
                                    "control storage is busy" => "control_storage_busy",
                                    "managed catalog is busy" => "catalog_busy",
                                    "managed lock is busy" => "managed_lock_busy",
                                    "managed source observation deadline reached" => {
                                        "source_deadline"
                                    }
                                    "source snapshot is busy or deadline exceeded" => {
                                        "snapshot_busy_or_deadline"
                                    }
                                    _ => "other_busy",
                                },
                                _ => "non_busy",
                            };
                            failures.borrow_mut().push((
                                *id == warm_id,
                                phase,
                                failure(error),
                                detail,
                                revisit,
                                remaining.as_millis(),
                            ));
                        }
                        _ => {}
                    }
                    Ok(())
                }
            });
            schedule.hooks.probe_due = Some(probe_due);
            let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
            assert!(
                result.unwrap(),
                "a slice is not a terminal cycle cutoff: provider={}, roots={:?}, warm_visits={}, failures(warm,phase,reason,detail,revisit,remaining_ms)={:?}",
                provider.as_str(),
                cycle
                    .selections
                    .iter()
                    .map(|selection| (
                        selection.discovery_complete,
                        selection.discovered_count,
                        selection.observed_count,
                        selection.committed_count,
                        selection.error,
                    ))
                    .collect::<Vec<_>>(),
                visits.get(),
                failures.borrow(),
            );
            assert_eq!(
                visits.get(),
                2,
                "same-cycle append needs a second real visit"
            );
            let order = trace.borrow();
            let second = order
                .iter()
                .enumerate()
                .filter(|(_, (id, _))| *id == prior.binding.source_id)
                .nth(1)
                .unwrap()
                .0;
            assert!(
                second < order.len() - 1,
                "warm revisit must preempt outstanding cold work"
            );
            assert_eq!(fixture.hits("afterfirstturn"), 1);
            let current = fixture
                .sources()
                .into_iter()
                .find(|s| s.binding.source_id == prior.binding.source_id)
                .unwrap();
            assert_eq!(current.binding.namespace_id, prior.binding.namespace_id);
            assert_eq!(
                current.latest_receipt.as_ref().unwrap().cycle_seq,
                cycle.token.cycle_seq.get()
            );
            assert_ne!(
                current.latest_receipt.unwrap().revision_id,
                prior.latest_receipt.unwrap().revision_id
            );
            assert!(
                fixture.latest(&barrier),
                "all exact claims and final heads must qualify"
            );
            for selection in &cycle.selections {
                assert!(selection.discovery_complete);
                let expected = if selection.selection.selection_id == fixture.selection.id {
                    9
                } else {
                    1
                };
                assert_eq!(selection.discovered_count, expected);
                assert_eq!(selection.observed_count, expected);
                assert_eq!(selection.committed_count, expected);
            }
        }
    }

    #[test]
    fn scheduler_active_fifo_debt_and_promotion_survive_cycle_rollover() {
        let mut state = SourceScheduleState::default();
        let end = Instant::now() + Duration::from_secs(30);
        let ids = [
            "hot-a",
            "hot-b",
            "owed-warm",
            "cold-a",
            "cold-b",
            "verify",
            "absence",
        ]
        .map(|id| SourceId::parse(id).unwrap());
        {
            let mut cycle = CycleSchedule::new(&mut state);
            for (index, id) in ids.iter().enumerate() {
                let lane = match index {
                    0..=2 => SourceLane::Active,
                    3..=4 => SourceLane::Cold,
                    _ => SourceLane::Verification,
                };
                cycle.add(id, None, lane, end, index < 3).unwrap();
            }
            let mut served = Vec::new();
            for _ in 0..2 {
                let Some(ScheduledTurn::Attempt(id, lane)) = cycle.next(Instant::now()) else {
                    panic!("missing active turn");
                };
                cycle.started(&id, lane).unwrap();
                served.push(id.clone());
                cycle.turns.get_mut(&id).unwrap().revisitable = true;
                cycle.hint(
                    &id,
                    SourceHint {
                        len: 2,
                        mtime_ms: 1,
                    },
                    Some(1),
                );
                cycle.hint(
                    &id,
                    SourceHint {
                        len: 3,
                        mtime_ms: 2,
                    },
                    Some(1),
                );
            }
            assert_eq!(served, ids[..2]);
            // Expiry spends no credit, does not rotate owed tickets, and ends
            // every current first-turn obligation without an infinite loop.
            let mut expired = 0;
            while let Some(turn) = cycle.next(end) {
                assert!(matches!(turn, ScheduledTurn::NotScheduled(_)));
                expired += 1;
            }
            assert_eq!(expired, 5);
        }
        let owed_ticket = state.sources[&ids[2]].ticket;
        let mut cycle = CycleSchedule::new(&mut state);
        for (index, id) in ids.iter().enumerate() {
            let lane = match index {
                0..=1 => SourceLane::Active,
                3..=4 => SourceLane::Cold,
                _ => SourceLane::Verification,
            };
            cycle
                .add(id, None, lane, end + CADENCE, index <= 2)
                .unwrap();
        }
        cycle.hint(
            &ids[2],
            SourceHint {
                len: 2,
                mtime_ms: 1,
            },
            Some(1),
        );
        assert_eq!(cycle.state.sources[&ids[2]].ticket, owed_ticket);
        let mut order = Vec::new();
        for _ in 0..11 {
            let Some(ScheduledTurn::Attempt(id, lane)) = cycle.next(Instant::now()) else {
                break;
            };
            cycle.started(&id, lane).unwrap();
            order.push((id.clone(), lane));
            if lane == SourceLane::Active && id != ids[2] {
                cycle.turns.get_mut(&id).unwrap().revisitable = true;
                cycle.hint(
                    &id,
                    SourceHint {
                        len: 8,
                        mtime_ms: 8,
                    },
                    Some(1),
                );
            }
        }
        assert_eq!(
            order[0],
            (ids[3].clone(), SourceLane::Cold),
            "active credit survives rollover"
        );
        assert_eq!(
            order[1].0, ids[2],
            "owed warm survives promotion ahead of hot revisits"
        );
        let debt = order
            .iter()
            .filter(|(_, lane)| *lane != SourceLane::Active)
            .map(|(_, lane)| *lane)
            .collect::<Vec<_>>();
        assert_eq!(
            debt,
            [
                SourceLane::Cold,
                SourceLane::Verification,
                SourceLane::Cold,
                SourceLane::Verification
            ]
        );
        let mut consecutive = 0;
        for (_, lane) in &order {
            if *lane == SourceLane::Active {
                consecutive += 1;
            } else {
                consecutive = 0;
            }
            assert!(consecutive <= 2);
        }
        assert_eq!(cycle.first_pending, 0);
    }

    #[test]
    fn scheduler_expired_tail_is_not_attempted_and_cold_debt_advances_next_cycle() {
        let fixture = CycleFixture::new();
        for n in 0..4 {
            fixture.write_source(
                &format!("cold-{n}.jsonl"),
                SearchProvider::Claude,
                &format!("coldword{n}"),
            );
        }
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        let mut started = BTreeSet::new();
        for _ in 0..7 {
            let elapsed = Rc::new(Cell::new(Duration::ZERO));
            let attempts = Rc::new(RefCell::new(Vec::new()));
            schedule.hooks = scheduler_hooks(elapsed.clone(), {
                let attempts = attempts.clone();
                move |event| {
                    if let ScheduleTestEvent::AfterAttempt(id, lane) = event {
                        attempts.borrow_mut().push((id.clone(), lane));
                        elapsed.set(SOURCE_OBSERVATION_BUDGET);
                    }
                    Ok(())
                }
            });
            let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
            assert!(!result.unwrap());
            assert_eq!(cycle.state, CycleState::Partial);
            assert!(!fixture.latest(&barrier));
            assert_eq!(attempts.borrow().len(), 1, "no expired tail may start");
            let id = attempts.borrow()[0].0.clone();
            if attempts.borrow()[0].1 == SourceLane::Cold {
                assert!(
                    started.insert(id),
                    "unserved cold debt precedes repeated cold work"
                );
            } else {
                assert!(
                    started.contains(&id),
                    "published sources get full verification turns"
                );
            }
            let progress = &cycle.selections[0];
            assert_eq!(
                (
                    progress.discovered_count,
                    progress.observed_count,
                    progress.committed_count
                ),
                (4, 1, 1)
            );
            for id in schedule.sources.keys().filter(|id| !started.contains(*id)) {
                assert!(
                    fixture
                        .control
                        .source_progress(&ControlId::parse(id.as_str()).unwrap())
                        .unwrap()
                        .is_none(),
                    "NotScheduled creates no fake failed attempts"
                );
            }
            if started.len() == 4 {
                break;
            }
        }
        assert_eq!(fixture.sources().len(), 4);
        schedule.hooks = ScheduleTestHooks::default();
        let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
        assert!(
            result.unwrap(),
            "full verification still gets a complete cycle"
        );
        assert_eq!(cycle.selections[0].committed_count, 4);
        assert!(fixture.latest(&barrier));
    }

    #[test]
    fn scheduler_revisits_use_latest_published_prefix_and_hold_rewritten_tail() {
        for provider in [SearchProvider::Claude, SearchProvider::Codex] {
            let fixture = CycleFixture::new_for_provider(provider);
            let warm = fixture.write_source("warm.jsonl", provider, "baseline");
            let mut schedule = SourceScheduleState::default();
            let boot = ObservationClock::new(Instant::now() - Duration::from_secs(6));
            assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
            let prior = fixture.sources().pop().unwrap();
            let warm_id = prior.binding.source_id.clone();
            // Keep an independent cold root alive long enough for all three
            // warm visits. This also covers roots with different original ends.
            let cold_root = fixture._temp.path().join("cold-history");
            std::fs::create_dir(&cold_root).unwrap();
            for n in 0..10 {
                std::fs::write(
                    cold_root.join(format!("cold-{n}.jsonl")),
                    synthetic_record(SearchProvider::Claude, &format!("cold-{n}"), "history"),
                )
                .unwrap();
            }
            let request =
                crate::managed_control::source_selection(SearchProvider::Claude, &cold_root)
                    .unwrap();
            control_change_before(&fixture.control, fixture.scope_end, |seq| {
                fixture.control.add_selection(seq, request.clone())
            })
            .unwrap();
            let visits = Rc::new(Cell::new(0));
            let elapsed = Rc::new(Cell::new(Duration::ZERO));
            let original_end = Rc::new(Cell::new(None));
            schedule.hooks = scheduler_hooks(elapsed.clone(), {
                let visits = visits.clone();
                let original_end = original_end.clone();
                let warm = warm.clone();
                move |event| {
                    match event {
                        ScheduleTestEvent::Planned => {
                            append_record(&warm, provider, "tail-one", "firsttail")
                        }
                        ScheduleTestEvent::BeforeAttempt(id, end, _) if *id == warm_id => {
                            if let Some(original) = original_end.get() {
                                assert_eq!(original, end);
                            }
                            original_end.set(Some(end));
                        }
                        ScheduleTestEvent::Published(id, end) if *id == warm_id => {
                            assert_eq!(original_end.get(), Some(end));
                            // Publication already captured the preceding length.
                            // A post-publication stat must not consume this append.
                            if visits.get() == 0 {
                                append_record(&warm, provider, "tail-two", "secondtail");
                            }
                        }
                        ScheduleTestEvent::AfterAttempt(id, _) => {
                            if *id == warm_id {
                                visits.set(visits.get() + 1);
                                if visits.get() == 2 {
                                    let content = std::fs::read_to_string(&warm)
                                        .unwrap()
                                        .replace("firsttail", "rewrittentail");
                                    std::fs::write(&warm, content).unwrap();
                                    append_record(&warm, provider, "tail-three", "thirdtail");
                                }
                            }
                            elapsed.set(elapsed.get() + CADENCE);
                        }
                        _ => {}
                    }
                    Ok(())
                }
            });
            let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
            assert!(!result.unwrap());
            assert_eq!(visits.get(), 3, "held rewrite is terminal for this cycle");
            assert_eq!(fixture.hits("firsttail"), 1);
            assert_eq!(fixture.hits("secondtail"), 1);
            assert_eq!(fixture.hits("rewrittentail"), 0);
            assert_eq!(fixture.hits("thirdtail"), 0);
            let current = fixture
                .sources()
                .into_iter()
                .find(|s| s.binding.source_id == prior.binding.source_id)
                .unwrap();
            assert!(current.indexed_len.unwrap() > prior.indexed_len.unwrap());
            let progress = fixture
                .control
                .source_progress(&ControlId::parse(prior.binding.source_id.as_str()).unwrap())
                .unwrap()
                .unwrap();
            let held = progress.confirmation.unwrap();
            assert_eq!(held.first_cycle, cycle.token.cycle_seq);
            assert!(held.confirm_cycle.is_none());
            assert!(!fixture.latest(&barrier));
        }
    }

    #[test]
    fn scheduler_commit_before_ack_failure_never_retries_a_guessed_baseline() {
        let fixture = CycleFixture::new();
        let warm = fixture.write_source("warm.jsonl", SearchProvider::Claude, "baseline");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        let prior = fixture.sources().pop().unwrap();
        for n in 0..5 {
            fixture.write_source(
                &format!("cold-{n}.jsonl"),
                SearchProvider::Claude,
                "history",
            );
        }
        let warm_id = prior.binding.source_id.clone();
        let visits = Rc::new(Cell::new(0));
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        schedule.hooks = scheduler_hooks(elapsed.clone(), {
            let visits = visits.clone();
            move |event| {
                match event {
                    ScheduleTestEvent::Planned => {
                        append_record(&warm, SearchProvider::Claude, "append", "committedword")
                    }
                    ScheduleTestEvent::Published(id, _) if *id == warm_id => {
                        visits.set(visits.get() + 1);
                        return Err(changed());
                    }
                    ScheduleTestEvent::AfterAttempt(_, _) => elapsed.set(elapsed.get() + CADENCE),
                    _ => {}
                }
                Ok(())
            }
        });
        let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
        assert!(!result.unwrap());
        assert_eq!(visits.get(), 1);
        assert_eq!(cycle.selections[0].observed_count, 6);
        assert_eq!(cycle.selections[0].committed_count, 5);
        assert!(!fixture.latest(&barrier));
        let committed = fixture
            .sources()
            .into_iter()
            .find(|s| s.binding.source_id == prior.binding.source_id)
            .unwrap();
        assert_ne!(
            committed.latest_receipt.unwrap().revision_id,
            prior.latest_receipt.unwrap().revision_id
        );
        assert_eq!(fixture.hits("committedword"), 1);
        schedule.hooks = ScheduleTestHooks::default();
        let (result, _, barrier) = fixture.scheduled(&mut schedule, &boot);
        assert!(
            result.unwrap(),
            "next cycle reloads the actual committed head"
        );
        assert!(fixture.latest(&barrier));
    }

    #[test]
    fn scheduler_probe_expiry_does_no_admission_and_preserves_unstarted_receipt() {
        let fixture = CycleFixture::new();
        let warm = fixture.write_source("warm.jsonl", SearchProvider::Claude, "baseline");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        let prior = fixture.sources().pop().unwrap();
        let before = fixture.read_control(|control| {
            control.source_progress(&ControlId::parse(prior.binding.source_id.as_str()).unwrap())
        });
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let probes = Rc::new(Cell::new(0));
        schedule.hooks = scheduler_hooks(elapsed.clone(), {
            let probes = probes.clone();
            move |event| {
                match event {
                    ScheduleTestEvent::BeforeProbe(_, end) => {
                        probes.set(probes.get() + 1);
                        elapsed.set(end.saturating_duration_since(Instant::now()) + CADENCE);
                        // If admission is accidentally reached after expiry it
                        // will fail; it must not be acknowledged as an attempt.
                        std::fs::remove_file(&warm).unwrap();
                    }
                    ScheduleTestEvent::BeforeAttempt(_, _, _) => {
                        panic!("expired probe started a source")
                    }
                    _ => {}
                }
                Ok(())
            }
        });
        schedule.next_probe = None;
        let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
        assert!(!result.unwrap());
        assert_eq!(probes.get(), 1);
        assert_eq!(
            (
                cycle.selections[0].discovered_count,
                cycle.selections[0].observed_count,
                cycle.selections[0].committed_count
            ),
            (1, 0, 0)
        );
        assert_eq!(
            fixture.read_control(|control| {
                control
                    .source_progress(&ControlId::parse(prior.binding.source_id.as_str()).unwrap())
            }),
            before
        );
        assert!(!fixture.latest(&barrier));
        assert_eq!(fixture.hits("baseline"), 1);
    }

    #[test]
    fn scheduler_expired_retirement_records_root_gap_before_aborted_finalization() {
        let fixture = CycleFixture::new();
        let control = &fixture.control;
        let unrelated = fixture.write_source(
            "unrelated.jsonl",
            SearchProvider::Claude,
            "unrelatedoriginal",
        );
        let affected_root = fixture._temp.path().join("affected");
        let affected_child = affected_root.join("nested");
        std::fs::create_dir_all(&affected_child).unwrap();
        let missing = affected_child.join("missing.jsonl");
        let rewrite_root = fixture._temp.path().join("rewrite");
        std::fs::create_dir(&rewrite_root).unwrap();
        let rewrite = rewrite_root.join("rewrite.jsonl");
        for (path, id, text) in [
            (&missing, "missing", "missingoriginal"),
            (&rewrite, "rewrite", "rewriteoriginal"),
        ] {
            std::fs::write(path, synthetic_record(SearchProvider::Claude, id, text)).unwrap();
        }
        let mut affected_selections = Vec::new();
        for path in [&affected_root, &affected_child, &rewrite_root] {
            let request =
                crate::managed_control::source_selection(SearchProvider::Claude, path).unwrap();
            let selection = control_change_before(control, fixture.scope_end, |seq| {
                control.add_selection(seq, request.clone())
            })
            .unwrap()
            .value;
            if path != &rewrite_root {
                affected_selections.push(selection);
            }
        }
        let mut schedule = SourceScheduleState::default();
        let mut boot = ObservationClock::new(Instant::now());
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        let originals = fixture.sources();
        let missing_source = originals
            .iter()
            .find(|source| Path::new(&source.binding.source_path) == missing)
            .unwrap();
        let missing_id = missing_source.binding.source_id.clone();
        let progress = || {
            originals
                .iter()
                .map(|source| {
                    let id = ControlId::parse(source.binding.source_id.as_str()).unwrap();
                    fixture.read_control(|control| control.source_progress(&id))
                })
                .collect::<Vec<_>>()
        };
        let heads = || {
            fixture
                .sources()
                .into_iter()
                .map(|source| {
                    (
                        source.binding.source_id,
                        (source.latest_receipt, source.indexed_len),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };

        // C1 establishes real deletion and rewrite holds on separate roots.
        std::fs::remove_file(&missing).unwrap();
        std::fs::remove_file(&unrelated).unwrap();
        std::fs::write(
            &rewrite,
            synthetic_record(SearchProvider::Claude, "rewrite", "replacementoriginal"),
        )
        .unwrap();
        let (first_result, first, _) = fixture.scheduled(&mut schedule, &boot);
        assert!(!first_result.unwrap());
        let before_progress = progress();
        for source in &before_progress {
            let held = source.as_ref().unwrap().confirmation.as_ref().unwrap();
            assert_eq!(held.first_cycle, first.token.cycle_seq);
        }
        let before_heads = heads();

        // Put the affected parent first, so its shared missing source has the
        // earliest original end. The abort fires immediately after retirement,
        // before any source attempt or root accounting can invalidate its hold.
        let policy =
            fixture.read_control(|control| control.read_policy(RequestIntersection::Selected));
        let mut selections = policy
            .selections
            .iter()
            .filter(|selection| selection.enabled)
            .cloned()
            .collect::<Vec<_>>();
        selections.sort_by_key(|selection| usize::from(selection.id != affected_selections[0].id));
        let revisions = selections
            .iter()
            .map(selection_revision)
            .collect::<PortResult<Vec<_>>>()
            .unwrap();
        let CycleAdmission::Queued(queued) =
            control_change_before(control, fixture.scope_end, |seq| {
                control.queue_cycle(seq, revisions.clone())
            })
            .unwrap()
            .value
        else {
            panic!("synthetic interrupted cycle was not queued");
        };
        let worker = fixture.worker();
        let interrupted = fixture.start(&worker, &queued);
        let retired = Rc::new(Cell::new(false));
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        schedule.hooks = scheduler_hooks(elapsed.clone(), {
            let retired = retired.clone();
            let missing_id = missing_id.clone();
            move |event| {
                match event {
                    ScheduleTestEvent::Planned => {
                        elapsed.set(SOURCE_OBSERVATION_BUDGET + CADENCE);
                    }
                    ScheduleTestEvent::AfterNotScheduled(id) => {
                        assert_eq!(*id, missing_id);
                        retired.set(true);
                        return Err(changed());
                    }
                    ScheduleTestEvent::BeforeAttempt(_, _, _) => {
                        panic!("expired source reached attempt admission");
                    }
                    ScheduleTestEvent::Finalizing => {
                        panic!("injected abort must precede root accounting");
                    }
                    _ => {}
                }
                Ok(())
            }
        });
        let result = control.with_runtime_deadline(fixture.scope_end, || {
            observe_cycle(
                &fixture.db,
                control,
                &worker,
                &policy,
                &selections,
                &interrupted,
                &boot,
                &mut schedule,
            )
        });
        assert!(retired.get());
        assert!(matches!(result, Err(PortError::SnapshotChanged(_))));
        control_change_before(control, fixture.scope_end, |seq| {
            control.finish_cycle(
                seq,
                &worker,
                interrupted.token.cycle_seq,
                CycleFinish::Aborted,
                4,
            )
        })
        .unwrap();
        assert_eq!(
            progress(),
            before_progress,
            "no fake source acknowledgement"
        );
        assert_eq!(heads(), before_heads, "no unstarted source publication");
        let aborted = fixture.read_control(|control| control.cycle(interrupted.token.cycle_seq));
        assert_eq!(aborted.state, CycleState::Aborted);
        assert!(aborted.selections.iter().all(|selection| {
            !selection.discovery_complete
                && selection.discovered_count == 0
                && selection.observed_count == 0
                && selection.committed_count == 0
        }));

        // Inspect both overlap clocks, not just whichever advisory root C1
        // selected. Complete enumeration must preserve a same-root Rewrite.
        let locator = CanonicalLocator::parse(&missing_source.binding.source_path).unwrap();
        for selection in &affected_selections {
            for (kind, expected) in [
                (
                    ConfirmationKind::Deletion,
                    Some(interrupted.token.cycle_seq),
                ),
                (
                    ConfirmationKind::Rewrite {
                        candidate_digest: ControlId::parse("unchanged-candidate").unwrap(),
                    },
                    None,
                ),
            ] {
                assert_eq!(
                    boot.lost_after(
                        &ConfirmationSource {
                            id: &missing_id,
                            locator: &locator,
                            contexts: &[],
                        },
                        selection,
                        &kind,
                        policy.policy_epoch,
                    ),
                    expected,
                );
            }
        }
        for (source, previous) in originals.iter().zip(&before_progress) {
            let held = previous.as_ref().unwrap().confirmation.as_ref().unwrap();
            if source.binding.source_id != missing_id {
                let selection = selections
                    .iter()
                    .find(|selection| selection.root_identity.as_ref() == Some(&held.root_identity))
                    .unwrap();
                assert!(
                    boot.lost_after(
                        &ConfirmationSource {
                            id: &source.binding.source_id,
                            locator: &CanonicalLocator::parse(&source.binding.source_path).unwrap(),
                            contexts: &[],
                        },
                        selection,
                        &held.kind,
                        policy.policy_epoch,
                    )
                    .is_none()
                );
            }
        }

        // Advance only the confirmation clock, retaining the same worker and
        // failure table. C3 must restart B; healthy deletion/rewrite can finish.
        boot.started -= Duration::from_secs(6);
        schedule.hooks = ScheduleTestHooks::default();
        let (third_result, third, _) = fixture.scheduled(&mut schedule, &boot);
        assert!(!third_result.unwrap());
        let after_progress = progress();
        for (source, previous, current) in originals
            .iter()
            .zip(&before_progress)
            .zip(&after_progress)
            .map(|((source, previous), current)| (source, previous, current))
        {
            let current = current.as_ref().unwrap();
            if source.binding.source_id == missing_id {
                let held = current.confirmation.as_ref().unwrap();
                assert_eq!(held.first_cycle, third.token.cycle_seq);
                assert!(held.confirm_cycle.is_none());
                assert!(
                    held.first_monotonic_ms.get()
                        >= previous
                            .as_ref()
                            .unwrap()
                            .confirmation
                            .as_ref()
                            .unwrap()
                            .first_monotonic_ms
                            .get()
                            + CONFIRMATION_MS
                );
            } else {
                assert!(current.confirmation.is_none());
                assert_eq!(current.coverage, Coverage::Complete);
                assert_eq!(current.receipt.as_ref().unwrap().token, third.token);
            }
        }
        assert_eq!(fixture.hits("missingoriginal"), 1);
        assert_eq!(fixture.hits("unrelatedoriginal"), 0);
        assert_eq!(fixture.hits("rewriteoriginal"), 0);
        assert_eq!(fixture.hits("replacementoriginal"), 1);
    }

    #[test]
    fn scheduler_millisecond_hints_do_not_skip_verification_or_promote_cold_sources() {
        let fixture = CycleFixture::new();
        let warm = fixture.write_source("warm.jsonl", SearchProvider::Claude, "originalword");
        let modified = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_750_000_000_123_456_789);
        std::fs::File::options()
            .write(true)
            .open(&warm)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        let prior = fixture.sources().pop().unwrap();
        let hint = schedule.sources[&prior.binding.source_id]
            .verified
            .as_ref()
            .unwrap()
            .1;
        assert_eq!(hint.mtime_ms, 1_750_000_000_123);
        let metadata_hint = SourceHint::from_metadata(&std::fs::metadata(&warm).unwrap()).unwrap();
        assert_eq!(hint, metadata_hint);
        let content = std::fs::read_to_string(&warm)
            .unwrap()
            .replace("originalword", "rewritenword");
        std::fs::write(&warm, content).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&warm)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let lanes = Rc::new(RefCell::new(Vec::new()));
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let lanes = lanes.clone();
            move |event| {
                if let ScheduleTestEvent::AfterAttempt(_, lane) = event {
                    lanes.borrow_mut().push(lane);
                }
                Ok(())
            }
        });
        let (result, _, _) = fixture.scheduled(&mut schedule, &boot);
        assert!(
            !result.unwrap(),
            "matching metadata still requires a full fingerprint"
        );
        assert_eq!(&*lanes.borrow(), &[SourceLane::Verification]);
        assert_eq!(fixture.hits("originalword"), 1);
        assert_eq!(fixture.hits("rewritenword"), 0);
        let mut unpublished = prior.clone();
        unpublished.latest_receipt.as_mut().unwrap().published = false;
        assert!(!published_baseline(None));
        assert!(!published_baseline(Some(&unpublished)));
        assert!(published_baseline(Some(&prior)));
        let mut state = SourceScheduleState::default();
        let mut cycle = CycleSchedule::new(&mut state);
        cycle
            .add(
                &prior.binding.source_id,
                None,
                SourceLane::Cold,
                Instant::now() + CADENCE,
                false,
            )
            .unwrap();
        cycle
            .started(&prior.binding.source_id, SourceLane::Cold)
            .unwrap();
        cycle.succeeded(
            &prior.binding.source_id,
            &SuccessfulSourceAttempt {
                baseline: prior.clone(),
                hint,
                revisitable: true,
            },
        );
        cycle.hint(
            &prior.binding.source_id,
            SourceHint {
                len: hint.len + 1,
                ..hint
            },
            Some(hint.len),
        );
        assert!(
            cycle.queues[SourceLane::Active as usize].is_empty(),
            "newly imported cold sources cannot revisit this cycle"
        );
    }

    #[test]
    fn scheduler_latest_admitted_after_start_cannot_use_same_cycle_revisits() {
        let fixture = CycleFixture::new();
        let warm = fixture.write_source("warm.jsonl", SearchProvider::Claude, "baseline");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        let prior = fixture.sources().pop().unwrap();
        for n in 0..4 {
            fixture.write_source(
                &format!("cold-{n}.jsonl"),
                SearchProvider::Claude,
                "history",
            );
        }
        let control = SqliteControlStore::open_existing_writable(
            fixture.db.parent().unwrap(),
            &fixture
                .control
                .read_policy(RequestIntersection::Selected)
                .unwrap()
                .installation_id,
        )
        .unwrap();
        let selection = selection_revision(&fixture.selection).unwrap();
        let late = Rc::new(RefCell::new(None));
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        schedule.hooks = scheduler_hooks(elapsed.clone(), {
            let late = late.clone();
            move |event| {
                if let ScheduleTestEvent::AfterAttempt(id, _) = event {
                    if *id == prior.binding.source_id && late.borrow().is_none() {
                        let request = LatestRequest {
                            selections: vec![selection.clone()],
                            max_wait_ms: 1000,
                            now_ms: 5,
                        };
                        let LatestAdmission::Queued(barrier) = control_change(&control, |seq| {
                            control.admit_latest(seq, request.clone())
                        })?
                        .value
                        else {
                            panic!("late barrier not queued");
                        };
                        *late.borrow_mut() = Some(barrier);
                        append_record(&warm, SearchProvider::Claude, "late", "laterword");
                    }
                    elapsed.set(elapsed.get() + CADENCE);
                }
                Ok(())
            }
        });
        let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
        assert!(result.unwrap());
        assert_eq!(fixture.hits("laterword"), 1);
        assert!(fixture.latest(&barrier));
        let late = late.borrow().as_ref().unwrap().clone();
        assert!(late.required_cycle_seq > cycle.token.cycle_seq);
        assert!(!fixture.latest(&late));
        schedule.hooks = ScheduleTestHooks::default();
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        assert!(fixture.latest(&late));
    }

    fn admission_scope_failure_case(kind: SourceKind, missing: bool, policy_failure: bool) {
        use agent_session_grep_ports::managed::RevisionRef;

        let fixture = CycleFixture::new();
        let control = &fixture.control;
        let affected_path = fixture._temp.path().join("admission-history");
        std::fs::create_dir(&affected_path).unwrap();
        let metadata = kind == SourceKind::WorkBuddyMetadata;
        let provider = if metadata {
            SearchProvider::parse("workbuddy").unwrap()
        } else {
            SearchProvider::Claude
        };
        let input_path = affected_path.join(if metadata {
            "workbuddy.db"
        } else {
            "source.jsonl"
        });
        if !missing {
            std::fs::write(&input_path, b"synthetic admission input").unwrap();
        }
        let request = crate::managed_control::source_selection(provider, &affected_path).unwrap();
        let affected = control_change_before(control, fixture.scope_end, |seq| {
            control.add_selection(seq, request.clone())
        })
        .unwrap()
        .value;
        let selections = [&affected, &fixture.selection];
        let worker = fixture.worker();
        let next = || {
            let CycleAdmission::Queued(queued) =
                control_change_before(control, fixture.scope_end, |seq| {
                    control.queue_cycle(
                        seq,
                        selections
                            .iter()
                            .map(|selection| selection_revision(selection))
                            .collect::<PortResult<_>>()?,
                    )
                })
                .unwrap()
                .value
            else {
                panic!("synthetic admission cycle was not queued");
            };
            fixture.start(&worker, &queued)
        };
        let finish = |cycle: &ObservationCycle, state| {
            control_change_before(control, fixture.scope_end, |seq| {
                control.finish_cycle(seq, &worker, cycle.token.cycle_seq, state, 4)
            })
            .unwrap();
        };
        let ids = [
            SourceId::parse("affected-confirmation").unwrap(),
            SourceId::parse("unrelated-confirmation").unwrap(),
        ];
        let input_id = if metadata {
            SourceId::parse("failed-metadata").unwrap()
        } else {
            ids[0].clone()
        };
        let first = next();
        let kind_of_confirmation = if metadata {
            ConfirmationKind::Rewrite {
                candidate_digest: ControlId::parse("metadata-candidate").unwrap(),
            }
        } else {
            ConfirmationKind::Deletion
        };
        for (id, selection) in ids.iter().zip(selections) {
            let ack = SourceAcknowledgement {
                source_id: ControlId::parse(id.as_str()).unwrap(),
                provider: selection.region.provider,
                token: first.token.clone(),
                selection: selection_revision(selection).unwrap(),
                attempted_at_ms: 3,
                coverage: Coverage::Partial,
                update_state: UpdateState::Deferred,
                backfill_state: BackfillState::Pending,
                error: Some(if metadata {
                    BackgroundFailure::RewritePending
                } else {
                    BackgroundFailure::DeletionPending
                }),
                receipt: None,
                confirmation: Some(PendingConfirmation {
                    kind: kind_of_confirmation.clone(),
                    first_cycle: first.token.cycle_seq,
                    confirm_cycle: None,
                    worker_boot_id: first.token.worker_boot_id.clone(),
                    root_identity: selection.root_identity.clone().unwrap(),
                    policy_epoch: first.policy_epoch,
                    first_monotonic_ms: ControlSeq::new(0).unwrap(),
                }),
            };
            control_change_before(control, fixture.scope_end, |seq| {
                control.acknowledge_source(seq, &worker, ack.clone())
            })
            .unwrap();
        }
        finish(&first, CycleFinish::Partial);
        let progress = || {
            ids.iter()
                .map(|id| {
                    fixture.read_control(|control| {
                        control.source_progress(&ControlId::parse(id.as_str()).unwrap())
                    })
                })
                .collect::<Vec<_>>()
        };
        let before = progress();
        let input_binding = SourceBinding {
            source_id: input_id.clone(),
            source_path: input_path.to_str().unwrap().into(),
            provider,
            namespace_id: None,
            root_identity: affected.root_identity.as_ref().unwrap().as_str().into(),
        };
        let context = if metadata {
            SourcePublicationContext {
                dependencies: vec![SourceDependency {
                    native_session: NativeSessionId::parse("synthetic-native").unwrap(),
                    resolution: DependencyResolution::Resolved(Box::new(MetadataDependencyProof {
                        binding: input_binding.clone(),
                        receipt: RevisionRef {
                            revision_id: RevisionId::parse("synthetic-metadata-revision").unwrap(),
                            digest: "a".repeat(64),
                            observed_at_ms: 1,
                            cycle_seq: first.token.cycle_seq.get(),
                            worker_boot_id: first.token.worker_boot_id.as_str().into(),
                            catalog_incarnation: "pending-catalog".into(),
                            policy_epoch: first.policy_epoch.get(),
                            started_control_seq: first.started_control_seq.unwrap().get(),
                            committed_generation: Some(1),
                            published: true,
                        },
                        selection: SelectionProof {
                            selection_id: affected.id.as_str().into(),
                            selection_revision: affected.revision.get(),
                            root_identity: affected.root_identity.as_ref().unwrap().as_str().into(),
                        },
                        state: LifecycleState::SoftDeleted,
                        state_digest: StateDigest::parse(&"b".repeat(64)).unwrap(),
                    })),
                }],
                authority: None,
            }
        } else {
            SourcePublicationContext::default()
        };
        context.validate().unwrap();
        let failed_cycle = next();
        let mut policy =
            fixture.read_control(|control| control.read_policy(RequestIntersection::Selected));
        if policy_failure {
            policy.policy_epoch = PolicyEpoch::new(policy.policy_epoch.get() + 1).unwrap();
        }
        let hidden = fixture._temp.path().join("unavailable-admission-history");
        std::fs::rename(&affected_path, &hidden).unwrap();
        let clock = ObservationClock::new(Instant::now() - Duration::from_secs(6));
        let observed = Rc::new(Cell::new(false));
        // This is the sole end for the directly exercised production seam.
        // Only the hook after an actual Offline failure waits for it to expire.
        let end = Instant::now() + Duration::from_secs(1);
        let schedule = SourceScheduleState {
            hooks: scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
                let observed = observed.clone();
                let input_id = input_id.clone();
                move |event| {
                    if let ScheduleTestEvent::AfterAdmissionFailure(id, original_end, reason) =
                        event
                    {
                        assert_eq!(*id, input_id);
                        assert_eq!(original_end, end);
                        assert_eq!(reason, BackgroundFailure::Offline);
                        assert!(Instant::now() < end, "root failure must precede expiry");
                        observed.set(true);
                        std::thread::sleep(end.saturating_duration_since(Instant::now()));
                    }
                    Ok(())
                }
            }),
            ..SourceScheduleState::default()
        };
        let roots = [RootState {
            selection: &affected,
            revision: selection_revision(&affected).unwrap(),
            discovery: Ok(Discovery {
                files: Vec::new(),
                complete: true,
            }),
            original_end: end,
        }];
        let incarnation = ControlId::parse("pending-catalog").unwrap();
        let result = if missing {
            let prior = BackgroundSource {
                binding: input_binding,
                latest_receipt: None,
                indexed_len: None,
                superseded: false,
            };
            observe_missing_source(
                &fixture.db,
                control,
                &worker,
                &policy,
                &roots,
                &failed_cycle,
                &incarnation,
                &MissingSource {
                    prior: &prior,
                    roots: vec![0],
                    original_end: end,
                },
                &clock,
                &BTreeMap::new(),
                &schedule,
            )
            .map(|_| ())
        } else {
            observe_shared_source(
                &fixture.db,
                control,
                &worker,
                &policy,
                &roots,
                &BTreeSet::new(),
                &failed_cycle,
                &incarnation,
                &SharedSource {
                    path: input_path,
                    id: input_id.clone(),
                    hint: SourceHint {
                        len: 0,
                        mtime_ms: 0,
                    },
                    roots: vec![0],
                    provider,
                    descriptor: SourceDescriptor {
                        kind,
                        surface: None,
                        native_session: None,
                    },
                    original_end: end,
                },
                None,
                false,
                &clock,
                &mut BTreeMap::new(),
                &schedule,
            )
            .map(|_| ())
        };
        std::fs::rename(&hidden, &affected_path).unwrap();
        if policy_failure {
            assert!(matches!(result, Err(PortError::SnapshotChanged(_))));
            assert!(
                !observed.get(),
                "policy refusal did not observe a source failure"
            );
        } else {
            assert!(observed.get());
            assert!(
                matches!(result, Err(PortError::WriterBusy(ref reason))
                if reason == "control runtime deadline reached"),
                "return the original scope error, not the collected Offline error"
            );
            assert!(Instant::now() >= end);
        }
        assert_eq!(
            progress(),
            before,
            "scope failure must not fabricate an acknowledgement"
        );
        finish(&failed_cycle, CycleFinish::Aborted);
        let current = next();
        for (index, (id, selection)) in ids.iter().zip(selections).enumerate() {
            let empty = SourcePublicationContext::default();
            let contexts = [if index == 0 { &context } else { &empty }];
            let (candidate, stable) = fixture.read_control(|control| {
                confirmation(
                    control,
                    ConfirmationSource {
                        id,
                        locator: &selection.region.locator,
                        contexts: &contexts,
                    },
                    selection,
                    &current,
                    kind_of_confirmation.clone(),
                    &clock,
                )
            });
            if index == 0 && !policy_failure {
                assert_eq!(candidate.first_cycle, current.token.cycle_seq);
                assert!(
                    !stable,
                    "known failed admission must restart the confirmation"
                );
            } else {
                assert_eq!(candidate.first_cycle, first.token.cycle_seq);
                assert_eq!(candidate.first_monotonic_ms.get(), 0);
                assert!(
                    stable,
                    "unobserved or unrelated chains keep their original clock"
                );
            }
        }
        finish(&current, CycleFinish::Partial);
    }

    #[test]
    fn scheduler_shared_admission_failure_survives_runtime_scope_expiry() {
        admission_scope_failure_case(SourceKind::Jsonl, false, false);
    }

    #[test]
    fn scheduler_shared_metadata_admission_failure_survives_runtime_scope_expiry() {
        admission_scope_failure_case(SourceKind::WorkBuddyMetadata, false, false);
    }

    #[test]
    fn scheduler_missing_admission_failure_survives_runtime_scope_expiry() {
        admission_scope_failure_case(SourceKind::Jsonl, true, false);
    }

    #[test]
    fn scheduler_policy_refusal_before_admission_preserves_unobserved_chains() {
        admission_scope_failure_case(SourceKind::Jsonl, false, true);
        admission_scope_failure_case(SourceKind::Jsonl, true, true);
    }

    #[test]
    fn lost_failure_ack_reopens_only_its_source_dependency_or_exact_region() {
        use agent_session_grep_ports::managed::RevisionRef;
        for scope in ["source", "metadata", "root", "ordinary-abort"] {
            let fixture = CycleFixture::new();
            let control = &fixture.control;
            let parent = Path::new(fixture.selection.region.locator.as_str());
            let paths = [parent.join("a.jsonl"), parent.join("c.jsonl")];
            let mut selections = vec![fixture.selection.clone()];
            for path in &paths {
                std::fs::write(path, b"synthetic source").unwrap();
                let request = crate::managed_control::source_selection(
                    SearchProvider::parse("workbuddy").unwrap(),
                    path,
                )
                .unwrap();
                selections.push(
                    control_change_before(control, fixture.scope_end, |seq| {
                        control.add_selection(seq, request.clone())
                    })
                    .unwrap()
                    .value,
                );
            }
            assert_eq!(selections[1].root_identity, selections[2].root_identity);
            let worker = fixture.worker();
            let next = || {
                let queued = control_change_before(control, fixture.scope_end, |seq| {
                    control.queue_cycle(
                        seq,
                        selections
                            .iter()
                            .map(selection_revision)
                            .collect::<PortResult<_>>()?,
                    )
                })
                .unwrap()
                .value;
                let CycleAdmission::Queued(queued) = queued else {
                    panic!("synthetic multi-selection cycle was blocked")
                };
                fixture.start(&worker, &queued)
            };
            let first = next();
            let kind = ConfirmationKind::Rewrite {
                candidate_digest: ControlId::parse("candidate").unwrap(),
            };
            let ids = [
                SourceId::parse("unrelated-claude").unwrap(),
                SourceId::parse("affected-workbuddy").unwrap(),
                SourceId::parse("other-workbuddy-exact").unwrap(),
            ];
            for (id, selection) in ids.iter().zip(&selections) {
                let held = PendingConfirmation {
                    kind: kind.clone(),
                    first_cycle: first.token.cycle_seq,
                    confirm_cycle: None,
                    worker_boot_id: first.token.worker_boot_id.clone(),
                    root_identity: selection.root_identity.clone().unwrap(),
                    policy_epoch: first.policy_epoch,
                    first_monotonic_ms: ControlSeq::new(0).unwrap(),
                };
                let ack = SourceAcknowledgement {
                    source_id: ControlId::parse(id.as_str()).unwrap(),
                    provider: selection.region.provider,
                    token: first.token.clone(),
                    selection: selection_revision(selection).unwrap(),
                    attempted_at_ms: 4,
                    coverage: Coverage::Partial,
                    update_state: UpdateState::Deferred,
                    backfill_state: BackfillState::Pending,
                    error: Some(BackgroundFailure::RewritePending),
                    receipt: None,
                    confirmation: Some(held),
                };
                control_change_before(control, fixture.scope_end, |seq| {
                    control.acknowledge_source(seq, &worker, ack.clone())
                })
                .unwrap();
            }
            control_change_before(control, fixture.scope_end, |seq| {
                control.finish_cycle(seq, &worker, first.token.cycle_seq, CycleFinish::Partial, 5)
            })
            .unwrap();
            let metadata_id = SourceId::parse("metadata").unwrap();
            let context = SourcePublicationContext {
                dependencies: vec![SourceDependency {
                    native_session: NativeSessionId::parse("native").unwrap(),
                    resolution: DependencyResolution::Resolved(Box::new(MetadataDependencyProof {
                        binding: SourceBinding {
                            source_id: metadata_id.clone(),
                            source_path: parent.join("metadata.db").to_str().unwrap().into(),
                            provider: SearchProvider::parse("workbuddy").unwrap(),
                            namespace_id: None,
                            root_identity: selections[1]
                                .root_identity
                                .as_ref()
                                .unwrap()
                                .as_str()
                                .into(),
                        },
                        receipt: RevisionRef {
                            revision_id: RevisionId::parse("metadata-revision").unwrap(),
                            digest: "a".repeat(64),
                            observed_at_ms: 1,
                            cycle_seq: first.token.cycle_seq.get(),
                            worker_boot_id: first.token.worker_boot_id.as_str().into(),
                            catalog_incarnation: "pending-catalog".into(),
                            policy_epoch: first.policy_epoch.get(),
                            started_control_seq: first.started_control_seq.unwrap().get(),
                            committed_generation: Some(1),
                            published: true,
                        },
                        selection: SelectionProof {
                            selection_id: selections[1].id.as_str().into(),
                            selection_revision: selections[1].revision.get(),
                            root_identity: selections[1]
                                .root_identity
                                .as_ref()
                                .unwrap()
                                .as_str()
                                .into(),
                        },
                        state: LifecycleState::SoftDeleted,
                        state_digest: StateDigest::parse(&"b".repeat(64)).unwrap(),
                    })),
                }],
                authority: None,
            };
            context.validate().unwrap();
            let clock = ObservationClock::new(Instant::now() - Duration::from_secs(6));
            let failed = next();
            if scope != "ordinary-abort" {
                let lost = match scope {
                    "source" => FailureScope::Source(ids[1].clone()),
                    "metadata" => FailureScope::Metadata(metadata_id),
                    "root" => FailureScope::Root {
                        selection: selections[1].clone(),
                        confirmations: RootConfirmations::All,
                    },
                    _ => unreachable!(),
                };
                let writer = rusqlite::Connection::open(SqliteControlStore::path(
                    fixture.db.parent().unwrap(),
                ))
                .unwrap();
                writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                let failure = clock.record_failure(&failed, lost, || {
                    acknowledge_failure(
                        control,
                        &worker,
                        &selections[1],
                        &failed,
                        &ids[1],
                        BackgroundFailure::SourceChanged,
                    )
                });
                writer.execute_batch("ROLLBACK").unwrap();
                assert!(matches!(failure, Err(PortError::WriterBusy(_))));
            }
            control_change_before(control, fixture.scope_end, |seq| {
                control.finish_cycle(
                    seq,
                    &worker,
                    failed.token.cycle_seq,
                    CycleFinish::Aborted,
                    6,
                )
            })
            .unwrap();
            let current = next();
            for (index, (id, selection)) in ids.iter().zip(&selections).enumerate() {
                let empty = SourcePublicationContext::default();
                let contexts = if index == 1 { [&context] } else { [&empty] };
                let source = ConfirmationSource {
                    id,
                    locator: &selection.region.locator,
                    contexts: &contexts,
                };
                let (candidate, stable) =
                    confirmation(control, source, selection, &current, kind.clone(), &clock)
                        .unwrap();
                if index == 1 && scope != "ordinary-abort" {
                    assert_eq!(candidate.first_cycle, current.token.cycle_seq, "{scope}");
                    assert!(!stable, "{scope}");
                } else {
                    assert_eq!(
                        candidate.first_cycle, first.token.cycle_seq,
                        "{scope}/{index}"
                    );
                    assert_eq!(candidate.first_monotonic_ms.get(), 0, "{scope}/{index}");
                    assert!(stable, "{scope}/{index}");
                }
            }
        }
    }

    #[test]
    fn root_failure_scope_maps_complete_discovery_to_deletion_only() {
        assert!(matches!(
            root_failure_confirmations(true),
            RootConfirmations::DeletionOnly
        ));
        assert!(matches!(
            root_failure_confirmations(false),
            RootConfirmations::All
        ));
    }

    #[test]
    fn lost_root_failure_preserves_rewrite_and_deletion_watermarks_separately() {
        for scopes in [
            [RootConfirmations::All, RootConfirmations::DeletionOnly],
            [RootConfirmations::DeletionOnly, RootConfirmations::All],
        ] {
            let fixture = CycleFixture::new();
            let control = &fixture.control;
            let selection = &fixture.selection;
            let worker = fixture.worker();
            let next = || {
                let queued = control_change_before(control, fixture.scope_end, |seq| {
                    control.queue_cycle(seq, vec![selection_revision(selection)?])
                })
                .unwrap()
                .value;
                let CycleAdmission::Queued(queued) = queued else {
                    panic!("synthetic root cycle was blocked")
                };
                fixture.start(&worker, &queued)
            };
            let finish = |cycle: &ObservationCycle, state| {
                control_change_before(control, fixture.scope_end, |seq| {
                    control.finish_cycle(seq, &worker, cycle.token.cycle_seq, state, 5)
                })
                .unwrap();
            };
            let kinds = [
                ConfirmationKind::Deletion,
                ConfirmationKind::Rewrite {
                    candidate_digest: ControlId::parse("candidate").unwrap(),
                },
            ];
            let ids = [
                SourceId::parse("missing-source").unwrap(),
                SourceId::parse("rewritten-source").unwrap(),
            ];
            let save = |cycle: &ObservationCycle, source: &SourceId, held: PendingConfirmation| {
                let ack = SourceAcknowledgement {
                    source_id: ControlId::parse(source.as_str()).unwrap(),
                    provider: selection.region.provider,
                    token: cycle.token.clone(),
                    selection: selection_revision(selection).unwrap(),
                    attempted_at_ms: 4,
                    coverage: Coverage::Partial,
                    update_state: UpdateState::Deferred,
                    backfill_state: BackfillState::Pending,
                    error: Some(if matches!(held.kind, ConfirmationKind::Deletion) {
                        BackgroundFailure::DeletionPending
                    } else {
                        BackgroundFailure::RewritePending
                    }),
                    receipt: None,
                    confirmation: Some(held),
                };
                control_change_before(control, fixture.scope_end, |seq| {
                    control.acknowledge_source(seq, &worker, ack.clone())
                })
                .unwrap();
            };
            let first = next();
            for (id, kind) in ids.iter().zip(&kinds) {
                save(
                    &first,
                    id,
                    PendingConfirmation {
                        kind: kind.clone(),
                        first_cycle: first.token.cycle_seq,
                        confirm_cycle: None,
                        worker_boot_id: first.token.worker_boot_id.clone(),
                        root_identity: selection.root_identity.clone().unwrap(),
                        policy_epoch: first.policy_epoch,
                        first_monotonic_ms: ControlSeq::new(0).unwrap(),
                    },
                );
            }
            finish(&first, CycleFinish::Partial);
            let clock = ObservationClock::new(Instant::now() - Duration::from_secs(6));
            let mut expected_first = [first.token.cycle_seq; 2];
            let empty = SourcePublicationContext::default();
            let contexts = [&empty];
            for scope in scopes {
                let failed = next();
                let writer = rusqlite::Connection::open(SqliteControlStore::path(
                    fixture.db.parent().unwrap(),
                ))
                .unwrap();
                writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                let failure = clock.record_failure(
                    &failed,
                    FailureScope::Root {
                        selection: selection.clone(),
                        confirmations: scope,
                    },
                    || {
                        acknowledge_failure(
                            control,
                            &worker,
                            selection,
                            &failed,
                            &ids[0],
                            BackgroundFailure::Deferred,
                        )
                    },
                );
                writer.execute_batch("ROLLBACK").unwrap();
                assert!(matches!(failure, Err(PortError::WriterBusy(_))));
                finish(&failed, CycleFinish::Aborted);
                let current = next();
                for (index, (id, kind)) in ids.iter().zip(&kinds).enumerate() {
                    let source = ConfirmationSource {
                        id,
                        locator: &selection.region.locator,
                        contexts: &contexts,
                    };
                    let (held, _) =
                        confirmation(control, source, selection, &current, kind.clone(), &clock)
                            .unwrap();
                    if index == 0 || matches!(scope, RootConfirmations::All) {
                        expected_first[index] = current.token.cycle_seq;
                    }
                    assert_eq!(held.first_cycle, expected_first[index], "source {index}");
                    save(&current, id, held);
                }
                finish(&current, CycleFinish::Partial);
            }
        }
    }

    #[test]
    fn root_progress_read_failure_records_local_invalidation() {
        let fixture = CycleFixture::new();
        let control = &fixture.control;
        let selection = &fixture.selection;
        let worker = fixture.worker();
        let other_root = fixture._temp.path().join("other-history");
        std::fs::create_dir(&other_root).unwrap();
        let other_request =
            crate::managed_control::source_selection(SearchProvider::Claude, &other_root).unwrap();
        let other_selection = control_change_before(control, fixture.scope_end, |seq| {
            control.add_selection(seq, other_request.clone())
        })
        .unwrap()
        .value;
        let selections = [selection.clone(), other_selection.clone()];
        let next = || {
            let queued = control_change_before(control, fixture.scope_end, |seq| {
                control.queue_cycle(
                    seq,
                    selections
                        .iter()
                        .map(selection_revision)
                        .collect::<PortResult<_>>()?,
                )
            })
            .unwrap()
            .value;
            let CycleAdmission::Queued(queued) = queued else {
                panic!("synthetic root cycle was blocked")
            };
            fixture.start(&worker, &queued)
        };
        let finish = |cycle: &ObservationCycle, state| {
            control_change_before(control, fixture.scope_end, |seq| {
                control.finish_cycle(seq, &worker, cycle.token.cycle_seq, state, 5)
            })
            .unwrap();
        };

        let source_path = Path::new(selection.region.locator.as_str()).join("missing.jsonl");
        let other_source_path = other_root.join("unrelated.jsonl");
        std::fs::write(&source_path, b"synthetic source").unwrap();
        std::fs::write(&other_source_path, b"synthetic other source").unwrap();
        let locator = CanonicalLocator::from_path(&source_path).unwrap();
        let other_locator = CanonicalLocator::from_path(&other_source_path).unwrap();
        let source_id = SourceId::parse("interrupted-deletion").unwrap();
        let other_source_id = SourceId::parse("unrelated-deletion").unwrap();
        let first = next();
        for (source_id, claim) in [
            (&source_id, selection),
            (&other_source_id, &other_selection),
        ] {
            let held = PendingConfirmation {
                kind: ConfirmationKind::Deletion,
                first_cycle: first.token.cycle_seq,
                confirm_cycle: None,
                worker_boot_id: first.token.worker_boot_id.clone(),
                root_identity: claim.root_identity.clone().unwrap(),
                policy_epoch: first.policy_epoch,
                first_monotonic_ms: ControlSeq::new(0).unwrap(),
            };
            let ack = SourceAcknowledgement {
                source_id: ControlId::parse(source_id.as_str()).unwrap(),
                provider: claim.region.provider,
                token: first.token.clone(),
                selection: selection_revision(claim).unwrap(),
                attempted_at_ms: 4,
                coverage: Coverage::Partial,
                update_state: UpdateState::Deferred,
                backfill_state: BackfillState::Pending,
                error: Some(BackgroundFailure::DeletionPending),
                receipt: None,
                confirmation: Some(held),
            };
            control_change_before(control, fixture.scope_end, |seq| {
                control.acknowledge_source(seq, &worker, ack.clone())
            })
            .unwrap();
        }
        finish(&first, CycleFinish::Partial);

        let clock = ObservationClock::new(Instant::now() - Duration::from_secs(6));
        let failed = next();
        let read = record_root_failure(
            &clock,
            &failed,
            selection.clone(),
            RootConfirmations::All,
            || Err(PortError::WriterBusy("synthetic progress read".into())),
            || Err(PortError::Backend("failure acknowledgement ran".into())),
        );
        assert!(matches!(read, Err(PortError::WriterBusy(_))));
        finish(&failed, CycleFinish::Aborted);

        let current = next();
        let contexts: [&SourcePublicationContext; 0] = [];
        let (candidate, stable) = confirmation(
            control,
            ConfirmationSource {
                id: &source_id,
                locator: &locator,
                contexts: &contexts,
            },
            selection,
            &current,
            ConfirmationKind::Deletion,
            &clock,
        )
        .unwrap();
        assert_eq!(candidate.first_cycle, current.token.cycle_seq);
        assert!(!stable);
        let (unrelated, unrelated_stable) = confirmation(
            control,
            ConfirmationSource {
                id: &other_source_id,
                locator: &other_locator,
                contexts: &contexts,
            },
            &other_selection,
            &current,
            ConfirmationKind::Deletion,
            &clock,
        )
        .unwrap();
        assert_eq!(unrelated.first_cycle, first.token.cycle_seq);
        assert_eq!(unrelated.first_monotonic_ms.get(), 0);
        assert!(unrelated_stable);
    }

    #[test]
    fn pending_cycle_busy_completion_recovers_same_worker_before_next_cycle() {
        for state in [
            UpdateState::Busy,
            UpdateState::Deferred,
            UpdateState::Failed,
        ] {
            let fixture = CycleFixture::new();
            let fixture_end = Instant::now() + Duration::from_secs(60);
            let control = &fixture.control;
            let worker = fixture.worker();
            let (queued, barrier) = fixture.queued();
            let cycle = fixture.start(&worker, &queued);
            let mut pending = Some(PendingCycle {
                token: cycle.token.clone(),
                finish: CycleFinish::Partial,
            });
            let contender =
                rusqlite::Connection::open(SqliteControlStore::path(fixture.db.parent().unwrap()))
                    .unwrap();
            contender.execute_batch("BEGIN IMMEDIATE").unwrap();
            assert!(matches!(
                finish_pending_cycle(
                    control,
                    &worker,
                    &mut pending,
                    Instant::now() + Duration::from_millis(20),
                ),
                Err(PortError::WriterBusy(_))
            ));
            assert_eq!(pending.as_ref().unwrap().token, cycle.token);
            assert_eq!(pending.as_ref().unwrap().finish, CycleFinish::Partial);
            contender.execute_batch("ROLLBACK").unwrap();
            drop(contender);
            control_change_before(control, fixture_end, |seq| {
                control.heartbeat_worker(seq, &worker, state, Some(BackgroundFailure::Busy), 4)
            })
            .unwrap();
            assert!(
                run_cycle(
                    &fixture.db,
                    control,
                    &worker,
                    &ObservationClock::new(Instant::now()),
                    0,
                    fixture_end,
                    &mut pending,
                    &mut SourceScheduleState::default(),
                )
                .unwrap()
            );
            let finished = control
                .with_runtime_deadline(fixture_end, || control.cycle(cycle.token.cycle_seq))
                .unwrap();
            assert_eq!(finished.token, cycle.token);
            assert_eq!(finished.state, CycleState::Partial);
            assert!(pending.is_none());
            assert_eq!(
                control
                    .with_runtime_deadline(fixture_end, || control.background_status())
                    .unwrap()
                    .worker
                    .boot_id,
                Some(worker.boot_id().clone())
            );
            assert_eq!(
                control
                    .with_runtime_deadline(fixture_end, || control.background_status())
                    .unwrap()
                    .worker
                    .state,
                UpdateState::Running
            );
            assert_eq!(
                control
                    .with_runtime_deadline(fixture_end, || control.barrier(&barrier.id))
                    .unwrap()
                    .state,
                BarrierState::AwaitingCatalog
            );
        }
    }

    #[test]
    fn pending_cycle_start_committed_with_lost_deadline_ack_is_drained_before_next_cycle() {
        let fixture = CycleFixture::new();
        let control = &fixture.control;
        let worker = fixture.worker();
        let (queued, barrier) = fixture.queued();
        let mut pending = None;
        let mut committed = false;
        let end = Instant::now() + Duration::from_secs(1);
        let result = start_cycle_with_pending(control, &queued, &mut pending, end, |seq| {
            control.with_runtime_deadline(end, || {
                let cycle = control
                    .start_cycle(seq, &worker, queued.token.cycle_seq, 3)?
                    .value;
                committed = true;
                // The actual deadline API refuses the acknowledgement after
                // SQLite has committed; no SQL fixture manufactures Observing.
                std::thread::sleep(end.saturating_duration_since(Instant::now()));
                Ok(cycle)
            })
        });
        assert!(
            committed,
            "synthetic start did not reach its durable side effect"
        );
        // The committed acknowledgement now survives the trailing deadline
        // expiry instead of surfacing as WriterBusy; the pending intent still
        // guards the Observation state until the worker finishes its cycle.
        assert!(matches!(&result, Ok(cycle) if cycle.token == queued.token));
        assert_eq!(
            control.cycle(queued.token.cycle_seq).unwrap().state,
            CycleState::Observing
        );
        assert_eq!(pending.as_ref().unwrap().token, queued.token);
        assert_eq!(pending.as_ref().unwrap().finish, CycleFinish::Aborted);
        control_change_before(control, fixture.scope_end, |seq| {
            control.heartbeat_worker(
                seq,
                &worker,
                UpdateState::Busy,
                Some(BackgroundFailure::Busy),
                4,
            )
        })
        .unwrap();
        assert!(
            run_cycle(
                &fixture.db,
                control,
                &worker,
                &ObservationClock::new(Instant::now()),
                0,
                fixture.scope_end,
                &mut pending,
                &mut SourceScheduleState::default(),
            )
            .unwrap()
        );
        let aborted = control.cycle(queued.token.cycle_seq).unwrap();
        assert_eq!(aborted.token, queued.token);
        assert_eq!(aborted.state, CycleState::Aborted);
        assert!(pending.is_none());
        assert_eq!(
            control.barrier(&barrier.id).unwrap().state,
            BarrierState::Blocked
        );
        assert_eq!(
            control.background_status().unwrap().worker.boot_id,
            Some(worker.boot_id().clone())
        );
    }

    #[test]
    fn pending_cycle_policy_aborts_are_recognized_without_resuming_intent() {
        for change in ["pause", "stop", "maintenance", "revoke"] {
            let fixture = CycleFixture::new();
            let control = &fixture.control;
            let worker = fixture.worker();
            let (queued, barrier) = fixture.queued();
            let cycle = fixture.start(&worker, &queued);
            let mut pending = Some(PendingCycle {
                token: cycle.token.clone(),
                finish: CycleFinish::Committed,
            });
            let owner = ControlId::parse("pending-maintenance").unwrap();
            control_change_before(control, fixture.scope_end, |seq| match change {
                "pause" => control
                    .set_desired_updates(seq, DesiredUpdates::Paused)
                    .map(|_| ()),
                "stop" => control
                    .set_desired_updates(seq, DesiredUpdates::Stopped)
                    .map(|_| ()),
                "maintenance" => control
                    .set_maintenance(
                        seq,
                        &owner,
                        MaintenanceFence {
                            state: MaintenanceState::Updating,
                            owner: Some(owner.clone()),
                            phase: Some(MaintenancePhase::Quiescing),
                        },
                    )
                    .map(|_| ()),
                "revoke" => control
                    .revoke_selection(seq, &fixture.selection.id, None, 4)
                    .map(|_| ()),
                _ => unreachable!(),
            })
            .unwrap();
            let before = control.status().unwrap();
            let terminal = control.cycle(cycle.token.cycle_seq).unwrap();
            assert_eq!(terminal.state, CycleState::Aborted);
            finish_pending_cycle(
                control,
                &worker,
                &mut pending,
                Instant::now() + CONTROL_BUDGET,
            )
            .unwrap();
            assert!(pending.is_none());
            assert_eq!(control.status().unwrap(), before);
            assert_eq!(control.cycle(cycle.token.cycle_seq).unwrap(), terminal);
            assert_eq!(
                control.barrier(&barrier.id).unwrap().state,
                BarrierState::Blocked
            );
            if change != "revoke" {
                let started = Instant::now();
                assert!(matches!(
                    run_cycle(
                        &fixture.db,
                        control,
                        &worker,
                        &ObservationClock::new(Instant::now()),
                        0,
                        fixture.scope_end,
                        &mut pending,
                        &mut SourceScheduleState::default(),
                    ),
                    Err(PortError::SnapshotChanged(_))
                ));
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "policy refusal must not retry the heartbeat to the observation deadline"
                );
                assert_eq!(control.status().unwrap(), before);
            } else {
                assert!(!control.status().unwrap().policy.selections[0].enabled);
                assert_eq!(control.purge_jobs().unwrap()[0].state, PurgeState::Pending);
            }
        }
    }

    #[test]
    fn pending_cycle_rejects_foreign_token_without_mutation() {
        for aborted in [false, true] {
            let fixture = CycleFixture::new();
            let control = &fixture.control;
            let worker = fixture.worker();
            let (queued, _) = fixture.queued();
            let cycle = fixture.start(&worker, &queued);
            if aborted {
                control_change_before(control, fixture.scope_end, |seq| {
                    control.finish_cycle(
                        seq,
                        &worker,
                        cycle.token.cycle_seq,
                        CycleFinish::Aborted,
                        4,
                    )
                })
                .unwrap();
            }
            let foreign = ObservationToken {
                cycle_seq: cycle.token.cycle_seq,
                worker_boot_id: ControlId::parse("foreign-worker").unwrap(),
            };
            let mut pending = Some(PendingCycle {
                token: foreign.clone(),
                finish: CycleFinish::Partial,
            });
            let before = control.status().unwrap();
            let original = control.cycle(cycle.token.cycle_seq).unwrap();
            assert!(matches!(
                finish_pending_cycle(
                    control,
                    &worker,
                    &mut pending,
                    Instant::now() + CONTROL_BUDGET
                ),
                Err(PortError::SnapshotChanged(_))
            ));
            assert_eq!(pending.as_ref().unwrap().token, foreign);
            assert_eq!(control.status().unwrap(), before);
            assert_eq!(control.cycle(cycle.token.cycle_seq).unwrap(), original);

            // Even a matching terminal token is not owned by another boot.
            let foreign_worker = control
                .bind_worker(&fixture.worker_lock, foreign.worker_boot_id.clone())
                .unwrap();
            let mut pending = Some(PendingCycle {
                token: cycle.token.clone(),
                finish: CycleFinish::Partial,
            });
            assert!(matches!(
                finish_pending_cycle(
                    control,
                    &foreign_worker,
                    &mut pending,
                    Instant::now() + CONTROL_BUDGET,
                ),
                Err(PortError::SnapshotChanged(_))
            ));
            assert_eq!(pending.as_ref().unwrap().token, cycle.token);
            assert_eq!(control.status().unwrap(), before);
            assert_eq!(control.cycle(cycle.token.cycle_seq).unwrap(), original);
        }
    }

    #[test]
    fn pending_cycle_terminal_readback_never_republishes_completion_or_latest_proof() {
        for finish in [
            CycleFinish::Committed,
            CycleFinish::Partial,
            CycleFinish::Aborted,
        ] {
            let fixture = CycleFixture::new();
            let control = &fixture.control;
            let worker = fixture.worker();
            let (queued, barrier) = fixture.queued();
            let cycle = fixture.start(&worker, &queued);
            if finish == CycleFinish::Committed {
                control_change_before(control, fixture.scope_end, |seq| {
                    control.acknowledge_discovery(
                        seq,
                        &worker,
                        DiscoveryAcknowledgement {
                            token: cycle.token.clone(),
                            selection: selection_revision(&fixture.selection).unwrap(),
                            complete: true,
                            discovered_count: 0,
                            observed_count: 0,
                            committed_count: 0,
                            error: None,
                        },
                    )
                })
                .unwrap();
            }
            control_change_before(control, fixture.scope_end, |seq| {
                control.finish_cycle(seq, &worker, cycle.token.cycle_seq, finish, 4)
            })
            .unwrap();
            let terminal = control.cycle(cycle.token.cycle_seq).unwrap();
            let before = control.status().unwrap();
            let mut pending = Some(PendingCycle {
                token: cycle.token.clone(),
                finish: CycleFinish::Committed,
            });
            finish_pending_cycle(control, &worker, &mut pending, fixture.scope_end).unwrap();
            assert!(pending.is_none());
            assert_eq!(control.status().unwrap(), before);
            assert_eq!(control.cycle(cycle.token.cycle_seq).unwrap(), terminal);
            let store = ManagedStore::open(&fixture.db, control).unwrap();
            assert!(
                !store
                    .with_read(
                        control,
                        RequestIntersection::Selected,
                        Instant::now() + Duration::from_secs(2),
                        |read| read.latest_satisfied(&barrier),
                    )
                    .unwrap()
            );
        }
    }

    #[test]
    fn explicit_control_deadline_refuses_expired_work_and_sql_reuses_original_end() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let control = SqliteControlStore::create(
            &temp.path().join("private"),
            &ControlId::parse("install").unwrap(),
            DesiredUpdates::Paused,
        )
        .unwrap();
        let before = control.status().unwrap();
        let mut entered = false;
        assert!(matches!(
            control_change_before(&control, Instant::now(), |_| {
                entered = true;
                Ok(())
            }),
            Err(PortError::WriterBusy(_))
        ));
        assert!(!entered);
        let root = temp.path().join("private");
        let contender = rusqlite::Connection::open(SqliteControlStore::path(&root)).unwrap();
        contender.execute_batch("BEGIN IMMEDIATE").unwrap();
        let start = Instant::now();
        assert!(matches!(
            control_change_before(&control, start + Duration::from_millis(20), |seq| {
                control.set_desired_updates(seq, DesiredUpdates::Running)
            }),
            Err(PortError::WriterBusy(_))
        ));
        assert!(start.elapsed() < Duration::from_millis(200));
        contender.execute_batch("ROLLBACK").unwrap();
        assert_eq!(control.status().unwrap(), before);
        control_change_before(&control, Instant::now() + Duration::from_secs(1), |seq| {
            control.set_desired_updates(seq, DesiredUpdates::Running)
        })
        .unwrap();
        assert_eq!(
            control.status().unwrap().desired_updates,
            DesiredUpdates::Running
        );
    }
}
