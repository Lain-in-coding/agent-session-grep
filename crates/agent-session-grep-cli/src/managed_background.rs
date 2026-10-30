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
                        let watermarks = if let Some(index) =
                            failures.roots.iter().position(|lost| {
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
        result
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
) -> PortResult<CanonicalLocator> {
    check_policy(control, policy)?;
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
    modified: SystemTime,
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
            let modified = std::fs::symlink_metadata(&path)
                .and_then(|metadata| metadata.modified())
                .map_err(|_| unavailable())?;
            result.files.push(Discovered {
                path,
                id,
                modified,
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
            .modified
            .cmp(&left.modified)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(result)
}
fn observation_deadline(end: Instant) -> PortResult<()> {
    if Instant::now() >= end {
        Err(PortError::WriterBusy(
            "managed source observation deadline reached".into(),
        ))
    } else {
        Ok(())
    }
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

fn run_cycle(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    boot: &ObservationClock,
    round: u64,
    end: Instant,
    pending: &mut Option<PendingCycle>,
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
    let result = observe_cycle(db, control, authority, &policy, &selections, &cycle, boot);
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
    modified: SystemTime,
    roots: Vec<usize>,
    provider: SearchProvider,
    descriptor: SourceDescriptor,
    original_end: Instant,
}

struct ObservationOutcome {
    published: bool,
    claimed: BTreeSet<usize>,
    failed: Option<BackgroundFailure>,
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
    let locator = admit(control, policy, advisory, &source.path, &source.id)?;
    let snapshot = capture_with_deadline(&source.path, limit, end)?;
    admit(control, policy, advisory, &source.path, &source.id)?;
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
        admit(control, policy, claim, &source.path, &source.id)?;
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
        admit(control, policy, claim, &source.path, &source.id)?;
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
            admit(control, policy, claim, &self.source.path, &self.source.id)?;
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

fn observe_cycle(
    db: &Path,
    control: &SqliteControlStore,
    authority: &LockedWorkerAuthority<'_>,
    policy: &ReadPolicy,
    selections: &[Selection],
    cycle: &ObservationCycle,
    boot: &ObservationClock,
) -> PortResult<bool> {
    let store = ManagedStore::open(db, control)?;
    let incarnation = store.incarnation().clone();
    let known = store
        .background_sources(control)?
        .into_iter()
        .map(|s| (s.binding.source_path.clone(), s))
        .collect::<BTreeMap<_, _>>();
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
                        modified: file.modified,
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
    // Phase 2: observe each shared locator once with every independently
    // validated selection/root claim.
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
    // Metadata is observed first only if independently selected. Its immutable
    // empty-content receipt is then linked to transcript observations from this
    // same cycle; no planner-created sibling permission is possible.
    let mut groups = shared
        .values()
        .filter(|source| !shadowed.contains(source.id.as_str()))
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        matches!(right.descriptor.kind, SourceKind::WorkBuddyMetadata)
            .cmp(&matches!(
                left.descriptor.kind,
                SourceKind::WorkBuddyMetadata
            ))
            .then_with(|| right.modified.cmp(&left.modified))
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut metadata = BTreeMap::<String, WorkBuddyMetadata>::new();
    let mut outcomes = BTreeMap::<String, ObservationOutcome>::new();
    for group in groups {
        check_policy(control, policy)?;
        let mut claimed = Vec::new();
        let mut failed = None;
        for &index in &group.roots {
            match admit(
                control,
                policy,
                roots[index].selection,
                &group.path,
                &group.id,
            ) {
                Ok(_) => claimed.push(index),
                Err(error) => {
                    failed.get_or_insert(failure(&error));
                }
            }
        }
        if claimed.is_empty() {
            let failure = failed.unwrap_or(BackgroundFailure::ScopeUnverified);
            // Every participating root failed independent validation; keep the
            // source's control summary honest instead of silently skipping it.
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
                    failure,
                )
            })?;
            outcomes.insert(
                group.id.as_str().to_owned(),
                ObservationOutcome {
                    published: false,
                    claimed: BTreeSet::new(),
                    failed: Some(failure),
                },
            );
            continue;
        }
        let prior = group.path.to_str().and_then(|path| known.get(path));
        // Rewrite eligibility belongs to one independently complete root, not
        // the intersection of every overlapping root's coverage. Keep a pending
        // qualifying root even if the historical root later becomes complete.
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
            .source_progress(&ControlId::parse(group.id.as_str())?)?
            .and_then(|progress| progress.confirmation)
            .filter(|pending| matches!(pending.kind, ConfirmationKind::Rewrite { .. }));
        let advisory = roots[advisory_selection(
            if qualifying.is_empty() {
                &claimed
            } else {
                &qualifying
            },
            &roots,
            prior.map(|prior| prior.binding.root_identity.as_str()),
            pending
                .as_ref()
                .map(|pending| pending.root_identity.as_str()),
        )]
        .selection;
        let claims = claimed
            .iter()
            .map(|&index| roots[index].selection)
            .collect::<Vec<_>>();
        let discovery_complete = !qualifying.is_empty();
        if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
            let source = Discovered {
                path: group.path.clone(),
                id: group.id.clone(),
                modified: group.modified,
                descriptor: group.descriptor.clone(),
                original_end: group.original_end,
            };
            let result = control.with_runtime_deadline(group.original_end, || {
                observe_workbuddy_metadata(
                    db,
                    control,
                    authority,
                    policy,
                    advisory,
                    &claims,
                    cycle,
                    &incarnation,
                    &source,
                    prior,
                )
            });
            let (published, failed) = match result {
                Ok(observed) => {
                    metadata.insert(
                        CanonicalLocator::from_path(&group.path)?.as_str().into(),
                        observed,
                    );
                    (true, None)
                }
                Err(error) => {
                    let reason = failure(&error);
                    boot.record_failure(cycle, FailureScope::Metadata(group.id.clone()), || {
                        acknowledge_failure(control, authority, advisory, cycle, &group.id, reason)
                    })?;
                    (false, Some(reason))
                }
            };
            outcomes.insert(
                group.id.as_str().into(),
                ObservationOutcome {
                    published,
                    claimed: claimed.into_iter().collect(),
                    failed,
                },
            );
            continue;
        }
        match control.with_runtime_deadline(group.original_end, || {
            observe_source(
                db,
                control,
                authority,
                policy,
                advisory,
                &claims,
                cycle,
                &incarnation,
                &Discovered {
                    path: group.path.clone(),
                    id: group.id.clone(),
                    modified: group.modified,
                    descriptor: group.descriptor.clone(),
                    original_end: group.original_end,
                },
                prior,
                boot,
                discovery_complete,
                &metadata,
            )
        }) {
            Ok(published) => {
                outcomes.insert(
                    group.id.as_str().to_owned(),
                    ObservationOutcome {
                        published,
                        claimed: claimed.into_iter().collect(),
                        failed: None,
                    },
                );
            }
            Err(error) => {
                let failure = failure(&error);
                boot.record_failure(cycle, FailureScope::Source(group.id.clone()), || {
                    acknowledge_failure(control, authority, advisory, cycle, &group.id, failure)
                })?;
                outcomes.insert(
                    group.id.as_str().to_owned(),
                    ObservationOutcome {
                        published: false,
                        claimed: claimed.into_iter().collect(),
                        failed: Some(failure),
                    },
                );
            }
        }
    }
    // Absence needs every covering root complete; an offline or partial root
    // keeps its own coverage incomplete instead of supplying stale deletion.
    let mut absent = BTreeMap::<String, ObservationOutcome>::new();
    for prior in known.values() {
        let id = prior.binding.source_id.as_str().to_owned();
        if prior.superseded || shared.contains_key(&id) {
            continue;
        }
        let prior_descriptor = managed_source_discovery::describe(
            prior.binding.provider,
            Path::new(&prior.binding.source_path),
            false,
        );
        if prior_descriptor.as_ref().is_some_and(|old| {
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
        if covering.is_empty() {
            continue;
        }
        if !covering.iter().all(|&index| {
            roots[index]
                .discovery
                .as_ref()
                .is_ok_and(|discovery| discovery.complete)
        }) {
            continue;
        }
        check_policy(control, policy)?;
        let source_id = ControlId::parse(&id)?;
        let mut claimed = Vec::new();
        let mut failed = None;
        for &index in &covering {
            let selection = roots[index].selection;
            match verify_root(selection) {
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
        if claimed.is_empty() {
            let failure = failed.unwrap_or(BackgroundFailure::ScopeUnverified);
            boot.record_failure(
                cycle,
                FailureScope::Source(prior.binding.source_id.clone()),
                || {
                    acknowledge_failure(
                        control,
                        authority,
                        roots[covering[0]].selection,
                        cycle,
                        &prior.binding.source_id,
                        failure,
                    )
                },
            )?;
            absent.insert(
                id,
                ObservationOutcome {
                    published: false,
                    claimed: BTreeSet::new(),
                    failed: Some(failure),
                },
            );
            continue;
        }
        let advisory = roots[advisory_selection(
            &claimed,
            &roots,
            Some(prior.binding.root_identity.as_str()),
            None,
        )]
        .selection;
        let claims = claimed
            .iter()
            .map(|&index| roots[index].selection)
            .collect::<Vec<_>>();
        match observe_missing(
            db,
            control,
            authority,
            policy,
            advisory,
            &claims,
            cycle,
            &incarnation,
            prior,
            boot,
            &metadata,
            covering
                .iter()
                .map(|&index| roots[index].original_end)
                .min()
                .ok_or_else(invalid)?,
        ) {
            Ok(confirmed) => {
                absent.insert(
                    id,
                    ObservationOutcome {
                        published: confirmed,
                        claimed: claimed.into_iter().collect(),
                        failed: (!confirmed).then_some(BackgroundFailure::DeletionPending),
                    },
                );
            }
            Err(error) => {
                let failure = failure(&error);
                boot.record_failure(
                    cycle,
                    FailureScope::Source(prior.binding.source_id.clone()),
                    || {
                        acknowledge_failure(
                            control,
                            authority,
                            advisory,
                            cycle,
                            &prior.binding.source_id,
                            failure,
                        )
                    },
                )?;
                absent.insert(
                    id,
                    ObservationOutcome {
                        published: false,
                        claimed: claimed.into_iter().collect(),
                        failed: Some(failure),
                    },
                );
            }
        }
    }
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
                if outcome.claimed.contains(&index) {
                    observed += 1;
                    if outcome.published {
                        committed += 1;
                    } else {
                        observations_clean = false;
                        error.get_or_insert(outcome.failed.unwrap_or(BackgroundFailure::Deferred));
                    }
                } else {
                    observations_clean = false;
                    error.get_or_insert(
                        outcome.failed.unwrap_or(BackgroundFailure::ScopeUnverified),
                    );
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
            if complete && error.is_none() {
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
                        Some(outcome) if outcome.claimed.contains(&index) => {
                            observed += 1;
                            if outcome.published {
                                committed += 1;
                            } else {
                                error.get_or_insert(BackgroundFailure::DeletionPending);
                            }
                        }
                        Some(outcome) => {
                            observations_clean = false;
                            error.get_or_insert(
                                outcome.failed.unwrap_or(BackgroundFailure::ScopeUnverified),
                            );
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
) -> PortResult<bool> {
    let end = source.original_end;
    let input_limit = source.descriptor.kind.max_input_bytes();
    observation_deadline(end)?;
    let locator = admit(control, policy, advisory, &source.path, &source.id)?;
    let snapshot = capture_with_deadline(&source.path, input_limit, end)?;
    admit(control, policy, advisory, &source.path, &source.id)?;
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
    admit(control, policy, advisory, &source.path, &source.id)?;
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
        admit(control, policy, advisory, &source.path, &source.id)?;
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
    admit(control, policy, advisory, &source.path, &source.id)?;
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
    admit(control, policy, advisory, &source.path, &source.id)?;
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
        admit(control, policy, claim, &source.path, &source.id)?;
    }
    observation_deadline(end)?;
    observation.committed_at_ms = app_clock_ms();
    let publication = writer.commit_source_with_context(
        control,
        authority,
        &batch,
        &observation,
        &context,
        end,
    )?;
    let current = publication.receipt.published
        && writer.source_current(&publication.receipt, control, end)?;
    drop(writer);
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
    Ok(current)
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
            let request =
                crate::managed_control::source_selection(SearchProvider::Claude, &history).unwrap();
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
            let cycle = self.control.cycle(barrier.required_cycle_seq).unwrap();
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
