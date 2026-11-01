//! Selected-history worker. Only an explicit control action starts this process.
//! The OS background lock owns its entire lifetime; catalog leases cover one
//! publication at a time. Public reports contain no source locators or content.
use crate::{
    CliError, ProtocolError, app_clock_ms,
    managed_source_discovery::{self, SourceDescriptor, SourceKind},
    update_state::EpochGate,
};
use agent_session_grep_adapters_sqlite::{
    PARSER_SEMANTIC_VERSION, SourceBatch, SqliteControlStore, capture_with_deadline,
    control::LockedWorkerAuthority,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_refresh::RefreshOutcome,
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
    collections::{BTreeMap, BTreeSet, VecDeque},
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
const SOURCE_HOT_HINT_BATCH: usize = 16;
const FULL_VERIFICATION_INTERVAL: Duration = Duration::from_secs(300);

/// The monotonic confirmation clock and failures whose invalidation could not
/// be recorded in control. Ordinary cycle aborts do not invalidate other
/// sources. These boot-local marks retain only the affected source, metadata
/// dependency or exact discovery region; a new epoch already invalidates every
/// old confirmation. Capacity exhaustion ends this worker before more source
/// work, so an unrecorded failure can never be silently forgotten.
struct ObservationClock {
    started: Instant,
    failures: RefCell<LostFailures>,
    epoch_gate: EpochGate,
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
    fn at_startup(started: Instant) -> Self {
        Self::with_epoch_gate(started, EpochGate::at_startup())
    }

    #[cfg(test)]
    fn new(started: Instant) -> Self {
        Self::with_epoch_gate(started, EpochGate::fixture())
    }

    fn with_epoch_gate(started: Instant, epoch_gate: EpochGate) -> Self {
        Self {
            started,
            failures: RefCell::new(LostFailures::default()),
            epoch_gate,
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

    fn epoch_permit(
        &self,
        control: &SqliteControlStore,
        end: Instant,
        #[cfg(test)] hooks: &ScheduleTestHooks,
    ) -> Result<crate::update_state::EpochPermit, crate::update_state::EpochRefusal> {
        #[cfg(test)]
        if let Some(prefix) = &hooks.epoch_lock_prefix {
            return EpochGate::fixture_for_installation(prefix.clone()).permit(control, end);
        }
        self.epoch_gate.permit(control, end)
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

    fn baseline_lost(
        &self,
        source: &SharedSource,
        roots: &[RootState<'_>],
        receipt_cycle: i64,
        epoch: PolicyEpoch,
    ) -> bool {
        let failures = self.failures.borrow();
        if failures.epoch != Some(epoch) {
            return false;
        }
        failures
            .sources
            .get(&source.id)
            .is_some_and(|lost| lost.get() >= receipt_cycle)
            || source.roots.iter().any(|&index| {
                failures.roots.iter().any(|lost| {
                    roots[index].selection.root_identity.as_ref() == Some(&lost.identity)
                        && lost.all.is_some_and(|lost| lost.get() >= receipt_cycle)
                })
            })
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
    let boot = ObservationClock::at_startup(Instant::now());
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
        let mut idle_completed = None;
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
                Ok(outcome) => {
                    let closed_idle = outcome.idle();
                    idle_completed = if closed_idle {
                        schedule.closed_idle_at
                    } else {
                        None
                    };
                    (
                        if closed_idle {
                            UpdateState::Idle
                        } else {
                            UpdateState::Deferred
                        },
                        if closed_idle {
                            None
                        } else {
                            Some(BackgroundFailure::Deferred)
                        },
                    )
                }
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
                    idle_completed = None;
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
        let wait = if let Some(completed) = idle_completed {
            CADENCE.saturating_sub(completed.elapsed())
        } else {
            CADENCE.saturating_sub(tick.elapsed())
        };
        std::thread::sleep(wait);
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
    let current = control.lifecycle_status()?;
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

#[derive(Debug, Clone, Copy)]
struct CycleOutcome {
    catalog_complete: bool,
    all_sources_attempted: bool,
    remaining_work: bool,
}

impl CycleOutcome {
    fn idle(self) -> bool {
        self.catalog_complete && !self.remaining_work
    }

    fn finish(self) -> CycleFinish {
        if self.catalog_complete && self.all_sources_attempted {
            CycleFinish::Committed
        } else {
            CycleFinish::Partial
        }
    }
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
) -> PortResult<CycleOutcome> {
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
        schedule.closed_idle_at = Some(Instant::now());
        return Ok(CycleOutcome {
            catalog_complete: true,
            all_sources_attempted: true,
            remaining_work: false,
        });
    }
    // Rotate the first selection as well as processing every candidate. An old
    // root cannot be permanently behind a continuously busy recent root.
    let rotation = round as usize % selections.len();
    selections.rotate_left(rotation);
    let revisions = selections
        .iter()
        .map(selection_revision)
        .collect::<PortResult<Vec<_>>>()?;
    let demands = control.with_runtime_deadline(end, || control.latest_demands())?;
    schedule.update_demands(demands, &policy, schedule.now())?;
    // A subset latest request can own a queued cycle that ordinary all-root
    // allocation would never coalesce with. Start it only under its real token.
    let demanded = schedule.queued_demand(schedule.now());
    let demanded = demanded
        .map(|number| control.with_runtime_deadline(end, || control.cycle(number)))
        .transpose()?
        .filter(|queued| {
            queued.state == CycleState::Queued
                && queued.token.worker_boot_id == *authority.boot_id()
                && queued.policy_epoch == policy.policy_epoch
                && queued
                    .selections
                    .iter()
                    .all(|selected| revisions.contains(&selected.selection))
        });
    let queued = if let Some(queued) = demanded {
        selections.retain(|selection| {
            queued.selections.iter().any(|selected| {
                selected.selection.selection_id == selection.id
                    && selected.selection.revision == selection.revision
                    && selection.root_identity.as_ref() == Some(&selected.selection.root_identity)
            })
        });
        queued
    } else {
        let queued = control_change_before(control, end, |seq| {
            control.queue_cycle(seq, revisions.clone())
        })?;
        let CycleAdmission::Queued(queued) = queued.value else {
            return Err(changed());
        };
        queued
    };
    let cycle = start_cycle_with_pending(control, &queued, pending, end, |seq| {
        control
            .start_cycle(seq, authority, queued.token.cycle_seq, app_clock_ms())
            .map(|change| change.value)
    })?;
    // A short eligibility check only chooses the plan. Release its permit
    // before any root/source observation; publication must acquire a new one.
    let epoch_plan = boot
        .epoch_permit(
            control,
            end,
            #[cfg(test)]
            &schedule.hooks,
        )
        .map(drop);
    #[cfg(test)]
    if let Err(reason) = epoch_plan {
        schedule
            .hooks
            .epoch_refusals
            .borrow_mut()
            .push((EpochSite::Plan, reason));
    }
    let epoch_plan_allowed = epoch_plan.is_ok();
    let result = observe_cycle(
        db,
        control,
        authority,
        &policy,
        &selections,
        &cycle,
        boot,
        schedule,
        epoch_plan_allowed,
    );
    schedule.closed_idle_at = result
        .as_ref()
        .ok()
        .filter(|outcome| outcome.idle())
        .map(|_| Instant::now());
    pending.as_mut().ok_or_else(invalid)?.finish = match &result {
        Ok(outcome) => outcome.finish(),
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
    ProbeFailed(BackgroundFailure),
    VerifiedBaseline {
        hint: SourceHint,
        claimed: BTreeSet<usize>,
    },
    Attempted {
        published: bool,
        committed: bool,
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
    published: bool,
    successful: Option<SuccessfulSourceAttempt>,
}

struct SuccessfulSourceAttempt {
    baseline: BackgroundSource,
    hint: SourceHint,
    revisitable: bool,
    /// Exactly the roots this attempt wrote to receipt_selection_claims.
    claims: Vec<SelectionRevision>,
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
    worker_boot: ControlId,
    parser: u32,
    epoch: PolicyEpoch,
    selections: Vec<SelectionRevision>,
}

struct SourceDebt {
    ticket: u64,
    verified: Option<(RevisionId, SourceHint, Vec<SelectionRevision>)>,
    last_full_verified: Option<Instant>,
    owed: bool,
    dirty: bool,
}

struct LatestDemand {
    barrier: LatestBarrier,
    service_end: Instant,
    retired: bool,
    queued_considered: bool,
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
    hot_probes: VecDeque<SourceId>,
    next_probe: Option<Instant>,
    probes_in_window: usize,
    probe_window: Option<Instant>,
    demands: BTreeMap<ControlId, LatestDemand>,
    closed_idle_at: Option<Instant>,
    #[cfg(test)]
    hooks: ScheduleTestHooks,
}

impl SourceScheduleState {
    fn prepare(
        &mut self,
        policy: &ReadPolicy,
        incarnation: &ControlId,
        worker_boot: &ControlId,
    ) -> PortResult<()> {
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
            worker_boot: worker_boot.clone(),
            parser: PARSER_SEMANTIC_VERSION,
            epoch: policy.policy_epoch,
            selections,
        };
        if self.identity.as_ref() != Some(&identity) {
            self.sources.clear();
            self.next_ticket = 0;
            self.active_attempts = 0;
            self.next_debt = SourceLane::Cold;
            self.probe_after = None;
            self.hot_probes.clear();
            self.next_probe = None;
            self.probes_in_window = 0;
            self.probe_window = None;
            self.identity = Some(identity);
            self.closed_idle_at = None;
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
                    last_full_verified: None,
                    owed: true,
                    dirty: false,
                },
            );
        }
        let debt = self.sources.get_mut(id).ok_or_else(invalid)?;
        if debt.verified.as_ref().is_some_and(|(revision, _, _)| {
            prior
                .and_then(|p| p.latest_receipt.as_ref())
                .is_none_or(|receipt| !receipt.published || &receipt.revision_id != revision)
        }) {
            // A possibly committed failure is reconciled from the real head in
            // the next cycle. Never attach a remembered hint to another receipt.
            debt.verified = None;
            debt.last_full_verified = None;
            debt.owed = true;
        }
        Ok(())
    }

    fn invalidate(&mut self, id: &SourceId) {
        if let Some(debt) = self.sources.get_mut(id) {
            debt.verified = None;
            debt.last_full_verified = None;
            debt.owed = true;
        }
    }

    fn full_due(&self, id: &SourceId, now: Instant) -> bool {
        self.sources.get(id).is_none_or(|debt| {
            debt.owed
                || debt.dirty
                || debt.last_full_verified.is_none_or(|last| {
                    now.saturating_duration_since(last) >= FULL_VERIFICATION_INTERVAL
                })
        })
    }

    fn remember_hot(&mut self, id: &SourceId) {
        if !self.hot_probes.contains(id) {
            self.hot_probes.push_back(id.clone());
            if self.hot_probes.len() > SOURCE_HINT_BATCH {
                self.hot_probes.pop_front();
            }
        }
    }

    fn update_demands(
        &mut self,
        barriers: Vec<LatestBarrier>,
        policy: &ReadPolicy,
        now: Instant,
    ) -> PortResult<()> {
        self.update_demands_within(
            barriers,
            policy,
            now,
            agent_session_grep_adapters_sqlite::control::MAX_RUNTIME_REFERENCES,
        )
    }

    fn update_demands_within(
        &mut self,
        barriers: Vec<LatestBarrier>,
        policy: &ReadPolicy,
        now: Instant,
        capacity: usize,
    ) -> PortResult<()> {
        // The inventory is complete. A barrier leaves it only as terminal,
        // epoch-blocked or another boot's, and never returns, so forgetting it
        // cannot reopen a window. A retired ID still listed stays retired.
        let present = barriers
            .iter()
            .map(|barrier| barrier.id.clone())
            .collect::<BTreeSet<_>>();
        self.demands.retain(|id, _| present.contains(id));
        for barrier in barriers {
            let compatible = barrier.policy_epoch == policy.policy_epoch
                && barrier.selections.iter().all(|revision| {
                    policy.selections.iter().any(|selection| {
                        selection.enabled
                            && selection.id == revision.selection_id
                            && selection.revision == revision.revision
                            && selection.root_identity.as_ref() == Some(&revision.root_identity)
                    })
                });
            if let Some(demand) = self.demands.get_mut(&barrier.id) {
                demand.retired |= !compatible
                    || barrier.state == BarrierState::Blocked
                    || now >= demand.service_end;
                // An immutable admission mismatch is never a new service window.
                if demand.barrier.admission_control_seq != barrier.admission_control_seq
                    || demand.barrier.required_cycle_seq != barrier.required_cycle_seq
                    || demand.barrier.selections != barrier.selections
                {
                    return Err(changed());
                }
                demand.barrier = barrier;
                continue;
            }
            if self.demands.len() >= capacity {
                return Err(discovery_capacity());
            }
            let window =
                Duration::from_millis(u64::from(barrier.requested_wait_ms.min(MAX_LATEST_WAIT_MS)));
            self.demands.insert(
                barrier.id.clone(),
                LatestDemand {
                    retired: !compatible || barrier.state == BarrierState::Blocked,
                    barrier,
                    service_end: now + window,
                    queued_considered: false,
                },
            );
        }
        for demand in self.demands.values_mut() {
            demand.retired |= now >= demand.service_end;
        }
        Ok(())
    }

    fn queued_demand(&mut self, now: Instant) -> Option<CycleSeq> {
        let demand = self
            .demands
            .values_mut()
            .filter(|demand| {
                !demand.retired
                    && now < demand.service_end
                    && demand.barrier.state == BarrierState::Pending
                    && !demand.queued_considered
            })
            .min_by_key(|demand| demand.barrier.required_cycle_seq)?;
        demand.queued_considered = true;
        Some(demand.barrier.required_cycle_seq)
    }

    fn latest_threshold(
        &self,
        revisions: impl Iterator<Item = SelectionRevision>,
        now: Instant,
    ) -> Option<(i64, i64)> {
        let revisions = revisions.collect::<Vec<_>>();
        self.demands
            .values()
            .filter(|demand| {
                !demand.retired
                    && now < demand.service_end
                    && demand
                        .barrier
                        .selections
                        .iter()
                        .any(|selection| revisions.contains(selection))
            })
            .map(|demand| {
                (
                    demand.barrier.required_cycle_seq.get(),
                    demand.barrier.admission_control_seq.get(),
                )
            })
            .reduce(|a, b| (a.0.max(b.0), a.1.max(b.1)))
    }

    fn cycle_can_serve(
        &self,
        revisions: impl Iterator<Item = SelectionRevision>,
        cycle: &ObservationCycle,
        now: Instant,
    ) -> bool {
        self.latest_threshold(revisions, now)
            .is_none_or(|(required, admission)| {
                cycle.token.cycle_seq.get() >= required
                    && cycle
                        .started_control_seq
                        .is_some_and(|start| start.get() > admission)
            })
    }

    fn latest_owed(
        &self,
        revisions: impl Iterator<Item = SelectionRevision>,
        receipt: Option<&agent_session_grep_ports::managed::RevisionRef>,
        now: Instant,
    ) -> bool {
        self.latest_threshold(revisions, now)
            .is_some_and(|(required, admission)| {
                receipt.is_none_or(|receipt| {
                    !receipt.published
                        || receipt.cycle_seq < required
                        || receipt.started_control_seq <= admission
                })
            })
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
    // Consumed only by final discover; never extends the original root end.
    final_discovery_end: Option<std::rc::Rc<std::cell::Cell<Option<Instant>>>>,
    epoch_lock_prefix: Option<PathBuf>,
    source_phase: std::cell::Cell<SourceAttemptPhase>,
    on_event: Option<RefCell<ScheduleEventHook>>,
    // Typed refusals in call order. Recording never fails, so it adds no
    // early return between cycle start and completion.
    epoch_refusals: RefCell<Vec<(EpochSite, crate::update_state::EpochRefusal)>>,
}

/// Where the worker asked for an epoch permit.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EpochSite {
    /// The short eligibility check that chooses the cycle plan.
    Plan,
    /// The fresh permit before an epoch discovery commit.
    Commit,
}

#[cfg(test)]
enum ScheduleTestEvent<'a> {
    Planned,
    BeforeProbe(&'a SourceId, Instant),
    BeforeAttempt(&'a SourceId, Instant, SourceLane),
    BeforeParse(&'a SourceId, Instant),
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
    BeforeDiscoveryPublication {
        epoch: bool,
    },
    AfterDiscoveryPublication {
        epoch: bool,
    },
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
    latest_only: bool,
}

#[derive(Clone, Copy)]
enum TurnObligation {
    Owed,
    ProbeOnly,
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
    final_probe_done: bool,
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
            final_probe_done: false,
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
        self.add_obligation(id, prior, lane, end, probe, TurnObligation::Owed)?;
        self.state.sources.get_mut(id).ok_or_else(invalid)?.owed = true;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_obligation(
        &mut self,
        id: &SourceId,
        prior: Option<&BackgroundSource>,
        lane: SourceLane,
        end: Instant,
        probe: bool,
        obligation: TurnObligation,
    ) -> PortResult<()> {
        if self.turns.len() >= MAX_DISCOVERY_PATHS || self.turns.contains_key(id) {
            return Err(discovery_capacity());
        }
        self.state.register(id, prior)?;
        self.turns.insert(
            id.clone(),
            SourceTurn {
                original_end: end,
                first_pending: matches!(obligation, TurnObligation::Owed),
                lane: None,
                probe,
                revisitable: matches!(obligation, TurnObligation::ProbeOnly),
                last_slice: None,
                latest_only: false,
            },
        );
        self.expirations.insert((end, id.clone()));
        if probe {
            self.probes.insert(id.clone());
        }
        if matches!(obligation, TurnObligation::Owed) {
            self.first_pending += 1;
            self.set_lane(id, Some(lane));
        }
        Ok(())
    }

    fn latest_obligation(&mut self, id: &SourceId, owed: bool) {
        let full_due = self.state.full_due(id, self.state.now());
        let turn = self.turns.get_mut(id).expect("registered source turn");
        if owed && !full_due {
            if !turn.first_pending && turn.last_slice.is_none() {
                turn.first_pending = true;
                self.first_pending += 1;
            }
            turn.latest_only = true;
            self.set_lane(id, Some(SourceLane::Verification));
        } else if !owed && turn.latest_only && !full_due {
            turn.latest_only = false;
            if turn.first_pending {
                turn.first_pending = false;
                self.first_pending -= 1;
            }
            self.set_lane(id, None);
        }
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
            .map(|(_, verified, _)| *verified != hint)
            .unwrap_or_else(|| indexed_len.is_some_and(|len| len != hint.len));
        if debt.dirty {
            debt.owed = true;
            let turn = self.turns.get_mut(id).expect("registered source turn");
            turn.latest_only = false;
            if !turn.first_pending && turn.last_slice.is_none() {
                turn.first_pending = true;
                self.first_pending += 1;
            }
            self.state.remember_hot(id);
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
        let ready = self.queues.iter().any(|queue| !queue.is_empty());
        let final_pass = !ready && !self.final_probe_done;
        if (!ready && self.final_probe_done)
            || self.state.next_probe.is_some_and(|next| now < next)
            || !self.queues[SourceLane::Metadata as usize].is_empty()
        {
            return Vec::new();
        }
        if final_pass {
            self.final_probe_done = true;
        }
        if self
            .state
            .probe_window
            .is_none_or(|start| now.saturating_duration_since(start) >= CADENCE)
        {
            self.state.probe_window = Some(now);
            self.state.probes_in_window = 0;
        }
        let budget = SOURCE_HINT_BATCH.saturating_sub(self.state.probes_in_window);
        if budget == 0 {
            return Vec::new();
        }
        self.state.next_probe = Some(now + CADENCE);
        let mut keys = Vec::new();
        let mut selected = BTreeSet::new();
        let hot_count = self.state.hot_probes.len();
        for _ in 0..hot_count {
            let Some(id) = self.state.hot_probes.pop_front() else {
                break;
            };
            if self.probes.contains(&id) {
                self.state.hot_probes.push_back(id.clone());
                if keys.len() < SOURCE_HOT_HINT_BATCH.min(budget) {
                    selected.insert(id.clone());
                    keys.push(id);
                }
                if keys.len() == SOURCE_HOT_HINT_BATCH.min(budget) {
                    break;
                }
            }
        }
        let aging = if let Some(after) = &self.state.probe_after {
            self.probes
                .range((Excluded(after.clone()), Unbounded))
                .chain(self.probes.range(..=after.clone()))
                .filter(|id| !selected.contains(*id))
                .take(budget - keys.len())
                .cloned()
                .collect::<Vec<_>>()
        } else {
            self.probes
                .iter()
                .filter(|id| !selected.contains(*id))
                .take(budget - keys.len())
                .cloned()
                .collect()
        };
        self.state.probe_after = aging
            .last()
            .cloned()
            .or_else(|| self.state.probe_after.clone());
        keys.extend(aging);
        self.state.probes_in_window += keys.len();
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
            let owed = self.turns[&id].lane.is_some() && self.turns[&id].last_slice.is_none();
            self.set_lane(&id, None);
            self.probes.remove(&id);
            let turn = self.turns.get_mut(&id).expect("registered source turn");
            turn.revisitable = false;
            if turn.first_pending {
                turn.first_pending = false;
                self.first_pending -= 1;
            }
            if owed {
                return Some(ScheduledTurn::NotScheduled(id));
            }
        }
        if self.queues.iter().all(BTreeSet::is_empty) {
            return None;
        }
        if self.slice_attempts >= SOURCE_SLICE_ATTEMPTS
            || now.saturating_duration_since(self.slice_started) >= CADENCE
        {
            self.slice = self.slice.wrapping_add(1);
            self.slice_attempts = 0;
            self.slice_started = now;
        }
        // If only a just-serviced dirty source remains, move to a new slice
        // instead of abandoning its owed revisit at the first-turn boundary.
        if self.queues.iter().all(|queue| {
            queue
                .iter()
                .all(|(_, id)| self.turns[id].last_slice == Some(self.slice))
        }) {
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

    /// Whether `next(now)` would serve an Active attempt, after it retires
    /// expired turns, without changing any state. It applies the same rules:
    /// no queued metadata, an unexpired Active turn this slice has not served,
    /// and Active credit left or no unexpired Cold/Verification debt.
    fn ready_active(&self, now: Instant) -> bool {
        if !self.queues[SourceLane::Metadata as usize].is_empty() {
            return false;
        }
        let (queues, turns) = (&self.queues, &self.turns);
        let live = move |lane: SourceLane| {
            queues[lane as usize]
                .iter()
                .filter(move |(_, id)| now < turns[id].original_end)
        };
        let lanes = [
            SourceLane::Active,
            SourceLane::Cold,
            SourceLane::Verification,
        ];
        // `next` opens a new slice on its budget or cadence, and again when
        // every remaining turn was already served in the current slice.
        let mut slice = self.slice;
        if self.slice_attempts >= SOURCE_SLICE_ATTEMPTS
            || now.saturating_duration_since(self.slice_started) >= CADENCE
        {
            slice = slice.wrapping_add(1);
        }
        if lanes
            .iter()
            .flat_map(|&lane| live(lane))
            .all(|(_, id)| turns[id].last_slice == Some(slice))
        {
            slice = slice.wrapping_add(1);
        }
        let ready =
            |lane: SourceLane| live(lane).any(|(_, id)| turns[id].last_slice != Some(slice));
        let debt = ready(SourceLane::Cold) || ready(SourceLane::Verification);
        ready(SourceLane::Active) && (self.state.active_attempts < 2 || !debt)
    }

    fn started(&mut self, id: &SourceId, lane: SourceLane) -> PortResult<()> {
        self.final_probe_done = false;
        let ticket = self.state.ticket()?;
        self.set_lane(id, None);
        self.probes.remove(id);
        let debt = self.state.sources.get_mut(id).ok_or_else(invalid)?;
        debt.ticket = ticket;
        debt.owed = true;
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
        let now = self.state.now();
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
            success.claims.clone(),
        ));
        debt.dirty = false;
        debt.owed = false;
        debt.last_full_verified = Some(now);
        let turn = self.turns.get_mut(id).expect("registered source turn");
        // probe is false for sources first imported in this cycle.
        turn.revisitable = turn.probe && success.revisitable;
        if turn.revisitable {
            self.probes.insert(id.clone());
        }
    }

    fn failed(&mut self, id: &SourceId) {
        self.set_lane(id, None);
        self.probes.remove(id);
        self.state.invalidate(id);
        let turn = self.turns.get_mut(id).expect("registered source turn");
        turn.revisitable = false;
    }

    fn probe_failed(&mut self, id: &SourceId) {
        self.state.invalidate(id);
        let turn = self.turns.get_mut(id).expect("registered source turn");
        // A real probe failure leaves independently owed verification. A
        // possibly committed source attempt is never rearmed in this cycle.
        if !turn.revisitable && !turn.first_pending {
            return;
        }
        if !turn.first_pending && turn.last_slice.is_none() {
            turn.first_pending = true;
            self.first_pending += 1;
        }
        turn.latest_only = false;
        self.set_lane(id, Some(SourceLane::Verification));
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

fn plain_source(source: &SharedSource) -> bool {
    source.descriptor.kind == SourceKind::Jsonl
        && matches!(
            source.provider,
            SearchProvider::Claude | SearchProvider::Codex
        )
}

fn source_revisions(
    source: &SharedSource,
    roots: &[RootState<'_>],
) -> impl Iterator<Item = SelectionRevision> {
    source
        .roots
        .iter()
        .map(|&index| roots[index].revision.clone())
}

/// Checked catalog state supplies membership; only a live process's successful
/// capture supplies the monotonic full-verification timer.
#[allow(clippy::too_many_arguments)]
fn validated_baseline(
    source: &SharedSource,
    prior: Option<&BackgroundSource>,
    inventory: &BTreeMap<SourceId, BackgroundSource>,
    progress: &BTreeMap<ControlId, SourceProgress>,
    boot: &ObservationClock,
    policy: &ReadPolicy,
    roots: &[RootState<'_>],
    schedule: &mut SourceScheduleState,
) -> PortResult<Option<SourceHint>> {
    if !plain_source(source) {
        return Ok(None);
    }
    let Some(checked) = inventory.get(&source.id) else {
        schedule.invalidate(&source.id);
        return Ok(None);
    };
    let Some(receipt) = checked.latest_receipt.as_ref() else {
        return Err(changed());
    };
    let same_head = prior
        .and_then(|prior| prior.latest_receipt.as_ref())
        .is_some_and(|prior| prior == receipt);
    // A subset-cycle receipt proves only the roots it claimed. Every covering
    // root in this cycle needs the claim written by the remembered attempt.
    let debt = &schedule.sources[&source.id];
    let covering = &source.roots;
    let hint = if let Some((revision, remembered, claims)) = debt.verified.as_ref()
        && revision == &receipt.revision_id
        && checked.indexed_len == Some(remembered.len)
        && covering
            .iter()
            .all(|&index| claims.contains(&roots[index].revision))
    {
        Some(*remembered)
    } else {
        None
    };
    let progress = progress.get(&ControlId::parse(source.id.as_str())?);
    let clean = progress.is_some_and(|progress| {
        progress.confirmation.is_none()
            && progress.error.is_none()
            && progress.coverage == Coverage::Complete
            && progress.receipt.as_ref().is_some_and(|summary| {
                summary.revision.as_str() == receipt.revision_id.as_str()
                    && summary.token.cycle_seq.get() == receipt.cycle_seq
                    && progress.last_observation.as_ref() == Some(&summary.token)
            })
    });
    if !same_head
        || hint.is_none()
        || !clean
        || boot.baseline_lost(source, roots, receipt.cycle_seq, policy.policy_epoch)
    {
        schedule.invalidate(&source.id);
        return Ok(None);
    }
    Ok(hint)
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
                committed: false,
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
                published: true,
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
                    committed: result.published,
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
                    committed: false,
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
        committed: published,
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
    epoch_plan_allowed: bool,
) -> PortResult<CycleOutcome> {
    let store = ManagedStore::open(db, control)?;
    let incarnation = store.incarnation().clone();
    let known = store
        .background_sources(control)?
        .into_iter()
        .map(|s| (s.binding.source_path.clone(), s))
        .collect::<BTreeMap<_, _>>();
    schedule.prepare(policy, &incarnation, authority.boot_id())?;
    let inventory_end =
        SqliteControlStore::effective_runtime_deadline(Instant::now() + SOURCE_OBSERVATION_BUDGET);
    let progress = control
        .with_runtime_deadline(inventory_end, || control.source_progress_inventory())?
        .into_iter()
        .map(|progress| (progress.source_id.clone(), progress))
        .collect::<BTreeMap<_, _>>();
    let checked_baselines = store
        .current_plain_baselines(control, inventory_end)?
        .into_iter()
        .map(|source| (source.binding.source_id.clone(), source))
        .collect::<BTreeMap<_, _>>();
    let demands = control.with_runtime_deadline(inventory_end, || control.latest_demands())?;
    schedule.update_demands(demands, policy, schedule.now())?;
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
        && selections.len()
            == policy
                .selections
                .iter()
                .filter(|selection| selection.enabled)
                .count()
    {
        schedule.sources.retain(|id, _| {
            (shared.contains_key(id.as_str()) && !shadowed.contains(id.as_str()))
                || missing.contains_key(id)
        });
    }
    let mut scheduler = CycleSchedule::new(schedule);
    let mut outcomes = BTreeMap::<String, ObservationOutcome>::new();
    let preferred_sources = roots
        .iter()
        .flat_map(|root| {
            root.discovery
                .as_ref()
                .into_iter()
                .flat_map(|discovery| discovery.files.iter().map(|source| source.id.clone()))
        })
        .collect::<Vec<_>>();
    let mut registered = BTreeSet::new();
    for id in preferred_sources {
        if shadowed.contains(id.as_str()) || !registered.insert(id.clone()) {
            continue;
        }
        let group = shared.get(id.as_str()).ok_or_else(invalid)?;
        let prior = group.path.to_str().and_then(|path| known.get(path));
        let published = published_baseline(prior);
        scheduler.state.register(&group.id, prior)?;
        let checked_hint = validated_baseline(
            group,
            prior,
            &checked_baselines,
            &progress,
            boot,
            policy,
            &roots,
            scheduler.state,
        )?;
        // Still validate the inventory on refusal: a corrupt receipt is never
        // an empty baseline. Exact planning then creates real source work.
        let checked_hint = checked_hint.filter(|_| epoch_plan_allowed);
        let full_due = !epoch_plan_allowed
            || checked_hint.is_none()
            || scheduler.state.full_due(&group.id, scheduler.state.now());
        let latest_due = scheduler.state.cycle_can_serve(
            source_revisions(group, &roots),
            cycle,
            scheduler.state.now(),
        ) && scheduler.state.latest_owed(
            source_revisions(group, &roots),
            prior.and_then(|prior| prior.latest_receipt.as_ref()),
            scheduler.state.now(),
        );
        let lane = if group.descriptor.kind == SourceKind::WorkBuddyMetadata {
            SourceLane::Metadata
        } else if published {
            SourceLane::Verification
        } else {
            SourceLane::Cold
        };
        if full_due {
            scheduler
                .state
                .sources
                .get_mut(&group.id)
                .ok_or_else(invalid)?
                .owed = true;
        }
        scheduler.add_obligation(
            &group.id,
            prior,
            lane,
            group.original_end,
            plain_source(group) && published,
            if full_due || latest_due {
                TurnObligation::Owed
            } else {
                TurnObligation::ProbeOnly
            },
        )?;
        if !full_due && latest_due {
            scheduler
                .turns
                .get_mut(&group.id)
                .ok_or_else(invalid)?
                .latest_only = true;
        }
        if let Some(hint) = checked_hint {
            outcomes.insert(
                group.id.as_str().into(),
                ObservationOutcome::VerifiedBaseline {
                    hint,
                    claimed: group.roots.iter().copied().collect(),
                },
            );
        }
        if plain_source(group) && published {
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
    scheduler
        .state
        .hot_probes
        .retain(|id| scheduler.turns.contains_key(id));
    let mut metadata = BTreeMap::<String, WorkBuddyMetadata>::new();
    let mut absent = BTreeMap::<String, ObservationOutcome>::new();
    let mut baselines = BTreeMap::<SourceId, BackgroundSource>::new();
    let mut successful_hints = BTreeMap::<SourceId, SourceHint>::new();
    let mut attempted_sources = BTreeMap::<usize, BTreeSet<SourceId>>::new();
    let mut published_sources = BTreeMap::<usize, BTreeSet<SourceId>>::new();
    let mut independent_probe_failures = BTreeSet::new();
    let mut next_demand_poll = None;
    // Set when this cycle's first source attempt starts.
    let mut attempt_started = false;
    #[cfg(test)]
    scheduler.state.hooks.event(ScheduleTestEvent::Planned)?;
    loop {
        let now = scheduler.state.now();
        if next_demand_poll.is_none_or(|next| now >= next) {
            let demand_end = roots
                .iter()
                .map(|root| root.original_end)
                .max()
                .ok_or_else(invalid)?;
            if now < demand_end {
                let demands =
                    control.with_runtime_deadline(demand_end, || control.latest_demands())?;
                scheduler.state.update_demands(demands, policy, now)?;
                next_demand_poll = Some(now + CADENCE);
                for group in shared.values().filter(|source| plain_source(source)) {
                    if !scheduler.turns.contains_key(&group.id)
                        || now >= group.original_end
                        || matches!(
                            outcomes.get(group.id.as_str()),
                            Some(ObservationOutcome::Attempted { .. })
                        )
                    {
                        continue;
                    }
                    let prior = baselines
                        .get(&group.id)
                        .or_else(|| group.path.to_str().and_then(|path| known.get(path)));
                    let owed = scheduler.state.latest_owed(
                        source_revisions(group, &roots),
                        prior.and_then(|prior| prior.latest_receipt.as_ref()),
                        now,
                    );
                    if !owed
                        || scheduler.state.cycle_can_serve(
                            source_revisions(group, &roots),
                            cycle,
                            now,
                        )
                    {
                        scheduler.latest_obligation(&group.id, owed);
                    }
                }
            }
        }
        // Registration already queued every source whose enumeration hint
        // changed. Until this cycle's first attempt starts, serve a ready
        // Active turn before the probe batch, which can admit up to
        // SOURCE_HINT_BATCH other sources first. Probing resumes after it with
        // unchanged budgets, window and rotation.
        let probes = if !attempt_started && scheduler.ready_active(now) {
            Vec::new()
        } else {
            scheduler.probe_batch(now)
        };
        for id in probes {
            let group = shared.get(id.as_str()).ok_or_else(invalid)?;
            #[cfg(test)]
            scheduler
                .state
                .hooks
                .event(ScheduleTestEvent::BeforeProbe(&id, group.original_end))?;
            if scheduler.state.now() >= group.original_end {
                continue;
            }
            // A refusal before probe I/O at an expired unowed end records
            // nothing. A real admitted probe failure cannot close on old hints.
            match probe_source_hint(control, policy, &roots, group, scheduler.state) {
                Ok(hint) => {
                    let prior = baselines
                        .get(&id)
                        .or_else(|| group.path.to_str().and_then(|path| known.get(path)));
                    scheduler.hint(&id, hint, prior.and_then(|prior| prior.indexed_len));
                }
                Err(error) => {
                    if matches!(
                        outcomes.get(id.as_str()),
                        Some(ObservationOutcome::Attempted { .. })
                    ) {
                        independent_probe_failures.insert(id.clone());
                        scheduler.failed(&id);
                    } else {
                        outcomes.insert(
                            id.as_str().into(),
                            ObservationOutcome::ProbeFailed(failure(&error)),
                        );
                        scheduler.probe_failed(&id);
                    }
                }
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
                    absent
                        .entry(id.as_str().into())
                        .or_insert(ObservationOutcome::NotScheduled);
                } else {
                    outcomes
                        .entry(id.as_str().into())
                        .or_insert(ObservationOutcome::NotScheduled);
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
        attempt_started = true;
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
            if let ObservationOutcome::Attempted {
                committed, claimed, ..
            } = &outcome
            {
                for &index in claimed {
                    attempted_sources
                        .entry(index)
                        .or_default()
                        .insert(id.clone());
                    if *committed {
                        published_sources
                            .entry(index)
                            .or_default()
                            .insert(id.clone());
                    }
                }
            }
            absent.insert(id.as_str().into(), outcome);
        } else {
            let group = shared.get(id.as_str()).ok_or_else(invalid)?;
            let prior = baselines
                .get(&id)
                .or_else(|| group.path.to_str().and_then(|path| known.get(path)));
            let revisit = matches!(
                outcomes.get(id.as_str()),
                Some(ObservationOutcome::Attempted { .. })
            );
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
                successful_hints.insert(id.clone(), success.hint);
                scheduler.succeeded(&id, &success);
                baselines.insert(id.clone(), success.baseline);
            } else {
                scheduler.failed(&id);
                if let ObservationOutcome::Attempted {
                    published: true, ..
                } = &outcome
                    && let Some(observed) =
                        metadata.values().find(|metadata| metadata.source.id == id)
                {
                    successful_hints
                        .insert(id.clone(), SourceHint::from_snapshot(&observed.snapshot));
                    baselines.insert(
                        id.clone(),
                        BackgroundSource {
                            binding: observed.binding.clone(),
                            latest_receipt: Some(observed.receipt.clone()),
                            indexed_len: Some(observed.snapshot.len),
                            superseded: false,
                        },
                    );
                }
            }
            if let ObservationOutcome::Attempted {
                committed, claimed, ..
            } = &outcome
            {
                for &index in claimed {
                    attempted_sources
                        .entry(index)
                        .or_default()
                        .insert(id.clone());
                    if *committed {
                        published_sources
                            .entry(index)
                            .or_default()
                            .insert(id.clone());
                    }
                }
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
    let mut catalog_complete = true;
    let mut all_sources_attempted = true;
    for (index, root) in roots.iter().enumerate() {
        check_policy(control, policy)?;
        let selection = root.selection;
        let revision = root.revision.clone();
        let mut error = None;
        let mut represented = 0_u64;
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
                    ObservationOutcome::VerifiedBaseline { claimed, .. } => {
                        if claimed.contains(&index)
                            && !scheduler.state.full_due(&source.id, scheduler.state.now())
                        {
                            represented += 1;
                        } else {
                            observations_clean = false;
                            error.get_or_insert(BackgroundFailure::Deferred);
                        }
                    }
                    ObservationOutcome::NotScheduled => {
                        observations_clean = false;
                        error.get_or_insert(BackgroundFailure::Deferred);
                    }
                    ObservationOutcome::ProbeFailed(reason) => {
                        observations_clean = false;
                        error.get_or_insert(*reason);
                    }
                    ObservationOutcome::Attempted {
                        published,
                        claimed,
                        failed,
                        ..
                    } => {
                        if claimed.contains(&index) {
                            if *published {
                                represented += 1;
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
                            ..
                        }) if claimed.contains(&index) => {
                            if *published {
                                represented += 1;
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
                        Some(ObservationOutcome::ProbeFailed(reason)) => {
                            observations_clean = false;
                            error.get_or_insert(*reason);
                        }
                        Some(ObservationOutcome::VerifiedBaseline { .. }) => {
                            complete = false;
                            error.get_or_insert(BackgroundFailure::DeletionPending);
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
                    // Unstarted work and an unattempted verified baseline made no
                    // observation here; a durable failure token would only force
                    // a later full rehash of unchanged bytes.
                    if matches!(
                        outcomes
                            .get(prior.binding.source_id.as_str())
                            .or_else(|| absent.get(prior.binding.source_id.as_str())),
                        Some(
                            ObservationOutcome::NotScheduled
                                | ObservationOutcome::VerifiedBaseline { .. }
                        )
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
        if complete
            && error.is_none()
            && represented == count
            && observation_deadline_at(root.original_end, scheduler.state.now()).is_err()
        {
            // A root whose budget was spent by its last represented source
            // defers the final re-enumeration to a later cycle. Aborting here
            // would discard every acknowledgement this cycle has earned.
            complete = false;
        }
        if complete && error.is_none() && represented == count {
            verify_root(selection)?;
            // Re-enumeration detects a new/removed candidate while earlier
            // sources were being parsed; no heartbeat substitutes for this proof.
            let final_set = control.with_runtime_deadline(root.original_end, || {
                #[cfg(test)]
                let discovery_end = scheduler
                    .state
                    .hooks
                    .final_discovery_end
                    .as_ref()
                    .and_then(|end| end.take())
                    .map_or(root.original_end, |end| end.min(root.original_end));
                #[cfg(not(test))]
                let discovery_end = root.original_end;
                discover(control, policy, selection, &known, discovery_end)
            });
            match final_set {
                Ok(final_set) => {
                    let expected: BTreeSet<_> = root
                        .discovery
                        .as_ref()
                        .map_err(|_| changed())?
                        .files
                        .iter()
                        .map(|file| file.id.clone())
                        .collect();
                    let actual: BTreeSet<_> =
                        final_set.files.iter().map(|file| file.id.clone()).collect();
                    let mut hints_match = true;
                    for file in &final_set.files {
                        if shadowed.contains(file.id.as_str()) {
                            continue;
                        }
                        let expected_hint = successful_hints.get(&file.id).copied().or_else(|| {
                            match outcomes.get(file.id.as_str()) {
                                Some(ObservationOutcome::VerifiedBaseline { hint, .. }) => {
                                    Some(*hint)
                                }
                                _ => None,
                            }
                        });
                        let source = shared.get(file.id.as_str());
                        if source.is_none() {
                            hints_match = false;
                        } else if source.is_some_and(plain_source)
                            && expected_hint != Some(file.hint)
                        {
                            scheduler.state.invalidate(&file.id);
                            if let Some(debt) = scheduler.state.sources.get_mut(&file.id) {
                                debt.dirty = true;
                            }
                            scheduler.state.remember_hot(&file.id);
                            hints_match = false;
                        }
                        if independent_probe_failures.contains(&file.id) {
                            // Verification after a prior success belongs to a later
                            // cycle if any subsequent actual probe failed.
                            hints_match = false;
                        }
                    }
                    if !final_set.complete || expected != actual || !hints_match {
                        complete = false;
                        error = Some(BackgroundFailure::SourceChanged);
                    } else {
                        let epoch_candidate = epoch_plan_allowed
                            && matches!(
                                selection.region.provider,
                                SearchProvider::Claude | SearchProvider::Codex
                            );
                        let all_exact = ids.iter().all(|id| {
                            matches!(
                                outcomes.get(id.as_str()),
                                Some(ObservationOutcome::Attempted {
                                    published: true,
                                    committed: true,
                                    claimed,
                                    ..
                                }) if claimed.contains(&index)
                            )
                        });
                        // The installation lock precedes the catalog writer and
                        // lives through epoch publication. No lock spans the
                        // source observation interval.
                        let attempt = epoch_candidate.then(|| {
                            boot.epoch_permit(
                                control,
                                root.original_end,
                                #[cfg(test)]
                                &scheduler.state.hooks,
                            )
                        });
                        #[cfg(test)]
                        if let Some(Err(reason)) = attempt.as_ref() {
                            scheduler
                                .state
                                .hooks
                                .epoch_refusals
                                .borrow_mut()
                                .push((EpochSite::Commit, *reason));
                        }
                        let permit = attempt.and_then(Result::ok);
                        if epoch_candidate && permit.is_none() && !all_exact {
                            complete = false;
                            // A baseline is not this cycle's receipt. Preserve
                            // earned work and make later cycles pay the exact
                            // obligation; do not reopen or extend this root.
                            for id in &ids {
                                if matches!(
                                    outcomes.get(id.as_str()),
                                    Some(ObservationOutcome::VerifiedBaseline { .. })
                                ) && let Some(debt) = scheduler.state.sources.get_mut(id)
                                {
                                    debt.owed = true;
                                }
                            }
                        } else {
                            #[cfg(test)]
                            scheduler.state.hooks.event(
                                ScheduleTestEvent::BeforeDiscoveryPublication {
                                    epoch: permit.is_some(),
                                },
                            )?;
                            let result = control.with_runtime_deadline(root.original_end, || {
                                let writer = ManagedStore::open_for_write(db, control)?;
                                let result = if permit.is_some() {
                                    writer.commit_discovery_epoch_with_deadline(
                                        control,
                                        authority,
                                        cycle,
                                        &revision,
                                        &ids,
                                        root.original_end,
                                    )
                                } else {
                                    writer.commit_discovery_with_deadline(
                                        control,
                                        authority,
                                        cycle,
                                        &revision,
                                        &ids,
                                        root.original_end,
                                    )
                                };
                                #[cfg(test)]
                                if result.is_ok() {
                                    scheduler.state.hooks.event(
                                        ScheduleTestEvent::AfterDiscoveryPublication {
                                            epoch: permit.is_some(),
                                        },
                                    )?;
                                }
                                result
                            });
                            if let Err(write_error) = result {
                                error = Some(failure(&write_error));
                            }
                        }
                        drop(permit);
                    }
                }
                Err(PortError::WriterBusy(_)) => {
                    // Keep the newest fence incomplete and earlier source commits
                    // intact. Normal root accounting records Deferred without
                    // retrying enumeration or renewing the original end.
                    complete = false;
                }
                Err(discover_error) => return Err(discover_error),
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
            observed_count: ids
                .iter()
                .filter(|id| {
                    attempted_sources
                        .get(&index)
                        .is_some_and(|sources| sources.contains(*id))
                })
                .count() as u64,
            committed_count: ids
                .iter()
                .filter(|id| {
                    published_sources
                        .get(&index)
                        .is_some_and(|sources| sources.contains(*id))
                })
                .count() as u64,
            error,
        };
        catalog_complete &= ack.complete;
        all_sources_attempted &= ack.complete && ack.committed_count == ack.discovered_count;
        control_change(control, |seq| {
            control.acknowledge_discovery(seq, authority, ack.clone())
        })?;
    }
    let now = scheduler.state.now();
    let known_plain = known
        .values()
        .filter(|source| {
            matches!(
                source.binding.provider,
                SearchProvider::Claude | SearchProvider::Codex
            )
        })
        .map(|source| source.binding.source_id.clone())
        .collect::<BTreeSet<_>>();
    let due = scheduler.state.sources.iter().any(|(id, _)| {
        !matches!(
            absent.get(id.as_str()),
            Some(ObservationOutcome::Attempted {
                published: true,
                ..
            })
        ) && (shared.get(id.as_str()).is_some_and(plain_source) || known_plain.contains(id))
            && scheduler.state.full_due(id, now)
    });
    let latest_owed = shared.values().any(|source| {
        let prior = baselines
            .get(&source.id)
            .or_else(|| source.path.to_str().and_then(|path| known.get(path)));
        scheduler.state.latest_owed(
            source_revisions(source, &roots),
            prior.and_then(|prior| prior.latest_receipt.as_ref()),
            now,
        )
    });
    if catalog_complete {
        let completed = scheduler
            .state
            .demands
            .iter()
            .filter_map(|(id, demand)| {
                if demand.retired || now >= demand.service_end {
                    return None;
                }
                let closed = demand.barrier.selections.iter().all(|revision| {
                    roots.iter().any(|root| &root.revision == revision)
                        && cycle.token.cycle_seq >= demand.barrier.required_cycle_seq
                        && cycle
                            .started_control_seq
                            .is_some_and(|start| start > demand.barrier.admission_control_seq)
                });
                let sources_current = shared.values().all(|source| {
                    if !source_revisions(source, &roots)
                        .any(|revision| demand.barrier.selections.contains(&revision))
                    {
                        return true;
                    }
                    let receipt = baselines
                        .get(&source.id)
                        .or_else(|| source.path.to_str().and_then(|path| known.get(path)))
                        .and_then(|source| source.latest_receipt.as_ref());
                    receipt.is_some_and(|receipt| {
                        receipt.published
                            && receipt.cycle_seq >= demand.barrier.required_cycle_seq.get()
                            && receipt.started_control_seq
                                > demand.barrier.admission_control_seq.get()
                    })
                });
                (closed && sources_current).then(|| id.clone())
            })
            .collect::<Vec<_>>();
        for id in completed {
            scheduler
                .state
                .demands
                .get_mut(&id)
                .ok_or_else(invalid)?
                .retired = true;
        }
    }
    let other_demand = scheduler
        .state
        .demands
        .values()
        .any(|demand| !demand.retired && now < demand.service_end);
    let remaining_scope = policy
        .selections
        .iter()
        .filter(|selection| selection.enabled)
        .any(|selection| !roots.iter().any(|root| root.selection.id == selection.id));
    Ok(CycleOutcome {
        catalog_complete,
        all_sources_attempted,
        remaining_work: due || latest_owed || other_demand || remaining_scope || !catalog_complete,
    })
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
    if state == ObservationState::Complete
        && source.descriptor.kind == SourceKind::Jsonl
        && matches!(
            advisory.region.provider,
            SearchProvider::Claude | SearchProvider::Codex
        )
        && let Some(prior) = prior.filter(|prior| {
            !prior.superseded
                && prior.binding.namespace_id.is_some()
                && prior.indexed_len == Some(snapshot.len)
                && prior.latest_receipt.as_ref().is_some_and(|receipt| {
                    receipt.published && receipt.digest == snapshot.fingerprint
                })
        })
    {
        let mut refresh = observation(
            prior.binding.clone(),
            incarnation,
            cycle,
            claims,
            &snapshot.fingerprint,
            ObservationState::Complete,
        )?;
        let refresh_claims = claims
            .iter()
            .copied()
            .map(selection_revision)
            .collect::<PortResult<Vec<_>>>()?;
        for claim in claims {
            admit(control, policy, claim, &source.path, &source.id, end)?;
        }
        observation_deadline(end)?;
        let writer = ManagedStore::open_for_write(db, control)?;
        refresh.committed_at_ms = app_clock_ms();
        #[cfg(test)]
        hooks.source_phase.set(SourceAttemptPhase::Publication);
        // Only Ineligible may reach the full path below. Every Err, including
        // SchemaIncompatible for a tuple that path would still accept, ends this
        // attempt as the source's own durable failure (observe_shared_source);
        // the cycle continues and WriterBusy keeps its ordinary retry meaning.
        match writer.refresh_verified_unchanged_source(
            control,
            authority,
            prior.latest_receipt.as_ref().ok_or_else(invalid)?,
            &refresh,
            &snapshot,
            input_limit,
            end,
        )? {
            RefreshOutcome::Refreshed(publication) => {
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
                    if current {
                        ObservationState::Complete
                    } else {
                        ObservationState::Incomplete
                    },
                    None,
                )?;
                return Ok(SourceAttemptResult {
                    current,
                    published: publication.receipt.published,
                    successful: current.then(|| SuccessfulSourceAttempt {
                        baseline: BackgroundSource {
                            binding: refresh.binding,
                            latest_receipt: Some(publication.receipt),
                            indexed_len: Some(snapshot.len),
                            superseded: false,
                        },
                        hint: SourceHint::from_snapshot(&snapshot),
                        revisitable: true,
                        claims: refresh_claims,
                    }),
                });
            }
            RefreshOutcome::Ineligible(_) => {
                drop(writer);
                #[cfg(test)]
                hooks.source_phase.set(SourceAttemptPhase::Prepare);
            }
        }
    }
    let mut parsed = if state == ObservationState::Complete {
        #[cfg(test)]
        hooks.event(ScheduleTestEvent::BeforeParse(&source.id, end))?;
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
    let attempt_claims = claims
        .iter()
        .copied()
        .map(selection_revision)
        .collect::<PortResult<Vec<_>>>()?;
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
        published: publication.receipt.published,
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
            claims: attempt_claims,
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
    use crate::update_state::EpochRefusal;
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
            self.scheduled_for(schedule, boot, |_| true)
        }

        /// Like run_cycle, a latest demand starts with only its own selections.
        fn scheduled_for(
            &self,
            schedule: &mut SourceScheduleState,
            boot: &ObservationClock,
            include: impl Fn(&Selection) -> bool,
        ) -> (PortResult<bool>, ObservationCycle, LatestBarrier) {
            let worker = self.worker();
            let policy =
                self.read_control(|control| control.read_policy(RequestIntersection::Selected));
            let selections = policy
                .selections
                .iter()
                .filter(|&s| s.enabled && include(s))
                .cloned()
                .collect::<Vec<_>>();
            let request = LatestRequest {
                selections: selections
                    .iter()
                    .map(selection_revision)
                    .collect::<PortResult<_>>()
                    .unwrap(),
                max_wait_ms: MAX_LATEST_WAIT_MS,
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
                let epoch_plan_allowed = boot
                    .epoch_permit(&self.control, self.scope_end, &schedule.hooks)
                    .is_ok();
                observe_cycle(
                    &self.db,
                    &self.control,
                    &worker,
                    &policy,
                    &selections,
                    &cycle,
                    boot,
                    schedule,
                    epoch_plan_allowed,
                )
            });
            let finish = match &result {
                Ok(outcome) => outcome.finish(),
                Err(_) => CycleFinish::Aborted,
            };
            control_change_before(&self.control, self.scope_end, |seq| {
                self.control
                    .finish_cycle(seq, &worker, cycle.token.cycle_seq, finish, 4)
            })
            .unwrap();
            let terminal = self.read_control(|control| control.cycle(cycle.token.cycle_seq));
            (
                result.map(|outcome| outcome.catalog_complete),
                terminal,
                barrier,
            )
        }

        fn ordinary(
            &self,
            schedule: &mut SourceScheduleState,
            boot: &ObservationClock,
        ) -> (PortResult<CycleOutcome>, ObservationCycle) {
            let worker = self.worker();
            control_change_before(&self.control, self.scope_end, |seq| {
                self.control.heartbeat_worker(
                    seq,
                    &worker,
                    UpdateState::Running,
                    None,
                    app_clock_ms(),
                )
            })
            .unwrap();
            let policy =
                self.read_control(|control| control.read_policy(RequestIntersection::Selected));
            let selections = policy
                .selections
                .iter()
                .filter(|selection| selection.enabled)
                .cloned()
                .collect::<Vec<_>>();
            let revisions = selections
                .iter()
                .map(selection_revision)
                .collect::<PortResult<Vec<_>>>()
                .unwrap();
            let CycleAdmission::Queued(queued) =
                control_change_before(&self.control, self.scope_end, |seq| {
                    self.control.queue_cycle(seq, revisions.clone())
                })
                .unwrap()
                .value
            else {
                panic!("synthetic ordinary cycle was blocked");
            };
            let cycle = self.start(&worker, &queued);
            let result = self.control.with_runtime_deadline(self.scope_end, || {
                let epoch_plan_allowed = boot
                    .epoch_permit(&self.control, self.scope_end, &schedule.hooks)
                    .is_ok();
                observe_cycle(
                    &self.db,
                    &self.control,
                    &worker,
                    &policy,
                    &selections,
                    &cycle,
                    boot,
                    schedule,
                    epoch_plan_allowed,
                )
            });
            let finish = result
                .as_ref()
                .map(|outcome| outcome.finish())
                .unwrap_or(CycleFinish::Aborted);
            control_change_before(&self.control, self.scope_end, |seq| {
                self.control
                    .finish_cycle(seq, &worker, cycle.token.cycle_seq, finish, 4)
            })
            .unwrap();
            let terminal = self.read_control(|control| control.cycle(cycle.token.cycle_seq));
            (result, terminal)
        }

        /// Uses production queue/start/planning/completion instead of repeating
        /// the planner in the direct observation fixture.
        fn production_cycle(
            &self,
            schedule: &mut SourceScheduleState,
            boot: &ObservationClock,
        ) -> (PortResult<CycleOutcome>, ObservationCycle) {
            let worker = self.worker();
            let mut pending = None;
            let result = self.control.with_runtime_deadline(self.scope_end, || {
                run_cycle(
                    &self.db,
                    &self.control,
                    &worker,
                    boot,
                    0,
                    self.scope_end,
                    &mut pending,
                    schedule,
                )
            });
            assert!(
                pending.is_none(),
                "production completion must acknowledge its cycle"
            );
            let next = self
                .read_control(|control| control.background_status())
                .next_cycle_seq;
            let cycle =
                self.read_control(|control| control.cycle(CycleSeq::new(next.get() - 1).unwrap()));
            (result, cycle)
        }

        fn head_claims(&self) -> i64 {
            let head = self.sources().pop().unwrap().latest_receipt.unwrap();
            rusqlite::Connection::open(&self.db)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM receipt_selection_claims WHERE revision_id=?1",
                    [head.revision_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap()
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
            final_discovery_end: None,
            epoch_lock_prefix: None,
            source_phase: Cell::new(SourceAttemptPhase::Prepare),
            on_event: Some(RefCell::new(Box::new(hook))),
            epoch_refusals: RefCell::default(),
        }
    }

    #[test]
    fn scheduler_quiet_plain_poll_closes_with_zero_attempts_and_no_receipt_or_clock_change() {
        for provider in [SearchProvider::Claude, SearchProvider::Codex] {
            let fixture = CycleFixture::new_for_provider(provider);
            let path = fixture.write_source("quiet.jsonl", provider, "quietbaseline");
            let original = std::fs::read(&path).unwrap();
            let mut schedule = SourceScheduleState::default();
            let boot = ObservationClock::new(Instant::now());
            let (first, _) = fixture.ordinary(&mut schedule, &boot);
            assert!(first.unwrap().idle());
            let before = fixture.sources().pop().unwrap();
            let id = before.binding.source_id.clone();
            let verified_at = schedule.sources[&id].last_full_verified;
            let progress = fixture.read_control(|control| {
                control.source_progress(&ControlId::parse(id.as_str()).unwrap())
            });
            schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), |event| {
                if matches!(
                    event,
                    ScheduleTestEvent::BeforeAttempt(..) | ScheduleTestEvent::Published(..)
                ) {
                    panic!("a quiet baseline must not be observed or republished");
                }
                Ok(())
            });
            let (quiet, cycle) = fixture.ordinary(&mut schedule, &boot);
            let quiet = quiet.unwrap();
            assert!(quiet.idle());
            assert!(!quiet.all_sources_attempted);
            assert_eq!(cycle.state, CycleState::Partial);
            assert_eq!(
                (
                    cycle.selections[0].discovered_count,
                    cycle.selections[0].observed_count,
                    cycle.selections[0].committed_count
                ),
                (1, 0, 0)
            );
            assert!(cycle.selections[0].discovery_complete);
            assert!(cycle.selections[0].error.is_none());
            assert_eq!(fixture.sources()[0].latest_receipt, before.latest_receipt);
            assert_eq!(schedule.sources[&id].last_full_verified, verified_at);
            assert_eq!(
                fixture.read_control(|control| {
                    control.source_progress(&ControlId::parse(id.as_str()).unwrap())
                }),
                progress
            );
            assert_eq!(std::fs::read(path).unwrap(), original);
        }
    }

    fn assert_exact_discovery(fixture: &CycleFixture, cycle: &ObservationCycle) {
        let conn = rusqlite::Connection::open(&fixture.db).unwrap();
        let (members, crossed): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(r.cycle_seq <> d.cycle_seq), 0)
                 FROM discovery_receipts d
                 JOIN discovery_sources s ON s.cycle_seq=d.cycle_seq AND s.selection_id=d.selection_id
                 JOIN source_revision_receipts r ON r.source_id=s.source_id AND r.revision_id=s.revision_id
                 WHERE d.cycle_seq=?1 AND d.complete=1",
                [cycle.token.cycle_seq.get()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((members, crossed), (1, 0));
    }

    #[test]
    fn scheduler_unverified_package_pays_real_exact_work_on_every_cycle() {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("exact.jsonl", SearchProvider::Claude, "exactfallback");
        let original = std::fs::read(&path).unwrap();
        let boot = ObservationClock::with_epoch_gate(Instant::now(), EpochGate::Unverified);
        let mut schedule = SourceScheduleState::default();
        let (first, first_cycle) = fixture.production_cycle(&mut schedule, &boot);
        assert!(first.unwrap().all_sources_attempted);
        assert_exact_discovery(&fixture, &first_cycle);
        let before = fixture.sources().pop().unwrap().latest_receipt.unwrap();

        let (second, second_cycle) = fixture.production_cycle(&mut schedule, &boot);

        let second = second.unwrap();
        assert!(second.idle());
        assert!(second.all_sources_attempted);
        assert_eq!(second_cycle.state, CycleState::Committed);
        let selection = &second_cycle.selections[0];
        assert_eq!(
            (
                selection.discovered_count,
                selection.observed_count,
                selection.committed_count
            ),
            (1, 1, 1)
        );
        let after = fixture.sources().pop().unwrap().latest_receipt.unwrap();
        assert_ne!(after.revision_id, before.revision_id);
        assert_eq!(after.cycle_seq, second_cycle.token.cycle_seq.get());
        assert_exact_discovery(&fixture, &second_cycle);
        assert_eq!(std::fs::read(path).unwrap(), original);
        // Planning refuses each cycle; an exact plan never asks at commit.
        assert_eq!(
            *schedule.hooks.epoch_refusals.borrow(),
            [
                (EpochSite::Plan, EpochRefusal::Unverified),
                (EpochSite::Plan, EpochRefusal::Unverified),
            ]
        );
    }

    #[test]
    fn scheduler_commit_refusal_keeps_baselines_incomplete_and_owed_without_new_attempts() {
        use crate::update_state::acquire_installation_lock;

        let fixture = CycleFixture::new();
        fixture.write_source("baseline.jsonl", SearchProvider::Claude, "refusedbaseline");
        let boot = ObservationClock::new(Instant::now());
        let mut schedule = SourceScheduleState::default();
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let before = fixture.sources().pop().unwrap();
        let verified_at = schedule.sources[&before.binding.source_id].last_full_verified;
        let prefix = fixture._temp.path().join("installation");
        crate::native_autostart::platform::create_private_directory(&prefix).unwrap();
        let lock = Rc::new(RefCell::new(None));
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let prefix = prefix.clone();
            let lock = lock.clone();
            move |event| {
                match event {
                    ScheduleTestEvent::BeforeAttempt(..) => {
                        panic!("the quiet baseline should not be attempted before refusal")
                    }
                    ScheduleTestEvent::Finalizing => {
                        *lock.borrow_mut() = Some(
                            acquire_installation_lock(
                                &prefix,
                                Instant::now() + Duration::from_secs(3),
                            )
                            .unwrap(),
                        );
                    }
                    ScheduleTestEvent::BeforeDiscoveryPublication { .. } => {
                        panic!("a refused baseline cannot open a discovery writer")
                    }
                    _ => {}
                }
                Ok(())
            }
        });
        schedule.hooks.epoch_lock_prefix = Some(prefix.clone());
        let (refused, cycle) = fixture.ordinary(&mut schedule, &boot);
        assert_eq!(
            *schedule.hooks.epoch_refusals.borrow(),
            [(EpochSite::Commit, EpochRefusal::Busy)]
        );
        assert!(!refused.unwrap().catalog_complete);
        assert_eq!(cycle.state, CycleState::Partial);
        let selection = &cycle.selections[0];
        assert!(!selection.discovery_complete);
        assert_eq!(selection.error, Some(BackgroundFailure::Deferred));
        assert_eq!(
            (selection.observed_count, selection.committed_count),
            (0, 0)
        );
        assert_eq!(fixture.sources()[0].latest_receipt, before.latest_receipt);
        assert_eq!(
            schedule.sources[&before.binding.source_id].last_full_verified,
            verified_at
        );
        assert!(schedule.sources[&before.binding.source_id].owed);
        assert!(lock.borrow().is_some());
        drop(lock.borrow_mut().take());
        schedule.hooks = ScheduleTestHooks::default();
        let (repaid, _) = fixture.ordinary(&mut schedule, &boot);
        assert!(repaid.unwrap().all_sources_attempted);
        assert_ne!(fixture.sources()[0].latest_receipt, before.latest_receipt);
    }

    #[test]
    fn scheduler_mixed_attempt_and_baseline_refusal_preserves_earned_work_and_owes_baseline() {
        use crate::update_state::acquire_installation_lock;

        let fixture = CycleFixture::new();
        fixture.write_source("baseline.jsonl", SearchProvider::Claude, "mixedbaseline");
        let boot = ObservationClock::new(Instant::now());
        let mut schedule = SourceScheduleState::default();
        assert!(
            fixture
                .production_cycle(&mut schedule, &boot)
                .0
                .unwrap()
                .idle()
        );
        let before = fixture.sources().pop().unwrap();
        let baseline_id = before.binding.source_id.clone();
        let verified_at = schedule.sources[&baseline_id].last_full_verified;
        fixture.write_source("new.jsonl", SearchProvider::Claude, "mixedearned");
        let prefix = fixture._temp.path().join("installation");
        crate::native_autostart::platform::create_private_directory(&prefix).unwrap();
        let lock = Rc::new(RefCell::new(None));
        let attempts = Rc::new(Cell::new(0));
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let prefix = prefix.clone();
            let baseline_id = baseline_id.clone();
            let lock = lock.clone();
            let attempts = attempts.clone();
            move |event| {
                match event {
                    ScheduleTestEvent::BeforeAttempt(id, _, _) => {
                        assert_ne!(*id, baseline_id);
                        attempts.set(attempts.get() + 1);
                    }
                    ScheduleTestEvent::Finalizing => {
                        *lock.borrow_mut() = Some(
                            acquire_installation_lock(
                                &prefix,
                                Instant::now() + Duration::from_secs(3),
                            )
                            .unwrap(),
                        );
                    }
                    ScheduleTestEvent::BeforeDiscoveryPublication { .. } => {
                        panic!("one attempted source cannot authorize an exact baseline member")
                    }
                    _ => {}
                }
                Ok(())
            }
        });
        schedule.hooks.epoch_lock_prefix = Some(prefix);

        let (refused, cycle) = fixture.production_cycle(&mut schedule, &boot);

        assert_eq!(
            *schedule.hooks.epoch_refusals.borrow(),
            [(EpochSite::Commit, EpochRefusal::Busy)]
        );
        assert!(!refused.unwrap().catalog_complete);
        assert_eq!(cycle.state, CycleState::Partial);
        let selection = &cycle.selections[0];
        assert!(!selection.discovery_complete);
        assert_eq!(selection.error, Some(BackgroundFailure::Deferred));
        assert_eq!(
            (
                selection.discovered_count,
                selection.observed_count,
                selection.committed_count
            ),
            (2, 1, 1)
        );
        assert_eq!(attempts.get(), 1);
        let sources = fixture.sources();
        let baseline = sources
            .iter()
            .find(|source| source.binding.source_id == baseline_id)
            .unwrap();
        assert_eq!(baseline.latest_receipt, before.latest_receipt);
        assert_eq!(
            schedule.sources[&baseline_id].last_full_verified,
            verified_at
        );
        assert!(schedule.sources[&baseline_id].owed);
        let earned = sources
            .iter()
            .find(|source| source.binding.source_id != baseline_id)
            .unwrap();
        let earned_receipt = earned.latest_receipt.clone().unwrap();
        assert!(earned_receipt.published);
        assert_eq!(earned_receipt.cycle_seq, cycle.token.cycle_seq.get());
        let conn = rusqlite::Connection::open(&fixture.db).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT complete FROM discovery_receipts WHERE cycle_seq=?1 AND selection_id=?2",
                rusqlite::params![cycle.token.cycle_seq.get(), fixture.selection.id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM discovery_sources WHERE cycle_seq=?1",
                [cycle.token.cycle_seq.get()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        drop(conn);
        drop(lock.borrow_mut().take());
        schedule.hooks = ScheduleTestHooks::default();
        let (repaid, repaid_cycle) = fixture.production_cycle(&mut schedule, &boot);
        assert!(repaid.unwrap().catalog_complete);
        assert_eq!(repaid_cycle.selections[0].observed_count, 1);
        let sources = fixture.sources();
        assert_ne!(
            sources
                .iter()
                .find(|source| source.binding.source_id == baseline_id)
                .unwrap()
                .latest_receipt,
            before.latest_receipt
        );
        assert_eq!(
            sources
                .iter()
                .find(|source| source.binding.source_id != baseline_id)
                .unwrap()
                .latest_receipt,
            Some(earned_receipt)
        );
    }

    #[test]
    fn scheduler_commit_refusal_can_close_only_fully_attempted_exact_receipts() {
        use crate::update_state::acquire_installation_lock;

        let fixture = CycleFixture::new();
        fixture.write_source("attempted.jsonl", SearchProvider::Claude, "exactonrefusal");
        let prefix = fixture._temp.path().join("installation");
        crate::native_autostart::platform::create_private_directory(&prefix).unwrap();
        let boot = ObservationClock::new(Instant::now());
        let lock = Rc::new(RefCell::new(None));
        let exact = Rc::new(Cell::new(false));
        let mut hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let prefix = prefix.clone();
            let lock = lock.clone();
            let exact = exact.clone();
            move |event| {
                match event {
                    ScheduleTestEvent::BeforeAttempt(..) => {
                        // Planning released the lock before source observation.
                        drop(
                            acquire_installation_lock(
                                &prefix,
                                Instant::now() + Duration::from_secs(3),
                            )
                            .unwrap(),
                        );
                    }
                    ScheduleTestEvent::Finalizing => {
                        *lock.borrow_mut() = Some(
                            acquire_installation_lock(
                                &prefix,
                                Instant::now() + Duration::from_secs(3),
                            )
                            .unwrap(),
                        );
                    }
                    ScheduleTestEvent::BeforeDiscoveryPublication { epoch } => {
                        assert!(!epoch);
                        exact.set(true);
                    }
                    _ => {}
                }
                Ok(())
            }
        });
        hooks.epoch_lock_prefix = Some(prefix);
        let mut schedule = SourceScheduleState {
            hooks,
            ..SourceScheduleState::default()
        };

        let (outcome, cycle) = fixture.production_cycle(&mut schedule, &boot);

        assert!(outcome.unwrap().all_sources_attempted);
        assert!(exact.get());
        assert_eq!(
            *schedule.hooks.epoch_refusals.borrow(),
            [(EpochSite::Commit, EpochRefusal::Busy)]
        );
        assert!(cycle.selections[0].discovery_complete);
        assert_exact_discovery(&fixture, &cycle);
        drop(lock.borrow_mut().take());
    }

    #[test]
    fn scheduler_epoch_holds_installation_permit_until_the_publication_returns() {
        use crate::update_state::acquire_installation_lock;
        use agent_session_grep_adapters_sqlite::managed_locks::JobLockKey;

        let fixture = CycleFixture::new();
        fixture.write_source("locked.jsonl", SearchProvider::Claude, "lockedevidence");
        let prefix = fixture._temp.path().join("installation");
        crate::native_autostart::platform::create_private_directory(&prefix).unwrap();
        let boot = ObservationClock::new(Instant::now());
        let published = Rc::new(Cell::new(false));
        let committed = Rc::new(Cell::new(false));
        let mut hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let prefix = prefix.clone();
            let published = published.clone();
            let committed = committed.clone();
            move |event| {
                if let ScheduleTestEvent::BeforeDiscoveryPublication { epoch }
                | ScheduleTestEvent::AfterDiscoveryPublication { epoch } = event
                {
                    assert!(epoch);
                    assert!(matches!(
                        ExclusiveGuard::try_acquire(
                            &prefix,
                            LockKind::MaintenanceJob(
                                JobLockKey::parse("installation-update").unwrap()
                            )
                        ),
                        Err(PortError::WriterBusy(_))
                    ));
                    if matches!(event, ScheduleTestEvent::BeforeDiscoveryPublication { .. }) {
                        published.set(true);
                    } else {
                        committed.set(true);
                    }
                }
                Ok(())
            }
        });
        hooks.epoch_lock_prefix = Some(prefix.clone());
        let mut schedule = SourceScheduleState {
            hooks,
            ..SourceScheduleState::default()
        };

        let (outcome, _) = fixture.ordinary(&mut schedule, &boot);

        assert!(outcome.unwrap().catalog_complete);
        assert!(published.get());
        assert!(committed.get());
        assert!(
            schedule.hooks.epoch_refusals.borrow().is_empty(),
            "a granted permit records nothing"
        );
        drop(acquire_installation_lock(&prefix, fixture.scope_end).unwrap());
    }

    #[test]
    fn scheduler_plan_refusal_under_a_held_installation_lock_is_recorded_once() {
        use crate::update_state::acquire_installation_lock;

        let fixture = CycleFixture::new();
        fixture.write_source("planned.jsonl", SearchProvider::Claude, "plannedexact");
        let prefix = fixture._temp.path().join("installation");
        crate::native_autostart::platform::create_private_directory(&prefix).unwrap();
        let boot = ObservationClock::new(Instant::now());
        let held = acquire_installation_lock(&prefix, fixture.scope_end).unwrap();
        let mut schedule = SourceScheduleState {
            hooks: ScheduleTestHooks {
                epoch_lock_prefix: Some(prefix),
                ..ScheduleTestHooks::default()
            },
            ..SourceScheduleState::default()
        };

        let (outcome, cycle) = fixture.production_cycle(&mut schedule, &boot);

        assert!(outcome.unwrap().all_sources_attempted);
        assert_exact_discovery(&fixture, &cycle);
        // An exact plan never asks again at commit.
        assert_eq!(
            *schedule.hooks.epoch_refusals.borrow(),
            [(EpochSite::Plan, EpochRefusal::Busy)]
        );
        drop(held);
    }

    /// Probe and attempt events in call order; a probe carries no lane.
    fn probe_attempt_trace(
        trace: &Rc<RefCell<Vec<(SourceId, Option<SourceLane>)>>>,
    ) -> ScheduleTestHooks {
        let trace = trace.clone();
        scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), move |event| {
            match event {
                ScheduleTestEvent::BeforeProbe(id, _) => {
                    trace.borrow_mut().push((id.clone(), None))
                }
                ScheduleTestEvent::BeforeAttempt(id, _, lane) => {
                    trace.borrow_mut().push((id.clone(), Some(lane)));
                }
                _ => {}
            }
            Ok(())
        })
    }

    fn source_id_named(fixture: &CycleFixture, name: &str) -> SourceId {
        fixture
            .sources()
            .into_iter()
            .find(|source| source.binding.source_path.ends_with(name))
            .unwrap()
            .binding
            .source_id
    }

    #[test]
    fn scheduler_dirty_carry_over_is_served_before_the_cycles_first_probe_batch() {
        for exact in [false, true] {
            let fixture = CycleFixture::new();
            let hot = fixture.write_source("hot.jsonl", SearchProvider::Claude, "carriedbase");
            fixture.write_source("aging.jsonl", SearchProvider::Claude, "agingbase");
            let boot = if exact {
                ObservationClock::with_epoch_gate(Instant::now(), EpochGate::Unverified)
            } else {
                ObservationClock::new(Instant::now())
            };
            let mut schedule = SourceScheduleState::default();
            let (first, _) = fixture.production_cycle(&mut schedule, &boot);
            assert!(first.unwrap().all_sources_attempted);
            let hot_id = source_id_named(&fixture, "hot.jsonl");
            // Dirtied after its last service in cycle N.
            append_record(&hot, SearchProvider::Claude, "carried", "carriedappend");
            let trace = Rc::new(RefCell::new(Vec::new()));
            schedule.hooks = probe_attempt_trace(&trace);
            // Cycle N's probe window must not hide the first batch of N+1.
            schedule.next_probe = None;

            let (second, _) = fixture.production_cycle(&mut schedule, &boot);

            assert!(second.unwrap().catalog_complete, "exact={exact}");
            let order = trace.borrow();
            assert_eq!(
                order.first(),
                Some(&(hot_id, Some(SourceLane::Active))),
                "exact={exact}: the carried attempt precedes every probe: {order:?}"
            );
            assert!(
                order[1..].iter().any(|(_, lane)| lane.is_none()),
                "exact={exact}: probing resumes after the first attempt: {order:?}"
            );
            assert_eq!(fixture.hits("carriedappend"), 1);
            let refusals = schedule.hooks.epoch_refusals.borrow();
            if exact {
                assert_eq!(*refusals, [(EpochSite::Plan, EpochRefusal::Unverified)]);
            } else {
                assert!(refusals.is_empty(), "granted permits record nothing");
            }
        }
    }

    #[test]
    fn scheduler_carried_two_active_credit_keeps_debt_and_probe_batch_first() {
        let fixture = CycleFixture::new();
        let hot = fixture.write_source("hot.jsonl", SearchProvider::Claude, "creditbase");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        let (first, _) = fixture.production_cycle(&mut schedule, &boot);
        assert!(first.unwrap().all_sources_attempted);
        let hot_id = source_id_named(&fixture, "hot.jsonl");
        append_record(&hot, SearchProvider::Claude, "credit", "creditappend");
        fixture.write_source("cold.jsonl", SearchProvider::Claude, "colddebt");
        // The state a cycle leaves after two Active attempts while debt was
        // still owed; active_attempts survives rollover unchanged.
        schedule.active_attempts = 2;
        schedule.next_probe = None;
        let trace = Rc::new(RefCell::new(Vec::new()));
        schedule.hooks = probe_attempt_trace(&trace);

        let (second, _) = fixture.production_cycle(&mut schedule, &boot);

        assert!(second.unwrap().catalog_complete);
        let order = trace.borrow();
        let attempts = order
            .iter()
            .filter_map(|(id, lane)| lane.map(|lane| (id.clone(), lane)))
            .collect::<Vec<_>>();
        assert_eq!(attempts.len(), 2, "{order:?}");
        assert_eq!(
            attempts[0].1,
            SourceLane::Cold,
            "debt goes first: {order:?}"
        );
        assert_eq!(attempts[1], (hot_id.clone(), SourceLane::Active));
        // Without a ready Active turn the probe batch keeps its place.
        assert_eq!(order.first(), Some(&(hot_id, None)), "{order:?}");
    }

    #[test]
    fn scheduler_pause_or_epoch_change_fails_the_carried_attempt_at_admission() {
        for change in ["pause", "revoke"] {
            let fixture = CycleFixture::new();
            let hot = fixture.write_source("hot.jsonl", SearchProvider::Claude, "revokedbase");
            let mut schedule = SourceScheduleState::default();
            let boot = ObservationClock::new(Instant::now());
            let (first, _) = fixture.production_cycle(&mut schedule, &boot);
            assert!(first.unwrap().all_sources_attempted);
            let hot_id = source_id_named(&fixture, "hot.jsonl");
            append_record(&hot, SearchProvider::Claude, "revoked", "revokedappend");
            let receipts = || -> i64 {
                rusqlite::Connection::open(&fixture.db)
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM source_revision_receipts", [], |row| {
                        row.get(0)
                    })
                    .unwrap()
            };
            let before = receipts();
            let installation =
                fixture.read_control(|control| control.read_policy(RequestIntersection::Selected));
            let control = SqliteControlStore::open_existing_writable(
                fixture.db.parent().unwrap(),
                &installation.installation_id,
            )
            .unwrap();
            let selection = fixture.selection.id.clone();
            let trace = Rc::new(RefCell::new(Vec::new()));
            schedule.next_probe = None;
            schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
                let trace = trace.clone();
                move |event| {
                    match event {
                        ScheduleTestEvent::BeforeProbe(..) => trace.borrow_mut().push("probe"),
                        ScheduleTestEvent::BeforeParse(..) => trace.borrow_mut().push("parse"),
                        ScheduleTestEvent::BeforeAttempt(id, _, lane) => {
                            assert_eq!((id, lane), (&hot_id, SourceLane::Active));
                            trace.borrow_mut().push("attempt");
                            control_change(&control, |seq| match change {
                                "pause" => control
                                    .set_desired_updates(seq, DesiredUpdates::Paused)
                                    .map(|_| ()),
                                _ => control
                                    .revoke_selection(seq, &selection, None, 4)
                                    .map(|_| ()),
                            })
                            .unwrap();
                        }
                        _ => {}
                    }
                    Ok(())
                }
            });

            let (refused, cycle) = fixture.production_cycle(&mut schedule, &boot);

            assert!(
                matches!(refused, Err(PortError::SnapshotChanged(_))),
                "{change}: {refused:?}"
            );
            assert_eq!(cycle.state, CycleState::Aborted, "{change}");
            assert_eq!(
                *trace.borrow(),
                ["attempt"],
                "{change}: no capture or parse"
            );
            assert_eq!(receipts(), before, "{change}");
        }
    }

    #[test]
    fn scheduler_ready_active_matches_next_across_carried_credit_and_expiry() {
        let mut state = SourceScheduleState::default();
        let end = Instant::now() + Duration::from_secs(30);
        let ids = ["hot-a", "hot-b", "hot-c", "cold-a"].map(|id| SourceId::parse(id).unwrap());
        let lanes = [
            SourceLane::Active,
            SourceLane::Active,
            SourceLane::Active,
            SourceLane::Cold,
        ];
        {
            let mut cycle = CycleSchedule::new(&mut state);
            for (id, lane) in ids.iter().zip(lanes) {
                cycle.add(id, None, lane, end, false).unwrap();
            }
            for served in &ids[..2] {
                assert!(cycle.ready_active(Instant::now()));
                let Some(ScheduledTurn::Attempt(id, SourceLane::Active)) =
                    cycle.next(Instant::now())
                else {
                    panic!("ready Active turn was not served");
                };
                assert_eq!(&id, served);
                cycle.started(&id, SourceLane::Active).unwrap();
            }
            // Two Active attempts while Cold debt is owed: credit is spent.
            assert!(!cycle.ready_active(Instant::now()));
            assert!(matches!(
                cycle.next(Instant::now()),
                Some(ScheduledTurn::Attempt(_, SourceLane::Cold))
            ));
            // End the cycle with that debt unserved.
            while cycle.next(end).is_some() {}
        }
        assert_eq!(state.active_attempts, 2);
        let mut cycle = CycleSchedule::new(&mut state);
        for (id, lane) in ids.iter().zip(lanes) {
            cycle.add(id, None, lane, end + CADENCE, false).unwrap();
        }
        // The carried credit keeps the first turn of the next cycle as debt.
        assert!(!cycle.ready_active(Instant::now()));
        let Some(ScheduledTurn::Attempt(id, lane)) = cycle.next(Instant::now()) else {
            panic!("owed debt was not served");
        };
        assert_eq!((&id, lane), (&ids[3], SourceLane::Cold));
        cycle.started(&id, lane).unwrap();
        assert!(cycle.ready_active(Instant::now()));
        assert!(matches!(
            cycle.next(Instant::now()),
            Some(ScheduledTurn::Attempt(_, SourceLane::Active))
        ));
        // Expired Active work is retired by next, never served as ready.
        assert!(!cycle.ready_active(end + CADENCE));
    }

    #[test]
    fn scheduler_final_discovery_deadline_keeps_earned_source_and_awaiting_catalog_barrier() {
        let fixture = CycleFixture::new();
        fixture.write_source("committed.jsonl", SearchProvider::Claude, "earnedsource");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let before = fixture.sources().pop().unwrap().latest_receipt.unwrap();
        let earned = Rc::new(RefCell::new(None));
        let final_end = Rc::new(Cell::new(None));
        let db = fixture.db.clone();
        let private_root = fixture._temp.path().join("private");
        let scope_end = fixture.scope_end;
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let earned = earned.clone();
            let final_end = final_end.clone();
            move |event| {
                if matches!(event, ScheduleTestEvent::Finalizing) {
                    // Phase 1 and the source commit/acknowledgement are durable here.
                    let witness = SqliteControlStore::open_current_read_only_with_deadline(
                        &private_root,
                        scope_end,
                    )?;
                    let source = ManagedStore::open(&db, &witness)?
                        .background_sources(&witness)?
                        .pop()
                        .unwrap();
                    let receipt = source.latest_receipt.as_ref().unwrap();
                    assert!(receipt.published);
                    let source_id = ControlId::parse(source.binding.source_id.as_str())?;
                    let progress = witness.source_progress(&source_id)?.unwrap();
                    assert_eq!(progress.coverage, Coverage::Complete);
                    assert!(progress.error.is_none());
                    *earned.borrow_mut() = Some((source, progress));
                    // Shorten only the final discover end. The normal precheck still
                    // sees the unexpired original root end, so WriterBusy can come only
                    // from discover's own deadline check.
                    final_end.set(Some(Instant::now()));
                }
                Ok(())
            }
        });
        schedule.hooks.final_discovery_end = Some(final_end.clone());
        let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
        assert!(
            final_end.get().is_none(),
            "final discover must consume the shortened end; the precheck cannot substitute"
        );
        // The old direct `?` returned WriterBusy here and aborted the cycle.
        assert!(matches!(result, Ok(false)), "{result:?}");
        assert_eq!(cycle.state, CycleState::Partial);
        let root = &cycle.selections[0];
        assert!(!root.discovery_complete);
        assert_eq!(root.error, Some(BackgroundFailure::Deferred));
        assert_eq!(
            (
                root.discovered_count,
                root.observed_count,
                root.committed_count
            ),
            (1, 1, 1)
        );
        let (earned_source, earned_progress) = earned.take().unwrap();
        let receipt = earned_source.latest_receipt.as_ref().unwrap();
        assert_ne!(receipt.revision_id, before.revision_id);
        assert_eq!(receipt.cycle_seq, cycle.token.cycle_seq.get());
        let observed = earned_progress.last_observation.as_ref();
        assert_eq!(observed, Some(&cycle.token));
        let current = fixture.sources().pop().unwrap();
        assert_eq!(current.latest_receipt, earned_source.latest_receipt);
        let earned_id = earned_source.binding.source_id.clone();
        let source_id = ControlId::parse(earned_id.as_str()).unwrap();
        let progress = fixture.read_control(|control| control.source_progress(&source_id));
        assert_eq!(progress, Some(earned_progress));
        let persisted = fixture.read_control(|control| control.persisted_barrier(&barrier.id));
        assert_eq!(persisted.state, BarrierState::AwaitingCatalog);
        assert!(persisted.error.is_none());
        assert_eq!(persisted.completed_cycle_seq, Some(cycle.token.cycle_seq));
        let catalog = rusqlite::Connection::open(&fixture.db).unwrap();
        let newest: (i64, i64) = catalog
            .query_row(
                "SELECT cycle_seq,complete FROM discovery_receipts
                 WHERE selection_id=?1 ORDER BY cycle_seq DESC LIMIT 1",
                [fixture.selection.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(newest, (cycle.token.cycle_seq.get(), 0));
        let members: i64 = catalog
            .query_row(
                "SELECT COUNT(*) FROM discovery_sources WHERE cycle_seq=?1",
                [cycle.token.cycle_seq.get()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(members, 0);
        assert!(!fixture.latest(&barrier));
    }

    /// A subset latest cycle may narrow the head receipt to its own roots. The
    /// next all-root cycle must reclaim every covering root before closing.
    fn subset_receipt_reclaims_both_overlapping_roots(subset_is_parent: bool) {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("shared.jsonl", SearchProvider::Claude, "sharedword");
        let provider = SearchProvider::Claude;
        let exact = crate::managed_control::source_selection(provider, &path).unwrap();
        let child = control_change_before(&fixture.control, fixture.scope_end, |seq| {
            fixture.control.add_selection(seq, exact.clone())
        })
        .unwrap()
        .value;
        assert_eq!(child.region.kind, RootKind::Exact);
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        let (first, cycle, full) = fixture.scheduled(&mut schedule, &boot);
        assert!(first.unwrap());
        assert_eq!(cycle.selections.len(), 2);
        assert!(fixture.latest(&full));
        assert_eq!(fixture.head_claims(), 2);
        let first_revision = fixture.sources().pop().unwrap().latest_receipt.unwrap();
        let subset_id = if subset_is_parent {
            fixture.selection.id.clone()
        } else {
            child.id.clone()
        };
        let include = |selection: &Selection| selection.id == subset_id;
        let (subset_result, subset, _) = fixture.scheduled_for(&mut schedule, &boot, include);
        assert!(subset_result.unwrap());
        assert_eq!(subset.selections.len(), 1);
        assert_eq!(subset.selections[0].selection.selection_id, subset_id);
        assert_eq!(subset.selections[0].observed_count, 1);
        assert_eq!(subset.selections[0].committed_count, 1);
        assert_eq!(fixture.head_claims(), 1);
        let subset_revision = fixture.sources().pop().unwrap().latest_receipt.unwrap();
        assert_ne!(subset_revision.revision_id, first_revision.revision_id);
        let (ordinary, cycle) = fixture.ordinary(&mut schedule, &boot);
        assert_eq!(cycle.selections.len(), 2);
        for root in &cycle.selections {
            assert!(root.discovery_complete, "{root:?}");
            assert!(root.error.is_none(), "{root:?}");
            assert_eq!((root.observed_count, root.committed_count), (1, 1));
        }
        assert!(ordinary.unwrap().catalog_complete);
        assert_eq!(fixture.head_claims(), 2);
        let reclaimed = fixture.sources().pop().unwrap().latest_receipt.unwrap();
        assert_ne!(reclaimed.revision_id, subset_revision.revision_id);
        assert!(fixture.latest(&full));
    }

    #[test]
    fn scheduler_parent_subset_receipt_reclaims_both_overlapping_roots() {
        subset_receipt_reclaims_both_overlapping_roots(true);
    }

    #[test]
    fn scheduler_child_subset_receipt_reclaims_both_overlapping_roots() {
        subset_receipt_reclaims_both_overlapping_roots(false);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn scheduler_incomplete_root_keeps_an_unattempted_baseline_probe_only() {
        let fixture = CycleFixture::new();
        fixture.write_source("stable.jsonl", SearchProvider::Claude, "stablebaseline");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let before = fixture.sources().pop().unwrap();
        let id = ControlId::parse(before.binding.source_id.as_str()).unwrap();
        let progress = fixture.read_control(|control| control.source_progress(&id));
        // A refused linked entry leaves the root enumeration incomplete without
        // touching the stable source's bytes or hint.
        let target = fixture._temp.path().join("refused-target");
        std::fs::create_dir(&target).unwrap();
        let link = Path::new(fixture.selection.region.locator.as_str()).join("refused-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let output = std::process::Command::new("cmd")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .creation_flags(0x0800_0000)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "synthetic junction creation failed"
            );
        }
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), |event| {
            if matches!(event, ScheduleTestEvent::BeforeAttempt(..)) {
                panic!("an unattempted baseline must stay probe-only beside a refused entry");
            }
            Ok(())
        });
        // The second incomplete cycle proves no failure token forced a rehash.
        for _ in 0..2 {
            let (outcome, cycle) = fixture.ordinary(&mut schedule, &boot);
            assert!(!outcome.unwrap().catalog_complete);
            assert_eq!(cycle.state, CycleState::Partial);
            assert!(!cycle.selections[0].discovery_complete);
            assert_eq!(
                fixture.read_control(|control| control.source_progress(&id)),
                progress
            );
            assert_eq!(fixture.sources()[0].latest_receipt, before.latest_receipt);
        }
        #[cfg(unix)]
        std::fs::remove_file(&link).unwrap();
        #[cfg(windows)]
        std::fs::remove_dir(&link).unwrap();
    }

    #[test]
    fn scheduler_latest_refresh_skips_parse_but_ineligible_scan_reuses_the_full_path() {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("refresh.jsonl", SearchProvider::Claude, "refreshbaseline");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), |event| {
            if matches!(event, ScheduleTestEvent::BeforeParse(..)) {
                panic!("eligible unchanged latest must use verified refresh before parse");
            }
            Ok(())
        });
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        let connection = rusqlite::Connection::open(&fixture.db).unwrap();
        connection
            .execute(
                "UPDATE source_scans SET parser_version=0 WHERE source_path=?1",
                [CanonicalLocator::from_path(&path).unwrap().as_str()],
            )
            .unwrap();
        drop(connection);
        let parsed = Rc::new(Cell::new(0));
        let source_id = fixture.sources()[0].binding.source_id.clone();
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let parsed = parsed.clone();
            move |event| {
                if let ScheduleTestEvent::BeforeParse(id, end) = event {
                    assert_eq!(*id, source_id);
                    assert!(end > Instant::now());
                    parsed.set(parsed.get() + 1);
                }
                Ok(())
            }
        });
        assert!(fixture.scheduled(&mut schedule, &boot).0.unwrap());
        assert_eq!(
            parsed.get(),
            1,
            "only recognized Ineligible may reach full parsing"
        );
    }

    #[test]
    fn scheduler_refresh_corruption_ends_the_attempt_without_parse_or_same_cycle_retry() {
        for provider in [SearchProvider::Claude, SearchProvider::Codex] {
            let fixture = CycleFixture::new_for_provider(provider);
            fixture.write_source("refresh-error.jsonl", provider, "refresherrorbaseline");
            let mut schedule = SourceScheduleState::default();
            let boot = ObservationClock::new(Instant::now());
            assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
            let prior = fixture.sources().pop().unwrap();
            let id = prior.binding.source_id.clone();
            let path = prior.binding.source_path.clone();
            let digest = prior.latest_receipt.as_ref().unwrap().digest.clone();
            let db = fixture.db.clone();
            let attempts = Rc::new(Cell::new(0));
            let failures = Rc::new(Cell::new(0));
            schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
                let attempts = attempts.clone();
                let failures = failures.clone();
                move |event| {
                    match event {
                        ScheduleTestEvent::Planned => {
                            rusqlite::Connection::open(&db)
                                .unwrap()
                                .execute(
                                    "UPDATE source_scans SET fingerprint='broken' WHERE source_path=?1",
                                    [&path],
                                )
                                .unwrap();
                        }
                        ScheduleTestEvent::BeforeAttempt(observed, _, _) => {
                            assert_eq!(*observed, id);
                            attempts.set(attempts.get() + 1);
                        }
                        ScheduleTestEvent::BeforeParse(..) => {
                            panic!("refresh corruption must terminate before full parsing");
                        }
                        ScheduleTestEvent::SourceFailed {
                            id: observed,
                            phase,
                            error,
                            revisit,
                            ..
                        } => {
                            assert_eq!(*observed, id);
                            assert!(matches!(phase, SourceAttemptPhase::Publication));
                            assert!(matches!(error, PortError::SchemaIncompatible(_)));
                            assert!(!revisit);
                            failures.set(failures.get() + 1);
                            rusqlite::Connection::open(&db)
                                .unwrap()
                                .execute(
                                    "UPDATE source_scans SET fingerprint=?2 WHERE source_path=?1",
                                    [&path, &digest],
                                )
                                .unwrap();
                        }
                        _ => {}
                    }
                    Ok(())
                }
            });
            let (result, cycle, barrier) = fixture.scheduled(&mut schedule, &boot);
            assert!(!result.unwrap());
            assert_eq!(attempts.get(), 1);
            assert_eq!(failures.get(), 1);
            assert_eq!(cycle.selections[0].observed_count, 1);
            assert_eq!(cycle.selections[0].committed_count, 0);
            assert_eq!(fixture.sources()[0].latest_receipt, prior.latest_receipt);
            assert!(schedule.full_due(&prior.binding.source_id, schedule.now()));
            assert!(!fixture.latest(&barrier));
            // The refusal is that source's own durable failure inside a cycle
            // that still finishes: neither an abort nor a full-path fallback.
            assert_eq!(cycle.state, CycleState::Partial);
            let progress = fixture
                .read_control(|control| {
                    control.source_progress(
                        &ControlId::parse(prior.binding.source_id.as_str()).unwrap(),
                    )
                })
                .unwrap();
            assert_eq!(
                (progress.coverage, progress.error),
                (Coverage::Partial, Some(BackgroundFailure::Failed))
            );
            assert_eq!(
                progress.last_observation.map(|token| token.cycle_seq),
                Some(cycle.token.cycle_seq)
            );
        }
    }

    #[test]
    fn scheduler_final_enumeration_hint_change_stays_incomplete_without_losing_debt() {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("final.jsonl", SearchProvider::Claude, "beforefinal");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let before = fixture.sources().pop().unwrap();
        let appended = path.clone();
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), move |event| {
            if matches!(event, ScheduleTestEvent::Finalizing) {
                append_record(
                    &appended,
                    SearchProvider::Claude,
                    "final-append",
                    "afterfinal",
                );
            }
            Ok(())
        });
        let (changed, cycle) = fixture.ordinary(&mut schedule, &boot);
        assert!(!changed.unwrap().catalog_complete);
        assert_eq!(
            cycle.selections[0].error,
            Some(BackgroundFailure::SourceChanged)
        );
        assert_eq!(cycle.selections[0].observed_count, 0);
        assert_eq!(fixture.sources()[0].latest_receipt, before.latest_receipt);
        assert!(schedule.full_due(&before.binding.source_id, schedule.now()));
        assert_eq!(fixture.hits("afterfinal"), 0);
        schedule.hooks = ScheduleTestHooks::default();
        assert!(
            fixture
                .ordinary(&mut schedule, &boot)
                .0
                .unwrap()
                .catalog_complete
        );
        assert_eq!(fixture.hits("afterfinal"), 1);
    }

    #[test]
    fn scheduler_failed_actual_probe_keeps_owed_work_until_an_independent_cycle() {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("probe.jsonl", SearchProvider::Claude, "probeoriginal");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let before = fixture.sources().pop().unwrap();
        let id = before.binding.source_id.clone();
        let saved = path.with_extension("saved");
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let probe = path.clone();
        let restore = saved.clone();
        schedule.next_probe = None;
        schedule.hooks = scheduler_hooks(elapsed.clone(), move |event| {
            match event {
                ScheduleTestEvent::BeforeProbe(..) => {
                    std::fs::rename(&probe, &restore).unwrap();
                }
                ScheduleTestEvent::Finalizing => std::fs::rename(&restore, &probe).unwrap(),
                _ => {}
            }
            Ok(())
        });
        let (failed, _) = fixture.ordinary(&mut schedule, &boot);
        assert!(!failed.unwrap().catalog_complete);
        assert!(schedule.full_due(&id, schedule.now()));
        assert_eq!(fixture.sources()[0].latest_receipt, before.latest_receipt);
        schedule.hooks = ScheduleTestHooks::default();
        assert!(
            fixture
                .ordinary(&mut schedule, &boot)
                .0
                .unwrap()
                .catalog_complete
        );
    }

    #[test]
    fn scheduler_full_sweep_is_due_from_the_last_capture_and_registration_never_renews_it() {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("sweep.jsonl", SearchProvider::Claude, "originalword");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let prior = fixture.sources().pop().unwrap();
        let id = &prior.binding.source_id;
        let last = schedule.sources[id].last_full_verified.unwrap();
        for second in [1, 100, 299] {
            schedule.register(id, Some(&prior)).unwrap();
            assert_eq!(schedule.sources[id].last_full_verified, Some(last));
            assert!(!schedule.full_due(id, last + Duration::from_secs(second)));
        }
        assert!(schedule.full_due(id, last + FULL_VERIFICATION_INTERVAL));
        let bytes = std::fs::read_to_string(&path)
            .unwrap()
            .replace("originalword", "rewritenword");
        std::fs::write(&path, bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert!(
            fixture
                .ordinary(&mut schedule, &boot)
                .0
                .unwrap()
                .catalog_complete
        );
        assert_eq!(fixture.hits("rewritenword"), 0);
        schedule.sources.get_mut(id).unwrap().last_full_verified =
            Instant::now().checked_sub(FULL_VERIFICATION_INTERVAL);
        let (due, _) = fixture.ordinary(&mut schedule, &boot);
        assert!(
            !due.unwrap().catalog_complete,
            "same-hint rewrite must reach the real fingerprint/confirmation path"
        );
        assert!(schedule.full_due(id, schedule.now()));
        assert_eq!(fixture.hits("originalword"), 1);
        assert_eq!(fixture.hits("rewritenword"), 0);
    }

    #[test]
    fn scheduler_probe_only_promotes_once_and_expiry_does_not_manufacture_a_first_turn() {
        let id = SourceId::parse("stable").unwrap();
        let mut state = SourceScheduleState::default();
        let now = Instant::now();
        state.register(&id, None).unwrap();
        {
            let debt = state.sources.get_mut(&id).unwrap();
            debt.owed = false;
            debt.last_full_verified = Some(now);
            debt.verified = Some((
                RevisionId::parse("receipt").unwrap(),
                SourceHint {
                    len: 1,
                    mtime_ms: 1,
                },
                Vec::new(),
            ));
        }
        let ticket = state.sources[&id].ticket;
        let mut cycle = CycleSchedule::new(&mut state);
        cycle
            .add_obligation(
                &id,
                None,
                SourceLane::Verification,
                now + CADENCE,
                true,
                TurnObligation::ProbeOnly,
            )
            .unwrap();
        // No persisted head is available in this pure queue test; restore the
        // captured pair after registration, independently of lane accounting.
        cycle.state.sources.get_mut(&id).unwrap().verified = Some((
            RevisionId::parse("receipt").unwrap(),
            SourceHint {
                len: 1,
                mtime_ms: 1,
            },
            Vec::new(),
        ));
        cycle.state.sources.get_mut(&id).unwrap().owed = false;
        cycle.state.sources.get_mut(&id).unwrap().last_full_verified = Some(now);
        assert_eq!(cycle.first_pending, 0);
        assert!(cycle.next(now).is_none());
        let hint = SourceHint {
            len: 2,
            mtime_ms: 2,
        };
        cycle.hint(&id, hint, Some(1));
        cycle.hint(&id, hint, Some(1));
        assert_eq!(cycle.first_pending, 1);
        assert_eq!(cycle.state.sources[&id].ticket, ticket);
        let Some(ScheduledTurn::Attempt(served, lane)) = cycle.next(now) else {
            panic!("dirty ProbeOnly source was not promoted");
        };
        assert_eq!(served, id);
        assert_eq!(lane, SourceLane::Active);
        cycle.started(&id, lane).unwrap();
        cycle.failed(&id);
        assert!(cycle.next(now + CADENCE).is_none());
        assert!(cycle.state.full_due(&id, now + CADENCE));
    }

    #[test]
    fn scheduler_unowed_probe_expiry_preserves_capture_and_creates_no_not_scheduled_outcome() {
        let fixture = CycleFixture::new();
        fixture.write_source("unowed.jsonl", SearchProvider::Claude, "unowed");
        let mut state = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut state, &boot).0.unwrap().idle());
        let prior = fixture.sources().pop().unwrap();
        let id = &prior.binding.source_id;
        let verified = state.sources[id].verified.clone();
        let verified_at = state.sources[id].last_full_verified;
        let ticket = state.sources[id].ticket;
        let end = Instant::now() + CADENCE;
        let mut cycle = CycleSchedule::new(&mut state);
        cycle
            .add_obligation(
                id,
                Some(&prior),
                SourceLane::Verification,
                end,
                true,
                TurnObligation::ProbeOnly,
            )
            .unwrap();
        assert!(cycle.probe_batch(end).is_empty());
        assert!(cycle.next(end).is_none());
        assert_eq!(cycle.first_pending, 0);
        assert_eq!(cycle.state.sources[id].ticket, ticket);
        assert_eq!(cycle.state.sources[id].verified, verified);
        assert_eq!(cycle.state.sources[id].last_full_verified, verified_at);
        assert!(!cycle.state.full_due(id, end));
    }

    #[test]
    fn scheduler_465_full_debts_keep_fifo_tickets_across_independent_bounded_cycles() {
        let mut state = SourceScheduleState::default();
        let start = Instant::now();
        let ids = (0..465)
            .map(|n| SourceId::parse(&format!("owed-{n:03}")).unwrap())
            .collect::<Vec<_>>();
        let mut served: Vec<SourceId> = Vec::new();
        let mut first_ticket = None;
        for round in 0..4 {
            let remaining = ids
                .iter()
                .filter(|id| !served.contains(id))
                .cloned()
                .collect::<Vec<_>>();
            let end = start + Duration::from_secs(round + 1);
            let mut cycle = CycleSchedule::new(&mut state);
            for id in &remaining {
                cycle
                    .add(id, None, SourceLane::Verification, end, false)
                    .unwrap();
            }
            if let Some((id, ticket)) = first_ticket.take() {
                assert_eq!(
                    cycle.state.sources[&id].ticket, ticket,
                    "expiry must not rotate an unstarted obligation"
                );
            }
            for _ in 0..150 {
                let Some(ScheduledTurn::Attempt(id, lane)) = cycle.next(start) else {
                    break;
                };
                cycle.started(&id, lane).unwrap();
                served.push(id);
            }
            if let Some(id) = remaining.iter().find(|id| !served.contains(id)) {
                first_ticket = Some((id.clone(), cycle.state.sources[id].ticket));
            }
            while let Some(turn) = cycle.next(end) {
                assert!(matches!(turn, ScheduledTurn::NotScheduled(..)));
            }
        }
        assert_eq!(served, ids);
    }

    #[test]
    fn scheduler_invalid_baseline_scan_failure_and_new_boot_force_real_observation() {
        let fixture = CycleFixture::new();
        let path = fixture.write_source("invalid.jsonl", SearchProvider::Claude, "invalidbaseline");
        let mut schedule = SourceScheduleState::default();
        let boot = ObservationClock::new(Instant::now());
        assert!(fixture.ordinary(&mut schedule, &boot).0.unwrap().idle());
        let prior = fixture.sources().pop().unwrap();
        let canonical = CanonicalLocator::from_path(&path).unwrap();
        let connection = rusqlite::Connection::open(&fixture.db).unwrap();
        connection
            .execute(
                "UPDATE source_scans SET parser_version=0 WHERE source_path=?1",
                [canonical.as_str()],
            )
            .unwrap();
        drop(connection);
        let visits = Rc::new(Cell::new(0));
        schedule.hooks = scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
            let visits = visits.clone();
            move |event| {
                if matches!(event, ScheduleTestEvent::BeforeAttempt(..)) {
                    visits.set(visits.get() + 1);
                }
                Ok(())
            }
        });
        assert!(
            fixture
                .ordinary(&mut schedule, &boot)
                .0
                .unwrap()
                .catalog_complete
        );
        assert_eq!(
            visits.get(),
            1,
            "stale parser scan must not become ProbeOnly"
        );
        let mut restarted = SourceScheduleState {
            hooks: scheduler_hooks(Rc::new(Cell::new(Duration::ZERO)), {
                let visits = visits.clone();
                move |event| {
                    if matches!(event, ScheduleTestEvent::BeforeAttempt(..)) {
                        visits.set(visits.get() + 1);
                    }
                    Ok(())
                }
            }),
            ..Default::default()
        };
        assert!(
            fixture
                .ordinary(&mut restarted, &boot)
                .0
                .unwrap()
                .catalog_complete
        );
        assert_eq!(
            visits.get(),
            2,
            "persisted receipt cannot seed a new worker's timer"
        );
        assert_ne!(fixture.sources()[0].latest_receipt, prior.latest_receipt);
    }

    #[test]
    fn scheduler_probe_rotation_keeps_aging_work_under_a_hot_backfill() {
        let mut state = SourceScheduleState::default();
        let start = Instant::now();
        let ids = (0..465)
            .map(|n| SourceId::parse(&format!("source-{n:03}")).unwrap())
            .collect::<Vec<_>>();
        let mut cycle = CycleSchedule::new(&mut state);
        for id in &ids {
            cycle
                .add_obligation(
                    id,
                    None,
                    SourceLane::Verification,
                    start + Duration::from_secs(30),
                    true,
                    TurnObligation::ProbeOnly,
                )
                .unwrap();
        }
        for id in &ids[..16] {
            cycle.state.remember_hot(id);
        }
        cycle
            .add(
                &SourceId::parse("backfill-debt").unwrap(),
                None,
                SourceLane::Cold,
                start + SOURCE_OBSERVATION_BUDGET,
                false,
            )
            .unwrap();
        let mut aging = BTreeSet::new();
        for tick in 0..10 {
            let batch = cycle.probe_batch(start + Duration::from_secs(tick));
            assert!(batch.len() <= SOURCE_HINT_BATCH);
            assert_eq!(batch.iter().filter(|id| ids[..16].contains(id)).count(), 16);
            aging.extend(batch.into_iter().filter(|id| !ids[..16].contains(id)));
        }
        assert_eq!(
            aging.len(),
            449,
            "aging probes must not starve behind the hot set"
        );
        assert_eq!(cycle.first_pending, 1);
    }

    #[test]
    fn scheduler_latest_windows_do_not_renew_and_late_admission_cannot_join_started_work() {
        let fixture = CycleFixture::new();
        let worker = fixture.worker();
        let (queued, barrier) = fixture.queued();
        let cycle = fixture.start(&worker, &queued);
        let policy =
            fixture.read_control(|control| control.read_policy(RequestIntersection::Selected));
        let mut schedule = SourceScheduleState::default();
        let now = Instant::now();
        schedule
            .update_demands(vec![barrier.clone()], &policy, now)
            .unwrap();
        let revision = selection_revision(&fixture.selection).unwrap();
        assert!(schedule.cycle_can_serve(std::iter::once(revision.clone()), &cycle, now));
        let mut late = barrier.clone();
        late.id = ControlId::parse("late-demand").unwrap();
        late.required_cycle_seq = CycleSeq::new(cycle.token.cycle_seq.get() + 1).unwrap();
        late.admission_control_seq = cycle.started_control_seq.unwrap();
        late.requested_wait_ms = MAX_LATEST_WAIT_MS;
        schedule
            .update_demands(vec![barrier.clone(), late.clone()], &policy, now)
            .unwrap();
        assert!(!schedule.cycle_can_serve(std::iter::once(revision.clone()), &cycle, now));
        let end = schedule.demands[&late.id].service_end;
        late.state = BarrierState::AwaitingCatalog;
        schedule
            .update_demands(vec![late.clone()], &policy, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(schedule.demands[&late.id].service_end, end);
        schedule
            .update_demands(vec![late.clone()], &policy, end)
            .unwrap();
        schedule
            .update_demands(vec![late], &policy, end + CADENCE)
            .unwrap();
        assert!(!schedule.latest_owed(std::iter::once(revision), None, end + CADENCE));
    }

    #[test]
    fn scheduler_demand_table_forgets_departed_barriers_without_reopening_listed_windows() {
        let fixture = CycleFixture::new();
        let (_, barrier) = fixture.queued();
        let policy =
            fixture.read_control(|control| control.read_policy(RequestIntersection::Selected));
        let demand = |name: &str| {
            let mut demand = barrier.clone();
            demand.id = ControlId::parse(name).unwrap();
            demand
        };
        let (a, b, c) = (demand("demand-a"), demand("demand-b"), demand("demand-c"));
        let mut schedule = SourceScheduleState::default();
        let now = Instant::now();
        schedule
            .update_demands_within(vec![a.clone(), b.clone()], &policy, now, 2)
            .unwrap();
        let b_end = schedule.demands[&b.id].service_end;
        // Every listed barrier still counts against the bound.
        assert!(matches!(
            schedule.update_demands_within(vec![a.clone(), b.clone(), c.clone()], &policy, now, 2),
            Err(PortError::WriterBusy(_))
        ));
        // A departed terminal barrier frees its slot; b's window has lapsed
        // while it is still listed, so it stays retired on its first end.
        let later = b_end + CADENCE;
        schedule
            .update_demands_within(vec![b.clone(), c.clone()], &policy, later, 2)
            .unwrap();
        assert!(!schedule.demands.contains_key(&a.id));
        assert!(!schedule.demands[&c.id].retired);
        schedule
            .update_demands_within(vec![b.clone(), c], &policy, later + CADENCE, 2)
            .unwrap();
        assert!(schedule.demands[&b.id].retired);
        assert_eq!(schedule.demands[&b.id].service_end, b_end);
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
            assert_eq!(expired, 5, "only unserved first turns are NotScheduled");
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
            let epoch_plan_allowed = boot
                .epoch_permit(control, fixture.scope_end, &schedule.hooks)
                .is_ok();
            observe_cycle(
                &fixture.db,
                control,
                &worker,
                &policy,
                &selections,
                &interrupted,
                &boot,
                &mut schedule,
                epoch_plan_allowed,
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
                claims: vec![selection_revision(&fixture.selection).unwrap()],
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
            let outcome = run_cycle(
                &fixture.db,
                control,
                &worker,
                &ObservationClock::new(Instant::now()),
                0,
                fixture_end,
                &mut pending,
                &mut SourceScheduleState::default(),
            )
            .unwrap();
            assert!(outcome.idle(), "{outcome:?}");
            assert_eq!(outcome.finish(), CycleFinish::Committed);
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
        let outcome = run_cycle(
            &fixture.db,
            control,
            &worker,
            &ObservationClock::new(Instant::now()),
            0,
            fixture.scope_end,
            &mut pending,
            &mut SourceScheduleState::default(),
        )
        .unwrap();
        assert!(outcome.idle(), "{outcome:?}");
        assert_eq!(outcome.finish(), CycleFinish::Committed);
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
