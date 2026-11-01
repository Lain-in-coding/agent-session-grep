//! Login lifetime and bounded crash recovery. The child owns the background
//! lock; this process owns only the supervisor lock and never signals a PID.
//! Native managers may use the same policy without duplicating ingestion.

#[cfg(not(test))]
use agent_session_grep_adapters_sqlite::SqliteControlStore;
use agent_session_grep_adapters_sqlite::{
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity},
    managed_store::{ManagedStore, validate_catalog_path},
};
use agent_session_grep_launcher::{
    BackgroundChild, CurrentPointer, ReleaseMetadata, VerifiedApplication, metadata,
    verify_installation,
};
use agent_session_grep_ports::{
    PortError, PortResult,
    control::{
        BackgroundControl, ControlId, ControlSeq, ControlStatus, ControlStore, DesiredUpdates,
        MaintenanceState, UpdateState,
    },
};
use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::package_installation::ImagePin;
#[cfg(test)]
use integration_deadline_tests::ObservedControl as SqliteControlStore;

pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const HEALTHY_RESET: Duration = Duration::from_secs(600);
pub const MAX_UNEXPECTED_EXITS: u8 = 5;
const CONTROL_POLL_BUDGET: Duration = Duration::from_millis(250);
const STARTUP_BUDGET: Duration = Duration::from_secs(5);

/// The schedule is capped independently of the stricter five-exit budget.
pub fn restart_delay(unexpected_exits: u8) -> Duration {
    Duration::from_secs(match unexpected_exits {
        0 | 1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        5 => 16,
        _ => 30,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Ready,
    Running,
    Paused,
    Backoff,
    BackgroundFailed,
    CleanIdle,
    OtherWorker,
    Busy,
    Stopping,
    Finished,
}

/// Pure boot-local state. `now` and healthy durations must exclude suspend.
/// Idle/backoff/suspend time cannot replenish the crash budget. Exhaustion is
/// latched even if a caller later supplies a long healthy duration.
#[derive(Debug)]
pub struct RestartPolicy {
    restart_seq: ControlSeq,
    unexpected: u8,
    healthy: Duration,
    retry_at: Duration,
    clean_idle: bool,
}

impl RestartPolicy {
    pub fn new(restart_seq: ControlSeq) -> Self {
        Self {
            restart_seq,
            unexpected: 0,
            healthy: Duration::ZERO,
            retry_at: Duration::ZERO,
            clean_idle: false,
        }
    }

    /// Only an explicit new request resets idle/exhaustion, even when the
    /// desired state was already running. It does not change pause/stop intent.
    pub fn observe_restart(&mut self, restart_seq: ControlSeq) -> PortResult<()> {
        if restart_seq < self.restart_seq {
            return Err(changed());
        }
        if restart_seq > self.restart_seq {
            *self = Self::new(restart_seq);
        }
        Ok(())
    }

    pub fn unexpected_exits(&self) -> u8 {
        self.unexpected
    }

    pub fn record_healthy_active(&mut self, elapsed: Duration) {
        if self.unexpected == 0 || self.unexpected >= MAX_UNEXPECTED_EXITS || self.clean_idle {
            return;
        }
        self.healthy = self.healthy.saturating_add(elapsed);
        if self.healthy >= HEALTHY_RESET {
            self.unexpected = 0;
            self.healthy = Duration::ZERO;
        }
    }

    pub fn record_exit(&mut self, now: Duration, code: i32, intentional: bool) {
        if intentional || code == 0 {
            self.clean_idle = true;
            return;
        }
        self.unexpected = self.unexpected.saturating_add(1).min(MAX_UNEXPECTED_EXITS);
        self.healthy = Duration::ZERO;
        self.retry_at = now.saturating_add(restart_delay(self.unexpected));
    }

    pub fn state(&self, now: Duration) -> SupervisorState {
        if self.unexpected >= MAX_UNEXPECTED_EXITS {
            SupervisorState::BackgroundFailed
        } else if self.clean_idle {
            SupervisorState::CleanIdle
        } else if now < self.retry_at {
            SupervisorState::Backoff
        } else {
            SupervisorState::Ready
        }
    }
}

#[derive(PartialEq, Eq)]
struct ApplicationIdentity {
    generation: u64,
    version: String,
    digest: String,
    source_commit: String,
}

impl ApplicationIdentity {
    fn read(app: &VerifiedApplication) -> PortResult<Self> {
        let info = app.info();
        if i64::from(info.catalog_schema) != agent_session_grep_adapters_sqlite::SCHEMA_VERSION
            || i64::from(info.control_schema)
                != agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION
        {
            return Err(changed());
        }
        Ok(Self {
            generation: info.generation,
            version: info.version.into(),
            digest: info.app_sha256.into(),
            source_commit: info.source_commit.into(),
        })
    }
}

/// Mutable package records are witnessed by exact bounded bytes, not retained
/// deny-write handles. Updates can fence/drain while startup waits on control.
struct PackageWitness {
    pointer: CurrentPointer,
    release: ReleaseMetadata,
    pointer_bytes: Vec<u8>,
    release_bytes: Vec<u8>,
    version_identity: RootIdentity,
}

impl PackageWitness {
    fn read(prefix: &Path, end: Instant) -> PortResult<(Self, [File; 2])> {
        let (pointer_bytes, pointer_file) = read_package_record(&prefix.join("current.json"), end)?;
        let pointer = CurrentPointer::parse(&pointer_bytes).map_err(|_| changed())?;
        let version_dir = prefix.join(&pointer.dir);
        let version_identity = RootIdentity::read(&version_dir)?;
        let (release_bytes, release_file) =
            read_package_record(&version_dir.join("release.json"), end)?;
        let release = ReleaseMetadata::parse(&release_bytes, &pointer).map_err(|_| changed())?;
        check_deadline(end)?;
        Ok((
            Self {
                pointer,
                release,
                pointer_bytes,
                release_bytes,
                version_identity,
            },
            [pointer_file, release_file],
        ))
    }

    fn matches(&self, app: &VerifiedApplication) -> bool {
        let info = app.info();
        info.generation == self.pointer.generation.get()
            && info.version == self.pointer.version
            && info.app_sha256 == self.pointer.app_sha256
            && info.source_commit == self.release.source_commit
            && info.catalog_schema == self.release.catalog_schema.get()
            && info.control_schema == self.release.control_schema.get()
    }

    fn recheck(&self, prefix: &Path, end: Instant) -> PortResult<[File; 2]> {
        let (current, pins) = Self::read(prefix, end)?;
        if current.pointer_bytes != self.pointer_bytes
            || current.release_bytes != self.release_bytes
            || current.version_identity != self.version_identity
        {
            return Err(changed());
        }
        Ok(pins)
    }
}

fn read_package_record(path: &Path, end: Instant) -> PortResult<(Vec<u8>, File)> {
    check_deadline(end)?;
    let mut file = crate::package_installation::pinned(path).map_err(|_| changed())?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(metadata::MAX_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| changed())?;
    check_deadline(end)?;
    if bytes.len() > metadata::MAX_METADATA_BYTES {
        return Err(changed());
    }
    Ok((bytes, file))
}

// The shared image pin binds the hash operation to the same physical image
// before and after it, and again immediately before launch. The launcher also
// retains its own file pin.
struct StartupApplication {
    application: VerifiedApplication,
    witness: PackageWitness,
    image: ImagePin,
    supervisor_image: Option<ImagePin>,
    _package_guards: Vec<File>,
}

impl StartupApplication {
    fn verify(
        prefix: &Path,
        executable: Option<&Path>,
        expected: &ApplicationIdentity,
        end: Instant,
    ) -> PortResult<Self> {
        check_deadline(end)?;
        let (witness, metadata_pins) = PackageWitness::read(prefix, end)?;
        let image = ImagePin::open(prefix.join(&witness.pointer.dir).join(&witness.pointer.app))
            .map_err(|_| changed())?;
        let supervisor_image = executable
            .map(|path| ImagePin::open(path.into()))
            .transpose()
            .map_err(|_| changed())?;
        drop(metadata_pins);
        check_deadline(end)?;
        // This verifier has no cancellation API. Invoke it only once per
        // admitted attempt, then refuse every side effect if the end elapsed.
        let (application, package_guards) = if let Some(executable) = executable {
            let mut installation =
                crate::package_installation::inspect_installation(prefix).map_err(|_| changed())?;
            let (expected_path, _) = installation.supervisor.as_ref().ok_or_else(changed)?;
            if std::fs::canonicalize(executable).map_err(|_| changed())?
                != std::fs::canonicalize(expected_path).map_err(|_| changed())?
            {
                return Err(changed());
            }
            check_deadline(end)?;
            installation.release_update_pins();
            (installation._application, installation._guards)
        } else {
            (
                verify_installation(prefix).map_err(|_| changed())?,
                Vec::new(),
            )
        };
        check_deadline(end)?;
        if ApplicationIdentity::read(&application)? != *expected || !witness.matches(&application) {
            return Err(changed());
        }
        image.recheck().map_err(|_| changed())?;
        if let Some(image) = &supervisor_image {
            image.recheck().map_err(|_| changed())?;
        }
        drop(witness.recheck(prefix, end)?);
        Ok(Self {
            application,
            witness,
            image,
            supervisor_image,
            _package_guards: package_guards,
        })
    }

    fn recheck(&self, prefix: &Path, end: Instant) -> PortResult<[File; 2]> {
        check_deadline(end)?;
        self.image.recheck().map_err(|_| changed())?;
        if let Some(image) = &self.supervisor_image {
            image.recheck().map_err(|_| changed())?;
        }
        self.witness.recheck(prefix, end)
    }
}

/// The original admission end survives Busy and expiry. Expiry releases file
/// pins but cannot turn the next ordinary control poll into another hash loop.
struct StartupAttempt {
    end: Instant,
    application: Option<StartupApplication>,
}

/// One process owns this value for its lifetime. Dropping it never kills the
/// worker: only the worker's own lock and durable controls govern that process.
pub struct Supervisor {
    prefix: PathBuf,
    catalog: PathBuf,
    prefix_identity: RootIdentity,
    guard: ExclusiveGuard,
    installation: ControlId,
    incarnation: Option<ControlId>,
    application: ApplicationIdentity,
    startup: Option<StartupAttempt>,
    child: Option<BackgroundChild>,
    policy: RestartPolicy,
    last_sample: Duration,
    last_heartbeat: Option<(ControlId, i64)>,
    last_control_seq: ControlSeq,
    was_healthy: bool,
    stopping: bool,
    supervisor_executable: Option<PathBuf>,
}

enum OpenFailure {
    Duplicate,
    Other(PortError),
}

impl From<PortError> for OpenFailure {
    fn from(error: PortError) -> Self {
        Self::Other(error)
    }
}

impl Supervisor {
    /// The native-registration owner verifies the supervisor package member
    /// and supplies its bound prefix/catalog. Revalidate those paths here and
    /// before every spawn; never derive authority from argv[0], PATH or a PID.
    pub fn open(prefix: &Path, catalog: &Path) -> PortResult<Self> {
        Self::open_checked(prefix, catalog, Instant::now() + STARTUP_BUDGET).map_err(|error| {
            match error {
                OpenFailure::Duplicate => {
                    PortError::WriterBusy("supervisor already owns its lock".into())
                }
                OpenFailure::Other(error) => error,
            }
        })
    }

    fn open_checked(prefix: &Path, catalog: &Path, deadline: Instant) -> Result<Self, OpenFailure> {
        let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
        check_deadline(deadline)?;
        if !prefix.is_absolute() || !catalog.is_absolute() {
            return Err(invalid().into());
        }
        validate_catalog_path(catalog)?;
        let prefix_identity = RootIdentity::read(prefix)?;
        let app = verify_installation(prefix).map_err(|_| changed())?;
        check_deadline(deadline)?;
        loop {
            match Self::open_bound(prefix, catalog, prefix_identity, &app, deadline) {
                Err(OpenFailure::Other(PortError::WriterBusy(_))) if Instant::now() < deadline => {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                result => return result,
            }
        }
    }

    fn open_bound(
        prefix: &Path,
        catalog: &Path,
        prefix_identity: RootIdentity,
        app: &VerifiedApplication,
        deadline: Instant,
    ) -> Result<Self, OpenFailure> {
        check_deadline(deadline)?;
        if RootIdentity::read(prefix)? != prefix_identity {
            return Err(changed().into());
        }
        let root = catalog.parent().ok_or_else(invalid)?;
        let control = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
        let status = control.with_runtime_deadline(deadline, || control.status())?;
        let guard =
            ExclusiveGuard::try_acquire(root, LockKind::Supervisor).map_err(
                |error| match error {
                    PortError::WriterBusy(_) => OpenFailure::Duplicate,
                    error => OpenFailure::Other(error),
                },
            )?;
        let incarnation = if allowed(&status) {
            let store = control
                .with_runtime_deadline(deadline, || ManagedStore::open(catalog, &control))?;
            if status
                .catalog_incarnation
                .as_ref()
                .is_some_and(|id| id != store.incarnation())
            {
                return Err(changed().into());
            }
            Some(store.incarnation().clone())
        } else {
            status.catalog_incarnation.clone()
        };
        Ok(Self {
            prefix: prefix.to_path_buf(),
            catalog: catalog.to_path_buf(),
            prefix_identity,
            guard,
            installation: status.policy.installation_id,
            incarnation,
            application: ApplicationIdentity::read(app)?,
            startup: None,
            child: None,
            policy: RestartPolicy::new(status.restart_request_seq),
            last_sample: active_time()?,
            last_heartbeat: None,
            last_control_seq: status.policy.control_seq,
            was_healthy: false,
            stopping: false,
            supervisor_executable: None,
        })
    }

    /// An observation of our own child, not authority to signal this number.
    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().map(BackgroundChild::id)
    }

    pub fn policy(&self) -> &RestartPolicy {
        &self.policy
    }

    fn control(&self, deadline: Instant) -> PortResult<SqliteControlStore> {
        self.read_control(deadline).map(|(control, _)| control)
    }

    fn read_control(&self, deadline: Instant) -> PortResult<(SqliteControlStore, ControlStatus)> {
        check_deadline(deadline)?;
        let root = self.catalog.parent().ok_or_else(invalid)?;
        if RootIdentity::read(root)? != self.guard.root_identity()
            || RootIdentity::read(&self.prefix)? != self.prefix_identity
        {
            return Err(changed());
        }
        let control = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
        let status = control.with_runtime_deadline(deadline, || control.status())?;
        if status.policy.installation_id != self.installation {
            return Err(changed());
        }
        Ok((control, status))
    }

    fn report_failure(&self, failed: bool, deadline: Instant) -> PortResult<()> {
        let root = self.catalog.parent().ok_or_else(invalid)?;
        self.control(deadline)?;
        let control = SqliteControlStore::open_existing_writable_with_deadline(
            root,
            &self.installation,
            deadline,
        )?;
        loop {
            check_deadline(deadline)?;
            let current = control.with_runtime_deadline(deadline, || control.status())?;
            if current.supervisor_failed == failed {
                return Ok(());
            }
            // A concurrent explicit restart owns the newer request. Let the
            // next tick consume it instead of publishing obsolete exhaustion.
            if failed && current.restart_request_seq != self.policy.restart_seq {
                return Ok(());
            }
            match control.with_runtime_deadline(deadline, || {
                control.report_supervisor_failure(current.policy.control_seq, &self.guard, failed)
            }) {
                Ok(_) => return Ok(()),
                Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Ordinary control work retains its 250 ms end. Only a Ready observation
    /// admits a separate startup attempt; Busy cannot renew that attempt's end.
    pub fn tick(&mut self) -> PortResult<SupervisorState> {
        self.expire_startup();
        let deadline =
            SqliteControlStore::effective_runtime_deadline(Instant::now() + CONTROL_POLL_BUDGET);
        let state = loop {
            match self.tick_until(deadline) {
                Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                    self.was_healthy = false;
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(PortError::WriterBusy(_)) => {
                    self.was_healthy = false;
                    self.expire_startup();
                    return Ok(SupervisorState::Busy);
                }
                Err(error) => {
                    self.startup = None;
                    return Err(error);
                }
                Ok(state) => break state,
            }
        };
        if state == SupervisorState::Ready {
            self.advance_startup()
        } else {
            Ok(state)
        }
    }

    fn expire_startup(&mut self) {
        if let Some(attempt) = &mut self.startup
            && Instant::now() >= attempt.end
        {
            attempt.application = None;
        }
    }

    fn tick_until(&mut self, deadline: Instant) -> PortResult<SupervisorState> {
        check_deadline(deadline)?;
        let now = active_time()?;
        let elapsed = now.checked_sub(self.last_sample).ok_or_else(changed)?;
        self.last_sample = now;
        let (control, current) = self.read_control(deadline)?;
        if current.policy.maintenance.state == MaintenanceState::Idle
            && control
                .with_runtime_deadline(deadline, || control.purge_jobs())?
                .iter()
                .any(|j| j.state != agent_session_grep_ports::control::PurgeState::Complete)
        {
            crate::managed_purge::ensure_started(&self.catalog, deadline);
        }
        if current.policy.control_seq < self.last_control_seq {
            return Err(changed());
        }
        self.last_control_seq = current.policy.control_seq;
        let new_request = current.restart_request_seq > self.policy.restart_seq;
        self.policy.observe_restart(current.restart_request_seq)?;
        self.stopping = !allowed(&current);
        if new_request || self.stopping {
            self.startup = None;
        }
        let failed = self.policy.state(now) == SupervisorState::BackgroundFailed;
        if current.supervisor_failed != failed {
            self.report_failure(failed, deadline)?;
        }

        if let Some(child) = &mut self.child {
            if let Some(code) = child.try_wait().map_err(|_| unavailable())? {
                self.child = None;
                self.was_healthy = false;
                self.last_heartbeat = None;
                self.policy.record_exit(now, code, self.stopping);
                // A request observed together with completion belongs after
                // that exit; otherwise a clean exit could consume and lose an
                // explicit start that arrived while the old worker drained.
                if new_request {
                    self.policy = RestartPolicy::new(current.restart_request_seq);
                }
                if self.policy.state(now) == SupervisorState::BackgroundFailed {
                    self.report_failure(true, deadline)?;
                }
            } else {
                let worker = control
                    .with_runtime_deadline(deadline, || control.background_status())?
                    .worker;
                let heartbeat = worker.boot_id.zip(worker.heartbeat_at_ms);
                let healthy = !self.stopping
                    && current.desired_updates == DesiredUpdates::Running
                    && worker.pid_hint == Some(child.id())
                    && matches!(worker.state, UpdateState::Running | UpdateState::Idle)
                    && worker.error.is_none();
                if healthy
                    && self.was_healthy
                    && heartbeat.is_some()
                    && heartbeat != self.last_heartbeat
                {
                    // Credit only one observed cadence. A stalled/suspended
                    // observer cannot turn an unobserved interval into health.
                    self.policy
                        .record_healthy_active(elapsed.min(POLL_INTERVAL));
                }
                self.was_healthy = healthy;
                self.last_heartbeat = heartbeat;
                return Ok(if self.stopping {
                    SupervisorState::Stopping
                } else if current.desired_updates == DesiredUpdates::Paused {
                    SupervisorState::Paused
                } else {
                    SupervisorState::Running
                });
            }
        }
        if self.stopping {
            return Ok(SupervisorState::Finished);
        }
        let state = self.policy.state(now);
        if state != SupervisorState::Ready {
            return Ok(state);
        }
        let root = self.catalog.parent().ok_or_else(invalid)?;
        match ExclusiveGuard::try_acquire(root, LockKind::Background) {
            Ok(guard) => drop(guard),
            Err(PortError::WriterBusy(_)) => return Ok(SupervisorState::OtherWorker),
            Err(error) => return Err(error),
        }

        Ok(SupervisorState::Ready)
    }

    fn advance_startup(&mut self) -> PortResult<SupervisorState> {
        let attempt = self.startup.get_or_insert_with(|| StartupAttempt {
            end: SqliteControlStore::effective_runtime_deadline(Instant::now() + STARTUP_BUDGET),
            application: None,
        });
        let end = attempt.end;
        if Instant::now() >= end {
            attempt.application = None;
            return Ok(SupervisorState::Busy);
        }
        if attempt.application.is_none() {
            match StartupApplication::verify(
                &self.prefix,
                self.supervisor_executable.as_deref(),
                &self.application,
                end,
            ) {
                Ok(application) => attempt.application = Some(application),
                Err(PortError::WriterBusy(_)) => {
                    self.expire_startup();
                    return Ok(SupervisorState::Busy);
                }
                Err(error) => {
                    self.startup = None;
                    return Err(error);
                }
            }
        }
        // Post-verification control/catalog admission remains a short poll,
        // capped by the same startup end on every subsequent Busy retry.
        let poll_end = end.min(SqliteControlStore::effective_runtime_deadline(
            Instant::now() + CONTROL_POLL_BUDGET,
        ));
        match self.spawn_until(poll_end) {
            Err(PortError::WriterBusy(_)) => {
                self.was_healthy = false;
                self.expire_startup();
                Ok(SupervisorState::Busy)
            }
            Err(error) => {
                self.startup = None;
                Err(error)
            }
            result => result,
        }
    }

    fn spawn_until(&mut self, deadline: Instant) -> PortResult<SupervisorState> {
        check_deadline(deadline)?;
        let (control, current) = self.read_control(deadline)?;
        if !allowed(&current) {
            self.stopping = true;
            self.startup = None;
            return Ok(SupervisorState::Finished);
        }
        let store = control
            .with_runtime_deadline(deadline, || ManagedStore::open(&self.catalog, &control))?;
        if self.incarnation.as_ref() != Some(store.incarnation()) {
            return Err(changed());
        }
        drop(store);
        let _metadata_pins = self
            .startup
            .as_ref()
            .and_then(|attempt| attempt.application.as_ref())
            .ok_or_else(changed)?
            .recheck(&self.prefix, deadline)?;
        // This read follows hashes, physical image/path checks and catalog
        // verification. A pause starts only a control worker; a fence/stop
        // releases every pending executable pin without spawning.
        let current = control.with_runtime_deadline(deadline, || control.status())?;
        if !allowed(&current) {
            self.stopping = true;
            self.startup = None;
            return Ok(SupervisorState::Finished);
        }
        if current.policy.installation_id != self.installation
            || current.policy.control_seq < self.last_control_seq
            || RootIdentity::read(&self.prefix)? != self.prefix_identity
            || current
                .catalog_incarnation
                .as_ref()
                .is_some_and(|id| Some(id) != self.incarnation.as_ref())
        {
            return Err(changed());
        }
        self.last_control_seq = current.policy.control_seq;
        let new_request = current.restart_request_seq > self.policy.restart_seq;
        self.policy.observe_restart(current.restart_request_seq)?;
        // The final control read happens after the ordinary Ready poll and
        // physical verification. A request observed here belongs to a new
        // admission, so release the old attempt before it can reach a busy
        // owner or a later control error and leave its expired latch behind.
        if new_request {
            self.startup = None;
            return Ok(SupervisorState::Ready);
        }
        let root = self.catalog.parent().ok_or_else(invalid)?;
        match ExclusiveGuard::try_acquire(root, LockKind::Background) {
            Ok(guard) => drop(guard),
            Err(PortError::WriterBusy(_)) => return Ok(SupervisorState::OtherWorker),
            Err(error) => return Err(error),
        }
        let args = [
            OsString::from("__managed-background"),
            OsString::from("--db"),
            self.catalog.as_os_str().to_owned(),
        ];
        check_deadline(deadline)?;
        let application = self
            .startup
            .take()
            .and_then(|attempt| attempt.application)
            .ok_or_else(changed)?;
        match application.application.spawn_background(&args) {
            Ok(child) => {
                self.child = Some(child);
                self.was_healthy = false;
                Ok(if current.desired_updates == DesiredUpdates::Paused {
                    SupervisorState::Paused
                } else {
                    SupervisorState::Running
                })
            }
            Err(_) => {
                let now = active_time()?;
                self.policy.record_exit(now, 1, false);
                if self.policy.state(now) == SupervisorState::BackgroundFailed {
                    self.report_failure(true, deadline)?;
                }
                Ok(self.policy.state(now))
            }
        }
    }

    pub fn run(&mut self) -> PortResult<()> {
        loop {
            if self.tick()? == SupervisorState::Finished {
                return Ok(());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

fn check_deadline(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        return Err(PortError::WriterBusy(
            "supervisor control deadline reached".into(),
        ));
    }
    Ok(())
}

fn allowed(status: &ControlStatus) -> bool {
    status.desired_updates != DesiredUpdates::Stopped
        && status.policy.maintenance.state == MaintenanceState::Idle
}

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid supervisor request".into())
}
fn changed() -> PortError {
    PortError::GenerationMismatch("supervisor installation binding changed".into())
}
fn unavailable() -> PortError {
    PortError::SourceIo("supervisor process observation unavailable".into())
}

/// Private fixed entry grammar, independent of the ordinary CLI. No diagnostics
/// or content reach inherited handles, including malformed requests and errors.
pub fn run_entry(args: &[OsString]) -> i32 {
    if args.len() == 1 && args[0] == "--version" {
        crate::protocol::write_stdout_line(concat!("asg-supervisor ", env!("CARGO_PKG_VERSION")));
        return 0;
    }
    let paths = if args.len() == 4 && args[0] == "--prefix" && args[2] == "--db" {
        Ok((PathBuf::from(&args[1]), PathBuf::from(&args[3])))
    } else if args.len() == 2 && args[0] == "--db" {
        installed_prefix().map(|prefix| (prefix, PathBuf::from(&args[1])))
    } else {
        return 2;
    };
    match paths
        .and_then(|(prefix, catalog)| {
            let executable = std::env::current_exe().map_err(|_| unavailable())?;
            let deadline = Instant::now() + STARTUP_BUDGET;
            verify_self(&prefix, &executable)?;
            check_deadline(deadline)?;
            match Supervisor::open_checked(&prefix, &catalog, deadline) {
                Ok(mut supervisor) => {
                    supervisor.supervisor_executable = Some(executable);
                    Ok(Some(supervisor))
                }
                Err(OpenFailure::Duplicate) => Ok(None),
                Err(OpenFailure::Other(error)) => Err(error),
            }
        })
        .and_then(|supervisor| supervisor.map_or(Ok(()), |mut s| s.run()))
    {
        Ok(()) => 0,
        Err(error) => crate::ProtocolError::from_private_port_error(error)
            .code
            .exit_code(),
    }
}

fn verify_self(prefix: &Path, executable: &Path) -> PortResult<()> {
    crate::setup_command::verify_supervisor(prefix, executable).map_err(|_| {
        PortError::SchemaIncompatible("supervisor package identity is unavailable".into())
    })
}

fn installed_prefix() -> PortResult<PathBuf> {
    let executable = std::env::current_exe().map_err(|_| unavailable())?;
    let expected_name = if cfg!(windows) {
        "asg-supervisor.exe"
    } else {
        "asg-supervisor"
    };
    if executable
        .file_name()
        .is_none_or(|name| name != expected_name)
    {
        return Err(changed());
    }
    let version_dir = executable.parent().ok_or_else(changed)?;
    let versions = version_dir
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "versions"))
        .ok_or_else(changed)?;
    let prefix = versions.parent().ok_or_else(changed)?;
    // The shared package verifier immediately checks this exact versioned
    // member against current.json. Do not hash the whole application again
    // merely to derive a path before that verification.
    Ok(prefix.to_path_buf())
}

fn active_time() -> PortResult<Duration> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;
        let mut ticks = 0_u64;
        // SAFETY: a valid writable u64 outlives the synchronous query. This
        // boot-local 100ns counter excludes sleep and hibernation.
        if unsafe { QueryUnbiasedInterruptTime(&mut ticks) } == 0 {
            return Err(unavailable());
        }
        Ok(Duration::new(
            ticks / 10_000_000,
            ((ticks % 10_000_000) * 100) as u32,
        ))
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        let clock = libc::CLOCK_UPTIME_RAW;
        #[cfg(not(target_os = "macos"))]
        let clock = libc::CLOCK_MONOTONIC;
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: value is a valid output pointer. Both selected native clocks
        // are monotonic and exclude system suspend.
        if unsafe { libc::clock_gettime(clock, &mut value) } != 0
            || value.tv_sec < 0
            || !(0..1_000_000_000).contains(&value.tv_nsec)
        {
            return Err(unavailable());
        }
        Ok(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
    }
    #[cfg(not(any(windows, unix)))]
    Err(unavailable())
}

#[cfg(test)]
mod integration_deadline_tests {
    use super::*;
    use agent_session_grep_adapters_sqlite::SqliteControlStore;
    use agent_session_grep_ports::control::{ControlChange, PurgeJob};
    use rusqlite::Connection;
    use std::{cell::RefCell, ops::Deref};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ControlCall {
        ReadOpen,
        WriteOpen,
        Status,
        FailureWrite,
        PurgeJobs,
    }

    struct DeadlineTrace {
        end: Instant,
        calls: Vec<(ControlCall, Instant)>,
    }

    thread_local! {
        static DEADLINE_TRACE: RefCell<Option<DeadlineTrace>> = const { RefCell::new(None) };
    }

    struct ObserveDeadline;

    impl ObserveDeadline {
        fn start(end: Instant) -> Self {
            DEADLINE_TRACE.with(|trace| {
                assert!(trace.borrow().is_none());
                *trace.borrow_mut() = Some(DeadlineTrace {
                    end,
                    calls: Vec::new(),
                });
            });
            Self
        }

        fn finish(self) -> Vec<ControlCall> {
            let trace = DEADLINE_TRACE.with(|trace| trace.borrow_mut().take().unwrap());
            for (call, end) in &trace.calls {
                assert_eq!(*end, trace.end, "{call:?} lost the caller's original end");
            }
            trace.calls.into_iter().map(|(call, _)| call).collect()
        }
    }

    impl Drop for ObserveDeadline {
        fn drop(&mut self) {
            DEADLINE_TRACE.with(|trace| *trace.borrow_mut() = None);
        }
    }

    fn observe_control_call(call: ControlCall, requested: Option<Instant>) {
        DEADLINE_TRACE.with(|trace| {
            if let Some(trace) = trace.borrow_mut().as_mut() {
                // An unscoped call returns the later probe, so removing a
                // with_runtime_deadline cannot pass as the original end.
                let end = requested.unwrap_or_else(|| {
                    SqliteControlStore::effective_runtime_deadline(
                        trace.end + Duration::from_nanos(1),
                    )
                });
                trace.calls.push((call, end));
            }
        });
    }

    // Only this module's test build observes admission arguments and the
    // actual scope at SQL entry. Every call still reaches the real adapter;
    // this neither installs a deadline nor changes time or lock behavior.
    pub(super) struct ObservedControl(SqliteControlStore);

    impl Deref for ObservedControl {
        type Target = SqliteControlStore;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl ObservedControl {
        pub(super) fn effective_runtime_deadline(end: Instant) -> Instant {
            SqliteControlStore::effective_runtime_deadline(end)
        }

        pub(super) fn open_current_read_only_with_deadline(
            root: &Path,
            end: Instant,
        ) -> PortResult<Self> {
            observe_control_call(ControlCall::ReadOpen, Some(end));
            SqliteControlStore::open_current_read_only_with_deadline(root, end).map(Self)
        }

        pub(super) fn open_existing_writable_with_deadline(
            root: &Path,
            installation: &ControlId,
            end: Instant,
        ) -> PortResult<Self> {
            observe_control_call(ControlCall::WriteOpen, Some(end));
            SqliteControlStore::open_existing_writable_with_deadline(root, installation, end)
                .map(Self)
        }

        pub(super) fn status(&self) -> PortResult<ControlStatus> {
            observe_control_call(ControlCall::Status, None);
            self.0.status()
        }

        pub(super) fn purge_jobs(&self) -> PortResult<Vec<PurgeJob>> {
            observe_control_call(ControlCall::PurgeJobs, None);
            self.0.purge_jobs()
        }

        pub(super) fn report_supervisor_failure(
            &self,
            expected: ControlSeq,
            guard: &ExclusiveGuard,
            failed: bool,
        ) -> PortResult<ControlChange<()>> {
            observe_control_call(ControlCall::FailureWrite, None);
            self.0.report_supervisor_failure(expected, guard, failed)
        }
    }

    fn fixture_deadline() -> Instant {
        Instant::now() + STARTUP_BUDGET
    }

    fn fixture_retry<T>(
        mut operation: impl FnMut() -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        let end = fixture_deadline();
        loop {
            match operation() {
                Err(PortError::WriterBusy(_)) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => return result,
            }
        }
    }

    fn fixture_guard(root: &Path, kind: LockKind) -> ExclusiveGuard {
        fixture_retry(|| ExclusiveGuard::try_acquire(root, kind.clone())).unwrap()
    }

    // Actual private control state; these cases never spawn, inspect a package,
    // touch provider histories, or enter the purge helper.
    fn fixture() -> (tempfile::TempDir, Supervisor) {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().join("synthetic-installation");
        std::fs::create_dir(&prefix).unwrap();
        let root = temp.path().join("private");
        let control = SqliteControlStore::create(
            &root,
            &ControlId::parse("synthetic-supervisor-deadline").unwrap(),
            DesiredUpdates::Stopped,
        )
        .unwrap();
        let status = control
            .with_runtime_deadline(fixture_deadline(), || control.status())
            .unwrap();
        drop(control);
        let guard = fixture_guard(&root, LockKind::Supervisor);
        let supervisor = Supervisor {
            prefix_identity: RootIdentity::read(&prefix).unwrap(),
            prefix,
            catalog: root.join("catalog.db"),
            guard,
            installation: status.policy.installation_id,
            incarnation: None,
            application: ApplicationIdentity {
                generation: 1,
                version: "synthetic".into(),
                digest: "a".repeat(64),
                source_commit: "b".repeat(40),
            },
            startup: None,
            child: None,
            policy: RestartPolicy::new(status.restart_request_seq),
            last_sample: active_time().unwrap(),
            last_heartbeat: None,
            last_control_seq: status.policy.control_seq,
            was_healthy: false,
            stopping: false,
            supervisor_executable: None,
        };
        (temp, supervisor)
    }

    /// Small synthetic hash input only; these unit cases never execute it.
    /// The integration suite separately uses the actual compiled CLI and shim.
    fn pin_startup(supervisor: &mut Supervisor, end: Instant) -> PathBuf {
        use sha2::{Digest, Sha256};
        let bytes = b"synthetic immutable image; never executed\n";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let version = env!("CARGO_PKG_VERSION");
        let dir = format!("versions/{version}-{}", &digest[..12]);
        let image = supervisor.prefix.join(&dir).join(metadata::APP_NAME);
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(&image, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let pointer = serde_json::json!({
            "schema": "asg.current/v1", "generation": 1, "version": version,
            "dir": dir, "app": metadata::APP_NAME, "app_sha256": digest,
            "launcher_protocol": 1, "activated_at": "2026-10-17T00:00:00Z"
        });
        let release = serde_json::json!({
            "schema": "asg.version/v1", "version": version, "target": metadata::BUILD_TARGET,
            "source_commit": "b".repeat(40), "app_sha256": digest,
            "catalog_schema": agent_session_grep_adapters_sqlite::SCHEMA_VERSION,
            "control_schema": agent_session_grep_adapters_sqlite::control::CONTROL_SCHEMA_VERSION,
            "launcher_protocol_min": 1, "launcher_protocol_max": 1,
            "built_at": "2026-10-17T00:00:00Z"
        });
        std::fs::write(
            supervisor.prefix.join("current.json"),
            serde_json::to_vec(&pointer).unwrap(),
        )
        .unwrap();
        std::fs::write(
            image.parent().unwrap().join("release.json"),
            serde_json::to_vec(&release).unwrap(),
        )
        .unwrap();
        supervisor.application = ApplicationIdentity {
            generation: 1,
            version: version.into(),
            digest,
            source_commit: "b".repeat(40),
        };
        supervisor.startup = Some(StartupAttempt {
            end,
            application: Some(
                StartupApplication::verify(&supervisor.prefix, None, &supervisor.application, end)
                    .unwrap(),
            ),
        });
        image
    }

    fn running(supervisor: &Supervisor) -> SqliteControlStore {
        let root = supervisor.catalog.parent().unwrap();
        let deadline = fixture_deadline();
        let installation = fixture_retry(|| {
            let current = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
            Ok(current.status()?.policy.installation_id)
        })
        .unwrap();
        let control = fixture_retry(|| {
            SqliteControlStore::open_existing_writable_with_deadline(root, &installation, deadline)
        })
        .unwrap();
        control
            .with_runtime_deadline(deadline, || {
                let seq = control.status()?.policy.control_seq;
                control.set_desired_updates(seq, DesiredUpdates::Running)
            })
            .unwrap();
        control
    }

    fn control_status(control: &SqliteControlStore) -> ControlStatus {
        control
            .with_runtime_deadline(fixture_deadline(), || control.status())
            .unwrap()
    }

    fn ready_with_fixture_retry(
        supervisor: &mut Supervisor,
        mut operation: impl FnMut(&mut Supervisor, Instant) -> Result<SupervisorState, PortError>,
    ) -> SupervisorState {
        let end = fixture_deadline();
        loop {
            match operation(supervisor, end) {
                Ok(SupervisorState::Ready) => return SupervisorState::Ready,
                Ok(SupervisorState::OtherWorker) | Err(PortError::WriterBusy(_))
                    if Instant::now() < end =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => return result.expect("fixture supervisor operation failed"),
            }
        }
    }

    #[test]
    fn ready_control_poll_does_not_hash_or_open_a_catalog() {
        let (_temp, mut supervisor) = fixture();
        drop(running(&supervisor));
        assert_eq!(
            ready_with_fixture_retry(&mut supervisor, Supervisor::tick_until),
            SupervisorState::Ready,
        );
        assert!(supervisor.startup.is_none());
        assert!(!supervisor.prefix.join("current.json").exists());
        assert!(!supervisor.catalog.exists());
        assert!(matches!(
            supervisor.advance_startup(),
            Err(PortError::GenerationMismatch(_))
        ));
        assert!(supervisor.child_id().is_none());
    }

    #[test]
    fn startup_expiry_releases_pins_without_renewing_until_explicit_start() {
        let (_temp, mut supervisor) = fixture();
        let control = running(&supervisor);
        // Running is itself an explicit restart request. Admit that request
        // before testing expiry so the next poll has no newer reset to consume.
        assert_eq!(
            ready_with_fixture_retry(&mut supervisor, Supervisor::tick_until),
            SupervisorState::Ready,
        );
        let image = pin_startup(&mut supervisor, Instant::now() + STARTUP_BUDGET);
        let expired = Instant::now();
        supervisor.startup.as_mut().unwrap().end = expired;
        assert_eq!(supervisor.advance_startup().unwrap(), SupervisorState::Busy);
        assert!(supervisor.startup.as_ref().unwrap().application.is_none());
        std::fs::write(&image, b"released image").unwrap();
        assert_eq!(supervisor.tick().unwrap(), SupervisorState::Busy);
        assert_eq!(supervisor.startup.as_ref().unwrap().end, expired);
        control
            .with_runtime_deadline(fixture_deadline(), || {
                let seq = control.status()?.policy.control_seq;
                control.request_background_start(seq)
            })
            .unwrap();
        drop(control);
        assert_eq!(
            ready_with_fixture_retry(&mut supervisor, Supervisor::tick_until),
            SupervisorState::Ready,
        );
        assert!(supervisor.startup.is_none());
        assert!(supervisor.child_id().is_none());
    }

    #[test]
    fn startup_control_busy_keeps_pinned_image_and_original_admission_end() {
        let (_temp, mut supervisor) = fixture();
        let image = pin_startup(&mut supervisor, Instant::now() + STARTUP_BUDGET);
        let end = supervisor.startup.as_ref().unwrap().end;
        let root = supervisor.catalog.parent().unwrap();
        let blocker = ExclusiveGuard::try_acquire(root, LockKind::ControlHandles).unwrap();
        let poll_end = Instant::now() + Duration::from_millis(20);
        let observed = ObserveDeadline::start(poll_end);
        assert!(matches!(
            supervisor.spawn_until(poll_end),
            Err(PortError::WriterBusy(_)),
        ));
        let calls = observed.finish();
        assert!(
            calls.is_empty() || calls == [ControlCall::ReadOpen],
            "{calls:?}"
        );
        assert_eq!(supervisor.startup.as_ref().unwrap().end, end);
        assert!(supervisor.startup.as_ref().unwrap().application.is_some());
        drop(blocker);
        let poll_end = Instant::now() + CONTROL_POLL_BUDGET;
        let observed = ObserveDeadline::start(poll_end);
        assert_eq!(
            supervisor.tick_until(poll_end).unwrap(),
            SupervisorState::Finished,
        );
        assert_eq!(
            observed.finish(),
            [
                ControlCall::ReadOpen,
                ControlCall::Status,
                ControlCall::PurgeJobs
            ]
        );
        assert!(supervisor.startup.is_none());
        std::fs::write(&image, b"released after stop").unwrap();
    }

    #[test]
    fn final_restart_releases_the_old_attempt_and_stays_eligible() {
        let (_temp, mut supervisor) = fixture();
        let incarnation = ControlId::parse("catalog-final-restart").unwrap();
        let root = supervisor.catalog.parent().unwrap();
        let deadline = fixture_deadline();
        let installation = fixture_retry(|| {
            let current = SqliteControlStore::open_current_read_only_with_deadline(root, deadline)?;
            Ok(current.status()?.policy.installation_id)
        })
        .unwrap();
        let control = fixture_retry(|| {
            SqliteControlStore::open_existing_writable_with_deadline(root, &installation, deadline)
        })
        .unwrap();
        let store =
            ManagedStore::create(&supervisor.catalog, &control, incarnation.clone(), 1).unwrap();
        supervisor.incarnation = Some(store.incarnation().clone());
        drop(store);
        drop(control);

        let control = running(&supervisor);
        let first_request = control_status(&control).restart_request_seq;
        assert_eq!(
            ready_with_fixture_retry(&mut supervisor, Supervisor::tick_until),
            SupervisorState::Ready
        );
        assert_eq!(supervisor.policy.restart_seq, first_request);

        let image = pin_startup(&mut supervisor, Instant::now() + STARTUP_BUDGET);
        let image_bytes = std::fs::read(&image).unwrap();
        let old_end = supervisor.startup.as_ref().unwrap().end;
        assert!(old_end > Instant::now());
        let owner = fixture_guard(supervisor.catalog.parent().unwrap(), LockKind::Background);
        control
            .with_runtime_deadline(fixture_deadline(), || {
                let control_seq = control.status()?.policy.control_seq;
                control.request_background_start(control_seq)
            })
            .unwrap();
        let newer_request = control_status(&control).restart_request_seq;
        assert!(newer_request > first_request);

        assert_eq!(
            ready_with_fixture_retry(&mut supervisor, Supervisor::spawn_until),
            SupervisorState::Ready
        );
        assert!(supervisor.startup.is_none());
        assert_eq!(supervisor.policy.restart_seq, newer_request);
        assert_eq!(supervisor.child_id(), None);
        assert_eq!(supervisor.policy.unexpected_exits(), 0);
        assert!(
            control
                .with_runtime_deadline(fixture_deadline(), || control.background_status())
                .unwrap()
                .worker
                .boot_id
                .is_none()
        );

        // Dropping StartupAttempt must release the executable pin even though
        // the final Background owner prevented any spawn.
        std::fs::write(&image, b"released before the next admission").unwrap();
        std::fs::write(&image, image_bytes).unwrap();
        drop(owner);

        assert_eq!(
            ready_with_fixture_retry(&mut supervisor, Supervisor::tick_until),
            SupervisorState::Ready
        );
        assert!(supervisor.startup.is_none());
        assert_eq!(supervisor.policy.restart_seq, newer_request);
        assert_eq!(supervisor.child_id(), None);
        assert_eq!(supervisor.policy.unexpected_exits(), 0);
    }

    #[test]
    fn post_verification_pointer_and_image_changes_are_refused() {
        let (_temp, mut supervisor) = fixture();
        let image = pin_startup(&mut supervisor, Instant::now() + STARTUP_BUDGET);
        let attempt = supervisor.startup.as_ref().unwrap();
        let application = attempt.application.as_ref().unwrap();
        let pointer = supervisor.prefix.join("current.json");
        let original = std::fs::read(&pointer).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["generation"] = serde_json::json!(2);
        // Mutable pointer pins were released while the verified image is held.
        std::fs::write(&pointer, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            application.recheck(&supervisor.prefix, attempt.end),
            Err(PortError::GenerationMismatch(_)),
        ));
        std::fs::write(&pointer, original).unwrap();
        #[cfg(unix)]
        {
            // Unix descriptors pin an inode, not its mutable bytes. A changed
            // image stamp must reject even when the descriptor is unchanged.
            std::fs::write(&image, b"changed same inode").unwrap();
            assert!(matches!(
                application.recheck(&supervisor.prefix, attempt.end),
                Err(PortError::GenerationMismatch(_)),
            ));
        }
        #[cfg(windows)]
        assert!(std::fs::write(&image, b"blocked by verified image pin").is_err());
        assert!(supervisor.child_id().is_none());
    }

    #[test]
    fn post_verification_stop_and_maintenance_release_pins_without_spawn() {
        for maintenance in [false, true] {
            let (_temp, mut supervisor) = fixture();
            let control = running(&supervisor);
            let image = pin_startup(&mut supervisor, Instant::now() + STARTUP_BUDGET);
            let seq = control.status().unwrap().policy.control_seq;
            if maintenance {
                let _job = ExclusiveGuard::try_acquire(
                    supervisor.catalog.parent().unwrap(),
                    LockKind::MaintenanceJob(
                        agent_session_grep_adapters_sqlite::managed_locks::JobLockKey::parse(
                            "supervisor-admission-maintenance",
                        )
                        .unwrap(),
                    ),
                )
                .unwrap();
                let owner = ControlId::parse("supervisor-admission-owner").unwrap();
                control
                    .set_maintenance(
                        seq,
                        &owner,
                        agent_session_grep_ports::control::MaintenanceFence {
                            state: MaintenanceState::Updating,
                            owner: Some(owner.clone()),
                            phase: Some(
                                agent_session_grep_ports::control::MaintenancePhase::Quiescing,
                            ),
                        },
                    )
                    .unwrap();
            } else {
                control
                    .set_desired_updates(seq, DesiredUpdates::Stopped)
                    .unwrap();
            }
            let expected = control.status().unwrap();
            drop(control);
            assert_eq!(
                supervisor
                    .spawn_until(Instant::now() + CONTROL_POLL_BUDGET)
                    .unwrap(),
                SupervisorState::Finished,
            );
            assert!(supervisor.child_id().is_none());
            assert!(supervisor.startup.is_none());
            assert!(!supervisor.catalog.exists());
            std::fs::write(&image, b"released after intentional drain").unwrap();
            let control =
                SqliteControlStore::open_current_read_only(supervisor.catalog.parent().unwrap())
                    .unwrap();
            let current = control.status().unwrap();
            assert_eq!(current.desired_updates, expected.desired_updates);
            assert_eq!(current.policy.maintenance, expected.policy.maintenance);
        }
    }

    #[test]
    fn expired_failure_report_refuses_before_control_mutation() {
        let (_temp, supervisor) = fixture();
        let end = Instant::now();
        let observed = ObserveDeadline::start(end);
        let result = supervisor.report_failure(true, end);
        assert!(observed.finish().is_empty());
        let control =
            SqliteControlStore::open_current_read_only(supervisor.catalog.parent().unwrap())
                .unwrap();
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(!control.status().unwrap().supervisor_failed);
    }

    #[test]
    fn failure_report_writer_contention_uses_original_remaining_deadline() {
        let (_temp, supervisor) = fixture();
        let root = supervisor.catalog.parent().unwrap();
        let before = SqliteControlStore::open_current_read_only(root)
            .unwrap()
            .status()
            .unwrap();
        let writer = Connection::open(SqliteControlStore::path(root)).unwrap();
        writer.busy_timeout(Duration::ZERO).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let end = Instant::now() + Duration::from_millis(20);
        let observed = ObserveDeadline::start(end);
        let result = supervisor.report_failure(true, end);
        let calls = observed.finish();
        writer.execute_batch("ROLLBACK").unwrap();
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        let report_calls = [
            ControlCall::ReadOpen,
            ControlCall::Status,
            ControlCall::WriteOpen,
            ControlCall::Status,
            ControlCall::FailureWrite,
        ];
        // A preempted call may expire at any boundary. Exact scope equality,
        // plus a complete successful trace below, detects renewed 250 ms waits.
        assert!(report_calls.starts_with(&calls), "{calls:?}");
        let control = SqliteControlStore::open_current_read_only(root).unwrap();
        assert_eq!(control.status().unwrap(), before);
        drop(control);
        let end = Instant::now() + Duration::from_secs(1);
        let observed = ObserveDeadline::start(end);
        supervisor.report_failure(true, end).unwrap();
        assert_eq!(observed.finish(), report_calls);
        assert!(
            SqliteControlStore::open_current_read_only(root)
                .unwrap()
                .status()
                .unwrap()
                .supervisor_failed
        );
    }

    #[test]
    fn expired_open_refuses_before_package_access() {
        let (_temp, supervisor) = fixture();
        assert!(matches!(
            Supervisor::open_checked(&supervisor.prefix, &supervisor.catalog, Instant::now()),
            Err(OpenFailure::Other(PortError::WriterBusy(_)))
        ));
        assert!(!supervisor.catalog.exists());
    }

    #[test]
    fn tick_control_handle_contention_keeps_original_deadline_and_recovers() {
        let (_temp, mut supervisor) = fixture();
        let root = supervisor.catalog.parent().unwrap().to_path_buf();
        let blocker = ExclusiveGuard::try_acquire(&root, LockKind::ControlHandles).unwrap();
        let end = Instant::now() + Duration::from_millis(20);
        let observed = ObserveDeadline::start(end);
        let result = supervisor.tick_until(end);
        let calls = observed.finish();
        drop(blocker);
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(
            calls.is_empty() || calls == [ControlCall::ReadOpen],
            "{calls:?}"
        );
        assert_eq!(supervisor.child_id(), None);
        let end = Instant::now() + Duration::from_secs(1);
        let observed = ObserveDeadline::start(end);
        assert_eq!(
            supervisor.tick_until(end).unwrap(),
            SupervisorState::Finished
        );
        assert_eq!(
            observed.finish(),
            [
                ControlCall::ReadOpen,
                ControlCall::Status,
                ControlCall::PurgeJobs
            ]
        );
    }

    #[test]
    fn expired_spawn_refuses_before_control_read_or_child_creation() {
        let (_temp, mut supervisor) = fixture();
        let end = Instant::now();
        let observed = ObserveDeadline::start(end);
        assert!(matches!(
            supervisor.spawn_until(end),
            Err(PortError::WriterBusy(_))
        ));
        assert!(observed.finish().is_empty());
        assert!(supervisor.child_id().is_none());
        assert!(!supervisor.catalog.exists());
    }

    #[test]
    fn expired_tick_refuses_before_sampling_or_control_read() {
        let (_temp, mut supervisor) = fixture();
        // Consecutive native clock samples can be equal; use an unmistakable
        // prior value so removing the entry guard cannot pass by coincidence.
        let previous_sample = Duration::ZERO;
        supervisor.last_sample = previous_sample;
        let end = Instant::now();
        let observed = ObserveDeadline::start(end);
        assert!(matches!(
            supervisor.tick_until(end),
            Err(PortError::WriterBusy(_))
        ));
        assert!(observed.finish().is_empty());
        assert_eq!(supervisor.last_sample, previous_sample);
        assert_eq!(supervisor.child_id(), None);
    }
}
