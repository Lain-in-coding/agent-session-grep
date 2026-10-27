//! Private control-handle lifetime and terminal retirement capabilities.
//!
//! Normal admission never recreates policy after retirement. This module only
//! publishes a small content-free marker; it never removes databases or data.
//! Callers retain their original deadline and all drain guards through cleanup.

use crate::{
    control::{
        CONTROL_SCHEMA_VERSION, INSTALLATION_LOCK_KEY, PURGE_LOCK_KEY, SqliteControlStore,
        validate_private_directory, validate_private_owned_file,
    },
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity, SharedGuard},
    managed_maintenance::validate_identity,
};
use agent_session_grep_ports::{
    PortError, PortResult,
    control::{ControlId, ControlSeq, ControlStore, MaintenanceState, PolicyEpoch, PurgeState},
};
use rusqlite::{Connection, OpenFlags, Row, types::ValueRef};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MARKER_SCHEMA: &str = "asg.control-retirement/v1";
/// These owned siblings must survive terminal cleanup. Their existence denies
/// normal admission even when their bytes are corrupt or control.db is absent.
pub const RETIREMENT_MARKER: &str = ".asg-control-retired";
pub const RETIREMENT_PENDING_MARKER: &str = ".asg-control-retired.pending";
const MAX_MARKER_BYTES: u64 = 2048;

thread_local! {
    static RETIREMENT_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

fn deadline_error() -> PortError {
    PortError::WriterBusy("control retirement deadline reached".into())
}

fn retirement_tick() -> PortResult<()> {
    if RETIREMENT_DEADLINE
        .with(Cell::get)
        .is_some_and(|end| Instant::now() >= end)
    {
        return Err(deadline_error());
    }
    Ok(())
}

struct RetirementDeadlineScope(Option<Instant>);
impl Drop for RetirementDeadlineScope {
    fn drop(&mut self) {
        RETIREMENT_DEADLINE.with(|slot| slot.set(self.0));
    }
}

fn with_retirement_deadline<T>(
    end: Instant,
    operation: impl FnOnce(Instant) -> PortResult<T>,
) -> PortResult<T> {
    let previous = RETIREMENT_DEADLINE.with(Cell::get);
    let effective = previous.map_or(end, |outer| outer.min(end));
    if Instant::now() >= effective {
        return Err(deadline_error());
    }
    let _scope = RetirementDeadlineScope(previous);
    RETIREMENT_DEADLINE.with(|slot| slot.set(Some(effective)));
    operation(effective).and_then(|value| {
        retirement_tick()?;
        Ok(value)
    })
}

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid control retirement capability".into())
}
fn changed() -> PortError {
    PortError::GenerationMismatch("control retirement binding changed".into())
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("private control retirement state is invalid".into())
}
fn retired() -> PortError {
    PortError::SchemaIncompatible("private control state is retired".into())
}
fn storage<E>(_: E) -> PortError {
    PortError::Backend("private control retirement storage is unavailable".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            PortError::WriterBusy("control retirement verification is busy".into())
        }
        Some(rusqlite::ErrorCode::OperationInterrupted) => deadline_error(),
        _ => corrupt(),
    }
}

/// Read-only retirement admission, including when control.db no longer exists.
/// A missing root remains NotFound without creating directories or lock files.
pub fn validate_retirement(root: &Path) -> PortResult<()> {
    retirement_tick()?;
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PortError::NotFound("control state not found".into()));
        }
        Err(error) => return Err(storage(error)),
        Ok(_) => {}
    }
    validate_prefix(root)?;
    let identity = RootIdentity::read(root)?;
    for marker in [RETIREMENT_MARKER, RETIREMENT_PENDING_MARKER] {
        retirement_tick()?;
        match fs::symlink_metadata(root.join(marker)) {
            Ok(_) => return Err(retired()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage(error)),
        }
    }
    validate_prefix(root)?;
    if RootIdentity::read(root)? != identity {
        return Err(changed());
    }
    Ok(())
}

/// Acquired before any normal control file open and retained until SQLite
/// closes. Put this field after the connection in the owning struct.
#[must_use = "the shared control-handle lease must outlive the SQLite connection"]
pub struct ControlHandleLease {
    guard: SharedGuard,
}

impl ControlHandleLease {
    /// One nonblocking acquisition; missing roots are never created. Pending or
    /// completed retirement refuses admission before inspecting control.db.
    pub fn try_acquire(root: &Path) -> PortResult<Self> {
        validate_retirement(root)?;
        match fs::symlink_metadata(SqliteControlStore::path(root)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PortError::NotFound("control state not found".into()));
            }
            Err(error) => return Err(storage(error)),
        }
        Self::try_acquire_for_create(root)
    }

    /// Explicit setup only: the root already exists, but control.db need not.
    /// Retirement remains fail-closed and no directory or database is created.
    pub fn try_acquire_for_create(root: &Path) -> PortResult<Self> {
        validate_retirement(root)?;
        validate_private_directory(root)?;
        let lease = Self {
            guard: SharedGuard::try_acquire(root, LockKind::ControlHandles)?,
        };
        lease.validate_admission(root)?;
        Ok(lease)
    }

    /// Recheck after connection open and at each normal store admission.
    pub fn validate_admission(&self, root: &Path) -> PortResult<()> {
        validate_private_directory(root)?;
        self.guard.validate_current(root)?;
        for marker in [RETIREMENT_MARKER, RETIREMENT_PENDING_MARKER] {
            // Existence, including a final symlink/reparse/directory, is enough
            // to deny. This check never opens or follows the marker target.
            if self.guard.child_exists(marker)? {
                return Err(retired());
            }
        }
        self.guard.validate_current(root)
    }

    pub fn root_identity(&self) -> RootIdentity {
        self.guard.root_identity()
    }

    pub(crate) fn publish_child_no_replace(
        &self,
        pending: &str,
        final_name: &str,
    ) -> PortResult<()> {
        self.guard.publish_child_no_replace(pending, final_name)
    }
}

impl fmt::Debug for ControlHandleLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlHandleLease([private])")
    }
}

/// Explicit borrowed proof of every other cooperating owner being drained.
/// PolicyOwner is acquired last by the caller, after waiting is finished.
#[derive(Clone, Copy)]
pub struct RetirementDrainGuards<'a> {
    pub policy_owner: &'a ExclusiveGuard,
    pub emission: &'a ExclusiveGuard,
    pub catalog_handles: &'a ExclusiveGuard,
    pub background: &'a ExclusiveGuard,
    pub supervisor: &'a ExclusiveGuard,
    pub purge: &'a ExclusiveGuard,
}

impl RetirementDrainGuards<'_> {
    fn validate(&self, root: &Path, identity: RootIdentity) -> PortResult<()> {
        let required = [
            (self.policy_owner, LockKind::PolicyOwner),
            (self.emission, LockKind::PolicyEmission),
            (self.catalog_handles, LockKind::CatalogHandles),
            (self.background, LockKind::Background),
            (self.supervisor, LockKind::Supervisor),
            (
                self.purge,
                LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY)?),
            ),
        ];
        for (guard, kind) in required {
            retirement_tick()?;
            if guard.kind() != &kind || guard.root_identity() != identity {
                return Err(invalid());
            }
            guard.validate_current(root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    control_root_id: String,
    prefix_root_id: String,
    installation_id: String,
    catalog_incarnation: String,
    operation_id: String,
    control_seq: i64,
    policy_epoch: i64,
}

impl Marker {
    fn validate(&self) -> PortResult<()> {
        retirement_tick()?;
        if self.schema != MARKER_SCHEMA {
            return Err(corrupt());
        }
        for value in [
            &self.control_root_id,
            &self.prefix_root_id,
            &self.installation_id,
            &self.catalog_incarnation,
            &self.operation_id,
        ] {
            retirement_tick()?;
            ControlId::parse(value).map_err(|_| corrupt())?;
        }
        ControlSeq::new(self.control_seq).map_err(|_| corrupt())?;
        PolicyEpoch::new(self.policy_epoch).map_err(|_| corrupt())?;
        retirement_tick()
    }
}

/// Owned snapshot of a real durable Uninstalling fence, held under the actual
/// immutable installation's OS lock. This does not borrow a control connection.
#[derive(Clone)]
pub struct RetirementIntent<'a> {
    root: PathBuf,
    root_identity: RootIdentity,
    prefix: PathBuf,
    prefix_identity: RootIdentity,
    installation_guard: &'a ExclusiveGuard,
    marker: Marker,
}

impl<'a> RetirementIntent<'a> {
    /// Runtime callers must pass their original uninstall deadline. Nested
    /// retirement/control scopes can shorten it; none starts a fresh budget.
    pub fn bind_with_deadline(
        control: &SqliteControlStore,
        catalog: &Path,
        prefix: &Path,
        installation_guard: &'a ExclusiveGuard,
        operation: &ControlId,
        end: Instant,
    ) -> PortResult<Self> {
        with_retirement_deadline(end, |effective| {
            control.with_runtime_deadline(effective, || {
                Self::bind(control, catalog, prefix, installation_guard, operation)
            })
        })
    }

    pub fn refresh_with_deadline(
        &self,
        control: &SqliteControlStore,
        policy_owner: &ExclusiveGuard,
        end: Instant,
    ) -> PortResult<Self> {
        with_retirement_deadline(end, |effective| {
            control.with_runtime_deadline(effective, || self.refresh(control, policy_owner))
        })
    }

    pub fn try_acquire_with_deadline(
        &self,
        drains: RetirementDrainGuards<'a>,
        end: Instant,
    ) -> PortResult<ControlRetirement<'a>> {
        with_retirement_deadline(end, |_| self.try_acquire(drains))
    }

    /// Verify the real control fence and catalog identity, without creating or
    /// migrating either database. Invoke before closing the caller's handles.
    pub fn bind(
        control: &SqliteControlStore,
        catalog: &Path,
        prefix: &Path,
        installation_guard: &'a ExclusiveGuard,
        operation: &ControlId,
    ) -> PortResult<Self> {
        retirement_tick()?;
        control.validate_live_root()?;
        validate_prefix(prefix)?;
        let installation = control.bind_installation(prefix, installation_guard)?;
        installation.validate(control)?;
        let status = control.status()?;
        if status.policy.maintenance.state != MaintenanceState::Uninstalling
            || status.policy.maintenance.owner.as_ref() != Some(operation)
        {
            return Err(invalid());
        }
        let root = control.private_root();
        let root_identity = RootIdentity::read(root)?;
        let catalog_handles = SharedGuard::try_acquire(root, LockKind::CatalogHandles)?;
        control.validate_catalog_file(catalog)?;
        let pinned = control.open_private_read(catalog)?;
        let identity = with_read_only(catalog, |conn| {
            // Reject oversized identity text before the shared identity decoder
            // allocates it. This check grants no schema/installation authority.
            let mut stmt = conn.prepare("SELECT installation_id,catalog_incarnation FROM catalog_meta WHERE singleton=1").map_err(sql)?;
            let mut rows = stmt.query([]).map_err(sql)?;
            let row = rows.next().map_err(sql)?.ok_or_else(corrupt)?;
            retirement_tick()?;
            required_text(row, 0)?;
            required_text(row, 1)?;
            validate_identity(conn, &status.policy.installation_id)
        })?;
        control.validate_private_read(catalog, &pinned)?;
        if status.catalog_incarnation.as_ref() != Some(&identity.incarnation) {
            return Err(changed());
        }
        retirement_tick()?;
        drop(pinned);
        drop(catalog_handles);
        let prefix_identity = RootIdentity::read(prefix)?;
        let intent = Self {
            root: root.to_path_buf(),
            root_identity,
            prefix: prefix.to_path_buf(),
            prefix_identity,
            installation_guard,
            marker: Marker {
                schema: MARKER_SCHEMA.into(),
                control_root_id: root_identity.control_id().as_str().into(),
                prefix_root_id: prefix_identity.control_id().as_str().into(),
                installation_id: identity.installation.as_str().into(),
                catalog_incarnation: identity.incarnation.as_str().into(),
                operation_id: operation.as_str().into(),
                control_seq: status.policy.control_seq.get(),
                policy_epoch: status.policy.policy_epoch.get(),
            },
        };
        intent.validate_binding()?;
        retirement_tick()?;
        if control.status()? != status {
            return Err(changed());
        }
        Ok(intent)
    }

    /// Refresh only control counters after owned cleanup under the same real
    /// installation lock. The catalog identity was verified when this intent
    /// was captured; no recovery/update can replace it while that lock lives.
    /// Require the final purge state before the caller closes its connection.
    pub fn refresh(
        &self,
        control: &SqliteControlStore,
        policy_owner: &ExclusiveGuard,
    ) -> PortResult<Self> {
        self.validate_binding()?;
        control.validate_live_root()?;
        if !control.matches_root(self.root_identity)
            || policy_owner.kind() != &LockKind::PolicyOwner
            || policy_owner.root_identity() != self.root_identity
        {
            return Err(invalid());
        }
        policy_owner.validate_current(&self.root)?;
        let installation = control.bind_installation(&self.prefix, self.installation_guard)?;
        installation.validate(control)?;
        let status = control.status()?;
        if status.policy.installation_id.as_str() != self.marker.installation_id
            || status.catalog_incarnation.as_ref().map(ControlId::as_str)
                != Some(self.marker.catalog_incarnation.as_str())
            || status.policy.maintenance.state != MaintenanceState::Uninstalling
            || status
                .policy
                .maintenance
                .owner
                .as_ref()
                .map(ControlId::as_str)
                != Some(self.marker.operation_id.as_str())
            || control
                .purge_jobs()?
                .iter()
                .any(|job| job.state != PurgeState::Complete)
        {
            return Err(changed());
        }
        let mut refreshed = self.clone();
        refreshed.marker.control_seq = status.policy.control_seq.get();
        refreshed.marker.policy_epoch = status.policy.policy_epoch.get();
        refreshed.validate_binding()?;
        retirement_tick()?;
        if control.status()? != status {
            return Err(changed());
        }
        Ok(refreshed)
    }

    /// No waiting or lock takeover. Close all normal control handles first.
    /// A busy result is pending cleanup, never proof that Unix readers stopped.
    pub fn try_acquire(
        &self,
        drains: RetirementDrainGuards<'a>,
    ) -> PortResult<ControlRetirement<'a>> {
        self.validate_binding()?;
        drains.validate(&self.root, self.root_identity)?;
        let handles = ExclusiveGuard::try_acquire(&self.root, LockKind::ControlHandles)?;
        let retirement = ControlRetirement {
            intent: self.clone(),
            drains,
            handles,
        };
        retirement.validate_live_control()?;
        Ok(retirement)
    }

    fn validate_binding(&self) -> PortResult<()> {
        retirement_tick()?;
        self.marker.validate()?;
        validate_private_directory(&self.root)?;
        validate_prefix(&self.prefix)?;
        if RootIdentity::read(&self.root)? != self.root_identity
            || self.marker.control_root_id != self.root_identity.control_id().as_str()
            || RootIdentity::read(&self.prefix)? != self.prefix_identity
            || self.marker.prefix_root_id != self.prefix_identity.control_id().as_str()
            || self.installation_guard.kind()
                != &LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY)?)
            || self.installation_guard.root_identity() != self.prefix_identity
        {
            return Err(changed());
        }
        self.installation_guard.validate_current(&self.prefix)?;
        retirement_tick()
    }
}

impl fmt::Debug for RetirementIntent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetirementIntent([private])")
    }
}

/// Exact expected private receipt values. Matching strings alone do not grant
/// authority: resume additionally requires the durable marker and real locks.
pub struct RetirementBinding<'a> {
    pub installation: &'a ControlId,
    pub catalog_incarnation: &'a ControlId,
    pub operation: &'a ControlId,
}

/// Only known control siblings are removable; marker/lock names have no variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetiredControlFile {
    Database,
    Wal,
    SharedMemory,
}
impl RetiredControlFile {
    fn name(self) -> &'static str {
        match self {
            Self::Database => "control.db",
            Self::Wal => "control.db-wal",
            Self::SharedMemory => "control.db-shm",
        }
    }
}

/// Terminal helper capability. All borrowed drain guards and the owned
/// exclusive ControlHandles guard must remain alive through file cleanup.
#[must_use = "terminal control drain is proven only while this capability is held"]
pub struct ControlRetirement<'a> {
    intent: RetirementIntent<'a>,
    drains: RetirementDrainGuards<'a>,
    handles: ExclusiveGuard,
}

impl<'a> ControlRetirement<'a> {
    /// Resume an already owned marker under the original cleanup deadline.
    /// Deadline refusal leaves pending/published bytes and caller drains intact.
    pub fn try_resume_with_deadline(
        root: &Path,
        prefix: &Path,
        installation_guard: &'a ExclusiveGuard,
        expected: RetirementBinding<'_>,
        drains: RetirementDrainGuards<'a>,
        end: Instant,
    ) -> PortResult<Self> {
        with_retirement_deadline(end, |_| {
            Self::try_resume(root, prefix, installation_guard, expected, drains)
        })
    }

    pub fn publish_marker_with_deadline(&self, end: Instant) -> PortResult<()> {
        with_retirement_deadline(end, |_| self.publish_marker())
    }

    pub fn validate_marker_with_deadline(&self, end: Instant) -> PortResult<()> {
        with_retirement_deadline(end, |_| self.validate_marker())
    }

    pub fn remove_control_file_with_deadline(
        &self,
        file: RetiredControlFile,
        end: Instant,
    ) -> PortResult<bool> {
        with_retirement_deadline(end, |_| self.remove_control_file(file))
    }

    /// Resume only an exact complete retirement marker (published or pending).
    /// No control/catalog is created or required; no new retirement is initiated.
    /// Invalid/truncated markers remain untouched and keep normal admission shut.
    pub fn try_resume(
        root: &Path,
        prefix: &Path,
        installation_guard: &'a ExclusiveGuard,
        expected: RetirementBinding<'_>,
        drains: RetirementDrainGuards<'a>,
    ) -> PortResult<Self> {
        retirement_tick()?;
        validate_private_directory(root)?;
        validate_prefix(prefix)?;
        let root_identity = RootIdentity::read(root)?;
        let prefix_identity = RootIdentity::read(prefix)?;
        drains.validate(root, root_identity)?;
        if installation_guard.kind()
            != &LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY)?)
            || installation_guard.root_identity() != prefix_identity
        {
            return Err(invalid());
        }
        installation_guard.validate_current(prefix)?;
        let handles = ExclusiveGuard::try_acquire(root, LockKind::ControlHandles)?;
        let published = handles.child_exists(RETIREMENT_MARKER)?;
        if published && handles.child_exists(RETIREMENT_PENDING_MARKER)? {
            return Err(corrupt());
        }
        let marker_name = if published {
            RETIREMENT_MARKER
        } else {
            RETIREMENT_PENDING_MARKER
        };
        let marker = read_bound_marker(&handles, root, marker_name)?;
        if marker.control_root_id != root_identity.control_id().as_str()
            || marker.prefix_root_id != prefix_identity.control_id().as_str()
            || marker.installation_id != expected.installation.as_str()
            || marker.catalog_incarnation != expected.catalog_incarnation.as_str()
            || marker.operation_id != expected.operation.as_str()
        {
            return Err(changed());
        }
        let retirement = Self {
            intent: RetirementIntent {
                root: root.to_path_buf(),
                root_identity,
                prefix: prefix.to_path_buf(),
                prefix_identity,
                installation_guard,
                marker,
            },
            drains,
            handles,
        };
        if !published {
            retirement.validate_guards()?;
            // Bind complete pending bytes before finishing an interrupted
            // publication. Corrupt or conflicting markers are never replaced.
            retirement_tick()?;
            retirement.handles.sync_child(RETIREMENT_PENDING_MARKER)?;
            retirement_tick()?;
            retirement
                .handles
                .publish_child_no_replace(RETIREMENT_PENDING_MARKER, RETIREMENT_MARKER)?;
            retirement.handles.sync_directory()?;
        }
        retirement.validate_marker()?;
        Ok(retirement)
    }

    fn validate_guards(&self) -> PortResult<()> {
        retirement_tick()?;
        self.intent.validate_binding()?;
        self.drains
            .validate(&self.intent.root, self.intent.root_identity)?;
        if self.handles.kind() != &LockKind::ControlHandles
            || self.handles.root_identity() != self.intent.root_identity
        {
            return Err(invalid());
        }
        self.handles.validate_current(&self.intent.root)?;
        retirement_tick()
    }

    fn validate_live_control(&self) -> PortResult<()> {
        self.validate_guards()?;
        let path = SqliteControlStore::path(&self.intent.root);
        validate_private_owned_file(&path)?;
        let pinned = self.handles.open_child_read("control.db")?;
        with_read_only(&path, |conn| {
            let application: i64 = conn
                .query_row("PRAGMA application_id", [], |row| row.get(0))
                .map_err(sql)?;
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(sql)?;
            retirement_tick()?;
            if application != 0x41534331 || version != CONTROL_SCHEMA_VERSION {
                return Err(corrupt());
            }
            // Bound borrowed schema text before the shared exact validator
            // allocates/normalizes it. These caps grant no schema authority.
            validate_bounded_schema(conn)?;
            crate::control::validate_schema(conn)?;
            let mut stmt = conn.prepare(
                "SELECT installation_id,catalog_incarnation,control_seq,policy_epoch,maintenance_state,maintenance_owner FROM control_meta WHERE singleton=1 AND schema_version=?1",
            ).map_err(sql)?;
            let mut rows = stmt.query([CONTROL_SCHEMA_VERSION]).map_err(sql)?;
            let row = rows.next().map_err(sql)?.ok_or_else(corrupt)?;
            retirement_tick()?;
            let actual = (
                required_text(row, 0)?,
                bounded_text(row, 1)?,
                row.get::<_, i64>(2).map_err(sql)?,
                row.get::<_, i64>(3).map_err(sql)?,
                required_text(row, 4)?,
                bounded_text(row, 5)?,
            );
            retirement_tick()?;
            let pending: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM purge_jobs WHERE state!='complete')",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            retirement_tick()?;
            let m = &self.intent.marker;
            if actual.0 != m.installation_id
                || actual.1.as_deref() != Some(&m.catalog_incarnation)
                || actual.2 != m.control_seq
                || actual.3 != m.policy_epoch
                || actual.4 != "uninstalling"
                || actual.5.as_deref() != Some(&m.operation_id)
                || pending
            {
                return Err(changed());
            }
            Ok(())
        })?;
        retirement_tick()?;
        self.handles.validate_child("control.db", &pinned)?;
        validate_private_owned_file(&path)?;
        self.validate_guards()
    }

    /// First publication only. A previous marker is never silently overwritten.
    /// Reserve a fail-closed pending name, sync its bounded bytes, then atomically
    /// publish without replacement and durably sync the directory on Unix.
    pub fn publish_marker(&self) -> PortResult<()> {
        self.validate_live_control()?;
        if self.handles.child_exists(RETIREMENT_MARKER)?
            || self.handles.child_exists(RETIREMENT_PENDING_MARKER)?
        {
            return Err(retired());
        }
        retirement_tick()?;
        let bytes = serde_json::to_vec(&self.intent.marker).map_err(storage)?;
        retirement_tick()?;
        if bytes.len() as u64 > MAX_MARKER_BYTES {
            return Err(corrupt());
        }
        retirement_tick()?;
        let mut file = self.handles.create_child_new(RETIREMENT_PENDING_MARKER)?;
        // Keep the exclusive native creator through the write, then close it
        // before opening a second verification handle (Windows share_mode=0).
        self.validate_guards()?;
        file.write_all(&bytes).map_err(storage)?;
        retirement_tick()?;
        file.sync_all().map_err(storage)?;
        retirement_tick()?;
        drop(file);
        validate_private_owned_file(&self.intent.root.join(RETIREMENT_PENDING_MARKER))?;
        let verified = self.handles.open_child_read(RETIREMENT_PENDING_MARKER)?;
        self.handles
            .validate_child(RETIREMENT_PENDING_MARKER, &verified)?;
        drop(verified);
        self.handles.sync_directory()?;
        self.validate_live_control()?;
        retirement_tick()?;
        self.handles
            .publish_child_no_replace(RETIREMENT_PENDING_MARKER, RETIREMENT_MARKER)?;
        self.handles.sync_directory()?;
        self.validate_marker()
    }

    /// Recheck before each caller-owned terminal cleanup step. This validates
    /// only owned marker/lock paths; no source locator or PID is ever consulted.
    pub fn validate_marker(&self) -> PortResult<()> {
        self.validate_guards()?;
        let marker = self.read_marker(RETIREMENT_MARKER)?;
        if marker != self.intent.marker || self.handles.child_exists(RETIREMENT_PENDING_MARKER)? {
            return Err(changed());
        }
        self.validate_guards()
    }

    /// Remove one validated owned sibling only after durable retirement.
    /// False means a genuinely absent leaf. Never creates missing state or
    /// removes a marker/lock. The caller retains the original cleanup budget.
    pub fn remove_control_file(&self, file: RetiredControlFile) -> PortResult<bool> {
        self.validate_marker()?;
        let name = file.name();
        if !self.handles.child_exists(name)? {
            return Ok(false);
        }
        validate_private_owned_file(&self.intent.root.join(name))?;
        self.validate_guards()?;
        retirement_tick()?;
        let removed = self.handles.remove_child(name)?;
        retirement_tick()?;
        self.handles.sync_directory()?;
        self.validate_marker()?;
        Ok(removed)
    }

    fn read_marker(&self, name: &str) -> PortResult<Marker> {
        read_bound_marker(&self.handles, &self.intent.root, name)
    }
}

impl fmt::Debug for ControlRetirement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlRetirement([private])")
    }
}

struct RawSqlProgress<'a> {
    conn: &'a Connection,
    armed: bool,
}
impl RawSqlProgress<'_> {
    fn restore(&mut self) -> PortResult<()> {
        if self.armed {
            self.armed = false;
            self.conn
                .progress_handler(0, None::<fn() -> bool>)
                .map_err(sql)?;
        }
        Ok(())
    }
}
impl Drop for RawSqlProgress<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn with_raw_sql<T>(conn: &Connection, operation: impl FnOnce() -> PortResult<T>) -> PortResult<T> {
    retirement_tick()?;
    conn.busy_timeout(Duration::ZERO).map_err(sql)?;
    let mut reset = RawSqlProgress { conn, armed: true };
    conn.progress_handler(1000, Some(|| retirement_tick().is_err()))
        .map_err(sql)?;
    let result = operation().and_then(|value| {
        retirement_tick()?;
        Ok(value)
    });
    let restored = reset.restore();
    match (result, restored) {
        (Err(error), _) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn with_read_only<T>(
    path: &Path,
    operation: impl FnOnce(&Connection) -> PortResult<T>,
) -> PortResult<T> {
    retirement_tick()?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    with_raw_sql(&conn, || {
        conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
            .map_err(sql)?;
        retirement_tick()?;
        operation(&conn)
    })
}

fn validate_bounded_schema(conn: &Connection) -> PortResult<()> {
    let mut stmt = conn
        .prepare("SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' LIMIT 65")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql)? {
        retirement_tick()?;
        count += 1;
        if count > 64 {
            return Err(corrupt());
        }
        for (column, limit) in [(0, 128), (1, 4096)] {
            match row.get_ref(column).map_err(sql)? {
                ValueRef::Text(bytes) if bytes.len() <= limit => {}
                _ => return Err(corrupt()),
            }
        }
    }
    retirement_tick()
}

fn bounded_text(row: &Row<'_>, column: usize) -> PortResult<Option<String>> {
    retirement_tick()?;
    match row.get_ref(column).map_err(sql)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) if bytes.len() <= 128 => {
            let text = std::str::from_utf8(bytes).map_err(|_| corrupt())?;
            Ok(Some(text.into()))
        }
        _ => Err(corrupt()),
    }
}
fn required_text(row: &Row<'_>, column: usize) -> PortResult<String> {
    bounded_text(row, column)?.ok_or_else(corrupt)
}

fn read_bound_marker(handles: &ExclusiveGuard, root: &Path, name: &str) -> PortResult<Marker> {
    retirement_tick()?;
    let path = root.join(name);
    validate_private_owned_file(&path)?;
    let mut file = handles.open_child_read(name)?;
    let size = file.metadata().map_err(storage)?.len();
    if size == 0 || size > MAX_MARKER_BYTES {
        return Err(corrupt());
    }
    retirement_tick()?;
    let mut bytes = Vec::with_capacity(size as usize);
    (&mut file)
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    retirement_tick()?;
    if bytes.len() as u64 != size || bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(corrupt());
    }
    handles.validate_child(name, &file)?;
    validate_private_owned_file(&path)?;
    retirement_tick()?;
    let marker: Marker = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    marker.validate()?;
    retirement_tick()?;
    Ok(marker)
}

fn validate_prefix(prefix: &Path) -> PortResult<()> {
    retirement_tick()?;
    if !prefix.is_absolute() {
        return Err(invalid());
    }
    for ancestor in prefix.ancestors() {
        retirement_tick()?;
        let metadata = fs::symlink_metadata(ancestor).map_err(storage)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod retirement_deadline_tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let control = SqliteControlStore::create(
            &root,
            &ControlId::parse("synthetic-retirement-sql").unwrap(),
            agent_session_grep_ports::control::DesiredUpdates::Stopped,
        )
        .unwrap();
        drop(control);
        (temp, SqliteControlStore::path(&root))
    }

    #[test]
    fn raw_sql_progress_interrupts_actual_long_query_and_recovers() {
        let (_temp, path) = fixture();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let original = std::fs::read(&path).unwrap();
        let started = Instant::now();
        let mut interrupted = false;
        let result = with_retirement_deadline(started + Duration::from_millis(20), |_| {
            with_raw_sql(&conn, || {
                let query: rusqlite::Result<i64> = conn.query_row(
                    "WITH RECURSIVE n(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM n WHERE value<1000000000) SELECT sum(value) FROM n",
                    [], |row| row.get(0),
                );
                interrupted = matches!(&query, Err(error) if error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted));
                query.map_err(sql)
            })
        });
        assert!(
            interrupted,
            "actual SQLite progress callback must interrupt the statement"
        );
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(RETIREMENT_DEADLINE.with(Cell::get).is_none());
        let sum: i64 = conn.query_row(
            "WITH RECURSIVE n(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM n WHERE value<10000) SELECT sum(value) FROM n",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(sum, 50_005_000);
        assert_eq!(
            conn.query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(
            with_retirement_deadline(Instant::now() + Duration::from_secs(1), |_| {
                with_read_only(&path, |connection| {
                    connection
                        .query_row("SELECT count(*) FROM control_meta", [], |row| {
                            row.get::<_, i64>(0)
                        })
                        .map_err(sql)
                })
            })
            .is_ok()
        );
    }

    #[test]
    fn nested_deadline_cannot_extend_outer_and_unwind_restores_sql_handler() {
        let (_temp, path) = fixture();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let outer = Instant::now() + Duration::from_secs(1);
        with_retirement_deadline(outer, |effective| {
            assert_eq!(effective, outer);
            with_retirement_deadline(outer + Duration::from_secs(10), |inner| {
                assert_eq!(inner, outer);
                Ok(())
            })?;
            let panic = catch_unwind(AssertUnwindSafe(|| {
                let _: PortResult<()> = with_retirement_deadline(outer, |_| {
                    with_raw_sql(&conn, || panic!("synthetic retirement unwind"))
                });
            }));
            assert!(panic.is_err());
            assert_eq!(RETIREMENT_DEADLINE.with(Cell::get), Some(outer));
            Ok(())
        })
        .unwrap();
        assert!(RETIREMENT_DEADLINE.with(Cell::get).is_none());
        assert_eq!(
            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn oversized_schema_text_refuses_before_shared_schema_decoder() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE oversized(value TEXT DEFAULT '{}')",
            "x".repeat(4096)
        ))
        .unwrap();
        let result = with_retirement_deadline(Instant::now() + Duration::from_secs(1), |_| {
            with_raw_sql(&conn, || validate_bounded_schema(&conn))
        });
        assert!(matches!(result, Err(PortError::SchemaIncompatible(_))));
        assert!(RETIREMENT_DEADLINE.with(Cell::get).is_none());
        assert_eq!(
            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn raw_sql_row_decode_checks_clock_before_allocating_oversized_identity() {
        use rusqlite::functions::FunctionFlags;
        let conn = Connection::open_in_memory().unwrap();
        conn.create_scalar_function("expire_row", 0, FunctionFlags::SQLITE_UTF8, |_| {
            RETIREMENT_DEADLINE.with(|slot| slot.set(Some(Instant::now())));
            Ok("x".repeat(1024))
        })
        .unwrap();
        let result = with_retirement_deadline(Instant::now() + Duration::from_secs(1), |_| {
            with_raw_sql(&conn, || {
                let mut stmt = conn.prepare("SELECT expire_row()").map_err(sql)?;
                let mut rows = stmt.query([]).map_err(sql)?;
                bounded_text(rows.next().map_err(sql)?.ok_or_else(corrupt)?, 0)
            })
        });
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
        assert!(RETIREMENT_DEADLINE.with(Cell::get).is_none());
        assert_eq!(
            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
