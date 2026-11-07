//! Consuming connection boundary for the private reinstall continuation.
//! Unconfirmed close retains the ENTIRE owned bundle until process exit.
//! Neither field drop order nor an empty connection slot proves SQLite closed.
use super::*;
use crate::WriterLease;
use crate::managed_maintenance::CatalogIdentity;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

/// Actual owned capabilities, moved from the drained reinstall coordinator.
/// Serialized identities and the opaque retention payload cannot replace them.
pub struct ReinstallOwnedGuards {
    pub prefix: ExclusiveGuard,
    pub policy_owner: ExclusiveGuard,
    pub emission: ExclusiveGuard,
    pub supervisor: ExclusiveGuard,
    pub background: ExclusiveGuard,
    pub purge: ExclusiveGuard,
    pub history_readers: ExclusiveGuard,
    pub catalog_handles: ExclusiveGuard,
    pub writer: WriterLease,
}

impl ReinstallOwnedGuards {
    fn validate(&self, root: &Path, prefix: &Path) -> PortResult<()> {
        let identity = RootIdentity::read(root)?;
        for (guard, kind) in [
            (&self.policy_owner, LockKind::PolicyOwner),
            (&self.emission, LockKind::PolicyEmission),
            (&self.supervisor, LockKind::Supervisor),
            (&self.background, LockKind::Background),
            (
                &self.purge,
                LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY)?),
            ),
            (&self.history_readers, LockKind::HistoryReaders),
            (&self.catalog_handles, LockKind::CatalogHandles),
        ] {
            runtime_tick()?;
            if guard.kind() != &kind || guard.root_identity() != identity {
                return Err(invalid());
            }
            guard.validate_current(root)?;
        }
        if self.prefix.kind()
            != &LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY)?)
            || self.prefix.root_identity() != RootIdentity::read(prefix)?
        {
            return Err(invalid());
        }
        self.prefix.validate_current(prefix)?;
        self.writer.validate_current(root)
    }
}

/// Original pins accompanying the fixed preparation's byte commitments.
pub struct ReinstallOwnedPins {
    pub control_main: fs::File,
    pub control_wal: Option<fs::File>,
    pub catalog_main: fs::File,
    pub catalog_wal: Option<fs::File>,
    pub prefix_binding: fs::File,
}

/// Comparison inputs plus actual owned resources. `retained` is never inspected
/// or invoked: the CLI moves its real exit guards, package/image and root pins
/// into it. `'static` forbids borrowing those resources from an outer scope.
/// This input is not proof of a published preparation or permission to adopt.
pub struct ReinstallOwnedInput<R: 'static> {
    pub root: PathBuf,
    pub prefix: PathBuf,
    pub catalog: PathBuf,
    pub expected: ControlStatus,
    pub files: ReinstallFiles,
    pub prefix_binding: ReinstallFileBinding,
    pub guards: ReinstallOwnedGuards,
    pub pins: ReinstallOwnedPins,
    pub retained: R,
}

/// Read/write control admission is deliberately separate from catalog admission.
/// There is no raw connection, arbitrary SQL or callback interface.
pub struct ReinstallControlOwner<R: 'static> {
    owned: OwnedBundle<R>,
}

/// The catalog remains query-only even though SQLite opened it READ_WRITE.
/// Both real connections and the complete exclusion remain inside this owner.
pub struct ReinstallQueryOnlyCatalog<R: 'static> {
    owned: OwnedBundle<R>,
    identity: CatalogIdentity,
}

/// Only explicit close success can construct this return value. Resources
/// remain held until the caller consumes or drops this value.
pub struct ReinstallClosed<R: 'static> {
    owned: OwnedBundle<R>,
}

/// Successful close returns the same resources, including the already held
/// ControlHandles lease. Returning them is not a new acquisition or an ACK.
pub struct ReinstallClosedResources<R: 'static> {
    pub input: ReinstallOwnedInput<R>,
    pub control_handles: ControlHandleLease,
    // Retain also the rendezvous and any SQLite-created sibling pins. These
    // are physical retention, not additional capability-granting interfaces.
    _observed: ClosedPins,
}

/// A terminal request error. Discarding this error retains any unconfirmed
/// connection and EVERY resource to process exit; it cannot release a subset.
/// The caller must take its existing CLI/owned-child failure-exit path.
pub struct ReinstallConnectionError<R: 'static> {
    owned: OwnedBundle<R>,
    error: PortError,
}

impl<R: 'static> std::fmt::Debug for ReinstallConnectionError<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReinstallConnectionError")
            .field("close_attempted", &self.close_attempted())
            .field("requires_process_exit", &self.requires_process_exit())
            .finish_non_exhaustive()
    }
}

impl<R: 'static> ReinstallConnectionError<R> {
    pub fn error(&self) -> &PortError {
        &self.error
    }

    pub fn close_attempted(&self) -> bool {
        self.owned
            .bundle()
            .connections()
            .any(|slot| slot.close_attempted)
    }

    pub fn requires_process_exit(&self) -> bool {
        self.owned.bundle().unconfirmed()
    }

    pub fn sqlite_close_code(&self) -> Option<i32> {
        self.owned
            .bundle()
            .connections()
            .find_map(|slot| slot.close_code)
    }
}

struct ConnectionSlot {
    conn: Option<Connection>,
    close_confirmed: bool,
    close_attempted: bool,
    close_code: Option<i32>,
}

impl ConnectionSlot {
    fn new(conn: Connection) -> Self {
        Self {
            conn: Some(conn),
            close_confirmed: false,
            close_attempted: false,
            close_code: None,
        }
    }

    fn get(&self) -> PortResult<&Connection> {
        self.conn.as_ref().ok_or_else(invalid)
    }

    fn close_once(&mut self) -> PortResult<()> {
        runtime_tick()?;
        if self.close_attempted || self.close_confirmed {
            return Err(invalid());
        }
        self.close_attempted = true;
        let conn = self.conn.take().ok_or_else(invalid)?;
        #[cfg(test)]
        tests::after_take_for_close();
        match conn.close() {
            Ok(()) => {
                // This assignment has exactly one source: actual close Ok.
                self.close_confirmed = true;
                Ok(())
            }
            Err((returned, error)) => {
                // Restore FIRST, before classification, allocation or return.
                self.conn = Some(returned);
                self.close_code = error.sqlite_error().map(|error| error.extended_code);
                Err(sql_error(error))
            }
        }
    }
}

struct ObservedWal {
    file: fs::File,
    binding: ReinstallFileBinding,
}

struct ObservedShm {
    file: fs::File,
    identity: (u64, u64),
}

struct ClosedPins {
    _rendezvous: Option<ReinstallHandlesPin>,
    _control_wal: Option<ObservedWal>,
    _catalog_wal: Option<ObservedWal>,
    _control_shm: Option<ObservedShm>,
    _catalog_shm: Option<ObservedShm>,
}

struct Bundle<R: 'static> {
    input: ReinstallOwnedInput<R>,
    end: Instant,
    control: Option<ConnectionSlot>,
    catalog: Option<ConnectionSlot>,
    handle_lease: Option<ControlHandleLease>,
    rendezvous: Option<ReinstallHandlesPin>,
    control_wal: Option<ObservedWal>,
    catalog_wal: Option<ObservedWal>,
    control_shm: Option<ObservedShm>,
    catalog_shm: Option<ObservedShm>,
    #[cfg(test)]
    outstanding: Option<tests::OutstandingStatement>,
}

impl<R: 'static> Bundle<R> {
    fn new(input: ReinstallOwnedInput<R>, end: Instant) -> Self {
        Self {
            input,
            end: SqliteControlStore::effective_runtime_deadline(end),
            control: None,
            catalog: None,
            handle_lease: None,
            rendezvous: None,
            control_wal: None,
            catalog_wal: None,
            control_shm: None,
            catalog_shm: None,
            #[cfg(test)]
            outstanding: None,
        }
    }

    fn connections(&self) -> impl Iterator<Item = &ConnectionSlot> {
        self.control.iter().chain(self.catalog.iter())
    }

    fn unconfirmed(&self) -> bool {
        self.connections().any(|slot| !slot.close_confirmed)
    }

    fn tick(&self) -> PortResult<()> {
        runtime_tick()?;
        if Instant::now() >= self.end {
            return Err(PortError::WriterBusy(
                "control runtime deadline reached".into(),
            ));
        }
        Ok(())
    }

    fn validate_inputs(&mut self, allow_empty_wal: bool) -> PortResult<()> {
        self.tick()?;
        let input = &self.input;
        input.files.validate()?;
        input.expected.policy.maintenance.validate()?;
        if !input.root.is_absolute()
            || !input.prefix.is_absolute()
            || input.catalog.parent() != Some(input.root.as_path())
            || input.expected.catalog_incarnation.is_none()
            || input.expected.policy.maintenance.owner.is_none()
            || !matches!(
                (
                    input.expected.policy.maintenance.state,
                    input.expected.policy.maintenance.phase
                ),
                (
                    MaintenanceState::Uninstalling,
                    Some(MaintenancePhase::Quiescing)
                ) | (
                    MaintenanceState::Recovering,
                    Some(MaintenancePhase::Reconciling)
                )
            )
            || input.prefix_binding.size > MAX_PREFIX_BINDING_BYTES
        {
            return Err(invalid());
        }
        private_directory(&input.root, false)?;
        reject_links(&input.prefix)?;
        crate::managed_store::validate_catalog_path(&input.catalog)?;
        input.guards.validate(&input.root, &input.prefix)?;
        if let Some(lease) = &self.handle_lease {
            lease.validate_admission(&input.root)?;
        }
        if let Some(pin) = &self.rendezvous {
            pin.validate()?;
        }
        self.validate_files(allow_empty_wal)?;
        self.tick()
    }

    fn validate_files(&mut self, allow_empty_wal: bool) -> PortResult<()> {
        let input = &mut self.input;
        let control_path = SqliteControlStore::path(&input.root);
        let prefix_path = input.root.join(PREFIX_BINDING_FILE);
        for (path, pin, binding) in [
            (
                &control_path,
                &mut input.pins.control_main,
                &input.files.control_main,
            ),
            (
                &input.catalog,
                &mut input.pins.catalog_main,
                &input.files.catalog_main,
            ),
            (
                &prefix_path,
                &mut input.pins.prefix_binding,
                &input.prefix_binding,
            ),
        ] {
            verify_reinstall_file_bytes(path, pin, binding, self.end)?;
        }
        verify_wal(
            &control_path,
            &mut input.pins.control_wal,
            input.files.control_wal.as_ref(),
            &mut self.control_wal,
            allow_empty_wal,
            self.end,
        )?;
        verify_wal(
            &input.catalog,
            &mut input.pins.catalog_wal,
            input.files.catalog_wal.as_ref(),
            &mut self.catalog_wal,
            allow_empty_wal,
            self.end,
        )?;
        verify_shm(
            &control_path,
            input.files.control_shm.as_ref(),
            &mut self.control_shm,
        )?;
        verify_shm(
            &input.catalog,
            input.files.catalog_shm.as_ref(),
            &mut self.catalog_shm,
        )?;
        for main in [&control_path, &input.catalog] {
            verify_sidecars(main)?;
            match fs::symlink_metadata(sidecar(main, "-journal")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
                Ok(_) => return Err(corrupt()),
            }
        }
        Ok(())
    }

    fn validate_receipt(&mut self, status: &ControlStatus) -> PortResult<()> {
        let input = &mut self.input;
        let pin = &mut input.pins.prefix_binding;
        pin.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut bytes = Vec::new();
        pin.take(MAX_PREFIX_BINDING_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 != input.prefix_binding.size {
            return Err(conflict());
        }
        let receipt: InstallationPrefixBinding =
            serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        if receipt.schema != "asg.installation-prefix/v1"
            || receipt.installation_id != status.policy.installation_id.as_str()
            || receipt.control_root_id
                != input
                    .guards
                    .policy_owner
                    .root_identity()
                    .control_id()
                    .as_str()
            || receipt.prefix_root_id != input.guards.prefix.root_identity().control_id().as_str()
        {
            return Err(invalid());
        }
        input.guards.prefix.validate_current(&input.prefix)?;
        self.tick()
    }

    fn read_control(&mut self) -> PortResult<ControlStatus> {
        self.validate_inputs(true)?;
        self.handle_lease
            .as_ref()
            .ok_or_else(invalid)?
            .validate_admission(&self.input.root)?;
        if self.rendezvous.is_none() {
            self.rendezvous = Some(ReinstallHandlesPin::open(&self.input.root)?);
        }
        self.rendezvous.as_ref().ok_or_else(invalid)?.validate()?;
        let path = SqliteControlStore::path(&self.input.root);
        let conn = self.control.as_ref().ok_or_else(invalid)?.get()?;
        require_close_policy(conn)?;
        verify_reinstall_connection(conn, &path, self.input.files.control_main.identity)?;
        let status = {
            let tx = conn.unchecked_transaction().map_err(sql_error)?;
            validate_schema(&tx)?;
            let version: i64 = tx
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(sql_error)?;
            let mode: String = tx
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .map_err(sql_error)?;
            if version != VERSION || mode != "wal" {
                return Err(corrupt());
            }
            validate_policy_admission_capacity(&tx)?;
            let status = load_status_core(&tx)?;
            if status != self.input.expected {
                return Err(conflict());
            }
            runtime_tick()?;
            tx.commit().map_err(sql_error)?;
            status
        };
        verify_reinstall_connection(conn, &path, self.input.files.control_main.identity)?;
        self.validate_receipt(&status)?;
        self.validate_files(true)?;
        self.rendezvous.as_ref().ok_or_else(invalid)?.validate()?;
        self.tick()?;
        Ok(status)
    }

    fn open_control(&mut self, writable: bool) -> PortResult<()> {
        self.validate_inputs(false)?;
        if self
            .control
            .as_ref()
            .is_some_and(|slot| !slot.close_confirmed)
        {
            return Err(invalid());
        }
        if self
            .catalog
            .as_ref()
            .is_some_and(|slot| slot.close_confirmed)
        {
            self.catalog = None;
        }
        if self.rendezvous.is_none() {
            self.rendezvous = Some(ReinstallHandlesPin::open(&self.input.root)?);
        }
        if self.handle_lease.is_none() {
            self.handle_lease = Some(admit_control_handle(&self.input.root, false)?);
        }
        self.rendezvous.as_ref().ok_or_else(invalid)?.validate()?;
        let path = SqliteControlStore::path(&self.input.root);
        let conn = raw_reinstall_connection(&path, writable)?;
        // No fallible call between successful open and owned containment.
        self.control = Some(ConnectionSlot::new(conn));
        #[cfg(test)]
        tests::after_containment(tests::OpenKind::Control);
        let conn = self.control.as_ref().ok_or_else(invalid)?.get()?;
        install_reinstall_close_policy(conn)?;
        verify_reinstall_connection(conn, &path, self.input.files.control_main.identity)?;
        configure_query_only(conn)?;
        self.read_control()?;
        if writable {
            self.control
                .as_ref()
                .ok_or_else(invalid)?
                .get()?
                .execute_batch("PRAGMA query_only=OFF;")
                .map_err(sql_error)?;
        }
        self.tick()
    }

    fn open_catalog(&mut self, writable: bool) -> PortResult<CatalogIdentity> {
        self.tick()?;
        if self
            .catalog
            .as_ref()
            .is_some_and(|slot| !slot.close_confirmed)
        {
            return Err(invalid());
        }
        self.validate_files(true)?;
        let conn = raw_reinstall_connection(&self.input.catalog, writable)?;
        self.catalog = Some(ConnectionSlot::new(conn));
        #[cfg(test)]
        tests::after_containment(if writable {
            tests::OpenKind::WritableCatalog
        } else {
            tests::OpenKind::CatalogProbe
        });
        let conn = self.catalog.as_ref().ok_or_else(invalid)?.get()?;
        install_reinstall_close_policy(conn)?;
        verify_reinstall_connection(
            conn,
            &self.input.catalog,
            self.input.files.catalog_main.identity,
        )?;
        configure_query_only(conn)?;
        let identity = crate::managed_maintenance::read_reinstall_catalog_identity(
            conn,
            &self.input.expected.policy.installation_id,
            self.input
                .expected
                .catalog_incarnation
                .as_ref()
                .ok_or_else(invalid)?,
            self.end,
        )?;
        verify_reinstall_connection(
            conn,
            &self.input.catalog,
            self.input.files.catalog_main.identity,
        )?;
        self.validate_files(true)?;
        self.tick()?;
        Ok(identity)
    }

    fn catalog_transition(&mut self, owner: &ControlId) -> PortResult<CatalogIdentity> {
        let status = self.read_control()?;
        if status.policy.maintenance.state != MaintenanceState::Recovering
            || status.policy.maintenance.phase != Some(MaintenancePhase::Reconciling)
            || status.policy.maintenance.owner.as_ref() != Some(owner)
        {
            return Err(invalid());
        }
        let before = self.open_catalog(false)?;
        self.tick()?;
        self.catalog.as_mut().ok_or_else(invalid)?.close_once()?;
        // The closed probe is replaced, never retried. All locks and pins remain
        // inside this same bundle across both opens.
        let after = self.open_catalog(true)?;
        if before != after || self.read_control()? != status {
            return Err(conflict());
        }
        Ok(after)
    }

    fn close_all(&mut self) -> PortResult<()> {
        self.read_control()?;
        if let Some(slot) = &self.catalog {
            let conn = slot.get()?;
            require_close_policy(conn)?;
            verify_reinstall_connection(
                conn,
                &self.input.catalog,
                self.input.files.catalog_main.identity,
            )?;
        }
        self.validate_files(true)?;
        self.tick()?;
        if let Some(slot) = &mut self.catalog {
            slot.close_once()?;
        }
        self.control.as_mut().ok_or_else(invalid)?.close_once()
    }
}

/// The box is allocated before opening SQLite. On any unconfirmed path its
/// allocation and all fields are deliberately retained to OS process teardown.
/// There is no global registry, background cleanup, Drop close or retry clock.
struct OwnedBundle<R: 'static> {
    value: Option<Box<Bundle<R>>>,
}

impl<R: 'static> OwnedBundle<R> {
    fn new(input: ReinstallOwnedInput<R>, end: Instant) -> Self {
        Self {
            value: Some(Box::new(Bundle::new(input, end))),
        }
    }

    fn bundle(&self) -> &Bundle<R> {
        self.value.as_deref().expect("reinstall owner is present")
    }

    fn bundle_mut(&mut self) -> &mut Bundle<R> {
        self.value
            .as_deref_mut()
            .expect("reinstall owner is present")
    }

    fn scoped<T>(
        &mut self,
        operation: impl FnOnce(&mut Bundle<R>) -> PortResult<T>,
    ) -> PortResult<T> {
        let end = SqliteControlStore::effective_runtime_deadline(self.bundle().end);
        self.bundle_mut().end = end;
        let scope = RuntimeDeadlineScope::enter(end)?;
        let mut scoped = ConnectionScope {
            bundle: self.bundle_mut(),
            scope: Some(scope),
        };
        scoped.configure()?;
        let result = operation(&mut *scoped.bundle);
        let restored = scoped.restore();
        match (result, restored) {
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn failed(self, error: PortError) -> Box<ReinstallConnectionError<R>> {
        Box::new(ReinstallConnectionError { owned: self, error })
    }
}

impl<R: 'static> Drop for OwnedBundle<R> {
    fn drop(&mut self) {
        if let Some(bundle) = self.value.take()
            && bundle.unconfirmed()
        {
            // R includes the CLI's actual exit/package/root resources. Leaking
            // only Connection would release exclusion and is forbidden.
            std::mem::forget(bundle);
        }
    }
}

struct ConnectionScope<'a, R: 'static> {
    bundle: &'a mut Bundle<R>,
    scope: Option<RuntimeDeadlineScope>,
}

impl<R: 'static> ConnectionScope<'_, R> {
    fn configure(&self) -> PortResult<()> {
        for slot in self.bundle.connections() {
            if let Some(conn) = &slot.conn {
                configure_runtime_deadline(conn)?;
            }
        }
        Ok(())
    }

    fn restore(&mut self) -> PortResult<()> {
        drop(self.scope.take());
        // After confirmed final close there are no SQL handlers to reset, so
        // success has no fallible post-close read/configuration or deadline test.
        self.configure()
    }
}

impl<R: 'static> Drop for ConnectionScope<'_, R> {
    fn drop(&mut self) {
        if self.scope.is_some() {
            let _ = self.restore();
        }
    }
}

impl<R: 'static> ReinstallControlOwner<R> {
    pub fn open_read_only(
        input: ReinstallOwnedInput<R>,
        end: Instant,
    ) -> Result<Self, Box<ReinstallConnectionError<R>>> {
        let mut owned = OwnedBundle::new(input, end);
        match owned.scoped(|bundle| bundle.open_control(false)) {
            Ok(()) => Ok(Self { owned }),
            Err(error) => Err(owned.failed(error)),
        }
    }

    pub fn read_bound_status(
        mut self,
    ) -> Result<(Self, ControlStatus), Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(Bundle::read_control) {
            Ok(status) => Ok((self, status)),
            Err(error) => Err(self.owned.failed(error)),
        }
    }

    pub fn open_query_only_catalog(
        mut self,
        owner: ControlId,
    ) -> Result<ReinstallQueryOnlyCatalog<R>, Box<ReinstallConnectionError<R>>> {
        match self
            .owned
            .scoped(|bundle| bundle.catalog_transition(&owner))
        {
            Ok(identity) => Ok(ReinstallQueryOnlyCatalog {
                owned: self.owned,
                identity,
            }),
            Err(error) => Err(self.owned.failed(error)),
        }
    }

    pub fn close(mut self) -> Result<ReinstallClosed<R>, Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(Bundle::close_all) {
            Ok(()) => Ok(ReinstallClosed { owned: self.owned }),
            Err(error) => Err(self.owned.failed(error)),
        }
    }
}

impl SqliteControlStore {
    /// Consume an existing transfer-policy store and the complete caller-owned
    /// resource set BEFORE checking anything fallible. No new lease is acquired.
    /// Ordinary store construction/Drop is unchanged by this private-use seam.
    pub fn into_reinstall_close_owner<R: 'static>(
        self,
        input: ReinstallOwnedInput<R>,
        end: Instant,
    ) -> ReinstallControlOwner<R> {
        let mut owned = OwnedBundle::new(input, end);
        let Self {
            conn, handle_lease, ..
        } = self;
        let bundle = owned.bundle_mut();
        bundle.control = Some(ConnectionSlot::new(conn.into_inner()));
        bundle.handle_lease = Some(handle_lease);
        ReinstallControlOwner { owned }
    }
}

impl<R: 'static> ReinstallQueryOnlyCatalog<R> {
    pub fn identity(&self) -> &CatalogIdentity {
        &self.identity
    }

    pub fn close(mut self) -> Result<ReinstallClosed<R>, Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(Bundle::close_all) {
            Ok(()) => Ok(ReinstallClosed { owned: self.owned }),
            Err(error) => Err(self.owned.failed(error)),
        }
    }
}

impl<R: 'static> ReinstallClosed<R> {
    /// The same retained ControlHandles lease crosses this boundary. No new
    /// end, lease acquisition or incomplete-close recovery is accepted here.
    pub fn reopen_writable(
        mut self,
    ) -> Result<ReinstallControlOwner<R>, Box<ReinstallConnectionError<R>>> {
        match self.owned.scoped(|bundle| bundle.open_control(true)) {
            Ok(()) => Ok(ReinstallControlOwner { owned: self.owned }),
            Err(error) => Err(self.owned.failed(error)),
        }
    }

    pub fn into_resources(mut self) -> ReinstallClosedResources<R> {
        let bundle = *self
            .owned
            .value
            .take()
            .expect("confirmed reinstall owner is present");
        ReinstallClosedResources {
            input: bundle.input,
            control_handles: bundle
                .handle_lease
                .expect("confirmed control lease is present"),
            _observed: ClosedPins {
                _rendezvous: bundle.rendezvous,
                _control_wal: bundle.control_wal,
                _catalog_wal: bundle.catalog_wal,
                _control_shm: bundle.control_shm,
                _catalog_shm: bundle.catalog_shm,
            },
        }
    }
}

fn raw_reinstall_connection(path: &Path, writable: bool) -> PortResult<Connection> {
    let access = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let flags = access | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    // Unlike connect_raw, even the fallible VFS check happens AFTER containment.
    #[cfg(unix)]
    let conn = Connection::open_with_flags_and_vfs(path, flags, CONTROL_VFS).map_err(sql_error)?;
    #[cfg(not(unix))]
    let conn = Connection::open_with_flags(path, flags).map_err(sql_error)?;
    Ok(conn)
}

fn configure_query_only(conn: &Connection) -> PortResult<()> {
    configure_runtime_deadline(conn)?;
    runtime_tick()?;
    conn.execute_batch(
        "PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;
         PRAGMA trusted_schema=OFF; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=-1;",
    )
    .map_err(sql_error)
}

fn require_close_policy(conn: &Connection) -> PortResult<()> {
    if !conn
        .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
        .map_err(sql_error)?
    {
        return Err(invalid());
    }
    Ok(())
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn verify_wal(
    main: &Path,
    original: &mut Option<fs::File>,
    expected: Option<&ReinstallFileBinding>,
    observed: &mut Option<ObservedWal>,
    allow_empty: bool,
    end: Instant,
) -> PortResult<()> {
    let path = sidecar(main, "-wal");
    match (original, expected) {
        (Some(file), Some(binding)) => verify_reinstall_file_bytes(&path, file, binding, end),
        (None, None) => {
            if let Some(wal) = observed {
                return verify_reinstall_file_bytes(&path, &mut wal.file, &wal.binding, end);
            }
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Ok(metadata) if allow_empty && metadata.len() == 0 => {
                    let mut file = open_reinstall_pin(&path)?;
                    let binding = ReinstallFileBinding {
                        identity: reinstall_file_identity(&file)?,
                        size: 0,
                        sha256: ReinstallDigest(Sha256::digest([]).into()),
                    };
                    verify_reinstall_file_bytes(&path, &mut file, &binding, end)?;
                    *observed = Some(ObservedWal { file, binding });
                    Ok(())
                }
                _ => Err(conflict()),
            }
        }
        _ => Err(invalid()),
    }
}

fn verify_shm(
    main: &Path,
    expected: Option<&ReinstallShmBinding>,
    observed: &mut Option<ObservedShm>,
) -> PortResult<()> {
    runtime_tick()?;
    let path = sidecar(main, "-shm");
    match fs::symlink_metadata(&path) {
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && expected.is_none()
                && observed.is_none() =>
        {
            return Ok(());
        }
        Err(_) => return Err(conflict()),
        Ok(metadata)
            if metadata.len() > 64 * 1024 * 1024 || !metadata.len().is_multiple_of(32768) =>
        {
            return Err(corrupt());
        }
        Ok(_) => {}
    }
    if observed.is_none() {
        let file = open_reinstall_pin(&path)?;
        let identity = reinstall_file_identity(&file)?;
        if expected.is_some_and(|binding| binding.identity != identity) {
            return Err(conflict());
        }
        *observed = Some(ObservedShm { file, identity });
    }
    let pin = observed.as_ref().ok_or_else(invalid)?;
    private_file(&path)?;
    if reinstall_file_identity(&pin.file)? != pin.identity {
        return Err(conflict());
    }
    #[cfg(windows)]
    windows_private::validate_private_read(&path, &pin.file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if (metadata.dev(), metadata.ino()) != pin.identity {
            return Err(conflict());
        }
    }
    Ok(())
}

/// Compatible sharing keeps this pin live across a writable query-only open.
/// Metadata/file identity remains authoritative; no lock bytes are ever read.
fn open_reinstall_pin(path: &Path) -> PortResult<fs::File> {
    private_file(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
            READ_CONTROL,
        };
        let file = fs::OpenOptions::new()
            .access_mode(0x80000000 | READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(io_error)?;
        windows_private::validate_private_read(path, &file)?;
        Ok(file)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        ))]
        {
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    crate::managed_locks::platform::NOFOLLOW
                        | crate::managed_locks::platform::NONBLOCK
                        | crate::managed_locks::platform::CLOEXEC,
                )
                .open(path)
                .map_err(io_error)?;
            verify_private(path, &file.metadata().map_err(io_error)?)?;
            Ok(file)
        }
        #[cfg(not(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ),
            target_os = "macos"
        )))]
        Err(invalid())
    }
    #[cfg(not(any(unix, windows)))]
    Err(invalid())
}

fn reinstall_file_identity(file: &fs::File) -> PortResult<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(io_error)?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: File owns this live handle, output is its exact ABI type.
        // This is the existing seal formula, not a FILE_ID_INFO conversion.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io_error(()));
        }
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(invalid())
    }
}

fn verify_reinstall_connection(
    conn: &Connection,
    path: &Path,
    expected: (u64, u64),
) -> PortResult<()> {
    runtime_tick()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        verify_connection_vfs(conn)?;
        if connection_main_filename(conn)? != path {
            return Err(invalid());
        }
        connection_unmoved(conn)?;
        private_file(path)?;
        let meta = fs::symlink_metadata(path).map_err(io_error)?;
        if (meta.dev(), meta.ino()) != expected {
            return Err(conflict());
        }
        connection_unmoved(conn)?;
    }
    #[cfg(windows)]
    if windows_private::connection_file_identity(connection_win32_handle(conn)?, path)? != expected
    {
        return Err(conflict());
    }
    #[cfg(not(any(unix, windows)))]
    return Err(invalid());
    runtime_tick()
}

fn verify_reinstall_file_bytes(
    path: &Path,
    file: &mut fs::File,
    expected: &ReinstallFileBinding,
    end: Instant,
) -> PortResult<()> {
    let tick = || {
        runtime_tick()?;
        if Instant::now() >= end {
            Err(PortError::WriterBusy(
                "control runtime deadline reached".into(),
            ))
        } else {
            Ok(())
        }
    };
    tick()?;
    private_file(path)?;
    let before = file.metadata().map_err(io_error)?;
    if before.len() != expected.size || reinstall_file_identity(file)? != expected.identity {
        return Err(conflict());
    }
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut bytes = 0u64;
    loop {
        tick()?;
        let remaining = expected.size.saturating_sub(bytes).saturating_add(1);
        let chunk = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = file.read(&mut buffer[..chunk]).map_err(io_error)?;
        if count == 0 {
            break;
        }
        bytes = bytes.checked_add(count as u64).ok_or_else(invalid)?;
        if bytes > expected.size {
            return Err(conflict());
        }
        hasher.update(&buffer[..count]);
    }
    if bytes != expected.size
        || ReinstallDigest(hasher.finalize().into()) != expected.sha256
        || reinstall_file_identity(file)? != expected.identity
        || file.metadata().map_err(io_error)?.len() != expected.size
    {
        return Err(conflict());
    }
    #[cfg(windows)]
    windows_private::validate_private_read(path, file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let named = fs::symlink_metadata(path).map_err(io_error)?;
        if (named.dev(), named.ino()) != expected.identity {
            return Err(conflict());
        }
        verify_private(path, &named)?;
    }
    tick()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{managed_locks::SharedGuard, managed_store::ManagedStore};
    use fs4::fs_std::FileExt;
    #[cfg(not(windows))]
    use std::process::{Child, Command, Stdio};
    use std::{
        collections::BTreeMap,
        io::{BufRead, BufReader, ErrorKind, Write},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError},
        },
        thread::JoinHandle,
    };
    #[cfg(windows)]
    use windows_child::Child;

    const CHILD_MODE: &str = "ASG_REINSTALL_CLOSE_TEST_MODE";
    const CHILD_ROOT: &str = "ASG_REINSTALL_CLOSE_TEST_ROOT";
    const CHILD_TEST: &str = "control::reinstall_connection::tests::reinstall_connection_child";
    const PROCESS_BOUND: Duration = Duration::from_secs(60);
    const REAP_RESERVE: Duration = Duration::from_secs(5);
    const PROCESS_POLL: Duration = Duration::from_millis(10);
    const MAX_OUTPUT_LINE: usize = 4096;
    const MAX_OUTPUT_BYTES: usize = 64 * 1024;
    const MAX_OUTPUT_LINES: usize = 256;
    const CLEANUP_FAILURE_EXIT: i32 = 86;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum OpenKind {
        Control,
        CatalogProbe,
        WritableCatalog,
    }

    thread_local! {
        static PANIC_AFTER_OPEN: Cell<Option<OpenKind>> = const { Cell::new(None) };
        static PANIC_AFTER_TAKE: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn after_containment(kind: OpenKind) {
        PANIC_AFTER_OPEN.with(|slot| {
            if slot.get() == Some(kind) {
                slot.set(None);
                panic!("injected unwind after owned connection containment");
            }
        });
    }

    pub(super) fn after_take_for_close() {
        PANIC_AFTER_TAKE.with(|slot| {
            if slot.replace(false) {
                panic!("injected unwind with unconfirmed empty connection slot");
            }
        });
    }

    /// Test-only prepared statement ownership; the database is always owned by
    /// rusqlite. An unconfirmed bundle retains this statement too until process
    /// exit. Normal controls finalize it once before the single explicit close.
    pub(super) struct OutstandingStatement(*mut rusqlite::ffi::sqlite3_stmt);

    impl OutstandingStatement {
        fn prepare(conn: &Connection) -> Self {
            let mut statement = std::ptr::null_mut();
            // SAFETY: this is a live borrowed connection. SQLite creates only a
            // statement here; no database ownership is transferred or freed.
            let result = unsafe {
                rusqlite::ffi::sqlite3_prepare_v2(
                    conn.handle(),
                    c"SELECT 1".as_ptr(),
                    -1,
                    &mut statement,
                    std::ptr::null_mut(),
                )
            };
            let owned = Self(statement);
            // Own the result before assertions, including unexpected failures.
            assert_eq!(result, rusqlite::ffi::SQLITE_OK);
            assert!(!owned.0.is_null());
            owned
        }
    }

    impl Drop for OutstandingStatement {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this wrapper uniquely owns this statement. Its
                // connection stays in the bundle until statement finalization
                // or OS process teardown. Never close/free the database here.
                unsafe { rusqlite::ffi::sqlite3_finalize(self.0) };
            }
        }
    }

    struct Retained {
        _parent_exit: fs::File,
        _runner_exit: fs::File,
        _image: fs::File,
        _data_root: fs::File,
        _prefix_root: fs::File,
        dropped: PathBuf,
    }

    impl Drop for Retained {
        fn drop(&mut self) {
            fs::write(&self.dropped, b"retention-payload-dropped").unwrap();
        }
    }

    fn directory_pin(path: &Path) -> fs::File {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
                FILE_SHARE_WRITE,
            };
            options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        options.open(path).unwrap()
    }

    fn exit_pin(path: &Path) -> fs::File {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        assert!(file.try_lock_exclusive().unwrap());
        file
    }

    fn cid(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }

    fn lock(root: &Path, kind: LockKind) -> ExclusiveGuard {
        ExclusiveGuard::try_acquire(root, kind).unwrap()
    }

    fn binding(path: &Path) -> (fs::File, ReinstallFileBinding) {
        let file = open_reinstall_pin(path).unwrap();
        let bytes = fs::read(path).unwrap();
        let expected = ReinstallFileBinding {
            identity: reinstall_file_identity(&file).unwrap(),
            size: bytes.len() as u64,
            sha256: ReinstallDigest(Sha256::digest(&bytes).into()),
        };
        (file, expected)
    }

    fn optional_binding(path: &Path) -> (Option<fs::File>, Option<ReinstallFileBinding>) {
        if path.exists() {
            let (file, expected) = binding(path);
            (Some(file), Some(expected))
        } else {
            (None, None)
        }
    }

    fn shm_binding(path: &Path) -> Option<ReinstallShmBinding> {
        path.exists().then(|| {
            let file = open_reinstall_pin(path).unwrap();
            ReinstallShmBinding {
                identity: reinstall_file_identity(&file).unwrap(),
                size: file.metadata().unwrap().len(),
            }
        })
    }

    fn close_fixture_store(store: SqliteControlStore) {
        let SqliteControlStore {
            conn, handle_lease, ..
        } = store;
        match conn.into_inner().close() {
            Ok(()) => drop(handle_lease),
            Err((conn, error)) => {
                // Unexpected setup refusal is terminal. Even the fixture must
                // not demonstrate the unsafe Drop(conn)-then-release pattern.
                std::mem::forget((conn, handle_lease));
                panic!("fixture close refused: {error}");
            }
        }
    }

    fn fixture(
        base: &Path,
        recovering: bool,
        live_catalog_wal: bool,
    ) -> ReinstallOwnedInput<Retained> {
        let root = base.join("data");
        let prefix = base.join("prefix");
        private_directory(&prefix, true).unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        let store = SqliteControlStore::create_with_deadline(
            &root,
            &cid("close-installation"),
            DesiredUpdates::Paused,
            until,
        )
        .unwrap();
        let catalog = root.join("catalog.db");
        let incarnation = cid("close-catalog");
        drop(
            ManagedStore::create_with_deadline(&catalog, &store, incarnation.clone(), 1, until)
                .unwrap(),
        );
        if live_catalog_wal {
            let conn = raw_reinstall_connection(&catalog, true).unwrap();
            install_reinstall_close_policy(&conn).unwrap();
            conn.execute_batch(
                "PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=-1;
                 UPDATE store_metadata SET active_generation=active_generation+1;",
            )
            .unwrap();
            match conn.close() {
                Ok(()) => {}
                Err((conn, error)) => {
                    std::mem::forget(conn);
                    panic!("catalog fixture close refused: {error}");
                }
            }
            assert!(fs::metadata(sidecar(&catalog, "-wal")).unwrap().len() > 32);
        }
        let policy_owner = lock(&root, LockKind::PolicyOwner);
        let prefix_guard = lock(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap()),
        );
        store
            .with_runtime_deadline(until, || {
                let owner = store.bind_control_root(&policy_owner)?;
                store.record_verified_installation_prefix(&prefix, &prefix_guard, &owner, until)?;
                let background = lock(&root, LockKind::Background);
                let worker = store.bind_worker(&background, cid("close-worker"))?;
                let registered =
                    store.register_worker(store.status()?.policy.control_seq, &worker, 1, 1)?;
                store.reconcile_catalog_summary(
                    registered.control_seq,
                    &worker,
                    &incarnation,
                    1,
                )?;
                let installation = store.bind_installation(&prefix, &prefix_guard)?;
                store.begin_maintenance(
                    store.status()?.policy.control_seq,
                    &cid("close-old-owner"),
                    &owner,
                    &installation,
                    MaintenanceFence {
                        state: MaintenanceState::Uninstalling,
                        owner: Some(cid("close-old-owner")),
                        phase: Some(MaintenancePhase::Quiescing),
                    },
                )?;
                if recovering {
                    store.recover_maintenance(
                        store.status()?.policy.control_seq,
                        &cid("close-fixed-owner"),
                        &owner,
                        &installation,
                        &cid("close-old-owner"),
                        MaintenanceFence {
                            state: MaintenanceState::Recovering,
                            owner: Some(cid("close-fixed-owner")),
                            phase: Some(MaintenancePhase::Reconciling),
                        },
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let expected = store
            .with_runtime_deadline(until, || store.lifecycle_status())
            .unwrap();
        {
            let conn = store.conn.borrow();
            install_reinstall_close_policy(&conn).unwrap();
            conn.execute_batch("PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=-1;")
                .unwrap();
        }
        close_fixture_store(store);
        let (control_main, control_binding) = binding(&SqliteControlStore::path(&root));
        let (control_wal, control_wal_binding) = optional_binding(&root.join("control.db-wal"));
        let (catalog_main, catalog_binding) = binding(&catalog);
        let (catalog_wal, catalog_wal_binding) = optional_binding(&sidecar(&catalog, "-wal"));
        let (prefix_pin, prefix_binding) = binding(&root.join(PREFIX_BINDING_FILE));
        let files = ReinstallFiles {
            control_main: control_binding,
            control_wal: control_wal_binding,
            control_shm: shm_binding(&root.join("control.db-shm")),
            catalog_main: catalog_binding,
            catalog_wal: catalog_wal_binding,
            catalog_shm: shm_binding(&sidecar(&catalog, "-shm")),
        };
        let guards = ReinstallOwnedGuards {
            prefix: prefix_guard,
            policy_owner,
            emission: lock(&root, LockKind::PolicyEmission),
            supervisor: lock(&root, LockKind::Supervisor),
            background: lock(&root, LockKind::Background),
            purge: lock(
                &root,
                LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY).unwrap()),
            ),
            history_readers: lock(&root, LockKind::HistoryReaders),
            catalog_handles: lock(&root, LockKind::CatalogHandles),
            writer: WriterLease::try_acquire(&root).unwrap(),
        };
        let image_path = base.join("incoming-image");
        fs::write(&image_path, b"synthetic pinned incoming image").unwrap();
        let retained = Retained {
            _parent_exit: exit_pin(&base.join("parent-exit.lock")),
            _runner_exit: exit_pin(&base.join("runner-exit.lock")),
            _image: fs::File::open(image_path).unwrap(),
            _data_root: directory_pin(&root),
            _prefix_root: directory_pin(&prefix),
            dropped: base.join("retained-dropped"),
        };
        ReinstallOwnedInput {
            root,
            prefix,
            catalog,
            expected,
            files,
            prefix_binding,
            guards,
            pins: ReinstallOwnedPins {
                control_main,
                control_wal,
                catalog_main,
                catalog_wal,
                prefix_binding: prefix_pin,
            },
            retained,
        }
    }

    fn durable_snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(root)
            .unwrap()
            .map(Result::unwrap)
            .filter_map(|entry| {
                let name = entry.file_name().to_str().unwrap().to_owned();
                if name.ends_with(".lock") || name.ends_with("-shm") {
                    return None;
                }
                assert!(entry.file_type().unwrap().is_file());
                Some((name, fs::read(entry.path()).unwrap()))
            })
            .collect()
    }

    fn arm_busy<R: 'static>(bundle: &mut Bundle<R>, catalog: bool) {
        let slot = if catalog {
            bundle.catalog.as_ref()
        } else {
            bundle.control.as_ref()
        }
        .unwrap();
        let statement = OutstandingStatement::prepare(slot.get().unwrap());
        assert!(bundle.outstanding.replace(statement).is_none());
    }

    fn close_error<R: 'static>(
        result: Result<ReinstallClosed<R>, Box<ReinstallConnectionError<R>>>,
    ) -> Box<ReinstallConnectionError<R>> {
        match result {
            Ok(_) => panic!("unfinished statement unexpectedly allowed close"),
            Err(error) => error,
        }
    }

    fn assert_busy_close<R: 'static>(error: &ReinstallConnectionError<R>) {
        assert!(error.close_attempted());
        assert!(error.requires_process_exit());
        assert_eq!(error.sqlite_close_code(), Some(rusqlite::ffi::SQLITE_BUSY));
        assert!(matches!(error.error(), PortError::WriterBusy(_)));
        let bundle = error.owned.bundle();
        assert!(
            bundle
                .connections()
                .any(|slot| slot.close_attempted && slot.conn.is_some() && !slot.close_confirmed)
        );
    }

    fn signal(value: &str) {
        println!("{value}");
        std::io::stdout().flush().unwrap();
    }

    fn bounded_line(
        reader: &mut impl BufRead,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, PipeFailure> {
        let mut line = Vec::new();
        let read = reader
            .take(limit as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| PipeFailure::Io(error.kind()))?;
        if read > limit {
            return Err(PipeFailure::Limit);
        }
        if read == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') {
            return Err(PipeFailure::Truncated);
        }
        Ok(Some(line))
    }

    fn line_content(line: &[u8]) -> &[u8] {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        line.strip_suffix(b"\r").unwrap_or(line)
    }

    /// The child accepts a finite protocol only. Its one reader may block in a
    /// pipe read, but the test thread never does: receive is bounded by the one
    /// child protocol end, and the parent's earlier process bound is decisive.
    struct ChildRequests {
        incoming: Receiver<Result<(), PipeFailure>>,
        reader: JoinHandle<()>,
        end: Instant,
    }

    impl ChildRequests {
        fn new(normal: bool) -> Self {
            let end = Instant::now() + PROCESS_BOUND;
            let (sender, incoming) = mpsc::sync_channel(2);
            let reader = std::thread::spawn(move || {
                let input = std::io::stdin();
                let mut input = input.lock();
                let commands: &[&[u8]] = if normal {
                    &[b"release", b"exit"]
                } else {
                    &[b"exit"]
                };
                for expected in commands {
                    let received = match bounded_line(&mut input, 9) {
                        Ok(Some(line)) if line_content(&line) == *expected => Ok(()),
                        Ok(Some(_)) => Err(PipeFailure::Unexpected),
                        Ok(None) => Err(PipeFailure::Eof),
                        Err(error) => Err(error),
                    };
                    let refused = received.is_err();
                    if sender.send(received).is_err() || refused {
                        return;
                    }
                }
            });
            Self {
                incoming,
                reader,
                end,
            }
        }

        fn receive(&self) {
            let remaining = self.end.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "child input exceeded its original process bound"
            );
            self.incoming
                .recv_timeout(remaining)
                .expect("child input did not arrive before its original end")
                .expect("child received EOF or a non-protocol signal");
        }

        fn finish(self) {
            while !self.reader.is_finished() {
                let remaining = self.end.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "child input reader did not finish");
                std::thread::sleep(PROCESS_POLL.min(remaining));
            }
            self.reader.join().expect("child input reader panicked");
        }
    }

    #[test]
    fn reinstall_connection_child() {
        let Ok(mode) = std::env::var(CHILD_MODE) else {
            return;
        };
        let requests = ChildRequests::new(mode == "normal");
        let base = PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
        if matches!(mode.as_str(), "cleanup-no-exit" | "cleanup-live-reader") {
            struct CleanupSentinel(PathBuf);
            impl Drop for CleanupSentinel {
                fn drop(&mut self) {
                    fs::write(&self.0, b"fixture-cleanup-ran").unwrap();
                }
            }
            let _sentinel = CleanupSentinel(base.join("fixture-cleanup-ran"));
            signal("cleanup-failure-ready");
            requests.receive();
            requests.finish();
            let end = Instant::now();
            let step = cleanup_step(
                mode == "cleanup-live-reader",
                mode == "cleanup-no-exit",
                end,
                end,
            );
            assert_eq!(step, CleanupStep::Abort);
            abort_unconfirmed_child_cleanup();
        }
        let input = fixture(&base, true, true);
        let before = durable_snapshot(&input.root);
        let root = input.root.clone();
        let until = Instant::now() + Duration::from_secs(30);
        if mode == "open-unwind" {
            PANIC_AFTER_OPEN.with(|slot| slot.set(Some(OpenKind::Control)));
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _owner = ReinstallControlOwner::open_read_only(input, until).unwrap();
                }))
                .is_err()
            );
        } else if mode == "expired" {
            let store = SqliteControlStore::open_reinstall_read_only_with_deadline(
                ReinstallControlOpen {
                    root: &input.root,
                    prefix: &input.prefix,
                    policy_owner: &input.guards.policy_owner,
                    prefix_guard: &input.guards.prefix,
                    sealed: SealedControlFile::from_recorded(input.files.control_main.identity),
                    expected: &input.expected,
                },
                until,
            )
            .unwrap();
            // Preparation has ended; this consuming request enters with an
            // expired original end while still owning its real connection.
            let expired = Instant::now();
            let owner = store.into_reinstall_close_owner(input, expired);
            let error = close_error(owner.close());
            assert!(error.requires_process_exit());
            assert!(!error.close_attempted());
            assert_eq!(error.sqlite_close_code(), None);
            assert_eq!(error.owned.bundle().end, expired);
            assert!(matches!(error.error(), PortError::WriterBusy(_)));
            drop(error);
        } else {
            let mut owner = ReinstallControlOwner::open_read_only(input, until).unwrap();
            match mode.as_str() {
                "owner-drop" => {
                    arm_busy(owner.owned.bundle_mut(), false);
                    drop(owner);
                }
                "owner-unwind" => {
                    arm_busy(owner.owned.bundle_mut(), false);
                    assert!(
                        catch_unwind(AssertUnwindSafe(move || {
                            let _owner = owner;
                            panic!("injected owner unwind");
                        }))
                        .is_err()
                    );
                }
                "close-unwind" => {
                    arm_busy(owner.owned.bundle_mut(), false);
                    PANIC_AFTER_TAKE.with(|slot| slot.set(true));
                    assert!(
                        catch_unwind(AssertUnwindSafe(move || {
                            let _result = owner.close();
                        }))
                        .is_err()
                    );
                }
                "error-drop" | "error-unwind" => {
                    arm_busy(owner.owned.bundle_mut(), false);
                    let error = close_error(owner.close());
                    assert_busy_close(&error);
                    if mode == "error-drop" {
                        drop(error);
                    } else {
                        assert!(
                            catch_unwind(AssertUnwindSafe(move || {
                                let _error = error;
                                panic!("injected close-error unwind");
                            }))
                            .is_err()
                        );
                    }
                }
                "catalog-busy" => {
                    let mut catalog = owner
                        .open_query_only_catalog(cid("close-fixed-owner"))
                        .unwrap();
                    arm_busy(catalog.owned.bundle_mut(), true);
                    let error = close_error(catalog.close());
                    assert_busy_close(&error);
                    drop(error);
                }
                "control-busy-after-catalog" => {
                    let mut catalog = owner
                        .open_query_only_catalog(cid("close-fixed-owner"))
                        .unwrap();
                    arm_busy(catalog.owned.bundle_mut(), false);
                    let error = close_error(catalog.close());
                    assert_busy_close(&error);
                    let bundle = error.owned.bundle();
                    let catalog = bundle.catalog.as_ref().unwrap();
                    assert!(catalog.close_attempted && catalog.close_confirmed);
                    assert!(catalog.conn.is_none());
                    let control = bundle.control.as_ref().unwrap();
                    assert!(control.close_attempted && !control.close_confirmed);
                    assert!(control.conn.is_some());
                    drop(error);
                }
                "probe-unwind" | "catalog-unwind" => {
                    PANIC_AFTER_OPEN.with(|slot| {
                        slot.set(Some(if mode == "probe-unwind" {
                            OpenKind::CatalogProbe
                        } else {
                            OpenKind::WritableCatalog
                        }))
                    });
                    assert!(
                        catch_unwind(AssertUnwindSafe(move || {
                            let _catalog = owner
                                .open_query_only_catalog(cid("close-fixed-owner"))
                                .unwrap();
                        }))
                        .is_err()
                    );
                }
                "refused" => {
                    let error = match owner.open_query_only_catalog(cid("wrong-fixed-owner")) {
                        Ok(_) => panic!("wrong recovering owner was admitted"),
                        Err(error) => error,
                    };
                    assert!(error.requires_process_exit());
                    assert!(!error.close_attempted());
                    assert!(matches!(error.error(), PortError::InvalidRequest(_)));
                    drop(error);
                }
                "normal" => {
                    arm_busy(owner.owned.bundle_mut(), false);
                    drop(owner.owned.bundle_mut().outstanding.take());
                    let closed = owner.close().unwrap();
                    assert!(
                        closed
                            .owned
                            .bundle()
                            .control
                            .as_ref()
                            .unwrap()
                            .close_confirmed
                    );
                    assert_eq!(durable_snapshot(&root), before);
                    assert!(!base.join("retained-dropped").exists());
                    signal("closed-and-held");
                    requests.receive();
                    drop(closed.into_resources());
                    assert!(base.join("retained-dropped").exists());
                    signal("released");
                    requests.receive();
                    requests.finish();
                    return;
                }
                _ => panic!("unknown isolated close test mode"),
            }
        }
        assert_eq!(durable_snapshot(&root), before);
        assert!(!base.join("retained-dropped").exists());
        assert_eq!(runtime_deadline(), None);
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), BUSY_TIMEOUT);
        signal("unconfirmed-and-retained");
        requests.receive();
        requests.finish();
        // Confirmed OS process exit is the only release on this branch. No
        // destructor, raw database close or repeated close attempt runs here.
        std::process::exit(23);
    }

    #[derive(Clone, Copy, Debug)]
    enum PipeFailure {
        Io(ErrorKind),
        Limit,
        Truncated,
        Unexpected,
        Eof,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PipeName {
        Stdout,
        Stderr,
    }

    enum PipeEvent {
        Line(PipeName, Vec<u8>),
        Eof(PipeName),
        Failed(PipeName, PipeFailure),
    }

    struct OutputBound {
        bytes: AtomicUsize,
        lines: AtomicUsize,
    }

    fn pipe_reader(
        input: impl Read + Send + 'static,
        name: PipeName,
        sender: SyncSender<PipeEvent>,
        bound: Arc<OutputBound>,
    ) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let mut input = BufReader::new(input);
            loop {
                let event = match bounded_line(&mut input, MAX_OUTPUT_LINE) {
                    Ok(Some(line)) => {
                        let bytes = bound.bytes.fetch_add(line.len(), Ordering::Relaxed);
                        let lines = bound.lines.fetch_add(1, Ordering::Relaxed);
                        if bytes.saturating_add(line.len()) > MAX_OUTPUT_BYTES
                            || lines >= MAX_OUTPUT_LINES
                        {
                            PipeEvent::Failed(name, PipeFailure::Limit)
                        } else {
                            PipeEvent::Line(name, line)
                        }
                    }
                    Ok(None) => PipeEvent::Eof(name),
                    Err(error) => PipeEvent::Failed(name, error),
                };
                let terminal = !matches!(&event, PipeEvent::Line(_, _));
                if sender.send(event).is_err() || terminal {
                    return;
                }
            }
        })
    }

    #[cfg(windows)]
    mod windows_child {
        use super::{CHILD_MODE, CHILD_ROOT, CHILD_TEST};
        use std::{
            ffi::{OsStr, c_void},
            io::{self, PipeReader, PipeWriter},
            mem::size_of,
            os::windows::{
                ffi::OsStrExt,
                io::{AsRawHandle, FromRawHandle, OwnedHandle},
                process::ExitStatusExt,
            },
            path::Path,
            process::ExitStatus,
            ptr::{null, null_mut},
        };
        use windows_sys::Win32::{
            Foundation::{
                HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
            },
            System::Threading::{
                CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, DeleteProcThreadAttributeList,
                EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, IO_COUNTERS,
                InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
                TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
            },
        };

        // The adapter does not enable JobObjects/Security features. These
        // test-local ABI declarations match the pinned windows-sys 0.61.2
        // declarations; security-attribute pointers are always NULL.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            #[link_name = "CreateJobObjectW"]
            fn create_job(attributes: *const c_void, name: *const u16) -> HANDLE;
            #[link_name = "SetInformationJobObject"]
            fn set_job(job: HANDLE, class: i32, value: *const c_void, size: u32) -> i32;
            #[link_name = "CreateProcessW"]
            fn create_process(
                application: *const u16,
                command: *mut u16,
                process_attributes: *const c_void,
                thread_attributes: *const c_void,
                inherit: i32,
                flags: u32,
                environment: *const c_void,
                directory: *const u16,
                startup: *const STARTUPINFOW,
                information: *mut PROCESS_INFORMATION,
            ) -> i32;
            #[link_name = "CompareStringOrdinal"]
            fn compare_names(
                left: *const u16,
                left_len: i32,
                right: *const u16,
                right_len: i32,
                ignore_case: i32,
            ) -> i32;
        }

        #[repr(C)]
        #[derive(Default)]
        struct BasicLimits {
            _process_time: i64,
            _job_time: i64,
            flags: u32,
            _minimum_working_set: usize,
            _maximum_working_set: usize,
            _active_processes: u32,
            _affinity: usize,
            _priority: u32,
            _scheduling: u32,
        }

        #[repr(C)]
        #[derive(Default)]
        struct ExtendedLimits {
            basic: BasicLimits,
            _io: IO_COUNTERS,
            _process_memory: usize,
            _job_memory: usize,
            _peak_process_memory: usize,
            _peak_job_memory: usize,
        }

        struct Attributes(Vec<usize>);

        impl Attributes {
            fn new() -> io::Result<Self> {
                let mut size = 0;
                // SAFETY: size query followed by initialization of aligned,
                // owned storage, as in the existing native probe harness.
                unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
                if size == 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut data = vec![0usize; size.div_ceil(size_of::<usize>())];
                if unsafe {
                    InitializeProcThreadAttributeList(data.as_mut_ptr().cast(), 2, 0, &mut size)
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self(data))
            }

            fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
                self.0.as_mut_ptr().cast()
            }
        }

        impl Drop for Attributes {
            fn drop(&mut self) {
                // SAFETY: only successfully initialized lists reach this owner.
                unsafe { DeleteProcThreadAttributeList(self.raw()) };
            }
        }

        fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
            let value: Vec<u16> = value.encode_wide().collect();
            if value.contains(&0) || i32::try_from(value.len()).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid child input",
                ));
            }
            Ok(value)
        }

        fn environment(base: &Path, mode: &str) -> io::Result<Vec<u16>> {
            let mut entries = Vec::new();
            for (key, value) in std::env::vars_os() {
                if key.to_string_lossy().eq_ignore_ascii_case(CHILD_MODE)
                    || key.to_string_lossy().eq_ignore_ascii_case(CHILD_ROOT)
                {
                    continue;
                }
                entries.push((wide(&key)?, wide(&value)?));
            }
            entries.push((wide(OsStr::new(CHILD_MODE))?, wide(OsStr::new(mode))?));
            entries.push((wide(OsStr::new(CHILD_ROOT))?, wide(base.as_os_str())?));
            // Windows environment ordering is ordinal and case-insensitive,
            // including non-ASCII keys. No mutation of the parent's environment.
            entries.sort_by(|(left, _), (right, _)| {
                // SAFETY: live UTF-16 buffers with checked i32 lengths.
                match unsafe {
                    compare_names(
                        left.as_ptr(),
                        left.len() as i32,
                        right.as_ptr(),
                        right.len() as i32,
                        1,
                    )
                } {
                    1 => std::cmp::Ordering::Less,
                    2 => std::cmp::Ordering::Equal,
                    3 => std::cmp::Ordering::Greater,
                    _ => panic!("owned child environment comparison failed before spawn"),
                }
            });
            let mut block = Vec::new();
            for (key, value) in entries {
                block.extend(key);
                block.push(u16::from(b'='));
                block.extend(value);
                block.push(0);
            }
            block.push(0);
            Ok(block)
        }

        pub(super) struct Child {
            process: OwnedHandle,
            _job: OwnedHandle,
            status: Option<ExitStatus>,
            pub(super) stdin: Option<PipeWriter>,
            pub(super) stdout: Option<PipeReader>,
            pub(super) stderr: Option<PipeReader>,
        }

        impl Child {
            pub(super) fn spawn(base: &Path, mode: &str) -> io::Result<Self> {
                let executable = wide(std::env::current_exe()?.as_os_str())?;
                if executable.contains(&u16::from(b'"')) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid child executable",
                    ));
                }
                let mut line = vec![u16::from(b'"')];
                line.extend_from_slice(&executable);
                line.extend(format!("\" --exact {CHILD_TEST} --nocapture").encode_utf16());
                line.push(0);
                let mut application = executable;
                application.push(0);
                let environment = environment(base, mode)?;
                let (input, stdin) = io::pipe()?;
                let (stdout, output) = io::pipe()?;
                let (stderr, error) = io::pipe()?;
                // SAFETY: unnamed, noninheritable job, owned immediately.
                let raw_job = unsafe { create_job(null(), null()) };
                if raw_job.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let job = unsafe { OwnedHandle::from_raw_handle(raw_job) };
                let mut limits = ExtendedLimits::default();
                limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                // SAFETY: exact JOBOBJECT_EXTENDED_LIMIT_INFORMATION C layout.
                if unsafe {
                    set_job(
                        raw_job,
                        9,
                        (&limits as *const ExtendedLimits).cast(),
                        size_of::<ExtendedLimits>() as u32,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let handles = [
                    input.as_raw_handle(),
                    output.as_raw_handle(),
                    error.as_raw_handle(),
                ];
                for handle in handles {
                    // SAFETY: only the three child pipe ends are inheritable.
                    if unsafe {
                        SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                let jobs = [raw_job];
                let mut attributes = Attributes::new()?;
                for (kind, values) in [
                    (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.as_slice()),
                    (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs.as_slice()),
                ] {
                    // SAFETY: handles and their lists outlive attribute-list destruction.
                    if unsafe {
                        UpdateProcThreadAttribute(
                            attributes.raw(),
                            0,
                            kind as usize,
                            values.as_ptr().cast(),
                            std::mem::size_of_val(values),
                            null_mut(),
                            null(),
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                let startup = STARTUPINFOEXW {
                    StartupInfo: STARTUPINFOW {
                        cb: size_of::<STARTUPINFOEXW>() as u32,
                        dwFlags: STARTF_USESTDHANDLES,
                        hStdInput: handles[0],
                        hStdOutput: handles[1],
                        hStdError: handles[2],
                        ..Default::default()
                    },
                    lpAttributeList: attributes.raw(),
                };
                let mut information = PROCESS_INFORMATION::default();
                // SAFETY: fixed executable/protocol, valid NUL-terminated UTF-16
                // and live attributes. The job is attached before any child code
                // runs; there is no spawn/assignment gap or breakaway fallback.
                if unsafe {
                    create_process(
                        application.as_ptr(),
                        line.as_mut_ptr(),
                        null(),
                        null(),
                        1,
                        CREATE_NO_WINDOW
                            | CREATE_UNICODE_ENVIRONMENT
                            | EXTENDED_STARTUPINFO_PRESENT,
                        environment.as_ptr().cast(),
                        null(),
                        &startup.StartupInfo,
                        &mut information,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: successful creation returned these unique handles.
                let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess) };
                let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread) };
                let child = Self {
                    process,
                    _job: job,
                    status: None,
                    stdin: Some(stdin),
                    stdout: Some(stdout),
                    stderr: Some(stderr),
                };
                drop(thread);
                Ok(child)
            }

            pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
                if let Some(status) = self.status {
                    return Ok(Some(status));
                }
                // SAFETY: zero-time observation of the exact owned process.
                match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
                    WAIT_TIMEOUT => Ok(None),
                    WAIT_OBJECT_0 => {
                        let mut code = 0;
                        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) }
                            == 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        let status = ExitStatus::from_raw(code);
                        self.status = Some(status);
                        Ok(Some(status))
                    }
                    _ => Err(io::Error::last_os_error()),
                }
            }

            pub(super) fn kill(&mut self) -> io::Result<()> {
                // SAFETY: only this exact owned child, no PID or process search.
                if unsafe { TerminateProcess(self.process.as_raw_handle(), 1) } == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum CleanupStep {
        Complete,
        Poll,
        Abort,
    }

    fn cleanup_step(
        exited: bool,
        readers_finished: bool,
        now: Instant,
        end: Instant,
    ) -> CleanupStep {
        if now >= end {
            CleanupStep::Abort
        } else if exited && readers_finished {
            CleanupStep::Complete
        } else {
            CleanupStep::Poll
        }
    }

    fn abort_unconfirmed_child_cleanup() -> ! {
        // No panic, unwinding, stdio flushing, atexit hooks or fixture deletion.
        // This is a harness failure, never confirmation of native child exit.
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
            // SAFETY: terminate only this test process. OS teardown closes its
            // sole job handle and terminates the owned child, without a wait.
            unsafe { TerminateProcess(GetCurrentProcess(), CLEANUP_FAILURE_EXIT as u32) };
            // A failed self-termination must still never resume fixture cleanup.
            std::process::abort()
        }
        #[cfg(not(windows))]
        {
            unsafe extern "C" {
                fn _exit(status: std::ffi::c_int) -> !;
            }
            // SAFETY: POSIX immediate exit for this test process; no destructor
            // or report/pipe write is allowed after the fixed end expires.
            unsafe { _exit(CLEANUP_FAILURE_EXIT) }
        }
    }

    struct IsolatedChild {
        child: Child,
        output: Option<Receiver<PipeEvent>>,
        readers: Vec<JoinHandle<()>>,
        end: Instant,
        exited: bool,
        stdout_eof: bool,
        stderr_eof: bool,
        cleanup_confirmed: bool,
        normal: bool,
        sent: usize,
    }

    impl IsolatedChild {
        fn start(base: &Path, mode: &str) -> Self {
            // One bound covers spawn, readiness, every signal, exit and cleanup.
            // Reserve part of it for exact-child termination/reaping on failure.
            let end = Instant::now() + PROCESS_BOUND;
            #[cfg(not(windows))]
            let mut command = Command::new(std::env::current_exe().unwrap());
            #[cfg(not(windows))]
            command
                .args(["--exact", CHILD_TEST, "--nocapture"])
                .env(CHILD_MODE, mode)
                .env(CHILD_ROOT, base)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(not(windows))]
            let child = command.spawn().unwrap();
            #[cfg(windows)]
            let child = Child::spawn(base, mode).unwrap();
            let mut owned = Self {
                child,
                output: None,
                readers: Vec::with_capacity(2),
                end,
                exited: false,
                stdout_eof: false,
                stderr_eof: false,
                cleanup_confirmed: false,
                normal: mode == "normal",
                sent: 0,
            };
            // Establish exact-child RAII before any fallible pipe setup.
            let stdout = owned.child.stdout.take().unwrap();
            let stderr = owned.child.stderr.take().unwrap();
            let (sender, output) = mpsc::sync_channel(16);
            owned.output = Some(output);
            let bound = Arc::new(OutputBound {
                bytes: AtomicUsize::new(0),
                lines: AtomicUsize::new(0),
            });
            owned.readers.push(pipe_reader(
                stdout,
                PipeName::Stdout,
                sender.clone(),
                bound.clone(),
            ));
            owned
                .readers
                .push(pipe_reader(stderr, PipeName::Stderr, sender, bound));
            owned
        }

        fn remaining(&self) -> Duration {
            let remaining = (self.end - REAP_RESERVE).saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "owned child exceeded its original process bound"
            );
            remaining
        }

        fn event(&mut self, event: PipeEvent) -> Option<Vec<u8>> {
            match event {
                PipeEvent::Line(PipeName::Stdout, line) => Some(line),
                PipeEvent::Line(PipeName::Stderr, line) => {
                    // Preserve bounded child panic diagnostics in the parent's
                    // verification log; protocol readiness still uses stdout.
                    eprintln!("{}", String::from_utf8_lossy(line_content(&line)));
                    None
                }
                PipeEvent::Eof(PipeName::Stdout) => {
                    self.stdout_eof = true;
                    None
                }
                PipeEvent::Eof(PipeName::Stderr) => {
                    self.stderr_eof = true;
                    None
                }
                PipeEvent::Failed(name, PipeFailure::Io(kind)) => {
                    panic!("isolated child {name:?} pipe failed: {kind:?}");
                }
                PipeEvent::Failed(name, failure) => {
                    panic!("isolated child {name:?} protocol refused: {failure:?}");
                }
            }
        }

        fn drain(&mut self) {
            loop {
                self.remaining();
                match self.output.as_ref().unwrap().try_recv() {
                    Ok(event) => {
                        let _ = self.event(event);
                    }
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            }
        }

        fn assert_alive(&mut self) {
            self.remaining();
            self.drain();
            assert!(
                !self.stdout_eof,
                "isolated child closed stdout before release"
            );
            match self.child.try_wait().unwrap() {
                None => {}
                Some(status) => {
                    self.exited = true;
                    panic!("isolated child exited before exclusion check: {status}");
                }
            }
        }

        fn expect(&mut self, expected: &str) {
            loop {
                let remaining = self.remaining();
                if let Some(status) = self.child.try_wait().unwrap() {
                    self.exited = true;
                    panic!("isolated child exited before {expected}: {status}");
                }
                match self
                    .output
                    .as_ref()
                    .unwrap()
                    .recv_timeout(PROCESS_POLL.min(remaining))
                {
                    Ok(event) => {
                        if let Some(line) = self.event(event)
                            && line_content(&line) == expected.as_bytes()
                        {
                            self.assert_alive();
                            return;
                        }
                        assert!(
                            !self.stdout_eof,
                            "isolated child stdout ended before {expected}"
                        );
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        panic!("isolated child pipes ended before {expected}");
                    }
                }
            }
        }

        fn send(&mut self, value: &str) {
            self.remaining();
            let expected = if self.normal && self.sent == 0 {
                "release"
            } else {
                "exit"
            };
            assert!(self.sent < if self.normal { 2 } else { 1 });
            assert_eq!(value, expected);
            // At most thirteen bytes in total, one writer, below pipe capacity;
            // no arbitrary input can fill a pipe while a child refuses to read.
            let bytes: &[u8] = if value == "release" {
                b"release\n"
            } else {
                b"exit\n"
            };
            self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
            self.sent += 1;
            self.remaining();
        }

        fn finish(mut self, code: i32) {
            self.send("exit");
            drop(self.child.stdin.take());
            loop {
                let remaining = self.remaining();
                self.drain();
                if let Some(status) = self.child.try_wait().unwrap() {
                    self.exited = true;
                    assert_eq!(status.code(), Some(code));
                    break;
                }
                std::thread::sleep(PROCESS_POLL.min(remaining));
            }
            while self.readers.iter().any(|reader| !reader.is_finished()) {
                let remaining = self.remaining();
                self.drain();
                std::thread::sleep(PROCESS_POLL.min(remaining));
            }
            self.drain();
            assert!(
                self.stdout_eof && self.stderr_eof,
                "child exit did not close both pipes"
            );
            for reader in self.readers.drain(..) {
                // Only join after is_finished, never an unbounded wait.
                reader.join().expect("isolated child pipe reader panicked");
            }
            self.remaining();
            self.cleanup_confirmed = true;
        }
    }

    impl Drop for IsolatedChild {
        fn drop(&mut self) {
            if self.cleanup_confirmed {
                return;
            }
            drop(self.child.stdin.take());
            // Disconnect bounded sends before waiting for reader termination.
            drop(self.output.take());
            if !self.exited {
                self.exited = self.child.try_wait().is_ok_and(|status| status.is_some());
            }
            if !self.exited {
                // Child is the exact handle returned by spawn, never a recorded
                // PID or a descendant search. Kill once, no replacement child.
                let _ = self.child.kill();
            }
            loop {
                match cleanup_step(
                    self.exited,
                    self.readers.iter().all(JoinHandle::is_finished),
                    Instant::now(),
                    self.end,
                ) {
                    CleanupStep::Complete => break,
                    CleanupStep::Abort => abort_unconfirmed_child_cleanup(),
                    CleanupStep::Poll => {
                        if !self.exited {
                            self.exited =
                                self.child.try_wait().is_ok_and(|status| status.is_some());
                        }
                        std::thread::sleep(
                            PROCESS_POLL.min(self.end.saturating_duration_since(Instant::now())),
                        );
                    }
                }
            }
            for reader in self.readers.drain(..) {
                // All readers were observed finished before leaving the bounded
                // controller. No unfinished reader can be detached on return.
                if reader.join().is_err() {
                    abort_unconfirmed_child_cleanup();
                }
            }
            if Instant::now() >= self.end {
                abort_unconfirmed_child_cleanup();
            }
            self.cleanup_confirmed = true;
        }
    }

    fn contenders(base: &Path, held: bool) {
        let root = base.join("data");
        let prefix = base.join("prefix");
        for kind in [
            LockKind::ControlHandles,
            LockKind::CatalogHandles,
            LockKind::PolicyOwner,
            LockKind::PolicyEmission,
            LockKind::Supervisor,
            LockKind::Background,
            LockKind::HistoryReaders,
            LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY).unwrap()),
        ] {
            let result = ExclusiveGuard::try_acquire(&root, kind);
            if held {
                assert!(matches!(result, Err(PortError::WriterBusy(_))));
            } else {
                drop(result.unwrap());
            }
        }
        let prefix_result = ExclusiveGuard::try_acquire(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap()),
        );
        let writer_result = WriterLease::try_acquire(&root);
        if held {
            assert!(matches!(prefix_result, Err(PortError::WriterBusy(_))));
            assert!(matches!(writer_result, Err(PortError::WriterBusy(_))));
        } else {
            drop(prefix_result.unwrap());
            drop(writer_result.unwrap());
        }
        for name in ["parent-exit.lock", "runner-exit.lock"] {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(base.join(name))
                .unwrap();
            assert_eq!(file.try_lock_exclusive().unwrap(), !held);
            if !held {
                FileExt::unlock(&file).unwrap();
            }
        }
    }

    fn retained_case(mode: &str) {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let mut child = IsolatedChild::start(temp.path(), mode);
        child.expect("unconfirmed-and-retained");
        // This process has no in-process guard registry for the child. These
        // are actual independent OS contenders, while that child is still live.
        child.assert_alive();
        contenders(temp.path(), true);
        child.assert_alive();
        assert!(!temp.path().join("retained-dropped").exists());
        child.finish(23);
        assert!(!temp.path().join("retained-dropped").exists());
        contenders(temp.path(), false);
    }

    #[test]
    fn reinstall_close_busy_error_drop_and_unwind_keep_all_resources_until_exit() {
        for mode in ["error-drop", "error-unwind", "catalog-busy"] {
            retained_case(mode);
        }
    }

    #[test]
    fn reinstall_control_busy_after_catalog_close_retains_the_complete_bundle() {
        retained_case("control-busy-after-catalog");
    }

    #[test]
    fn reinstall_child_cleanup_requires_exit_and_reader_confirmation_before_return() {
        let end = Instant::now();
        let before = end - PROCESS_POLL;
        for exited in [false, true] {
            for readers_finished in [false, true] {
                assert_eq!(
                    cleanup_step(exited, readers_finished, before, end),
                    if exited && readers_finished {
                        CleanupStep::Complete
                    } else {
                        CleanupStep::Poll
                    }
                );
                assert_eq!(
                    cleanup_step(exited, readers_finished, end, end),
                    CleanupStep::Abort
                );
            }
        }
        for mode in ["cleanup-no-exit", "cleanup-live-reader"] {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let mut child = IsolatedChild::start(temp.path(), mode);
            child.expect("cleanup-failure-ready");
            child.finish(CLEANUP_FAILURE_EXIT);
            // The actual non-returning controller failure must skip stack
            // destructors; a panic/log-and-return would write this sentinel.
            assert!(!temp.path().join("fixture-cleanup-ran").exists());
        }
    }

    #[test]
    fn reinstall_owner_drop_and_unwind_keep_all_resources_until_exit() {
        for mode in ["owner-drop", "owner-unwind", "close-unwind"] {
            retained_case(mode);
        }
    }

    #[test]
    fn reinstall_open_unwind_is_contained_before_first_configuration() {
        for mode in ["open-unwind", "probe-unwind", "catalog-unwind"] {
            retained_case(mode);
        }
    }

    #[test]
    fn reinstall_expired_and_refused_close_keep_original_exclusion() {
        for mode in ["expired", "refused"] {
            retained_case(mode);
        }
    }

    #[test]
    fn reinstall_confirmed_close_returns_resources_without_releasing_them() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let mut child = IsolatedChild::start(temp.path(), "normal");
        child.expect("closed-and-held");
        child.assert_alive();
        contenders(temp.path(), true);
        child.assert_alive();
        child.send("release");
        child.expect("released");
        contenders(temp.path(), false);
        child.finish(0);
    }

    #[test]
    fn reinstall_owner_keeps_earliest_end_and_restores_outer_scope() {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let input = fixture(temp.path(), true, true);
        let root = input.root.clone();
        let before = durable_snapshot(&root);
        let prior_end = runtime_deadline();
        let prior_busy = RUNTIME_BUSY_ALLOWANCE.with(Cell::get);
        let requested = Instant::now() + Duration::from_secs(30);
        let outer_end = requested - Duration::from_secs(5);
        let inner_end = outer_end - Duration::from_secs(5);
        let outer_busy = Duration::from_millis(37);
        let outer = RuntimeDeadlineScope::enter_with_busy(outer_end, outer_busy).unwrap();
        let owner = ReinstallControlOwner::open_read_only(input, requested).unwrap();
        assert_eq!(owner.owned.bundle().end, outer_end);
        assert_eq!(runtime_deadline(), Some(outer_end));
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), outer_busy);
        let inner_busy = Duration::from_millis(11);
        let inner = RuntimeDeadlineScope::enter_with_busy(inner_end, inner_busy).unwrap();
        let (mut owner, _) = owner.read_bound_status().unwrap();
        assert_eq!(owner.owned.bundle().end, inner_end);
        assert_eq!(runtime_deadline(), Some(inner_end));
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), inner_busy);
        drop(inner);
        for panic in [false, true] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                owner.owned.scoped::<()>(|bundle| {
                    assert_eq!(runtime_deadline(), Some(inner_end));
                    require_close_policy(bundle.control.as_ref().unwrap().get()?)?;
                    if panic {
                        panic!("synthetic inner operation unwind");
                    }
                    Err(PortError::Backend(
                        "synthetic inner operation refusal".into(),
                    ))
                })
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert!(matches!(result.unwrap(), Err(PortError::Backend(_))));
            }
            assert_eq!(owner.owned.bundle().end, inner_end);
            assert_eq!(runtime_deadline(), Some(outer_end));
            assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), outer_busy);
            assert!(RUNTIME_BUSY_END.with(Cell::get).is_none());
        }
        drop(outer);
        let (owner, _) = owner.read_bound_status().unwrap();
        assert_eq!(owner.owned.bundle().end, inner_end);
        assert_eq!(runtime_deadline(), prior_end);
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), prior_busy);
        if prior_end.is_none() {
            let timeout: i64 = owner
                .owned
                .bundle()
                .control
                .as_ref()
                .unwrap()
                .get()
                .unwrap()
                .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
                .unwrap();
            assert_eq!(timeout, i64::try_from(BUSY_TIMEOUT.as_millis()).unwrap());
        }
        let resources = owner.close().unwrap().into_resources();
        assert_eq!(durable_snapshot(&root), before);
        assert!(!temp.path().join("retained-dropped").exists());
        drop(resources);
        contenders(temp.path(), false);
        assert_eq!(runtime_deadline(), prior_end);
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), prior_busy);
        assert!(RUNTIME_BUSY_END.with(Cell::get).is_none());
    }

    #[test]
    fn reinstall_query_only_catalog_consumes_held_guards_and_preserves_wal() {
        for live_wal in [false, true] {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let input = fixture(temp.path(), true, live_wal);
            let root = input.root.clone();
            let before = durable_snapshot(&root);
            let original_files = input.files.clone();
            let until = Instant::now() + Duration::from_secs(30);
            let owner = ReinstallControlOwner::open_read_only(input, until).unwrap();
            let closed = owner.close().unwrap();
            let writable = closed.reopen_writable().unwrap();
            let mut catalog = writable
                .open_query_only_catalog(cid("close-fixed-owner"))
                .unwrap();
            assert_eq!(catalog.identity().incarnation, cid("close-catalog"));
            assert_eq!(catalog.identity().generation, u64::from(live_wal));
            assert_eq!(catalog.owned.bundle().end, until);
            catalog
                .owned
                .scoped(|bundle| {
                    let conn = bundle.catalog.as_ref().unwrap().get()?;
                    require_close_policy(conn)?;
                    assert_eq!(
                        conn.query_row("PRAGMA query_only", [], |row| row.get::<_, i64>(0))
                            .unwrap(),
                        1
                    );
                    for statement in [
                        "UPDATE store_metadata SET active_generation=active_generation+1",
                        "CREATE TEMP TABLE forbidden_transfer_write(n INTEGER)",
                    ] {
                        let error = conn.execute_batch(statement).unwrap_err();
                        assert_eq!(
                            error.sqlite_error_code(),
                            Some(rusqlite::ErrorCode::ReadOnly)
                        );
                    }
                    assert!(matches!(
                        SharedGuard::try_acquire(&root, LockKind::CatalogHandles),
                        Err(PortError::WriterBusy(_))
                    ));
                    assert!(matches!(
                        WriterLease::try_acquire(&root),
                        Err(PortError::WriterBusy(_))
                    ));
                    Ok(())
                })
                .unwrap();
            let resources = catalog.close().unwrap().into_resources();
            let after = durable_snapshot(&root);
            for (name, bytes) in &before {
                assert_eq!(after.get(name), Some(bytes), "{name}");
            }
            for (name, bytes) in &after {
                if !before.contains_key(name) {
                    assert_eq!(name, "catalog.db-wal");
                    assert!(bytes.is_empty());
                }
            }
            assert!(resources.input.files == original_files);
            assert!(!temp.path().join("retained-dropped").exists());
            drop(resources);
            assert!(temp.path().join("retained-dropped").exists());
            contenders(temp.path(), false);
        }
    }
}
