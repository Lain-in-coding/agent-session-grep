//! Managed catalog composition. No legacy CatalogStore or raw connection escapes.
//! Content publication reuses the existing durable outbox and generation CAS.
//! Receipt-only observations are atomic without advancing content generation.
use crate::{
    CanonicalBatchManifest, NoopRepoSlugResolver, RelationManifests, SCHEMA_VERSION,
    SEMANTIC_SIMILARITY_FLOOR_DEFAULT, SourceBatch, SqliteControlStore, SqliteStore, WriterLease,
    managed,
    managed_locks::{ExclusiveGuard, LockKind, RootIdentity, SharedGuard},
};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider,
    control::{
        BackgroundControl, CanonicalLocator, ControlId, ControlStore, CycleSeq, CycleState,
        DesiredUpdates, MaintenanceState, ObservationCycle, ReadPolicy, RequestIntersection,
        SelectionRevision, WorkerAuthority,
    },
    managed::{
        DiscoveryObservation, DiscoverySource, Publication, RevisionId, RevisionRef,
        SelectionProof, SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed catalog operation".into())
}

pub(crate) const APPLICATION_ID: i64 = 0x41534732;

/// Match the database and intent using ordinary file names, never Win32 alias
/// trimming, device names or alternate streams. Check before any filesystem I/O.
pub fn validate_catalog_path(path: &Path) -> PortResult<()> {
    if path.as_os_str().is_empty() {
        return Err(invalid());
    }
    #[cfg(windows)]
    for component in path.components() {
        use std::path::{Component, Prefix};
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_)
                | Prefix::VerbatimDisk(_)
                | Prefix::UNC(_, _)
                | Prefix::VerbatimUNC(_, _) => {}
                _ => return Err(invalid()),
            },
            Component::Normal(part) => {
                let name = part.to_str().ok_or_else(invalid)?;
                if name.starts_with(' ')
                    || name.ends_with([' ', '.'])
                    || name.contains([':', '*', '?', '"', '<', '>', '|'])
                    || name.chars().any(char::is_control)
                {
                    return Err(invalid());
                }
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                if matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
                ) || ["COM", "LPT"].iter().any(|prefix| {
                    stem.strip_prefix(prefix).is_some_and(|n| {
                        matches!(
                            n,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                }) {
                    return Err(invalid());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn creation_intent_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".asg-managed-create");
    PathBuf::from(name)
}

/// Existence denies legacy adoption, including an empty marker after a crash.
/// Marker contents never grant ownership or authorize recovery.
pub(crate) fn reject_creation_intent(path: &Path) -> PortResult<()> {
    match std::fs::symlink_metadata(creation_intent_path(path)) {
        Ok(_) => Err(incompatible()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(incompatible()),
    }
}

fn reserve_creation(path: &Path, control: &SqliteControlStore) -> PortResult<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(invalid()),
    }
    let marker = creation_intent_path(path);
    control.create_private_catalog_file(&marker)?;
    // Flush the creation intent before a database inode can exist. The marker
    // remains after success and failure; owned uninstall handles its removal.
    #[cfg(unix)]
    std::fs::File::open(path.parent().ok_or_else(invalid)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| incompatible())?;
    Ok(())
}
fn incompatible() -> PortError {
    PortError::SchemaIncompatible("managed catalog identity is unavailable or incompatible".into())
}
fn changed() -> PortError {
    PortError::GenerationMismatch("managed catalog or policy changed".into())
}
fn history_cache_error(error: crate::managed_cache::CacheError) -> PortError {
    use crate::managed_cache::{CacheError, CacheUnavailable};
    match error {
        CacheError::Unavailable(CacheUnavailable::Busy | CacheUnavailable::Deadline) => {
            PortError::WriterBusy("history cache dependency capture is busy".into())
        }
        CacheError::Unavailable(CacheUnavailable::Storage) => {
            PortError::SourceIo("history cache dependency storage unavailable".into())
        }
        CacheError::Unavailable(
            CacheUnavailable::PolicyChanged | CacheUnavailable::ClockChanged,
        ) => PortError::GenerationMismatch("history cache dependencies changed".into()),
        _ => PortError::SchemaIncompatible("history cache dependencies invalid".into()),
    }
}

fn storage(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            PortError::WriterBusy("managed catalog is busy".into())
        }
        _ => incompatible(),
    }
}

fn acquire_handles(root: &Path) -> PortResult<SharedGuard> {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match SharedGuard::try_acquire(root, LockKind::CatalogHandles) {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// A managed connection owns the shared handle gate; writes also own the writer
/// lease. Its internal legacy store is only a reuse boundary, never a read API.
pub struct ManagedStore {
    inner: SqliteStore,
    installation: ControlId,
    incarnation: ControlId,
    root: RootIdentity,
}

/// A small dependency-preserving housekeeping batch. This is not freshness
/// or purge completion and exposes no source path, receipt or worker token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryRetentionReport {
    pub catalog: crate::managed_history::HistoryCounts,
    pub control_cycles_deleted: usize,
    pub control_barriers_deleted: usize,
    pub has_more: bool,
    pub control_pending: bool,
}

/// Internal parser identity inputs. Never include these in a public response.
pub struct SourceNamespace {
    pub namespace_id: String,
    pub input: String,
}

/// Private scheduling inputs, including unpublished bindings needed for restart.
#[derive(Debug, Clone)]
pub struct BackgroundSource {
    pub binding: SourceBinding,
    pub latest_receipt: Option<RevisionRef>,
    pub indexed_len: Option<u64>,
    pub superseded: bool,
}

impl std::fmt::Debug for SourceNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceNamespace([private])")
    }
}

/// Internal activation capability: the receiving root remains exclusively
/// drained and the writer lease is borrowed, never reacquired by migration.
pub(crate) struct LegacyActivation<'a> {
    pub connection: &'a Connection,
    pub control: &'a SqliteControlStore,
    pub lease: &'a WriterLease,
    pub handles: &'a ExclusiveGuard,
    pub installation: &'a ControlId,
    pub incarnation: &'a ControlId,
    pub now_ms: i64,
    pub deadline: Instant,
}

impl ManagedStore {
    pub(crate) fn activate_legacy_copy(input: LegacyActivation<'_>) -> PortResult<()> {
        crate::managed_maintenance::set_sql_deadline(input.connection, input.deadline)?;
        let root = input.handles.root_identity();
        let lease_root = input.lease.path().parent().ok_or_else(invalid)?;
        if input.handles.kind() != &LockKind::CatalogHandles
            || RootIdentity::read(lease_root)? != root
            || !input.control.matches_root(root)
        {
            return Err(invalid());
        }
        let status = input.control.status()?;
        if status.policy.installation_id != *input.installation
            || status
                .catalog_incarnation
                .as_ref()
                .is_some_and(|current| current != input.incarnation)
        {
            return Err(changed());
        }
        let tx = input.connection.unchecked_transaction().map_err(storage)?;
        managed::activate_legacy_copy_in_tx(
            &tx,
            input.installation.as_str(),
            input.incarnation.as_str(),
            input.now_ms,
        )?;
        tx.commit().map_err(storage)
    }
    /// Explicit empty setup only. Existing catalogs (including legacy ones)
    /// are never adopted or migrated here. Side-path legacy import is separate.
    pub fn create(
        path: &Path,
        control: &SqliteControlStore,
        incarnation: ControlId,
        now_ms: i64,
    ) -> PortResult<Self> {
        validate_catalog_path(path)?;
        if now_ms < 0 || !path.is_absolute() {
            return Err(invalid());
        }
        let root_path = path.parent().ok_or_else(invalid)?;
        let handles = acquire_handles(root_path)?;
        let root = handles.root_identity();
        let policy = admission(control, root)?;
        let lease = WriterLease::try_acquire(root_path)?;
        reserve_creation(path, control)?;
        control.create_private_catalog_file(path)?;
        let conn = connect(path, true)?;
        // Reserve this file for the policy-enforcing facade before any schema
        // work. A crash after initialization but before activation must not let
        // a legacy writer adopt the partly initialized managed catalog.
        conn.pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(storage)?;
        SqliteStore::init(&conn)?;
        let tx = conn.unchecked_transaction().map_err(storage)?;
        managed::initialize_catalog_in_tx(
            &tx,
            policy.installation_id.as_str(),
            incarnation.as_str(),
            now_ms,
        )?;
        tx.commit().map_err(storage)?;
        control.validate_catalog_file(path)?;
        Ok(Self::from_parts(
            conn,
            Some(lease),
            handles,
            policy.installation_id,
            incarnation,
        ))
    }

    pub fn open(path: &Path, control: &SqliteControlStore) -> PortResult<Self> {
        Self::open_existing(path, control, false)
    }

    pub fn open_for_write(path: &Path, control: &SqliteControlStore) -> PortResult<Self> {
        Self::open_existing(path, control, true)
    }

    fn open_existing(
        path: &Path,
        control: &SqliteControlStore,
        writable: bool,
    ) -> PortResult<Self> {
        validate_catalog_path(path)?;
        control.validate_catalog_file(path)?;
        let handles = acquire_handles(path.parent().ok_or_else(invalid)?)?;
        let policy = admission(control, handles.root_identity())?;
        if writable && control.status()?.desired_updates != DesiredUpdates::Running {
            return Err(PortError::WriterBusy(
                "managed updates are paused or stopped".into(),
            ));
        }
        let lease = if writable {
            Some(WriterLease::try_acquire(
                path.parent().ok_or_else(invalid)?,
            )?)
        } else {
            None
        };
        let conn = connect(path, writable)?;
        let incarnation = identity(&conn, &policy.installation_id)?;
        let store = Self::from_parts(conn, lease, handles, policy.installation_id, incarnation);
        if writable {
            store.inner.recover_interrupted()?;
        }
        control.validate_catalog_file(path)?;
        Ok(store)
    }

    fn from_parts(
        conn: Connection,
        lease: Option<WriterLease>,
        handles: SharedGuard,
        installation: ControlId,
        incarnation: ControlId,
    ) -> Self {
        let root = handles.root_identity();
        Self {
            inner: SqliteStore {
                conn: RefCell::new(conn),
                _lease: lease,
                semantic_model_id: RefCell::new(None),
                semantic_similarity_floor: Cell::new(SEMANTIC_SIMILARITY_FLOOR_DEFAULT),
                repo_slug_resolver: RefCell::new(Box::new(NoopRepoSlugResolver)),
                pending_installations: RefCell::new(BTreeMap::new()),
                relocation_clock: crate::unix_ms,
                _catalog_handles: Some(handles),
            },
            installation,
            incarnation,
            root,
        }
    }

    pub fn incarnation(&self) -> &ControlId {
        &self.incarnation
    }

    /// Read the active content generation through an already-authorized
    /// read-only managed handle. This deliberately grants no history-reader
    /// capability and does not create that lock file during inventory.
    pub fn inspected_generation(&self) -> PortResult<u64> {
        self.inner.active_generation()
    }

    /// Reserve the existing installation identity before canonical staging.
    /// The reservation is private memory until an observation receipt commits.
    /// Even an incomplete observation preserves identity across restart, while
    /// its unverified content remains unpublished. No provider file is opened.
    pub fn reserve_namespace(
        &self,
        control: &SqliteControlStore,
        observation: &SourceObservation,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        legacy_input: &str,
    ) -> PortResult<SourceNamespace> {
        if self.inner._lease.is_none() {
            return Err(invalid());
        }
        self.authorize_observation(control, worker, observation)?;
        let path = &observation.binding.source_path;
        let input = self.inner.resolve_or_allocate_installation_namespace(
            observation.binding.provider.as_str(),
            path,
            legacy_input,
        )?;
        let key = agent_session_grep_application::relocation::normalize_absolute_path(path)?;
        let pending = self.inner.pending_installations.borrow().get(&key).cloned();
        let assignment = match pending {
            Some(assignment) => assignment,
            None => SqliteStore::assignment_for_source(&self.inner.conn.borrow(), path)?
                .ok_or_else(incompatible)?,
        };
        Ok(SourceNamespace {
            namespace_id: assignment.namespace_id().into(),
            input,
        })
    }

    /// No source content is opened here. Caller supplies an already verified
    /// full source snapshot, including rewrite/deletion hold classification.
    pub fn commit_source(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        batch: &SourceBatch,
        observation: &SourceObservation,
    ) -> PortResult<Publication> {
        self.commit_source_with_context(
            control,
            worker,
            batch,
            observation,
            &agent_session_grep_ports::source_context::SourcePublicationContext::default(),
            Instant::now() + Duration::from_secs(10),
        )
    }

    pub fn commit_source_with_context(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        batch: &SourceBatch,
        observation: &SourceObservation,
        context: &agent_session_grep_ports::source_context::SourcePublicationContext,
        deadline: Instant,
    ) -> PortResult<Publication> {
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.commit_source_context_inner(
                    control,
                    worker,
                    batch,
                    observation,
                    context,
                    deadline,
                )
            })
        })
    }

    fn commit_source_context_inner(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        batch: &SourceBatch,
        observation: &SourceObservation,
        context: &agent_session_grep_ports::source_context::SourcePublicationContext,
        deadline: Instant,
    ) -> PortResult<Publication> {
        if self.inner._lease.is_none() {
            return Err(invalid());
        }
        self.authorize_observation(control, worker, observation)?;
        let installation = self.inner.installation_for_source_commit(batch)?;
        if installation.as_ref().map(|a| a.namespace_id())
            != observation.binding.namespace_id.as_deref()
        {
            return Err(changed());
        }
        let manifest = observation_manifest(batch, observation, context)?;
        let base = self.generation()?;
        let target = base.checked_add(1).ok_or_else(invalid)?;
        // Validate exact projection facts before writing a durable content
        // intent. Rolling this transaction back publishes neither rows nor FTS.
        let preview = {
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let policy = admission(control, self.root)?;
            let result = crate::managed_source_context::publish_source_with_context_in_tx(
                &tx,
                batch,
                observation,
                context,
                &policy,
                target,
                deadline,
            )?;
            if let Some(assignment) = &installation {
                SqliteStore::persist_installation_in_tx(
                    &tx,
                    &batch.source_path,
                    assignment,
                    observation.committed_at_ms,
                    false,
                )?;
            }
            tx.rollback().map_err(storage)?;
            result
        };
        let relations = RelationManifests::default();
        let pending = if preview.content_changed {
            Some(
                self.inner
                    .begin_index_batch_with_manifest(&manifest, &[], &[], &relations)?,
            )
        } else {
            None
        };
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some(pending) = &pending {
            SqliteStore::verify_pending_in_tx(&tx, pending, &[], &[], &relations, &manifest)?;
        } else {
            let actual: i64 = tx
                .query_row(
                    "SELECT active_generation FROM store_metadata WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if actual != base {
                return Err(changed());
            }
        }
        self.authorize_observation(control, worker, observation)?;
        let policy = admission(control, self.root)?;
        let mut publication = crate::managed_source_context::publish_source_with_context_in_tx(
            &tx,
            batch,
            observation,
            context,
            &policy,
            target,
            deadline,
        )?;
        if let Some(assignment) = &installation {
            SqliteStore::persist_installation_in_tx(
                &tx,
                &batch.source_path,
                assignment,
                observation.committed_at_ms,
                false,
            )?;
        }
        if publication.content_changed != preview.content_changed {
            return Err(changed());
        }
        if publication.content_changed {
            let count = tx.execute("UPDATE store_metadata SET active_generation=?1 WHERE singleton=1 AND active_generation=?2", params![target,base]).map_err(storage)?;
            if count != 1 {
                return Err(changed());
            }
        }
        managed::finalize_publications_in_tx(&tx, std::slice::from_mut(&mut publication))?;
        if publication.receipt.published {
            tx.execute("INSERT INTO source_scans(source_path,scanned_at_ms,len_bytes,fingerprint,provider_id,parser_version) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(source_path) DO UPDATE SET scanned_at_ms=excluded.scanned_at_ms,len_bytes=excluded.len_bytes,fingerprint=excluded.fingerprint,provider_id=excluded.provider_id,parser_version=excluded.parser_version",params![batch.source_path,observation.observed_at_ms,batch.len_bytes,observation.revision_digest,observation.binding.provider.as_str(),observation.parser_version]).map_err(storage)?;
        }
        if let Some(pending) = pending {
            let count=tx.execute("UPDATE index_batches SET state='activated',durable_point='activated',committed_at_ms=?2 WHERE operation_id=?1 AND state='building'",params![pending.operation_id,observation.committed_at_ms]).map_err(storage)?;
            if count != 1 {
                return Err(changed());
            }
        }
        // A concurrent deny remains authoritative even if it commits after
        // this check. Such content cannot be read and its purge remains pending.
        self.authorize_observation(control, worker, observation)?;
        tx.commit().map_err(storage)?;
        self.inner
            .clear_installation_reservations(std::iter::once(batch.source_path.as_str()));
        Ok(publication)
    }

    fn generation(&self) -> PortResult<i64> {
        self.inner
            .conn
            .borrow()
            .query_row(
                "SELECT active_generation FROM store_metadata WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(storage)
    }

    pub fn source_binding_for_locator(
        &self,
        control: &SqliteControlStore,
        provider: SearchProvider,
        locator: &CanonicalLocator,
    ) -> PortResult<Option<SourceBinding>> {
        Ok(self
            .background_sources(control)?
            .into_iter()
            .find(|s| {
                s.binding.provider == provider
                    && CanonicalLocator::parse(&s.binding.source_path).is_ok_and(|p| p == *locator)
            })
            .map(|s| s.binding))
    }

    pub fn reserve_namespace_for_surface(
        &self,
        control: &SqliteControlStore,
        observation: &SourceObservation,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        surface_root: &CanonicalLocator,
        physical_identity: &ControlId,
        deadline: Instant,
    ) -> PortResult<SourceNamespace> {
        control.with_runtime_deadline(deadline, || {
            self.authorize_observation(control, worker, observation)?;
            let locator = CanonicalLocator::parse(&observation.binding.source_path)?;
            if !surface_root.contains(&locator)
                || !matches!(
                    observation.binding.provider.as_str(),
                    "antigravity" | "deepseek-harness"
                )
            {
                return Err(invalid());
            }
            let input = self.inner.resolve_or_allocate_surface_namespace(
                observation.binding.provider.as_str(),
                &observation.binding.source_path,
                surface_root.as_str(),
                physical_identity.as_str(),
            )?;
            let key = agent_session_grep_application::relocation::normalize_absolute_path(
                &observation.binding.source_path,
            )?;
            let pending = self.inner.pending_installations.borrow().get(&key).cloned();
            let assignment = match pending {
                Some(a) => a,
                None => SqliteStore::assignment_for_source(
                    &self.inner.conn.borrow(),
                    &observation.binding.source_path,
                )?
                .ok_or_else(incompatible)?,
            };
            self.authorize_observation(control, worker, observation)?;
            Ok(SourceNamespace {
                namespace_id: assignment.namespace_id().into(),
                input,
            })
        })
    }

    pub fn publication_context(
        &self,
        control: &SqliteControlStore,
        receipt: &RevisionRef,
        deadline: Instant,
    ) -> PortResult<agent_session_grep_ports::source_context::SourcePublicationContext> {
        control.with_runtime_deadline(deadline, || {
            let policy = admission(control, self.root)?;
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn.transaction().map_err(storage)?;
            let result = crate::managed_source_context::publication_context(
                &tx, receipt, &policy, deadline,
            )?;
            tx.rollback().map_err(storage)?;
            if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(result)
        })
    }

    pub fn authority_prior(
        &self,
        control: &SqliteControlStore,
        key: &agent_session_grep_ports::source_context::SourceAuthorityKey,
        deadline: Instant,
    ) -> PortResult<Option<agent_session_grep_ports::source_context::SourceAuthorityPrior>> {
        control.with_runtime_deadline(deadline, || {
            let policy = admission(control, self.root)?;
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn.transaction().map_err(storage)?;
            let result =
                crate::managed_source_context::authority_prior(&tx, key, &policy, deadline)?;
            tx.rollback().map_err(storage)?;
            if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(result)
        })
    }

    pub fn source_current(
        &self,
        receipt: &RevisionRef,
        control: &SqliteControlStore,
        deadline: Instant,
    ) -> PortResult<bool> {
        control.with_runtime_deadline(deadline, || {
            let policy = admission(control, self.root)?;
            let mut conn = self.inner.conn.borrow_mut();
            let tx = conn.transaction().map_err(storage)?;
            if crate::managed_receipt::read_checked(&tx, receipt.revision_id.as_str(), None)?
                != *receipt
            {
                return Err(changed());
            }
            let current = crate::managed_source_context::receipt_context_current(
                &tx,
                receipt.revision_id.as_str(),
                Some(&policy),
                deadline,
            )?;
            tx.rollback().map_err(storage)?;
            if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(current)
        })
    }

    pub fn background_sources(
        &self,
        control: &SqliteControlStore,
    ) -> PortResult<Vec<BackgroundSource>> {
        let policy = admission(control, self.root)?;
        if policy.installation_id != self.installation {
            return Err(changed());
        }
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn.transaction().map_err(storage)?;
        let mut stmt=tx.prepare("SELECT b.source_id,b.source_path,b.provider_id,b.namespace_id,b.root_identity,h.latest_receipt_id,s.len_bytes FROM source_bindings b JOIN source_heads h USING(source_id) LEFT JOIN source_scans s USING(source_path) ORDER BY b.source_id").map_err(storage)?;
        let mut rows = stmt.query([]).map_err(storage)?;
        let mut sources = Vec::new();
        while let Some(row) = rows.next().map_err(storage)? {
            let source_id = SourceId::parse(&row.get::<_, String>(0).map_err(storage)?)?;
            let source_path: String = row.get(1).map_err(storage)?;
            let locator = CanonicalLocator::parse(&source_path)?;
            let provider_wire: String = row.get(2).map_err(storage)?;
            let provider = SearchProvider::parse(&provider_wire)
                .filter(|p| p.as_str() == provider_wire)
                .ok_or_else(incompatible)?;
            let source = ControlId::parse(source_id.as_str())?;
            let namespace_id: Option<String> = row.get(3).map_err(storage)?;
            let root_identity: String = row.get(4).map_err(storage)?;
            ControlId::parse(&root_identity)?;
            if !policy.allows_source(provider, &locator, &source) {
                continue;
            }
            let receipt: Option<String> = row.get(5).map_err(storage)?;
            let latest_receipt = receipt
                .map(|id| crate::managed_receipt::read_checked(&tx, &id, Some(source_id.as_str())))
                .transpose()?;
            let len: Option<i64> = row.get(6).map_err(storage)?;
            let indexed_len = len
                .map(|n| u64::try_from(n).map_err(|_| incompatible()))
                .transpose()?;
            sources.push(BackgroundSource {
                binding: SourceBinding {
                    source_id,
                    source_path,
                    provider,
                    namespace_id,
                    root_identity,
                },
                latest_receipt,
                indexed_len,
                superseded: !crate::managed_source_context::source_read_eligible(
                    &tx,
                    source.as_str(),
                )?,
            });
        }
        drop(rows);
        drop(stmt);
        tx.commit().map_err(storage)?;
        if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
            return Err(changed());
        }
        Ok(sources)
    }

    /// Repair catalog identity and committed source heads already verified by
    /// this live connection. Never restore permissions, pause, or barrier state.
    pub fn reconcile_progress(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
    ) -> PortResult<()> {
        let policy = admission(control, self.root)?;
        if policy.installation_id != self.installation
            || worker.installation_id() != &self.installation
            || !worker.is_bound_to(control)
        {
            return Err(invalid());
        }
        control.reconcile_catalog_summary(
            control.status()?.policy.control_seq,
            worker,
            &self.incarnation,
            crate::unix_ms()?,
        )?;
        for source in self.background_sources(control)? {
            if let Some(receipt) = source.latest_receipt {
                if receipt.catalog_incarnation != self.incarnation.as_str() {
                    let conn = self.inner.conn.borrow();
                    if !managed::retained_receipt_matches(
                        &conn,
                        &receipt,
                        self.incarnation.as_str(),
                        self.generation()?,
                    )? {
                        return Err(incompatible());
                    }
                    // Restored evidence remains readable, but is not current
                    // control progress. Only a fresh source observation repairs
                    // the receipt and its source projection provenance.
                    continue;
                }
                control.reconcile_source_summary(
                    control.status()?.policy.control_seq,
                    worker,
                    &source.binding,
                    &receipt,
                )?;
            }
        }
        Ok(())
    }

    /// Run one bounded history batch while owning the existing catalog writer
    /// lease. Live requests hold the separate shared reader guard even while
    /// latest drops a SQLite snapshot, so retention never invalidates an active
    /// barrier or continuation. Busy/unknown dependencies authorize no cleanup.
    pub fn retain_history(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        deadline: Instant,
    ) -> PortResult<HistoryRetentionReport> {
        control.with_runtime_deadline(deadline, || {
            if self.inner._lease.is_none()
                || !worker.is_bound_to(control)
                || worker.installation_id() != &self.installation
            {
                return Err(invalid());
            }
            worker.validate()?;
            let policy = admission(control, self.root)?;
            let readers =
                ExclusiveGuard::try_acquire(control.private_root(), LockKind::HistoryReaders)?;
            let captured = control.capture_history_dependencies(worker, &readers, deadline)?;
            if captured.installation != self.installation
                || captured.policy_epoch != policy.policy_epoch
                || captured.incarnation.as_ref() != Some(&self.incarnation)
            {
                return Err(changed());
            }
            let cache = crate::managed_cache::ManagedCache::at(control.private_root(), control)
                .map_err(history_cache_error)?;
            let cache_revisions = cache
                .history_revisions(control, &readers, crate::unix_ms()?, deadline)
                .map_err(history_cache_error)?;
            let pruned = {
                let mut conn = self.inner.conn.borrow_mut();
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(storage)?;
                let (generation, destructive_epoch): (i64, i64) = tx.query_row(
                "SELECT active_generation,destructive_epoch FROM store_metadata WHERE singleton=1",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(storage)?;
                let dependencies = crate::managed_history::HistoryDependencies {
                    installation_id: self.installation.clone(),
                    snapshot: agent_session_grep_ports::managed::ReadSnapshot {
                        catalog_incarnation: self.incarnation.as_str().into(),
                        generation,
                        destructive_epoch,
                        policy_epoch: captured.policy_epoch.get(),
                    },
                    keep_cycles: captured.cycles.clone(),
                    keep_receipts: captured.receipts.clone(),
                };
                let result = crate::managed_history::prune_in_tx(
                    &tx,
                    &dependencies,
                    &cache_revisions,
                    crate::managed_history::HistoryLimits::default(),
                    deadline,
                )?;
                let now = admission(control, self.root)?;
                if now.policy_epoch != captured.policy_epoch
                    || now.control_seq != captured.control_seq
                {
                    return Err(changed());
                }
                readers.validate_current(control.private_root())?;
                if Instant::now() >= deadline {
                    return Err(PortError::WriterBusy(
                        "history retention deadline reached".into(),
                    ));
                }
                tx.commit().map_err(storage)?;
                result
            };
            let mut report = HistoryRetentionReport {
                catalog: pruned.counts,
                has_more: pruned.has_more,
                ..HistoryRetentionReport::default()
            };
            match pruned.cycles {
                crate::managed_history::CycleRetention::PendingCatalogPrune => {
                    report.control_pending = true;
                }
                crate::managed_history::CycleRetention::Complete(tokens) => {
                    match control.prune_history(worker, &readers, &captured, &tokens, deadline) {
                        Ok(counts) => {
                            report.control_cycles_deleted = counts.cycles;
                            report.control_barriers_deleted = counts.barriers;
                            report.has_more |= counts.has_more;
                        }
                        Err(PortError::WriterBusy(_) | PortError::GenerationMismatch(_)) => {
                            report.control_pending = true;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(report)
        })
    }

    pub fn commit_discovery(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: &[SourceId],
        _now_ms: i64,
    ) -> PortResult<()> {
        self.commit_discovery_with_deadline(
            control,
            worker,
            cycle,
            selection,
            sources,
            Instant::now() + Duration::from_secs(10),
        )
    }

    /// Complete one selection using the caller's original cycle deadline.
    /// Requires the existing writer lease and a root-bound observing worker.
    /// Exact source/context receipts and policy are checked in this transaction.
    pub fn commit_discovery_with_deadline(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: &[SourceId],
        deadline: Instant,
    ) -> PortResult<()> {
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.publish_discovery(control, worker, cycle, selection, Some(sources), deadline)
            })
        })
    }

    /// Fence older discovery proofs before filesystem observation begins. A
    /// crash or failed enumeration must leave this attempt visibly incomplete.
    pub fn begin_discovery(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        _now_ms: i64,
    ) -> PortResult<()> {
        self.begin_discovery_with_deadline(
            control,
            worker,
            cycle,
            selection,
            Instant::now() + Duration::from_secs(10),
        )
    }

    /// Record the incomplete fence before enumeration, under the same original
    /// deadline as the eventual source commits and complete discovery.
    pub fn begin_discovery_with_deadline(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        deadline: Instant,
    ) -> PortResult<()> {
        control.with_runtime_deadline(deadline, || {
            self.with_context_sql_deadline(deadline, || {
                self.publish_discovery(control, worker, cycle, selection, None, deadline)
            })
        })
    }

    fn with_context_sql_deadline<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> PortResult<T>,
    ) -> PortResult<T> {
        context_deadline(deadline)?;
        let mut reset = ContextSqlDeadline {
            connection: &self.inner.conn,
            active: true,
        };
        {
            let conn = self.inner.conn.borrow();
            conn.busy_handler(Some(|_| false)).map_err(storage)?;
            conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
                .map_err(storage)?;
        }
        let result = operation().and_then(|value| {
            context_deadline(deadline)?;
            Ok(value)
        });
        let restored = reset.restore();
        match (result, restored) {
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn publish_discovery(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        cycle: &ObservationCycle,
        selection: &SelectionRevision,
        sources: Option<&[SourceId]>,
        deadline: Instant,
    ) -> PortResult<()> {
        context_deadline(deadline)?;
        if self.inner._lease.is_none() {
            return Err(invalid());
        }
        let policy = admission(control, self.root)?;
        worker.validate()?;
        if !worker.is_bound_to(control)
            || policy.installation_id != self.installation
            || cycle.policy_epoch != policy.policy_epoch
            || cycle.token.worker_boot_id != *worker.boot_id()
            || control.status()?.desired_updates != DesiredUpdates::Running
        {
            return Err(changed());
        }
        let active = control.cycle(cycle.token.cycle_seq)?;
        if active.state != CycleState::Observing
            || active.token != cycle.token
            || active.started_control_seq != cycle.started_control_seq
            || !active.selections.iter().any(|s| &s.selection == selection)
        {
            return Err(changed());
        }
        let selected = policy
            .selections
            .iter()
            .find(|s| {
                s.enabled
                    && s.id == selection.selection_id
                    && s.revision == selection.revision
                    && s.root_identity.as_ref() == Some(&selection.root_identity)
            })
            .ok_or_else(changed)?;
        let mut conn = self.inner.conn.borrow_mut();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut receipts = Vec::new();
        if sources
            .is_some_and(|s| s.len() > agent_session_grep_ports::source_context::MAX_AUTHORITY_KEYS)
        {
            return Err(invalid());
        }
        for source in sources.unwrap_or_default() {
            context_deadline(deadline)?;
            let (path,provider,receipt):(String,String,String)=tx.query_row("SELECT b.source_path,b.provider_id,h.latest_receipt_id FROM source_bindings b JOIN source_heads h USING(source_id) WHERE source_id=?1",[source.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(storage)?;
            let locator = CanonicalLocator::parse(&path)?;
            if provider != selected.region.provider.as_str()
                || !selected.region.matches(selected.region.provider, &locator)
                || !policy.allows_source(
                    selected.region.provider,
                    &locator,
                    &ControlId::parse(source.as_str())?,
                )
            {
                return Err(changed());
            }
            receipts.push(DiscoverySource {
                source_id: source.clone(),
                revision_id: RevisionId::parse(&receipt)?,
            });
        }
        let observation = DiscoveryObservation {
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: worker.boot_id().as_str().into(),
            catalog_incarnation: self.incarnation.as_str().into(),
            policy_epoch: policy.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.ok_or_else(invalid)?.get(),
            selection: SelectionProof {
                selection_id: selection.selection_id.as_str().into(),
                selection_revision: selection.revision.get(),
                root_identity: selection.root_identity.as_str().into(),
            },
            sources: receipts,
            complete: sources.is_some(),
        };
        crate::managed_discovery::publish_with_deadline_in_tx(
            &tx,
            &observation,
            Some(&policy),
            deadline,
        )?;
        if admission(control, self.root)?.policy_epoch != policy.policy_epoch {
            return Err(changed());
        }
        context_deadline(deadline)?;
        tx.commit().map_err(storage)
    }

    fn authorize_observation(
        &self,
        control: &SqliteControlStore,
        worker: &crate::control::LockedWorkerAuthority<'_>,
        o: &SourceObservation,
    ) -> PortResult<()> {
        let policy = admission(control, self.root)?;
        worker.validate()?;
        if !worker.is_bound_to(control)
            || worker.installation_id() != &self.installation
            || policy.installation_id != self.installation
            || o.catalog_incarnation != self.incarnation.as_str()
            || o.worker_boot_id != worker.boot_id().as_str()
            || o.policy_epoch != policy.policy_epoch.get()
            || control.status()?.desired_updates != DesiredUpdates::Running
        {
            return Err(changed());
        }
        let source = ControlId::parse(o.binding.source_id.as_str())?;
        let locator = CanonicalLocator::parse(&o.binding.source_path)?;
        if !policy.allows_source(o.binding.provider, &locator, &source) {
            return Err(invalid());
        }
        let cycle = control.cycle(CycleSeq::new(o.cycle_seq)?)?;
        if cycle.state != CycleState::Observing
            || cycle.token.worker_boot_id != *worker.boot_id()
            || cycle.policy_epoch != policy.policy_epoch
            || cycle.started_control_seq.map(|s| s.get()) != Some(o.started_control_seq)
            || o.selections.is_empty()
        {
            return Err(changed());
        }
        for proof in &o.selections {
            let valid = policy.selections.iter().any(|s| {
                s.enabled
                    && s.id.as_str() == proof.selection_id
                    && s.revision.get() == proof.selection_revision
                    && s.root_identity.as_ref().map(ControlId::as_str)
                        == Some(proof.root_identity.as_str())
                    && s.region.matches(o.binding.provider, &locator)
                    && cycle.selections.iter().any(|c| {
                        c.selection.selection_id == s.id
                            && c.selection.revision == s.revision
                            && c.selection.root_identity.as_str() == proof.root_identity
                    })
            });
            if !valid {
                return Err(changed());
            }
        }
        Ok(())
    }

    /// Caller must still recheck policy while holding the emission gate before
    /// publishing rendered output. The callback cannot retain a SQLite handle.
    pub fn with_read<T>(
        &self,
        control: &SqliteControlStore,
        request: RequestIntersection,
        deadline: Instant,
        read: impl FnOnce(&managed::ManagedRead<'_>) -> PortResult<T>,
    ) -> PortResult<T> {
        control.with_runtime_deadline(deadline, || {
            admission(control, self.root)?;
            let _history_read = loop {
                if Instant::now() >= deadline {
                    return Err(PortError::WriterBusy(
                        "managed history admission deadline reached".into(),
                    ));
                }
                match SharedGuard::try_acquire(control.private_root(), LockKind::HistoryReaders) {
                    Ok(guard) => break guard,
                    Err(PortError::WriterBusy(_)) => std::thread::sleep(
                        Duration::from_millis(1)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    Err(error) => return Err(error),
                }
            };
            let mut policy = admission(control, self.root)?;
            policy.request_intersection = request;
            if policy.installation_id != self.installation {
                return Err(changed());
            }
            let conn = self.inner.conn.borrow();
            let snapshot = managed::ManagedRead::begin_authorized(
                &conn,
                &policy,
                self.incarnation.as_str(),
                deadline,
            )?;
            let result = read(&snapshot)?;
            let current = admission(control, self.root)?;
            if current.policy_epoch != policy.policy_epoch {
                return Err(changed());
            }
            Ok(result)
        })
    }
}

fn context_deadline(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(PortError::WriterBusy(
            "managed catalog deadline reached".into(),
        ))
    } else {
        Ok(())
    }
}
struct ContextSqlDeadline<'a> {
    connection: &'a RefCell<Connection>,
    active: bool,
}
impl ContextSqlDeadline<'_> {
    fn restore(&mut self) -> PortResult<()> {
        let conn = self.connection.borrow();
        conn.progress_handler(0, None::<fn() -> bool>)
            .map_err(storage)?;
        // The deadline scope installed `busy_handler(|_| false)`; leaving it
        // in place made every later call fail immediately on transient BUSY
        // instead of waiting. Reinstate the connection's busy timeout, which
        // replaces the custom handler.
        conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MILLIS))
            .map_err(storage)?;
        self.active = false;
        Ok(())
    }
}
impl Drop for ContextSqlDeadline<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.restore();
        }
    }
}

fn admission(control: &SqliteControlStore, root: RootIdentity) -> PortResult<ReadPolicy> {
    if !control.matches_root(root) {
        return Err(invalid());
    }
    let policy = control.read_policy(RequestIntersection::Selected)?;
    if policy.maintenance.state != MaintenanceState::Idle || policy.emission_blocked() {
        return Err(PortError::WriterBusy(
            "managed control fence is active".into(),
        ));
    }
    Ok(policy)
}
/// Wait budget for transient SQLITE_BUSY on managed connections. Restored after
/// any deadline-scoped call reinstalls its immediate busy handler.
const BUSY_TIMEOUT_MILLIS: u64 = 250;

fn connect(path: &Path, writable: bool) -> PortResult<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
        .map_err(storage)?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MILLIS))
        .map_err(storage)?;
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .map_err(storage)?;
    SqliteStore::register_scalar_functions(&conn)?;
    Ok(conn)
}
fn identity(conn: &Connection, installation: &ControlId) -> PortResult<ControlId> {
    let application_id: i64 = conn
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(storage)?;
    if application_id != APPLICATION_ID {
        return Err(incompatible());
    }
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(storage)?;
    if version != SCHEMA_VERSION {
        return Err(incompatible());
    }
    crate::managed_source_context::validate_schema(conn)?;
    let (actual,incarnation):(String,String)=conn.query_row("SELECT installation_id,catalog_incarnation FROM catalog_meta CROSS JOIN store_metadata WHERE catalog_meta.singleton=1 AND store_metadata.singleton=1 AND managed_mode=1 AND projection_contract_version=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
    if actual != installation.as_str() {
        return Err(incompatible());
    }
    ControlId::parse(&incarnation).map_err(|_| incompatible())
}

fn observation_manifest(
    batch: &SourceBatch,
    o: &SourceObservation,
    context: &agent_session_grep_ports::source_context::SourcePublicationContext,
) -> PortResult<CanonicalBatchManifest> {
    // Commit the complete immutable input to a digest; no original transcript
    // text or native resume values are retained in the outbox detail columns.
    let claims: Vec<_> = batch
        .resume_claims
        .iter()
        .map(crate::resume_claim_value)
        .collect();
    let activities: Vec<_> = batch
        .activities
        .iter()
        .map(|a| serde_json::json!([a.message_id, a.activity]))
        .collect();
    let usages: Vec<_> = batch
        .usage_events
        .iter()
        .map(|u| serde_json::json!([u.session_id, u.message_id, u.usage]))
        .collect();
    let proofs: Vec<_> = o
        .selections
        .iter()
        .map(|p| serde_json::json!([p.selection_id, p.selection_revision, p.root_identity]))
        .collect();
    let context_bytes = crate::managed_source_context::context_manifest(context)?;
    let context_value: serde_json::Value =
        serde_json::from_slice(&context_bytes).map_err(|_| invalid())?;
    let value = serde_json::json!({"context":context_value,"format":"asg.managed-observation/v1","entries":batch.entries,"placements":batch.placements,"edges":batch.edges,"activities":activities,"usages":usages,"claims":claims,"complete":batch.relation_complete,"length":batch.len_bytes,"fingerprint":batch.fingerprint,"provider":batch.provider_id,
        "source":[o.binding.source_id.as_str(),o.binding.source_path,o.binding.provider.as_str(),o.binding.namespace_id,o.binding.root_identity],"revision":[o.revision_id.as_str(),o.revision_digest],"parser":o.parser_version,"state":format!("{:?}",o.state),"token":[o.cycle_seq,o.worker_boot_id],"incarnation":o.catalog_incarnation,"epoch":o.policy_epoch,"started":o.started_control_seq,"observed":o.observed_at_ms,"committed":o.committed_at_ms,"selections":proofs,"repositories":o.repositories});
    let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    Ok(CanonicalBatchManifest {
        upsert_ids: Vec::new(),
        delete_ids: Vec::new(),
        relation_upserts_json: "[]".into(),
        relation_deletes_json: "[]".into(),
        source_replacements_json:
            serde_json::json!([{"format":"asg.managed-observation/v1","digest":digest}]).to_string(),
        relocation_json: "null".into(),
        operation_digest: digest,
    })
}
