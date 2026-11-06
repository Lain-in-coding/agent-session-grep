//! Complete current-schema control commitments for the private keep-data
//! transfer. All row and relationship reads share one deferred transaction.
use super::{
    reinstall_records::{TABLE_COUNT, TableDigest},
    *,
};
use rusqlite::{Row, types::ValueRef};
use sha2::{Digest, Sha256};

/// Borrowed real guards; recorded hashes and roots never substitute for these.
pub struct ReinstallSnapshotBinding<'a, 'held> {
    pub control_root: RootIdentity,
    pub owner: &'a ControlRootGuard<'held>,
    pub installation: &'a InstallationLockAuthority<'held>,
    pub sealed: SealedControlFile,
}

pub struct ReinstallPreparationRead<'a, 'held> {
    pub binding: ReinstallSnapshotBinding<'a, 'held>,
    pub context: &'a ReinstallContext,
    pub files: &'a ReinstallFiles,
}

/// Two independent image commitments, produced from one actual before snapshot.
/// It proves neither filesystem publication nor continuing lock ownership.
pub struct ReinstallCommitmentPair {
    prep: ReinstallPrep,
}

impl ReinstallCommitmentPair {
    pub fn into_preparation(self) -> ReinstallPrep {
        self.prep
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinstallImageMatch {
    Before,
    After,
}

impl SqliteControlStore {
    pub fn prepare_reinstall_commitments_with_deadline(
        &self,
        input: ReinstallPreparationRead<'_, '_>,
        end: Instant,
    ) -> PortResult<ReinstallCommitmentPair> {
        self.with_runtime_deadline(end, || {
            let (before, after) =
                self.reinstall_images(&input.binding, input.context, input.files, true)?;
            let prep = ReinstallPrep::new(
                input.context.clone(),
                input.files.clone(),
                before,
                after.ok_or_else(corrupt)?,
            )?;
            Ok(ReinstallCommitmentPair { prep })
        })
    }

    /// Compute ONLY the current image. Even at q+1 this never computes q+2,
    /// reconstructs the old image, writes a record or calls recover_maintenance.
    pub fn compare_reinstall_commitment_with_deadline(
        &self,
        binding: ReinstallSnapshotBinding<'_, '_>,
        prep: &ReinstallPrep,
        end: Instant,
    ) -> PortResult<ReinstallImageMatch> {
        self.with_runtime_deadline(end, || {
            prep.validate()?;
            let (current, _) =
                self.reinstall_images(&binding, prep.context(), prep.files(), false)?;
            if current == *prep.before() {
                Ok(ReinstallImageMatch::Before)
            } else if current == *prep.after() {
                Ok(ReinstallImageMatch::After)
            } else {
                Err(conflict())
            }
        })
    }

    fn reinstall_images(
        &self,
        binding: &ReinstallSnapshotBinding<'_, '_>,
        context: &ReinstallContext,
        files: &ReinstallFiles,
        derive: bool,
    ) -> PortResult<(ReinstallImage, Option<ReinstallImage>)> {
        runtime_tick()?;
        context.validate()?;
        files.validate()?;
        if binding.control_root != self.root_identity
            || binding.owner.identity != self.root_identity
            || binding.sealed != SealedControlFile::from_recorded(files.control_main.identity)
        {
            return Err(invalid());
        }
        self.validate_reinstall_read_binding(binding)?;
        let handles = ReinstallHandlesPin::open(&self.private_root)?;
        let result = {
            let mut conn = self.conn.borrow_mut();
            // This entry consumes the foundation's already configured connection;
            // it cannot silently turn an ordinary connection into a transfer open.
            if !conn
                .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
                .map_err(sql_error)?
            {
                return Err(invalid());
            }
            configure_runtime_deadline(&conn)?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(sql_error)?;
            for (query, expected) in [
                ("PRAGMA user_version", VERSION),
                ("PRAGMA application_id", APPLICATION_ID),
                ("PRAGMA wal_autocheckpoint", 0),
                ("PRAGMA journal_size_limit", -1),
            ] {
                if tx
                    .query_row(query, [], |r| r.get::<_, i64>(0))
                    .map_err(sql_error)?
                    != expected
                {
                    return Err(corrupt());
                }
            }
            if tx
                .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                .map_err(sql_error)?
                != "wal"
            {
                return Err(corrupt());
            }
            validate_schema(&tx)?;
            let unexpected: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                     WHERE name LIKE 'sqlite_%'
                       AND NOT (type='index' AND sql IS NULL
                                AND name GLOB 'sqlite_autoindex_*'))",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            require(!unexpected)?;
            let state = read_meta(&tx, context, derive)?;
            binding
                .installation
                .validate_bound(self, || ControlId::parse(&state.installation))?;
            binding
                .installation
                .guard
                .validate_current(&binding.installation.prefix)?;
            let result = stream(&tx, context, files, &state, derive)?;
            runtime_tick()?;
            tx.commit().map_err(sql_error)?;
            result
        };
        handles.validate()?;
        self.validate_reinstall_read_binding(binding)?;
        binding
            .installation
            .validate_bound(self, || ControlId::parse(&context.installation))?;
        runtime_tick()?;
        Ok(result)
    }

    fn validate_reinstall_read_binding(
        &self,
        binding: &ReinstallSnapshotBinding<'_, '_>,
    ) -> PortResult<()> {
        binding.owner.validate(self)?;
        binding.owner.guard.validate_current(&self.private_root)?;
        binding
            .installation
            .guard
            .validate_current(&binding.installation.prefix)?;
        self.validate_live_root()?;
        self.verify_connection_file(binding.sealed)?;
        verify_sidecars(&Self::path(&self.private_root))?;
        if binding.owner.guard.child_exists("control.db-journal")? {
            return Err(corrupt());
        }
        runtime_tick()
    }
}

trait CellFrame<'a>: Sized {
    fn decode(value: ValueRef<'a>) -> PortResult<Self>;
    fn feed(&self, hash: &mut Sha256);
}

impl<'a> CellFrame<'a> for i64 {
    fn decode(value: ValueRef<'a>) -> PortResult<Self> {
        match value {
            ValueRef::Integer(value) => Ok(value),
            _ => Err(corrupt()),
        }
    }
    fn feed(&self, hash: &mut Sha256) {
        hash.update([1]);
        hash.update(self.to_be_bytes());
    }
}

impl<'a> CellFrame<'a> for &'a str {
    fn decode(value: ValueRef<'a>) -> PortResult<Self> {
        match value {
            ValueRef::Text(bytes) => std::str::from_utf8(bytes).map_err(|_| corrupt()),
            _ => Err(corrupt()),
        }
    }
    fn feed(&self, hash: &mut Sha256) {
        hash.update([2]);
        hash.update((self.len() as u64).to_be_bytes());
        hash.update(self.as_bytes());
    }
}

#[derive(Clone, Copy)]
struct Locator<'a>(&'a str);

impl<'a> CellFrame<'a> for Locator<'a> {
    fn decode(value: ValueRef<'a>) -> PortResult<Self> {
        let text = <&str>::decode(value)?;
        CanonicalLocator::parse(text).map_err(|_| corrupt())?;
        Ok(Self(text))
    }
    fn feed(&self, hash: &mut Sha256) {
        hash.update([3]);
        hash.update((self.0.len() as u64).to_be_bytes());
        hash.update(Sha256::digest(self.0.as_bytes()));
    }
}

impl<'a, T: CellFrame<'a>> CellFrame<'a> for Option<T> {
    fn decode(value: ValueRef<'a>) -> PortResult<Self> {
        match value {
            ValueRef::Null => Ok(None),
            value => T::decode(value).map(Some),
        }
    }
    fn feed(&self, hash: &mut Sha256) {
        match self {
            Some(value) => value.feed(hash),
            None => hash.update([0]),
        }
    }
}

macro_rules! row_type {
    ($name:ident, $table:literal, $order:literal, {$($field:ident:$ty:ty),+ $(,)?}) => {
        #[derive(Clone)]
        struct $name<'a> { $($field: $ty),+ }
        impl<'a> $name<'a> {
            const COLUMNS: &'static [&'static str] = &[$(stringify!($field)),+];
            const TABLE: &'static str = $table;
            const ORDER: &'static str = $order;
            fn decode(row: &'a Row<'_>) -> PortResult<Self> {
                let mut column = 0;
                let result = Self { $($field: {
                    let value = <$ty>::decode(row.get_ref(column).map_err(sql_error)?)?;
                    column += 1;
                    value
                }),+ };
                if column != Self::COLUMNS.len() { return Err(corrupt()); }
                Ok(result)
            }
            fn feed(&self, hash: &mut Sha256) {
                let mut column = 0u16;
                $(hash.update(column.to_be_bytes()); self.$field.feed(hash); column += 1;)+
                debug_assert_eq!(usize::from(column), Self::COLUMNS.len());
            }
        }
    };
}

row_type!(MetaRow, "control_meta", "singleton", {
    singleton:i64,schema_version:i64,installation_id:&'a str,policy_epoch:i64,
    control_seq:i64,next_cycle_seq:i64,catalog_incarnation:Option<&'a str>,
    restart_request_seq:i64,desired_updates:&'a str,autostart_enabled:i64,
    maintenance_state:&'a str,maintenance_owner:Option<&'a str>,
    maintenance_phase:Option<&'a str>,supervisor_failed:i64
});
row_type!(SelectionRow, "selections", "selection_id COLLATE BINARY", {
    selection_id:&'a str,provider_id:&'a str,canonical_locator:Locator<'a>,
    root_kind:&'a str,root_identity:Option<&'a str>,enabled:i64,revision:i64,
    created_at_ms:i64,revoked_at_ms:Option<i64>
});
row_type!(ExclusionRow, "exclusions", "exclusion_id COLLATE BINARY", {
    exclusion_id:&'a str,provider_id:&'a str,canonical_locator:Option<Locator<'a>>,
    region_kind:&'a str,source_id:Option<&'a str>,revision:i64,
    created_policy_epoch:i64,created_at_ms:i64
});
row_type!(WorkerRow, "worker_state", "singleton", {
    singleton:i64,boot_id:Option<&'a str>,pid_hint:Option<i64>,
    heartbeat_at_ms:Option<i64>,effective_state:&'a str,last_error:Option<&'a str>
});
row_type!(SourceRow, "source_updates", "source_id COLLATE BINARY", {
    source_id:&'a str,provider_id:&'a str,last_attempt_at_ms:Option<i64>,
    last_observed_cycle:Option<i64>,indexed_revision:Option<&'a str>,
    receipt_cycle:Option<i64>,catalog_incarnation:Option<&'a str>,
    catalog_generation:Option<i64>,coverage:&'a str,update_state:&'a str,
    error_code:Option<&'a str>,backfill_state:&'a str,missing_first_cycle:Option<i64>,
    missing_confirm_cycle:Option<i64>,confirmation_boot_id:Option<&'a str>,
    confirmation_root_identity:Option<&'a str>,confirmation_policy_epoch:Option<i64>,
    rewrite_candidate_digest:Option<&'a str>,rewrite_first_cycle:Option<i64>,
    rewrite_confirm_cycle:Option<i64>,confirmation_first_monotonic_ms:Option<i64>
});
row_type!(CycleRow, "cycles", "cycle_seq", {
    cycle_seq:i64,worker_boot_id:Option<&'a str>,policy_epoch:i64,state:&'a str,
    admitted_control_seq:i64,started_control_seq:Option<i64>,
    started_at_ms:Option<i64>,completed_at_ms:Option<i64>
});
row_type!(CycleSelectionRow, "cycle_selections", "cycle_seq,selection_id COLLATE BINARY", {
    cycle_seq:i64,selection_id:&'a str,selection_revision:i64,discovery_complete:i64,
    root_identity:Option<&'a str>,discovered_count:i64,observed_count:i64,
    committed_count:i64,error_code:Option<&'a str>
});
row_type!(BarrierRow, "barriers", "barrier_id COLLATE BINARY", {
    barrier_id:&'a str,policy_epoch:i64,admission_control_seq:i64,required_cycle_seq:i64,
    state:&'a str,requested_wait_ms:i64,admitted_at_ms:i64,
    completed_cycle_seq:Option<i64>,catalog_incarnation:Option<&'a str>,
    error_code:Option<&'a str>
});
row_type!(BarrierSelectionRow, "barrier_selections", "barrier_id COLLATE BINARY,selection_id COLLATE BINARY", {
    barrier_id:&'a str,selection_id:&'a str,selection_revision:i64
});
row_type!(RevocationRow, "revocation_intents", "intent_id COLLATE BINARY", {
    intent_id:&'a str,policy_epoch:i64,owner_nonce:Option<&'a str>,state:&'a str,
    created_at_ms:i64,settled_at_ms:Option<i64>
});
row_type!(PurgeRow, "purge_jobs", "job_id COLLATE BINARY", {
    job_id:&'a str,policy_epoch:i64,selection_id:Option<&'a str>,
    selection_revision:Option<i64>,state:&'a str,progress_key:Option<&'a str>,
    owner_nonce:Option<&'a str>,attempts:i64,last_error:Option<&'a str>,
    created_at_ms:i64,updated_at_ms:i64
});
row_type!(ArtifactRow, "private_artifacts", "artifact_id COLLATE BINARY", {
    artifact_id:&'a str,kind:&'a str,relative_locator:&'a str,policy_epoch:i64,
    owner_nonce:Option<&'a str>,state:&'a str,digest:Option<&'a str>
});
row_type!(ArtifactSourceRow, "artifact_sources", "artifact_id COLLATE BINARY,source_id COLLATE BINARY", {
    artifact_id:&'a str,source_id:&'a str
});
row_type!(BackupRow, "backup_manifests", "backup_id COLLATE BINARY", {
    backup_id:&'a str,purpose:&'a str,relative_locator:&'a str,
    catalog_incarnation:&'a str,catalog_generation:i64,schema_version:i64,
    digest:&'a str,size_bytes:i64,state:&'a str,created_at_ms:i64
});
row_type!(BackupSourceRow, "backup_sources", "backup_id COLLATE BINARY,source_id COLLATE BINARY", {
    backup_id:&'a str,source_id:&'a str
});
row_type!(ReceiptRow, "update_receipts", "update_id COLLATE BINARY", {
    update_id:&'a str,phase:&'a str,from_version:&'a str,to_version:&'a str,
    target:&'a str,source_commit:&'a str,archive_digest:&'a str,manifest_digest:&'a str,
    backup_id:Option<&'a str>,schema_before:Option<i64>,schema_after:Option<i64>,
    generation_before:Option<i64>,generation_after:Option<i64>,error_code:Option<&'a str>,
    started_at_ms:i64,updated_at_ms:i64,completed_at_ms:Option<i64>
});

struct Meta {
    installation: String,
    incarnation: String,
    epoch: i64,
    sequence: i64,
    next_cycle: i64,
}

fn require(ok: bool) -> PortResult<()> {
    if ok { Ok(()) } else { Err(corrupt()) }
}

fn identifier(value: &str) -> PortResult<()> {
    ControlId::parse(value).map(drop).map_err(|_| corrupt())
}

fn identifiers<'a>(values: impl IntoIterator<Item = &'a str>) -> PortResult<()> {
    for value in values {
        identifier(value)?;
    }
    Ok(())
}

fn nonnegative(values: impl IntoIterator<Item = i64>) -> PortResult<()> {
    require(values.into_iter().all(|value| value >= 0))
}

fn failure(value: Option<&str>) -> PortResult<()> {
    value.map(failure_decode).transpose().map(drop)
}

fn read_meta(conn: &Connection, context: &ReinstallContext, derive: bool) -> PortResult<Meta> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {} FROM control_meta",
            MetaRow::COLUMNS.join(",")
        ))
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let row = MetaRow::decode(rows.next().map_err(sql_error)?.ok_or_else(corrupt)?)?;
    row.validate()?;
    let incarnation = row.catalog_incarnation.ok_or_else(corrupt)?;
    require(
        row.installation_id == context.installation
            && incarnation == context.incarnation
            && row.policy_epoch == context.policy_epoch,
    )?;
    let before = row.control_seq == context.old_control_seq
        && row.maintenance_state == "uninstalling"
        && row.maintenance_owner == Some(context.old_owner.as_str())
        && row.maintenance_phase == Some("quiescing");
    let after = Some(row.control_seq) == context.old_control_seq.checked_add(1)
        && row.maintenance_state == "recovering"
        && row.maintenance_owner == Some(context.operation.as_str())
        && row.maintenance_phase == Some("reconciling");
    if !(before || !derive && after) {
        return Err(conflict());
    }
    let result = Meta {
        installation: row.installation_id.into(),
        incarnation: incarnation.into(),
        epoch: row.policy_epoch,
        sequence: row.control_seq,
        next_cycle: row.next_cycle_seq,
    };
    require(rows.next().map_err(sql_error)?.is_none())?;
    Ok(result)
}

impl MetaRow<'_> {
    fn validate(&self) -> PortResult<()> {
        identifiers(
            std::iter::once(self.installation_id)
                .chain(self.catalog_incarnation)
                .chain(self.maintenance_owner),
        )?;
        nonnegative([
            self.policy_epoch,
            self.control_seq,
            self.restart_request_seq,
        ])?;
        desired_decode(self.desired_updates)?;
        boolean(self.autostart_enabled)?;
        boolean(self.supervisor_failed)?;
        let fence = MaintenanceFence {
            state: maintenance_decode(self.maintenance_state)?,
            owner: self.maintenance_owner.map(ControlId::parse).transpose()?,
            phase: self.maintenance_phase.map(phase_decode).transpose()?,
        };
        fence.validate().map_err(|_| corrupt())?;
        require(
            self.singleton == 1
                && self.schema_version == VERSION
                && self.next_cycle_seq > 0
                && self.policy_epoch <= self.control_seq
                && self.restart_request_seq <= self.control_seq,
        )
    }
}

impl SelectionRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifiers(std::iter::once(self.selection_id).chain(self.root_identity))?;
        provider(self.provider_id.into())?;
        kind_decode(self.root_kind)?;
        let enabled = boolean(self.enabled)?;
        nonnegative(
            [self.revision, self.created_at_ms]
                .into_iter()
                .chain(self.revoked_at_ms),
        )?;
        require(self.revision <= meta.sequence && enabled != self.revoked_at_ms.is_some())
    }
}

impl ExclusionRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifiers(std::iter::once(self.exclusion_id).chain(self.source_id))?;
        provider(self.provider_id.into())?;
        nonnegative([self.revision, self.created_policy_epoch, self.created_at_ms])?;
        require(
            self.revision <= meta.sequence
                && self.created_policy_epoch <= meta.epoch
                && matches!(
                    (self.region_kind, self.canonical_locator, self.source_id),
                    ("source_identity", None, Some(_)) | ("root" | "exact", Some(_), None)
                ),
        )
    }
}

impl WorkerRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        identifiers(self.boot_id)?;
        nonnegative(self.heartbeat_at_ms)?;
        update_decode(self.effective_state)?;
        failure(self.last_error)?;
        require(
            self.singleton == 1
                && self
                    .pid_hint
                    .is_none_or(|pid| pid > 0 && u32::try_from(pid).is_ok())
                && self.boot_id.is_some() == self.pid_hint.is_some()
                && if self.boot_id.is_some() {
                    self.heartbeat_at_ms.is_some()
                } else {
                    self.effective_state == "offline"
                        && self.heartbeat_at_ms.is_none()
                        && self.last_error.is_none()
                },
        )
    }
}

impl CycleRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifier(self.worker_boot_id.ok_or_else(corrupt)?)?;
        let state = cycle_decode(self.state)?;
        nonnegative(
            [self.policy_epoch, self.admitted_control_seq]
                .into_iter()
                .chain(self.started_control_seq)
                .chain(self.started_at_ms)
                .chain(self.completed_at_ms),
        )?;
        require(
            self.cycle_seq > 0
                && self.cycle_seq < meta.next_cycle
                && self.policy_epoch <= meta.epoch
                && self.admitted_control_seq <= meta.sequence
                && self.started_control_seq.is_none_or(|value| {
                    value > self.admitted_control_seq && value <= meta.sequence
                })
                && self.started_control_seq.is_some() == self.started_at_ms.is_some()
                && !(state == CycleState::Queued
                    && (self.started_control_seq.is_some() || self.completed_at_ms.is_some()))
                && !(matches!(
                    state,
                    CycleState::Observing | CycleState::Committed | CycleState::Partial
                ) && self.started_control_seq.is_none())
                && !(state == CycleState::Observing && self.completed_at_ms.is_some())
                && !(matches!(state, CycleState::Committed | CycleState::Partial)
                    && self.completed_at_ms.is_none()),
        )
    }
}

impl CycleSelectionRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        identifiers([self.selection_id, self.root_identity.ok_or_else(corrupt)?])?;
        boolean(self.discovery_complete)?;
        nonnegative([
            self.discovered_count,
            self.observed_count,
            self.committed_count,
        ])?;
        failure(self.error_code)?;
        require(
            self.cycle_seq > 0
                && self.selection_revision > 0
                && self.committed_count <= self.observed_count
                && self.observed_count <= self.discovered_count
                && !(self.discovery_complete == 1 && self.error_code.is_some()),
        )
    }
}

impl BarrierRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifier(self.barrier_id)?;
        barrier_decode(self.state)?;
        failure(self.error_code)?;
        nonnegative([
            self.policy_epoch,
            self.admission_control_seq,
            self.admitted_at_ms,
        ])?;
        require(
            self.policy_epoch <= meta.epoch
                && self.admission_control_seq <= meta.sequence
                && self.required_cycle_seq > 0
                && self.completed_cycle_seq.is_none_or(|value| value > 0)
                && (0..=i64::from(MAX_LATEST_WAIT_MS)).contains(&self.requested_wait_ms)
                && self.catalog_incarnation.is_none()
                && (self.state == "blocked") == self.error_code.is_some()
                && !(self.state == "awaiting_catalog" && self.completed_cycle_seq.is_none())
                && !(self.state == "pending" && self.completed_cycle_seq.is_some()),
        )
    }
}

impl BarrierSelectionRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        identifiers([self.barrier_id, self.selection_id])?;
        nonnegative([self.selection_revision])
    }
}

impl RevocationRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifiers(std::iter::once(self.intent_id).chain(self.owner_nonce))?;
        nonnegative(
            [self.policy_epoch, self.created_at_ms]
                .into_iter()
                .chain(self.settled_at_ms),
        )?;
        require(
            self.policy_epoch <= meta.epoch
                && matches!(self.state, "awaiting_drain" | "settled")
                && (self.state == "settled") == self.settled_at_ms.is_some(),
        )
    }
}

impl PurgeRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifiers(
            std::iter::once(self.job_id)
                .chain(self.selection_id)
                .chain(self.owner_nonce),
        )?;
        nonnegative(
            [
                self.policy_epoch,
                self.attempts,
                self.created_at_ms,
                self.updated_at_ms,
            ]
            .into_iter()
            .chain(self.selection_revision),
        )?;
        let checkpoint = self.progress_key.map(PurgeCheckpoint::decode).transpose()?;
        self.last_error.map(PurgeFailure::decode).transpose()?;
        require(
            self.policy_epoch <= meta.epoch
                && self.state == "complete"
                && self.attempts > 0
                && checkpoint == Some(PurgeCheckpoint::ArtifactsVerified)
                && self.owner_nonce.is_none()
                && self.last_error.is_none()
                && self.selection_id.is_some()
                && self.selection_revision.is_some(),
        )
    }
}

impl ArtifactRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifiers(std::iter::once(self.artifact_id).chain(self.owner_nonce))?;
        let state = ArtifactState::decode(self.state)?;
        require(
            self.kind == "catalog_backup"
                && valid_relative_locator(self.relative_locator)
                && self.policy_epoch >= 0
                && self.policy_epoch <= meta.epoch
                && matches!(
                    state,
                    ArtifactState::Complete | ArtifactState::PurgedByPolicy
                )
                && (state == ArtifactState::Complete) == self.owner_nonce.is_some()
                && self.digest.is_none_or(hex64)
                && !(state == ArtifactState::Complete && self.digest.is_none()),
        )
    }
}

impl ArtifactSourceRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        identifiers([self.artifact_id, self.source_id])
    }
}

impl BackupRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        identifiers([self.backup_id, self.catalog_incarnation])?;
        BackupPurpose::decode(self.purpose)?;
        BackupState::decode(self.state)?;
        nonnegative([self.catalog_generation, self.size_bytes, self.created_at_ms])?;
        require(
            valid_relative_locator(self.relative_locator)
                && self.relative_locator == backup_locator(&ControlId::parse(self.backup_id)?)
                && self.schema_version > 0
                && u32::try_from(self.schema_version).is_ok()
                && matches!(self.state, "complete" | "purged_by_policy")
                && ((self.state == "purged_by_policy"
                    && self.digest.is_empty()
                    && self.size_bytes == 0)
                    || (hex64(self.digest) && self.size_bytes > 0)),
        )
    }
}

impl BackupSourceRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        identifiers([self.backup_id, self.source_id])
    }
}

impl ReceiptRow<'_> {
    fn validate(&self, _: &Meta) -> PortResult<()> {
        // No reserved row, including one with valid primitive storage types,
        // has executable semantics in this schema.
        Err(corrupt())
    }
}

impl SourceRow<'_> {
    fn validate(&self, meta: &Meta) -> PortResult<()> {
        identifiers(
            std::iter::once(self.source_id)
                .chain(self.indexed_revision)
                .chain(self.catalog_incarnation)
                .chain(self.confirmation_boot_id)
                .chain(self.confirmation_root_identity)
                .chain(self.rewrite_candidate_digest),
        )?;
        provider(self.provider_id.into())?;
        coverage_decode(self.coverage)?;
        update_decode(self.update_state)?;
        backfill_decode(self.backfill_state)?;
        failure(self.error_code)?;
        nonnegative(
            self.last_attempt_at_ms
                .into_iter()
                .chain(self.catalog_generation)
                .chain(self.confirmation_policy_epoch)
                .chain(self.confirmation_first_monotonic_ms),
        )?;
        require(
            [
                self.last_observed_cycle,
                self.receipt_cycle,
                self.missing_first_cycle,
                self.missing_confirm_cycle,
                self.rewrite_first_cycle,
                self.rewrite_confirm_cycle,
            ]
            .into_iter()
            .flatten()
            .all(|cycle| cycle > 0 && cycle < meta.next_cycle),
        )?;
        let receipt = [
            self.indexed_revision.is_some(),
            self.receipt_cycle.is_some(),
            self.catalog_incarnation.is_some(),
            self.catalog_generation.is_some(),
        ];
        require(receipt.iter().all(|part| *part) || receipt.iter().all(|part| !*part))?;
        require(
            self.catalog_incarnation
                .is_none_or(|value| value == meta.incarnation)
                && !self.receipt_cycle.is_some_and(|receipt| {
                    self.last_observed_cycle.is_some_and(|last| receipt > last)
                })
                && !(self.coverage == "complete"
                    && (self.error_code.is_some()
                        || self.receipt_cycle.is_none()
                        || self.receipt_cycle != self.last_observed_cycle))
                && !(self.last_observed_cycle.is_some() && self.last_attempt_at_ms.is_none()),
        )?;
        let common = [
            self.confirmation_boot_id.is_some(),
            self.confirmation_root_identity.is_some(),
            self.confirmation_policy_epoch.is_some(),
            self.confirmation_first_monotonic_ms.is_some(),
        ];
        let absent = common.iter().all(|part| !*part)
            && self.missing_first_cycle.is_none()
            && self.missing_confirm_cycle.is_none()
            && self.rewrite_first_cycle.is_none()
            && self.rewrite_confirm_cycle.is_none()
            && self.rewrite_candidate_digest.is_none();
        if absent {
            return Ok(());
        }
        let (first, confirm, expected_error) = match (
            self.missing_first_cycle,
            self.rewrite_first_cycle,
            self.rewrite_candidate_digest,
        ) {
            (Some(first), None, None) if self.rewrite_confirm_cycle.is_none() => {
                (first, self.missing_confirm_cycle, "deletion_pending")
            }
            (None, Some(first), Some(_)) if self.missing_confirm_cycle.is_none() => {
                (first, self.rewrite_confirm_cycle, "rewrite_pending")
            }
            _ => return Err(corrupt()),
        };
        require(
            common.iter().all(|part| *part)
                && self.update_state == "deferred"
                && self.coverage != "complete"
                && self.error_code == Some(expected_error)
                && self.confirmation_policy_epoch == Some(meta.epoch)
                && confirm.is_none_or(|last| last > first)
                && self.last_observed_cycle == Some(confirm.unwrap_or(first)),
        )
    }
}

fn table_hash(ordinal: u16, columns: &[&str]) -> PortResult<Sha256> {
    let mut hash = Sha256::new();
    hash.update(b"asg.reinstall-control-table/v1\0");
    hash.update(ordinal.to_be_bytes());
    hash.update(
        u16::try_from(columns.len())
            .map_err(|_| corrupt())?
            .to_be_bytes(),
    );
    for column in columns {
        hash.update(
            u16::try_from(column.len())
                .map_err(|_| corrupt())?
                .to_be_bytes(),
        );
        hash.update(column.as_bytes());
    }
    Ok(hash)
}

fn finish_table(mut hash: Sha256, rows: u64) -> TableDigest {
    hash.update([0x45]);
    hash.update(rows.to_be_bytes());
    TableDigest {
        rows,
        sha256: ReinstallDigest(hash.finalize().into()),
    }
}

fn next_row_count(count: u64) -> PortResult<u64> {
    count.checked_add(1).ok_or_else(corrupt)
}

fn stream(
    conn: &Connection,
    context: &ReinstallContext,
    files: &ReinstallFiles,
    meta: &Meta,
    derive: bool,
) -> PortResult<(ReinstallImage, Option<ReinstallImage>)> {
    let empty = TableDigest {
        rows: 0,
        sha256: ReinstallDigest([0; 32]),
    };
    let mut before = [empty; TABLE_COUNT];
    let mut after = [empty; TABLE_COUNT];
    macro_rules! visit {
        ($ordinal:literal, $row:ident, $validate:expr, $transform:expr) => {{
            runtime_tick()?;
            let mut current_hash = table_hash($ordinal, $row::COLUMNS)?;
            let mut after_hash = derive.then(|| current_hash.clone());
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {} FROM {} ORDER BY {}",
                    $row::COLUMNS.join(","),
                    $row::TABLE,
                    $row::ORDER,
                ))
                .map_err(sql_error)?;
            let mut rows = statement.query([]).map_err(sql_error)?;
            let mut count = 0u64;
            while let Some(sql_row) = rows.next().map_err(sql_error)? {
                runtime_tick()?;
                let row = $row::decode(sql_row)?;
                ($validate)(&row)?;
                current_hash.update([0x52]);
                current_hash.update(count.to_be_bytes());
                row.feed(&mut current_hash);
                if let Some(hash) = &mut after_hash {
                    hash.update([0x52]);
                    hash.update(count.to_be_bytes());
                    ($transform)(&row, hash)?;
                }
                count = next_row_count(count)?;
                #[cfg(test)]
                tests::observe(Step::Row($ordinal, count))?;
            }
            before[$ordinal] = finish_table(current_hash, count);
            if let Some(hash) = after_hash {
                after[$ordinal] = finish_table(hash, count);
            }
            drop(rows);
            drop(statement);
            #[cfg(test)]
            tests::observe(Step::Table($ordinal))?;
        }};
    }
    macro_rules! unchanged {
        ($ordinal:literal, $row:ident) => {
            visit!(
                $ordinal,
                $row,
                |r: &$row<'_>| r.validate(meta),
                |r: &$row<'_>, h: &mut Sha256| -> PortResult<()> {
                    r.feed(h);
                    Ok(())
                }
            );
        };
    }
    visit!(
        0,
        MetaRow,
        |r: &MetaRow<'_>| r.validate(),
        |r: &MetaRow<'_>, h: &mut Sha256| -> PortResult<()> {
            let changed = MetaRow {
                control_seq: r.control_seq.checked_add(1).ok_or_else(corrupt)?,
                maintenance_state: "recovering",
                maintenance_owner: Some(context.operation.as_str()),
                maintenance_phase: Some("reconciling"),
                ..r.clone()
            };
            changed.feed(h);
            Ok(())
        }
    );
    unchanged!(1, SelectionRow);
    unchanged!(2, ExclusionRow);
    unchanged!(3, WorkerRow);
    visit!(
        4,
        SourceRow,
        |r: &SourceRow<'_>| r.validate(meta),
        |r: &SourceRow<'_>, h: &mut Sha256| -> PortResult<()> {
            let changed = SourceRow {
                coverage: if r.receipt_cycle.is_none() {
                    "empty"
                } else {
                    "partial"
                },
                update_state: "deferred",
                error_code: Some("upgrading"),
                backfill_state: "pending",
                missing_first_cycle: None,
                missing_confirm_cycle: None,
                confirmation_boot_id: None,
                confirmation_root_identity: None,
                confirmation_policy_epoch: None,
                rewrite_candidate_digest: None,
                rewrite_first_cycle: None,
                rewrite_confirm_cycle: None,
                confirmation_first_monotonic_ms: None,
                ..r.clone()
            };
            changed.feed(h);
            Ok(())
        }
    );
    visit!(
        5,
        CycleRow,
        |r: &CycleRow<'_>| r.validate(meta),
        |r: &CycleRow<'_>, h: &mut Sha256| -> PortResult<()> {
            let changed = CycleRow {
                state: if matches!(r.state, "queued" | "observing") {
                    "aborted"
                } else {
                    r.state
                },
                ..r.clone()
            };
            changed.feed(h);
            Ok(())
        }
    );
    unchanged!(6, CycleSelectionRow);
    visit!(
        7,
        BarrierRow,
        |r: &BarrierRow<'_>| r.validate(meta),
        |r: &BarrierRow<'_>, h: &mut Sha256| -> PortResult<()> {
            let pending = matches!(r.state, "pending" | "awaiting_catalog");
            let changed = BarrierRow {
                state: if pending { "blocked" } else { r.state },
                error_code: if pending {
                    Some("upgrading")
                } else {
                    r.error_code
                },
                ..r.clone()
            };
            changed.feed(h);
            Ok(())
        }
    );
    unchanged!(8, BarrierSelectionRow);
    unchanged!(9, RevocationRow);
    unchanged!(10, PurgeRow);
    unchanged!(11, ArtifactRow);
    unchanged!(12, ArtifactSourceRow);
    unchanged!(13, BackupRow);
    unchanged!(14, BackupSourceRow);
    unchanged!(15, ReceiptRow);
    require(before[0].rows == 1 && before[3].rows == 1 && before[15].rows == 0)?;
    validate_relations(conn)?;
    validate_live_capacity(conn)?;
    runtime_tick()?;
    Ok((
        ReinstallImage::new(context, files, before),
        derive.then(|| ReinstallImage::new(context, files, after)),
    ))
}

/// Every predicate is a read against the same transaction as the row streams.
/// Primary-key lookups and ordered joins retain no application-side history.
fn validate_relations(conn: &Connection) -> PortResult<()> {
    const REFUSALS: &[&str] = &[
        // Policy regions are unique by meaning as well as by their opaque key.
        "SELECT 1 FROM selections GROUP BY provider_id,canonical_locator,root_kind HAVING COUNT(*)>1 LIMIT 1",
        "SELECT 1 FROM exclusions GROUP BY provider_id,region_kind,canonical_locator,source_id HAVING COUNT(*)>1 LIMIT 1",
        "SELECT 1 FROM revocation_intents r WHERE NOT EXISTS
          (SELECT 1 FROM purge_jobs j WHERE j.policy_epoch=r.policy_epoch) LIMIT 1",
        "SELECT 1 FROM purge_jobs j
          LEFT JOIN selections s ON s.selection_id=j.selection_id
          LEFT JOIN revocation_intents r ON r.policy_epoch=j.policy_epoch
          WHERE s.selection_id IS NULL OR r.intent_id IS NULL
             OR j.selection_revision>s.revision LIMIT 1",
        // All history is checked, including rows absent from the runtime tail.
        "SELECT 1 FROM cycle_selections x
          LEFT JOIN cycles c ON c.cycle_seq=x.cycle_seq
          LEFT JOIN selections s ON s.selection_id=x.selection_id
          WHERE c.cycle_seq IS NULL OR s.selection_id IS NULL
             OR x.selection_revision>s.revision
             OR (c.state='queued' AND
                 (x.discovery_complete<>0 OR x.discovered_count<>0 OR x.error_code IS NOT NULL))
             OR (c.state='committed' AND
                 (x.discovery_complete<>1 OR x.error_code IS NOT NULL
                  OR x.committed_count<>x.discovered_count)) LIMIT 1",
        "SELECT 1 FROM cycles c WHERE NOT EXISTS
          (SELECT 1 FROM cycle_selections x WHERE x.cycle_seq=c.cycle_seq) LIMIT 1",
        "SELECT 1 FROM cycles c CROSS JOIN control_meta m CROSS JOIN worker_state w
          WHERE c.state IN ('queued','observing') AND
            (c.worker_boot_id IS NOT w.boot_id OR c.policy_epoch<>m.policy_epoch
             OR m.desired_updates<>'running' OR m.maintenance_state<>'idle') LIMIT 1",
        "SELECT 1 FROM cycle_selections x
          JOIN cycles c ON c.cycle_seq=x.cycle_seq
          JOIN selections s ON s.selection_id=x.selection_id
          WHERE c.state IN ('queued','observing') AND
            (s.enabled<>1 OR s.revision<>x.selection_revision
             OR s.root_identity IS NOT x.root_identity) LIMIT 1",
        "SELECT 1 FROM cycles WHERE state='observing' LIMIT 1 OFFSET 1",
        "SELECT 1 FROM barriers b LEFT JOIN cycles c ON c.cycle_seq=b.required_cycle_seq
          WHERE c.cycle_seq IS NULL OR b.policy_epoch<>c.policy_epoch
             OR b.admission_control_seq<c.admitted_control_seq
             OR c.started_control_seq<=b.admission_control_seq
             OR (b.state='pending' AND c.state NOT IN ('queued','observing'))
             OR (b.completed_cycle_seq IS NOT NULL AND
                 (b.completed_cycle_seq<>c.cycle_seq OR
                  c.state NOT IN ('committed','partial','aborted'))) LIMIT 1",
        "SELECT 1 FROM barriers b WHERE NOT EXISTS
          (SELECT 1 FROM barrier_selections x WHERE x.barrier_id=b.barrier_id) LIMIT 1",
        "SELECT 1 FROM barrier_selections x
          LEFT JOIN barriers b ON b.barrier_id=x.barrier_id
          LEFT JOIN cycle_selections s ON s.cycle_seq=b.required_cycle_seq
                                     AND s.selection_id=x.selection_id
          WHERE b.barrier_id IS NULL OR s.selection_id IS NULL
             OR x.selection_revision<>s.selection_revision LIMIT 1",
        // Source last-observation/receipt tokens must name started cycles whose
        // selections prove the source provider; a stale boot can still be history.
        "SELECT 1 FROM source_updates s WHERE s.last_observed_cycle IS NOT NULL AND
          NOT EXISTS (SELECT 1 FROM cycles c
                      JOIN cycle_selections x ON x.cycle_seq=c.cycle_seq
                      JOIN selections p ON p.selection_id=x.selection_id
                      WHERE c.cycle_seq=s.last_observed_cycle
                        AND c.started_control_seq IS NOT NULL
                        AND p.provider_id=s.provider_id) LIMIT 1",
        "SELECT 1 FROM source_updates s WHERE s.receipt_cycle IS NOT NULL AND
          NOT EXISTS (SELECT 1 FROM cycles c
                      JOIN cycle_selections x ON x.cycle_seq=c.cycle_seq
                      JOIN selections p ON p.selection_id=x.selection_id
                      WHERE c.cycle_seq=s.receipt_cycle
                        AND c.started_control_seq IS NOT NULL
                        AND p.provider_id=s.provider_id) LIMIT 1",
        "SELECT 1 FROM source_updates s CROSS JOIN worker_state w
          WHERE s.confirmation_boot_id IS NOT NULL
            AND s.confirmation_boot_id IS NOT w.boot_id LIMIT 1",
        // No dangling artifact/backup link and no backup without its exact peer.
        "SELECT 1 FROM private_artifacts a LEFT JOIN backup_manifests b ON b.backup_id=a.artifact_id
          WHERE b.backup_id IS NULL OR b.relative_locator<>a.relative_locator
             OR b.state<>a.state
             OR (CASE WHEN b.digest='' THEN NULL ELSE b.digest END) IS NOT a.digest LIMIT 1",
        "SELECT 1 FROM backup_manifests b LEFT JOIN private_artifacts a ON a.artifact_id=b.backup_id
          WHERE a.artifact_id IS NULL LIMIT 1",
        "SELECT 1 FROM artifact_sources x LEFT JOIN private_artifacts a ON a.artifact_id=x.artifact_id
          WHERE a.artifact_id IS NULL OR a.state='purged_by_policy' OR NOT EXISTS
            (SELECT 1 FROM backup_sources y WHERE y.backup_id=x.artifact_id AND y.source_id=x.source_id) LIMIT 1",
        "SELECT 1 FROM backup_sources x LEFT JOIN backup_manifests b ON b.backup_id=x.backup_id
          WHERE b.backup_id IS NULL OR b.state='purged_by_policy' OR NOT EXISTS
            (SELECT 1 FROM artifact_sources y WHERE y.artifact_id=x.backup_id AND y.source_id=x.source_id) LIMIT 1",
    ];
    for sql in REFUSALS {
        runtime_tick()?;
        if conn
            .query_row(sql, [], |_| Ok(()))
            .optional()
            .map_err(sql_error)?
            .is_some()
        {
            return Err(corrupt());
        }
    }
    for column in [
        "missing_first_cycle",
        "missing_confirm_cycle",
        "rewrite_first_cycle",
        "rewrite_confirm_cycle",
    ] {
        runtime_tick()?;
        let sql = format!(
            "SELECT 1 FROM source_updates s WHERE s.{column} IS NOT NULL AND NOT EXISTS
             (SELECT 1 FROM cycles c JOIN cycle_selections x ON x.cycle_seq=c.cycle_seq
              WHERE c.cycle_seq=s.{column}
                AND c.worker_boot_id=s.confirmation_boot_id
                AND c.policy_epoch=s.confirmation_policy_epoch
                AND c.started_control_seq IS NOT NULL
                AND x.root_identity=s.confirmation_root_identity) LIMIT 1"
        );
        if conn
            .query_row(&sql, [], |_| Ok(()))
            .optional()
            .map_err(sql_error)?
            .is_some()
        {
            return Err(corrupt());
        }
    }
    runtime_tick()
}

/// The ordinary runtime dependency closure expressed as read-only CTEs. These
/// bounds still govern the same live/staged selectors, never all terminal rows.
fn validate_live_capacity(conn: &Connection) -> PortResult<()> {
    for table in [
        "selections",
        "exclusions",
        "revocation_intents",
        "purge_jobs",
    ] {
        runtime_rows_within(
            conn,
            &format!("SELECT 1 FROM {table}"),
            MAX_RUNTIME_REFERENCES,
        )?;
    }
    validate_policy_admission_capacity(conn)?;
    const CLOSURE: &str = "
      WITH tail_cycles AS (SELECT cycle_seq FROM cycles ORDER BY cycle_seq DESC LIMIT 64),
      tail_barriers AS (
        SELECT barrier_id FROM barriers ORDER BY admission_control_seq DESC,barrier_id LIMIT 64),
      chosen_barriers AS (
        SELECT barrier_id FROM barriers WHERE state='pending'
        UNION SELECT barrier_id FROM tail_barriers),
      chosen_cycles AS (
        SELECT cycle_seq FROM cycles WHERE state IN ('queued','observing')
        UNION SELECT cycle_seq FROM tail_cycles
        UNION SELECT required_cycle_seq FROM barriers
              WHERE barrier_id IN (SELECT barrier_id FROM chosen_barriers)
        UNION SELECT completed_cycle_seq FROM barriers
              WHERE barrier_id IN (SELECT barrier_id FROM chosen_barriers)
                AND completed_cycle_seq IS NOT NULL
        UNION SELECT last_observed_cycle FROM source_updates WHERE last_observed_cycle IS NOT NULL
        UNION SELECT receipt_cycle FROM source_updates WHERE receipt_cycle IS NOT NULL
        UNION SELECT missing_first_cycle FROM source_updates WHERE missing_first_cycle IS NOT NULL
        UNION SELECT missing_confirm_cycle FROM source_updates WHERE missing_confirm_cycle IS NOT NULL
        UNION SELECT rewrite_first_cycle FROM source_updates WHERE rewrite_first_cycle IS NOT NULL
        UNION SELECT rewrite_confirm_cycle FROM source_updates WHERE rewrite_confirm_cycle IS NOT NULL)";
    for (selector, limit) in [
        ("SELECT 1 FROM chosen_cycles", MAX_RUNTIME_REFERENCES),
        ("SELECT 1 FROM chosen_barriers", MAX_RUNTIME_REFERENCES),
        (
            "SELECT 1 FROM cycle_selections WHERE cycle_seq IN (SELECT cycle_seq FROM chosen_cycles)",
            MAX_RUNTIME_RELATIONS,
        ),
        (
            "SELECT 1 FROM barrier_selections WHERE barrier_id IN (SELECT barrier_id FROM chosen_barriers)",
            MAX_RUNTIME_RELATIONS,
        ),
    ] {
        runtime_rows_within(conn, &format!("{CLOSURE} {selector}"), limit)?;
    }
    runtime_tick()
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Row(u16, u64),
    Table(u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_store::ManagedStore;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::{
        collections::BTreeMap,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    type Hook = Box<dyn FnMut(Step) -> PortResult<()>>;
    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(super) fn observe(step: Step) -> PortResult<()> {
        HOOK.with_borrow_mut(|slot| match slot.as_mut() {
            Some(hook) => hook(step),
            None => Ok(()),
        })
    }

    fn with_hook<T>(
        hook: impl FnMut(Step) -> PortResult<()> + 'static,
        operation: impl FnOnce() -> T,
    ) -> T {
        struct Reset(Option<Hook>);
        impl Drop for Reset {
            fn drop(&mut self) {
                HOOK.with_borrow_mut(|slot| *slot = self.0.take());
            }
        }
        let reset = Reset(HOOK.with_borrow_mut(|slot| slot.replace(Box::new(hook))));
        let result = operation();
        drop(reset);
        result
    }

    fn end() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn cid(value: &str) -> ControlId {
        ControlId::parse(value).unwrap()
    }

    fn identity(path: &Path) -> (u64, u64) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(path).unwrap();
            (metadata.dev(), metadata.ino())
        }
        #[cfg(windows)]
        {
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
            };
            let file = fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .unwrap();
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: the metadata-only File owns this live handle and the
            // output is exactly BY_HANDLE_FILE_INFORMATION. No lock bytes read.
            assert_ne!(
                unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
                0
            );
            (
                u64::from(info.dwVolumeSerialNumber),
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            )
        }
        #[cfg(not(any(unix, windows)))]
        panic!("reinstall requires a supported local filesystem");
    }

    fn file_binding(path: &Path) -> ReinstallFileBinding {
        let bytes = fs::read(path).unwrap();
        ReinstallFileBinding {
            identity: identity(path),
            size: bytes.len() as u64,
            sha256: ReinstallDigest::of_bytes(&bytes),
        }
    }

    fn sibling(path: &Path) -> Option<ReinstallFileBinding> {
        match fs::symlink_metadata(path) {
            Ok(_) => Some(file_binding(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("fixture sibling metadata failed: {error}"),
        }
    }

    fn shm(path: &Path) -> Option<ReinstallShmBinding> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Some(ReinstallShmBinding {
                identity: identity(path),
                size: metadata.len(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("fixture shared-memory metadata failed: {error}"),
        }
    }

    struct Fixture {
        // Connections close before either real guard or the fixture root drops.
        store: SqliteControlStore,
        owner: ExclusiveGuard,
        prefix_guard: ExclusiveGuard,
        root: PathBuf,
        prefix: PathBuf,
        context: ReinstallContext,
        _temp: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = agent_session_grep_testkit::tempdir().unwrap();
            let root = temp.path().join("data");
            let prefix = temp.path().join("prefix");
            private_directory(&prefix, true).unwrap();
            let until = end();
            let store = SqliteControlStore::create_with_deadline(
                &root,
                &cid("stream-installation"),
                DesiredUpdates::Paused,
                until,
            )
            .unwrap();
            let catalog = ManagedStore::create_with_deadline(
                &root.join("catalog.db"),
                &store,
                cid("stream-incarnation"),
                1,
                until,
            )
            .unwrap();
            drop(catalog);
            let owner = ExclusiveGuard::try_acquire(&root, LockKind::PolicyOwner).unwrap();
            let prefix_guard = ExclusiveGuard::try_acquire(
                &prefix,
                LockKind::MaintenanceJob(JobLockKey::parse(INSTALLATION_LOCK_KEY).unwrap()),
            )
            .unwrap();
            store
                .with_runtime_deadline(until, || {
                    let bound = store.bind_control_root(&owner)?;
                    store.record_verified_installation_prefix(
                        &prefix,
                        &prefix_guard,
                        &bound,
                        until,
                    )?;
                    let background = ExclusiveGuard::try_acquire(&root, LockKind::Background)?;
                    let worker = store.bind_worker(&background, cid("stream-worker"))?;
                    let registered =
                        store.register_worker(store.status()?.policy.control_seq, &worker, 1, 1)?;
                    store.reconcile_catalog_summary(
                        registered.control_seq,
                        &worker,
                        &cid("stream-incarnation"),
                        1,
                    )?;
                    let installation = store.bind_installation(&prefix, &prefix_guard)?;
                    store.begin_maintenance(
                        store.status()?.policy.control_seq,
                        &cid("stream-old-owner"),
                        &bound,
                        &installation,
                        MaintenanceFence {
                            state: MaintenanceState::Uninstalling,
                            owner: Some(cid("stream-old-owner")),
                            phase: Some(MaintenancePhase::Quiescing),
                        },
                    )?;
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
            let sealed =
                SealedControlFile::from_recorded(identity(&SqliteControlStore::path(&root)));
            drop(store);
            let store = SqliteControlStore::open_reinstall_writable_with_deadline(
                ReinstallControlOpen {
                    root: &root,
                    prefix: &prefix,
                    policy_owner: &owner,
                    prefix_guard: &prefix_guard,
                    sealed,
                    expected: &expected,
                },
                until,
            )
            .unwrap();
            let journal = prefix.join("uninstall");
            let helper = journal.join("helper");
            let sidecar = prefix.join(".asg-reinstall");
            let evidence = sidecar.join("evidence");
            for path in [&journal, &helper, &sidecar, &evidence] {
                private_directory(path, true).unwrap();
            }
            let context = ReinstallContext {
                operation: "stream-fixed-owner".into(),
                intent_sha256: ReinstallDigest::of_bytes(b"fixture-fixed-intent"),
                ready_sha256: ReinstallDigest::of_bytes(b"fixture-ready"),
                consumed_sha256: ReinstallDigest::of_bytes(b"fixture-consumed"),
                incoming_sha256: ReinstallDigest::of_bytes(b"fixture-package"),
                roots: ReinstallRoots {
                    prefix: identity(&prefix),
                    data: identity(&root),
                    journal: identity(&journal),
                    helper: identity(&helper),
                },
                sidecar_identity: identity(&sidecar),
                evidence_identity: identity(&evidence),
                old_owner: "stream-old-owner".into(),
                installation: expected.policy.installation_id.as_str().into(),
                incarnation: expected.catalog_incarnation.unwrap().as_str().into(),
                old_control_seq: expected.policy.control_seq.get(),
                policy_epoch: expected.policy.policy_epoch.get(),
                application_id: APPLICATION_ID as u32,
                user_version: VERSION as u32,
                schema_sha256: ReinstallContext::current_schema_digest(),
                sqlite_policy: "no-close-checkpoint/v1".into(),
            };
            Self {
                store,
                owner,
                prefix_guard,
                root,
                prefix,
                context,
                _temp: temp,
            }
        }

        fn files(&self) -> ReinstallFiles {
            ReinstallFiles {
                control_main: file_binding(&self.root.join("control.db")),
                control_wal: sibling(&self.root.join("control.db-wal")),
                control_shm: shm(&self.root.join("control.db-shm")),
                catalog_main: file_binding(&self.root.join("catalog.db")),
                catalog_wal: sibling(&self.root.join("catalog.db-wal")),
                catalog_shm: shm(&self.root.join("catalog.db-shm")),
            }
        }

        fn with_binding<T>(
            &self,
            operation: impl FnOnce(ReinstallSnapshotBinding<'_, '_>) -> T,
        ) -> T {
            let owner = self.store.bind_control_root(&self.owner).unwrap();
            // Same internal construction used by the foundation. No status()
            // call can create TEMP staging before the mutation-denial test.
            let installation = InstallationLockAuthority {
                guard: &self.prefix_guard,
                prefix: self.prefix.clone(),
                identity: self.prefix_guard.root_identity(),
                installation: cid(&self.context.installation),
                control_root: self.store.root_identity,
            };
            operation(ReinstallSnapshotBinding {
                control_root: self.store.root_identity,
                owner: &owner,
                installation: &installation,
                sealed: SealedControlFile::from_recorded(identity(&self.root.join("control.db"))),
            })
        }

        fn prepare(&self, files: &ReinstallFiles, until: Instant) -> PortResult<ReinstallPrep> {
            self.with_binding(|binding| {
                self.store
                    .prepare_reinstall_commitments_with_deadline(
                        ReinstallPreparationRead {
                            binding,
                            context: &self.context,
                            files,
                        },
                        until,
                    )
                    .map(ReinstallCommitmentPair::into_preparation)
            })
        }

        fn compare(&self, prep: &ReinstallPrep, until: Instant) -> PortResult<ReinstallImageMatch> {
            self.with_binding(|binding| {
                self.store
                    .compare_reinstall_commitment_with_deadline(binding, prep, until)
            })
        }

        fn adopt(&self) {
            self.with_binding(|binding| {
                self.store
                    .with_runtime_deadline(end(), || {
                        self.store.recover_maintenance(
                            seq(self.context.old_control_seq)?,
                            &cid(&self.context.operation),
                            binding.owner,
                            binding.installation,
                            &cid(&self.context.old_owner),
                            MaintenanceFence {
                                state: MaintenanceState::Recovering,
                                owner: Some(cid(&self.context.operation)),
                                phase: Some(MaintenancePhase::Reconciling),
                            },
                        )
                    })
                    .unwrap();
            });
        }

        fn seed_history(&self, cycles: i64, selections: i64, wide_ids: bool) {
            let mut conn = self.store.conn.borrow_mut();
            let tx = conn.transaction().unwrap();
            {
                let mut insert = tx
                    .prepare("INSERT INTO selections VALUES(?1,'codex',?2,'root',?3,1,1,1,NULL)")
                    .unwrap();
                for number in 0..selections {
                    let key = format!("selection_{number:03}");
                    let suffix = if wide_ids {
                        "_".repeat(128 - key.len())
                    } else {
                        String::new()
                    };
                    let selection = format!("{key}{suffix}");
                    let directory = self.root.join(format!("selected-{number}"));
                    let selected_locator = CanonicalLocator::from_path(&directory).unwrap();
                    insert
                        .execute(params![
                            selection,
                            selected_locator.as_str(),
                            "stream-root".to_owned() + &"_".repeat(if wide_ids { 117 } else { 0 })
                        ])
                        .unwrap();
                }
            }
            tx.execute("UPDATE control_meta SET next_cycle_seq=?1", [cycles + 1])
                .unwrap();
            tx.execute(
                "WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<?1)
                 INSERT INTO cycles SELECT v,'stream-worker',0,'committed',1,2,1,2 FROM n",
                [cycles],
            )
            .unwrap();
            tx.execute_batch(
                "INSERT INTO cycle_selections
                 SELECT c.cycle_seq,s.selection_id,1,1,s.root_identity,1,1,1,NULL
                 FROM cycles c CROSS JOIN selections s;",
            )
            .unwrap();
            tx.commit().unwrap();
        }

        fn durable_bytes(&self) -> BTreeMap<PathBuf, Vec<u8>> {
            self.owner.validate_current(&self.root).unwrap();
            self.prefix_guard.validate_current(&self.prefix).unwrap();
            let mut result = BTreeMap::new();
            for entry in fs::read_dir(&self.root).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_str().unwrap();
                if name.ends_with(".db") || name.ends_with(".db-wal") || name == PREFIX_BINDING_FILE
                {
                    result.insert(PathBuf::from(name), fs::read(&path).unwrap());
                }
            }
            result
        }
    }

    #[test]
    fn large_terminal_history_is_streamed_and_an_old_hidden_row_changes_commitment() {
        let f = Fixture::new();
        // 16,385 entities and 81,925 relations; their long, valid ID cells alone
        // exceed 16 MiB of the rejected old full-image representation.
        f.seed_history(16_385, 5, true);
        let files = f.files();
        let before_bytes = f.durable_bytes();
        let prepared = f.prepare(&files, end()).unwrap();
        assert_eq!(prepared.before().table_rows(5), Some(16_385));
        assert_eq!(prepared.before().table_rows(6), Some(81_925));
        let history_bytes: i64 = f
            .store
            .conn
            .borrow()
            .query_row(
                "SELECT SUM(length(CAST(selection_id AS BLOB))+
                            length(CAST(root_identity AS BLOB))) FROM cycle_selections",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(history_bytes > 16 * 1024 * 1024);
        assert_eq!(
            f.compare(&prepared, end()).unwrap(),
            ReinstallImageMatch::Before
        );
        assert!(
            before_bytes == f.durable_bytes(),
            "streaming changed durable bytes"
        );
        f.store
            .conn
            .borrow()
            .execute("UPDATE cycles SET completed_at_ms=3 WHERE cycle_seq=1", [])
            .unwrap();
        assert!(matches!(
            f.compare(&prepared, end()),
            Err(PortError::GenerationMismatch(_))
        ));
        let changed = f.prepare(&f.files(), end()).unwrap();
        assert_ne!(prepared.before().sha256(), changed.before().sha256());
        assert_eq!(runtime_deadline(), None);
    }

    #[test]
    fn q_plus_one_lost_ack_compares_current_only_without_repeating_adoption() {
        let f = Fixture::new();
        f.seed_history(2, 1, false);
        f.store.conn.borrow().execute_batch(
            "INSERT INTO source_updates
             (source_id,provider_id,last_attempt_at_ms,last_observed_cycle,indexed_revision,
              receipt_cycle,catalog_incarnation,catalog_generation,coverage,update_state,backfill_state)
             VALUES('stream-source','codex',2,2,'stream-revision',2,'stream-incarnation',1,
                    'complete','idle','complete');
             INSERT INTO barriers VALUES('stream-barrier',0,1,2,'awaiting_catalog',0,1,2,NULL,NULL);
             INSERT INTO barrier_selections SELECT 'stream-barrier',selection_id,revision FROM selections;"
        ).unwrap();
        let prep = f.prepare(&f.files(), end()).unwrap();
        f.adopt();
        let after_bytes = f.durable_bytes();
        let commit_count = runtime_commit_seq();
        assert_eq!(f.compare(&prep, end()).unwrap(), ReinstallImageMatch::After);
        assert_eq!(f.compare(&prep, end()).unwrap(), ReinstallImageMatch::After);
        assert_eq!(runtime_commit_seq(), commit_count);
        let conn = f.store.conn.borrow();
        assert_eq!(
            conn.query_row("SELECT control_seq FROM control_meta", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            f.context.old_control_seq + 1
        );
        let source: (String, String, String, String) = conn
            .query_row(
                "SELECT coverage,update_state,error_code,backfill_state FROM source_updates",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            source,
            (
                "partial".into(),
                "deferred".into(),
                "upgrading".into(),
                "pending".into()
            )
        );
        assert_eq!(
            conn.query_row("SELECT state FROM barriers", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "blocked"
        );
        drop(conn);
        assert!(after_bytes == f.durable_bytes());
        let observed_files = f.files();
        let ack = ReinstallAck::from_observations(
            &prep,
            ReinstallCatalogIdentity {
                installation: f.context.installation.clone(),
                incarnation: f.context.incarnation.clone(),
                schema: crate::SCHEMA_VERSION as u32,
                generation: 0,
            },
            observed_files,
        )
        .unwrap();
        let bytes = ack.encode(&prep).unwrap();
        assert!(ReinstallAck::decode(&bytes, &prep).is_ok());
    }

    #[test]
    fn row_streams_and_relation_checks_share_one_snapshot() {
        let f = Fixture::new();
        f.seed_history(2, 1, false);
        let files = f.files();
        let before = f.prepare(&files, end()).unwrap();
        let other = connect_raw(&f.root.join("control.db"), true).unwrap();
        install_reinstall_close_policy(&other).unwrap();
        other
            .execute_batch("PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=-1;")
            .unwrap();
        let mut changed = false;
        let during = with_hook(
            move |step| {
                if step == Step::Table(5) {
                    assert!(!changed);
                    // A new dangling row commits AFTER cycles were streamed,
                    // BEFORE relations are streamed and checked on the reader.
                    other
                        .execute(
                            "INSERT INTO cycle_selections
                         SELECT 999999,selection_id,1,1,root_identity,1,1,1,NULL FROM selections",
                            [],
                        )
                        .unwrap();
                    changed = true;
                }
                Ok(())
            },
            || f.prepare(&files, end()),
        )
        .unwrap();
        assert_eq!(before.before().sha256(), during.before().sha256());
        assert!(matches!(
            f.prepare(&files, end()),
            Err(PortError::SchemaIncompatible(_))
        ));
    }

    #[test]
    fn sealed_stream_denies_mutations_and_restores_original_deadline() {
        let f = Fixture::new();
        f.seed_history(4, 1, false);
        let files = f.files();
        let bytes = f.durable_bytes();
        let reads = Arc::new(AtomicUsize::new(0));
        let denied = Arc::new(AtomicUsize::new(0));
        let observed_reads = Arc::clone(&reads);
        let observed_denied = Arc::clone(&denied);
        f.store
            .conn
            .borrow()
            .authorizer(Some(move |ctx: AuthContext<'_>| {
                let allowed = match ctx.action {
                    AuthAction::Read { .. } | AuthAction::Select => {
                        observed_reads.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    AuthAction::Transaction { .. }
                    | AuthAction::Function { .. }
                    | AuthAction::Recursive => true,
                    AuthAction::Pragma {
                        pragma_name,
                        pragma_value: None,
                    } => matches!(
                        pragma_name,
                        "user_version"
                            | "application_id"
                            | "journal_mode"
                            | "wal_autocheckpoint"
                            | "journal_size_limit"
                    ),
                    _ => false,
                };
                if allowed {
                    Authorization::Allow
                } else {
                    observed_denied.fetch_add(1, Ordering::Relaxed);
                    Authorization::Deny
                }
            }))
            .unwrap();
        let prep = f.prepare(&files, end()).unwrap();
        let first_reads = reads.load(Ordering::Relaxed);
        assert!(first_reads > 0);
        assert_eq!(denied.load(Ordering::Relaxed), 0);
        assert_eq!(
            f.compare(&prep, end()).unwrap(),
            ReinstallImageMatch::Before
        );
        assert!(reads.load(Ordering::Relaxed) > first_reads);
        assert_eq!(denied.load(Ordering::Relaxed), 0);
        for sql in [
            "CREATE TABLE stream_forbidden(value)",
            "CREATE TEMP TABLE stream_forbidden(value)",
            "UPDATE main.control_meta SET control_seq=control_seq",
        ] {
            let count = denied.load(Ordering::Relaxed);
            assert!(matches!(
                f.store.conn.borrow().execute_batch(sql),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
            ));
            assert!(denied.load(Ordering::Relaxed) > count);
        }
        f.store
            .conn
            .borrow()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .unwrap();
        assert!(bytes == f.durable_bytes());
        let outer = end();
        let scope =
            RuntimeDeadlineScope::enter_with_busy(outer, Duration::from_millis(17)).unwrap();
        with_hook(
            move |_| {
                assert_eq!(runtime_deadline(), Some(outer));
                assert_eq!(
                    RUNTIME_BUSY_ALLOWANCE.with(Cell::get),
                    Duration::from_millis(17)
                );
                Ok(())
            },
            || f.prepare(&files, outer + Duration::from_secs(5)).unwrap(),
        );
        assert_eq!(runtime_deadline(), Some(outer));
        drop(scope);
        assert_eq!(runtime_deadline(), None);
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), BUSY_TIMEOUT);
    }

    #[test]
    fn stream_expiry_and_unwind_restore_handlers_without_writes() {
        let f = Fixture::new();
        f.seed_history(4, 1, false);
        let files = f.files();
        let bytes = f.durable_bytes();
        assert!(
            with_hook(
                |_| panic!("expired entry reached a row"),
                || f.prepare(&files, Instant::now()),
            )
            .is_err()
        );
        let expired = with_hook(
            |step| {
                if step == Step::Row(5, 2) {
                    RUNTIME_DEADLINE.with(|deadline| deadline.set(Some(Instant::now())));
                }
                Ok(())
            },
            || f.prepare(&files, end()),
        );
        assert!(matches!(expired, Err(PortError::WriterBusy(_))));
        assert_eq!(runtime_deadline(), None);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            with_hook(
                |step| {
                    if step == Step::Row(6, 1) {
                        panic!("injected row decoder unwind");
                    }
                    Ok(())
                },
                || f.prepare(&files, end()),
            )
        }));
        assert!(panic.is_err());
        assert_eq!(runtime_deadline(), None);
        assert_eq!(RUNTIME_BUSY_ALLOWANCE.with(Cell::get), BUSY_TIMEOUT);
        assert_eq!(
            f.store
                .conn
                .borrow()
                .query_row("PRAGMA busy_timeout", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            250
        );
        assert!(bytes == f.durable_bytes());
        assert!(f.prepare(&files, end()).is_ok());
    }

    #[test]
    fn stream_refuses_schema_storage_type_relations_and_foreign_binding() {
        for sql in [
            "CREATE TABLE unexpected(value)",
            "CREATE TABLE sqlitex_shadow(value)",
            "UPDATE worker_state SET heartbeat_at_ms=x'01'",
            "UPDATE cycle_selections SET selection_id='absent-selection' WHERE cycle_seq=1",
            "UPDATE cycles SET completed_at_ms=-1 WHERE cycle_seq=1",
            "INSERT INTO update_receipts VALUES('r','p','v','v','t','c','a','m',NULL,NULL,NULL,NULL,NULL,NULL,1,1,NULL)",
            "DELETE FROM worker_state",
            "UPDATE control_meta SET control_seq=9223372036854775807",
        ] {
            let f = Fixture::new();
            f.seed_history(2, 1, false);
            f.store.conn.borrow().execute_batch(sql).unwrap();
            let files = f.files();
            let bytes = f.durable_bytes();
            assert!(
                f.prepare(&files, end()).is_err(),
                "invalid fixture was accepted"
            );
            assert!(bytes == f.durable_bytes());
        }
        let f = Fixture::new();
        let other = Fixture::new();
        let files = f.files();
        other.with_binding(|binding| {
            assert!(
                f.store
                    .prepare_reinstall_commitments_with_deadline(
                        ReinstallPreparationRead {
                            binding,
                            context: &f.context,
                            files: &files
                        },
                        end(),
                    )
                    .is_err()
            );
        });
    }

    #[test]
    fn typed_cell_frames_keep_null_integer_text_and_locator_distinct() {
        fn digest(value: impl FnOnce(&mut Sha256)) -> ReinstallDigest {
            let mut hash = Sha256::new();
            value(&mut hash);
            ReinstallDigest(hash.finalize().into())
        }
        let null = digest(|h| Option::<i64>::None.feed(h));
        assert_ne!(null, digest(|h| 0i64.feed(h)));
        assert_ne!(null, digest(|h| "".feed(h)));
        assert_ne!(digest(|h| 1i64.feed(h)), digest(|h| "1".feed(h)));
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let path = temp.path().join("synthetic-\u{754c}");
        let locator = CanonicalLocator::from_path(&path).unwrap();
        let value = Locator(locator.as_str());
        let mut expected = vec![3];
        expected.extend_from_slice(&(locator.as_str().len() as u64).to_be_bytes());
        expected.extend_from_slice(&Sha256::digest(locator.as_str().as_bytes()));
        assert_eq!(
            digest(|h| value.feed(h)),
            ReinstallDigest::of_bytes(&expected)
        );
        assert!(<i64>::decode(ValueRef::Real(1.0)).is_err());
        assert!(<&str>::decode(ValueRef::Blob(b"x")).is_err());
        assert!(<&str>::decode(ValueRef::Text(&[0xff])).is_err());
        let hash = finish_table(table_hash(15, ReceiptRow::COLUMNS).unwrap(), 0);
        assert_eq!(hash.rows, 0);
        assert!(matches!(
            next_row_count(u64::MAX),
            Err(PortError::SchemaIncompatible(_))
        ));
    }
}
