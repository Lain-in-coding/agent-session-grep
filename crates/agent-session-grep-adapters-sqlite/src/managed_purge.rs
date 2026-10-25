//! Owned managed-catalog withdrawal cleanup. Provider histories are never opened.
//!
//! One original deadline covers drain, catalog mutation, cache retirement and
//! owned backup cleanup. Durable denial is independent of ingestion state.
//! PolicyOwner is borrowed only for short control transactions, never while
//! draining, copying, checkpointing, hashing or removing files.
use crate::{
    SqliteControlStore, WriterLease,
    control::{
        BackupState, InstallationLockAuthority, PURGE_LOCK_KEY, PurgeCheckpoint, PurgeFailure,
        PurgeOwner, PurgeTransition, validate_private_directory,
    },
    managed_cache::ManagedCache,
    managed_locks::{ExclusiveGuard, JobLockKey, LockKind, RootIdentity},
    managed_maintenance::{
        PurgeOutcome, catalog_coverage_is_classified, catalog_journal_is_content_free,
        purge_backup, set_sql_deadline, source_binding_is_retired, validate_identity,
        verify_backup_until, verify_derived_integrity,
    },
    managed_store::validate_catalog_path,
};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider,
    control::{
        CanonicalLocator, ControlId, ControlStore, MaintenanceState, PolicyEpoch, PurgeJob,
        PurgeState, ReadPolicy, RequestIntersection,
    },
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Use this exact domain when acquiring the guard supplied to bind_purge_owner.
pub fn purge_lock_kind() -> PortResult<LockKind> {
    Ok(LockKind::MaintenanceJob(JobLockKey::parse(PURGE_LOCK_KEY)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeStage {
    Complete,
    Pending(PurgeFailure),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    pub jobs: Vec<PurgeJob>,
    pub sources_retired: u64,
    pub rows_removed: u64,
    pub generation: Option<u64>,
    pub catalog: PurgeStage,
    pub cache: PurgeStage,
    pub backups: PurgeStage,
}
impl PurgeReport {
    pub fn complete(&self) -> bool {
        self.catalog == PurgeStage::Complete
            && self.cache == PurgeStage::Complete
            && self.backups == PurgeStage::Complete
            && self
                .jobs
                .iter()
                .all(|job| job.state == PurgeState::Complete)
    }
}

const MAX_PRIVATE_ARTIFACTS: usize = 4096;
const MAX_PRIVATE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// Integration settings/recovery inventory, not source evidence. The CLI owns
/// these schemas and must decode each record, validate its installation/root
/// and referenced hashes/operation chain before constructing this evidence.
/// Merely matching a file name or JSON schema string is not classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateArtifactClass {
    SetupInventory,
    NativeRegistration,
    UserPathRegistration,
    UpdateJournal,
    LegacyMigrationIntent,
    /// Exact content-free restore journal validated by the maintenance adapter.
    /// Staging/displaced catalog images require canonical backup registration.
    CatalogRestoreReceipt,
}

/// One exact, already-classified private file. Paths/bytes/digests never enter a
/// public response. The constructor checks finite known layouts and bounds; it
/// does not replace the caller's schema/ownership proof. No directory wildcard
/// or catalog/cache/backup classification is supported through this API.
#[derive(Clone)]
pub struct ClassifiedPrivateArtifact {
    class: PrivateArtifactClass,
    relative: String,
    size: u64,
    digest: String,
}
impl fmt::Debug for ClassifiedPrivateArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClassifiedPrivateArtifact([private])")
    }
}
impl ClassifiedPrivateArtifact {
    pub fn new(
        class: PrivateArtifactClass,
        relative: &str,
        size: u64,
        blake3_digest: &str,
    ) -> PortResult<Self> {
        if !private_locator(relative)
            || !lower_hex(blake3_digest, 64)
            || known_layout(class, relative).is_none_or(|limit| size > limit)
        {
            return Err(invalid());
        }
        Ok(Self {
            class,
            relative: relative.into(),
            size,
            digest: blake3_digest.into(),
        })
    }
}

/// Request-local classified evidence bound to the root captured BEFORE the CLI
/// read its private records and the exact permission epoch. It grants no source
/// permission, cleanup authority or OS ownership. Pause/control job sequences
/// may change independently; a changed epoch/root invalidates the whole set.
/// No SQLite transaction or handles are held across requests.
pub struct PrivateArtifactInventory {
    root: RootIdentity,
    installation: ControlId,
    epoch: PolicyEpoch,
    files: BTreeMap<String, ClassifiedPrivateArtifact>,
}
impl fmt::Debug for PrivateArtifactInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateArtifactInventory([private])")
    }
}
impl PrivateArtifactInventory {
    pub fn bind(
        control: &SqliteControlStore,
        expected_root: RootIdentity,
        expected_epoch: PolicyEpoch,
        artifacts: Vec<ClassifiedPrivateArtifact>,
    ) -> PortResult<Self> {
        if artifacts.len() > MAX_PRIVATE_ARTIFACTS {
            return Err(invalid());
        }
        let mut files = BTreeMap::new();
        let mut folded = BTreeSet::new();
        let mut bytes = 0_u64;
        for artifact in artifacts {
            bytes = bytes.checked_add(artifact.size).ok_or_else(invalid)?;
            if bytes > MAX_PRIVATE_ARTIFACT_BYTES
                || !folded.insert(artifact.relative.to_ascii_lowercase())
            {
                return Err(invalid());
            }
            files.insert(artifact.relative.clone(), artifact);
        }
        let value = Self {
            root: expected_root,
            installation: control.status()?.policy.installation_id,
            epoch: expected_epoch,
            files,
        };
        value.validate(control)?;
        Ok(value)
    }
    /// Private caller-only proof coordinates. This does not authorize removal;
    /// callers must recheck the captured root/epoch and each opened file.
    pub fn artifacts(&self) -> impl Iterator<Item = (PrivateArtifactClass, &str, u64, &str)> {
        self.files.values().map(|artifact| {
            (
                artifact.class,
                artifact.relative.as_str(),
                artifact.size,
                artifact.digest.as_str(),
            )
        })
    }
    fn validate(&self, control: &SqliteControlStore) -> PortResult<()> {
        control.validate_live_root()?;
        let status = control.status()?;
        if !control.matches_root(self.root)
            || RootIdentity::read(control.private_root())? != self.root
            || status.policy.installation_id != self.installation
            || status.policy.policy_epoch != self.epoch
        {
            return Err(changed());
        }
        Ok(())
    }
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
fn numbered(value: &str, prefix: &str, suffix: &str, min: usize, max: usize) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|v| v.strip_suffix(suffix))
        .is_some_and(|v| (min..=max).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()))
}
fn setup_name(value: &str) -> bool {
    ["setup-hosts-", "setup-autostart-"].iter().any(|prefix| {
        [".json", ".pending"].iter().any(|suffix| {
            value
                .strip_prefix(prefix)
                .and_then(|v| v.strip_suffix(suffix))
                .is_some_and(|id| lower_hex(id, 32))
        })
    })
}
fn update_image(value: &str) -> bool {
    let Some((sequence, rest)) = value.split_once('-') else {
        return false;
    };
    let Some((key, extension)) = rest.rsplit_once('.') else {
        return false;
    };
    !sequence.is_empty()
        && sequence.len() <= 20
        && sequence.bytes().all(|b| b.is_ascii_digit())
        && matches!(extension, "before" | "new" | "displaced")
        && matches!(
            key,
            "package_manifest"
                | "package_receipt"
                | "release_manifest"
                | "checksums"
                | "current"
                | "installer_sh"
                | "installer_powershell"
                | "install_guide"
                | "readme"
                | "changelog"
                | "license_mit"
                | "license_apache"
                | "notice"
                | "security"
                | "dependencies_json"
                | "dependencies_csv"
        )
}
/// File sizes mirror the emitting integration's published bounds. Update stage
/// binaries and unknown retained files are intentionally not generalized here.
fn known_layout(class: PrivateArtifactClass, relative: &str) -> Option<u64> {
    use PrivateArtifactClass::*;
    let parts: Vec<_> = relative.split('/').collect();
    match (class, parts.as_slice()) {
        (SetupInventory, [name]) if setup_name(name) => Some(1024 * 1024),
        (NativeRegistration, ["native-autostart", "owner.json"]) => Some(16384),
        (NativeRegistration, ["native-autostart", "owner.lock"]) => Some(0),
        (NativeRegistration, ["native-autostart", id, name]) if lower_hex(id, 32) => {
            if numbered(name, "state-", ".json", 4, 10) {
                Some(16 * 1024 * 1024)
            } else if matches!(*name, "staged.bin" | "displaced.bin") {
                Some(1024 * 1024)
            } else if name
                .strip_prefix("observed-")
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(|digest| lower_hex(digest, 64))
            {
                Some(16 * 1024 * 1024)
            } else {
                None
            }
        }
        (UserPathRegistration, ["user-path", "owner.json"]) => Some(65536),
        (UserPathRegistration, ["user-path", id, name]) if lower_hex(id, 32) => match *name {
            "operation.json" | "intent.json" | "receipt.json" => Some(65536),
            "before.bin" | "after.bin" => Some(1024 * 1024),
            _ => None,
        },
        (UpdateJournal, ["update", name])
            if matches!(
                *name,
                "state.json"
                    | "state.next.json"
                    | "state.previous.json"
                    | "state.reconcile.json"
                    | "state.reconciled-old.json"
                    | "state.archive.json"
            ) =>
        {
            Some(65536)
        }
        (UpdateJournal, ["update", id, name]) if ControlId::parse(id).is_ok() => {
            if matches!(*name, "completed-state.json" | "native-binding.json") {
                Some(65536)
            } else if update_image(name) {
                Some(1024 * 1024)
            } else {
                None
            }
        }
        (CatalogRestoreReceipt, [name])
            if name
                .strip_prefix("restore-")
                .and_then(|s| s.strip_suffix(".jsonl"))
                .is_some_and(|digest| lower_hex(digest, 32)) =>
        {
            Some(256 * 1024)
        }
        (LegacyMigrationIntent, [name])
            if matches!(
                *name,
                "legacy-migration-command.json"
                    | "legacy-migration-command.pending"
                    | "legacy-migration-control-start.json"
            ) =>
        {
            Some(65536)
        }
        (LegacyMigrationIntent, [name])
            if name
                .strip_suffix(".asg-legacy-file")
                .or_else(|| name.strip_suffix(".asg-managed-create"))
                .is_some_and(|base| {
                    !base.is_empty() && !matches!(base, "control.db" | "continuations.db")
                }) =>
        {
            Some(65536)
        }
        _ => None,
    }
}
fn invalid() -> PortError {
    PortError::InvalidRequest("invalid owned purge operation".into())
}
fn storage() -> PortError {
    PortError::Backend("owned purge storage is unavailable".into())
}
fn incompatible() -> PortError {
    PortError::SchemaIncompatible("owned purge classification is unavailable".into())
}
fn changed() -> PortError {
    PortError::GenerationMismatch("owned purge policy changed".into())
}
fn check(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(PortError::WriterBusy("owned purge deadline reached".into()))
    } else {
        Ok(())
    }
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => PortError::WriterBusy("owned purge storage is busy".into()),
        _ => incompatible(),
    }
}
fn failure(error: &PortError, deadline: Instant) -> PurgeFailure {
    match error {
        PortError::WriterBusy(_) if Instant::now() >= deadline => PurgeFailure::Deadline,
        PortError::WriterBusy(_) => PurgeFailure::Busy,
        PortError::GenerationMismatch(_) => PurgeFailure::PolicyChanged,
        PortError::SchemaIncompatible(_) => PurgeFailure::UnclassifiedCatalog,
        _ => PurgeFailure::Storage,
    }
}
/// The control scope deliberately has a 1ms SQLite busy allowance. Brief
/// contention may refuse a transaction, so retry only that typed class within
/// the original slice. Every closure releases PolicyOwner before the wait.
fn retry_control_before<T>(
    deadline: Instant,
    mut operation: impl FnMut() -> PortResult<T>,
) -> PortResult<T> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    loop {
        check(deadline)?;
        match operation() {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}

fn acquire(root: &Path, kind: LockKind, deadline: Instant) -> PortResult<ExclusiveGuard> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    loop {
        check(deadline)?;
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}
fn lease(root: &Path, deadline: Instant) -> PortResult<WriterLease> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    loop {
        check(deadline)?;
        match WriterLease::try_acquire(root) {
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// Run unfinished owned purge jobs for the current policy. No indexing/start/
/// pause/trust state is changed. Installation authority is required only when
/// removing an owned rollback artifact; absent authority stays explicit.
pub fn run(
    control: &SqliteControlStore,
    catalog: &Path,
    owner: &PurgeOwner<'_>,
    installation: Option<&InstallationLockAuthority<'_>>,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<PurgeReport> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    control.with_purge_deadline(deadline, || {
        run_bounded(
            control,
            catalog,
            owner,
            installation,
            None,
            now_ms,
            deadline,
        )
    })
}

/// Add only caller-validated non-corpus files to private-root accounting. Every
/// declared file is rehashed before and after backup cleanup under the same
/// root/epoch and original deadline. Unknown/missing/changed files remain
/// Pending(UnclassifiedArtifact); settings and recovery records are never
/// deleted by source purge. Backups/cache/catalog keep their existing authority.
pub fn run_with_inventory(
    control: &SqliteControlStore,
    catalog: &Path,
    owner: &PurgeOwner<'_>,
    installation: Option<&InstallationLockAuthority<'_>>,
    inventory: &PrivateArtifactInventory,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<PurgeReport> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    control.with_purge_deadline(deadline, || {
        inventory.validate(control)?;
        run_bounded(
            control,
            catalog,
            owner,
            installation,
            Some(inventory),
            now_ms,
            deadline,
        )
    })
}

fn run_bounded(
    control: &SqliteControlStore,
    catalog: &Path,
    owner: &PurgeOwner<'_>,
    installation: Option<&InstallationLockAuthority<'_>>,
    inventory: Option<&PrivateArtifactInventory>,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<PurgeReport> {
    let deadline = SqliteControlStore::effective_runtime_deadline(deadline);
    owner.validate(control)?;
    check(deadline)?;
    if now_ms < 0 {
        return Err(invalid());
    }
    if let Some(installation) = installation {
        installation.validate(control)?;
    }
    validate_catalog_path(catalog)?;
    if !catalog.is_absolute() || catalog.parent() != Some(control.private_root()) {
        return Err(invalid());
    }
    let status = control.status()?;
    if status.policy.maintenance.state != MaintenanceState::Idle {
        return Err(PortError::WriterBusy(
            "owned purge waits for installation maintenance".into(),
        ));
    }
    let jobs: Vec<_> = control
        .purge_jobs()?
        .into_iter()
        .filter(|job| job.state != PurgeState::Complete)
        .collect();
    let mut report = PurgeReport {
        jobs,
        sources_retired: 0,
        rows_removed: 0,
        generation: None,
        catalog: PurgeStage::Pending(PurgeFailure::Busy),
        cache: PurgeStage::Pending(PurgeFailure::CachePending),
        backups: PurgeStage::Pending(PurgeFailure::ArtifactPending),
    };
    for job in &report.jobs {
        check(deadline)?;
        retry_control_before(deadline, || {
            let lock = acquire(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let bound = control.bind_control_root(&lock)?;
            control.claim_purge_job(
                control.status()?.policy.control_seq,
                owner,
                &bound,
                &job.id,
                now_ms,
            )
        })?;
    }
    let outcome = run_claimed(
        control,
        catalog,
        owner,
        installation,
        inventory,
        (now_ms, deadline),
        &mut report,
    );
    match outcome {
        Ok(()) => {
            report.jobs = control
                .purge_jobs()?
                .into_iter()
                .filter(|job| report.jobs.iter().any(|prior| prior.id == job.id))
                .collect();
            Ok(report)
        }
        Err(error) => {
            let reason = failure(&error, deadline);
            if report.catalog != PurgeStage::Complete {
                report.catalog = PurgeStage::Pending(reason);
            } else if report.cache != PurgeStage::Complete {
                report.cache = PurgeStage::Pending(reason);
            } else {
                report.backups = PurgeStage::Pending(reason);
            }
            // Never invent a fresh budget for a terminal status write. If the
            // original budget is exhausted, the last durable claim stays
            // resumable under the next real OS owner.
            if Instant::now() < deadline {
                block_jobs(control, owner, now_ms, deadline, reason)?;
            }
            report.jobs = control
                .purge_jobs()?
                .into_iter()
                .filter(|job| report.jobs.iter().any(|prior| prior.id == job.id))
                .collect();
            Ok(report)
        }
    }
}

fn block_jobs(
    control: &SqliteControlStore,
    owner: &PurgeOwner<'_>,
    now_ms: i64,
    deadline: Instant,
    reason: PurgeFailure,
) -> PortResult<()> {
    for job in control
        .purge_jobs()?
        .into_iter()
        .filter(|job| job.state != PurgeState::Complete)
    {
        let previous = control.purge_job_status(&job.id)?;
        if previous.owner_nonce.as_ref() != Some(owner.nonce()) {
            continue;
        }
        let lock = acquire(control.private_root(), LockKind::PolicyOwner, deadline)?;
        let bound = control.bind_control_root(&lock)?;
        let policy = control.status()?.policy;
        control.advance_purge_job(
            policy.control_seq,
            owner,
            &bound,
            &job.id,
            PurgeTransition {
                state: PurgeState::Blocked,
                checkpoint: previous.checkpoint.unwrap_or(PurgeCheckpoint::Claimed),
                failure: Some(reason),
                verified_epoch: policy.policy_epoch,
                now_ms,
            },
        )?;
    }
    Ok(())
}

fn advance_jobs(
    control: &SqliteControlStore,
    owner: &PurgeOwner<'_>,
    jobs: &[PurgeJob],
    transition: PurgeTransition,
    deadline: Instant,
) -> PortResult<()> {
    for job in jobs {
        retry_control_before(deadline, || {
            let lock = acquire(control.private_root(), LockKind::PolicyOwner, deadline)?;
            let bound = control.bind_control_root(&lock)?;
            let prior = control.purge_job_status(&job.id)?;
            // A completed control commit can return Busy after its durable
            // point. Recognize only this exact terminal state/checkpoint; do
            // not reclaim or repeat a completed job after losing its nonce.
            if transition.state == PurgeState::Complete
                && prior.job.state == PurgeState::Complete
                && prior.checkpoint == Some(transition.checkpoint)
                && prior.failure.is_none()
            {
                return Ok(());
            }
            control.advance_purge_job(
                control.status()?.policy.control_seq,
                owner,
                &bound,
                &job.id,
                PurgeTransition { ..transition },
            )?;
            Ok(())
        })?;
    }
    Ok(())
}

fn run_claimed(
    control: &SqliteControlStore,
    catalog: &Path,
    owner: &PurgeOwner<'_>,
    installation: Option<&InstallationLockAuthority<'_>>,
    inventory: Option<&PrivateArtifactInventory>,
    time: (i64, Instant),
    report: &mut PurgeReport,
) -> PortResult<()> {
    let (now_ms, deadline) = time;
    // Catalog handles are drained before acquiring the writer/emission locks.
    // Never hold PolicyOwner while waiting for a reader or writer to close.
    let handles = acquire(control.private_root(), LockKind::CatalogHandles, deadline)?;
    let writer = lease(control.private_root(), deadline)?;
    let emission = acquire(control.private_root(), LockKind::PolicyEmission, deadline)?;
    owner.validate(control)?;
    control.validate_catalog_file(catalog)?;
    let mut conn = Connection::open_with_flags(
        catalog,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    set_sql_deadline(&conn, deadline)?;
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;")
        .map_err(sql)?;
    // A purge invocation can also finish a crashed revoke's drain. Settlement
    // is emission-only proof; a blocked cleanup is still never called clean.
    for intent in control
        .status()?
        .policy
        .revocations
        .into_iter()
        .filter(|intent| {
            intent.state == agent_session_grep_ports::control::RevocationState::AwaitingDrain
        })
    {
        let policy_owner = acquire(control.private_root(), LockKind::PolicyOwner, deadline)?;
        control.settle_revocation(
            control.status()?.policy.control_seq,
            &policy_owner,
            &emission,
            &intent.id,
            now_ms,
        )?;
    }
    let policy = control.read_policy(RequestIntersection::Selected)?;
    validate_identity(&conn, &policy.installation_id)?;
    if policy.maintenance.state != MaintenanceState::Idle {
        return Err(changed());
    }
    let mutation = purge_catalog(
        &mut conn,
        control,
        owner,
        &policy,
        &report.jobs,
        now_ms,
        deadline,
    )?;
    report.sources_retired = mutation.sources;
    report.rows_removed = mutation.rows;
    report.generation = Some(mutation.generation);
    advance_jobs(
        control,
        owner,
        &report.jobs,
        PurgeTransition {
            state: PurgeState::Artifacts,
            checkpoint: PurgeCheckpoint::CatalogCommitted,
            failure: None,
            verified_epoch: policy.policy_epoch,
            now_ms,
        },
        deadline,
    )?;
    // Vacuum/checkpoint may fail after a durable content transaction. Such a
    // failure stays resumable; it is never labeled physical cleanup complete.
    physical_catalog_cleanup(&conn, deadline)?;
    report.catalog = PurgeStage::Complete;
    let cache = ManagedCache::at(control.private_root(), control).map_err(|_| storage())?;
    match cache.purge_all(control, &emission, deadline) {
        Ok(result) if result.wal_drained => {
            physical_cache_cleanup(control, deadline)?;
            report.cache = PurgeStage::Complete;
        }
        _ => {
            report.cache = PurgeStage::Pending(PurgeFailure::CachePending);
            block_jobs(control, owner, now_ms, deadline, PurgeFailure::CachePending)?;
            return Ok(());
        }
    }
    advance_jobs(
        control,
        owner,
        &report.jobs,
        PurgeTransition {
            state: PurgeState::Artifacts,
            checkpoint: PurgeCheckpoint::CacheRetired,
            failure: None,
            verified_epoch: policy.policy_epoch,
            now_ms,
        },
        deadline,
    )?;
    if !private_root_is_accounted(control, catalog, inventory, deadline)? {
        report.backups = PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact);
        block_jobs(
            control,
            owner,
            now_ms,
            deadline,
            PurgeFailure::UnclassifiedArtifact,
        )?;
        return Ok(());
    }
    let backups = purge_backups(control, owner, installation, now_ms, deadline)?;
    report.backups = backups;
    if let PurgeStage::Pending(reason) = backups {
        block_jobs(control, owner, now_ms, deadline, reason)?;
        return Ok(());
    }
    // Recheck the entire backup set immediately before declaring terminal
    // progress. A later policy epoch is never passed off as the verified one.
    if !private_root_is_accounted(control, catalog, inventory, deadline)?
        || !backup_directory_is_accounted(control, deadline)?
    {
        report.backups = PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact);
        block_jobs(
            control,
            owner,
            now_ms,
            deadline,
            PurgeFailure::UnclassifiedArtifact,
        )?;
        return Ok(());
    }
    verify_catalog_clean(&conn, control, deadline)?;
    if control
        .read_policy(RequestIntersection::Selected)?
        .policy_epoch
        != policy.policy_epoch
    {
        return Err(changed());
    }
    advance_jobs(
        control,
        owner,
        &report.jobs,
        PurgeTransition {
            state: PurgeState::Verifying,
            checkpoint: PurgeCheckpoint::ArtifactsVerified,
            failure: None,
            verified_epoch: policy.policy_epoch,
            now_ms,
        },
        deadline,
    )?;
    advance_jobs(
        control,
        owner,
        &report.jobs,
        PurgeTransition {
            state: PurgeState::Complete,
            checkpoint: PurgeCheckpoint::ArtifactsVerified,
            failure: None,
            verified_epoch: policy.policy_epoch,
            now_ms,
        },
        deadline,
    )?;
    report.jobs = control
        .purge_jobs()?
        .into_iter()
        .filter(|job| report.jobs.iter().any(|prior| prior.id == job.id))
        .collect();
    // SQLite closes before either the exclusive handles or the writer lease.
    drop(conn);
    drop(emission);
    drop(writer);
    drop(handles);
    Ok(())
}

struct CatalogMutation {
    sources: u64,
    rows: u64,
    generation: u64,
}

fn purge_catalog(
    conn: &mut Connection,
    control: &SqliteControlStore,
    owner: &PurgeOwner<'_>,
    policy: &ReadPolicy,
    jobs: &[PurgeJob],
    now_ms: i64,
    deadline: Instant,
) -> PortResult<CatalogMutation> {
    check(deadline)?;
    set_sql_deadline(conn, deadline)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql)?;
    if !catalog_coverage_is_classified(&tx)? || !catalog_journal_is_content_free(&tx, deadline)? {
        return Err(incompatible());
    }
    tx.execute_batch("CREATE TEMP TABLE purge_sources(source_id TEXT PRIMARY KEY,source_path TEXT NOT NULL UNIQUE) WITHOUT ROWID;").map_err(sql)?;
    let sources = withdrawn_sources(&tx, policy, deadline)?;
    for (source, path) in &sources {
        set_sql_deadline(&tx, deadline)?;
        tx.execute(
            "INSERT INTO purge_sources VALUES(?1,?2)",
            params![source.as_str(), path],
        )
        .map_err(sql)?;
    }
    set_sql_deadline(&tx, deadline)?;
    let (generation, epoch): (i64, i64) = tx
        .query_row(
            "SELECT active_generation,destructive_epoch FROM store_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql)?;
    let mut affected = 0_i64;
    for (source, path) in &sources {
        check(deadline)?;
        if !source_binding_is_retired(&tx, source.as_str(), path)? {
            affected += 1;
        }
    }
    let mut rows = 0_usize;
    if affected > 0 {
        for table in [
            "fts",
            "session_fts",
            "projection_fts",
            "session_metadata_fts",
        ] {
            check(deadline)?;
            tx.execute(
                &format!("INSERT INTO {table}({table},rank) VALUES('secure-delete',1)"),
                [],
            )
            .map_err(sql)?;
        }
        tx.execute_batch(
            "CREATE TEMP TABLE purge_entities(entity_id TEXT PRIMARY KEY) WITHOUT ROWID;
             INSERT OR IGNORE INTO purge_entities SELECT message_id FROM source_projections JOIN purge_sources USING(source_id);
             INSERT OR IGNORE INTO purge_entities SELECT entity_id FROM source_entity_projections JOIN purge_sources USING(source_id);
             INSERT OR IGNORE INTO purge_entities SELECT message_id FROM source_membership JOIN purge_sources USING(source_path);
             INSERT OR IGNORE INTO purge_entities SELECT document_id FROM source_membership JOIN purge_sources USING(source_path) WHERE document_id IS NOT NULL;
             INSERT OR IGNORE INTO purge_entities SELECT session_id FROM source_occurrences JOIN purge_sources USING(source_id);
             INSERT OR IGNORE INTO purge_entities SELECT session_id FROM source_session_projections JOIN purge_sources USING(source_id);
             INSERT OR IGNORE INTO purge_entities SELECT session_id FROM source_session_resume_claims JOIN purge_sources USING(source_path);
             CREATE TEMP TABLE purge_placements(placement_id TEXT PRIMARY KEY) WITHOUT ROWID;
             INSERT INTO purge_placements SELECT DISTINCT placement_id FROM source_placement_membership JOIN purge_sources USING(source_path);
             CREATE TEMP TABLE purge_activities(activity_id TEXT PRIMARY KEY) WITHOUT ROWID;
             INSERT INTO purge_activities SELECT DISTINCT activity_id FROM tool_activity_membership JOIN purge_sources USING(source_path);
             CREATE TEMP TABLE purge_usages(usage_id TEXT PRIMARY KEY) WITHOUT ROWID;
             INSERT INTO purge_usages SELECT DISTINCT usage_id FROM usage_event_membership JOIN purge_sources USING(source_path);
             CREATE TEMP TABLE purge_discoveries(cycle_seq INTEGER,selection_id TEXT,PRIMARY KEY(cycle_seq,selection_id)) WITHOUT ROWID;
             INSERT INTO purge_discoveries SELECT DISTINCT cycle_seq,selection_id FROM discovery_sources JOIN purge_sources USING(source_id);"
        ).map_err(sql)?;
        let withdrawn: Vec<_> = sources
            .iter()
            .map(|(source, _)| agent_session_grep_ports::managed::SourceId::parse(source.as_str()))
            .collect::<PortResult<_>>()?;
        let context_cleanup =
            crate::managed_source_context::purge_sources_in_tx(&tx, &withdrawn, policy, deadline)?;
        rows += usize::try_from(
            context_cleanup
                .dependencies_withdrawn
                .checked_add(context_cleanup.contexts_removed)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        rows += execute_deletes(&tx, deadline)?;
        verify_derived_integrity(&tx, deadline)?;
        let target = generation.checked_add(1).ok_or_else(invalid)?;
        let destructive = epoch.checked_add(1).ok_or_else(invalid)?;
        let count = tx.execute(
            "UPDATE store_metadata SET active_generation=?1,destructive_epoch=?2 WHERE singleton=1 AND active_generation=?3 AND destructive_epoch=?4",
            params![target, destructive, generation, epoch],
        ).map_err(sql)?;
        if count != 1 {
            return Err(changed());
        }
        // Content-free durable outbox receipt proves the purge content commit.
        // Retrying after control-ack loss observes retired heads and has no
        // second destructive effect or generation advance.
        let operation = format!(
            "purge_{}_{}",
            jobs.first().map_or(owner.nonce(), |job| &job.id).as_str(),
            policy.policy_epoch.get()
        );
        let digest = blake3::hash(operation.as_bytes()).to_hex().to_string();
        tx.execute(
            "INSERT INTO index_batches(operation_id,base_generation,target_generation,state,operation_digest,upsert_ids_json,delete_ids_json,durable_point,created_at_ms,committed_at_ms) VALUES(?1,?2,?3,'activated',?4,'[]','[]','activated',?5,?5)",
            params![operation, generation, target, digest, now_ms],
        ).map_err(sql)?;
    }
    owner.validate(control)?;
    if control
        .read_policy(RequestIntersection::Selected)?
        .policy_epoch
        != policy.policy_epoch
    {
        return Err(changed());
    }
    set_sql_deadline(&tx, deadline)?;
    tx.commit().map_err(sql)?;
    let result = CatalogMutation {
        sources: u64::try_from(affected).map_err(|_| incompatible())?,
        rows: rows as u64,
        generation: u64::try_from(generation + i64::from(affected > 0))
            .map_err(|_| incompatible())?,
    };
    if control
        .read_policy(RequestIntersection::Selected)?
        .policy_epoch
        != policy.policy_epoch
    {
        return Err(changed());
    }
    Ok(result)
}

fn withdrawn_sources(
    conn: &Connection,
    policy: &ReadPolicy,
    deadline: Instant,
) -> PortResult<Vec<(ControlId, String)>> {
    let mut stmt = conn
        .prepare("SELECT source_id,source_path,provider_id FROM source_bindings ORDER BY source_id")
        .map_err(sql)?;
    let mut query = stmt.query([]).map_err(sql)?;
    let mut sources = Vec::new();
    while let Some(row) = query.next().map_err(sql)? {
        check(deadline)?;
        let source =
            ControlId::parse(&row.get::<_, String>(0).map_err(sql)?).map_err(|_| incompatible())?;
        let path = row.get::<_, String>(1).map_err(sql)?;
        let provider_wire: String = row.get(2).map_err(sql)?;
        let provider = SearchProvider::parse(&provider_wire)
            .filter(|provider| provider.as_str() == provider_wire)
            .ok_or_else(incompatible)?;
        let locator = CanonicalLocator::parse(&path).map_err(|_| incompatible())?;
        if !policy.allows_source(provider, &locator, &source) {
            sources.push((source, path));
        }
    }
    Ok(sources)
}

fn execute_deletes(conn: &Connection, deadline: Instant) -> PortResult<usize> {
    let mut removed = 0;
    for statement in [
        // All legacy merged values touched by a withdrawn contributor are
        // removed. Surviving permitted per-source originals remain unchanged.
        "DELETE FROM fts WHERE rowid IN(SELECT fts_rowid FROM fts_ids JOIN purge_entities ON wire_id=entity_id)",
        "DELETE FROM fts_ids WHERE wire_id IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM catalog WHERE id IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM message_vec WHERE wire_id IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM session_fts WHERE rowid IN(SELECT fts_rowid FROM session_fts_ids JOIN purge_entities ON session_wire=entity_id)",
        "DELETE FROM session_fts_ids WHERE session_wire IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM session_titles WHERE session_wire IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM session_repo_slugs WHERE session_wire IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM source_membership WHERE source_path IN(SELECT source_path FROM purge_sources) OR message_id IN(SELECT entity_id FROM purge_entities) OR document_id IN(SELECT entity_id FROM purge_entities)",
        "DELETE FROM source_placement_membership WHERE source_path IN(SELECT source_path FROM purge_sources) OR placement_id IN(SELECT placement_id FROM purge_placements)",
        "DELETE FROM source_relation_scans WHERE source_path IN(SELECT source_path FROM purge_sources)",
        "DELETE FROM source_session_resume_claims WHERE source_path IN(SELECT source_path FROM purge_sources)",
        "DELETE FROM tool_activity_membership WHERE source_path IN(SELECT source_path FROM purge_sources) OR activity_id IN(SELECT activity_id FROM purge_activities)",
        "DELETE FROM usage_event_membership WHERE source_path IN(SELECT source_path FROM purge_sources) OR usage_id IN(SELECT usage_id FROM purge_usages)",
        "DELETE FROM message_edges WHERE child_placement_id IN(SELECT placement_id FROM purge_placements)",
        "DELETE FROM message_placements WHERE placement_id IN(SELECT placement_id FROM purge_placements)",
        "DELETE FROM tool_activities WHERE activity_id IN(SELECT activity_id FROM purge_activities)",
        "DELETE FROM usage_events WHERE usage_id IN(SELECT usage_id FROM purge_usages)",
        "DELETE FROM source_scans WHERE source_path IN(SELECT source_path FROM purge_sources)",
        "DELETE FROM source_projections WHERE source_id IN(SELECT source_id FROM purge_sources)",
        "DELETE FROM source_occurrences WHERE source_id IN(SELECT source_id FROM purge_sources)",
        "DELETE FROM source_entity_projections WHERE source_id IN(SELECT source_id FROM purge_sources)",
        "DELETE FROM source_session_projections WHERE source_id IN(SELECT source_id FROM purge_sources)",
        "DELETE FROM source_scope_claims WHERE source_id IN(SELECT source_id FROM purge_sources)",
        "DELETE FROM receipt_selection_claims WHERE revision_id IN(SELECT revision_id FROM source_revision_receipts JOIN purge_sources USING(source_id))",
        // Invalidate the whole discovery proof containing a removed revision.
        "DELETE FROM discovery_sources WHERE (cycle_seq,selection_id) IN(SELECT cycle_seq,selection_id FROM purge_discoveries)",
        "DELETE FROM discovery_receipts WHERE (cycle_seq,selection_id) IN(SELECT cycle_seq,selection_id FROM purge_discoveries)",
        "DELETE FROM source_revision_receipts WHERE source_id IN(SELECT source_id FROM purge_sources)",
        "INSERT INTO source_heads(source_id,update_state) SELECT source_id,'revoked' FROM purge_sources WHERE true ON CONFLICT(source_id) DO UPDATE SET visible_revision_id=NULL,latest_receipt_id=NULL,content_set_digest=NULL,last_attempt_id=NULL,update_state='revoked',observed_cycle_seq=NULL",
    ] {
        set_sql_deadline(conn, deadline)?;
        removed += conn.execute(statement, []).map_err(sql)?;
    }
    Ok(removed)
}

fn physical_catalog_cleanup(conn: &Connection, deadline: Instant) -> PortResult<()> {
    set_sql_deadline(conn, deadline)?;
    // Merge away historical FTS delete-keys that predate secure-delete. This
    // does not rebuild or manufacture a source projection. VACUUM alone cannot
    // remove obsolete terms still retained inside an FTS segment.
    for table in [
        "fts",
        "session_fts",
        "projection_fts",
        "session_metadata_fts",
    ] {
        set_sql_deadline(conn, deadline)?;
        conn.execute(
            &format!("INSERT INTO {table}({table}) VALUES('optimize')"),
            [],
        )
        .map_err(sql)?;
    }
    verify_derived_integrity(conn, deadline)?;
    set_sql_deadline(conn, deadline)?;
    conn.execute_batch("VACUUM;").map_err(sql)?;
    set_sql_deadline(conn, deadline)?;
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(sql)?;
    if busy != 0 {
        return Err(PortError::WriterBusy(
            "owned purge catalog WAL is pinned".into(),
        ));
    }
    check(deadline)
}

fn physical_cache_cleanup(control: &SqliteControlStore, deadline: Instant) -> PortResult<()> {
    check(deadline)?;
    let path = ManagedCache::path(control.private_root());
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(storage()),
        Ok(_) => control.validate_catalog_file(&path)?,
    }
    control.validate_live_root()?;
    // purge_all validated the existing cache schema and invalidated every
    // token under the emission drain. Repack historical free pages as well;
    // do not merely call DELETE/WAL truncation physical cleanup.
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    set_sql_deadline(&conn, deadline)?;
    let retained: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM result_sets) OR EXISTS(SELECT 1 FROM result_sources)",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if retained {
        return Err(changed());
    }
    set_sql_deadline(&conn, deadline)?;
    conn.execute_batch("PRAGMA secure_delete=ON; PRAGMA synchronous=FULL; VACUUM;")
        .map_err(sql)?;
    set_sql_deadline(&conn, deadline)?;
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(sql)?;
    if busy != 0 {
        return Err(PortError::WriterBusy(
            "owned purge cache WAL is pinned".into(),
        ));
    }
    drop(conn);
    control.validate_live_root()?;
    control.validate_catalog_file(&path)?;
    check(deadline)
}

fn verify_catalog_clean(
    conn: &Connection,
    control: &SqliteControlStore,
    deadline: Instant,
) -> PortResult<()> {
    let policy = control.read_policy(RequestIntersection::Selected)?;
    set_sql_deadline(conn, deadline)?;
    for (source, path) in withdrawn_sources(conn, &policy, deadline)? {
        check(deadline)?;
        if !source_binding_is_retired(conn, source.as_str(), &path)? {
            return Err(changed());
        }
    }
    if !catalog_coverage_is_classified(conn)? || !catalog_journal_is_content_free(conn, deadline)? {
        return Err(incompatible());
    }
    check(deadline)
}

fn purge_backups(
    control: &SqliteControlStore,
    owner: &PurgeOwner<'_>,
    installation: Option<&InstallationLockAuthority<'_>>,
    now_ms: i64,
    deadline: Instant,
) -> PortResult<PurgeStage> {
    if !backup_directory_is_accounted(control, deadline)? {
        return Ok(PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact));
    }
    for backup in control.backup_records()? {
        check(deadline)?;
        if backup.state == BackupState::PurgedByPolicy
            && backup_artifact_absent(control, &backup.relative_locator)?
        {
            continue;
        }
        let needs_purge = match backup.state {
            BackupState::Quarantined | BackupState::PurgedByPolicy => true,
            _ => match verify_backup_until(control, &backup.backup_id, deadline) {
                Ok(verified) => {
                    let policy = control.read_policy(RequestIntersection::Selected)?;
                    verified.coverage().iter().any(|source| {
                        !policy.allows_source(source.provider, &source.locator, &source.source_id)
                    })
                }
                Err(error @ PortError::WriterBusy(_)) => return Err(error),
                Err(_) => {
                    let lock = acquire(control.private_root(), LockKind::PolicyOwner, deadline)?;
                    let bound = control.bind_control_root(&lock)?;
                    control.quarantine_unclassified_backup(
                        control.status()?.policy.control_seq,
                        owner,
                        &bound,
                        &backup.backup_id,
                    )?;
                    return Ok(PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact));
                }
            },
        };
        if !needs_purge {
            continue;
        }
        if backup.digest.is_none() {
            return Ok(PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact));
        }
        let Some(installation) = installation else {
            return Ok(PurgeStage::Pending(PurgeFailure::BackupAuthorityMissing));
        };
        match purge_backup(control, installation, &backup.backup_id, now_ms, deadline)? {
            PurgeOutcome::Purged {
                artifact_removed: true,
                ..
            }
            | PurgeOutcome::NotWithdrawn => {}
            PurgeOutcome::PendingCleanup { .. }
            | PurgeOutcome::Purged {
                artifact_removed: false,
                ..
            } => {
                return Ok(PurgeStage::Pending(PurgeFailure::ArtifactPending));
            }
            PurgeOutcome::Attention(_) => {
                let lock = acquire(control.private_root(), LockKind::PolicyOwner, deadline)?;
                let bound = control.bind_control_root(&lock)?;
                control.quarantine_unclassified_backup(
                    control.status()?.policy.control_seq,
                    owner,
                    &bound,
                    &backup.backup_id,
                )?;
                return Ok(PurgeStage::Pending(PurgeFailure::UnclassifiedArtifact));
            }
        }
    }
    Ok(PurgeStage::Complete)
}

fn backup_artifact_absent(control: &SqliteControlStore, locator: &str) -> PortResult<bool> {
    control.validate_live_root()?;
    let artifact = control.private_root().join(locator);
    let parent = artifact.parent().ok_or_else(invalid)?.to_path_buf();
    match fs::symlink_metadata(&parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(_) => return Err(storage()),
        Ok(_) => validate_private_directory(&parent)?,
    }
    for file in [artifact, parent.join("manifest.json")] {
        match fs::symlink_metadata(file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage()),
            Ok(_) => return Ok(false),
        }
    }
    Ok(true)
}

fn lock_file_name(key: &str) -> String {
    let mut value = String::from("maintenance-job-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in key.bytes() {
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 15)] as char);
    }
    value.push_str(".lock");
    value
}

fn inventory_file_is_unchanged(
    control: &SqliteControlStore,
    artifact: &ClassifiedPrivateArtifact,
    deadline: Instant,
) -> PortResult<bool> {
    check(deadline)?;
    if known_layout(artifact.class, &artifact.relative).is_none_or(|limit| artifact.size > limit) {
        return Ok(false);
    }
    let path = control.private_root().join(&artifact.relative);
    let mut file = match control.open_private_read(&path) {
        Ok(file) => file,
        Err(_) => return Ok(false),
    };
    if file.metadata().map_err(|_| storage())?.len() != artifact.size {
        return Ok(false);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 65536];
    let mut consumed = 0_u64;
    loop {
        check(deadline)?;
        let count = file.read(&mut buffer).map_err(|_| storage())?;
        if count == 0 {
            break;
        }
        consumed = consumed.checked_add(count as u64).ok_or_else(invalid)?;
        if consumed > artifact.size {
            return Ok(false);
        }
        hasher.update(&buffer[..count]);
    }
    check(deadline)?;
    Ok(consumed == artifact.size
        && hasher.finalize().to_hex().as_str() == artifact.digest
        && control.validate_private_read(&path, &file).is_ok())
}

fn private_root_is_accounted(
    control: &SqliteControlStore,
    catalog: &Path,
    inventory: Option<&PrivateArtifactInventory>,
    deadline: Instant,
) -> PortResult<bool> {
    control.validate_live_root()?;
    check(deadline)?;
    let mut supplemental = BTreeSet::new();
    let mut supplemental_directories = BTreeSet::new();
    if let Some(inventory) = inventory {
        inventory.validate(control)?;
        for (relative, artifact) in &inventory.files {
            check(deadline)?;
            if !inventory_file_is_unchanged(control, artifact, deadline)? {
                return Ok(false);
            }
            supplemental.insert(PathBuf::from(relative));
            let mut parent = Path::new(relative).parent();
            while let Some(directory) = parent.filter(|value| !value.as_os_str().is_empty()) {
                supplemental_directories.insert(directory.to_path_buf());
                parent = directory.parent();
            }
        }
    }
    let mut known: BTreeSet<std::ffi::OsString> = [
        "control.db",
        "control.db-wal",
        "control.db-shm",
        "control.db-journal",
        "continuations.db",
        "continuations.db-wal",
        "continuations.db-shm",
        "continuations.db-journal",
        "installation-prefix.json",
        "writer.lock",
        "policy-owner.lock",
        "policy-emission.lock",
        "catalog-handles.lock",
        "control-handles.lock",
        "history-readers.lock",
        "background.lock",
        "supervisor.lock",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let name = catalog.file_name().ok_or_else(invalid)?;
    known.insert(name.into());
    for suffix in ["-wal", "-shm", "-journal", ".asg-managed-create"] {
        let mut derived = name.to_os_string();
        derived.push(suffix);
        known.insert(derived);
    }
    // These are precise immutable empty rendezvous files created by the actual
    // integration's OS lock domain. Do not accept arbitrary maintenance keys.
    for key in [PURGE_LOCK_KEY, "user-path", "legacy-migration"] {
        known.insert(lock_file_name(key).into());
    }
    let mut pending = vec![PathBuf::new()];
    let mut visited = 0_usize;
    let mut seen = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        check(deadline)?;
        let absolute = control.private_root().join(&directory);
        validate_private_directory(&absolute)?;
        for entry in fs::read_dir(absolute).map_err(|_| storage())? {
            check(deadline)?;
            visited += 1;
            if visited > MAX_PRIVATE_ARTIFACTS {
                return Ok(false);
            }
            let entry = entry.map_err(|_| storage())?;
            let name = entry.file_name();
            let relative = directory.join(&name);
            if directory.as_os_str().is_empty() && name == "backups" {
                validate_private_directory(&entry.path())?;
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| storage())?;
            let linked = metadata.file_type().is_symlink();
            #[cfg(windows)]
            let linked = {
                use std::os::windows::fs::MetadataExt;
                linked || metadata.file_attributes() & 0x400 != 0
            };
            if linked {
                return Ok(false);
            }
            if metadata.is_dir() {
                if !supplemental_directories.contains(&relative) {
                    return Ok(false);
                }
                if validate_private_directory(&entry.path()).is_err() {
                    return Ok(false);
                }
                pending.push(relative);
                continue;
            }
            if !metadata.is_file() {
                return Ok(false);
            }
            let builtin = directory.as_os_str().is_empty() && known.contains(&name);
            if supplemental.contains(&relative) {
                seen.insert(relative);
            } else if !builtin {
                return Ok(false);
            }
            if name
                .to_str()
                .is_some_and(|name| name.ends_with(".lock") && name != "writer.lock")
                && metadata.len() != 0
            {
                return Ok(false);
            }
            if builtin
                && name != "writer.lock"
                && control.validate_catalog_file(&entry.path()).is_err()
            {
                return Ok(false);
            }
        }
    }
    check(deadline)?;
    if let Some(inventory) = inventory {
        inventory.validate(control)?;
    }
    Ok(seen.len() == supplemental.len())
}
fn backup_directory_is_accounted(
    control: &SqliteControlStore,
    deadline: Instant,
) -> PortResult<bool> {
    let root = control.private_root().join("backups");
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(_) => return Err(storage()),
        Ok(_) => validate_private_directory(&root)?,
    }
    let records = control.backup_records()?;
    let mut count = 0;
    for entry in fs::read_dir(&root).map_err(|_| storage())? {
        check(deadline)?;
        count += 1;
        if count > 4096 {
            return Ok(false);
        }
        let entry = entry.map_err(|_| storage())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        if !records
            .iter()
            .any(|backup| backup.backup_id.as_str() == name)
        {
            return Ok(false);
        }
        validate_private_directory(&entry.path())?;
        for file in fs::read_dir(entry.path()).map_err(|_| storage())? {
            check(deadline)?;
            let file = file.map_err(|_| storage())?;
            let name = file.file_name();
            if !matches!(name.to_str(), Some("catalog.db" | "manifest.json")) {
                return Ok(false);
            }
            control.validate_catalog_file(&file.path())?;
        }
    }
    Ok(true)
}
