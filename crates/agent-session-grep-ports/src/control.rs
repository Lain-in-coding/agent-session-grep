//! Private managed-history policy. These values are not public response DTOs.
//! Locator permission is lexical only: filesystem admission must additionally
//! verify the root identity, reparse points/links and the source binding.

use crate::{PortError, PortResult, SearchProvider};
use std::{
    fmt,
    path::{Component, Path},
};

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid control value".into())
}

/// Bounded opaque identifiers; never transcript/native identifiers or paths.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlId(String);

impl ControlId {
    pub fn parse(value: &str) -> PortResult<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(invalid());
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ControlId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlId([private])")
    }
}

macro_rules! counter {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(i64);
        impl $name {
            pub fn new(value: i64) -> PortResult<Self> {
                if value < 0 {
                    return Err(invalid());
                }
                Ok(Self(value))
            }
            pub const fn get(self) -> i64 {
                self.0
            }
        }
    };
}
counter!(ControlSeq);
counter!(PolicyEpoch);

/// Normalized absolute locator in the local platform's path syntax.
/// This does not access the filesystem or claim that a path is safe to open.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalLocator(String);

impl CanonicalLocator {
    /// Converts an already resolved local path to the control representation.
    /// On Windows only ordinary verbatim drive and UNC prefixes are removed;
    /// device namespaces remain rejected. The caller still verifies identity.
    pub fn from_path(path: &Path) -> PortResult<Self> {
        let value = path.to_str().ok_or_else(invalid)?;
        #[cfg(windows)]
        {
            let converted = if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
                format!(r"\\{unc}")
            } else if let Some(drive) = value.strip_prefix(r"\\?\") {
                if drive.as_bytes().get(1) != Some(&b':') {
                    return Err(invalid());
                }
                drive.to_owned()
            } else {
                value.to_owned()
            };
            Self::parse(&converted.replace('/', "\\"))
        }
        #[cfg(not(windows))]
        Self::parse(value)
    }
    pub fn parse(value: &str) -> PortResult<Self> {
        if value.is_empty() || value.len() > 32768 || value.chars().any(char::is_control) {
            return Err(invalid());
        }
        let path = Path::new(value);
        if !path.is_absolute() {
            return Err(invalid());
        }
        // Reject rather than collapse traversal/alternate spellings. Case and
        // physical aliases are resolved by FS admission, never guessed here.
        #[cfg(windows)]
        {
            if value.starts_with(r"\\?\")
                || value.starts_with(r"\\.\")
                || value.contains('/')
                || value
                    .split('\\')
                    .any(|p| p == "." || p == ".." || p.ends_with([' ', '.']))
            {
                return Err(invalid());
            }
        }
        #[cfg(not(windows))]
        if value.split('/').any(|p| p == "." || p == "..") {
            return Err(invalid());
        }
        for component in path.components() {
            match component {
                Component::ParentDir | Component::CurDir => return Err(invalid()),
                #[cfg(windows)]
                Component::Normal(part)
                    if part
                        .to_str()
                        .is_none_or(|p| p.contains([':', '*', '?', '"', '<', '>', '|'])) =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        let normalized: std::path::PathBuf = path.components().collect();
        if normalized.as_os_str() != path.as_os_str() {
            return Err(invalid());
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn contains(&self, other: &Self) -> bool {
        Path::new(&other.0).starts_with(Path::new(&self.0))
    }
    /// Denials deliberately overmatch case variants on Windows, including
    /// case-sensitive directories. Grants retain exact component spelling until
    /// FS admission supplies the resolved spelling and physical root identity.
    /// Unicode expansion can deny extra paths; it can never broaden a grant.
    pub fn denies(&self, other: &Self, kind: RootKind) -> bool {
        #[cfg(windows)]
        let (left, right) = (self.0.to_uppercase(), other.0.to_uppercase());
        #[cfg(not(windows))]
        let (left, right) = (&self.0, &other.0);
        match kind {
            RootKind::Root => Path::new(&right).starts_with(Path::new(&left)),
            RootKind::Exact => Path::new(&right) == Path::new(&left),
        }
    }
}

impl fmt::Debug for CanonicalLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanonicalLocator([private])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKind {
    Root,
    Exact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRegion {
    pub provider: SearchProvider,
    pub locator: CanonicalLocator,
    pub kind: RootKind,
}
impl ScopeRegion {
    pub fn matches(&self, provider: SearchProvider, locator: &CanonicalLocator) -> bool {
        self.provider == provider
            && match self.kind {
                RootKind::Root => self.locator.contains(locator),
                RootKind::Exact => self.locator == *locator,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub id: ControlId,
    pub region: ScopeRegion,
    pub root_identity: Option<ControlId>,
    pub enabled: bool,
    pub revision: ControlSeq,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExcludedRegion {
    Locator(ScopeRegion),
    SourceIdentity {
        provider: SearchProvider,
        source_id: ControlId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub id: ControlId,
    pub region: ExcludedRegion,
    pub revision: ControlSeq,
    pub created_policy_epoch: PolicyEpoch,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredUpdates {
    Running,
    Paused,
    Stopped,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceState {
    Idle,
    Updating,
    Recovering,
    Uninstalling,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenancePhase {
    Downloaded,
    Verified,
    Quiescing,
    BackedUp,
    Staged,
    Migrated,
    Switched,
    SelfChecked,
    Complete,
    Failed,
    RollbackPending,
    Reconciling,
    RolledBack,
    Attention,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceFence {
    pub state: MaintenanceState,
    pub owner: Option<ControlId>,
    pub phase: Option<MaintenancePhase>,
}
impl MaintenanceFence {
    pub fn idle() -> Self {
        Self {
            state: MaintenanceState::Idle,
            owner: None,
            phase: None,
        }
    }
    pub fn validate(&self) -> PortResult<()> {
        if (self.state == MaintenanceState::Idle) != (self.owner.is_none() && self.phase.is_none())
            || (self.state != MaintenanceState::Idle
                && (self.owner.is_none() || self.phase.is_none()))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Restriction is intersected with selected permission; an empty Only denies all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestIntersection {
    Selected,
    Only(Vec<ScopeRegion>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPolicy {
    pub installation_id: ControlId,
    pub policy_epoch: PolicyEpoch,
    pub control_seq: ControlSeq,
    pub selections: Vec<Selection>,
    pub exclusions: Vec<Exclusion>,
    pub request_intersection: RequestIntersection,
    pub maintenance: MaintenanceFence,
    pub revocations: Vec<RevocationIntent>,
}
impl ReadPolicy {
    /// Eligibility only. Does not prove source binding, completed projections,
    /// filesystem admission, or emission-gate ownership. Pause does not deny reads.
    pub fn allows_source(
        &self,
        provider: SearchProvider,
        locator: &CanonicalLocator,
        source_id: &ControlId,
    ) -> bool {
        let selected = self
            .selections
            .iter()
            .any(|s| s.enabled && s.region.matches(provider, locator));
        let excluded = self.exclusions.iter().any(|e| match &e.region {
            ExcludedRegion::Locator(region) => {
                region.provider == provider && region.locator.denies(locator, region.kind)
            }
            ExcludedRegion::SourceIdentity {
                provider: p,
                source_id: id,
            } => *p == provider && id == source_id,
        });
        let requested = match &self.request_intersection {
            RequestIntersection::Selected => true,
            RequestIntersection::Only(regions) => {
                regions.iter().any(|r| r.matches(provider, locator))
            }
        };
        selected && !excluded && requested
    }
    pub fn emission_blocked(&self) -> bool {
        self.maintenance.state != MaintenanceState::Idle
            || self
                .revocations
                .iter()
                .any(|r| r.state == RevocationState::AwaitingDrain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlStatus {
    pub policy: ReadPolicy,
    pub desired_updates: DesiredUpdates,
    pub autostart_enabled: bool,
    pub supervisor_failed: bool,
    pub restart_request_seq: ControlSeq,
    pub catalog_incarnation: Option<ControlId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRequest {
    pub region: ScopeRegion,
    pub root_identity: Option<ControlId>,
    pub now_ms: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    AwaitingDrain,
    Settled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationIntent {
    pub id: ControlId,
    pub policy_epoch: PolicyEpoch,
    pub state: RevocationState,
    pub created_at_ms: i64,
    pub settled_at_ms: Option<i64>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeState {
    Pending,
    Claims,
    Artifacts,
    Verifying,
    Complete,
    Blocked,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeJob {
    pub id: ControlId,
    pub policy_epoch: PolicyEpoch,
    pub selection_id: Option<ControlId>,
    pub selection_revision: Option<ControlSeq>,
    pub state: PurgeState,
    pub attempts: ControlSeq,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlChange<T> {
    pub control_seq: ControlSeq,
    pub policy_epoch: PolicyEpoch,
    pub changed: bool,
    pub value: T,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub intent: RevocationIntent,
    pub purge_job: PurgeJob,
}

/// Control operations never acquire the catalog writer lease. Each write CASes
/// the observed sequence, including no-op requests. Exclusions are only removed
/// by name, never as a side effect of adding an overlapping selection.
pub trait ControlStore {
    fn read_policy(&self, request: RequestIntersection) -> PortResult<ReadPolicy>;
    fn status(&self) -> PortResult<ControlStatus>;
    fn purge_jobs(&self) -> PortResult<Vec<PurgeJob>>;
    fn add_selection(
        &self,
        expected: ControlSeq,
        request: SelectionRequest,
    ) -> PortResult<ControlChange<Selection>>;
    fn revoke_selection(
        &self,
        expected: ControlSeq,
        selection: &ControlId,
        known_source: Option<&ControlId>,
        now_ms: i64,
    ) -> PortResult<ControlChange<Revocation>>;
    fn remove_exclusion(
        &self,
        expected: ControlSeq,
        exclusion: &ControlId,
    ) -> PortResult<ControlChange<Exclusion>>;
    fn set_desired_updates(
        &self,
        expected: ControlSeq,
        desired: DesiredUpdates,
    ) -> PortResult<ControlChange<DesiredUpdates>>;
    /// Requires installation-lock ownership at the composition boundary. This
    /// operation preserves desired updates and never steals another owner's fence.
    fn set_maintenance(
        &self,
        expected: ControlSeq,
        owner: &ControlId,
        fence: MaintenanceFence,
    ) -> PortResult<ControlChange<MaintenanceFence>>;
    // No settlement or purge-progress API until real OS ownership capabilities
    // can be supplied by the integration layer. A database row is not drain proof.
}

impl<T: ControlStore + ?Sized> ControlStore for &T {
    fn read_policy(&self, r: RequestIntersection) -> PortResult<ReadPolicy> {
        (**self).read_policy(r)
    }
    fn status(&self) -> PortResult<ControlStatus> {
        (**self).status()
    }
    fn purge_jobs(&self) -> PortResult<Vec<PurgeJob>> {
        (**self).purge_jobs()
    }
    fn add_selection(
        &self,
        e: ControlSeq,
        r: SelectionRequest,
    ) -> PortResult<ControlChange<Selection>> {
        (**self).add_selection(e, r)
    }
    fn revoke_selection(
        &self,
        e: ControlSeq,
        s: &ControlId,
        k: Option<&ControlId>,
        n: i64,
    ) -> PortResult<ControlChange<Revocation>> {
        (**self).revoke_selection(e, s, k, n)
    }
    fn remove_exclusion(
        &self,
        e: ControlSeq,
        x: &ControlId,
    ) -> PortResult<ControlChange<Exclusion>> {
        (**self).remove_exclusion(e, x)
    }
    fn set_desired_updates(
        &self,
        e: ControlSeq,
        d: DesiredUpdates,
    ) -> PortResult<ControlChange<DesiredUpdates>> {
        (**self).set_desired_updates(e, d)
    }
    fn set_maintenance(
        &self,
        e: ControlSeq,
        o: &ControlId,
        f: MaintenanceFence,
    ) -> PortResult<ControlChange<MaintenanceFence>> {
        (**self).set_maintenance(e, o, f)
    }
}

/// A globally allocated positive observation sequence, independent of boot IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CycleSeq(i64);
impl CycleSeq {
    pub fn new(value: i64) -> PortResult<Self> {
        if value <= 0 {
            return Err(invalid());
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Equality-only physical storage binding supplied by a trusted adapter. This
/// is neither an installation ID nor a permission grant. It has no wire format,
/// path accessor or default; it is meaningful only while its owner is alive.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRootBinding([u8; 32]);

impl PhysicalRootBinding {
    /// Wrap an adapter's domain-separated digest of an OS-verified directory
    /// identity. The adapter must use the same encoding for stores and guards;
    /// paths, installation IDs, boot IDs and persisted config are not identities.
    /// Construction alone does not establish live lock ownership.
    pub fn from_verified_identity(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for PhysicalRootBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhysicalRootBinding([private])")
    }
}

/// A borrowed lifecycle capability. Implementations must keep the installation's
/// exclusive worker OS lock alive and validate its binding. A PID, boot string,
/// heartbeat or timeout alone cannot implement this contract.
/// Every receiving store must compare root_binding with its own physical root,
/// including registration and no-op paths; validate only checks the issuer.
pub trait WorkerAuthority {
    fn installation_id(&self) -> &ControlId;
    fn boot_id(&self) -> &ControlId;
    fn root_binding(&self) -> PhysicalRootBinding;
    fn validate(&self) -> PortResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    Running,
    Idle,
    Paused,
    Stopped,
    Offline,
    Busy,
    Failed,
    Deferred,
    Upgrading,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundFailure {
    Paused,
    Stopped,
    Offline,
    Busy,
    Failed,
    Deferred,
    Upgrading,
    PolicyChanged,
    Timeout,
    ScopeUnverified,
    SourceChanged,
    WorkerRestarted,
    CatalogChanged,
    RewritePending,
    DeletionPending,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Empty,
    Partial,
    Complete,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillState {
    Pending,
    Running,
    Complete,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerStatus {
    pub boot_id: Option<ControlId>,
    pub pid_hint: Option<u32>,
    pub heartbeat_at_ms: Option<i64>,
    pub state: UpdateState,
    pub error: Option<BackgroundFailure>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundStatus {
    pub control_seq: ControlSeq,
    pub next_cycle_seq: CycleSeq,
    pub worker: WorkerStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationToken {
    pub cycle_seq: CycleSeq,
    pub worker_boot_id: ControlId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRevision {
    pub selection_id: ControlId,
    pub revision: ControlSeq,
    pub root_identity: ControlId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleState {
    Queued,
    Observing,
    Committed,
    Partial,
    Aborted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleFinish {
    Committed,
    Partial,
    Aborted,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleSelection {
    pub selection: SelectionRevision,
    pub discovery_complete: bool,
    pub discovered_count: u64,
    pub observed_count: u64,
    pub committed_count: u64,
    pub error: Option<BackgroundFailure>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCycle {
    pub token: ObservationToken,
    pub policy_epoch: PolicyEpoch,
    pub state: CycleState,
    pub admitted_control_seq: ControlSeq,
    pub started_control_seq: Option<ControlSeq>,
    pub started_at_ms: Option<i64>,
    pub completed_at_ms: Option<i64>,
    pub selections: Vec<CycleSelection>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleAdmission {
    Queued(ObservationCycle),
    Blocked(BackgroundFailure),
}

pub const MAX_LATEST_WAIT_MS: u32 = 30_000;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestRequest {
    pub selections: Vec<SelectionRevision>,
    pub max_wait_ms: u32,
    pub now_ms: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierState {
    Pending,
    AwaitingCatalog,
    Blocked,
}
/// Scheduling only. Even AwaitingCatalog is unsatisfied until Application
/// verifies discovery + source receipts in the actual catalog output snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestBarrier {
    pub id: ControlId,
    pub policy_epoch: PolicyEpoch,
    pub admission_control_seq: ControlSeq,
    pub required_cycle_seq: CycleSeq,
    pub state: BarrierState,
    pub requested_wait_ms: u32,
    pub admitted_at_ms: i64,
    pub completed_cycle_seq: Option<CycleSeq>,
    pub error: Option<BackgroundFailure>,
    pub selections: Vec<SelectionRevision>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatestAdmission {
    Queued(LatestBarrier),
    Blocked(BackgroundFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAcknowledgement {
    pub token: ObservationToken,
    pub selection: SelectionRevision,
    pub complete: bool,
    pub discovered_count: u64,
    pub observed_count: u64,
    pub committed_count: u64,
    pub error: Option<BackgroundFailure>,
}
/// A repaired summary of a catalog receipt, not a catalog proof capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReceiptSummary {
    pub token: ObservationToken,
    pub revision: ControlId,
    pub catalog_incarnation: ControlId,
    pub catalog_generation: ControlSeq,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmationKind {
    Deletion,
    Rewrite { candidate_digest: ControlId },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConfirmation {
    pub kind: ConfirmationKind,
    pub first_cycle: CycleSeq,
    pub confirm_cycle: Option<CycleSeq>,
    pub worker_boot_id: ControlId,
    pub root_identity: ControlId,
    pub policy_epoch: PolicyEpoch,
    pub first_monotonic_ms: ControlSeq,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAcknowledgement {
    pub source_id: ControlId,
    pub provider: SearchProvider,
    pub token: ObservationToken,
    pub selection: SelectionRevision,
    pub attempted_at_ms: i64,
    pub coverage: Coverage,
    pub update_state: UpdateState,
    pub backfill_state: BackfillState,
    pub error: Option<BackgroundFailure>,
    pub receipt: Option<SourceReceiptSummary>,
    pub confirmation: Option<PendingConfirmation>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProgress {
    pub source_id: ControlId,
    pub provider: SearchProvider,
    pub last_attempt_at_ms: Option<i64>,
    pub last_observation: Option<ObservationToken>,
    pub receipt: Option<SourceReceiptSummary>,
    pub coverage: Coverage,
    pub update_state: UpdateState,
    pub backfill_state: BackfillState,
    pub error: Option<BackgroundFailure>,
    pub confirmation: Option<PendingConfirmation>,
}

/// Every mutation makes one bounded CAS attempt. Callers may re-read and retry
/// under their original deadline; never retry with a newly widened selection.
/// All progress is advisory. None of these operations establishes freshness.
pub trait BackgroundControl: ControlStore {
    fn background_status(&self) -> PortResult<BackgroundStatus>;
    fn register_worker(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        pid_hint: u32,
        now_ms: i64,
    ) -> PortResult<ControlChange<WorkerStatus>>;
    fn heartbeat_worker(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        state: UpdateState,
        error: Option<BackgroundFailure>,
        now_ms: i64,
    ) -> PortResult<ControlChange<WorkerStatus>>;
    fn stop_worker(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        now_ms: i64,
    ) -> PortResult<ControlChange<WorkerStatus>>;
    fn queue_cycle(
        &self,
        expected: ControlSeq,
        selections: Vec<SelectionRevision>,
    ) -> PortResult<ControlChange<CycleAdmission>>;
    fn start_cycle(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        cycle: CycleSeq,
        now_ms: i64,
    ) -> PortResult<ControlChange<ObservationCycle>>;
    fn finish_cycle(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        cycle: CycleSeq,
        finish: CycleFinish,
        now_ms: i64,
    ) -> PortResult<ControlChange<ObservationCycle>>;
    fn cycle(&self, cycle: CycleSeq) -> PortResult<ObservationCycle>;
    fn admit_latest(
        &self,
        expected: ControlSeq,
        request: LatestRequest,
    ) -> PortResult<ControlChange<LatestAdmission>>;
    fn barrier(&self, barrier: &ControlId) -> PortResult<LatestBarrier>;
    fn acknowledge_discovery(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        acknowledgement: DiscoveryAcknowledgement,
    ) -> PortResult<ControlChange<CycleSelection>>;
    fn acknowledge_source(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        acknowledgement: SourceAcknowledgement,
    ) -> PortResult<ControlChange<SourceProgress>>;
    fn source_progress(&self, source: &ControlId) -> PortResult<Option<SourceProgress>>;
    /// Call only after observing the authoritative catalog incarnation while
    /// owning its recovery fence. Clears progress forward; never restores policy.
    fn reset_progress(
        &self,
        expected: ControlSeq,
        authority: &dyn WorkerAuthority,
        catalog_incarnation: &ControlId,
        now_ms: i64,
    ) -> PortResult<ControlChange<()>>;
}

impl<T: BackgroundControl + ?Sized> BackgroundControl for &T {
    fn background_status(&self) -> PortResult<BackgroundStatus> {
        (**self).background_status()
    }
    fn register_worker(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        p: u32,
        n: i64,
    ) -> PortResult<ControlChange<WorkerStatus>> {
        (**self).register_worker(e, a, p, n)
    }
    fn heartbeat_worker(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        s: UpdateState,
        r: Option<BackgroundFailure>,
        n: i64,
    ) -> PortResult<ControlChange<WorkerStatus>> {
        (**self).heartbeat_worker(e, a, s, r, n)
    }
    fn stop_worker(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        n: i64,
    ) -> PortResult<ControlChange<WorkerStatus>> {
        (**self).stop_worker(e, a, n)
    }
    fn queue_cycle(
        &self,
        e: ControlSeq,
        s: Vec<SelectionRevision>,
    ) -> PortResult<ControlChange<CycleAdmission>> {
        (**self).queue_cycle(e, s)
    }
    fn start_cycle(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        c: CycleSeq,
        n: i64,
    ) -> PortResult<ControlChange<ObservationCycle>> {
        (**self).start_cycle(e, a, c, n)
    }
    fn finish_cycle(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        c: CycleSeq,
        f: CycleFinish,
        n: i64,
    ) -> PortResult<ControlChange<ObservationCycle>> {
        (**self).finish_cycle(e, a, c, f, n)
    }
    fn cycle(&self, c: CycleSeq) -> PortResult<ObservationCycle> {
        (**self).cycle(c)
    }
    fn admit_latest(
        &self,
        e: ControlSeq,
        r: LatestRequest,
    ) -> PortResult<ControlChange<LatestAdmission>> {
        (**self).admit_latest(e, r)
    }
    fn barrier(&self, b: &ControlId) -> PortResult<LatestBarrier> {
        (**self).barrier(b)
    }
    fn acknowledge_discovery(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        d: DiscoveryAcknowledgement,
    ) -> PortResult<ControlChange<CycleSelection>> {
        (**self).acknowledge_discovery(e, a, d)
    }
    fn acknowledge_source(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        s: SourceAcknowledgement,
    ) -> PortResult<ControlChange<SourceProgress>> {
        (**self).acknowledge_source(e, a, s)
    }
    fn source_progress(&self, s: &ControlId) -> PortResult<Option<SourceProgress>> {
        (**self).source_progress(s)
    }
    fn reset_progress(
        &self,
        e: ControlSeq,
        a: &dyn WorkerAuthority,
        c: &ControlId,
        n: i64,
    ) -> PortResult<ControlChange<()>> {
        (**self).reset_progress(e, a, c, n)
    }
}
