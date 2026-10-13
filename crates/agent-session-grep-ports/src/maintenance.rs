//! Private maintenance manifests and capability boundaries. Only the explicit
//! summary projections are suitable for protocol output.
use crate::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub const DEFAULT_MAX_WRITE_SECONDS: u64 = 30;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceTarget {
    pub canonical_path: String,
    pub file_identity: String,
    pub schema_version: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceFieldSummary {
    pub field: String,
    pub bytes: u64,
    pub items: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceSelectionItem {
    pub operation_id: String,
    pub state: String,
    pub base_generation: u64,
    pub target_generation: u64,
    pub operation_digest: String,
    pub detail_digest: String,
    pub fields: Vec<MaintenanceFieldSummary>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceSelection {
    pub plan_digest: String,
    pub aggregated_fields: Vec<String>,
    pub batches: Vec<MaintenanceSelectionItem>,
    pub detail_bytes_before: u64,
    pub estimated_detail_bytes_after: u64,
    pub estimated_saved_bytes: u64,
}
#[derive(Clone)]
pub struct MaintenancePreview {
    pub token: String,
    pub target: MaintenanceTarget,
    pub selection: MaintenanceSelection,
    pub footprint: MaintenanceFootprint,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    Validate,
    Backup,
    Compact,
    Vacuum,
    Checkpoint,
    Verify,
    Cleanup,
    Done,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceState {
    Queued,
    Deferred,
    Running,
    NeedsReview,
    NeedsAttention,
    Completed,
    Failed,
    Cancelled,
}
impl MaintenanceState {
    pub fn is_runnable(self) -> bool {
        matches!(self, Self::Queued | Self::Deferred | Self::Running)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceFailureKind {
    Busy,
    BudgetExhausted,
    Cancelled,
    Paused,
    InsufficientSpace,
    PermissionDenied,
    TargetChanged,
    SelectionChanged,
    UnsupportedTarget,
    IntegrityFailed,
    CleanupFailed,
    Backend,
}
/// Bounded classification only: never carry backend diagnostics or private paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("maintenance step failed: {kind:?}")]
pub struct MaintenanceFailure {
    pub kind: MaintenanceFailureKind,
}
impl From<MaintenanceFailureKind> for MaintenanceFailure {
    fn from(kind: MaintenanceFailureKind) -> Self {
        Self { kind }
    }
}
pub type MaintenanceResult<T> = Result<T, MaintenanceFailure>;
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceFootprint {
    pub catalog_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    pub queue_bytes: u64,
    pub backup_bytes: u64,
    pub temporary_bytes: u64,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceMetrics {
    pub before: MaintenanceFootprint,
    pub after: MaintenanceFootprint,
    pub stage_millis: Vec<MaintenanceStageDuration>,
    pub max_writer_lock_millis: u64,
    pub peak_memory_bytes: u64,
    pub reclaimed_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceStageDuration {
    pub phase: MaintenancePhase,
    pub millis: u64,
}
/// Validate returns this intent, which the queue MUST persist before Backup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceBackup {
    pub relative_path: String,
    pub source_generation: u64,
    pub invariant_digest: String,
    pub verified: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct MaintenanceJob {
    pub id: String,
    pub token: String,
    pub compaction_id: String,
    pub target: MaintenanceTarget,
    pub selection: MaintenanceSelection,
    pub max_write_seconds: u64,
    pub state: MaintenanceState,
    pub phase: MaintenancePhase,
    pub reason: Option<MaintenanceFailureKind>,
    pub attempts: u64,
    pub consecutive_budget_exhaustions: u32,
    pub next_retry_at_ms: u64,
    pub cancel_requested: bool,
    pub backup: Option<MaintenanceBackup>,
    pub logical_compaction_committed: bool,
    pub logical_compaction_reconciled: bool,
    /// Durable irreversible cleanup commitment; cancellation closes at this CAS.
    pub cleanup_started: bool,
    pub metrics: MaintenanceMetrics,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct MaintenanceJobSummary {
    pub id: String,
    pub state: MaintenanceState,
    pub phase: MaintenancePhase,
    pub reason: Option<MaintenanceFailureKind>,
    pub affected_batches: usize,
    pub max_write_seconds: u64,
    pub attempts: u64,
    pub next_retry_at_ms: u64,
    pub cancel_requested: bool,
    pub cancellation_closed: bool,
    pub backup_verified: bool,
    pub logical_compaction_committed: Option<bool>,
    pub metrics: MaintenanceMetrics,
}
impl MaintenanceJob {
    pub fn summary(&self) -> MaintenanceJobSummary {
        MaintenanceJobSummary {
            id: self.id.clone(),
            state: self.state,
            phase: self.phase,
            reason: self.reason,
            affected_batches: self.selection.batches.len(),
            max_write_seconds: self.max_write_seconds,
            attempts: self.attempts,
            next_retry_at_ms: self.next_retry_at_ms,
            cancel_requested: self.cancel_requested,
            cancellation_closed: self.cleanup_started || self.phase == MaintenancePhase::Done,
            backup_verified: self.backup.as_ref().is_some_and(|b| b.verified),
            logical_compaction_committed: if self.phase == MaintenancePhase::Compact
                && !self.logical_compaction_committed
                && !self.logical_compaction_reconciled
            {
                None
            } else {
                Some(self.logical_compaction_committed)
            },
            metrics: self.metrics.clone(),
        }
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceQueueControl {
    pub paused: bool,
    pub cancel_requested: bool,
}
/// Atomics are updated by an independent queue monitor, never from SQLite callbacks.
#[derive(Clone, Default)]
pub struct MaintenanceControl {
    pub cancelled: Arc<AtomicBool>,
    pub paused: Arc<AtomicBool>,
}
impl MaintenanceControl {
    pub fn check(&self) -> MaintenanceResult<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(MaintenanceFailureKind::Cancelled.into());
        }
        if self.paused.load(Ordering::Acquire) {
            return Err(MaintenanceFailureKind::Paused.into());
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct MaintenanceStageResult {
    /// Explicitly repeat a phase after persisting refreshed backup intent.
    pub next_phase: Option<MaintenancePhase>,
    pub backup: Option<MaintenanceBackup>,
    pub logical_compaction_committed: bool,
    pub metrics: MaintenanceMetrics,
}
/// A catalog session owns one writer lease and one soft deadline (starting
/// AFTER acquisition), never renewed between execute calls. Cleanup-only
/// recovery after its durable commitment needs neither a catalog nor a lease.
pub trait MaintenanceSession {
    /// Cleanup-only recovery sessions own no catalog connection or writer lease.
    fn holds_writer_lease(&self) -> bool {
        true
    }
    fn execute(
        &mut self,
        phase: MaintenancePhase,
        job: &MaintenanceJob,
        control: &MaintenanceControl,
    ) -> MaintenanceResult<MaintenanceStageResult>;
}
pub trait MaintenanceCatalog {
    /// Read-only audit reconciliation. Must never execute compaction or mutate
    /// the catalog to discover whether a lost-ack transaction committed.
    fn reconcile(&self, job: &MaintenanceJob) -> MaintenanceResult<bool>;
    fn preview(&self, target: &str) -> PortResult<MaintenancePreview>;
    fn acquire(&self, job: &MaintenanceJob) -> MaintenanceResult<Box<dyn MaintenanceSession + '_>>;
}
/// Queue is independent of the catalog. Progress updates preserve control
/// fields and use revision CAS; every returned job reflects concurrent cancel.
pub trait MaintenanceQueue {
    fn enqueue(&self, job: &MaintenanceJob) -> PortResult<MaintenanceJob>;
    fn find_by_token(&self, token: &str) -> PortResult<Option<MaintenanceJob>>;
    fn get(&self, id: &str) -> PortResult<MaintenanceJob>;
    fn list(&self, target: Option<&str>) -> PortResult<Vec<MaintenanceJob>>;
    fn save_progress(&self, job: &MaintenanceJob) -> PortResult<MaintenanceJob>;
    fn request_cancel(&self, id: &str) -> PortResult<MaintenanceJob>;
    fn set_paused(&self, paused: bool) -> PortResult<()>;
    fn control(&self, id: Option<&str>) -> PortResult<MaintenanceQueueControl>;
}
pub fn validate_write_budget(seconds: u64) -> PortResult<()> {
    if seconds == 0 {
        return Err(PortError::InvalidRequest(
            "write budget must be positive".into(),
        ));
    }
    Ok(())
}
