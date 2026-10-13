//! Online maintenance policy. Persistence, catalog I/O, clocks and process
//! lifecycle are injected; no adapter or filesystem dependencies belong here.
use agent_session_grep_ports::{PortError, PortResult, maintenance::*};

pub const RETRY_SECONDS: [u64; 6] = [1, 2, 5, 15, 30, 60];
pub const NO_PROGRESS_BUDGET_LIMIT: u32 = 3;

pub struct MaintenanceService<'a> {
    queue: &'a dyn MaintenanceQueue,
    catalog: &'a dyn MaintenanceCatalog,
    clock: fn() -> u64,
}
impl<'a> MaintenanceService<'a> {
    pub fn new(
        queue: &'a dyn MaintenanceQueue,
        catalog: &'a dyn MaintenanceCatalog,
        clock: fn() -> u64,
    ) -> Self {
        Self {
            queue,
            catalog,
            clock,
        }
    }
    pub fn preview(&self, target: &str) -> PortResult<MaintenancePreview> {
        self.catalog.preview(target)
    }
    /// Caller supplies the canonical target and holds the producer lifecycle
    /// guard through enqueue and any authorized worker start.
    pub fn submit(
        &self,
        target: &str,
        token: &str,
        max_write_seconds: Option<u64>,
    ) -> PortResult<MaintenanceJob> {
        let budget = max_write_seconds.unwrap_or(DEFAULT_MAX_WRITE_SECONDS);
        validate_write_budget(budget)?;
        if let Some(existing) = self.queue.find_by_token(token)? {
            if existing.target.canonical_path != target {
                return Err(PortError::InvalidRequest(
                    "maintenance token targets another catalog".into(),
                ));
            }
            return Ok(existing);
        }
        let preview = self.catalog.preview(target)?;
        if preview.token != token {
            return Err(PortError::GenerationMismatch(
                "maintenance preview changed; obtain a new preview".into(),
            ));
        }
        if preview.selection.batches.is_empty() {
            return Err(PortError::InvalidRequest(
                "maintenance preview has no eligible batches".into(),
            ));
        }
        let id = blake3::hash(token.as_bytes()).to_hex().to_string();
        let now = (self.clock)();
        self.queue.enqueue(&MaintenanceJob {
            id: format!("job_v1_{id}"),
            token: token.into(),
            compaction_id: format!("cmp_m1_{id}"),
            target: preview.target,
            selection: preview.selection,
            max_write_seconds: budget,
            state: MaintenanceState::Queued,
            phase: MaintenancePhase::Validate,
            reason: None,
            attempts: 0,
            consecutive_budget_exhaustions: 0,
            next_retry_at_ms: now,
            cancel_requested: false,
            backup: None,
            logical_compaction_committed: false,
            logical_compaction_reconciled: false,
            cleanup_started: false,
            metrics: MaintenanceMetrics {
                before: preview.footprint,
                ..Default::default()
            },
            created_at_ms: now,
            updated_at_ms: now,
            revision: 0,
        })
    }
    pub fn retry(&self, id: &str, max_write_seconds: Option<u64>) -> PortResult<MaintenanceJob> {
        let mut job = self.queue.get(id)?;
        if let Some(seconds) = max_write_seconds {
            validate_write_budget(seconds)?;
            job.max_write_seconds = seconds;
        }
        if !matches!(
            job.state,
            MaintenanceState::Deferred
                | MaintenanceState::NeedsAttention
                | MaintenanceState::Failed
        ) || job.cancel_requested
        {
            return Err(PortError::InvalidRequest(
                "maintenance job cannot be retried; review its status".into(),
            ));
        }
        job.state = MaintenanceState::Queued;
        job.reason = None;
        job.consecutive_budget_exhaustions = 0;
        job.next_retry_at_ms = (self.clock)();
        job.updated_at_ms = job.next_retry_at_ms;
        self.queue.save_progress(&job)
    }
    pub fn next_runnable(&self, now: u64) -> PortResult<Option<MaintenanceJob>> {
        if self.queue.control(None)?.paused {
            return Ok(None);
        }
        Ok(self
            .queue
            .list(None)?
            .into_iter()
            .find(|job| job.state.is_runnable() && job.next_retry_at_ms <= now))
    }
    pub fn next_retry_at(&self) -> PortResult<Option<u64>> {
        if self.queue.control(None)?.paused {
            return Ok(None);
        }
        Ok(self
            .queue
            .list(None)?
            .into_iter()
            .filter(|job| job.state.is_runnable())
            .map(|job| job.next_retry_at_ms)
            .min())
    }
    /// Caller holds the root worker OS lock throughout. On queue-ack failure,
    /// drop the session and stop: replay must consult catalog audit authority.
    pub fn run_job(&self, id: &str, control: &MaintenanceControl) -> PortResult<MaintenanceJob> {
        let mut job = self.queue.get(id)?;
        if job.phase == MaintenancePhase::Done {
            job.state = MaintenanceState::Completed;
            job.reason = None;
            job.updated_at_ms = (self.clock)();
            return self.queue.save_progress(&job);
        }
        if !job.state.is_runnable() {
            return Ok(job);
        }
        if job.phase == MaintenancePhase::Compact && !job.logical_compaction_committed {
            match self.catalog.reconcile(&job) {
                Ok(committed) => {
                    job.logical_compaction_committed = committed;
                    job.logical_compaction_reconciled = true;
                    if committed {
                        job.phase = MaintenancePhase::Vacuum;
                        job.consecutive_budget_exhaustions = 0;
                    }
                    job = self.queue.save_progress(&job)?;
                }
                Err(error) => return self.fail(job, error.kind),
            }
        }
        if let Some(kind) = self.interruption(&job, control)? {
            return self.fail(job, kind);
        }
        job.state = MaintenanceState::Running;
        job.reason = None;
        job.attempts = job.attempts.saturating_add(1);
        job.updated_at_ms = (self.clock)();
        job = self.queue.save_progress(&job)?;
        let mut session = match self.catalog.acquire(&job) {
            Ok(session) => session,
            Err(error) => return self.fail(job, error.kind),
        };
        // The adapter's deadline begins inside acquire, AFTER taking its lease.
        // This clock records evidence, not timeout policy or deadline renewal.
        let acquired = (self.clock)();
        let leased = session.holds_writer_lease();
        loop {
            // Done is authoritative even if a late cancellation or pause raced
            // the successful cleanup acknowledgement. Never reopen the catalog.
            if job.phase == MaintenancePhase::Done {
                drop(session);
                job.metrics.max_writer_lock_millis =
                    job.metrics.max_writer_lock_millis.max(if leased {
                        (self.clock)().saturating_sub(acquired)
                    } else {
                        0
                    });
                job.state = MaintenanceState::Completed;
                job.reason = None;
                job.updated_at_ms = (self.clock)();
                return self.queue.save_progress(&job);
            }
            if let Some(kind) = self.interruption(&job, control)? {
                drop(session);
                job.metrics.max_writer_lock_millis =
                    job.metrics.max_writer_lock_millis.max(if leased {
                        (self.clock)().saturating_sub(acquired)
                    } else {
                        0
                    });
                return self.fail(job, kind);
            }
            let phase = job.phase;
            if phase == MaintenancePhase::Compact && job.logical_compaction_reconciled {
                job.logical_compaction_reconciled = false;
                job = self.queue.save_progress(&job)?;
            }
            if phase == MaintenancePhase::Cleanup && !job.cleanup_started {
                job.cleanup_started = true;
                // Queue atomically refuses this commitment if a cancellation
                // won first; no deletion may happen before the durable claim.
                job = self.queue.save_progress(&job)?;
                if !job.cleanup_started {
                    drop(session);
                    job.metrics.max_writer_lock_millis =
                        job.metrics.max_writer_lock_millis.max(if leased {
                            (self.clock)().saturating_sub(acquired)
                        } else {
                            0
                        });
                    return self.fail(job, MaintenanceFailureKind::Cancelled);
                }
            }
            let cleanup_control = MaintenanceControl {
                cancelled: Default::default(),
                paused: control.paused.clone(),
            };
            let effective_control = if job.cleanup_started {
                &cleanup_control
            } else {
                control
            };
            let began = (self.clock)();
            let outcome = session.execute(phase, &job, effective_control);
            let now = (self.clock)();
            if let Some(duration) = job
                .metrics
                .stage_millis
                .iter_mut()
                .find(|entry| entry.phase == phase)
            {
                duration.millis = duration.millis.saturating_add(now.saturating_sub(began));
            } else {
                job.metrics.stage_millis.push(MaintenanceStageDuration {
                    phase,
                    millis: now.saturating_sub(began),
                });
            }
            job.metrics.max_writer_lock_millis =
                job.metrics.max_writer_lock_millis.max(if leased {
                    now.saturating_sub(acquired)
                } else {
                    0
                });
            match outcome {
                Ok(result) => {
                    if let Some(backup) = result.backup {
                        job.backup = Some(backup);
                    }
                    job.logical_compaction_committed |= result.logical_compaction_committed;
                    merge_metrics(&mut job.metrics, result.metrics);
                    let next = result.next_phase.unwrap_or_else(|| next_phase(phase));
                    let valid = (next == next_phase(phase)
                        || (phase == MaintenancePhase::Backup && next == phase))
                        && (phase != MaintenancePhase::Validate || job.backup.is_some())
                        && (phase != MaintenancePhase::Backup
                            || next == phase
                            || job.backup.as_ref().is_some_and(|backup| backup.verified))
                        && (phase != MaintenancePhase::Compact || job.logical_compaction_committed);
                    if !valid {
                        drop(session);
                        job.metrics.max_writer_lock_millis =
                            job.metrics.max_writer_lock_millis.max(if leased {
                                (self.clock)().saturating_sub(acquired)
                            } else {
                                0
                            });
                        return self.fail(job, MaintenanceFailureKind::IntegrityFailed);
                    }
                    job.phase = next;
                    job.updated_at_ms = now;
                    job.consecutive_budget_exhaustions = 0;
                    job.reason = None;
                    // Full backup intent and each successful physical phase become
                    // durable before the next operation starts under this lease.
                    job = self.queue.save_progress(&job)?;
                }
                Err(error) => {
                    drop(session);
                    job.metrics.max_writer_lock_millis =
                        job.metrics.max_writer_lock_millis.max(if leased {
                            (self.clock)().saturating_sub(acquired)
                        } else {
                            0
                        });
                    return self.fail(job, error.kind);
                }
            }
        }
    }
    fn interruption(
        &self,
        job: &MaintenanceJob,
        control: &MaintenanceControl,
    ) -> PortResult<Option<MaintenanceFailureKind>> {
        let current = self.queue.control(Some(&job.id))?;
        if !job.cleanup_started && (current.cancel_requested || job.cancel_requested) {
            return Ok(Some(MaintenanceFailureKind::Cancelled));
        }
        if current.paused {
            return Ok(Some(MaintenanceFailureKind::Paused));
        }
        if job.cleanup_started {
            return Ok(control
                .paused
                .load(std::sync::atomic::Ordering::Acquire)
                .then_some(MaintenanceFailureKind::Paused));
        }
        Ok(control.check().err().map(|error| error.kind))
    }
    fn fail(
        &self,
        mut job: MaintenanceJob,
        kind: MaintenanceFailureKind,
    ) -> PortResult<MaintenanceJob> {
        let kind = if job.cleanup_started && kind == MaintenanceFailureKind::Cancelled {
            // A backend interruption after the irreversible commitment requires
            // finishing cleanup, never a promise that cancellation retained it.
            MaintenanceFailureKind::CleanupFailed
        } else {
            kind
        };
        let kind = if kind == MaintenanceFailureKind::Cancelled
            && job.phase == MaintenancePhase::Compact
            && !job.logical_compaction_committed
            && !job.logical_compaction_reconciled
        {
            match self.catalog.reconcile(&job) {
                Ok(committed) => {
                    job.logical_compaction_committed = committed;
                    job.logical_compaction_reconciled = true;
                    kind
                }
                Err(error) => error.kind,
            }
        } else {
            kind
        };
        use MaintenanceFailureKind as F;
        use MaintenanceState as S;
        job.reason = Some(kind);
        job.updated_at_ms = (self.clock)();
        job.state = match kind {
            F::Busy | F::Paused => S::Deferred,
            F::BudgetExhausted => {
                job.consecutive_budget_exhaustions =
                    job.consecutive_budget_exhaustions.saturating_add(1);
                if job.consecutive_budget_exhaustions >= NO_PROGRESS_BUDGET_LIMIT {
                    S::NeedsAttention
                } else {
                    S::Deferred
                }
            }
            F::Cancelled => S::Cancelled,
            F::TargetChanged | F::SelectionChanged | F::UnsupportedTarget => S::NeedsReview,
            F::InsufficientSpace | F::PermissionDenied | F::CleanupFailed => S::NeedsAttention,
            F::IntegrityFailed | F::Backend => S::Failed,
        };
        if job.state == S::Deferred {
            let index = job
                .attempts
                .saturating_sub(1)
                .min((RETRY_SECONDS.len() - 1) as u64) as usize;
            job.next_retry_at_ms = job
                .updated_at_ms
                .saturating_add(RETRY_SECONDS[index] * 1000);
        }
        self.queue.save_progress(&job)
    }
}
fn next_phase(phase: MaintenancePhase) -> MaintenancePhase {
    use MaintenancePhase::*;
    match phase {
        Validate => Backup,
        Backup => Compact,
        Compact => Vacuum,
        Vacuum => Checkpoint,
        Checkpoint => Verify,
        Verify => Cleanup,
        Cleanup | Done => Done,
    }
}
fn merge_metrics(current: &mut MaintenanceMetrics, incoming: MaintenanceMetrics) {
    if incoming.before != MaintenanceFootprint::default() {
        current.before = incoming.before;
    }
    if incoming.after != MaintenanceFootprint::default() {
        current.after = incoming.after;
    }
    current.max_writer_lock_millis = current
        .max_writer_lock_millis
        .max(incoming.max_writer_lock_millis);
    current.peak_memory_bytes = current.peak_memory_bytes.max(incoming.peak_memory_bytes);
    current.reclaimed_bytes = if current.after == MaintenanceFootprint::default() {
        0
    } else {
        footprint_bytes(&current.before).saturating_sub(footprint_bytes(&current.after))
    };
}

fn footprint_bytes(footprint: &MaintenanceFootprint) -> u64 {
    [
        footprint.catalog_bytes,
        footprint.wal_bytes,
        footprint.shm_bytes,
        footprint.queue_bytes,
        footprint.backup_bytes,
        footprint.temporary_bytes,
    ]
    .into_iter()
    .fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[derive(Default)]
    struct Queue {
        jobs: RefCell<Vec<MaintenanceJob>>,
        paused: Cell<bool>,
        fail_compaction_ack: Cell<bool>,
        fail_cleanup_ack: Cell<bool>,
        cancel_before_cleanup_claim: Cell<bool>,
    }
    impl MaintenanceQueue for Queue {
        fn enqueue(&self, job: &MaintenanceJob) -> PortResult<MaintenanceJob> {
            if let Some(old) = self.find_by_token(&job.token)? {
                return Ok(old);
            }
            self.jobs.borrow_mut().push(job.clone());
            Ok(job.clone())
        }
        fn find_by_token(&self, token: &str) -> PortResult<Option<MaintenanceJob>> {
            Ok(self
                .jobs
                .borrow()
                .iter()
                .find(|j| j.token == token)
                .cloned())
        }
        fn get(&self, id: &str) -> PortResult<MaintenanceJob> {
            self.jobs
                .borrow()
                .iter()
                .find(|j| j.id == id)
                .cloned()
                .ok_or_else(|| PortError::NotFound("job".into()))
        }
        fn list(&self, _: Option<&str>) -> PortResult<Vec<MaintenanceJob>> {
            Ok(self.jobs.borrow().clone())
        }
        fn save_progress(&self, job: &MaintenanceJob) -> PortResult<MaintenanceJob> {
            if job.phase == MaintenancePhase::Vacuum && self.fail_compaction_ack.replace(false) {
                return Err(PortError::Backend("injected lost acknowledgement".into()));
            }
            let mut jobs = self.jobs.borrow_mut();
            let old = jobs.iter_mut().find(|j| j.id == job.id).unwrap();
            if job.cleanup_started && !old.cleanup_started {
                if self.cancel_before_cleanup_claim.replace(false) {
                    old.cancel_requested = true;
                }
                if old.cancel_requested {
                    return Ok(old.clone());
                }
            }
            if job.phase == MaintenancePhase::Done && self.fail_cleanup_ack.replace(false) {
                return Err(PortError::Backend(
                    "injected cleanup acknowledgement loss".into(),
                ));
            }
            let cancel = old.cancel_requested;
            *old = job.clone();
            old.cancel_requested = cancel;
            old.revision += 1;
            Ok(old.clone())
        }
        fn request_cancel(&self, id: &str) -> PortResult<MaintenanceJob> {
            let mut jobs = self.jobs.borrow_mut();
            let old = jobs.iter_mut().find(|j| j.id == id).unwrap();
            if !old.cleanup_started && old.phase != MaintenancePhase::Done {
                old.cancel_requested = true;
            }
            Ok(old.clone())
        }
        fn set_paused(&self, paused: bool) -> PortResult<()> {
            self.paused.set(paused);
            Ok(())
        }
        fn control(&self, id: Option<&str>) -> PortResult<MaintenanceQueueControl> {
            Ok(MaintenanceQueueControl {
                paused: self.paused.get(),
                cancel_requested: id
                    .map(|id| self.get(id).unwrap().cancel_requested)
                    .unwrap_or(false),
            })
        }
    }
    struct Catalog<'a> {
        queue: &'a Queue,
        events: RefCell<Vec<MaintenancePhase>>,
        failure: Cell<Option<(MaintenancePhase, MaintenanceFailureKind)>>,
        busy_acquire: Cell<bool>,
        preview_calls: Cell<usize>,
        changed: Cell<bool>,
        cancel_at: Cell<Option<MaintenancePhase>>,
        committed: Cell<bool>,
    }
    impl<'a> Catalog<'a> {
        fn new(queue: &'a Queue) -> Self {
            Self {
                queue,
                events: RefCell::new(vec![]),
                failure: Cell::new(None),
                busy_acquire: Cell::new(false),
                preview_calls: Cell::new(0),
                changed: Cell::new(false),
                cancel_at: Cell::new(None),
                committed: Cell::new(false),
            }
        }
    }
    impl MaintenanceCatalog for Catalog<'_> {
        fn reconcile(&self, job: &MaintenanceJob) -> MaintenanceResult<bool> {
            Ok(job.logical_compaction_committed || self.committed.get())
        }
        fn preview(&self, target: &str) -> PortResult<MaintenancePreview> {
            self.preview_calls.set(self.preview_calls.get() + 1);
            Ok(MaintenancePreview {
                token: if self.changed.get() {
                    "changed"
                } else {
                    "plan"
                }
                .into(),
                target: MaintenanceTarget {
                    canonical_path: target.into(),
                    file_identity: "secret-file-identity".into(),
                    schema_version: 19,
                },
                selection: MaintenanceSelection {
                    plan_digest: "digest".into(),
                    aggregated_fields: vec![],
                    batches: vec![MaintenanceSelectionItem {
                        operation_id: "native-private-id".into(),
                        state: "activated".into(),
                        base_generation: 1,
                        target_generation: 2,
                        operation_digest: "op".into(),
                        detail_digest: "detail".into(),
                        fields: vec![],
                    }],
                    detail_bytes_before: 1000,
                    estimated_detail_bytes_after: 50,
                    estimated_saved_bytes: 950,
                },
                footprint: MaintenanceFootprint::default(),
            })
        }
        fn acquire(
            &self,
            _: &MaintenanceJob,
        ) -> MaintenanceResult<Box<dyn MaintenanceSession + '_>> {
            if self.busy_acquire.get() {
                return Err(MaintenanceFailureKind::Busy.into());
            }
            Ok(Box::new(Session(self)))
        }
    }
    struct Session<'a>(&'a Catalog<'a>);
    impl MaintenanceSession for Session<'_> {
        fn execute(
            &mut self,
            phase: MaintenancePhase,
            job: &MaintenanceJob,
            _: &MaintenanceControl,
        ) -> MaintenanceResult<MaintenanceStageResult> {
            self.0.events.borrow_mut().push(phase);
            if let Some((at, kind)) = self.0.failure.get()
                && phase == at
            {
                return Err(kind.into());
            }
            if self.0.cancel_at.get() == Some(phase) {
                self.0.queue.request_cancel(&job.id).unwrap();
            }
            let mut result = MaintenanceStageResult::default();
            if phase == MaintenancePhase::Validate {
                result.backup = Some(MaintenanceBackup {
                    relative_path: "owned/backup".into(),
                    source_generation: 2,
                    invariant_digest: "baseline".into(),
                    verified: false,
                });
            }
            if phase == MaintenancePhase::Backup {
                let persisted = self.0.queue.get(&job.id).unwrap();
                assert!(persisted.backup.is_some(), "intent must precede copying");
                let mut backup = persisted.backup.unwrap();
                backup.verified = true;
                result.backup = Some(backup);
            }
            if phase == MaintenancePhase::Compact {
                assert!(job.backup.as_ref().unwrap().verified);
                self.0.committed.set(true);
                result.logical_compaction_committed = true;
            }
            Ok(result)
        }
    }
    fn now() -> u64 {
        1000
    }
    #[test]
    fn completed_token_is_idempotent_without_repreview_and_summary_is_private() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("/private/catalog", "plan", None).unwrap();
        assert_eq!(job.max_write_seconds, 30);
        assert_eq!(job.compaction_id.len(), 71);
        let complete = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(complete.state, MaintenanceState::Completed);
        assert_eq!(complete.metrics.stage_millis.len(), 7);
        catalog.changed.set(true);
        let repeated = service
            .submit("/private/catalog", "plan", Some(40))
            .unwrap();
        assert_eq!(repeated.id, job.id);
        assert_eq!(catalog.preview_calls.get(), 1);
        assert_eq!(repeated.max_write_seconds, 30);
        let summary = serde_json::to_string(&complete.summary()).unwrap();
        for private in [
            "/private",
            "secret-file",
            "native-private",
            "baseline",
            "owned/backup",
        ] {
            assert!(!summary.contains(private));
        }
    }
    #[test]
    fn stale_preview_and_zero_budget_never_enqueue() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        assert!(matches!(
            service.submit("catalog", "bad", None),
            Err(PortError::GenerationMismatch(_))
        ));
        assert!(matches!(
            service.submit("catalog", "plan", Some(0)),
            Err(PortError::InvalidRequest(_))
        ));
        assert!(queue.list(None).unwrap().is_empty());
    }
    #[test]
    fn busy_backoff_caps_and_retries_require_no_new_submission() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.busy_acquire.set(true);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        for delay in [1, 2, 5, 15, 30, 60, 60] {
            let deferred = service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap();
            assert_eq!(deferred.next_retry_at_ms, 1000 + delay * 1000);
            assert_eq!(deferred.state, MaintenanceState::Deferred);
            assert!(
                service
                    .next_runnable(deferred.next_retry_at_ms - 1)
                    .unwrap()
                    .is_none()
            );
            assert!(
                service
                    .next_runnable(deferred.next_retry_at_ms)
                    .unwrap()
                    .is_some()
            );
        }
        catalog.busy_acquire.set(false);
        assert_eq!(
            service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap()
                .state,
            MaintenanceState::Completed
        );
    }
    #[test]
    fn three_budget_exhaustions_require_explicit_retry_and_keep_budget() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.failure.set(Some((
            MaintenancePhase::Validate,
            MaintenanceFailureKind::BudgetExhausted,
        )));
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        for expected in [
            MaintenanceState::Deferred,
            MaintenanceState::Deferred,
            MaintenanceState::NeedsAttention,
        ] {
            let result = service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap();
            assert_eq!(result.state, expected);
            assert_eq!(result.max_write_seconds, 30);
        }
        assert!(service.next_runnable(u64::MAX).unwrap().is_none());
        let retried = service.retry(&job.id, Some(60)).unwrap();
        assert_eq!(retried.max_write_seconds, 60);
        assert_eq!(retried.consecutive_budget_exhaustions, 0);
        catalog.failure.set(None);
        assert_eq!(
            service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap()
                .state,
            MaintenanceState::Completed
        );
    }
    #[test]
    fn durable_stage_progress_resets_budget_exhaustion_streak() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        catalog.failure.set(Some((
            MaintenancePhase::Validate,
            MaintenanceFailureKind::BudgetExhausted,
        )));
        service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        let second = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(second.consecutive_budget_exhaustions, 2);
        catalog.failure.set(Some((
            MaintenancePhase::Backup,
            MaintenanceFailureKind::BudgetExhausted,
        )));
        let advanced = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(advanced.phase, MaintenancePhase::Backup);
        assert_eq!(advanced.state, MaintenanceState::Deferred);
        assert_eq!(advanced.consecutive_budget_exhaustions, 1);
    }
    #[test]
    fn checkpoint_contention_never_repeats_compaction_or_vacuum_and_metrics_are_bounded() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.failure.set(Some((
            MaintenancePhase::Checkpoint,
            MaintenanceFailureKind::Busy,
        )));
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        for _ in 0..20 {
            let deferred = service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap();
            assert_eq!(deferred.phase, MaintenancePhase::Checkpoint);
            assert!(deferred.metrics.stage_millis.len() <= 7);
        }
        assert_eq!(
            catalog
                .events
                .borrow()
                .iter()
                .filter(|p| **p == MaintenancePhase::Compact)
                .count(),
            1
        );
        assert_eq!(
            catalog
                .events
                .borrow()
                .iter()
                .filter(|p| **p == MaintenancePhase::Vacuum)
                .count(),
            1
        );
        catalog.failure.set(None);
        assert_eq!(
            service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap()
                .state,
            MaintenanceState::Completed
        );
    }
    #[test]
    fn cancel_after_backup_retains_it_and_prevents_compaction() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.cancel_at.set(Some(MaintenancePhase::Backup));
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        let result = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(result.state, MaintenanceState::Cancelled);
        assert!(result.backup.unwrap().verified);
        assert!(!catalog.events.borrow().contains(&MaintenancePhase::Compact));
        assert!(service.retry(&job.id, None).is_err());
    }
    #[test]
    fn pause_is_persistent_and_start_does_not_increase_budget() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        queue.set_paused(true).unwrap();
        assert!(service.next_runnable(u64::MAX).unwrap().is_none());
        let paused = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(paused.reason, Some(MaintenanceFailureKind::Paused));
        assert!(catalog.events.borrow().is_empty());
        queue.set_paused(false).unwrap();
        assert!(service.next_runnable(u64::MAX).unwrap().is_some());
        assert_eq!(queue.get(&job.id).unwrap().max_write_seconds, 30);
    }
    #[test]
    fn cleanup_failure_retries_only_cleanup_and_drift_needs_new_preview() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.failure.set(Some((
            MaintenancePhase::Cleanup,
            MaintenanceFailureKind::CleanupFailed,
        )));
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        let failed = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(failed.state, MaintenanceState::NeedsAttention);
        assert_eq!(failed.phase, MaintenancePhase::Cleanup);
        service.retry(&job.id, None).unwrap();
        catalog.failure.set(None);
        service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(
            catalog
                .events
                .borrow()
                .iter()
                .filter(|p| **p == MaintenancePhase::Compact)
                .count(),
            1
        );
        let mut stale = queue.get(&job.id).unwrap();
        stale.state = MaintenanceState::NeedsReview;
        queue.save_progress(&stale).unwrap();
        assert!(service.retry(&job.id, None).is_err());
    }
    #[test]
    fn cancelled_lost_compaction_ack_reconciles_without_reexecuting_mutation() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        queue.fail_compaction_ack.set(true);
        assert!(
            service
                .run_job(&job.id, &MaintenanceControl::default())
                .is_err()
        );
        let crashed = queue.get(&job.id).unwrap();
        assert_eq!(crashed.phase, MaintenancePhase::Compact);
        assert_eq!(crashed.summary().logical_compaction_committed, None);
        assert!(catalog.committed.get());
        queue.request_cancel(&job.id).unwrap();
        let cancelled = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(cancelled.state, MaintenanceState::Cancelled);
        assert_eq!(cancelled.summary().logical_compaction_committed, Some(true));
        assert!(cancelled.backup.unwrap().verified);
        assert_eq!(
            catalog
                .events
                .borrow()
                .iter()
                .filter(|p| **p == MaintenancePhase::Compact)
                .count(),
            1
        );
        assert!(!catalog.events.borrow().contains(&MaintenancePhase::Vacuum));
    }
    #[test]
    fn cancellation_before_cleanup_claim_retains_backup_without_deleting() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        queue.cancel_before_cleanup_claim.set(true);
        let cancelled = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(cancelled.state, MaintenanceState::Cancelled);
        assert!(!cancelled.summary().cancellation_closed);
        assert!(cancelled.backup.unwrap().verified);
        assert!(!catalog.events.borrow().contains(&MaintenancePhase::Cleanup));
    }
    #[test]
    fn cancellation_inside_successful_cleanup_is_explicitly_closed_and_completes() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.cancel_at.set(Some(MaintenancePhase::Cleanup));
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        let completed = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(completed.state, MaintenanceState::Completed);
        assert!(completed.summary().cancellation_closed);
        assert!(!completed.cancel_requested);
    }
    #[test]
    fn cleanup_success_before_ack_recovers_under_cutoff_and_done_never_acquires() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        queue.fail_cleanup_ack.set(true);
        assert!(
            service
                .run_job(&job.id, &MaintenanceControl::default())
                .is_err()
        );
        let crashed = queue.get(&job.id).unwrap();
        assert_eq!(crashed.phase, MaintenancePhase::Cleanup);
        assert!(crashed.cleanup_started);
        assert!(!queue.request_cancel(&job.id).unwrap().cancel_requested);
        let completed = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(completed.state, MaintenanceState::Completed);
        catalog.busy_acquire.set(true);
        queue.set_paused(true).unwrap();
        assert_eq!(
            service
                .run_job(&job.id, &MaintenanceControl::default())
                .unwrap()
                .state,
            MaintenanceState::Completed
        );
    }
    #[test]
    fn cleanup_cutoff_preserves_pause_and_retry_not_cancellation() {
        let queue = Queue::default();
        let catalog = Catalog::new(&queue);
        catalog.failure.set(Some((
            MaintenancePhase::Cleanup,
            MaintenanceFailureKind::Cancelled,
        )));
        let service = MaintenanceService::new(&queue, &catalog, now);
        let job = service.submit("catalog", "plan", None).unwrap();
        let attention = service
            .run_job(&job.id, &MaintenanceControl::default())
            .unwrap();
        assert_eq!(attention.state, MaintenanceState::NeedsAttention);
        assert!(attention.summary().cancellation_closed);
        assert!(!queue.request_cancel(&job.id).unwrap().cancel_requested);
        service.retry(&job.id, None).unwrap();
        queue.set_paused(true).unwrap();
        let control = MaintenanceControl::default();
        control
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(
            service.run_job(&job.id, &control).unwrap().reason,
            Some(MaintenanceFailureKind::Paused)
        );
        queue.set_paused(false).unwrap();
        catalog.failure.set(None);
        assert_eq!(
            service.run_job(&job.id, &control).unwrap().state,
            MaintenanceState::Completed
        );
    }
    #[test]
    fn reclaimed_bytes_match_latest_footprint_not_historical_maximum() {
        let mut metrics = MaintenanceMetrics {
            before: MaintenanceFootprint {
                catalog_bytes: 1000,
                ..Default::default()
            },
            ..Default::default()
        };
        merge_metrics(
            &mut metrics,
            MaintenanceMetrics {
                after: MaintenanceFootprint {
                    catalog_bytes: 100,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(metrics.reclaimed_bytes, 900);
        merge_metrics(
            &mut metrics,
            MaintenanceMetrics {
                after: MaintenanceFootprint {
                    catalog_bytes: 800,
                    ..Default::default()
                },
                reclaimed_bytes: 900,
                ..Default::default()
            },
        );
        assert_eq!(metrics.reclaimed_bytes, 200);
    }
}
