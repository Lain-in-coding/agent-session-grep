//! A live worker may already report Busy/Deferred when a `--latest` read is
//! admitted. Actual CLI children read synthetic catalogs while each test owns
//! the worker lock and heartbeat; no real assistant history is involved.
use agent_session_grep_adapters_sqlite::{
    PARSER_SEMANTIC_VERSION, SourceBatch, SqliteControlStore,
    control::LockedWorkerAuthority,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{
    EvidenceSpan, IdKind, MessageEdge, MessagePlacement, MessageRelation, StableId,
};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider, SourceResumeClaim,
    control::*,
    managed::{
        ObservationState, RepositoryClaim, RevisionId, SelectionProof, SourceBinding, SourceId,
        SourceObservation,
    },
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_agent-session-grep");
const TEXT: &str = "advisory admission original needle";
const BOOT: &str = "synthetic-boot";

fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn entity(kind: IdKind, name: &str) -> StableId {
    StableId::native_checked(kind, name).unwrap()
}
fn lock(root: &Path, kind: LockKind) -> ExclusiveGuard {
    lock_before(root, kind, Instant::now() + Duration::from_secs(2))
}
fn lock_before(root: &Path, kind: LockKind, end: Instant) -> ExclusiveGuard {
    let deadline = end.min(Instant::now() + Duration::from_secs(2));
    loop {
        assert!(Instant::now() < deadline, "fixture lock deadline expired");
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(guard) => return guard,
            Err(PortError::WriterBusy(_)) if Instant::now() < deadline => std::thread::yield_now(),
            Err(error) => panic!("fixture lock: {error:?}"),
        }
    }
}
fn current(control: &SqliteControlStore) -> ControlSeq {
    control.status().unwrap().policy.control_seq
}

fn prepare_before<T>(
    control: &SqliteControlStore,
    requested: Instant,
    prepare: impl FnOnce(Instant) -> PortResult<T>,
) -> PortResult<T> {
    let end = SqliteControlStore::effective_runtime_deadline(requested);
    let probe = requested + Duration::from_secs(1);
    let previous = SqliteControlStore::effective_runtime_deadline(probe);
    let result = control.with_runtime_deadline(end, || {
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            end,
            "fixture preparation must receive its original scope"
        );
        prepare(end)
    });
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe),
        previous,
        "fixture preparation must restore the caller scope"
    );
    result
}

fn bind_before<'a>(
    control: &'a SqliteControlStore,
    guard: &'a ExclusiveGuard,
    end: Instant,
) -> PortResult<LockedWorkerAuthority<'a>> {
    prepare_before(control, end, |end| {
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(end + Duration::from_secs(1)),
            end,
            "worker binding must receive the original fixture end"
        );
        control.bind_worker(guard, id(BOOT))
    })
}

/// One committed synthetic source under a registered worker boot whose OS
/// lock is released; each test binds the same boot to act as the live owner.
struct Fixture {
    root: PathBuf,
    db: PathBuf,
    control: SqliteControlStore,
    batch: SourceBatch,
    observation: SourceObservation,
    publication_end: Instant,
    // Connections and OS guards must close before Windows temp cleanup.
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let root = temp.path().join("private");
        let db = root.join("catalog.db");
        let control = SqliteControlStore::create(
            &root,
            &id("synthetic-installation"),
            DesiredUpdates::Running,
        )
        .unwrap();
        // This is a new fixture preparation allowance after control creation,
        // not the test operation's separately started end or a create budget.
        let setup_end = SqliteControlStore::effective_runtime_deadline(
            Instant::now() + Duration::from_secs(20),
        );
        let (batch, observation, publication_end) =
            prepare_before(&control, setup_end, |setup_end| {
                let selection = control
                    .add_selection(
                        current(&control),
                        SelectionRequest {
                            region: ScopeRegion {
                                provider: SearchProvider::Claude,
                                locator: CanonicalLocator::from_path(
                                    &temp.path().canonicalize().unwrap(),
                                )
                                .unwrap(),
                                kind: RootKind::Root,
                            },
                            root_identity: Some(id("source-root")),
                            now_ms: 1,
                        },
                    )
                    .unwrap()
                    .value;
                let guard = lock_before(&root, LockKind::Background, setup_end);
                let worker = bind_before(&control, &guard, setup_end)?;
                control
                    .register_worker(current(&control), &worker, 1, 1)
                    .unwrap();
                let cycle = match control
                    .queue_cycle(
                        current(&control),
                        vec![SelectionRevision {
                            selection_id: selection.id.clone(),
                            revision: selection.revision,
                            root_identity: id("source-root"),
                        }],
                    )
                    .unwrap()
                    .value
                {
                    CycleAdmission::Queued(cycle) => cycle,
                    blocked => panic!("fixture cycle: {blocked:?}"),
                };
                let cycle = control
                    .start_cycle(current(&control), &worker, cycle.token.cycle_seq, 2)
                    .unwrap()
                    .value;
                let session = entity(IdKind::Session, "session");
                let document = entity(IdKind::Document, "document");
                let message = entity(IdKind::Message, "message-0");
                let system = entity(IdKind::Message, "system");
                let observation = SourceObservation {
                    binding: SourceBinding {
                        source_id: SourceId::parse("synthetic-source").unwrap(),
                        source_path: CanonicalLocator::from_path(
                            &temp.path().join("synthetic.jsonl"),
                        )
                        .unwrap()
                        .as_str()
                        .into(),
                        provider: SearchProvider::Claude,
                        namespace_id: None,
                        root_identity: "source-root".into(),
                    },
                    revision_id: RevisionId::parse("synthetic-revision").unwrap(),
                    revision_digest: "0123456789abcdef".repeat(4),
                    parser_version: PARSER_SEMANTIC_VERSION,
                    state: ObservationState::Complete,
                    cycle_seq: cycle.token.cycle_seq.get(),
                    worker_boot_id: BOOT.into(),
                    catalog_incarnation: "synthetic-incarnation".into(),
                    policy_epoch: cycle.policy_epoch.get(),
                    started_control_seq: cycle.started_control_seq.unwrap().get(),
                    observed_at_ms: 3,
                    committed_at_ms: 4,
                    selections: vec![SelectionProof {
                        selection_id: selection.id.as_str().into(),
                        selection_revision: selection.revision.get(),
                        root_identity: "source-root".into(),
                    }],
                    repositories: vec![RepositoryClaim {
                        session_id: session.clone(),
                        slug: "example.test/team/project".into(),
                    }],
                };
                let timestamp = "2026-10-17T12:00:00Z";
                let entries = vec![
            (
                session.clone(),
                serde_json::to_vec(
                    &json!({"documents":[document.as_str()],"title":"Synthetic session"}),
                )
                .unwrap(),
                String::new(),
            ),
            (
                document.clone(),
                serde_json::to_vec(&json!({"provider":"claude-code","variant":"synthetic-v1",
                    "fingerprint":observation.revision_digest,"len":1000000}))
                .unwrap(),
                String::new(),
            ),
            (
                message.clone(),
                serde_json::to_vec(&json!({"role":"user","text":TEXT,"timestamp":timestamp}))
                    .unwrap(),
                TEXT.into(),
            ),
            (
                system.clone(),
                serde_json::to_vec(
                    &json!({"role":"system","text":"synthetic system text","timestamp":timestamp}),
                )
                .unwrap(),
                "synthetic system text".into(),
            ),
        ];
                let placement = MessagePlacement::new(
                    session.clone(),
                    document.clone(),
                    message.clone(),
                    0,
                    false,
                    Some(EvidenceSpan { start: 0, end: 90 }),
                );
                let system_placement =
                    MessagePlacement::new(session.clone(), document, system, 1, false, None);
                let edges = vec![MessageEdge {
                    child_placement_id: system_placement.id.clone(),
                    parent_message_id: message,
                    parent_native_id: None,
                    relation: MessageRelation::Reply,
                }];
                let batch = SourceBatch {
                    source_path: observation.binding.source_path.clone(),
                    entries,
                    placements: vec![placement, system_placement],
                    edges,
                    activities: vec![],
                    usage_events: vec![],
                    relation_complete: true,
                    len_bytes: Some(1000000),
                    fingerprint: Some(observation.revision_digest.clone()),
                    provider_id: Some("claude-code".into()),
                    resume_claims: vec![SourceResumeClaim {
                        session_id: session.as_str().into(),
                        provider_id: "claude-code".into(),
                        provider_session_id: Some("synthetic-native-session".into()),
                        provider_session_id_state: "resolved".into(),
                        original_working_directory: Some("synthetic-working-directory".into()),
                        original_working_directory_state: "resolved".into(),
                        pair_observed: true,
                    }],
                };
                let store =
                    ManagedStore::create(&db, &control, id("synthetic-incarnation"), 1).unwrap();
                let publication_started = Instant::now();
                let publication_end = setup_end.min(publication_started + Duration::from_secs(10));
                let publish = |received: Instant| {
                    assert_eq!(
                        received, publication_end,
                        "catalog publication must receive the saved setup-capped end"
                    );
                    store.commit_source_with_context(
                    &control,
                    &worker,
                    &batch,
                    &observation,
                    &agent_session_grep_ports::source_context::SourcePublicationContext::default(),
                    received,
                )?;
                    Ok::<_, PortError>(received)
                };
                let publication_end = publish(publication_end)?;
                drop(store);
                drop(worker);
                drop(guard);
                Ok((batch, observation, publication_end))
            })
            .unwrap();
        Self {
            _temp: temp,
            root,
            db,
            control,
            batch,
            observation,
            publication_end,
        }
    }

    fn spawn_latest(&self, wait_ms: u32) -> LatestChild {
        let wait = wait_ms.to_string();
        LatestChild(Some(
            Command::new(BIN)
                .args(["--robot", "--db"])
                .arg(&self.db)
                .args([
                    "search",
                    "needle",
                    "--latest",
                    "--max-wait-ms",
                    wait.as_str(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }

    /// Open the writer as the live worker, retire the fixture's old cycle, and
    /// report `state` before any latest request exists. Returns the writer and
    /// the cycle number the request's admission will allocate.
    fn advise_before_admission(
        &self,
        worker: &LockedWorkerAuthority<'_>,
        state: UpdateState,
        end: Instant,
    ) -> (ManagedStore, CycleSeq) {
        let store = self
            .control
            .with_runtime_deadline(end, || {
                ManagedStore::open_for_write(&self.db, &self.control)
            })
            .unwrap();
        self.control
            .with_runtime_deadline(end, || store.reconcile_progress(&self.control, worker))
            .unwrap();
        let error = advisory(state);
        self.control
            .with_runtime_deadline(end, || {
                self.control.heartbeat_worker(
                    current(&self.control),
                    worker,
                    state,
                    Some(error),
                    12,
                )
            })
            .unwrap();
        let status = self
            .control
            .with_runtime_deadline(end, || self.control.background_status())
            .unwrap();
        assert_eq!(status.worker.state, state);
        assert_eq!(status.worker.error, Some(error));
        assert_eq!(status.worker.boot_id, Some(id(BOOT)));
        (store, status.next_cycle_seq)
    }

    /// Wait until the child admitted exactly one barrier for `next`, then
    /// check that the stored row is Pending although the live view overlays
    /// the advisory that was present before admission.
    fn await_admission(
        &self,
        child: &mut LatestChild,
        next: CycleSeq,
        wait_ms: u32,
        state: UpdateState,
        end: Instant,
    ) -> LatestBarrier {
        let deadline = Instant::now() + Duration::from_secs(8);
        let queued = loop {
            let exited = child.get().try_wait().unwrap().is_some();
            // Read after the exit check: a child that admits then exits at
            // once still leaves its committed cycle row behind.
            match self
                .control
                .with_runtime_deadline(end, || self.control.cycle(next))
            {
                Ok(cycle) => break cycle,
                Err(PortError::NotFound(_) | PortError::WriterBusy(_))
                    if !exited && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("latest child did not admit a queued cycle: {error:?}"),
            }
        };
        assert_eq!(queued.state, CycleState::Queued);
        let stored = self.only_barrier(end, |control, barrier| control.persisted_barrier(barrier));
        assert_eq!(stored.required_cycle_seq, next);
        assert_eq!(stored.requested_wait_ms, wait_ms);
        assert_eq!(stored.state, BarrierState::Pending);
        assert_eq!(stored.error, None);
        let live = self.only_barrier(end, |control, barrier| control.barrier(barrier));
        assert_same_admission(&stored, &live);
        assert_eq!(live.state, BarrierState::Blocked);
        assert_eq!(live.error, Some(advisory(state)));
        stored
    }

    fn only_barrier(
        &self,
        end: Instant,
        read: impl Fn(
            &SqliteControlStore,
            &ControlId,
        ) -> agent_session_grep_ports::PortResult<LatestBarrier>,
    ) -> LatestBarrier {
        let conn = rusqlite::Connection::open_with_flags(
            SqliteControlStore::path(&self.root),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM barriers", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "one CLI request must admit exactly one barrier"
        );
        let identifier: String = conn
            .query_row("SELECT barrier_id FROM barriers", [], |row| row.get(0))
            .unwrap();
        self.control
            .with_runtime_deadline(end, || read(&self.control, &id(&identifier)))
            .unwrap()
    }

    /// The request kept its one barrier and required cycle: nothing admitted
    /// a second cycle or replaced the worker boot.
    fn assert_single_admission(&self, admitted: &LatestBarrier, end: Instant) -> WorkerStatus {
        let stored = self.only_barrier(end, |control, barrier| control.persisted_barrier(barrier));
        assert_same_admission(admitted, &stored);
        let after = self
            .control
            .with_runtime_deadline(end, || self.control.background_status())
            .unwrap();
        assert_eq!(
            after.next_cycle_seq.get(),
            admitted.required_cycle_seq.get() + 1
        );
        assert_eq!(after.worker.boot_id, Some(id(BOOT)));
        after.worker
    }
}

struct LatestChild(Option<Child>);
impl LatestChild {
    fn get(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }
    fn assert_waiting(&mut self, duration: Duration) {
        let end = Instant::now() + duration;
        loop {
            assert!(
                self.get().try_wait().unwrap().is_none(),
                "latest returned before its catalog proof was published"
            );
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10).min(remaining));
        }
    }
    fn finish(mut self, within: Duration) -> Output {
        let end = Instant::now() + within;
        while self.get().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < end,
                "latest child did not exit within its bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for LatestChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn advisory(state: UpdateState) -> BackgroundFailure {
    match state {
        UpdateState::Busy => BackgroundFailure::Busy,
        UpdateState::Deferred => BackgroundFailure::Deferred,
        other => panic!("{other:?} is not a transient advisory"),
    }
}

fn assert_same_admission(before: &LatestBarrier, after: &LatestBarrier) {
    assert_eq!(after.id, before.id);
    assert_eq!(after.policy_epoch, before.policy_epoch);
    assert_eq!(after.admission_control_seq, before.admission_control_seq);
    assert_eq!(after.required_cycle_seq, before.required_cycle_seq);
    assert_eq!(after.requested_wait_ms, before.requested_wait_ms);
    assert_eq!(after.admitted_at_ms, before.admitted_at_ms);
    assert_eq!(after.selections, before.selections);
}

fn response(output: Output) -> Value {
    assert!(
        matches!(output.status.code(), Some(0 | 10)),
        "exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["freshness"]["latest_requested"], true);
    value
}

#[test]
fn preparation_and_real_worker_binding_restore_original_ends() {
    let fixture = Fixture::new();
    let control = &fixture.control;
    for nested in [false, true] {
        let end = Instant::now() + Duration::from_secs(20);
        let requested = end
            + if nested {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            };
        let calls = std::cell::Cell::new(0);
        let once = String::from("one preparation");
        let prepare = || {
            prepare_before(control, requested, |received| {
                drop(once);
                calls.set(calls.get() + 1);
                assert_eq!(received, end);
                let guard = lock_before(&fixture.root, LockKind::Background, received);
                let worker = bind_before(control, &guard, received)?;
                worker.validate()?;
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(
                        requested + Duration::from_secs(1)
                    ),
                    end
                );
                assert_eq!(control.background_status()?.worker.boot_id, Some(id(BOOT)));
                Ok(())
            })
        };
        if nested {
            control
                .with_runtime_deadline(end, || {
                    prepare()?;
                    assert_eq!(
                        SqliteControlStore::effective_runtime_deadline(requested),
                        end
                    );
                    Ok(())
                })
                .unwrap();
        } else {
            prepare().unwrap();
        }
        assert_eq!(calls.get(), 1);
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(requested),
            requested
        );
        // Also exercise the later, otherwise unscoped test-side binding.
        let guard = lock_before(&fixture.root, LockKind::Background, end);
        let worker = bind_before(control, &guard, end).unwrap();
        drop(worker);
        drop(guard);
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(requested),
            requested
        );
    }
}

#[test]
fn publication_receives_the_earlier_setup_end_before_catalog_sql() {
    let fixture = Fixture::new();
    let end = Instant::now() + Duration::from_secs(5);
    let nested = fixture
        .control
        .with_runtime_deadline(end, || Ok(Fixture::new()))
        .unwrap();
    assert_eq!(nested.publication_end, end);
    let probe = end + Duration::from_secs(1);
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
}

#[test]
fn expired_preparation_never_starts_selection_or_worker_lock() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("private");
    let control =
        SqliteControlStore::create(&root, &id("expired-setup"), DesiredUpdates::Paused).unwrap();
    let probe = Instant::now() + Duration::from_secs(20);
    let before = control
        .with_runtime_deadline(probe, || control.status())
        .unwrap();
    let calls = std::cell::Cell::new(0);
    let result = prepare_before(&control, Instant::now() - Duration::from_millis(1), |end| {
        calls.set(calls.get() + 1);
        let guard = lock_before(&root, LockKind::Background, end);
        let _worker = bind_before(&control, &guard, end)?;
        Ok(())
    });
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    assert_eq!(calls.get(), 0);
    assert!(!root.join("background.lock").exists());
    assert!(!root.join("catalog.db").exists());
    assert_eq!(
        control
            .with_runtime_deadline(probe, || control.status())
            .unwrap(),
        before
    );
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
}

#[test]
fn latest_admitted_during_live_advisory_waits_for_same_barrier_publication() {
    for state in [UpdateState::Busy, UpdateState::Deferred] {
        let f = Fixture::new();
        // Preparation gets its own end; the actual CLI keeps its usual budget.
        let end = Instant::now() + Duration::from_secs(20);
        let guard = lock(&f.root, LockKind::Background);
        let worker = bind_before(&f.control, &guard, end).unwrap();
        let (store, next) = f.advise_before_admission(&worker, state, end);
        let mut child = f.spawn_latest(10_000);
        let admitted = f.await_admission(&mut child, next, 10_000, state, end);
        // Only the advisory stands between the request and its proof.
        child.assert_waiting(Duration::from_millis(600));
        f.control
            .with_runtime_deadline(end, || {
                f.control.heartbeat_worker(
                    current(&f.control),
                    &worker,
                    UpdateState::Running,
                    None,
                    13,
                )
            })
            .unwrap();
        let cycle = f
            .control
            .with_runtime_deadline(end, || {
                f.control
                    .start_cycle(current(&f.control), &worker, next, 14)
            })
            .unwrap()
            .value;
        assert!(cycle.started_control_seq.unwrap() > admitted.admission_control_seq);
        store
            .begin_discovery_with_deadline(
                &f.control,
                &worker,
                &cycle,
                &cycle.selections[0].selection,
                end,
            )
            .unwrap();
        let mut observation = f.observation.clone();
        observation.cycle_seq = cycle.token.cycle_seq.get();
        observation.started_control_seq = cycle.started_control_seq.unwrap().get();
        observation.policy_epoch = cycle.policy_epoch.get();
        observation.revision_id = RevisionId::parse("advisory-admission-receipt").unwrap();
        observation.observed_at_ms = 15;
        observation.committed_at_ms = 16;
        let published = f
            .control
            .with_runtime_deadline(end, || {
                store.commit_source(&f.control, &worker, &f.batch, &observation)
            })
            .unwrap();
        assert!(published.receipt.published);
        // A source receipt alone still cannot satisfy discovery.
        child.assert_waiting(Duration::from_millis(100));
        store
            .commit_discovery_with_deadline(
                &f.control,
                &worker,
                &cycle,
                &cycle.selections[0].selection,
                std::slice::from_ref(&observation.binding.source_id),
                end,
            )
            .unwrap();
        let output = child.finish(Duration::from_secs(8));
        worker.validate().unwrap();
        f.assert_single_admission(&admitted, end);
        let value = response(output);
        // Search keeps its independent native-resume warning; freshness and the
        // original evidence still succeed under the one admitted barrier.
        assert_eq!(value["outcome"], "partial");
        assert_eq!(
            value["warnings"],
            json!(["resume_availability_unavailable"])
        );
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], true);
        assert_eq!(value["data"]["freshness"]["coverage"], "complete");
        assert_eq!(value["data"]["freshness"]["reason"], "verified");
        assert_eq!(value["data"]["freshness"]["pending_sources"], 0);
        assert_eq!(value["data"]["freshness"]["failed_sources"], 0);
        assert_eq!(value["data"]["truncation"]["truncated"], false);
        assert!(value.to_string().contains(TEXT));
    }
}

#[test]
fn latest_admitted_during_live_advisory_returns_offline_when_the_owner_is_gone() {
    for state in [UpdateState::Busy, UpdateState::Deferred] {
        for owner_gone_first in [true, false] {
            let f = Fixture::new();
            let end = Instant::now() + Duration::from_secs(20);
            let guard = lock(&f.root, LockKind::Background);
            let worker = bind_before(&f.control, &guard, end).unwrap();
            let (store, next) = f.advise_before_admission(&worker, state, end);
            drop(store);
            // The heartbeat row stays advisory; only the OS owner disappears,
            // either before the request starts or while it already waits.
            let (admitted, child) = if owner_gone_first {
                drop(worker);
                drop(guard);
                let mut child = f.spawn_latest(10_000);
                let admitted = f.await_admission(&mut child, next, 10_000, state, end);
                (admitted, child)
            } else {
                let mut child = f.spawn_latest(10_000);
                let admitted = f.await_admission(&mut child, next, 10_000, state, end);
                child.assert_waiting(Duration::from_millis(300));
                worker.validate().unwrap();
                drop(worker);
                drop(guard);
                (admitted, child)
            };
            let output = child.finish(Duration::from_secs(5));
            let worker = f.assert_single_admission(&admitted, end);
            // Returning offline is read-only: the stored row and the lost
            // owner's advisory heartbeat stay as they were.
            let stored = f.only_barrier(end, |control, barrier| control.persisted_barrier(barrier));
            assert_eq!(stored.state, BarrierState::Pending);
            assert_eq!(stored.error, None);
            assert_eq!(worker.state, state);
            assert_eq!(worker.error, Some(advisory(state)));
            let value = response(output);
            assert_eq!(value["outcome"], "partial");
            assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
            assert_eq!(value["data"]["freshness"]["reason"], "offline");
            assert!(value["meta"]["duration_ms"].as_u64().unwrap() < 10_000);
            assert!(value.to_string().contains(TEXT));
        }
    }
}

#[test]
fn latest_admitted_during_lasting_advisory_expires_at_its_original_end() {
    for (state, reason) in [
        (UpdateState::Busy, "busy"),
        (UpdateState::Deferred, "deferred"),
    ] {
        let f = Fixture::new();
        let end = Instant::now() + Duration::from_secs(20);
        let guard = lock(&f.root, LockKind::Background);
        let worker = bind_before(&f.control, &guard, end).unwrap();
        let (store, next) = f.advise_before_admission(&worker, state, end);
        drop(store);
        let mut child = f.spawn_latest(5000);
        let admitted = f.await_admission(&mut child, next, 5000, state, end);
        child.assert_waiting(Duration::from_millis(300));
        let output = child.finish(Duration::from_secs(12));
        worker.validate().unwrap();
        let after = f.assert_single_admission(&admitted, end);
        assert_eq!(after.state, state);
        let value = response(output);
        assert_eq!(value["outcome"], "partial");
        assert_eq!(value["data"]["freshness"]["latest_satisfied"], false);
        assert_eq!(value["data"]["freshness"]["reason"], reason);
        let duration = value["meta"]["duration_ms"].as_u64().unwrap();
        assert!(duration >= 5000, "returned before its wait: {duration}");
        assert!(duration < 10_000, "renewed its wait: {duration}");
        assert!(value.to_string().contains(TEXT));
    }
}
