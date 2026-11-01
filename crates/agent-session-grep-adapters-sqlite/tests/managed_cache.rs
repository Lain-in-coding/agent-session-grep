//! Synthetic private roots and real SQLite/processes only. No user histories.
use agent_session_grep_adapters_sqlite::{
    SourceBatch, SqliteControlStore,
    managed_cache::*,
    managed_locks::{ExclusiveGuard, LockKind},
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{PortError, SearchProvider, control::*, managed::*};
use rusqlite::{Connection, OpenFlags};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn id(s: &str) -> ControlId {
    ControlId::parse(s).unwrap()
}
fn entity(kind: IdKind, s: &str) -> StableId {
    StableId::native_checked(kind, s).unwrap()
}
fn seq(c: &SqliteControlStore) -> ControlSeq {
    c.status().unwrap().policy.control_seq
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
/// Fixture preparation and state reads share one end. Production calls keep
/// their own deadlines; a nested scope can only shorten one, never extend it.
const FIXTURE_BUDGET: Duration = Duration::from_secs(30);
fn acquire(root: &Path, kind: LockKind) -> ExclusiveGuard {
    let until = deadline();
    loop {
        match ExclusiveGuard::try_acquire(root, kind.clone()) {
            Ok(g) => return g,
            Err(PortError::WriterBusy(_)) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(1))
            }
            r => panic!("fixture lock: {r:?}"),
        }
    }
}
fn binding() -> CacheBinding {
    CacheBinding::new(
        "needle",
        "lexical-v1",
        &ProjectionQuery::default(),
        "none",
        "score-desc-id-asc-v1",
    )
    .unwrap()
}
struct InsertTrace<'a> {
    root: &'a Path,
    index: usize,
    now_ms: i64,
    started: Instant,
    end: Instant,
    phases: Vec<(&'static str, Duration, Instant)>,
    insert_result: Option<InsertOutcome>,
    read_result: Option<Result<(), String>>,
}
impl<'a> InsertTrace<'a> {
    fn new(root: &'a Path, index: usize, now_ms: i64, end: Instant) -> Self {
        Self {
            root,
            index,
            now_ms,
            started: Instant::now(),
            end,
            phases: Vec::with_capacity(8),
            insert_result: None,
            read_result: None,
        }
    }
    fn record(&mut self, name: &'static str) {
        self.phases.push((
            name,
            self.started.elapsed(),
            SqliteControlStore::effective_runtime_deadline(self.end + Duration::from_secs(5)),
        ));
    }
}
impl Drop for InsertTrace<'_> {
    fn drop(&mut self) {
        if matches!(&self.read_result, Some(Ok(()))) {
            return;
        }
        // Only after the operation returns or unwinds; never retry insertion
        // or let this independent read authorize the original result.
        let path = ManagedCache::path(self.root);
        let rows_after_failure = if path.exists() {
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).and_then(|conn| {
                conn.busy_timeout(Duration::ZERO)?;
                conn.query_row(
                    "SELECT count(*),coalesce(sum(size_bytes),0) FROM result_sets",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
            })
        } else {
            Ok((0, 0))
        };
        eprintln!(
            "cache insert diagnostic index={} now_ms={} end={:?} insert={:?} read={:?} post_failure_rows={:?} phases={:?}",
            self.index,
            self.now_ms,
            self.end,
            self.insert_result,
            self.read_result,
            rows_after_failure,
            self.phases,
        );
    }
}
struct Fixture {
    root: PathBuf,
    db: PathBuf,
    control: SqliteControlStore,
    worker_lock: ExclusiveGuard,
    observation: SourceObservation,
    selection: ControlId,
    end: Instant,
    insert_calls: Cell<usize>,
    // Connections and OS guards must close before Windows temp cleanup.
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let end = Instant::now() + FIXTURE_BUDGET;
        let root = temp.path().join("private");
        let db = root.join("catalog.db");
        let control =
            SqliteControlStore::create(&root, &id("cache-installation"), DesiredUpdates::Running)
                .unwrap();
        // Control preparation reads share the fixture end instead of each
        // creating its own 250ms status budget. Busy/expiry still fails.
        let (selection, worker_lock, cycle) = control
            .with_runtime_deadline(end, || {
                let selection = control
                    .add_selection(
                        seq(&control),
                        SelectionRequest {
                            region: ScopeRegion {
                                provider: SearchProvider::Claude,
                                locator: CanonicalLocator::from_path(temp.path()).unwrap(),
                                kind: RootKind::Root,
                            },
                            root_identity: Some(id("source-root")),
                            now_ms: 1,
                        },
                    )?
                    .value;
                let worker_lock = acquire(&root, LockKind::Background);
                let worker = control.bind_worker(&worker_lock, id("boot-one"))?;
                control.register_worker(seq(&control), &worker, 1, 1)?;
                let cycle = match control
                    .queue_cycle(
                        seq(&control),
                        vec![SelectionRevision {
                            selection_id: selection.id.clone(),
                            revision: selection.revision,
                            root_identity: id("source-root"),
                        }],
                    )?
                    .value
                {
                    CycleAdmission::Queued(c) => c,
                    _ => panic!("fixture cycle"),
                };
                let cycle = control
                    .start_cycle(seq(&control), &worker, cycle.token.cycle_seq, 2)?
                    .value;
                drop(worker);
                Ok((selection, worker_lock, cycle))
            })
            .unwrap();
        let observation = SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse("PRIVATE_CACHE_SOURCE").unwrap(),
                source_path: CanonicalLocator::from_path(&temp.path().join("synthetic.jsonl"))
                    .unwrap()
                    .as_str()
                    .into(),
                provider: SearchProvider::Claude,
                namespace_id: None,
                root_identity: "source-root".into(),
            },
            revision_id: RevisionId::parse("receipt-one").unwrap(),
            revision_digest: "original-digest".into(),
            parser_version: 1,
            state: ObservationState::Complete,
            cycle_seq: cycle.token.cycle_seq.get(),
            worker_boot_id: "boot-one".into(),
            catalog_incarnation: "catalog-one".into(),
            policy_epoch: cycle.policy_epoch.get(),
            started_control_seq: cycle.started_control_seq.unwrap().get(),
            observed_at_ms: 3,
            committed_at_ms: 4,
            selections: vec![SelectionProof {
                selection_id: selection.id.as_str().into(),
                selection_revision: selection.revision.get(),
                root_identity: "source-root".into(),
            }],
            repositories: vec![],
        };
        let f = Self {
            _temp: temp,
            root,
            db,
            control,
            worker_lock,
            observation,
            selection: selection.id,
            end,
            insert_calls: Cell::new(0),
        };
        f.bounded(|| {
            let store = ManagedStore::create(&f.db, &f.control, id("catalog-one"), 1).unwrap();
            let worker = f
                .control
                .bind_worker(&f.worker_lock, id("boot-one"))
                .unwrap();
            store
                .commit_source(&f.control, &worker, &f.batch(4, "needle"), &f.observation)
                .unwrap();
            drop(store);
            drop(worker);
            Ok(())
        })
        .unwrap();
        f
    }
    /// Runs fixture preparation or a state read under the one fixture end.
    fn bounded<T>(&self, operation: impl FnOnce() -> Result<T, PortError>) -> Result<T, PortError> {
        self.control.with_runtime_deadline(self.end, operation)
    }
    fn batch(&self, count: usize, text: &str) -> SourceBatch {
        let session = entity(IdKind::Session, "session");
        let document = entity(IdKind::Document, "document");
        let mut entries=vec![
            (session.clone(),serde_json::to_vec(&serde_json::json!({"documents":[document.as_str()],"title":"fixed title"})).unwrap(),String::new()),
            (document.clone(),serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":self.observation.revision_digest,"len":1000})).unwrap(),String::new()),
        ];
        let mut placements = vec![];
        for n in 0..count {
            let message = entity(IdKind::Message, &format!("message-{n}"));
            entries.push((message.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":format!("{text} {n}"),"timestamp":null})).unwrap(),format!("{text} {n}")));
            placements.push(MessagePlacement::new(
                session.clone(),
                document.clone(),
                message,
                n as u32,
                false,
                None,
            ));
        }
        SourceBatch {
            source_path: self.observation.binding.source_path.clone(),
            entries,
            placements,
            edges: vec![],
            activities: vec![],
            usage_events: vec![],
            relation_complete: true,
            len_bytes: Some(1000),
            fingerprint: Some(self.observation.revision_digest.clone()),
            provider_id: Some("claude-code".into()),
            resume_claims: vec![],
        }
    }
    fn publish(&self, count: usize, text: &str, revision: &str) {
        self.bounded(|| {
            let store = ManagedStore::open_for_write(&self.db, &self.control).unwrap();
            let worker = self
                .control
                .bind_worker(&self.worker_lock, id("boot-one"))
                .unwrap();
            let mut o = self.observation.clone();
            o.revision_id = RevisionId::parse(revision).unwrap();
            o.revision_digest = revision.into();
            let mut batch = self.batch(count, text);
            batch.fingerprint = Some(o.revision_digest.clone());
            let document = batch
                .entries
                .iter_mut()
                .find(|(id, _, _)| id.kind() == IdKind::Document)
                .unwrap();
            let mut data: serde_json::Value = serde_json::from_slice(&document.1).unwrap();
            data["fingerprint"] = serde_json::json!(o.revision_digest);
            document.1 = serde_json::to_vec(&data).unwrap();
            store
                .commit_source(&self.control, &worker, &batch, &o)
                .unwrap();
            Ok(())
        })
        .unwrap();
    }
    fn append_independent_source(&self) {
        let mut batch = self.batch(1, "new source evidence");
        let mut o = self.observation.clone();
        o.binding.source_id = SourceId::parse("second-source").unwrap();
        o.binding.source_path =
            CanonicalLocator::from_path(&self._temp.path().join("second.jsonl"))
                .unwrap()
                .as_str()
                .into();
        o.revision_id = RevisionId::parse("second-receipt").unwrap();
        batch.source_path = o.binding.source_path.clone();
        for (id, _, _) in &mut batch.entries {
            *id = entity(id.kind(), &format!("second-{}", id.as_str()));
        }
        let message = batch
            .entries
            .iter()
            .find(|(id, _, _)| id.kind() == IdKind::Message)
            .unwrap()
            .0
            .clone();
        let session = batch
            .entries
            .iter()
            .find(|(id, _, _)| id.kind() == IdKind::Session)
            .unwrap()
            .0
            .clone();
        let document = batch
            .entries
            .iter()
            .find(|(id, _, _)| id.kind() == IdKind::Document)
            .unwrap()
            .0
            .clone();
        batch
            .entries
            .iter_mut()
            .find(|(id, _, _)| id.kind() == IdKind::Session)
            .unwrap()
            .1 = serde_json::to_vec(
            &serde_json::json!({"documents":[document.as_str()],"title":"new session"}),
        )
        .unwrap();
        batch.placements = vec![MessagePlacement::new(
            session, document, message, 0, false, None,
        )];
        self.bounded(|| {
            let store = ManagedStore::open_for_write(&self.db, &self.control).unwrap();
            let worker = self
                .control
                .bind_worker(&self.worker_lock, id("boot-one"))
                .unwrap();
            let committed = store
                .commit_source(&self.control, &worker, &batch, &o)
                .unwrap();
            assert!(!committed.destructive);
            Ok(())
        })
        .unwrap();
    }
    fn candidates(read: &impl ProjectionRead) -> Vec<CacheCandidate> {
        let mut rows = read
            .list(&ProjectionQuery::default(), false, 512)
            .unwrap()
            .entries;
        rows.retain(|r| r.id().kind() == IdKind::Message);
        rows.reverse();
        rows.into_iter()
            .enumerate()
            .map(|(n, entry)| CacheCandidate {
                entry,
                score: 100.0 - n as f64,
            })
            .collect()
    }
    fn insert(&self, now: i64) -> CacheCursor {
        let end = deadline();
        let probe = end + Duration::from_secs(5);
        let previous = SqliteControlStore::effective_runtime_deadline(probe);
        let expected = SqliteControlStore::effective_runtime_deadline(end);
        let index = self.insert_calls.get() + 1;
        self.insert_calls.set(index);
        let mut trace = InsertTrace::new(&self.root, index, now, end);
        let mut operation = || {
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                expected
            );
            trace.record("cache_at");
            let cache = ManagedCache::at(&self.root, &self.control).unwrap();
            trace.record("store_open");
            let store = ManagedStore::open(&self.db, &self.control).unwrap();
            trace.record("with_read");
            let result = store.with_read(&self.control, RequestIntersection::Selected, end, |r| {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(probe),
                    expected
                );
                trace.record("callback");
                let binding = binding();
                let candidates = Self::candidates(r);
                trace.record("candidates");
                let request = CacheInsert {
                    binding: &binding,
                    candidates: &candidates,
                    next_offset: 1,
                    truncated: true,
                    now_ms: now,
                    deadline: end,
                };
                assert_eq!(request.deadline, end);
                trace.record("insert");
                let outcome = cache.insert(&self.control, r, request);
                trace.record("insert_return");
                trace.insert_result = Some(outcome.clone());
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(probe),
                    expected
                );
                Ok(match outcome {
                    InsertOutcome::Stored(c) => c,
                    other => panic!("insert: {other:?}"),
                })
            });
            trace.record("with_read_return");
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                expected
            );
            result
        };
        let result = self.control.with_runtime_deadline(end, &mut operation);
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            previous
        );
        trace.record("request_return");
        trace.read_result = Some(
            result
                .as_ref()
                .map(|_| ())
                .map_err(|error| format!("{error:?}")),
        );
        result.unwrap()
    }
    fn page(&self, cursor: &str, now: i64) -> std::result::Result<CachePage, CacheError> {
        let end = deadline();
        let probe = end + Duration::from_secs(5);
        let previous = SqliteControlStore::effective_runtime_deadline(probe);
        let expected = SqliteControlStore::effective_runtime_deadline(end);
        let result = self.control.with_runtime_deadline(end, || {
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                expected
            );
            let cache = ManagedCache::at(&self.root, &self.control).unwrap();
            let store = ManagedStore::open(&self.db, &self.control).unwrap();
            let result = store.with_read(&self.control, RequestIntersection::Selected, end, |r| {
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(probe),
                    expected
                );
                let request = CachePageRequest {
                    binding: &binding(),
                    cursor,
                    limit: 2,
                    now_ms: now,
                    deadline: end,
                };
                assert_eq!(request.deadline, end);
                let page = cache.page(&self.control, r, request);
                assert_eq!(
                    SqliteControlStore::effective_runtime_deadline(probe),
                    expected
                );
                Ok(page)
            });
            assert_eq!(
                SqliteControlStore::effective_runtime_deadline(probe),
                expected
            );
            result
        });
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe),
            previous
        );
        result.unwrap()
    }
    fn scalar(&self, sql: &str) -> i64 {
        Connection::open(ManagedCache::path(&self.root))
            .unwrap()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    }
}

#[test]
fn fixture_cache_requests_restore_a_later_outer_scope() {
    let f = Fixture::new();
    let outer = Instant::now() + Duration::from_secs(10);
    let probe = outer + Duration::from_secs(5);
    f.control
        .with_runtime_deadline(outer, || {
            let cursor = f.insert(100);
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            let page = f.page(cursor.as_str(), 101).unwrap();
            assert_eq!(page.candidates.len(), 2);
            assert_eq!(f.insert_calls.get(), 1);
            assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), outer);
            Ok(())
        })
        .unwrap();
    assert_eq!(SqliteControlStore::effective_runtime_deadline(probe), probe);
    assert_eq!(f.scalar("SELECT count(*) FROM result_sets"), 1);
}

#[test]
fn cross_process_page_child() {
    let Some(root) = std::env::var_os("ASG_SYNTHETIC_CACHE_CHILD_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let cursor = std::env::var("ASG_SYNTHETIC_CACHE_CHILD_CURSOR").unwrap();
    let control = SqliteControlStore::open_current_read_only(&root).unwrap();
    let store = ManagedStore::open(&root.join("catalog.db"), &control).unwrap();
    let cache = ManagedCache::at(&root, &control).unwrap();
    let page = store
        .with_read(
            &control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                Ok(cache.page(
                    &control,
                    read,
                    CachePageRequest {
                        binding: &binding(),
                        cursor: &cursor,
                        limit: 2,
                        now_ms: 101,
                        deadline: deadline(),
                    },
                ))
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        page.candidates
            .iter()
            .map(|c| c.entry.id().as_str())
            .collect::<Vec<_>>(),
        ["msg_v1_message-2", "msg_v1_message-1"]
    );
    assert_eq!(page.as_of.generation, 1);
    assert!(page.truncated);
    assert!(page.next_cursor.is_some());
}

#[test]
fn two_processes_keep_exact_order_as_of_proof_and_append_validity() {
    let f = Fixture::new();
    let cursor = f.insert(100);
    let saved = f.page(cursor.as_str(), 100).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cross_process_page_child", "--nocapture"])
        .env("ASG_SYNTHETIC_CACHE_CHILD_ROOT", &f.root)
        .env("ASG_SYNTHETIC_CACHE_CHILD_CURSOR", cursor.as_str())
        .status()
        .unwrap();
    assert!(status.success());
    f.append_independent_source();
    let appended = f.page(cursor.as_str(), 102).unwrap();
    assert_eq!(saved.candidates, appended.candidates);
    assert_eq!(saved.as_of, appended.as_of);
    // Returned page and cache object own no DB handle, transaction or lease.
    let drain = acquire(&f.root, LockKind::CatalogHandles);
    drop(drain);
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let emission = acquire(&f.root, LockKind::PolicyEmission);
    let purged = cache.purge_all(&f.control, &emission, deadline()).unwrap();
    assert!(purged.wal_drained);
    assert_eq!(purged.sets_removed, 1);
    drop(emission);
    assert_eq!(appended.candidates, saved.candidates);
    assert!(matches!(
        f.page(cursor.as_str(), 103),
        Err(CacheError::CursorExpired)
    ));
}

#[test]
fn rewrite_revoke_and_incarnation_change_invalidate_without_generation_equality() {
    let f = Fixture::new();
    let token = f.insert(100);
    f.publish(4, "rewritten", "rewrite-receipt");
    assert!(matches!(
        f.page(token.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
    let token = f.insert(102);
    let owner = acquire(&f.root, LockKind::PolicyOwner);
    let denied = f
        .bounded(|| {
            f.control
                .revoke_selection(seq(&f.control), &f.selection, None, 103)
        })
        .unwrap();
    let drain = acquire(&f.root, LockKind::PolicyEmission);
    f.bounded(|| {
        f.control.settle_revocation(
            denied.control_seq,
            &owner,
            &drain,
            &denied.value.intent.id,
            104,
        )
    })
    .unwrap();
    drop(drain);
    drop(owner);
    assert!(matches!(
        f.page(token.as_str(), 105),
        Err(CacheError::CursorExpired)
    ));
    let f = Fixture::new();
    let token = f.insert(100);
    let conn = Connection::open(&f.db).unwrap();
    conn.execute_batch("UPDATE catalog_meta SET catalog_incarnation='restored-catalog';")
        .unwrap();
    drop(conn);
    assert!(matches!(
        f.page(token.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
}

#[test]
fn ttl_clock_rollback_binding_and_token_tampering_fail_closed() {
    let f = Fixture::new();
    let token = f.insert(100);
    assert!(matches!(
        f.page("legacy.cursor", 101),
        Err(CacheError::CursorInvalid)
    ));
    let changed = token.as_str().replace(".1.", ".2.");
    assert!(matches!(
        f.page(&changed, 101),
        Err(CacheError::CursorInvalid)
    ));
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let model = CacheBinding::new(
        "needle",
        "other-model",
        &ProjectionQuery::default(),
        "none",
        "score-desc-id-asc-v1",
    )
    .unwrap();
    assert!(matches!(
        store
            .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
                Ok(cache.page(
                    &f.control,
                    r,
                    CachePageRequest {
                        binding: &model,
                        cursor: token.as_str(),
                        limit: 1,
                        now_ms: 102,
                        deadline: deadline(),
                    },
                ))
            })
            .unwrap(),
        Err(CacheError::CursorExpired)
    ));
    let query = CacheBinding::new(
        "different",
        "lexical-v1",
        &ProjectionQuery::default(),
        "none",
        "score-desc-id-asc-v1",
    )
    .unwrap();
    assert!(matches!(
        store
            .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
                Ok(cache.page(
                    &f.control,
                    r,
                    CachePageRequest {
                        binding: &query,
                        cursor: token.as_str(),
                        limit: 1,
                        now_ms: 102,
                        deadline: deadline(),
                    },
                ))
            })
            .unwrap(),
        Err(CacheError::CursorInvalid)
    ));
    assert!(matches!(
        f.page(token.as_str(), 99),
        Err(CacheError::CursorExpired)
    ));
    assert_eq!(f.scalar("SELECT count(*) FROM result_sets"), 0);
    let token = f.insert(200);
    assert!(matches!(
        f.page(token.as_str(), 200 + TTL_MS),
        Err(CacheError::CursorExpired)
    ));
}

#[test]
fn busy_missing_corrupt_and_oversize_cache_do_not_fail_one_shot_result() {
    let f = Fixture::new();
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    assert!(!ManagedCache::path(&f.root).exists());
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    store
        .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
            let mut candidates = Fixture::candidates(r);
            let original = candidates.clone();
            if let ProjectionListEntry::Message(p) = &mut candidates[0].entry {
                p.message.text = "x".repeat(MAX_SET_BYTES);
            }
            assert!(matches!(
                cache.insert(
                    &f.control,
                    r,
                    CacheInsert {
                        binding: &binding(),
                        candidates: &candidates,
                        next_offset: 1,
                        truncated: false,
                        now_ms: 100,
                        deadline: deadline()
                    }
                ),
                InsertOutcome::Unavailable(CacheUnavailable::Oversized)
            ));
            assert_eq!(Fixture::candidates(r), original);
            assert!(!ManagedCache::path(&f.root).exists());
            Ok(())
        })
        .unwrap();
    let token = f.insert(100);
    let conn = Connection::open(ManagedCache::path(&f.root)).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    store
        .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
            assert!(matches!(
                cache.insert(
                    &f.control,
                    r,
                    CacheInsert {
                        binding: &binding(),
                        candidates: &Fixture::candidates(r),
                        next_offset: 1,
                        truncated: false,
                        now_ms: 101,
                        deadline: deadline()
                    }
                ),
                InsertOutcome::Unavailable(CacheUnavailable::Busy)
            ));
            Ok(())
        })
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        f.page(token.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
    conn.execute_batch("ROLLBACK; UPDATE result_sets SET result_payload=x'7b7d';")
        .unwrap();
    drop(conn);
    assert!(matches!(
        f.page(token.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
    assert_eq!(Fixture::candidates_from_store(&f).len(), 4);
}
impl Fixture {
    fn candidates_from_store(f: &Self) -> Vec<CacheCandidate> {
        ManagedStore::open(&f.db, &f.control)
            .unwrap()
            .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
                Ok(Self::candidates(r))
            })
            .unwrap()
    }
}

#[test]
fn eviction_is_oldest_then_cache_id_and_cache_does_not_pin_catalog() {
    let f = Fixture::new();
    let first = f.insert(100);
    for n in 1..=64 {
        f.insert(100 + n);
    }
    assert_eq!(f.scalar("SELECT count(*) FROM result_sets"), 64);
    assert!(matches!(
        f.page(first.as_str(), 165),
        Err(CacheError::CursorExpired)
    ));
    let conn = Connection::open(ManagedCache::path(&f.root)).unwrap();
    let orphan:i64=conn.query_row("SELECT count(*) FROM result_sources WHERE cache_id NOT IN(SELECT cache_id FROM result_sets)",[],|r|r.get(0)).unwrap();
    assert_eq!(orphan, 0);
    drop(conn);
    drop(acquire(&f.root, LockKind::CatalogHandles));
}

#[test]
fn corrupt_schema_and_initial_empty_file_are_not_reset() {
    let f = Fixture::new();
    let path = ManagedCache::path(&f.root);
    std::fs::write(&path, []).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    let attempt = || {
        store
            .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
                Ok(cache.insert(
                    &f.control,
                    r,
                    CacheInsert {
                        binding: &binding(),
                        candidates: &Fixture::candidates(r),
                        next_offset: 1,
                        truncated: false,
                        now_ms: 100,
                        deadline: deadline(),
                    },
                ))
            })
            .unwrap()
    };
    assert!(matches!(attempt(), InsertOutcome::Unavailable(_)));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    // Explicit test recovery only; production never overwrites an unknown file.
    std::fs::remove_file(&path).unwrap();
    let _ = f.insert(100);
    let conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 999).unwrap();
    drop(conn);
    assert!(matches!(
        attempt(),
        InsertOutcome::Unavailable(CacheUnavailable::Corrupt)
    ));
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        999
    );
}

#[test]
fn malformed_enum_range_or_source_manifest_is_expired_not_an_empty_page() {
    for mutation in 0..3 {
        let f = Fixture::new();
        let cursor = f.insert(100);
        let conn = Connection::open(ManagedCache::path(&f.root)).unwrap();
        match mutation {
            0 => {
                let bytes: Vec<u8> = conn
                    .query_row("SELECT result_payload FROM result_sets", [], |r| r.get(0))
                    .unwrap();
                let mut data: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
                data["candidates"][0]["entry"]["message"]["role"] =
                    serde_json::json!("unknown_role");
                let json = serde_json::to_vec(&data).unwrap();
                let mut changed = blake3::hash(&json).as_bytes().to_vec();
                changed.extend(json);
                conn.execute("UPDATE result_sets SET result_payload=?1", [changed])
                    .unwrap();
            }
            1 => {
                conn.execute_batch(
                    "PRAGMA ignore_check_constraints=ON; UPDATE result_sets SET generation=-1;",
                )
                .unwrap();
            }
            _ => {
                conn.execute("DELETE FROM result_sources", []).unwrap();
            }
        }
        drop(conn);
        assert!(matches!(
            f.page(cursor.as_str(), 101),
            Err(CacheError::CursorExpired)
        ));
    }
}

#[test]
fn emission_drain_blocks_cache_insertion_and_pause_preserves_pages() {
    let f = Fixture::new();
    let cursor = f.insert(100);
    f.bounded(|| {
        f.control
            .set_desired_updates(seq(&f.control), DesiredUpdates::Paused)
    })
    .unwrap();
    assert!(f.page(cursor.as_str(), 101).is_ok());
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let drain = acquire(&f.root, LockKind::PolicyEmission);
    store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                assert!(matches!(
                    cache.insert(
                        &f.control,
                        read,
                        CacheInsert {
                            binding: &binding(),
                            candidates: &Fixture::candidates(read),
                            next_offset: 1,
                            truncated: false,
                            now_ms: 102,
                            deadline: deadline()
                        }
                    ),
                    InsertOutcome::Unavailable(CacheUnavailable::Busy)
                ));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(f.scalar("SELECT count(*) FROM result_sets"), 1);
    drop(drain);
    let wrong = acquire(&f.root, LockKind::PolicyOwner);
    assert!(matches!(
        cache.purge_all(&f.control, &wrong, deadline()),
        Err(CacheError::Unavailable(CacheUnavailable::PolicyChanged))
    ));
}

#[test]
fn equal_time_eviction_uses_cache_id_and_total_encoded_bytes_stay_bounded() {
    let f = Fixture::new();
    for _ in 0..64 {
        f.insert(100);
    }
    let conn = Connection::open(ManagedCache::path(&f.root)).unwrap();
    let oldest: String = conn
        .query_row(
            "SELECT cache_id FROM result_sets ORDER BY created_at_ms,cache_id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);
    f.insert(100);
    let conn = Connection::open(ManagedCache::path(&f.root)).unwrap();
    assert_eq!(
        conn.query_row::<i64, _, _>(
            "SELECT count(*) FROM result_sets WHERE cache_id=?1",
            [oldest],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    drop(conn);
    assert!(f.scalar("SELECT sum(size_bytes) FROM result_sets") <= MAX_TOTAL_BYTES as i64);
    assert_eq!(
        f.scalar("SELECT count(*) FROM result_sets"),
        MAX_SETS as i64
    );
}

#[test]
fn absent_cache_and_deadline_create_nothing_and_debug_is_content_free() {
    let f = Fixture::new();
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let cursor = format!("asgmc1.{}.1.1000.{}", "0".repeat(32), "0".repeat(64));
    assert!(matches!(
        f.page(&cursor, 100),
        Err(CacheError::CursorExpired)
    ));
    assert!(!ManagedCache::path(&f.root).exists());
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                let candidates = Fixture::candidates(read);
                let b = binding();
                assert!(!format!("{candidates:?} {b:?}").contains("needle"));
                assert!(matches!(
                    cache.insert(
                        &f.control,
                        read,
                        CacheInsert {
                            binding: &b,
                            candidates: &candidates,
                            next_offset: 1,
                            truncated: false,
                            now_ms: 100,
                            deadline: Instant::now()
                        }
                    ),
                    InsertOutcome::Unavailable(CacheUnavailable::Deadline)
                ));
                Ok(())
            },
        )
        .unwrap();
    assert!(!ManagedCache::path(&f.root).exists());
}

#[cfg(unix)]
#[test]
fn unix_private_modes_and_unwritable_cache_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let cursor = f.insert(100);
    let path = ManagedCache::path(&f.root);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(matches!(
        f.page(cursor.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        f.page(cursor.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
}

#[cfg(windows)]
#[test]
fn windows_readonly_cache_is_one_shot_unavailable() {
    let f = Fixture::new();
    let cursor = f.insert(100);
    let path = ManagedCache::path(&f.root);
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).unwrap();
    assert!(matches!(
        f.page(cursor.as_str(), 101),
        Err(CacheError::CursorExpired)
    ));
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                assert!(matches!(
                    cache.insert(
                        &f.control,
                        read,
                        CacheInsert {
                            binding: &binding(),
                            candidates: &Fixture::candidates(read),
                            next_offset: 1,
                            truncated: false,
                            now_ms: 102,
                            deadline: deadline()
                        }
                    ),
                    InsertOutcome::Unavailable(_)
                ));
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn encoded_total_cap_evicts_before_set_count_cap() {
    let f = Fixture::new();
    f.publish(
        4,
        &"large-safe-synthetic-text ".repeat(27_000),
        "large-receipt",
    );
    let first = f.insert(100);
    for n in 1..=28 {
        f.insert(100 + n);
    }
    let sets = f.scalar("SELECT count(*) FROM result_sets");
    assert!(
        sets < 29 && sets > 1,
        "byte cap must evict before the 64-set cap: {sets}"
    );
    assert!(f.scalar("SELECT sum(size_bytes) FROM result_sets") <= MAX_TOTAL_BYTES as i64);
    assert!(matches!(
        f.page(first.as_str(), 130),
        Err(CacheError::CursorExpired)
    ));
}

#[test]
fn page_copy_survives_concurrent_eviction_in_another_process() {
    let f = Fixture::new();
    let cursor = f.insert(100);
    let copied = f.page(cursor.as_str(), 100).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cross_process_page_child", "--nocapture"])
        .env("ASG_SYNTHETIC_CACHE_CHILD_ROOT", &f.root)
        .env("ASG_SYNTHETIC_CACHE_CHILD_CURSOR", cursor.as_str())
        .spawn()
        .unwrap();
    let result = child.wait().unwrap();
    assert!(result.success());
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let drain = acquire(&f.root, LockKind::PolicyEmission);
    assert_eq!(
        cache
            .purge_all(&f.control, &drain, deadline())
            .unwrap()
            .sets_removed,
        1
    );
    drop(drain);
    assert_eq!(copied.candidates.len(), 2);
    assert!(matches!(
        f.page(cursor.as_str(), 102),
        Err(CacheError::CursorExpired)
    ));
}

#[test]
fn explicit_scope_cannot_insert_or_read_an_authorized_cache() {
    use agent_session_grep_adapters_sqlite::managed::ManagedRead;
    let f = Fixture::new();
    let cursor = f.insert(100);
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let conn = Connection::open(&f.db).unwrap();
    let scope = ReadScope {
        catalog_incarnation: "catalog-one".into(),
        policy_epoch: f
            .bounded(|| f.control.status())
            .unwrap()
            .policy
            .policy_epoch
            .get(),
        allowed: vec![f.observation.binding.clone()],
    };
    let read = ManagedRead::begin(&conn, &scope, deadline()).unwrap();
    let candidates = Fixture::candidates(&read);
    assert!(matches!(
        cache.insert(
            &f.control,
            &read,
            CacheInsert {
                binding: &binding(),
                candidates: &candidates,
                next_offset: 1,
                truncated: false,
                now_ms: 101,
                deadline: deadline()
            }
        ),
        InsertOutcome::Unavailable(CacheUnavailable::PolicyChanged)
    ));
    assert!(matches!(
        cache.page(
            &f.control,
            &read,
            CachePageRequest {
                binding: &binding(),
                cursor: cursor.as_str(),
                limit: 1,
                now_ms: 101,
                deadline: deadline()
            }
        ),
        Err(CacheError::CursorExpired)
    ));
    assert_eq!(f.scalar("SELECT count(*) FROM result_sets"), 1);
}

#[test]
fn whole_app_set_preserves_frozen_hits_proofs_partial_and_actual_offsets() {
    use agent_session_grep_application::{
        AppRequest, ResponseBudget,
        managed::{ManagedApp, ManagedRequestContext},
    };
    use agent_session_grep_ports::{RetrievalMode, SearchFacets, SearchFilters};
    let f = Fixture::new();
    let cache = ManagedCache::at(&f.root, &f.control).unwrap();
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    let expired = || false;
    let (original, cursor) = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                let budget = ResponseBudget::default();
                let app = ManagedApp::new(
                    read,
                    ManagedRequestContext {
                        intersection: ProjectionQuery::default(),
                        budget: budget.clone(),
                        now_ms: 321,
                        current_repo: None,
                        deadline_expired: &expired,
                    },
                )
                .unwrap();
                let set = app
                    .collect_candidates(AppRequest::Search {
                        query: "needle".into(),
                        filters: SearchFilters::default(),
                        facets: SearchFacets::default(),
                        limit: 1,
                        cursor: None,
                        budget,
                        include_system: false,
                        group_by_session: false,
                        mode: RetrievalMode::Lexical,
                        query_embedding: None,
                    })
                    .unwrap();
                let message_ids = set
                    .candidates
                    .iter()
                    .filter_map(|c| match &c.entry {
                        ProjectionListEntry::Message(p) => Some(p.message.id.as_str().to_owned()),
                        _ => None,
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(
                    message_ids,
                    (0..4).map(|n| format!("msg_v1_message-{n}")).collect()
                );
                let metadata = set
                    .candidates
                    .iter()
                    .filter(|c| matches!(c.entry, ProjectionListEntry::Entity(_)))
                    .collect::<Vec<_>>();
                let [candidate] = metadata.as_slice() else {
                    panic!("expected one Session metadata candidate");
                };
                let ProjectionListEntry::Entity(projection) = &candidate.entry else {
                    unreachable!()
                };
                let EntityData::Session(session) = &projection.data else {
                    panic!("Document must not enter search");
                };
                assert_eq!(session.session.id, entity(IdKind::Session, "session"));
                assert_eq!(session.title.as_deref(), Some("fixed title"));
                assert_eq!(session.first_user_text.as_deref(), Some("needle 0"));
                let hit = candidate.hit.as_ref().unwrap();
                assert_eq!(hit.id, session.session.id);
                assert!(
                    hit.text.is_none(),
                    "Session field match must not borrow a Message snippet"
                );
                assert_eq!(hit.why_matched, ["session_metadata", "session_first_user"]);
                assert_eq!(candidate.evidence.len(), 1);
                let evidence = &candidate.evidence[0];
                assert_eq!(evidence.entity_id, session.session.id);
                assert_eq!(evidence.proof, projection.proof);
                assert_eq!(evidence.proof.source_id, f.observation.binding.source_id);
                assert_eq!(
                    evidence.proof.revision.digest,
                    f.observation.revision_digest
                );
                assert!(evidence.occurrence.is_none());
                assert!(evidence.related.is_empty());
                assert_eq!(set.candidates.len(), message_ids.len() + metadata.len());
                let cursor = match cache.insert_set(
                    &f.control,
                    read,
                    CacheSetInsert {
                        binding: &binding(),
                        set: &set,
                        next_offset: 1,
                        now_ms: 1000,
                        deadline: deadline(),
                    },
                ) {
                    InsertOutcome::Stored(c) => c,
                    other => panic!("set insert {other:?}"),
                };
                Ok((set, cursor))
            },
        )
        .unwrap();
    drop(store);
    f.append_independent_source();
    let store = ManagedStore::open(&f.db, &f.control).unwrap();
    let cached = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                Ok(cache.load_set(
                    &f.control,
                    read,
                    CachePageRequest {
                        binding: &binding(),
                        cursor: cursor.as_str(),
                        limit: 512,
                        now_ms: 1001,
                        deadline: deadline(),
                    },
                ))
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(cached.set, original);
    assert_eq!(cached.continuation.offset(), 1);
    assert!(cached.continuation.cursor_after(0).is_err());
    let next = cached.continuation.cursor_after(1).unwrap().unwrap();
    let loaded = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                Ok(cache.load_set(
                    &f.control,
                    read,
                    CachePageRequest {
                        binding: &binding(),
                        cursor: next.as_str(),
                        limit: 512,
                        now_ms: 1002,
                        deadline: deadline(),
                    },
                ))
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(loaded.continuation.offset(), 2);
    assert_eq!(loaded.set, original);
}
