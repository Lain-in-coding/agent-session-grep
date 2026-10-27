//! Synthetic private SQLite catalogs only; no provider history or native host.
use agent_session_grep_adapters_sqlite::{
    SCHEMA_VERSION, SourceBatch, SqliteControlStore, managed,
    managed_history::{
        CycleRetention, HistoryDependencies, HistoryLimits, HistoryPrune, prune_in_tx,
    },
    managed_locks::{ExclusiveGuard, LockKind, SharedGuard},
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{
    PortError, SearchProvider,
    control::{ControlId, CycleSeq, DesiredUpdates},
    managed::{
        ObservationState, ProjectionQuery, ProjectionRead, ReadScope, ReadSnapshot, RevisionId,
        SelectionProof, SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::{Connection, TransactionBehavior, params};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn revision(value: &str) -> RevisionId {
    RevisionId::parse(value).unwrap()
}
fn entity(kind: IdKind, suffix: &str) -> StableId {
    StableId::native_checked(kind, suffix).unwrap()
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    catalog: PathBuf,
    conn: Connection,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private-catalog");
        let catalog = root.join("catalog.db");
        let control =
            SqliteControlStore::create(&root, &id("history-installation"), DesiredUpdates::Paused)
                .unwrap();
        drop(ManagedStore::create(&catalog, &control, id("history-catalog"), 1).unwrap());
        drop(control);
        let conn = Connection::open(&catalog).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
            .unwrap();
        Self {
            _temp: temp,
            root,
            catalog,
            conn,
        }
    }
    fn binding(&self, source: &str) -> SourceBinding {
        SourceBinding {
            source_id: SourceId::parse(source).unwrap(),
            source_path: self
                ._temp
                .path()
                .join(format!("{source}.jsonl"))
                .to_str()
                .unwrap()
                .into(),
            provider: SearchProvider::Claude,
            namespace_id: None,
            root_identity: "synthetic-source-root".into(),
        }
    }
    fn publish(&mut self, source: &str, rev: &str, cycle: i64, boot: &str, text: &str) {
        self.observe(source, rev, cycle, boot, text, ObservationState::Complete);
    }
    fn observe(
        &mut self,
        source: &str,
        rev: &str,
        cycle: i64,
        boot: &str,
        text: &str,
        state: ObservationState,
    ) {
        let message = entity(IdKind::Message, source);
        let session = entity(IdKind::Session, source);
        // A rewritten snapshot has a new original document/fingerprint while
        // canonical message/session identities remain stable. Identical text
        // keeps the same document, exercising a true no-op observation.
        let fingerprint = blake3::hash(text.as_bytes()).to_hex().to_string();
        let document = entity(
            IdKind::Document,
            &format!("{source}-{}", &fingerprint[..12]),
        );
        let binding = self.binding(source);
        let batch = SourceBatch {
            source_path:binding.source_path.clone(),
            entries:vec![
                (message.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":null})).unwrap(),text.into()),
                (session.clone(),serde_json::to_vec(&serde_json::json!({"documents":[document.as_str()]})).unwrap(),String::new()),
                (document.clone(),serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":fingerprint,"len":100})).unwrap(),String::new()),
            ],
            placements:vec![MessagePlacement::new(session,document,message,0,false,None)],
            edges:Vec::new(),activities:Vec::new(),usage_events:Vec::new(),relation_complete:true,len_bytes:Some(100),fingerprint:Some(fingerprint.clone()),provider_id:Some("claude-code".into()),resume_claims:Vec::new(),
        };
        let observation = SourceObservation {
            binding,
            revision_id: revision(rev),
            revision_digest: fingerprint,
            parser_version: 1,
            state,
            cycle_seq: cycle,
            worker_boot_id: boot.into(),
            catalog_incarnation: "history-catalog".into(),
            policy_epoch: 0,
            started_control_seq: cycle,
            observed_at_ms: cycle,
            committed_at_ms: cycle,
            selections: vec![SelectionProof {
                selection_id: "selection-one".into(),
                selection_revision: 1,
                root_identity: "synthetic-source-root".into(),
            }],
            repositories: Vec::new(),
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let generation: i64 = tx
            .query_row("SELECT active_generation FROM store_metadata", [], |row| {
                row.get(0)
            })
            .unwrap();
        let publication =
            managed::publish_source_in_tx(&tx, &batch, &observation, generation + 1).unwrap();
        tx.execute(
            "UPDATE store_metadata SET active_generation=?1",
            [publication.required_generation],
        )
        .unwrap();
        managed::finalize_publications_in_tx(&tx, &mut [publication]).unwrap();
        tx.commit().unwrap();
    }
    fn discovery(&self, cycle: i64, boot: &str, source_revision: Option<(&str, &str)>) {
        let (complete, sources) = source_revision.map_or((false, Vec::new()), |(source, rev)| {
            (true, vec![(source.to_string(), rev.to_string())])
        });
        self.discovery_for(cycle, boot, "selection-one", complete, &sources);
    }
    fn discovery_for(
        &self,
        cycle: i64,
        boot: &str,
        selection: &str,
        complete: bool,
        sources: &[(String, String)],
    ) {
        let mut sorted = sources.to_vec();
        sorted.sort();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"asg-discovery-source-set-v1");
        for (source, rev) in &sorted {
            for value in [source, rev] {
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
            }
        }
        self.conn.execute("INSERT INTO discovery_receipts VALUES(?1,?2,1,?3,0,?1,'history-catalog','synthetic-source-root',?4,?5,?6)",params![cycle,selection,boot,hasher.finalize().to_hex().to_string(),complete,self.scalar("SELECT active_generation FROM store_metadata")]).unwrap();
        for (source, rev) in sources {
            self.conn
                .execute(
                    "INSERT INTO discovery_sources VALUES(?1,?2,?3,?4)",
                    params![cycle, selection, source, rev],
                )
                .unwrap();
        }
    }
    fn dependencies(&self) -> HistoryDependencies {
        HistoryDependencies {
            installation_id: id("history-installation"),
            snapshot: ReadSnapshot {
                catalog_incarnation: "history-catalog".into(),
                generation: self.scalar("SELECT active_generation FROM store_metadata"),
                destructive_epoch: self.scalar("SELECT destructive_epoch FROM store_metadata"),
                policy_epoch: 0,
            },
            keep_cycles: Vec::new(),
            keep_receipts: Vec::new(),
        }
    }
    fn scalar(&self, query: &str) -> i64 {
        self.conn.query_row(query, [], |row| row.get(0)).unwrap()
    }
    fn receipts(&self) -> Vec<String> {
        self.conn
            .prepare("SELECT revision_id FROM source_revision_receipts ORDER BY revision_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }
    fn prunes(
        &mut self,
        deps: &HistoryDependencies,
        cache: &[RevisionId],
        limits: HistoryLimits,
    ) -> Result<HistoryPrune, PortError> {
        self.prunes_until(deps, cache, limits, deadline())
    }
    fn prunes_until(
        &mut self,
        deps: &HistoryDependencies,
        cache: &[RevisionId],
        limits: HistoryLimits,
        end: Instant,
    ) -> Result<HistoryPrune, PortError> {
        let guard = ExclusiveGuard::try_acquire(&self.root, LockKind::HistoryReaders).unwrap();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let result = prune_in_tx(&tx, deps, cache, limits, end);
        // Commit even errors to prove the module's savepoint removed partial GC.
        tx.commit().unwrap();
        drop(guard);
        result
    }
    fn text(&self, source: &str) -> Vec<String> {
        let incarnation: String = self
            .conn
            .query_row("SELECT catalog_incarnation FROM catalog_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        let read = managed::ManagedRead::begin(
            &self.conn,
            &ReadScope {
                catalog_incarnation: incarnation,
                policy_epoch: 0,
                allowed: vec![self.binding(source)],
            },
            deadline(),
        )
        .unwrap();
        read.query_lexical("proof", &ProjectionQuery::default(), 5)
            .unwrap()
            .hits
            .into_iter()
            .map(|hit| hit.projection.message.text)
            .collect()
    }
    fn evidence_rows(&self) -> Vec<(String, String, String, Vec<u8>)> {
        self.conn.prepare("SELECT projection_id,revision_id,payload_digest,payload FROM source_projections ORDER BY projection_id").unwrap().query_map([],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }
}

#[test]
fn defaults_are_finite_and_retain_revision_allocation_high_watermark() {
    let limits = HistoryLimits::default();
    assert_eq!(limits.receipt_tail_per_source, 2);
    assert_eq!(limits.discovery_tail_per_selection, 1);
    assert_eq!(limits.batch_rows, 64);
    assert_eq!(limits.max_dependencies, 16_384);
    assert_eq!(limits.max_cycle_tokens, 16_384);
    let mut f = Fixture::new();
    for n in 1..=8 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
    }
    let deps = f.dependencies();
    let evidence = f.evidence_rows();
    let before = f.text("source-one");
    let pruned = f.prunes(&deps, &[], limits).unwrap();
    assert_eq!(pruned.counts.receipts_deleted, 5);
    assert_eq!(pruned.counts.receipt_claims_deleted, 5);
    assert!(!pruned.has_more);
    assert_eq!(f.receipts(), vec!["revision-1", "revision-7", "revision-8"]);
    assert_eq!(f.evidence_rows(), evidence);
    assert_eq!(f.text("source-one"), before);
    assert_eq!(f.dependencies().snapshot, deps.snapshot);
    f.publish("source-one", "revision-9", 9, "boot-new", "original proof");
    assert_eq!(
        f.scalar(
            "SELECT revision_seq FROM source_revision_receipts WHERE revision_id='revision-9'"
        ),
        9
    );
}

#[test]
fn latest_incomplete_discovery_supersedes_old_complete_without_fabricating_freshness() {
    let mut f = Fixture::new();
    f.publish("source-one", "revision-1", 1, "boot-old", "original proof");
    f.discovery(1, "boot-old", Some(("source-one", "revision-1")));
    for n in 2..=4 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
        f.discovery(
            n,
            "boot-old",
            Some(("source-one", &format!("revision-{n}"))),
        );
    }
    f.discovery(5, "boot-new", None);
    let deps = f.dependencies();
    let result = f.prunes(&deps, &[], HistoryLimits::default()).unwrap();
    assert_eq!(result.counts.discoveries_deleted, 4);
    assert_eq!(result.counts.discovery_sources_deleted, 4);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM discovery_receipts"), 1);
    assert_eq!(f.scalar("SELECT complete FROM discovery_receipts"), 0);
    assert_eq!(f.scalar("SELECT cycle_seq FROM discovery_receipts"), 5);
    assert_eq!(f.text("source-one"), vec!["original proof"]);
    let CycleRetention::Complete(tokens) = result.cycles else {
        panic!("complete token inventory required")
    };
    assert!(
        tokens
            .iter()
            .any(|token| token.cycle_seq.get() == 1 && token.worker_boot_id == id("boot-old"))
    );
    assert!(
        tokens
            .iter()
            .any(|token| token.cycle_seq.get() == 5 && token.worker_boot_id == id("boot-new"))
    );
}

#[test]
fn cache_control_receipt_and_pending_barrier_dependencies_outlive_diagnostic_tail() {
    let mut f = Fixture::new();
    for n in 1..=10 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
    }
    f.discovery(3, "boot-old", Some(("source-one", "revision-3")));
    f.discovery(11, "boot-new", None);
    let mut deps = f.dependencies();
    deps.keep_cycles = vec![
        CycleSeq::new(3).unwrap(),
        CycleSeq::new(4).unwrap(),
        CycleSeq::new(5).unwrap(),
        CycleSeq::new(6).unwrap(),
    ];
    deps.keep_receipts = vec![revision("revision-7")];
    let result = f
        .prunes(&deps, &[revision("revision-2")], HistoryLimits::default())
        .unwrap();
    assert_eq!(result.counts.receipts_deleted, 1);
    assert_eq!(
        f.receipts(),
        vec![
            "revision-1",
            "revision-10",
            "revision-2",
            "revision-3",
            "revision-4",
            "revision-5",
            "revision-6",
            "revision-7",
            "revision-9"
        ]
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM discovery_receipts"), 2);
    let mut released = f.dependencies();
    released.keep_receipts.clear();
    let result = f.prunes(&released, &[], HistoryLimits::default()).unwrap();
    assert_eq!(result.counts.discoveries_deleted, 1);
    assert_eq!(
        f.receipts(),
        vec!["revision-1", "revision-10", "revision-9"]
    );
}

#[test]
fn projection_proof_can_be_older_than_visible_head_and_latest_receipt() {
    let mut f = Fixture::new();
    f.publish("source-one", "revision-1", 1, "boot-old", "original proof");
    f.publish(
        "source-one",
        "revision-2",
        2,
        "boot-old",
        "original proof extended",
    );
    f.publish(
        "source-one",
        "revision-3",
        3,
        "boot-old",
        "original proof extended",
    );
    f.conn
        .execute("UPDATE source_projections SET revision_id='revision-1'", [])
        .unwrap();
    let evidence = f.evidence_rows();
    let deps = f.dependencies();
    let result = f
        .prunes(
            &deps,
            &[],
            HistoryLimits {
                receipt_tail_per_source: 1,
                ..HistoryLimits::default()
            },
        )
        .unwrap();
    assert_eq!(result.counts.receipts_deleted, 0);
    assert_eq!(f.evidence_rows(), evidence);
    assert_eq!(f.receipts(), vec!["revision-1", "revision-2", "revision-3"]);
}

#[test]
fn rewritten_unreferenced_content_receipts_expire_after_their_attempt_dependents() {
    let mut f = Fixture::new();
    f.publish("source-one", "revision-1", 1, "boot-old", "original proof");
    f.publish("source-one", "revision-2", 2, "boot-old", "original proof");
    f.publish(
        "source-one",
        "revision-3",
        3,
        "boot-new",
        "replacement proof",
    );
    for n in 4..=6 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-new",
            "replacement proof",
        );
    }
    let deps = f.dependencies();
    let first = f.prunes(&deps, &[], HistoryLimits::default()).unwrap();
    assert!(first.has_more);
    assert!(f.receipts().contains(&"revision-1".into()));
    assert!(!f.receipts().contains(&"revision-2".into()));
    let second = f.prunes(&deps, &[], HistoryLimits::default()).unwrap();
    assert!(!second.has_more);
    assert_eq!(f.receipts(), vec!["revision-3", "revision-5", "revision-6"]);
    assert_eq!(f.text("source-one"), vec!["replacement proof"]);
    assert_eq!(f.dependencies().snapshot, deps.snapshot);
}

#[test]
fn partial_and_held_rewrite_attempts_remain_receipts_and_never_become_evidence() {
    let mut f = Fixture::new();
    f.publish("source-one", "revision-1", 1, "boot-old", "original proof");
    for n in 2..=6 {
        f.observe(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "unpublished private candidate",
            ObservationState::RewritePending,
        );
    }
    let mut deps = f.dependencies();
    deps.keep_cycles = vec![CycleSeq::new(2).unwrap(), CycleSeq::new(3).unwrap()];
    let evidence = f.evidence_rows();
    f.prunes(&deps, &[], HistoryLimits::default()).unwrap();
    assert_eq!(f.evidence_rows(), evidence);
    assert_eq!(f.text("source-one"), vec!["original proof"]);
    assert_eq!(
        f.scalar("SELECT published FROM source_revision_receipts WHERE revision_id='revision-6'"),
        0
    );
    assert!(f.receipts().contains(&"revision-2".into()));
    assert!(f.receipts().contains(&"revision-3".into()));
}

#[test]
fn missing_cache_or_control_receipt_dependency_fails_without_any_deletion() {
    for cache in [false, true] {
        let mut f = Fixture::new();
        for n in 1..=6 {
            f.publish(
                "source-one",
                &format!("revision-{n}"),
                n,
                "boot-old",
                "original proof",
            );
        }
        let before = f.receipts();
        let mut deps = f.dependencies();
        if !cache {
            deps.keep_receipts.push(revision("missing-revision"));
        }
        let cache_refs = if cache {
            vec![revision("missing-revision")]
        } else {
            Vec::new()
        };
        assert!(matches!(
            f.prunes(&deps, &cache_refs, HistoryLimits::default()),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert_eq!(f.receipts(), before);
        // An error leaves no temp table state or failed savepoint behind.
        assert!(
            f.prunes(&f.dependencies(), &[], HistoryLimits::default())
                .is_ok()
        );
    }
}

#[test]
fn stale_incarnation_generation_destructive_epoch_or_installation_fails_before_writes() {
    for change in 0..4 {
        let mut f = Fixture::new();
        for n in 1..=5 {
            f.publish(
                "source-one",
                &format!("revision-{n}"),
                n,
                "boot-old",
                "original proof",
            );
        }
        let before = f.receipts();
        let mut deps = f.dependencies();
        match change {
            0 => deps.installation_id = id("other-installation"),
            1 => deps.snapshot.catalog_incarnation = "other-catalog".into(),
            2 => deps.snapshot.generation += 1,
            _ => deps.snapshot.destructive_epoch += 1,
        }
        assert!(matches!(
            f.prunes(&deps, &[], HistoryLimits::default()),
            Err(PortError::GenerationMismatch(_))
        ));
        assert_eq!(f.receipts(), before);
    }
}

#[test]
fn expired_deadline_invalid_bounds_and_dependency_overflow_do_not_delete_history() {
    let mut f = Fixture::new();
    for n in 1..=6 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
    }
    let before = f.receipts();
    let deps = f.dependencies();
    let tx = f
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        prune_in_tx(&tx, &deps, &[], HistoryLimits::default(), Instant::now()),
        Err(PortError::WriterBusy(_))
    ));
    tx.commit().unwrap();
    assert!(matches!(
        f.prunes(
            &deps,
            &[],
            HistoryLimits {
                receipt_tail_per_source: 0,
                ..HistoryLimits::default()
            }
        ),
        Err(PortError::InvalidRequest(_))
    ));
    let start = Instant::now();
    assert!(matches!(
        f.prunes(
            &deps,
            &[revision("revision-1"), revision("revision-2")],
            HistoryLimits {
                max_dependencies: 1,
                ..HistoryLimits::default()
            }
        ),
        Err(PortError::WriterBusy(_))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(f.receipts(), before);
    let start = Instant::now();
    assert!(matches!(
        f.prunes(
            &deps,
            &[],
            HistoryLimits {
                max_dependencies: 1,
                ..HistoryLimits::default()
            }
        ),
        Err(PortError::WriterBusy(_))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(f.receipts(), before);
}

#[test]
fn malformed_enum_or_cross_source_content_reference_is_not_cleaned_away() {
    for malformed in 0..3 {
        let mut f = Fixture::new();
        for n in 1..=6 {
            f.publish(
                "source-one",
                &format!("revision-{n}"),
                n,
                "boot-old",
                "original proof",
            );
        }
        f.publish(
            "source-other",
            "other-revision",
            7,
            "boot-old",
            "other proof",
        );
        f.conn
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        match malformed {
            0 => {
                f.conn.execute("UPDATE source_revision_receipts SET completeness='unknown' WHERE revision_id='revision-2'",[]).unwrap();
            }
            1 => {
                f.conn.execute("UPDATE source_revision_receipts SET content_revision_id='other-revision' WHERE revision_id='revision-2'",[]).unwrap();
            }
            _ => {
                f.conn.execute("UPDATE source_revision_receipts SET worker_boot_id='invalid private boot!' WHERE revision_id='revision-2'",[]).unwrap();
            }
        }
        let before = f.receipts();
        let error = f
            .prunes(&f.dependencies(), &[], HistoryLimits::default())
            .unwrap_err();
        assert!(matches!(error, PortError::SchemaIncompatible(_)));
        assert!(!error.to_string().contains(f.catalog.to_str().unwrap()));
        assert_eq!(f.receipts(), before);
    }
}

#[test]
fn null_obsolete_revision_refuses_gc_before_any_deletion() {
    let mut f = Fixture::new();
    for cycle in 1..=6 {
        f.publish(
            "source-one",
            &format!("revision-{cycle}"),
            cycle,
            "boot-old",
            "original proof",
        );
    }
    f.discovery(1, "boot-old", Some(("source-one", "revision-1")));
    f.discovery(6, "boot-old", Some(("source-one", "revision-6")));
    // An ordinary rowid table's TEXT PRIMARY KEY can contain NULL. Keep every
    // SQL guard enabled and damage an obsolete, unreferenced middle receipt.
    f.conn
        .execute(
            "DELETE FROM receipt_selection_claims WHERE revision_id='revision-2'",
            [],
        )
        .unwrap();
    f.conn
        .execute(
            "UPDATE source_revision_receipts SET revision_id=NULL WHERE revision_id='revision-2'",
            [],
        )
        .unwrap();
    assert_eq!(f.scalar("SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    let before = (
        f.scalar("SELECT COUNT(*) FROM source_revision_receipts"),
        f.scalar("SELECT COUNT(*) FROM receipt_selection_claims"),
        f.scalar("SELECT COUNT(*) FROM discovery_receipts"),
        f.evidence_rows(),
    );
    let limits = HistoryLimits {
        batch_rows: 1,
        ..HistoryLimits::default()
    };
    assert!(matches!(
        f.prunes(&f.dependencies(), &[], limits),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(
        (
            f.scalar("SELECT COUNT(*) FROM source_revision_receipts"),
            f.scalar("SELECT COUNT(*) FROM receipt_selection_claims"),
            f.scalar("SELECT COUNT(*) FROM discovery_receipts"),
            f.evidence_rows(),
        ),
        before,
        "even an outer commit must preserve all rows when an ID is invalid"
    );
}

#[test]
fn corrupt_discovery_digest_or_receipt_claim_prevents_partial_gc() {
    for corrupt_claim in [false, true] {
        let mut f = Fixture::new();
        for n in 1..=5 {
            f.publish(
                "source-one",
                &format!("revision-{n}"),
                n,
                "boot-old",
                "original proof",
            );
            f.discovery(
                n,
                "boot-old",
                Some(("source-one", &format!("revision-{n}"))),
            );
        }
        if corrupt_claim {
            f.conn.execute("UPDATE receipt_selection_claims SET root_identity='other-root' WHERE revision_id='revision-1'",[]).unwrap();
        } else {
            f.conn
                .execute(
                    "UPDATE discovery_receipts SET source_set_digest=?1 WHERE cycle_seq=1",
                    ["0".repeat(64)],
                )
                .unwrap();
        }
        let before = f.receipts();
        let discoveries = f.scalar("SELECT COUNT(*) FROM discovery_receipts");
        assert!(matches!(
            f.prunes(&f.dependencies(), &[], HistoryLimits::default()),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert_eq!(f.receipts(), before);
        assert_eq!(
            f.scalar("SELECT COUNT(*) FROM discovery_receipts"),
            discoveries
        );
    }
}

#[test]
fn injected_delete_failure_rolls_back_discovery_and_claim_deletions_even_on_outer_commit() {
    let mut f = Fixture::new();
    for n in 1..=6 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
        f.discovery(
            n,
            "boot-old",
            Some(("source-one", &format!("revision-{n}"))),
        );
    }
    f.conn.execute_batch("CREATE TRIGGER fail_history_delete BEFORE DELETE ON source_revision_receipts BEGIN SELECT RAISE(ABORT,'synthetic retention failure'); END;").unwrap();
    let before = f.receipts();
    let discoveries = f.scalar("SELECT COUNT(*) FROM discovery_receipts");
    let claims = f.scalar("SELECT COUNT(*) FROM receipt_selection_claims");
    assert!(
        f.prunes(&f.dependencies(), &[], HistoryLimits::default())
            .is_err()
    );
    assert_eq!(f.receipts(), before);
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM discovery_receipts"),
        discoveries
    );
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM receipt_selection_claims"),
        claims
    );
    f.conn
        .execute_batch("DROP TRIGGER fail_history_delete;")
        .unwrap();
    assert!(
        f.prunes(&f.dependencies(), &[], HistoryLimits::default())
            .is_ok()
    );
}

#[test]
fn one_bounded_batch_returns_complete_remaining_tokens_or_explicitly_blocks_control_gc() {
    let mut f = Fixture::new();
    for n in 1..=12 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
    }
    let deps = f.dependencies();
    let limits = HistoryLimits {
        batch_rows: 1,
        max_cycle_tokens: 2,
        ..HistoryLimits::default()
    };
    let first = f.prunes(&deps, &[], limits).unwrap();
    assert_eq!(first.counts.receipts_deleted, 1);
    assert!(first.has_more);
    assert_eq!(first.cycles, CycleRetention::PendingCatalogPrune);
    let limits = HistoryLimits {
        batch_rows: 1,
        ..HistoryLimits::default()
    };
    let mut batches = 1;
    loop {
        let result = f.prunes(&deps, &[], limits).unwrap();
        assert!(result.counts.receipts_deleted + result.counts.discoveries_deleted <= 1);
        batches += 1;
        if !result.has_more {
            let CycleRetention::Complete(tokens) = result.cycles else {
                panic!()
            };
            assert_eq!(
                tokens
                    .iter()
                    .map(|token| token.cycle_seq.get())
                    .collect::<Vec<_>>(),
                vec![1, 11, 12]
            );
            break;
        }
        assert!(batches < 16);
    }
    assert_eq!(
        f.receipts(),
        vec!["revision-1", "revision-11", "revision-12"]
    );
}

#[test]
fn more_than_a_batch_of_sources_prunes_incrementally_under_one_original_deadline() {
    let mut f = Fixture::new();
    let mut sources = Vec::new();
    for n in 1..=80 {
        let source = format!("source-{n:03}");
        for cycle in 1..=5 {
            f.publish(
                &source,
                &format!("revision-{n:03}-{cycle}"),
                cycle,
                "boot-old",
                "original proof",
            );
        }
        sources.push(source);
    }
    for cycle in 1..=5 {
        let receipts = sources
            .iter()
            .enumerate()
            .map(|(n, source)| (source.clone(), format!("revision-{:03}-{cycle}", n + 1)))
            .collect::<Vec<_>>();
        f.discovery_for(cycle, "boot-old", "selection-one", true, &receipts);
    }
    let deps = f.dependencies();
    let evidence = f.evidence_rows();
    let end = deadline();
    let mut receipt_count = 0;
    let mut discovery_count = 0;
    let mut discovery_sources = 0;
    let mut batches = 0;
    loop {
        let result = f
            .prunes_until(&deps, &[], HistoryLimits::default(), end)
            .unwrap();
        let parents = result.counts.receipts_deleted + result.counts.discoveries_deleted;
        assert!(parents <= 64);
        receipt_count += result.counts.receipts_deleted;
        discovery_count += result.counts.discoveries_deleted;
        discovery_sources += result.counts.discovery_sources_deleted;
        batches += 1;
        if !result.has_more {
            assert!(matches!(result.cycles, CycleRetention::Complete(_)));
            break;
        }
        assert!(
            parents > 0,
            "has_more must correspond to achievable housekeeping progress"
        );
        assert!(batches <= 4);
    }
    assert!(batches > 1);
    assert_eq!(receipt_count, 160);
    assert_eq!(discovery_count, 4);
    assert_eq!(discovery_sources, 320);
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM source_revision_receipts"),
        240
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM discovery_receipts"), 1);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM discovery_sources"), 80);
    assert_eq!(f.evidence_rows(), evidence);
    assert_eq!(f.dependencies().snapshot, deps.snapshot);
    assert!(Instant::now() < end);
}
#[test]
fn restored_exact_receipt_lineage_and_old_boot_tokens_are_kept_without_rewriting_proof() {
    let mut f = Fixture::new();
    for n in 1..=7 {
        f.publish(
            "source-one",
            &format!("revision-{n}"),
            n,
            "boot-old",
            "original proof",
        );
    }
    f.conn.execute("INSERT INTO retained_source_receipts SELECT revision_id,'recovery-catalog',catalog_incarnation,revision_digest,committed_generation,'recovery-one' FROM source_revision_receipts WHERE published=1",[]).unwrap();
    f.conn
        .execute(
            "UPDATE catalog_meta SET catalog_incarnation='recovery-catalog'",
            [],
        )
        .unwrap();
    let deps = f.dependencies();
    let mut deps = deps;
    deps.snapshot.catalog_incarnation = "recovery-catalog".into();
    let evidence = f.evidence_rows();
    let result = f.prunes(&deps, &[], HistoryLimits::default()).unwrap();
    assert_eq!(result.counts.receipts_deleted, 4);
    assert_eq!(result.counts.retained_proofs_deleted, 4);
    assert_eq!(f.evidence_rows(), evidence);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM retained_source_receipts"), 3);
    assert_eq!(f.conn.query_row("SELECT catalog_incarnation FROM source_revision_receipts WHERE revision_id='revision-1'",[],|row|row.get::<_,String>(0)).unwrap(),"history-catalog");
    let CycleRetention::Complete(tokens) = result.cycles else {
        panic!()
    };
    assert!(
        tokens
            .iter()
            .all(|token| token.worker_boot_id == id("boot-old"))
    );
}

#[test]
fn missing_retained_origin_and_cycle_boot_conflict_fail_closed() {
    for mismatch in [false, true] {
        let mut f = Fixture::new();
        for n in 1..=5 {
            f.publish(
                "source-one",
                &format!("revision-{n}"),
                n,
                "boot-old",
                "original proof",
            );
        }
        let mut deps = f.dependencies();
        if mismatch {
            f.discovery(2, "other-boot", None);
        } else {
            f.conn
                .execute(
                    "UPDATE catalog_meta SET catalog_incarnation='recovery-catalog'",
                    [],
                )
                .unwrap();
            deps.snapshot.catalog_incarnation = "recovery-catalog".into();
        }
        let before = f.receipts();
        assert!(matches!(
            f.prunes(&deps, &[], HistoryLimits::default()),
            Err(PortError::SchemaIncompatible(_))
        ));
        assert_eq!(f.receipts(), before);
    }
}

#[test]
fn history_read_guard_blocks_gc_and_releases_when_reader_finishes() {
    let f = Fixture::new();
    let reader = SharedGuard::try_acquire(&f.root, LockKind::HistoryReaders).unwrap();
    assert!(matches!(
        ExclusiveGuard::try_acquire(&f.root, LockKind::HistoryReaders),
        Err(PortError::WriterBusy(_))
    ));
    drop(reader);
    drop(ExclusiveGuard::try_acquire(&f.root, LockKind::HistoryReaders).unwrap());
}

#[test]
fn unsupported_schema_or_autocommit_never_repairs_or_creates_history_state() {
    let mut f = Fixture::new();
    f.publish("source-one", "revision-1", 1, "boot-old", "original proof");
    let deps = f.dependencies();
    assert!(matches!(
        prune_in_tx(&f.conn, &deps, &[], HistoryLimits::default(), deadline()),
        Err(PortError::InvalidRequest(_))
    ));
    f.conn
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    assert!(matches!(
        f.prunes(&deps, &[], HistoryLimits::default()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(f.scalar("PRAGMA user_version"), SCHEMA_VERSION + 1);
    assert_eq!(f.receipts(), vec!["revision-1"]);
}
