//! Synthetic admitted source metadata and private catalogs; no provider/source I/O.
use agent_session_grep_adapters_sqlite::{
    SCHEMA_VERSION, SourceBatch, SqliteControlStore, SqliteStore, managed,
    managed_history::{HistoryDependencies, HistoryLimits, prune_in_tx},
    managed_source_context as context,
    managed_store::ManagedStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{
    PortError, SearchProvider, control::*, managed::*, source_context::*,
};
use rusqlite::{Connection, params};
use std::time::{Duration, Instant};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn cid(s: &str) -> ControlId {
    ControlId::parse(s).unwrap()
}
fn entity(kind: IdKind, s: &str) -> StableId {
    StableId::native_checked(kind, s).unwrap()
}
fn locator(s: &str) -> String {
    #[cfg(windows)]
    {
        format!(r"C:\synthetic-surface\{s}")
    }
    #[cfg(not(windows))]
    {
        format!("/synthetic-surface/{s}")
    }
}
fn surface() -> CanonicalLocator {
    CanonicalLocator::parse(&locator("surface")).unwrap()
}
fn policy(provider: SearchProvider) -> ReadPolicy {
    ReadPolicy {
        installation_id: cid("installation"),
        policy_epoch: PolicyEpoch::new(1).unwrap(),
        control_seq: ControlSeq::new(10000).unwrap(),
        selections: vec![Selection {
            id: cid("selection"),
            region: ScopeRegion {
                provider,
                locator: surface(),
                kind: RootKind::Root,
            },
            root_identity: Some(cid("physical-root")),
            enabled: true,
            revision: ControlSeq::new(1).unwrap(),
            created_at_ms: 0,
            revoked_at_ms: None,
        }],
        exclusions: Vec::new(),
        request_intersection: RequestIntersection::Selected,
        maintenance: MaintenanceFence {
            state: MaintenanceState::Idle,
            owner: None,
            phase: None,
        },
        revocations: Vec::new(),
    }
}
fn schema() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE store_metadata(singleton INTEGER PRIMARY KEY,active_generation INTEGER NOT NULL,projection_contract_version INTEGER NOT NULL DEFAULT 0,managed_mode INTEGER NOT NULL DEFAULT 0,destructive_epoch INTEGER NOT NULL DEFAULT 0); INSERT INTO store_metadata VALUES(1,0,0,0,0); CREATE TABLE catalog(id TEXT PRIMARY KEY,payload BLOB); BEGIN IMMEDIATE;").unwrap();
    managed::create_schema(&c).unwrap();
    managed::initialize_catalog_in_tx(&c, "installation", "incarnation", 0).unwrap();
    c.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    c.pragma_update(None, "application_id", 0x41534732).unwrap();
    c.execute_batch("COMMIT").unwrap();
    c
}
fn observe(source: &str, seq: i64, provider: SearchProvider) -> SourceObservation {
    SourceObservation {
        binding: SourceBinding {
            source_id: SourceId::parse(source).unwrap(),
            source_path: format!(
                "{}{}{}",
                surface().as_str(),
                std::path::MAIN_SEPARATOR,
                source
            ),
            provider,
            namespace_id: Some("namespace".into()),
            root_identity: "physical-root".into(),
        },
        revision_id: RevisionId::parse(&format!("revision-{source}-{seq}")).unwrap(),
        revision_digest: format!("digest-{seq}"),
        parser_version: 1,
        state: ObservationState::Complete,
        cycle_seq: seq,
        worker_boot_id: "boot".into(),
        catalog_incarnation: "incarnation".into(),
        policy_epoch: 1,
        started_control_seq: seq,
        observed_at_ms: seq,
        committed_at_ms: seq,
        selections: vec![SelectionProof {
            selection_id: "selection".into(),
            selection_revision: 1,
            root_identity: "physical-root".into(),
        }],
        repositories: Vec::new(),
    }
}
fn batch(o: &SourceObservation, text: Option<&str>, native: &str) -> SourceBatch {
    let mut b = SourceBatch {
        source_path: o.binding.source_path.clone(),
        entries: Vec::new(),
        placements: Vec::new(),
        edges: Vec::new(),
        activities: Vec::new(),
        usage_events: Vec::new(),
        relation_complete: true,
        len_bytes: Some(100),
        fingerprint: Some(o.revision_digest.clone()),
        provider_id: Some(o.binding.provider.as_str().into()),
        resume_claims: Vec::new(),
    };
    if let Some(text) = text {
        let m = entity(IdKind::Message, "message");
        let s = entity(IdKind::Session, "session");
        let d = entity(
            IdKind::Document,
            &format!("document-{}", o.binding.source_id.as_str()),
        );
        b.entries=vec![(m.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":null})).unwrap(),text.into()),(s.clone(),serde_json::to_vec(&serde_json::json!({"documents":[d.as_str()]})).unwrap(),String::new()),(d.clone(),serde_json::to_vec(&serde_json::json!({"provider":o.binding.provider.as_str(),"variant":"synthetic","fingerprint":o.revision_digest,"len":100})).unwrap(),String::new())];
        b.placements = vec![MessagePlacement::new(s.clone(), d, m, 0, false, None)];
        b.resume_claims = vec![agent_session_grep_ports::SourceResumeClaim {
            provider_id: o.binding.provider.as_str().into(),
            session_id: s.as_str().into(),
            provider_session_id: Some(native.into()),
            provider_session_id_state: "resolved".into(),
            original_working_directory: None,
            original_working_directory_state: "missing".into(),
            pair_observed: false,
        }];
    }
    b
}
fn publish(
    c: &Connection,
    o: &SourceObservation,
    b: &SourceBatch,
    ctx: &SourcePublicationContext,
    p: &ReadPolicy,
) -> Publication {
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let base: i64 = c
        .query_row("SELECT active_generation FROM store_metadata", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut out =
        context::publish_source_with_context_in_tx(c, b, o, ctx, p, base + 1, deadline()).unwrap();
    if out.content_changed {
        c.execute(
            "UPDATE store_metadata SET active_generation=?1",
            [out.required_generation],
        )
        .unwrap();
    }
    managed::finalize_publications_in_tx(c, std::slice::from_mut(&mut out)).unwrap();
    c.execute_batch("COMMIT").unwrap();
    out
}
fn unresolved(native: &str) -> SourcePublicationContext {
    SourcePublicationContext {
        dependencies: vec![SourceDependency {
            native_session: NativeSessionId::parse(native).unwrap(),
            resolution: DependencyResolution::Unresolved(UnresolvedDependency::NotSelected),
        }],
        authority: None,
    }
}
fn dependency(
    meta: &SourceObservation,
    receipt: RevisionRef,
    state: LifecycleState,
) -> SourcePublicationContext {
    SourcePublicationContext {
        dependencies: vec![SourceDependency {
            native_session: NativeSessionId::parse("native").unwrap(),
            resolution: DependencyResolution::Resolved(Box::new(MetadataDependencyProof {
                binding: meta.binding.clone(),
                receipt,
                selection: meta.selections[0].clone(),
                state,
                state_digest: StateDigest::parse(&"a".repeat(64)).unwrap(),
            })),
        }],
        authority: None,
    }
}
fn key(provider: SearchProvider) -> SourceAuthorityKey {
    SourceAuthorityKey {
        provider,
        surface_id: cid("surface-id"),
        surface_root: surface(),
        surface_identity: cid("physical-root"),
        native_session: NativeSessionId::parse("native").unwrap(),
        session_id: entity(IdKind::Session, "session"),
    }
}
fn authority(
    k: SourceAuthorityKey,
    prior: Option<SourceAuthorityPrior>,
) -> SourcePublicationContext {
    SourcePublicationContext {
        dependencies: Vec::new(),
        authority: Some(SourceAuthorityTransition {
            key: k,
            expected_prior: prior,
        }),
    }
}
fn scalar(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}
fn history(c: &Connection) -> HistoryDependencies {
    let (g, e): (i64, i64) = c
        .query_row(
            "SELECT active_generation,destructive_epoch FROM store_metadata",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    HistoryDependencies {
        installation_id: cid("installation"),
        snapshot: ReadSnapshot {
            catalog_incarnation: "incarnation".into(),
            generation: g,
            destructive_epoch: e,
            policy_epoch: 1,
        },
        keep_cycles: Vec::new(),
        keep_receipts: Vec::new(),
    }
}

#[test]
fn missing_metadata_publishes_original_but_not_current_and_default_cannot_clear_it() {
    let c = schema();
    let p = policy(SearchProvider::parse("workbuddy").unwrap());
    let o = observe("transcript", 1, SearchProvider::parse("workbuddy").unwrap());
    let ctx = unresolved("native");
    let out = publish(
        &c,
        &o,
        &batch(&o, Some("original permitted body"), "native"),
        &ctx,
        &p,
    );
    assert!(out.receipt.published);
    assert!(
        !context::receipt_context_current(&c, o.revision_id.as_str(), Some(&p), deadline())
            .unwrap()
    );
    let read = managed::ManagedRead::begin(
        &c,
        &ReadScope {
            catalog_incarnation: "incarnation".into(),
            policy_epoch: 1,
            allowed: vec![o.binding.clone()],
        },
        deadline(),
    )
    .unwrap();
    assert_eq!(
        read.query_lexical("permitted", &ProjectionQuery::default(), 5)
            .unwrap()
            .hits
            .len(),
        1
    );
    drop(read);
    let decoded = context::publication_context(&c, &out.receipt, &p, deadline()).unwrap();
    assert_eq!(decoded, ctx);
    let next = observe("transcript", 2, SearchProvider::parse("workbuddy").unwrap());
    c.execute_batch("BEGIN").unwrap();
    assert!(
        context::publish_source_with_context_in_tx(
            &c,
            &batch(&next, Some("new"), "native"),
            &next,
            &SourcePublicationContext::default(),
            &p,
            2,
            deadline()
        )
        .is_err()
    );
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_revision_receipts"),
        1
    );
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn separately_selected_metadata_receipt_is_exact_and_withdrawal_keeps_original() {
    let c = schema();
    let p = policy(SearchProvider::parse("workbuddy").unwrap());
    let meta = observe("metadata", 1, SearchProvider::parse("workbuddy").unwrap());
    let m = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let o = observe("transcript", 1, SearchProvider::parse("workbuddy").unwrap());
    let ctx = dependency(&meta, m.receipt, LifecycleState::ActiveLocal);
    publish(&c, &o, &batch(&o, Some("original"), "native"), &ctx, &p);
    assert!(
        context::receipt_context_current(&c, o.revision_id.as_str(), Some(&p), deadline()).unwrap()
    );
    let mut withdrawn = p.clone();
    withdrawn.exclusions.push(Exclusion {
        id: cid("deny-metadata"),
        region: ExcludedRegion::Locator(ScopeRegion {
            provider: SearchProvider::parse("workbuddy").unwrap(),
            locator: CanonicalLocator::parse(&meta.binding.source_path).unwrap(),
            kind: RootKind::Exact,
        }),
        revision: ControlSeq::new(2).unwrap(),
        created_policy_epoch: PolicyEpoch::new(1).unwrap(),
        created_at_ms: 2,
    });
    assert!(
        !context::receipt_context_current(&c, o.revision_id.as_str(), Some(&withdrawn), deadline())
            .unwrap()
    );
    assert!(context::source_read_eligible(&c, o.binding.source_id.as_str()).unwrap());
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_entity_projections WHERE kind='repo_identity'"
        ),
        0
    );
}
#[test]
fn crossed_receipt_tokens_and_body_bearing_metadata_refuse_before_publication() {
    let c = schema();
    let p = policy(SearchProvider::parse("workbuddy").unwrap());
    let meta = observe("metadata", 1, SearchProvider::parse("workbuddy").unwrap());
    let m = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let o = observe("transcript", 2, SearchProvider::parse("workbuddy").unwrap());
    let ctx = dependency(&meta, m.receipt, LifecycleState::ActiveLocal);
    c.execute_batch("BEGIN").unwrap();
    assert!(
        context::publish_source_with_context_in_tx(
            &c,
            &batch(&o, Some("never publish"), "native"),
            &o,
            &ctx,
            &p,
            1,
            deadline()
        )
        .is_err()
    );
    assert_eq!(scalar(&c, "SELECT COUNT(*) FROM source_bindings"), 1);
    c.execute_batch("ROLLBACK").unwrap();
    let meta2 = observe("body-meta", 3, SearchProvider::parse("workbuddy").unwrap());
    let m2 = publish(
        &c,
        &meta2,
        &batch(&meta2, Some("metadata body"), "native"),
        &SourcePublicationContext::default(),
        &p,
    );
    let o2 = observe("transcript", 3, SearchProvider::parse("workbuddy").unwrap());
    c.execute_batch("BEGIN").unwrap();
    assert!(
        context::publish_source_with_context_in_tx(
            &c,
            &batch(&o2, Some("never"), "native"),
            &o2,
            &dependency(&meta2, m2.receipt, LifecycleState::ActiveLocal),
            &p,
            2,
            deadline()
        )
        .is_err()
    );
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn authority_switch_is_atomic_scope_bound_and_superseded_never_resurrects() {
    let c = schema();
    let provider = SearchProvider::parse("antigravity").unwrap();
    let p = policy(provider);
    let k = key(provider);
    let old = observe("db", 1, provider);
    publish(
        &c,
        &old,
        &batch(&old, Some("old original"), "native"),
        &authority(k.clone(), None),
        &p,
    );
    let prior = context::authority_prior(&c, &k, &p, deadline())
        .unwrap()
        .unwrap();
    let new = observe("full", 2, provider);
    let ctx = authority(k.clone(), Some(prior));
    c.execute_batch("BEGIN").unwrap();
    let target = scalar(&c, "SELECT active_generation+1 FROM store_metadata");
    let result = context::publish_source_with_context_in_tx(
        &c,
        &batch(&new, Some("new original"), "native"),
        &new,
        &ctx,
        &p,
        target,
        deadline(),
    )
    .unwrap();
    assert!(result.destructive);
    assert!(!context::source_read_eligible(&c, "db").unwrap());
    c.execute_batch("ROLLBACK").unwrap();
    assert!(context::source_read_eligible(&c, "db").unwrap());
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_bindings WHERE source_id='full'"
        ),
        0
    );
    let result = publish(
        &c,
        &new,
        &batch(&new, Some("new original"), "native"),
        &ctx,
        &p,
    );
    assert!(result.destructive);
    assert!(!context::source_read_eligible(&c, "db").unwrap());
    assert!(context::source_read_eligible(&c, "full").unwrap());
    let restore = observe("db", 3, provider);
    c.execute_batch("BEGIN").unwrap();
    assert!(
        managed::publish_source_in_tx(
            &c,
            &batch(&restore, Some("old"), "native"),
            &restore,
            result.required_generation + 1
        )
        .is_err()
    );
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn stale_authority_cas_and_old_exact_revoke_leave_candidate_unwritten() {
    let c = schema();
    let provider = SearchProvider::parse("antigravity").unwrap();
    let p = policy(provider);
    let k = key(provider);
    let old = observe("db", 1, provider);
    publish(
        &c,
        &old,
        &batch(&old, Some("old"), "native"),
        &authority(k.clone(), None),
        &p,
    );
    let mut prior = context::authority_prior(&c, &k, &p, deadline())
        .unwrap()
        .unwrap();
    prior.receipt.digest = "wrong".into();
    let new = observe("full", 2, provider);
    c.execute_batch("BEGIN").unwrap();
    assert!(
        context::publish_source_with_context_in_tx(
            &c,
            &batch(&new, Some("new"), "native"),
            &new,
            &authority(k.clone(), Some(prior)),
            &p,
            2,
            deadline()
        )
        .is_err()
    );
    c.execute_batch("ROLLBACK").unwrap();
    let mut deny = p.clone();
    deny.exclusions.push(Exclusion {
        id: cid("exclusion"),
        region: ExcludedRegion::SourceIdentity {
            provider,
            source_id: cid("db"),
        },
        revision: ControlSeq::new(2).unwrap(),
        created_policy_epoch: PolicyEpoch::new(1).unwrap(),
        created_at_ms: 2,
    });
    assert!(context::authority_prior(&c, &k, &deny, deadline()).is_err());
    assert_eq!(scalar(&c, "SELECT COUNT(*) FROM source_bindings"), 1);
}
#[test]
fn semantic_state_survives_db_digest_churn_and_old_dependency_receipt_is_retained() {
    let c = schema();
    let p = policy(SearchProvider::parse("workbuddy").unwrap());
    let meta = observe("metadata", 1, SearchProvider::parse("workbuddy").unwrap());
    let m = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let o = observe("transcript", 1, SearchProvider::parse("workbuddy").unwrap());
    let ctx = dependency(&meta, m.receipt.clone(), LifecycleState::ActiveLocal);
    publish(&c, &o, &batch(&o, Some("original"), "native"), &ctx, &p);
    for seq in 2..8 {
        let m = observe("metadata", seq, SearchProvider::parse("workbuddy").unwrap());
        publish(
            &c,
            &m,
            &batch(&m, None, ""),
            &SourcePublicationContext::default(),
            &p,
        );
    }
    let deps = history(&c);
    c.execute_batch("BEGIN").unwrap();
    prune_in_tx(
        &c,
        &deps,
        &[],
        HistoryLimits {
            receipt_tail_per_source: 1,
            ..HistoryLimits::default()
        },
        deadline(),
    )
    .unwrap();
    assert_eq!(
        c.query_row(
            "SELECT COUNT(*) FROM source_revision_receipts WHERE revision_id=?1",
            [m.receipt.revision_id.as_str()],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    c.execute_batch("COMMIT").unwrap();
    assert!(
        !context::receipt_context_current(&c, o.revision_id.as_str(), Some(&p), deadline())
            .unwrap()
    );
    let prior = context::publication_context(
        &c,
        &managed_receipt_test(&c, o.revision_id.as_str()),
        &p,
        deadline(),
    )
    .unwrap();
    assert_eq!(prior, ctx);
}
fn managed_receipt_test(c: &Connection, r: &str) -> RevisionRef {
    c.query_row("SELECT revision_id,revision_digest,observed_at_ms,cycle_seq,worker_boot_id,catalog_incarnation,policy_epoch,started_control_seq,committed_generation,published FROM source_revision_receipts WHERE revision_id=?1",[r],|r|Ok(RevisionRef {revision_id:RevisionId::parse(&r.get::<_,String>(0)?).unwrap(),digest:r.get(1)?,observed_at_ms:r.get(2)?,cycle_seq:r.get(3)?,worker_boot_id:r.get(4)?,catalog_incarnation:r.get(5)?,policy_epoch:r.get(6)?,started_control_seq:r.get(7)?,committed_generation:r.get(8)?,published:r.get(9)?})).unwrap()
}
#[test]
fn unknown_context_enum_and_crossed_edge_fail_closed_and_gc_does_not_hide_them() {
    let c = schema();
    let p = policy(SearchProvider::parse("workbuddy").unwrap());
    let o = observe("transcript", 1, SearchProvider::parse("workbuddy").unwrap());
    publish(
        &c,
        &o,
        &batch(&o, Some("original"), "native"),
        &unresolved("native"),
        &p,
    );
    let mut raw = context::context_manifest(&unresolved("native")).unwrap();
    let bad = String::from_utf8(raw.clone())
        .unwrap()
        .replace("not_selected", "future_state");
    raw = bad.into_bytes();
    c.execute_batch("DROP TRIGGER source_publication_context_immutable")
        .unwrap();
    c.execute(
        "UPDATE source_publication_contexts SET manifest=?1,context_digest=?2",
        params![raw, blake3::hash(&raw).to_hex().to_string()],
    )
    .unwrap();
    assert!(matches!(
        context::receipt_context_current(&c, o.revision_id.as_str(), Some(&p), deadline()),
        Err(PortError::SchemaIncompatible(_))
    ));
    let deps = history(&c);
    c.execute_batch("BEGIN").unwrap();
    assert!(prune_in_tx(&c, &deps, &[], HistoryLimits::default(), deadline()).is_err());
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_revision_receipts"),
        1
    );
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn migration_21_to_22_is_additive_and_creates_no_authority_or_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    let path = root.join("catalog.db");
    let control =
        SqliteControlStore::create(&root, &cid("installation"), DesiredUpdates::Running).unwrap();
    drop(ManagedStore::create(&path, &control, cid("incarnation"), 1).unwrap());
    let c = Connection::open(&path).unwrap();
    c.execute_batch("DROP TABLE source_authority_tombstones; DROP TABLE source_context_heads; DROP TABLE source_dependencies; DROP TABLE source_publication_contexts; DROP TABLE source_authority_members; DROP TABLE source_authority_transitions; DROP TABLE source_authorities; PRAGMA user_version=21;").unwrap();
    let before = scalar(&c, "SELECT active_generation FROM store_metadata");
    drop(c);
    assert!(ManagedStore::open(&path, &control).is_err());
    // The managed facade refuses older schema. Explicit maintenance migration
    // owns receiving-file admission; this test drives its exact transaction seam.
    assert!(ManagedStore::open_for_write(&path, &control).is_err());
    let c = Connection::open(&path).unwrap();
    assert_eq!(scalar(&c, "PRAGMA user_version"), 21);
    c.execute_batch("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;")
        .unwrap();
    context::create_schema(&c).unwrap();
    c.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    c.execute_batch("COMMIT").unwrap();
    assert_eq!(scalar(&c, "PRAGMA user_version"), 22);
    assert_eq!(
        scalar(&c, "SELECT active_generation FROM store_metadata"),
        before
    );
    for table in [
        "source_publication_contexts",
        "source_dependencies",
        "source_authorities",
        "source_authority_transitions",
        "source_authority_members",
        "source_context_heads",
    ] {
        assert_eq!(scalar(&c, &format!("SELECT COUNT(*) FROM {table}")), 0);
    }
    assert!(SqliteStore::open(path.to_str().unwrap()).is_err());
}

fn denied(policy: &ReadPolicy, source: &str) -> ReadPolicy {
    let mut result = policy.clone();
    result.exclusions.push(Exclusion {
        id: cid(&format!("deny-{source}")),
        region: ExcludedRegion::SourceIdentity {
            provider: policy.selections[0].region.provider,
            source_id: cid(source),
        },
        revision: ControlSeq::new(2).unwrap(),
        created_policy_epoch: policy.policy_epoch,
        created_at_ms: 2,
    });
    result
}
fn delete_source_receipts(c: &Connection, source: &str) {
    for table in [
        "source_projections",
        "source_occurrences",
        "source_entity_projections",
        "source_session_projections",
        "source_scope_claims",
    ] {
        c.execute(&format!("DELETE FROM {table} WHERE source_id=?1"), [source])
            .unwrap();
    }
    c.execute("DELETE FROM receipt_selection_claims WHERE revision_id IN(SELECT revision_id FROM source_revision_receipts WHERE source_id=?1)",[source]).unwrap();
    c.execute(
        "DELETE FROM source_revision_receipts WHERE source_id=?1",
        [source],
    )
    .unwrap();
    c.execute("UPDATE source_heads SET latest_receipt_id=NULL,last_attempt_id=NULL,visible_revision_id=NULL,update_state='revoked' WHERE source_id=?1",[source]).unwrap();
}
fn foreign_keys_valid(c: &Connection) {
    let mut check = c.prepare("PRAGMA foreign_key_check").unwrap();
    assert!(check.query([]).unwrap().next().unwrap().is_none());
}
#[test]
fn metadata_purge_unlinks_receipts_preserves_original_and_repeats_without_effects() {
    let c = schema();
    let provider = SearchProvider::parse("workbuddy").unwrap();
    let p = policy(provider);
    let meta = observe("metadata", 1, provider);
    let m = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let original = observe("transcript", 1, provider);
    let result = publish(
        &c,
        &original,
        &batch(&original, Some("private original remains"), "native"),
        &dependency(&meta, m.receipt, LifecycleState::ActiveLocal),
        &p,
    );
    let withdrawn = denied(&p, "metadata");
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let counts = context::purge_sources_in_tx(
        &c,
        std::slice::from_ref(&meta.binding.source_id),
        &withdrawn,
        deadline(),
    )
    .unwrap();
    assert_eq!(counts.dependencies_withdrawn, 1);
    assert_eq!(counts.contexts_removed, 1);
    delete_source_receipts(&c, "metadata");
    foreign_keys_valid(&c);
    c.execute_batch("COMMIT").unwrap();
    let decoded =
        context::publication_context(&c, &result.receipt, &withdrawn, deadline()).unwrap();
    assert_eq!(
        decoded.dependencies[0].resolution,
        DependencyResolution::Unresolved(UnresolvedDependency::Withdrawn)
    );
    assert!(
        !context::receipt_context_current(
            &c,
            original.revision_id.as_str(),
            Some(&withdrawn),
            deadline()
        )
        .unwrap()
    );
    let read = managed::ManagedRead::begin(
        &c,
        &ReadScope {
            catalog_incarnation: "incarnation".into(),
            policy_epoch: 1,
            allowed: vec![original.binding.clone()],
        },
        deadline(),
    )
    .unwrap();
    assert_eq!(
        read.query_lexical("remains", &ProjectionQuery::default(), 5)
            .unwrap()
            .hits
            .len(),
        1
    );
    drop(read);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let repeated =
        context::purge_sources_in_tx(&c, &[meta.binding.source_id], &withdrawn, deadline())
            .unwrap();
    assert_eq!(repeated, context::ContextPurgeCounts::default());
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn metadata_purge_failure_rolls_back_every_edge_and_receipt() {
    let c = schema();
    let provider = SearchProvider::parse("workbuddy").unwrap();
    let p = policy(provider);
    let meta = observe("metadata", 1, provider);
    let m = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let original = observe("transcript", 1, provider);
    publish(
        &c,
        &original,
        &batch(&original, Some("original"), "native"),
        &dependency(&meta, m.receipt, LifecycleState::ActiveLocal),
        &p,
    );
    c.execute_batch("CREATE TRIGGER synthetic_purge_failure BEFORE DELETE ON source_publication_contexts BEGIN SELECT RAISE(ABORT,'synthetic'); END; BEGIN IMMEDIATE;").unwrap();
    assert!(
        context::purge_sources_in_tx(
            &c,
            &[meta.binding.source_id],
            &denied(&p, "metadata"),
            deadline()
        )
        .is_err()
    );
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_dependencies WHERE resolution='resolved'"
        ),
        1
    );
    assert_eq!(scalar(&c, "SELECT COUNT(*) FROM source_context_heads"), 2);
    assert!(
        context::receipt_context_current(&c, original.revision_id.as_str(), Some(&p), deadline())
            .unwrap()
    );
    foreign_keys_valid(&c);
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn authority_old_purge_checkpoints_active_and_active_purge_never_restores_shadow() {
    let c = schema();
    let provider = SearchProvider::parse("antigravity").unwrap();
    let p = policy(provider);
    let k = key(provider);
    let old = observe("db", 1, provider);
    publish(
        &c,
        &old,
        &batch(&old, Some("old original"), "native"),
        &authority(k.clone(), None),
        &p,
    );
    let prior = context::authority_prior(&c, &k, &p, deadline())
        .unwrap()
        .unwrap();
    let active = observe("full", 2, provider);
    publish(
        &c,
        &active,
        &batch(&active, Some("preferred original"), "native"),
        &authority(k.clone(), Some(prior)),
        &p,
    );
    let old_denied = denied(&p, "db");
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let counts = context::purge_sources_in_tx(
        &c,
        std::slice::from_ref(&old.binding.source_id),
        &old_denied,
        deadline(),
    )
    .unwrap();
    assert_eq!(counts.authority_groups_checkpointed, 1);
    delete_source_receipts(&c, "db");
    foreign_keys_valid(&c);
    c.execute_batch("COMMIT").unwrap();
    assert!(!context::source_read_eligible(&c, "db").unwrap());
    assert!(context::source_read_eligible(&c, "full").unwrap());
    assert!(
        context::receipt_context_current(
            &c,
            active.revision_id.as_str(),
            Some(&old_denied),
            deadline()
        )
        .unwrap()
    );
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_authority_transitions WHERE kind='purge_checkpoint'"
        ),
        1
    );
    let checkpoint = context::authority_prior(&c, &k, &old_denied, deadline())
        .unwrap()
        .unwrap();
    let later = observe("full", 3, provider);
    publish(
        &c,
        &later,
        &batch(&later, Some("preferred original"), "native"),
        &authority(k.clone(), Some(checkpoint)),
        &old_denied,
    );
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(
        managed::publish_source_in_tx(
            &c,
            &batch(&observe("db", 4, provider), Some("resurrect"), "native"),
            &observe("db", 4, provider),
            4
        )
        .is_err()
    );
    c.execute_batch("ROLLBACK").unwrap();
    let active_denied = denied(&old_denied, "full");
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    context::purge_sources_in_tx(&c, &[active.binding.source_id], &active_denied, deadline())
        .unwrap();
    delete_source_receipts(&c, "full");
    foreign_keys_valid(&c);
    c.execute_batch("COMMIT").unwrap();
    assert!(!context::source_read_eligible(&c, "db").unwrap());
    assert!(!context::source_read_eligible(&c, "full").unwrap());
    assert_eq!(scalar(&c, "SELECT COUNT(*) FROM source_authorities"), 0);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let replacement = observe("third", 4, provider);
    assert!(
        context::publish_source_with_context_in_tx(
            &c,
            &batch(&replacement, Some("new"), "native"),
            &replacement,
            &authority(k, None),
            &p,
            4,
            deadline()
        )
        .is_err()
    );
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_bindings WHERE source_id='third'"
        ),
        0
    );
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn plain_currentness_requires_exact_latest_receipt_incarnation_and_permission() {
    let c = schema();
    let p = policy(SearchProvider::Claude);
    let old = observe("plain", 1, SearchProvider::Claude);
    let first = publish(
        &c,
        &old,
        &batch(&old, Some("original"), "native"),
        &SourcePublicationContext::default(),
        &p,
    );
    assert!(
        context::receipt_context_current(&c, old.revision_id.as_str(), Some(&p), deadline())
            .unwrap()
    );
    let next = observe("plain", 2, SearchProvider::Claude);
    let second = publish(
        &c,
        &next,
        &batch(&next, Some("original"), "native"),
        &SourcePublicationContext::default(),
        &p,
    );
    assert!(
        !context::receipt_context_current(
            &c,
            first.receipt.revision_id.as_str(),
            Some(&p),
            deadline()
        )
        .unwrap()
    );
    assert!(
        !context::receipt_context_current(
            &c,
            second.receipt.revision_id.as_str(),
            Some(&denied(&p, "plain")),
            deadline()
        )
        .unwrap()
    );
    let mut changed = p.clone();
    changed.policy_epoch = PolicyEpoch::new(2).unwrap();
    assert!(
        !context::receipt_context_current(
            &c,
            second.receipt.revision_id.as_str(),
            Some(&changed),
            deadline()
        )
        .unwrap()
    );
    c.execute("UPDATE catalog_meta SET catalog_incarnation='restored'", [])
        .unwrap();
    assert!(
        !context::receipt_context_current(
            &c,
            second.receipt.revision_id.as_str(),
            Some(&p),
            deadline()
        )
        .unwrap()
    );
}
#[test]
fn partial_source_context_schema_is_refused_without_repair_or_version_reset() {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE source_publication_contexts(revision_id TEXT); PRAGMA user_version=21; BEGIN IMMEDIATE;").unwrap();
    assert!(context::create_schema(&c).is_err());
    assert_eq!(scalar(&c, "PRAGMA user_version"), 21);
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='source_dependencies'"
        ),
        0
    );
    c.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn crossed_context_head_and_unknown_transition_fail_closed_in_read_and_gc() {
    let c = schema();
    let provider = SearchProvider::parse("antigravity").unwrap();
    let p = policy(provider);
    let first = observe("first", 1, provider);
    let second = observe("second", 2, provider);
    publish(
        &c,
        &first,
        &batch(&first, Some("first"), "native"),
        &SourcePublicationContext::default(),
        &p,
    );
    publish(
        &c,
        &second,
        &batch(&second, Some("second"), "native"),
        &SourcePublicationContext::default(),
        &p,
    );
    c.execute(
        "UPDATE source_context_heads SET revision_id=?1 WHERE source_id='first'",
        [second.revision_id.as_str()],
    )
    .unwrap();
    assert!(context::source_read_eligible(&c, "first").is_err());
    let dependencies = history(&c);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(prune_in_tx(&c, &dependencies, &[], HistoryLimits::default(), deadline()).is_err());
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_revision_receipts"),
        2
    );
    c.execute_batch("ROLLBACK").unwrap();
    let c = schema();
    let selected = observe("db", 1, provider);
    publish(
        &c,
        &selected,
        &batch(&selected, Some("original"), "native"),
        &authority(key(provider), None),
        &p,
    );
    c.execute_batch("DROP TRIGGER source_authority_transition_immutable; PRAGMA ignore_check_constraints=ON; UPDATE source_authority_transitions SET kind='future';").unwrap();
    assert!(context::source_read_eligible(&c, "db").is_err());
    assert!(context::authority_prior(&c, &key(provider), &p, deadline()).is_err());
    let dependencies = history(&c);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(prune_in_tx(&c, &dependencies, &[], HistoryLimits::default(), deadline()).is_err());
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn authority_transition_receipts_outlive_history_tail_and_independent_surfaces() {
    let c = schema();
    let provider = SearchProvider::parse("antigravity").unwrap();
    let p = policy(provider);
    let k = key(provider);
    let first = observe("db", 1, provider);
    let initial = publish(
        &c,
        &first,
        &batch(&first, Some("db"), "native"),
        &authority(k.clone(), None),
        &p,
    );
    let prior = context::authority_prior(&c, &k, &p, deadline())
        .unwrap()
        .unwrap();
    let preferred = observe("full", 2, provider);
    publish(
        &c,
        &preferred,
        &batch(&preferred, Some("preferred"), "native"),
        &authority(k.clone(), Some(prior)),
        &p,
    );
    for seq in 3..=7 {
        let prior = context::authority_prior(&c, &k, &p, deadline())
            .unwrap()
            .unwrap();
        let observed = observe("full", seq, provider);
        publish(
            &c,
            &observed,
            &batch(&observed, Some("preferred"), "native"),
            &authority(k.clone(), Some(prior)),
            &p,
        );
    }
    let mut separate_key = k.clone();
    separate_key.surface_id = cid("independent-installation");
    separate_key.surface_identity = cid("independent-physical-surface");
    let separate = observe("independent", 8, provider);
    publish(
        &c,
        &separate,
        &batch(&separate, Some("independent"), "native"),
        &authority(separate_key.clone(), None),
        &p,
    );
    assert!(context::source_read_eligible(&c, "full").unwrap());
    assert!(context::source_read_eligible(&c, "independent").unwrap());
    let dependencies = history(&c);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let retained =
        prune_in_tx(&c, &dependencies, &[], HistoryLimits::default(), deadline()).unwrap();
    assert!(retained.counts.receipts_deleted > 0);
    assert_eq!(
        managed_receipt_test(&c, initial.receipt.revision_id.as_str()),
        initial.receipt
    );
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_authority_transitions"),
        3
    );
    foreign_keys_valid(&c);
    c.execute_batch("COMMIT").unwrap();
    assert!(
        context::authority_prior(&c, &k, &p, deadline())
            .unwrap()
            .is_some()
    );
    assert!(
        context::authority_prior(&c, &separate_key, &p, deadline())
            .unwrap()
            .is_some()
    );
}
#[test]
fn contextual_history_overflow_and_expired_publish_deadline_never_delete_or_publish() {
    let c = schema();
    let provider = SearchProvider::parse("workbuddy").unwrap();
    let p = policy(provider);
    let meta = observe("metadata", 1, provider);
    let published = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let original = observe("transcript", 1, provider);
    let ctx = dependency(&meta, published.receipt, LifecycleState::ActiveLocal);
    publish(
        &c,
        &original,
        &batch(&original, Some("original"), "native"),
        &ctx,
        &p,
    );
    let dependencies = history(&c);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let limits = HistoryLimits {
        max_dependencies: 1,
        ..HistoryLimits::default()
    };
    assert!(prune_in_tx(&c, &dependencies, &[], limits, deadline()).is_err());
    let next = observe("new", 2, provider);
    assert!(
        context::publish_source_with_context_in_tx(
            &c,
            &batch(&next, Some("new"), "native"),
            &next,
            &SourcePublicationContext::default(),
            &p,
            2,
            Instant::now()
        )
        .is_err()
    );
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_revision_receipts"),
        2
    );
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_bindings WHERE source_id='new'"
        ),
        0
    );
    c.execute_batch("ROLLBACK").unwrap();
}
#[test]
fn dependency_gc_orders_obsolete_context_edges_before_metadata_deletion() {
    let c = schema();
    let provider = SearchProvider::parse("workbuddy").unwrap();
    let p = policy(provider);
    let meta = observe("metadata", 1, provider);
    let m = publish(
        &c,
        &meta,
        &batch(&meta, None, ""),
        &SourcePublicationContext::default(),
        &p,
    );
    let original = observe("transcript", 1, provider);
    publish(
        &c,
        &original,
        &batch(&original, Some("unchanged"), "native"),
        &dependency(&meta, m.receipt, LifecycleState::ActiveLocal),
        &p,
    );
    let changed = observe("transcript", 2, provider);
    // A text-only rewrite still retains unchanged session/resume facts from
    // revision1, which must pin its receipt. A complete empty replacement
    // retires those facts too, making this a real obsolete-context case.
    publish(
        &c,
        &changed,
        &batch(&changed, None, ""),
        &unresolved("native"),
        &p,
    );
    for seq in 3..=6 {
        let meta = observe("metadata", seq, provider);
        publish(
            &c,
            &meta,
            &batch(&meta, None, ""),
            &SourcePublicationContext::default(),
            &p,
        );
        let original = observe("transcript", seq, provider);
        publish(
            &c,
            &original,
            &batch(&original, None, ""),
            &unresolved("native"),
            &p,
        );
    }
    for _ in 0..4 {
        let dependencies = history(&c);
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        prune_in_tx(&c, &dependencies, &[], HistoryLimits::default(), deadline()).unwrap();
        foreign_keys_valid(&c);
        c.execute_batch("COMMIT").unwrap();
    }
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM source_revision_receipts WHERE revision_id='revision-transcript-1'"
        ),
        0
    );
    assert!(context::source_read_eligible(&c, "transcript").unwrap());
}

/// Review 4.3.4 #2: every observation stores a publication context, so the
/// table grows with history. Retention must bound the LIVE context inventory,
/// not the total, or GC fails forever exactly when cleanup is needed.
#[test]
fn obsolete_context_history_above_live_bound_still_prunes_in_bounded_batches() {
    for batch_rows in [1, 2] {
        prune_obsolete_context_history(batch_rows);
    }
}

/// A one-row batch would select a still-referenced metadata receipt ahead of
/// its owner forever. Each batch must instead retire an unreferenced receipt.
fn prune_obsolete_context_history(batch_rows: usize) {
    let c = schema();
    let provider = SearchProvider::parse("workbuddy").unwrap();
    let p = policy(provider);
    for seq in 1..=8 {
        let meta = observe("metadata", seq, provider);
        let m = publish(
            &c,
            &meta,
            &batch(&meta, None, ""),
            &SourcePublicationContext::default(),
            &p,
        );
        let original = observe("transcript", seq, provider);
        publish(
            &c,
            &original,
            &batch(&original, Some(&format!("revision {seq}")), "native"),
            &dependency(&meta, m.receipt, LifecycleState::ActiveLocal),
            &p,
        );
    }
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_publication_contexts"),
        16
    );
    // The total exceeds this bound, which used to refuse every batch.
    let limits = HistoryLimits {
        receipt_tail_per_source: 1,
        batch_rows,
        max_dependencies: 8,
        ..HistoryLimits::default()
    };
    let mut batches = 0;
    loop {
        let dependencies = history(&c);
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        let pruned = prune_in_tx(&c, &dependencies, &[], limits, deadline())
            .unwrap_or_else(|error| panic!("batch {batches}/{batch_rows} refused: {error:?}"));
        assert!(pruned.counts.receipts_deleted <= batch_rows as u64);
        foreign_keys_valid(&c);
        c.execute_batch("COMMIT").unwrap();
        batches += 1;
        if !pruned.has_more {
            break;
        }
        assert!(
            pruned.counts.receipts_deleted > 0,
            "a pending {batch_rows}-row batch must make progress"
        );
        assert!(batches < 32, "bounded retention stopped converging");
    }
    assert!(batches > 1);
    let survivors: Vec<String> = c
        .prepare("SELECT revision_id FROM source_revision_receipts ORDER BY revision_id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    // Each source keeps its newest observation plus revision 1, which still
    // owns unchanged content: the metadata source's empty content set and
    // the transcript's unchanged session/resume entity rows. Every obsolete
    // middle revision and its publication context is gone.
    assert_eq!(
        survivors,
        [
            "revision-metadata-1",
            "revision-metadata-8",
            "revision-transcript-1",
            "revision-transcript-8",
        ]
    );
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_publication_contexts"),
        4
    );
    assert!(context::source_read_eligible(&c, "transcript").unwrap());
    assert!(
        context::receipt_context_current(&c, "revision-transcript-8", Some(&p), deadline())
            .unwrap()
    );
}

/// An obsolete context is not a retention root, but retirement still
/// validates it. A corrupt old row refuses cleanup instead of vanishing.
#[test]
fn corrupt_obsolete_context_refuses_retirement_instead_of_vanishing() {
    let c = schema();
    let provider = SearchProvider::parse("workbuddy").unwrap();
    let p = policy(provider);
    for seq in 1..=4 {
        let original = observe("transcript", seq, provider);
        publish(
            &c,
            &original,
            &batch(&original, Some(&format!("revision {seq}")), "native"),
            &unresolved("native"),
            &p,
        );
    }
    // Revision 1 still owns unchanged content and revision 4 is the head.
    // Damage an obsolete middle context without removing the schema guard;
    // only retirement validation should encounter the wrong digest.
    let raw = context::context_manifest(&unresolved("native")).unwrap();
    c.execute(
        "DELETE FROM source_publication_contexts WHERE revision_id='revision-transcript-2'",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO source_publication_contexts(revision_id,source_id,manifest,context_digest,dependency_count,authority_id) VALUES('revision-transcript-2','transcript',?1,?2,1,NULL)",
        params![raw, "0".repeat(64)],
    )
    .unwrap();
    c.execute(
        "INSERT INTO source_dependencies(owner_revision_id,ordinal,metadata_source_id,metadata_revision_id,resolution) VALUES('revision-transcript-2',0,NULL,NULL,'unresolved')",
        [],
    )
    .unwrap();
    foreign_keys_valid(&c);
    let limits = HistoryLimits {
        receipt_tail_per_source: 1,
        ..HistoryLimits::default()
    };
    let dependencies = history(&c);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        prune_in_tx(&c, &dependencies, &[], limits, deadline()),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_publication_contexts"),
        4
    );
    assert_eq!(
        scalar(&c, "SELECT COUNT(*) FROM source_revision_receipts"),
        4
    );
    c.execute_batch("ROLLBACK").unwrap();
}

struct FacadeFixture {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
    catalog: std::path::PathBuf,
    surface: CanonicalLocator,
    control: SqliteControlStore,
    lock: agent_session_grep_adapters_sqlite::managed_locks::ExclusiveGuard,
    selection: Selection,
    cycle: ObservationCycle,
    provider: SearchProvider,
}
impl FacadeFixture {
    fn new(provider: SearchProvider) -> Self {
        use agent_session_grep_adapters_sqlite::managed_locks::{ExclusiveGuard, LockKind};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owned-private");
        let catalog = root.join("catalog.db");
        let surface = CanonicalLocator::from_path(temp.path()).unwrap();
        let control =
            SqliteControlStore::create(&root, &cid("installation"), DesiredUpdates::Running)
                .unwrap();
        let selection = control
            .add_selection(
                control.status().unwrap().policy.control_seq,
                SelectionRequest {
                    region: ScopeRegion {
                        provider,
                        locator: surface.clone(),
                        kind: RootKind::Root,
                    },
                    root_identity: Some(cid("physical-root")),
                    now_ms: 1,
                },
            )
            .unwrap()
            .value;
        let lock = ExclusiveGuard::try_acquire(&root, LockKind::Background).unwrap();
        let cycle = {
            let worker = control.bind_worker(&lock, cid("boot")).unwrap();
            control
                .register_worker(control.status().unwrap().policy.control_seq, &worker, 1, 1)
                .unwrap();
            let queued = control
                .queue_cycle(
                    control.status().unwrap().policy.control_seq,
                    vec![SelectionRevision {
                        selection_id: selection.id.clone(),
                        revision: selection.revision,
                        root_identity: cid("physical-root"),
                    }],
                )
                .unwrap()
                .value;
            let cycle = match queued {
                CycleAdmission::Queued(c) => c,
                _ => panic!("synthetic cycle was not admitted"),
            };
            control
                .start_cycle(
                    control.status().unwrap().policy.control_seq,
                    &worker,
                    cycle.token.cycle_seq,
                    2,
                )
                .unwrap()
                .value
        };
        Self {
            _temp: temp,
            root,
            catalog,
            surface,
            control,
            lock,
            selection,
            cycle,
            provider,
        }
    }
    fn observation(&self, name: &str, revision: &str) -> SourceObservation {
        SourceObservation {
            binding: SourceBinding {
                source_id: SourceId::parse(name).unwrap(),
                source_path: self._temp.path().join(name).to_str().unwrap().into(),
                provider: self.provider,
                namespace_id: None,
                root_identity: "physical-root".into(),
            },
            revision_id: RevisionId::parse(revision).unwrap(),
            revision_digest: "same-full-digest".into(),
            parser_version: 1,
            state: ObservationState::Complete,
            cycle_seq: self.cycle.token.cycle_seq.get(),
            worker_boot_id: "boot".into(),
            catalog_incarnation: "incarnation".into(),
            policy_epoch: self.cycle.policy_epoch.get(),
            started_control_seq: self.cycle.started_control_seq.unwrap().get(),
            observed_at_ms: 3,
            committed_at_ms: 4,
            selections: vec![SelectionProof {
                selection_id: self.selection.id.as_str().into(),
                selection_revision: self.selection.revision.get(),
                root_identity: "physical-root".into(),
            }],
            repositories: Vec::new(),
        }
    }
    fn scalar(&self, sql: &str) -> i64 {
        scalar(&Connection::open(&self.catalog).unwrap(), sql)
    }
}
#[test]
fn facade_context_manifest_noop_pause_and_currentness_use_real_control_and_outbox() {
    let f = FacadeFixture::new(SearchProvider::parse("workbuddy").unwrap());
    let store = ManagedStore::create(&f.catalog, &f.control, cid("incarnation"), 1).unwrap();
    let worker = f.control.bind_worker(&f.lock, cid("boot")).unwrap();
    let mut observation = f.observation("transcript", "facade-first");
    let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
        &observation.binding.source_path,
        f.provider.as_str(),
    );
    let namespace = store
        .reserve_namespace(&f.control, &observation, &worker, &legacy)
        .unwrap();
    observation.binding.namespace_id = Some(namespace.namespace_id.clone());
    let mut b = batch(&observation, Some("original facade evidence"), "native");
    // This original already has canonical identity and does not invent a native
    // session pairing; unresolved metadata carries the independent typed key.
    b.resume_claims.clear();
    let ctx = unresolved("native");
    let published = store
        .commit_source_with_context(&f.control, &worker, &b, &observation, &ctx, deadline())
        .unwrap();
    assert!(published.content_changed);
    assert!(
        !store
            .source_current(&published.receipt, &f.control, deadline())
            .unwrap()
    );
    assert_eq!(
        store
            .publication_context(&f.control, &published.receipt, deadline())
            .unwrap(),
        ctx
    );
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM index_batches WHERE state='activated'"),
        1
    );
    let c = Connection::open(&f.catalog).unwrap();
    let stored: Vec<u8> = c
        .query_row(
            "SELECT manifest FROM source_publication_contexts",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, context::context_manifest(&ctx).unwrap());
    let (outbox, operation): (String, String) = c
        .query_row(
            "SELECT source_replacements_json,operation_digest FROM index_batches",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let declaration: serde_json::Value = serde_json::from_str(&outbox).unwrap();
    assert_eq!(declaration[0]["format"], "asg.managed-observation/v1");
    assert_eq!(declaration[0]["digest"].as_str(), Some(operation.as_str()));
    assert_eq!(operation.len(), 64);
    drop(c);
    let mut next = observation.clone();
    next.revision_id = RevisionId::parse("facade-noop").unwrap();
    next.observed_at_ms = 5;
    next.committed_at_ms = 6;
    let noop = store
        .commit_source_with_context(&f.control, &worker, &b, &next, &ctx, deadline())
        .unwrap();
    assert!(!noop.content_changed);
    assert_eq!(
        noop.receipt.committed_generation,
        published.receipt.committed_generation
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM index_batches"), 1);
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM source_publication_contexts"),
        2
    );
    assert_eq!(
        store
            .publication_context(&f.control, &noop.receipt, deadline())
            .unwrap(),
        ctx
    );
    f.control
        .set_desired_updates(
            f.control.status().unwrap().policy.control_seq,
            DesiredUpdates::Paused,
        )
        .unwrap();
    let hit_count = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                let summary = read
                    .contributing_freshness(std::slice::from_ref(&observation.binding.source_id))?;
                assert_eq!(summary.verified_sources, 0);
                assert!(summary.pending_sources > 0);
                Ok(read
                    .query_lexical("facade", &ProjectionQuery::default(), 5)?
                    .hits
                    .len())
            },
        )
        .unwrap();
    assert_eq!(hit_count, 1);
    next.revision_id = RevisionId::parse("paused-refused").unwrap();
    assert!(
        store
            .commit_source_with_context(&f.control, &worker, &b, &next, &ctx, deadline())
            .is_err()
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM source_revision_receipts"), 2);
}
#[test]
fn facade_real_context_apply_failure_leaves_no_partial_source_or_authority() {
    let f = FacadeFixture::new(SearchProvider::parse("workbuddy").unwrap());
    let store = ManagedStore::create(&f.catalog, &f.control, cid("incarnation"), 1).unwrap();
    let worker = f.control.bind_worker(&f.lock, cid("boot")).unwrap();
    let mut observation = f.observation("transcript", "failure-first");
    let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
        &observation.binding.source_path,
        f.provider.as_str(),
    );
    let namespace = store
        .reserve_namespace(&f.control, &observation, &worker, &legacy)
        .unwrap();
    observation.binding.namespace_id = Some(namespace.namespace_id);
    let mut b = batch(&observation, Some("failure original"), "native");
    b.resume_claims.clear();
    let c = Connection::open(&f.catalog).unwrap();
    c.execute_batch("CREATE TRIGGER synthetic_real_context_failure BEFORE INSERT ON source_dependencies WHEN EXISTS(SELECT 1 FROM index_batches WHERE state='building') BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    assert!(
        store
            .commit_source_with_context(
                &f.control,
                &worker,
                &b,
                &observation,
                &unresolved("native"),
                deadline()
            )
            .is_err()
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM source_bindings"), 0);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM source_revision_receipts"), 0);
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM source_publication_contexts"),
        0
    );
    assert_eq!(f.scalar("SELECT active_generation FROM store_metadata"), 0);
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM index_batches WHERE state='building'"),
        1
    );
    c.execute_batch("DROP TRIGGER synthetic_real_context_failure")
        .unwrap();
    drop(c);
    drop(store);
    let store = ManagedStore::open_for_write(&f.catalog, &f.control).unwrap();
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM index_batches WHERE state='aborted'"),
        1
    );
    // The failed content transaction never committed a namespace assignment.
    // Re-stage that reservation after restart; do not reuse ephemeral authority.
    let namespace = store
        .reserve_namespace(&f.control, &observation, &worker, &legacy)
        .unwrap();
    observation.binding.namespace_id = Some(namespace.namespace_id);
    store
        .commit_source_with_context(
            &f.control,
            &worker,
            &b,
            &observation,
            &unresolved("native"),
            deadline(),
        )
        .unwrap();
    assert_eq!(f.scalar("SELECT COUNT(*) FROM source_revision_receipts"), 1);
}

fn scoped_batch(o: &SourceObservation, text: &str, session: &StableId) -> SourceBatch {
    let mut b = batch(o, Some(text), "native");
    let old = b.placements[0].session_id.clone();
    for (id, _, _) in &mut b.entries {
        if id == &old {
            *id = session.clone();
        }
    }
    let placement = &b.placements[0];
    b.placements[0] = MessagePlacement::new(
        session.clone(),
        placement.source_document_id.clone(),
        placement.message_id.clone(),
        0,
        false,
        None,
    );
    b.resume_claims[0].session_id = session.as_str().into();
    b
}
#[test]
fn facade_verified_surface_namespace_is_shared_without_rekeying_and_binds_authority() {
    let f = FacadeFixture::new(SearchProvider::parse("antigravity").unwrap());
    let store = ManagedStore::create(&f.catalog, &f.control, cid("incarnation"), 1).unwrap();
    let worker = f.control.bind_worker(&f.lock, cid("boot")).unwrap();
    let mut old = f.observation("db", "surface-db-first");
    old.binding.source_path = f
        ._temp
        .path()
        .join("conversations")
        .join("db.sqlite")
        .to_str()
        .unwrap()
        .into();
    let mut full = f.observation("full", "surface-full-first");
    full.binding.source_path = f
        ._temp
        .path()
        .join("brain")
        .join("native")
        .join("logs")
        .join("trace.jsonl")
        .to_str()
        .unwrap()
        .into();
    let first = store
        .reserve_namespace_for_surface(
            &f.control,
            &old,
            &worker,
            &f.surface,
            &cid("physical-root"),
            deadline(),
        )
        .unwrap();
    let second = store
        .reserve_namespace_for_surface(
            &f.control,
            &full,
            &worker,
            &f.surface,
            &cid("physical-root"),
            deadline(),
        )
        .unwrap();
    assert_eq!(first.namespace_id, second.namespace_id);
    assert_eq!(first.input, second.input);
    old.binding.namespace_id = Some(first.namespace_id.clone());
    full.binding.namespace_id = Some(second.namespace_id.clone());
    let canonical = StableId::native_session_scoped(
        &agent_session_grep_domain::SessionIdentityNamespace {
            provider_id: f.provider.as_str(),
            installation_namespace: &first.input,
        },
        "native",
    );
    let key = SourceAuthorityKey {
        provider: f.provider,
        surface_id: cid("provider-surface"),
        surface_root: f.surface.clone(),
        surface_identity: cid("physical-root"),
        native_session: NativeSessionId::parse("native").unwrap(),
        session_id: canonical.clone(),
    };
    let original = store
        .commit_source_with_context(
            &f.control,
            &worker,
            &scoped_batch(&old, "db original", &canonical),
            &old,
            &authority(key.clone(), None),
            deadline(),
        )
        .unwrap();
    let prior = store
        .authority_prior(&f.control, &key, deadline())
        .unwrap()
        .unwrap();
    assert_eq!(prior.receipt, original.receipt);
    let switched = store
        .commit_source_with_context(
            &f.control,
            &worker,
            &scoped_batch(&full, "full original", &canonical),
            &full,
            &authority(key.clone(), Some(prior)),
            deadline(),
        )
        .unwrap();
    assert!(switched.destructive);
    let sources = store.background_sources(&f.control).unwrap();
    assert!(
        sources
            .iter()
            .find(|s| s.binding.source_id == old.binding.source_id)
            .unwrap()
            .superseded
    );
    assert!(
        !sources
            .iter()
            .find(|s| s.binding.source_id == full.binding.source_id)
            .unwrap()
            .superseded
    );
    assert!(
        !store
            .source_current(&original.receipt, &f.control, deadline())
            .unwrap()
    );
    assert!(
        store
            .source_current(&switched.receipt, &f.control, deadline())
            .unwrap()
    );
    let mut other = f.observation("other", "surface-other");
    other.binding.source_path = f
        ._temp
        .path()
        .join("brain")
        .join("other")
        .join("logs")
        .join("trace.jsonl")
        .to_str()
        .unwrap()
        .into();
    assert!(
        store
            .reserve_namespace_for_surface(
                &f.control,
                &other,
                &worker,
                &f.surface,
                &cid("changed-physical-root"),
                deadline()
            )
            .is_err()
    );
    let same = store
        .reserve_namespace_for_surface(
            &f.control,
            &full,
            &worker,
            &f.surface,
            &cid("physical-root"),
            deadline(),
        )
        .unwrap();
    assert_eq!(same.namespace_id, first.namespace_id);
    assert_eq!(same.input, first.input);
    assert_eq!(f.scalar("SELECT COUNT(*) FROM installation_namespaces"), 1);
    assert!(f.root.join("catalog.db").exists());
    let hits = store
        .with_read(
            &f.control,
            RequestIntersection::Selected,
            deadline(),
            |read| {
                Ok(read
                    .query_lexical("original", &ProjectionQuery::default(), 5)?
                    .hits)
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].projection.message.text, "full original");
}

#[test]
fn facade_complete_discovery_respects_unresolved_context_and_original_expired_deadline() {
    let f = FacadeFixture::new(SearchProvider::parse("workbuddy").unwrap());
    let store = ManagedStore::create(&f.catalog, &f.control, cid("incarnation"), 1).unwrap();
    let worker = f.control.bind_worker(&f.lock, cid("boot")).unwrap();
    let selection = SelectionRevision {
        selection_id: f.selection.id.clone(),
        revision: f.selection.revision,
        root_identity: cid("physical-root"),
    };
    let mut observation = f.observation("transcript", "discovery-original");
    let legacy = agent_session_grep_application::relocation::legacy_installation_namespace(
        &observation.binding.source_path,
        f.provider.as_str(),
    );
    let namespace = store
        .reserve_namespace(&f.control, &observation, &worker, &legacy)
        .unwrap();
    observation.binding.namespace_id = Some(namespace.namespace_id);
    let mut b = batch(&observation, Some("permitted original"), "native");
    b.resume_claims.clear();
    store
        .commit_source_with_context(
            &f.control,
            &worker,
            &b,
            &observation,
            &unresolved("native"),
            deadline(),
        )
        .unwrap();
    store
        .begin_discovery_with_deadline(&f.control, &worker, &f.cycle, &selection, deadline())
        .unwrap();
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM discovery_receipts WHERE complete=0"),
        1
    );
    assert!(
        store
            .commit_discovery_with_deadline(
                &f.control,
                &worker,
                &f.cycle,
                &selection,
                std::slice::from_ref(&observation.binding.source_id),
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM discovery_receipts WHERE complete=1"),
        0
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM discovery_sources"), 0);
    assert!(
        store
            .begin_discovery_with_deadline(
                &f.control,
                &worker,
                &f.cycle,
                &selection,
                Instant::now()
            )
            .is_err()
    );
    assert!(
        store
            .commit_discovery_with_deadline(
                &f.control,
                &worker,
                &f.cycle,
                &selection,
                &[],
                Instant::now()
            )
            .is_err()
    );
    assert_eq!(f.scalar("SELECT COUNT(*) FROM discovery_receipts"), 1);
    let read_count = store
        .with_read(&f.control, RequestIntersection::Selected, deadline(), |r| {
            Ok(
                r.query_lexical("permitted", &ProjectionQuery::default(), 5)?
                    .hits
                    .len(),
            )
        })
        .unwrap();
    assert_eq!(read_count, 1);
}
#[test]
fn facade_discovery_sql_contention_does_not_extend_end_and_store_is_reusable() {
    let f = FacadeFixture::new(SearchProvider::Claude);
    let store = ManagedStore::create(&f.catalog, &f.control, cid("incarnation"), 1).unwrap();
    let worker = f.control.bind_worker(&f.lock, cid("boot")).unwrap();
    let selection = SelectionRevision {
        selection_id: f.selection.id.clone(),
        revision: f.selection.revision,
        root_identity: cid("physical-root"),
    };
    let external = Connection::open(&f.catalog).unwrap();
    external.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    let end = started + Duration::from_millis(40);
    assert!(matches!(
        store.begin_discovery_with_deadline(&f.control, &worker, &f.cycle, &selection, end),
        Err(PortError::WriterBusy(_))
    ));
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "catalog busy retry exceeded original bound"
    );
    external.execute_batch("ROLLBACK").unwrap();
    store
        .begin_discovery_with_deadline(&f.control, &worker, &f.cycle, &selection, deadline())
        .unwrap();
    store
        .commit_discovery_with_deadline(&f.control, &worker, &f.cycle, &selection, &[], deadline())
        .unwrap();
    assert_eq!(
        f.scalar("SELECT COUNT(*) FROM discovery_receipts WHERE complete=1"),
        1
    );
}
#[test]
fn missing_current_context_schema_is_refused_by_read_and_write_identity_without_creation() {
    let f = FacadeFixture::new(SearchProvider::Claude);
    drop(ManagedStore::create(&f.catalog, &f.control, cid("incarnation"), 1).unwrap());
    let c = Connection::open(&f.catalog).unwrap();
    c.execute_batch("DROP TABLE source_authority_tombstones;")
        .unwrap();
    let before = scalar(&c, "PRAGMA user_version");
    drop(c);
    assert!(ManagedStore::open(&f.catalog, &f.control).is_err());
    assert!(ManagedStore::open_for_write(&f.catalog, &f.control).is_err());
    let c = Connection::open(&f.catalog).unwrap();
    assert_eq!(scalar(&c, "PRAGMA user_version"), before);
    assert_eq!(
        scalar(
            &c,
            "SELECT COUNT(*) FROM sqlite_schema WHERE name='source_authority_tombstones'"
        ),
        0
    );
}
