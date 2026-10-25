//! Synthetic catalogs only: no source I/O, host configuration or real histories.
use agent_session_grep_adapters_sqlite::{SourceActivity, SourceBatch, SourceUsage, managed::*};
use agent_session_grep_application::{
    AppRequest, AppResponse, ContextLevel, ResponseBudget,
    managed::{ManagedApp, ManagedPartial, ManagedRequestContext, ManagedResponse},
};
use agent_session_grep_domain::{
    ContextPolicy, EvidenceSpan, IdKind, MessageEdge, MessagePlacement, MessageRelation, StableId,
    TokenSource, ToolActivity, ToolActivityActor, ToolActivityKind, ToolActivityStatus,
    UsageObservation,
};
use agent_session_grep_ports::{SearchProvider, SourceResumeClaim, managed::*};
use rusqlite::{Connection, params};
use std::time::{Duration, Instant};

fn id(kind: IdKind, value: &str) -> StableId {
    StableId::native_checked(kind, value).unwrap()
}
fn schema(conn: &Connection) {
    conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE store_metadata(singleton INTEGER PRIMARY KEY,active_generation INTEGER NOT NULL,projection_contract_version INTEGER NOT NULL DEFAULT 0,managed_mode INTEGER NOT NULL DEFAULT 0,destructive_epoch INTEGER NOT NULL DEFAULT 0); INSERT INTO store_metadata VALUES(1,0,0,0,0); CREATE TABLE catalog(id TEXT PRIMARY KEY,payload BLOB); BEGIN IMMEDIATE;").unwrap();
    create_schema(conn).unwrap();
    initialize_catalog_in_tx(conn, "synthetic-install", "synthetic-incarnation", 1).unwrap();
    conn.execute_batch("COMMIT").unwrap();
}
fn observation(source: &str, seq: i64) -> SourceObservation {
    SourceObservation {
        binding: SourceBinding {
            source_id: SourceId::parse(source).unwrap(),
            source_path: format!("synthetic-source-{source}"),
            provider: SearchProvider::Claude,
            namespace_id: None,
            root_identity: "synthetic-root".into(),
        },
        revision_id: RevisionId::parse(&format!("revision-{source}-{seq}")).unwrap(),
        revision_digest: format!("fingerprint-{seq}"),
        parser_version: 1,
        state: ObservationState::Complete,
        cycle_seq: seq,
        worker_boot_id: "synthetic-boot".into(),
        catalog_incarnation: "synthetic-incarnation".into(),
        policy_epoch: 1,
        started_control_seq: seq,
        observed_at_ms: seq,
        committed_at_ms: seq,
        selections: vec![SelectionProof {
            selection_id: "synthetic-selection".into(),
            selection_revision: 1,
            root_identity: "synthetic-root".into(),
        }],
        repositories: Vec::new(),
    }
}
fn batch(o: &SourceObservation, text: &str) -> SourceBatch {
    let message = id(IdKind::Message, "shared");
    let session = id(IdKind::Session, "shared");
    let document = id(
        IdKind::Document,
        &format!("document-{}", o.binding.source_id.as_str()),
    );
    SourceBatch {
        source_path:o.binding.source_path.clone(),
        entries:vec![
            (message.clone(),serde_json::to_vec(&serde_json::json!({"role":"user","text":text,"timestamp":"2026-10-17T01:00:00Z"})).unwrap(),text.into()),
            (session.clone(),serde_json::to_vec(&serde_json::json!({"documents":[document.as_str()]})).unwrap(),String::new()),
            (document.clone(),serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"synthetic-v1","fingerprint":o.revision_digest,"len":4096})).unwrap(),String::new()),
        ],placements:vec![MessagePlacement::new(session,document,message,0,false,None)],edges:Vec::new(),activities:Vec::new(),usage_events:Vec::new(),relation_complete:true,len_bytes:Some(4096),fingerprint:Some(o.revision_digest.clone()),provider_id:Some("claude-code".into()),resume_claims:Vec::new(),
    }
}
fn publish(conn: &Connection, batch: &SourceBatch, o: &SourceObservation) -> Publication {
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let base: i64 = conn
        .query_row("SELECT active_generation FROM store_metadata", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut result = publish_source_in_tx(conn, batch, o, base + 1).unwrap();
    conn.execute(
        "UPDATE store_metadata SET active_generation=?1",
        [result.required_generation],
    )
    .unwrap();
    finalize_publications_in_tx(conn, std::slice::from_mut(&mut result)).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    result
}
fn scope(allowed: &[&SourceObservation]) -> ReadScope {
    ReadScope {
        catalog_incarnation: "synthetic-incarnation".into(),
        policy_epoch: 1,
        allowed: allowed.iter().map(|o| o.binding.clone()).collect(),
    }
}
fn open_read<'a>(conn: &'a Connection, allowed: &[&SourceObservation]) -> ManagedRead<'a> {
    ManagedRead::begin(
        conn,
        &scope(allowed),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
}

#[test]
fn divergent_copy_cannot_match_or_supply_direct_text_after_revoke() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    publish(&conn, &batch(&a, "alpha"), &a);
    publish(&conn, &batch(&b, "alpha privateword"), &b);
    let read = open_read(&conn, &[&a]);
    let query = ProjectionQuery::default();
    assert!(
        read.query_lexical("privateword", &query, 10)
            .unwrap()
            .hits
            .is_empty()
    );
    let hits = read.query_lexical("alpha", &query, 10).unwrap().hits;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].projection.message.text, "alpha");
    assert_eq!(hits[0].projection.proof.source_id, a.binding.source_id);
    let direct = read
        .messages(&[id(IdKind::Message, "shared")], &query)
        .unwrap();
    assert_eq!(direct[0].as_ref().unwrap().message.text, "alpha");
    assert_eq!(
        direct[0].as_ref().unwrap().message.id,
        id(IdKind::Message, "shared")
    );
}

#[test]
fn partial_unstable_and_held_observations_preserve_every_visible_row() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    publish(&conn, &batch(&a, "old evidence"), &a);
    let before: (i64, String) = conn
        .query_row(
            "SELECT projection_rowid,projection_id FROM source_projections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    for (seq, state) in [
        (2, ObservationState::Incomplete),
        (3, ObservationState::Unstable),
        (4, ObservationState::RewritePending),
        (5, ObservationState::DeletionPending),
    ] {
        let mut o = observation("a", seq);
        o.state = state;
        let mut changed = batch(&o, "unpublishedword");
        if seq == 5 {
            changed.entries.clear();
            changed.placements.clear();
        }
        let result = publish(&conn, &changed, &o);
        assert!(!result.receipt.published);
        assert!(!result.content_changed);
        assert_eq!(result.destructive_epoch, 0);
        let current: (i64, String) = conn
            .query_row(
                "SELECT projection_rowid,projection_id FROM source_projections",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(current, before);
        let read = open_read(&conn, &[&a]);
        let progress = read.source_progress().unwrap();
        assert_eq!(progress[0].visible_revision.as_ref(), Some(&a.revision_id));
        assert!(!progress[0].last_attempt.as_ref().unwrap().published);
        assert!(
            read.query_lexical("unpublishedword", &ProjectionQuery::default(), 10)
                .unwrap()
                .hits
                .is_empty()
        );
        assert_eq!(
            read.messages(
                &[id(IdKind::Message, "shared")],
                &ProjectionQuery::default()
            )
            .unwrap()[0]
                .as_ref()
                .unwrap()
                .message
                .text,
            "old evidence"
        );
    }
    let mut empty = observation("empty", 1);
    empty.state = ObservationState::Incomplete;
    publish(&conn, &batch(&empty, "never published"), &empty);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM source_projections WHERE source_id='empty'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn no_op_observation_keeps_row_identity_and_generation_but_updates_receipt() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let first = observation("a", 1);
    let data = batch(&first, "alpha");
    publish(&conn, &data, &first);
    let before: (i64, String) = conn
        .query_row(
            "SELECT projection_rowid,projection_id FROM source_projections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut second = observation("a", 2);
    second.revision_digest = first.revision_digest.clone();
    let result = publish(&conn, &data, &second);
    assert!(!result.content_changed);
    assert_eq!(result.required_generation, 1);
    assert_eq!(result.destructive_epoch, 0);
    assert_eq!(result.receipt.committed_generation, Some(1));
    let after: (i64, String) = conn
        .query_row(
            "SELECT projection_rowid,projection_id FROM source_projections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, after);
    let heads: (String, String) = conn
        .query_row(
            "SELECT visible_revision_id,latest_receipt_id FROM source_heads",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        heads,
        (
            first.revision_id.as_str().into(),
            second.revision_id.as_str().into()
        )
    );
}

#[test]
fn metadata_conflict_never_matches_one_source_and_returns_another() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    publish(&conn, &batch(&a, "alpha"), &a);
    publish(&conn, &batch(&b, "betaword"), &b);
    let session = id(IdKind::Session, "shared");
    let both = open_read(&conn, &[&a, &b]);
    assert!(
        both.search_sessions("betaword", &ProjectionQuery::default(), 10)
            .unwrap()
            .is_empty()
    );
    let metadata = both
        .entities(
            EntityKind::Session,
            std::slice::from_ref(&session),
            &ProjectionQuery::default(),
        )
        .unwrap();
    assert!(matches!(&metadata[0].data,EntityData::Session(data) if data.title.is_none()));
    drop(both);
    let only_b = open_read(&conn, &[&b]);
    let hits = only_b
        .search_sessions("betaword", &ProjectionQuery::default(), 10)
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].proof.source_id, b.binding.source_id);
    assert!(
        matches!(&hits[0].data,EntityData::Session(data) if data.title.as_deref()==Some("betaword"))
    );
}

#[test]
fn provider_time_and_tool_filters_cannot_be_bypassed_by_container_reads() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let mut data = batch(&a, "alpha");
    let second = id(IdKind::Message, "second");
    let p = data.placements[0].clone();
    data.entries.push((second.clone(),serde_json::to_vec(&serde_json::json!({"role":"assistant","text":"other","timestamp":"2026-10-17T02:00:00Z"})).unwrap(),"other".into()));
    data.placements.push(MessagePlacement::new(
        p.session_id.clone(),
        p.source_document_id.clone(),
        second.clone(),
        1,
        false,
        None,
    ));
    data.usage_events.push(SourceUsage {
        session_id: p.session_id.clone(),
        message_id: Some(second),
        usage: UsageObservation {
            input_tokens: 99,
            output_tokens: 1,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            token_source: TokenSource::Observed,
        },
    });
    publish(&conn, &data, &a);
    let read = open_read(&conn, &[&a]);
    let mut query = ProjectionQuery::default();
    query.filters.until = Some(agent_session_grep_ports::SearchInstant {
        unix_seconds: 1792198800,
        nanosecond: 1,
    });
    assert_eq!(
        read.query_lexical("alpha", &query, 10).unwrap().hits.len(),
        1
    );
    assert!(
        read.entities(
            EntityKind::Usage,
            std::slice::from_ref(&p.session_id),
            &query
        )
        .unwrap()
        .is_empty()
    );
    query.filters = Default::default();
    query.filters.providers = vec![SearchProvider::Codex];
    assert!(
        read.entities(
            EntityKind::Session,
            std::slice::from_ref(&p.session_id),
            &query
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        read.search_sessions("alpha", &query, 10)
            .unwrap()
            .is_empty()
    );
    query.filters = Default::default();
    query.facets.tool_name = Some("unobserved-tool".into());
    assert!(
        read.query_lexical("alpha", &query, 10)
            .unwrap()
            .hits
            .is_empty()
    );
    assert!(
        read.entities(EntityKind::Session, &[p.session_id], &query)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn project_claim_occurrence_disagreement_fails_closed() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let mut a = observation("a", 1);
    let mut data = batch(&a, "alpha");
    let session = id(IdKind::Session, "shared");
    data.resume_claims.push(SourceResumeClaim {
        provider_id: "claude-code".into(),
        session_id: session.as_str().into(),
        provider_session_id: Some("synthetic-native".into()),
        provider_session_id_state: "resolved".into(),
        original_working_directory: Some("synthetic-workspace".into()),
        original_working_directory_state: "resolved".into(),
        pair_observed: true,
    });
    a.repositories.push(RepositoryClaim {
        session_id: session.clone(),
        slug: "example.test/team/allowed".into(),
    });
    publish(&conn, &data, &a);
    conn.execute(
        "UPDATE source_occurrences SET project_id='example.test/team/different'",
        [],
    )
    .unwrap();
    let read = open_read(&conn, &[&a]);
    let mut query = ProjectionQuery::default();
    query.filters.repo = Some("example.test/team/allowed".into());
    assert!(
        read.query_lexical("alpha", &query, 10)
            .unwrap()
            .hits
            .is_empty()
    );
    assert!(
        read.entities(EntityKind::Session, &[session], &query)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn stale_binding_incarnation_and_deadline_are_errors_without_legacy_fallback() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    publish(&conn, &batch(&a, "alpha"), &a);
    let mut policy = scope(&[&a]);
    policy.allowed[0].root_identity = "changed-root".into();
    assert!(ManagedRead::begin(&conn, &policy, Instant::now() + Duration::from_secs(1)).is_err());
    assert!(conn.is_autocommit());
    policy = scope(&[&a]);
    policy.catalog_incarnation = "changed-incarnation".into();
    assert!(ManagedRead::begin(&conn, &policy, Instant::now() + Duration::from_secs(1)).is_err());
    assert!(ManagedRead::begin(&conn, &scope(&[&a]), Instant::now()).is_err());
    assert_eq!(
        open_read(&conn, &[&a])
            .query_lexical("alpha", &ProjectionQuery::default(), 1)
            .unwrap()
            .hits
            .len(),
        1
    );
}

#[test]
fn identical_copies_do_not_change_scoped_score_and_hidden_prefix_cannot_fill_limit() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    publish(&conn, &batch(&a, "alpha mcp.json workbench"), &a);
    let before = open_read(&conn, &[&a])
        .query_lexical("alpha", &ProjectionQuery::default(), 1)
        .unwrap()
        .hits[0]
        .score;
    let b = observation("b", 1);
    publish(&conn, &batch(&b, "alpha mcp.json workbench"), &b);
    let both = open_read(&conn, &[&a, &b])
        .query_lexical("alpha", &ProjectionQuery::default(), 1)
        .unwrap();
    assert_eq!(both.hits.len(), 1);
    assert_eq!(both.hits[0].score, before);
    assert_eq!(both.hits[0].claim_count, 2);
    let hidden = observation("hidden", 1);
    let mut many = batch(&hidden, "alpha distraction");
    let p = many.placements[0].clone();
    for index in 0..520 {
        let m = id(IdKind::Message, &format!("hidden-{index}"));
        many.entries.push((
            m.clone(),
            serde_json::to_vec(
                &serde_json::json!({"role":"user","text":"alpha distraction","timestamp":null}),
            )
            .unwrap(),
            "alpha distraction".into(),
        ));
        many.placements.push(MessagePlacement::new(
            p.session_id.clone(),
            p.source_document_id.clone(),
            m,
            index + 1,
            false,
            None,
        ));
    }
    publish(&conn, &many, &hidden);
    let permitted = open_read(&conn, &[&a]);
    for query in ["alpha", "mcp.json", "work*"] {
        let hits = permitted
            .query_lexical(query, &ProjectionQuery::default(), 1)
            .unwrap()
            .hits;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].projection.proof.source_id, a.binding.source_id);
    }
    assert_eq!(
        permitted
            .query_lexical("alpha", &ProjectionQuery::default(), 1)
            .unwrap()
            .hits[0]
            .score,
        before
    );
}

#[test]
fn typed_metadata_tools_usage_and_native_claims_remain_source_scoped() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let mut a = observation("a", 1);
    let mut data = batch(&a, "alpha");
    let session = id(IdKind::Session, "shared");
    let message = id(IdKind::Message, "shared");
    data.resume_claims.push(SourceResumeClaim {
        provider_id: "claude-code".into(),
        session_id: session.as_str().into(),
        provider_session_id: Some("synthetic-native".into()),
        provider_session_id_state: "resolved".into(),
        original_working_directory: Some("synthetic-private-directory".into()),
        original_working_directory_state: "resolved".into(),
        pair_observed: true,
    });
    a.repositories.push(RepositoryClaim {
        session_id: session.clone(),
        slug: "example.test/team/repo".into(),
    });
    data.activities.push(SourceActivity {
        message_id: message.clone(),
        activity: ToolActivity {
            kind: ToolActivityKind::File,
            actor: ToolActivityActor::Main,
            name: "Read".into(),
            target: Some("synthetic-file".into()),
            status: ToolActivityStatus::Success,
        },
    });
    data.usage_events.push(SourceUsage {
        session_id: session.clone(),
        message_id: Some(message.clone()),
        usage: UsageObservation {
            input_tokens: 7,
            output_tokens: 3,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            token_source: TokenSource::Observed,
        },
    });
    publish(&conn, &data, &a);
    let read = open_read(&conn, &[&a]);
    let mut query = ProjectionQuery::default();
    query.filters.repo = Some("example.test/team/repo".into());
    assert_eq!(
        read.messages(std::slice::from_ref(&message), &query)
            .unwrap()[0]
            .as_ref()
            .unwrap()
            .occurrence
            .as_ref()
            .unwrap()
            .data
            .project_id,
        query.filters.repo
    );
    assert_eq!(
        read.entities(EntityKind::Tool, &[message], &query)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        read.entities(EntityKind::Usage, std::slice::from_ref(&session), &query)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        read.entities(EntityKind::Resume, std::slice::from_ref(&session), &query)
            .unwrap()
            .len(),
        1
    );
    assert!(
        read.search_sessions("synthetic-native", &ProjectionQuery::default(), 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        read.search_sessions(
            "synthetic-private-directory",
            &ProjectionQuery::default(),
            10
        )
        .unwrap()
        .is_empty()
    );
    drop(read);
    let forbidden = open_read(&conn, &[]);
    assert!(
        forbidden
            .entities(EntityKind::Resume, &[session], &ProjectionQuery::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn metadata_only_containers_and_legacy_migration_have_no_fallback() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let legacy = id(IdKind::Message, "legacy");
    conn.execute(
        "INSERT INTO catalog VALUES(?1,?2)",
        params![
            legacy.as_str(),
            br#"{"role":"user","text":"legacyword"}"#.to_vec()
        ],
    )
    .unwrap();
    let o = observation("a", 1);
    let mut data = batch(&o, "alpha");
    data.entries
        .retain(|(id, _, _)| id.kind() != IdKind::Message);
    data.placements.clear();
    data.entries.iter_mut().find(|(id,_,_)|id.kind()==IdKind::Session).unwrap().1=serde_json::to_vec(&serde_json::json!({"title":"metadataword","documents":[id(IdKind::Document,"document-a").as_str()]})).unwrap();
    publish(&conn, &data, &o);
    let read = open_read(&conn, &[&o]);
    assert!(
        read.messages(&[legacy], &ProjectionQuery::default())
            .unwrap()[0]
            .is_none()
    );
    assert!(
        read.query_lexical("legacyword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .is_empty()
    );
    assert_eq!(
        read.search_sessions("metadataword", &ProjectionQuery::default(), 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        read.entities(
            EntityKind::Document,
            &[id(IdKind::Document, "document-a")],
            &ProjectionQuery::default()
        )
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn wal_snapshot_remains_stable_while_source_is_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("catalog.db");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    schema(&writer);
    let a = observation("a", 1);
    publish(&writer, &batch(&a, "oldword"), &a);
    let reader = Connection::open(&path).unwrap();
    let pinned = open_read(&reader, &[&a]);
    let next = observation("a", 2);
    let result = publish(&writer, &batch(&next, "newword"), &next);
    assert!(result.destructive);
    assert_eq!(pinned.snapshot().generation, 1);
    assert_eq!(
        pinned
            .messages(
                &[id(IdKind::Message, "shared")],
                &ProjectionQuery::default()
            )
            .unwrap()[0]
            .as_ref()
            .unwrap()
            .message
            .text,
        "oldword"
    );
    assert!(
        pinned
            .query_lexical("newword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .is_empty()
    );
    let context = managed_request(
        &pinned,
        ProjectionQuery::default(),
        ResponseBudget::default(),
        context_request(ContextPolicy::Full, ContextLevel::Raw),
    )
    .unwrap();
    assert!(
        matches!(context.response,AppResponse::Context{messages,generation:1,..} if messages[0].payload["text"]=="oldword")
    );
    let contexts = pinned
        .message_contexts(
            &id(IdKind::Message, "shared"),
            &ProjectionQuery::default(),
            10,
            10,
        )
        .unwrap();
    assert_eq!(
        contexts.candidates[0].occurrences[0]
            .proof
            .revision
            .revision_id,
        a.revision_id
    );
    drop(pinned);
    assert_eq!(
        open_read(&reader, &[&a])
            .query_lexical("newword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .len(),
        1
    );
}

#[test]
fn outer_rollback_and_failed_publication_leave_no_partial_content() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    conn.execute_batch("BEGIN").unwrap();
    publish_source_in_tx(&conn, &batch(&a, "rolledback"), &a, 1).unwrap();
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM source_projections", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let mut bad = batch(&a, "invalid");
    bad.placements[0].source_ordinal = 1;
    conn.execute_batch("BEGIN").unwrap();
    assert!(publish_source_in_tx(&conn, &bad, &a, 1).is_err());
    conn.execute_batch("COMMIT").unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM source_bindings", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn complete_empty_replacement_removes_only_its_source_and_cascades_stats() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    publish(&conn, &batch(&a, "alpha withdrawn"), &a);
    publish(&conn, &batch(&b, "alpha"), &b);
    let next = observation("a", 2);
    let mut empty = batch(&next, "");
    empty.entries.clear();
    empty.placements.clear();
    let result = publish(&conn, &empty, &next);
    assert!(result.destructive);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM source_projections WHERE source_id='a'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM projection_fts_stats", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let read = open_read(&conn, &[&a, &b]);
    assert!(
        read.query_lexical("withdrawn", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .is_empty()
    );
    let hits = read
        .query_lexical("alpha", &ProjectionQuery::default(), 10)
        .unwrap()
        .hits;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].projection.proof.source_id, b.binding.source_id);
}

#[test]
fn edges_never_disclose_parent_without_allowed_evidence() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let mut child = batch(&a, "child");
    let parent = id(IdKind::Message, "hidden-parent");
    child.edges.push(MessageEdge {
        child_placement_id: child.placements[0].id.clone(),
        parent_message_id: parent.clone(),
        parent_native_id: Some("synthetic-private-native".into()),
        relation: MessageRelation::Reply,
    });
    publish(&conn, &child, &a);
    assert!(
        open_read(&conn, &[&a])
            .entities(
                EntityKind::Edge,
                &[id(IdKind::Message, "shared")],
                &ProjectionQuery::default()
            )
            .unwrap()
            .is_empty()
    );
    let b = observation("b", 1);
    let mut parent_batch = batch(&b, "parent");
    parent_batch.entries[0].0 = parent.clone();
    let old = &parent_batch.placements[0];
    parent_batch.placements[0] = MessagePlacement::new(
        old.session_id.clone(),
        old.source_document_id.clone(),
        parent,
        0,
        false,
        None,
    );
    publish(&conn, &parent_batch, &b);
    let edges = open_read(&conn, &[&a, &b])
        .entities(
            EntityKind::Edge,
            &[id(IdKind::Message, "shared")],
            &ProjectionQuery::default(),
        )
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert!(!format!("{edges:?}").contains("synthetic-private-native"));
}

#[test]
fn mixed_batch_finalizes_no_op_and_changed_receipts_to_the_same_generation() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let original = batch(&a, "alpha");
    publish(&conn, &original, &a);
    let mut noop = observation("a", 2);
    noop.revision_digest = a.revision_digest.clone();
    let b = observation("b", 1);
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let first = publish_source_in_tx(&conn, &original, &noop, 2).unwrap();
    let second = publish_source_in_tx(&conn, &batch(&b, "beta"), &b, 2).unwrap();
    let mut publications = [first, second];
    conn.execute(
        "UPDATE store_metadata SET active_generation=2 WHERE active_generation=1",
        [],
    )
    .unwrap();
    finalize_publications_in_tx(&conn, &mut publications).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    assert!(
        publications
            .iter()
            .all(|p| p.receipt.committed_generation == Some(2))
    );
    let progress = open_read(&conn, &[&a, &b]).source_progress().unwrap();
    assert!(
        progress
            .iter()
            .all(|p| p.latest_receipt.as_ref().unwrap().committed_generation == Some(2))
    );
}

fn authorized_observation(source: &str, seq: i64) -> SourceObservation {
    let mut o = observation(source, seq);
    #[cfg(windows)]
    {
        o.binding.source_path = format!(r"C:\synthetic\{source}");
    }
    #[cfg(not(windows))]
    {
        o.binding.source_path = format!("/synthetic/{source}");
    }
    o.binding.namespace_id = Some("ins_v1_synthetic".into());
    o
}
fn read_policy() -> agent_session_grep_ports::control::ReadPolicy {
    use agent_session_grep_ports::control::*;
    #[cfg(windows)]
    let locator = r"C:\synthetic";
    #[cfg(not(windows))]
    let locator = "/synthetic";
    ReadPolicy {
        installation_id: ControlId::parse("synthetic-install").unwrap(),
        policy_epoch: PolicyEpoch::new(1).unwrap(),
        control_seq: ControlSeq::new(1).unwrap(),
        selections: vec![Selection {
            id: ControlId::parse("synthetic-selection").unwrap(),
            region: ScopeRegion {
                provider: SearchProvider::Claude,
                locator: CanonicalLocator::parse(locator).unwrap(),
                kind: RootKind::Root,
            },
            root_identity: Some(ControlId::parse("synthetic-root").unwrap()),
            enabled: true,
            revision: ControlSeq::new(1).unwrap(),
            created_at_ms: 0,
            revoked_at_ms: None,
        }],
        exclusions: vec![],
        request_intersection: RequestIntersection::Selected,
        maintenance: MaintenanceFence::idle(),
        revocations: vec![],
    }
}

#[test]
fn authorized_read_skips_unverified_source_and_selection_revision_without_losing_old_evidence() {
    use agent_session_grep_ports::control::{ControlSeq, Selection};
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = authorized_observation("a", 1);
    publish(&conn, &batch(&a, "allowedword"), &a);
    let mut partial = authorized_observation("partial", 1);
    partial.state = ObservationState::Incomplete;
    publish(&conn, &batch(&partial, "unverifiedword"), &partial);
    let policy = read_policy();
    let read = ManagedRead::begin_authorized(
        &conn,
        &policy,
        "synthetic-incarnation",
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(
        read.query_lexical("allowedword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .len(),
        1
    );
    assert!(
        read.query_lexical("unverifiedword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .is_empty()
    );
    drop(read);
    assert_eq!(
        conn.query_row(
            "SELECT update_state FROM source_heads WHERE source_id='partial'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "partial"
    );
    let mut renewed = policy.clone();
    renewed.selections[0].revision = ControlSeq::new(2).unwrap();
    // A different still-verified exact source selection preserves its evidence.
    let mut b = authorized_observation("b", 1);
    b.selections[0].selection_id = "second-selection".into();
    publish(&conn, &batch(&b, "survivingword"), &b);
    let mut selection: Selection = policy.selections[0].clone();
    selection.id = agent_session_grep_ports::control::ControlId::parse("second-selection").unwrap();
    selection.region.locator =
        agent_session_grep_ports::control::CanonicalLocator::parse(&b.binding.source_path).unwrap();
    selection.region.kind = agent_session_grep_ports::control::RootKind::Exact;
    renewed.selections.push(selection);
    let read = ManagedRead::begin_authorized(
        &conn,
        &renewed,
        "synthetic-incarnation",
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        read.query_lexical("allowedword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .is_empty()
    );
    assert_eq!(
        read.query_lexical("survivingword", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .len(),
        1
    );
}

#[test]
fn authorized_read_rejects_malformed_binding_and_honors_identity_exclusion() {
    use agent_session_grep_ports::control::*;
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = authorized_observation("a", 1);
    publish(&conn, &batch(&a, "alpha"), &a);
    let mut policy = read_policy();
    policy.exclusions.push(Exclusion {
        id: ControlId::parse("deny-a").unwrap(),
        region: ExcludedRegion::SourceIdentity {
            provider: SearchProvider::Claude,
            source_id: ControlId::parse("a").unwrap(),
        },
        revision: ControlSeq::new(1).unwrap(),
        created_policy_epoch: PolicyEpoch::new(1).unwrap(),
        created_at_ms: 1,
    });
    let read = ManagedRead::begin_authorized(
        &conn,
        &policy,
        "synthetic-incarnation",
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        read.query_lexical("alpha", &ProjectionQuery::default(), 10)
            .unwrap()
            .hits
            .is_empty()
    );
    drop(read);
    conn.execute(
        "UPDATE source_bindings SET source_path='invalid-relative-locator'",
        [],
    )
    .unwrap();
    assert!(
        ManagedRead::begin_authorized(
            &conn,
            &policy,
            "synthetic-incarnation",
            Instant::now() + Duration::from_secs(5)
        )
        .is_err()
    );
    assert!(conn.is_autocommit());
}

#[test]
fn scoped_lists_and_statistics_deduplicate_copies_and_preserve_unknown_usage() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    let mut first = batch(&a, "alpha");
    let mut second = batch(&b, "alpha");
    let event = SourceUsage {
        session_id: id(IdKind::Session, "shared"),
        message_id: Some(id(IdKind::Message, "shared")),
        usage: UsageObservation {
            input_tokens: 7,
            output_tokens: 3,
            cache_read_tokens: 2,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            token_source: TokenSource::Observed,
        },
    };
    first.usage_events.push(event.clone());
    second.usage_events.push(event);
    publish(&conn, &first, &a);
    publish(&conn, &second, &b);
    let read = open_read(&conn, &[&a, &b]);
    let query = ProjectionQuery::default();
    let stats = read.stats(&query, 10).unwrap();
    assert_eq!(stats.catalog_count, 4);
    assert_eq!(stats.placements, 2);
    assert_eq!(stats.source_placement_claims, 2);
    let usage = stats.usage.unwrap();
    assert_eq!(
        (
            usage.sessions,
            usage.input_tokens,
            usage.output_tokens,
            usage.observed_events
        ),
        (1, 7, 3, 1)
    );
    let list = read.list(&query, false, 10).unwrap();
    assert_eq!(list.entries.len(), 4);
    assert!(!list.truncated);
    assert!(
        list.entries
            .windows(2)
            .all(|p| p[0].id().as_str() < p[1].id().as_str())
    );
    let small = read.list(&query, false, 1).unwrap();
    assert_eq!(small.entries.len(), 1);
    assert!(small.truncated);
    let sessions = read.list(&query, true, 10).unwrap();
    assert_eq!(sessions.entries.len(), 1);
    assert_eq!(sessions.entries[0].id().kind(), IdKind::Session);
    let mut absent = ProjectionQuery::default();
    absent.filters.providers = vec![SearchProvider::Codex];
    let stats = read.stats(&absent, 10).unwrap();
    assert_eq!(stats.catalog_count, 0);
    assert_eq!(stats.placements, 0);
    assert!(stats.usage.is_none());
    assert!(read.list(&absent, false, 10).unwrap().entries.is_empty());
    drop(read);
    let one = open_read(&conn, &[&a]);
    let stats = one.stats(&query, 10).unwrap();
    assert_eq!(stats.catalog_count, 3);
    assert_eq!(stats.usage.unwrap().input_tokens, 7);
    let none = open_read_after_drop(one, &conn);
    assert_eq!(none.stats(&query, 10).unwrap().catalog_count, 0);
}

fn open_read_after_drop<'a>(old: ManagedRead<'a>, conn: &'a Connection) -> ManagedRead<'a> {
    drop(old);
    open_read(conn, &[])
}

#[test]
fn managed_app_uses_real_scoped_snapshot_for_search_get_list_status_and_resume() {
    use agent_session_grep_application::{
        AppRequest, AppResponse, ResponseBudget,
        managed::{ManagedApp, ManagedPartial, ManagedRequestContext},
    };
    use agent_session_grep_ports::{RetrievalMode, SearchFacets, SearchFilters};
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let hidden = observation("hidden", 1);
    let mut data = batch(&a, "alpha permitted");
    data.resume_claims.push(SourceResumeClaim {
        provider_id: "claude-code".into(),
        session_id: id(IdKind::Session, "shared").as_str().into(),
        provider_session_id: Some("synthetic-native".into()),
        provider_session_id_state: "resolved".into(),
        original_working_directory: Some("synthetic-paired-directory".into()),
        original_working_directory_state: "resolved".into(),
        pair_observed: true,
    });
    publish(&conn, &data, &a);
    publish(&conn, &batch(&hidden, "alpha hiddenword"), &hidden);
    let read = open_read(&conn, &[&a]);
    let expired = || false;
    let app = ManagedApp::new(
        &read,
        ManagedRequestContext {
            intersection: ProjectionQuery::default(),
            budget: ResponseBudget::default(),
            now_ms: 1,
            current_repo: None,
            deadline_expired: &expired,
        },
    )
    .unwrap();
    let response = app
        .handle(AppRequest::Search {
            query: "alpha".into(),
            filters: SearchFilters::default(),
            facets: SearchFacets::default(),
            limit: 10,
            cursor: None,
            budget: ResponseBudget::default(),
            include_system: false,
            group_by_session: false,
            mode: RetrievalMode::Lexical,
            query_embedding: None,
        })
        .unwrap();
    assert!(
        matches!(&response.response,AppResponse::Search{hits,..} if hits.len()==2 && hits.iter().any(|h| h.text.as_deref()==Some("alpha permitted")) && hits.iter().any(|h| h.id.kind()==IdKind::Session && h.text.is_none()))
    );
    assert_eq!(response.evidence[0].proof.source_id, a.binding.source_id);
    assert!(
        !response
            .partial
            .contains(&ManagedPartial::MetadataSearchUnavailable)
    );
    let got = app
        .handle(AppRequest::Get {
            id: id(IdKind::Message, "shared"),
        })
        .unwrap();
    assert!(
        matches!(got.response,AppResponse::Get{payload:Some(bytes)} if std::str::from_utf8(&bytes).unwrap().contains("alpha permitted"))
    );
    let listed = app
        .handle(AppRequest::List {
            limit: 10,
            cursor: None,
            budget: ResponseBudget::default(),
            sessions_only: false,
        })
        .unwrap();
    assert!(
        matches!(listed.response,AppResponse::List{entries,next_cursor:None,..} if entries.len()==3)
    );
    let status = app.handle(AppRequest::Status).unwrap();
    assert!(matches!(
        status.response,
        AppResponse::Status {
            catalog_count: 3,
            placements: 1,
            ..
        }
    ));
    let resume = app
        .handle(AppRequest::GetSessionResume {
            session_id: id(IdKind::Session, "shared"),
        })
        .unwrap();
    assert!(
        matches!(resume.response,AppResponse::SessionResume(m) if m.provider_session_id.as_deref()==Some("synthetic-native")&&m.resume_available)
    );
    let mut restricted = ProjectionQuery::default();
    restricted.filters.providers = vec![SearchProvider::Codex];
    let restricted = ManagedApp::new(
        &read,
        ManagedRequestContext {
            intersection: restricted,
            budget: ResponseBudget::default(),
            now_ms: 1,
            current_repo: None,
            deadline_expired: &expired,
        },
    )
    .unwrap();
    assert!(matches!(
        restricted
            .handle(AppRequest::Get {
                id: id(IdKind::Message, "shared")
            })
            .unwrap()
            .response,
        AppResponse::Get { payload: None }
    ));
    assert!(matches!(
        restricted
            .handle(AppRequest::Show {
                id: id(IdKind::Session, "shared")
            })
            .unwrap()
            .response,
        AppResponse::Show { payload: None }
    ));
    assert!(matches!(
        restricted.handle(AppRequest::Status).unwrap().response,
        AppResponse::Status {
            catalog_count: 0,
            placements: 0,
            ..
        }
    ));
    assert!(
        restricted
            .handle(AppRequest::GetSessionResume {
                session_id: id(IdKind::Session, "shared")
            })
            .is_err()
    );
}

#[test]
fn statistics_reject_negative_usage_and_report_conflicting_source_facts() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    let event = SourceUsage {
        session_id: id(IdKind::Session, "shared"),
        message_id: Some(id(IdKind::Message, "shared")),
        usage: UsageObservation {
            input_tokens: 7,
            output_tokens: 3,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            token_source: TokenSource::Observed,
        },
    };
    let mut first = batch(&a, "alpha");
    first.usage_events.push(event.clone());
    let mut second = batch(&b, "alpha");
    second.usage_events.push(event);
    publish(&conn, &first, &a);
    publish(&conn, &second, &b);
    conn.execute("UPDATE source_entity_projections SET payload=CAST(json_set(payload,'$.data.usage.input_tokens',8) AS BLOB),payload_digest='synthetic-conflict' WHERE kind='usage_event' AND source_id='b'",[]).unwrap();
    let read = open_read(&conn, &[&a, &b]);
    let stats = read.stats(&ProjectionQuery::default(), 10).unwrap();
    assert!(stats.facts_incomplete);
    assert!(stats.usage.is_none());
    drop(read);
    conn.execute("UPDATE source_entity_projections SET payload=CAST(json_set(payload,'$.data.usage.input_tokens',-1) AS BLOB) WHERE kind='usage_event' AND source_id='a'",[]).unwrap();
    assert!(
        open_read(&conn, &[&a])
            .stats(&ProjectionQuery::default(), 10)
            .is_err()
    );
}

fn managed_request(
    read: &impl ProjectionRead,
    query: ProjectionQuery,
    budget: ResponseBudget,
    request: AppRequest,
) -> Result<ManagedResponse, agent_session_grep_application::AppError> {
    ManagedApp::new(
        read,
        ManagedRequestContext {
            intersection: query,
            budget,
            now_ms: 1,
            current_repo: None,
            deadline_expired: &|| false,
        },
    )?
    .handle(request)
}
fn context_request(policy: ContextPolicy, level: ContextLevel) -> AppRequest {
    AppRequest::Context {
        session_id: id(IdKind::Session, "shared"),
        policy,
        level,
        budget: ResponseBudget::default(),
    }
}
fn chain(o: &SourceObservation) -> SourceBatch {
    let mut data = batch(o, "original user question");
    data.placements[0].span = Some(EvidenceSpan { start: 0, end: 64 });
    for (ordinal, name, role, text) in [
        (1, "second", "assistant", "original reply"),
        (2, "third", "user", "followup question"),
    ] {
        let message_id = id(IdKind::Message, name);
        data.entries.push((
            message_id.clone(),
            serde_json::to_vec(&serde_json::json!({
                "role":role, "text":text, "timestamp":format!("2026-10-17T0{}:00:00Z", ordinal+1),
            }))
            .unwrap(),
            text.into(),
        ));
        let placement = MessagePlacement::new(
            data.placements[0].session_id.clone(),
            data.placements[0].source_document_id.clone(),
            message_id,
            ordinal,
            false,
            Some(EvidenceSpan {
                start: u64::from(ordinal) * 64,
                end: u64::from(ordinal + 1) * 64,
            }),
        );
        data.edges.push(MessageEdge {
            child_placement_id: placement.id.clone(),
            parent_message_id: data.placements.last().unwrap().message_id.clone(),
            parent_native_id: None,
            relation: MessageRelation::Reply,
        });
        data.placements.push(placement);
    }
    data.activities.push(SourceActivity {
        message_id: id(IdKind::Message, "second"),
        activity: ToolActivity {
            kind: ToolActivityKind::File,
            actor: ToolActivityActor::Main,
            name: "Read".into(),
            target: Some("synthetic-target".into()),
            status: ToolActivityStatus::Success,
        },
    });
    data
}

#[test]
fn context_full_preserves_each_original_occurrence_and_revoke_removes_its_whole_proof() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    publish(&conn, &batch(&a, "short original"), &a);
    publish(&conn, &batch(&b, "longer other source privateword"), &b);
    for allowed in [vec![&a, &b], vec![&a]] {
        let read = open_read(&conn, &allowed);
        let result = managed_request(
            &read,
            ProjectionQuery::default(),
            ResponseBudget::default(),
            context_request(ContextPolicy::Full, ContextLevel::Raw),
        )
        .unwrap();
        let AppResponse::Context {
            messages,
            evidence,
            session,
            ..
        } = &result.response
        else {
            panic!()
        };
        assert_eq!(messages.len(), allowed.len());
        assert_eq!(evidence.len(), messages.len());
        assert_eq!(
            session["documents"].as_array().unwrap().len(),
            allowed.len()
        );
        for (message, span) in messages.iter().zip(evidence) {
            let proof = result
                .evidence
                .iter()
                .find(|p| {
                    p.occurrence
                        .as_ref()
                        .is_some_and(|o| o.data.placement.id.as_str() == message.placement_id)
                })
                .unwrap();
            let source = proof.proof.source_id.as_str();
            assert_eq!(
                message.payload["text"],
                if source == "a" {
                    "short original"
                } else {
                    "longer other source privateword"
                }
            );
            assert_eq!(message.message_id, id(IdKind::Message, "shared").as_str());
            assert_eq!(span.occurrence_id, message.placement_id);
            assert_eq!(
                span.source_document_id.as_deref(),
                Some(
                    proof
                        .occurrence
                        .as_ref()
                        .unwrap()
                        .data
                        .placement
                        .source_document_id
                        .as_str()
                )
            );
            assert!(
                proof
                    .related
                    .iter()
                    .all(|r| r.source_id == proof.proof.source_id)
            );
        }
        assert!(!result.is_partial());
    }
}

#[test]
fn mainline_window_reuses_document_parent_resolution_and_exact_tool_evidence() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    let data = chain(&a);
    publish(&conn, &data, &a);
    publish(&conn, &batch(&b, "wrong shared source"), &b);
    let read = open_read(&conn, &[&a, &b]);
    let context = managed_request(
        &read,
        ProjectionQuery::default(),
        ResponseBudget::default(),
        context_request(ContextPolicy::Mainline, ContextLevel::Talks),
    )
    .unwrap();
    let AppResponse::Context {
        messages,
        evidence,
        tool_activities,
        talks,
        branch_leaf,
        effective_level,
        ..
    } = &context.response
    else {
        panic!()
    };
    assert_eq!(
        messages
            .iter()
            .map(|m| m.payload["text"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "original user question",
            "original reply",
            "followup question"
        ]
    );
    assert_eq!(
        branch_leaf.as_deref(),
        Some(id(IdKind::Message, "third").as_str())
    );
    assert_eq!(*effective_level, ContextLevel::Talks);
    assert_eq!(talks.len(), 2);
    assert_eq!(tool_activities.len(), 1);
    assert_eq!(tool_activities[0]["target"], "synthetic-target");
    assert_eq!(evidence[1].byte_start, Some(64));
    assert_eq!(evidence[1].byte_end, Some(128));
    assert!(
        context
            .evidence
            .iter()
            .filter(|p| p.occurrence.is_some())
            .all(|p| p.proof.source_id == a.binding.source_id)
    );
    let window = managed_request(
        &read,
        ProjectionQuery::default(),
        ResponseBudget::default(),
        AppRequest::Message {
            message_id: id(IdKind::Message, "second"),
            session_id: None,
            around: usize::MAX,
            budget: ResponseBudget::default(),
        },
    )
    .unwrap();
    let AppResponse::Message { window: w } = &window.response else {
        panic!()
    };
    assert_eq!(w.messages, *messages);
    assert_eq!(w.anchor_placement_id, data.placements[1].id.as_str());
    assert_eq!(window.evidence.len(), 3);
    assert!(!w.truncation.truncated);
}

#[test]
fn context_retrieval_intersects_provider_project_time_session_sidechain_and_tools() {
    use agent_session_grep_ports::{SearchInstant, SidechainFacet};
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let mut a = observation("a", 1);
    a.repositories.push(RepositoryClaim {
        session_id: id(IdKind::Session, "shared"),
        slug: "example.test/team/repo".into(),
    });
    let mut data = chain(&a);
    data.placements[2].is_sidechain = true;
    data.resume_claims.push(SourceResumeClaim {
        provider_id: "claude-code".into(),
        session_id: id(IdKind::Session, "shared").as_str().into(),
        provider_session_id: Some("synthetic-native".into()),
        provider_session_id_state: "resolved".into(),
        original_working_directory: Some("synthetic-directory".into()),
        original_working_directory_state: "resolved".into(),
        pair_observed: true,
    });
    publish(&conn, &data, &a);
    let read = open_read(&conn, &[&a]);
    let mut queries = Vec::new();
    let mut query = ProjectionQuery::default();
    query.filters.providers = vec![SearchProvider::Codex];
    queries.push(query);
    let mut query = ProjectionQuery::default();
    query.filters.repo = Some("example.test/other/repo".into());
    queries.push(query);
    let query = ProjectionQuery {
        session_id: Some(id(IdKind::Session, "other")),
        ..Default::default()
    };
    queries.push(query);
    let mut query = ProjectionQuery::default();
    query.facets.tool_name = Some("unobserved".into());
    queries.push(query);
    for query in queries {
        for request in [
            context_request(ContextPolicy::Full, ContextLevel::Raw),
            AppRequest::Message {
                message_id: id(IdKind::Message, "second"),
                session_id: Some(id(IdKind::Session, "shared")),
                around: 1,
                budget: ResponseBudget::default(),
            },
            AppRequest::MessageContexts {
                message_id: id(IdKind::Message, "second"),
            },
        ] {
            assert!(
                managed_request(&read, query.clone(), ResponseBudget::default(), request).is_err()
            );
        }
    }
    let mut query = ProjectionQuery::default();
    query.filters.since = Some(SearchInstant {
        unix_seconds: 1792202400,
        nanosecond: 0,
    });
    query.facets.sidechain = SidechainFacet::MainOnly;
    let graph = read
        .session_graph(
            &id(IdKind::Session, "shared"),
            &query,
            GraphReadLimits::default(),
        )
        .unwrap();
    assert_eq!(graph.occurrences.len(), 1);
    assert!(graph.occurrences[0].edge.is_none());
    let result = managed_request(
        &read,
        query,
        ResponseBudget::default(),
        context_request(ContextPolicy::Mainline, ContextLevel::Sessions),
    )
    .unwrap();
    let AppResponse::Context {
        messages,
        effective_level,
        summary,
        ..
    } = result.response
    else {
        panic!()
    };
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].payload["text"], "original reply");
    assert_eq!(effective_level, ContextLevel::Raw);
    assert!(summary.is_none());
    let mut query = ProjectionQuery::default();
    query.facets.sidechain = SidechainFacet::SubagentOnly;
    let result = managed_request(
        &read,
        query,
        ResponseBudget::default(),
        context_request(ContextPolicy::Mainline, ContextLevel::Raw),
    )
    .unwrap();
    assert!(
        matches!(result.response,AppResponse::Context{messages,..} if messages.len()==1 && messages[0].payload["text"]=="followup question")
    );
}

#[test]
fn message_context_candidates_are_bounded_and_ambiguous_sessions_require_selection() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let mut data = batch(&a, "shared text");
    for n in 0..10 {
        let session = id(IdKind::Session, &format!("other-{n}"));
        data.entries.push((
            session.clone(),
            serde_json::to_vec(
                &serde_json::json!({"documents":[data.placements[0].source_document_id.as_str()]}),
            )
            .unwrap(),
            String::new(),
        ));
        data.placements.push(MessagePlacement::new(
            session,
            data.placements[0].source_document_id.clone(),
            id(IdKind::Message, "shared"),
            n + 1,
            false,
            None,
        ));
    }
    publish(&conn, &data, &a);
    let read = open_read(&conn, &[&a]);
    let page = read
        .message_contexts(
            &id(IdKind::Message, "shared"),
            &ProjectionQuery::default(),
            2,
            2,
        )
        .unwrap();
    assert_eq!(page.candidate_count, 11);
    assert_eq!(page.candidates.len(), 2);
    assert!(page.truncated);
    let error = managed_request(
        &read,
        ProjectionQuery::default(),
        ResponseBudget::default(),
        AppRequest::Message {
            message_id: id(IdKind::Message, "shared"),
            session_id: None,
            around: 0,
            budget: ResponseBudget::default(),
        },
    )
    .unwrap_err();
    let agent_session_grep_application::AppError::MessageAmbiguous(ambiguity) = error else {
        panic!("expected ambiguity: {error}")
    };
    assert_eq!(ambiguity.candidate_count, 11);
    assert_eq!(ambiguity.candidate_session_ids.len(), 8);
    let budget = ResponseBudget {
        max_items: 1,
        max_evidence_spans: 1,
        ..Default::default()
    };
    let result = managed_request(
        &read,
        ProjectionQuery::default(),
        budget,
        AppRequest::MessageContexts {
            message_id: id(IdKind::Message, "shared"),
        },
    )
    .unwrap();
    assert!(
        matches!(result.response,AppResponse::MessageContexts{ref candidates,..} if candidates.len()==1 && candidates[0].placement_ids.len()==1)
    );
    assert_eq!(result.evidence.len(), 1);
    assert!(result.partial.contains(&ManagedPartial::ResponseBudget));
    let query = ProjectionQuery {
        session_id: Some(id(IdKind::Session, "shared")),
        ..Default::default()
    };
    let result = managed_request(
        &read,
        query,
        ResponseBudget::default(),
        AppRequest::Message {
            message_id: id(IdKind::Message, "shared"),
            session_id: None,
            around: 0,
            budget: ResponseBudget::default(),
        },
    )
    .unwrap();
    assert!(
        matches!(result.response,AppResponse::Message{window} if window.session_id==id(IdKind::Session,"shared").as_str())
    );
}

#[test]
fn context_and_anchor_budgets_keep_proofs_aligned_and_original_prefixes() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let mut data = chain(&a);
    let text = "\"\\界".repeat(20_000);
    data.entries
        .iter_mut()
        .find(|e| e.0 == id(IdKind::Message, "second"))
        .unwrap()
        .1 = serde_json::to_vec(
        &serde_json::json!({"role":"assistant","text":text,"timestamp":"2026-10-17T02:00:00Z"}),
    )
    .unwrap();
    publish(&conn, &data, &a);
    let read = open_read(&conn, &[&a]);
    for level in [
        ContextLevel::Raw,
        ContextLevel::Talks,
        ContextLevel::Sessions,
    ] {
        let budget = ResponseBudget {
            max_response_bytes: 16_384,
            max_messages: 1,
            max_evidence_spans: 1,
            ..Default::default()
        };
        let result = managed_request(
            &read,
            ProjectionQuery::default(),
            budget.clone(),
            context_request(ContextPolicy::Full, level),
        )
        .unwrap();
        let AppResponse::Context {
            messages,
            evidence,
            tool_activities,
            talks,
            summary,
            session,
            branch_leaf,
            branch_leaf_placement_id,
            hint,
            truncation,
            ..
        } = &result.response
        else {
            panic!()
        };
        assert_eq!(messages.len(), 1);
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|p| p.occurrence.is_some())
                .count(),
            1
        );
        assert!(truncation.truncated);
        assert!(result.is_partial());
        assert!(tool_activities.is_empty());
        let rendered=serde_json::to_vec(&serde_json::json!({"messages":messages,"evidence":evidence,"tools":tool_activities,"talks":talks,"summary":summary,"session":session,"leaf":branch_leaf,"placement":branch_leaf_placement_id,"hint":hint,"truncation":truncation})).unwrap();
        assert!(rendered.len() + 1024 < budget.max_response_bytes);
    }
    let budget = ResponseBudget {
        max_response_bytes: 8192,
        ..Default::default()
    };
    let result = managed_request(
        &read,
        ProjectionQuery::default(),
        budget.clone(),
        AppRequest::Message {
            message_id: id(IdKind::Message, "second"),
            session_id: None,
            around: usize::MAX,
            budget: ResponseBudget::default(),
        },
    )
    .unwrap();
    let AppResponse::Message { window } = &result.response else {
        panic!()
    };
    assert_eq!(window.messages.len(), 1);
    assert_eq!(result.evidence.len(), 1);
    let prefix = window.messages[0].payload["text"].as_str().unwrap();
    assert!(!prefix.is_empty());
    assert!(text.starts_with(prefix));
    assert!(prefix.len() < text.len());
    assert_eq!(window.anchor_placement_id, window.messages[0].placement_id);
    assert!(result.is_partial());
    assert!(serde_json::to_vec(&window.messages).unwrap().len() + 1024 < budget.max_response_bytes);
}

#[test]
fn complete_graph_limits_corrupt_occurrences_and_unverified_catalog_fail_closed() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    publish(&conn, &chain(&a), &a);
    let read = open_read(&conn, &[&a]);
    for limits in [
        GraphReadLimits {
            max_occurrences: 2,
            ..Default::default()
        },
        GraphReadLimits {
            max_bytes: 1,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            read.session_graph(
                &id(IdKind::Session, "shared"),
                &ProjectionQuery::default(),
                limits
            ),
            Err(agent_session_grep_ports::PortError::WriterBusy(_))
        ));
    }
    drop(read);
    conn.execute("UPDATE source_occurrences SET payload_digest='corrupt'", [])
        .unwrap();
    let read = open_read(&conn, &[&a]);
    assert!(
        read.session_graph(
            &id(IdKind::Session, "shared"),
            &ProjectionQuery::default(),
            GraphReadLimits::default()
        )
        .is_err()
    );
    assert!(
        read.message_contexts(
            &id(IdKind::Message, "shared"),
            &ProjectionQuery::default(),
            10,
            10
        )
        .is_err()
    );
    drop(read);
    let legacy = Connection::open_in_memory().unwrap();
    schema(&legacy);
    legacy
        .execute(
            "INSERT INTO catalog VALUES(?1,?2)",
            params![
                id(IdKind::Session, "shared").as_str(),
                b"legacy evidence".to_vec()
            ],
        )
        .unwrap();
    let read = open_read(&legacy, &[]);
    assert!(
        managed_request(
            &read,
            ProjectionQuery::default(),
            ResponseBudget::default(),
            context_request(ContextPolicy::Full, ContextLevel::Raw)
        )
        .is_err()
    );
}

#[test]
fn graph_canonical_timestamp_or_document_conflicts_are_explicit_errors() {
    for document_conflict in [false, true] {
        let conn = Connection::open_in_memory().unwrap();
        schema(&conn);
        let a = observation("a", 1);
        let b = observation("b", 1);
        let first = batch(&a, "first");
        let mut second = batch(&b, "second");
        if document_conflict {
            let old = second.placements[0].source_document_id.clone();
            let document = first.placements[0].source_document_id.clone();
            second.entries.iter_mut().find(|e| e.0 == old).unwrap().0 = document.clone();
            second.entries.iter_mut().find(|e|e.0.kind()==IdKind::Document).unwrap().1=serde_json::to_vec(&serde_json::json!({"provider":"claude-code","variant":"different","fingerprint":b.revision_digest,"len":4096})).unwrap();
            second
                .entries
                .iter_mut()
                .find(|e| e.0.kind() == IdKind::Session)
                .unwrap()
                .1 =
                serde_json::to_vec(&serde_json::json!({"documents":[document.as_str()]})).unwrap();
            second.placements[0] = MessagePlacement::new(
                id(IdKind::Session, "shared"),
                document,
                id(IdKind::Message, "shared"),
                1,
                false,
                None,
            );
        } else {
            second.entries[0].1=serde_json::to_vec(&serde_json::json!({"role":"user","text":"second","timestamp":"2026-10-17T02:00:00Z"})).unwrap();
        }
        publish(&conn, &first, &a);
        publish(&conn, &second, &b);
        let read = open_read(&conn, &[&a, &b]);
        assert!(
            managed_request(
                &read,
                ProjectionQuery::default(),
                ResponseBudget::default(),
                context_request(ContextPolicy::Full, ContextLevel::Raw)
            )
            .is_err()
        );
    }
}

#[test]
fn current_context_retains_unchanged_fact_revisions_across_verified_publications_and_partial_attempts()
 {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    publish(&conn, &chain(&a), &a);
    let next = observation("a", 2);
    publish(&conn, &chain(&next), &next);
    let mut partial = observation("a", 3);
    partial.state = ObservationState::Incomplete;
    publish(&conn, &batch(&partial, "unpublished replacement"), &partial);
    let read = open_read(&conn, &[&a]);
    let result = managed_request(
        &read,
        ProjectionQuery::default(),
        ResponseBudget::default(),
        context_request(ContextPolicy::Mainline, ContextLevel::Raw),
    )
    .unwrap();
    let AppResponse::Context {
        messages, evidence, ..
    } = &result.response
    else {
        panic!()
    };
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].payload["text"], "original user question");
    assert!(
        evidence
            .iter()
            .all(|e| e.source_fingerprint.as_deref() == Some(next.revision_digest.as_str()))
    );
    for proof in result.evidence.iter().filter(|p| p.occurrence.is_some()) {
        assert_eq!(proof.proof.revision.revision_id, a.revision_id);
        assert!(
            proof
                .related
                .iter()
                .any(|p| p.revision.revision_id == next.revision_id)
        );
        assert!(
            proof
                .related
                .iter()
                .all(|p| p.revision.revision_id != partial.revision_id)
        );
    }
}

#[test]
fn session_previews_keep_divergent_sources_and_filtered_endpoints_separate() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    publish(&conn, &chain(&a), &a);
    publish(&conn, &batch(&b, "other source original"), &b);
    let read = open_read(&conn, &[&a, &b]);
    let requests = vec![
        SessionPreviewRequest {
            session_id: id(IdKind::Session, "shared"),
            source_id: a.binding.source_id.clone(),
        },
        SessionPreviewRequest {
            session_id: id(IdKind::Session, "shared"),
            source_id: b.binding.source_id.clone(),
        },
    ];
    let previews = read
        .session_previews(&requests, &ProjectionQuery::default(), 1_000_000)
        .unwrap();
    assert_eq!(
        previews[0].first_user.as_ref().unwrap().text,
        "original user question"
    );
    assert_eq!(
        previews[0].last_user.as_ref().unwrap().text,
        "followup question"
    );
    assert_eq!(
        previews[1].first_user.as_ref().unwrap().text,
        "other source original"
    );
    assert!(previews.iter().all(|p| !p.unavailable));
    let mut query = ProjectionQuery::default();
    query.filters.since =
        agent_session_grep_application::parse_search_instant("2026-10-17T02:00:00Z");
    let previews = read.session_previews(&requests, &query, 1_000_000).unwrap();
    assert_eq!(
        previews[0].first_user.as_ref().unwrap().text,
        "followup question"
    );
    assert!(previews[1].first_user.is_none());
    let previews = read
        .session_previews(&requests, &ProjectionQuery::default(), 1)
        .unwrap();
    assert!(previews.iter().all(|p| p.unavailable));
    drop(read);
    let read = open_read(&conn, &[&a]);
    let previews = read
        .session_previews(&requests, &ProjectionQuery::default(), 1_000_000)
        .unwrap();
    assert!(
        previews[1].unavailable
            && previews[1].first_user.is_none()
            && previews[1].last_user.is_none()
    );
}

#[test]
fn managed_session_list_renders_verified_preview_title_and_original_proofs() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let mut data = chain(&a);
    data.entries.iter_mut().find(|e|e.0.kind()==IdKind::Session).unwrap().1=serde_json::to_vec(&serde_json::json!({"title":"verified title","documents":[data.placements[0].source_document_id.as_str()]})).unwrap();
    publish(&conn, &data, &a);
    let read = open_read(&conn, &[&a]);
    let response = managed_request(
        &read,
        ProjectionQuery::default(),
        ResponseBudget::default(),
        AppRequest::List {
            limit: 5,
            cursor: None,
            budget: ResponseBudget::default(),
            sessions_only: true,
        },
    )
    .unwrap();
    let AppResponse::List { peeks, titles, .. } = &response.response else {
        panic!()
    };
    assert_eq!(titles[0].as_deref(), Some("verified title"));
    assert_eq!(
        peeks[0].as_ref().unwrap().first_user_text.as_deref(),
        Some("original user question")
    );
    assert_eq!(
        peeks[0].as_ref().unwrap().last_user_text.as_deref(),
        Some("followup question")
    );
    assert_eq!(
        response
            .evidence
            .iter()
            .filter(|p| p.occurrence.is_some())
            .count(),
        2
    );
    assert!(
        !response
            .partial
            .contains(&ManagedPartial::ListPreviewUnavailable)
    );
}

#[test]
fn metadata_rank_uses_allowed_variants_before_limit_and_preserves_safe_fields() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    let b = observation("b", 1);
    let mut data = batch(&a, "unrelated body");
    data.entries.iter_mut().find(|e| e.0.kind() == IdKind::Session).unwrap().1 =
        serde_json::to_vec(&serde_json::json!({"title":"alpha metadata title","documents":[data.placements[0].source_document_id.as_str()]})).unwrap();
    publish(&conn, &data, &a);
    let before = open_read(&conn, &[&a])
        .query_session_metadata("alpha", &ProjectionQuery::default(), 1)
        .unwrap();
    assert_eq!(before.hits.len(), 1);
    assert_eq!(before.hits[0].fields, vec![SessionMetadataField::Title]);
    let mut copy = batch(&b, "unrelated body");
    copy.entries.iter_mut().find(|e| e.0.kind() == IdKind::Session).unwrap().1 =
        serde_json::to_vec(&serde_json::json!({"title":"alpha metadata title","documents":[copy.placements[0].source_document_id.as_str()]})).unwrap();
    publish(&conn, &copy, &b);
    let after = open_read(&conn, &[&a, &b])
        .query_session_metadata("alpha", &ProjectionQuery::default(), 1)
        .unwrap();
    assert_eq!(after.hits.len(), 1);
    assert_eq!(after.hits[0].score, before.hits[0].score);
    let hidden = observation("hidden", 1);
    publish(&conn, &batch(&hidden, "alpha hidden title"), &hidden);
    let read = open_read(&conn, &[&a]);
    let page = read
        .query_session_metadata("alpha", &ProjectionQuery::default(), 1)
        .unwrap();
    assert_eq!(page.hits, before.hits);
    assert!(!page.truncated && !page.incomplete);
    assert!(
        read.query_lexical("alpha", &ProjectionQuery::default(), 1)
            .unwrap()
            .hits
            .is_empty()
    );
    assert!(
        read.query_session_metadata("hidden", &ProjectionQuery::default(), 1)
            .unwrap()
            .hits
            .is_empty()
    );
}

#[test]
fn metadata_first_user_cannot_bypass_filtered_occurrence_or_title_conflict() {
    let conn = Connection::open_in_memory().unwrap();
    schema(&conn);
    let a = observation("a", 1);
    publish(&conn, &chain(&a), &a);
    let read = open_read(&conn, &[&a]);
    assert_eq!(
        read.query_session_metadata("original", &ProjectionQuery::default(), 5)
            .unwrap()
            .hits
            .len(),
        1
    );
    let mut query = ProjectionQuery::default();
    query.filters.since =
        agent_session_grep_application::parse_search_instant("2026-10-17T02:00:00Z");
    let page = read.query_session_metadata("original", &query, 5).unwrap();
    assert!(page.hits.is_empty() && page.incomplete);
    assert!(
        !read
            .query_lexical("followup", &query, 5)
            .unwrap()
            .hits
            .is_empty()
    );
    query.filters.since = None;
    query.filters.providers = vec![SearchProvider::Codex];
    assert!(
        read.query_session_metadata("original", &query, 5)
            .unwrap()
            .hits
            .is_empty()
    );
    drop(read);
    let b = observation("b", 1);
    publish(&conn, &batch(&b, "different title"), &b);
    let page = open_read(&conn, &[&a, &b])
        .query_session_metadata("original", &ProjectionQuery::default(), 5)
        .unwrap();
    assert!(page.hits.is_empty() && page.incomplete);
    assert_eq!(
        open_read(&conn, &[&a])
            .query_session_metadata("original", &ProjectionQuery::default(), 5)
            .unwrap()
            .hits
            .len(),
        1
    );
}
