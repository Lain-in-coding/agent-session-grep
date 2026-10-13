//! D3 六项不变量自查（adapters-sqlite 层）：#3 失败固化、#4 裁剪视图进缓存。
//!
//! #3 失败固化：解析/同步失败不得推进成功水位（generation / `source_scans`
//! 指纹）、不得覆盖 last-good（catalog payload + FTS 投影）、不得标记 current。
//! 断言锚点：`commit_source_batches_if_changed` 的"先全量校验、后单事务激活"
//! （`agent-session-grep-adapters-sqlite/src/lib.rs:3328-3396`）与 durable
//! outbox 两阶段提交（`begin_index_batch` → `commit_index_batch`，
//! `lib.rs:5336,5402,6977`）。
//!
//! #4 裁剪视图进缓存：展示/预算裁剪只发生在响应装配；持久化层只接受
//! **完整批次原子激活**，crashed intent 在下次写打开被标 aborted，绝不把
//! 半成品（"裁剪视图"）持久化为"新鲜全量"；`source_scans` 的新鲜度缓存
//! 只在成功提交里写。断言锚点：`open_for_write` 的恢复（`lib.rs:1571-1577`）
//! 与 `recover_interrupted`（`lib.rs:6977`）。
//!
//! 证据均为合成数据、显式注入时钟，无网络、无真实用户数据、无系统时间依赖。

use agent_session_grep_adapters_sqlite::{
    INDEX_PROJECTION_VERSION, PARSER_SEMANTIC_VERSION, SqliteStore,
};
use agent_session_grep_application::{App, AppRequest, AppResponse, ResponseBudget};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{
    CatalogStore, NoResumeClaims, PortError, RetrievalMode, SearchFacets, SearchFilters,
    SearchIndex,
};

const SOURCE_PATH: &str = "invariant-source.jsonl";

fn sid(kind: IdKind, tag: &str) -> StableId {
    StableId::native(kind, tag)
}

fn payload(text: &str) -> Vec<u8> {
    serde_json::json!({
        "role": "user",
        "text": text,
        "timestamp": "2026-08-24T00:00:00Z",
        "parent": null,
        "parent_native_id": null,
        "is_sidechain": false,
        "session": null,
        "sessions": [],
        "span": null,
    })
    .to_string()
    .into_bytes()
}

fn message_entry(id: &StableId, text: &str) -> (StableId, Vec<u8>, String) {
    (id.clone(), payload(text), text.to_string())
}

fn document_entry(id: &StableId) -> (StableId, Vec<u8>, String) {
    (
        id.clone(),
        serde_json::json!({
            "provider": "synthetic",
            "variant": "synthetic/jsonl-v1",
            "fingerprint": "0123456789abcdef",
            "len": 128,
        })
        .to_string()
        .into_bytes(),
        String::new(),
    )
}

/// 一个完整成功 scan 的合成 `SourceBatch`：消息 + 会话 + 文档实体，一条
/// placement；`fingerprint` 代表整源字节的内容指纹（水位）。
fn source_batch(
    entries: Vec<(StableId, Vec<u8>, String)>,
    placements: Vec<MessagePlacement>,
    len_bytes: i64,
    fingerprint: &str,
) -> agent_session_grep_adapters_sqlite::SourceBatch {
    agent_session_grep_adapters_sqlite::SourceBatch {
        source_path: SOURCE_PATH.to_string(),
        entries,
        placements,
        edges: Vec::new(),
        activities: Vec::new(),
        usage_events: Vec::new(),
        relation_complete: true,
        len_bytes: Some(len_bytes),
        fingerprint: Some(fingerprint.to_string()),
        provider_id: None,
        resume_claims: Vec::new(),
    }
}

fn seed_baseline(store: &SqliteStore) -> (StableId, StableId, StableId, Vec<u8>) {
    let message = sid(IdKind::Message, "failure-message");
    let session = sid(IdKind::Session, "failure-session");
    let document = sid(IdKind::Document, "failure-document");
    let placement = MessagePlacement::new(
        session.clone(),
        document.clone(),
        message.clone(),
        0,
        false,
        None,
    );
    let baseline_payload = payload("alpha baseline body");
    let batch = source_batch(
        vec![
            message_entry(&message, "alpha baseline body"),
            (
                session.clone(),
                br#"{"documents":[],"messages":[]}"#.to_vec(),
                String::new(),
            ),
            document_entry(&document),
        ],
        vec![placement],
        10,
        "fp-v1",
    );
    assert!(
        store.commit_source_batches_if_changed(&[batch]).unwrap(),
        "baseline batch must activate a first generation"
    );
    // last-good = 提交后的权威 catalog payload（提交路径会从 placement 派生
    // 上下文别名，与传入字节不必然逐字相等）。
    let last_good = store
        .get(&message)
        .unwrap()
        .expect("baseline commit must store the message payload");
    let stored: serde_json::Value = serde_json::from_slice(&last_good).unwrap();
    let sent: serde_json::Value = serde_json::from_slice(&baseline_payload).unwrap();
    assert_eq!(
        stored["text"], sent["text"],
        "sanity: baseline stores its own body"
    );
    (message, session, document, last_good)
}

fn fingerprint_of(store: &SqliteStore) -> (Option<i64>, Option<String>, i64) {
    store
        .source_fingerprints(&[SOURCE_PATH.to_string()])
        .unwrap()
        .remove(SOURCE_PATH)
        .expect("baseline scan must register a fingerprint cache row")
}

#[test]
fn failed_source_commit_keeps_watermark_fingerprint_and_last_good_rows() {
    let store = SqliteStore::open_in_memory().unwrap();
    let (message, session, document, baseline_payload) = seed_baseline(&store);
    let generation = store.active_generation().unwrap();
    assert_eq!(
        fingerprint_of(&store),
        (
            Some(10),
            Some("fp-v1".to_string()),
            i64::from(PARSER_SEMANTIC_VERSION)
        ),
        "baseline watermark: len/fingerprint/parser_version"
    );

    // 失败注入：同一源的新扫描同时携带"更新载荷 + 新指纹"和一个重复实体 id。
    // `batch_manifest` 必须在任何写入之前拒绝整批（duplicate entity ids）。
    let placement = MessagePlacement::new(session, document, message.clone(), 0, false, None);
    let mut broken = source_batch(
        vec![message_entry(&message, "omega would-be-new body")],
        vec![placement],
        20,
        "fp-v2",
    );
    broken.entries.push(broken.entries[0].clone());
    let error = store
        .commit_source_batches_if_changed(&[broken])
        .expect_err("duplicate entity ids must be rejected before any write");
    assert!(
        matches!(&error, PortError::Backend(message) if message.contains("duplicate entity id")),
        "unexpected error: {error:?}"
    );

    // 不推进成功水位。
    assert_eq!(
        store.active_generation().unwrap(),
        generation,
        "failed batch must not activate a generation"
    );
    // 不覆盖新鲜度缓存（水位）：仍是 last-good 扫描的指纹。
    assert_eq!(
        fingerprint_of(&store),
        (
            Some(10),
            Some("fp-v1".to_string()),
            i64::from(PARSER_SEMANTIC_VERSION)
        ),
        "failed batch must not advance the source-scan fingerprint"
    );
    // 不覆盖 last-good：catalog payload 与 FTS 投影都保持旧内容。
    assert_eq!(
        store.get(&message).unwrap().as_deref(),
        Some(baseline_payload.as_slice()),
        "failed batch must not overwrite the last-good catalog payload"
    );
    assert!(store.query("omega", 10).unwrap().is_empty());
    assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
}

#[test]
fn interrupted_intent_never_becomes_a_fresh_full_view_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db = db.to_str().unwrap().to_string();

    let (late_message, pending) = {
        let store = SqliteStore::open_for_write(&db).unwrap();
        let (_message, _session, _document, _payload) = seed_baseline(&store);
        let generation = store.active_generation().unwrap();
        assert_eq!(generation, 1);

        // 模拟崩溃：intent 已 durable（building），apply 未发生。
        let late_message = sid(IdKind::Message, "interrupted-message");
        let pending = store
            .begin_index_batch(
                &[message_entry(&late_message, "omega interrupted body")],
                &[],
            )
            .unwrap();
        assert_eq!(
            store
                .index_batch(&pending.operation_id)
                .unwrap()
                .unwrap()
                .state,
            "building"
        );
        assert_eq!(store.interrupted_batch_count().unwrap(), 1);
        // 不 commit：drop 模拟进程终止（lease 释放，intent 留在盘上）。
        (late_message, pending)
    };

    let store = SqliteStore::open_for_write(&db).unwrap();
    // 写打开自动收敛上次崩溃留下的无副作用 intent。
    assert_eq!(store.interrupted_batch_count().unwrap(), 0);
    let batch = store.index_batch(&pending.operation_id).unwrap().unwrap();
    assert_eq!(batch.state, "aborted");
    assert_eq!(
        batch.error_code.as_deref(),
        Some("interrupted_before_activation")
    );

    // 裁掉（未激活）的视图不得在重开后变成"新鲜全量"。
    assert_eq!(store.active_generation().unwrap(), 1);
    assert!(store.get(&late_message).unwrap().is_none());
    assert!(store.query("omega", 10).unwrap().is_empty());
    assert_eq!(store.query("alpha", 10).unwrap().len(), 1);
    assert_eq!(
        fingerprint_of(&store),
        (
            Some(10),
            Some("fp-v1".to_string()),
            i64::from(PARSER_SEMANTIC_VERSION)
        ),
        "recovery must not touch the successful scan's watermark"
    );
    assert!(
        store.index_projection_is_current().unwrap(),
        "projection version {INDEX_PROJECTION_VERSION} must still be current"
    );
}

fn invariant_clock() -> i64 {
    1_787_616_000_000
}

#[test]
fn budget_trimmed_response_is_not_persisted_as_a_fresh_full_view() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db = db.to_str().unwrap().to_string();
    let store = SqliteStore::open_for_write(&db).unwrap();

    let session = sid(IdKind::Session, "budget-session");
    let document = sid(IdKind::Document, "budget-document");
    let ids: Vec<StableId> = (0..3)
        .map(|i| sid(IdKind::Message, &format!("budget-message-{i}")))
        .collect();
    let placements: Vec<MessagePlacement> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            MessagePlacement::new(
                session.clone(),
                document.clone(),
                id.clone(),
                i as u32,
                false,
                None,
            )
        })
        .collect();
    let mut entries = vec![
        (
            session.clone(),
            br#"{"documents":[],"messages":[]}"#.to_vec(),
            String::new(),
        ),
        document_entry(&document),
    ];
    for id in &ids {
        // 长正文（超过默认 snippet 2000 字符）：4096 字节预算下页必然被字节闸裁剪。
        entries.push(message_entry(id, &format!("alpha {}", "x".repeat(3000))));
    }
    assert!(
        store
            .commit_source_batches_if_changed(&[source_batch(entries, placements, 10, "fp-v1")])
            .unwrap()
    );
    let generation = store.active_generation().unwrap();

    let app = App::with_resume_semantic_and_clock(
        &store,
        &store,
        NoResumeClaims,
        &store,
        invariant_clock,
    );
    // 预算下限（CONTRACT §3）：字节闸而非条目闸制造真实的响应裁剪。
    let tight = ResponseBudget {
        max_response_bytes: 4096,
        ..ResponseBudget::default()
    };
    let response = app
        .handle(AppRequest::Search {
            query: "alpha".into(),
            filters: SearchFilters::default(),
            facets: SearchFacets::default(),
            limit: 10,
            cursor: None,
            budget: tight,
            include_system: true,
            group_by_session: false,
            mode: RetrievalMode::Lexical,
            query_embedding: None,
        })
        .unwrap();
    let AppResponse::Search {
        hits,
        truncation,
        next_cursor,
        ..
    } = response
    else {
        panic!("search expected");
    };
    assert!(
        hits.len() < ids.len(),
        "byte gate must trim the page, got {} hits",
        hits.len()
    );
    assert!(truncation.truncated);
    assert_eq!(
        truncation.reason.as_deref(),
        Some("max_response_bytes"),
        "the byte gate decides the final item count"
    );
    assert!(
        next_cursor.is_some(),
        "trimmed hits stay reachable through the response cursor"
    );

    // 展示裁剪是响应态的：水位、指纹与全量可检索性都不受影响。
    assert_eq!(store.active_generation().unwrap(), generation);
    assert_eq!(
        fingerprint_of(&store),
        (
            Some(10),
            Some("fp-v1".to_string()),
            i64::from(PARSER_SEMANTIC_VERSION)
        )
    );
    drop(app);
    drop(store);

    let reopened = SqliteStore::open(&db).unwrap();
    assert_eq!(
        reopened.query("alpha", 10).unwrap().len(),
        3,
        "a trimmed page must never be persisted as the fresh full view"
    );
    for id in &ids {
        assert!(
            reopened.get(id).unwrap().is_some(),
            "reopen must still see every committed entity"
        );
    }
}
