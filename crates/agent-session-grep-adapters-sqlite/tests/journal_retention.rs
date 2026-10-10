//! B2 journal 治理证据（adapters-sqlite 层）：terminal 批次明细的受约束聚合。
//!
//! 固定实验形状：200 消息集合、21 次单条改写。
//! 先报 compact 前后的 journal 明细与库文件体积，再逐项钉住保留合同：
//! - 未决（building）行明细永久保留，且仍可继续 CAS 提交；
//! - preview 先展示（字段清单 / 受影响行数 / 体积收益），stage/apply 独立且默认不自动调用；
//! - 中断（stage 已 durable、apply 前进程被杀）可重入收敛；旧 v18 格式经迁移可读；
//!   未知格式 fail-closed；
//! - catalog / FTS / 关系 / 活跃 generation 水位与重放、冲突、恢复语义不变。
//!
//! 证据全部为合成数据：无网络、无真实用户数据；时间只进审计列，不参与断言。

use agent_session_grep_adapters_sqlite::{
    JOURNAL_COMPACTION_FIELDS, JOURNAL_DETAIL_FORMAT_AGGREGATED_V1, JOURNAL_DETAIL_FORMAT_FULL,
    SourceBatch, SqliteStore,
};
use agent_session_grep_domain::{IdKind, MessagePlacement, StableId};
use agent_session_grep_ports::{CatalogStore, PortError, SearchIndex};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};

const SOURCE_PATH: &str = "retention-source.jsonl";
const MESSAGE_COUNT: usize = 200;
const LATEST_REVISION: usize = 21;

fn sid(kind: IdKind, tag: &str) -> StableId {
    StableId::native(kind, tag)
}

fn soak_session() -> StableId {
    sid(IdKind::Session, "retention-session")
}

fn soak_document() -> StableId {
    sid(IdKind::Document, "retention-document")
}

fn message_payload(text: &str, session: &str) -> Vec<u8> {
    message_payload_with_role(text, session, "user")
}

fn message_payload_with_role(text: &str, session: &str, role: &str) -> Vec<u8> {
    serde_json::json!({
        "role": role,
        "text": text,
        "parent": null,
        "parent_native_id": null,
        "is_sidechain": false,
        "session": session,
        "sessions": [session],
        "span": { "start": 0, "end": 8 },
    })
    .to_string()
    .into_bytes()
}

/// 父实验形状的合成 batch：200 消息 + session/document 容器 + 200 placements；
/// `revision` 只改写最后一条消息，其余逐字节不变。
fn soak_batch(revision: usize) -> SourceBatch {
    let session = soak_session();
    let document = soak_document();
    let mut entries = Vec::with_capacity(MESSAGE_COUNT + 2);
    let mut placements = Vec::with_capacity(MESSAGE_COUNT);
    let mut members = Vec::with_capacity(MESSAGE_COUNT);
    for index in 0..MESSAGE_COUNT {
        let id = sid(IdKind::Message, &format!("retention-message-{index}"));
        let mut text = format!("retention body {index} {}", "filler".repeat(24));
        if index + 1 == MESSAGE_COUNT {
            // 改写标记严格变长：merge_message_payloads 对 text 采用"保留更长投影"
            // 的确定性合并，等长改写不改变权威 payload（store 的真实语义），变长
            // 才等价于一次可观察的单条改写。填充在前，保证 `revision-NNNN` 仍是
            // 独立词元。
            text.push_str(&"x".repeat(revision));
            text.push_str(&format!(" revision-{revision:04}"));
        }
        entries.push((id.clone(), message_payload(&text, session.as_str()), text));
        placements.push(MessagePlacement::new(
            session.clone(),
            document.clone(),
            id.clone(),
            u32::try_from(index).unwrap(),
            false,
            None,
        ));
        members.push(id);
    }
    entries.push((
        session.clone(),
        serde_json::json!({
            "document": document.as_str(),
            "documents": [document.as_str()],
            "messages": members.iter().map(|id| id.as_str()).collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes(),
        String::new(),
    ));
    entries.push((
        document.clone(),
        serde_json::json!({
            "provider": "synthetic",
            "variant": "synthetic/jsonl-v1",
            "fingerprint": "0123456789abcdef",
            "len": 128,
        })
        .to_string()
        .into_bytes(),
        String::new(),
    ));
    SourceBatch {
        source_path: SOURCE_PATH.to_string(),
        entries,
        placements,
        edges: Vec::new(),
        activities: Vec::new(),
        usage_events: Vec::new(),
        relation_complete: true,
        len_bytes: Some(56_320),
        fingerprint: Some(format!("fp-{revision:04}")),
        provider_id: None,
        resume_claims: Vec::new(),
    }
}

fn commit_revision(store: &SqliteStore, revision: usize) {
    assert!(
        store
            .commit_source_batches_if_changed(&[soak_batch(revision)])
            .unwrap(),
        "revision {revision} must activate a new generation"
    );
}

fn seed_revisions(store: &SqliteStore, count: usize) {
    for revision in 0..count {
        commit_revision(store, revision);
        assert_eq!(
            store.active_generation().unwrap(),
            u64::try_from(revision + 1).unwrap()
        );
    }
}

fn scalar(path: &Path, sql: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

fn scalar_with(path: &Path, sql: &str, param: &str) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(sql, [param], |row| row.get(0))
        .unwrap()
}

/// 父实验口径：五个可聚合列的字符总量（compact 前=完整 manifest，后=占位 `[]`）。
fn aggregatable_chars(path: &Path) -> i64 {
    scalar(
        path,
        "SELECT COALESCE(SUM(
             LENGTH(upsert_ids_json) + LENGTH(delete_ids_json)
             + LENGTH(relation_upserts_json) + LENGTH(relation_deletes_json)
             + LENGTH(source_replacements_json)), 0)
         FROM index_batches",
    )
}

fn summary_chars(path: &Path) -> i64 {
    scalar(
        path,
        "SELECT COALESCE(SUM(LENGTH(COALESCE(detail_summary_json, ''))), 0)
         FROM index_batches",
    )
}

/// 库文件与 wal/shm 侧车字节总量（父实验 store_bytes_including_sidecars 口径）。
fn file_bytes(path: &Path) -> u64 {
    ["", "-wal", "-shm"]
        .iter()
        .filter_map(|suffix| {
            std::fs::metadata(format!("{}{suffix}", path.to_string_lossy()))
                .ok()
                .map(|meta| meta.len())
        })
        .sum()
}

/// 永久保留字段的身份快照：代数 + operation_id + operation_digest。
fn batch_identity(path: &Path) -> Vec<(i64, String, String)> {
    let conn = rusqlite::Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT target_generation, operation_id, operation_digest
             FROM index_batches ORDER BY target_generation",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap();
    rows.map(Result::unwrap).collect()
}

fn full_rows(path: &Path) -> i64 {
    scalar(
        path,
        "SELECT COUNT(*) FROM index_batches WHERE detail_format = 'full'",
    )
}

fn aggregated_rows(path: &Path) -> i64 {
    scalar(
        path,
        "SELECT COUNT(*) FROM index_batches WHERE detail_format = 'aggregated_v1'",
    )
}

fn compact_now(store: &SqliteStore) -> u64 {
    let preview = store.preview_journal_compaction().unwrap();
    let stage = store.stage_journal_compaction(&preview).unwrap();
    store
        .apply_journal_compaction(&stage.compaction_id)
        .unwrap()
        .applied_batches
}

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sqlite_process_helper")
}

/// 重放同一 source 的可观察结果：是否推进、推进量、权威 payload 是否被改写、
/// 最新/上一版改写标记的 FTS 命中数。compact 前后必须逐项一致。
fn replay_probe(
    store: &SqliteStore,
    message: &StableId,
    revision: usize,
) -> (bool, u64, bool, usize, usize) {
    let generation = store.active_generation().unwrap();
    let payload_before = store.get(message).unwrap().unwrap();
    let advanced = store
        .commit_source_batches_if_changed(&[soak_batch(revision)])
        .unwrap();
    let payload_after = store.get(message).unwrap().unwrap();
    let delta = store.active_generation().unwrap() - generation;
    (
        advanced,
        delta,
        payload_before == payload_after,
        store.query(&format!("{revision:04}"), 10).unwrap().len(),
        store
            .query(&format!("{:04}", revision.saturating_sub(1)), 10)
            .unwrap()
            .len(),
    )
}

fn start_stage_holder(db_arg: &str) -> (Child, String) {
    let mut child = Command::new(helper())
        .args(["compact-stage", db_arg])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let trimmed = ready.trim().to_string();
    let mut parts = trimmed.split(':');
    assert_eq!(parts.next(), Some("STAGED"), "helper output: {trimmed}");
    let compaction_id = parts.next().expect("compaction id").to_string();
    assert_eq!(parts.next(), Some("4"), "helper output: {trimmed}");
    (child, compaction_id)
}

#[test]
fn preview_reports_scope_fields_and_savings_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    seed_revisions(&store, 3);
    let detail_before = aggregatable_chars(&db);
    assert!(detail_before > 0);

    let preview = store.preview_journal_compaction().unwrap();
    assert_eq!(preview.affected_batches, 3);
    assert_eq!(preview.batches.len(), 3);
    assert_eq!(
        preview.aggregated_fields,
        JOURNAL_COMPACTION_FIELDS.map(str::to_string).to_vec()
    );
    assert_eq!(
        preview.detail_bytes_before,
        u64::try_from(detail_before).unwrap()
    );
    assert_eq!(
        preview.estimated_saved_bytes,
        preview.detail_bytes_before - preview.estimated_detail_bytes_after
    );
    assert!(preview.estimated_saved_bytes > 0, "{preview:?}");
    // 明细 >> 摘要：预计收益至少覆盖明细的 90%。
    assert!(preview.estimated_detail_bytes_after * 10 < preview.detail_bytes_before);
    for item in &preview.batches {
        assert_eq!(item.state, "activated");
        assert_eq!(item.fields.len(), JOURNAL_COMPACTION_FIELDS.len());
        assert_eq!(item.operation_digest.len(), 64);
        assert_eq!(item.detail_digest.len(), 64);
        let upserts = item
            .fields
            .iter()
            .find(|field| field.field == "upsert_ids_json")
            .unwrap();
        assert_eq!(upserts.items, 202);
        let placements = item
            .fields
            .iter()
            .find(|field| field.field == "relation_upserts_json")
            .unwrap();
        assert_eq!(placements.items, 200);
    }

    // 计划承诺稳定；preview 不做任何写入。
    let twin = store.preview_journal_compaction().unwrap();
    assert_eq!(twin.plan_digest, preview.plan_digest);
    assert_ne!(twin.compaction_id, preview.compaction_id);
    assert_eq!(aggregatable_chars(&db), detail_before);
    assert_eq!(full_rows(&db), 3);
    assert_eq!(aggregated_rows(&db), 0);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM journal_compactions"), 0);

    // journal 在预览之后变化：stage 以 CAS 拒绝，且不留 staged 计划。
    for revision in 3..7 {
        commit_revision(&store, revision);
    }
    assert_eq!(store.active_generation().unwrap(), 7);
    let detail_after_revisions = aggregatable_chars(&db);
    assert!(detail_after_revisions > detail_before);
    let error = store.stage_journal_compaction(&preview).unwrap_err();
    assert!(matches!(error, PortError::GenerationMismatch(_)), "{error}");
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM journal_compactions"), 0);
    let fresh = store.preview_journal_compaction().unwrap();
    assert_eq!(fresh.affected_batches, 7);
    let stage = store.stage_journal_compaction(&fresh).unwrap();
    assert_eq!(stage.compaction_id, fresh.compaction_id);
    assert_eq!(stage.plan_digest, fresh.plan_digest);
    assert_eq!(stage.affected_batches, 7);
    assert_eq!(stage.estimated_saved_bytes, fresh.estimated_saved_bytes);
    let event = store
        .journal_compaction_event(&stage.compaction_id)
        .unwrap()
        .unwrap();
    assert_eq!(event.state, "staged");
    assert_eq!(event.affected_batches, 7);
    assert_eq!(event.saved_bytes, fresh.estimated_saved_bytes);
    assert!(event.resolved_at_ms.is_none());
    // stage 只写计划行：明细字符量与格式标记都不变。
    assert_eq!(full_rows(&db), 7);
    assert_eq!(aggregatable_chars(&db), detail_after_revisions);
}

#[test]
fn negligible_terminal_rows_stay_full_and_out_of_the_plan() {
    // 合同 §2：聚合无收益（明细不大于摘要）的 terminal 行保持 full——有约束治理只做减法。
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    let store = SqliteStore::open_for_write(&db_arg).unwrap();

    let small = sid(IdKind::Message, "retention-small-message");
    let small_text = "retention small body";
    let small_entries = [(
        small.clone(),
        message_payload(small_text, soak_session().as_str()),
        small_text.to_string(),
    )];
    let pending = store.begin_index_batch(&small_entries, &[]).unwrap();
    store
        .commit_index_batch(&pending, &small_entries, &[])
        .unwrap();
    let detail_before = scalar_with(
        &db,
        "SELECT LENGTH(upsert_ids_json) + LENGTH(delete_ids_json)
             + LENGTH(relation_upserts_json) + LENGTH(relation_deletes_json)
             + LENGTH(source_replacements_json)
         FROM index_batches WHERE operation_id = ?1",
        &pending.operation_id,
    );

    // 同库再来一条有收益的大行（soak 形状）：证明小行是被“无收益”筛掉，
    // 而不是整体被忽略。
    commit_revision(&store, 0);
    let preview = store.preview_journal_compaction().unwrap();
    assert_eq!(preview.affected_batches, 1);
    assert!(
        preview
            .batches
            .iter()
            .all(|item| item.operation_id != pending.operation_id)
    );
    assert!(preview.estimated_saved_bytes > 0);

    assert_eq!(compact_now(&store), 1);
    let small_row = store.index_batch(&pending.operation_id).unwrap().unwrap();
    assert_eq!(small_row.detail_format, JOURNAL_DETAIL_FORMAT_FULL);
    assert!(small_row.detail_summary.is_none());
    assert_eq!(small_row.upsert_ids, vec![small.as_str().to_string()]);
    assert_eq!(
        scalar_with(
            &db,
            "SELECT LENGTH(upsert_ids_json) + LENGTH(delete_ids_json)
                 + LENGTH(relation_upserts_json) + LENGTH(relation_deletes_json)
                 + LENGTH(source_replacements_json)
             FROM index_batches WHERE operation_id = ?1",
            &pending.operation_id
        ),
        detail_before,
        "无收益行必须逐字节保持 full"
    );
    assert_eq!(full_rows(&db), 1);
    assert_eq!(aggregated_rows(&db), 1);
}

#[test]
fn soak_200_messages_21_revisions_reports_sizes_and_keeps_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();

    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, LATEST_REVISION);
        assert_eq!(store.count().unwrap(), 202);
        assert_eq!(store.active_generation().unwrap(), 21);
        // 最后一版正文可检索、被替换掉的旧版本不可检索。
        assert_eq!(store.query("0020", 10).unwrap().len(), 1);
        assert!(store.query("0019", 10).unwrap().is_empty());
    }
    let identity_snapshot = batch_identity(&db);
    assert_eq!(identity_snapshot.len(), 21);
    let bytes_before = file_bytes(&db);
    let chars_before = aggregatable_chars(&db);
    let freelist_before = scalar(&db, "PRAGMA freelist_count");

    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    let preview = store.preview_journal_compaction().unwrap();
    assert_eq!(preview.affected_batches, 21);
    let stage = store.stage_journal_compaction(&preview).unwrap();
    let outcome = store
        .apply_journal_compaction(&stage.compaction_id)
        .unwrap();
    assert!(!outcome.already_committed);
    assert_eq!(outcome.applied_batches, 21);
    assert_eq!(outcome.detail_bytes_before, preview.detail_bytes_before);
    assert_eq!(
        outcome.detail_bytes_after,
        preview.estimated_detail_bytes_after
    );
    assert_eq!(outcome.saved_bytes, preview.estimated_saved_bytes);

    // 幂等重入：apply 已提交计划不改写任何行。
    let again = store
        .apply_journal_compaction(&stage.compaction_id)
        .unwrap();
    assert!(again.already_committed);
    assert_eq!(again.applied_batches, 0);
    assert_eq!(again.saved_bytes, outcome.saved_bytes);

    // 可观察语义不变：catalog 行数、FTS 命中、generation 水位、批次身份。
    assert_eq!(store.active_generation().unwrap(), 21);
    assert_eq!(store.count().unwrap(), 202);
    assert_eq!(store.query("0020", 10).unwrap().len(), 1);
    assert!(store.query("0019", 10).unwrap().is_empty());
    assert_eq!(batch_identity(&db), identity_snapshot);
    // 明细被摘要替换：格式标记与摘要规模。
    assert_eq!(full_rows(&db), 0);
    assert_eq!(aggregated_rows(&db), 21);
    let first = store.index_batch(&identity_snapshot[0].1).unwrap().unwrap();
    assert_eq!(first.detail_format, JOURNAL_DETAIL_FORMAT_AGGREGATED_V1);
    assert!(first.upsert_ids.is_empty(), "占位 [] 不是事实");
    let summary = first.detail_summary.unwrap();
    assert_eq!(summary.items["upsert_ids_json"], 202);
    assert_eq!(summary.items["relation_upserts_json"], 200);
    assert_eq!(summary.compaction_id, stage.compaction_id);
    assert_eq!(summary.detail_digest.len(), 64);
    drop(store);

    let bytes_after = file_bytes(&db);
    let chars_after = aggregatable_chars(&db);
    let freelist_after = scalar(&db, "PRAGMA freelist_count");
    println!(
        "[soak] journal 明细字符(5 列): before={chars_before} after={chars_after} kept={:.3}%",
        chars_after as f64 * 100.0 / chars_before as f64
    );
    println!(
        "[soak] store 字节(含侧车): before={bytes_before} after={bytes_after} freed_pages: {freelist_before}->{freelist_after}"
    );
    // 五个可聚合列只剩每行 10 字节占位；摘要另存新列，合计即 preview 的精确预算。
    assert_eq!(chars_after, 10 * aggregated_rows(&db));
    assert_eq!(
        summary_chars(&db),
        i64::try_from(preview.estimated_detail_bytes_after).unwrap() - chars_after
    );
    assert!(chars_after * 100 < chars_before, "明细压缩必须 >99%");
    assert!(bytes_after <= bytes_before, "compact 不得让库文件增长");
    assert!(freelist_after >= freelist_before, "释放的页必须可复用");
}

#[test]
fn killed_process_after_stage_converges_through_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 4);
    }
    let identity_before = batch_identity(&db);
    let chars_before = aggregatable_chars(&db);

    // 子进程把 staged 计划 durable 落盘后阻塞；父进程 kill 它（无清理路径）。
    let (mut child, compaction_id) = start_stage_holder(&db_arg);
    child.kill().unwrap();
    child.wait().unwrap();

    // 崩溃后：计划在、明细一行未动、catalog/generation 不变。
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    let event = store
        .journal_compaction_event(&compaction_id)
        .unwrap()
        .unwrap();
    assert_eq!(event.state, "staged");
    assert_eq!(full_rows(&db), 4);
    assert_eq!(aggregated_rows(&db), 0);
    assert_eq!(aggregatable_chars(&db), chars_before);
    assert_eq!(store.active_generation().unwrap(), 4);
    assert_eq!(store.count().unwrap(), 202);

    // 重入收敛：显式恢复提交 staged 计划。
    let recovery = store.recover_journal_compactions().unwrap();
    assert_eq!(recovery.committed, 1);
    assert_eq!(recovery.already_committed, 0);
    assert_eq!(recovery.abandoned, 0);
    assert_eq!(recovery.staged_remaining, 0);
    assert_eq!(full_rows(&db), 0);
    assert_eq!(aggregated_rows(&db), 4);
    assert_eq!(batch_identity(&db), identity_before);
    assert_eq!(store.active_generation().unwrap(), 4);
    assert_eq!(store.count().unwrap(), 202);
    assert_eq!(store.query("0020", 10).unwrap().len(), 0);
    assert_eq!(store.query("0003", 10).unwrap().len(), 1);

    // 再收敛是幂等空操作；apply 重入同样幂等。
    let again = store.recover_journal_compactions().unwrap();
    assert_eq!(again.committed, 0);
    assert_eq!(again.abandoned, 0);
    assert_eq!(again.staged_remaining, 0);
    let reapply = store.apply_journal_compaction(&compaction_id).unwrap();
    assert!(reapply.already_committed);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM journal_compactions"), 1);
    let committed = store
        .journal_compaction_event(&compaction_id)
        .unwrap()
        .unwrap();
    assert_eq!(committed.state, "committed");
    assert!(committed.resolved_at_ms.is_some());
}

#[test]
fn concurrent_reader_sees_one_consistent_journal_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 3);
    }

    // 读快照在 compact 之前建立：期间 compact 的 stage+apply 提交都不可见。
    let reader = rusqlite::Connection::open(&db).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let full_in_snapshot = reader
        .query_row(
            "SELECT COUNT(*) FROM index_batches WHERE detail_format = 'full'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(full_in_snapshot, 3);

    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        assert_eq!(compact_now(&store), 3);
    }

    // 旧快照仍是 compact 前的完整明细（没有半聚合行，也没有 staged 计划）。
    let full_during = reader
        .query_row(
            "SELECT COUNT(*) FROM index_batches WHERE detail_format = 'full'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(full_during, full_in_snapshot);
    let plans_during = reader
        .query_row("SELECT COUNT(*) FROM journal_compactions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(plans_during, 0);
    reader.execute_batch("COMMIT").unwrap();

    // 新快照原子看到全部结果：明细聚合 + 计划 committed 同时可见。
    let full_after = reader
        .query_row(
            "SELECT COUNT(*) FROM index_batches WHERE detail_format = 'full'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(full_after, 0);
    let committed_plans = reader
        .query_row(
            "SELECT COUNT(*) FROM journal_compactions WHERE state = 'committed'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(committed_plans, 1);
    let catalog_rows = reader
        .query_row("SELECT COUNT(*) FROM catalog", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(catalog_rows, 202);
}

#[test]
fn legacy_v18_rows_migrate_read_and_compact() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 2);
    }
    let identity_before = batch_identity(&db);

    // 把库降级成 v18 形状：删掉 v19 的列与计划表（既有行 = 无标记的完整明细）。
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "DROP TABLE IF EXISTS journal_compactions;
             ALTER TABLE index_batches DROP COLUMN detail_summary_json;
             ALTER TABLE index_batches DROP COLUMN detail_format;
             PRAGMA user_version = 18;",
        )
        .unwrap();
    }
    // 读打开不做迁移（版本门 fail-closed）；写打开走到 v19，旧行按 full 回填。
    assert!(matches!(
        SqliteStore::open(&db_arg),
        Err(PortError::SchemaIncompatible(_))
    ));
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    assert_eq!(store.schema_version().unwrap(), 19);
    let operation_id = identity_before[0].1.clone();
    let legacy = store.index_batch(&operation_id).unwrap().unwrap();
    assert_eq!(legacy.detail_format, JOURNAL_DETAIL_FORMAT_FULL);
    assert!(legacy.detail_summary.is_none());
    assert_eq!(legacy.upsert_ids.len(), 202);
    assert_eq!(legacy.relation_upserts.len(), 200);

    // 无标记旧行参与聚合，身份/摘要不变。
    let preview = store.preview_journal_compaction().unwrap();
    assert_eq!(preview.affected_batches, 2);
    let stage = store.stage_journal_compaction(&preview).unwrap();
    assert_eq!(
        store
            .apply_journal_compaction(&stage.compaction_id)
            .unwrap()
            .applied_batches,
        2
    );
    let compacted = store.index_batch(&operation_id).unwrap().unwrap();
    assert_eq!(compacted.detail_format, JOURNAL_DETAIL_FORMAT_AGGREGATED_V1);
    assert_eq!(
        compacted.detail_summary.unwrap().items["upsert_ids_json"],
        202
    );
    assert_eq!(batch_identity(&db), identity_before);
    assert_eq!(store.active_generation().unwrap(), 2);
    assert_eq!(store.query("0001", 10).unwrap().len(), 1);
}

#[test]
fn drifted_staged_plan_is_abandoned_without_touching_detail() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 2);
    }
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    let preview = store.preview_journal_compaction().unwrap();
    let stage = store.stage_journal_compaction(&preview).unwrap();
    let operation_id = preview.batches[0].operation_id.clone();

    // 计划行漂移（只改一条明细列）：apply 必须整批拒绝、零改写。
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE index_batches SET delete_ids_json = '[\"tampered\"]'
             WHERE operation_id = ?1",
            [&operation_id],
        )
        .unwrap();
    }
    let error = store
        .apply_journal_compaction(&stage.compaction_id)
        .unwrap_err();
    assert!(matches!(error, PortError::GenerationMismatch(_)), "{error}");
    assert_eq!(full_rows(&db), 2);
    assert_eq!(aggregated_rows(&db), 0);
    let event = store
        .journal_compaction_event(&stage.compaction_id)
        .unwrap()
        .unwrap();
    assert_eq!(event.state, "staged", "apply 失败必须回滚到 staged");

    // 显式恢复：漂移计划被 abandoned（原因入审计行），明细仍未被改写。
    let recovery = store.recover_journal_compactions().unwrap();
    assert_eq!(recovery.committed, 0);
    assert_eq!(recovery.already_committed, 0);
    assert_eq!(recovery.abandoned, 1);
    assert_eq!(recovery.staged_remaining, 0);
    let event = store
        .journal_compaction_event(&stage.compaction_id)
        .unwrap()
        .unwrap();
    assert_eq!(event.state, "abandoned");
    assert_eq!(
        event.reason.as_deref(),
        Some("journal changed since the compaction preview; re-run preview")
    );
    assert!(event.resolved_at_ms.is_some());
    assert_eq!(full_rows(&db), 2);
    assert_eq!(aggregated_rows(&db), 0);
    assert_eq!(
        scalar_with(
            &db,
            "SELECT LENGTH(delete_ids_json) FROM index_batches WHERE operation_id = ?1",
            &operation_id
        ),
        12,
        "漂移行保持原样，不静默改写"
    );
    // 已放弃的计划不可再 apply。
    let error = store
        .apply_journal_compaction(&stage.compaction_id)
        .unwrap_err();
    assert!(matches!(error, PortError::InvalidRequest(_)), "{error}");
}

#[test]
fn relocation_manifest_detail_is_never_aggregated() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    let manifest = r#"{"mapping_key":"synthetic","to_key":"synthetic-root"}"#;
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 1);
        let operation_id = batch_identity(&db)[0].1.clone();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE index_batches SET relocation_json = ?1 WHERE operation_id = ?2",
            rusqlite::params![manifest, operation_id],
        )
        .unwrap();
    }

    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    let preview = store.preview_journal_compaction().unwrap();
    assert_eq!(preview.affected_batches, 1);
    assert!(
        !preview
            .aggregated_fields
            .iter()
            .any(|field| field == "relocation_json"),
        "relocation manifest 是永久保留字段"
    );
    assert_eq!(compact_now(&store), 1);
    let operation_id = preview.batches[0].operation_id.clone();
    let stored_manifest: String = rusqlite::Connection::open(&db)
        .unwrap()
        .query_row(
            "SELECT relocation_json FROM index_batches WHERE operation_id = ?1",
            [&operation_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored_manifest, manifest,
        "relocation manifest 必须逐字节保留"
    );
    assert_eq!(aggregated_rows(&db), 1);
}

#[test]
fn unknown_detail_format_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 2);
    }
    let operation_id = batch_identity(&db)[0].1.clone();
    let upsert_chars_before = scalar_with(
        &db,
        "SELECT LENGTH(upsert_ids_json) FROM index_batches WHERE operation_id = ?1",
        &operation_id,
    );
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE index_batches
             SET detail_format = 'aggregated_v99',
                 detail_summary_json = '{\"format\":\"aggregated_v99\",\"compaction_id\":\"x\",\"items\":{},\"bytes\":{},\"detail_digest\":\"x\"}'
             WHERE operation_id = ?1",
            [&operation_id],
        )
        .unwrap();
    }

    // 读路径与 preview 都不解释未知格式：fail-closed，不写任何东西。
    let reader = SqliteStore::open(&db_arg).unwrap();
    let error = reader.index_batch(&operation_id).unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    let error = reader.preview_journal_compaction().unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    assert_eq!(
        scalar_with(
            &db,
            "SELECT LENGTH(upsert_ids_json) FROM index_batches WHERE operation_id = ?1",
            &operation_id
        ),
        upsert_chars_before,
        "fail-closed 不得改写未知格式行"
    );
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM journal_compactions"), 0);
    assert_eq!(full_rows(&db), 1);
}

#[test]
fn unknown_format_on_unresolved_row_still_fails_closed() {
    // 保留合同 §5 对未知 detail_format 无豁免：即使该行是不进计划的
    // 未决（building）行，preview 也不得静默跳过——跳过只适用于本二进制认识的格式。
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    seed_revisions(&store, 1);

    let late = sid(IdKind::Message, "retention-unresolved-unknown-format");
    let late_text = "retention unresolved body";
    let pending_entries = [(
        late.clone(),
        message_payload(late_text, soak_session().as_str()),
        late_text.to_string(),
    )];
    let pending = store.begin_index_batch(&pending_entries, &[]).unwrap();
    let upserts_before = scalar_with(
        &db,
        "SELECT LENGTH(upsert_ids_json) FROM index_batches WHERE operation_id = ?1",
        &pending.operation_id,
    );
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE index_batches
             SET detail_format = 'aggregated_v99',
                 detail_summary_json = '{\"format\":\"aggregated_v99\"}'
             WHERE operation_id = ?1",
            [&pending.operation_id],
        )
        .unwrap();
    }

    // 读与 preview 都 fail-closed：不解释、不跳过、零改写。
    let error = store.index_batch(&pending.operation_id).unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    let error = store.preview_journal_compaction().unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    assert_eq!(
        scalar_with(
            &db,
            "SELECT LENGTH(upsert_ids_json) FROM index_batches WHERE operation_id = ?1",
            &pending.operation_id
        ),
        upserts_before,
        "fail-closed 不得改写未决行明细"
    );
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM journal_compactions"), 0);
}

#[test]
fn unknown_state_fails_closed_in_preview_without_rewrite() {
    // 未知状态（未来 schema 才会写入的值）同样不得因“该行已聚合”而被跳过。
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        seed_revisions(&store, 2);
    }
    let operation_id = {
        let store = SqliteStore::open_for_write(&db_arg).unwrap();
        let operation_id = store.preview_journal_compaction().unwrap().batches[0]
            .operation_id
            .clone();
        assert_eq!(compact_now(&store), 2);
        operation_id
    };
    let summary_before = scalar_with(
        &db,
        "SELECT LENGTH(COALESCE(detail_summary_json, '')) FROM index_batches
         WHERE operation_id = ?1",
        &operation_id,
    );
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        conn.execute(
            "UPDATE index_batches SET state = 'mystery_state' WHERE operation_id = ?1",
            [&operation_id],
        )
        .unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .unwrap();
    }

    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    let error = store.preview_journal_compaction().unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    // 零改写：状态与已聚合摘要逐字节保留，计划行也不受影响。
    let state: String = rusqlite::Connection::open(&db)
        .unwrap()
        .query_row(
            "SELECT state FROM index_batches WHERE operation_id = ?1",
            [&operation_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "mystery_state");
    assert_eq!(
        scalar_with(
            &db,
            "SELECT LENGTH(COALESCE(detail_summary_json, '')) FROM index_batches
             WHERE operation_id = ?1",
            &operation_id
        ),
        summary_before
    );
    assert_eq!(
        scalar(
            &db,
            "SELECT COUNT(*) FROM journal_compactions WHERE state = 'committed'"
        ),
        1
    );
}

#[test]
fn apply_rejects_unknown_format_drift_without_rewrite() {
    // apply 路径的未知格式漂移：整事务拒绝、零改写，且 recover 不得把它当漂移
    // “自动放弃”（未知格式必须向上报错，计划保持 staged）。
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    seed_revisions(&store, 2);
    let preview = store.preview_journal_compaction().unwrap();
    let stage = store.stage_journal_compaction(&preview).unwrap();
    let operation_id = preview.batches[0].operation_id.clone();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE index_batches
             SET detail_format = 'aggregated_v99',
                 detail_summary_json = '{\"format\":\"aggregated_v99\"}'
             WHERE operation_id = ?1",
            [&operation_id],
        )
        .unwrap();
    }

    let error = store
        .apply_journal_compaction(&stage.compaction_id)
        .unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    assert_eq!(full_rows(&db), 1, "同事务的其余行必须回滚");
    assert_eq!(aggregated_rows(&db), 0);
    let error = store.recover_journal_compactions().unwrap_err();
    assert!(matches!(error, PortError::SchemaIncompatible(_)), "{error}");
    assert_eq!(
        scalar(
            &db,
            "SELECT COUNT(*) FROM journal_compactions WHERE state = 'staged'"
        ),
        1,
        "未知格式不得被 recover 自动放弃"
    );
}

#[test]
fn unresolved_and_conflict_paths_are_unaffected_by_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("catalog.db");
    let db_arg = db.to_string_lossy().into_owned();
    let store = SqliteStore::open_for_write(&db_arg).unwrap();
    seed_revisions(&store, 3);

    // 冲突投影：text 是内容投影（合并保留更长投影，不构成冲突），稳定字段
    // role 不一致才是真正的跨源冲突。
    let conflict_text = "retention body 0 conflicting projection";
    let conflicting = SourceBatch {
        source_path: "retention-conflict.jsonl".into(),
        entries: vec![(
            sid(IdKind::Message, "retention-message-0"),
            message_payload_with_role(conflict_text, soak_session().as_str(), "assistant"),
            conflict_text.to_string(),
        )],
        placements: Vec::new(),
        edges: Vec::new(),
        activities: Vec::new(),
        usage_events: Vec::new(),
        relation_complete: true,
        len_bytes: None,
        fingerprint: None,
        provider_id: None,
        resume_claims: Vec::new(),
    };
    let conflict_before = format!(
        "{}",
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&conflicting))
            .unwrap_err()
    );
    assert!(
        conflict_before.contains("conflicting projections"),
        "{conflict_before}"
    );

    // 未决 durable intent：创建在 compact 之前，明细完整保留且不进入聚合。
    let late = sid(IdKind::Message, "retention-late-message");
    let late_text = "retention late body";
    let pending_entries = [(
        late.clone(),
        message_payload(late_text, soak_session().as_str()),
        late_text.to_string(),
    )];
    let pending = store.begin_index_batch(&pending_entries, &[]).unwrap();
    let preview = store.preview_journal_compaction().unwrap();
    assert_eq!(preview.affected_batches, 3, "building 行不得进入聚合");
    assert!(
        preview
            .batches
            .iter()
            .all(|item| item.operation_id != pending.operation_id)
    );
    let stage = store.stage_journal_compaction(&preview).unwrap();
    assert_eq!(
        store
            .apply_journal_compaction(&stage.compaction_id)
            .unwrap()
            .applied_batches,
        3
    );

    // 未决行仍是完整明细，且能继续按自己的 CAS 提交（compact 不动 generation 水位）。
    let building = store.index_batch(&pending.operation_id).unwrap().unwrap();
    assert_eq!(building.state, "building");
    assert_eq!(building.detail_format, JOURNAL_DETAIL_FORMAT_FULL);
    assert_eq!(building.upsert_ids, vec![late.as_str().to_string()]);
    assert_eq!(store.active_generation().unwrap(), 3);
    store
        .commit_index_batch(&pending, &pending_entries, &[])
        .unwrap();
    assert_eq!(store.active_generation().unwrap(), 4);
    assert!(store.get(&late).unwrap().is_some());

    // 冲突检测不回退：compact 前后同一条冲突投影给出同一拒绝。
    let conflict_after = format!(
        "{}",
        store
            .commit_source_batches_if_changed(std::slice::from_ref(&conflicting))
            .unwrap_err()
    );
    assert_eq!(conflict_after, conflict_before);
    assert_eq!(store.active_generation().unwrap(), 4);

    // 重放语义不变：同一 source 的重放在 compact 前后可观察结果一致
    // （重放本身按既有收敛规则推进 generation，这不是 compact 引入的行为）。
    let latest = sid(
        IdKind::Message,
        &format!("retention-message-{}", MESSAGE_COUNT - 1),
    );
    let replay_before = replay_probe(&store, &latest, 2);
    assert_eq!(compact_now(&store), 1, "重放产生的新 terminal 行可再次聚合");
    let replay_after = replay_probe(&store, &latest, 2);
    assert_eq!(replay_after, replay_before);

    // 恢复路径：没有 building 残留，recover_interrupted 是幂等 no-op。
    assert_eq!(store.recover_interrupted().unwrap(), 0);
    assert_eq!(store.interrupted_batch_count().unwrap(), 0);
}
